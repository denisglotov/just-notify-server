use crate::behaviour::{AppBehaviour, AppBehaviourEvent};
use crate::ipc::{IpcRequest, IpcResponse};
use crate::service_key::{self, extract_ip_addresses, extract_peer_id, normalize_observed_address};

use anyhow::Context;
use futures::{SinkExt, StreamExt};
use libp2p::kad::store::RecordStore;
use libp2p::{autonat, identify, kad, ping, Multiaddr, PeerId, Swarm, SwarmBuilder};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Framed, LinesCodec};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredProvider {
    pub peer_id: String,
    pub addresses: Vec<String>,
}

struct PendingSearch {
    providers: Arc<Mutex<HashMap<PeerId, HashSet<Multiaddr>>>>,
    sender: oneshot::Sender<Vec<DiscoveredProvider>>,
}

enum DaemonEvent {
    Ipc {
        request: IpcRequest,
        responder: oneshot::Sender<IpcResponse>,
    },
}

struct SocketCleanupGuard {
    path: PathBuf,
}

impl Drop for SocketCleanupGuard {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = std::fs::remove_file(&self.path);
            info!(
                "Cleaned up IPC Unix Domain Socket at {}",
                self.path.display()
            );
        }
    }
}

fn load_bootstrap_nodes(
    file_path: &std::path::Path,
    cli_nodes: &[String],
) -> anyhow::Result<Vec<String>> {
    let mut all_nodes = Vec::new();

    if file_path.exists() {
        let content = std::fs::read_to_string(file_path).with_context(|| {
            format!(
                "Failed to read bootstrap nodes file at '{}'",
                file_path.display()
            )
        })?;

        let nodes: Vec<String> = content
            .lines()
            .map(|line| line.trim())
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.to_string())
            .collect();

        info!(
            "Loaded {} bootstrap node(s) from {}",
            nodes.len(),
            file_path.display()
        );
        all_nodes.extend(nodes);
    } else if cli_nodes.is_empty() {
        anyhow::bail!(
            "Bootstrap nodes file does not exist at '{}' and no --bootstrap-node CLI options provided.",
            file_path.display()
        );
    }

    all_nodes.extend(cli_nodes.iter().cloned());

    if all_nodes.is_empty() {
        anyhow::bail!("No valid bootstrap nodes provided");
    }

    Ok(all_nodes)
}

#[allow(clippy::too_many_arguments)]
pub async fn run_daemon(
    tcp_port: u16,
    quic_port: u16,
    socket_path: PathBuf,
    service_name: String,
    reannounce_interval_secs: u64,
    bootstrap_nodes_file: PathBuf,
    cli_bootstrap_nodes: Vec<String>,
    key_file: PathBuf,
) -> anyhow::Result<()> {
    info!("Starting IPFS libp2p server daemon...");

    // Load or generate identity keypair
    let local_key = service_key::load_or_generate_keypair(Some(&key_file))?;
    let local_peer_id = PeerId::from(local_key.public());
    info!("Local Peer ID: {}", local_peer_id);
    info!("Node identity persisted at: {}", key_file.display());

    // Build swarm with TCP + DNS + QUIC transports
    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default(),
            libp2p::noise::Config::new,
            libp2p::yamux::Config::default,
        )?
        .with_quic()
        .with_dns()?
        .with_behaviour(|key| {
            let peer_id = key.public().to_peer_id();

            // Kademlia store & config
            let store = kad::store::MemoryStore::new(peer_id);
            let mut kad_config = kad::Config::default();
            kad_config.set_query_timeout(Duration::from_secs(30));
            if let Some(replication) = std::num::NonZeroUsize::new(20) {
                kad_config.set_replication_factor(replication);
            }
            kad_config.set_provider_publication_interval(Some(Duration::from_secs(
                reannounce_interval_secs,
            )));
            let mut kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);
            kademlia.set_mode(Some(kad::Mode::Server));

            // Identify
            let identify = identify::Behaviour::new(identify::Config::new(
                "/ipfs/1.0.0".to_string(),
                key.public(),
            ));

            // Ping
            let ping = ping::Behaviour::new(ping::Config::new());

            // AutoNAT
            let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());

            Ok(AppBehaviour {
                kademlia,
                identify,
                ping,
                autonat,
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // Clean up existing UDS socket file if present and ensure directory exists
    if let Some(parent) = socket_path.parent() {
        if !parent.exists() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    let ipc_listener = UnixListener::bind(&socket_path).with_context(|| {
        format!(
            "Failed to bind Unix Domain Socket at {}",
            socket_path.display()
        )
    })?;

    // RAII Guard to guarantee socket deletion on any exit or drop
    let _socket_guard = SocketCleanupGuard {
        path: socket_path.clone(),
    };

    info!(
        "IPC Unix Domain Socket listening at {}",
        socket_path.display()
    );

    // MPSC channel to receive IPC events from async socket tasks
    let (ipc_tx, mut ipc_rx) = mpsc::channel::<DaemonEvent>(64);

    // Spawn task to accept UDS IPC connections
    let listener_tx = ipc_tx.clone();
    tokio::spawn(async move {
        loop {
            match ipc_listener.accept().await {
                Ok((stream, _)) => {
                    let conn_tx = listener_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_ipc_connection(stream, conn_tx).await {
                            debug!("IPC connection ended: {:?}", e);
                        }
                    });
                }
                Err(e) => {
                    warn!("Non-fatal error accepting IPC connection: {:?}", e);
                    // Add a tiny backoff on temporary OS errors (e.g. EMFILE, ECONNABORTED)
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    });

    // Listen on TCP multiaddress
    let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", tcp_port).parse()?;
    swarm.listen_on(tcp_addr.clone())?;
    info!("Listening for P2P TCP connections on {}", tcp_addr);

    // Listen on QUIC multiaddress
    let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", quic_port).parse()?;
    swarm.listen_on(quic_addr.clone())?;
    info!("Listening for P2P QUIC connections on {}", quic_addr);

    let bootstrap_addrs = load_bootstrap_nodes(&bootstrap_nodes_file, &cli_bootstrap_nodes)?;
    info!("Bootstrapping into IPFS / libp2p network...");
    for addr_str in &bootstrap_addrs {
        match addr_str.parse::<Multiaddr>() {
            Ok(addr) => {
                if let Some(peer_id) = extract_peer_id(&addr) {
                    let _ = swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                }
                if let Err(e) = swarm.dial(addr.clone()) {
                    debug!("Failed to dial bootstrap node {}: {:?}", addr, e);
                } else {
                    info!("Dialing bootstrap node: {}", addr);
                }
            }
            Err(err) => {
                warn!(
                    "Failed to parse bootstrap multiaddress '{}': {:?}",
                    addr_str, err
                );
            }
        }
    }
    if let Err(e) = swarm.behaviour_mut().kademlia.bootstrap() {
        warn!("Kademlia initial bootstrap trigger warning: {:?}", e);
    }

    // Register service provider record ("org.dymka.just-notify-server")
    let (service_cid, service_mhash) = service_key::derive_service_multihash(&service_name);
    let record_key = kad::RecordKey::new(&service_mhash.to_bytes());
    info!(
        "Configured provider record for service '{}' (CID: {}) on IPFS DHT",
        service_name, service_cid
    );

    // Progressive re-announcement delays for initial warmup: 3s, 10s, 30s, 60s, 120s
    let progressive_delays = [3, 10, 30, 60, 120];
    let mut progressive_idx = 0;
    let mut next_reannounce =
        tokio::time::Instant::now() + Duration::from_secs(progressive_delays[0]);

    let mut pending_searches: HashMap<kad::QueryId, PendingSearch> = HashMap::new();
    let mut peer_lookups: HashMap<kad::QueryId, PeerId> = HashMap::new();
    let mut known_external_addrs: HashSet<Multiaddr> = HashSet::new();
    let mut observed_candidates_quorum: HashMap<Multiaddr, HashSet<PeerId>> = HashMap::new();
    let mut bootstrapped = false;

    #[cfg(unix)]
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    info!("Daemon running. Awaiting network events and IPC client commands...");

    loop {
        tokio::select! {
            // Shutdown on SIGINT (Ctrl+C)
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT (Ctrl+C), shutting down daemon...");
                break;
            }

            // Shutdown on SIGTERM
            _ = async {
                #[cfg(unix)]
                {
                    sigterm.recv().await;
                }
                #[cfg(not(unix))]
                {
                    std::future::pending::<()>().await;
                }
            } => {
                info!("Received SIGTERM, shutting down daemon...");
                break;
            }

            // Progressive and periodic service re-announcements
            _ = tokio::time::sleep_until(next_reannounce) => {
                info!("Announcing service '{}' provider record to IPFS DHT", service_name);
                if let Err(e) = swarm.behaviour_mut().kademlia.start_providing(record_key.clone()) {
                    debug!("Provider announcement query error: {:?}", e);
                }

                // Calculate next reannounce time
                if progressive_idx + 1 < progressive_delays.len() {
                    progressive_idx += 1;
                    next_reannounce = tokio::time::Instant::now() + Duration::from_secs(progressive_delays[progressive_idx]);
                } else {
                    next_reannounce = tokio::time::Instant::now() + Duration::from_secs(reannounce_interval_secs);
                }
            }

            // IPC commands from client
            maybe_event = ipc_rx.recv() => {
                match maybe_event {
                    Some(DaemonEvent::Ipc { request, responder }) => {
                        handle_ipc_request(
                            request,
                            responder,
                            &mut swarm,
                            local_peer_id,
                            &service_name,
                            &mut pending_searches,
                        );
                    }
                    None => {
                        warn!("IPC receiver stream closed");
                    }
                }
            }

            // Swarm events
            event = swarm.select_next_some() => {
                handle_swarm_event(
                    event,
                    &mut swarm,
                    &mut pending_searches,
                    &mut peer_lookups,
                    &mut known_external_addrs,
                    &mut observed_candidates_quorum,
                    &mut bootstrapped,
                    &record_key,
                    &service_name,
                    tcp_port,
                    quic_port,
                );
            }
        }
    }

    info!("Daemon shutdown complete.");
    Ok(())
}

async fn handle_ipc_connection(
    stream: UnixStream,
    ipc_tx: mpsc::Sender<DaemonEvent>,
) -> anyhow::Result<()> {
    let mut framed = Framed::new(stream, LinesCodec::new_with_max_length(1024 * 1024));

    while let Some(line_res) = framed.next().await {
        let line = match line_res {
            Ok(l) => l,
            Err(e) => {
                debug!("Error reading line from IPC client: {:?}", e);
                break;
            }
        };

        let request: IpcRequest = match serde_json::from_str(&line) {
            Ok(req) => req,
            Err(e) => {
                let resp = IpcResponse::Error {
                    message: format!("Invalid JSON request: {}", e),
                };
                let _ = framed.send(serde_json::to_string(&resp)?).await;
                continue;
            }
        };

        let (resp_tx, resp_rx) = oneshot::channel();
        if let Err(e) = ipc_tx
            .send(DaemonEvent::Ipc {
                request,
                responder: resp_tx,
            })
            .await
        {
            let resp = IpcResponse::Error {
                message: format!("Daemon internal channel error: {}", e),
            };
            let _ = framed.send(serde_json::to_string(&resp)?).await;
            break;
        }

        match resp_rx.await {
            Ok(response) => {
                let json_resp = serde_json::to_string(&response)?;
                if let Err(e) = framed.send(json_resp).await {
                    debug!("Failed to send response to IPC client: {:?}", e);
                    break;
                }
            }
            Err(_) => {
                let resp = IpcResponse::Error {
                    message: "Daemon dropped response channel".to_string(),
                };
                let _ = framed.send(serde_json::to_string(&resp)?).await;
                break;
            }
        }
    }
    Ok(())
}

fn handle_ipc_request(
    request: IpcRequest,
    responder: oneshot::Sender<IpcResponse>,
    swarm: &mut Swarm<AppBehaviour>,
    local_peer_id: PeerId,
    daemon_service_name: &str,
    pending_searches: &mut HashMap<kad::QueryId, PendingSearch>,
) {
    match request {
        IpcRequest::Info => {
            let listen_addrs: Vec<String> = swarm.listeners().map(|a| a.to_string()).collect();
            let external_addrs: Vec<String> =
                swarm.external_addresses().map(|a| a.to_string()).collect();
            let num_peers = swarm.connected_peers().count();
            let kbucket_count: usize = swarm
                .behaviour_mut()
                .kademlia
                .kbuckets()
                .map(|b| b.num_entries())
                .sum();

            let info_json = serde_json::json!({
                "peer_id": local_peer_id.to_string(),
                "listen_addresses": listen_addrs,
                "external_addresses": external_addrs,
                "connected_peers_count": num_peers,
                "routing_table_entries": kbucket_count,
            });

            let _ = responder.send(IpcResponse::Success { data: info_json });
        }

        IpcRequest::Peers => {
            let peers: Vec<_> = swarm
                .connected_peers()
                .cloned()
                .collect::<Vec<_>>()
                .into_iter()
                .map(|p| {
                    let addrs =
                        get_kademlia_peer_addresses(&mut swarm.behaviour_mut().kademlia, &p);
                    let ip_addresses = extract_ip_addresses(&addrs);
                    serde_json::json!({
                        "peer_id": p.to_string(),
                        "ip_addresses": ip_addresses,
                        "addresses": addrs.iter().map(|a| a.to_string()).collect::<Vec<_>>(),
                    })
                })
                .collect();

            let _ = responder.send(IpcResponse::Success {
                data: serde_json::json!({ "peers": peers }),
            });
        }

        IpcRequest::Search {
            service_name,
            timeout_secs,
        } => {
            let (cid, mhash) = service_key::derive_service_multihash(&service_name);
            let record_key = kad::RecordKey::new(&mhash.to_bytes());

            // Collect known local providers and their addresses
            let mut initial_providers: HashMap<PeerId, HashSet<Multiaddr>> = HashMap::new();
            let stored_records: Vec<(PeerId, Vec<Multiaddr>)> = swarm
                .behaviour_mut()
                .kademlia
                .store_mut()
                .providers(&record_key)
                .into_iter()
                .map(|rec| (rec.provider, rec.addresses))
                .collect();

            for (provider, addresses) in stored_records {
                let mut addrs: HashSet<Multiaddr> = addresses.into_iter().collect();
                addrs.extend(get_kademlia_peer_addresses(
                    &mut swarm.behaviour_mut().kademlia,
                    &provider,
                ));
                initial_providers.insert(provider, addrs);
            }

            if service_name == daemon_service_name {
                let mut local_addrs: HashSet<Multiaddr> = swarm.listeners().cloned().collect();
                local_addrs.extend(swarm.external_addresses().cloned());
                initial_providers
                    .entry(local_peer_id)
                    .or_default()
                    .extend(local_addrs);
            }

            let query_id = swarm.behaviour_mut().kademlia.get_providers(record_key);

            info!(
                "Triggered DHT provider search for '{}' (CID: {}, QueryID: {:?}, known local: {})",
                service_name,
                cid,
                query_id,
                initial_providers.len()
            );

            let (search_tx, search_rx) = oneshot::channel::<Vec<DiscoveredProvider>>();
            let shared_providers = Arc::new(Mutex::new(initial_providers));
            pending_searches.insert(
                query_id,
                PendingSearch {
                    providers: shared_providers.clone(),
                    sender: search_tx,
                },
            );

            let timeout_duration = Duration::from_secs(timeout_secs.unwrap_or(30));
            let timeout_providers = shared_providers.clone();

            // Spawn timeout task to complete search if DHT query finishes or times out
            tokio::spawn(async move {
                let result = tokio::time::timeout(timeout_duration, search_rx).await;
                let response = match result {
                    Ok(Ok(providers)) => IpcResponse::Success {
                        data: serde_json::json!({
                            "service": service_name,
                            "cid": cid.to_string(),
                            "providers": providers
                        }),
                    },
                    Ok(Err(_)) => {
                        let providers = format_provider_results(&timeout_providers);
                        IpcResponse::Success {
                            data: serde_json::json!({
                                "service": service_name,
                                "cid": cid.to_string(),
                                "providers": providers
                            }),
                        }
                    }
                    Err(_) => {
                        let providers = format_provider_results(&timeout_providers);
                        if !providers.is_empty() {
                            IpcResponse::Success {
                                data: serde_json::json!({
                                    "service": service_name,
                                    "cid": cid.to_string(),
                                    "providers": providers,
                                    "timed_out": true
                                }),
                            }
                        } else {
                            IpcResponse::Error {
                                message: format!(
                                    "Search timed out after {}s while querying IPFS DHT",
                                    timeout_duration.as_secs()
                                ),
                            }
                        }
                    }
                };
                let _ = responder.send(response);
            });
        }
    }
}

/// Minimum number of distinct peers that must observe the same public external address
/// before the daemon accepts and advertises it.
const OBSERVED_ADDR_QUORUM_THRESHOLD: usize = 3;

#[allow(clippy::too_many_arguments)]
fn handle_swarm_event(
    event: libp2p::swarm::SwarmEvent<AppBehaviourEvent>,
    swarm: &mut Swarm<AppBehaviour>,
    pending_searches: &mut HashMap<kad::QueryId, PendingSearch>,
    peer_lookups: &mut HashMap<kad::QueryId, PeerId>,
    known_external_addrs: &mut HashSet<Multiaddr>,
    observed_candidates_quorum: &mut HashMap<Multiaddr, HashSet<PeerId>>,
    bootstrapped: &mut bool,
    record_key: &kad::RecordKey,
    service_name: &str,
    tcp_port: u16,
    quic_port: u16,
) {
    match event {
        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
            info!("Listening on multiaddress: {}", address);
        }
        libp2p::swarm::SwarmEvent::ExternalAddrConfirmed { address } => {
            if let Some(clean_addr) = normalize_observed_address(&address, tcp_port, quic_port) {
                if known_external_addrs.insert(clean_addr.clone()) {
                    info!("Confirmed external public address: {}", clean_addr);
                    swarm.add_external_address(clean_addr);
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .kademlia
                        .start_providing(record_key.clone())
                    {
                        debug!("Start providing on external address confirmation: {:?}", e);
                    }
                }
            }
        }
        libp2p::swarm::SwarmEvent::ExternalAddrExpired { address } => {
            if let Some(clean_addr) = normalize_observed_address(&address, tcp_port, quic_port) {
                known_external_addrs.remove(&clean_addr);
                swarm.remove_external_address(&clean_addr);
                info!("External public address expired: {}", clean_addr);
            }
        }
        libp2p::swarm::SwarmEvent::NewExternalAddrCandidate { address } => {
            debug!("New external address candidate: {}", address);
        }
        libp2p::swarm::SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            debug!(
                "Connection established with peer {} via {:?}",
                peer_id,
                endpoint.get_remote_address()
            );
        }
        libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            debug!("Outgoing connection error to {:?}: {:?}", peer_id, error);
        }
        libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            debug!("Connection closed with peer {}: {:?}", peer_id, cause);
        }
        libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Kademlia(kad_event)) => {
            handle_kademlia_event(
                kad_event,
                swarm,
                pending_searches,
                peer_lookups,
                record_key,
                service_name,
            );
        }
        libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Identify(
            identify::Event::Received { peer_id, info, .. },
        )) => {
            debug!(
                "Identify received from {}: agent='{}', protocols={:?}",
                peer_id, info.agent_version, info.protocols
            );

            // Normalize observed external address to verify public routability
            if let Some(clean_addr) =
                normalize_observed_address(&info.observed_addr, tcp_port, quic_port)
            {
                let voters = observed_candidates_quorum
                    .entry(clean_addr.clone())
                    .or_default();
                voters.insert(peer_id);
                let quorum_count = voters.len();

                if quorum_count >= OBSERVED_ADDR_QUORUM_THRESHOLD
                    && known_external_addrs.insert(clean_addr.clone())
                {
                    info!(
                        "External public address confirmed by quorum ({} distinct peers): {}",
                        quorum_count, clean_addr
                    );
                    swarm.add_external_address(clean_addr);
                    if let Err(e) = swarm
                        .behaviour_mut()
                        .kademlia
                        .start_providing(record_key.clone())
                    {
                        debug!(
                            "Start providing on quorum external address confirmation: {:?}",
                            e
                        );
                    }
                } else if quorum_count < OBSERVED_ADDR_QUORUM_THRESHOLD {
                    debug!(
                        "Observed candidate address {} seen by {}/{} peers",
                        clean_addr, quorum_count, OBSERVED_ADDR_QUORUM_THRESHOLD
                    );
                }
            }

            // Update any active search that is waiting for this peer's addresses
            update_pending_searches_for_peer(pending_searches, &peer_id, &info.listen_addrs);

            // Kademlia requires insertion of discovered peers into its routing table
            for addr in info.listen_addrs {
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
            }

            // Once we have identified a peer, trigger routing table bootstrap if not already started
            if !*bootstrapped {
                match swarm.behaviour_mut().kademlia.bootstrap() {
                    Ok(qid) => {
                        info!(
                            "Triggered Kademlia DHT routing table bootstrap (Query ID: {:?})",
                            qid
                        );
                        *bootstrapped = true;
                    }
                    Err(e) => {
                        debug!("Kademlia bootstrap trigger on identify info: {:?}", e);
                    }
                }
            }
        }
        libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Autonat(autonat_event)) => {
            match autonat_event {
                autonat::Event::StatusChanged { old, new } => {
                    info!("AutoNAT status changed from {:?} to {:?}", old, new);
                    if let autonat::NatStatus::Public(ref public_addr) = new {
                        if let Some(clean_addr) =
                            normalize_observed_address(public_addr, tcp_port, quic_port)
                        {
                            if known_external_addrs.insert(clean_addr.clone()) {
                                info!("AutoNAT confirmed public external address: {}", clean_addr);
                                swarm.add_external_address(clean_addr);
                                if let Err(e) = swarm
                                    .behaviour_mut()
                                    .kademlia
                                    .start_providing(record_key.clone())
                                {
                                    debug!("Start providing on AutoNAT confirmation: {:?}", e);
                                }
                            }
                        }
                    }
                }
                _ => {
                    debug!("AutoNAT event: {:?}", autonat_event);
                }
            }
        }
        libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Ping(ping_event)) => {
            debug!("Ping event: {:?}", ping_event);
        }
        _ => {}
    }
}

fn handle_kademlia_event(
    event: kad::Event,
    swarm: &mut Swarm<AppBehaviour>,
    pending_searches: &mut HashMap<kad::QueryId, PendingSearch>,
    peer_lookups: &mut HashMap<kad::QueryId, PeerId>,
    record_key: &kad::RecordKey,
    service_name: &str,
) {
    match event {
        kad::Event::OutboundQueryProgressed {
            id, result, step, ..
        } => {
            match result {
                kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                    providers,
                    ..
                })) => {
                    debug!("Found {} provider(s) for query {:?}", providers.len(), id);
                    if let Some(pending) = pending_searches.get(&id) {
                        let mut lock = match pending.providers.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        for p in providers {
                            let mut addrs: HashSet<Multiaddr> = get_kademlia_peer_addresses(
                                &mut swarm.behaviour_mut().kademlia,
                                &p,
                            )
                            .into_iter()
                            .collect();

                            // Also check stored provider records in local memory
                            for rec in swarm
                                .behaviour_mut()
                                .kademlia
                                .store_mut()
                                .providers(record_key)
                            {
                                if rec.provider == p {
                                    addrs.extend(rec.addresses);
                                }
                            }

                            // If we don't have addresses for this discovered peer, trigger a DHT lookup
                            if addrs.is_empty() {
                                let lookup_qid =
                                    swarm.behaviour_mut().kademlia.get_closest_peers(p);
                                peer_lookups.insert(lookup_qid, p);
                                debug!(
                                    "Triggered DHT peer address lookup for provider {} (Query ID: {:?})",
                                    p, lookup_qid
                                );
                                let _ = swarm.dial(p);
                            }

                            lock.entry(p).or_default().extend(addrs);
                        }
                    }
                }
                kad::QueryResult::GetProviders(Ok(
                    kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. },
                )) => {
                    debug!("DHT provider query {:?} finished searching records", id);
                }
                kad::QueryResult::GetProviders(Err(e)) => {
                    warn!("DHT provider query {:?} returned: {:?}", id, e);
                }
                kad::QueryResult::GetClosestPeers(Ok(kad::GetClosestPeersOk { key, peers })) => {
                    debug!(
                        "GetClosestPeers query {:?} completed for key with {} peers",
                        id,
                        peers.len()
                    );
                    if let Some(target_peer) = peer_lookups.remove(&id) {
                        let addrs = get_kademlia_peer_addresses(
                            &mut swarm.behaviour_mut().kademlia,
                            &target_peer,
                        );
                        update_pending_searches_for_peer(pending_searches, &target_peer, &addrs);
                    }
                    let _ = key;
                }
                kad::QueryResult::GetClosestPeers(Err(e)) => {
                    debug!("GetClosestPeers query {:?} returned error: {:?}", id, e);
                    peer_lookups.remove(&id);
                }
                kad::QueryResult::StartProviding(Ok(add_provider_ok)) => {
                    info!(
                        "Provider record announcement succeeded for key {}",
                        format_record_key(&add_provider_ok.key)
                    );
                }
                kad::QueryResult::StartProviding(Err(e)) => {
                    warn!("Provider record announcement query returned: {:?}", e);
                }
                kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk {
                    peer,
                    num_remaining,
                })) => {
                    debug!(
                        "Kademlia bootstrap progress: peer={}, remaining={}",
                        peer, num_remaining
                    );
                    if num_remaining == 0 {
                        info!(
                            "Kademlia routing table bootstrap complete! Re-announcing provider record for '{}'...",
                            service_name
                        );
                        if let Err(e) = swarm
                            .behaviour_mut()
                            .kademlia
                            .start_providing(record_key.clone())
                        {
                            debug!("Start providing on bootstrap completion: {:?}", e);
                        }
                    }
                }
                kad::QueryResult::Bootstrap(Err(e)) => {
                    debug!("Kademlia bootstrap query returned: {:?}", e);
                }
                _ => {}
            }

            if step.last {
                if let Some(pending) = pending_searches.remove(&id) {
                    let provider_list = format_provider_results(&pending.providers);
                    info!(
                        "DHT provider search query {:?} completed with {} providers",
                        id,
                        provider_list.len()
                    );
                    let _ = pending.sender.send(provider_list);
                }
            }
        }
        kad::Event::RoutingUpdated {
            peer, addresses, ..
        } => {
            let addrs: Vec<Multiaddr> = addresses.iter().cloned().collect();
            // Update active searches with newly discovered addresses
            update_pending_searches_for_peer(pending_searches, &peer, &addrs);
        }
        _ => {}
    }
}

fn update_pending_searches_for_peer(
    pending_searches: &HashMap<kad::QueryId, PendingSearch>,
    peer: &PeerId,
    new_addrs: &[Multiaddr],
) {
    if new_addrs.is_empty() || pending_searches.is_empty() {
        return;
    }
    pending_searches.values().for_each(|search| {
        let mut lock = search
            .providers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(peer_addrs) = lock.get_mut(peer) {
            peer_addrs.extend(new_addrs.iter().cloned());
        }
    });
}

fn format_provider_results(
    providers_ref: &Arc<Mutex<HashMap<PeerId, HashSet<Multiaddr>>>>,
) -> Vec<DiscoveredProvider> {
    let map = providers_ref
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let mut list: Vec<_> = map
        .iter()
        .map(|(peer, addrs_set)| {
            let mut addresses: Vec<String> = addrs_set.iter().map(|a| a.to_string()).collect();
            addresses.sort();
            DiscoveredProvider {
                peer_id: peer.to_string(),
                addresses,
            }
        })
        .collect();

    list.sort_by(|a, b| a.peer_id.cmp(&b.peer_id));
    list
}

fn get_kademlia_peer_addresses(
    kademlia: &mut kad::Behaviour<kad::store::MemoryStore>,
    peer: &PeerId,
) -> Vec<Multiaddr> {
    for bucket in kademlia.kbuckets() {
        for entry in bucket.iter() {
            if entry.node.key.preimage() == peer {
                return entry.node.value.clone().into_vec();
            }
        }
    }
    Vec::new()
}

fn format_record_key(key: &kad::RecordKey) -> String {
    let bytes = key.as_ref();
    if let Ok(mhash) = libp2p::multihash::Multihash::<64>::from_bytes(bytes) {
        let cid = cid::Cid::new_v1(0x55, mhash);
        format!("{}", cid)
    } else {
        bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc;

    #[tokio::test]
    async fn test_daemon_stress_and_resilience() {
        let temp_dir = std::env::temp_dir();
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let socket_path = temp_dir.join(format!("test_daemon_{}.sock", unique_id));
        let key_file = temp_dir.join(format!("test_daemon_{}.key", unique_id));

        let sock_clone = socket_path.clone();
        let key_clone = key_file.clone();
        let daemon_handle = tokio::spawn(async move {
            let res = run_daemon(
                0,
                0,
                sock_clone,
                "test-service".to_string(),
                3600,
                PathBuf::from("non_existent_bootstrap.txt"),
                vec![
                    "/ip4/127.0.0.1/tcp/49999/p2p/QmNnooDu7bfjPFoTmdxMNeaVQEBTbkV4Ddbdb415D9x5D4"
                        .to_string(),
                ],
                key_clone,
            )
            .await;
            if let Err(e) = res {
                eprintln!("run_daemon returned error: {:?}", e);
            }
        });

        // Wait for daemon socket to be created
        let mut ready = false;
        for _ in 0..100 {
            if socket_path.exists() {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(ready, "Daemon socket was not created in time");

        // 1. Send multiple sequential requests
        for i in 0..15 {
            let req = if i % 2 == 0 {
                IpcRequest::Info
            } else {
                IpcRequest::Peers
            };
            let resp = ipc::send_ipc_request(&socket_path, &req).await;
            assert!(
                resp.is_ok(),
                "Sequential request {} failed: {:?}",
                i,
                resp.err()
            );
        }

        // 2. Send invalid JSON over raw socket, ensure daemon survives
        {
            let stream = UnixStream::connect(&socket_path).await.unwrap();
            let mut framed = Framed::new(stream, LinesCodec::new());
            framed.send("NOT_JSON_DATA".to_string()).await.unwrap();
            drop(framed);
        }

        // 3. Connect and immediately close socket without sending anything (aborted connection)
        for _ in 0..5 {
            let stream = UnixStream::connect(&socket_path).await.unwrap();
            drop(stream);
        }

        // 4. Send concurrent requests from multiple tasks
        let mut handles = Vec::new();
        for i in 0..25 {
            let sock = socket_path.clone();
            let handle = tokio::spawn(async move {
                let req = if i % 2 == 0 {
                    IpcRequest::Info
                } else {
                    IpcRequest::Peers
                };
                ipc::send_ipc_request(&sock, &req).await
            });
            handles.push(handle);
        }

        for (i, h) in handles.into_iter().enumerate() {
            let res = h.await.unwrap();
            assert!(
                res.is_ok(),
                "Concurrent request {} failed: {:?}",
                i,
                res.err()
            );
        }

        // 5. Ensure daemon is still responsive after all stress/errors
        for i in 0..5 {
            let resp = ipc::send_ipc_request(&socket_path, &IpcRequest::Info).await;
            assert!(
                resp.is_ok(),
                "Post-stress request {} failed: {:?}",
                i,
                resp.err()
            );
        }

        daemon_handle.abort();
        let _ = std::fs::remove_file(&socket_path);
        let _ = std::fs::remove_file(&key_file);
    }
}
