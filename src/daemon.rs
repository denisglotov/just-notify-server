use crate::behaviour::{AppBehaviour, AppBehaviourEvent};
use crate::ipc::{IpcRequest, IpcResponse};
use crate::service_key;

use anyhow::Context;
use futures::{SinkExt, StreamExt};
use libp2p::{autonat, identify, identity, kad, ping, Multiaddr, PeerId, Swarm, SwarmBuilder};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::codec::{Framed, LinesCodec};
use tracing::{debug, error, info, warn};

use crate::service_key::extract_peer_id;

struct PendingSearch {
    providers: HashSet<PeerId>,
    sender: oneshot::Sender<Vec<String>>,
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

fn load_bootstrap_nodes(file_path: &std::path::Path) -> anyhow::Result<Vec<String>> {
    if !file_path.exists() {
        anyhow::bail!(
            "Bootstrap nodes file does not exist at '{}'. Please create the file or specify a valid path using --bootstrap-nodes-file <PATH>",
            file_path.display()
        );
    }

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

    if nodes.is_empty() {
        anyhow::bail!(
            "Bootstrap nodes file at '{}' contains no valid multiaddresses",
            file_path.display()
        );
    }

    info!(
        "Loaded {} bootstrap node(s) from {}",
        nodes.len(),
        file_path.display()
    );
    Ok(nodes)
}

pub async fn run_daemon(
    tcp_port: u16,
    quic_port: u16,
    socket_path: PathBuf,
    service_name: String,
    reannounce_interval_secs: u64,
    bootstrap_nodes_file: PathBuf,
) -> anyhow::Result<()> {
    info!("Starting IPFS libp2p server daemon...");

    // Generate identity keypair
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    info!("Local Peer ID: {}", local_peer_id);

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
            let mut kademlia = kad::Behaviour::new(peer_id, store);
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

    // Listen on TCP multiaddress
    let tcp_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", tcp_port).parse()?;
    swarm.listen_on(tcp_addr.clone())?;
    info!("Listening for P2P TCP connections on {}", tcp_addr);

    // Listen on QUIC multiaddress
    let quic_addr: Multiaddr = format!("/ip4/0.0.0.0/udp/{}/quic-v1", quic_port).parse()?;
    swarm.listen_on(quic_addr.clone())?;
    info!("Listening for P2P QUIC connections on {}", quic_addr);

    let bootstrap_addrs = load_bootstrap_nodes(&bootstrap_nodes_file)?;
    info!("Bootstrapping into public IPFS network...");
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
                    info!("Dialing IPFS bootstrap node: {}", addr);
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

    // Register service provider record ("dymka-just-notify")
    let (service_cid, service_mhash) = service_key::derive_service_multihash(&service_name);
    let record_key = kad::RecordKey::new(&service_mhash.to_bytes());
    info!(
        "Registering provider record for service '{}' (CID: {}) on IPFS DHT",
        service_name, service_cid
    );

    match swarm
        .behaviour_mut()
        .kademlia
        .start_providing(record_key.clone())
    {
        Ok(query_id) => info!(
            "Started providing service '{}' (Query ID: {:?})",
            service_name, query_id
        ),
        Err(e) => error!("Failed to start providing service: {:?}", e),
    }

    // Setup periodic re-announcement timer
    let mut reannounce_timer = tokio::time::interval(Duration::from_secs(reannounce_interval_secs));
    reannounce_timer.reset();

    // Clean up existing UDS socket file if present
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
    let (ipc_tx, mut ipc_rx) = mpsc::channel::<DaemonEvent>(32);

    // Spawn task to accept UDS IPC connections
    tokio::spawn(async move {
        loop {
            match ipc_listener.accept().await {
                Ok((stream, _)) => {
                    let ipc_tx = ipc_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_ipc_connection(stream, ipc_tx).await {
                            debug!("IPC connection ended: {:?}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Error accepting IPC connection: {:?}", e);
                    break;
                }
            }
        }
    });

    let mut pending_searches: HashMap<kad::QueryId, PendingSearch> = HashMap::new();

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

            // Periodic service re-announcement
            _ = reannounce_timer.tick() => {
                info!("Re-announcing service '{}' provider record to IPFS DHT", service_name);
                if let Err(e) = swarm.behaviour_mut().kademlia.start_providing(record_key.clone()) {
                    error!("Re-announcement failed: {:?}", e);
                }
            }

            // IPC commands from client
            Some(event) = ipc_rx.recv() => {
                match event {
                    DaemonEvent::Ipc { request, responder } => {
                        handle_ipc_request(
                            request,
                            responder,
                            &mut swarm,
                            local_peer_id,
                            &mut pending_searches,
                        );
                    }
                }
            }

            // Swarm events
            event = swarm.select_next_some() => {
                handle_swarm_event(event, &mut swarm, &mut pending_searches);
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
    let mut framed = Framed::new(stream, LinesCodec::new());

    while let Some(line_res) = framed.next().await {
        let line = line_res?;
        let request: IpcRequest = serde_json::from_str(&line)?;

        let (resp_tx, resp_rx) = oneshot::channel();
        ipc_tx
            .send(DaemonEvent::Ipc {
                request,
                responder: resp_tx,
            })
            .await?;

        if let Ok(response) = resp_rx.await {
            let json_resp = serde_json::to_string(&response)?;
            framed.send(json_resp).await?;
        }
    }
    Ok(())
}

fn handle_ipc_request(
    request: IpcRequest,
    responder: oneshot::Sender<IpcResponse>,
    swarm: &mut Swarm<AppBehaviour>,
    local_peer_id: PeerId,
    pending_searches: &mut HashMap<kad::QueryId, PendingSearch>,
) {
    match request {
        IpcRequest::Info => {
            let listen_addrs: Vec<String> = swarm.listeners().map(|a| a.to_string()).collect();
            let num_peers = swarm.connected_peers().count();
            let mut kbucket_count = 0;
            for bucket in swarm.behaviour_mut().kademlia.kbuckets() {
                kbucket_count += bucket.num_entries();
            }

            let info_json = serde_json::json!({
                "peer_id": local_peer_id.to_string(),
                "listen_addresses": listen_addrs,
                "connected_peers_count": num_peers,
                "routing_table_entries": kbucket_count,
            });

            let _ = responder.send(IpcResponse::Success { data: info_json });
        }

        IpcRequest::Peers => {
            let peers: Vec<serde_json::Value> = swarm
                .connected_peers()
                .map(|p| serde_json::json!({ "peer_id": p.to_string() }))
                .collect();

            let _ = responder.send(IpcResponse::Success {
                data: serde_json::json!({ "peers": peers }),
            });
        }

        IpcRequest::Search { service_name } => {
            let (cid, mhash) = service_key::derive_service_multihash(&service_name);
            let record_key = kad::RecordKey::new(&mhash.to_bytes());
            let query_id = swarm.behaviour_mut().kademlia.get_providers(record_key);

            info!(
                "Triggered DHT provider search for '{}' (CID: {}, QueryID: {:?})",
                service_name, cid, query_id
            );

            let (search_tx, search_rx) = oneshot::channel::<Vec<String>>();
            pending_searches.insert(
                query_id,
                PendingSearch {
                    providers: HashSet::new(),
                    sender: search_tx,
                },
            );

            // Spawn timeout task to complete search if DHT query finishes or times out in 8 seconds
            tokio::spawn(async move {
                let result = tokio::time::timeout(Duration::from_secs(8), search_rx).await;
                let response = match result {
                    Ok(Ok(providers)) => IpcResponse::Success {
                        data: serde_json::json!({
                            "service": service_name,
                            "cid": cid.to_string(),
                            "providers": providers
                        }),
                    },
                    Ok(Err(_)) => IpcResponse::Error {
                        message: "Search cancelled".to_string(),
                    },
                    Err(_) => IpcResponse::Error {
                        message: "Search timed out while querying IPFS DHT".to_string(),
                    },
                };
                let _ = responder.send(response);
            });
        }
    }
}

fn handle_swarm_event(
    event: libp2p::swarm::SwarmEvent<AppBehaviourEvent>,
    swarm: &mut Swarm<AppBehaviour>,
    pending_searches: &mut HashMap<kad::QueryId, PendingSearch>,
) {
    match event {
        libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
            info!("Listening on multiaddress: {}", address);
        }
        libp2p::swarm::SwarmEvent::ConnectionEstablished {
            peer_id, endpoint, ..
        } => {
            info!(
                "Connection established with peer {} via {:?}",
                peer_id,
                endpoint.get_remote_address()
            );
        }
        libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            info!("Outgoing connection error to {:?}: {:?}", peer_id, error);
        }
        libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
            debug!("Connection closed with peer {}: {:?}", peer_id, cause);
        }
        libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Kademlia(kad_event)) => {
            handle_kademlia_event(kad_event, pending_searches);
        }
        libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Identify(
            identify::Event::Received { peer_id, info, .. },
        )) => {
            debug!(
                "Identify received from {}: agent='{}', protocols={:?}",
                peer_id, info.agent_version, info.protocols
            );
            // Kademlia requires manual insertion of discovered peers into its routing table
            for addr in info.listen_addrs {
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
            }
        }
        libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Autonat(autonat_event)) => {
            debug!("AutoNAT event: {:?}", autonat_event);
        }
        libp2p::swarm::SwarmEvent::Behaviour(AppBehaviourEvent::Ping(ping_event)) => {
            debug!("Ping event: {:?}", ping_event);
        }
        _ => {}
    }
}

fn handle_kademlia_event(
    event: kad::Event,
    pending_searches: &mut HashMap<kad::QueryId, PendingSearch>,
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
                    info!("Found {} provider(s) for query {:?}", providers.len(), id);
                    if let Some(pending) = pending_searches.get_mut(&id) {
                        for p in providers {
                            pending.providers.insert(p);
                        }
                    }
                }
                kad::QueryResult::GetProviders(Err(e)) => {
                    warn!("DHT provider query {:?} returned error: {:?}", id, e);
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
                _ => {}
            }

            if step.last {
                if let Some(pending) = pending_searches.remove(&id) {
                    info!("DHT provider search query {:?} completed", id);
                    let provider_list: Vec<String> = pending
                        .providers
                        .into_iter()
                        .map(|p| p.to_string())
                        .collect();
                    let _ = pending.sender.send(provider_list);
                }
            }
        }
        kad::Event::RoutingUpdated {
            peer,
            is_new_peer: true,
            ..
        } => {
            debug!("Kademlia routing table added new peer {}", peer);
        }
        _ => {}
    }
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
