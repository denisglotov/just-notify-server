use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::time::Duration;

use crate::daemon::DaemonConfig;

pub const DEFAULT_SOCKET_PATH: &str = "/tmp/just-notify-server.sock";
pub const DEFAULT_SERVICE_NAME: &str = "org.dymka.just-notify-server";
pub const DEFAULT_BOOTSTRAP_FILE: &str = "bootstrap_nodes.txt";
pub const DEFAULT_KEY_FILE: &str = "node.key";
pub const DEFAULT_TCP_PORT: u16 = 4001;
pub const DEFAULT_QUIC_PORT: u16 = 4001;
pub const DEFAULT_REANNOUNCE_INTERVAL_SECS: u64 = 1800;
pub const DEFAULT_SEARCH_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_MAX_ESTABLISHED_CONNS: u32 = 500;
pub const DEFAULT_MAX_ESTABLISHED_PER_PEER: u32 = 3;
pub const DEFAULT_MAX_PENDING_INCOMING_CONNS: u32 = 64;
pub const DEFAULT_MAX_PENDING_OUTGOING_CONNS: u32 = 64;
pub const DEFAULT_MAX_PROVIDED_KEYS: usize = 65_536;
pub const DEFAULT_IDLE_CONNECTION_TIMEOUT_SECS: u64 = 300;

#[derive(Parser, Debug)]
#[command(name = "just-notify-server")]
#[command(about = "IPFS-compatible libp2p server daemon and control CLI", long_about = None)]
pub struct Cli {
    /// Tracing log level filter (e.g. info, debug, warn, trace, error)
    #[arg(long, global = true, default_value = "info")]
    pub log_level: String,

    /// Path to Unix Domain Socket for local IPC control
    #[arg(long, global = true, default_value = DEFAULT_SOCKET_PATH)]
    pub socket_path: PathBuf,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Args, Debug, Clone, PartialEq, Eq)]
pub struct DaemonArgs {
    /// TCP listening port
    #[arg(long, default_value_t = DEFAULT_TCP_PORT)]
    pub tcp_port: u16,

    /// QUIC listening port (UDP)
    #[arg(long, default_value_t = DEFAULT_QUIC_PORT)]
    pub quic_port: u16,

    /// Service name to automatically register on IPFS mainnet DHT
    #[arg(long, default_value = DEFAULT_SERVICE_NAME)]
    pub service_name: String,

    /// Interval in seconds to re-announce service provider record to DHT
    #[arg(long, default_value_t = DEFAULT_REANNOUNCE_INTERVAL_SECS)]
    pub reannounce_interval: u64,

    /// Path to text file containing bootstrap multiaddresses (one per line)
    #[arg(long, default_value = DEFAULT_BOOTSTRAP_FILE)]
    pub bootstrap_nodes_file: PathBuf,

    /// Additional bootstrap multiaddress(es) or direct peer(s)
    #[arg(long = "bootstrap-node", action = clap::ArgAction::Append)]
    pub bootstrap_nodes: Vec<String>,

    /// Path to ed25519 identity key file to persist node Peer ID across restarts
    #[arg(long, default_value = DEFAULT_KEY_FILE)]
    pub key_file: PathBuf,

    /// Maximum total established peer connections
    #[arg(long, default_value_t = DEFAULT_MAX_ESTABLISHED_CONNS)]
    pub max_connections: u32,

    /// Maximum established connections per individual peer
    #[arg(long, default_value_t = DEFAULT_MAX_ESTABLISHED_PER_PEER)]
    pub max_connections_per_peer: u32,

    /// Maximum pending incoming connections
    #[arg(long, default_value_t = DEFAULT_MAX_PENDING_INCOMING_CONNS)]
    pub max_pending_incoming_connections: u32,

    /// Maximum pending outgoing connections
    #[arg(long, default_value_t = DEFAULT_MAX_PENDING_OUTGOING_CONNS)]
    pub max_pending_outgoing_connections: u32,

    /// Maximum number of provider keys stored in memory DHT store
    #[arg(long, default_value_t = DEFAULT_MAX_PROVIDED_KEYS)]
    pub max_provided_keys: usize,

    /// Idle connection timeout in seconds before closing inactive connections
    #[arg(long, default_value_t = DEFAULT_IDLE_CONNECTION_TIMEOUT_SECS)]
    pub idle_connection_timeout: u64,
}

impl DaemonArgs {
    pub fn into_config(self, socket_path: PathBuf) -> DaemonConfig {
        DaemonConfig {
            tcp_port: self.tcp_port,
            quic_port: self.quic_port,
            socket_path,
            service_name: self.service_name,
            reannounce_interval: Duration::from_secs(self.reannounce_interval),
            bootstrap_nodes_file: self.bootstrap_nodes_file,
            cli_bootstrap_nodes: self.bootstrap_nodes,
            key_file: self.key_file,
            max_connections: self.max_connections,
            max_connections_per_peer: self.max_connections_per_peer,
            max_pending_incoming_connections: self.max_pending_incoming_connections,
            max_pending_outgoing_connections: self.max_pending_outgoing_connections,
            max_provided_keys: self.max_provided_keys,
            idle_connection_timeout: Duration::from_secs(self.idle_connection_timeout),
        }
    }
}

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Commands {
    /// Start the libp2p IPFS server daemon
    Daemon(DaemonArgs),

    /// Search IPFS mainnet DHT for providers of a service or CID
    Search {
        /// Target service name or CID to search for
        #[arg(default_value = DEFAULT_SERVICE_NAME)]
        service_name: String,

        /// Search timeout in seconds
        #[arg(long, default_value_t = DEFAULT_SEARCH_TIMEOUT_SECS)]
        timeout: u64,
    },

    /// Query connected peers from the running daemon
    Peers,

    /// Query node identity and routing table status from the daemon
    Info,
}
