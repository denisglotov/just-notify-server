use clap::{Parser, Subcommand};
use std::path::PathBuf;

pub const DEFAULT_SOCKET_PATH: &str = "/tmp/just-notify-server.sock";
pub const DEFAULT_SERVICE_NAME: &str = "org.dymka.just-notify-server";
pub const DEFAULT_BOOTSTRAP_FILE: &str = "bootstrap_nodes.txt";
pub const DEFAULT_KEY_FILE: &str = "node.key";
pub const DEFAULT_TCP_PORT: u16 = 4001;
pub const DEFAULT_QUIC_PORT: u16 = 4001;
pub const DEFAULT_REANNOUNCE_INTERVAL_SECS: u64 = 1800;
pub const DEFAULT_SEARCH_TIMEOUT_SECS: u64 = 30;

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

#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum Commands {
    /// Start the libp2p IPFS server daemon
    Daemon {
        /// TCP listening port
        #[arg(long, default_value_t = DEFAULT_TCP_PORT)]
        tcp_port: u16,

        /// QUIC listening port (UDP)
        #[arg(long, default_value_t = DEFAULT_QUIC_PORT)]
        quic_port: u16,

        /// Service name to automatically register on IPFS mainnet DHT
        #[arg(long, default_value = DEFAULT_SERVICE_NAME)]
        service_name: String,

        /// Interval in seconds to re-announce service provider record to DHT
        #[arg(long, default_value_t = DEFAULT_REANNOUNCE_INTERVAL_SECS)]
        reannounce_interval: u64,

        /// Path to text file containing bootstrap multiaddresses (one per line)
        #[arg(long, default_value = DEFAULT_BOOTSTRAP_FILE)]
        bootstrap_nodes_file: PathBuf,

        /// Additional bootstrap multiaddress(es) or direct peer(s)
        #[arg(long = "bootstrap-node", action = clap::ArgAction::Append)]
        bootstrap_nodes: Vec<String>,

        /// Path to ed25519 identity key file to persist node Peer ID across restarts
        #[arg(long, default_value = DEFAULT_KEY_FILE)]
        key_file: PathBuf,
    },

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
