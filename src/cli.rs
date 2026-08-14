use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "just-notify-server")]
#[command(about = "IPFS-compatible libp2p server daemon and control CLI", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Start the libp2p IPFS server daemon
    Daemon {
        /// TCP listening port
        #[arg(long, default_value_t = 4001)]
        tcp_port: u16,

        /// QUIC listening port (UDP)
        #[arg(long, default_value_t = 4001)]
        quic_port: u16,

        /// Path to Unix Domain Socket for local IPC control
        #[arg(long, default_value = "/tmp/just-notify-server.sock")]
        socket_path: PathBuf,

        /// Service name to automatically register on IPFS mainnet DHT
        #[arg(long, default_value = "org.dymka.just-notify-server")]
        service_name: String,

        /// Interval in seconds to re-announce service provider record to DHT
        #[arg(long, default_value_t = 1800)]
        reannounce_interval: u64,

        /// Path to text file containing bootstrap multiaddresses (one per line)
        #[arg(long, default_value = "bootstrap_nodes.txt")]
        bootstrap_nodes_file: PathBuf,

        /// Additional bootstrap multiaddress(es) or direct peer(s)
        #[arg(long = "bootstrap-node", action = clap::ArgAction::Append)]
        bootstrap_nodes: Vec<String>,

        /// Path to ed25519 identity key file to persist node Peer ID across restarts
        #[arg(long, default_value = "node.key")]
        key_file: PathBuf,

        /// Tracing log level filter (e.g. info, debug, warn, trace)
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// Search IPFS mainnet DHT for providers of a service or CID
    Search {
        /// Target service name or CID to search for
        #[arg(default_value = "org.dymka.just-notify-server")]
        service_name: String,

        /// Path to daemon Unix Domain Socket
        #[arg(long, default_value = "/tmp/just-notify-server.sock")]
        socket_path: PathBuf,

        /// Search timeout in seconds
        #[arg(long, default_value_t = 30)]
        timeout: u64,
    },

    /// Query connected peers from the running daemon
    Peers {
        /// Path to daemon Unix Domain Socket
        #[arg(long, default_value = "/tmp/just-notify-server.sock")]
        socket_path: PathBuf,
    },

    /// Query node identity and routing table status from the daemon
    Info {
        /// Path to daemon Unix Domain Socket
        #[arg(long, default_value = "/tmp/just-notify-server.sock")]
        socket_path: PathBuf,
    },
}
