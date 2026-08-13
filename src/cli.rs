use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "ipfs-server")]
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
        #[arg(long, default_value = "/tmp/ipfs-server.sock")]
        socket_path: PathBuf,

        /// Service name to automatically register on IPFS mainnet DHT
        #[arg(long, default_value = "dymka-just-notify")]
        service_name: String,

        /// Interval in seconds to re-announce service provider record to DHT
        #[arg(long, default_value_t = 1800)]
        reannounce_interval: u64,

        /// Path to text file containing bootstrap multiaddresses (one per line)
        #[arg(long, default_value = "bootstrap_nodes.txt")]
        bootstrap_nodes_file: PathBuf,

        /// Tracing log level filter (e.g. info, debug, warn, trace)
        #[arg(long, default_value = "info")]
        log_level: String,
    },

    /// Search IPFS mainnet DHT for providers of a service or CID
    Search {
        /// Target service name or CID to search for (defaults to "dymka-just-notify")
        #[arg(default_value = "dymka-just-notify")]
        service_name: String,

        /// Path to daemon Unix Domain Socket
        #[arg(long, default_value = "/tmp/ipfs-server.sock")]
        socket_path: PathBuf,
    },

    /// Query connected peers from the running daemon
    Peers {
        /// Path to daemon Unix Domain Socket
        #[arg(long, default_value = "/tmp/ipfs-server.sock")]
        socket_path: PathBuf,
    },

    /// Query node identity and routing table status from the daemon
    Info {
        /// Path to daemon Unix Domain Socket
        #[arg(long, default_value = "/tmp/ipfs-server.sock")]
        socket_path: PathBuf,
    },
}
