mod behaviour;
mod cli;
mod daemon;
mod ipc;
mod service_key;

use crate::cli::{Cli, Commands};
use crate::ipc::{send_ipc_request, IpcRequest, IpcResponse};
use clap::Parser;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::builder().parse_lossy(&cli.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();

    let socket_path = cli.socket_path;

    match cli.command {
        Commands::Daemon {
            tcp_port,
            quic_port,
            service_name,
            reannounce_interval,
            bootstrap_nodes_file,
            bootstrap_nodes,
            key_file,
            max_connections,
            max_connections_per_peer,
            max_pending_incoming_connections,
            max_pending_outgoing_connections,
            max_provided_keys,
        } => {
            let config = daemon::DaemonConfig {
                tcp_port,
                quic_port,
                socket_path,
                service_name,
                reannounce_interval: std::time::Duration::from_secs(reannounce_interval),
                bootstrap_nodes_file,
                cli_bootstrap_nodes: bootstrap_nodes,
                key_file,
                max_connections,
                max_connections_per_peer,
                max_pending_incoming_connections,
                max_pending_outgoing_connections,
                max_provided_keys,
            };
            daemon::run_daemon(config).await?;
        }

        cmd => {
            if let Commands::Search {
                ref service_name,
                timeout,
            } = cmd
            {
                println!(
                    "Querying daemon at {} for service '{}' (timeout: {}s)...",
                    socket_path.display(),
                    service_name,
                    timeout
                );
            }
            let req = IpcRequest::try_from(cmd).expect("Non-daemon commands convert to IpcRequest");
            handle_ipc_result(send_ipc_request(&socket_path, &req).await);
        }
    }

    Ok(())
}

fn handle_ipc_result(result: anyhow::Result<IpcResponse>) {
    match result {
        Ok(IpcResponse::Success { data }) => match serde_json::to_string_pretty(&data) {
            Ok(json) => println!("{}", json),
            Err(e) => {
                eprintln!("Failed to format response JSON: {}", e);
                std::process::exit(1);
            }
        },
        Ok(IpcResponse::Error { message }) => {
            eprintln!("Daemon returned error: {}", message);
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("IPC Error: {}", e);
            std::process::exit(1);
        }
    }
}
