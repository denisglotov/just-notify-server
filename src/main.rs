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

    match cli.command {
        Commands::Daemon {
            tcp_port,
            quic_port,
            socket_path,
            service_name,
            reannounce_interval,
            bootstrap_nodes_file,
            bootstrap_nodes,
            key_file,
        } => {
            daemon::run_daemon(
                tcp_port,
                quic_port,
                socket_path,
                service_name,
                reannounce_interval,
                bootstrap_nodes_file,
                bootstrap_nodes,
                key_file,
            )
            .await?;
        }

        Commands::Search {
            service_name,
            socket_path,
            timeout,
        } => {
            println!(
                "Querying daemon at {} for service '{}' (timeout: {}s)...",
                socket_path.display(),
                service_name,
                timeout
            );
            let req = IpcRequest::Search {
                service_name,
                timeout_secs: Some(timeout),
            };
            handle_ipc_result(send_ipc_request(&socket_path, &req).await);
        }

        Commands::Peers { socket_path } => {
            let req = IpcRequest::Peers;
            handle_ipc_result(send_ipc_request(&socket_path, &req).await);
        }

        Commands::Info { socket_path } => {
            let req = IpcRequest::Info;
            handle_ipc_result(send_ipc_request(&socket_path, &req).await);
        }
    }

    Ok(())
}

fn handle_ipc_result(result: anyhow::Result<IpcResponse>) {
    match result {
        Ok(IpcResponse::Success { data }) => {
            if let Ok(json) = serde_json::to_string_pretty(&data) {
                println!("{}", json);
            }
        }
        Ok(IpcResponse::Error { message }) => {
            eprintln!("Daemon returned error: {}", message);
        }
        Err(e) => {
            eprintln!("IPC Error: {}", e);
            std::process::exit(1);
        }
    }
}
