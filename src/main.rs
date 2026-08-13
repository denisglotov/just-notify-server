mod behaviour;
mod cli;
mod daemon;
mod ipc;
mod service_key;

use clap::Parser;
use cli::{Cli, Commands};
use ipc::{send_ipc_request, IpcRequest, IpcResponse};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon {
            tcp_port,
            quic_port,
            socket_path,
            service_name,
            reannounce_interval,
            bootstrap_nodes_file,
            log_level,
        } => {
            let filter = EnvFilter::builder()
                .with_default_directive(
                    log_level
                        .parse::<LevelFilter>()
                        .unwrap_or(LevelFilter::INFO)
                        .into(),
                )
                .from_env_lossy();

            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_target(false)
                .init();

            daemon::run_daemon(
                tcp_port,
                quic_port,
                socket_path,
                service_name,
                reannounce_interval,
                bootstrap_nodes_file,
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
