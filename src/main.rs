mod behaviour;
mod cli;
mod daemon;
mod ipc;
mod service_key;

use crate::cli::{Cli, Commands};
use crate::ipc::{send_ipc_request, IpcRequest, IpcResponse};
use anyhow::Context;
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
        Commands::Daemon(args) => {
            daemon::run_daemon(args.into_config(socket_path)).await?;
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
            match send_ipc_request(&socket_path, &req).await? {
                IpcResponse::Success { data } => {
                    let json = serde_json::to_string_pretty(&data)
                        .context("Failed to format response JSON")?;
                    println!("{}", json);
                }
                IpcResponse::Error { message } => {
                    anyhow::bail!("Daemon returned error: {}", message);
                }
            }
        }
    }

    Ok(())
}
