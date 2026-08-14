use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LinesCodec};

use crate::cli::Commands;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum IpcRequest {
    Search {
        service_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_secs: Option<u64>,
    },
    Peers,
    Info,
}

impl TryFrom<Commands> for IpcRequest {
    type Error = Commands;

    fn try_from(cmd: Commands) -> Result<Self, Self::Error> {
        match cmd {
            Commands::Search {
                service_name,
                timeout,
            } => Ok(IpcRequest::Search {
                service_name,
                timeout_secs: Some(timeout),
            }),
            Commands::Peers => Ok(IpcRequest::Peers),
            Commands::Info => Ok(IpcRequest::Info),
            daemon @ Commands::Daemon(..) => Err(daemon),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum IpcResponse {
    Success { data: serde_json::Value },
    Error { message: String },
}

pub const MAX_IPC_FRAME_LENGTH: usize = 1024 * 1024;

/// Connects to daemon UDS socket, sends a request, and returns the response.
pub async fn send_ipc_request(
    socket_path: &Path,
    request: &IpcRequest,
) -> anyhow::Result<IpcResponse> {
    let stream = match UnixStream::connect(socket_path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            anyhow::bail!(
                "Connection refused at '{}'. Is the daemon running? Start it with: 'just-notify-server daemon'",
                socket_path.display()
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "Daemon socket does not exist at '{}'. Please start the daemon first with: 'just-notify-server daemon'",
                socket_path.display()
            );
        }
        Err(e) => return Err(e.into()),
    };
    let mut framed = Framed::new(
        stream,
        LinesCodec::new_with_max_length(MAX_IPC_FRAME_LENGTH),
    );

    let json_req = serde_json::to_string(request)?;
    framed.send(json_req).await?;

    if let Some(res) = framed.next().await {
        let line = res?;
        let response: IpcResponse = serde_json::from_str(&line)?;
        Ok(response)
    } else {
        anyhow::bail!("Connection closed by daemon before response was received")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies JSON wire protocol serialization and deserialization for IPC search queries.
    ///
    /// - Guards against wire protocol regressions between the CLI client and the background daemon.
    /// - Ensures backward compatibility with legacy clients that omit optional fields like `timeout_secs`,
    ///   confirming they default to `None` without parsing errors.
    #[test]
    fn test_ipc_request_search_serde() {
        let req_with_timeout = IpcRequest::Search {
            service_name: "test-service".to_string(),
            timeout_secs: Some(45),
        };
        let serialized = serde_json::to_string(&req_with_timeout).unwrap();
        let deserialized: IpcRequest = serde_json::from_str(&serialized).unwrap();
        match deserialized {
            IpcRequest::Search {
                service_name,
                timeout_secs,
            } => {
                assert_eq!(service_name, "test-service");
                assert_eq!(timeout_secs, Some(45));
            }
            _ => panic!("Expected Search variant"),
        }

        // Backward compatibility: deserializing without timeout_secs
        let json_str = r#"{"type":"Search","payload":{"service_name":"test-service"}}"#;
        let legacy: IpcRequest = serde_json::from_str(json_str).unwrap();
        match legacy {
            IpcRequest::Search {
                service_name,
                timeout_secs,
            } => {
                assert_eq!(service_name, "test-service");
                assert_eq!(timeout_secs, None);
            }
            _ => panic!("Expected Search variant"),
        }
    }

    /// Verifies translation from CLI command enum variants into IPC request payloads.
    ///
    /// - Ensures CLI subcommands (`search`, `peers`, `info`) are correctly transformed into their
    ///   matching IPC network messages with appropriate parameter passing (e.g. search timeout).
    /// - Prevents accidental dispatch of daemon-only commands across IPC.
    #[test]
    fn test_ipc_request_from_commands() {
        let search_cmd = Commands::Search {
            service_name: "test-srv".to_string(),
            timeout: 15,
        };
        let req = IpcRequest::try_from(search_cmd).unwrap();
        assert!(matches!(
            req,
            IpcRequest::Search {
                service_name,
                timeout_secs: Some(15),
            } if service_name == "test-srv"
        ));

        let peers_req = IpcRequest::try_from(Commands::Peers).unwrap();
        assert!(matches!(peers_req, IpcRequest::Peers));

        let info_req = IpcRequest::try_from(Commands::Info).unwrap();
        assert!(matches!(info_req, IpcRequest::Info));
    }
}
