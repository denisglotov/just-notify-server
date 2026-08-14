use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LinesCodec};

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum IpcResponse {
    Success { data: serde_json::Value },
    Error { message: String },
}

/// Connects to daemon UDS socket, sends a request, and returns the response.
pub async fn send_ipc_request(
    socket_path: &Path,
    request: &IpcRequest,
) -> anyhow::Result<IpcResponse> {
    if !socket_path.exists() {
        anyhow::bail!(
            "Daemon socket does not exist at '{}'. Please start the daemon first with: 'just-notify-server daemon'",
            socket_path.display()
        );
    }

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
    let mut framed = Framed::new(stream, LinesCodec::new_with_max_length(1024 * 1024));

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
}
