use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LinesCodec};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum IpcRequest {
    Search { service_name: String },
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
            "Daemon socket does not exist at '{}'. Please start the daemon first with: 'ipfs-server daemon'",
            socket_path.display()
        );
    }

    let stream = match UnixStream::connect(socket_path).await {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
            anyhow::bail!(
                "Connection refused at '{}'. Is the daemon running? Start it with: 'ipfs-server daemon'",
                socket_path.display()
            );
        }
        Err(e) => return Err(e.into()),
    };
    let mut framed = Framed::new(stream, LinesCodec::new());

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
