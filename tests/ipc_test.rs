use futures::SinkExt;
use std::path::PathBuf;
use std::time::Duration;
use tokio::net::UnixStream;
use tokio_util::codec::{Framed, LinesCodec};

use just_notify_server::daemon;
use just_notify_server::ipc::{self, IpcRequest};

#[tokio::test]
async fn test_daemon_stress_and_resilience() {
    let socket_path = PathBuf::from("./target/test_daemon_resilience.sock");
    let key_file = PathBuf::from("./target/test_daemon_resilience.key");
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }
    if key_file.exists() {
        let _ = std::fs::remove_file(&key_file);
    }

    let sock_clone = socket_path.clone();
    let key_clone = key_file.clone();
    let daemon_handle = tokio::spawn(async move {
        let res = daemon::run_daemon(
            29003,
            29003,
            sock_clone,
            "test-service".to_string(),
            3600,
            PathBuf::from("./bootstrap_nodes.txt"),
            vec![],
            key_clone,
        )
        .await;
        if let Err(e) = res {
            eprintln!("run_daemon returned error: {:?}", e);
        }
    });

    // Wait for daemon socket to be created
    let mut ready = false;
    for _ in 0..100 {
        if socket_path.exists() {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(ready, "Daemon socket was not created in time");

    // 1. Send multiple sequential requests
    for i in 0..15 {
        let req = if i % 2 == 0 {
            IpcRequest::Info
        } else {
            IpcRequest::Peers
        };
        let resp = ipc::send_ipc_request(&socket_path, &req).await;
        assert!(
            resp.is_ok(),
            "Sequential request {} failed: {:?}",
            i,
            resp.err()
        );
    }

    // 2. Send invalid JSON over raw socket, ensure daemon survives
    {
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        let mut framed = Framed::new(stream, LinesCodec::new());
        framed.send("NOT_JSON_DATA".to_string()).await.unwrap();
        // Disconnect immediately
        drop(framed);
    }

    // 3. Connect and immediately close socket without sending anything (aborted connection)
    for _ in 0..5 {
        let stream = UnixStream::connect(&socket_path).await.unwrap();
        drop(stream);
    }

    // 4. Send concurrent requests from multiple tasks
    let mut handles = Vec::new();
    for i in 0..25 {
        let sock = socket_path.clone();
        let handle = tokio::spawn(async move {
            let req = if i % 2 == 0 {
                IpcRequest::Info
            } else {
                IpcRequest::Peers
            };
            ipc::send_ipc_request(&sock, &req).await
        });
        handles.push(handle);
    }

    for (i, h) in handles.into_iter().enumerate() {
        let res = h.await.unwrap();
        assert!(
            res.is_ok(),
            "Concurrent request {} failed: {:?}",
            i,
            res.err()
        );
    }

    // 5. Ensure daemon is still responsive after all stress/errors
    for i in 0..5 {
        let resp = ipc::send_ipc_request(&socket_path, &IpcRequest::Info).await;
        assert!(
            resp.is_ok(),
            "Post-stress request {} failed: {:?}",
            i,
            resp.err()
        );
    }

    daemon_handle.abort();
    let _ = std::fs::remove_file(&socket_path);
    let _ = std::fs::remove_file(&key_file);
}
