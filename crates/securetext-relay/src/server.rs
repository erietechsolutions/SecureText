//! Serving one relay connection: Noise_XX (the relay proves it holds the
//! key in its address; the client's static key is a throwaway), then a
//! yamux stream carrying request/response frames.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use securetext_net::{MuxMode, SecureMux};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::{read_json, write_json, Request, Response, RelayStore, MAX_REQUEST_FRAME};

/// A client gets this long per request before the connection is dropped,
/// so idle or stalled connections can't pile up.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

/// Serve one client until it disconnects. Returns the Noise static key
/// the client presented, which a well-behaved client generates fresh per
/// connection. It's returned only so tests can check that; the relay
/// itself never records it.
pub async fn serve_connection<S>(mut stream: S, noise_private: &[u8], store: Arc<Mutex<RelayStore>>) -> anyhow::Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (noise, client_key) = tokio::time::timeout(
        REQUEST_TIMEOUT,
        securetext_net::handshake_responder(&mut stream, noise_private),
    )
    .await??;
    let mut mux = SecureMux::new(stream, noise, MuxMode::Server);
    let mut request_stream = tokio::time::timeout(REQUEST_TIMEOUT, mux.accept())
        .await?
        .ok_or_else(|| anyhow::anyhow!("client opened no stream"))?;

    loop {
        let request = match tokio::time::timeout(
            REQUEST_TIMEOUT,
            read_json::<_, Request>(&mut request_stream, MAX_REQUEST_FRAME),
        )
        .await
        {
            Ok(Ok(Some(request))) => request,
            _ => break,
        };
        let response = handle(&store, request);
        write_json(&mut request_stream, &response).await?;
    }
    let _ = mux.close().await;
    Ok(client_key)
}

pub fn handle(store: &Arc<Mutex<RelayStore>>, request: Request) -> Response {
    let store = store.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let result = match request {
        Request::Deposit { mailbox, blob } => store.deposit(&mailbox, &blob, now_secs()).map(|r| match r {
            Ok(()) => Response::Deposited,
            Err(e) => Response::Error { reason: e.to_string() },
        }),
        Request::Fetch { secret, limit } => store.fetch(&secret, limit).map(|items| Response::Blobs { items }),
        Request::Ack { secret, ids } => store.ack(&secret, &ids).map(|removed| Response::Acked { removed }),
    };
    result.unwrap_or_else(|e| {
        eprintln!("[securetext-relay] storage error: {e:#}");
        Response::Error { reason: "internal error".into() }
    })
}

pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
