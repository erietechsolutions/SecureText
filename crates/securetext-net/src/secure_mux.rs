//! Multiplexes multiple logical streams over one Noise-encrypted
//! onion-service connection (architecture.md §6): avoids paying Tor
//! circuit-build latency per logical stream (e.g. one per channel) by
//! reusing a single established connection for several concurrent streams.
//!
//! Two layers compose here:
//!
//! 1. A background "pump" task turns the raw onion-service `DataStream`
//!    plus an already-established [`NoiseTransport`] into a plain, already
//!    -secure byte pipe (a `tokio::io::duplex`) -- chunking outgoing bytes
//!    into bounded Noise messages and reassembling incoming ones. yamux has
//!    no cryptography of its own, so it needs something that already looks
//!    like a secure ordinary stream.
//! 2. [`SecureMux`] drives a `yamux::Connection` over that pipe. Yamux's
//!    `Connection` can only make progress while `poll_next_inbound` is
//!    being polled -- true even for purely outbound stream I/O, confirmed
//!    against `rust-libp2p`'s own yamux muxer (the primary real-world
//!    consumer of this exact crate, since the crate itself ships no
//!    end-to-end usage example). `SecureMux` runs that polling in a
//!    dedicated background task and exposes a plain async `open`/`accept`
//!    API over channels instead, so callers don't need to know about that
//!    requirement.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use crate::noise::NoiseTransport;
use crate::NetError;

/// Largest plaintext chunk the pump task will encrypt as a single Noise
/// message. Comfortably under Noise's own ~65535-byte message limit, with
/// room for the AEAD tag.
const MAX_PLAINTEXT_CHUNK: usize = 32 * 1024;

/// One multiplexed logical stream, readable/writable via the ordinary
/// tokio `AsyncRead`/`AsyncWrite` ecosystem the rest of this codebase uses.
pub type MuxStream = tokio_util::compat::Compat<yamux::Stream>;

/// A multiplexed, Noise-encrypted connection over a Tor onion-service
/// stream. Construct with [`SecureMux::new`] after completing the Noise
/// handshake (see `noise::handshake_initiator`/`handshake_responder`).
pub struct SecureMux {
    open_tx: mpsc::UnboundedSender<oneshot::Sender<Result<yamux::Stream, NetError>>>,
    close_tx: mpsc::UnboundedSender<oneshot::Sender<()>>,
    inbound_rx: mpsc::UnboundedReceiver<yamux::Stream>,
    driver: tokio::task::JoinHandle<()>,
}

enum DriverCommand {
    Open(oneshot::Sender<Result<yamux::Stream, NetError>>),
    Close(oneshot::Sender<()>),
}

impl SecureMux {
    /// `mode` must be [`yamux::Mode::Client`] on the side that dialed
    /// (Noise initiator) and [`yamux::Mode::Server`] on the side that
    /// accepted the connection (Noise responder) -- yamux's stream-ID
    /// allocation scheme depends on the two ends agreeing on this.
    pub fn new<S>(raw_stream: S, noise: NoiseTransport, mode: yamux::Mode) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let pipe_end = spawn_noise_pump(raw_stream, noise);
        let mut connection = yamux::Connection::new(pipe_end.compat(), yamux::Config::default(), mode);

        let (open_tx, mut open_rx) =
            mpsc::unbounded_channel::<oneshot::Sender<Result<yamux::Stream, NetError>>>();
        let (close_tx, mut close_rx) = mpsc::unbounded_channel::<oneshot::Sender<()>>();
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();

        let driver = tokio::spawn(async move {
            loop {
                let command = tokio::select! {
                    reply_opt = open_rx.recv() => reply_opt.map(DriverCommand::Open),
                    close_opt = close_rx.recv() => close_opt.map(DriverCommand::Close),
                    inbound = std::future::poll_fn(|cx| connection.poll_next_inbound(cx)) => {
                        match inbound {
                            Some(Ok(stream)) => {
                                if inbound_tx.send(stream).is_err() {
                                    break; // no one left to accept
                                }
                                continue;
                            }
                            _ => break, // connection closed or errored
                        }
                    }
                };

                match command {
                    Some(DriverCommand::Open(reply)) => {
                        let result = std::future::poll_fn(|cx| connection.poll_new_outbound(cx))
                            .await
                            .map_err(|e| NetError::Mux(format!("{e:?}")));
                        let _ = reply.send(result);
                    }
                    Some(DriverCommand::Close(reply)) => {
                        // Drive an orderly close: flushes/settles the
                        // underlying connection (and, transitively, the
                        // pump task's writes to the raw stream) before
                        // this task ends, rather than aborting mid-flight
                        // (see `close()`'s doc comment for why that
                        // matters -- the same lesson as everywhere else in
                        // this crate about flush not implying delivery).
                        let _ = std::future::poll_fn(|cx| connection.poll_close(cx)).await;
                        let _ = reply.send(());
                        break;
                    }
                    None => break, // no SecureMux handle left; nothing more to drive
                }
            }
        });

        Self {
            open_tx,
            close_tx,
            inbound_rx,
            driver,
        }
    }

    /// Open a new outbound logical stream.
    pub async fn open(&self) -> Result<MuxStream, NetError> {
        let (tx, rx) = oneshot::channel();
        self.open_tx
            .send(tx)
            .map_err(|_| NetError::Mux("mux driver task has stopped".into()))?;
        let stream = rx
            .await
            .map_err(|_| NetError::Mux("mux driver task has stopped".into()))??;
        Ok(stream.compat())
    }

    /// Accept the next inbound logical stream opened by the peer. Returns
    /// `None` once the underlying connection has closed.
    pub async fn accept(&mut self) -> Option<MuxStream> {
        self.inbound_rx.recv().await.map(|s| s.compat())
    }

    /// Orderly shutdown: waits for the underlying yamux connection to
    /// settle (buffered writes on any still-open logical stream actually
    /// reach the Noise pump and get sent) before returning. **Call this
    /// before dropping a `SecureMux` whenever you've just written to a
    /// stream you care about the peer receiving** -- plain `drop` aborts
    /// the driver task immediately, which can cut off data that was
    /// flushed locally but hadn't yet propagated through the pump to the
    /// raw onion-service stream. This is the same category of race as
    /// `DataStream`'s buffering (tech-stack.md's implementation findings),
    /// one layer up.
    pub async fn close(&mut self) -> Result<(), NetError> {
        let (tx, rx) = oneshot::channel();
        if self.close_tx.send(tx).is_err() {
            return Ok(()); // driver already gone; nothing to close
        }
        let _ = rx.await;
        Ok(())
    }
}

impl Drop for SecureMux {
    fn drop(&mut self) {
        // Best-effort: if `close()` wasn't called, don't leak the driver
        // task, but this is abrupt -- see `close()`'s doc comment.
        self.driver.abort();
    }
}

fn spawn_noise_pump<S>(mut raw_stream: S, mut noise: NoiseTransport) -> tokio::io::DuplexStream
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (app_side, mut pump_side) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut read_buf = vec![0u8; MAX_PLAINTEXT_CHUNK];
        loop {
            tokio::select! {
                n = pump_side.read(&mut read_buf) => {
                    let n = match n {
                        Ok(0) | Err(_) => break, // app (yamux) side closed
                        Ok(n) => n,
                    };
                    let Ok(ciphertext) = noise.encrypt(&read_buf[..n]) else { break };
                    if write_length_prefixed(&mut raw_stream, &ciphertext).await.is_err() {
                        break;
                    }
                }
                frame = read_length_prefixed(&mut raw_stream) => {
                    let Ok(ciphertext) = frame else { break };
                    let Ok(plaintext) = noise.decrypt(&ciphertext) else { break };
                    if pump_side.write_all(&plaintext).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    app_side
}

async fn write_length_prefixed<S: AsyncWrite + Unpin>(stream: &mut S, payload: &[u8]) -> std::io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(std::io::Error::other)?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    // Same lesson as everywhere else in this crate: an explicit flush is
    // required, or bytes sit in DataStream's internal buffer forever.
    stream.flush().await
}

async fn read_length_prefixed<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Local-only correctness proof: two `SecureMux`es over an in-memory
    /// duplex pipe (standing in for the Noise-encrypted onion-service
    /// stream) open/accept multiple concurrent logical streams and
    /// exchange data on each correctly, with no live Tor network needed.
    #[tokio::test]
    async fn multiple_streams_over_one_connection() {
        let (client_raw, server_raw) = tokio::io::duplex(1 << 20);

        let client_keys = snow::Builder::new(crate::noise::NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();
        let server_keys = snow::Builder::new(crate::noise::NOISE_PATTERN.parse().unwrap())
            .generate_keypair()
            .unwrap();

        let mut client_raw = client_raw;
        let mut server_raw = server_raw;
        let (client_noise, server_noise) = tokio::join!(
            crate::noise::handshake_initiator(&mut client_raw, &client_keys.private),
            crate::noise::handshake_responder(&mut server_raw, &server_keys.private)
        );
        let (client_noise, _) = client_noise.expect("client handshake");
        let (server_noise, _) = server_noise.expect("server handshake");

        let client_mux = SecureMux::new(client_raw, client_noise, yamux::Mode::Client);
        let mut server_mux = SecureMux::new(server_raw, server_noise, yamux::Mode::Server);

        let server_task = tokio::spawn(async move {
            for _ in 0..3 {
                let mut stream = server_mux.accept().await.expect("accept stream");
                let mut buf = vec![0u8; 64];
                let n = stream.read(&mut buf).await.expect("read");
                stream.write_all(&buf[..n]).await.expect("echo");
                stream.flush().await.expect("flush echo");
            }
            // Without this, dropping server_mux aborts its driver task
            // immediately, which can (and, before this fix, reliably did)
            // cut off the last echo before it fully propagated through
            // the Noise pump to the client -- see `close()`'s doc comment.
            server_mux.close().await.expect("close server mux");
        });

        // Open three concurrent logical streams over the one connection
        // and prove each carries its own, independent data correctly.
        for i in 0..3 {
            let mut stream = client_mux.open().await.expect("open stream");
            let msg = format!("message on stream {i}");
            stream.write_all(msg.as_bytes()).await.expect("write");
            stream.flush().await.expect("flush");

            let mut buf = vec![0u8; 64];
            let n = stream.read(&mut buf).await.expect("read echo");
            assert_eq!(&buf[..n], msg.as_bytes());
        }

        server_task.await.expect("server task");
    }
}
