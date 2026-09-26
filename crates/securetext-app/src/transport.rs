//! Where raw byte streams come from. The node only needs two things from a
//! network: "dial this onion address" and "here are incoming connections".
//! Hiding them behind [`Transport`] lets the whole application (MLS,
//! Noise, yamux, the peer protocol, the offline queue) run over an
//! in-memory network in tests, with Tor swapped in for real use. The
//! Noise handshake and everything above it runs identically either way;
//! only the bottom layer changes.

use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use futures::future::BoxFuture;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

/// The single logical port SecureText's peer protocol listens on.
pub const PEER_PORT: u16 = 1;

pub trait RawStream: AsyncRead + AsyncWrite + Unpin + Send + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + 'static> RawStream for T {}

pub type BoxedStream = Box<dyn RawStream>;

pub trait Transport: Send + Sync + 'static {
    fn dial<'a>(&'a self, onion_address: &'a str) -> BoxFuture<'a, anyhow::Result<BoxedStream>>;
}

/// A bound listener: our own address plus the stream of incoming
/// connections to it. `_guard` keeps whatever resources back the listener
/// (the running onion service, or an in-memory registration) alive for as
/// long as the node holds this.
pub struct Listening {
    pub onion_address: String,
    pub incoming: mpsc::UnboundedReceiver<BoxedStream>,
    pub _guard: Box<dyn Send + Sync>,
}

/// Real transport: arti. Every connection is to or from a v3 onion
/// service; there is no code path here that can open a clearnet socket
/// (threat-model.md's mandatory-anonymity requirement).
pub struct TorTransport {
    client: securetext_net::Client,
}

impl TorTransport {
    pub fn new(client: securetext_net::Client) -> Self {
        Self { client }
    }

    /// Launch this identity's onion service and forward accepted streams.
    /// The service key lives in arti's keystore under the client's state
    /// directory, so with a persistent state directory the address stays
    /// the same across restarts (what keeps old invite links working).
    pub fn listen(&self, nickname: &str) -> anyhow::Result<Listening> {
        let mut listener = securetext_net::Listener::launch(&self.client, nickname)?;
        let onion_address = listener.onion_address()?;
        let (tx, rx) = mpsc::unbounded_channel();
        let accept_task = tokio::spawn(async move {
            loop {
                match listener.accept_next().await {
                    Ok(Some(stream)) => {
                        if tx.send(Box::new(stream) as BoxedStream).is_err() {
                            break;
                        }
                    }
                    Ok(None) => break,
                    // One failed rendezvous shouldn't take the service down.
                    Err(e) => eprintln!("[securetext] incoming connection failed: {e}"),
                }
            }
        });
        Ok(Listening {
            onion_address,
            incoming: rx,
            _guard: Box::new(AbortOnDrop(accept_task)),
        })
    }
}

impl Transport for TorTransport {
    fn dial<'a>(&'a self, onion_address: &'a str) -> BoxFuture<'a, anyhow::Result<BoxedStream>> {
        Box::pin(async move {
            let stream = securetext_net::dial(&self.client, onion_address, PEER_PORT).await?;
            Ok(Box::new(stream) as BoxedStream)
        })
    }
}

struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// An in-process stand-in for the Tor network, for tests: named
/// "addresses" backed by in-memory pipes. Nodes can be taken offline to
/// exercise the offline-delivery paths.
#[derive(Clone, Default)]
pub struct MemoryNetwork {
    inner: Arc<Mutex<MemoryInner>>,
}

#[derive(Default)]
struct MemoryInner {
    listeners: HashMap<String, mpsc::UnboundedSender<BoxedStream>>,
    unreachable: HashSet<String>,
    /// Per address: once set, that address's existing connections go
    /// silent (see [`MemoryNetwork::vanish`]).
    vanished: HashMap<String, Arc<AtomicBool>>,
}

impl MemoryNetwork {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn listen(&self, address: &str) -> Listening {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut inner = self.inner.lock().unwrap();
        inner.listeners.insert(address.to_string(), tx);
        inner.vanished.insert(address.to_string(), Arc::new(AtomicBool::new(false)));
        drop(inner);
        Listening {
            onion_address: address.to_string(),
            incoming: rx,
            _guard: Box::new(()),
        }
    }

    /// Make `address` refuse new connections (existing ones are
    /// unaffected; shut the node down to drop those).
    pub fn set_reachable(&self, address: &str, reachable: bool) {
        let mut inner = self.inner.lock().unwrap();
        if reachable {
            inner.unreachable.remove(address);
        } else {
            inner.unreachable.insert(address.to_string());
        }
    }

    /// Simulate `address` dropping off the network without closing
    /// anything: its open connections stop delivering in both directions
    /// while still accepting writes (what a crashed or suspended peer's Tor
    /// stream looks like from the other end), and new dials fail.
    pub fn vanish(&self, address: &str) {
        let mut inner = self.inner.lock().unwrap();
        inner.unreachable.insert(address.to_string());
        if let Some(flag) = inner.vanished.get(address) {
            flag.store(true, Ordering::SeqCst);
        }
    }

    /// A dialer for the node listening at `own_address` (relays and other
    /// dial-only users can pass any name). Knowing both ends lets
    /// [`Self::vanish`] silence a connection whichever side opened it.
    pub fn transport(&self, own_address: &str) -> Arc<dyn Transport> {
        Arc::new(MemoryDialer { network: self.clone(), own_address: own_address.to_string() })
    }

    fn flag(inner: &MemoryInner, address: &str) -> Arc<AtomicBool> {
        inner.vanished.get(address).cloned().unwrap_or_default()
    }
}

struct MemoryDialer {
    network: MemoryNetwork,
    own_address: String,
}

impl Transport for MemoryDialer {
    fn dial<'a>(&'a self, onion_address: &'a str) -> BoxFuture<'a, anyhow::Result<BoxedStream>> {
        Box::pin(async move {
            let inner = self.network.inner.lock().unwrap();
            anyhow::ensure!(!inner.unreachable.contains(onion_address), "{onion_address} is unreachable");
            let listener = inner
                .listeners
                .get(onion_address)
                .ok_or_else(|| anyhow::anyhow!("no such address: {onion_address}"))?;
            let flags = [MemoryNetwork::flag(&inner, onion_address), MemoryNetwork::flag(&inner, &self.own_address)];
            let (ours, theirs) = tokio::io::duplex(256 * 1024);
            listener
                .send(Box::new(Silenceable { inner: theirs, silenced: flags.clone() }))
                .map_err(|_| anyhow::anyhow!("{onion_address} is not accepting connections"))?;
            Ok(Box::new(Silenceable { inner: ours, silenced: flags }) as BoxedStream)
        })
    }
}

/// An in-memory stream that can be made to go silent: reads never
/// complete and writes are discarded, without either end seeing a close.
struct Silenceable<S> {
    inner: S,
    /// Silenced if either endpoint has vanished.
    silenced: [Arc<AtomicBool>; 2],
}

impl<S> Silenceable<S> {
    fn is_silenced(&self) -> bool {
        self.silenced.iter().any(|f| f.load(Ordering::SeqCst))
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Silenceable<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        if self.is_silenced() {
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Silenceable<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<std::io::Result<usize>> {
        if self.is_silenced() {
            return Poll::Ready(Ok(data.len()));
        }
        Pin::new(&mut self.inner).poll_write(cx, data)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        if self.is_silenced() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
