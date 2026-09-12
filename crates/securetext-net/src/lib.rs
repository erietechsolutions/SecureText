//! Tor v3 onion-service transport (architecture.md §1). Every peer listens
//! only on its own onion service; there is no direct-IP fallback for
//! text/group/file traffic (threat-model.md's mandatory anonymity goal).
//!
//! Bootstrapping onto the live Tor network requires real outbound
//! connectivity to Tor relays, which may not be available in every build/CI
//! sandbox (see the note in the crate's tests). The API here is written
//! against arti's documented, production-ready onion-service client and
//! service support; live end-to-end verification against the real Tor
//! network should be done on an unrestricted machine as part of Phase 1's
//! exit criteria, not assumed from a passing compile.

use std::sync::Arc;

use arti_client::{config::onion_service::OnionServiceConfigBuilder, TorClient, TorClientConfig};
pub use arti_client::DataStream;
use futures::StreamExt;
use tor_hsservice::{HsNickname, RunningOnionService};
use tor_rtcompat::PreferredRuntime;

#[derive(thiserror::Error, Debug)]
pub enum NetError {
    #[error("tor client error: {0}")]
    Tor(#[from] arti_client::Error),
    #[error("onion service config error: {0}")]
    Config(String),
    #[error("onion service launch failed: {0}")]
    Launch(String),
    #[error("stream accept/reject error: {0}")]
    Stream(String),
    #[error("this onion service has no address yet")]
    NoAddress,
}

pub type Client = Arc<TorClient<PreferredRuntime>>;

/// Bootstrap a Tor client using arti's default state/cache locations
/// (platform-appropriate app-data directories — platform-support.md). This
/// performs real network activity (fetching consensus/descriptor documents
/// from the Tor network) and can take from a few seconds up to significantly
/// longer depending on network conditions — see architecture.md §6 on the
/// accepted latency tradeoff.
///
/// Arti enforces that its state directory has a trustworthy owner
/// (correct, security-conscious behavior — not something to relax). On a
/// real user machine this just works; in a sandboxed dev environment where
/// `$HOME`'s ancestor directories have unusual ownership, this call will
/// fail with a filesystem-permissions error. Use
/// [`bootstrap_with_dirs`] pointed at a directory with a clean ownership
/// chain in that case (see `crates/securetext-net`'s tests and
/// tech-stack.md's implementation findings).
pub async fn bootstrap() -> Result<Client, NetError> {
    let config = TorClientConfig::default();
    let client = TorClient::create_bootstrapped(config).await?;
    Ok(client)
}

/// Bootstrap a Tor client using explicit state/cache directories instead of
/// arti's platform default. See [`bootstrap`] for when you'd want this.
pub async fn bootstrap_with_dirs(
    state_dir: &std::path::Path,
    cache_dir: &std::path::Path,
) -> Result<Client, NetError> {
    let config = arti_client::config::TorClientConfigBuilder::from_directories(state_dir, cache_dir)
        .build()
        .map_err(|e| NetError::Config(format!("{e:?}")))?;
    let client = TorClient::create_bootstrapped(config).await?;
    Ok(client)
}

/// A running onion service plus the stream of incoming client connections.
pub struct Listener {
    pub service: Arc<RunningOnionService>,
    incoming: std::pin::Pin<Box<dyn futures::Stream<Item = tor_hsservice::StreamRequest> + Send>>,
}

impl Listener {
    /// Launch an onion service identified locally by `nickname` (this is
    /// not sent over the network; it's just how this node refers to its own
    /// service key on disk).
    pub fn launch(client: &Client, nickname: &str) -> Result<Self, NetError> {
        let nickname = HsNickname::try_from(nickname.to_string())
            .map_err(|e| NetError::Config(format!("{e:?}")))?;
        let config = OnionServiceConfigBuilder::default()
            .nickname(nickname)
            .enabled(true)
            .build()
            .map_err(|e| NetError::Config(format!("{e:?}")))?;

        let (service, rend_requests) = client
            .launch_onion_service(config)
            .map_err(|e| NetError::Launch(format!("{e:?}")))?
            .ok_or_else(|| NetError::Launch("onion service disabled in config".into()))?;

        let incoming = Box::pin(tor_hsservice::handle_rend_requests(rend_requests));

        Ok(Self { service, incoming })
    }

    /// The onion address other peers dial to reach this service
    /// (architecture.md §2 — this is the entire reachability model, no IP
    /// ever changes hands).
    pub fn onion_address(&self) -> Result<String, NetError> {
        use safelog::DisplayRedacted;
        self.service
            .onion_address()
            .map(|addr| addr.display_unredacted().to_string())
            .ok_or(NetError::NoAddress)
    }

    /// Accept the next incoming stream from a client, sending the
    /// `CONNECTED` acknowledgement. Returns a bidirectional
    /// `AsyncRead + AsyncWrite` stream, exactly like the client-dial side
    /// (`dial` below) — the two sides of the transport are symmetric once
    /// a connection is established.
    pub async fn accept_next(&mut self) -> Result<Option<DataStream>, NetError> {
        let Some(stream_request) = self.incoming.next().await else {
            return Ok(None);
        };
        let onion_service_stream = stream_request
            .accept(tor_cell::relaycell::msg::Connected::new_empty())
            .await
            .map_err(|e| NetError::Stream(format!("{e:?}")))?;
        Ok(Some(onion_service_stream))
    }
}

/// Dial another peer's onion address (from an invite link — architecture.md
/// §2). `port` is a logical port distinguishing services on the same onion
/// address if ever needed; SecureText uses a single fixed port for its
/// protocol.
pub async fn dial(client: &Client, onion_address: &str, port: u16) -> Result<DataStream, NetError> {
    let stream = client.connect((onion_address, port)).await?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// This test requires real, unrestricted internet access to the Tor
    /// network and is skipped by default in sandboxed/CI environments where
    /// that isn't available (Tor bootstrap needs direct TCP to Tor relays
    /// on arbitrary ports, which many sandboxes block even when ordinary
    /// HTTPS egress works). Run explicitly with:
    ///   cargo test -p securetext-net --ignored -- --nocapture
    /// on a machine known to have unrestricted outbound connectivity.
    #[ignore]
    #[tokio::test]
    async fn bootstrap_and_launch_onion_service_live() {
        // A sandboxed dev environment may have unusual ownership on `$HOME`'s
        // ancestor directories, which trips arti's (correct, and not to be
        // relaxed in production) fs-mistrust ownership check on its default
        // state/cache dirs. Point at a scratch directory instead of
        // bypassing the check — see tech-stack.md's open items.
        let scratch = tempfile::tempdir().expect("scratch dir for arti state/cache");
        let config = arti_client::config::TorClientConfigBuilder::from_directories(
            scratch.path().join("state"),
            scratch.path().join("cache"),
        )
        .build()
        .expect("build tor client config");
        let client = TorClient::create_bootstrapped(config)
            .await
            .expect("bootstrap onto the Tor network");
        let listener = Listener::launch(&client, "securetext-test").expect("launch onion service");
        let address = listener.onion_address().expect("onion address assigned");
        eprintln!("onion service address: {address}");
        assert!(address.ends_with(".onion"));
    }

    fn scratch_config() -> arti_client::TorClientConfig {
        let scratch = tempfile::tempdir().expect("scratch dir for arti state/cache");
        // Leak intentionally: the dir must outlive this config for the
        // duration of the test process; cleaned up when the OS temp dir is
        // next swept, same as any other test tempdir would be.
        let path = scratch.keep();
        arti_client::config::TorClientConfigBuilder::from_directories(
            path.join("state"),
            path.join("cache"),
        )
        .build()
        .expect("build tor client config")
    }

    /// The actual Phase 1 exit-criteria proof: two independent Tor clients,
    /// standing in for two peers' devices, exchange bytes with one side
    /// only ever knowing the other's `.onion` address — never an IP.
    #[ignore]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn two_peer_round_trip_over_onion_service_live() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        eprintln!("bootstrapping listener side...");
        let listener_client = TorClient::create_bootstrapped(scratch_config())
            .await
            .expect("bootstrap listener client");
        let mut listener = Listener::launch(&listener_client, "securetext-rt-test")
            .expect("launch onion service");
        let address = listener.onion_address().expect("onion address");
        eprintln!("listening on {address}");

        eprintln!("bootstrapping dialer side...");
        let dialer_client = TorClient::create_bootstrapped(scratch_config())
            .await
            .expect("bootstrap dialer client");

        let accept_task = tokio::spawn(async move {
            let mut stream = listener
                .accept_next()
                .await
                .expect("accept incoming stream")
                .expect("stream present");
            let mut buf = [0u8; 64];
            let n = stream.read(&mut buf).await.expect("read from dialer");
            stream
                .write_all(&buf[..n])
                .await
                .expect("echo back to dialer");
            stream.flush().await.expect("flush echo to dialer");
            stream.shutdown().await.expect("shutdown after echo");
            // A successful shutdown().await means our local buffer was
            // handed off, not that the remote side has necessarily
            // received it yet -- delivery across a live multi-hop Tor
            // circuit takes real wall-clock time. Dropping `stream`
            // immediately after risks the circuit being reclaimed before
            // that delivery completes, which is exactly what caused this
            // test to flake with `NotConnected` on the dialer's read side.
            // See tech-stack.md's implementation findings.
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            buf[..n].to_vec()
        });

        // Give the onion service a moment to publish its descriptor before
        // the dialer tries to reach it.
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;

        let mut dial_stream = dial(&dialer_client, &address, 1). // architecture.md §2: SecureText uses a fixed logical port
            await
            .expect("dial listener's onion address");
        dial_stream
            .write_all(b"hello over tor")
            .await
            .expect("write to listener");
        // DataStream buffers internally -- without flushing, the listener's
        // read() blocks forever waiting for bytes that never leave the
        // local buffer. See tech-stack.md's implementation findings.
        dial_stream.flush().await.expect("flush to listener");

        let mut echo_buf = [0u8; 64];
        let n = dial_stream
            .read(&mut echo_buf)
            .await
            .expect("read echo from listener");

        let received_by_listener = accept_task.await.expect("accept task");
        assert_eq!(received_by_listener, b"hello over tor");
        assert_eq!(&echo_buf[..n], b"hello over tor");
        eprintln!("round trip over onion services succeeded, both directions verified");
    }
}
