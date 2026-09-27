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

#![forbid(unsafe_code)]

use std::sync::Arc;

use arti_client::{config::onion_service::OnionServiceConfigBuilder, TorClient, TorClientConfig};
pub use arti_client::DataStream;
use futures::StreamExt;
use tor_hsservice::{HsNickname, RunningOnionService};
use tor_rtcompat::PreferredRuntime;

mod noise;
pub use noise::{handshake_initiator, handshake_responder, NoiseTransport, NOISE_PATTERN};

mod secure_mux;
pub use secure_mux::{MuxStream, SecureMux};
pub use yamux::Mode as MuxMode;

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
    #[error("noise handshake/transport error: {0}")]
    Noise(String),
    #[error("stream multiplexing error: {0}")]
    Mux(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
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

/// An obfs4 bridge to route around Tor being blocked or throttled
/// (architecture.md §5, threat-model.md's mandatory-anonymity requirement
/// -- the app must stay usable where Tor itself is blocked, not just where
/// it isn't). `bridge_line` is a standard Tor bridge line, the same format
/// Tor Browser uses (`Bridge obfs4 <ip>:<port> <fingerprint> cert=... iat-mode=...`),
/// typically obtained from Tor's own bridge distribution channels.
/// `obfs4proxy_path` is the path to the `obfs4proxy` (or `lyrebird`)
/// binary, which arti launches itself (`run_on_startup`) rather than
/// requiring you to run it separately.
pub struct BridgeConfig {
    pub bridge_line: String,
    pub obfs4proxy_path: std::path::PathBuf,
}

/// Bootstrap a Tor client through an obfs4 bridge instead of connecting to
/// the Tor network directly -- see [`BridgeConfig`].
///
/// **Verification note:** this is built against arti's own real example
/// (`arti-client/examples/snowflake.rs` -- the crate ships no obfs4-specific
/// example, so the snowflake one, which uses the identical
/// `BridgeConfigBuilder`/`TransportConfigBuilder` API, was used as the
/// verified reference) and exercised by this crate's local config-only
/// test. **What it has not been verified against is an actual live,
/// currently-provisioned obfs4 bridge or `obfs4proxy` binary** -- neither
/// was available in this development sandbox (no Go toolchain to build
/// `obfs4proxy` from source, and standing up a real bridge relay to test
/// against is its own separate undertaking). This is the same category of
/// gap as the Windows cross-platform verification in `roadmap.md`: the
/// code is written against the real, verified API, but a genuine
/// end-to-end censorship-circumvention test still needs to be run by
/// someone with an `obfs4proxy` binary and a real bridge line.
pub async fn bootstrap_with_bridge(
    state_dir: &std::path::Path,
    cache_dir: &std::path::Path,
    bridge: &BridgeConfig,
) -> Result<Client, NetError> {
    use arti_client::config::pt::TransportConfigBuilder;
    use arti_client::config::{BridgeConfigBuilder, CfgPath};

    let mut builder = arti_client::config::TorClientConfigBuilder::from_directories(state_dir, cache_dir);

    let bridge_config: BridgeConfigBuilder = bridge
        .bridge_line
        .parse()
        .map_err(|e| NetError::Config(format!("invalid bridge line: {e:?}")))?;
    builder.bridges().bridges().push(bridge_config);

    let mut transport = TransportConfigBuilder::default();
    transport
        .protocols(vec!["obfs4".parse().expect("\"obfs4\" is a valid transport name")])
        .path(CfgPath::new(bridge.obfs4proxy_path.to_string_lossy().into_owned()))
        .run_on_startup(true);
    builder.bridges().transports().push(transport);

    let config = builder.build().map_err(|e| NetError::Config(format!("{e:?}")))?;
    let client = TorClient::create_bootstrapped(config).await?;
    Ok(client)
}

#[cfg(test)]
mod bridge_config_tests {
    /// Local-only: proves the bridge/transport config this crate builds is
    /// accepted by arti's own config validation, without needing a live
    /// bridge or `obfs4proxy` binary to actually bootstrap through (see
    /// `bootstrap_with_bridge`'s doc comment for what remains unverified).
    #[test]
    fn bridge_config_builds_successfully() {
        use arti_client::config::pt::TransportConfigBuilder;
        use arti_client::config::{BridgeConfigBuilder, CfgPath};

        // A syntactically valid obfs4 bridge line (fingerprint/cert are
        // made up, not a real bridge -- this only tests config parsing).
        const BRIDGE_LINE: &str = "Bridge obfs4 192.0.2.3:443 0011223344556677889900112233445566778899 cert=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA iat-mode=0";

        let mut builder =
            arti_client::config::TorClientConfigBuilder::from_directories("/tmp/securetext-test-state", "/tmp/securetext-test-cache");

        let bridge_config: BridgeConfigBuilder = BRIDGE_LINE.parse().expect("valid bridge line");
        builder.bridges().bridges().push(bridge_config);

        let mut transport = TransportConfigBuilder::default();
        transport
            .protocols(vec!["obfs4".parse().unwrap()])
            .path(CfgPath::new("obfs4proxy".to_string()))
            .run_on_startup(true);
        builder.bridges().transports().push(transport);

        builder.build().expect("bridge config should build successfully");
    }
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
    // Addresses come from other people (invite links, contact cards, relay
    // addresses). Without this check, a contact could name a clearnet host
    // and have us reach it through a Tor exit. Messaging is onion-only by
    // design, so anything else is refused here, the one place every
    // messaging connection passes through.
    if !is_v3_onion(onion_address) {
        return Err(NetError::Config(format!("not a v3 onion address: {onion_address:.80}")));
    }
    let stream = client.connect((onion_address, port)).await?;
    Ok(stream)
}

/// A syntactically valid Tor v3 onion address: 56 base32 characters (the
/// last one encoding version 3), then `.onion`.
pub fn is_v3_onion(address: &str) -> bool {
    let Some(label) = address.strip_suffix(".onion") else { return false };
    label.len() == 56
        && label.bytes().all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        && label.ends_with('d')
}

pub use arti_client::IsolationToken;

/// One relay in a circuit we built (the hop viewer).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hop {
    /// The relay's RSA identity fingerprint (hex), as Tor tools show it.
    pub fingerprint: Option<String>,
    /// The relay's public address.
    pub address: Option<String>,
    /// Two-letter country code, from Tor's own GeoIP database (no lookup
    /// leaves the machine).
    pub country: Option<String>,
    /// A hop we can't see into: the other side's half of an onion-service
    /// connection.
    pub hidden: bool,
}

/// The relays on our side of `stream`'s circuit, in order (guard first),
/// or `None` if it isn't a stream we opened (connections others open to
/// our onion service use circuits arti doesn't expose to us).
pub fn circuit_hops(stream: &DataStream) -> Option<Vec<Hop>> {
    use tor_linkspec::{HasAddrs, HasRelayIds};
    use tor_proto::client::stream::ClientStreamCtrl;
    let tunnel = stream.client_stream_ctrl()?.tunnel()?;
    let path = tunnel.all_paths().into_iter().next()?;
    let geoip = geoip();
    Some(
        path.hops()
            .iter()
            .map(|entry| match entry.as_chan_target() {
                Some(target) => {
                    let addr = target.addrs().next();
                    Hop {
                        fingerprint: target.rsa_identity().map(|id| id.as_bytes().iter().map(|b| format!("{b:02X}")).collect()),
                        address: addr.map(|a| a.to_string()),
                        country: addr.and_then(|a| geoip.lookup_country_code(a.ip())).map(|c| c.to_string()),
                        hidden: false,
                    }
                }
                None => Hop { fingerprint: None, address: None, country: None, hidden: true },
            })
            .collect(),
    )
}

fn geoip() -> std::sync::Arc<tor_geoip::GeoipDb> {
    static DB: std::sync::OnceLock<std::sync::Arc<tor_geoip::GeoipDb>> = std::sync::OnceLock::new();
    DB.get_or_init(tor_geoip::GeoipDb::new_embedded).clone()
}

/// A two-letter country code arti accepts for exit selection, or an error.
pub fn parse_country(code: &str) -> Result<arti_client::CountryCode, NetError> {
    code.parse().map_err(|_| NetError::Config(format!("not a country code: {code:.8}")))
}

/// A stream to an ordinary (non-onion) host, through a Tor exit relay.
///
/// Messaging never uses this: peers and relays are onion services only.
/// It exists for the updater (roadmap Phase 6), which has to reach GitHub
/// Releases without revealing this machine's IP to GitHub or DNS. The host
/// name is resolved by the exit, never locally. `isolation` keeps these
/// streams off circuits used for anything else.
pub async fn connect_exit(
    client: &Client,
    host: &str,
    port: u16,
    isolation: IsolationToken,
    exit_country: Option<&str>,
) -> Result<DataStream, NetError> {
    let mut prefs = arti_client::StreamPrefs::new();
    prefs.set_isolation(isolation);
    // Updates only: the user may pick which country the exit relay (the
    // one that talks to GitHub) is in. Messaging never uses exits.
    if let Some(code) = exit_country {
        prefs.exit_country(parse_country(code)?);
    }
    let stream = client.connect_with_prefs((host, port), &prefs).await?;
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_v3_onion_addresses_are_dialable() {
        assert!(is_v3_onion("e4tlats24pehr4x62iivdluvdnj5i2ux7zesxpk4mvcovcrg2yzg5oad.onion"));
        assert!(!is_v3_onion("example.com"), "clearnet host");
        assert!(!is_v3_onion("github.com.onion"), "wrong length");
        assert!(!is_v3_onion("E4TLATS24PEHR4X62IIVDLUVDNJ5I2UX7ZESXPK4MVCOVCRG2YZG5OAD.onion"), "uppercase");
        assert!(!is_v3_onion("e4tlats24pehr4x62iivdluvdnj5i2ux7zesxpk4mvcovcrg2yzg5oa1.onion"), "not base32");
        assert!(!is_v3_onion("e4tlats24pehr4x62iivdluvdnj5i2ux7zesxpk4mvcovcrg2yzg5oad.onion.evil.com"));
        assert!(!is_v3_onion("expyuzz4wqqyqhjn.onion"), "v2");
    }

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

    /// The hop viewer against the live network: dial an onion service and
    /// read back our side of the circuit, with countries.
    ///   cargo test -p securetext-net -- --ignored hops_live --nocapture
    #[ignore]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn hops_live() {
        let service = TorClient::create_bootstrapped(scratch_config()).await.unwrap();
        let mut listener = Listener::launch(&service, "securetext-hops").unwrap();
        let address = listener.onion_address().unwrap();
        tokio::spawn(async move { while let Ok(Some(_s)) = listener.accept_next().await {} });
        let client = TorClient::create_bootstrapped(scratch_config()).await.unwrap();
        let mut stream = None;
        for _ in 0..6 {
            match dial(&client, &address, 1).await {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => {
                    eprintln!("dial not ready yet: {e}");
                    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                }
            }
        }
        let hops = circuit_hops(&stream.expect("dialed the onion service")).expect("a client stream has a path");
        for (i, h) in hops.iter().enumerate() {
            eprintln!("hop {}: {:?} {:?} {:?} hidden={}", i + 1, h.country, h.address, h.fingerprint, h.hidden);
        }
        let visible: Vec<&Hop> = hops.iter().filter(|h| !h.hidden).collect();
        assert!(visible.len() >= 3, "our side of an onion circuit has at least 3 relays: {hops:?}");
        assert!(visible.iter().all(|h| h.fingerprint.is_some() && h.address.is_some()));
        assert!(visible.iter().filter(|h| h.country.is_some()).count() >= 2, "countries come from Tor's GeoIP db");
    }

    /// Exit-country selection (update downloads only) against the live
    /// network: pin the exit to Germany and check the circuit's last relay.
    #[ignore]
    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn exit_country_live() {
        let client = TorClient::create_bootstrapped(scratch_config()).await.unwrap();
        let stream = connect_exit(&client, "github.com", 443, IsolationToken::new(), Some("DE")).await.expect("exit via DE");
        let hops = circuit_hops(&stream).unwrap();
        eprintln!("exit circuit: {:?}", hops.iter().map(|h| h.country.clone()).collect::<Vec<_>>());
        assert_eq!(hops.last().unwrap().country.as_deref(), Some("DE"));
        assert!(connect_exit(&client, "github.com", 443, IsolationToken::new(), Some("not a country")).await.is_err());
    }
}
