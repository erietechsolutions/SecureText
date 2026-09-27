//! Automatic update checks (roadmap Phase 6), run by the node because the
//! node owns the Tor client: every check and download goes out through a
//! Tor exit, never a direct connection.
//!
//! Timing is randomised so checks don't form a pattern an observer could
//! use to pick SecureText users out: the first check happens a random time
//! after Tor is up, later ones roughly daily with ±25% jitter. Updates are
//! downloaded (and hash-checked) in the background, but only installed
//! when the user says so. The whole thing can be switched off.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::BoxFuture;
use rand::Rng;
use securetext_update::{ed25519::VerifyingKey, https::Io, Connector, HttpsClient, InstallKind, Offer};
use serde::Serialize;
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use crate::node::NetEvent;

pub struct UpdateConfig {
    /// This build's version (`CARGO_PKG_VERSION` of the shell).
    pub current_version: String,
    pub manifest_url: String,
    /// Update-signing public keys pinned into this build.
    pub trusted_keys: Vec<VerifyingKey>,
    pub install: InstallKind,
    /// Where downloads are kept until installed.
    pub staging_dir: PathBuf,
    /// The first automatic check comes a random time in this range after
    /// the network is up.
    pub first_check: (Duration, Duration),
    /// Roughly how often to check after that.
    pub interval: Duration,
    /// Tests: fetch with this client instead of through Tor.
    pub client_override: Option<HttpsClient>,
}

impl UpdateConfig {
    pub fn desktop(current_version: String, trusted_keys: Vec<VerifyingKey>, staging_dir: PathBuf) -> Self {
        Self {
            current_version,
            manifest_url: securetext_update::DESKTOP_MANIFEST_URL.into(),
            trusted_keys,
            install: InstallKind::detect(),
            staging_dir,
            first_check: (Duration::from_secs(10 * 60), Duration::from_secs(3 * 3600)),
            interval: Duration::from_secs(24 * 3600),
            client_override: None,
        }
    }
}

/// Everything the UI needs to show about updates.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct UpdateStatus {
    pub current_version: String,
    /// Automatic checks are on.
    pub auto: bool,
    /// Exit country for update downloads (`None`: any).
    pub region: Option<String>,
    /// This install can apply updates itself (not a source build).
    pub can_install: bool,
    #[serde(flatten)]
    pub state: UpdateState,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum UpdateState {
    Idle,
    Checking,
    UpToDate { checked_at: i64 },
    /// A newer release exists. `installable` is false when there's no
    /// installer for this kind of install; the user is pointed at GitHub.
    Available { version: String, notes: String, installable: bool },
    Downloading { version: String, notes: String },
    /// Downloaded and verified. `system_installer`: applying it opens the
    /// system's software installer (deb/rpm) instead of restarting.
    Ready { version: String, notes: String, system_installer: bool },
    Failed { error: String },
}

pub(crate) enum UpdateEvent {
    Checked(Result<Option<Offer>, String>),
    Downloaded(Result<PathBuf, String>),
}

pub(crate) struct Updater {
    config: UpdateConfig,
    exit_factory: Option<ExitFactory>,
    pub(crate) auto: bool,
    /// Country the exit relay for update downloads must be in, if chosen.
    pub(crate) exit_country: Option<String>,
    state: UpdateState,
    offer: Option<Offer>,
    staged: Option<PathBuf>,
    next_check: Option<Instant>,
    busy: bool,
}

/// Tor exit streams from the node's own arti client, one isolation group
/// per check so update traffic never shares a circuit with anything else.
struct TorExit {
    client: securetext_net::Client,
    isolation: securetext_net::IsolationToken,
    /// The user's chosen exit country for update downloads, if any.
    country: Option<String>,
}

impl Connector for TorExit {
    fn connect<'a>(&'a self, host: &'a str, port: u16) -> BoxFuture<'a, std::io::Result<Box<dyn Io>>> {
        Box::pin(async move {
            let stream = securetext_net::connect_exit(&self.client, host, port, self.isolation, self.country.as_deref())
                .await
                .map_err(std::io::Error::other)?;
            Ok(Box::new(stream) as Box<dyn Io>)
        })
    }
}

pub(crate) fn tor_exit(client: securetext_net::Client) -> ExitFactory {
    Arc::new(move |country: Option<String>| {
        Arc::new(TorExit { client: client.clone(), isolation: securetext_net::IsolationToken::new(), country })
            as Arc<dyn Connector>
    })
}

/// The HTTPS client the updater uses in real life: GitHub hosts only, over
/// Tor exits from `client`. Public for the live test.
pub fn tor_https_client(client: securetext_net::Client) -> HttpsClient {
    HttpsClient::new(tor_exit(client)(None), securetext_update::https::github_hosts(), REQUEST_TIMEOUT)
}

/// Makes a fresh connector (and so a fresh circuit isolation group) per
/// check.
/// The argument is the exit country for update downloads (`None`: any).
pub(crate) type ExitFactory = Arc<dyn Fn(Option<String>) -> Arc<dyn Connector> + Send + Sync>;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(20 * 60);

impl Updater {
    pub(crate) fn new(config: UpdateConfig, auto: bool) -> Self {
        Self {
            config,
            exit_factory: None,
            auto,
            exit_country: None,
            state: UpdateState::Idle,
            offer: None,
            staged: None,
            next_check: None,
            busy: false,
        }
    }

    pub(crate) fn status(&self) -> UpdateStatus {
        UpdateStatus {
            current_version: self.config.current_version.clone(),
            auto: self.auto,
            region: self.exit_country.clone(),
            can_install: self.config.install.platform_key().is_some(),
            state: self.state.clone(),
        }
    }

    /// The network is up; schedule the first check.
    pub(crate) fn network_ready(&mut self, exit: Option<ExitFactory>) {
        if exit.is_some() {
            self.exit_factory = exit;
        }
        if self.next_check.is_none() {
            let (lo, hi) = self.config.first_check;
            self.next_check = Some(Instant::now() + random_between(lo, hi.max(lo)));
        }
    }

    pub(crate) fn set_auto(&mut self, auto: bool) {
        self.auto = auto;
    }

    fn client(&mut self) -> Option<HttpsClient> {
        if let Some(client) = &self.config.client_override {
            return Some(client.clone());
        }
        let connector = self.exit_factory.as_ref().map(|make| make(self.exit_country.clone()))?;
        // Tor only: there is no fallback to a direct connection.
        Some(HttpsClient::new(connector, securetext_update::https::github_hosts(), REQUEST_TIMEOUT))
    }

    /// Called on every node tick.
    pub(crate) fn tick(&mut self, tasks: &mut JoinSet<()>, net_tx: &mpsc::UnboundedSender<NetEvent>) {
        if self.auto && !self.busy && self.next_check.is_some_and(|t| Instant::now() >= t) {
            self.start_check(tasks, net_tx);
        }
    }

    /// A check the user asked for (or a scheduled one).
    pub(crate) fn start_check(&mut self, tasks: &mut JoinSet<()>, net_tx: &mpsc::UnboundedSender<NetEvent>) -> bool {
        if self.busy {
            return false;
        }
        let Some(client) = self.client() else {
            self.state = UpdateState::Failed { error: "not connected to Tor yet".into() };
            return false;
        };
        self.busy = true;
        self.state = UpdateState::Checking;
        let jitter = self.config.interval.as_secs_f64() * 0.25;
        let next = self.config.interval.as_secs_f64() + rand::thread_rng().gen_range(-jitter..=jitter);
        self.next_check = Some(Instant::now() + Duration::from_secs_f64(next.max(60.0)));
        let url = self.config.manifest_url.clone();
        let keys = self.config.trusted_keys.clone();
        let current = self.config.current_version.clone();
        let install = self.config.install.clone();
        let tx = net_tx.clone();
        tasks.spawn(async move {
            let result = securetext_update::check(&client, &url, &keys, &current, &install)
                .await
                .map_err(|e| format!("{e:#}"));
            let _ = tx.send(NetEvent::Update(UpdateEvent::Checked(result)));
        });
        true
    }

    pub(crate) fn start_download(&mut self, tasks: &mut JoinSet<()>, net_tx: &mpsc::UnboundedSender<NetEvent>) -> anyhow::Result<()> {
        anyhow::ensure!(!self.busy, "an update check or download is already running");
        let offer = self.offer.clone().ok_or_else(|| anyhow::anyhow!("no update is available"))?;
        anyhow::ensure!(offer.asset.is_some(), "this release has no installer for this kind of install");
        let client = self.client().ok_or_else(|| anyhow::anyhow!("not connected to Tor yet"))?;
        self.busy = true;
        self.state = UpdateState::Downloading { version: offer.version.clone(), notes: offer.notes.clone() };
        let install = self.config.install.clone();
        let staging = self.config.staging_dir.clone();
        let tx = net_tx.clone();
        tasks.spawn(async move {
            let result = securetext_update::download(&client, &offer, &install, &staging)
                .await
                .map_err(|e| format!("{e:#}"));
            let _ = tx.send(NetEvent::Update(UpdateEvent::Downloaded(result)));
        });
        Ok(())
    }

    pub(crate) fn on_event(&mut self, event: UpdateEvent, tasks: &mut JoinSet<()>, net_tx: &mpsc::UnboundedSender<NetEvent>) {
        self.busy = false;
        match event {
            UpdateEvent::Checked(Ok(None)) => {
                self.offer = None;
                self.state = UpdateState::UpToDate { checked_at: crate::node::now_ms() };
            }
            UpdateEvent::Checked(Ok(Some(offer))) => {
                let already_staged = matches!(&self.state, UpdateState::Ready { version, .. } if *version == offer.version)
                    && self.staged.is_some();
                if already_staged {
                    return;
                }
                let installable = offer.asset.is_some() && self.config.install.platform_key().is_some();
                self.state = UpdateState::Available {
                    version: offer.version.clone(),
                    notes: offer.notes.clone(),
                    installable,
                };
                self.offer = Some(offer);
                // Fetch it in the background; installing still waits for
                // the user.
                if installable && self.auto {
                    let _ = self.start_download(tasks, net_tx);
                }
            }
            UpdateEvent::Checked(Err(error)) => self.state = UpdateState::Failed { error },
            UpdateEvent::Downloaded(Ok(path)) => {
                let offer = self.offer.clone().expect("a download follows an offer");
                self.staged = Some(path);
                self.state = UpdateState::Ready {
                    version: offer.version,
                    notes: offer.notes,
                    system_installer: matches!(self.config.install, InstallKind::Deb | InstallKind::Rpm),
                };
            }
            UpdateEvent::Downloaded(Err(error)) => self.state = UpdateState::Failed { error },
        }
    }

    /// The verified download and how to apply it, for the shell to install.
    pub(crate) fn staged(&self) -> anyhow::Result<(PathBuf, securetext_update::Asset, InstallKind)> {
        let path = self.staged.clone().ok_or_else(|| anyhow::anyhow!("no update has been downloaded"))?;
        let asset = self
            .offer
            .as_ref()
            .and_then(|o| o.asset.clone())
            .ok_or_else(|| anyhow::anyhow!("no update has been downloaded"))?;
        Ok((path, asset, self.config.install.clone()))
    }
}

fn random_between(lo: Duration, hi: Duration) -> Duration {
    if hi <= lo {
        return lo;
    }
    Duration::from_secs_f64(rand::thread_rng().gen_range(lo.as_secs_f64()..hi.as_secs_f64()))
}
