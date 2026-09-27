//! SecureText's application core: everything the desktop client (Phase 4)
//! needs, with no UI code in it.
//!
//! A [`NodeHandle`] is a running node for one local profile. It:
//!
//! - opens (or creates) the passphrase-encrypted identity store,
//! - brings up the transport (Tor in real use; an in-memory network in
//!   tests), publishing this device's onion service,
//! - keeps contacts, DMs, servers and channels, each backed by its own MLS
//!   group (a DM is a 2-member group, crypto-spec.md §2; a server and each
//!   of its channels are separate groups, architecture.md §7),
//! - delivers messages peer to peer over Noise + yamux connections, fanning
//!   each message out to every member itself since there is no server,
//! - queues anything it can't deliver yet in a persistent outbox and sends
//!   it when the recipient is next reachable (architecture.md §4, the
//!   pre-relay offline behaviour),
//! - publishes [`Event`]s so a UI can update live.
//!
//! The UI talks to it only through `NodeHandle`'s async methods, which
//! return plain serializable view structs.

pub mod api;
mod node;
mod relay;
mod store;
pub mod transport;
mod updates;
pub mod wire;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use securetext_identity::IdentityStore;
use serde::Serialize;
use tokio::sync::{broadcast, mpsc, oneshot};

pub use node::{fingerprint, CallParticipantView, CallView, MAX_MESSAGE_CHARS};
use node::{CallSetup, Job, NetEvent, NodeState, Opened, Timing};
pub use securetext_call as call;
pub use transport::{MemoryNetwork, TorTransport, Transport};
pub use updates::{tor_https_client, UpdateConfig, UpdateState, UpdateStatus};
pub use securetext_update as update;
pub use wire::ConversationKind;

/// The profile file, inside a profile directory.
pub const IDENTITY_FILE: &str = "identity.enc";

/// How the node reaches the network.
pub enum NetworkConfig {
    /// Real use: bootstrap Tor (arti) with persistent state under the
    /// profile directory, so the onion address stays stable across
    /// restarts. `bridge` routes around Tor blocking (architecture.md §5).
    Tor { bridge: Option<securetext_net::BridgeConfig> },
    /// Tests: an in-process network, this node listening at `address`.
    Memory { network: MemoryNetwork, address: String },
}

pub struct NodeConfig {
    /// Directory holding this profile's encrypted identity file and (for
    /// Tor) its Tor state. Must have a clean ownership chain for arti's
    /// permission checks (platform-support.md).
    pub profile_dir: PathBuf,
    /// Display label, used only when creating a new profile.
    pub label: String,
    pub passphrase: String,
    pub network: NetworkConfig,
    /// How often queued messages are retried and state is sealed to disk.
    pub retry_interval: Duration,
    /// Give up on a connection attempt after this long. Onion-service
    /// connections to a peer that's actually online usually take seconds
    /// to tens of seconds (tech-stack.md's measurements).
    pub dial_timeout: Duration,
    /// How often to reconnect to everyone we share a conversation with.
    pub presence_interval: Duration,
    /// How often to check our relay mailbox (if one is set) for messages
    /// left while we were offline.
    pub relay_poll_interval: Duration,
    /// Automatic updates (desktop builds only; `None` disables them).
    pub update: Option<UpdateConfig>,
    /// Microphone and speakers for calls (`None`: calls unavailable).
    pub call_audio: Option<Arc<dyn call::AudioBackend>>,
    /// Tests: accept TURN relays on 127.0.0.1.
    pub call_allow_loopback: bool,
}

impl NodeConfig {
    pub fn tor(profile_dir: PathBuf, label: String, passphrase: String) -> Self {
        Self {
            profile_dir,
            label,
            passphrase,
            network: NetworkConfig::Tor { bridge: None },
            retry_interval: Duration::from_secs(20),
            dial_timeout: Duration::from_secs(120),
            presence_interval: Duration::from_secs(600),
            relay_poll_interval: Duration::from_secs(90),
            update: None,
            call_audio: Some(Arc::new(call::CpalBackend)),
            call_allow_loopback: false,
        }
    }
}

/// Whether a profile already exists in `profile_dir` (decides between the
/// "create profile" and "unlock" screens).
pub fn profile_exists(profile_dir: &std::path::Path) -> bool {
    profile_dir.join(IDENTITY_FILE).exists()
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum NetworkState {
    Starting,
    Bootstrapping,
    Ready,
    Error(String),
}

#[derive(Clone, Debug, Serialize)]
pub struct StatusView {
    pub label: String,
    pub public_key: String,
    pub fingerprint: String,
    pub onion_address: Option<String>,
    pub network: NetworkState,
    pub online_peers: usize,
    /// Our offline-delivery relay address, if one is set.
    pub relay: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConversationView {
    pub id: String,
    pub kind: ConversationKind,
    pub name: String,
    pub server_id: Option<String>,
    pub is_admin: bool,
    pub private: bool,
    /// We were removed; history stays readable, nothing new arrives.
    pub removed: bool,
    /// For DMs: the other person's key.
    pub peer_key: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct MessageView {
    pub id: String,
    pub sender_key: String,
    pub sender_label: String,
    pub body: String,
    pub sent_at: i64,
    pub outgoing: bool,
    /// "pending" (queued for at least one recipient), "sent" (written to
    /// every recipient's connection), "relayed" (the last undelivered copy
    /// was left at a recipient's relay mailbox), or "received".
    pub status: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemberView {
    pub key: String,
    pub label: String,
    pub fingerprint: String,
    pub is_admin: bool,
    pub is_me: bool,
    pub online: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ContactView {
    pub key: String,
    pub label: String,
    pub fingerprint: String,
    pub online: bool,
    /// We hold their signed contact card, which inviting them to a server
    /// requires (they have to have connected to us at least once).
    pub has_card: bool,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Event {
    Network { state: NetworkState },
    ConversationsChanged,
    MembersChanged { conversation_id: String },
    Message { conversation_id: String, message: MessageView },
    MessageStatus { conversation_id: String, id: String, status: String },
    Peer { key: String, online: bool },
    Update { status: UpdateStatus },
    /// The call changed (or ended: `call` is `None` and `ended` says why).
    Call { call: Option<CallView>, ended: Option<String> },
    /// A video frame (base64 JPEG) from a call participant.
    CallVideo { peer_key: String, jpeg: String },
}

/// A running node. Cheap to clone; every clone talks to the same node.
#[derive(Clone)]
pub struct NodeHandle {
    jobs: mpsc::UnboundedSender<Job>,
    events: broadcast::Sender<Event>,
}

impl NodeHandle {
    /// Open (or create) the profile and start the node. Fails fast on a
    /// wrong passphrase; the network comes up in the background and is
    /// reported through [`Event::Network`] / [`StatusView::network`].
    pub async fn start(config: NodeConfig) -> anyhow::Result<Self> {
        std::fs::create_dir_all(&config.profile_dir)?;
        let identity_path = config.profile_dir.join(IDENTITY_FILE);
        let label = config.label.trim().to_string();
        let passphrase = config.passphrase.clone();
        // Argon2id is deliberately slow; keep it off the async workers.
        let opened = tokio::task::spawn_blocking(move || -> anyhow::Result<Opened> {
            let (identity, public) = if identity_path.exists() {
                IdentityStore::open(&identity_path, &passphrase)?
            } else {
                anyhow::ensure!(!label.is_empty(), "choose a display name");
                IdentityStore::create(&identity_path, label, &passphrase)?
            };
            Ok(Opened { identity, public })
        })
        .await??;

        let (events, _) = broadcast::channel(1024);
        let (net_tx, mut net_rx) = mpsc::unbounded_channel::<NetEvent>();
        let (jobs_tx, mut jobs_rx) = mpsc::unbounded_channel::<Job>();
        let timing = Timing {
            retry_interval: config.retry_interval,
            dial_timeout: config.dial_timeout,
            presence_interval: config.presence_interval,
            relay_poll_interval: config.relay_poll_interval,
        };
        let mut state = NodeState::new(opened, events.clone(), net_tx.clone(), timing)?;
        if let Some(update) = config.update {
            state.enable_updates(update);
        }
        if let Some(audio) = config.call_audio {
            state.enable_calls(CallSetup { audio, allow_loopback: config.call_allow_loopback });
        }

        match config.network {
            NetworkConfig::Memory { network, address } => {
                let listening = network.listen(&address);
                state.handle_net(NetEvent::TransportReady { transport: network.transport(&address), listening, exit: None });
            }
            NetworkConfig::Tor { bridge } => {
                let _ = events.send(Event::Network { state: NetworkState::Bootstrapping });
                let dir = config.profile_dir.clone();
                let tx = net_tx.clone();
                tokio::spawn(async move {
                    let result = async {
                        let state_dir = dir.join("tor-state");
                        let cache_dir = dir.join("tor-cache");
                        let client = match bridge {
                            Some(bridge) => securetext_net::bootstrap_with_bridge(&state_dir, &cache_dir, &bridge).await?,
                            None => securetext_net::bootstrap_with_dirs(&state_dir, &cache_dir).await?,
                        };
                        let exit = updates::tor_exit(client.clone());
                        let transport = TorTransport::new(client);
                        let listening = transport.listen("securetext-peer")?;
                        Ok::<_, anyhow::Error>((transport, listening, exit))
                    }
                    .await;
                    let _ = tx.send(match result {
                        Ok((transport, listening, exit)) => {
                            NetEvent::TransportReady { transport: Arc::new(transport), listening, exit: Some(exit) }
                        }
                        Err(e) => NetEvent::TransportFailed(format!("{e:#}")),
                    });
                });
            }
        }

        let retry_interval = config.retry_interval;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(retry_interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    job = jobs_rx.recv() => match job {
                        Some(job) => job(&mut state),
                        None => { state.shutdown(); break; }
                    },
                    Some(event) = net_rx.recv() => state.handle_net(event),
                    _ = tick.tick() => state.tick(),
                }
                if state.stopping {
                    break;
                }
            }
        });

        Ok(Self { jobs: jobs_tx, events })
    }

    async fn call<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut NodeState) -> anyhow::Result<T> + Send + 'static,
    ) -> anyhow::Result<T> {
        let (tx, rx) = oneshot::channel();
        self.jobs
            .send(Box::new(move |state: &mut NodeState| {
                let _ = tx.send(f(state));
            }))
            .map_err(|_| anyhow::anyhow!("the node has shut down"))?;
        rx.await.map_err(|_| anyhow::anyhow!("the node has shut down"))?
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    pub async fn status(&self) -> anyhow::Result<StatusView> {
        self.call(|s| Ok(s.status())).await
    }

    /// A fresh single-use invite link for this identity.
    pub async fn create_invite(&self) -> anyhow::Result<String> {
        self.call(|s| s.create_invite()).await
    }

    /// Accept someone's invite link. Returns the new DM's conversation id.
    pub async fn add_contact(&self, link: String) -> anyhow::Result<String> {
        self.call(move |s| s.add_contact(&link)).await
    }

    pub async fn conversations(&self) -> anyhow::Result<Vec<ConversationView>> {
        self.call(|s| s.conversations()).await
    }

    pub async fn messages(&self, conversation_id: String, limit: u32) -> anyhow::Result<Vec<MessageView>> {
        self.call(move |s| s.messages(&conversation_id, limit)).await
    }

    pub async fn send_message(&self, conversation_id: String, body: String) -> anyhow::Result<MessageView> {
        self.call(move |s| s.send_message(&conversation_id, &body)).await
    }

    /// Create a server (with a "general" channel). Returns its id.
    pub async fn create_server(&self, name: String) -> anyhow::Result<String> {
        self.call(move |s| s.create_server(&name)).await
    }

    pub async fn create_channel(
        &self,
        server_id: String,
        name: String,
        private: bool,
        member_keys: Vec<String>,
    ) -> anyhow::Result<String> {
        self.call(move |s| s.create_channel(&server_id, &name, private, &member_keys)).await
    }

    pub async fn invite_to_server(&self, server_id: String, peer_key: String) -> anyhow::Result<()> {
        self.call(move |s| s.invite_to_server(&server_id, &peer_key)).await
    }

    pub async fn kick(&self, server_id: String, peer_key: String) -> anyhow::Result<()> {
        self.call(move |s| s.kick(&server_id, &peer_key)).await
    }

    pub async fn members(&self, conversation_id: String) -> anyhow::Result<Vec<MemberView>> {
        self.call(move |s| s.members(&conversation_id)).await
    }

    pub async fn contacts(&self) -> anyhow::Result<Vec<ContactView>> {
        self.call(|s| s.contacts()).await
    }

    /// Use the relay at `address` (a `securetext-relay1:` link) as this
    /// profile's offline mailbox, or stop using one (`None`). Returns the
    /// relay now in use. Contacts learn the change through our contact
    /// card; invites created afterwards include it.
    pub async fn set_relay(&self, address: Option<String>) -> anyhow::Result<Option<String>> {
        self.call(move |s| s.set_relay(address.as_deref())).await
    }

    // ---- calls (Phase 7) ----

    /// Ring everyone in a DM or channel. Needs a TURN server (see
    /// [`Self::set_turn_servers`]) and at least one member online.
    pub async fn start_call(&self, conversation_id: String, video: bool) -> anyhow::Result<CallView> {
        self.call(move |s| s.start_call(&conversation_id, video)).await
    }

    pub async fn accept_call(&self) -> anyhow::Result<CallView> {
        self.call(|s| s.accept_call()).await
    }

    pub async fn decline_call(&self) -> anyhow::Result<()> {
        self.call(|s| s.decline_call()).await
    }

    pub async fn hang_up(&self) -> anyhow::Result<()> {
        self.call(|s| s.hang_up()).await
    }

    pub async fn set_call_muted(&self, muted: bool) -> anyhow::Result<()> {
        self.call(move |s| s.set_call_muted(muted)).await
    }

    pub async fn call_status(&self) -> anyhow::Result<Option<CallView>> {
        self.call(|s| Ok(s.call_view())).await
    }

    /// How each participant's media is actually carried (candidate types,
    /// bytes), straight from WebRTC's stats.
    pub async fn call_stats(&self) -> anyhow::Result<Vec<call::PeerStats>> {
        let engine = self.call(|s| Ok(s.call_engine())).await?;
        Ok(node::call_stats(engine).await)
    }

    /// Send one camera frame (JPEG bytes) to everyone in the call.
    pub async fn send_video_frame(&self, jpeg: Vec<u8>) -> anyhow::Result<()> {
        let engine = self.call(|s| Ok(s.call_engine())).await?;
        match engine {
            Some(engine) => engine.send_video(&jpeg).await,
            None => Ok(()),
        }
    }

    /// Test audio only: what the synthetic speaker played recently (pitch
    /// and how much was audible), proving audio crossed the call intact.
    pub async fn call_heard(&self) -> anyhow::Result<Option<call::audio::Heard>> {
        self.call(|s| Ok(s.heard())).await
    }

    pub async fn turn_servers(&self) -> anyhow::Result<Vec<call::TurnServer>> {
        self.call(|s| s.turn_servers()).await
    }

    pub async fn set_turn_servers(&self, servers: Vec<call::TurnServer>) -> anyhow::Result<Vec<call::TurnServer>> {
        self.call(move |s| s.set_turn_servers(servers)).await
    }

    pub async fn update_status(&self) -> anyhow::Result<Option<UpdateStatus>> {
        self.call(|s| Ok(s.update_status())).await
    }

    /// Check GitHub Releases (over Tor) now instead of waiting for the next
    /// scheduled check.
    pub async fn check_for_updates(&self) -> anyhow::Result<Option<UpdateStatus>> {
        self.call(|s| s.check_for_updates()).await
    }

    /// Download the available update (automatic when auto-updates are on).
    pub async fn download_update(&self) -> anyhow::Result<Option<UpdateStatus>> {
        self.call(|s| s.download_update()).await
    }

    pub async fn set_auto_update(&self, enabled: bool) -> anyhow::Result<Option<UpdateStatus>> {
        self.call(move |s| s.set_auto_update(enabled)).await
    }

    /// The downloaded, hash-verified update, for the shell to install:
    /// (file, the signed asset it must match, how this copy is installed).
    pub async fn staged_update(&self) -> anyhow::Result<(PathBuf, update::Asset, update::InstallKind)> {
        self.call(|s| s.staged_update()).await
    }

    /// Seal everything to disk and stop. Queued messages stay queued in
    /// the encrypted profile and go out after the next start.
    pub async fn shutdown(&self) {
        let _ = self
            .call(|s| {
                s.shutdown();
                Ok(())
            })
            .await;
    }
}
