//! The long-running node: one task that owns every piece of mutable state
//! (identity store, MLS groups, the app database) and reacts to two
//! streams of input: commands from the UI and events from the network.
//!
//! Owning everything in one task means no locks around MLS group state,
//! which must never be mutated concurrently (two interleaved commits would
//! fork the group). Network I/O happens in separate per-connection tasks
//! that only ever hand frames to and from this one.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use openmls::prelude::{GroupId, MlsGroup};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::RustCrypto;
use rusqlite::Connection;
use securetext_crypto::{Incoming, Member, PersistentProvider};
use securetext_identity::{IdentityStore, PublicIdentity};
use securetext_invite::Invite;
use securetext_net::{MuxMode, SecureMux};
use tokio::sync::{broadcast, mpsc};
use securetext_relay::{client as relay_client, RelayAddress, Request as RelayRequest, Response as RelayResponse, StoredBlob};
use tokio::task::JoinSet;

use crate::relay::{self, MyRelay};
use crate::store::{ConversationRow, MessageRow, PeerRow, Store};
use crate::transport::{BoxedStream, Listening, Transport};
use crate::wire::{
    self, to_hex, ContactCard, ConversationInfo, ConversationKind, Payload, SignedCard, WireMessage,
};
use crate::{
    ContactView, ConversationView, Event, MemberView, MessageView, NetworkState, StatusView,
};

/// Key packages handed to a contact when the relationship starts, so they
/// can add us to a server and its channels without us being online.
const INITIAL_KEY_PACKAGES: usize = 6;
/// Upper bound on how many of one peer's key packages we'll hold.
const MAX_PEER_KEY_PACKAGES: u32 = 16;
/// Messages for a group we can't process yet (typically: they belong to
/// an epoch whose commit hasn't arrived yet), per group.
const MAX_PENDING_PER_GROUP: usize = 256;
/// How many times a pending message is retried before it's dropped
/// (a duplicate delivery will never succeed and shouldn't linger).
const MAX_PENDING_TRIES: u8 = 8;
pub const MAX_MESSAGE_CHARS: usize = 4000;
const MAX_NAME_CHARS: usize = 64;
const MAX_BACKOFF: Duration = Duration::from_secs(300);
/// Blobs fetched from our relay mailbox per round trip.
const COLLECT_BATCH: u32 = 50;

pub(crate) type Job = Box<dyn FnOnce(&mut NodeState) + Send>;

pub(crate) enum NetEvent {
    TransportReady {
        transport: Arc<dyn Transport>,
        listening: Listening,
    },
    TransportFailed(String),
    Incoming(BoxedStream),
    Connected {
        peer_key: Vec<u8>,
        card: Option<SignedCard>,
        conn_id: u64,
        tx: mpsc::UnboundedSender<Outgoing>,
    },
    Frame {
        peer_key: Vec<u8>,
        message: WireMessage,
    },
    Disconnected {
        peer_key: Vec<u8>,
        conn_id: u64,
    },
    DialFailed {
        peer_key: Vec<u8>,
        error: String,
    },
    /// Queued frames for `peer_key` were left at their relay.
    Relayed {
        peer_key: Vec<u8>,
        outbox_ids: Vec<i64>,
    },
    RelayDepositFailed {
        peer_key: Vec<u8>,
        error: String,
    },
    /// Blobs collected from our own relay mailbox.
    RelayCollected {
        items: Vec<StoredBlob>,
    },
    RelayCollectFailed {
        error: String,
    },
}

pub(crate) struct Outgoing {
    outbox_id: Option<i64>,
    message: WireMessage,
}

struct Conn {
    id: u64,
    tx: mpsc::UnboundedSender<Outgoing>,
}

struct PendingWelcome {
    from: Vec<u8>,
    welcome: Vec<u8>,
    info: ConversationInfo,
    roster: Vec<SignedCard>,
    received: Instant,
}

/// How many early channel Welcomes are held, and for how long.
const MAX_PENDING_WELCOMES: usize = 64;
const PENDING_WELCOME_TTL: Duration = Duration::from_secs(3600);

struct Pending {
    from: Vec<u8>,
    message: Vec<u8>,
    tries: u8,
}

#[derive(Clone)]
pub(crate) struct Timing {
    pub retry_interval: Duration,
    pub dial_timeout: Duration,
    pub presence_interval: Duration,
    pub relay_poll_interval: Duration,
}

pub(crate) struct NodeState {
    identity: IdentityStore,
    public: PublicIdentity,
    member: Member<PersistentProvider<Connection>>,
    signer: SignatureKeyPair,
    noise_private: Vec<u8>,
    crypto: RustCrypto,
    store: Store,
    groups: HashMap<Vec<u8>, MlsGroup>,

    network: NetworkState,
    transport: Option<Arc<dyn Transport>>,
    listening_guard: Option<Box<dyn Send + Sync>>,
    my_card: Option<SignedCard>,
    my_onion: Option<String>,
    my_relay: Option<MyRelay>,

    connections: HashMap<Vec<u8>, Conn>,
    /// Cards presented by peers on connections they opened to us, for
    /// peers we don't know yet (they become known once they send a valid
    /// Welcome).
    presented_cards: HashMap<Vec<u8>, SignedCard>,
    dialing: HashSet<Vec<u8>>,
    backoff: HashMap<Vec<u8>, (Instant, u32)>,
    pending: HashMap<Vec<u8>, Vec<Pending>>,
    /// Channel Welcomes that arrived before their server's Welcome. Over
    /// Tor two peers often end up with two connections at once, and frames
    /// resent on the newer one can overtake the older one, so ordering
    /// across frames isn't guaranteed.
    pending_welcomes: Vec<PendingWelcome>,
    /// Outbox entries sent on a live connection and not yet acknowledged:
    /// id -> (peer, when sent).
    awaiting_ack: HashMap<i64, (Vec<u8>, Instant)>,
    last_presence: Option<Instant>,
    /// Peers whose queue is currently being deposited at their relay.
    relaying: HashSet<Vec<u8>>,
    collecting: bool,
    last_collect: Option<Instant>,
    next_conn_id: u64,
    tasks: JoinSet<()>,

    events: broadcast::Sender<Event>,
    net_tx: mpsc::UnboundedSender<NetEvent>,
    timing: Timing,
    dirty: bool,
    pub(crate) stopping: bool,
}

pub(crate) struct Opened {
    pub identity: IdentityStore,
    pub public: PublicIdentity,
}

impl NodeState {
    pub(crate) fn new(
        opened: Opened,
        events: broadcast::Sender<Event>,
        net_tx: mpsc::UnboundedSender<NetEvent>,
        timing: Timing,
    ) -> anyhow::Result<Self> {
        let Opened { identity, public } = opened;
        let signer = identity
            .signing_key_pair(&public)?
            .ok_or_else(|| anyhow::anyhow!("identity store has no signing key"))?;
        let member_signer = identity
            .signing_key_pair(&public)?
            .ok_or_else(|| anyhow::anyhow!("identity store has no signing key"))?;
        let noise_private = identity.noise_static_private_key()?;

        let mut provider = PersistentProvider::new(Connection::open(identity.db_path())?);
        provider.run_migrations()?;
        let member = Member::new(&public.label, member_signer, provider);
        let store = Store::open(identity.db_path())?;
        let my_relay = MyRelay::load(&store)?;

        let mut groups = HashMap::new();
        for conversation in store.conversations()? {
            if let Some(group) = member.load_group(&GroupId::from_slice(&conversation.group_id))? {
                groups.insert(conversation.group_id.clone(), group);
            }
        }

        Ok(Self {
            identity,
            public,
            member,
            signer,
            noise_private,
            crypto: RustCrypto::default(),
            store,
            groups,
            network: NetworkState::Starting,
            transport: None,
            listening_guard: None,
            my_card: None,
            my_onion: None,
            my_relay,
            connections: HashMap::new(),
            presented_cards: HashMap::new(),
            dialing: HashSet::new(),
            backoff: HashMap::new(),
            pending: HashMap::new(),
            pending_welcomes: Vec::new(),
            awaiting_ack: HashMap::new(),
            last_presence: None,
            relaying: HashSet::new(),
            collecting: false,
            last_collect: None,
            next_conn_id: 0,
            tasks: JoinSet::new(),
            events,
            net_tx,
            timing,
            dirty: false,
            stopping: false,
        })
    }

    fn emit(&self, event: Event) {
        // No subscribers (e.g. UI not attached yet) is fine.
        let _ = self.events.send(event);
    }

    fn my_key(&self) -> &[u8] {
        &self.public.public_key
    }

    pub(crate) fn seal_if_dirty(&mut self) {
        if self.dirty {
            match self.identity.seal() {
                Ok(()) => self.dirty = false,
                Err(e) => eprintln!("[securetext] failed to seal profile to disk: {e}"),
            }
        }
    }

    pub(crate) fn shutdown(&mut self) {
        self.dirty = true;
        self.seal_if_dirty();
        self.stopping = true;
        self.tasks.abort_all();
        self.connections.clear();
        self.listening_guard = None;
        self.transport = None;
    }

    // =====================================================================
    // Network events
    // =====================================================================

    pub(crate) fn handle_net(&mut self, event: NetEvent) {
        match event {
            NetEvent::TransportReady { transport, mut listening } => {
                self.my_onion = Some(listening.onion_address.clone());
                if let Err(e) = self.refresh_my_card() {
                    self.set_network(NetworkState::Error(e.to_string()));
                    return;
                }
                let _ = self.store.set_setting("onion_address", &listening.onion_address);
                let incoming_tx = self.net_tx.clone();
                let mut incoming = std::mem::replace(&mut listening.incoming, mpsc::unbounded_channel().1);
                self.tasks.spawn(async move {
                    while let Some(stream) = incoming.recv().await {
                        if incoming_tx.send(NetEvent::Incoming(stream)).is_err() {
                            break;
                        }
                    }
                });
                self.listening_guard = Some(listening._guard);
                self.transport = Some(transport);
                self.set_network(NetworkState::Ready);
                self.presence_sweep();
                self.maybe_collect();
            }
            NetEvent::TransportFailed(error) => self.set_network(NetworkState::Error(error)),
            NetEvent::Incoming(stream) => self.spawn_accept(stream),
            NetEvent::Connected { peer_key, card, conn_id, tx } => {
                self.on_connected(peer_key, card, conn_id, tx)
            }
            NetEvent::Frame { peer_key, message } => {
                if let Err(e) = self.on_frame(&peer_key, message) {
                    eprintln!("[securetext] dropped a frame from {}: {e:#}", short(&peer_key));
                }
            }
            NetEvent::Disconnected { peer_key, conn_id } => {
                if self.connections.get(&peer_key).is_some_and(|c| c.id == conn_id) {
                    self.connections.remove(&peer_key);
                    self.emit(Event::Peer { key: to_hex(&peer_key), online: false });
                }
            }
            NetEvent::DialFailed { peer_key, error } => {
                self.dialing.remove(&peer_key);
                let entry = self.backoff.entry(peer_key.clone()).or_insert((Instant::now(), 0));
                entry.0 = Instant::now();
                entry.1 = entry.1.saturating_add(1);
                eprintln!("[securetext] could not reach {}: {error}", short(&peer_key));
                self.maybe_deposit(&peer_key);
            }
            NetEvent::Relayed { peer_key, outbox_ids } => {
                self.relaying.remove(&peer_key);
                for id in outbox_ids {
                    self.awaiting_ack.remove(&id);
                    if let Ok(Some((msg_ref, 0))) = self.store.outbox_delivered(id, &peer_key) {
                        self.set_message_status(&msg_ref, "relayed");
                    }
                }
                self.dirty = true;
            }
            NetEvent::RelayDepositFailed { peer_key, error } => {
                self.relaying.remove(&peer_key);
                eprintln!("[securetext] could not leave messages at {}'s relay: {error}", short(&peer_key));
            }
            NetEvent::RelayCollected { items } => self.on_collected(items),
            NetEvent::RelayCollectFailed { error } => {
                self.collecting = false;
                eprintln!("[securetext] could not check the relay mailbox: {error}");
            }
        }
    }

    fn set_network(&mut self, state: NetworkState) {
        self.network = state.clone();
        self.emit(Event::Network { state });
    }

    pub(crate) fn tick(&mut self) {
        while self.tasks.try_join_next().is_some() {}
        self.drop_silent_connections();
        if self.transport.is_some() {
            if let Ok(peers) = self.store.peers_with_outbox() {
                for peer in peers {
                    self.ensure_dial(&peer);
                }
            }
            let presence_due = self
                .last_presence
                .is_none_or(|t| t.elapsed() >= self.timing.presence_interval);
            if presence_due {
                self.presence_sweep();
            }
            self.maybe_collect();
        }
        self.seal_if_dirty();
    }

    /// A connection whose peer hasn't acknowledged something for longer
    /// than a dial is allowed to take is treated as dead, even if it hasn't
    /// been closed: a peer that vanished (crash, sleep, network loss) can
    /// leave a Tor stream open for a long time. Dropping it sends the
    /// queued frames back through redial and, failing that, the relay.
    fn drop_silent_connections(&mut self) {
        let timeout = self.timing.dial_timeout;
        let stale: HashSet<Vec<u8>> = self
            .awaiting_ack
            .values()
            .filter(|(_, sent)| sent.elapsed() > timeout)
            .map(|(peer, _)| peer.clone())
            .collect();
        for peer in stale {
            self.awaiting_ack.retain(|_, (p, _)| *p != peer);
            if self.connections.remove(&peer).is_some() {
                eprintln!("[securetext] {} stopped acknowledging; reconnecting", short(&peer));
                self.emit(Event::Peer { key: to_hex(&peer), online: false });
            }
            self.ensure_dial(&peer);
        }
    }

    // =====================================================================
    // Relay (Phase 5): deposit for unreachable peers, collect our own mail
    // =====================================================================

    /// (Re)build and sign our contact card from our current onion address
    /// and relay mailbox.
    fn refresh_my_card(&mut self) -> anyhow::Result<()> {
        let Some(onion) = self.my_onion.clone() else { return Ok(()) };
        let card = ContactCard {
            label: self.public.label.clone(),
            mls_public_key: self.public.public_key.clone(),
            onion_address: onion,
            noise_public_key: self.public.noise_public_key.clone(),
            relay: self.my_relay.as_ref().map(MyRelay::card),
        };
        self.my_card = Some(SignedCard::sign(card, &self.signer)?);
        Ok(())
    }

    /// A direct connection to `peer_key` just failed. If they have a relay
    /// mailbox, leave everything queued for them there instead of waiting
    /// for both of us to be online at the same time.
    fn maybe_deposit(&mut self, peer_key: &[u8]) {
        if self.relaying.contains(peer_key) || self.connections.contains_key(peer_key) {
            return;
        }
        let (Some(transport), Some(my_card)) = (self.transport.clone(), self.my_card.clone()) else { return };
        let Ok(Some(peer)) = self.store.peer(peer_key) else { return };
        let Some(relay_card) = peer.relay else { return };
        let Ok(address) = RelayAddress::parse(&relay_card.address) else { return };
        let Ok(rows) = self.store.outbox_for(peer_key) else { return };
        if rows.is_empty() {
            return;
        }

        let mut blobs = Vec::new();
        for batch in relay::batch(rows.into_iter().map(|r| (r.id, r.frame)).collect()) {
            let (ids, frames): (Vec<i64>, Vec<WireMessage>) = batch.into_iter().unzip();
            match relay::seal(&my_card, &self.signer, peer_key, &frames, &relay_card) {
                Ok(blob) => blobs.push((ids, blob)),
                Err(e) => {
                    eprintln!("[securetext] could not seal messages for the relay: {e:#}");
                    return;
                }
            }
        }

        self.relaying.insert(peer_key.to_vec());
        let net_tx = self.net_tx.clone();
        let timeout = self.timing.dial_timeout;
        let peer_key = peer_key.to_vec();
        self.tasks.spawn(async move {
            let outcome = tokio::time::timeout(timeout, async {
                let stream = transport.dial(&address.onion_address).await?;
                let requests = blobs
                    .iter()
                    .map(|(_, blob)| RelayRequest::Deposit { mailbox: relay_card.mailbox.clone(), blob: blob.clone() })
                    .collect();
                let responses = relay_client::exchange(stream, &address.noise_public_key, requests).await?;
                // Only what the relay accepted counts as delivered; the
                // rest stays queued.
                let mut delivered = Vec::new();
                let mut refused = None;
                for ((ids, _), response) in blobs.into_iter().zip(responses) {
                    match response {
                        RelayResponse::Deposited => delivered.extend(ids),
                        RelayResponse::Error { reason } => refused = Some(reason),
                        _ => refused = Some("unexpected reply".into()),
                    }
                }
                Ok::<_, anyhow::Error>((delivered, refused))
            })
            .await;
            let event = match outcome {
                Ok(Ok((delivered, None))) => NetEvent::Relayed { peer_key, outbox_ids: delivered },
                Ok(Ok((delivered, Some(reason)))) => {
                    if !delivered.is_empty() {
                        let _ = net_tx.send(NetEvent::Relayed { peer_key: peer_key.clone(), outbox_ids: delivered });
                    }
                    NetEvent::RelayDepositFailed { peer_key, error: format!("relay refused: {reason}") }
                }
                Ok(Err(e)) => NetEvent::RelayDepositFailed { peer_key, error: format!("{e:#}") },
                Err(_) => NetEvent::RelayDepositFailed { peer_key, error: "timed out".into() },
            };
            let _ = net_tx.send(event);
        });
    }

    /// Check our own mailbox, if we have one and it's time.
    fn maybe_collect(&mut self) {
        if self.collecting || self.stopping {
            return;
        }
        let (Some(transport), Some(mine)) = (self.transport.clone(), self.my_relay.clone()) else { return };
        if self.last_collect.is_some_and(|t| t.elapsed() < self.timing.relay_poll_interval) {
            return;
        }
        self.collecting = true;
        self.last_collect = Some(Instant::now());
        let net_tx = self.net_tx.clone();
        let timeout = self.timing.dial_timeout;
        self.tasks.spawn(async move {
            let outcome = tokio::time::timeout(timeout, async {
                let stream = transport.dial(&mine.address.onion_address).await?;
                let request = RelayRequest::Fetch { secret: mine.secret.clone(), limit: COLLECT_BATCH };
                let mut responses = relay_client::exchange(stream, &mine.address.noise_public_key, vec![request]).await?;
                match responses.pop() {
                    Some(RelayResponse::Blobs { items }) => Ok(items),
                    Some(RelayResponse::Error { reason }) => anyhow::bail!("relay refused: {reason}"),
                    _ => anyhow::bail!("unexpected reply from relay"),
                }
            })
            .await;
            let _ = net_tx.send(match outcome {
                Ok(Ok(items)) => NetEvent::RelayCollected { items },
                Ok(Err(e)) => NetEvent::RelayCollectFailed { error: format!("{e:#}") },
                Err(_) => NetEvent::RelayCollectFailed { error: "timed out".into() },
            });
        });
    }

    fn on_collected(&mut self, items: Vec<StoredBlob>) {
        self.collecting = false;
        let Some(mine) = self.my_relay.clone() else { return };
        if items.is_empty() {
            return;
        }
        let full_batch = items.len() as u32 >= COLLECT_BATCH;
        let ids: Vec<i64> = items.iter().map(|b| b.id).collect();
        for item in items {
            match relay::open(&item.blob, &mine, &self.public.public_key, &self.crypto) {
                Ok((card, frames)) => {
                    let from = card.card.mls_public_key.clone();
                    if from == self.public.public_key {
                        continue;
                    }
                    self.accept_card(&from, &card);
                    for frame in frames {
                        if let Err(e) = self.on_frame(&from, frame) {
                            eprintln!("[securetext] dropped a relayed frame from {}: {e:#}", short(&from));
                        }
                    }
                }
                // Junk, or sealed for an older mailbox: nothing to do but
                // clear it out.
                Err(e) => eprintln!("[securetext] discarded an unreadable relay blob: {e:#}"),
            }
        }
        self.dirty = true;

        // Everything fetched has been handled (or was unreadable), so
        // delete it from the relay. Frames already applied above are safe
        // to lose from the relay even if this ack fails: a re-delivery is
        // deduplicated (MLS rejects replays; chat ids are unique).
        let Some(transport) = self.transport.clone() else { return };
        self.tasks.spawn(async move {
            if let Ok(stream) = transport.dial(&mine.address.onion_address).await {
                let _ = relay_client::exchange(
                    stream,
                    &mine.address.noise_public_key,
                    vec![RelayRequest::Ack { secret: mine.secret.clone(), ids }],
                )
                .await;
            }
        });
        if full_batch {
            self.last_collect = None; // more waiting; collect again next tick
        }
    }

    /// Adopt a verified card presented by `from` (on a connection or in a
    /// relay envelope): remembered for a later Welcome, and applied right
    /// away if they're already known.
    fn accept_card(&mut self, from: &[u8], card: &SignedCard) {
        if let Ok(Some(existing)) = self.store.peer(from) {
            let row = PeerRow {
                mls_key: from.to_vec(),
                label: clamp_chars(&card.card.label, MAX_NAME_CHARS),
                onion_address: card.card.onion_address.clone(),
                noise_key: card.card.noise_public_key.clone(),
                is_contact: existing.is_contact,
                relay: card.card.relay.clone(),
            };
            let _ = self.store.upsert_peer(&row, Some(card));
            self.dirty = true;
        }
        self.presented_cards.insert(from.to_vec(), card.clone());
    }

    pub(crate) fn set_relay(&mut self, link: Option<&str>) -> anyhow::Result<Option<String>> {
        match link.map(str::trim).filter(|l| !l.is_empty()) {
            Some(link) => {
                let mine = MyRelay::new(link)?;
                mine.save(&self.store)?;
                self.my_relay = Some(mine);
            }
            None => {
                MyRelay::clear(&self.store)?;
                self.my_relay = None;
            }
        }
        self.dirty = true;
        self.last_collect = None;
        self.refresh_my_card()?;
        // Tell everyone we're connected to right away; others pick up the
        // new card the next time we connect to them.
        if let Some(card) = self.my_card.clone() {
            for conn in self.connections.values() {
                let _ = conn.tx.send(Outgoing { outbox_id: None, message: WireMessage::Hello { card: card.clone() } });
            }
        }
        self.maybe_collect();
        Ok(self.my_relay.as_ref().map(|r| r.link.clone()))
    }

    /// Connect to everyone we share an active conversation with, so their
    /// online status is visible and the first message doesn't pay for
    /// circuit setup (architecture.md §6: build circuits once, reuse them).
    fn presence_sweep(&mut self) {
        self.last_presence = Some(Instant::now());
        let mut keys = HashSet::new();
        for (gid, group) in &self.groups {
            if self.store.conversation(gid).ok().flatten().is_some_and(|c| !c.removed) && group.is_active() {
                for m in group.members() {
                    if m.signature_key != self.public.public_key {
                        keys.insert(m.signature_key);
                    }
                }
            }
        }
        for key in keys {
            self.ensure_dial(&key);
        }
    }

    fn ensure_dial(&mut self, peer_key: &[u8]) {
        if self.stopping || self.connections.contains_key(peer_key) || self.dialing.contains(peer_key) {
            return;
        }
        let (Some(transport), Some(my_card)) = (self.transport.clone(), self.my_card.clone()) else {
            return;
        };
        if let Some((last, attempts)) = self.backoff.get(peer_key) {
            let wait = self
                .timing
                .retry_interval
                .saturating_mul(2u32.saturating_pow((*attempts).min(10)))
                .min(MAX_BACKOFF);
            if last.elapsed() < wait {
                return;
            }
        }
        let Ok(Some(peer)) = self.store.peer(peer_key) else { return };

        self.dialing.insert(peer_key.to_vec());
        let conn_id = self.next_id();
        let net_tx = self.net_tx.clone();
        let noise_private = self.noise_private.clone();
        let timeout = self.timing.dial_timeout;
        let peer_key = peer_key.to_vec();
        self.tasks.spawn(async move {
            let attempt = tokio::time::timeout(timeout, async {
                let mut stream = transport.dial(&peer.onion_address).await?;
                let (noise, remote_static) =
                    securetext_net::handshake_initiator(&mut stream, &noise_private).await?;
                // The whole point of the Noise layer: an onion service
                // answering isn't enough, it must hold the key we expect.
                anyhow::ensure!(
                    remote_static == peer.noise_key,
                    "peer presented an unexpected Noise key; refusing the connection"
                );
                let mux = SecureMux::new(stream, noise, MuxMode::Client);
                let mut mux_stream = mux.open().await?;
                wire::write_frame(&mut mux_stream, &WireMessage::Hello { card: my_card }).await?;
                Ok::<_, anyhow::Error>((mux, mux_stream))
            })
            .await;
            match attempt {
                Ok(Ok((mux, stream))) => {
                    run_connection(mux, stream, peer_key, None, conn_id, net_tx).await;
                }
                Ok(Err(e)) => {
                    let _ = net_tx.send(NetEvent::DialFailed { peer_key, error: format!("{e:#}") });
                }
                Err(_) => {
                    let _ = net_tx.send(NetEvent::DialFailed { peer_key, error: "timed out".into() });
                }
            }
        });
    }

    fn spawn_accept(&mut self, mut stream: BoxedStream) {
        let conn_id = self.next_id();
        let net_tx = self.net_tx.clone();
        let noise_private = self.noise_private.clone();
        let timeout = self.timing.dial_timeout;
        self.tasks.spawn(async move {
            let accepted = tokio::time::timeout(timeout, async {
                let (noise, remote_static) =
                    securetext_net::handshake_responder(&mut stream, &noise_private).await?;
                let mut mux = SecureMux::new(stream, noise, MuxMode::Server);
                let mut mux_stream = mux
                    .accept()
                    .await
                    .ok_or_else(|| anyhow::anyhow!("peer closed before opening a stream"))?;
                let card = match wire::read_frame(&mut mux_stream).await? {
                    Some(WireMessage::Hello { card }) => card,
                    _ => anyhow::bail!("first frame was not a Hello"),
                };
                // Bind the connection to the card: it must be signed by
                // the MLS key it names, and name the Noise key this
                // connection actually authenticated with.
                card.verify(&RustCrypto::default())?;
                anyhow::ensure!(
                    card.card.noise_public_key == remote_static,
                    "Hello card does not match the connection's Noise key"
                );
                Ok::<_, anyhow::Error>((mux, mux_stream, card))
            })
            .await;
            if let Ok(Ok((mux, stream, card))) = accepted {
                let peer_key = card.card.mls_public_key.clone();
                run_connection(mux, stream, peer_key, Some(card), conn_id, net_tx).await;
            }
        });
    }

    fn next_id(&mut self) -> u64 {
        self.next_conn_id += 1;
        self.next_conn_id
    }

    fn on_connected(
        &mut self,
        peer_key: Vec<u8>,
        card: Option<SignedCard>,
        conn_id: u64,
        tx: mpsc::UnboundedSender<Outgoing>,
    ) {
        if peer_key == self.public.public_key {
            return; // someone replaying our own card; the Noise check makes this us, pointless
        }
        self.dialing.remove(&peer_key);
        self.backoff.remove(&peer_key);
        if let Some(card) = card {
            // A verified card from a known peer is authoritative for how
            // to reach them. Unknown peers are only remembered once they
            // send something that makes them known (a Welcome).
            self.accept_card(&peer_key, &card);
        }

        // Anything queued while they were unreachable goes out now, in order.
        if let Ok(rows) = self.store.outbox_for(&peer_key) {
            for row in rows {
                self.awaiting_ack.insert(row.id, (peer_key.clone(), Instant::now()));
                let _ = tx.send(Outgoing { outbox_id: Some(row.id), message: row.frame });
            }
        }
        self.connections.insert(peer_key.clone(), Conn { id: conn_id, tx });
        self.emit(Event::Peer { key: to_hex(&peer_key), online: true });
    }

    fn on_frame(&mut self, from: &[u8], message: WireMessage) -> anyhow::Result<()> {
        match message {
            // Mid-connection, a Hello is a card update (e.g. they changed
            // relay). It must be theirs and keep the Noise key this
            // connection was authenticated with.
            WireMessage::Hello { card } => {
                card.verify(&self.crypto)?;
                anyhow::ensure!(card.card.mls_public_key == from, "Hello card is for someone else");
                if let Some(peer) = self.store.peer(from)? {
                    anyhow::ensure!(card.card.noise_public_key == peer.noise_key, "Hello card changes the Noise key");
                }
                self.accept_card(from, &card);
                Ok(())
            }
            WireMessage::Welcome { welcome, info, roster } => self.on_welcome(from, &welcome, info, roster),
            WireMessage::Mls { group_id, message } => {
                self.on_mls(from, group_id, message, 0);
                Ok(())
            }
            WireMessage::KeyPackages { packages } => {
                anyhow::ensure!(self.store.peer(from)?.is_some(), "key packages from an unknown peer");
                let room = MAX_PEER_KEY_PACKAGES.saturating_sub(self.store.peer_key_package_count(from)?);
                for kp in packages.into_iter().take(room as usize) {
                    self.store.add_peer_key_package(from, &kp)?;
                }
                self.dirty = true;
                Ok(())
            }
            WireMessage::Tracked { id, message } => {
                if matches!(*message, WireMessage::Tracked { .. } | WireMessage::Ack { .. }) {
                    anyhow::bail!("nested tracking frame");
                }
                // Acknowledge even if processing fails: a frame we can't use
                // now won't become usable by being resent forever.
                let result = self.on_frame(from, *message);
                if let Some(conn) = self.connections.get(from) {
                    let _ = conn.tx.send(Outgoing { outbox_id: None, message: WireMessage::Ack { id } });
                }
                result
            }
            WireMessage::Ack { id } => {
                self.awaiting_ack.remove(&id);
                if let Some((msg_ref, 0)) = self.store.outbox_delivered(id, from)? {
                    self.set_message_status(&msg_ref, "sent");
                }
                self.dirty = true;
                Ok(())
            }
            WireMessage::NeedKeyPackages { count } => {
                anyhow::ensure!(self.store.peer(from)?.is_some(), "key package request from an unknown peer");
                self.send_key_packages(from, (count as usize).min(INITIAL_KEY_PACKAGES))
            }
        }
    }

    fn on_welcome(
        &mut self,
        from: &[u8],
        welcome: &[u8],
        info: ConversationInfo,
        roster: Vec<SignedCard>,
    ) -> anyhow::Result<()> {
        // A channel's Welcome can overtake its server's. Check before
        // joining: joining consumes our single-use key package, so a
        // Welcome rejected afterwards could never be retried.
        if info.kind == ConversationKind::Channel {
            let server_known = match info.server_group_id.as_deref() {
                Some(id) => self.store.conversation(id)?.is_some(),
                None => anyhow::bail!("channel without a server"),
            };
            if !server_known {
                self.pending_welcomes.retain(|p| p.received.elapsed() < PENDING_WELCOME_TTL);
                if self.pending_welcomes.len() < MAX_PENDING_WELCOMES {
                    self.pending_welcomes.push(PendingWelcome {
                        from: from.to_vec(),
                        welcome: welcome.to_vec(),
                        info,
                        roster,
                        received: Instant::now(),
                    });
                }
                return Ok(());
            }
        }
        let group = self.member.join_from_welcome(welcome)?;
        let gid = group.group_id().as_slice().to_vec();
        if self.store.conversation(&gid)?.is_some() {
            return Ok(());
        }

        // The Welcome itself is MLS-verified; the metadata riding along
        // with it is only as good as its sender. Check it's consistent:
        // the sender must be in the group, and must be its admin.
        anyhow::ensure!(
            group.members().any(|m| m.signature_key == from),
            "Welcome sender is not a member of the group"
        );
        anyhow::ensure!(info.admin_public_key == from, "Welcome sender is not the group's admin");
        if info.kind == ConversationKind::Channel {
            let server_id = info
                .server_group_id
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("channel without a server"))?;
            let server = self
                .store
                .conversation(server_id)?
                .ok_or_else(|| anyhow::anyhow!("channel for a server we're not in"))?;
            anyhow::ensure!(server.admin_key == from, "channel admin differs from server admin");
        }

        // Remember the sender first (from the card they presented on this
        // connection, or their own entry in the roster), then the rest.
        let sender_card = self
            .presented_cards
            .get(from)
            .cloned()
            .or_else(|| roster.iter().find(|c| c.card.mls_public_key == from).cloned());
        if let Some(card) = sender_card {
            self.remember_card(&card, info.kind == ConversationKind::Dm)?;
        }
        anyhow::ensure!(self.store.peer(from)?.is_some(), "no contact card for the Welcome's sender");
        for card in &roster {
            if card.card.mls_public_key != self.public.public_key && card.card.mls_public_key != from {
                if let Err(e) = self.remember_card(card, false) {
                    eprintln!("[securetext] ignored a roster card: {e:#}");
                }
            }
        }

        let mut name = info.name.clone();
        if info.kind == ConversationKind::Dm {
            if let Some(peer) = self.store.peer(from)? {
                name = peer.label;
            }
        }
        let mut row = ConversationRow::from_info(gid.clone(), &info, now_ms());
        row.name = clamp_chars(&name, MAX_NAME_CHARS);
        self.store.insert_conversation(&row)?;
        self.groups.insert(gid.clone(), group);
        self.dirty = true;

        // Top up the sender's supply of our key packages: they just used
        // one. A new DM is the start of a relationship, so give a batch.
        let count = if info.kind == ConversationKind::Dm { INITIAL_KEY_PACKAGES } else { 1 };
        self.send_key_packages(from, count)?;

        self.retry_pending(&gid);
        if info.kind == ConversationKind::Server {
            self.retry_pending_welcomes(&gid);
        }
        self.emit(Event::ConversationsChanged);
        Ok(())
    }

    fn retry_pending_welcomes(&mut self, server_gid: &[u8]) {
        let (ready, waiting): (Vec<_>, Vec<_>) = std::mem::take(&mut self.pending_welcomes)
            .into_iter()
            .partition(|p| p.info.server_group_id.as_deref() == Some(server_gid));
        self.pending_welcomes = waiting;
        for p in ready {
            if let Err(e) = self.on_welcome(&p.from, &p.welcome, p.info, p.roster) {
                eprintln!("[securetext] dropped a held channel invitation: {e:#}");
            }
        }
    }

    fn remember_card(&mut self, card: &SignedCard, is_contact: bool) -> anyhow::Result<()> {
        card.verify(&self.crypto)?;
        let row = PeerRow {
            mls_key: card.card.mls_public_key.clone(),
            label: clamp_chars(&card.card.label, MAX_NAME_CHARS),
            onion_address: card.card.onion_address.clone(),
            noise_key: card.card.noise_public_key.clone(),
            is_contact,
            relay: card.card.relay.clone(),
        };
        self.store.upsert_peer(&row, Some(card))?;
        self.dirty = true;
        Ok(())
    }

    fn on_mls(&mut self, from: &[u8], gid: Vec<u8>, message: Vec<u8>, tries: u8) {
        let Some(group) = self.groups.get_mut(&gid) else {
            // Possibly ahead of its Welcome (a different path delivered it
            // first). Hold it briefly.
            self.hold_pending(gid, from, message, tries);
            return;
        };
        match self.member.process(group, &message) {
            Ok(Incoming::Application { sender_public_key, plaintext }) => {
                self.dirty = true;
                if let Err(e) = self.on_payload(&gid, &sender_public_key, &plaintext) {
                    eprintln!("[securetext] ignored a message payload: {e:#}");
                }
            }
            Ok(Incoming::Commit { removed_self }) => {
                self.dirty = true;
                if removed_self {
                    let _ = self.store.mark_removed(&gid);
                    self.pending.remove(&gid);
                } else {
                    self.retry_pending(&gid);
                }
                self.emit(Event::ConversationsChanged);
                self.emit(Event::MembersChanged { conversation_id: to_hex(&gid) });
            }
            Ok(Incoming::Other) => {}
            // Most often: a message from an epoch we haven't reached yet.
            Err(_) => self.hold_pending(gid, from, message, tries),
        }
    }

    fn hold_pending(&mut self, gid: Vec<u8>, from: &[u8], message: Vec<u8>, tries: u8) {
        if tries >= MAX_PENDING_TRIES {
            return;
        }
        let queue = self.pending.entry(gid).or_default();
        if queue.len() < MAX_PENDING_PER_GROUP {
            queue.push(Pending { from: from.to_vec(), message, tries: tries + 1 });
        }
    }

    fn retry_pending(&mut self, gid: &[u8]) {
        let Some(queue) = self.pending.remove(gid) else { return };
        for p in queue {
            self.on_mls(&p.from, gid.to_vec(), p.message, p.tries);
        }
    }

    fn on_payload(&mut self, gid: &[u8], sender: &[u8], plaintext: &[u8]) -> anyhow::Result<()> {
        let conversation = self
            .store
            .conversation(gid)?
            .ok_or_else(|| anyhow::anyhow!("message for an unknown conversation"))?;
        match Payload::from_bytes(plaintext)? {
            Payload::Chat { id, body, sent_at } => {
                let row = MessageRow {
                    id: clamp_chars(&id, 64),
                    group_id: gid.to_vec(),
                    sender_key: sender.to_vec(),
                    body: clamp_chars(&body, MAX_MESSAGE_CHARS),
                    sent_at,
                    outgoing: false,
                    status: "received".into(),
                };
                if self.store.insert_message(&row)? {
                    let view = self.message_view(&row);
                    self.emit(Event::Message { conversation_id: to_hex(gid), message: view });
                }
            }
            Payload::Roster { cards } => {
                anyhow::ensure!(sender == conversation.admin_key, "roster update from a non-admin");
                for card in &cards {
                    if card.card.mls_public_key != self.public.public_key {
                        self.remember_card(card, false)?;
                    }
                }
                self.emit(Event::MembersChanged { conversation_id: to_hex(gid) });
            }
        }
        Ok(())
    }

    // =====================================================================
    // Sending
    // =====================================================================

    /// Queue `frame` for `peer_key`. It's persisted first, so it survives
    /// a restart; it's removed only once written to a live connection.
    fn send_frame(&mut self, peer_key: &[u8], frame: WireMessage, msg_ref: Option<&str>) -> anyhow::Result<()> {
        let id = self.store.enqueue(peer_key, &frame, msg_ref, now_ms())?;
        self.dirty = true;
        match self.connections.get(peer_key) {
            Some(conn) => {
                self.awaiting_ack.insert(id, (peer_key.to_vec(), Instant::now()));
                if conn.tx.send(Outgoing { outbox_id: Some(id), message: frame }).is_err() {
                    self.connections.remove(peer_key);
                    self.ensure_dial(peer_key);
                }
            }
            None => self.ensure_dial(peer_key),
        }
        Ok(())
    }

    fn send_key_packages(&mut self, peer_key: &[u8], count: usize) -> anyhow::Result<()> {
        let packages = (0..count)
            .map(|_| self.member.key_package_bytes())
            .collect::<Result<Vec<_>, _>>()?;
        self.send_frame(peer_key, WireMessage::KeyPackages { packages }, None)
    }

    /// Send an MLS message to every member of `gid` except us (and except
    /// `skip`). There is no server to fan out through: each member gets
    /// their own copy over their own connection.
    fn fan_out(&mut self, gid: &[u8], bytes: &[u8], skip: &[&[u8]], msg_ref: Option<&str>) -> anyhow::Result<usize> {
        let recipients: Vec<Vec<u8>> = self
            .groups
            .get(gid)
            .ok_or_else(|| anyhow::anyhow!("no such group"))?
            .members()
            .map(|m| m.signature_key)
            .filter(|k| k.as_slice() != self.my_key() && !skip.contains(&k.as_slice()))
            .collect();
        let mut sent = 0;
        for key in recipients {
            if self.store.peer(&key)?.is_none() {
                eprintln!("[securetext] no route to group member {}; skipping", short(&key));
                continue;
            }
            let frame = WireMessage::Mls { group_id: gid.to_vec(), message: bytes.to_vec() };
            self.send_frame(&key, frame, msg_ref)?;
            sent += 1;
        }
        Ok(sent)
    }

    fn set_message_status(&mut self, id: &str, status: &str) {
        if let Ok(Some(gid)) = self.store.set_message_status(id, status) {
            self.emit(Event::MessageStatus {
                conversation_id: to_hex(&gid),
                id: id.to_string(),
                status: status.to_string(),
            });
        }
    }

    // =====================================================================
    // Commands (called from the UI via `NodeHandle`)
    // =====================================================================

    pub(crate) fn status(&self) -> StatusView {
        StatusView {
            label: self.public.label.clone(),
            public_key: to_hex(&self.public.public_key),
            fingerprint: fingerprint(&self.public.public_key),
            onion_address: self.my_card.as_ref().map(|c| c.card.onion_address.clone()),
            network: self.network.clone(),
            online_peers: self.connections.len(),
            relay: self.my_relay.as_ref().map(|r| r.link.clone()),
        }
    }

    pub(crate) fn create_invite(&mut self) -> anyhow::Result<String> {
        let card = self.my_card.as_ref().ok_or_else(|| {
            anyhow::anyhow!("still connecting to Tor; an invite needs this device's onion address")
        })?;
        let invite = Invite {
            label: self.public.label.clone(),
            onion_address: card.card.onion_address.clone(),
            noise_public_key: self.public.noise_public_key.clone(),
            mls_key_package: self.member.key_package_bytes()?,
            relay: self.my_relay.as_ref().map(MyRelay::card),
        };
        self.dirty = true; // the key package's private half was just stored
        Ok(invite.to_link())
    }

    /// Accept someone's invite link: start a DM with them.
    pub(crate) fn add_contact(&mut self, link: &str) -> anyhow::Result<String> {
        let invite = Invite::from_link(link.trim())?;
        if self.my_card.as_ref().is_some_and(|c| c.card.onion_address == invite.onion_address)
            || invite.noise_public_key == self.public.noise_public_key
        {
            anyhow::bail!("that's your own invite link");
        }
        let my_card = self
            .my_card
            .clone()
            .ok_or_else(|| anyhow::anyhow!("still connecting to Tor; try again once connected"))?;

        let mut group = self.member.create_group()?;
        let (_commit, welcome) = self.member.add_member(&mut group, &invite.mls_key_package)?;
        let their_key = group
            .members()
            .map(|m| m.signature_key)
            .find(|k| k.as_slice() != self.my_key())
            .ok_or_else(|| anyhow::anyhow!("invite's key package produced no second member"))?;

        let already = self.store.conversations()?.into_iter().any(|c| {
            c.kind == ConversationKind::Dm
                && !c.removed
                && self.groups.get(&c.group_id).is_some_and(|g| g.members().any(|m| m.signature_key == their_key))
        });
        anyhow::ensure!(!already, "you already have a conversation with {}", invite.label);

        let label = clamp_chars(&invite.label, MAX_NAME_CHARS);
        self.store.upsert_peer(
            &PeerRow {
                mls_key: their_key.clone(),
                label: label.clone(),
                onion_address: invite.onion_address.clone(),
                noise_key: invite.noise_public_key.clone(),
                is_contact: true,
                relay: invite.relay.clone(),
            },
            None,
        )?;
        let gid = group.group_id().as_slice().to_vec();
        let info = ConversationInfo {
            kind: ConversationKind::Dm,
            name: label.clone(),
            server_group_id: None,
            admin_public_key: self.public.public_key.clone(),
            private: true,
        };
        self.store.insert_conversation(&ConversationRow::from_info(gid.clone(), &info, now_ms()))?;
        self.groups.insert(gid.clone(), group);

        let mut dm_info = info;
        dm_info.name = self.public.label.clone();
        self.send_frame(&their_key, WireMessage::Welcome { welcome, info: dm_info, roster: vec![my_card] }, None)?;
        self.send_key_packages(&their_key, INITIAL_KEY_PACKAGES)?;
        self.emit(Event::ConversationsChanged);
        Ok(to_hex(&gid))
    }

    pub(crate) fn conversations(&self) -> anyhow::Result<Vec<ConversationView>> {
        Ok(self
            .store
            .conversations()?
            .into_iter()
            .map(|c| ConversationView {
                id: to_hex(&c.group_id),
                kind: c.kind,
                name: c.name.clone(),
                server_id: c.server_id.as_deref().map(to_hex),
                is_admin: c.admin_key == self.public.public_key,
                private: c.private,
                removed: c.removed,
                peer_key: if c.kind == ConversationKind::Dm {
                    self.groups.get(&c.group_id).and_then(|g| {
                        g.members()
                            .map(|m| m.signature_key)
                            .find(|k| k.as_slice() != self.my_key())
                            .map(|k| to_hex(&k))
                    })
                } else {
                    None
                },
            })
            .collect())
    }

    pub(crate) fn messages(&self, conversation_id: &str, limit: u32) -> anyhow::Result<Vec<MessageView>> {
        let gid = wire::from_hex(conversation_id)?;
        Ok(self
            .store
            .messages(&gid, limit.clamp(1, 1000))?
            .iter()
            .map(|m| self.message_view(m))
            .collect())
    }

    fn message_view(&self, m: &MessageRow) -> MessageView {
        MessageView {
            id: m.id.clone(),
            sender_key: to_hex(&m.sender_key),
            sender_label: self.label_for(&m.sender_key),
            body: m.body.clone(),
            sent_at: m.sent_at,
            outgoing: m.outgoing,
            status: m.status.clone(),
        }
    }

    fn label_for(&self, key: &[u8]) -> String {
        if key == self.my_key() {
            return self.public.label.clone();
        }
        match self.store.peer(key) {
            Ok(Some(peer)) => peer.label,
            _ => format!("unknown ({})", fingerprint(key)),
        }
    }

    pub(crate) fn send_message(&mut self, conversation_id: &str, body: &str) -> anyhow::Result<MessageView> {
        let body = body.trim();
        anyhow::ensure!(!body.is_empty(), "message is empty");
        anyhow::ensure!(
            body.chars().count() <= MAX_MESSAGE_CHARS,
            "message is longer than {MAX_MESSAGE_CHARS} characters"
        );
        let gid = wire::from_hex(conversation_id)?;
        let conversation = self.active_conversation(&gid)?;
        anyhow::ensure!(conversation.kind != ConversationKind::Server, "post in one of the server's channels");

        let id = random_id();
        let sent_at = now_ms();
        let payload = Payload::Chat { id: id.clone(), body: body.to_string(), sent_at };
        let group = self.groups.get_mut(&gid).ok_or_else(|| anyhow::anyhow!("group state missing"))?;
        let ciphertext = self.member.encrypt(group, &payload.to_bytes())?;

        let row = MessageRow {
            id: id.clone(),
            group_id: gid.clone(),
            sender_key: self.public.public_key.clone(),
            body: body.to_string(),
            sent_at,
            outgoing: true,
            status: "pending".into(),
        };
        self.store.insert_message(&row)?;
        let recipients = self.fan_out(&gid, &ciphertext, &[], Some(&id))?;
        if recipients == 0 {
            self.store.set_message_status(&id, "sent")?;
        }
        self.dirty = true;
        let row = MessageRow {
            status: if recipients == 0 { "sent".into() } else { row.status },
            ..row
        };
        Ok(self.message_view(&row))
    }

    fn active_conversation(&self, gid: &[u8]) -> anyhow::Result<ConversationRow> {
        let conversation = self
            .store
            .conversation(gid)?
            .ok_or_else(|| anyhow::anyhow!("no such conversation"))?;
        anyhow::ensure!(!conversation.removed, "you are no longer a member of this conversation");
        Ok(conversation)
    }

    fn admin_server(&self, server_id: &str) -> anyhow::Result<ConversationRow> {
        let gid = wire::from_hex(server_id)?;
        let server = self.active_conversation(&gid)?;
        anyhow::ensure!(server.kind == ConversationKind::Server, "not a server");
        anyhow::ensure!(server.admin_key == self.public.public_key, "only the server's admin can do that");
        Ok(server)
    }

    pub(crate) fn create_server(&mut self, name: &str) -> anyhow::Result<String> {
        let name = validate_name(name)?;
        let group = self.member.create_group()?;
        let gid = group.group_id().as_slice().to_vec();
        let info = ConversationInfo {
            kind: ConversationKind::Server,
            name,
            server_group_id: None,
            admin_public_key: self.public.public_key.clone(),
            private: false,
        };
        self.store.insert_conversation(&ConversationRow::from_info(gid.clone(), &info, now_ms()))?;
        self.groups.insert(gid.clone(), group);
        self.dirty = true;
        self.create_channel(&to_hex(&gid), "general", false, &[])?;
        self.emit(Event::ConversationsChanged);
        Ok(to_hex(&gid))
    }

    /// Create a channel. Public channels include every server member;
    /// private ones only `member_keys` (which must be server members).
    /// Either way it's its own MLS group (architecture.md §7), so
    /// non-members are cryptographically excluded, not just hidden.
    pub(crate) fn create_channel(
        &mut self,
        server_id: &str,
        name: &str,
        private: bool,
        member_keys: &[String],
    ) -> anyhow::Result<String> {
        let server = self.admin_server(server_id)?;
        let name = validate_name(name)?;
        let server_members: Vec<Vec<u8>> = self.group_members(&server.group_id)?;
        let wanted: Vec<Vec<u8>> = if private {
            let mut keys = Vec::new();
            for hex in member_keys {
                let key = wire::from_hex(hex)?;
                anyhow::ensure!(server_members.contains(&key), "{} is not in this server", self.label_for(&key));
                if key != self.public.public_key && !keys.contains(&key) {
                    keys.push(key);
                }
            }
            keys
        } else {
            server_members.into_iter().filter(|k| k.as_slice() != self.my_key()).collect()
        };
        self.require_key_packages(&wanted, 1)?;

        let mut group = self.member.create_group()?;
        let gid = group.group_id().as_slice().to_vec();
        let info = ConversationInfo {
            kind: ConversationKind::Channel,
            name,
            server_group_id: Some(server.group_id.clone()),
            admin_public_key: self.public.public_key.clone(),
            private,
        };
        let welcome = if wanted.is_empty() {
            None
        } else {
            let kps = self.take_key_packages(&wanted)?;
            let refs: Vec<&[u8]> = kps.iter().map(Vec::as_slice).collect();
            let (_commit, welcome) = self.member.add_members(&mut group, &refs)?;
            Some(welcome)
        };
        self.store.insert_conversation(&ConversationRow::from_info(gid.clone(), &info, now_ms()))?;
        self.groups.insert(gid.clone(), group);
        if let Some(welcome) = welcome {
            let roster = self.roster_cards(&gid)?;
            for key in &wanted {
                let frame = WireMessage::Welcome { welcome: welcome.clone(), info: info.clone(), roster: roster.clone() };
                self.send_frame(key, frame, None)?;
            }
        }
        self.dirty = true;
        self.emit(Event::ConversationsChanged);
        Ok(to_hex(&gid))
    }

    /// Add a contact to a server and to each of its public channels.
    pub(crate) fn invite_to_server(&mut self, server_id: &str, peer_key_hex: &str) -> anyhow::Result<()> {
        let server = self.admin_server(server_id)?;
        let peer_key = wire::from_hex(peer_key_hex)?;
        let peer = self
            .store
            .peer(&peer_key)?
            .ok_or_else(|| anyhow::anyhow!("not one of your contacts"))?;
        anyhow::ensure!(
            !self.group_members(&server.group_id)?.contains(&peer_key),
            "{} is already in this server",
            peer.label
        );
        let new_card = self.store.peer_card(&peer_key)?.ok_or_else(|| {
            anyhow::anyhow!(
                "{} hasn't connected to you yet; once they've been online at the same time as you, try again",
                peer.label
            )
        })?;
        let public_channels: Vec<ConversationRow> = self
            .store
            .channels_of(&server.group_id)?
            .into_iter()
            .filter(|c| !c.private && !c.removed)
            .collect();
        self.require_key_packages(std::slice::from_ref(&peer_key), 1 + public_channels.len() as u32)?;

        // Server group first: existing members learn about the newcomer
        // (commit, then their card), the newcomer gets the Welcome plus
        // everyone's cards.
        self.add_to_group(&server.group_id, &peer_key, &new_card)?;
        for channel in public_channels {
            self.add_to_group(&channel.group_id, &peer_key, &new_card)?;
        }
        self.emit(Event::MembersChanged { conversation_id: to_hex(&server.group_id) });
        Ok(())
    }

    fn add_to_group(&mut self, gid: &[u8], peer_key: &[u8], new_card: &SignedCard) -> anyhow::Result<()> {
        let conversation = self.active_conversation(gid)?;
        let existing: Vec<Vec<u8>> = self.group_members(gid)?;
        let kp = self
            .store
            .take_peer_key_package(peer_key)?
            .ok_or_else(|| anyhow::anyhow!("out of key packages for this contact"))?;
        let group = self.groups.get_mut(gid).ok_or_else(|| anyhow::anyhow!("group state missing"))?;
        let (commit, welcome) = self.member.add_member(group, &kp)?;

        let me = self.public.public_key.clone();
        for key in existing.iter().filter(|k| **k != me) {
            let frame = WireMessage::Mls { group_id: gid.to_vec(), message: commit.clone() };
            self.send_frame(key, frame, None)?;
        }
        if conversation.kind == ConversationKind::Server {
            // Announce the newcomer's card inside the (new-epoch) group, so
            // existing members can reach them. Sent after the commit on
            // each connection, so it arrives after it.
            let group = self.groups.get_mut(gid).expect("checked above");
            let announcement = Payload::Roster { cards: vec![new_card.clone()] };
            let ciphertext = self.member.encrypt(group, &announcement.to_bytes())?;
            self.fan_out(gid, &ciphertext, &[peer_key], None)?;
        }

        let info = ConversationInfo {
            kind: conversation.kind,
            name: conversation.name.clone(),
            server_group_id: conversation.server_id.clone(),
            admin_public_key: conversation.admin_key.clone(),
            private: conversation.private,
        };
        let roster = self.roster_cards(gid)?;
        self.send_frame(peer_key, WireMessage::Welcome { welcome, info, roster }, None)?;
        self.dirty = true;
        Ok(())
    }

    /// Remove a member from a server and every channel of it they're in.
    pub(crate) fn kick(&mut self, server_id: &str, peer_key_hex: &str) -> anyhow::Result<()> {
        let server = self.admin_server(server_id)?;
        let peer_key = wire::from_hex(peer_key_hex)?;
        anyhow::ensure!(peer_key != self.public.public_key, "you can't remove yourself from your own server");
        anyhow::ensure!(
            self.group_members(&server.group_id)?.contains(&peer_key),
            "they're not in this server"
        );
        let mut scopes = vec![server.group_id.clone()];
        for channel in self.store.channels_of(&server.group_id)? {
            if !channel.removed && self.group_members(&channel.group_id)?.contains(&peer_key) {
                scopes.push(channel.group_id);
            }
        }
        for gid in scopes {
            let group = self.groups.get_mut(&gid).ok_or_else(|| anyhow::anyhow!("group state missing"))?;
            let commit = self.member.remove_member(group, &peer_key)?;
            // Everyone left needs the commit to move to the new epoch. The
            // removed member gets it too, so their client can show they
            // were removed. They can't read anything after it either way.
            self.fan_out(&gid, &commit, &[], None)?;
            let frame = WireMessage::Mls { group_id: gid.clone(), message: commit };
            self.send_frame(&peer_key, frame, None)?;
            self.emit(Event::MembersChanged { conversation_id: to_hex(&gid) });
        }
        self.dirty = true;
        Ok(())
    }

    pub(crate) fn members(&self, conversation_id: &str) -> anyhow::Result<Vec<MemberView>> {
        let gid = wire::from_hex(conversation_id)?;
        let conversation = self
            .store
            .conversation(&gid)?
            .ok_or_else(|| anyhow::anyhow!("no such conversation"))?;
        let mut members: Vec<MemberView> = self
            .group_members(&gid)?
            .into_iter()
            .map(|key| MemberView {
                key: to_hex(&key),
                label: self.label_for(&key),
                fingerprint: fingerprint(&key),
                is_admin: key == conversation.admin_key,
                is_me: key == self.public.public_key,
                online: key == self.public.public_key || self.connections.contains_key(&key),
            })
            .collect();
        members.sort_by(|a, b| b.is_admin.cmp(&a.is_admin).then(a.label.to_lowercase().cmp(&b.label.to_lowercase())));
        Ok(members)
    }

    pub(crate) fn contacts(&self) -> anyhow::Result<Vec<ContactView>> {
        Ok(self
            .store
            .peers()?
            .into_iter()
            .filter(|p| p.is_contact)
            .map(|p| ContactView {
                key: to_hex(&p.mls_key),
                label: p.label,
                fingerprint: fingerprint(&p.mls_key),
                online: self.connections.contains_key(&p.mls_key),
                has_card: self.store.peer_card(&p.mls_key).ok().flatten().is_some(),
            })
            .collect())
    }

    fn group_members(&self, gid: &[u8]) -> anyhow::Result<Vec<Vec<u8>>> {
        Ok(self
            .groups
            .get(gid)
            .ok_or_else(|| anyhow::anyhow!("group state missing"))?
            .members()
            .map(|m| m.signature_key)
            .collect())
    }

    fn roster_cards(&self, gid: &[u8]) -> anyhow::Result<Vec<SignedCard>> {
        let mut cards = Vec::new();
        for key in self.group_members(gid)? {
            if key == self.public.public_key {
                if let Some(card) = &self.my_card {
                    cards.push(card.clone());
                }
            } else if let Some(card) = self.store.peer_card(&key)? {
                cards.push(card);
            }
        }
        Ok(cards)
    }

    fn require_key_packages(&mut self, peers: &[Vec<u8>], each: u32) -> anyhow::Result<()> {
        let mut short_of = Vec::new();
        for key in peers {
            let have = self.store.peer_key_package_count(key)?;
            if have < each {
                short_of.push(self.label_for(key));
                let frame = WireMessage::NeedKeyPackages { count: (each - have).max(INITIAL_KEY_PACKAGES as u32) };
                self.send_frame(key, frame, None)?;
            }
        }
        anyhow::ensure!(
            short_of.is_empty(),
            "waiting on fresh keys from {}; they've been asked and will send them next time they're online, then try again",
            short_of.join(", ")
        );
        Ok(())
    }

    fn take_key_packages(&mut self, peers: &[Vec<u8>]) -> anyhow::Result<Vec<Vec<u8>>> {
        peers
            .iter()
            .map(|key| {
                self.store
                    .take_peer_key_package(key)?
                    .ok_or_else(|| anyhow::anyhow!("out of key packages for {}", self.label_for(key)))
            })
            .collect()
    }
}

/// Drive one established connection: forward every frame read to the
/// node, and write every frame the node hands us, until either side ends.
async fn run_connection(
    mut mux: SecureMux,
    stream: securetext_net::MuxStream,
    peer_key: Vec<u8>,
    card: Option<SignedCard>,
    conn_id: u64,
    net_tx: mpsc::UnboundedSender<NetEvent>,
) {
    let (tx, mut rx) = mpsc::unbounded_channel::<Outgoing>();
    if net_tx
        .send(NetEvent::Connected { peer_key: peer_key.clone(), card, conn_id, tx })
        .is_err()
    {
        return;
    }
    let (mut reader, mut writer) = tokio::io::split(stream);

    let reader_tx = net_tx.clone();
    let reader_peer = peer_key.clone();
    let mut read_task = tokio::spawn(async move {
        while let Ok(Some(message)) = wire::read_frame(&mut reader).await {
            if reader_tx.send(NetEvent::Frame { peer_key: reader_peer.clone(), message }).is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            _ = &mut read_task => break,
            outgoing = rx.recv() => {
                let Some(outgoing) = outgoing else { break };
                let frame = match outgoing.outbox_id {
                    Some(id) => WireMessage::Tracked { id, message: Box::new(outgoing.message) },
                    None => outgoing.message,
                };
                if wire::write_frame(&mut writer, &frame).await.is_err() {
                    break;
                }
            }
        }
    }
    read_task.abort();
    drop(writer);
    let _ = mux.close().await;
    let _ = net_tx.send(NetEvent::Disconnected { peer_key, conn_id });
}

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn random_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    to_hex(&bytes)
}

/// A short, human-comparable rendering of a public key. It's for telling
/// people apart at a glance, not for security verification (use the full
/// key for that).
pub fn fingerprint(key: &[u8]) -> String {
    let hex = to_hex(&key[..key.len().min(8)]);
    hex.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

fn short(key: &[u8]) -> String {
    fingerprint(key)
}

fn validate_name(name: &str) -> anyhow::Result<String> {
    let name = name.trim();
    anyhow::ensure!(!name.is_empty(), "name can't be empty");
    anyhow::ensure!(name.chars().count() <= MAX_NAME_CHARS, "name is longer than {MAX_NAME_CHARS} characters");
    Ok(name.to_string())
}

fn clamp_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A node with no network, whose outgoing frames we carry by hand.
    fn offline_node(dir: &std::path::Path, name: &str) -> NodeState {
        let (identity, public) =
            IdentityStore::create(&dir.join(format!("{name}.enc")), name, "passphrase").unwrap();
        let (events, _) = broadcast::channel(64);
        let (net_tx, _net_rx) = mpsc::unbounded_channel();
        let timing = Timing {
            retry_interval: Duration::from_secs(60),
            dial_timeout: Duration::from_secs(1),
            presence_interval: Duration::from_secs(3600),
            relay_poll_interval: Duration::from_secs(3600),
        };
        let mut node = NodeState::new(Opened { identity, public }, events, net_tx, timing).unwrap();
        node.my_onion = Some(format!("{name}.onion"));
        node.refresh_my_card().unwrap();
        node
    }

    /// Everything `from` has queued for `to`, removed from its outbox.
    fn take_frames(from: &mut NodeState, to: &NodeState) -> Vec<WireMessage> {
        let rows = from.store.outbox_for(to.my_key()).unwrap();
        for row in &rows {
            from.store.outbox_delivered(row.id, to.my_key()).unwrap();
        }
        rows.into_iter().map(|r| r.frame).collect()
    }

    fn deliver(from: &NodeState, to: &mut NodeState, frames: Vec<WireMessage>) {
        let key = from.my_key().to_vec();
        for frame in frames {
            to.on_frame(&key, frame).unwrap();
        }
    }

    #[tokio::test]
    async fn a_channel_welcome_that_overtakes_its_server_welcome_still_joins() {
        let dir = tempfile::tempdir().unwrap();
        let mut alice = offline_node(dir.path(), "alice");
        let mut bob = offline_node(dir.path(), "bob");

        // Become contacts (Bob accepts Alice's invite), shuttling frames.
        let invite = alice.create_invite().unwrap();
        bob.add_contact(&invite).unwrap();
        let frames = take_frames(&mut bob, &alice);
        deliver(&bob, &mut alice, frames);
        let frames = take_frames(&mut alice, &bob);
        deliver(&alice, &mut bob, frames);

        let server = alice.create_server("Club").unwrap();
        alice.invite_to_server(&server, &to_hex(bob.my_key())).unwrap();
        let mut frames = take_frames(&mut alice, &bob);
        let welcomes: Vec<usize> = frames
            .iter()
            .enumerate()
            .filter(|(_, f)| matches!(f, WireMessage::Welcome { .. }))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(welcomes.len(), 2, "server + #general");
        // Deliver them in the wrong order: channel first.
        frames.swap(welcomes[0], welcomes[1]);
        deliver(&alice, &mut bob, frames);

        let kinds: Vec<ConversationKind> = bob.conversations().unwrap().iter().map(|c| c.kind).collect();
        assert!(kinds.contains(&ConversationKind::Server));
        assert!(kinds.contains(&ConversationKind::Channel), "the early channel Welcome was lost: {kinds:?}");
        assert!(bob.pending_welcomes.is_empty());
    }
}
