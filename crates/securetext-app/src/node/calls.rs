//! Calls (Phase 7): signaling over the conversation's MLS group, media
//! through `securetext-call`'s relay-only engine.
//!
//! One call at a time. The caller rings the whole conversation (a DM or a
//! channel). Whoever accepts announces `Join`, and everyone already in the
//! call offers them a connection. That makes a full mesh with no media
//! server. If two people offer each other at the same moment, the offer
//! from the lower identity key wins.
//!
//! Signals go only to members connected right now (never the outbox or a
//! relay): a ring delivered hours later is worse than none.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use securetext_call::{AudioBackend, CallEngine, EngineConfig, EngineEvent, PeerStats, TurnServer};
use serde::Serialize;

use super::{now_ms, random_id, NetEvent, NodeState, Outgoing};
use crate::wire::{self, to_hex, CallSignal, ConversationKind, Payload, WireMessage};
use crate::Event;

/// Ringing gives up after this long.
const RING_TIMEOUT: Duration = Duration::from_secs(60);
/// A pair in the call that still isn't connected after this long gets
/// another try (signals are live-only, so one can be lost).
const STUCK: Duration = Duration::from_secs(10);
/// An unanswered ring is sent again this often (signals are live-only, so
/// one can be lost on a flaky link; receivers ignore repeats).
const RING_RESEND: Duration = Duration::from_secs(5);
/// A ring older than this when it arrives is ignored.
const STALE_RING_MS: i64 = 90_000;
const TURN_SETTING: &str = "turn_servers";

pub(crate) struct CallSetup {
    pub audio: Arc<dyn AudioBackend>,
    pub allow_loopback: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// We rang; nobody has joined yet.
    Outgoing,
    /// Someone is ringing us.
    Incoming,
    /// We're in the call.
    Active,
}

pub(crate) struct CallState {
    call_id: String,
    gid: Vec<u8>,
    key: Vec<u8>,
    video: bool,
    phase: Phase,
    caller: Vec<u8>,
    /// Remote participants in the call, with their connection state.
    participants: HashMap<Vec<u8>, String>,
    /// Offers we've sent that haven't been answered.
    offered: HashSet<Vec<u8>>,
    /// Offers that arrived before our engine was ready.
    queued_offers: Vec<(Vec<u8>, String)>,
    engine: Option<Arc<CallEngine>>,
    starting: bool,
    /// TURN servers the caller offered (for members without their own).
    ring_turn: Vec<TurnServer>,
    /// Which servers we're using: "yours" or "the caller's".
    turn_source: &'static str,
    started: Instant,
    muted: bool,
    /// When each not-yet-connected participant last got a (re)try.
    since: HashMap<Vec<u8>, Instant>,
    /// When we last re-announced ourselves to people who owe us an offer.
    last_nudge: Option<Instant>,
    /// Our own ring, for re-sending while nobody has answered: when it was
    /// last sent, and the original start time it carries.
    last_ring: Option<(Instant, i64)>,
}

pub(crate) enum CallNet {
    EngineReady { call_id: String, result: Result<Arc<CallEngine>, String> },
    Sdp { call_id: String, peer: Vec<u8>, offer: bool, result: Result<String, String> },
    Media { call_id: String, event: EngineEvent },
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CallParticipantView {
    pub key: String,
    pub label: String,
    /// WebRTC connection state: "joined" until media starts, then
    /// "connecting", "connected", "failed", …
    pub state: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CallView {
    pub call_id: String,
    pub conversation_id: String,
    pub conversation_name: String,
    /// "outgoing" (ringing others), "incoming" (ringing us), "active".
    pub state: String,
    pub video: bool,
    pub caller_key: String,
    pub caller_label: String,
    pub muted: bool,
    /// Whose TURN server carries our media: "yours" or "the caller's".
    pub turn: String,
    pub participants: Vec<CallParticipantView>,
}

impl NodeState {
    fn my_turn_servers(&self) -> Vec<TurnServer> {
        self.store
            .get_setting(TURN_SETTING)
            .ok()
            .flatten()
            .and_then(|json| serde_json::from_str(&json).ok())
            .unwrap_or_default()
    }

    pub(crate) fn turn_servers(&self) -> anyhow::Result<Vec<TurnServer>> {
        Ok(self.my_turn_servers())
    }

    pub(crate) fn set_turn_servers(&mut self, servers: Vec<TurnServer>) -> anyhow::Result<Vec<TurnServer>> {
        for s in &servers {
            s.validate()?;
        }
        if servers.is_empty() {
            self.store.delete_setting(TURN_SETTING)?;
        } else {
            self.store.set_setting(TURN_SETTING, &serde_json::to_string(&servers)?)?;
        }
        self.dirty = true;
        Ok(servers)
    }

    pub(crate) fn call_view(&self) -> Option<CallView> {
        let c = self.call.as_ref()?;
        let conversation = self.store.conversation(&c.gid).ok().flatten();
        let mut participants: Vec<CallParticipantView> = c
            .participants
            .iter()
            .map(|(k, state)| CallParticipantView { key: to_hex(k), label: self.label_for(k), state: state.clone() })
            .collect();
        participants.sort_by(|a, b| a.label.cmp(&b.label));
        Some(CallView {
            call_id: c.call_id.clone(),
            conversation_id: to_hex(&c.gid),
            conversation_name: conversation.map(|c| c.name).unwrap_or_default(),
            state: match c.phase {
                Phase::Outgoing => "outgoing",
                Phase::Incoming => "incoming",
                Phase::Active => "active",
            }
            .into(),
            video: c.video,
            caller_key: to_hex(&c.caller),
            caller_label: self.label_for(&c.caller),
            muted: c.muted,
            turn: c.turn_source.into(),
            participants,
        })
    }

    fn emit_call(&self, ended: Option<&str>) {
        self.emit(Event::Call { call: self.call_view(), ended: ended.map(str::to_string) });
    }

    /// Remember that a call is over here (bounded), so rings for it are
    /// ignored from now on.
    fn remember_ended(&mut self, call_id: &str) {
        if self.ended_calls.len() >= 32 {
            self.ended_calls.pop_front();
        }
        self.ended_calls.push_back(call_id.to_string());
    }

    /// Send a call signal to every member of the conversation: straight
    /// away to those connected, and to the rest if a connection comes up
    /// within a few seconds (they're dialed now). Never queued durably.
    fn send_call_signal(&mut self, gid: &[u8], call_id: &str, signal: CallSignal) -> anyhow::Result<usize> {
        let payload = Payload::Call { call_id: call_id.to_string(), signal };
        let group = self.groups.get_mut(gid).ok_or_else(|| anyhow::anyhow!("group state missing"))?;
        let ciphertext = self.member.encrypt(group, &payload.to_bytes())?;
        self.dirty = true;
        let me = self.public.public_key.clone();
        let members: Vec<Vec<u8>> = group.members().map(|m| m.signature_key).filter(|k| *k != me).collect();
        let mut sent = 0;
        for key in members {
            let frame = WireMessage::Mls { group_id: gid.to_vec(), message: ciphertext.clone() };
            match self.connections.get(&key) {
                Some(conn) => {
                    if conn.tx.send(Outgoing { outbox_id: None, message: frame }).is_ok() {
                        sent += 1;
                    }
                }
                None => {
                    self.live_pending.entry(key.clone()).or_default().push((Instant::now(), frame));
                    self.ensure_dial(&key);
                }
            }
        }
        Ok(sent)
    }

    pub(crate) fn start_call(&mut self, conversation_id: &str, video: bool) -> anyhow::Result<CallView> {
        anyhow::ensure!(self.call.is_none(), "you're already in a call");
        let gid = wire::from_hex(conversation_id)?;
        let conversation = self.active_conversation(&gid)?;
        anyhow::ensure!(conversation.kind != ConversationKind::Server, "start a call in one of the server's channels");
        self.require_here(&gid, super::perms::CONNECT, "start calls")?;
        let turn = self.my_turn_servers();
        anyhow::ensure!(
            !turn.is_empty(),
            "calls are relayed through a TURN server so nobody learns your IP address; add one in Settings → Calls first"
        );
        let online = self
            .group_members(&gid)?
            .iter()
            .filter(|k| **k != self.public.public_key && self.connections.contains_key(*k))
            .count();
        anyhow::ensure!(online > 0, "nobody in this conversation is connected right now; try again when they're online");

        let call_id = random_id();
        let key = securetext_call::crypto::CallKey::generate().to_vec();
        let started_at = now_ms();
        self.send_call_signal(
            &gid,
            &call_id,
            CallSignal::Ring { video, key: key.clone(), turn: turn.clone(), started_at },
        )?;
        self.call = Some(CallState {
            call_id,
            gid,
            key,
            video,
            phase: Phase::Outgoing,
            caller: self.public.public_key.clone(),
            participants: HashMap::new(),
            offered: HashSet::new(),
            queued_offers: Vec::new(),
            engine: None,
            starting: false,
            ring_turn: turn,
            turn_source: "yours",
            started: Instant::now(),
            muted: false,
            since: HashMap::new(),
            last_nudge: None,
            last_ring: Some((Instant::now(), started_at)),
        });
        self.start_engine();
        self.emit_call(None);
        Ok(self.call_view().expect("just set"))
    }

    pub(crate) fn accept_call(&mut self) -> anyhow::Result<CallView> {
        let own = self.my_turn_servers();
        let gid = self.call.as_ref().map(|c| c.gid.clone()).ok_or_else(|| anyhow::anyhow!("nobody is calling"))?;
        self.require_here(&gid, super::perms::CONNECT, "join calls")?;
        let c = self.call.as_mut().ok_or_else(|| anyhow::anyhow!("nobody is calling"))?;
        anyhow::ensure!(c.phase == Phase::Incoming, "nobody is calling");
        c.phase = Phase::Active;
        c.started = Instant::now();
        if own.is_empty() {
            c.turn_source = "the caller's";
        } else {
            c.ring_turn = own;
            c.turn_source = "yours";
        }
        // The caller is in the call by definition.
        let caller = c.caller.clone();
        c.participants.entry(caller).or_insert_with(|| "joined".into());
        self.start_engine();
        self.emit_call(None);
        Ok(self.call_view().expect("still set"))
    }

    pub(crate) fn decline_call(&mut self) -> anyhow::Result<()> {
        let Some(c) = self.call.take_if(|c| c.phase == Phase::Incoming) else {
            anyhow::bail!("nobody is calling");
        };
        let _ = self.send_call_signal(&c.gid, &c.call_id, CallSignal::Decline);
        self.remember_ended(&c.call_id);
        self.emit_call(Some("declined"));
        Ok(())
    }

    pub(crate) fn hang_up(&mut self) -> anyhow::Result<()> {
        let Some(c) = self.call.take() else { return Ok(()) };
        if c.phase != Phase::Incoming {
            let _ = self.send_call_signal(&c.gid, &c.call_id, CallSignal::Leave);
        }
        self.remember_ended(&c.call_id);
        close_engine(c.engine);
        self.emit_call(Some("you hung up"));
        Ok(())
    }

    fn end_call(&mut self, reason: &str) {
        if let Some(c) = self.call.take() {
            if c.phase != Phase::Incoming {
                let _ = self.send_call_signal(&c.gid, &c.call_id, CallSignal::Leave);
            }
            self.remember_ended(&c.call_id);
            close_engine(c.engine);
            self.emit_call(Some(reason));
        }
    }

    pub(crate) fn set_call_muted(&mut self, muted: bool) -> anyhow::Result<()> {
        let c = self.call.as_mut().ok_or_else(|| anyhow::anyhow!("not in a call"))?;
        c.muted = muted;
        if let Some(engine) = &c.engine {
            engine.set_muted(muted);
        }
        self.emit_call(None);
        Ok(())
    }

    pub(crate) fn heard(&self) -> Option<securetext_call::audio::Heard> {
        self.call_setup.as_ref().and_then(|s| s.audio.heard())
    }

    /// The running engine, for callers that need to await on it (video
    /// frames, stats) outside the node's task.
    pub(crate) fn call_engine(&self) -> Option<Arc<CallEngine>> {
        self.call.as_ref().filter(|c| c.phase != Phase::Incoming).and_then(|c| c.engine.clone())
    }

    fn start_engine(&mut self) {
        let Some(c) = self.call.as_mut() else { return };
        if c.starting || c.engine.is_some() {
            return;
        }
        let Some(setup) = self.call_setup.as_ref() else {
            let _ = self.net_tx.send(NetEvent::Call(CallNet::EngineReady {
                call_id: c.call_id.clone(),
                result: Err("calls aren't available in this build".into()),
            }));
            return;
        };
        c.starting = true;
        let config = EngineConfig {
            call_id: c.call_id.clone(),
            key: c.key.clone(),
            turn: c.ring_turn.clone(),
            allow_loopback: setup.allow_loopback,
        };
        let audio = setup.audio.clone();
        let call_id = c.call_id.clone();
        let net_tx = self.net_tx.clone();
        self.tasks.spawn(async move {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
            let result = CallEngine::start(config, audio, tx).await.map_err(|e| format!("{e:#}"));
            let ok = result.is_ok();
            let _ = net_tx.send(NetEvent::Call(CallNet::EngineReady { call_id: call_id.clone(), result }));
            if ok {
                while let Some(event) = rx.recv().await {
                    if net_tx.send(NetEvent::Call(CallNet::Media { call_id: call_id.clone(), event })).is_err() {
                        break;
                    }
                }
            }
        });
    }

    fn spawn_offer(&mut self, peer: Vec<u8>) {
        let Some(c) = self.call.as_mut() else { return };
        let Some(engine) = c.engine.clone() else { return };
        c.offered.insert(peer.clone());
        c.participants.insert(peer.clone(), "connecting".into());
        c.since.insert(peer.clone(), Instant::now());
        let call_id = c.call_id.clone();
        let net_tx = self.net_tx.clone();
        self.tasks.spawn(async move {
            let result = engine.offer(&to_hex(&peer)).await.map_err(|e| format!("{e:#}"));
            let _ = net_tx.send(NetEvent::Call(CallNet::Sdp { call_id, peer, offer: true, result }));
        });
    }

    fn spawn_answer(&mut self, peer: Vec<u8>, sdp: String) {
        let Some(c) = self.call.as_mut() else { return };
        let Some(engine) = c.engine.clone() else {
            c.queued_offers.push((peer, sdp));
            return;
        };
        c.participants.insert(peer.clone(), "connecting".into());
        let call_id = c.call_id.clone();
        let net_tx = self.net_tx.clone();
        self.tasks.spawn(async move {
            let result = engine.answer(&to_hex(&peer), &sdp).await.map_err(|e| format!("{e:#}"));
            let _ = net_tx.send(NetEvent::Call(CallNet::Sdp { call_id, peer, offer: false, result }));
        });
    }

    pub(crate) fn on_call_net(&mut self, event: CallNet) {
        match event {
            CallNet::EngineReady { call_id, result } => {
                let Some(c) = self.call.as_mut().filter(|c| c.call_id == call_id) else {
                    // The call ended while the engine was starting.
                    if let Ok(engine) = result {
                        close_engine(Some(engine));
                    }
                    return;
                };
                c.starting = false;
                match result {
                    Ok(engine) => {
                        engine.set_muted(c.muted);
                        c.engine = Some(engine);
                        let (gid, id, phase, caller) = (c.gid.clone(), c.call_id.clone(), c.phase, c.caller.clone());
                        let queued = std::mem::take(&mut c.queued_offers);
                        let me = self.public.public_key.clone();
                        if phase == Phase::Active && caller != me {
                            // Tell everyone we're here; they'll offer.
                            let _ = self.send_call_signal(&gid, &id, CallSignal::Join);
                        }
                        for (peer, sdp) in queued {
                            self.spawn_answer(peer, sdp);
                        }
                        // Anyone who joined while our engine was starting,
                        // and whom it's our turn to offer to (`we_offer`).
                        let waiting: Vec<Vec<u8>> = self
                            .call
                            .as_ref()
                            .map(|c| {
                                c.participants
                                    .iter()
                                    .filter(|(k, state)| state.as_str() == "joined" && we_offer(&me, &caller, k))
                                    .map(|(k, _)| k.clone())
                                    .collect()
                            })
                            .unwrap_or_default();
                        for peer in waiting {
                            self.spawn_offer(peer);
                        }
                    }
                    Err(e) => self.end_call(&format!("couldn't start the call: {e}")),
                }
                self.emit_call(None);
            }
            CallNet::Sdp { call_id, peer, offer, result } => {
                let Some(c) = self.call.as_ref().filter(|c| c.call_id == call_id) else { return };
                // An offer we gave up on (we answered theirs instead) is
                // stale; sending it would only confuse the other side.
                if offer && !c.offered.contains(&peer) {
                    return;
                }
                let gid = c.gid.clone();
                match result {
                    Ok(sdp) => {
                        let signal = if offer {
                            CallSignal::Offer { to: peer, sdp }
                        } else {
                            CallSignal::Answer { to: peer, sdp }
                        };
                        let _ = self.send_call_signal(&gid, &call_id, signal);
                    }
                    Err(e) => {
                        eprintln!("[securetext] call connection to {} failed: {e}", super::short(&peer));
                        if let Some(c) = self.call.as_mut() {
                            c.participants.insert(peer, "failed".into());
                        }
                        self.emit_call(None);
                    }
                }
            }
            CallNet::Media { call_id, event } => {
                if !self.call.as_ref().is_some_and(|c| c.call_id == call_id) {
                    return;
                }
                match event {
                    EngineEvent::PeerState { peer, state } => {
                        if let (Some(c), Ok(key)) = (self.call.as_mut(), wire::from_hex(&peer)) {
                            if c.participants.contains_key(&key) {
                                if state == "connected" {
                                    c.since.remove(&key);
                                }
                                c.participants.insert(key, state);
                            }
                        }
                        self.emit_call(None);
                    }
                    EngineEvent::VideoFrame { peer, jpeg } => {
                        self.emit(Event::CallVideo {
                            peer_key: peer,
                            jpeg: base64::engine::general_purpose::STANDARD.encode(jpeg),
                        });
                    }
                }
            }
        }
    }

    /// A call signal from `sender` in conversation `gid` (already
    /// decrypted and authenticated by MLS).
    pub(crate) fn on_call_signal(&mut self, gid: &[u8], sender: &[u8], call_id: String, signal: CallSignal) {
        let me = self.public.public_key.clone();
        if sender == me {
            return;
        }
        let ours = self.call.as_ref().is_some_and(|c| c.call_id == call_id && c.gid == gid);
        match signal {
            CallSignal::Ring { video, key, turn, started_at } => {
                if self.call.is_some()
                    || self.ended_calls.contains(&call_id)
                    || now_ms() - started_at > STALE_RING_MS
                    || key.len() != 32
                {
                    return; // busy, already over here, stale, or malformed
                }
                let removed = self.store.conversation(gid).ok().flatten().is_none_or(|c| c.removed);
                // Rings from someone not allowed to call here are ignored.
                if removed || self.permissions_here(gid, sender) & super::perms::CONNECT == 0 {
                    return;
                }
                self.call = Some(CallState {
                    call_id,
                    gid: gid.to_vec(),
                    key,
                    video,
                    phase: Phase::Incoming,
                    caller: sender.to_vec(),
                    participants: HashMap::new(),
                    offered: HashSet::new(),
                    queued_offers: Vec::new(),
                    engine: None,
                    starting: false,
                    ring_turn: turn.into_iter().filter(|t| t.validate().is_ok()).take(4).collect(),
                    turn_source: "the caller's",
                    started: Instant::now(),
                    muted: false,
                    since: HashMap::new(),
                    last_nudge: None,
                    last_ring: None,
                });
                self.emit_call(None);
            }
            _ if !ours => {}
            CallSignal::Join => {
                let c = self.call.as_mut().expect("ours");
                c.participants.entry(sender.to_vec()).or_insert_with(|| "joined".into());
                c.since.entry(sender.to_vec()).or_insert_with(Instant::now);
                if c.phase == Phase::Outgoing {
                    c.phase = Phase::Active;
                }
                // Offer the newcomer a connection if it's our turn
                // (`we_offer`), once our engine is up; until then the join
                // is remembered and offered to when it is.
                // A repeated Join (a retry) must not disturb a connection
                // that's up or being set up.
                let settled = c.participants.get(sender).is_some_and(|st| st == "connected" || st == "connecting");
                if c.phase == Phase::Active
                    && c.engine.is_some()
                    && !settled
                    && !c.offered.contains(sender)
                    && we_offer(&me, &c.caller, sender)
                {
                    self.spawn_offer(sender.to_vec());
                }
                self.emit_call(None);
            }
            CallSignal::Offer { to, sdp } if to == me => {
                let c = self.call.as_mut().expect("ours");
                if c.phase == Phase::Incoming {
                    return; // not accepted
                }
                // `we_offer` means this shouldn't happen, but if both sides
                // did offer (say, mixed versions), the lower key's offer wins.
                if c.offered.contains(sender) {
                    if me.as_slice() < sender {
                        return;
                    }
                    c.offered.remove(sender);
                }
                self.spawn_answer(sender.to_vec(), sdp);
                self.emit_call(None);
            }
            CallSignal::Answer { to, sdp } if to == me => {
                let c = self.call.as_mut().expect("ours");
                if !c.offered.remove(sender) {
                    return;
                }
                if let Some(engine) = c.engine.clone() {
                    let peer = to_hex(sender);
                    self.tasks.spawn(async move {
                        if let Err(e) = engine.accept_answer(&peer, &sdp).await {
                            eprintln!("[securetext] call answer rejected: {e:#}");
                        }
                    });
                }
            }
            CallSignal::Offer { .. } | CallSignal::Answer { .. } => {}
            CallSignal::Leave | CallSignal::Decline => {
                let c = self.call.as_mut().expect("ours");
                if c.phase == Phase::Incoming {
                    if sender == c.caller {
                        let id = c.call_id.clone();
                        self.call = None;
                        self.remember_ended(&id);
                        self.emit_call(Some("missed call"));
                    }
                    return;
                }
                c.participants.remove(sender);
                c.offered.remove(sender);
                if let Some(engine) = c.engine.clone() {
                    let peer = to_hex(sender);
                    tokio::spawn(async move { engine.remove_peer(&peer).await });
                }
                let is_dm = self.store.conversation(gid).ok().flatten().is_some_and(|c| c.kind == ConversationKind::Dm);
                let empty = self.call.as_ref().is_some_and(|c| c.participants.is_empty() && c.phase == Phase::Active);
                if is_dm || empty {
                    let label = self.label_for(sender);
                    let reason = if matches!(signal, CallSignal::Decline) {
                        format!("{label} declined")
                    } else {
                        format!("{label} hung up")
                    };
                    self.end_call(&reason);
                } else {
                    self.emit_call(None);
                }
            }
        }
    }

    /// Called from the node's tick: ringing times out, and pairs that
    /// haven't connected get another try.
    pub(crate) fn call_tick(&mut self) {
        self.retry_stuck_pairs();
        self.resend_ring();
        let Some(c) = &self.call else { return };
        if c.started.elapsed() < RING_TIMEOUT {
            return;
        }
        match c.phase {
            Phase::Outgoing => self.end_call("no answer"),
            Phase::Incoming => {
                let id = c.call_id.clone();
                self.call = None;
                self.remember_ended(&id);
                self.emit_call(Some("missed call"));
            }
            Phase::Active => {}
        }
    }
}

/// Which side of a pair starts their connection, so exactly one does and
/// two offers never cross: the caller offers to everyone who joins, and
/// between two others, the lower identity key offers. (If offers crossed,
/// one side's late-finishing offer could replace the connection it had
/// just answered on, leaving the pair stuck. The CI test found this on a
/// slow runner.)
fn we_offer(me: &[u8], caller: &[u8], peer: &[u8]) -> bool {
    me == caller || (peer != caller && me < peer)
}

impl NodeState {
    /// While a call we started is still ringing, ring again every
    /// `RING_RESEND`, in case the first one was lost.
    fn resend_ring(&mut self) {
        let Some(c) = self.call.as_mut() else { return };
        if c.phase != Phase::Outgoing {
            return;
        }
        let Some((sent, started_at)) = c.last_ring else { return };
        if sent.elapsed() < RING_RESEND {
            return;
        }
        c.last_ring = Some((Instant::now(), started_at));
        let signal = CallSignal::Ring { video: c.video, key: c.key.clone(), turn: c.ring_turn.clone(), started_at };
        let (gid, id) = (c.gid.clone(), c.call_id.clone());
        let _ = self.send_call_signal(&gid, &id, signal);
    }

    /// Call signals are live-only, so on a flaky link one can be lost and
    /// leave a pair of participants unconnected. After `STUCK`, whoever
    /// offers for that pair offers again (replacing any half-built
    /// connection), and whoever waits re-announces its Join so the other
    /// side knows to.
    fn retry_stuck_pairs(&mut self) {
        let me = self.public.public_key.clone();
        let Some(c) = self.call.as_mut() else { return };
        if c.phase != Phase::Active || c.engine.is_none() {
            return;
        }
        let stuck: Vec<Vec<u8>> = c
            .participants
            .iter()
            .filter(|(k, state)| state.as_str() != "connected" && c.since.get(*k).is_none_or(|t| t.elapsed() > STUCK))
            .map(|(k, _)| k.clone())
            .collect();
        let caller = c.caller.clone();
        let mut nudge = false;
        for peer in stuck {
            if we_offer(&me, &caller, &peer) {
                if let Some(c) = self.call.as_mut() {
                    c.offered.remove(&peer);
                }
                self.spawn_offer(peer);
            } else {
                nudge = true;
                if let Some(c) = self.call.as_mut() {
                    c.since.insert(peer, Instant::now());
                }
            }
        }
        let Some(c) = self.call.as_mut() else { return };
        if nudge && c.last_nudge.is_none_or(|t| t.elapsed() > STUCK) {
            c.last_nudge = Some(Instant::now());
            let (gid, id) = (c.gid.clone(), c.call_id.clone());
            let _ = self.send_call_signal(&gid, &id, CallSignal::Join);
        }
    }
}

fn close_engine(engine: Option<Arc<CallEngine>>) {
    if let Some(engine) = engine {
        tokio::spawn(async move { engine.close().await });
    }
}

/// Stats for the UI and tests: how each participant's media is carried.
pub async fn stats(engine: Option<Arc<CallEngine>>) -> Vec<PeerStats> {
    match engine {
        Some(engine) => engine.stats().await,
        None => Vec::new(),
    }
}
