//! One call from this device's side: a WebRTC peer connection per other
//! participant (a small mesh; there is no media server), all forced through
//! TURN relays.
//!
//! The anonymity trade-off is disclosed to the user before any call
//! (threat-model.md): calls don't go over Tor. Forced relay limits who
//! learns what. Every connection uses `iceTransportPolicy = relay`, so
//! this device never offers its own addresses (no host, server-reflexive,
//! or mDNS candidates), and an SDP carrying anything but relay candidates
//! is refused before it's sent. Other participants only ever see a TURN
//! server's address, never this device's IP. The TURN operator does see
//! the IP; that's the accepted exposure (architecture.md §9).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::{MediaEngine, MIME_TYPE_OPUS};
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::{APIBuilder, API};
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::media::Sample;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::stats::StatsReportType;
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;

use crate::audio::{AudioBackend, Mixer, OpusDecoder, OpusEncoder, SharedMixer, FRAME, SAMPLE_RATE};
use crate::crypto::{CallKey, MediaKind};

/// Largest video frame accepted (a JPEG from the sender's webview).
pub const MAX_VIDEO_FRAME: usize = 60 * 1024;
const GATHER_TIMEOUT: Duration = Duration::from_secs(20);

/// A TURN server to relay media through.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TurnServer {
    /// `turn:host:port` (UDP) or `turn:host:port?transport=tcp`.
    pub url: String,
    pub username: String,
    pub credential: String,
}

impl TurnServer {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.url.starts_with("turn:") || self.url.starts_with("turns:"),
            "a TURN server address starts with turn: (for example turn:turn.example.org:3478)"
        );
        anyhow::ensure!(!self.username.is_empty() && !self.credential.is_empty(), "a TURN server needs a username and password");
        webrtc::ice::url::Url::parse_url(&self.url).map_err(|e| anyhow::anyhow!("invalid TURN address: {e}"))?;
        Ok(())
    }
}

pub struct EngineConfig {
    pub call_id: String,
    pub key: Vec<u8>,
    pub turn: Vec<TurnServer>,
    /// Tests run their TURN server on 127.0.0.1.
    pub allow_loopback: bool,
}

#[derive(Clone, Debug)]
pub enum EngineEvent {
    PeerState { peer: String, state: String },
    VideoFrame { peer: String, jpeg: Vec<u8> },
}

/// How a peer connection is actually carried, from WebRTC's own stats:
/// the evidence that media went through a relay.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct PeerStats {
    pub peer: String,
    pub state: String,
    pub local_candidate: String,
    pub remote_candidate: String,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

struct PeerEntry {
    pc: Arc<RTCPeerConnection>,
    video: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
}

pub struct CallEngine {
    api: API,
    config: RTCConfiguration,
    key: CallKey,
    audio_track: Arc<TrackLocalStaticSample>,
    peers: tokio::sync::Mutex<HashMap<String, PeerEntry>>,
    mixer: SharedMixer,
    muted: Arc<AtomicBool>,
    events: mpsc::UnboundedSender<EngineEvent>,
    _audio: Mutex<Option<Box<dyn Send>>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl CallEngine {
    pub async fn start(
        config: EngineConfig,
        audio: Arc<dyn AudioBackend>,
        events: mpsc::UnboundedSender<EngineEvent>,
    ) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!(!config.turn.is_empty(), "calls need a TURN server to relay through (Settings → Calls)");
        for t in &config.turn {
            t.validate()?;
        }
        let key = CallKey::new(&config.key, &config.call_id)?;

        let mut media = MediaEngine::default();
        media.register_default_codecs()?;
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media)?;
        let mut settings = SettingEngine::default();
        // Never announce local addresses by mDNS either.
        settings.set_ice_multicast_dns_mode(webrtc::ice::mdns::MulticastDnsMode::Disabled);
        if config.allow_loopback {
            settings.set_include_loopback_candidate(true);
        }
        let api = APIBuilder::new()
            .with_media_engine(media)
            .with_interceptor_registry(registry)
            .with_setting_engine(settings)
            .build();
        let rtc_config = RTCConfiguration {
            ice_servers: config
                .turn
                .iter()
                .map(|t| RTCIceServer { urls: vec![t.url.clone()], username: t.username.clone(), credential: t.credential.clone() })
                .collect(),
            ice_transport_policy: RTCIceTransportPolicy::Relay,
            ..Default::default()
        };

        let audio_track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability { mime_type: MIME_TYPE_OPUS.to_owned(), ..Default::default() },
            "audio".to_owned(),
            "securetext".to_owned(),
        ));
        let mixer: SharedMixer = Arc::new(Mutex::new(Mixer::default()));
        let engine = Arc::new(Self {
            api,
            config: rtc_config,
            key,
            audio_track,
            peers: tokio::sync::Mutex::new(HashMap::new()),
            mixer: mixer.clone(),
            muted: Arc::new(AtomicBool::new(false)),
            events,
            _audio: Mutex::new(None),
            tasks: Mutex::new(Vec::new()),
        });

        // Microphone → Opus → seal → the shared outgoing track (one track,
        // bound to every peer connection).
        let (capture_tx, mut capture_rx) = mpsc::channel::<Vec<i16>>(16);
        *engine._audio.lock().unwrap() = Some(audio.start(capture_tx, mixer)?);
        let sender = engine.clone();
        let task = tokio::spawn(async move {
            let Ok(mut encoder) = OpusEncoder::new() else { return };
            let silence = vec![0i16; FRAME];
            while let Some(frame) = capture_rx.recv().await {
                let frame = if sender.muted.load(Ordering::Relaxed) { &silence } else { &frame };
                let Ok(packet) = encoder.encode(frame) else { continue };
                let sealed = sender.key.seal(MediaKind::Audio, &packet);
                let sample = Sample {
                    data: Bytes::from(sealed),
                    duration: Duration::from_millis(1000 * FRAME as u64 / SAMPLE_RATE as u64),
                    ..Default::default()
                };
                let _ = sender.audio_track.write_sample(&sample).await;
            }
        });
        engine.tasks.lock().unwrap().push(task);
        Ok(engine)
    }

    async fn new_peer(self: &Arc<Self>, peer: &str) -> anyhow::Result<Arc<RTCPeerConnection>> {
        let pc = Arc::new(self.api.new_peer_connection(self.config.clone()).await?);
        pc.add_track(self.audio_track.clone() as Arc<dyn TrackLocal + Send + Sync>).await?;

        // Their audio: unseal → decode → mixer.
        let engine = Arc::downgrade(self);
        let name = peer.to_string();
        pc.on_track(Box::new(move |track, _, _| {
            let engine = engine.clone();
            let name = name.clone();
            Box::pin(async move {
                let task = tokio::spawn(async move {
                    let Ok(mut decoder) = OpusDecoder::new() else { return };
                    while let Ok((packet, _)) = track.read_rtp().await {
                        let Some(engine) = engine.upgrade() else { return };
                        // Anything that doesn't authenticate under the call
                        // key is dropped, whatever DTLS thought of it.
                        let Ok(opus) = engine.key.open(MediaKind::Audio, &packet.payload) else { continue };
                        if let Ok(pcm) = decoder.decode(&opus) {
                            engine.mixer.lock().unwrap().push(&name, &pcm);
                        }
                    }
                });
                drop(task);
            })
        }));

        let events = self.events.clone();
        let name = peer.to_string();
        pc.on_peer_connection_state_change(Box::new(move |state: RTCPeerConnectionState| {
            let _ = events.send(EngineEvent::PeerState { peer: name.clone(), state: state.to_string() });
            Box::pin(async {})
        }));
        Ok(pc)
    }

    fn wire_video(self: &Arc<Self>, peer: &str, dc: Arc<RTCDataChannel>) {
        let engine = Arc::downgrade(self);
        let name = peer.to_string();
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            if let Some(engine) = engine.upgrade() {
                if msg.data.len() <= MAX_VIDEO_FRAME + 64 {
                    if let Ok(jpeg) = engine.key.open(MediaKind::Video, &msg.data) {
                        let _ = engine.events.send(EngineEvent::VideoFrame { peer: name.clone(), jpeg });
                    }
                }
            }
            Box::pin(async {})
        }));
    }

    /// Start a connection to `peer`: returns the offer SDP to send them
    /// (complete, with relay candidates only; no trickle).
    pub async fn offer(self: &Arc<Self>, peer: &str) -> anyhow::Result<String> {
        self.remove_peer(peer).await;
        let pc = self.new_peer(peer).await?;
        let dc = pc
            .create_data_channel(
                "video",
                Some(RTCDataChannelInit { ordered: Some(false), max_retransmits: Some(0), ..Default::default() }),
            )
            .await?;
        self.wire_video(peer, dc.clone());
        let offer = pc.create_offer(None).await?;
        let mut gathered = pc.gathering_complete_promise().await;
        pc.set_local_description(offer).await?;
        let _ = tokio::time::timeout(GATHER_TIMEOUT, gathered.recv()).await;
        let sdp = pc.local_description().await.ok_or_else(|| anyhow::anyhow!("no local description"))?.sdp;
        check_relay_only(&sdp)?;
        self.peers
            .lock()
            .await
            .insert(peer.to_string(), PeerEntry { pc, video: Arc::new(Mutex::new(Some(dc))) });
        Ok(sdp)
    }

    /// Answer `peer`'s offer: returns the answer SDP to send back.
    pub async fn answer(self: &Arc<Self>, peer: &str, offer_sdp: &str) -> anyhow::Result<String> {
        self.remove_peer(peer).await;
        let pc = self.new_peer(peer).await?;
        let video = Arc::new(Mutex::new(None));
        let slot = video.clone();
        let engine = Arc::downgrade(self);
        let name = peer.to_string();
        pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
            if let Some(engine) = engine.upgrade() {
                engine.wire_video(&name, dc.clone());
            }
            *slot.lock().unwrap() = Some(dc);
            Box::pin(async {})
        }));
        pc.set_remote_description(RTCSessionDescription::offer(offer_sdp.to_string())?).await?;
        let answer = pc.create_answer(None).await?;
        let mut gathered = pc.gathering_complete_promise().await;
        pc.set_local_description(answer).await?;
        let _ = tokio::time::timeout(GATHER_TIMEOUT, gathered.recv()).await;
        let sdp = pc.local_description().await.ok_or_else(|| anyhow::anyhow!("no local description"))?.sdp;
        check_relay_only(&sdp)?;
        self.peers.lock().await.insert(peer.to_string(), PeerEntry { pc, video });
        Ok(sdp)
    }

    pub async fn accept_answer(&self, peer: &str, answer_sdp: &str) -> anyhow::Result<()> {
        let peers = self.peers.lock().await;
        let entry = peers.get(peer).ok_or_else(|| anyhow::anyhow!("no pending offer to that participant"))?;
        entry.pc.set_remote_description(RTCSessionDescription::answer(answer_sdp.to_string())?).await?;
        Ok(())
    }

    pub async fn has_peer(&self, peer: &str) -> bool {
        self.peers.lock().await.contains_key(peer)
    }

    pub async fn remove_peer(&self, peer: &str) {
        if let Some(entry) = self.peers.lock().await.remove(peer) {
            let _ = entry.pc.close().await;
        }
        self.mixer.lock().unwrap().remove(peer);
    }

    pub fn set_muted(&self, muted: bool) {
        self.muted.store(muted, Ordering::Relaxed);
    }

    /// Send one camera frame (a JPEG) to everyone, sealed with the call key.
    pub async fn send_video(&self, jpeg: &[u8]) -> anyhow::Result<()> {
        anyhow::ensure!(jpeg.len() <= MAX_VIDEO_FRAME, "video frame too large");
        let sealed = Bytes::from(self.key.seal(MediaKind::Video, jpeg));
        let channels: Vec<Arc<RTCDataChannel>> = self
            .peers
            .lock()
            .await
            .values()
            .filter_map(|p| p.video.lock().unwrap().clone())
            .collect();
        for dc in channels {
            let _ = dc.send(&sealed).await;
        }
        Ok(())
    }

    /// Per-peer transport facts from WebRTC's stats: connection state, the
    /// candidate types actually in use, and byte counts.
    pub async fn stats(&self) -> Vec<PeerStats> {
        let peers: Vec<(String, Arc<RTCPeerConnection>)> =
            self.peers.lock().await.iter().map(|(k, v)| (k.clone(), v.pc.clone())).collect();
        let mut out = Vec::new();
        for (peer, pc) in peers {
            let report = pc.get_stats().await;
            let mut s = PeerStats {
                peer,
                state: pc.connection_state().to_string(),
                local_candidate: String::new(),
                remote_candidate: String::new(),
                bytes_sent: 0,
                bytes_received: 0,
            };
            let candidate_type = |id: &str| match report.reports.get(id) {
                Some(StatsReportType::LocalCandidate(c)) | Some(StatsReportType::RemoteCandidate(c)) => {
                    c.candidate_type.to_string()
                }
                _ => String::new(),
            };
            for r in report.reports.values() {
                match r {
                    StatsReportType::CandidatePair(pair) if pair.nominated || s.local_candidate.is_empty() => {
                        s.local_candidate = candidate_type(&pair.local_candidate_id);
                        s.remote_candidate = candidate_type(&pair.remote_candidate_id);
                    }
                    // Candidate-pair byte counters aren't filled in by
                    // webrtc-rs; the ICE transport's are.
                    StatsReportType::Transport(t) => {
                        s.bytes_sent += t.bytes_sent as u64;
                        s.bytes_received += t.bytes_received as u64;
                    }
                    _ => {}
                }
            }
            out.push(s);
        }
        out
    }

    pub async fn close(&self) {
        let peers: Vec<PeerEntry> = self.peers.lock().await.drain().map(|(_, v)| v).collect();
        for p in peers {
            let _ = p.pc.close().await;
        }
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
        *self._audio.lock().unwrap() = None;
    }
}

/// Refuse to hand out an SDP that offers anything but relay candidates.
/// The relay-only ICE policy should already guarantee this; checking the
/// actual text means a WebRTC bug or misconfiguration fails closed instead
/// of leaking this device's address to the other side.
pub fn check_relay_only(sdp: &str) -> anyhow::Result<()> {
    let candidates: Vec<&str> = sdp.lines().filter(|l| l.starts_with("a=candidate:")).collect();
    anyhow::ensure!(!candidates.is_empty(), "couldn't get a relay allocation from the TURN server");
    for c in &candidates {
        anyhow::ensure!(c.contains(" typ relay"), "refusing to send a non-relay ICE candidate");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_relay_candidates_may_leave_the_device() {
        let relay = "v=0\r\na=candidate:1 1 udp 16777215 203.0.113.5 50000 typ relay raddr 0.0.0.0 rport 0\r\n";
        check_relay_only(relay).unwrap();
        let host = format!("{relay}a=candidate:2 1 udp 2130706431 192.168.1.20 40000 typ host\r\n");
        assert!(check_relay_only(&host).is_err());
        let srflx = format!("{relay}a=candidate:3 1 udp 1694498815 198.51.100.7 40000 typ srflx raddr 192.168.1.20 rport 40000\r\n");
        assert!(check_relay_only(&srflx).is_err());
        assert!(check_relay_only("v=0\r\n").is_err(), "no allocation at all");
    }

    #[test]
    fn turn_addresses_are_validated() {
        let ok = TurnServer { url: "turn:turn.example.org:3478".into(), username: "u".into(), credential: "p".into() };
        ok.validate().unwrap();
        assert!(TurnServer { url: "stun:stun.example.org:3478".into(), ..ok.clone() }.validate().is_err());
        assert!(TurnServer { credential: String::new(), ..ok }.validate().is_err());
    }
}
