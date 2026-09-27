//! Two call engines talking through a real TURN server on loopback: the
//! whole media path (capture → Opus → call-key seal → SRTP → TURN relay →
//! unseal → decode → mix) with synthetic tones, so what comes out the far
//! end can be checked, not just that "something connected".

use std::sync::Arc;
use std::time::Duration;

use securetext_call::audio::dominant_frequency;
use securetext_call::crypto::CallKey;
use securetext_call::engine::check_relay_only;
use securetext_call::{turn_server, CallEngine, EngineConfig, EngineEvent, ToneBackend, TurnServer};
use tokio::sync::mpsc;

async fn turn() -> (turn_server::TurnHandle, TurnServer) {
    let users = vec![("alice".to_string(), "correct horse battery".to_string())];
    let server = turn_server::start("127.0.0.1:0".parse().unwrap(), "127.0.0.1".parse().unwrap(), &users)
        .await
        .unwrap();
    let t = TurnServer {
        url: format!("turn:127.0.0.1:{}", server.listen.port()),
        username: "alice".into(),
        credential: "correct horse battery".into(),
    };
    (server, t)
}

async fn engine(
    key: &[u8],
    turn: &TurnServer,
    tone: f32,
) -> (Arc<CallEngine>, Arc<ToneBackend>, mpsc::UnboundedReceiver<EngineEvent>) {
    let backend = Arc::new(ToneBackend::new(tone));
    let (tx, rx) = mpsc::unbounded_channel();
    let e = CallEngine::start(
        EngineConfig { call_id: "call-1".into(), key: key.to_vec(), turn: vec![turn.clone()], allow_loopback: true },
        backend.clone(),
        tx,
    )
    .await
    .unwrap();
    (e, backend, rx)
}

async fn connect(a: &Arc<CallEngine>, b: &Arc<CallEngine>) -> (String, String) {
    let offer = a.offer("b").await.unwrap();
    let answer = b.answer("a", &offer).await.unwrap();
    a.accept_answer("b", &answer).await.unwrap();
    (offer, answer)
}

async fn wait_connected(e: &Arc<CallEngine>) {
    for _ in 0..200 {
        if e.stats().await.iter().all(|s| s.state == "connected") && !e.stats().await.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("never connected: {:?}", e.stats().await);
}

fn heard(backend: &ToneBackend) -> Option<f32> {
    let played = backend.played.lock().unwrap();
    // The last second: after connection setup, in steady state.
    let tail = &played[played.len().saturating_sub(48_000)..];
    dominant_frequency(tail)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relayed_call_carries_both_voices_and_video_end_to_end() {
    let (server, t) = turn().await;
    let key = CallKey::generate();
    let (a, a_audio, _a_events) = engine(&key, &t, 440.0).await;
    let (b, b_audio, mut b_events) = engine(&key, &t, 660.0).await;

    let (offer, answer) = connect(&a, &b).await;
    // Neither side's description offers anything but the relay.
    check_relay_only(&offer).unwrap();
    check_relay_only(&answer).unwrap();
    assert!(!offer.contains("typ host") && !answer.contains("typ host"));

    wait_connected(&a).await;
    wait_connected(&b).await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Each hears the other's tone (not their own, not silence).
    let a_heard = heard(&a_audio).expect("Alice hears something");
    let b_heard = heard(&b_audio).expect("Bob hears something");
    assert!((a_heard - 660.0).abs() < 25.0, "Alice heard {a_heard} Hz");
    assert!((b_heard - 440.0).abs() < 25.0, "Bob heard {b_heard} Hz");

    // WebRTC's own view: both ends of the pair in use are relay candidates.
    for s in a.stats().await.into_iter().chain(b.stats().await) {
        assert_eq!((s.local_candidate.as_str(), s.remote_candidate.as_str()), ("relay", "relay"), "{s:?}");
        assert!(s.bytes_sent > 10_000 && s.bytes_received > 10_000, "{s:?}");
    }

    // Video frames arrive intact.
    let frame = b"\xff\xd8pretend-jpeg\xff\xd9".to_vec();
    let mut got = None;
    for _ in 0..50 {
        a.send_video(&frame).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        while let Ok(ev) = b_events.try_recv() {
            if let EngineEvent::VideoFrame { peer, jpeg } = ev {
                got = Some((peer, jpeg));
            }
        }
        if got.is_some() {
            break;
        }
    }
    assert_eq!(got, Some(("a".to_string(), frame)));

    // Mute sends silence.
    a.set_muted(true);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(heard(&b_audio), None, "muted audio should be silence");

    a.close().await;
    b.close().await;
    server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_participant_without_the_call_key_hears_nothing() {
    // DTLS connects them fine (as it would for anyone given the SDP), but
    // media sealed under the call key doesn't open without it.
    let (server, t) = turn().await;
    let (a, _a_audio, _) = engine(&CallKey::generate(), &t, 440.0).await;
    let (b, b_audio, _) = engine(&CallKey::generate(), &t, 660.0).await;
    connect(&a, &b).await;
    wait_connected(&b).await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(heard(&b_audio), None, "audio under another key must not play");
    a.close().await;
    b.close().await;
    server.close().await;
}

#[tokio::test]
async fn no_turn_server_means_no_call() {
    let (tx, _rx) = mpsc::unbounded_channel();
    let err = CallEngine::start(
        EngineConfig { call_id: "c".into(), key: CallKey::generate().to_vec(), turn: vec![], allow_loopback: false },
        Arc::new(ToneBackend::new(440.0)),
        tx,
    )
    .await
    .err()
    .expect("refused");
    assert!(err.to_string().contains("TURN"), "{err}");
}
