//! Calls through running nodes (Phase 7): signaling over the real MLS
//! groups on the in-memory network, media through a real TURN server on
//! loopback, synthetic tones for audio. What each person hears is checked
//! by frequency, so "connected" isn't mistaken for "working".

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::*;
use securetext_app::call::audio::SAMPLE_RATE;
use securetext_app::call::{turn_server, ToneBackend, TurnServer};

struct Caller {
    node: NodeHandle,
    audio: Arc<ToneBackend>,
}

async fn start_with_tone(dir: &std::path::Path, name: &str, net: &MemoryNetwork, tone: f32) -> Caller {
    let audio = Arc::new(ToneBackend::new(tone));
    let mut cfg = config(dir, name, net);
    cfg.call_audio = Some(audio.clone());
    cfg.call_allow_loopback = true;
    Caller { node: NodeHandle::start(cfg).await.unwrap(), audio }
}

async fn turn() -> (turn_server::TurnHandle, TurnServer) {
    let users = vec![("turnuser".to_string(), "turn password 123".to_string())];
    let server = turn_server::start("127.0.0.1:0".parse().unwrap(), "127.0.0.1".parse().unwrap(), &users)
        .await
        .unwrap();
    let t = TurnServer {
        url: format!("turn:127.0.0.1:{}", server.listen.port()),
        username: "turnuser".into(),
        credential: "turn password 123".into(),
    };
    (server, t)
}

/// Energy at `freq` relative to the signal's total energy (Goertzel), over
/// the last second of what someone heard. A mix of several tones shows up
/// as a clear share at each of them.
fn share_at(audio: &ToneBackend, freq: f32) -> f32 {
    let played = audio.played.lock().unwrap();
    let tail = &played[played.len().saturating_sub(SAMPLE_RATE as usize)..];
    if tail.is_empty() {
        return 0.0;
    }
    let w = 2.0 * std::f32::consts::PI * freq / SAMPLE_RATE as f32;
    let coeff = 2.0 * w.cos();
    let (mut s1, mut s2) = (0f32, 0f32);
    let mut total = 0f32;
    for &x in tail {
        let x = x as f32;
        let s0 = x + coeff * s1 - s2;
        s2 = s1;
        s1 = s0;
        total += x * x;
    }
    let power = s1 * s1 + s2 * s2 - coeff * s1 * s2;
    if total == 0.0 {
        0.0
    } else {
        power / (total * tail.len() as f32 / 2.0)
    }
}

/// Wait until the last second `audio` played is mostly `freq` (slow CI
/// runners take a while for audio to settle).
async fn wait_hears(audio: &ToneBackend, freq: f32, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while share_at(audio, freq) <= 0.5 {
        assert!(std::time::Instant::now() < deadline, "{what}: {}", share_at(audio, freq));
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn wait_state(node: &NodeHandle, state: &str) -> securetext_app::CallView {
    let state = state.to_string();
    eventually(&format!("call state {state}"), || {
        let node = node.clone();
        let state = state.clone();
        async move { node.call_status().await.unwrap().filter(|c| c.state == state) }
    })
    .await
}

async fn wait_media(node: &NodeHandle, peers: usize) {
    eventually("every participant's media connected through the relay", || {
        let node = node.clone();
        async move {
            let stats = node.call_stats().await.unwrap();
            (stats.len() == peers && stats.iter().all(|s| s.state == "connected")).then_some(())
        }
    })
    .await;
}

/// Like `wait_media`, without `eventually`'s own 20 s limit (the caller
/// sets one).
async fn wait_media_long(node: &NodeHandle, peers: usize) {
    loop {
        let stats = node.call_stats().await.unwrap();
        if stats.len() == peers && stats.iter().all(|s| s.state == "connected") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_dm_call_rings_connects_through_the_relay_and_hangs_up() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let (server, t) = turn().await;
    let alice = start_with_tone(dir.path(), "alice", &net, 440.0).await;
    let bob = start_with_tone(dir.path(), "bob", &net, 660.0).await;
    let dm = befriend(&alice.node, &bob.node).await;

    // No TURN server configured: calling is refused, not attempted directly.
    let err = alice.node.start_call(dm.clone(), false).await.unwrap_err().to_string();
    assert!(err.contains("TURN"), "{err}");
    // Only Alice has one; Bob will use hers.
    alice.node.set_turn_servers(vec![t.clone()]).await.unwrap();

    let ringing = alice.node.start_call(dm.clone(), true).await.unwrap();
    assert_eq!(ringing.state, "outgoing");
    let incoming = wait_state(&bob.node, "incoming").await;
    assert_eq!(incoming.caller_label, "alice");
    assert!(incoming.video);
    let accepted = bob.node.accept_call().await.unwrap();
    assert_eq!(accepted.turn, "the caller's");

    wait_state(&alice.node, "active").await;
    wait_media(&alice.node, 1).await;
    wait_media(&bob.node, 1).await;
    // Each hears the other, not themselves.
    wait_hears(&bob.audio, 440.0, "Bob hears Alice").await;
    wait_hears(&alice.audio, 660.0, "Alice hears Bob").await;
    assert!(share_at(&alice.audio, 440.0) < 0.05, "no echo of herself");

    // Relayed on both ends, per WebRTC's own stats.
    for s in alice.node.call_stats().await.unwrap().into_iter().chain(bob.node.call_stats().await.unwrap()) {
        assert_eq!((s.local_candidate.as_str(), s.remote_candidate.as_str()), ("relay", "relay"), "{s:?}");
    }

    // Mute.
    alice.node.set_call_muted(true).await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(share_at(&bob.audio, 440.0) < 0.05, "muted");

    // Bob hangs up: Alice's side ends too.
    let mut events = alice.node.subscribe();
    bob.node.hang_up().await.unwrap();
    assert!(bob.node.call_status().await.unwrap().is_none());
    eventually("alice's call to end", || {
        let alice = alice.node.clone();
        async move { alice.call_status().await.unwrap().is_none().then_some(()) }
    })
    .await;
    let mut reason = None;
    while let Ok(ev) = events.try_recv() {
        if let securetext_app::Event::Call { call: None, ended } = ev {
            reason = ended;
        }
    }
    assert_eq!(reason.as_deref(), Some("bob hung up"));
    server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_declined_call_ends_for_the_caller() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let (server, t) = turn().await;
    let alice = start_with_tone(dir.path(), "alice", &net, 440.0).await;
    let bob = start_with_tone(dir.path(), "bob", &net, 660.0).await;
    let dm = befriend(&alice.node, &bob.node).await;
    alice.node.set_turn_servers(vec![t]).await.unwrap();
    alice.node.start_call(dm, false).await.unwrap();
    wait_state(&bob.node, "incoming").await;
    bob.node.decline_call().await.unwrap();
    eventually("alice's call to end", || {
        let alice = alice.node.clone();
        async move { alice.call_status().await.unwrap().is_none().then_some(()) }
    })
    .await;
    server.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn a_channel_call_meshes_three_people_and_everyone_hears_everyone() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let (server, t) = turn().await;
    let alice = start_with_tone(dir.path(), "alice", &net, 440.0).await;
    let bob = start_with_tone(dir.path(), "bob", &net, 660.0).await;
    let carol = start_with_tone(dir.path(), "carol", &net, 880.0).await;
    befriend(&alice.node, &bob.node).await;
    befriend(&alice.node, &carol.node).await;
    let server_id = alice.node.create_server("Club".into()).await.unwrap();
    alice.node.invite_to_server(server_id.clone(), my_key(&bob.node).await).await.unwrap();
    alice.node.invite_to_server(server_id.clone(), my_key(&carol.node).await).await.unwrap();
    let general_b = channel_named(&bob.node, &server_id, "general").await;
    let general_c = channel_named(&carol.node, &server_id, "general").await;
    let general = channel_named(&alice.node, &server_id, "general").await;
    assert_eq!(general, general_b);
    assert_eq!(general, general_c);
    // Bob and Carol have never been connected to each other: the call's
    // own signaling has to bring that about.
    for p in [&alice, &bob, &carol] {
        p.node.set_turn_servers(vec![t.clone()]).await.unwrap();
    }

    alice.node.start_call(general.clone(), false).await.unwrap();
    wait_state(&bob.node, "incoming").await;
    wait_state(&carol.node, "incoming").await;
    bob.node.accept_call().await.unwrap();
    carol.node.accept_call().await.unwrap();

    for p in [&alice, &bob, &carol] {
        // Generous: on a slow machine a lost signal costs a 10 s retry.
        if tokio::time::timeout(Duration::from_secs(60), wait_media_long(&p.node, 2)).await.is_err() {
            for (who, q) in [("alice", &alice), ("bob", &bob), ("carol", &carol)] {
                eprintln!("{who} ({}): {:?}", my_key(&q.node).await, q.node.call_status().await);
                eprintln!("{who} stats: {:?}", q.node.call_stats().await);
            }
            panic!("media never connected for everyone");
        }
    }
    // Each person hears both others' tones in the mix, and not their own.
    // Measured over the last second, polled: on a starved CI machine a
    // given second can have dropouts, so wait for a clean one.
    let people = [
        ("alice", &alice, 440.0, [660.0, 880.0]),
        ("bob", &bob, 660.0, [440.0, 880.0]),
        ("carol", &carol, 880.0, [440.0, 660.0]),
    ];
    let hears_right = |p: &Caller, own: f32, others: [f32; 2]| {
        others.iter().all(|f| share_at(&p.audio, *f) > 0.15) && share_at(&p.audio, own) < 0.05
    };
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    tokio::time::sleep(Duration::from_secs(2)).await;
    while !people.iter().all(|(_, p, own, others)| hears_right(p, *own, *others)) {
        if tokio::time::Instant::now() > deadline {
            for (who, p, own, others) in &people {
                eprintln!(
                    "{who}: own {own} Hz {:.2}, others {:?}",
                    share_at(&p.audio, *own),
                    others.iter().map(|f| (f, share_at(&p.audio, *f))).collect::<Vec<_>>()
                );
            }
            panic!("not everyone heard both others (and only them)");
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    for (who, p, _, _) in &people {
        for s in p.node.call_stats().await.unwrap() {
            assert_eq!(s.local_candidate, "relay", "{who}: {s:?}");
            assert_eq!(s.remote_candidate, "relay", "{who}: {s:?}");
        }
    }

    // One person leaving doesn't end it for the others.
    carol.node.hang_up().await.unwrap();
    for p in [&alice, &bob] {
        wait_media(&p.node, 1).await;
        assert!(p.node.call_status().await.unwrap().is_some());
    }
    server.close().await;
}
