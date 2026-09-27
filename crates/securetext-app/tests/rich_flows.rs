//! Rich messaging through running nodes (Phase 8): threads, reactions,
//! disappearing-message timers, presence, and file sharing, over the
//! in-memory network with the real stack above it.

mod common;

use common::*;
use rand::RngCore;
use securetext_app::MessageView;

async fn message(node: &NodeHandle, conversation: &str, pred: impl Fn(&MessageView) -> bool + Clone) -> MessageView {
    eventually("a matching message", || {
        let node = node.clone();
        let conversation = conversation.to_string();
        let pred = pred.clone();
        async move { node.messages(conversation, 200).await.ok()?.into_iter().find(|m| pred(m)) }
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn threads_and_reactions_reach_the_other_side() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let alice = start(dir.path(), "alice", &net).await;
    let bob = start(dir.path(), "bob", &net).await;
    let dm = befriend(&alice, &bob).await;

    let root = alice.post(dm.clone(), "Where shall we meet?".into(), None).await.unwrap();
    wait_for_message(&bob, &dm, "Where shall we meet?").await;
    let reply = bob.post(dm.clone(), "The library".into(), Some(root.id.clone())).await.unwrap();
    assert_eq!(reply.reply_to.as_deref(), Some(root.id.as_str()));

    // Alice sees the reply in the thread, and the root's reply count.
    let got = message(&alice, &dm, |m| m.body == "The library").await;
    assert_eq!(got.reply_to.as_deref(), Some(root.id.as_str()));
    let root_id = root.id.clone();
    message(&alice, &dm, move |m| m.id == root_id && m.reply_count == 1).await;
    // Threads don't nest.
    assert!(alice.post(dm.clone(), "x".into(), Some(reply.id.clone())).await.is_err());

    // Reactions: Bob adds one, Alice sees who; Bob takes it back.
    bob.react(dm.clone(), root.id.clone(), "👍".into(), true).await.unwrap();
    let root_id = root.id.clone();
    let seen = message(&alice, &dm, move |m| m.id == root_id && !m.reactions.is_empty()).await;
    assert_eq!(seen.reactions[0].emoji, "👍");
    assert_eq!(seen.reactions[0].count, 1);
    assert_eq!(seen.reactions[0].by, vec!["bob".to_string()]);
    assert!(!seen.reactions[0].mine);
    alice.react(dm.clone(), root.id.clone(), "👍".into(), true).await.unwrap();
    let root_id = root.id.clone();
    message(&bob, &dm, move |m| m.id == root_id && m.reactions.first().is_some_and(|r| r.count == 2 && r.mine)).await;
    bob.react(dm.clone(), root.id.clone(), "👍".into(), false).await.unwrap();
    let root_id = root.id.clone();
    message(&alice, &dm, move |m| m.id == root_id && m.reactions.first().is_some_and(|r| r.count == 1 && r.mine)).await;

    assert!(bob.react(dm.clone(), root.id.clone(), "not an emoji".into(), true).await.is_err());
    assert!(bob.react(dm.clone(), "no-such-message".into(), "👍".into(), true).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_disappearing_timer_applies_to_both_sides() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let alice = start(dir.path(), "alice", &net).await;
    let bob = start(dir.path(), "bob", &net).await;
    let dm = befriend(&alice, &bob).await;

    assert!(alice.set_disappearing(dm.clone(), Some(5)).await.is_err(), "under a minute");
    alice.set_disappearing(dm.clone(), Some(3600)).await.unwrap();
    // Bob's side learns the timer and shows a note.
    eventually("bob to learn the timer", || {
        let bob = bob.clone();
        let dm = dm.clone();
        async move {
            bob.conversations().await.ok()?.into_iter().find(|c| c.id == dm && c.disappear_secs == Some(3600)).map(|_| ())
        }
    })
    .await;
    let note = message(&bob, &dm, |m| m.status == "system").await;
    assert!(note.body.contains("1 hour"), "{}", note.body);

    // Messages from either side now carry an expiry about an hour out.
    let before = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    bob.post(dm.clone(), "this will vanish".into(), None).await.unwrap();
    let got = message(&alice, &dm, |m| m.body == "this will vanish").await;
    let expires = got.expires_at.expect("an expiry");
    assert!((expires - before - 3_600_000).abs() < 60_000, "expires in about an hour: {}", expires - before);

    alice.set_disappearing(dm.clone(), None).await.unwrap();
    alice.post(dm.clone(), "this stays".into(), None).await.unwrap();
    let kept = message(&bob, &dm, |m| m.body == "this stays").await;
    assert_eq!(kept.expires_at, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn presence_is_shared_with_connected_contacts() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let alice = start(dir.path(), "alice", &net).await;
    let bob = start(dir.path(), "bob", &net).await;
    befriend(&alice, &bob).await;
    let alice_key = my_key(&alice).await;

    assert!(alice.set_presence("invisible".into(), String::new()).await.is_err());
    alice.set_presence("away".into(), "at lunch".into()).await.unwrap();
    eventually("bob to see alice away", || {
        let bob = bob.clone();
        let alice_key = alice_key.clone();
        async move {
            bob.contacts()
                .await
                .ok()?
                .into_iter()
                .find(|c| c.key == alice_key && c.status == "away" && c.status_text == "at lunch")
                .map(|_| ())
        }
    })
    .await;

    // Offline means offline, whatever she last said.
    alice.shutdown().await;
    net.set_reachable("alice.onion", false);
    eventually("bob to see alice offline", || {
        let bob = bob.clone();
        let alice_key = alice_key.clone();
        async move { bob.contacts().await.ok()?.into_iter().find(|c| c.key == alice_key && c.status == "offline").map(|_| ()) }
    })
    .await;
}

async fn wait_file(node: &NodeHandle, conversation: &str, file_id: &str, state: &str) {
    let label = node.status().await.map(|s| s.label).unwrap_or_default();
    let what = format!("{label}'s copy of file {file_id} to be {state}");
    let file_id = file_id.to_string();
    let state = state.to_string();
    eventually(&what, || {
        let node = node.clone();
        let conversation = conversation.to_string();
        let file_id = file_id.clone();
        let state = state.clone();
        async move {
            node.messages(conversation, 200)
                .await
                .ok()?
                .into_iter()
                .find(|m| m.attachment.as_ref().is_some_and(|a| a.file_id == file_id && a.state == state))
                .map(|_| ())
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn files_are_fetched_from_whoever_has_them_and_arrive_intact() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let alice = start(dir.path(), "alice", &net).await;
    let bob = start(dir.path(), "bob", &net).await;
    let carol = start(dir.path(), "carol", &net).await;
    befriend(&alice, &bob).await;
    befriend(&alice, &carol).await;
    let server = alice.create_server("Club".into()).await.unwrap();
    invite(&alice, &server, &my_key(&bob).await).await;
    invite(&alice, &server, &my_key(&carol).await).await;
    let general = channel_named(&alice, &server, "general").await;
    channel_named(&bob, &server, "general").await;
    channel_named(&carol, &server, "general").await;

    // A file big enough to take several chunks.
    let mut data = vec![0u8; 700 * 1024];
    rand::thread_rng().fill_bytes(&mut data);
    let sent = alice
        .send_file(general.clone(), "../../plans.bin".into(), "application/octet-stream".into(), data.clone(), "the plans".into(), None)
        .await
        .unwrap();
    let file = sent.attachment.clone().unwrap();
    assert_eq!(file.state, "complete");
    assert_eq!(file.name, "_.._plans.bin", "path components never survive into the name");

    // Not an image: nothing downloads until asked.
    wait_for_message(&bob, &general, "the plans").await;
    wait_file(&bob, &general, &file.file_id, "available").await;
    bob.download_attachment(file.file_id.clone()).await.unwrap();
    wait_file(&bob, &general, &file.file_id, "complete").await;
    let out = tempfile::tempdir().unwrap();
    let path = bob.save_attachment(file.file_id.clone(), Some(out.path().to_path_buf())).await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), data);
    // Saving again never overwrites.
    let second = bob.save_attachment(file.file_id.clone(), Some(out.path().to_path_buf())).await.unwrap();
    assert_ne!(path, second);

    // The ciphertext at rest doesn't contain the file.
    let stored = std::fs::read_dir(dir.path().join("bob").join("attachments")).unwrap().next().unwrap().unwrap().path();
    let at_rest = std::fs::read(stored).unwrap();
    assert!(!at_rest.windows(64).any(|w| w == &data[1000..1064]));

    // Alice goes away. Carol still gets the file, from Bob.
    alice.shutdown().await;
    net.set_reachable("alice.onion", false);
    wait_for_message(&carol, &general, "the plans").await;
    carol.download_attachment(file.file_id.clone()).await.unwrap();
    wait_file(&carol, &general, &file.file_id, "complete").await;
    let path = carol.save_attachment(file.file_id.clone(), Some(out.path().to_path_buf())).await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), data);
}

#[tokio::test(flavor = "multi_thread")]
async fn small_images_download_by_themselves_and_render_only_if_real() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let alice = start(dir.path(), "alice", &net).await;
    let bob = start(dir.path(), "bob", &net).await;
    let dm = befriend(&alice, &bob).await;

    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(&[0u8; 2000]);
    let sent = alice.send_file(dm.clone(), "cat.png".into(), "image/png".into(), png.clone(), String::new(), None).await.unwrap();
    let file_id = sent.attachment.unwrap().file_id;
    wait_file(&bob, &dm, &file_id, "complete").await;
    let shown = bob.attachment_data(file_id).await.unwrap();
    assert_eq!(shown.mime, "image/png");

    // Something claiming to be an image but isn't is neither labelled nor
    // rendered as one.
    let fake = alice
        .send_file(dm.clone(), "x.svg".into(), "image/svg+xml".into(), b"<svg onload=alert(1)/>".to_vec(), String::new(), None)
        .await
        .unwrap();
    let attachment = fake.attachment.unwrap();
    assert!(!attachment.image);
    assert_eq!(attachment.mime, "application/octet-stream");
    assert!(alice.attachment_data(attachment.file_id).await.is_err());
}
