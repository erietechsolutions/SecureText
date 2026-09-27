//! End-to-end application flows across several nodes, run over the
//! in-memory network instead of Tor. Everything above the transport is the
//! real stack: encrypted identity stores, MLS, the Noise_XX handshake
//! with key pinning, yamux, the peer protocol, and the persistent outbox.
//! Tor itself is exercised separately (securetext-net's live tests and the
//! CLI's live runs); these tests make the app logic deterministic.

mod common;

use std::time::Duration;

use common::*;

#[tokio::test(flavor = "multi_thread")]
async fn invite_link_starts_a_dm_both_ways() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let alice = start(dir.path(), "alice", &net).await;
    let bob = start(dir.path(), "bob", &net).await;

    let dm = befriend(&alice, &bob).await;

    let sent = bob.send_message(dm.clone(), "hi alice".into()).await.unwrap();
    assert!(sent.outgoing);
    wait_for_message(&alice, &dm, "hi alice").await;
    alice.send_message(dm.clone(), "hi bob".into()).await.unwrap();
    wait_for_message(&bob, &dm, "hi bob").await;

    // The sender's copy moves from pending to sent once it's on the wire.
    eventually("bob's message to be marked sent", || {
        let bob = bob.clone();
        let dm = dm.clone();
        async move {
            bob.messages(dm, 10).await.unwrap().iter().any(|m| m.body == "hi alice" && m.status == "sent").then_some(())
        }
    })
    .await;

    // DMs are named after the other person, and labelled messages carry
    // the sender's name.
    let alice_view = alice.conversations().await.unwrap();
    assert_eq!(alice_view.iter().find(|c| c.id == dm).unwrap().name, "bob");
    let received = alice.messages(dm.clone(), 10).await.unwrap();
    assert_eq!(received.iter().find(|m| m.body == "hi alice").unwrap().sender_label, "bob");

    // An invite link can't be used to befriend yourself.
    let own = alice.create_invite().await.unwrap();
    assert!(alice.add_contact(own).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn server_channels_membership_and_kick() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let alice = start(dir.path(), "alice", &net).await;
    let bob = start(dir.path(), "bob", &net).await;
    let carol = start(dir.path(), "carol", &net).await;
    let bob_key = my_key(&bob).await;
    let carol_key = my_key(&carol).await;

    // Bob and Carol each know Alice, but not each other.
    befriend(&alice, &bob).await;
    befriend(&alice, &carol).await;

    let server = alice.create_server("Book Club".into()).await.unwrap();
    let general = channel_named(&alice, &server, "general").await;
    invite(&alice, &server, &bob_key).await;
    invite(&alice, &server, &carol_key).await;

    assert_eq!(channel_named(&bob, &server, "general").await, general);
    assert_eq!(channel_named(&carol, &server, "general").await, general);

    // Carol can reach Bob even though they never exchanged invites: the
    // admin's roster announcement gave each the other's signed card.
    carol.send_message(general.clone(), "hello from carol".into()).await.unwrap();
    wait_for_message(&bob, &general, "hello from carol").await;
    wait_for_message(&alice, &general, "hello from carol").await;
    bob.send_message(general.clone(), "hi carol, bob here".into()).await.unwrap();
    wait_for_message(&carol, &general, "hi carol, bob here").await;

    // Every member sees all three members, with Alice as admin.
    let members = eventually("carol to see all three members", || {
        let carol = carol.clone();
        let server = server.clone();
        async move {
            let m = carol.members(server).await.unwrap();
            (m.len() == 3).then_some(m)
        }
    })
    .await;
    assert!(members.iter().find(|m| m.label == "alice").unwrap().is_admin);
    assert!(members.iter().filter(|m| m.is_admin).count() == 1);

    // A private channel for Alice and Bob only.
    let secret = alice
        .create_channel(server.clone(), "planning".into(), true, vec![bob_key.clone()])
        .await
        .unwrap();
    assert_eq!(channel_named(&bob, &server, "planning").await, secret);
    alice.send_message(secret.clone(), "surprise party friday".into()).await.unwrap();
    wait_for_message(&bob, &secret, "surprise party friday").await;
    assert!(
        !carol.conversations().await.unwrap().iter().any(|c| c.id == secret),
        "carol must not have the private channel"
    );

    // Only the admin manages the server.
    assert!(bob.create_channel(server.clone(), "mine".into(), false, vec![]).await.is_err());
    assert!(bob.kick(server.clone(), carol_key.clone()).await.is_err());

    // Kick Carol: she learns she was removed from the server and from
    // #general, and stops receiving anything sent afterwards.
    alice.kick(server.clone(), carol_key.clone()).await.unwrap();
    eventually("carol to see she was removed", || {
        let carol = carol.clone();
        let server = server.clone();
        let general = general.clone();
        async move {
            let cs = carol.conversations().await.unwrap();
            let removed = |id: &str| cs.iter().find(|c| c.id == id).is_some_and(|c| c.removed);
            (removed(&server) && removed(&general)).then_some(())
        }
    })
    .await;
    assert!(carol.send_message(general.clone(), "still here?".into()).await.is_err());

    alice.send_message(general.clone(), "after carol left".into()).await.unwrap();
    wait_for_message(&bob, &general, "after carol left").await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(!has_message(&carol, &general, "after carol left").await);
    assert_eq!(bob.members(server.clone()).await.unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn offline_messages_queue_and_survive_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let alice = start(dir.path(), "alice", &net).await;
    let bob = start(dir.path(), "bob", &net).await;
    let dm = befriend(&alice, &bob).await;
    bob.send_message(dm.clone(), "before the outage".into()).await.unwrap();
    wait_for_message(&alice, &dm, "before the outage").await;

    // Bob goes offline. Alice's message can't be delivered, so it waits
    // in her outbox, marked pending.
    bob.shutdown().await;
    net.set_reachable("bob.onion", false);
    alice.send_message(dm.clone(), "sent while you were away".into()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    let queued = alice.messages(dm.clone(), 10).await.unwrap();
    assert_eq!(queued.iter().find(|m| m.body == "sent while you were away").unwrap().status, "pending");

    // Alice restarts too: the queue is in her encrypted profile, not memory.
    alice.shutdown().await;
    let alice = start(dir.path(), "alice", &net).await;

    // Bob comes back with the same identity; the message arrives.
    net.set_reachable("bob.onion", true);
    let bob = start(dir.path(), "bob", &net).await;
    wait_for_message(&bob, &dm, "sent while you were away").await;
    assert!(has_message(&bob, &dm, "before the outage").await, "history survives restart");

    // And the conversation keeps working in both directions.
    bob.send_message(dm.clone(), "back online".into()).await.unwrap();
    wait_for_message(&alice, &dm, "back online").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn wrong_passphrase_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let alice = start(dir.path(), "alice", &net).await;
    alice.shutdown().await;

    let mut bad = config(dir.path(), "alice", &net);
    bad.passphrase = "not it".into();
    assert!(NodeHandle::start(bad).await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn an_impostor_cannot_answer_for_a_contact() {
    // Mallory takes over Bob's address (say, a stale invite's onion
    // address ends up pointing at her). Alice's node must refuse to talk
    // to her, because she can't present Bob's Noise key.
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let alice = start(dir.path(), "alice", &net).await;
    let bob = start(dir.path(), "bob", &net).await;
    let dm = befriend(&alice, &bob).await;
    bob.shutdown().await;

    let mut mallory_cfg = config(dir.path(), "mallory", &net);
    mallory_cfg.network = NetworkConfig::Memory { network: net.clone(), address: "bob.onion".into() };
    let mallory = NodeHandle::start(mallory_cfg).await.unwrap();

    alice.send_message(dm.clone(), "for bob only".into()).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mine = alice.messages(dm.clone(), 10).await.unwrap();
    assert_eq!(mine.iter().find(|m| m.body == "for bob only").unwrap().status, "pending");
    assert!(mallory.conversations().await.unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_new_display_name_reaches_contacts_and_servers() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let alice = start(dir.path(), "alice", &net).await;
    let bob = start(dir.path(), "bob", &net).await;
    let dm = befriend(&alice, &bob).await;
    let alice_key = my_key(&alice).await;
    let server = alice.create_server("Club".into()).await.unwrap();
    invite(&alice, &server, &my_key(&bob).await).await;
    alice.send_message(dm.clone(), "before".into()).await.unwrap();
    wait_for_message(&bob, &dm, "before").await;

    assert!(alice.set_display_name("   ".into()).await.is_err());
    assert!(alice.set_display_name("x".repeat(65)).await.is_err());
    assert!(alice.set_display_name("a\u{7}b".into()).await.is_err());
    assert_eq!(alice.set_display_name("  Alice Liddell ".into()).await.unwrap(), "Alice Liddell");
    assert_eq!(alice.status().await.unwrap().label, "Alice Liddell");

    // Bob sees it in his contacts, as the DM's name, on her messages (old
    // ones too) and in the server's member list.
    eventually("bob to see alice's new name", || {
        let (bob, dm, server, alice_key) = (bob.clone(), dm.clone(), server.clone(), alice_key.clone());
        async move {
            let contact = bob.contacts().await.ok()?.into_iter().any(|c| c.key == alice_key && c.label == "Alice Liddell");
            let dm_named = bob.conversations().await.ok()?.into_iter().any(|c| c.id == dm && c.name == "Alice Liddell");
            let old_msg = bob.messages(dm, 50).await.ok()?.into_iter().any(|m| m.body == "before" && m.sender_label == "Alice Liddell");
            let member = bob.members(server).await.ok()?.into_iter().any(|m| m.key == alice_key && m.label == "Alice Liddell");
            (contact && dm_named && old_msg && member).then_some(())
        }
    })
    .await;

    // It survives a restart.
    alice.shutdown().await;
    let alice = start(dir.path(), "alice", &net).await;
    assert_eq!(alice.status().await.unwrap().label, "Alice Liddell");
}
