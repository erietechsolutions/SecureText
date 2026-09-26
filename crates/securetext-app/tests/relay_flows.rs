//! Phase 5: offline delivery through a store-and-forward relay, end to end.
//! Real nodes (encrypted profiles, MLS, Noise, outbox) and a real relay
//! server (`securetext_relay::server`, with its on-disk SQLite store), on
//! the in-memory network in place of Tor.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use securetext_app::{MemoryNetwork, NetworkConfig, NodeConfig, NodeHandle};
use securetext_relay::{server::serve_connection, Limits, RelayAddress, RelayStore};

const WAIT: Duration = Duration::from_secs(20);

struct Relay {
    link: String,
    db_path: std::path::PathBuf,
    store: Arc<Mutex<RelayStore>>,
    /// Every Noise static key a client presented to the relay.
    client_keys: Arc<Mutex<Vec<Vec<u8>>>>,
}

fn spawn_relay(net: &MemoryNetwork, dir: &std::path::Path) -> Relay {
    let keys = snow::Builder::new(securetext_net::NOISE_PATTERN.parse().unwrap())
        .generate_keypair()
        .unwrap();
    let db_path = dir.join("relay.db");
    let store = Arc::new(Mutex::new(RelayStore::open(&db_path, Limits::default()).unwrap()));
    let client_keys = Arc::new(Mutex::new(Vec::new()));
    let mut listening = net.listen("relay.onion");
    let (task_store, task_keys, private) = (store.clone(), client_keys.clone(), keys.private.clone());
    tokio::spawn(async move {
        while let Some(stream) = listening.incoming.recv().await {
            let (store, keys, private) = (task_store.clone(), task_keys.clone(), private.clone());
            tokio::spawn(async move {
                if let Ok(client_key) = serve_connection(stream, &private, store).await {
                    keys.lock().unwrap().push(client_key);
                }
            });
        }
    });
    let link = RelayAddress { onion_address: "relay.onion".into(), noise_public_key: keys.public }.to_link();
    Relay { link, db_path, store, client_keys }
}

fn config(dir: &std::path::Path, name: &str, net: &MemoryNetwork) -> NodeConfig {
    NodeConfig {
        profile_dir: dir.join(name),
        label: name.to_string(),
        passphrase: format!("{name} passphrase"),
        network: NetworkConfig::Memory { network: net.clone(), address: format!("{name}.onion") },
        retry_interval: Duration::from_millis(100),
        dial_timeout: Duration::from_secs(5),
        presence_interval: Duration::from_secs(3600),
        relay_poll_interval: Duration::from_millis(200),
    }
}

async fn start(dir: &std::path::Path, name: &str, net: &MemoryNetwork) -> NodeHandle {
    NodeHandle::start(config(dir, name, net)).await.expect("node starts")
}

async fn eventually<T, F, Fut>(what: &str, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if let Some(v) = check().await {
            return v;
        }
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn befriend(a: &NodeHandle, b: &NodeHandle) -> String {
    let dm = b.add_contact(a.create_invite().await.unwrap()).await.unwrap();
    let b_key = b.status().await.unwrap().public_key;
    eventually("contacts to be established", || {
        let (a, b_key, dm) = (a.clone(), b_key.clone(), dm.clone());
        async move {
            let has_dm = a.conversations().await.unwrap().iter().any(|c| c.id == dm);
            let has_card = a.contacts().await.unwrap().iter().any(|c| c.key == b_key && c.has_card);
            (has_dm && has_card).then_some(())
        }
    })
    .await;
    dm
}

async fn message_status(node: &NodeHandle, dm: &str, body: &str) -> Option<String> {
    node.messages(dm.to_string(), 100)
        .await
        .ok()?
        .into_iter()
        .find(|m| m.body == body)
        .map(|m| m.status)
}

async fn wait_for_message(node: &NodeHandle, dm: &str, body: &str) {
    let what = format!("message {body:?}");
    eventually(&what, || {
        let (node, dm, body) = (node.clone(), dm.to_string(), body.to_string());
        async move { message_status(&node, &dm, &body).await.map(|_| ()) }
    })
    .await;
}

async fn wait_for_status(node: &NodeHandle, dm: &str, body: &str, status: &str) {
    let what = format!("{body:?} to be {status}");
    eventually(&what, || {
        let (node, dm, body, status) = (node.clone(), dm.to_string(), body.to_string(), status.to_string());
        async move { (message_status(&node, &dm, &body).await.as_deref() == Some(&status)).then_some(()) }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn sender_and_recipient_never_online_together() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let relay = spawn_relay(&net, dir.path());
    let alice = start(dir.path(), "alice", &net).await;
    let bob = start(dir.path(), "bob", &net).await;
    bob.set_relay(Some(relay.link.clone())).await.unwrap();
    let dm = befriend(&alice, &bob).await;

    // Bob goes offline. Alice's message can't be delivered directly, so
    // it's left at Bob's relay.
    bob.shutdown().await;
    alice.send_message(dm.clone(), "left at the relay for you".into()).await.unwrap();
    wait_for_status(&alice, &dm, "left at the relay for you", "relayed").await;

    // Alice goes offline too. Bob comes back and still gets it.
    alice.shutdown().await;
    let bob = start(dir.path(), "bob", &net).await;
    wait_for_message(&bob, &dm, "left at the relay for you").await;

    // Collected mail is deleted from the relay.
    let bob_mailbox_empty = || relay.store.lock().unwrap().fetch(&[0; 32], 1).map(|v| v.is_empty()).unwrap();
    assert!(bob_mailbox_empty()); // sanity: an unknown secret sees nothing either way
    eventually("relay to be emptied after collection", || {
        let db = relay.db_path.clone();
        async move {
            let conn = rusqlite::Connection::open(db).unwrap();
            let n: i64 = conn.query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0)).unwrap();
            (n == 0).then_some(())
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invite_can_be_accepted_while_the_inviter_is_offline() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let relay = spawn_relay(&net, dir.path());
    let alice = start(dir.path(), "alice", &net).await;
    alice.set_relay(Some(relay.link.clone())).await.unwrap();
    let invite = alice.create_invite().await.unwrap();
    alice.shutdown().await;

    // Bob accepts and writes while Alice is away; then he leaves as well.
    let bob = start(dir.path(), "bob", &net).await;
    let dm = bob.add_contact(invite).await.unwrap();
    bob.send_message(dm.clone(), "hi! got your invite".into()).await.unwrap();
    wait_for_status(&bob, &dm, "hi! got your invite", "relayed").await;
    bob.shutdown().await;

    // Alice comes back to a new conversation, with the message in it.
    let alice = start(dir.path(), "alice", &net).await;
    wait_for_message(&alice, &dm, "hi! got your invite").await;
    let view = alice.conversations().await.unwrap();
    assert_eq!(view.iter().find(|c| c.id == dm).unwrap().name, "bob");

    // Bob's card came in the envelope, so Alice can reply directly once
    // he's back.
    alice.send_message(dm.clone(), "welcome, bob".into()).await.unwrap();
    let bob = start(dir.path(), "bob", &net).await;
    wait_for_message(&bob, &dm, "welcome, bob").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn relay_holds_nothing_readable_and_cannot_link_senders() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let relay = spawn_relay(&net, dir.path());
    let alice = start(dir.path(), "alice", &net).await;
    let bob = start(dir.path(), "bob", &net).await;
    let alice_invite = securetext_invite::Invite::from_link(&alice.create_invite().await.unwrap()).unwrap();
    let alice_key = alice.status().await.unwrap().public_key;
    let bob_key = bob.status().await.unwrap().public_key;
    let dm = befriend(&alice, &bob).await;

    // Bob picks a relay *after* becoming Alice's contact. Alice learns it
    // over their open connection (a mid-connection card update).
    bob.set_relay(Some(relay.link.clone())).await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    bob.shutdown().await;

    let secret_text = "the eagle lands at midnight";
    alice.send_message(dm.clone(), secret_text.into()).await.unwrap();
    alice.send_message(dm.clone(), "second note".into()).await.unwrap();
    wait_for_status(&alice, &dm, "second note", "relayed").await;

    // Inspect exactly what the relay has on disk: the raw SQLite file.
    let raw = std::fs::read(&relay.db_path).unwrap();
    let alice_mls = from_hex(&alice_key);
    let bob_mls = from_hex(&bob_key);
    let group_id = from_hex(&dm);
    let needles: Vec<(&str, Vec<u8>)> = vec![
        ("message text", secret_text.as_bytes().to_vec()),
        ("sender's label", b"alice".to_vec()),
        ("sender's onion address", b"alice.onion".to_vec()),
        ("recipient's onion address", b"bob.onion".to_vec()),
        ("sender's identity key", alice_mls.clone()),
        ("sender's identity key (hex)", alice_key.as_bytes().to_vec()),
        ("sender's identity key (base64)", b64(&alice_mls)),
        ("recipient's identity key", bob_mls.clone()),
        ("recipient's identity key (base64)", b64(&bob_mls)),
        ("sender's Noise key", alice_invite.noise_public_key.clone()),
        ("sender's Noise key (base64)", b64(&alice_invite.noise_public_key)),
        ("conversation's group id", group_id.clone()),
        ("conversation's group id (base64)", b64(&group_id)),
    ];
    let stored: i64 = rusqlite::Connection::open(&relay.db_path)
        .unwrap()
        .query_row("SELECT COUNT(*) FROM blobs", [], |r| r.get(0))
        .unwrap();
    assert!(stored > 0, "the relay should be holding Alice's messages");
    for (what, needle) in &needles {
        assert!(!contains(&raw, needle), "relay storage contains the {what}");
    }

    // Every connection to the relay used a different, throwaway Noise
    // key, never an identity's own: the relay can't tell whether two
    // deposits (or a deposit and a collection) came from the same person.
    let seen = relay.client_keys.lock().unwrap().clone();
    assert!(!seen.is_empty());
    assert!(!seen.contains(&alice_invite.noise_public_key));
    let mut unique = seen.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), seen.len(), "a client key was reused across relay connections");

    // And Bob, back online, reads it.
    let bob = start(dir.path(), "bob", &net).await;
    wait_for_message(&bob, &dm, secret_text).await;
    wait_for_message(&bob, &dm, "second note").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_vanishes_mid_connection_still_gets_mail_via_relay() {
    // Bob's machine drops off the network without closing anything. Alice's
    // connection to him still accepts writes, so "written" must not count
    // as delivered: without an acknowledgement, the message has to fall
    // back to Bob's relay.
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let relay = spawn_relay(&net, dir.path());
    let mut alice_cfg = config(dir.path(), "alice", &net);
    alice_cfg.dial_timeout = Duration::from_secs(2);
    let alice = NodeHandle::start(alice_cfg).await.unwrap();
    let bob = start(dir.path(), "bob", &net).await;
    bob.set_relay(Some(relay.link.clone())).await.unwrap();
    let dm = befriend(&alice, &bob).await;
    bob.send_message(dm.clone(), "still connected".into()).await.unwrap();
    wait_for_message(&alice, &dm, "still connected").await;

    net.vanish("bob.onion");
    alice.send_message(dm.clone(), "into the void?".into()).await.unwrap();
    wait_for_status(&alice, &dm, "into the void?", "relayed").await;

    // Bob comes back (on a fresh process) and collects it.
    bob.shutdown().await;
    net.set_reachable("bob.onion", true);
    let bob = start(dir.path(), "bob", &net).await;
    wait_for_message(&bob, &dm, "into the void?").await;
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn b64(bytes: &[u8]) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes).into_bytes()
}
