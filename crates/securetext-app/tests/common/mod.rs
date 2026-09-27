//! Helpers shared by the multi-node integration tests.
#![allow(dead_code)]

use std::time::Duration;

pub use securetext_app::{ConversationKind, MemoryNetwork, NetworkConfig, NodeConfig, NodeHandle};

pub const WAIT: Duration = Duration::from_secs(20);

pub fn config(dir: &std::path::Path, name: &str, network: &MemoryNetwork) -> NodeConfig {
    NodeConfig {
        profile_dir: dir.join(name),
        label: name.to_string(),
        passphrase: format!("{name} passphrase"),
        network: NetworkConfig::Memory { network: network.clone(), address: format!("{name}.onion") },
        retry_interval: Duration::from_millis(100),
        dial_timeout: Duration::from_secs(5),
        presence_interval: Duration::from_secs(3600),
        relay_poll_interval: Duration::from_millis(200),
        update: None,
        call_audio: None,
        call_allow_loopback: false,
    }
}

pub async fn start(dir: &std::path::Path, name: &str, network: &MemoryNetwork) -> NodeHandle {
    NodeHandle::start(config(dir, name, network)).await.expect("node starts")
}

/// Poll `check` until it returns `Some`, or fail after `WAIT`.
pub async fn eventually<T, F, Fut>(what: &str, mut check: F) -> T
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Option<T>>,
{
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        if let Some(value) = check().await {
            return value;
        }
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for: {what}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

pub async fn my_key(node: &NodeHandle) -> String {
    node.status().await.unwrap().public_key
}

/// `a` invites `b`; returns the DM's conversation id (same on both sides).
pub async fn befriend(a: &NodeHandle, b: &NodeHandle) -> String {
    let link = a.create_invite().await.unwrap();
    let dm = b.add_contact(link).await.unwrap();
    let dm_for_a = dm.clone();
    eventually("the invite's DM to appear on the inviter's side", || {
        let a = a.clone();
        let dm = dm_for_a.clone();
        async move { a.conversations().await.unwrap().iter().any(|c| c.id == dm).then_some(()) }
    })
    .await;
    // Both sides must hold each other's signed card and key packages
    // before servers can be built; wait until the inviter can see b as a
    // contact with a card.
    let b_key = my_key(b).await;
    eventually("contact cards to be exchanged", || {
        let a = a.clone();
        let b_key = b_key.clone();
        async move {
            a.contacts().await.unwrap().iter().any(|c| c.key == b_key && c.has_card).then_some(())
        }
    })
    .await;
    dm
}

pub async fn wait_for_message(node: &NodeHandle, conversation: &str, body: &str) {
    let what = format!("message {body:?}");
    eventually(&what, || {
        let node = node.clone();
        let conversation = conversation.to_string();
        let body = body.to_string();
        async move {
            node.messages(conversation, 100)
                .await
                .ok()?
                .iter()
                .any(|m| m.body == body)
                .then_some(())
        }
    })
    .await;
}

pub async fn has_message(node: &NodeHandle, conversation: &str, body: &str) -> bool {
    node.messages(conversation.to_string(), 100)
        .await
        .map(|ms| ms.iter().any(|m| m.body == body))
        .unwrap_or(false)
}

pub async fn channel_named(node: &NodeHandle, server: &str, name: &str) -> String {
    let what = format!("channel #{name}");
    eventually(&what, || {
        let node = node.clone();
        let server = server.to_string();
        let name = name.to_string();
        async move {
            node.conversations()
                .await
                .unwrap()
                .into_iter()
                .find(|c| c.kind == ConversationKind::Channel && c.server_id.as_deref() == Some(&server) && c.name == name)
                .map(|c| c.id)
        }
    })
    .await
}

