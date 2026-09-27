//! Resource limits against anyone who can reach a node's address (Phase 9
//! hardening). The node-level caps on held messages, presented cards and
//! stranger connections are tested in `node.rs`. This one needs a real
//! transport.

mod common;

use std::time::Duration;

use common::*;
use tokio::io::AsyncReadExt;

#[tokio::test(flavor = "multi_thread")]
async fn a_flood_of_silent_connections_is_capped() {
    let dir = tempfile::tempdir().unwrap();
    let net = MemoryNetwork::new();
    let _alice = start(dir.path(), "alice", &net).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Forty connections that never start the handshake.
    let attacker = net.transport("attacker.onion");
    let mut streams = Vec::new();
    for _ in 0..40 {
        streams.push(attacker.dial("alice.onion").await.unwrap());
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The node is working on at most 32 handshakes at once; the rest were
    // closed straight away rather than queued.
    let mut closed = 0;
    for s in &mut streams {
        let mut byte = [0u8; 1];
        if let Ok(Ok(0)) = tokio::time::timeout(Duration::from_millis(50), s.read(&mut byte)).await {
            closed += 1;
        }
    }
    assert_eq!(closed, 8, "exactly the connections past the limit are dropped");
}
