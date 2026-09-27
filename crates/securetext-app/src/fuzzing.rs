//! Entry points for coverage-guided fuzzing (`fuzz/`, built with
//! `--cfg fuzzing`). They reach the parts of the node that face untrusted
//! input, bypassing the layers a fuzzer could never get past on its own
//! (AEAD, MLS), so their contents get explored directly:
//!
//! - [`wire`]: frame and payload parsing;
//! - [`relay_envelope`]: a relay envelope's decrypted contents, which is
//!   what a malicious contact could put in our mailbox;
//! - [`node_input`]: a live node handling any frame from a stranger or a
//!   contact, or any MLS payload from a contact. Every handler (chat,
//!   reactions, files, calls, timers, presence) is reachable.
//!
//! Any panic is a bug: untrusted input must only ever produce errors.

use std::cell::RefCell;
use std::time::Duration;

use openmls_rust_crypto::RustCrypto;
use securetext_identity::IdentityStore;
use tokio::sync::{broadcast, mpsc};

use crate::node::{NodeState, Opened, Timing};
use crate::relay::{self, MyRelay};
use crate::wire::{self, Payload, WireMessage};

pub fn wire(data: &[u8]) {
    let _ = serde_json::from_slice::<WireMessage>(data);
    let _ = Payload::from_bytes(data);
    let rt = tokio::runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(async {
        let mut cursor = std::io::Cursor::new(data.to_vec());
        while let Ok(Some(_)) = wire::read_frame(&mut cursor).await {}
    });
}

thread_local! {
    static RELAY: MyRelay = MyRelay::new(
        "securetext-relay1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.onion#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ).expect("fixed relay link parses");
}

/// Seal `plaintext` for our mailbox and open it, as if a contact had left
/// it at our relay.
pub fn relay_envelope(plaintext: &[u8]) {
    RELAY.with(|mine| {
        let blob = relay::seal_raw_for_fuzzing(mine, plaintext);
        let _ = relay::open(&blob, mine, &[3u8; 32], &RustCrypto::default());
    });
}

struct Fixture {
    rt: tokio::runtime::Runtime,
    alice: NodeState,
    /// Kept (unread) so the nodes' event channels stay open.
    _net_rx: Vec<mpsc::UnboundedReceiver<crate::node::NetEvent>>,
    bob_key: Vec<u8>,
    dm: Vec<u8>,
    _dir: tempfile::TempDir,
}

thread_local! {
    static FIXTURE: RefCell<Option<Fixture>> = const { RefCell::new(None) };
}

fn node(dir: &std::path::Path, name: &str) -> (NodeState, mpsc::UnboundedReceiver<crate::node::NetEvent>) {
    let (identity, public) = IdentityStore::create(&dir.join(format!("{name}.enc")), name, "fuzz passphrase").unwrap();
    let (events, _) = broadcast::channel(4096);
    let (net_tx, net_rx) = mpsc::unbounded_channel();
    let timing = Timing {
        retry_interval: Duration::from_secs(3600),
        dial_timeout: Duration::from_secs(1),
        presence_interval: Duration::from_secs(3600),
        relay_poll_interval: Duration::from_secs(3600),
    };
    let mut n = NodeState::new(Opened { identity, public }, events, net_tx, timing).unwrap();
    n.set_profile_dir(dir);
    n.fuzz_set_onion(&format!("{name}.onion"));
    (n, net_rx)
}

fn fixture() -> Fixture {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let _guard = rt.enter();
    let dir = tempfile::tempdir().unwrap();
    let (mut alice, alice_rx) = node(dir.path(), "alice");
    let (mut bob, bob_rx) = node(dir.path(), "bob");
    let invite = alice.create_invite().unwrap();
    let dm = wire::from_hex(&bob.add_contact(&invite).unwrap()).unwrap();
    for frame in bob.fuzz_take_outbox(alice.fuzz_key()) {
        let _ = alice.fuzz_on_frame(bob.fuzz_key(), frame);
    }
    let bob_key = bob.fuzz_key().to_vec();
    drop(_guard);
    drop(bob);
    Fixture { rt, alice, _net_rx: vec![alice_rx, bob_rx], bob_key, dm, _dir: dir }
}

/// First byte picks the input: 0 a frame from a stranger, 1 a frame from
/// Bob (a contact with a DM), 2 an MLS payload from Bob in that DM. The
/// rest is the JSON.
pub fn node_input(data: &[u8]) {
    let Some((&mode, rest)) = data.split_first() else { return };
    FIXTURE.with(|cell| {
        let mut slot = cell.borrow_mut();
        let f = slot.get_or_insert_with(fixture);
        let _guard = f.rt.enter();
        match mode % 3 {
            0 => {
                if let Ok(frame) = serde_json::from_slice::<WireMessage>(rest) {
                    let _ = f.alice.fuzz_on_frame(&[9u8; 32], frame);
                }
            }
            1 => {
                if let Ok(frame) = serde_json::from_slice::<WireMessage>(rest) {
                    let _ = f.alice.fuzz_on_frame(&f.bob_key.clone(), frame);
                }
            }
            _ => {
                let (dm, bob) = (f.dm.clone(), f.bob_key.clone());
                let _ = f.alice.fuzz_on_payload(&dm, &bob, rest);
            }
        }
        // Let spawned work (dials, call engines) run a little, then keep
        // state from growing without bound across iterations.
        f.rt.block_on(tokio::task::yield_now());
        f.alice.tick();
    });
}
