//! Phase 1 proof-of-integration CLI.
//!
//! `securetext demo` runs the actual Phase 1 exit criteria end to end in one
//! process, standing in for two separate machines: two local identities
//! (Alice, Bob) each generate a signing key, form a 2-member MLS group, and
//! exchange E2EE application messages over **real Tor v3 onion services** —
//! not a mock transport. Alice never learns Bob's IP and vice versa; the
//! only address exchanged is Bob's `.onion` address.
//!
//! What this demo does **not** yet include, tracked as follow-ups rather
//! than silently skipped:
//! - The Noise defense-in-depth layer and yamux multiplexing
//!   (crypto-spec.md §4, architecture.md §6) — this demo frames messages
//!   with a plain length prefix directly over the onion-service stream.
//! - Invite links (Phase 2) — the key package and Welcome are exchanged
//!   in-process here instead of via a real out-of-band invite mechanism.
//! - Persisting the MLS group across restarts (tracked in tech-stack.md).

use securetext_crypto::Member;
use securetext_identity::IdentityStore;
use securetext_net::{Client, DataStream, Listener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("demo") => run_demo().await,
        _ => {
            eprintln!("usage: securetext demo");
            eprintln!("  Runs the Phase 1 proof: two local identities exchange an MLS-encrypted");
            eprintln!("  message over real Tor v3 onion services.");
            std::process::exit(2);
        }
    }
}

async fn run_demo() -> anyhow::Result<()> {
    let work_dir = tempfile::tempdir()?;
    println!("[setup] identities and MLS group (local, no network yet)");

    let (alice_store, alice_public) =
        IdentityStore::create(&work_dir.path().join("alice.enc"), "alice", "demo passphrase")?;
    let (bob_store, bob_public) =
        IdentityStore::create(&work_dir.path().join("bob.enc"), "bob", "demo passphrase")?;

    let alice_signer = alice_store
        .signing_key_pair(&alice_public)?
        .expect("alice key pair present");
    let bob_signer = bob_store
        .signing_key_pair(&bob_public)?
        .expect("bob key pair present");

    let alice = Member::new("alice", alice_signer);
    let bob = Member::new("bob", bob_signer);

    let mut alice_group = alice.create_group()?;
    let bob_key_package = bob.key_package_bytes()?;
    let welcome_bytes = alice.add_member(&mut alice_group, &bob_key_package)?;
    println!("[setup] alice created a 2-member MLS group and added bob (locally, not sent yet)");

    println!("[tor] bootstrapping bob's Tor client (listener side) — this talks to the real Tor network...");
    let bob_tor: Client = securetext_net::bootstrap().await?;
    let mut bob_listener = Listener::launch(&bob_tor, "securetext-demo-bob")?;
    let bob_address = bob_listener.onion_address()?;
    println!("[tor] bob is listening on {bob_address}");

    println!("[tor] bootstrapping alice's Tor client (dialer side)...");
    let alice_tor: Client = securetext_net::bootstrap().await?;

    let bob_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        println!("[bob] waiting for alice to connect...");
        let mut stream = bob_listener
            .accept_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("listener closed with no connection"))?;
        println!("[bob] alice connected over the onion service");

        let welcome_bytes = read_framed(&mut stream).await?;
        let mut bob_group = bob.join_from_welcome(&welcome_bytes)?;
        println!("[bob] joined the MLS group from alice's Welcome message");

        let ciphertext = read_framed(&mut stream).await?;
        let plaintext = bob
            .decrypt(&mut bob_group, &ciphertext)?
            .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
        println!(
            "[bob] decrypted message from alice: {:?}",
            String::from_utf8_lossy(&plaintext)
        );

        let reply = bob.encrypt(&mut bob_group, b"Hi Alice, this came back over Tor!")?;
        write_framed(&mut stream, &reply).await?;
        println!("[bob] sent an encrypted reply");
        Ok(())
    });

    // Give bob's onion service a moment to publish its descriptor to the
    // Tor network before alice tries to reach it.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    println!("[alice] dialing bob's onion address...");
    let mut stream = securetext_net::dial(&alice_tor, &bob_address, 1).await?;
    println!("[alice] connected to bob over Tor (alice never learned bob's IP)");

    write_framed(&mut stream, &welcome_bytes).await?;
    println!("[alice] sent Welcome message to bob");

    let ciphertext = alice.encrypt(&mut alice_group, b"Hello Bob, this is over Tor!")?;
    write_framed(&mut stream, &ciphertext).await?;
    println!("[alice] sent an encrypted message to bob");

    let reply_ciphertext = read_framed(&mut stream).await?;
    let reply_plaintext = alice
        .decrypt(&mut alice_group, &reply_ciphertext)?
        .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
    println!(
        "[alice] decrypted reply from bob: {:?}",
        String::from_utf8_lossy(&reply_plaintext)
    );

    bob_task.await??;
    println!("[done] Phase 1 proof complete: identity + MLS + Tor onion services, end to end.");
    Ok(())
}

/// Minimal length-prefixed framing over the raw onion-service stream — a
/// stand-in for the Noise/yamux layer (crypto-spec.md §4, architecture.md
/// §6), not the final wire protocol. Tracked as a follow-up, not hidden.
async fn write_framed(stream: &mut DataStream, payload: &[u8]) -> anyhow::Result<()> {
    let len = u32::try_from(payload.len())?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    Ok(())
}

async fn read_framed(stream: &mut DataStream) -> anyhow::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}
