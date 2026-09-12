//! Phase 1 proof-of-integration CLI.
//!
//! `securetext demo` runs the actual Phase 1 exit criteria end to end in one
//! process, standing in for two separate machines: two local identities
//! (Alice, Bob) each generate a signing key, form a 2-member MLS group, and
//! exchange E2EE application messages over **real Tor v3 onion services** —
//! not a mock transport. Alice never learns Bob's IP and vice versa; the
//! only address exchanged is Bob's `.onion` address. Every message is also
//! wrapped in a **Noise_XX transport session** (crypto-spec.md §4) layered
//! on top of the onion-service stream, independent of both Tor's own
//! transport crypto and MLS's message-layer E2EE.
//!
//! What this demo does **not** yet include, tracked as follow-ups rather
//! than silently skipped:
//! - yamux multiplexing over the Noise session (architecture.md §6) — this
//!   demo still uses one logical stream per connection.
//! - Invite links (Phase 2) — the onion address, Noise static public key,
//!   and MLS key package are exchanged in-process (`demo`) or via manual
//!   copy-paste (`net-listen`/`net-dial`) instead of a real invite
//!   mechanism.
//! - Persisting the MLS group across restarts (tracked in tech-stack.md).

use securetext_crypto::Member;
use securetext_identity::IdentityStore;
use securetext_net::{Client, DataStream, Listener, NoiseTransport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("demo") => run_demo().await,
        Some("bench") => {
            let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
            run_bench(n).await
        }
        Some("net-listen") => run_net_listen().await,
        Some("net-dial") => {
            let address = args.get(2).cloned().ok_or_else(|| {
                anyhow::anyhow!("usage: securetext net-dial <onion-address> <listener-noise-pubkey-hex>")
            })?;
            let expected_noise_pubkey_hex = args.get(3).cloned().ok_or_else(|| {
                anyhow::anyhow!("usage: securetext net-dial <onion-address> <listener-noise-pubkey-hex>")
            })?;
            let expected_noise_pubkey = from_hex(&expected_noise_pubkey_hex)?;
            run_net_dial(&address, &expected_noise_pubkey).await
        }
        _ => {
            eprintln!("usage: securetext demo | bench [N]");
            eprintln!("  Runs the Phase 1 proof: two local identities exchange an MLS-encrypted,");
            eprintln!("  Noise-wrapped message over real Tor v3 onion services, in one process.");
            eprintln!();
            eprintln!("usage: securetext net-listen | net-dial <onion-address> <noise-pubkey-hex>");
            eprintln!("  Same round trip split across two separate OS processes (run in two");
            eprintln!("  terminals) -- net-listen prints the onion address and its Noise static");
            eprintln!("  public key; paste both into net-dial's arguments in the other terminal.");
            std::process::exit(2);
        }
    }
}

/// Standalone process, half A: bootstrap, launch an onion service, print its
/// address and Noise static public key, and echo back whatever the dialer
/// sends once. Does not pin the dialer's Noise key -- an onion service
/// accepting a connection doesn't know in advance who's calling, unlike the
/// dialer, which already has the listener's published contact info
/// (address + key) before it ever connects.
async fn run_net_listen() -> anyhow::Result<()> {
    println!("[listen] bootstrapping this process's own Tor client...");
    let tor = bootstrap_for_this_run().await?;
    let mut listener = Listener::launch(&tor, "securetext-net-listen")?;
    let address = listener.onion_address()?;

    let noise_keys = snow::Builder::new(securetext_net::NOISE_PATTERN.parse()?).generate_keypair()?;
    println!("[listen] onion address: {address}");
    println!("[listen] noise static public key: {}", to_hex(&noise_keys.public));
    println!(
        "[listen] run in another terminal: securetext net-dial {address} {}",
        to_hex(&noise_keys.public)
    );
    println!("[listen] waiting for a connection...");

    let mut stream = listener
        .accept_next()
        .await?
        .ok_or_else(|| anyhow::anyhow!("listener closed with no connection"))?;
    println!("[listen] dialer connected over the onion service");

    let (mut noise, remote_noise_key) =
        securetext_net::handshake_responder(&mut stream, &noise_keys.private).await?;
    println!(
        "[listen] noise handshake complete; dialer's static key: {}",
        to_hex(&remote_noise_key)
    );

    let received = read_framed(&mut stream, &mut noise).await?;
    println!(
        "[listen] received: {:?}",
        String::from_utf8_lossy(&received)
    );
    write_framed(&mut stream, &mut noise, &received).await?;
    stream.shutdown().await?;
    // A per-stream shutdown() alone isn't enough here: this process exits
    // right after, which drops the whole TorClient and kills its
    // background reactor tasks almost instantly -- well before the just-
    // flushed echo has actually propagated across a real multi-hop Tor
    // circuit (that takes real wall-clock time, unlike a local socket).
    // Without this pause the dialer reliably sees "stream not connected"
    // instead of the echo. This is specifically a short-lived-CLI-process
    // problem: the real, long-running app doesn't exit after one exchange,
    // so it won't need this. See tech-stack.md's implementation findings.
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    println!("[listen] echoed it back; done");
    Ok(())
}

/// Standalone process, half B: bootstrap its own independent Tor client,
/// dial the address printed by `net-listen`, and verify the listener's
/// presented Noise static key matches `expected_noise_pubkey` -- this is
/// the actual "authenticate the specific peer identity" property Noise
/// gives us (crypto-spec.md §4), not just "some onion service answered."
async fn run_net_dial(address: &str, expected_noise_pubkey: &[u8]) -> anyhow::Result<()> {
    println!("[dial] bootstrapping this process's own Tor client...");
    let tor = bootstrap_for_this_run().await?;
    println!("[dial] dialing {address}...");
    let mut stream = securetext_net::dial(&tor, address, 1).await?;
    println!("[dial] connected over the onion service (never learned the listener's IP)");

    let noise_keys = snow::Builder::new(securetext_net::NOISE_PATTERN.parse()?).generate_keypair()?;
    let (mut noise, remote_noise_key) =
        securetext_net::handshake_initiator(&mut stream, &noise_keys.private).await?;
    anyhow::ensure!(
        remote_noise_key == expected_noise_pubkey,
        "listener's Noise static key does not match the expected one -- refusing to trust this connection \
         (presented: {}, expected: {})",
        to_hex(&remote_noise_key),
        to_hex(expected_noise_pubkey)
    );
    println!("[dial] noise handshake complete; listener's identity verified");

    write_framed(&mut stream, &mut noise, b"hello from a separate process").await?;
    let echoed = read_framed(&mut stream, &mut noise).await?;
    println!("[dial] echo received: {:?}", String::from_utf8_lossy(&echoed));
    anyhow::ensure!(echoed == b"hello from a separate process", "echo mismatch");
    println!("[dial] round trip verified; done");
    Ok(())
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
    let alice_noise_private = alice_store.noise_static_private_key()?;
    let bob_noise_private = bob_store.noise_static_private_key()?;

    let alice = Member::new("alice", alice_signer);
    let bob = Member::new("bob", bob_signer);

    let mut alice_group = alice.create_group()?;
    let bob_key_package = bob.key_package_bytes()?;
    let welcome_bytes = alice.add_member(&mut alice_group, &bob_key_package)?;
    println!("[setup] alice created a 2-member MLS group and added bob (locally, not sent yet)");

    println!("[tor] bootstrapping bob's Tor client (listener side) — this talks to the real Tor network...");
    let bob_tor: Client = bootstrap_for_this_run().await?;
    let mut bob_listener = Listener::launch(&bob_tor, "securetext-demo-bob")?;
    let bob_address = bob_listener.onion_address()?;
    println!("[tor] bob is listening on {bob_address}");

    println!("[tor] bootstrapping alice's Tor client (dialer side)...");
    let alice_tor: Client = bootstrap_for_this_run().await?;

    let expected_alice_noise_key = alice_public.noise_public_key.clone();
    let bob_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        println!("[bob] waiting for alice to connect...");
        let mut stream = bob_listener
            .accept_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("listener closed with no connection"))?;
        println!("[bob] alice connected over the onion service");

        let (mut noise, alice_noise_key) =
            securetext_net::handshake_responder(&mut stream, &bob_noise_private).await?;
        // Bob happens to already know alice's expected key in this
        // in-process demo, so verifying both directions demonstrates
        // Noise_XX's mutual authentication; a real onion service accepting
        // a connection from an as-yet-unknown caller (see run_net_listen)
        // wouldn't have this available and wouldn't pin here.
        anyhow::ensure!(
            alice_noise_key == expected_alice_noise_key,
            "alice's noise key didn't match what her identity published"
        );
        println!("[bob] noise handshake complete; alice's identity verified");

        let welcome_bytes = read_framed(&mut stream, &mut noise).await?;
        let mut bob_group = bob.join_from_welcome(&welcome_bytes)?;
        println!("[bob] joined the MLS group from alice's Welcome message");

        let ciphertext = read_framed(&mut stream, &mut noise).await?;
        let plaintext = bob
            .decrypt(&mut bob_group, &ciphertext)?
            .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
        println!(
            "[bob] decrypted message from alice: {:?}",
            String::from_utf8_lossy(&plaintext)
        );

        let reply = bob.encrypt(&mut bob_group, b"Hi Alice, this came back over Tor!")?;
        write_framed(&mut stream, &mut noise, &reply).await?;
        // See run_net_listen's comment: a flush alone doesn't guarantee
        // the remote side has received the bytes yet, and dropping the
        // stream (when this task returns) too soon after risks the
        // circuit being reclaimed before delivery finishes.
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        println!("[bob] sent an encrypted reply");
        Ok(())
    });

    // Give bob's onion service a moment to publish its descriptor to the
    // Tor network before alice tries to reach it.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    println!("[alice] dialing bob's onion address...");
    let mut stream = securetext_net::dial(&alice_tor, &bob_address, 1).await?;
    println!("[alice] connected to bob over Tor (alice never learned bob's IP)");

    let (mut noise, bob_noise_key) =
        securetext_net::handshake_initiator(&mut stream, &alice_noise_private).await?;
    anyhow::ensure!(
        bob_noise_key == bob_public.noise_public_key,
        "bob's noise key didn't match what his identity published -- refusing to trust this connection"
    );
    println!("[alice] noise handshake complete; bob's identity verified");

    write_framed(&mut stream, &mut noise, &welcome_bytes).await?;
    println!("[alice] sent Welcome message to bob");

    let ciphertext = alice.encrypt(&mut alice_group, b"Hello Bob, this is over Tor!")?;
    write_framed(&mut stream, &mut noise, &ciphertext).await?;
    println!("[alice] sent an encrypted message to bob");

    let reply_ciphertext = read_framed(&mut stream, &mut noise).await?;
    let reply_plaintext = alice
        .decrypt(&mut alice_group, &reply_ciphertext)?
        .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
    println!(
        "[alice] decrypted reply from bob: {:?}",
        String::from_utf8_lossy(&reply_plaintext)
    );

    bob_task.await??;
    println!("[done] Phase 1 proof complete: identity + MLS + Noise + Tor onion services, end to end.");
    Ok(())
}

/// Resolves tech-stack.md's open item #1: measure the *combined*
/// real-world per-message latency of MLS + Noise + a live Tor circuit,
/// once the connection is already established -- not connection setup
/// time, which is dominated by Tor circuit/onion-service bootstrap and
/// isn't representative of ongoing chat-speed messaging cost.
async fn run_bench(n: usize) -> anyhow::Result<()> {
    let work_dir = tempfile::tempdir()?;
    println!("[bench] setting up identities, MLS group, and a live Tor connection ({n} round trips after setup)...");

    let (alice_store, alice_public) =
        IdentityStore::create(&work_dir.path().join("alice.enc"), "alice", "bench passphrase")?;
    let (bob_store, bob_public) =
        IdentityStore::create(&work_dir.path().join("bob.enc"), "bob", "bench passphrase")?;
    let alice_signer = alice_store.signing_key_pair(&alice_public)?.expect("alice key pair");
    let bob_signer = bob_store.signing_key_pair(&bob_public)?.expect("bob key pair");
    let alice_noise_private = alice_store.noise_static_private_key()?;
    let bob_noise_private = bob_store.noise_static_private_key()?;

    let alice = Member::new("alice", alice_signer);
    let bob = Member::new("bob", bob_signer);
    let mut alice_group = alice.create_group()?;
    let bob_key_package = bob.key_package_bytes()?;
    let welcome_bytes = alice.add_member(&mut alice_group, &bob_key_package)?;

    let bob_tor: Client = bootstrap_for_this_run().await?;
    let mut bob_listener = Listener::launch(&bob_tor, "securetext-bench-bob")?;
    let bob_address = bob_listener.onion_address()?;
    let alice_tor: Client = bootstrap_for_this_run().await?;

    let bob_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        let mut stream = bob_listener
            .accept_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("listener closed with no connection"))?;
        let (mut noise, _alice_noise_key) =
            securetext_net::handshake_responder(&mut stream, &bob_noise_private).await?;

        let welcome_bytes = read_framed(&mut stream, &mut noise).await?;
        let mut bob_group = bob.join_from_welcome(&welcome_bytes)?;

        for _ in 0..n {
            let ciphertext = read_framed(&mut stream, &mut noise).await?;
            bob.decrypt(&mut bob_group, &ciphertext)?
                .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
            let ack = bob.encrypt(&mut bob_group, b"ack")?;
            write_framed(&mut stream, &mut noise, &ack).await?;
        }
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        Ok(())
    });

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let mut stream = securetext_net::dial(&alice_tor, &bob_address, 1).await?;
    let (mut noise, bob_noise_key) =
        securetext_net::handshake_initiator(&mut stream, &alice_noise_private).await?;
    anyhow::ensure!(bob_noise_key == bob_public.noise_public_key, "bob's noise key mismatch");

    write_framed(&mut stream, &mut noise, &welcome_bytes).await?;
    println!("[bench] connection established (identity + MLS + Noise + Tor); starting timed round trips...");

    let mut durations = Vec::with_capacity(n);
    for i in 0..n {
        let msg = format!("bench message {i}");
        let start = std::time::Instant::now();
        let ciphertext = alice.encrypt(&mut alice_group, msg.as_bytes())?;
        write_framed(&mut stream, &mut noise, &ciphertext).await?;
        let ack_ciphertext = read_framed(&mut stream, &mut noise).await?;
        alice
            .decrypt(&mut alice_group, &ack_ciphertext)?
            .ok_or_else(|| anyhow::anyhow!("expected an ack"))?;
        durations.push(start.elapsed());
    }

    bob_task.await??;

    durations.sort();
    let total: std::time::Duration = durations.iter().sum();
    let avg = total / n as u32;
    let min = durations.first().copied().unwrap_or_default();
    let max = durations.last().copied().unwrap_or_default();
    let p50 = durations[durations.len() / 2];
    println!(
        "[bench] {n} MLS+Noise round trips over an established Tor circuit: \
         min={min:?} p50={p50:?} avg={avg:?} max={max:?}"
    );
    println!(
        "[bench] (excludes one-time connection setup: identity/MLS group creation, \
         two Tor bootstraps, and the Noise handshake -- this is steady-state chat-speed cost)"
    );
    Ok(())
}

/// Bootstrap using a fresh scratch state/cache dir rather than arti's
/// platform-default location under the user's real app-data directory.
///
/// This is an interim choice for Phase 1's CLI, not the final design: it
/// means every run re-bootstraps from scratch (no cached consensus/guards
/// across runs, so every launch pays full bootstrap latency) and it exists
/// specifically to route around `bootstrap()`'s ownership check failing in
/// a sandboxed dev environment (tech-stack.md's implementation findings).
/// The real app should use `securetext_net::bootstrap()` with a proper
/// persistent per-platform app-data directory (platform-support.md's
/// `directories` crate plan) once running outside a sandbox with unusual
/// `$HOME` ownership.
async fn bootstrap_for_this_run() -> anyhow::Result<Client> {
    let scratch = tempfile::tempdir()?;
    let path = scratch.keep();
    let tor = securetext_net::bootstrap_with_dirs(&path.join("state"), &path.join("cache")).await?;
    Ok(tor)
}

/// Encrypt `payload` with the established Noise transport session, then
/// send it length-prefixed over the raw onion-service stream. This is
/// still a placeholder for the final wire protocol -- yamux multiplexing
/// (architecture.md §6) isn't implemented yet, so this remains one logical
/// stream per connection -- but the Noise encryption itself is real.
async fn write_framed(stream: &mut DataStream, noise: &mut NoiseTransport, payload: &[u8]) -> anyhow::Result<()> {
    let ciphertext = noise.encrypt(payload)?;
    let len = u32::try_from(ciphertext.len())?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&ciphertext).await?;
    // DataStream buffers internally to minimize Tor cells sent; without an
    // explicit flush, written bytes never actually leave the buffer. Easy
    // to miss (write_all "succeeding" gives no indication data wasn't
    // sent) -- see tech-stack.md's implementation findings.
    stream.flush().await?;
    Ok(())
}

async fn read_framed(stream: &mut DataStream, noise: &mut NoiseTransport) -> anyhow::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut ciphertext = vec![0u8; len];
    stream.read_exact(&mut ciphertext).await?;
    let plaintext = noise.decrypt(&ciphertext)?;
    Ok(plaintext)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(s.len() % 2 == 0, "hex string must have an even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(anyhow::Error::from))
        .collect()
}
