//! SecureText proof-of-integration CLI (Phase 1 + Phase 2 so far).
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
//! Two of those logical streams are multiplexed over that one connection
//! via `SecureMux` (architecture.md §6, backed by `yamux`): a "control"
//! stream for the MLS Welcome and a "chat" stream for application
//! messages, avoiding a second Tor circuit for the second stream.
//!
//! MLS group state is persisted to the same encrypted SQLite file as the
//! identity itself (`securetext_crypto::PersistentProvider`, sharing
//! `IdentityStore::db_path()` via a second connection to that file) --
//! `securetext restart-demo` proves this survives an actual simulated
//! restart: identity stores sealed and dropped, then reopened from their
//! encrypted files and the MLS group reloaded by ID before continuing.
//!
//! `securetext invite` / `securetext connect <link>` (Phase 2) replace that
//! three-argument manual exchange with a single shareable invite link
//! (`securetext-invite`) encoding the onion address, Noise static key, and
//! MLS key package together -- see architecture.md §2. Unlike `demo`/
//! `bench`/`net-listen`/`net-dial`, these two commands use a **persistent**
//! identity and Tor state directory (`--dir`), so the onion address stays
//! stable across runs and an invite printed once remains valid later.

#![forbid(unsafe_code)]
use rusqlite::Connection;
use securetext_crypto::{Member, PersistentProvider};
use securetext_identity::IdentityStore;
use securetext_invite::Invite;
use securetext_net::{Client, Listener, SecureMux};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Open a *second*, independent connection to `identity_store`'s
/// underlying SQLite file and wrap it as an MLS storage provider -- see
/// `IdentityStore::db_path`'s doc comment for why this doesn't just share
/// the store's own `Connection` by reference.
fn mls_provider_for(identity_store: &IdentityStore) -> anyhow::Result<PersistentProvider<Connection>> {
    let connection = Connection::open(identity_store.db_path())?;
    let mut provider = PersistentProvider::new(connection);
    provider.run_migrations()?;
    Ok(provider)
}

/// Find `--name value` in `args` (the args after the subcommand itself).
fn parse_flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// Open (or create, on first run) a persistent identity and its Tor client
/// under `dir`, so both survive across separate process invocations --
/// what makes an invite link printed by one run still valid the next time
/// this identity's process starts. `dir`'s ownership chain must be clean
/// for arti's own sake (platform-support.md; a sandboxed dev environment
/// may need `dir` under e.g. `/tmp` -- see tech-stack.md's implementation
/// findings).
async fn open_persistent_identity(
    dir: &std::path::Path,
    label: &str,
    passphrase: &str,
) -> anyhow::Result<(IdentityStore, securetext_identity::PublicIdentity, Client)> {
    std::fs::create_dir_all(dir)?;
    let identity_path = dir.join("identity.enc");
    let (identity_store, public_identity) = if identity_path.exists() {
        IdentityStore::open(&identity_path, passphrase)?
    } else {
        IdentityStore::create(&identity_path, label, passphrase)?
    };

    let tor = securetext_net::bootstrap_with_dirs(&dir.join("tor-state"), &dir.join("tor-cache")).await?;
    Ok((identity_store, public_identity, tor))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("demo") => run_demo().await,
        Some("bench") => {
            let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20);
            run_bench(n).await
        }
        Some("restart-demo") => run_restart_demo().await,
        Some("rotate-demo") => run_rotate_demo().await,
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
        Some("invite") => {
            let rest = &args[2..];
            let dir = parse_flag(rest, "--dir").ok_or_else(|| anyhow::anyhow!("--dir <path> is required"))?;
            let label = parse_flag(rest, "--label").unwrap_or_else(|| "me".to_string());
            let passphrase = parse_flag(rest, "--passphrase")
                .ok_or_else(|| anyhow::anyhow!("--passphrase <value> is required"))?;
            run_invite(std::path::Path::new(&dir), &label, &passphrase).await
        }
        Some("connect") => {
            let link = args
                .get(2)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("usage: securetext connect <invite-link> --dir <path> --passphrase <value>"))?;
            let rest = &args[3..];
            let dir = parse_flag(rest, "--dir").ok_or_else(|| anyhow::anyhow!("--dir <path> is required"))?;
            let label = parse_flag(rest, "--label").unwrap_or_else(|| "me".to_string());
            let passphrase = parse_flag(rest, "--passphrase")
                .ok_or_else(|| anyhow::anyhow!("--passphrase <value> is required"))?;
            run_connect(&link, std::path::Path::new(&dir), &label, &passphrase).await
        }
        _ => {
            eprintln!("usage: securetext demo | bench [N] | restart-demo | rotate-demo");
            eprintln!("  Runs the Phase 1 proof: two local identities exchange an MLS-encrypted,");
            eprintln!("  Noise-wrapped message over real Tor v3 onion services, in one process.");
            eprintln!();
            eprintln!("usage: securetext net-listen | net-dial <onion-address> <noise-pubkey-hex>");
            eprintln!("  Same round trip split across two separate OS processes (run in two");
            eprintln!("  terminals) -- net-listen prints the onion address and its Noise static");
            eprintln!("  public key; paste both into net-dial's arguments in the other terminal.");
            eprintln!();
            eprintln!("usage: securetext invite --dir <path> --passphrase <value> [--label <name>]");
            eprintln!("usage: securetext connect <invite-link> --dir <path> --passphrase <value> [--label <name>]");
            eprintln!("  Phase 2: a real invite-link exchange (architecture.md §2) instead of");
            eprintln!("  net-listen/net-dial's manual arguments. `--dir` is a persistent identity +");
            eprintln!("  Tor state directory (unlike demo/bench/net-*, which use a fresh one every");
            eprintln!("  run), so the printed invite link keeps working across restarts.");
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
    let (tor, _tor_scratch) = bootstrap_for_this_run().await?;
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

    let (noise, remote_noise_key) =
        securetext_net::handshake_responder(&mut stream, &noise_keys.private).await?;
    println!(
        "[listen] noise handshake complete; dialer's static key: {}",
        to_hex(&remote_noise_key)
    );

    // Wraps the Noise-encrypted stream with yamux multiplexing
    // (architecture.md §6): this side accepts logical streams the dialer
    // opens, since the dialer (Noise initiator) is yamux::Mode::Client.
    let mut mux = SecureMux::new(stream, noise, securetext_net::MuxMode::Server);
    let mut mux_stream = mux
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("dialer never opened a logical stream"))?;

    let received = read_framed(&mut mux_stream).await?;
    println!(
        "[listen] received: {:?}",
        String::from_utf8_lossy(&received)
    );
    write_framed(&mut mux_stream, &received).await?;
    drop(mux_stream);
    mux.close().await?;
    // A mux-level close() alone isn't enough here: this process exits
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
    let (tor, _tor_scratch) = bootstrap_for_this_run().await?;
    println!("[dial] dialing {address}...");
    let mut stream = securetext_net::dial(&tor, address, 1).await?;
    println!("[dial] connected over the onion service (never learned the listener's IP)");

    let noise_keys = snow::Builder::new(securetext_net::NOISE_PATTERN.parse()?).generate_keypair()?;
    let (noise, remote_noise_key) =
        securetext_net::handshake_initiator(&mut stream, &noise_keys.private).await?;
    anyhow::ensure!(
        remote_noise_key == expected_noise_pubkey,
        "listener's Noise static key does not match the expected one -- refusing to trust this connection \
         (presented: {}, expected: {})",
        to_hex(&remote_noise_key),
        to_hex(expected_noise_pubkey)
    );
    println!("[dial] noise handshake complete; listener's identity verified");

    // This side dials, so it's yamux::Mode::Client, opening the logical
    // stream the listener (Mode::Server) accepts.
    let mut mux = SecureMux::new(stream, noise, securetext_net::MuxMode::Client);
    let mut mux_stream = mux.open().await?;

    write_framed(&mut mux_stream, b"hello from a separate process").await?;
    let echoed = read_framed(&mut mux_stream).await?;
    println!("[dial] echo received: {:?}", String::from_utf8_lossy(&echoed));
    anyhow::ensure!(echoed == b"hello from a separate process", "echo mismatch");
    drop(mux_stream);
    mux.close().await?;
    println!("[dial] round trip verified; done");
    Ok(())
}

/// Phase 2: create/open a persistent identity, print an invite link for
/// it, and wait for one holder of that link to connect -- accepts the
/// resulting Welcome on a control stream, joins the group, then exchanges
/// one application message on a chat stream (mirroring `demo`'s shape, but
/// reached via the invite link instead of in-process wiring).
async fn run_invite(dir: &std::path::Path, label: &str, passphrase: &str) -> anyhow::Result<()> {
    println!("[invite] opening/creating identity at {}...", dir.display());
    let (identity_store, public_identity, tor) = open_persistent_identity(dir, label, passphrase).await?;
    let signer = identity_store
        .signing_key_pair(&public_identity)?
        .expect("key pair present");
    let noise_private = identity_store.noise_static_private_key()?;
    let member = Member::new(label, signer, mls_provider_for(&identity_store)?);

    let mut listener = Listener::launch(&tor, "securetext")?;
    let onion_address = listener.onion_address()?;
    let key_package = member.key_package_bytes()?;

    let invite = Invite {
        label: label.to_string(),
        onion_address: onion_address.clone(),
        noise_public_key: public_identity.noise_public_key.clone(),
        mls_key_package: key_package,
        relay: None,
    };
    println!("[invite] share this link:");
    println!("{}", invite.to_link());
    println!("[invite] waiting for someone to connect with it...");

    let mut stream = listener
        .accept_next()
        .await?
        .ok_or_else(|| anyhow::anyhow!("listener closed with no connection"))?;
    println!("[invite] someone connected over the onion service");

    let (noise, remote_noise_key) = securetext_net::handshake_responder(&mut stream, &noise_private).await?;
    println!(
        "[invite] noise handshake complete; connecting party's static key: {}",
        to_hex(&remote_noise_key)
    );

    let mut mux = SecureMux::new(stream, noise, securetext_net::MuxMode::Server);
    let mut control_stream = mux
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("connecting party never opened the control stream"))?;
    let mut chat_stream = mux
        .accept()
        .await
        .ok_or_else(|| anyhow::anyhow!("connecting party never opened the chat stream"))?;

    let welcome_bytes = read_framed(&mut control_stream).await?;
    let mut group = member.join_from_welcome(&welcome_bytes)?;
    println!("[invite] joined the group from the connecting party's Welcome message");

    let ciphertext = read_framed(&mut chat_stream).await?;
    let plaintext = member
        .decrypt(&mut group, &ciphertext)?
        .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
    println!("[invite] received: {:?}", String::from_utf8_lossy(&plaintext));

    let reply = member.encrypt(&mut group, b"Got your message via the invite link!")?;
    write_framed(&mut chat_stream, &reply).await?;
    drop(control_stream);
    drop(chat_stream);
    mux.close().await?;
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    println!("[invite] sent a reply; done");
    Ok(())
}

/// Phase 2: parse an invite link, create/open a persistent identity, and
/// use the invite's onion address + Noise key + MLS key package to reach
/// and add the inviter to a brand-new group -- no manually copy-pasted
/// address or key, unlike `net-dial`.
async fn run_connect(link: &str, dir: &std::path::Path, label: &str, passphrase: &str) -> anyhow::Result<()> {
    let invite = Invite::from_link(link)?;
    println!(
        "[connect] parsed invite for {:?} at {}",
        invite.label, invite.onion_address
    );

    let (identity_store, public_identity, tor) = open_persistent_identity(dir, label, passphrase).await?;
    let signer = identity_store
        .signing_key_pair(&public_identity)?
        .expect("key pair present");
    let member = Member::new(label, signer, mls_provider_for(&identity_store)?);
    let noise_private = identity_store.noise_static_private_key()?;

    let mut group = member.create_group()?;
    let (_commit_bytes, welcome_bytes) = member.add_member(&mut group, &invite.mls_key_package)?;
    println!("[connect] created a new group and added {:?} from their key package", invite.label);

    println!("[connect] dialing {}...", invite.onion_address);
    let mut stream = securetext_net::dial(&tor, &invite.onion_address, 1).await?;
    println!("[connect] connected over the onion service (never learned their IP)");

    let (noise, remote_noise_key) = securetext_net::handshake_initiator(&mut stream, &noise_private).await?;
    anyhow::ensure!(
        remote_noise_key == invite.noise_public_key,
        "the party at this onion address presented a different Noise key than the invite promised \
         -- refusing to trust this connection (presented: {}, expected: {})",
        to_hex(&remote_noise_key),
        to_hex(&invite.noise_public_key)
    );
    println!("[connect] noise handshake complete; identity matches the invite");

    let mut mux = SecureMux::new(stream, noise, securetext_net::MuxMode::Client);
    let mut control_stream = mux.open().await?;
    let mut chat_stream = mux.open().await?;

    write_framed(&mut control_stream, &welcome_bytes).await?;
    println!("[connect] sent Welcome message");

    let ciphertext = member.encrypt(&mut group, b"Hello via your invite link!")?;
    write_framed(&mut chat_stream, &ciphertext).await?;
    println!("[connect] sent an application message");

    let reply_ciphertext = read_framed(&mut chat_stream).await?;
    let reply_plaintext = member
        .decrypt(&mut group, &reply_ciphertext)?
        .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
    println!("[connect] received: {:?}", String::from_utf8_lossy(&reply_plaintext));

    drop(control_stream);
    drop(chat_stream);
    mux.close().await?;
    println!("[connect] done");
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

    let alice = Member::new("alice", alice_signer, mls_provider_for(&alice_store)?);
    let bob = Member::new("bob", bob_signer, mls_provider_for(&bob_store)?);

    let mut alice_group = alice.create_group()?;
    let bob_key_package = bob.key_package_bytes()?;
    let (_commit_bytes, welcome_bytes) = alice.add_member(&mut alice_group, &bob_key_package)?;
    println!("[setup] alice created a 2-member MLS group and added bob (locally, not sent yet; persisted to disk)");

    println!("[tor] bootstrapping bob's Tor client (listener side) — this talks to the real Tor network...");
    let (bob_tor, _bob_tor_scratch): (Client, _) = bootstrap_for_this_run().await?;
    let mut bob_listener = Listener::launch(&bob_tor, "securetext-demo-bob")?;
    let bob_address = bob_listener.onion_address()?;
    println!("[tor] bob is listening on {bob_address}");

    println!("[tor] bootstrapping alice's Tor client (dialer side)...");
    let (alice_tor, _alice_tor_scratch): (Client, _) = bootstrap_for_this_run().await?;

    let expected_alice_noise_key = alice_public.noise_public_key.clone();
    let bob_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        println!("[bob] waiting for alice to connect...");
        let mut stream = bob_listener
            .accept_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("listener closed with no connection"))?;
        println!("[bob] alice connected over the onion service");

        let (noise, alice_noise_key) =
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

        // Two logical streams multiplexed over this one Noise-encrypted
        // onion-service connection (architecture.md §6): a "control"
        // stream carrying the MLS Welcome, and a separate "chat" stream
        // for application messages -- proving multiplexing is actually
        // wired in, not just implemented and unit-tested in isolation.
        let mut mux = SecureMux::new(stream, noise, securetext_net::MuxMode::Server);
        let mut control_stream = mux
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("alice never opened the control stream"))?;
        let mut chat_stream = mux
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("alice never opened the chat stream"))?;

        let welcome_bytes = read_framed(&mut control_stream).await?;
        let mut bob_group = bob.join_from_welcome(&welcome_bytes)?;
        println!("[bob] joined the MLS group from alice's Welcome message (control stream)");

        let ciphertext = read_framed(&mut chat_stream).await?;
        let plaintext = bob
            .decrypt(&mut bob_group, &ciphertext)?
            .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
        println!(
            "[bob] decrypted message from alice (chat stream): {:?}",
            String::from_utf8_lossy(&plaintext)
        );

        let reply = bob.encrypt(&mut bob_group, b"Hi Alice, this came back over Tor!")?;
        write_framed(&mut chat_stream, &reply).await?;
        drop(control_stream);
        drop(chat_stream);
        mux.close().await?;
        // See run_net_listen's comment: mux close() settles the yamux
        // connection but the process still exits right after, which drops
        // the whole TorClient -- see tech-stack.md's implementation
        // findings on why that needs its own grace period too.
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

    let (noise, bob_noise_key) =
        securetext_net::handshake_initiator(&mut stream, &alice_noise_private).await?;
    anyhow::ensure!(
        bob_noise_key == bob_public.noise_public_key,
        "bob's noise key didn't match what his identity published -- refusing to trust this connection"
    );
    println!("[alice] noise handshake complete; bob's identity verified");

    let mut mux = SecureMux::new(stream, noise, securetext_net::MuxMode::Client);
    let mut control_stream = mux.open().await?;
    let mut chat_stream = mux.open().await?;

    write_framed(&mut control_stream, &welcome_bytes).await?;
    println!("[alice] sent Welcome message to bob (control stream)");

    let ciphertext = alice.encrypt(&mut alice_group, b"Hello Bob, this is over Tor!")?;
    write_framed(&mut chat_stream, &ciphertext).await?;
    println!("[alice] sent an encrypted message to bob (chat stream, multiplexed with control stream)");

    let reply_ciphertext = read_framed(&mut chat_stream).await?;
    let reply_plaintext = alice
        .decrypt(&mut alice_group, &reply_ciphertext)?
        .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
    println!(
        "[alice] decrypted reply from bob: {:?}",
        String::from_utf8_lossy(&reply_plaintext)
    );
    drop(control_stream);
    drop(chat_stream);
    mux.close().await?;

    bob_task.await??;
    println!(
        "[done] Phase 1 proof complete: identity + MLS + Noise + yamux + Tor onion services, end to end."
    );
    Ok(())
}

/// Resolves tech-stack.md's open item #5: proves identity *and* MLS group
/// state actually survive a restart, not just "in a unit test with nothing
/// dropped" -- this simulates it for real: identity stores are sealed to
/// their encrypted files and fully dropped (temp files removed), then
/// reopened from those files and the MLS group reloaded by ID, entirely
/// separately from the first run's in-memory state. No Tor involved here
/// deliberately -- this isolates the persistence property from the
/// network layer, which `demo`/`bench` already cover.
async fn run_restart_demo() -> anyhow::Result<()> {
    let work_dir = tempfile::tempdir()?;
    let alice_path = work_dir.path().join("alice.enc");
    let bob_path = work_dir.path().join("bob.enc");

    println!("[restart-demo] === run 1: create identities, form an MLS group, exchange a message ===");
    let alice_group_id = {
        let (alice_store, alice_public) = IdentityStore::create(&alice_path, "alice", "restart demo passphrase")?;
        let (bob_store, bob_public) = IdentityStore::create(&bob_path, "bob", "restart demo passphrase")?;
        let alice_signer = alice_store.signing_key_pair(&alice_public)?.expect("alice key pair");
        let bob_signer = bob_store.signing_key_pair(&bob_public)?.expect("bob key pair");

        let alice = Member::new("alice", alice_signer, mls_provider_for(&alice_store)?);
        let bob = Member::new("bob", bob_signer, mls_provider_for(&bob_store)?);

        let mut alice_group = alice.create_group()?;
        let group_id = alice_group.group_id().clone();
        let bob_key_package = bob.key_package_bytes()?;
        let (_commit_bytes, welcome_bytes) = alice.add_member(&mut alice_group, &bob_key_package)?;
        let mut bob_group = bob.join_from_welcome(&welcome_bytes)?;

        let ciphertext = alice.encrypt(&mut alice_group, b"Hello Bob, before the restart!")?;
        let plaintext = bob
            .decrypt(&mut bob_group, &ciphertext)?
            .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
        println!(
            "[restart-demo] bob decrypted: {:?}",
            String::from_utf8_lossy(&plaintext)
        );

        // Drop the MLS providers (and their SQLite connections) before
        // sealing, so the identity stores' seal() reads a file with no
        // outstanding writers.
        drop(alice_group);
        drop(bob_group);
        drop(alice);
        drop(bob);

        let mut alice_store = alice_store;
        let mut bob_store = bob_store;
        alice_store.seal()?;
        bob_store.seal()?;
        println!("[restart-demo] sealed both identities to disk; dropping everything now (simulated restart)");
        group_id
        // alice_store/bob_store drop here -> their decrypted temp files
        // are removed. Only alice.enc/bob.enc remain on disk.
    };

    println!("[restart-demo] === run 2: reopen identities from their encrypted files, reload the MLS group ===");
    let (alice_store, alice_public) = IdentityStore::open(&alice_path, "restart demo passphrase")?;
    let (bob_store, bob_public) = IdentityStore::open(&bob_path, "restart demo passphrase")?;
    let alice_signer = alice_store.signing_key_pair(&alice_public)?.expect("alice key pair");
    let bob_signer = bob_store.signing_key_pair(&bob_public)?.expect("bob key pair");

    let alice = Member::new("alice", alice_signer, mls_provider_for(&alice_store)?);
    let bob = Member::new("bob", bob_signer, mls_provider_for(&bob_store)?);

    let mut alice_group = alice
        .load_group(&alice_group_id)?
        .ok_or_else(|| anyhow::anyhow!("alice's group was not persisted"))?;
    let mut bob_group = bob
        .load_group(&alice_group_id)?
        .ok_or_else(|| anyhow::anyhow!("bob's group was not persisted"))?;
    println!("[restart-demo] both identities reopened and the MLS group reloaded from disk");

    let ciphertext = alice.encrypt(&mut alice_group, b"Hello again, after the restart!")?;
    let plaintext = bob
        .decrypt(&mut bob_group, &ciphertext)?
        .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
    println!(
        "[restart-demo] bob decrypted (after restart): {:?}",
        String::from_utf8_lossy(&plaintext)
    );

    let reply_ciphertext = bob.encrypt(&mut bob_group, b"Got it, still works!")?;
    let reply_plaintext = alice
        .decrypt(&mut alice_group, &reply_ciphertext)?
        .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
    println!(
        "[restart-demo] alice decrypted (after restart): {:?}",
        String::from_utf8_lossy(&reply_plaintext)
    );

    println!("[done] identity + MLS group state both survived a simulated restart.");
    Ok(())
}

/// Phase 2's last item: onion-address rotation + "I've moved" re-linking
/// (architecture.md §2). Alice hosts (bob dials), they exchange messages,
/// then alice rotates her onion address *and* Noise static key together
/// (rotating only one would weaken the unlinkability this exists to
/// provide) and tells bob via an `AppMessage::Moved` sent through their
/// still-open MLS-encrypted connection -- not a fresh invite. Bob updates
/// his contact record for alice and successfully reconnects at her new
/// address, proving the full rotate-notify-reconnect flow live over Tor.
async fn run_rotate_demo() -> anyhow::Result<()> {
    let work_dir = tempfile::tempdir()?;
    println!("[rotate-demo] setting up identities and an MLS group...");

    let (mut alice_store, alice_public) =
        IdentityStore::create(&work_dir.path().join("alice.enc"), "alice", "rotate demo passphrase")?;
    let (bob_store, bob_public) =
        IdentityStore::create(&work_dir.path().join("bob.enc"), "bob", "rotate demo passphrase")?;
    let alice_signer = alice_store.signing_key_pair(&alice_public)?.expect("alice key pair");
    let bob_signer = bob_store.signing_key_pair(&bob_public)?.expect("bob key pair");
    let alice_mls_public_key = alice_public.public_key.clone();

    let alice = Member::new("alice", alice_signer, mls_provider_for(&alice_store)?);
    let bob = Member::new("bob", bob_signer, mls_provider_for(&bob_store)?);
    let mut alice_group = alice.create_group()?;
    let bob_key_package = bob.key_package_bytes()?;
    let (_commit_bytes, welcome_bytes) = alice.add_member(&mut alice_group, &bob_key_package)?;
    // Both "sides" of this one process already have the plain welcome_bytes
    // value in memory (this demo is about rotation, not re-proving Welcome
    // delivery, which `demo` already covers over a real network) -- bob
    // just joins directly, no network round trip needed for this step.
    let mut bob_group = bob.join_from_welcome(&welcome_bytes)?;

    let (alice_tor, alice_tor_scratch): (Client, _) = bootstrap_for_this_run().await?;
    let (bob_tor, _bob_tor_scratch): (Client, _) = bootstrap_for_this_run().await?;

    let alice_noise_private_v1 = alice_store.noise_static_private_key()?;
    let alice_noise_public_v1 = alice_public.noise_public_key.clone();

    let mut listener_v1 = Listener::launch(&alice_tor, "securetext-rotate-v1")?;
    let address_v1 = listener_v1.onion_address()?;
    println!("[alice] listening at v1 address: {address_v1}");

    let alice_task: tokio::task::JoinHandle<anyhow::Result<(String, Vec<u8>)>> = tokio::spawn(async move {
        // Keep the scratch dir alive for as long as alice_tor (and thus
        // listener_v1/v2) are in use in this task -- see
        // bootstrap_for_this_run's doc comment on why this must not be
        // leaked via `.keep()`.
        let _alice_tor_scratch = alice_tor_scratch;
        // --- First connection: initial exchange, then tell bob we're moving. ---
        let mut stream = listener_v1
            .accept_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("bob never connected to v1"))?;
        let (noise, _bob_noise_key) =
            securetext_net::handshake_responder(&mut stream, &alice_noise_private_v1).await?;
        let mut mux = SecureMux::new(stream, noise, securetext_net::MuxMode::Server);
        let mut chat_stream = mux.accept().await.ok_or_else(|| anyhow::anyhow!("no chat stream"))?;

        let ciphertext = read_framed(&mut chat_stream).await?;
        let plaintext = alice
            .decrypt(&mut alice_group, &ciphertext)?
            .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
        println!("[alice] received: {:?}", String::from_utf8_lossy(&plaintext));

        // --- Rotate: new onion address, new Noise key, together. ---
        let mut listener_v2 = Listener::launch(&alice_tor, "securetext-rotate-v2")?;
        let address_v2 = listener_v2.onion_address()?;
        let new_noise_public_key = alice_store.rotate_noise_key()?;
        let new_noise_private_key = alice_store.noise_static_private_key()?;
        println!("[alice] rotated: new address {address_v2}, new noise key {}", to_hex(&new_noise_public_key));

        let moved = securetext_crypto::AppMessage::Moved {
            new_onion_address: address_v2.clone(),
            new_noise_public_key: new_noise_public_key.clone(),
        };
        let moved_ciphertext = alice.encrypt(&mut alice_group, &moved.to_bytes())?;
        write_framed(&mut chat_stream, &moved_ciphertext).await?;
        println!("[alice] sent an 'I've moved' message over the still-open v1 connection");

        drop(chat_stream);
        mux.close().await?;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // --- Second connection: bob reconnects at the new address. ---
        println!("[alice] waiting for bob to reconnect at the new address...");
        let mut stream = listener_v2
            .accept_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("bob never reconnected at v2"))?;
        let (noise, _bob_noise_key) =
            securetext_net::handshake_responder(&mut stream, &new_noise_private_key).await?;
        let mut mux = SecureMux::new(stream, noise, securetext_net::MuxMode::Server);
        let mut chat_stream = mux.accept().await.ok_or_else(|| anyhow::anyhow!("no chat stream on v2"))?;

        let ciphertext = read_framed(&mut chat_stream).await?;
        let plaintext = alice
            .decrypt(&mut alice_group, &ciphertext)?
            .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
        println!("[alice] received via new address: {:?}", String::from_utf8_lossy(&plaintext));

        let reply = alice.encrypt(&mut alice_group, b"Reconnected after rotation, all good!")?;
        write_framed(&mut chat_stream, &reply).await?;
        drop(chat_stream);
        mux.close().await?;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        Ok((address_v2, new_noise_public_key))
    });

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    println!("[bob] dialing alice's v1 address...");
    let mut stream = securetext_net::dial(&bob_tor, &address_v1, 1).await?;
    let (noise, alice_noise_key) =
        securetext_net::handshake_initiator(&mut stream, &bob_store.noise_static_private_key()?).await?;
    anyhow::ensure!(alice_noise_key == alice_noise_public_v1, "alice's initial noise key mismatch");
    let mut mux = SecureMux::new(stream, noise, securetext_net::MuxMode::Client);
    let mut chat_stream = mux.open().await?;

    // Record alice's contact info as observed from this connection -- a
    // real app would do this for any known group member, not just after
    // an explicit Moved message.
    bob_store.upsert_contact(&securetext_identity::Contact {
        peer_mls_public_key: alice_mls_public_key.clone(),
        peer_label: "alice".to_string(),
        onion_address: address_v1.clone(),
        noise_public_key: alice_noise_public_v1.clone(),
    })?;

    let ciphertext = bob.encrypt(&mut bob_group, b"Hello Alice, before you move!")?;
    write_framed(&mut chat_stream, &ciphertext).await?;
    println!("[bob] sent initial message");

    let moved_ciphertext = read_framed(&mut chat_stream).await?;
    let moved_plaintext = bob
        .decrypt(&mut bob_group, &moved_ciphertext)?
        .ok_or_else(|| anyhow::anyhow!("expected a Moved message"))?;
    match securetext_crypto::AppMessage::from_bytes(&moved_plaintext)? {
        securetext_crypto::AppMessage::Moved { new_onion_address, new_noise_public_key } => {
            println!(
                "[bob] received 'I've moved' -> new address {new_onion_address}, new noise key {}",
                to_hex(&new_noise_public_key)
            );
            bob_store.upsert_contact(&securetext_identity::Contact {
                peer_mls_public_key: alice_mls_public_key.clone(),
                peer_label: "alice".to_string(),
                onion_address: new_onion_address,
                noise_public_key: new_noise_public_key,
            })?;
        }
        securetext_crypto::AppMessage::Chat(_) => anyhow::bail!("expected a Moved message, got chat"),
    }

    drop(chat_stream);
    mux.close().await?;
    println!("[bob] closed the v1 connection; looking up alice's updated contact info...");

    let contact = bob_store
        .get_contact(&alice_mls_public_key)?
        .ok_or_else(|| anyhow::anyhow!("no contact record for alice"))?;

    // v1's dial got an explicit grace period after listener_v1 launched,
    // for the onion service descriptor to propagate through the Tor
    // network before anyone tries to reach it. v2 is launched around the
    // same time as this point in bob's flow, but with no equivalent
    // delay -- confirmed live: this reliably produced "Unable to download
    // hidden service descriptor" without it, and passed consistently once
    // added. Same underlying lesson as `bootstrap_for_this_run`'s: verify
    // the interim CLI's timing assumptions live, don't just assume the
    // first working run generalizes.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    println!("[bob] dialing alice's new address per the updated contact record: {}", contact.onion_address);

    let mut stream = securetext_net::dial(&bob_tor, &contact.onion_address, 1).await?;
    let (noise, alice_noise_key_v2) =
        securetext_net::handshake_initiator(&mut stream, &bob_store.noise_static_private_key()?).await?;
    anyhow::ensure!(
        alice_noise_key_v2 == contact.noise_public_key,
        "alice's rotated noise key didn't match her contact record -- refusing to trust this connection"
    );
    println!("[bob] noise handshake complete; alice's rotated identity verified");

    let mut mux = SecureMux::new(stream, noise, securetext_net::MuxMode::Client);
    let mut chat_stream = mux.open().await?;
    let ciphertext = bob.encrypt(&mut bob_group, b"Reconnecting via your new address!")?;
    write_framed(&mut chat_stream, &ciphertext).await?;

    let reply_ciphertext = read_framed(&mut chat_stream).await?;
    let reply_plaintext = bob
        .decrypt(&mut bob_group, &reply_ciphertext)?
        .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
    println!("[bob] received: {:?}", String::from_utf8_lossy(&reply_plaintext));

    drop(chat_stream);
    mux.close().await?;

    let (returned_address, returned_key) = alice_task.await??;
    anyhow::ensure!(returned_address == contact.onion_address, "address mismatch");
    anyhow::ensure!(returned_key == contact.noise_public_key, "key mismatch");
    println!("[done] onion-address + Noise-key rotation, notified via the existing MLS channel, reconnect verified.");
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

    let alice = Member::new("alice", alice_signer, mls_provider_for(&alice_store)?);
    let bob = Member::new("bob", bob_signer, mls_provider_for(&bob_store)?);
    let mut alice_group = alice.create_group()?;
    let bob_key_package = bob.key_package_bytes()?;
    let (_commit_bytes, welcome_bytes) = alice.add_member(&mut alice_group, &bob_key_package)?;

    let (bob_tor, _bob_tor_scratch): (Client, _) = bootstrap_for_this_run().await?;
    let mut bob_listener = Listener::launch(&bob_tor, "securetext-bench-bob")?;
    let bob_address = bob_listener.onion_address()?;
    let (alice_tor, _alice_tor_scratch): (Client, _) = bootstrap_for_this_run().await?;

    let bob_task: tokio::task::JoinHandle<anyhow::Result<()>> = tokio::spawn(async move {
        let mut stream = bob_listener
            .accept_next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("listener closed with no connection"))?;
        let (noise, _alice_noise_key) =
            securetext_net::handshake_responder(&mut stream, &bob_noise_private).await?;
        let mut mux = SecureMux::new(stream, noise, securetext_net::MuxMode::Server);
        let mut mux_stream = mux
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("alice never opened a stream"))?;

        let welcome_bytes = read_framed(&mut mux_stream).await?;
        let mut bob_group = bob.join_from_welcome(&welcome_bytes)?;

        for _ in 0..n {
            let ciphertext = read_framed(&mut mux_stream).await?;
            bob.decrypt(&mut bob_group, &ciphertext)?
                .ok_or_else(|| anyhow::anyhow!("expected an application message"))?;
            let ack = bob.encrypt(&mut bob_group, b"ack")?;
            write_framed(&mut mux_stream, &ack).await?;
        }
        drop(mux_stream);
        mux.close().await?;
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        Ok(())
    });

    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let mut stream = securetext_net::dial(&alice_tor, &bob_address, 1).await?;
    let (noise, bob_noise_key) =
        securetext_net::handshake_initiator(&mut stream, &alice_noise_private).await?;
    anyhow::ensure!(bob_noise_key == bob_public.noise_public_key, "bob's noise key mismatch");

    let mut mux = SecureMux::new(stream, noise, securetext_net::MuxMode::Client);
    let mut mux_stream = mux.open().await?;

    write_framed(&mut mux_stream, &welcome_bytes).await?;
    println!(
        "[bench] connection established (identity + MLS + Noise + yamux + Tor); starting timed round trips..."
    );

    let mut durations = Vec::with_capacity(n);
    for i in 0..n {
        let msg = format!("bench message {i}");
        let start = std::time::Instant::now();
        let ciphertext = alice.encrypt(&mut alice_group, msg.as_bytes())?;
        write_framed(&mut mux_stream, &ciphertext).await?;
        let ack_ciphertext = read_framed(&mut mux_stream).await?;
        alice
            .decrypt(&mut alice_group, &ack_ciphertext)?
            .ok_or_else(|| anyhow::anyhow!("expected an ack"))?;
        durations.push(start.elapsed());
    }
    drop(mux_stream);
    mux.close().await?;

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
///
/// Returns the `TempDir` guard alongside the client -- **callers must hold
/// onto it for as long as `Client` is used** (it needs to outlive the Tor
/// client, since arti keeps reading/writing state there), but must *not*
/// call `.keep()` on it or otherwise leak it. An earlier version of this
/// function did call `.keep()` (to solve exactly that lifetime problem)
/// and every demo/bench run consequently left a permanent ~40MB directory
/// behind -- across a long testing session that silently filled this
/// sandbox's tmpfs and caused unrelated test failures ("No space left on
/// device") with no connection to the actual change being tested. Letting
/// the guard drop normally when the caller's function returns cleans up
/// automatically while still keeping the directory alive for the whole
/// command's run.
async fn bootstrap_for_this_run() -> anyhow::Result<(Client, tempfile::TempDir)> {
    let scratch = tempfile::tempdir()?;
    let tor = securetext_net::bootstrap_with_dirs(&scratch.path().join("state"), &scratch.path().join("cache")).await?;
    Ok((tor, scratch))
}

/// Plain length-prefixed framing over a (already Noise-encrypted, already
/// multiplexed -- see `SecureMux`) logical stream. No crypto happens at
/// this layer anymore: encryption is handled transparently one layer down
/// by the mux's internal Noise pump, so application code (identity + MLS,
/// here) just needs ordinary message framing over what looks like a plain
/// byte stream.
async fn write_framed<S: AsyncWrite + Unpin>(stream: &mut S, payload: &[u8]) -> anyhow::Result<()> {
    let len = u32::try_from(payload.len())?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    // The lesson from tech-stack.md's implementation findings applies at
    // every layer that buffers: explicit flush, or bytes never actually
    // leave the buffer.
    stream.flush().await?;
    Ok(())
}

async fn read_framed<S: AsyncRead + Unpin>(stream: &mut S) -> anyhow::Result<Vec<u8>> {
    let mut len_bytes = [0u8; 4];
    stream.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(s.len().is_multiple_of(2), "hex string must have an even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(anyhow::Error::from))
        .collect()
}
