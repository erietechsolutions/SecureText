//! `securetext-relay --dir <path>`: run a store-and-forward relay as a Tor
//! onion service (Phase 5, architecture.md §4).
//!
//! Everything lives under `--dir`: the relay's Noise key, its mailbox
//! database, and its Tor state (which holds the onion service key, so the
//! address stays the same across restarts). On start it prints the relay
//! address that users paste into SecureText's offline-delivery setting,
//! and writes it to `<dir>/address` (where packaged installs find it:
//! `/var/lib/securetext-relay/address`). The relay never opens a clearnet
//! listener.

#![forbid(unsafe_code)]
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use securetext_relay::{server, Limits, RelayAddress, RelayStore};

const NICKNAME: &str = "securetext-relay";
/// Connections served at once. Past this, new ones are dropped straight
/// away, so a flood of connections can't exhaust the relay's memory.
const MAX_CONNECTIONS: usize = 256;

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--version") {
        println!("securetext-relay {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let dir = args
        .iter()
        .position(|a| a == "--dir")
        .and_then(|i| args.get(i + 1))
        .map(PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("usage: securetext-relay --dir <path>"))?;
    std::fs::create_dir_all(&dir)?;

    let (noise_public, noise_private) = load_or_create_key(&dir.join("relay-noise.key"))?;
    let store = Arc::new(Mutex::new(RelayStore::open(&dir.join("mailboxes.db"), Limits::default())?));

    eprintln!("[securetext-relay] connecting to Tor...");
    let tor = securetext_net::bootstrap_with_dirs(&dir.join("tor-state"), &dir.join("tor-cache")).await?;
    let mut listener = securetext_net::Listener::launch(&tor, NICKNAME)?;
    let address = RelayAddress { onion_address: listener.onion_address()?, noise_public_key: noise_public };
    println!("{}", address.to_link());
    std::fs::write(dir.join("address"), format!("{}\n", address.to_link()))?;
    eprintln!("[securetext-relay] serving. Give the address above to SecureText users (Settings > Offline delivery).");

    let prune_store = store.clone();
    tokio::spawn(async move {
        let mut hourly = tokio::time::interval(std::time::Duration::from_secs(3600));
        loop {
            hourly.tick().await;
            let pruned = prune_store.lock().map(|s| s.prune(server::now_secs()));
            if let Ok(Ok(n)) = pruned {
                if n > 0 {
                    eprintln!("[securetext-relay] expired {n} uncollected blob(s)");
                }
            }
        }
    });

    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
    loop {
        match listener.accept_next().await {
            Ok(Some(stream)) => {
                let Ok(slot) = slots.clone().try_acquire_owned() else { continue };
                let store = store.clone();
                let key = noise_private.clone();
                tokio::spawn(async move {
                    let _slot = slot;
                    // Errors here are per-connection (a client going away
                    // mid-request); they don't affect the relay.
                    let _ = server::serve_connection(stream, &key, store).await;
                });
            }
            Ok(None) => anyhow::bail!("onion service stopped"),
            Err(e) => eprintln!("[securetext-relay] incoming connection failed: {e}"),
        }
    }
}

/// The relay's long-term Noise key, created on first run. Stored as
/// public||private, readable only by the owner.
fn load_or_create_key(path: &Path) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    if let Ok(bytes) = std::fs::read(path) {
        anyhow::ensure!(bytes.len() == 64, "{} is corrupt", path.display());
        return Ok((bytes[..32].to_vec(), bytes[32..].to_vec()));
    }
    let keys = snow::Builder::new(securetext_net::NOISE_PATTERN.parse()?)
        .generate_keypair()
        .map_err(|e| anyhow::anyhow!("noise keygen: {e:?}"))?;
    let mut bytes = keys.public.clone();
    bytes.extend_from_slice(&keys.private);
    write_private(path, &bytes)?;
    Ok((keys.public, keys.private))
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(bytes)?;
    Ok(())
}

#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    // Windows: the file inherits the (per-user) ACL of the relay's data
    // directory.
    std::fs::write(path, bytes)?;
    Ok(())
}
