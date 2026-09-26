//! Automatic updates through the running node (Phase 6), against a local
//! stand-in for GitHub Releases. The real app fetches through Tor exits;
//! here the same HTTPS client is pointed at a local TLS server, and the
//! signed-manifest, version and hash checks all run for real.

use std::collections::BTreeMap;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use securetext_app::update::{manifest, testing, Asset, InstallKind, Manifest, SignedManifest};
use securetext_app::{MemoryNetwork, NetworkConfig, NodeConfig, NodeHandle, UpdateConfig, UpdateState};

const WAIT: Duration = Duration::from_secs(20);

struct Release {
    key: SigningKey,
    installer: Vec<u8>,
    client: securetext_app::update::HttpsClient,
}

/// A "GitHub" serving a signed 0.2.0 release with an AppImage.
async fn release() -> Release {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let installer = b"SecureText 0.2.0 AppImage".to_vec();
    let mut assets = BTreeMap::new();
    assets.insert(
        "linux-x86_64-appimage".to_string(),
        Asset {
            url: "https://github.com/o/r/releases/download/v0.2.0/SecureText.AppImage".into(),
            sha256: manifest::sha256_hex(&installer),
            size: installer.len() as u64,
        },
    );
    let m = Manifest {
        product: manifest::DESKTOP_PRODUCT.into(),
        version: "0.2.0".into(),
        notes: "Voice calls.".into(),
        published_at: 1,
        assets,
    };
    let routes = vec![
        ("/latest.json".to_string(), testing::http_ok(SignedManifest::sign(&m, &key).to_json().as_bytes())),
        ("/o/r/releases/download/v0.2.0/SecureText.AppImage".to_string(), testing::http_ok(&installer)),
    ];
    let (addr, roots) = testing::server(&["github.com"], routes).await;
    Release { key, installer, client: testing::client(addr, roots) }
}

fn config(dir: &std::path::Path, release: &Release, first_check: Duration) -> NodeConfig {
    NodeConfig {
        profile_dir: dir.join("me"),
        label: "me".into(),
        passphrase: "me passphrase".into(),
        network: NetworkConfig::Memory { network: MemoryNetwork::new(), address: "me.onion".into() },
        retry_interval: Duration::from_millis(100),
        dial_timeout: Duration::from_secs(5),
        presence_interval: Duration::from_secs(3600),
        relay_poll_interval: Duration::from_secs(3600),
        update: Some(UpdateConfig {
            current_version: "0.1.0".into(),
            manifest_url: "https://github.com/latest.json".into(),
            trusted_keys: vec![release.key.verifying_key()],
            install: InstallKind::AppImage { path: dir.join("SecureText.AppImage") },
            staging_dir: dir.join("updates"),
            first_check: (first_check, first_check),
            interval: Duration::from_secs(24 * 3600),
            client_override: Some(release.client.clone()),
        }),
    }
}

async fn wait_for_state(node: &NodeHandle, what: &str, pred: impl Fn(&UpdateState) -> bool) -> UpdateState {
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let status = node.update_status().await.unwrap().expect("updates are enabled");
        if pred(&status.state) {
            return status.state;
        }
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}; last state {:?}", status.state);
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn a_scheduled_check_finds_downloads_and_verifies_an_update_but_waits_for_the_user() {
    let dir = tempfile::tempdir().unwrap();
    let release = release().await;
    let node = NodeHandle::start(config(dir.path(), &release, Duration::from_millis(300))).await.unwrap();
    let mut events = node.subscribe();

    let state = wait_for_state(&node, "the update to be downloaded", |s| matches!(s, UpdateState::Ready { .. })).await;
    assert_eq!(
        state,
        UpdateState::Ready { version: "0.2.0".into(), notes: "Voice calls.".into(), system_installer: false }
    );
    let (path, asset, kind) = node.staged_update().await.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), release.installer);
    securetext_app::update::install::verify_file(&path, &asset.sha256, asset.size).unwrap();
    assert!(matches!(kind, InstallKind::AppImage { .. }));
    // Downloading isn't installing: the "installed" AppImage is untouched
    // until the user chooses to restart (the shell applies it then).
    assert!(!dir.path().join("SecureText.AppImage").exists());

    // The UI heard about it without polling.
    let mut saw_ready = false;
    while let Ok(event) = events.try_recv() {
        if let securetext_app::Event::Update { status } = event {
            saw_ready |= matches!(status.state, UpdateState::Ready { .. });
        }
    }
    assert!(saw_ready, "an Update event announced the ready download");
    node.shutdown().await;
}

#[tokio::test]
async fn turning_updates_off_stops_automatic_checks_and_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let release = release().await;
    // First check far in the future, so nothing happens before we switch off.
    let node = NodeHandle::start(config(dir.path(), &release, Duration::from_secs(3600))).await.unwrap();
    let status = node.set_auto_update(false).await.unwrap().unwrap();
    assert!(!status.auto);
    node.shutdown().await;

    // Restarted with the first check due almost immediately: it must not run.
    let node = NodeHandle::start(config(dir.path(), &release, Duration::from_millis(100))).await.unwrap();
    assert!(!node.update_status().await.unwrap().unwrap().auto, "the setting persisted");
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(node.update_status().await.unwrap().unwrap().state, UpdateState::Idle);

    // A manual check still works, and with auto off it only reports.
    node.check_for_updates().await.unwrap();
    let state = wait_for_state(&node, "the manual check", |s| matches!(s, UpdateState::Available { .. })).await;
    assert_eq!(
        state,
        UpdateState::Available { version: "0.2.0".into(), notes: "Voice calls.".into(), installable: true }
    );
    node.download_update().await.unwrap();
    wait_for_state(&node, "the manual download", |s| matches!(s, UpdateState::Ready { .. })).await;
    node.shutdown().await;
}

#[tokio::test]
async fn a_release_signed_with_another_key_is_reported_and_never_downloaded() {
    let dir = tempfile::tempdir().unwrap();
    let release = release().await;
    let mut cfg = config(dir.path(), &release, Duration::from_millis(100));
    // This build pins a different key than the one the release was signed with.
    cfg.update.as_mut().unwrap().trusted_keys = vec![SigningKey::generate(&mut rand::rngs::OsRng).verifying_key()];
    let node = NodeHandle::start(cfg).await.unwrap();
    let state = wait_for_state(&node, "the check to fail", |s| matches!(s, UpdateState::Failed { .. })).await;
    let UpdateState::Failed { error } = state else { unreachable!() };
    assert!(error.contains("not signed by a trusted key"), "{error}");
    assert!(node.staged_update().await.is_err());
    assert!(!dir.path().join("updates").exists() || std::fs::read_dir(dir.path().join("updates")).unwrap().count() == 0);
    node.shutdown().await;
}

/// The updater's real transport: a GitHub release download (which
/// redirects to GitHub's CDN host) fetched through a Tor exit by the same
/// client the app uses, with TLS checked against the bundled roots. Needs
/// the live Tor network, so it's ignored by default:
///   cargo test -p securetext-app --test update_flow -- --ignored --nocapture
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn fetches_a_real_github_release_asset_over_tor_live() {
    let scratch = tempfile::tempdir().unwrap();
    let tor = securetext_net_client(scratch.path()).await;
    let client = securetext_app::tor_https_client(tor);
    // A small, long-lived asset of a public project's release.
    let url = "https://github.com/cli/cli/releases/download/v2.60.0/gh_2.60.0_checksums.txt";
    let started = std::time::Instant::now();
    let body = client.get(url, 1024 * 1024).await.expect("fetch over Tor");
    eprintln!("fetched {} bytes over Tor in {:?}", body.len(), started.elapsed());
    assert!(String::from_utf8_lossy(&body).contains("gh_2.60.0_linux_amd64.tar.gz"));
}

async fn securetext_net_client(dir: &std::path::Path) -> securetext_net::Client {
    securetext_net::bootstrap_with_dirs(&dir.join("state"), &dir.join("cache")).await.expect("bootstrap Tor")
}
