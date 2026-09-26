//! Signed, Tor-only updates from GitHub Releases (roadmap Phase 6).
//!
//! - [`manifest`]: the signed manifest attached to each release and the
//!   version policy (strictly newer only; no downgrades).
//! - [`https`]: a minimal HTTPS GET client that runs over whatever
//!   connector it's given. SecureText gives it Tor exit streams from its
//!   own arti client, and nothing else.
//! - [`install`]: detecting how the app was installed, and applying an
//!   update to that kind of install.
//!
//! [`check`] and [`download`] tie these together. Nothing fetched is
//! trusted until the manifest's signature verifies against a pinned key,
//! and nothing downloaded is kept unless its SHA-256 and size match what
//! that signed manifest says.

#![forbid(unsafe_code)]

pub mod https;
pub mod install;
pub mod manifest;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;

use std::io::Write;
use std::path::{Path, PathBuf};

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};

pub use ed25519_dalek as ed25519;
pub use https::{Connector, HttpsClient};
pub use install::{Applied, InstallKind};
pub use manifest::{Asset, Manifest, SignedManifest};

/// Where the desktop app looks for the newest release's manifest. GitHub
/// serves `releases/latest/download/<name>` from whichever release is
/// marked latest, so this URL never changes.
pub const DESKTOP_MANIFEST_URL: &str =
    "https://github.com/erietechsolutions/SecureText/releases/latest/download/securetext-update.json";
pub const MANIFEST_FILE_NAME: &str = "securetext-update.json";

/// A newer release this install can move to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Offer {
    pub version: String,
    pub notes: String,
    pub published_at: i64,
    /// `None` when there's no asset for this kind of install (a source
    /// build, or a platform the release doesn't cover): the user is told a
    /// release exists but it can't be applied from inside the app.
    pub asset: Option<Asset>,
}

/// Fetch and verify the manifest; return an offer if it names a strictly
/// newer version than `current_version`.
pub async fn check(
    client: &HttpsClient,
    manifest_url: &str,
    trusted: &[VerifyingKey],
    current_version: &str,
    kind: &InstallKind,
) -> anyhow::Result<Option<Offer>> {
    let raw = client.get(manifest_url, manifest::MAX_MANIFEST_BYTES).await?;
    let manifest = SignedManifest::verify(&raw, trusted, manifest::DESKTOP_PRODUCT)?;
    if !manifest::is_upgrade(current_version, &manifest.version)? {
        return Ok(None);
    }
    let asset = kind.platform_key().and_then(|key| manifest.assets.get(key).cloned());
    Ok(Some(Offer {
        version: manifest.version,
        notes: manifest.notes,
        published_at: manifest.published_at,
        asset,
    }))
}

/// Download an offer's installer into `staging_dir`, hashing as it
/// streams. Returns the path only if the size and SHA-256 match the signed
/// manifest; otherwise the partial file is deleted.
pub async fn download(client: &HttpsClient, offer: &Offer, kind: &InstallKind, staging_dir: &Path) -> anyhow::Result<PathBuf> {
    let asset = offer
        .asset
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("this release has no installer for this kind of install"))?;
    std::fs::create_dir_all(staging_dir)?;
    // Only one staged update at a time; older ones are stale.
    for entry in std::fs::read_dir(staging_dir)?.flatten() {
        let _ = std::fs::remove_file(entry.path());
    }
    let version = sanitize(&offer.version);
    let path = staging_dir.join(format!("SecureText-{version}.{}", kind.extension()));
    let partial = staging_dir.join(format!("SecureText-{version}.partial"));

    let result = async {
        let mut file = std::fs::File::create(&partial)?;
        let mut hasher = Sha256::new();
        let mut written = 0u64;
        client
            .get_with(&asset.url, asset.size, |chunk| {
                hasher.update(chunk);
                written += chunk.len() as u64;
                file.write_all(chunk)
            })
            .await?;
        file.sync_all()?;
        anyhow::ensure!(written == asset.size, "update download is {written} bytes, expected {}", asset.size);
        let actual: String = hasher.finalize().iter().map(|b| format!("{b:02x}")).collect();
        anyhow::ensure!(
            actual.eq_ignore_ascii_case(&asset.sha256),
            "update download does not match the signed hash; discarded"
        );
        std::fs::rename(&partial, &path)?;
        Ok(path.clone())
    }
    .await;
    if result.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    result
}

fn sanitize(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+')).take(40).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::http_ok;

    #[test]
    fn staged_file_names_cannot_escape_the_staging_directory() {
        assert_eq!(sanitize("1.2.3-rc.1"), "1.2.3-rc.1");
        assert_eq!(sanitize("../../etc/passwd"), "....etcpasswd");
    }

    /// The whole flow against a stand-in for GitHub: signed manifest,
    /// redirect to the CDN host, download, hash check.
    #[tokio::test]
    async fn check_and_download_accept_only_what_the_pinned_key_signed() {
        use ed25519_dalek::SigningKey;
        let key = SigningKey::generate(&mut rand::rngs::OsRng);
        let installer = b"pretend this is SecureText 0.2.0".to_vec();
        let mut assets = std::collections::BTreeMap::new();
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
            notes: "Faster startup.".into(),
            published_at: 1,
            assets,
        };
        let signed = SignedManifest::sign(&m, &key).to_json().into_bytes();
        let mut bad_asset = m.clone();
        bad_asset.assets.get_mut("linux-x86_64-appimage").unwrap().url =
            "https://github.com/o/r/releases/download/v0.2.0/tampered.AppImage".into();
        let signed_bad = SignedManifest::sign(&bad_asset, &key).to_json().into_bytes();
        let routes = vec![
            ("/good.json".to_string(), http_ok(&signed)),
            ("/bad.json".to_string(), http_ok(&signed_bad)),
            (
                "/o/r/releases/download/v0.2.0/SecureText.AppImage".to_string(),
                b"HTTP/1.1 302 Found\r\nLocation: https://objects.githubusercontent.com/a\r\n\r\n".to_vec(),
            ),
            ("/a".to_string(), http_ok(&installer)),
            // Someone swapped the file on the release after signing.
            ("/o/r/releases/download/v0.2.0/tampered.AppImage".to_string(), http_ok(b"pretend this is SecureText 0.2.1")),
        ];
        let (addr, roots) = testing::server(&["github.com", "objects.githubusercontent.com"], routes).await;
        let client = testing::client(addr, roots);
        let trusted = [key.verifying_key()];
        let appimage = InstallKind::AppImage { path: "/nowhere".into() };
        let staging = tempfile::tempdir().unwrap();

        let offer = check(&client, "https://github.com/good.json", &trusted, "0.1.0", &appimage)
            .await
            .unwrap()
            .expect("0.2.0 is newer");
        assert_eq!(offer.notes, "Faster startup.");
        let staged = download(&client, &offer, &appimage, staging.path()).await.unwrap();
        assert_eq!(std::fs::read(&staged).unwrap(), installer);

        // Already up to date: no offer.
        assert!(check(&client, "https://github.com/good.json", &trusted, "0.2.0", &appimage).await.unwrap().is_none());
        // A source build learns about the release but gets nothing to install.
        let dev = check(&client, "https://github.com/good.json", &trusted, "0.1.0", &InstallKind::Development).await.unwrap();
        assert!(dev.unwrap().asset.is_none());
        // Not our key: refused outright.
        let other = SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
        assert!(check(&client, "https://github.com/good.json", &[other], "0.1.0", &appimage).await.is_err());

        // A file that doesn't match its signed hash is discarded.
        let offer = check(&client, "https://github.com/bad.json", &trusted, "0.1.0", &appimage).await.unwrap().unwrap();
        let err = download(&client, &offer, &appimage, staging.path()).await.unwrap_err();
        assert!(err.to_string().contains("does not match the signed hash"), "{err:#}");
        assert_eq!(std::fs::read_dir(staging.path()).unwrap().count(), 0, "nothing left staged");
    }
}
