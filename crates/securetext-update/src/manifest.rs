//! The signed update manifest: what the newest release is, and the hash of
//! each platform's installer.
//!
//! One file, `securetext-update.json`, is attached to every GitHub Release.
//! It holds the manifest's exact bytes (base64) and an Ed25519 signature
//! over them made with the update-signing key. The app pins that key's
//! public half at build time, so a manifest is only believed if the key
//! holder signed it: control of the GitHub account, the release, the
//! download CDN or the Tor exit is not enough to push an update.
//!
//! Installers aren't signed individually. The signed manifest carries each
//! one's SHA-256 and exact size, and a download that doesn't match both is
//! thrown away before anything runs it.

use std::collections::BTreeMap;

use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Domain separation: a signature made for anything else with the same
/// key can never pass as a manifest signature.
const SIGNATURE_CONTEXT: &[u8] = b"securetext-update-manifest-v1\0";

/// The product every manifest must name, so a validly signed manifest for
/// some other artifact (the relay, a future mobile app) can't be fed to
/// the desktop app.
pub const DESKTOP_PRODUCT: &str = "securetext-desktop";

/// Manifests are small; anything bigger is refused before parsing.
pub const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
/// Upper bound on one installer download.
pub const MAX_ASSET_BYTES: u64 = 400 * 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Manifest {
    pub product: String,
    /// Semantic version, without a leading `v`.
    pub version: String,
    /// Release notes shown to the user before they install.
    pub notes: String,
    /// Unix seconds.
    pub published_at: i64,
    /// Platform key (see [`crate::install::InstallKind::platform_key`]) to
    /// installer.
    pub assets: BTreeMap<String, Asset>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Asset {
    pub url: String,
    /// Lowercase hex.
    pub sha256: String,
    pub size: u64,
}

/// The file as published: the manifest's exact signed bytes plus the
/// signature. Keeping the bytes opaque means verification never depends
/// on re-serializing JSON the same way twice.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedManifest {
    pub manifest: String,
    pub signature: String,
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum ManifestError {
    #[error("the update manifest is malformed: {0}")]
    Malformed(String),
    #[error("the update manifest is not signed by a trusted key")]
    BadSignature,
    #[error("the update manifest is for {0}, not {1}")]
    WrongProduct(String, String),
    #[error("the update manifest has an invalid version: {0}")]
    BadVersion(String),
}

impl SignedManifest {
    pub fn sign(manifest: &Manifest, key: &SigningKey) -> Self {
        let bytes = serde_json::to_vec(manifest).expect("Manifest always serializes");
        let signature = key.sign(&signing_input(&bytes));
        Self {
            manifest: b64().encode(&bytes),
            signature: b64().encode(signature.to_bytes()),
        }
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("SignedManifest always serializes")
    }

    /// Parse the published file and check it against the pinned keys (any
    /// one of them, so the key can be rotated by shipping the new key in a
    /// release signed with the old one). Returns the manifest only if a
    /// trusted key signed these exact bytes and it names `product`.
    pub fn verify(raw: &[u8], trusted: &[VerifyingKey], product: &str) -> Result<Manifest, ManifestError> {
        if raw.len() as u64 > MAX_MANIFEST_BYTES {
            return Err(ManifestError::Malformed("too large".into()));
        }
        let signed: SignedManifest =
            serde_json::from_slice(raw).map_err(|e| ManifestError::Malformed(e.to_string()))?;
        let bytes = b64()
            .decode(&signed.manifest)
            .map_err(|e| ManifestError::Malformed(e.to_string()))?;
        let signature = b64()
            .decode(&signed.signature)
            .ok()
            .and_then(|s| Signature::from_slice(&s).ok())
            .ok_or_else(|| ManifestError::Malformed("bad signature encoding".into()))?;
        let input = signing_input(&bytes);
        if !trusted.iter().any(|key| key.verify_strict(&input, &signature).is_ok()) {
            return Err(ManifestError::BadSignature);
        }
        // Only now is the content worth looking at.
        let manifest: Manifest =
            serde_json::from_slice(&bytes).map_err(|e| ManifestError::Malformed(e.to_string()))?;
        if manifest.product != product {
            return Err(ManifestError::WrongProduct(manifest.product, product.into()));
        }
        parse_version(&manifest.version)?;
        for asset in manifest.assets.values() {
            if asset.sha256.len() != 64 || !asset.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ManifestError::Malformed("asset hash is not SHA-256 hex".into()));
            }
            if asset.size == 0 || asset.size > MAX_ASSET_BYTES {
                return Err(ManifestError::Malformed("asset size out of range".into()));
            }
        }
        Ok(manifest)
    }
}

fn signing_input(manifest_bytes: &[u8]) -> Vec<u8> {
    let mut input = SIGNATURE_CONTEXT.to_vec();
    input.extend_from_slice(manifest_bytes);
    input
}

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD
}

pub fn parse_version(v: &str) -> Result<semver::Version, ManifestError> {
    semver::Version::parse(v.trim_start_matches('v')).map_err(|e| ManifestError::BadVersion(format!("{v}: {e}")))
}

/// Whether `candidate` should replace `current`. Strictly newer only: a
/// replayed old manifest (still validly signed) must never roll anyone
/// back to a version with known holes. Pre-releases are only offered to
/// people already running a pre-release.
pub fn is_upgrade(current: &str, candidate: &str) -> Result<bool, ManifestError> {
    let current = parse_version(current)?;
    let candidate = parse_version(candidate)?;
    if !candidate.pre.is_empty() && current.pre.is_empty() {
        return Ok(false);
    }
    Ok(candidate > current)
}

/// Parse a public key as written in `update-signing.pub` / by
/// `securetext-release keygen`: base64 of the 32 raw bytes, optionally
/// surrounded by comment lines starting with `#`.
pub fn parse_public_key(text: &str) -> anyhow::Result<VerifyingKey> {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .ok_or_else(|| anyhow::anyhow!("no key found"))?;
    let bytes: [u8; 32] = b64()
        .decode(line)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("an update public key is 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

pub fn encode_public_key(key: &VerifyingKey) -> String {
    b64().encode(key.as_bytes())
}

const KEY_FILE_HEADER: &str = "securetext-update-signing-key-v1";
const KEY_SALT_LEN: usize = 16;
const KEY_NONCE_LEN: usize = 12;

/// The signing key as stored on disk: encrypted under a passphrase with
/// Argon2id + ChaCha20-Poly1305 (the same construction as the app's
/// profile, crypto-spec.md §5), so a copy of the file alone can't sign
/// anything.
pub fn encrypt_signing_key(key: &SigningKey, passphrase: &str) -> anyhow::Result<String> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    use rand::RngCore;
    anyhow::ensure!(passphrase.chars().count() >= 12, "use a passphrase of at least 12 characters");
    let mut salt = [0u8; KEY_SALT_LEN];
    let mut nonce = [0u8; KEY_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let wrapping = derive_wrapping_key(passphrase, &salt)?;
    let cipher = chacha20poly1305::ChaCha20Poly1305::new((&*wrapping).into());
    let secret = zeroize::Zeroizing::new(key.to_bytes());
    let ciphertext = cipher
        .encrypt((&nonce).into(), secret.as_slice())
        .map_err(|_| anyhow::anyhow!("encrypting the signing key failed"))?;
    let mut blob = salt.to_vec();
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);
    Ok(format!("{KEY_FILE_HEADER}\n{}\n", b64().encode(blob)))
}

pub fn decrypt_signing_key(text: &str, passphrase: &str) -> anyhow::Result<SigningKey> {
    use chacha20poly1305::aead::{Aead, KeyInit};
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    anyhow::ensure!(lines.next() == Some(KEY_FILE_HEADER), "not a SecureText update-signing key file");
    let blob = b64().decode(lines.next().ok_or_else(|| anyhow::anyhow!("key file is truncated"))?)?;
    anyhow::ensure!(blob.len() == KEY_SALT_LEN + KEY_NONCE_LEN + 32 + 16, "key file is corrupt");
    let (salt, rest) = blob.split_at(KEY_SALT_LEN);
    let (nonce, ciphertext) = rest.split_at(KEY_NONCE_LEN);
    let wrapping = derive_wrapping_key(passphrase, salt)?;
    let cipher = chacha20poly1305::ChaCha20Poly1305::new((&*wrapping).into());
    let secret = zeroize::Zeroizing::new(
        cipher
            .decrypt(nonce.into(), ciphertext)
            .map_err(|_| anyhow::anyhow!("wrong passphrase, or the key file is corrupt"))?,
    );
    let bytes: [u8; 32] = secret.as_slice().try_into()?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn derive_wrapping_key(passphrase: &str, salt: &[u8]) -> anyhow::Result<zeroize::Zeroizing<[u8; 32]>> {
    // Stronger than the app's interactive setting: this runs once per
    // release, so it can afford to be slow.
    let params = argon2::Params::new(256 * 1024, 4, 1, Some(32)).map_err(|e| anyhow::anyhow!("{e}"))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut out = zeroize::Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(passphrase.as_bytes(), salt, out.as_mut())
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    Ok(out)
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    fn manifest(version: &str) -> Manifest {
        let mut assets = BTreeMap::new();
        assets.insert(
            "linux-x86_64-appimage".into(),
            Asset { url: "https://github.com/x/y/releases/download/v1/a.AppImage".into(), sha256: "ab".repeat(32), size: 10 },
        );
        Manifest {
            product: DESKTOP_PRODUCT.into(),
            version: version.into(),
            notes: "fixes".into(),
            published_at: 1,
            assets,
        }
    }

    #[test]
    fn a_signed_manifest_verifies_and_any_change_breaks_it() {
        let k = key();
        let signed = SignedManifest::sign(&manifest("1.2.0"), &k);
        let raw = signed.to_json().into_bytes();
        assert_eq!(SignedManifest::verify(&raw, &[k.verifying_key()], DESKTOP_PRODUCT).unwrap(), manifest("1.2.0"));

        // Someone who controls the release but not the key can't change
        // where the installer comes from or what it hashes to.
        let mut tampered_manifest = manifest("1.2.0");
        tampered_manifest.assets.get_mut("linux-x86_64-appimage").unwrap().sha256 = "cd".repeat(32);
        let tampered = SignedManifest {
            manifest: b64().encode(serde_json::to_vec(&tampered_manifest).unwrap()),
            signature: signed.signature.clone(),
        };
        assert_eq!(
            SignedManifest::verify(tampered.to_json().as_bytes(), &[k.verifying_key()], DESKTOP_PRODUCT),
            Err(ManifestError::BadSignature)
        );

        // Nor sign with their own key.
        let impostor = SignedManifest::sign(&manifest("1.2.0"), &key());
        assert_eq!(
            SignedManifest::verify(impostor.to_json().as_bytes(), &[k.verifying_key()], DESKTOP_PRODUCT),
            Err(ManifestError::BadSignature)
        );

        // A valid manifest for another product is refused too.
        assert!(matches!(
            SignedManifest::verify(&raw, &[k.verifying_key()], "securetext-relay"),
            Err(ManifestError::WrongProduct(..))
        ));
    }

    #[test]
    fn any_pinned_key_is_accepted_so_the_key_can_rotate() {
        let (old, new) = (key(), key());
        let signed = SignedManifest::sign(&manifest("2.0.0"), &new);
        SignedManifest::verify(signed.to_json().as_bytes(), &[old.verifying_key(), new.verifying_key()], DESKTOP_PRODUCT)
            .unwrap();
    }

    #[test]
    fn only_strictly_newer_versions_are_upgrades() {
        assert!(is_upgrade("0.1.0", "0.2.0").unwrap());
        assert!(is_upgrade("0.1.0", "v0.1.1").unwrap());
        assert!(!is_upgrade("0.2.0", "0.2.0").unwrap(), "same version");
        assert!(!is_upgrade("0.2.0", "0.1.9").unwrap(), "downgrade");
        assert!(!is_upgrade("0.2.0", "0.3.0-rc.1").unwrap(), "pre-release to a stable user");
        assert!(is_upgrade("0.3.0-rc.1", "0.3.0").unwrap());
        assert!(is_upgrade("0.3.0-rc.1", "0.3.0-rc.2").unwrap());
        assert!(is_upgrade("0.1.0", "banana").is_err());
    }

    #[test]
    fn keys_round_trip_through_their_text_form() {
        let k = key();
        let text = format!("# SecureText update key\n{}\n", encode_public_key(&k.verifying_key()));
        assert_eq!(parse_public_key(&text).unwrap(), k.verifying_key());
    }

    #[test]
    fn the_signing_key_file_is_useless_without_its_passphrase() {
        let k = key();
        let file = encrypt_signing_key(&k, "correct horse battery").unwrap();
        assert!(!file.contains(&b64().encode(k.to_bytes())), "the raw key must not appear in the file");
        assert_eq!(decrypt_signing_key(&file, "correct horse battery").unwrap().to_bytes(), k.to_bytes());
        assert!(decrypt_signing_key(&file, "wrong horse battery").is_err());
        assert!(encrypt_signing_key(&k, "short").is_err(), "weak passphrases are refused");
    }
}
