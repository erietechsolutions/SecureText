//! Release tooling for SecureText maintainers and the release pipeline.
//!
//! ```text
//! securetext-release keygen <secret-key-file> <public-key-file>
//! securetext-release manifest --version 0.2.0 --notes-file NOTES.md \
//!     --base-url https://github.com/<owner>/<repo>/releases/download/v0.2.0 \
//!     --asset linux-x86_64-appimage=path/SecureText.AppImage [--asset ...] \
//!     --key-file <secret-key-file> --out securetext-update.json
//! securetext-release verify securetext-update.json <public-key-file>
//! ```
//!
//! The signing key never goes near CI: whoever controls the GitHub account
//! or its Actions secrets could otherwise sign an update. It lives in a
//! passphrase-encrypted file on the maintainer's machine (ideally on
//! removable, encrypted storage) and is used by `scripts/sign-release.sh`.
//! The passphrase comes from `SECURETEXT_RELEASE_PASSPHRASE` or is read
//! from standard input, never from the command line.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use securetext_update::manifest::{self, Asset, Manifest, SignedManifest};

fn main() {
    if let Err(e) = run(std::env::args().skip(1).collect()) {
        eprintln!("securetext-release: {e:#}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> anyhow::Result<()> {
    match args.first().map(String::as_str) {
        Some("keygen") => {
            let [_, secret, public] = args.as_slice() else { anyhow::bail!("usage: keygen <secret-key-file> <public-key-file>") };
            keygen(Path::new(secret), Path::new(public))
        }
        Some("manifest") => build_manifest(&args[1..]),
        Some("verify") => {
            let [_, file, public] = args.as_slice() else { anyhow::bail!("usage: verify <manifest> <public-key-file>") };
            let key = manifest::parse_public_key(&std::fs::read_to_string(public)?)?;
            let raw = std::fs::read(file)?;
            let m = SignedManifest::verify(&raw, &[key], manifest::DESKTOP_PRODUCT)
                .or_else(|_| SignedManifest::verify(&raw, &[key], manifest::DESKTOP_DEV_PRODUCT))?;
            println!("OK: {} {} ({} assets)", m.product, m.version, m.assets.len());
            for (platform, asset) in &m.assets {
                println!("  {platform}: {} bytes, sha256 {}", asset.size, asset.sha256);
            }
            Ok(())
        }
        _ => anyhow::bail!("usage: securetext-release keygen|manifest|verify ... (see the source for details)"),
    }
}

fn passphrase(confirm: bool) -> anyhow::Result<String> {
    if let Ok(p) = std::env::var("SECURETEXT_RELEASE_PASSPHRASE") {
        return Ok(p);
    }
    let read = |prompt: &str| -> anyhow::Result<String> {
        eprint!("{prompt}");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    };
    eprintln!("(the passphrase is read from standard input and will be visible as you type)");
    let first = read("Signing key passphrase: ")?;
    if confirm {
        anyhow::ensure!(read("Repeat passphrase: ")? == first, "passphrases don't match");
    }
    Ok(first)
}

fn keygen(secret: &Path, public: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(!secret.exists(), "{} already exists; refusing to overwrite a key", secret.display());
    let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
    write_secret(secret, &manifest::encrypt_signing_key(&key, &passphrase(true)?)?)?;
    std::fs::write(
        public,
        format!(
            "# SecureText update-signing public key (Ed25519, base64). Pinned into the app at build time.\n{}\n",
            manifest::encode_public_key(&key.verifying_key())
        ),
    )?;
    eprintln!("wrote {} (keep offline; never commit) and {}", secret.display(), public.display());
    Ok(())
}

#[cfg(unix)]
fn write_secret(path: &Path, text: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    f.write_all(text.as_bytes())?;
    Ok(())
}

#[cfg(not(unix))]
fn write_secret(path: &Path, text: &str) -> anyhow::Result<()> {
    std::fs::write(path, text)?;
    Ok(())
}

fn build_manifest(args: &[String]) -> anyhow::Result<()> {
    let mut version = None;
    let mut notes = String::new();
    let mut base_url = None;
    let mut assets: Vec<(String, PathBuf)> = Vec::new();
    let mut key_file = None;
    let mut product = manifest::DESKTOP_PRODUCT.to_string();
    let mut out = PathBuf::from(securetext_update::MANIFEST_FILE_NAME);
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut value = || it.next().cloned().ok_or_else(|| anyhow::anyhow!("{flag} needs a value"));
        match flag.as_str() {
            "--version" => version = Some(value()?.trim_start_matches('v').to_string()),
            "--notes" => notes = value()?,
            "--notes-file" => notes = std::fs::read_to_string(value()?)?,
            "--base-url" => base_url = Some(value()?.trim_end_matches('/').to_string()),
            "--asset" => {
                let v = value()?;
                let (platform, path) = v.split_once('=').ok_or_else(|| anyhow::anyhow!("--asset wants platform=path"))?;
                assets.push((platform.to_string(), PathBuf::from(path)));
            }
            "--key-file" => key_file = Some(value()?),
            "--channel" => {
                product = match value()?.as_str() {
                    "stable" => manifest::DESKTOP_PRODUCT.into(),
                    "dev" => manifest::DESKTOP_DEV_PRODUCT.into(),
                    other => anyhow::bail!("unknown channel {other} (stable or dev)"),
                }
            }
            "--out" => out = PathBuf::from(value()?),
            other => anyhow::bail!("unknown flag {other}"),
        }
    }
    let version = version.ok_or_else(|| anyhow::anyhow!("--version is required"))?;
    manifest::parse_version(&version)?;
    let base_url = base_url.ok_or_else(|| anyhow::anyhow!("--base-url is required"))?;
    anyhow::ensure!(!assets.is_empty(), "at least one --asset is required");
    let key_file = key_file.ok_or_else(|| anyhow::anyhow!("--key-file is required"))?;
    let key = manifest::decrypt_signing_key(&std::fs::read_to_string(key_file)?, &passphrase(false)?)?;

    let mut map = BTreeMap::new();
    for (platform, path) in assets {
        let bytes = std::fs::read(&path)?;
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("bad asset path {}", path.display()))?;
        // GitHub stores release asset names with spaces turned into dots.
        let name = name.replace(' ', ".");
        map.insert(
            platform,
            Asset { url: format!("{base_url}/{name}"), sha256: manifest::sha256_hex(&bytes), size: bytes.len() as u64 },
        );
    }
    let published_at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
    let m = Manifest { product: product.clone(), version, notes, published_at, assets: map };
    let signed = SignedManifest::sign(&m, &key);
    // Self-check before publishing anything.
    SignedManifest::verify(signed.to_json().as_bytes(), &[key.verifying_key()], &product)?;
    std::fs::write(&out, signed.to_json())?;
    eprintln!("wrote {} for {} ({} assets)", out.display(), m.version, m.assets.len());
    Ok(())
}
