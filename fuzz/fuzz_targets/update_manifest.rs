//! The update manifest, as fetched from GitHub over Tor.
#![no_main]
use std::sync::OnceLock;

use securetext_update::ed25519::VerifyingKey;
use securetext_update::manifest::{self, SignedManifest};

fn key() -> &'static VerifyingKey {
    static KEY: OnceLock<VerifyingKey> = OnceLock::new();
    KEY.get_or_init(|| VerifyingKey::from_bytes(&[
        215, 90, 152, 1, 130, 177, 10, 183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243, 218, 166, 35,
        37, 175, 2, 26, 104, 247, 7, 81, 26,
    ]).unwrap())
}

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = SignedManifest::verify(data, &[*key()], manifest::DESKTOP_PRODUCT);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = manifest::parse_public_key(text);
        let _ = manifest::decrypt_signing_key(text, "fuzz passphrase");
        let _ = securetext_update::https::Url::parse(text);
        let _ = manifest::is_upgrade("0.1.0", text);
    }
});
