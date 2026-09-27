//! End-to-end encryption of call media on top of WebRTC's own DTLS-SRTP
//! (architecture.md §9).
//!
//! DTLS-SRTP already runs peer to peer, through the TURN relay, and the
//! DTLS fingerprints it depends on travel inside MLS-encrypted signaling,
//! so the relay can't read media or sit in the middle. This layer adds a
//! second, independent guarantee that doesn't rest on WebRTC's DTLS stack:
//! every audio frame and video frame is sealed with ChaCha20-Poly1305
//! under a per-call key. The caller generates that key at random and
//! distributes it only inside the MLS-encrypted call invitation, so only
//! the conversation's current members can decrypt the media.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

pub const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;

/// What a sealed payload carries, bound into its authentication so an
/// audio frame can't be replayed as video or into another call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MediaKind {
    Audio,
    Video,
}

#[derive(Clone)]
pub struct CallKey {
    cipher: ChaCha20Poly1305,
    call_id: String,
}

impl CallKey {
    pub fn generate() -> [u8; KEY_LEN] {
        let mut key = [0u8; KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut key);
        key
    }

    pub fn new(key: &[u8], call_id: &str) -> anyhow::Result<Self> {
        anyhow::ensure!(key.len() == KEY_LEN, "a call key is {KEY_LEN} bytes");
        Ok(Self { cipher: ChaCha20Poly1305::new(Key::from_slice(key)), call_id: call_id.to_string() })
    }

    fn aad(&self, kind: MediaKind) -> Vec<u8> {
        let mut aad = b"securetext-call-media-v1\0".to_vec();
        aad.extend_from_slice(self.call_id.as_bytes());
        aad.push(match kind {
            MediaKind::Audio => b'a',
            MediaKind::Video => b'v',
        });
        aad
    }

    /// Random nonce per frame (96 bits: no realistic collision risk over a
    /// call's lifetime), prepended to the ciphertext.
    pub fn seal(&self, kind: MediaKind, plaintext: &[u8]) -> Vec<u8> {
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let aad = self.aad(kind);
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
            .expect("ChaCha20-Poly1305 encryption cannot fail for in-memory buffers");
        let mut out = nonce.to_vec();
        out.extend_from_slice(&ciphertext);
        out
    }

    pub fn open(&self, kind: MediaKind, sealed: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::ensure!(sealed.len() > NONCE_LEN, "media frame too short");
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        let aad = self.aad(kind);
        self.cipher
            .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| anyhow::anyhow!("media frame failed authentication"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_open_only_with_the_right_key_call_and_kind() {
        let key = CallKey::generate();
        let a = CallKey::new(&key, "call-1").unwrap();
        let sealed = a.seal(MediaKind::Audio, b"opus frame");
        assert_eq!(a.open(MediaKind::Audio, &sealed).unwrap(), b"opus frame");
        assert!(!sealed.windows(10).any(|w| w == b"opus frame"), "plaintext must not appear");

        assert!(a.open(MediaKind::Video, &sealed).is_err(), "audio replayed as video");
        assert!(CallKey::new(&key, "call-2").unwrap().open(MediaKind::Audio, &sealed).is_err(), "other call");
        assert!(CallKey::new(&CallKey::generate(), "call-1").unwrap().open(MediaKind::Audio, &sealed).is_err());
        let mut flipped = sealed.clone();
        *flipped.last_mut().unwrap() ^= 1;
        assert!(a.open(MediaKind::Audio, &flipped).is_err(), "tampered");
        assert_ne!(sealed, a.seal(MediaKind::Audio, b"opus frame"), "fresh nonce per frame");
    }
}
