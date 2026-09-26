//! Offline delivery through a store-and-forward relay (Phase 5,
//! architecture.md §4), on the client side.
//!
//! Each user may name one relay as their mailbox host. Their contact card
//! and invite links then carry a [`RelayCard`]: the relay's address, their
//! mailbox ID, and a *mailbox key*. When a direct connection to someone
//! fails, whatever is queued for them is sealed into an [`Envelope`] and
//! left at their relay. They collect it next time they're online, whether
//! or not the sender still is.
//!
//! Layers, from the relay's point of view, outside in:
//!
//! 1. Tor onion-service connection: the relay can't see who connected.
//! 2. Noise with a throwaway client key per connection: nothing links two
//!    deposits by the same sender.
//! 3. The envelope, sealed with ChaCha20-Poly1305 under the recipient's
//!    mailbox key (which the relay never gets) and padded to a 1 KiB
//!    multiple: the relay learns nothing about the sender, the recipient's
//!    identity, or which conversation it's for, and only roughly how big
//!    it is.
//! 4. Inside: the same frames a direct connection would carry, so chat
//!    content is additionally MLS-encrypted end to end.
//!
//! The envelope is signed by the sender's MLS identity key over the exact
//! frame bytes and the recipient's key, so a mailbox-key holder (any of
//! the recipient's contacts) can't forge envelopes as someone else or
//! replay one addressed to a different person.

use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, types::SignatureScheme};
use rand::RngCore;
use securetext_invite::RelayCard;
use securetext_relay::{mailbox_id, RelayAddress};
use serde::{Deserialize, Serialize};

use crate::store::Store;
use crate::wire::{b64, to_hex, from_hex, SignedCard, WireMessage};

const ENVELOPE_CONTEXT: &[u8] = b"securetext-relay-envelope-v1";
const PAD_TO: usize = 1024;
/// Plaintext budget per sealed blob, comfortably under the relay's default
/// 256 KiB blob limit after sealing overhead.
pub(crate) const MAX_ENVELOPE_PLAINTEXT: usize = 180 * 1024;

/// This device's own relay mailbox.
#[derive(Clone)]
pub(crate) struct MyRelay {
    pub address: RelayAddress,
    pub link: String,
    pub secret: Vec<u8>,
    pub key: Vec<u8>,
    pub mailbox: Vec<u8>,
}

impl MyRelay {
    /// A fresh mailbox at the relay `link` points to.
    pub fn new(link: &str) -> anyhow::Result<Self> {
        let address = RelayAddress::parse(link)?;
        let mut secret = vec![0u8; 32];
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret);
        rand::thread_rng().fill_bytes(&mut key);
        Ok(Self { link: address.to_link(), mailbox: mailbox_id(&secret), address, secret, key })
    }

    pub fn load(store: &Store) -> anyhow::Result<Option<Self>> {
        let (Some(link), Some(secret), Some(key)) = (
            store.get_setting("relay_address")?,
            store.get_setting("relay_secret")?,
            store.get_setting("relay_key")?,
        ) else {
            return Ok(None);
        };
        let secret = from_hex(&secret)?;
        Ok(Some(Self {
            address: RelayAddress::parse(&link)?,
            link,
            mailbox: mailbox_id(&secret),
            secret,
            key: from_hex(&key)?,
        }))
    }

    pub fn save(&self, store: &Store) -> anyhow::Result<()> {
        store.set_setting("relay_address", &self.link)?;
        store.set_setting("relay_secret", &to_hex(&self.secret))?;
        store.set_setting("relay_key", &to_hex(&self.key))
    }

    pub fn clear(store: &Store) -> anyhow::Result<()> {
        for key in ["relay_address", "relay_secret", "relay_key"] {
            store.delete_setting(key)?;
        }
        Ok(())
    }

    /// What contacts get: enough to deposit, not to collect.
    pub fn card(&self) -> RelayCard {
        RelayCard { address: self.link.clone(), mailbox: self.mailbox.clone(), key: self.key.clone() }
    }
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    card: SignedCard,
    #[serde(with = "b64")]
    to: Vec<u8>,
    /// The frames, as the exact JSON bytes that were signed.
    frames: String,
    #[serde(with = "b64")]
    signature: Vec<u8>,
}

fn signing_bytes(to: &[u8], frames: &str) -> Vec<u8> {
    let mut bytes = ENVELOPE_CONTEXT.to_vec();
    bytes.extend_from_slice(&(to.len() as u32).to_be_bytes());
    bytes.extend_from_slice(to);
    bytes.extend_from_slice(frames.as_bytes());
    bytes
}

/// Seal `frames` from us (`card`, signed by `signer`) to the holder of
/// MLS key `to`, for their relay mailbox `relay`.
pub(crate) fn seal(
    card: &SignedCard,
    signer: &impl Signer,
    to: &[u8],
    frames: &[WireMessage],
    relay: &RelayCard,
) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(relay.key.len() == 32 && relay.mailbox.len() == 32, "malformed relay card");
    let frames = serde_json::to_string(frames)?;
    let signature = signer
        .sign(&signing_bytes(to, &frames))
        .map_err(|e| anyhow::anyhow!("signing envelope: {e:?}"))?;
    let mut plaintext = serde_json::to_vec(&Envelope { card: card.clone(), to: to.to_vec(), frames, signature })?;
    // JSON ignores trailing whitespace, so padding needs no length field.
    let padded = plaintext.len().div_ceil(PAD_TO) * PAD_TO;
    plaintext.resize(padded, b' ');

    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&relay.key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), AeadPayload { msg: &plaintext, aad: &relay.mailbox })
        .map_err(|_| anyhow::anyhow!("sealing envelope failed"))?;
    let mut blob = nonce.to_vec();
    blob.extend(ciphertext);
    Ok(blob)
}

/// Open a blob from our own mailbox. Returns the verified sender card and
/// the frames they sent us.
pub(crate) fn open(
    blob: &[u8],
    mine: &MyRelay,
    my_key: &[u8],
    crypto: &impl OpenMlsCrypto,
) -> anyhow::Result<(SignedCard, Vec<WireMessage>)> {
    anyhow::ensure!(blob.len() > 12, "blob too short");
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&mine.key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&blob[..12]), AeadPayload { msg: &blob[12..], aad: &mine.mailbox })
        .map_err(|_| anyhow::anyhow!("blob isn't sealed for this mailbox"))?;
    let envelope: Envelope = serde_json::from_slice(&plaintext)?;
    anyhow::ensure!(envelope.to == my_key, "envelope is addressed to someone else");
    envelope.card.verify(crypto)?;
    crypto
        .verify_signature(
            SignatureScheme::ED25519,
            &signing_bytes(&envelope.to, &envelope.frames),
            &envelope.card.card.mls_public_key,
            &envelope.signature,
        )
        .map_err(|e| anyhow::anyhow!("envelope signature is invalid: {e:?}"))?;
    Ok((envelope.card, serde_json::from_str(&envelope.frames)?))
}

/// Split frames into groups that each seal to a blob the relay accepts.
pub(crate) fn batch(frames: Vec<(i64, WireMessage)>) -> Vec<Vec<(i64, WireMessage)>> {
    let mut batches = Vec::new();
    let mut current = Vec::new();
    let mut size = 0;
    for (id, frame) in frames {
        let len = serde_json::to_vec(&frame).map(|v| v.len()).unwrap_or(0);
        if !current.is_empty() && size + len > MAX_ENVELOPE_PLAINTEXT {
            batches.push(std::mem::take(&mut current));
            size = 0;
        }
        size += len;
        current.push((id, frame));
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::ContactCard;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::RustCrypto;

    fn identity(label: &str) -> (SignatureKeyPair, SignedCard) {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let card = ContactCard {
            label: label.into(),
            mls_public_key: signer.to_public_vec(),
            onion_address: format!("{label}.onion"),
            noise_public_key: vec![1; 32],
            relay: None,
        };
        let signed = SignedCard::sign(card, &signer).unwrap();
        (signer, signed)
    }

    fn mailbox() -> MyRelay {
        MyRelay::new(&RelayAddress { onion_address: "relay.onion".into(), noise_public_key: vec![2; 32] }.to_link())
            .unwrap()
    }

    #[test]
    fn sealed_envelopes_open_only_for_their_mailbox_and_recipient() {
        let (alice_signer, alice_card) = identity("alice");
        let (bob_signer, _) = identity("bob");
        let bob_box = mailbox();
        let frames = vec![WireMessage::NeedKeyPackages { count: 2 }];
        let blob = seal(&alice_card, &alice_signer, bob_signer.public(), &frames, &bob_box.card()).unwrap();

        let (from, got) = open(&blob, &bob_box, bob_signer.public(), &RustCrypto::default()).unwrap();
        assert_eq!(from, alice_card);
        assert!(matches!(got.as_slice(), [WireMessage::NeedKeyPackages { count: 2 }]));

        // Padded, so the relay sees only a coarse size.
        assert_eq!((blob.len() - 12 - 16) % PAD_TO, 0);
        // Another mailbox's key can't open it.
        assert!(open(&blob, &mailbox(), bob_signer.public(), &RustCrypto::default()).is_err());
        // Nor can it be redirected to someone else sharing the mailbox key.
        let (carol_signer, _) = identity("carol");
        assert!(open(&blob, &bob_box, carol_signer.public(), &RustCrypto::default()).is_err());
    }

    #[test]
    fn a_contact_cannot_forge_an_envelope_as_someone_else() {
        // Mallory has Bob's mailbox key (she's his contact too) and Alice's
        // public card. She can seal, but not sign as Alice.
        let (_alice_signer, alice_card) = identity("alice");
        let (mallory_signer, _) = identity("mallory");
        let (bob_signer, _) = identity("bob");
        let bob_box = mailbox();
        let forged = seal(&alice_card, &mallory_signer, bob_signer.public(), &[], &bob_box.card()).unwrap();
        let err = open(&forged, &bob_box, bob_signer.public(), &RustCrypto::default()).unwrap_err();
        assert!(err.to_string().contains("signature"), "{err}");
    }
}
