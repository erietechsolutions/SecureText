//! Store-and-forward relay (Phase 5, architecture.md §4): a blind mailbox
//! that holds encrypted blobs for someone who is offline until they come
//! back and collect them.
//!
//! Kept deliberately small (tech-stack.md: "store blob, TTL, opaque routing
//! ID lookup") because every line here is audit surface. What a relay
//! knows, and doesn't:
//!
//! - It's reachable **only** as a Tor onion service, and serves nothing
//!   else. Onion-service connections carry no client address, so a relay
//!   never learns a depositor's or collector's IP.
//! - It stores opaque blobs under an opaque 32-byte mailbox ID. The blobs
//!   are sealed by the sender with a key the relay never sees (see
//!   `securetext-app`'s relay envelope), and what's inside that seal is
//!   MLS ciphertext, so there are two layers between the relay and any
//!   content. It can't tell who sent a blob; senders connect anonymously
//!   with a fresh Noise key per connection.
//! - It does see that *some* mailbox received N blobs of certain sizes at
//!   roughly certain times, and when they were collected (crypto-spec.md
//!   §6 lists this as accepted residual metadata). Deposit times are
//!   stored rounded to the hour to keep less of that at rest.
//!
//! Collecting requires the mailbox *secret*: the mailbox ID is
//! `SHA-256(context || secret)`, so people who can deposit (anyone given
//! the mailbox ID) can't read or delete what's there.

#![forbid(unsafe_code)]

use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub mod client;
pub mod server;
pub mod store;

pub use store::{Limits, RelayStore};

const ADDRESS_PREFIX: &str = "securetext-relay1:";
const MAILBOX_CONTEXT: &[u8] = b"securetext-relay-mailbox-v1";

/// Largest request frame a relay accepts: one maximum-size blob, base64
/// encoded, plus framing.
pub const MAX_REQUEST_FRAME: usize = 512 * 1024;
/// Largest response frame a client accepts.
pub const MAX_RESPONSE_FRAME: usize = 4 * 1024 * 1024;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum RelayError {
    #[error("blob is larger than this relay accepts")]
    TooLarge,
    #[error("that mailbox is full")]
    MailboxFull,
    #[error("the relay is out of space")]
    RelayFull,
}

/// Where a relay is and how to authenticate it: its onion address plus
/// its Noise static public key, pinned the same way a contact's is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayAddress {
    pub onion_address: String,
    pub noise_public_key: Vec<u8>,
}

impl RelayAddress {
    pub fn to_link(&self) -> String {
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&self.noise_public_key);
        format!("{ADDRESS_PREFIX}{}#{key}", self.onion_address)
    }

    pub fn parse(link: &str) -> anyhow::Result<Self> {
        let rest = link
            .trim()
            .strip_prefix(ADDRESS_PREFIX)
            .ok_or_else(|| anyhow::anyhow!("not a SecureText relay address (should start with {ADDRESS_PREFIX})"))?;
        let (onion, key) = rest
            .split_once('#')
            .ok_or_else(|| anyhow::anyhow!("relay address is missing its key"))?;
        anyhow::ensure!(
            onion.ends_with(".onion") && onion.len() > ".onion".len(),
            "relay address must be an onion address"
        );
        let noise_public_key = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(key)
            .map_err(|e| anyhow::anyhow!("relay key is not valid base64: {e}"))?;
        anyhow::ensure!(noise_public_key.len() == 32, "relay key has the wrong length");
        Ok(Self { onion_address: onion.to_string(), noise_public_key })
    }
}

/// The public mailbox ID for a mailbox secret.
pub fn mailbox_id(secret: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(MAILBOX_CONTEXT);
    hasher.update(secret);
    hasher.finalize().to_vec()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Request {
    /// Leave a blob in a mailbox. Anyone who knows the mailbox ID can.
    Deposit {
        #[serde(with = "b64")]
        mailbox: Vec<u8>,
        #[serde(with = "b64")]
        blob: Vec<u8>,
    },
    /// Read (without deleting) up to `limit` blobs from the mailbox whose
    /// ID is derived from `secret`.
    Fetch {
        #[serde(with = "b64")]
        secret: Vec<u8>,
        limit: u32,
    },
    /// Delete collected blobs. Separate from `Fetch` so a client that
    /// crashes mid-collection loses nothing.
    Ack {
        #[serde(with = "b64")]
        secret: Vec<u8>,
        ids: Vec<i64>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredBlob {
    pub id: i64,
    #[serde(with = "b64")]
    pub blob: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Response {
    Deposited,
    Blobs { items: Vec<StoredBlob> },
    Acked { removed: u32 },
    Error { reason: String },
}

mod b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        base64::engine::general_purpose::STANDARD
            .decode(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

pub(crate) async fn write_json<S, T>(stream: &mut S, value: &T) -> std::io::Result<()>
where
    S: tokio::io::AsyncWrite + Unpin,
    T: Serialize,
{
    use tokio::io::AsyncWriteExt;
    let bytes = serde_json::to_vec(value).map_err(std::io::Error::other)?;
    stream.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

pub(crate) async fn read_json<S, T>(stream: &mut S, max: usize) -> std::io::Result<Option<T>>
where
    S: tokio::io::AsyncRead + Unpin,
    T: serde::de::DeserializeOwned,
{
    use tokio::io::AsyncReadExt;
    let mut len = [0u8; 4];
    match stream.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > max {
        return Err(std::io::Error::other(format!("frame of {len} bytes is over the {max}-byte limit")));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map(Some).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_address_round_trips_and_rejects_junk() {
        let addr = RelayAddress { onion_address: "abcdef.onion".into(), noise_public_key: vec![9; 32] };
        assert_eq!(RelayAddress::parse(&addr.to_link()).unwrap(), addr);
        assert!(RelayAddress::parse("securetext1:abc").is_err());
        assert!(RelayAddress::parse("securetext-relay1:example.com#AAAA").is_err());
        assert!(RelayAddress::parse("securetext-relay1:abcdef.onion#AAAA").is_err()); // short key
    }

    #[test]
    fn mailbox_id_is_one_way_and_distinct() {
        let a = mailbox_id(&[1; 32]);
        assert_eq!(a.len(), 32);
        assert_ne!(a, mailbox_id(&[2; 32]));
        assert_ne!(a, vec![1; 32]);
    }
}
