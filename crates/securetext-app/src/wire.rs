//! The peer-to-peer protocol spoken over an established connection (Tor
//! onion service -> Noise_XX -> yamux stream), plus the payloads carried
//! *inside* MLS application messages.
//!
//! Two layers, deliberately kept apart:
//!
//! - [`WireMessage`] travels between two directly connected peers. Only the
//!   Noise session protects it, so it never carries plaintext chat. It
//!   carries MLS ciphertext, MLS Welcomes, key packages, and signed contact
//!   cards.
//! - [`Payload`] is what gets MLS-encrypted: chat text and the admin's
//!   roster announcements. Anything a group member says to the group goes
//!   here, so only current group members can read it.

use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, types::SignatureScheme};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Largest frame accepted from a peer. A Welcome for a large group is the
/// biggest legitimate message; this bounds how much memory one malicious
/// peer can make us allocate per frame.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;

const CARD_SIGNATURE_CONTEXT: &[u8] = b"securetext-contact-card-v1";

/// How to reach someone and how to recognise them: the same information an
/// invite link carries, plus the MLS identity key it belongs to.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ContactCard {
    /// Self-chosen display label (crypto-spec.md §1): shown, never trusted.
    pub label: String,
    #[serde(with = "b64")]
    pub mls_public_key: Vec<u8>,
    pub onion_address: String,
    #[serde(with = "b64")]
    pub noise_public_key: Vec<u8>,
    /// Their offline-delivery mailbox, if they have one (Phase 5). Left out
    /// of the serialized card when unset, so cards without one sign and
    /// verify exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<securetext_invite::RelayCard>,
}

/// A [`ContactCard`] signed by the MLS identity key it names.
///
/// The signature is what lets a card be forwarded safely: an admin
/// announcing a new server member's card, or a peer presenting its own card
/// in a `Hello`, cannot change where that member's traffic gets routed
/// without the member's private key. Combined with the Noise handshake
/// check (the connection's static key must equal the card's
/// `noise_public_key`), a verified card binds a live connection to an MLS
/// identity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedCard {
    pub card: ContactCard,
    #[serde(with = "b64")]
    pub signature: Vec<u8>,
}

impl SignedCard {
    pub fn sign(card: ContactCard, signer: &impl Signer) -> anyhow::Result<Self> {
        let signature = signer
            .sign(&card_signing_bytes(&card))
            .map_err(|e| anyhow::anyhow!("signing contact card: {e:?}"))?;
        Ok(Self { card, signature })
    }

    /// Checks the card was signed by the MLS key it names. Says nothing
    /// about whether that key belongs to anyone in particular; that is the
    /// invite link's job (trust on first use).
    pub fn verify(&self, crypto: &impl OpenMlsCrypto) -> anyhow::Result<()> {
        crypto
            .verify_signature(
                SignatureScheme::ED25519,
                &card_signing_bytes(&self.card),
                &self.card.mls_public_key,
                &self.signature,
            )
            .map_err(|e| anyhow::anyhow!("contact card signature is invalid: {e:?}"))
    }
}

fn card_signing_bytes(card: &ContactCard) -> Vec<u8> {
    let mut bytes = CARD_SIGNATURE_CONTEXT.to_vec();
    bytes.extend(serde_json::to_vec(card).expect("ContactCard always serializes"));
    bytes
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConversationKind {
    Dm,
    Server,
    Channel,
}

impl ConversationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dm => "dm",
            Self::Server => "server",
            Self::Channel => "channel",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "dm" => Some(Self::Dm),
            "server" => Some(Self::Server),
            "channel" => Some(Self::Channel),
            _ => None,
        }
    }
}

/// What a Welcome is *for*. MLS itself only knows about groups; the app
/// needs to know whether a new group is a DM, a server, or one of a
/// server's channels.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ConversationInfo {
    pub kind: ConversationKind,
    pub name: String,
    /// Set for channels: the server group this channel belongs to.
    #[serde(default, with = "b64_opt")]
    pub server_group_id: Option<Vec<u8>>,
    /// The MLS identity key allowed to add/remove members (v1: the
    /// creator; architecture.md §7).
    #[serde(with = "b64")]
    pub admin_public_key: Vec<u8>,
    #[serde(default)]
    pub private: bool,
    /// Server Welcomes carry the server's current settings (roles,
    /// categories, channel layout), so the newcomer sees the same server as
    /// everyone else from the start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_state: Option<Vec<StampedEdit>>,
}

/// One field of a server's settings (see `node/server.rs`): `key` names
/// the field, `value` is its JSON value (`None` = deleted).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Edit {
    pub key: String,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
}

/// An edit with the stamp that decides which of two concurrent edits
/// wins: the higher Lamport clock, then the higher author key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct StampedEdit {
    pub key: String,
    #[serde(default)]
    pub value: Option<serde_json::Value>,
    pub lamport: u64,
    #[serde(with = "b64")]
    pub author: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum WireMessage {
    /// First frame the dialing side sends on every connection.
    Hello { card: SignedCard },
    /// Invitation into an MLS group. `roster` carries the signed cards of
    /// the group's other members so the joiner can reach them directly;
    /// there is no server to relay through.
    Welcome {
        #[serde(with = "b64")]
        welcome: Vec<u8>,
        info: ConversationInfo,
        roster: Vec<SignedCard>,
    },
    /// An MLS handshake or application message for one group.
    Mls {
        #[serde(with = "b64")]
        group_id: Vec<u8>,
        #[serde(with = "b64")]
        message: Vec<u8>,
    },
    /// Fresh single-use key packages the receiver may use to add the
    /// sender to groups later (e.g. inviting a contact into a server).
    KeyPackages {
        #[serde(with = "b64_vec")]
        packages: Vec<Vec<u8>>,
    },
    /// Ask the peer for more key packages; their pool with us ran low.
    NeedKeyPackages { count: u32 },
    /// A queued frame, tagged with the sender's outbox ID. The receiver
    /// processes `message` and answers with `Ack { id }`; only then does
    /// the sender drop it from its outbox. A successful socket write
    /// proves nothing (a peer that vanished without closing the
    /// connection still "accepts" writes for a while), so delivery is
    /// confirmed end to end instead.
    Tracked { id: i64, message: Box<WireMessage> },
    Ack { id: i64 },
    /// The sender's status (Phase 8), for peers it's connected to. Only
    /// the Noise session protects it (it isn't about any one conversation),
    /// and it's never stored, queued or relayed.
    Presence { status: String, text: String },
    /// Ask for a piece of an attachment's ciphertext (Phase 8). Answered
    /// only for members of the conversation the file was shared in.
    FileRequest { file_id: String, offset: u64 },
    FileChunk {
        file_id: String,
        offset: u64,
        #[serde(with = "b64")]
        data: Vec<u8>,
    },
    /// The asked-for file isn't available from this peer (not a member,
    /// or not downloaded yet).
    FileUnavailable { file_id: String },
}

/// A file shared in a message: what's needed to fetch its ciphertext from
/// whoever has it, check it, and decrypt it. Carried inside MLS, so the
/// key reaches only the conversation's members.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttachmentRef {
    pub file_id: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    pub cipher_size: u64,
    pub cipher_sha256: String,
    #[serde(with = "b64")]
    pub key: Vec<u8>,
}

/// The plaintext inside an MLS application message.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum Payload {
    Chat {
        id: String,
        body: String,
        sent_at: i64,
        /// Phase 8 fields, left out when unset so older clients still read
        /// plain messages. The thread this replies in (root message id):
        #[serde(default, skip_serializing_if = "Option::is_none")]
        reply_to: Option<String>,
        /// Disappearing messages: seconds after which recipients delete it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expires_in: Option<i64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attachment: Option<AttachmentRef>,
    },
    /// Add or remove an emoji reaction to a message.
    Reaction { target: String, emoji: String, on: bool },
    /// Set (or, with `None`, clear) the conversation's disappearing-message
    /// timer. DMs: either person; channels: members with Manage Channels.
    Disappear { secs: Option<i64> },
    /// Changes to a server's settings (roles, layout, names), sent in the
    /// server's group. Each edit is checked against its author's
    /// permissions by every receiver.
    ServerEdit { lamport: u64, edits: Vec<Edit> },
    /// Sent by a server's admin to announce members' contact cards, so
    /// every member can reach every other member directly. MLS
    /// authenticates the admin as the sender; each card's own signature
    /// authenticates its contents.
    Roster { cards: Vec<SignedCard> },
    /// Call signaling (Phase 7). Travels like any other group message, so
    /// only members can read it and MLS authenticates who sent it. That's
    /// what makes the DTLS fingerprints in the SDP trustworthy. Sent live
    /// only, never queued or left at a relay: a ring that arrives late is
    /// useless.
    Call { call_id: String, signal: CallSignal },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "s", rename_all = "snake_case")]
pub enum CallSignal {
    /// Start of a call. `key` seals every media frame (securetext-call's
    /// crypto module); `turn` is the caller's TURN server, which members
    /// without their own may use.
    Ring {
        video: bool,
        #[serde(with = "b64")]
        key: Vec<u8>,
        turn: Vec<securetext_call::TurnServer>,
        started_at: i64,
    },
    /// The sender is now in the call. Participants already in it offer
    /// them a connection.
    Join,
    /// WebRTC session descriptions, addressed to one participant.
    Offer {
        #[serde(with = "b64")]
        to: Vec<u8>,
        sdp: String,
    },
    Answer {
        #[serde(with = "b64")]
        to: Vec<u8>,
        sdp: String,
    },
    Leave,
    Decline,
}

impl Payload {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("Payload always serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> serde_json::Result<Self> {
        serde_json::from_slice(bytes)
    }
}

pub async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, message: &WireMessage) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(message).map_err(std::io::Error::other)?;
    let len = u32::try_from(bytes.len()).map_err(std::io::Error::other)?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    // Every buffering layer in this stack needs an explicit flush
    // (tech-stack.md's implementation findings).
    stream.flush().await
}

/// Returns `Ok(None)` on a clean end of stream.
pub async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<Option<WireMessage>> {
    let mut len_bytes = [0u8; 4];
    match stream.read_exact(&mut len_bytes).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::other(format!("frame of {len} bytes exceeds the {MAX_FRAME}-byte limit")));
    }
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await?;
    serde_json::from_slice(&buf).map(Some).map_err(std::io::Error::other)
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(s: &str) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(s.len().is_multiple_of(2), "hex string must have an even length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(anyhow::Error::from))
        .collect()
}

/// Byte fields as base64 strings rather than JSON number arrays, for the
/// same size reason as `securetext-invite`.
pub(crate) mod b64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&base64::engine::general_purpose::STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}

pub(crate) mod b64_opt {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_some(&base64::engine::general_purpose::STANDARD.encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|encoded| {
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(serde::de::Error::custom)
            })
            .transpose()
    }
}

pub(crate) mod b64_vec {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(items: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error> {
        items
            .iter()
            .map(|bytes| base64::engine::general_purpose::STANDARD.encode(bytes))
            .collect::<Vec<_>>()
            .serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(deserializer)?
            .into_iter()
            .map(|encoded| {
                base64::engine::general_purpose::STANDARD
                    .decode(encoded)
                    .map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::RustCrypto;

    fn card_for(signer: &SignatureKeyPair) -> ContactCard {
        ContactCard {
            label: "alice".into(),
            mls_public_key: signer.to_public_vec(),
            onion_address: "example.onion".into(),
            noise_public_key: vec![7; 32],
            relay: None,
        }
    }

    #[test]
    fn signed_card_verifies_and_rejects_tampering() {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let signed = SignedCard::sign(card_for(&signer), &signer).unwrap();
        signed.verify(&RustCrypto::default()).expect("genuine card verifies");

        // Redirecting the card to an attacker's address must break it.
        let mut redirected = signed.clone();
        redirected.card.onion_address = "attacker.onion".into();
        assert!(redirected.verify(&RustCrypto::default()).is_err());

        // So must claiming someone else's identity key.
        let other = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        let mut stolen = signed;
        stolen.card.mls_public_key = other.to_public_vec();
        assert!(stolen.verify(&RustCrypto::default()).is_err());
    }

    #[tokio::test]
    async fn frames_round_trip_and_oversized_frames_are_rejected() {
        let (mut a, mut b) = tokio::io::duplex(1024 * 1024);
        let message = WireMessage::NeedKeyPackages { count: 3 };
        write_frame(&mut a, &message).await.unwrap();
        match read_frame(&mut b).await.unwrap() {
            Some(WireMessage::NeedKeyPackages { count: 3 }) => {}
            other => panic!("unexpected frame: {other:?}"),
        }

        a.write_all(&(MAX_FRAME as u32 + 1).to_be_bytes()).await.unwrap();
        assert!(read_frame(&mut b).await.is_err());

        drop(a);
        assert!(read_frame(&mut b).await.unwrap().is_none());
    }
}
