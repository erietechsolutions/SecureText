//! Invite links (architecture.md §2, Phase 2): a single shareable string
//! encoding everything needed to reach and cryptographically bootstrap a
//! session with someone, replacing Phase 1's manual copy-paste of an onion
//! address, a Noise static key, and an MLS key package as three separate
//! values.
//!
//! An invite is fundamentally a **contact card**: "here's how to reach me
//! (my onion address), here's how to know it's really me (my Noise static
//! key), and here's what you need to add me to a conversation (my MLS key
//! package)." Whoever holds the invite dials the onion address, verifies
//! the Noise key during the handshake, and uses the key package to add the
//! inviter to a new or existing MLS group — matching the flow already
//! proven in `securetext-cli`'s `demo`/`net-listen`/`net-dial`, just
//! packaged as one opaque string instead of separate arguments.
//!
//! The invite link is the trust anchor in this model (Trust-On-First-Use):
//! whatever channel the string travels over (a QR code, another
//! already-trusted messaging app, in person) is what vouches for it. This
//! matches how Signal/Session/Cwtch-style invite mechanisms work; it is
//! not a new trust model invented here.

use serde::{Deserialize, Serialize};

const SCHEME_PREFIX: &str = "securetext1:";

#[derive(thiserror::Error, Debug)]
pub enum InviteError {
    #[error("not a securetext invite link (missing '{SCHEME_PREFIX}' prefix)")]
    WrongScheme,
    #[error("invite link is not valid base64: {0}")]
    Base64(String),
    #[error("invite link is malformed: {0}")]
    Malformed(String),
}

/// A parsed invite: everything needed to reach and cryptographically
/// bootstrap a session with the identity that created it.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Invite {
    /// Display label chosen by the inviter (crypto-spec.md §1's local,
    /// unverified label) -- shown to the recipient before they connect, not
    /// a verified identity claim.
    pub label: String,
    /// The inviter's onion address (architecture.md §2) -- the entire
    /// reachability model; no DHT, no other discovery mechanism.
    pub onion_address: String,
    /// The inviter's Noise static public key (crypto-spec.md §4). The
    /// dialer verifies the responder presents exactly this key during the
    /// handshake before trusting the connection -- this is the "know it's
    /// really them" property, not the onion address alone (an onion
    /// address is unguessable but a different party can't accidentally
    /// or maliciously use *this* invite without also holding the matching
    /// Noise private key).
    #[serde(with = "as_base64")]
    pub noise_public_key: Vec<u8>,
    /// The inviter's serialized MLS `KeyPackage` (crypto-spec.md §2) --
    /// what the invite holder uses to add the inviter to a new or
    /// existing MLS group.
    #[serde(with = "as_base64")]
    pub mls_key_package: Vec<u8>,
    /// Where to leave messages for the inviter while they're offline
    /// (Phase 5's store-and-forward relay, architecture.md §4). Omitted
    /// from the link entirely when unset, so links without one are
    /// unchanged from Phase 2's format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayCard>,
}

/// Everything someone needs to leave sealed messages for you at your
/// relay: the relay's address (a `securetext-relay1:` link, which pins the
/// relay's own key), your mailbox ID there, and the key senders seal
/// envelopes with so the relay can't read them.
///
/// Hand this only to people you'd accept messages from. It lets them
/// deposit into your mailbox, but not read or delete from it (that takes
/// the mailbox *secret*, which never leaves your device).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayCard {
    pub address: String,
    #[serde(with = "as_base64")]
    pub mailbox: Vec<u8>,
    #[serde(with = "as_base64")]
    pub key: Vec<u8>,
}

/// Serializes a `Vec<u8>` field as a base64 string instead of serde_json's
/// default JSON array-of-numbers, which is dramatically more compact for
/// byte blobs like keys and key packages -- meaningfully shrinks the
/// resulting invite link (relevant if it's ever put in a QR code).
mod as_base64 {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        serializer.serialize_str(&encoded)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map_err(serde::de::Error::custom)
    }
}

impl Invite {
    /// Encode as a single shareable string.
    pub fn to_link(&self) -> String {
        use base64::Engine;
        let json = serde_json::to_vec(self).expect("Invite always serializes");
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json);
        format!("{SCHEME_PREFIX}{encoded}")
    }

    /// Parse a string previously produced by [`Invite::to_link`].
    pub fn from_link(link: &str) -> Result<Self, InviteError> {
        use base64::Engine;
        let encoded = link.strip_prefix(SCHEME_PREFIX).ok_or(InviteError::WrongScheme)?;
        let json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded.trim())
            .map_err(|e| InviteError::Base64(e.to_string()))?;
        serde_json::from_slice(&json).map_err(|e| InviteError::Malformed(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_through_a_link_string() {
        let invite = Invite {
            label: "alice".to_string(),
            onion_address: "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwxyz2345.onion"
                .to_string(),
            noise_public_key: vec![1, 2, 3, 4, 5],
            mls_key_package: vec![9, 9, 9, 8, 8, 8, 7],
            relay: None,
        };

        let link = invite.to_link();
        assert!(link.starts_with(SCHEME_PREFIX));

        let parsed = Invite::from_link(&link).expect("parse");
        assert_eq!(parsed, invite);
    }

    #[test]
    fn relay_card_is_optional_and_round_trips() {
        let mut invite = Invite {
            label: "alice".to_string(),
            onion_address: "example.onion".to_string(),
            noise_public_key: vec![1; 32],
            mls_key_package: vec![2; 8],
            relay: None,
        };
        // Without a relay the link carries no trace of the field, so it's
        // exactly the Phase 2 format.
        let plain = invite.to_link();
        assert!(!String::from_utf8(
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, &plain[SCHEME_PREFIX.len()..]).unwrap()
        )
        .unwrap()
        .contains("relay"));

        invite.relay = Some(RelayCard {
            address: "securetext-relay1:relay.onion#key".to_string(),
            mailbox: vec![3; 32],
            key: vec![4; 32],
        });
        assert_eq!(Invite::from_link(&invite.to_link()).unwrap(), invite);
    }

    #[test]
    fn rejects_a_link_with_the_wrong_scheme() {
        let result = Invite::from_link("https://example.com/not-an-invite");
        assert!(matches!(result, Err(InviteError::WrongScheme)));
    }

    #[test]
    fn rejects_garbage_after_a_valid_scheme() {
        let result = Invite::from_link("securetext1:not-valid-base64-json!!!");
        assert!(result.is_err());
    }
}
