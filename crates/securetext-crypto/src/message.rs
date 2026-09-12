//! Structured application payloads sent through an MLS-encrypted channel
//! (`Member::encrypt`/`decrypt` deal in raw bytes; this is the small,
//! optional layer on top that lets a chat message and a control message
//! like "I've moved" share the same encrypted transport without the
//! crypto layer itself needing to know about either).
//!
//! Authenticity of the *sender* of an `AppMessage` is already provided by
//! MLS itself -- `process_message` verifies the sender's credential as
//! part of the protocol, so a `Moved` message arriving through an existing
//! group is already known to come from that group member's identity key,
//! with no separate signature needed here.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AppMessage {
    /// An ordinary chat message.
    Chat(Vec<u8>),
    /// Sent when a member rotates their onion address and/or Noise static
    /// key (architecture.md §2's unlinkability rotation) -- lets existing
    /// contacts update how they reach this identity without a fresh
    /// invite exchange. Delivered over the same MLS-encrypted channel the
    /// contact is already part of, so it inherits that channel's
    /// authenticity and confidentiality for free.
    Moved {
        new_onion_address: String,
        new_noise_public_key: Vec<u8>,
    },
}

impl AppMessage {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("AppMessage always serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}
