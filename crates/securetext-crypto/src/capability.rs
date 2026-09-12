//! Signed role/permission capability tokens (architecture.md §7):
//! "pubkey X may post/invite/kick in server Y," checkable by any member
//! without a central authority. A capability is issued by signing a
//! canonical payload with the issuer's MLS identity key
//! (`openmls_basic_credential::SignatureKeyPair`, which already implements
//! `Signer` -- it's the exact same signing key used for MLS group
//! operations, not a separate key) and verified by anyone using the
//! group's ciphersuite's own signature verification
//! (`OpenMlsCrypto::verify_signature`), so no new cryptographic machinery
//! is introduced beyond what MLS already provides.
//!
//! v1 policy model: a single admin key per server (architecture.md §7 --
//! "v1 assumes a single admin keypair per server (the creator); multi-admin
//! / admin transfer is a Phase 3-4 design question"). Anyone can *verify*
//! a capability's signature; whether to *honor* it (i.e., whether the
//! issuer is actually recognized as this group's admin) is an application
//! -level policy decision this module doesn't make -- see
//! `Capability::verify`'s doc comment.

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::{crypto::OpenMlsCrypto, signatures::Signer, types::SignatureScheme};
use serde::{Deserialize, Serialize};

use crate::CryptoError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Permission {
    /// May send application messages in the scope this capability names.
    Post,
    /// May add new members to the scope this capability names.
    Invite,
    /// May remove members from the scope this capability names.
    Kick,
}

/// The signed fields of a capability, minus the signature itself -- this
/// is exactly what gets signed and re-derived for verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CapabilityPayload {
    /// Which group ("server" or, once channels use separate MLS groups,
    /// a specific channel) this capability applies to.
    group_id: Vec<u8>,
    /// Whose capability this is -- the MLS identity public key of the
    /// member being granted the permission.
    subject_public_key: Vec<u8>,
    permission: Permission,
    /// The MLS identity public key of whoever issued this capability.
    issued_by: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Capability {
    payload: CapabilityPayload,
    signature: Vec<u8>,
}

impl Capability {
    /// Issue a capability, signed by `issuer` (typically a server's admin
    /// -- an `openmls_basic_credential::SignatureKeyPair`, the same kind
    /// of key used for MLS group operations, not a separate key type).
    pub fn issue(
        issuer: &SignatureKeyPair,
        group_id: &[u8],
        subject_public_key: &[u8],
        permission: Permission,
    ) -> Result<Self, CryptoError> {
        let payload = CapabilityPayload {
            group_id: group_id.to_vec(),
            subject_public_key: subject_public_key.to_vec(),
            permission,
            issued_by: issuer.to_public_vec(),
        };
        let payload_bytes = serde_json::to_vec(&payload).map_err(|e| CryptoError::Mls(format!("{e:?}")))?;
        let signature = issuer
            .sign(&payload_bytes)
            .map_err(|e| CryptoError::Mls(format!("signing capability: {e:?}")))?;
        Ok(Self { payload, signature })
    }

    pub fn group_id(&self) -> &[u8] {
        &self.payload.group_id
    }

    pub fn subject_public_key(&self) -> &[u8] {
        &self.payload.subject_public_key
    }

    pub fn permission(&self) -> Permission {
        self.payload.permission
    }

    pub fn issued_by(&self) -> &[u8] {
        &self.payload.issued_by
    }

    /// Verify this capability's signature is valid for its claimed issuer.
    ///
    /// **This only proves "whoever holds the private key for
    /// `issued_by` signed exactly this payload"** -- it does *not* prove
    /// `issued_by` is actually a group's recognized admin. That's a
    /// separate, application-level policy check (v1: compare
    /// `issued_by()` against the single admin key the group's creator
    /// published -- architecture.md §7): checking that is deliberately
    /// left to the caller rather than baked in here, since "who is an
    /// admin" is exactly the kind of policy multi-admin support (a Phase
    /// 3-4 open question) would need to change without touching the
    /// signature-verification primitive itself.
    pub fn verify(&self, crypto: &impl OpenMlsCrypto) -> Result<(), CryptoError> {
        let payload_bytes =
            serde_json::to_vec(&self.payload).map_err(|e| CryptoError::Mls(format!("{e:?}")))?;
        crypto
            .verify_signature(SignatureScheme::ED25519, &payload_bytes, &self.payload.issued_by, &self.signature)
            .map_err(|e| CryptoError::Mls(format!("capability signature verification failed: {e:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::OpenMlsProvider;

    #[test]
    fn issued_capability_verifies_for_the_real_issuer() {
        let admin = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
        let provider = OpenMlsRustCrypto::default();

        let capability =
            Capability::issue(&admin, b"some-group-id", b"bobs-public-key", Permission::Post)
                .expect("issue capability");

        assert_eq!(capability.issued_by(), admin.to_public_vec());
        assert_eq!(capability.subject_public_key(), b"bobs-public-key");
        assert_eq!(capability.permission(), Permission::Post);
        capability.verify(provider.crypto()).expect("verifies for the real issuer");
    }

    #[test]
    fn tampered_capability_fails_verification() {
        let admin = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
        let provider = OpenMlsRustCrypto::default();

        let mut capability =
            Capability::issue(&admin, b"some-group-id", b"bobs-public-key", Permission::Post)
                .expect("issue capability");

        // Tamper with the payload after signing (e.g. escalate Post to Kick).
        capability.payload.permission = Permission::Kick;

        assert!(capability.verify(provider.crypto()).is_err());
    }

    #[test]
    fn capability_from_a_different_issuer_fails_verification() {
        let real_admin = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
        let impostor = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
        let provider = OpenMlsRustCrypto::default();

        let mut capability =
            Capability::issue(&real_admin, b"some-group-id", b"bobs-public-key", Permission::Invite)
                .expect("issue capability");

        // Claim it came from the impostor without actually having their
        // signing key -- the signature was made by real_admin, so it
        // won't verify against the impostor's claimed public key.
        capability.payload.issued_by = impostor.to_public_vec();

        assert!(capability.verify(provider.crypto()).is_err());
    }
}
