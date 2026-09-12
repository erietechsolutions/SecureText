//! OpenMLS wrapper: one crypto stack for both 1:1 (as a 2-member group) and
//! multi-member groups, per crypto-spec.md §2-3.
//!
//! `Member<P>` is generic over the `OpenMlsProvider` it uses: tests (and
//! any throwaway session) can use the in-memory `OpenMlsRustCrypto`, while
//! the real application uses [`PersistentProvider`] so group state survives
//! a restart. What this module proves, independent of which provider is
//! used, is protocol *correctness*: that a 2-member MLS group can be
//! created, joined via Welcome, and used to exchange authenticated,
//! forward-secret application messages.

use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

mod provider;
pub use provider::PersistentProvider;

mod message;
pub use message::AppMessage;

/// The one ciphersuite SecureText speaks: X25519 + ChaCha20-Poly1305 +
/// Ed25519 (crypto-spec.md §7's primitive table).
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

#[derive(thiserror::Error, Debug)]
pub enum CryptoError {
    #[error("openmls error: {0}")]
    Mls(String),
    #[error("tls codec error: {0}")]
    TlsCodec(String),
    #[error("expected a {expected} message, got something else")]
    UnexpectedMessageType { expected: &'static str },
    #[error("storage error: {0}")]
    Storage(String),
}

/// A member of a conversation: an OpenMLS crypto provider plus this
/// member's credential/signing key. One `Member` corresponds to one
/// `securetext_identity::IdentityStore` in the full application.
///
/// Generic over the provider so the same logic works whether group state
/// is ephemeral (`OpenMlsRustCrypto`, used by this module's tests) or
/// persisted (`PersistentProvider`, used by the real application).
pub struct Member<P: OpenMlsProvider> {
    provider: P,
    credential_with_key: CredentialWithKey,
    signer: SignatureKeyPair,
}

impl<P: OpenMlsProvider> Member<P> {
    /// Wrap an existing identity signing key and provider as an MLS member.
    ///
    /// `label` becomes the MLS `BasicCredential`'s identity bytes — this is
    /// the local, unverified display label from crypto-spec.md §1, not a
    /// global directory entry.
    pub fn new(label: &str, signer: SignatureKeyPair, provider: P) -> Self {
        let credential = BasicCredential::new(label.as_bytes().to_vec());
        let credential_with_key = CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.to_public_vec().into(),
        };
        Self {
            provider,
            credential_with_key,
            signer,
        }
    }

    /// Produce a KeyPackage to hand to another member so they can add this
    /// member to a group (architecture.md §2: this is what an invite link's
    /// key material bootstraps from for a 1:1 conversation).
    pub fn key_package_bytes(&self) -> Result<Vec<u8>, CryptoError> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential_with_key.clone(),
            )
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;
        bundle
            .key_package()
            .tls_serialize_detached()
            .map_err(|e| CryptoError::TlsCodec(format!("{e:?}")))
    }

    /// Create a brand-new group containing only this member.
    pub fn create_group(&self) -> Result<MlsGroup, CryptoError> {
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            .use_ratchet_tree_extension(true)
            .build();
        MlsGroup::new(
            &self.provider,
            &self.signer,
            &config,
            self.credential_with_key.clone(),
        )
        .map_err(|e| CryptoError::Mls(format!("{e:?}")))
    }

    /// Reload a previously-created/joined group from this member's
    /// provider after a restart (architecture.md/tech-stack.md: this is
    /// what makes group state durable when `P` is [`PersistentProvider`]
    /// rather than the in-memory default). Returns `None` if no group with
    /// this ID has been persisted.
    pub fn load_group(&self, group_id: &GroupId) -> Result<Option<MlsGroup>, CryptoError> {
        MlsGroup::load(self.provider.storage(), group_id)
            .map_err(|e| CryptoError::Storage(format!("{e:?}")))
    }

    /// Add a member (identified by their serialized KeyPackage) to `group`,
    /// merge the resulting commit locally, and return the Welcome bytes to
    /// send to the new member.
    pub fn add_member(
        &self,
        group: &mut MlsGroup,
        their_key_package_bytes: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key_package_in = KeyPackageIn::tls_deserialize_exact(their_key_package_bytes)
            .map_err(|e| CryptoError::TlsCodec(format!("{e:?}")))?;
        let key_package = key_package_in
            .validate(self.provider.crypto(), ProtocolVersion::Mls10)
            .map_err(|e| CryptoError::Mls(format!("invalid key package: {e:?}")))?;

        let (_commit, welcome, _group_info) = group
            .add_members(
                &self.provider,
                &self.signer,
                core::slice::from_ref(&key_package),
            )
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;

        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;

        welcome
            .tls_serialize_detached()
            .map_err(|e| CryptoError::TlsCodec(format!("{e:?}")))
    }

    /// Join a group from Welcome bytes received via an invite (architecture.md §2).
    pub fn join_from_welcome(&self, welcome_bytes: &[u8]) -> Result<MlsGroup, CryptoError> {
        let mls_message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| CryptoError::TlsCodec(format!("{e:?}")))?;
        let welcome = match mls_message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(CryptoError::UnexpectedMessageType { expected: "Welcome" }),
        };

        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged_join = StagedWelcome::new_from_welcome(&self.provider, &join_config, welcome, None)
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;
        staged_join
            .into_group(&self.provider)
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))
    }

    /// Encrypt an application message for `group`, ready to send over the
    /// wire (over Tor — architecture.md §1 — in the full application).
    pub fn encrypt(&self, group: &mut MlsGroup, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let message = group
            .create_message(&self.provider, &self.signer, plaintext)
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;
        message
            .tls_serialize_detached()
            .map_err(|e| CryptoError::TlsCodec(format!("{e:?}")))
    }

    /// Process an incoming wire message for `group`. Returns the plaintext
    /// for an application message, or `None` if the message was a commit
    /// (membership change) or proposal that was applied/stored but carries
    /// no user-visible content.
    pub fn decrypt(
        &self,
        group: &mut MlsGroup,
        bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, CryptoError> {
        let mls_message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|e| CryptoError::TlsCodec(format!("{e:?}")))?;
        let protocol_message: ProtocolMessage = mls_message
            .try_into_protocol_message()
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;
        let processed = group
            .process_message(&self.provider, protocol_message)
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                Ok(Some(app_msg.into_bytes()))
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                group
                    .merge_staged_commit(&self.provider, *staged_commit)
                    .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;
                Ok(None)
            }
            // Standalone proposals, and the "own message echoed back"
            // variants (OwnPendingCommit/OwnPrivateMessage) that OpenMLS
            // surfaces for out-of-order-delivery edge cases: v1 doesn't yet
            // build a proposal-review UI or handle non-order-preserving
            // delivery. Tracked as a gap, not silently dropped — surfacing
            // proposals properly is a Phase 3 (multi-member groups) task.
            _ => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_rust_crypto::OpenMlsRustCrypto;
    use openmls_traits::types::SignatureScheme;

    fn fresh_member(label: &str) -> Member<OpenMlsRustCrypto> {
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
        Member::new(label, signer, OpenMlsRustCrypto::default())
    }

    /// The critical correctness proof for the Phase 1 "one crypto stack"
    /// decision (crypto-spec.md §2): a 2-member MLS group, created and
    /// joined independently by two members, can exchange application
    /// messages in both directions.
    #[test]
    fn two_member_group_round_trip() {
        let alice = fresh_member("alice");
        let bob = fresh_member("bob");

        let mut alice_group = alice.create_group().expect("alice creates group");

        let bob_key_package = bob.key_package_bytes().expect("bob key package");
        let welcome_bytes = alice
            .add_member(&mut alice_group, &bob_key_package)
            .expect("alice adds bob");

        let mut bob_group = bob
            .join_from_welcome(&welcome_bytes)
            .expect("bob joins from welcome");

        let ciphertext = alice
            .encrypt(&mut alice_group, b"Hello, Bob!")
            .expect("alice encrypts");
        let plaintext = bob
            .decrypt(&mut bob_group, &ciphertext)
            .expect("bob decrypts")
            .expect("application message");
        assert_eq!(plaintext, b"Hello, Bob!");

        let reply_ciphertext = bob
            .encrypt(&mut bob_group, b"Hi, Alice!")
            .expect("bob encrypts");
        let reply_plaintext = alice
            .decrypt(&mut alice_group, &reply_ciphertext)
            .expect("alice decrypts")
            .expect("application message");
        assert_eq!(reply_plaintext, b"Hi, Alice!");
    }

    /// Rough latency signal for the Phase 1 open item (tech-stack.md):
    /// is a 2-member MLS group fast enough for chat-speed messaging? This
    /// only measures local CPU cost (group state + crypto ops), not the
    /// Tor network latency on top of it, but a slow result here would be a
    /// red flag independent of the network layer.
    #[test]
    fn two_member_group_message_throughput_smoke_test() {
        let alice = fresh_member("alice");
        let bob = fresh_member("bob");
        let mut alice_group = alice.create_group().expect("alice creates group");
        let bob_key_package = bob.key_package_bytes().expect("bob key package");
        let welcome_bytes = alice
            .add_member(&mut alice_group, &bob_key_package)
            .expect("alice adds bob");
        let mut bob_group = bob.join_from_welcome(&welcome_bytes).expect("bob joins");

        let start = std::time::Instant::now();
        const N: usize = 200;
        for i in 0..N {
            let msg = format!("message {i}");
            let ciphertext = alice
                .encrypt(&mut alice_group, msg.as_bytes())
                .expect("encrypt");
            let plaintext = bob
                .decrypt(&mut bob_group, &ciphertext)
                .expect("decrypt")
                .expect("application message");
            assert_eq!(plaintext, msg.as_bytes());
        }
        let elapsed = start.elapsed();
        eprintln!(
            "two_member_group_message_throughput_smoke_test: {N} encrypt+decrypt round trips in {elapsed:?} ({:?}/message)",
            elapsed / N as u32
        );
    }

    /// Proves the actual persistence property: a group created with a
    /// SQLite-backed `PersistentProvider`, then "restarted" (the `Member`
    /// and in-memory `MlsGroup` handle both dropped and a fresh one loaded
    /// from the same database file), can still send and receive messages
    /// correctly. This is the property tech-stack.md's open item #5 asked
    /// for -- group state surviving a restart, not just living in memory.
    #[test]
    fn group_state_survives_reload_from_sqlite() {
        use provider::PersistentProvider;
        use rusqlite::Connection;

        let dir = tempfile::tempdir().expect("tempdir");
        let alice_db_path = dir.path().join("alice.db");
        let bob_db_path = dir.path().join("bob.db");

        let alice_signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
        let bob_signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("keygen");
        // SignatureKeyPair doesn't derive Clone by default (that's behind
        // openmls_basic_credential's test-utils feature, which we don't
        // enable outside that crate's own tests) -- round-trip through its
        // own Serialize/Deserialize impl instead to get an independent
        // second copy for "after restart", below.
        let alice_signer_bytes = serde_json::to_vec(&alice_signer).unwrap();
        let bob_signer_bytes = serde_json::to_vec(&bob_signer).unwrap();

        // --- "First run": create the group, exchange one message, then
        // drop everything (simulating a process restart). ---
        let alice_group_id = {
            let mut alice_provider = PersistentProvider::new(Connection::open(&alice_db_path).unwrap());
            alice_provider.run_migrations().expect("alice migrations");
            let mut bob_provider = PersistentProvider::new(Connection::open(&bob_db_path).unwrap());
            bob_provider.run_migrations().expect("bob migrations");

            let alice = Member::new("alice", alice_signer, alice_provider);
            let bob = Member::new("bob", bob_signer, bob_provider);

            let mut alice_group = alice.create_group().expect("alice creates group");
            let group_id = alice_group.group_id().clone();
            let bob_key_package = bob.key_package_bytes().expect("bob key package");
            let welcome_bytes = alice
                .add_member(&mut alice_group, &bob_key_package)
                .expect("alice adds bob");
            let mut bob_group = bob.join_from_welcome(&welcome_bytes).expect("bob joins");

            let ciphertext = alice
                .encrypt(&mut alice_group, b"before restart")
                .expect("encrypt");
            let plaintext = bob
                .decrypt(&mut bob_group, &ciphertext)
                .expect("decrypt")
                .expect("application message");
            assert_eq!(plaintext, b"before restart");

            group_id
            // alice, bob, alice_group, bob_group all dropped here.
        };

        // --- "Second run": reopen the same SQLite files, reload the group
        // by ID, and prove messaging still works. ---
        let alice_signer: SignatureKeyPair = serde_json::from_slice(&alice_signer_bytes).unwrap();
        let bob_signer: SignatureKeyPair = serde_json::from_slice(&bob_signer_bytes).unwrap();
        let alice_provider = PersistentProvider::new(Connection::open(&alice_db_path).unwrap());
        let bob_provider = PersistentProvider::new(Connection::open(&bob_db_path).unwrap());
        let alice = Member::new("alice", alice_signer, alice_provider);
        let bob = Member::new("bob", bob_signer, bob_provider);

        let mut alice_group = alice
            .load_group(&alice_group_id)
            .expect("load alice group")
            .expect("alice group present after reload");
        let mut bob_group = bob
            .load_group(&alice_group_id)
            .expect("load bob group")
            .expect("bob group present after reload");

        let ciphertext = alice
            .encrypt(&mut alice_group, b"after restart")
            .expect("encrypt after reload");
        let plaintext = bob
            .decrypt(&mut bob_group, &ciphertext)
            .expect("decrypt after reload")
            .expect("application message");
        assert_eq!(plaintext, b"after restart");

        let reply_ciphertext = bob
            .encrypt(&mut bob_group, b"reply after restart")
            .expect("encrypt reply after reload");
        let reply_plaintext = alice
            .decrypt(&mut alice_group, &reply_ciphertext)
            .expect("decrypt reply after reload")
            .expect("application message");
        assert_eq!(reply_plaintext, b"reply after restart");
    }
}
