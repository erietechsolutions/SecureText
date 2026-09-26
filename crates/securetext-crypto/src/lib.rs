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

mod capability;
pub use capability::{Capability, Permission};

/// The one ciphersuite SecureText speaks: X25519 + ChaCha20-Poly1305 +
/// Ed25519 (crypto-spec.md §7's primitive table).
pub const CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519;

/// How many past epochs' message secrets a group keeps. Zero (OpenMLS's
/// default) is only safe if every application message is delivered in the
/// epoch it was sent in. Once a group has more than two members, and
/// especially once Phase 5's relay adds a second delivery path, a chat
/// message sent just before a membership change can arrive just after it.
/// Without this, the message fails to decrypt even for a legitimate
/// member. Kept deliberately small: every retained epoch is a window where
/// a compromised device could still read that epoch's messages, a real
/// (bounded) cost to forward secrecy.
pub const MAX_PAST_EPOCHS: usize = 3;

/// The result of processing one incoming MLS wire message with
/// [`Member::process`].
#[derive(Debug)]
pub enum Incoming {
    /// An application message, with the sender's MLS identity public key
    /// (the same stable handle as `Member::public_key`). MLS itself has
    /// already authenticated that this key sent it.
    Application { sender_public_key: Vec<u8>, plaintext: Vec<u8> },
    /// A commit was applied. `removed_self` is true if it removed this
    /// member from the group: the group is now inactive and later messages
    /// in it are unreadable to us.
    Commit { removed_self: bool },
    /// A standalone proposal or another non-content message.
    Other,
}

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
            .max_past_epochs(MAX_PAST_EPOCHS)
            .build();
        MlsGroup::new(
            &self.provider,
            &self.signer,
            &config,
            self.credential_with_key.clone(),
        )
        .map_err(|e| CryptoError::Mls(format!("{e:?}")))
    }

    /// This member's MLS identity public key (matches
    /// `securetext_identity::PublicIdentity::public_key`) -- the stable
    /// handle used to find/remove them in a group's member list
    /// (`remove_member`) or record them as a contact.
    pub fn public_key(&self) -> &[u8] {
        self.signer.public()
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

    /// Issue a signed capability (architecture.md §7) using this member's
    /// own MLS identity key -- e.g. a server admin granting another
    /// member permission to post/invite/kick.
    pub fn issue_capability(
        &self,
        group_id: &GroupId,
        subject_public_key: &[u8],
        permission: Permission,
    ) -> Result<Capability, CryptoError> {
        Capability::issue(&self.signer, group_id.as_slice(), subject_public_key, permission)
    }

    /// Verify a capability's signature using this member's crypto
    /// provider. See [`Capability::verify`] for exactly what this does
    /// and does not prove.
    pub fn verify_capability(&self, capability: &Capability) -> Result<(), CryptoError> {
        capability.verify(self.provider.crypto())
    }

    /// Add a member (identified by their serialized KeyPackage) to `group`,
    /// merge the resulting commit locally, and return `(commit_bytes,
    /// welcome_bytes)`: `commit_bytes` must be fanned out to every
    /// *existing* member besides the sender (so their view of the group
    /// advances to include the new member -- essential once a group has
    /// more than the two parties involved in this one Add, or their view
    /// desyncs from the actual roster), and `welcome_bytes` goes to the
    /// new member being added.
    pub fn add_member(
        &self,
        group: &mut MlsGroup,
        their_key_package_bytes: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        self.add_members(group, &[their_key_package_bytes])
    }

    /// Add several members in a single commit. Same return value and
    /// fan-out rules as [`Self::add_member`]; the one Welcome carries the
    /// secrets for every new member, so each of them gets the same bytes.
    /// Adding people one commit at a time would instead put each earlier
    /// joiner behind by one commit per later joiner, and they'd have to
    /// receive those commits in order before they could read anything.
    pub fn add_members(
        &self,
        group: &mut MlsGroup,
        key_packages: &[&[u8]],
    ) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut validated = Vec::with_capacity(key_packages.len());
        for bytes in key_packages {
            let key_package_in = KeyPackageIn::tls_deserialize_exact(*bytes)
                .map_err(|e| CryptoError::TlsCodec(format!("{e:?}")))?;
            let key_package = key_package_in
                .validate(self.provider.crypto(), ProtocolVersion::Mls10)
                .map_err(|e| CryptoError::Mls(format!("invalid key package: {e:?}")))?;
            validated.push(key_package);
        }

        let (commit, welcome, _group_info) = group
            .add_members(&self.provider, &self.signer, &validated)
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;

        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;

        let commit_bytes = commit
            .tls_serialize_detached()
            .map_err(|e| CryptoError::TlsCodec(format!("{e:?}")))?;
        let welcome_bytes = welcome
            .tls_serialize_detached()
            .map_err(|e| CryptoError::TlsCodec(format!("{e:?}")))?;
        Ok((commit_bytes, welcome_bytes))
    }

    /// Remove `target_public_key` (an MLS identity public key -- see
    /// `PublicIdentity::public_key`) from `group`, merge the resulting
    /// commit locally, and return the commit bytes to fan out to every
    /// *remaining* member (including, if reachable, the removed member
    /// themselves -- OpenMLS marks their view of the group inactive once
    /// they process it, per its own "getting removed" semantics). This is
    /// Phase 3's core exit criterion: after this commit is merged
    /// everywhere it needs to be, a message encrypted in the new epoch is
    /// not decryptable by the removed member, who no longer has that
    /// epoch's keys -- true whether or not they ever process this commit.
    pub fn remove_member(&self, group: &mut MlsGroup, target_public_key: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let leaf_index = group
            .members()
            .find(|member| member.signature_key == target_public_key)
            .map(|member| member.index)
            .ok_or_else(|| CryptoError::Mls("target is not a member of this group".into()))?;

        let (commit, _welcome_option, _group_info) = group
            .remove_members(&self.provider, &self.signer, &[leaf_index])
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;

        group
            .merge_pending_commit(&self.provider)
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;

        commit
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
            .max_past_epochs(MAX_PAST_EPOCHS)
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
    /// no user-visible content. See [`Self::process`] for the variant that
    /// also reports who sent it.
    pub fn decrypt(
        &self,
        group: &mut MlsGroup,
        bytes: &[u8],
    ) -> Result<Option<Vec<u8>>, CryptoError> {
        match self.process(group, bytes)? {
            Incoming::Application { plaintext, .. } => Ok(Some(plaintext)),
            Incoming::Commit { .. } | Incoming::Other => Ok(None),
        }
    }

    /// Like [`Self::decrypt`], but also reports the authenticated sender of
    /// an application message and whether a commit removed us. A chat
    /// client needs both: the sender to label the message, and the removal
    /// flag to stop treating a group we were kicked from as usable.
    pub fn process(&self, group: &mut MlsGroup, bytes: &[u8]) -> Result<Incoming, CryptoError> {
        let mls_message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|e| CryptoError::TlsCodec(format!("{e:?}")))?;
        let protocol_message: ProtocolMessage = mls_message
            .try_into_protocol_message()
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;
        let processed = group
            .process_message(&self.provider, protocol_message)
            .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;

        // Resolve the sender before a commit is merged: the merge can
        // change (or remove) the leaf this index points to.
        let sender_public_key = match processed.sender() {
            Sender::Member(leaf_index) => group
                .member_at(*leaf_index)
                .map(|member| member.signature_key),
            _ => None,
        };

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(app_msg) => {
                let sender_public_key = sender_public_key
                    .ok_or_else(|| CryptoError::Mls("application message from a non-member sender".into()))?;
                Ok(Incoming::Application {
                    sender_public_key,
                    plaintext: app_msg.into_bytes(),
                })
            }
            ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                let removed_self = staged_commit.self_removed();
                group
                    .merge_staged_commit(&self.provider, *staged_commit)
                    .map_err(|e| CryptoError::Mls(format!("{e:?}")))?;
                Ok(Incoming::Commit { removed_self })
            }
            // Standalone proposals, and the "own message echoed back"
            // variants (OwnPendingCommit/OwnPrivateMessage) that OpenMLS
            // surfaces for out-of-order-delivery edge cases. SecureText
            // never sends standalone proposals (every membership change is
            // a full commit from the group's admin), so there is nothing
            // to review here yet.
            _ => Ok(Incoming::Other),
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
        let (_commit_bytes, welcome_bytes) = alice
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
        let (_commit_bytes, welcome_bytes) = alice
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
    /// Phase 3's core exit criterion: a 3+ member group works, and once a
    /// member is removed, a message encrypted *after* that removal is not
    /// decryptable by them -- verified directly (actually attempting the
    /// decrypt and checking it fails), not assumed from the library.
    #[test]
    fn removed_member_cannot_decrypt_subsequent_messages() {
        let alice = fresh_member("alice");
        let bob = fresh_member("bob");
        let charlie = fresh_member("charlie");

        // --- Build a 3-member group. ---
        let mut alice_group = alice.create_group().expect("alice creates group");
        let bob_key_package = bob.key_package_bytes().expect("bob key package");
        let (_commit, welcome_for_bob) = alice
            .add_member(&mut alice_group, &bob_key_package)
            .expect("alice adds bob");
        let mut bob_group = bob.join_from_welcome(&welcome_for_bob).expect("bob joins");

        let charlie_key_package = charlie.key_package_bytes().expect("charlie key package");
        let (commit_for_bob, welcome_for_charlie) = alice
            .add_member(&mut alice_group, &charlie_key_package)
            .expect("alice adds charlie");
        // Bob is an *existing* member at this point (unlike Phase 1/2's
        // 2-member scenarios, where there was never a third existing
        // member to notify) -- he must process this Add commit or his
        // view of the group desyncs from alice's and charlie's.
        let bob_processed = bob
            .decrypt(&mut bob_group, &commit_for_bob)
            .expect("bob processes the add-charlie commit");
        assert_eq!(bob_processed, None, "a commit carries no application content");
        let mut charlie_group = charlie
            .join_from_welcome(&welcome_for_charlie)
            .expect("charlie joins");

        // Sanity: all three can read a message sent before any removal.
        let before_ciphertext = alice
            .encrypt(&mut alice_group, b"hello everyone")
            .expect("alice encrypts");
        assert_eq!(
            bob.decrypt(&mut bob_group, &before_ciphertext).expect("bob decrypts"),
            Some(b"hello everyone".to_vec())
        );
        assert_eq!(
            charlie
                .decrypt(&mut charlie_group, &before_ciphertext)
                .expect("charlie decrypts"),
            Some(b"hello everyone".to_vec())
        );

        // --- Alice removes bob. ---
        let removal_commit = alice
            .remove_member(&mut alice_group, bob.public_key())
            .expect("alice removes bob");
        // Charlie (remaining member) processes the removal to advance to
        // the new epoch.
        charlie
            .decrypt(&mut charlie_group, &removal_commit)
            .expect("charlie processes the removal commit");

        // --- A message encrypted in the new (post-removal) epoch... ---
        let after_ciphertext = alice
            .encrypt(&mut alice_group, b"bob should not see this")
            .expect("alice encrypts after removal");

        // ...is readable by the remaining member...
        assert_eq!(
            charlie
                .decrypt(&mut charlie_group, &after_ciphertext)
                .expect("charlie decrypts after removal"),
            Some(b"bob should not see this".to_vec())
        );

        // ...but NOT by the removed member, whose group handle is stuck at
        // the old epoch and lacks the new epoch's keys. This is the actual
        // revocation property, verified by attempting it, not assumed.
        let bob_result = bob.decrypt(&mut bob_group, &after_ciphertext);
        assert!(
            bob_result.is_err(),
            "removed member must NOT be able to decrypt a post-removal message, got: {bob_result:?}"
        );
    }

    /// Ties capability tokens and removal together in a realistic
    /// moderation scenario: alice (the server's admin) delegates Kick
    /// authority to charlie without giving up her own membership or
    /// re-keying anything -- charlie verifies the capability really came
    /// from alice (architecture.md §7: any peer can check this without a
    /// central authority) before acting on it, then uses his own MLS
    /// signing key to actually remove bob (the capability grants
    /// *authorization*; the removal itself still goes through the normal
    /// MLS commit machinery, signed by whoever the group's crypto layer
    /// says performed it).
    #[test]
    fn authorized_moderator_can_remove_a_member() {
        let alice = fresh_member("alice");
        let bob = fresh_member("bob");
        let charlie = fresh_member("charlie");

        let mut alice_group = alice.create_group().expect("alice creates group");
        let bob_key_package = bob.key_package_bytes().expect("bob key package");
        let (_commit, welcome_for_bob) = alice
            .add_member(&mut alice_group, &bob_key_package)
            .expect("alice adds bob");
        let mut bob_group = bob.join_from_welcome(&welcome_for_bob).expect("bob joins");

        let charlie_key_package = charlie.key_package_bytes().expect("charlie key package");
        let (commit_for_bob, welcome_for_charlie) = alice
            .add_member(&mut alice_group, &charlie_key_package)
            .expect("alice adds charlie");
        bob.decrypt(&mut bob_group, &commit_for_bob)
            .expect("bob processes the add-charlie commit");
        let mut charlie_group = charlie
            .join_from_welcome(&welcome_for_charlie)
            .expect("charlie joins");

        // Alice delegates Kick authority over this group to charlie.
        let kick_capability = alice
            .issue_capability(alice_group.group_id(), charlie.public_key(), Permission::Kick)
            .expect("alice issues a Kick capability to charlie");

        // Charlie -- or anyone else who receives this capability -- can
        // verify it really came from alice without contacting her again.
        charlie
            .verify_capability(&kick_capability)
            .expect("capability verifies");
        assert_eq!(kick_capability.subject_public_key(), charlie.public_key());
        assert_eq!(kick_capability.permission(), Permission::Kick);
        assert_eq!(kick_capability.issued_by(), alice.public_key());

        // Charlie, now authorized, removes bob himself.
        let removal_commit = charlie
            .remove_member(&mut charlie_group, bob.public_key())
            .expect("charlie removes bob");
        alice
            .decrypt(&mut alice_group, &removal_commit)
            .expect("alice processes charlie's removal commit");

        let after_ciphertext = charlie
            .encrypt(&mut charlie_group, b"bob is gone now")
            .expect("charlie encrypts after removal");
        assert_eq!(
            alice
                .decrypt(&mut alice_group, &after_ciphertext)
                .expect("alice decrypts"),
            Some(b"bob is gone now".to_vec())
        );
        assert!(bob.decrypt(&mut bob_group, &after_ciphertext).is_err());
    }

    /// Channel-level key partitioning (architecture.md §3/§7): proves a
    /// "private channel" (narrower membership than the server) achieves
    /// *real* cryptographic exclusion, not just an application-level
    /// filter -- a server member who isn't in the channel's group plainly
    /// cannot decrypt the channel's messages, verified directly.
    ///
    /// Design note (see tech-stack.md's implementation findings for the
    /// full reasoning): this models a channel as its own independent MLS
    /// group with a subset of the server's members, reusing
    /// create_group/add_member/remove_member as-is, rather than OpenMLS's
    /// native sub-group branching feature (RFC 9420 §11.3). Branching adds
    /// real value this doesn't have -- a cryptographic tie to the exact
    /// parent epoch a channel was created from -- but requires tracking a
    /// sliding window of `BranchInfo` per parent epoch and careful
    /// sender/receiver epoch-matching to get right. An independent group
    /// gives the property this test actually needs (narrower membership,
    /// real exclusion) with far less correctness risk, at the cost of that
    /// parent-epoch binding -- a reasonable v1 tradeoff, revisit if a
    /// concrete need for the branching-specific guarantee shows up.
    /// Capability tokens scope naturally to this: a channel's `GroupId` is
    /// just another value `Capability::issue`'s `group_id` can name, so
    /// "may post in this specific channel" falls out of the existing
    /// capability mechanism for free.
    #[test]
    fn private_channel_excludes_non_members() {
        let alice = fresh_member("alice");
        let bob = fresh_member("bob");
        let charlie = fresh_member("charlie");

        // The "server": all three are members.
        let mut server_group = alice.create_group().expect("alice creates server group");
        let bob_key_package = bob.key_package_bytes().expect("bob key package");
        let (_commit, welcome_for_bob) = alice
            .add_member(&mut server_group, &bob_key_package)
            .expect("alice adds bob to the server");
        let mut bob_server_group = bob.join_from_welcome(&welcome_for_bob).expect("bob joins the server");

        let charlie_key_package = charlie.key_package_bytes().expect("charlie key package");
        let (commit_for_bob, welcome_for_charlie) = alice
            .add_member(&mut server_group, &charlie_key_package)
            .expect("alice adds charlie to the server");
        bob.decrypt(&mut bob_server_group, &commit_for_bob)
            .expect("bob processes the add-charlie commit");
        charlie.join_from_welcome(&welcome_for_charlie).expect("charlie joins the server");

        // A private "mod channel": alice creates a *separate* MLS group
        // and adds only charlie -- bob, though a server member, is never
        // added to this group at all.
        let mut channel_group = alice.create_group().expect("alice creates the channel group");
        let channel_id = channel_group.group_id().clone();
        // KeyPackages are single-use (crypto-spec.md §2) -- charlie's
        // server-join key package was already consumed above, so he needs
        // a fresh one for this second, independent group.
        let charlie_channel_key_package = charlie.key_package_bytes().expect("charlie's channel key package");
        let (_commit, welcome_for_charlie_channel) = alice
            .add_member(&mut channel_group, &charlie_channel_key_package)
            .expect("alice adds charlie to the channel");
        let mut charlie_channel_group = charlie
            .join_from_welcome(&welcome_for_charlie_channel)
            .expect("charlie joins the channel");

        // Capability tokens scope to this channel's own GroupId, exactly
        // like they would for the server.
        let post_capability = alice
            .issue_capability(&channel_id, charlie.public_key(), Permission::Post)
            .expect("alice grants charlie posting rights in the channel");
        charlie.verify_capability(&post_capability).expect("verifies");
        assert_eq!(post_capability.group_id(), channel_id.as_slice());

        let channel_ciphertext = alice
            .encrypt(&mut channel_group, b"mods only: bob is being annoying")
            .expect("alice encrypts a channel message");

        // Charlie, a real channel member, reads it fine.
        assert_eq!(
            charlie
                .decrypt(&mut charlie_channel_group, &channel_ciphertext)
                .expect("charlie decrypts"),
            Some(b"mods only: bob is being annoying".to_vec())
        );

        // Bob is a server member but was never added to the channel's own
        // MLS group. He has no group state for the channel at all, so
        // there's no "bob's channel view" to decrypt with directly -- the
        // closest real attack is bob (having somehow obtained the
        // ciphertext bytes, e.g. from a relay) trying to process them
        // against the only group state he *does* have, his server group.
        // This must fail: the ciphertext's group ID doesn't match, and
        // even if it did, his server group is at a completely different
        // epoch/key schedule than the channel group.
        assert_ne!(server_group.group_id(), &channel_id, "server and channel are different MLS groups");
        let bob_attempt = bob.decrypt(&mut bob_server_group, &channel_ciphertext);
        assert!(
            bob_attempt.is_err(),
            "a server member excluded from the channel must NOT be able to decrypt its messages, got: {bob_attempt:?}"
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
            let (_commit_bytes, welcome_bytes) = alice
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
