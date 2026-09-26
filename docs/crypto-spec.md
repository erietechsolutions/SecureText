# Cryptographic Design

Guiding rule: **do not invent cryptography.** Every mechanism below composes
existing, audited protocols/libraries. Where a choice is genuinely open, the
default picked is the more conservative, more widely-reviewed option.

## 1. Identity

- Each identity is an **Ed25519 keypair** (signing) plus an **X25519
  keypair** (key agreement), generated locally on first run.
- The public keys, or a fingerprint/hash of them, are the only "identity" —
  no email, phone number, or other PII is collected or required.
- A human-readable display name is a local, unverified label attached by
  each peer to a pubkey — never a global directory entry, since a global
  username directory is itself a censorship/deanonymization chokepoint.
- **Key backup:** optional, explicit, user-initiated export as a BIP39-style
  mnemonic seed phrase encrypted under a user passphrase. Without this, a
  lost device means a lost identity (Signal-style safety-number
  re-verification is required to re-establish trust under a new identity).
- v1 assumption: **one identity == one device.** Multi-device is deferred to
  Phase 7 (see threat-model.md — it changes the trust model).

## 2. Resolved: one crypto stack for everything — MLS, including 1:1

**Decision (finalized):** rather than running two separate cryptographic
stacks — X3DH + Double Ratchet for 1:1, MLS for groups — SecureText uses
**MLS (RFC 9420) for both**, treating a 1:1 conversation as a 2-member MLS
group. This was decided after evaluating libsignal and every viable
alternative (see the research trail: libsignal is AGPL-3.0-licensed and its
own README states "use outside of Signal is unsupported" with no API
stability guarantee; Ockam's X3DH crate is abandoned inside its own
now-current codebase; `double-ratchet-2` is an unmaintained, unaudited
solo project; `vodozemac` has an unresolved high-severity disclosure as of
Feb 2026; `p2panda-encryption` is purpose-built for this exact use case but
pre-1.0 and not yet stable). Every option either fails on license, fails on
maintenance/audit status, or both — while OpenMLS (already required for
groups) is standardized, actively maintained, and eliminates a second
dependency and a second audit surface entirely.

- **Why this is safe to do:** MLS's TreeKEM construction degrades cleanly to
  a 2-party case; it still provides forward secrecy and post-compromise
  security via the same Commit/epoch mechanism used for larger groups.
- **Known tradeoff to validate in Phase 1:** MLS's per-message ratchet is
  not as narrowly optimized for rapid-fire 1:1 exchange as a dedicated
  Double Ratchet (Commits are somewhat heavier than a pure symmetric-ratchet
  step). Phase 1 must include a latency/throughput benchmark of 2-member
  MLS groups under realistic chat-speed message rates over the actual Tor
  transport (architecture.md §1) before this is considered fully settled —
  if it's a real problem in practice, the fallback is a from-spec Double
  Ratchet implementation reviewed in the Phase 8 audit (using Wire's
  Proteus as prior-art reference, not as a dependency, since it's
  GPL-3.0-licensed), not adopting any of the rejected options above.
- **AEAD:** ChaCha20-Poly1305 for message encryption (fast, constant-time,
  no hardware-AES dependency for cross-platform consistency).

## 3. Group messaging ("servers" & channels): MLS

Use **MLS — Messaging Layer Security, RFC 9420** — the modern IETF standard
for group E2EE, already adopted by Matrix/Element, Wire, Google Messages
(RCS), and Cisco Webex, and now used uniformly for both 1:1 and group
conversations in SecureText (§2 above):

- Each **"server"** in the Discord-like UI maps to one MLS group.
- Each **channel** within a server maps to its own, separate MLS group
  containing a subset of the server's members (implemented and verified —
  see architecture.md §7 for why this was chosen over OpenMLS's native
  sub-group branching), so a member without channel access — not added to
  that channel's group at all — cannot derive that channel's message keys
  even though they're a member of the server's own group.
- **Membership changes** (invite, kick, ban, leave) are MLS **Commit**
  messages: signed, ordered, and they trigger a group key rotation. A
  removed member cryptographically cannot decrypt messages sent after their
  removal — this is enforced by the protocol, not just client-side UI
  filtering, and verified directly (`securetext-crypto`'s
  `removed_member_cannot_decrypt_subsequent_messages`: the removed member's
  decrypt attempt is checked to actually fail, not assumed).
- **Roles/permissions** (who can post, invite, kick) are separate from MLS
  group membership: implemented (`securetext-crypto`'s `Capability`) as
  signed capability tokens issued by an admin key ("pubkey X may post in
  channel #general" — a capability's `group_id` names either the server or
  a specific channel's own group). Any peer can verify a capability token
  without contacting a central authority — it's just a signature check
  (`OpenMlsCrypto::verify_signature`) against the claimed issuer's public
  key; whether that issuer is actually recognized as an admin is a
  separate, deliberately-not-baked-in application policy decision (see
  `Capability::verify`'s doc comment).

**Library:** `OpenMLS` (Rust, actively maintained, implements RFC 9420).
Building the group/channel/role model in application code on top of OpenMLS
avoids reimplementing the hard cryptographic parts (tree-based key
derivation, commit ordering, welcome messages for new members).

## 4. Transport-layer encryption (defense in depth)

Independent of the message-layer E2EE above, and independent of Tor's own
onion-layer encryption (architecture.md §1), the stream between two peers
gets an additional authenticated encryption layer:

- **Noise Protocol Framework** (via the `snow` crate) runs immediately once
  an onion-service stream is established, authenticating the specific
  peer's long-term identity key (not just "some onion service responded")
  and adding a layer of encryption that doesn't depend on trusting Tor's
  own transport crypto exclusively.
- This is defense-in-depth, not the anonymity mechanism — anonymity (hiding
  *that* two identities are communicating at all, and both parties' real
  IPs) is provided entirely by routing the connection over Tor v3 onion
  services in the first place (architecture.md §1), not by this layer.

## 5. At-rest encryption

- Local message history stored in **SQLite via SQLCipher** (or an
  equivalent encrypted-SQLite binding), keyed by a value derived from the
  user's local passphrase via **Argon2id** (memory-hard, resists GPU/ASIC
  brute-force better than PBKDF2/bcrypt).
- Private key material itself is stored separately from message history,
  ideally in the OS-native secure enclave / keychain where available
  (Credential Manager/DPAPI on Windows, Secret Service on Ubuntu/Fedora),
  falling back to the same passphrase-derived encryption when no OS keyring
  is available (e.g., a headless Linux install with no Secret Service
  daemon running — see platform-support.md for this gap in detail).

## 6. What is explicitly NOT encrypted (and must be minimized)

Being upfront about residual metadata is part of not overpromising
(threat-model.md's confidentiality-and-anonymity section applies here too):

- Packet timing and size are still observable to *someone on the Tor
  circuit path* even though Tor hides the endpoints from each other and
  from outside observers — padding/timing obfuscation beyond what Tor
  itself provides is possible later hardening, not a v1 commitment.
- A relay node handling store-and-forward delivery (Phase 5, as built in
  `securetext-relay` and `securetext-app/src/relay.rs`) sees *that* a blob
  arrived for mailbox ID Y, its size rounded up to 1 KiB, and roughly when
  it was deposited and collected (stored only to the hour). It cannot read
  the blob, can't tell who deposited it, and never learns anyone's IP (it's
  reachable only as an onion service). The mailbox ID is `SHA-256(context ||
  secret)` and unrelated to any identity key. Every relay connection uses
  a fresh throwaway Noise key, so deposits and collections can't be linked
  to each other or to an identity by key. The mailbox ID *is* stable until
  the user changes relay, so the relay can tell that one mailbox gets mail
  and when; rotating it is future hardening. Separately, a contact who
  colludes with the relay could open the outer envelope layer (every
  contact holds the mailbox key) and see which of the user's contacts sent
  what when. The contents stay MLS-encrypted.
- Voice/video calls (Phase 6) are the one feature where IP-level exposure
  is accepted by design — see threat-model.md's disclosed exception.

## 7. Primitive summary

| Purpose | Primitive |
|---|---|
| Signing | Ed25519 |
| Key agreement | X25519 |
| 1:1 session | MLS (RFC 9420) via OpenMLS, as a 2-member group |
| Group session | MLS (RFC 9420) via OpenMLS |
| Symmetric AEAD | ChaCha20-Poly1305 |
| Transport-layer defense in depth | Noise Protocol Framework (`snow`) |
| Network-level anonymity | Tor v3 onion services (`arti`) — architecture.md §1 |
| Password/passphrase KDF | Argon2id |
| Local storage encryption | SQLCipher (AES-256) |

## 8. Non-negotiable process rule

**No custom cryptographic protocol ships without a third-party security
audit (Phase 8).** If a design decision here turns out to require novel
crypto to implement, that's a signal to simplify the design, not to invent
the crypto.
