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

## 2. One-to-one messaging: X3DH + Double Ratchet

Adopt the Signal protocol design directly (do not reimplement from the
paper — use an existing library):

- **X3DH (Extended Triple Diffie-Hellman)** for the initial asynchronous key
  agreement, so two peers can establish a shared secret even if one is
  offline when the "session request" is sent (requires the initiating peer
  to have fetched the recipient's prekey bundle in advance — see
  architecture.md §4 for how prekeys are distributed without a central
  server).
- **Double Ratchet** for the ongoing session: every message advances a
  symmetric-key ratchet (forward secrecy — a compromised key can't decrypt
  past messages) and periodically advances a Diffie-Hellman ratchet
  (post-compromise security — the session heals after a compromise).
- **AEAD:** ChaCha20-Poly1305 for message encryption (fast, constant-time,
  no hardware-AES dependency for cross-platform consistency); AES-256-GCM
  is an acceptable alternative if a chosen library standardizes on it.

**Library:** `libsignal` (Signal's own Rust/C++ implementation, if its
license and API fit) or a from-spec Rust crate implementing X3DH + Double
Ratchet with a maintained audit history. This is decided in
tech-stack.md — the point here is: **use a library, not a paper.**

## 3. Group messaging ("servers" & channels): MLS

Double Ratchet doesn't scale to groups efficiently (pairwise ratchets =
O(n²) key management). Use **MLS — Messaging Layer Security, RFC 9420** —
the modern IETF standard for group E2EE, already adopted by Matrix/Element,
Wire, Google Messages (RCS), and Cisco Webex:

- Each **"server"** in the Discord-like UI maps to one MLS group.
- Each **channel** within a server maps to a sub-tree/partitioned key
  derivation within that group, so a member without channel access cannot
  derive that channel's message keys even though they're a group member.
- **Membership changes** (invite, kick, ban, leave) are MLS **Commit**
  messages: signed, ordered, and they trigger a group key rotation. A
  removed member cryptographically cannot decrypt messages sent after their
  removal — this is enforced by the protocol, not just client-side UI
  filtering.
- **Roles/permissions** (who can post, invite, kick) are separate from MLS
  group membership: implemented as signed capability tokens issued by an
  admin key (e.g., "pubkey X may post in channel #general, until epoch N").
  Any peer can verify a capability token without contacting a central
  authority — it's just a signature check against the group's known admin
  key(s).

**Library:** `OpenMLS` (Rust, actively maintained, implements RFC 9420).
Building the group/channel/role model in application code on top of OpenMLS
avoids reimplementing the hard cryptographic parts (tree-based key
derivation, commit ordering, welcome messages for new members).

## 4. Transport-layer encryption (defense in depth)

Independent of the message-layer E2EE above, the peer-to-peer transport
itself is encrypted:

- **Noise Protocol Framework** (via libp2p's built-in `noise` transport
  security) for the encrypted channel between directly-connected peers.
- This means even metadata like "which libp2p stream protocol is being
  negotiated" isn't visible to a passive network observer — though it
  doesn't hide *that* two IPs are talking to each other (that's the
  anonymity-layer's job, see threat-model.md).

## 5. At-rest encryption

- Local message history stored in **SQLite via SQLCipher** (or an
  equivalent encrypted-SQLite binding), keyed by a value derived from the
  user's local passphrase via **Argon2id** (memory-hard, resists GPU/ASIC
  brute-force better than PBKDF2/bcrypt).
- Private key material itself is stored separately from message history,
  ideally in the OS-native secure enclave / keychain where available
  (Keychain on macOS, Credential Manager/DPAPI on Windows, Secret Service
  on Linux), falling back to the same passphrase-derived encryption.

## 6. What is explicitly NOT encrypted (and must be minimized)

Being upfront about residual metadata is part of not overpromising
(threat-model.md's confidentiality/anonymity split applies here too):

- Packet timing and size are visible to network-level observers unless the
  optional anonymity transport (Tor/onion routing, Phase 9) is enabled —
  padding/timing obfuscation is a possible later hardening, not a v1
  commitment.
- A relay node handling store-and-forward delivery (Phase 5) sees *that* a
  blob addressed to routing-ID Y exists and roughly when it was
  deposited/collected, even though it cannot read the blob. Routing IDs
  should be distinct from long-term identity keys and ideally rotated to
  limit correlation.

## 7. Primitive summary

| Purpose | Primitive |
|---|---|
| Signing | Ed25519 |
| Key agreement | X25519 |
| 1:1 session establishment | X3DH |
| 1:1 ongoing session | Double Ratchet |
| Group session | MLS (RFC 9420) via OpenMLS |
| Symmetric AEAD | ChaCha20-Poly1305 |
| Transport security | Noise Protocol Framework |
| Password/passphrase KDF | Argon2id |
| Local storage encryption | SQLCipher (AES-256) |

## 8. Non-negotiable process rule

**No custom cryptographic protocol ships without a third-party security
audit (Phase 8).** If a design decision here turns out to require novel
crypto to implement, that's a signal to simplify the design, not to invent
the crypto.
