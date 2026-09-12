# Threat Model

This document defines what SecureText protects against, what it explicitly
does not, and the assumptions every later design decision relies on. Every
subsequent doc (crypto-spec, architecture) should trace back to a line item
here — if a feature can't be justified against this list, question whether
it belongs in v1.

## Goals, in priority order

1. **Confidentiality** — message content is readable only by the intended
   participants, never by SecureText developers, relay operators, network
   observers, or anyone who compromises infrastructure we run.
2. **No central point of seizure** — there is no server whose operator can be
   subpoenaed, hacked, or compelled to hand over a user's message history,
   because no such server holds it.
3. **Forward secrecy & post-compromise security** — compromising a device's
   current key material should not expose past messages (forward secrecy)
   and the session should be able to heal after a compromise is detected
   (post-compromise security), consistent with modern ratcheting protocols.
4. **Best-effort anonymity** — by default we do not require real-world
   identity (no phone/email). Full network-level anonymity (hiding *who is
   talking to whom* from a network observer) is an opt-in mode, not a
   default guarantee — seeAssumptions & Non-Goals below for why.

## In scope (we defend against)

| Adversary / attack | Defense |
|---|---|
| Passive network eavesdropper (ISP, Wi-Fi operator, backbone tap) | E2EE for all message content; Noise/TLS 1.3 for transport metadata where feasible |
| A relay/rendezvous node we or a volunteer operates | Relays only ever see ciphertext + opaque routing IDs, never plaintext or long-term identity |
| Message tampering / replay in transit | AEAD ciphers with authenticated encryption; ratchet-based replay protection |
| Server/database compromise | N/A by design — there is no server holding plaintext or a master key |
| Group membership tampering (unauthorized add/remove) | Signed MLS commits; every membership change is cryptographically attributable and verifiable by all members |
| A removed group member reading future messages | MLS key rotation on every membership change (post-compromise security at the group level) |
| Stolen/lost device exposing local history | At-rest encryption of the local message store, keyed from a user passphrase (Argon2id-derived) |
| Casual metadata correlation (e.g. "these two usernames talk a lot," visible to a relay operator) | Opaque routing IDs distinct from long-term identity keys; rotate where practical |

## Explicitly out of scope for v1 (be honest about this)

- **A compromised endpoint device** (malware, keylogger, screen capture, a
  coerced/unlocked device). No messaging software fixes this; it's a device
  security problem, not a protocol problem.
- **Legal compulsion of a specific, identified user's own device.** We are
  not building an anti-forensics tool.
- **A global passive adversary performing full traffic analysis across the
  entire network** (nation-state-level "who talks to whom, always, everywhere").
  This is the domain of Tor/mixnets and is only addressed by the optional
  anonymity transport (see below), not by the base protocol.
- **Availability guarantees.** A P2P system with no mandatory central
  infrastructure has weaker delivery guarantees than a centralized service —
  offline-offline delivery depends on optional relay availability. This is a
  deliberate tradeoff for the confidentiality/no-central-authority goals.
- **Sybil-resistant reputation / spam prevention at scale.** We will ship
  basic rate-limiting and local blocklists (see architecture.md §7) but a
  fully Sybil-resistant decentralized reputation system is a research
  problem, not a v1 commitment.

## Confidentiality vs. anonymity — a deliberate split

These are different guarantees and conflating them leads to overpromising:

- **Confidentiality** (nobody can read the content) is a **default, always-on
  guarantee** in SecureText — this is the non-negotiable core promise.
- **Anonymity** (nobody can tell who is talking to whom) is **best-effort by
  default and strong only when the user opts into the Tor/onion-routing
  transport** (Phase 9). Mandating onion routing for every message adds
  meaningful latency and complexity that most users won't want for everyday
  chat — so it's a toggle ("Paranoid Mode"), not baked into the base
  protocol. This must be communicated clearly in the UI so users don't
  assume anonymity guarantees they don't have.

## Assumptions

- Users generate and are responsible for safeguarding their own private key
  material; SecureText cannot recover a lost identity without an explicit,
  user-initiated backup (an export seed phrase, itself a security tradeoff
  users opt into knowingly).
- Volunteer/self-hosted relay nodes are assumed *honest-but-curious*: they
  will follow the protocol (so we can rely on delivery) but may try to learn
  what they can from ciphertext and metadata they see. The protocol must
  remain safe even if every relay is curious; it does not need to remain
  safe if a relay is actively malicious in ways the protocol doesn't already
  account for (e.g., a relay dropping messages is a DoS/availability
  concern, not a confidentiality break).
- Cryptographic primitives (Curve25519, AES-GCM/ChaCha20-Poly1305, Argon2id)
  are assumed sound; we are not designing novel cryptographic primitives,
  only composing audited ones (see crypto-spec.md).

## Revisit triggers

This document should be revisited (not just the code) whenever:
- A new feature changes what data leaves a device unencrypted (e.g., typing
  indicators, read receipts, presence — each is a metadata leak to evaluate).
- Multi-device support is designed (Phase 7) — it changes the trust
  boundary of "identity == one device."
- The relay/store-and-forward design (Phase 5) is finalized — relay
  operators are a new class of adversary this doc currently treats abstractly.
