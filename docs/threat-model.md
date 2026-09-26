# Threat Model

This document defines what SecureText protects against, what it explicitly
does not, and the assumptions every later design decision relies on. Every
subsequent doc (crypto-spec, architecture) should trace back to a line item
here — if a feature can't be justified against this list, question whether
it belongs in v1.

## Goals, in priority order

1. **Confidentiality** — message content is readable only by the sender and
   the intended recipient(s), never by SecureText developers, relay
   operators, network observers, or anyone who compromises infrastructure we
   run.
2. **Network-level anonymity, mandatory and by default** — no network
   observer, relay operator, or peer should be able to determine the IP
   address or physical device behind any identity or message. This is a
   **hard requirement, not a toggle**: all text/group/file traffic is routed
   over Tor v3 onion services unconditionally (architecture.md §1–2). There
   is deliberately no "fast, non-anonymous" mode for this traffic — see
   §"Confidentiality and anonymity are both mandatory" below for the one
   explicit, disclosed exception (voice/video).
3. **No central point of seizure** — there is no server whose operator can be
   subpoenaed, hacked, or compelled to hand over a user's message history or
   identity, because no such server holds it.
4. **Forward secrecy & post-compromise security** — compromising a device's
   current key material should not expose past messages (forward secrecy)
   and the session should be able to heal after a compromise is detected
   (post-compromise security), provided by MLS (crypto-spec.md).

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
| IP address / device correlation with a message or identity | All text/group/relay traffic routed over Tor v3 onion services (architecture.md §1); no component in the system ever sees a peer's real IP address |
| Tor being blocked or throttled on the user's network | Pluggable transport (obfs4) support via arti, built in from Phase 1, not a later add-on (architecture.md §5) |

## Explicitly out of scope for v1 (be honest about this)

- **A compromised endpoint device** (malware, keylogger, screen capture, a
  coerced/unlocked device). No messaging software fixes this; it's a device
  security problem, not a protocol problem.
- **Legal compulsion of a specific, identified user's own device.** We are
  not building an anti-forensics tool.
- **A global passive adversary performing full traffic analysis across the
  entire Tor network** (nation-state-level "who talks to whom, always,
  everywhere," correlating traffic timing at many points simultaneously).
  This is Tor's own known limit, inherited as-is — we rely on Tor's onion
  routing for anonymity and do not attempt to improve on its guarantees
  against a global adversary (that's mixnet-level research territory,
  out of scope).
- **Voice/video call IP exposure (explicit, disclosed exception).** Per the
  Phase 7 design decision, calls use a separate, faster transport than text
  messaging to keep call quality usable — this means a call participant's
  IP is exposed to the relay/TURN-equivalent infrastructure handling the
  call, and potentially to the other participant depending on the final
  Phase 7 design, for the *duration of that call only*. Text, group, and
  file messaging are unaffected and remain fully Tor-routed. **This must be
  disclosed clearly in the calling UI** (e.g., "starting a call uses a
  faster, non-anonymous connection") so users aren't misled about a
  guarantee that doesn't apply to that feature.
- **Availability guarantees.** A P2P system with no mandatory central
  infrastructure has weaker delivery guarantees than a centralized service —
  offline-offline delivery depends on relay availability, and Tor's own
  network conditions (circuit build time, onion service reachability) add
  latency and occasional connection failures beyond what a clearnet service
  would see. This is a deliberate tradeoff for the anonymity and
  no-central-authority goals.
- **Sybil-resistant reputation / spam prevention at scale.** We will ship
  basic rate-limiting and local blocklists (see architecture.md §7) but a
  fully Sybil-resistant decentralized reputation system is a research
  problem, not a v1 commitment.

## Confidentiality and anonymity are both mandatory

Earlier drafts of this document treated anonymity as optional ("Paranoid
Mode") to avoid Tor's latency cost by default. That has been superseded by
an explicit product requirement: **both guarantees are mandatory, all the
time, for text/group/file messaging** — there is no non-anonymous mode to
opt out into.

- **Confidentiality** (nobody can read the content): E2EE via MLS for both
  1:1 and group conversations (crypto-spec.md).
- **Anonymity** (nobody can tell who is talking to whom, or from what
  device/IP): mandatory Tor v3 onion-service routing for all such traffic
  (architecture.md §1). This is accepted to come with real latency cost —
  see "efficiency within the Tor constraint" in architecture.md §6 for how
  we minimize that cost without compromising the guarantee (persistent
  circuits, stream multiplexing) rather than by weakening the guarantee
  itself.
- **The one carved-out exception is voice/video calls** (see above) — this
  is a deliberate, disclosed, narrowly-scoped tradeoff for usability, not a
  general precedent. Any future feature that wants a similar exception must
  be justified here explicitly, not assumed.

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
- Tor's onion routing is assumed to provide the anonymity properties it
  claims against the adversaries in scope above (not a global passive
  adversary). We are consuming Tor as a client via `arti`, not modifying or
  extending the onion routing protocol itself.

## Revisit triggers

This document should be revisited (not just the code) whenever:
- A new feature changes what data leaves a device unencrypted (e.g., typing
  indicators, read receipts, presence — each is a metadata leak to evaluate).
- Multi-device support is designed (Phase 8) — it changes the trust
  boundary of "identity == one device."
- The relay/store-and-forward design (Phase 5) is finalized — relay
  operators are a new class of adversary this doc currently treats abstractly.
- The Phase 7 voice/video transport design is finalized — the disclosed
  exception above is a placeholder until the actual mechanism (direct
  WebRTC, forced-TURN-relay, etc.) is decided, and the exact exposure it
  creates must be re-described precisely once it is.
