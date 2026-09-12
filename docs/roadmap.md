# Development Roadmap

Each phase's exit criteria should be checked before starting the next —
this is a security-sensitive project where shortcuts compound.

## Phase 0 — Spec & Threat Model *(current phase)*
- [x] Threat model (`threat-model.md`)
- [x] Cryptographic design (`crypto-spec.md`)
- [x] Network architecture (`architecture.md`)
- [x] Tech stack decisions (`tech-stack.md`)
- [x] Platform support matrix (`platform-support.md`)
- [x] Resolved: mandatory Tor v3 onion-service transport for all
      text/group/file traffic (no opt-out), OpenMLS as the single E2EE
      stack for both 1:1 and groups, calls on a separate disclosed path.
      See threat-model.md, architecture.md §1–2, crypto-spec.md §2.
- [ ] Remaining open items tracked in `tech-stack.md` §"Open items"
      (MLS-as-1:1 latency validation, SQLCipher-on-Windows, bridge UX,
      webrtc-rs coverage) — small spikes, not blocking Phase 1 start.
- **Exit criteria:** all five design docs reviewed, open items resolved or
  explicitly deferred with a rationale, before any Phase 1 code is written.

## Phase 1 — MVP: 1:1 Encrypted Messaging over Tor *(in progress)*
- [x] Local identity generation (Ed25519 MLS signing keypair via
      `openmls_basic_credential`), persisted through `openmls_sqlite_storage`
      with whole-file Argon2id + ChaCha20-Poly1305 envelope encryption at
      rest (`crates/securetext-identity`, both round-trip and
      wrong-passphrase tests passing)
- [x] OpenMLS 2-member group established and used for 1:1 messaging
      (crypto-spec.md §2), verified with a real serialize/deserialize wire
      round trip in both directions (`crates/securetext-crypto`); local
      encrypt+decrypt throughput measured at ~5.7ms/message — not a
      bottleneck (tech-stack.md's implementation findings)
- [x] `arti`-based onion service hosting and outbound dialing
      (`crates/securetext-net`), **fully live-verified against the real Tor
      network in this dev environment**: bootstrap (~15s), a real `.onion`
      v3 address issued, and a complete two-party byte round trip — both
      as two `TorClient`s in one process and as two genuinely separate OS
      processes (`securetext net-listen` / `net-dial`). The apparent
      10+-minute "bootstrap stall" seen earlier was a red herring: it was
      actually a missing `.flush()` on the buffered `DataStream` writer
      (tech-stack.md's implementation findings) — fixed.
- [x] Proof-of-integration CLI (`securetext demo`) wiring identity + MLS +
      Tor together exactly as the real app would, **run and verified end
      to end**: two local identities form a 2-member MLS group, exchange a
      Welcome and an encrypted application message in both directions,
      entirely over live Tor onion services with no IP ever exchanged.
- [x] Noise_XX-secured transport session on top of the onion-service
      connection (crypto-spec.md §4), **live-verified**: each identity now
      has a persistent Noise static X25519 keypair (`securetext-identity`),
      `securetext-net` performs the full handshake and transport
      encryption (unit-tested locally over an in-memory pipe, no Tor
      needed for that check), and `securetext demo` / `net-dial` verify
      the peer's presented static key against the expected one obtained
      out-of-band before trusting the connection — real mutual
      authentication, not just "some onion service answered."
- [ ] yamux multiplexing over the Noise session (architecture.md §6) —
      not yet implemented; each connection is still one logical stream,
      framed with a plain length prefix around the Noise ciphertext
      (tech-stack.md open item #6)
- [x] MLS group state persistence across restarts (tech-stack.md open item
      #5), **verified via a full simulated restart**: `securetext
      restart-demo` seals identity stores to their encrypted files, drops
      everything, reopens from those files, reloads the MLS group by ID,
      and keeps messaging correctly in both directions
- [x] End-to-end latency benchmark combining MLS + a real Tor circuit
      (`securetext bench`), **measured**: 20 round trips over one
      established circuit came in at p50=3.09s, avg=3.46s (tech-stack.md
      open item #1) — usable for text chat, consistent with the disclosed
      "slower than Discord" tradeoff in architecture.md §6, not a surprise
- [ ] Manual address exchange only — invite links come in Phase 2
- **Exit criteria:** two instances on different machines exchange E2EE
  messages entirely over Tor, with no direct IP exchange at any point
  (verified by packet capture / network monitor showing only Tor circuit
  traffic, never a direct connection to the peer's real IP). Verified
  across at least one Linux-to-Windows pair (e.g., Fedora ↔ Windows 11) in
  addition to same-OS pairs, since this is the first phase where
  cross-platform wire compatibility could silently break. MLS-as-1:1
  benchmark results recorded and reviewed against chat-speed usability
  expectations.

## Phase 2 — Invite Links & Bridges
- Invite-link format encoding onion address + MLS key package/Welcome
  message (architecture.md §2), replacing manual address exchange
- Onion-address rotation + "I've moved" re-linking within existing MLS
  groups (architecture.md §2)
- Pluggable transport (obfs4) support via `arti`, with the bridge
  configuration UX decided in Phase 1's open items (architecture.md §5)
- **Exit criteria:** two peers connect via invite link with no manual
  address exchange; a simulated Tor-blocked network condition is overcome
  using a configured obfs4 bridge, verified end-to-end.

## Phase 3 — Groups ("Servers") & Channels
- MLS group creation/join/leave via OpenMLS, scaled beyond 2 members
- Channel-level key partitioning within a group
- Signed role/permission capability tokens (post/invite/kick)
- **Exit criteria:** a 3+ member group can be created, a member removed
  loses access to subsequently-sent messages (verified directly, not just
  assumed from the library), entirely over the Tor transport from Phase 1.

## Phase 4 — Discord-like Client UI
- Server list, channel list, DM list, message view, member/role list
- Built on top of the Phase 1–3 backend via Tauri
- Onion-connection status and Tor circuit health surfaced in the UI (so
  users understand why a first message to a new contact takes longer —
  architecture.md §6)
- **Exit criteria:** a non-technical tester can create a server, invite a
  friend, and chat, without touching a CLI, and understands from the UI
  alone that their connection is Tor-routed.

## Phase 5 — Offline Delivery
- Store-and-forward relay service (self-hosted and/or volunteer-run),
  reachable only via its own onion service (architecture.md §4)
- Client-side polling/retrieval of queued encrypted blobs over Tor
- **Exit criteria:** a message sent while the recipient is offline is
  delivered once they come online, without the relay ever holding
  decryptable content or learning either party's real IP (verified by
  inspecting relay-side storage and network traffic, not just assumed).

## Phase 6 — Voice & Video (the disclosed exception)
- WebRTC integration for calls and screen share, keyed from the existing
  MLS session material, using the forced-relay design from
  architecture.md §9 (never a direct peer connection for media)
- Calling UI explicitly discloses the reduced anonymity guarantee for
  calls before a call starts (threat-model.md)
- **Exit criteria:** a 1:1 call and a group call both work at usable
  quality; a network capture confirms media is relayed (never direct
  peer-to-peer) so participants don't learn each other's raw IP; the
  disclosure UI is reviewed for clarity, not just presence.

## Phase 7 — Rich Features
- Encrypted file/image sharing, reactions, threads, presence/status,
  disappearing messages — all over the Tor transport from Phase 1
- **Exit criteria:** feature parity checklist against the "Discord-like"
  goal from the original vision, each new feature re-checked against
  threat-model.md for new metadata leakage before shipping.

## Phase 8 — Hardening & Third-Party Audit
- Independent security audit covering: the crypto implementation and
  protocol composition (MLS-for-1:1 included, since it's a less-common
  usage pattern than MLS-for-groups-only), and the Tor integration
  specifically (onion-service key handling, bridge configuration, the
  Phase 6 calls exception's actual exposure).
- Address findings before any "production-ready" claim is made.
- **Exit criteria:** audit complete, critical/high findings remediated.
  **This phase is not optional and should not be skipped or compressed
  under schedule pressure** — see crypto-spec.md §8.

## Phase 9 — Mobile Clients
- React Native or Flutter mobile clients calling the Rust core via UniFFI
- Mobile-specific Tor integration considerations (background circuit
  maintenance under mobile OS power management, which is known to be
  harder than desktop — flag as a research spike early in this phase
  rather than assuming desktop's approach ports directly)
- **Exit criteria:** mobile clients pass the same Phase 1/3 correctness
  checks as desktop, including the "no direct IP exchange" verification.

## Cross-cutting, ongoing throughout all phases

- **Every phase's exit criteria must be verified on Ubuntu, Fedora, and
  Windows 10/11** (see `platform-support.md`), not just the OS the code
  happened to be written on. macOS is not an official v1 target.
- **No feature ships that creates a direct IP exchange for text/group/file
  traffic**, per the mandatory-anonymity requirement in threat-model.md —
  this is a standing constraint to check new features against, not just a
  Phase 1 concern.
- Revisit `threat-model.md` whenever a new feature changes what data
  leaves a device unencrypted, or whenever a feature might reintroduce IP
  exposure outside the Phase 6 disclosed exception.
- No custom cryptographic protocol changes ship without review against
  `crypto-spec.md`'s "use a library, not a paper" rule.
- No new crypto/network-adjacent dependency is added without the vetting
  process in `tech-stack.md`'s standing rule (license, maintenance, audit
  history — verified directly, not assumed from name or popularity).
- Track the open items in `tech-stack.md` as they get resolved, and record
  *why* a decision was made (not just what), so later phases don't
  relitigate settled tradeoffs without new information.
