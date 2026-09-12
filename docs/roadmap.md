# Development Roadmap

Each phase's exit criteria should be checked before starting the next —
this is a security-sensitive project where shortcuts compound.

## Phase 0 — Spec & Threat Model *(current phase)*
- [x] Threat model (`threat-model.md`)
- [x] Cryptographic design (`crypto-spec.md`)
- [x] Network architecture (`architecture.md`)
- [x] Tech stack decisions (`tech-stack.md`)
- [ ] Resolve the open items in `tech-stack.md` §"Open items" (especially
      the `libsignal` vs. from-spec Double Ratchet decision) via a small
      focused spike
- **Exit criteria:** all four design docs reviewed, open items resolved or
  explicitly deferred with a rationale, before any Phase 1 code is written.

## Phase 1 — MVP: 1:1 Encrypted Messaging (P2P core)
- Local identity generation (Ed25519 + X25519 keypairs)
- Direct P2P connection between two known peers (manual address exchange
  acceptable for now — discovery comes in Phase 2)
- X3DH + Double Ratchet session establishment and messaging
- Bare-bones CLI or minimal test UI to prove crypto + networking work
  end-to-end
- **Exit criteria:** two instances on different machines can exchange E2EE
  messages with no shared server, verified against the threat model's
  eavesdropper scenario (e.g., a packet capture shows only ciphertext).

## Phase 2 — Peer Discovery & NAT Traversal
- Kademlia DHT integration for peer discovery
- STUN/TURN/ICE and libp2p hole punching (DCUtR) for NAT traversal
- Invite-link based connection replacing manual address exchange
- **Exit criteria:** two peers on typical home NATs (no port forwarding)
  connect via invite link with no manual IP exchange.

## Phase 3 — Groups ("Servers") & Channels
- MLS group creation/join/leave via OpenMLS
- Channel-level key partitioning within a group
- Signed role/permission capability tokens (post/invite/kick)
- **Exit criteria:** a 3+ member group can be created, a member removed
  loses access to subsequently-sent messages (verified directly, not just
  assumed from the library).

## Phase 4 — Discord-like Client UI
- Server list, channel list, DM list, message view, member/role list
- Built on top of the Phase 1–3 backend via Tauri
- **Exit criteria:** a non-technical tester can create a server, invite a
  friend, and chat, without touching a CLI.

## Phase 5 — Offline Delivery
- Store-and-forward relay service (self-hosted and/or volunteer-run)
- Client-side polling/retrieval of queued encrypted blobs
- **Exit criteria:** a message sent while the recipient is offline is
  delivered once they come online, without the relay ever holding
  decryptable content (verified by inspecting relay-side storage).

## Phase 6 — Voice & Video
- WebRTC integration for calls and screen share, keyed from the existing
  channel/DM session material
- **Exit criteria:** a 1:1 call and a group call both work across a NAT'd
  connection using the Phase 2 traversal stack.

## Phase 7 — Rich Features
- Encrypted file/image sharing, reactions, threads, presence/status,
  disappearing messages
- **Exit criteria:** feature parity checklist against the "Discord-like"
  goal from the original vision, each new feature re-checked against
  threat-model.md for new metadata leakage before shipping.

## Phase 8 — Hardening & Third-Party Audit
- Independent security audit of the crypto implementation and protocol
  composition (not just the libraries — the way they're wired together)
- Address findings before any "production-ready" claim is made
- **Exit criteria:** audit complete, critical/high findings remediated.
  **This phase is not optional and should not be skipped or compressed
  under schedule pressure** — see crypto-spec.md §8.

## Phase 9 — Mobile Clients & Optional Anonymity Layer
- React Native or Flutter mobile clients calling the Rust core via UniFFI
- Opt-in Tor/onion-routing "Paranoid Mode" transport
- **Exit criteria:** mobile clients pass the same Phase 1/3 correctness
  checks as desktop; Paranoid Mode measurably prevents the IP-correlation
  attack it claims to prevent (tested, not assumed).

## Cross-cutting, ongoing throughout all phases

- Revisit `threat-model.md` whenever a new feature changes what data
  leaves a device unencrypted.
- No custom cryptographic protocol changes ship without review against
  `crypto-spec.md`'s "use a library, not a paper" rule.
- Track the open items in `tech-stack.md` as they get resolved, and record
  *why* a decision was made (not just what), so later phases don't
  relitigate settled tradeoffs without new information.
