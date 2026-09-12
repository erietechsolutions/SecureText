# Network Architecture

## 1. Topology: Tor v3 onion services, mandatory, for everything except calls

**Every peer runs a Tor v3 onion service (via `arti`, the Tor Project's own
Rust implementation) as its sole listening address.** No component of the
system — peers, store-and-forward relays, or the app's own infrastructure —
ever learns another party's real IP address for text, group, or file
traffic. This directly satisfies the requirement that no message be
traceable to a device: an onion address is not a network location, and
onion routing means neither end of a connection (nor anyone relaying it)
can determine the other end's IP.

```
 Peer A                                                    Peer B
 (.onion service,                                    (.onion service,
  arti)                                                arti)
   │                                                        │
   └───── Tor circuit (3+ hops, mutually anonymous) ─────────┘
                             │
              Store-and-forward relay (Phase 5) —
              also a .onion service; never sees a
              real IP, never sees plaintext
                             │
              obfs4 bridge (optional, when Tor
              itself is blocked/throttled — §5)
```

This replaces the earlier libp2p-based hybrid-P2P design (direct
connections + DHT discovery + STUN/TURN/ICE NAT traversal). That design is
no longer needed: **Tor onion services solve NAT traversal and discovery
reachability inherently** (an onion service is reachable through any NAT
without port forwarding, by construction), so the DHT/STUN/TURN/hole-punching
machinery that hybrid P2P designs need is simply not required for this
transport. `rust-libp2p` has accordingly been dropped from the stack —
see tech-stack.md.

This pattern is proven prior art, not speculative: **Cwtch** (Open Privacy
Research Society), inspired by **Ricochet**, uses exactly this shape — E2EE
messaging entirely over Tor v3 onion services, with untrusted relay
infrastructure for offline delivery — for the same goal of metadata-resistant,
serverless anonymous messaging.

## 2. Identity, onion addresses, and invites

- A v3 onion address is itself derived from an Ed25519 public key. Each
  identity's onion-service key is kept **separate from** the long-term MLS
  identity signing key (crypto-spec.md §1) — this is a deliberate
  separation of concerns (network-reachability key vs. cryptographic
  identity key), not a cost-saving reuse, so that either can be rotated
  independently without disturbing the other (e.g., rotating the onion
  address for better unlinkability over time without losing MLS group
  membership continuity, which is tied to the identity key).
- **Invite links** encode: the target's current onion address + enough
  initial key material (an MLS "Welcome" message for joining a group, or
  the recipient's MLS key package for starting a 1:1 — see crypto-spec.md
  §2) to bootstrap the cryptographic session without any additional
  discovery step. There is no DHT and no other discovery mechanism in v1 —
  onion address + invite is the entire reachability model, matching
  Cwtch/Ricochet's approach.
- Onion addresses can be rotated by a user (generating a new onion-service
  key) as a deliberate unlinkability measure; peers who already hold a
  contact's MLS identity key learn the new address via an MLS-group-internal
  "I've moved" message signed by the same long-term identity key, so
  rotation doesn't require re-establishing trust from scratch.

## 3. Why no DHT / STUN / TURN / hole-punching for messaging

The previous design used a Kademlia DHT for peer discovery and
STUN/TURN/ICE/DCUtR for NAT traversal, because pure clearnet P2P needs both.
Onion services make both unnecessary for this traffic:

- **Discovery:** solved by invite links (§2) — there's no need for a global
  or semi-global discovery mechanism in v1, and a clearnet DHT would
  actively work against the anonymity goal (DHT participation ordinarily
  means exposing your IP to arbitrary other DHT nodes).
- **NAT traversal:** solved inherently — an onion service is reachable via
  the Tor network regardless of the host's NAT/firewall situation, with no
  port forwarding, STUN, or TURN required. This also sidesteps the
  platform-specific firewall friction noted in platform-support.md (Windows
  Defender prompts, Fedora's `firewalld` default-deny) for this traffic,
  since there's no inbound clearnet port involved at all.

This is a meaningful simplification, not just an anonymity win: it removes
an entire category of NAT-traversal edge cases and platform-specific
firewall handling from the codebase, directly serving the "efficient [to
build and maintain], secure" goal alongside the anonymity requirement.

## 4. Offline message delivery

Unchanged in spirit from the original design, adapted to onion services:

- **Phase 1–4:** messages queue locally and send on next successful
  connection to the recipient's onion service; no offline-to-offline
  delivery yet.
- **Phase 5:** **store-and-forward relay nodes** — volunteer-run or
  self-hosted — each reachable only via its own onion service, hold
  encrypted, addressed blobs for a bounded time until the recipient's
  client polls and retrieves them. A relay never sees a real IP (clients
  reach it only through Tor) and never sees plaintext (crypto-spec.md §6).

## 5. Circumventing Tor blocking: pluggable transports (bridges)

Some networks and countries block or throttle Tor itself. Since the
anonymity guarantee is mandatory rather than optional, SecureText must
remain usable on such networks from the start, not as a later add-on:

- **`arti` supports pluggable transports, including obfs4, since v1.1.0**
  (configured via an external `obfs4proxy` binary, the same mechanism the
  reference C Tor implementation uses). This is built into Phase 1, not
  deferred.
- The client ships with (or can fetch) a set of known public bridge
  addresses and supports the user adding their own (e.g., obtained via
  Tor's bridge distribution channels), consistent with how Tor Browser
  handles bridge configuration.
- **Open item:** decide the UX for bridge configuration in Phase 1/2 —
  auto-detect-and-prompt when a direct Tor connection fails, vs. an
  explicit settings toggle. Not blocking initial architecture work, but
  should be resolved before Phase 1's exit criteria are finalized.

## 6. Efficiency within the Tor constraint

Mandatory onion routing has an unavoidable latency floor (circuit
construction and multi-hop relaying are simply slower than a direct or
lightly-relayed clearnet connection). "Efficient" for SecureText means
minimizing overhead *within* that constraint, not competing with a
clearnet service's raw latency:

- **Persistent circuits / connection reuse:** build a Tor circuit to a
  given contact or server once and reuse it for the session rather than
  rebuilding per message — circuit construction is the dominant latency
  cost, not the per-message onion relaying itself.
- **Stream multiplexing over one circuit:** rather than opening a new
  onion-service connection per logical stream (e.g., per channel, or a
  control stream vs. a data stream), multiplex multiple logical streams
  over a single established connection using a lightweight multiplexer
  (the `yamux` crate) on top of the Noise-secured stream (crypto-spec.md
  §4). This avoids paying circuit-build latency repeatedly for what the UI
  presents as one "connection" to a server.
- **Efficient serialization:** binary/structured wire formats (not
  JSON/text) for protocol messages, to minimize bytes sent over
  already-latency-constrained circuits.
- **Client resource efficiency:** the Rust + Tauri stack (tech-stack.md)
  keeps CPU/memory overhead low independent of the network layer, so the
  Tor latency cost isn't compounded by an inefficient client.
- This is a genuine, disclosed tradeoff: text messaging over Tor will feel
  noticeably slower than Discord's direct clearnet connections, especially
  for the first message in a new session (circuit build time). Set
  expectations accordingly rather than promising Discord-equivalent
  responsiveness for text.

## 7. "Servers" and channels without a server

Mapping Discord's guild/channel/role model onto the group-crypto model from
crypto-spec.md §3 — unchanged by the Tor pivot, since this operates at the
message/group layer, orthogonal to the transport:

- **Server** = one MLS group. Its "existence" is just the set of members who
  hold current key state — there's no single machine that must stay online
  for the group to persist, and no server-side onion service required
  beyond each member's own.
- **Channels** = key-partitioned sub-scopes within the group, so channel
  membership can be narrower than server membership. **Implemented as
  independent MLS groups** (a channel's roster is a subset of the server's
  members, added to that channel's own group the normal way), not
  OpenMLS's native sub-group branching (RFC 9420 §11.3) — branching
  cryptographically ties a sub-group to the exact parent epoch it split
  from, which is real value this design forgoes, but it needs tracking a
  sliding window of `BranchInfo` per parent epoch and careful
  sender/receiver epoch-matching to implement correctly. An independent
  group delivers the actual property needed here (narrower membership,
  genuine cryptographic exclusion — verified directly in
  `securetext-crypto`'s `private_channel_excludes_non_members` test: a
  server member excluded from a channel provably cannot decrypt its
  messages) with far less correctness risk. Revisit if a concrete need for
  the parent-epoch binding specifically comes up.
- **Roles & permissions** = signed capability tokens (`securetext-crypto`'s
  `Capability`/`Permission`) issued by admin key(s) (crypto-spec.md §3) —
  checked locally by every client using the group's own signature
  verification, no central authority contacted. A capability's `group_id`
  can name either a server or one of its channels, so "may post in this
  specific channel" uses the exact same mechanism as a server-wide grant.
- **Admin key management**: v1 assumes a single admin keypair per server
  (the creator); multi-admin/transfer is a Phase 3–4 question.

## 8. Moderation & abuse mitigation

Unchanged from the original design (decentralization's moderation weakness
is orthogonal to the transport choice — see threat-model.md's non-goals):

- **Signed ban lists**, distributed within a group, enforced client-side.
- **Local, per-user block lists**, optionally exportable/shareable.
- **Rate-limiting / lightweight proof-of-work** on message sends.
- **Client-side moderation bots**: just another member with elevated
  signed capabilities.

## 9. Voice & video (Phase 6) — the disclosed exception

Per the explicit design decision (see threat-model.md's disclosed
exception): calls use a **separate, faster path than text messaging**,
trading some anonymity for usable call quality, rather than routing
real-time media over Tor.

- **WebRTC** for media transport (SRTP), using STUN/TURN/ICE for NAT
  traversal — this reintroduces, *for calls only*, the NAT-traversal
  machinery that §3 otherwise eliminates for messaging.
- **Mitigation to preserve as much anonymity as practical:** default to a
  **forced-relay mode** (media always routed through a TURN-style relay
  rather than attempting a direct peer connection), so participants don't
  learn each other's raw IP directly — the relay operator can see both
  IPs, which is the accepted exposure for this feature, but the other call
  participant does not. This mirrors how mainstream E2EE calling apps
  (e.g., Signal's "always relay calls" setting) handle the same tradeoff.
- **Call signaling** (who is being called, ringing, accept/decline) still
  goes over the Tor-routed MLS channel like any other message — only the
  real-time media stream itself uses the separate path, once a call is
  accepted.
- Call content itself remains E2EE: layer SecureText's own MLS-derived key
  material on top of WebRTC's DTLS-SRTP rather than relying solely on
  WebRTC's default, which doesn't guarantee confidentiality end-to-end when
  media is server-relayed.
- **UI requirement:** the calling UI must disclose that starting a call
  uses a faster, non-anonymous connection, so users don't assume the
  always-on text anonymity guarantee extends to calls (threat-model.md).
- This design is a placeholder for Phase 6 — the exact mechanism should be
  re-validated against threat-model.md's disclosed-exception language once
  Phase 6 actually starts.
