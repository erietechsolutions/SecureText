# Network Architecture

## 1. Topology: hybrid P2P, not pure mesh

Pure P2P (every peer only ever talks directly to every other peer) breaks on
two real-world problems: **discovery** (how do you find a peer without a
central directory?) and **NAT traversal** (most consumer devices sit behind
NATs that block unsolicited inbound connections). SecureText uses the same
hybrid pattern as other successful "P2P" chat systems (Session, Briar,
Tox): direct P2P connections whenever possible, with minimal, dumb,
untrusted infrastructure filling the gaps.

```
 Peer A ───────── direct P2P (libp2p/Noise) ─────────── Peer B
   │                                                        │
   │        (when direct connection fails: NAT'd,           │
   │         both offline, etc.)                            │
   └──────────► DHT for discovery ◄──────────────────────────┘
                       │
              TURN relay (fallback transport,
              sees ciphertext only)
                       │
              Store-and-forward relay (Phase 5,
              holds encrypted blobs briefly,
              sees ciphertext only)
```

None of the infrastructure boxes above ever see plaintext or hold long-term
message history — see threat-model.md and crypto-spec.md.

## 2. Core networking library: libp2p

**libp2p** (`rust-libp2p`) provides, out of the box:
- Multiplexed streams over a single connection
- Pluggable transports (TCP, QUIC, WebRTC)
- `noise` transport security (see crypto-spec.md §4)
- A Kademlia DHT implementation for discovery
- NAT traversal helpers (identify protocol, AutoNAT, relay protocol, hole
  punching / DCUtR)

Building on libp2p avoids reimplementing NAT traversal and stream
multiplexing, which are notoriously easy to get subtly wrong.

## 3. Peer discovery

- Each **identity** publishes a record into the **Kademlia DHT**, keyed by a
  hash of its public key, containing its currently-reachable
  multiaddresses (updated as connectivity changes).
- Each **group ("server")** has its own DHT rendezvous key, derived from the
  group ID, that members use to find each other.
- **Invite links** encode: the group/peer rendezvous key + enough initial
  key material (an MLS "Welcome" message, or an X3DH prekey bundle for 1:1)
  to bootstrap the cryptographic session without any additional
  handshake round trip against a central server.

## 4. Prekey distribution (for X3DH)

X3DH requires the *responder* to have published prekeys somewhere the
*initiator* can fetch them even while the responder is offline. Without a
central server, this means:
- A peer publishes a signed prekey bundle into the DHT under its own
  identity key, refreshed periodically and after each use of a one-time
  prekey.
- If the peer is unreachable and no DHT record is fresh, the initiator's
  message queues locally and retries — or is handed to a store-and-forward
  relay (Phase 5) once that exists.

## 5. NAT traversal

Layered fallback, most-preferred first:
1. **Direct connection** — both peers have public/reachable addresses.
2. **Hole punching (DCUtR)** — libp2p's direct connection upgrade through
   relay, works for most consumer NATs.
3. **STUN** — address discovery to attempt a direct path even through NAT.
4. **TURN relay fallback** — when direct connection is impossible (symmetric
   NAT, restrictive firewalls), traffic is relayed through a TURN-like
   node. This node sees ciphertext and connection metadata only, never
   plaintext (transport encryption via Noise is already in place before
   this hop).

Budget for TURN relay fallback being used far more often in practice than
naive P2P demos suggest — carrier-grade NAT and corporate firewalls are
common.

## 6. Offline message delivery

The one place pure P2P fundamentally struggles: if both peers are offline
simultaneously, no direct or relayed connection is possible at all.

- **Phase 1–4 (MVP through UI):** messages queue locally and send on next
  successful connection; no offline-to-offline delivery yet. This is an
  acceptable, explicit limitation for early phases.
- **Phase 5:** introduce **store-and-forward relay nodes** — volunteer-run
  or self-hosted — that hold encrypted, addressed blobs for a bounded time
  (e.g., a rolling 30-day window) until the recipient's client polls and
  retrieves them. Relays are, by design, blind: they route on an opaque
  routing ID, not the recipient's identity key, and cannot decrypt the
  payload (see crypto-spec.md §6 for the residual metadata this still
  exposes, and why routing IDs should differ from identity keys).

## 7. "Servers" and channels without a server

Mapping Discord's guild/channel/role model onto the group-crypto model from
crypto-spec.md §3:

- **Server** = one MLS group. Its "existence" is just the set of members who
  hold current key state — there's no single machine that must stay online
  for the group to persist.
- **Channels** = key-partitioned sub-scopes within the group, so channel
  membership can be narrower than server membership (e.g., a private
  mod-only channel within an otherwise-open server).
- **Roles & permissions** = signed capability tokens issued by admin
  key(s) (crypto-spec.md §3) — e.g. "may post," "may kick," "may invite" —
  checked locally by every client, no central enforcement point.
- **Admin key management**: v1 assumes a single admin keypair per server
  (the creator); multi-admin / admin transfer is a Phase 3–4 design
  question once the base group model is working, likely via a
  threshold-signature or simply multiple keys on an ACL.

## 8. Moderation & abuse mitigation

Decentralization weakens centralized-style moderation — plan around it
rather than pretending it isn't a gap (see threat-model.md's non-goals):

- **Signed ban lists**, distributed within a group, enforced client-side by
  every member's client.
- **Local, per-user block lists**, optionally exportable/shareable
  ("import a trusted blocklist" from someone you trust).
- **Rate-limiting / lightweight proof-of-work** on message sends to raise
  the cost of spam floods, since there's no central rate limiter.
- **Client-side moderation bots**: a bot is just another group member with
  elevated signed capabilities (e.g., "may kick") — no special server-side
  hook needed.

## 9. Voice & video (Phase 6)

- **WebRTC** for media transport — handles SRTP media encryption, NAT
  traversal (it uses the same STUN/TURN/ICE machinery as §5), and is the
  de facto standard so we're not reinventing real-time media handling.
  Layer SecureText's own key exchange (from the MLS/Double-Ratchet session
  already established for the channel/DM) on top to get E2EE guarantees
  WebRTC's default (DTLS-SRTP) doesn't fully provide when a call is
  server-relayed elsewhere.

## 10. Optional anonymity transport (Phase 9)

- Opt-in "Paranoid Mode": route P2P traffic over **Tor** (as a hidden/onion
  service per peer) or a purpose-built onion-routing overlay, trading
  latency for IP-level unlinkability.
- This is additive to, not a replacement for, the E2EE guarantees above —
  see threat-model.md's confidentiality-vs-anonymity split for why it's a
  toggle rather than mandatory.
