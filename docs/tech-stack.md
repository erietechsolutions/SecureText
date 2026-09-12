# Technology Stack Decisions

Core language decision: **Rust**, confirmed for this project. Rationale:
best-in-class crypto and Tor ecosystem (OpenMLS, RustCrypto crates, `arti`),
memory safety without a garbage collector (relevant for a security-sensitive
app handling key material), and a Rust core compiles cleanly to a shared
library that mobile clients (Phase 9) can call into via UniFFI — avoiding a
second implementation of the crypto/networking layer for mobile.

**Target platforms:** Ubuntu, Fedora, and Windows 10/11 (see
[platform-support.md](platform-support.md) for the full matrix and
per-platform implementation notes — OS keyring, firewall defaults,
packaging). Every choice below was made with cross-platform Rust crates
specifically to avoid OS-specific forks of the core logic.

**Anonymity and crypto stack, finalized:** all text/group/file traffic is
routed over Tor v3 onion services (mandatory, not optional), and both 1:1
and group messaging use OpenMLS as the single E2EE stack. See
[architecture.md](architecture.md) and [crypto-spec.md](crypto-spec.md) for
the full reasoning. This resolves what were previously open items in this
document (the libp2p networking choice and the libsignal/vodozemac
question) — both are now settled below.

## Core / backend

| Concern | Choice | Why |
|---|---|---|
| Language | Rust | See above |
| Anonymous transport | **`arti`** (the Tor Project's own pure-Rust Tor implementation) | Production-ready client + onion-service support as of its 2026 releases; supports pluggable transports (obfs4) since v1.1.0 for bridge/censorship-resistance needs (architecture.md §5); pure Rust keeps the whole stack auditable without an external `tor` binary dependency |
| Stream multiplexing (over one Tor circuit) | `yamux` | Lightweight, widely used multiplexer; avoids paying Tor circuit-build latency per logical stream (architecture.md §6) |
| Transport-layer defense in depth | `snow` (Noise Protocol Framework) | Authenticates the specific peer identity on top of the onion-service stream; independent of Tor's own transport crypto (crypto-spec.md §4) |
| E2EE (1:1 and groups) | `OpenMLS` | Actively maintained RFC 9420 implementation in Rust; used uniformly for both 1:1 (as a 2-member group) and multi-member groups — see crypto-spec.md §2 for why libsignal, vodozemac, and other alternatives were rejected |
| Symmetric crypto primitives | `RustCrypto` crates (`chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`) | Widely used, individually audited primitive crates rather than a monolithic library |
| Password/passphrase KDF | `argon2` crate (Argon2id) | Memory-hard, current best practice over PBKDF2/bcrypt |
| Local storage | SQLite via `rusqlite` + SQLCipher | Encrypted at rest; SQL is sufficient for message/channel/member metadata at this scale |
| Voice/video | WebRTC via `webrtc-rs` | Native Rust WebRTC implementation; used only for the Phase 6 calls exception (architecture.md §9), which is deliberately outside the Tor transport |

**Dropped from the stack:** `rust-libp2p`. It was chosen when the network
design was hybrid clearnet P2P needing DHT discovery and STUN/TURN/ICE NAT
traversal. Onion services solve both of those problems inherently
(architecture.md §3), making libp2p's NAT-traversal and DHT machinery dead
weight — removing it reduces dependency and audit surface, which directly
serves the "efficient and secure" goal rather than trading against it.

## Client / UI

| Concern | Choice | Why |
|---|---|---|
| Desktop shell | **Tauri** | Rust backend (shares the core directly, no FFI boundary for desktop), web frontend for fast UI iteration, much smaller binary/resource footprint than Electron; ships native installers for all three target OSes (see platform-support.md) |
| Frontend framework | React or Svelte (pick during Phase 4 UI work, not a Phase 0 blocker) | Either works fine inside Tauri; decision deferred since it doesn't affect the core architecture |
| Mobile (Phase 9) | React Native or Flutter shell, calling the Rust core via UniFFI | Reuses the audited Rust core instead of reimplementing crypto/networking per platform |

## Infrastructure (minimal, by design)

| Concern | Choice | Why |
|---|---|---|
| Call relay (Phase 6 only) | `coturn` (self-hostable) or a small custom Rust TURN-compatible relay | Standard, well-understood software; only used for the disclosed calls exception (architecture.md §9), never for text/group traffic |
| Store-and-forward relay (Phase 5) | Custom minimal Rust service, reachable only via its own onion service | No existing off-the-shelf "blind encrypted mailbox" server fits exactly; keep it deliberately simple (store blob, TTL, opaque routing ID lookup) to minimize audit surface |
| Pluggable transport (bridges) | `obfs4proxy` (external binary, invoked by `arti` per its documented pluggable-transport config) | Same mechanism the reference C Tor implementation uses; no need to reimplement obfs4 |

## Open items to resolve before Phase 1 coding starts

1. **MLS-as-1:1 latency/throughput validation** — benchmark 2-member
   OpenMLS groups at realistic chat-speed message rates over an actual Tor
   circuit (not just localhost) before considering the "one crypto stack"
   decision (crypto-spec.md §2) fully settled. If it's a real problem,
   the fallback is a from-spec Double Ratchet implementation reviewed in
   the Phase 8 audit, not a third-party dependency.
2. **SQLCipher Rust binding maturity** — verify `rusqlite`'s SQLCipher
   feature flag builds cleanly on Ubuntu, Fedora, and Windows before
   relying on it for at-rest encryption; the OpenSSL/vcpkg dependency
   chain on Windows is the highest-risk part (see platform-support.md
   open item #1 for the fallback plan if it proves painful).
3. **`webrtc-rs` vs. FFI to `libwebrtc`** — `webrtc-rs` is younger than
   Google's `libwebrtc`; verify it covers everything needed (in particular
   ICE/TURN interop for the forced-relay calling mode) before Phase 6, or
   plan an FFI fallback.
4. **Bridge configuration UX** — auto-detect-and-prompt vs. explicit
   settings toggle for obfs4 bridges (architecture.md §5); needs a decision
   before Phase 1's exit criteria are finalized, not a hard blocker for
   starting the Tor integration itself.
5. **Frontend framework for Tauri** (React vs. Svelte vs. other) — deferred
   to Phase 4, not blocking.

## Standing rule: crypto/network-adjacent dependency vetting

Prompted by how noisy a crates.io search for Signal-protocol-adjacent
crates turned out to be (many low-quality or suspiciously-named packages
with tiny download counts) — **no crate touching cryptography, identity, or
the network/anonymity layer gets added to this project based on name match,
download count, or a quick glance alone.** Before adding one, verify
directly (not from memory): current license, whether the repository is
actively maintained (recent commits, not just recent version bumps), star
count/real-world adoption as a maintenance signal, and whether it has any
public audit history. This applies to every future dependency addition in
this category, not just the ones evaluated in Phase 0.
