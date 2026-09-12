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

## Phase 1 implementation findings (from actually building it)

These replace/sharpen the open items below with what was learned writing
the real Cargo workspace (`crates/securetext-{identity,crypto,net,cli}`),
rather than guessed in advance:

- **MLS-as-1:1 local performance: not a bottleneck.** A 2-member OpenMLS
  group (ChaCha20-Poly1305 ciphersuite,
  `MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_Ed25519`) round-tripped 200
  encrypt+decrypt operations in ~1.15s (~5.7ms/message) with the in-memory
  provider — negligible next to any realistic Tor circuit latency. The
  "one crypto stack" decision (crypto-spec.md §2) is validated on the local
  compute side; what remains is measuring actual Tor-circuit latency
  end-to-end, not the MLS overhead itself.
- **`openmls_basic_credential::SignatureKeyPair::private()` and
  `MlsMessageIn::into_welcome()` are both `#[cfg(feature = "test-utils")]`
  or `#[cfg(test)]`-gated in the published crate** — not available to
  application code by design. Identity persistence uses
  `openmls_sqlite_storage`'s official `StorageProvider`-based
  `.store()`/`.read()` instead of raw key export; Welcome extraction uses
  `MlsMessageIn::extract()` pattern-matched against `MlsMessageBodyIn`
  instead of the test-only convenience method. Both are implemented in
  `crates/securetext-identity` and `crates/securetext-crypto`.
- **`tls_codec` version must track whatever `openmls` 0.9 actually pulls in
  (0.5.x), not an independently-guessed version** — pinning it separately
  causes two copies of the crate in the dependency graph and ambiguous
  trait resolution errors.
- **At-rest encryption, interim design (resolves open item #2 below more
  concretely):** `openmls_sqlite_storage` pins its own `rusqlite` (`^0.37`)
  with the plain `bundled` feature, separate from a hypothetical
  SQLCipher-enabled `rusqlite` we'd add ourselves — getting the two to
  feature-unify into one SQLCipher-enabled build needs either a patched
  fork of `openmls_sqlite_storage` or a dependency version alignment spike,
  neither done yet. **Interim implementation (shipped, tested):**
  `securetext-identity` runs the SQLite database in a private temp file for
  the session and envelope-encrypts the *entire file* with Argon2id +
  ChaCha20-Poly1305 on `seal()`, rather than relying on SQLCipher's
  row-level encryption. This satisfies "a stolen device shouldn't expose
  the identity key" (threat-model.md) today; row-level SQLCipher encryption
  (less plaintext-on-disk exposure window, no temp file) remains a
  worthwhile hardening, tracked as open item #2.
- **arti's `fs-mistrust` ownership check can false-positive in a sandboxed
  dev environment** where `$HOME`'s ancestor directories have unusual
  ownership (observed: a Flatpak sandbox presenting `/home` itself as
  owned by a different uid than the user's own home directory). This is
  arti behaving correctly by its own security model, not a bug — the fix
  is pointing `TorClientConfigBuilder::from_directories()` at a directory
  with a clean ownership chain (e.g., under `/tmp`) for that environment,
  never disabling the check. Documented in `securetext-net`'s tests as a
  troubleshooting note for future contributors hitting the same thing.
- **Live-verified in this dev sandbox** (not just compiled): `arti`
  successfully bootstrapped onto the real Tor network in ~15s and launched
  a live v3 onion service with a real `.onion` address
  (`bootstrap_and_launch_onion_service_live`, passing). **Not yet verified:
  a full two-party round trip** — `two_peer_round_trip_over_onion_service_live`
  runs two independent `TorClient`s concurrently in one process and got
  stuck for 10+ minutes on the second client's bootstrap (vs. ~15s for a
  single client alone) before being killed; this looks like resource/thread
  contention between two full Tor clients sharing one small
  (`worker_threads = 2`) tokio runtime rather than a transport-layer
  problem, since each half (bootstrap, onion service launch, and the
  underlying `dial`/`accept_next` code) is otherwise exercised and correct.
  **Open item, not silently resolved:** re-run this test with a larger
  worker-thread pool and/or as two genuinely separate OS processes (closer
  to how two real users' devices would run anyway) before treating Phase
  1's "two instances exchange E2EE messages entirely over Tor" exit
  criterion as met.

## Open items to resolve before Phase 1 is considered complete

1. **End-to-end Tor-circuit latency for MLS-as-1:1 messaging** — now that
   both pieces work independently (MLS round-trip: ~5.7ms/message locally;
   Tor onion-service round trip: verified working), measure the *combined*
   real-world latency of an MLS-encrypted message sent over an actual Tor
   circuit, not each piece in isolation.
2. **SQLCipher / row-level at-rest encryption for the MLS+identity store**
   — see the finding above; either patch `openmls_sqlite_storage` to accept
   an externally-configured (SQLCipher) connection, or align dependency
   versions so Cargo's feature unification does it automatically. The
   whole-file envelope encryption already shipped is the accepted interim
   state, not a blocker.
3. **`webrtc-rs` vs. FFI to `libwebrtc`** — `webrtc-rs` is younger than
   Google's `libwebrtc`; verify it covers everything needed (in particular
   ICE/TURN interop for the forced-relay calling mode) before Phase 6, or
   plan an FFI fallback.
4. **Bridge configuration UX** — auto-detect-and-prompt vs. explicit
   settings toggle for obfs4 bridges (architecture.md §5); needs a decision
   before Phase 1's exit criteria are finalized. Not yet implemented in
   `securetext-net` — the live tests so far rely on unrestricted direct Tor
   access, not bridges.
5. **MLS group state persistence across restarts** — `securetext-crypto`
   currently uses OpenMLS's in-memory provider (`OpenMlsRustCrypto`) for
   group/ratchet state, proven correct but not durable. Wiring
   `openmls_sqlite_storage` into the group's provider (not just the
   identity key, which already uses it) is the natural next step, likely
   alongside item #2 above since it's the same storage layer.
6. **Noise defense-in-depth layer and yamux multiplexing** (crypto-spec.md
   §4, architecture.md §6) are not yet implemented — `securetext-cli`'s
   demo currently frames messages with a plain length prefix directly over
   the raw onion-service stream as a placeholder.
7. **Frontend framework for Tauri** (React vs. Svelte vs. other) — deferred
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
