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
| Invite link encoding | `base64` (`marshallpierce/rust-base64`) | Extremely widely used (1.5B+ downloads), MIT/Apache-2.0, actively maintained — vetted per this doc's own standing rule below; used to keep byte fields (keys, key packages) compact within an invite link's JSON payload instead of serde_json's default number-array encoding |

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
- **Noise defense-in-depth layer (crypto-spec.md §4): implemented and
  live-verified.** Uses `snow` with `Noise_XX_25519_ChaChaPoly_BLAKE2s`
  (matching the project's ChaCha20-Poly1305 preference). Each identity now
  carries a persistent Noise static X25519 keypair alongside its MLS
  signing key (`securetext-identity`, stored in the same envelope-encrypted
  SQLite file). Two things worth flagging for future work in this area:
  `snow` 0.10's `Builder::local_private_key()` returns a `Result` (the
  docs.rs example available at the time showed it as infallible — always
  verify against the actual installed version, not cached documentation);
  and the handshake/transport functions in `securetext-net` are generic
  over `AsyncRead + AsyncWrite` rather than concretely typed to
  `arti_client::DataStream`, specifically so the handshake logic could be
  correctness-tested locally over an in-memory `tokio::io::duplex` pipe
  without needing a live Tor connection for every iteration — worth doing
  for any future protocol layer built on top of the transport.
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
- **Live-verified in this dev sandbox, fully** (not just compiled):
  `arti` bootstraps onto the real Tor network in ~15s, launches a live v3
  onion service, and a complete two-party byte round trip over it succeeds
  — both as two independent `TorClient`s in one process
  (`two_peer_round_trip_over_onion_service_live`, ~35-48s total) and as two
  genuinely separate OS processes (`securetext net-listen` /
  `securetext net-dial <address>` in two terminals). The full identity + MLS
  + Tor integration also verified end to end via `securetext demo`: two
  local identities form an MLS group, exchange a Welcome and an encrypted
  application message in both directions, entirely over live onion
  services.
- **`DataStream` buffers writes internally and requires an explicit
  `.flush()`** — `AsyncWriteExt::write_all` succeeding does *not* mean the
  bytes left the local buffer, let alone reached the remote peer. This was
  the actual cause of what first looked like a 10+-minute bootstrap stall
  in the concurrent-two-clients test: bootstrap had already finished in
  both cases (there was simply no log line between "bootstrapping" and the
  final success message to reveal that), and the test was silently hung on
  an unflushed write with the reader blocked forever waiting for bytes that
  never left the sender's buffer. Once `.flush()` was added, the same test
  finished in under a minute — the original "thread contention between two
  Tor clients" theory was wrong; there was no bootstrap problem at all, in
  one process or two.
- **A successful `.flush()`/`.shutdown()` doesn't mean the *remote* has
  received the data yet** — delivery across a live multi-hop Tor circuit
  takes real wall-clock time that isn't synchronized with the local
  future's completion. Dropping a stream (or exiting the process) right
  after a successful flush/shutdown reliably raced the in-flight data and
  produced `NotConnected` on the reader's side. Fixed with a short
  (~3s) grace period after the last write and before the stream is
  dropped/the process exits — acceptable for this short-lived CLI/test
  code, and irrelevant for the real app, which is a long-running process
  that doesn't exit right after sending a message. Both fixes are in
  `crates/securetext-net/src/lib.rs`'s tests and
  `crates/securetext-cli/src/main.rs`.

## Open items to resolve before Phase 1 is considered complete

1. ~~**End-to-end Tor-circuit latency for MLS-as-1:1 messaging**~~ —
   **measured** (`securetext bench [N]`, `crates/securetext-cli`): 20
   MLS+Noise-encrypted round trips over one already-established Tor
   circuit (i.e. excluding the one-time connection setup: two Tor
   bootstraps, onion-service launch, and the Noise handshake) came in at
   min=2.23s, p50=3.09s, avg=3.46s, max=6.32s in this dev environment.
   MLS's own overhead is negligible (~5.7ms/message locally, per the
   finding above) — this multi-second cost is essentially all Tor circuit
   latency, consistent with architecture.md §6's disclosed tradeoff
   ("text messaging over Tor will feel noticeably slower than Discord").
   **Verdict:** usable for text chat (a few seconds per message is
   tolerable, unlike for calls — architecture.md §9's separate path
   remains the right call there), but confirms this is a real, now-
   quantified cost rather than a hypothetical one. Numbers will vary by
   network conditions and should be re-measured periodically, not treated
   as a permanent constant; worth re-running once yamux multiplexing
   (open item #6) lands, since reusing one circuit for multiple logical
   streams may change steady-state behavior.
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
5. ~~**MLS group state persistence across restarts**~~ — **done.**
   `Member<P>` (`crates/securetext-crypto`) is now generic over its
   `OpenMlsProvider`; `PersistentProvider` (new: `provider.rs`) composes
   `openmls_rust_crypto::RustCrypto` (crypto/rand — no need to persist
   that) with `openmls_sqlite_storage::SqliteStorageProvider` (storage).
   OpenMLS's own persistence design does the rest: group state is written
   through automatically during normal operations, and `MlsGroup::load(storage,
   group_id)` reconstructs a group handle from a fresh provider — no
   custom serialization needed on our side. `PersistentProvider` opens its
   *own* connection to `IdentityStore::db_path()`'s underlying SQLite file
   rather than sharing the store's live `Connection` by reference, which
   would otherwise tie a `Member`'s lifetime to the store's borrow state
   (conflicting with `seal(&mut self)`) — SQLite handles multiple
   connections to one file fine. Verified two ways: a fast local unit test
   (`group_state_survives_reload_from_sqlite`, no Tor) that drops and
   reloads a group mid-test, and `securetext restart-demo`, which performs
   a *complete* simulated restart — identity stores sealed to their
   encrypted files and fully dropped, then reopened from those files with
   the MLS group reloaded by ID — and successfully exchanges messages in
   both directions afterward. Matches OpenMLS's own persistence guidance
   ("protect the storage backend itself, for example with authenticated
   encryption") for free, since it's reusing `securetext-identity`'s
   already-encrypted file rather than a second, separately-secured store.
6. ~~**yamux multiplexing over the Noise session**~~ — **done, live-verified.**
   `securetext-net`'s new `SecureMux` (`secure_mux.rs`) composes a
   background "Noise pump" task (turns the raw onion-service `DataStream`
   plus an established `NoiseTransport` into a plain `tokio::io::duplex`
   pipe, chunking/reassembling across Noise's bounded message size) with a
   `yamux::Connection` driven over that pipe. Two implementation notes
   worth keeping for future maintainers:
   - The `yamux` crate ships no end-to-end usage example; the driving
     pattern (a dedicated task looping on `poll_next_inbound`, since that's
     *the only way yamux makes any progress at all* — true even for
     purely outbound stream I/O) was verified against `rust-libp2p`'s own
     yamux muxer, the primary real-world consumer of this exact crate.
   - **The same "flush ≠ delivered" race from the Noise/DataStream layer
     recurs one level up.** The first version of the local test failed
     intermittently because dropping a `SecureMux` (which aborts its
     driver task) immediately after a final write doesn't guarantee that
     write actually finished propagating through the pump to the raw
     stream. Fixed with a proper `SecureMux::close()` that drives
     `yamux::Connection::poll_close()` to settle the connection before the
     driver task ends, rather than a sleep — confirmed by the test
     dropping from failing intermittently to passing in ~0.01s consistently
     (20/20 runs) once `close()` was used instead of a delay.
   Verified two ways: a local test (`multiple_streams_over_one_connection`,
   no Tor, opens 3 concurrent logical streams and exchanges independent
   data on each) and live against the real Tor network via `securetext
   demo`, which now opens two multiplexed streams (a "control" stream for
   the MLS Welcome, a "chat" stream for application messages) over one
   onion-service connection.
7. **Frontend framework for Tauri** (React vs. Svelte vs. other) — deferred
   to Phase 4, not blocking.

## Phase 2 implementation findings

- **Invite links needed a persistent identity/Tor-state directory, which
  the Phase 1 CLI didn't have.** `demo`/`bench`/`net-listen`/`net-dial` all
  use a fresh `tempfile::tempdir()` per run — fine for one-shot proofs, but
  an invite link printed by one run of a tempdir-based process would
  reference an onion address that stops existing the moment that process
  exits. `invite`/`connect` introduced `open_persistent_identity()`
  (`crates/securetext-cli`), which opens/creates the identity at
  `<dir>/identity.enc` and points `arti` at `<dir>/tor-state` /
  `<dir>/tor-cache` instead of a tempdir, so the onion-service key (and
  thus the address) stays stable across restarts — this is the same
  `bootstrap_with_dirs` function from Phase 1, just pointed somewhere
  durable instead of ephemeral.
- **serde's default `Vec<u8>` encoding (a JSON array of numbers) is very
  wasteful for key material.** An invite carrying a 32-byte Noise key and a
  ~200-300 byte MLS key package came out well over 1000 characters before
  fixing this — each byte was ~4-5 JSON characters (`"186,"`) instead of
  ~1.4 base64 characters. Fixed with a small `#[serde(with = "as_base64")]`
  helper module (`securetext-invite`) rather than switching the whole
  payload format; still JSON, just with base64 strings for the byte
  fields. Worth remembering for any future wire format carrying key
  material as JSON.

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
