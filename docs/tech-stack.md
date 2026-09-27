# Technology Stack Decisions

Core language decision: **Rust**, confirmed for this project. Rationale:
best-in-class crypto and Tor ecosystem (OpenMLS, RustCrypto crates, `arti`),
memory safety without a garbage collector (relevant for a security-sensitive
app handling key material), and a Rust core compiles cleanly to a shared
library that mobile clients (Phase 10) can call into via UniFFI — avoiding a
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
| Voice/video | `webrtc-rs` (`webrtc` 0.17, `turn` 0.17), `opus` 0.4 (libopus built in via `opusic-sys`), `cpal` | Native Rust WebRTC, used only for the Phase 7 calls exception (architecture.md §9), which is deliberately outside the Tor transport. Media runs in Rust because distro WebKitGTK builds lack WebRTC (Phase 7 findings). The `turn` crate also provides `securetext-turn` |
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
| Mobile (Phase 10) | **To decide in Phase 10:** Tauri 2 mobile (reuses `desktop/ui` and calls the Rust core directly) vs. a React Native/Flutter shell calling the core via UniFFI (the original plan) | Either way the audited Rust core is reused instead of reimplementing crypto/networking per platform; Tauri mobile became the likely lower-effort option once the desktop client was built on Tauri |
| Installers & updates (Phase 6) | Tauri bundler, GitHub Releases, GitHub Actions; our own updater (`securetext-update`: Ed25519 via `ed25519-dalek`, TLS via `rustls` + bundled `webpki-roots`, a minimal HTTP/1.1 client) | Native installers per OS from one codebase. Tauri's updater plugin was passed over because it fetches over the clearnet; ours runs only over arti exit streams, and is small enough to audit. Updates are signature-verified against an offline key and fetched **over Tor only** |

## Infrastructure (minimal, by design)

| Concern | Choice | Why |
|---|---|---|
| Call relay (Phase 7 only) | `coturn` (self-hostable) or a small custom Rust TURN-compatible relay | Standard, well-understood software; only used for the disclosed calls exception (architecture.md §9), never for text/group traffic |
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
   ICE/TURN interop for the forced-relay calling mode) before Phase 7, or
   plan an FFI fallback. *(Resolved in Phase 7: relay-only ICE through its
   TURN client works, verified with its TURN server and over the GUI. It
   hasn't yet been tested against coturn or across real NATs.)*
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
7. **Frontend framework for Tauri** (React vs. Svelte vs. other).
   **Resolved in Phase 4: neither.** The UI is plain HTML/CSS/JS with no
   framework, no npm dependencies and no build step (`desktop/ui/`). The
   screens here (lists, a message view, a few dialogs) don't need a
   framework, and every npm package in a privacy tool's frontend is
   third-party code running next to decrypted messages, pulled from a
   registry with a long supply-chain-incident history. This keeps that
   surface at zero. Revisit if the UI grows past what hand-written DOM
   code handles cleanly (Phase 8's threads/reactions are the likely
   trigger).

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
- **obfs4 bridge support needs the `pt-client` Cargo feature on
  `arti-client`** (pulls in `bridge-client`, `tor-ptmgr`, and PT support in
  `tor-chanmgr`/`tor-guardmgr`) — confirmed no regression to normal
  (non-bridge) bootstrap after enabling it. **The `arti-client` crate ships
  no obfs4-specific example**; the real, verified reference for the
  `BridgeConfigBuilder`/`TransportConfigBuilder` API was
  `arti-client/examples/snowflake.rs` in arti's own repository, which uses
  the identical API surface for a different pluggable transport
  (snowflake instead of obfs4) — worth knowing this pattern generalizes to
  other PTs if one is ever needed. See `securetext_net::bootstrap_with_bridge`.
- **"I've moved" notifications ride the existing MLS-encrypted channel
  rather than needing a new signature scheme.** MLS's `process_message`
  already verifies the sender's credential as part of the protocol, so an
  `AppMessage::Moved` (`securetext-crypto`, a small enum alongside
  `AppMessage::Chat`) delivered through a group a peer is already a
  verified member of inherits that authenticity for free — no separate
  signature over the new address/key was needed. The harder design
  question turned out to be *when* to send it: a rotated address is only
  reachable *before* the switch, so the notification has to go out over
  the still-open old connection, not a new one (a new connection to an
  address the recipient doesn't know yet is a chicken-and-egg problem).
  `securetext rotate-demo` sequences this explicitly: rotate, notify over
  the still-open v1 connection, only *then* close it and let the peer
  reconnect via their updated contact record.
- **`bootstrap_for_this_run`'s `.keep()` call was a real, silent disk-space
  leak, found by actually stress-testing the CLI repeatedly rather than in
  code review.** It called `.keep()` on its `tempfile::TempDir` to solve a
  genuine lifetime problem (the Tor state/cache dir must outlive the
  function, since arti keeps using it for as long as the returned `Client`
  does) -- but that also means the directory (~40MB per Tor bootstrap,
  consensus/descriptor data) was never cleaned up, for the life of the
  process or the disk. Across this session's many `demo`/`bench`/
  `rotate-demo` runs, these silently accumulated and eventually filled
  this sandbox's 1.6GB tmpfs, which then caused unrelated `securetext-identity`
  tests to fail with "No space left on device" -- a failure with zero
  apparent connection to the change actually being tested, which took a
  `df`/`du` investigation to trace back to this. **Fixed** by returning the
  `TempDir` guard alongside the `Client` instead of leaking it, so callers
  hold it for exactly as long as they need it and it cleans up
  automatically via `Drop` when their function returns -- same lifetime
  guarantee, no leak. Worth remembering generally: `.keep()`/`.into_path()`
  on a tempdir is a real permanent leak, not a convenience, and needs a
  matching cleanup story if used at all.
- **A second real bug found the same way: onion-service descriptor
  propagation delay was only applied to the *first* dial, not the second.**
  `rotate-demo`'s v1 connection had an explicit 5-second sleep after
  `Listener::launch()` before anyone tried to dial it (needed for the
  onion service's descriptor to become discoverable on the Tor network).
  The v2 (post-rotation) listener had no equivalent delay before bob's
  reconnection dial, which reliably reproduced arti's "Unable to download
  hidden service descriptor" error live. Fixed by adding the same 5-second
  delay before the v2 dial. General lesson: a working demo's timing
  assumptions don't automatically generalize to a structurally similar but
  not-identical code path in the same function -- each dial-after-launch
  needs its own verified delay, not just the first one.

## Phase 4 implementation findings

- **Tauri builds and runs against real WebKitGTK here without root.** This
  dev sandbox has no `webkit2gtk4.1-devel`, but the installed
  `org.gnome.Platform//50` Flatpak runtime ships `libwebkit2gtk-4.1` and
  `libjavascriptcoregtk-4.1`. The webkit2gtk Rust bindings need only the
  shared libraries at link time (no C headers), so a two-line pkg-config
  file pointing at copies of them was enough to link. The binary then
  runs inside that runtime. On a normal Fedora machine, `sudo dnf install
  webkit2gtk4.1-devel` replaces all of this.
- **Correction: there was no WebKit layout bug.** The Phase 4 commit
  reported that the lock screen "collapsed to a sliver" in WebKitGTK
  because of `width: min(420px, 100%)` in a centered grid, and switched it
  to flex + `max-width`. Later diagnosis inside the running WebView showed
  `innerWidth = -115200` and `devicePixelRatio = -1/96`: GTK's Broadway
  backend was giving WebKit a garbage scale factor, so *every* layout was
  broken, not that one rule. Under a real (virtual) compositor the page
  renders correctly. The CSS change is harmless and stays. The lesson:
  confirm a rendering environment is sane (check `innerWidth`/DPR) before
  blaming the page.
- **Headless GUI runs that work:** KWin's virtual backend
  (`dbus-run-session -- kwin_wayland --virtual --socket <name>`, on a
  private D-Bus session so it can't touch the real desktop) gives the real
  Tauri binary a genuine Wayland display with nothing on screen.
  `TAURI_WEBVIEW_AUTOMATION=true` plus `WebKitWebDriver` (both in the GNOME
  runtime) then allows full WebDriver control, including native clicks and
  typing (`desktop/e2e/gui_e2e.py`). Broadway doesn't work for this (see
  above). One sandbox-specific trap: GTK image loading goes through
  glycin, which spawns loaders via the Flatpak portal, and the portal
  rejects a bare `flatpak run <runtime>` ("Key file does not have group
  Application"); it needs an app context.
- **Single-owner state.** The node is one task owning the identity store,
  every `MlsGroup`, and the app database. UI calls are closures sent to
  that task. This rules out the worst MLS failure mode (two concurrent
  commits forking a group) by construction rather than by locking
  discipline, and the SQLite connections never cross threads.
- **Key packages are single-use (RFC 9420 §10), and the app has to plan
  for it.** An invite's key package is consumed by the DM it creates, so
  adding the same contact to a server and its channels later needs more.
  Peers now hand each other a small pool when a relationship starts and
  top it up whenever a Welcome consumes one. If the pool runs dry, the
  admin's client asks for more and tells the user to retry once the
  contact has been online. This isn't a hard failure.

## Phase 5 implementation findings

- **New direct dependency: `sha2` 0.10 (RustCrypto)**, used for relay
  mailbox IDs. Vetting per the standing rule below: it was already in the
  build as a transitive dependency of `openmls_rust_crypto` (same version
  line), it comes from the same RustCrypto organisation as the
  already-adopted `chacha20poly1305` and `argon2`, it's MIT/Apache-2.0,
  and it's actively maintained. Making it direct adds no new code to the
  binary.
- **Relay-connection Noise keys must be throwaway.** The obvious
  implementation, reusing the identity's Noise key (the way peer
  connections do), would give the relay a stable identifier linking
  every deposit and collection a user makes. The relay client generates a
  fresh key per connection, and `relay_flows.rs` checks that no key
  repeats.
- **Sign the bytes you send, not a re-serialization.** Envelope signatures
  cover the frames' exact JSON string (carried as a string), not a value
  re-serialized by the receiver. Otherwise any serializer difference
  between versions would make valid envelopes fail verification.
- **Verify the verifier.** The relay-storage inspection test was checked by
  temporarily making the client deposit plaintext. It failed as it should
  ("relay storage contains the sender's label"), so a pass means something.

## Phase 4/5 live-run findings

Driving the real desktop app over live Tor (`desktop/e2e/gui_e2e.py`) found
four bugs that every in-memory test had passed over. Each is now fixed and
has a deterministic regression test that fails without the fix (checked by
temporarily reverting it).

1. **Data loss in the Noise pump under simultaneous traffic (Phase 1
   code).** `SecureMux`'s pump `select!`ed between "read from the app" and
   "read a length-prefixed frame from the network". That read takes
   several `read` calls, and when the other branch won mid-frame, the
   bytes already read were dropped. The stream then desynced, decryption
   failed, and the connection died silently. In-memory pipes deliver whole
   frames at once, so it never showed locally. Over Tor it lost messages
   whenever both sides sent at the same moment (e.g. a reply crossing a
   key-package top-up). Fixed by running each direction as its own loop
   over its own half of the stream. Test:
   `simultaneous_traffic_over_a_fragmenting_transport`, over a transport
   that hands out 5 bytes per read. It stalled with the old pump and
   passes in milliseconds with the new one. This is the general cancel-safety trap:
   never put a multi-step read inside a `select!` loop that can drop it.
2. **"Written to the socket" is not "delivered".** A peer that vanishes
   without closing its connection leaves the Tor stream accepting writes
   for a long time. Messages were marked sent, dropped from the outbox, and
   lost; the relay fallback never ran because nothing looked undelivered.
   Queued frames now carry their outbox ID and stay queued until the
   receiving *node* acknowledges them (`WireMessage::Tracked`/`Ack`). A
   connection with unacknowledged frames older than the dial timeout is
   treated as dead, which triggers redial and then the relay. Acks are
   checked against the acknowledging peer, so one contact can't clear
   another's queue. Test: `a_peer_that_vanishes_mid_connection_still_gets_mail_via_relay`
   (the in-memory network can now make a node vanish without closing
   anything).
3. **Frames can arrive out of order across connections.** Two peers often
   end up with two connections at once over Tor (both dial), and frames
   resent on the newer one can overtake the older one. A channel's Welcome
   that beat its server's Welcome was rejected, and because joining
   consumes a single-use key package, it could never succeed later. The
   server check now happens *before* joining, and early channel Welcomes
   are held until their server arrives. Used key packages are also recorded,
   so a late duplicate can't be reused. Test:
   `a_channel_welcome_that_overtakes_its_server_welcome_still_joins`.
4. **UI: a toast covered the Send button** for its 4.5 seconds right after
   adding a contact (found because the WebDriver click was "intercepted").
   Toasts now sit below the header and never take clicks. Screenshots from
   the same runs also caught the home screen's invite button staying on
   "Waiting for Tor…" after Tor connected, and a removed member's stale
   member list. Both fixed.

Test-environment notes, so nobody repeats them: the dev machine's
loopback interface had gone down after a KDE network toggle
(NetworkManager doesn't bring `lo` back); the virtual KWin started its
own lock screen unless given `--no-lockscreen`; and WebKitWebDriver
doesn't pass the app's stderr through, so the E2E script dumps each node's
state through the app's own API when a step fails.

## Phase 7 implementation findings

- **Distro WebKitGTK has no WebRTC.** The plan was calls inside the
  webview (it's what a browser would do). A probe inside the running app
  found `RTCPeerConnection` undefined even with WebKit's `enable-webrtc`
  setting on. Checking the libraries themselves showed that
  `libwebkit2gtk-4.1` in **Ubuntu 24.04 (2.52.6), Fedora 44 (2.54.0) and
  the GNOME 50 runtime** is built without the WebRTC bindings (no
  `JSRTCPeerConnection` symbols at all). `getUserMedia` does work there
  (camera and microphone), and so does WebKit's mock-device setting used
  in tests. So media moved to Rust, and only camera capture stays in the
  webview. Windows' WebView2 does have WebRTC, but one code path for every
  platform was preferred.
- **wry sets neither WebRTC nor media capture**, and doesn't answer
  WebKitGTK's permission requests, which then default to *deny*. The
  desktop shell sets `enable-media-stream` itself (plus `enable-webrtc` for
  the future) and allows camera/microphone requests only. The page is
  reloaded once after, because a page's available APIs are fixed when it
  loads.
- **webrtc-rs candidate-pair stats have no byte counts.** Use the ICE
  transport's stats for bytes, and the nominated pair for the candidate
  types in use.
- **Estimating a tone's pitch from zero crossings** has to skip silent
  stretches, or playback gaps read as a lower pitch (a first GUI run
  "heard" 607 Hz for a 660 Hz tone). The analyser now reports pitch over
  audible blocks and, separately, the audible fraction, which shows
  dropouts directly.
- **Call signals must survive a connection that's still being dialed.** In
  a channel, two members may never have connected directly. Dropping
  signals for non-connected members broke three-way calls (caught by the
  test). They're now held for up to 30 s while the connection is dialed,
  and still never persisted.
- **`opus` 0.3's `audiopus_sys` is unmaintained** (RUSTSEC-2026-0150), and
  its bundled build fails with CMake 4, which would have broken Windows
  builds. `cargo-deny` flagged it. Moved to `opus` 0.4 (`opusic-sys`), which
  builds libopus into the binary, so packages don't need a libopus
  dependency; only ALSA remains on Linux.
- **Headless GUI testing:** a leftover virtual compositor from an earlier
  run keeps the Wayland socket, and new WebDriver sessions then hang
  silently. The document portal can also be absent (`flatpak run
  --no-documents-portal`). Clean up by exact process name. `pkill -f` on a
  pattern also matches the shell running it.

## Phase 9 implementation findings

- **`tempfile::tempdir()` doesn't make private directories.** It follows
  the umask (usually giving 0755). The profile's decrypted working copy
  lived in one from Phase 1 on, readable by other local users (finding
  P9-01, audit/README.md). Use `tempfile::Builder::permissions(0o700)`,
  and create sensitive files 0600 before anything else opens them.
- **yamux's defaults are for trusted peers:** 512 streams and a 1 GiB
  receive window per connection. Anything facing anonymous peers should
  set `max_num_streams` and `max_connection_receive_window` (P9-03).
- **Fuzzing through the AEAD and MLS layers** needs entry points that skip
  them. They're compiled only under `--cfg fuzzing`
  (`securetext-app/src/fuzzing.rs`) and declared in `[lints.rust]
  unexpected_cfgs`, so normal builds don't warn. Target-specific
  dependencies (`[target.'cfg(fuzzing)'.dependencies]`) keep fuzz-only
  crates out of normal builds.

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
