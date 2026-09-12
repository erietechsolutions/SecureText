# Technology Stack Decisions

Core language decision: **Rust**, confirmed for this project. Rationale:
best-in-class crypto and libp2p ecosystem (OpenMLS, RustCrypto crates,
rust-libp2p), memory safety without a garbage collector (relevant for a
security-sensitive app handling key material), and a Rust core compiles
cleanly to a shared library that mobile clients (Phase 9) can call into via
UniFFI — avoiding a second implementation of the crypto/networking layer
for mobile.

## Core / backend

| Concern | Choice | Why |
|---|---|---|
| Language | Rust | See above |
| P2P networking | `rust-libp2p` | Most mature Rust libp2p implementation; built-in Noise transport, Kademlia DHT, NAT traversal helpers |
| Transport security | libp2p's `noise` module | Noise Protocol Framework, audited, integrates directly with libp2p |
| Group E2EE (MLS) | `OpenMLS` | Actively maintained RFC 9420 implementation in Rust |
| 1:1 E2EE (X3DH + Double Ratchet) | Evaluate `libsignal` (Signal's own crate) vs. a from-spec Rust Double Ratchet crate | Decision needed once license/API fit is checked against Signal's terms — flagged as an open item below |
| Symmetric crypto primitives | `RustCrypto` crates (`chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`) | Widely used, individually audited primitive crates rather than a monolithic library |
| Password/passphrase KDF | `argon2` crate (Argon2id) | Memory-hard, current best practice over PBKDF2/bcrypt |
| Local storage | SQLite via `rusqlite` + SQLCipher | Encrypted at rest; SQL is sufficient for message/channel/member metadata at this scale |
| Voice/video | WebRTC via `webrtc-rs` | Native Rust WebRTC implementation, avoids FFI into libwebrtc where possible |

## Client / UI

| Concern | Choice | Why |
|---|---|---|
| Desktop shell | **Tauri** | Rust backend (shares the core directly, no FFI boundary for desktop), web frontend for fast UI iteration, much smaller binary/resource footprint than Electron |
| Frontend framework | React or Svelte (pick during Phase 4 UI work, not a Phase 0 blocker) | Either works fine inside Tauri; decision deferred since it doesn't affect the core architecture |
| Mobile (Phase 9) | React Native or Flutter shell, calling the Rust core via UniFFI | Reuses the audited Rust core instead of reimplementing crypto/networking per platform |

## Infrastructure (minimal, by design)

| Concern | Choice | Why |
|---|---|---|
| TURN relay fallback | `coturn` (self-hostable) or a small custom Rust TURN-compatible relay | Standard, well-understood software; sees ciphertext + connection metadata only |
| Store-and-forward relay (Phase 5) | Custom minimal Rust service | No existing off-the-shelf "blind encrypted mailbox" server fits exactly; keep it deliberately simple (store blob, TTL, opaque routing ID lookup) to minimize audit surface |
| Optional anonymity transport (Phase 9) | Tor (`arti`, the Rust Tor implementation) or embed via existing `tor` binary | `arti` keeps the whole stack in Rust; fall back to shelling out to the reference `tor` implementation if `arti`'s feature coverage isn't sufficient yet |

## Open items to resolve before Phase 1 coding starts

1. **`libsignal` license/API fit** — confirm whether Signal's own crate can
   be used directly (check license terms and whether its API assumes
   Signal's own server infrastructure) or whether a from-spec
   Double-Ratchet crate (or writing a thin implementation directly against
   the published X3DH/Double Ratchet specs, reviewed carefully) is the
   better fit. This is the single highest-risk library decision — resolve
   it with a focused spike before committing.
2. **SQLCipher Rust binding maturity** — verify `rusqlite`'s SQLCipher
   feature flag is well-maintained on all target platforms (Linux/macOS/
   Windows) before relying on it for at-rest encryption.
3. **`webrtc-rs` vs. FFI to `libwebrtc`** — `webrtc-rs` is younger than
   Google's `libwebrtc`; verify it covers everything needed (in particular
   ICE/TURN interop) before Phase 6, or plan an FFI fallback.
4. **Frontend framework for Tauri** (React vs. Svelte vs. other) — deferred
   to Phase 4, not blocking.
