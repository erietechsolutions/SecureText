# SecureText

An anonymous, end-to-end encrypted messaging application — Discord-like in
UX (servers, channels, roles, voice), decentralized and anonymous in
architecture: no central account database, no server that can read or be
compelled to hand over message content, and no way to trace a message back
to a device or IP address. All text/group/file traffic is mandatorily
routed over Tor v3 onion services; messages are readable only by the
sender and the intended recipient(s) via end-to-end encryption (MLS,
RFC 9420). Voice/video calls (planned) are the one explicit, disclosed
exception to the anonymity guarantee — see
[docs/threat-model.md](docs/threat-model.md).

> **Pre-audit software.** The independent security audit (roadmap Phase 9)
> hasn't happened yet. Don't rely on SecureText for anything that matters
> until it has.

## Status

| Phase | Scope | Status |
|---|---|---|
| 0 | Spec & threat model | ✅ Complete |
| 1 | 1:1 encrypted messaging over Tor | ✅ Live-verified on Linux · Windows pairing pending |
| 2 | Invite links & bridges | ✅ Live-verified on Linux · obfs4 bridge live test pending |
| 3 | Groups ("servers") & channels | ✅ Verified deterministically |
| 4 | Desktop client (Tauri) | ✅ Verified through the GUI over live Tor · real-user test pending |
| 5 | Offline delivery (relays) | ✅ Verified deterministically and over live Tor |
| 6 | Desktop installers & auto-updates | Next up |
| 7 | Voice & video | Not started |
| 8 | Rich features (files, reactions, threads…) | Not started |
| 9 | Hardening & third-party audit | Not started |
| 10 | Mobile core compatibility | Not started |
| 11 | Android app, export & updates | Not started |

[docs/roadmap.md](docs/roadmap.md) has the details, including exactly what
each phase's verification did and didn't cover.

## What works today

- **Private profile, no account.** Your identity lives only on your device,
  encrypted with your passphrase (Argon2id + ChaCha20-Poly1305).
- **Everything over Tor.** Each device is reachable only as its own Tor v3
  onion service; there's no clearnet fallback. The app shows that traffic
  is Tor-routed and explains why a first message can take up to a minute.
- **Contacts by invite link.** Share a `securetext1:…` link over a channel
  you trust; accepting it opens an end-to-end encrypted conversation.
- **Servers and channels.** Create a server, invite contacts, make private
  channels that non-members can't decrypt, and remove members (removal
  re-keys everything they were in).
- **Offline delivery.** Messages to someone offline wait on your device
  and send when they're reachable, or can be left at their chosen relay so
  they arrive even if you're never online at the same time. Relays hold
  only sealed, anonymous blobs.
- **Confirmed delivery.** A message counts as sent only once the
  recipient's app acknowledges it.

Not yet: installers and updates, calls, file sharing, reactions/threads,
mobile apps. See the status table above.

## Getting SecureText

There are **no installers yet**; they come with Phase 6, along with
automatic updates from GitHub Releases. For now, build from source.

### Building from source

You need a Rust toolchain ([rustup](https://rustup.rs)).

```sh
cargo test --workspace   # the core crates; no GUI system packages needed
```

The desktop app is a [Tauri 2](https://tauri.app) app and needs its system
prerequisites (see Tauri's prerequisites guide for the full list):

- **Fedora:** `sudo dnf install webkit2gtk4.1-devel libsoup3-devel gtk3-devel openssl-devel librsvg2-devel`
- **Ubuntu:** `sudo apt install libwebkit2gtk-4.1-dev libsoup-3.0-dev libgtk-3-dev build-essential libssl-dev librsvg2-dev`
- **Windows:** Microsoft C++ Build Tools and WebView2 (preinstalled on Windows 11)

```sh
cd desktop
cargo run --release
```

The desktop app is its own Cargo workspace, so the core builds and tests
without these packages. Its profile lives in the platform app-data
directory; set `SECURETEXT_PROFILE_DIR` to use another location (for
example, to run two profiles side by side).

### Running an offline-delivery relay

A relay is a blind mailbox reachable only as a Tor onion service:

```sh
cargo run --release -p securetext-relay -- --dir /var/lib/securetext-relay
```

It prints a `securetext-relay1:…` address. Each user who wants offline
delivery pastes a relay address into the app (⚙ next to their name).

## Testing

```sh
cargo test --workspace                           # unit + integration tests (in-memory network)
cargo test -p securetext-net -- --ignored        # live Tor tests (needs network access)
python3 desktop/e2e/gui_e2e.py --binary desktop/target/debug/securetext-desktop [--relay securetext-relay1:…]
```

The last one drives two real app windows through WebDriver over live Tor.
It needs `WebKitWebDriver` and a display; see the script's docstring for
running it headlessly.

## Layout

- `crates/securetext-identity`: encrypted-at-rest identity store
- `crates/securetext-crypto`: MLS (OpenMLS) groups, capabilities
- `crates/securetext-net`: Tor onion services (arti), Noise_XX, yamux
- `crates/securetext-invite`: invite links
- `crates/securetext-app`: the application core (node, storage, peer protocol, relay client)
- `crates/securetext-relay`: store-and-forward relay server
- `crates/securetext-cli`: proof-of-integration CLI and live-Tor demos
- `desktop/`: Tauri desktop client (own Cargo workspace), its web UI, and the GUI end-to-end test

## Supported platforms

| Platform | Status |
|---|---|
| Fedora 44 | Supported · **tested** (all verification so far ran here) |
| Ubuntu 22.04+ | Supported · not yet tested |
| Windows 10 (21H2+) / 11 | Supported · not yet tested |
| Android | Planned (Phases 10–11) |
| macOS, iOS | Not supported |

See [docs/platform-support.md](docs/platform-support.md) for details.

## Documents

- [docs/threat-model.md](docs/threat-model.md) — what SecureText protects against, and what it explicitly does not
- [docs/crypto-spec.md](docs/crypto-spec.md) — key management, 1:1 encryption, group encryption
- [docs/architecture.md](docs/architecture.md) — networking, invites, offline delivery, server/channel model
- [docs/tech-stack.md](docs/tech-stack.md) — libraries and tools chosen, with rationale and implementation findings
- [docs/platform-support.md](docs/platform-support.md) — supported platforms, packaging and CI notes
- [docs/roadmap.md](docs/roadmap.md) — phase-by-phase plan and verification status

## License

The crates declare `MIT OR Apache-2.0` in `Cargo.toml`. The license
texts (`LICENSE-MIT`, `LICENSE-APACHE`) still need to be added to the repo
before it goes public.
