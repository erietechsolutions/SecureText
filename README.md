# SecureText

An anonymous, end-to-end encrypted messaging application — Discord-like in
UX (servers, channels, roles, voice), decentralized and anonymous in
architecture: no central account database, no server that can read or be
compelled to hand over message content, and no way to trace a message back
to a device or IP address. All text/group/file traffic is mandatorily
routed over Tor v3 onion services; messages are readable only by the
sender and the intended recipient(s) via end-to-end encryption (MLS,
RFC 9420). Voice/video calls are the one explicit, disclosed exception to
the anonymity guarantee — see [docs/threat-model.md](docs/threat-model.md).

## Status

Phases 0–3 (design, 1:1 messaging over Tor, invite links, groups and
channels) are implemented in the Rust crates under `crates/`. Phase 4, the
desktop client, is in `desktop/` on top of the `securetext-app` core. Phase
5, offline delivery through store-and-forward relays, is in
`securetext-relay` and the app core. See
[docs/roadmap.md](docs/roadmap.md) for exactly what's verified and what's
still pending for each phase. **This is pre-audit software (Phase 8 hasn't
happened). Don't rely on it for anything that matters yet.**

## Layout

- `crates/securetext-identity`: encrypted-at-rest identity store
- `crates/securetext-crypto`: MLS (OpenMLS) groups, capabilities
- `crates/securetext-net`: Tor onion services (arti), Noise_XX, yamux
- `crates/securetext-invite`: invite links
- `crates/securetext-app`: the application core (node, storage, peer protocol, offline relay client)
- `crates/securetext-relay`: store-and-forward relay server for offline delivery (Phase 5)
- `crates/securetext-cli`: proof-of-integration CLI and live-Tor demos
- `desktop/`: Tauri desktop client (own Cargo workspace) and its web UI

## Building

```sh
cargo test --workspace            # core crates; no system GUI deps needed

# Desktop client: needs Tauri's Linux prerequisites
# (Fedora: sudo dnf install webkit2gtk4.1-devel libsoup3-devel gtk3-devel)
cd desktop && cargo run
```

To run an offline-delivery relay (reachable only as a Tor onion service):

```sh
cargo run --release -p securetext-relay -- --dir /var/lib/securetext-relay
```

It prints a `securetext-relay1:…` address. Paste it into the desktop app's
offline-delivery setting (⚙ next to your name).

The desktop app keeps its profile under the platform app-data directory.
Set `SECURETEXT_PROFILE_DIR` to use a different one (e.g. to run two
profiles side by side).

## Documents

- [docs/threat-model.md](docs/threat-model.md) — what SecureText protects against, and what it explicitly does not
- [docs/crypto-spec.md](docs/crypto-spec.md) — key management, 1:1 encryption, group encryption
- [docs/architecture.md](docs/architecture.md) — networking, discovery, NAT traversal, offline delivery, server/channel model
- [docs/tech-stack.md](docs/tech-stack.md) — concrete libraries and tools chosen, with rationale
- [docs/platform-support.md](docs/platform-support.md) — supported OS matrix (Ubuntu, Fedora, Windows 10/11) and cross-platform implementation notes
- [docs/roadmap.md](docs/roadmap.md) — phase-by-phase development plan

## Supported platforms

Ubuntu (22.04+), Fedora (current release), Windows 10 (21H2+), and Windows
11. See [docs/platform-support.md](docs/platform-support.md) for details.
macOS is not currently an officially supported OS.

Tested and Supported:
Ubuntu 22.04+
Fedora 44 or Newer

Untested but Supported:

Windows 10
Windows 11

Not Officially Supported or Tested:

macOS


