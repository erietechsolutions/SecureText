# Platform Support

## Officially supported platforms (v1 target)

| OS | Versions |
|---|---|
| Ubuntu | 22.04 LTS and newer |
| Fedora | 44 or newer |
| Windows | Windows 10 (21H2+) and Windows 11 |
| Android | *Planned* (roadmap Phases 10–11); Planned to be backwards compatible with version 12 or newer |

## Officially supported relay platforms (v1 target)
|---|---|
| Ubuntu | 22.04 LTS and newer |
| Ubuntu Server | 20.04 LTS and newer |
| Debian Server | 13 or newer |
| Fedora | 44 or newer |

**Current verification (2026-09-26):** everything through Phase 5 has been
built and verified on Fedora 44 only. Ubuntu and Windows are supported
targets but not yet tested (roadmap.md tracks this per phase).

**macOS is not an official v1 target** (nor is iOS). Tauri's cross-platform nature means
it will likely build and largely work on macOS, but it is untested and
unsupported until explicitly prioritized — don't spend design effort
accommodating macOS-specific behavior in v1.

Every phase's exit criteria (roadmap.md) should be verified on at least one
representative of each row above, not just "it compiles."

## Why this doc exists

The core crypto/networking design (crypto-spec.md, architecture.md) is
already OS-agnostic by construction — libp2p, OpenMLS, and webrtc-rs are
pure/cross-platform Rust with no OS-specific code paths. The places where
platform differences actually bite are: OS secret storage, firewall
defaults, filesystem conventions, and packaging. This doc is the single
place those are tracked so they don't get rediscovered separately on each
OS.

## Secret/key storage across platforms

- Windows: Credential Manager / DPAPI.
- Linux (Ubuntu, GNOME default): GNOME Keyring via the Secret Service D-Bus
  API.
- Linux (Fedora, GNOME default; KDE spin): GNOME Keyring or KWallet, both
  via Secret Service.
- **Gap to design for:** Secret Service is not guaranteed present on a
  minimal or headless Linux install (e.g., a bare Fedora Server, a
  container, or a stripped-down Ubuntu server image) — there is no D-Bus
  session/secrets daemon running. The app must detect this and fall back
  cleanly to the passphrase-derived SQLCipher key path (crypto-spec.md §5)
  rather than failing to start.
- Use the `keyring` crate (or equivalent) to abstract over Windows
  Credential Manager and Secret Service rather than hand-rolling
  per-OS code.

## Firewall & inbound connections

- **Windows Defender Firewall** will prompt the user on first run when the
  app listens for inbound P2P connections — expected and fine, but the UI
  should explain why the prompt appears rather than leaving the user
  confused.
- **Fedora** ships `firewalld` with a default-deny inbound policy that
  typically blocks arbitrary application ports out of the box.
- **Ubuntu** ships `ufw` but it is inactive by default on desktop installs,
  so this is less often an issue there — but cannot be assumed off.
- **Design implication:** prefer outbound-initiated connections and hole
  punching (DCUtR, architecture.md §5) as the primary path so basic
  messaging works without requiring the user to open firewall ports.
  Document manual `firewalld`/Windows Firewall rule setup as an
  advanced/optional step only for users who choose to run a relay or
  store-and-forward node (architecture.md §6), not for ordinary clients.

## Filesystem & data directory conventions

- Use the `directories` crate (or equivalent) to resolve per-OS conventions
  rather than hardcoding paths: XDG Base Directory spec on Linux
  (`~/.config`, `~/.local/share`), `%APPDATA%`/`%LOCALAPPDATA%` on Windows.
- No wire format (message/group protocol data) should ever depend on
  text-mode line-ending conventions (CRLF vs LF) — all protocol data is
  binary/structured (MLS, Double Ratchet framing), so this is a non-issue
  for the protocol itself, but flag it if any human-editable config file
  format is introduced later.

## Windowing / display server (Linux specifically)

- Both Ubuntu (22.04+) and Fedora default to **Wayland**. Tauri's Linux
  webview backend (WebKitGTK) handles Wayland and X11, but this must be
  explicitly verified rather than assumed — particularly for clipboard
  behavior and, later, screen sharing (Phase 7), since Wayland's screen
  capture portals behave differently from X11's and Fedora/Ubuntu may ship
  different portal backends (e.g., GNOME's `xdg-desktop-portal-gnome` vs.
  KDE's `xdg-desktop-portal-kde`).

## Packaging & distribution

Tauri's bundler produces native installers per OS from the same codebase —
build each target on its native OS rather than cross-compiling installers:

| OS | Package format(s) |
|---|---|
| Ubuntu | `.deb` and/or `.AppImage` |
| Fedora | `.rpm` |
| Windows | `.msi` (WiX) or NSIS `.exe` |
| Android | signed `.apk` (direct install / F-Droid) and `.aab` (store upload), Phase 11 |

Installers and updates ship through **GitHub Releases** (roadmap Phase 6).
Auto-update checks and downloads must go over Tor, never the clearnet: a
direct request to github.com would reveal that an IP runs SecureText.
Updates are signature-verified before installing.

## CI matrix

GitHub Actions hosted runners natively cover `ubuntu-latest` and
`windows-latest`. Fedora is not a hosted runner OS, so Fedora coverage
needs a container step:

- `ubuntu-latest` — native runner
- `windows-latest` — native runner
- `fedora:latest` (or a pinned Fedora version) — run as a container on top
  of the `ubuntu-latest` runner

Note the Fedora container path won't exercise a real D-Bus session
(Secret Service) the way a full desktop install would — the keyring
fallback behavior above needs at least one manual/VM-based verification
pass per release, not just CI.

## Open items to resolve before/during Phase 1

1. **SQLCipher on Windows** — historically the trickiest cross-platform
   piece: `rusqlite`'s SQLCipher feature pulls in an OpenSSL/vcpkg
   dependency chain on Windows vs. system OpenSSL on Linux. Spike this
   early; if it proves painful, consider a bundled build or an
   alternative at-rest encryption layer decoupled from SQLCipher
   specifically (e.g., encrypt at the application layer around a plain
   SQLite file instead of relying on SQLCipher's native support).
2. **`keyring` crate coverage** — verify behavior across GNOME Keyring
   (Ubuntu default), KWallet (Fedora KDE spin), a headless/no-Secret-Service
   environment, and Windows Credential Manager, before depending on it in
   Phase 1's identity storage.
3. **Wayland screen-share portals** (Phase 7, deferred but worth flagging
   now) — GNOME vs. KDE portal differences on Fedora/Ubuntu.
