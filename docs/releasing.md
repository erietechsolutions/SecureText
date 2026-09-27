# Releasing SecureText

How installers are built, how updates reach users, and what a maintainer
does to ship a version. The design reasoning is in architecture.md §10.

## The trust chain in one paragraph

CI builds and tests every installer, but it **cannot publish an update**.
Installed copies only install an update whose manifest
(`securetext-update.json`) is signed by the **update-signing key**, whose
public half is pinned in `desktop/update-signing.pub` and compiled into the
app. That key lives offline, encrypted with a passphrase, and is used only
on a maintainer's machine by `scripts/sign-release.sh`. Taking over the
GitHub account, its Actions secrets, a release, GitHub's CDN or a Tor exit
isn't enough to push an update to anyone.

## One-time setup: the update-signing key

```sh
cargo run -p securetext-update --bin securetext-release -- \
    keygen /media/offline-usb/update-signing.key desktop/update-signing.pub
```

- It asks for a passphrase (at least 12 characters; it's visible as you
  type, so do this somewhere private). The key file is useless without it.
- Keep `update-signing.key` off the repo and off GitHub: ideally on
  encrypted removable storage, with a second copy somewhere safe. **If it's
  lost, installed copies can't be updated automatically any more.** Users
  would have to install a new release by hand.
- Commit `desktop/update-signing.pub`. Until it holds a key, builds have
  automatic updates switched off.
- **Rotating the key:** add the new public key as a second line in
  `update-signing.pub`, since the app accepts any key listed there. Ship
  one release signed with the *old* key that pins both. Later releases can
  then be signed with the new key, and the old one retired.

## One-time setup: the repository

- Update checks fetch
  `https://github.com/erietechsolutions/SecureText/releases/latest/download/securetext-update.json`
  without logging in, so **the repository (or a separate releases
  repository) must be public** before updates can work. If releases move
  to another repository, change `DESKTOP_MANIFEST_URL` in
  `crates/securetext-update/src/lib.rs`.
- Pushing `.github/workflows/` needs a GitHub token with the `workflow`
  scope (`gh auth refresh -s workflow`).

## Shipping a version

1. Bump the version in `desktop/tauri.conf.json` and `desktop/Cargo.toml`
   (the pipeline refuses a mismatch), commit, and push.
2. Tag and push the tag: `git tag v0.2.0 && git push origin v0.2.0`.
3. The **Release** workflow runs:
   - the test suite on Linux and Windows,
   - installers built natively: `.deb` + `.AppImage` on Ubuntu 22.04,
     `.rpm` in a Fedora 44 container, NSIS `.exe` + `.msi` on Windows,
     plus the relay's `.deb`/`.rpm` (one static musl binary, from
     `scripts/build-relay-static.sh`),
   - each installer installed on a fresh runner (Ubuntu 22.04 and 24.04,
     Fedora 44, Windows), started, and checked that it stays up; the
     Windows NSIS and Linux packages are uninstalled again,
   - the relay packages installed, started and removed on every supported
     relay host (Ubuntu 20.04, 22.04 and 24.04, Debian 13, Fedora 44),
   - a **draft** release holding everything plus `SHA256SUMS`.
4. Write the release notes users will see in the app (plain text), then:

   ```sh
   scripts/sign-release.sh v0.2.0 /media/offline-usb/update-signing.key notes.txt
   ```

   This downloads the draft's files, checks them against `SHA256SUMS`,
   builds and signs the manifest locally, verifies it against the pinned
   public key, uploads it, and publishes the release as *latest*.

Installed copies check at a random time, roughly once a day, so an update
reaches most users within a day or two.

To test the pipeline without releasing, run the Release workflow by hand
(Actions → Release → Run workflow). By default it builds and install-tests
everything without creating a release. The `gui_e2e` option also runs the
two-window GUI test over live Tor.

## What each kind of install does with an update

| Installed from | The app… |
|---|---|
| AppImage | downloads the new AppImage over Tor, verifies it, and swaps it in place when the user clicks *Restart to update* |
| Windows NSIS `.exe` (per-user, no admin) | runs the new installer in passive mode, which closes the app, installs and relaunches it |
| Windows `.msi` | runs `msiexec /passive` (needs admin, like the original install) |
| `.deb` / `.rpm` | downloads and verifies the package, then opens it in the system's software installer, which asks for the admin password |
| built from source | is told a release exists, never updates itself |

## Code signing (not done yet)

- **Windows Authenticode:** without it, SmartScreen warns on the installer.
  It needs a code-signing certificate, which the project doesn't have. The
  release workflow marks where the signing step goes.
- **Linux packages:** `SHA256SUMS` comes from CI. The signed update
  manifest covers the hashes for in-app updates. A GPG signature over
  `SHA256SUMS` for people installing by hand is still to do.

## Uninstalling

Uninstalling never deletes the encrypted profile silently:

- **Windows (NSIS):** the uninstaller has a "Delete the application data"
  checkbox, off by default.
- **`.deb` / `.rpm`:** package removal never touches home directories. The
  profile stays in `~/.local/share/com.erietechsolutions.securetext/`.
- **AppImage:** there's nothing to uninstall but the file. The profile
  stays in the same place as above.

## Relay packages

`securetext-relay_<v>_amd64.deb` / `securetext-relay-<v>-1.x86_64.rpm`
are one static binary, so the same packages work on every supported relay
host (Ubuntu Server 20.04+, Ubuntu Desktop 22.04+, Debian 13+, Fedora 44+).
They install the relay with a sandboxed systemd unit (`DynamicUser`,
`ProtectSystem=strict`, no capabilities) and start it. Its address is in
`/var/lib/securetext-relay/address` once Tor is up. Removing the package
keeps the relay's keys, so a reinstall keeps its address; `apt purge`
deletes them. A container image builds from
`packaging/relay/Containerfile`.
