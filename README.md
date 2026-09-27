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

# Dev Builds

Please be aware that dev builds/releases are only supported on Fedora 44 or higher

## Status

| Phase | Scope | Status |
|---|---|---|
| 0 | Spec & threat model | ✅ Complete |
| 1 | 1:1 encrypted messaging over Tor | ✅ Live-verified on Linux · Windows pairing pending |
| 2 | Invite links & bridges | ✅ Live-verified on Linux · obfs4 bridge live test pending |
| 3 | Groups ("servers") & channels | ✅ Verified deterministically |
| 4 | Desktop client (Tauri) | ✅ Verified through the GUI over live Tor · real-user test pending |
| 5 | Offline delivery (relays) | ✅ Verified deterministically and over live Tor |
| 6 | Desktop installers & auto-updates | ✅ Built and verified locally · first signed release pending |
| 7 | Voice & video | ✅ Built · verified via the GUI · real devices/networks pending |
| 8 | Rich features (files, reactions, threads…) | ✅ Verified through the GUI over live Tor |
| 9 | Hardening & security review | ✅ Complete |
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

- **Files, reactions, threads, status, disappearing messages.** Share
  files and images up to 25 MB (encrypted, fetched over Tor from whoever in
  the conversation has them), react, reply in threads, set a status, and
  make messages delete themselves after a set time.
- **Voice and video calls** in DMs and channels. This is the one feature
  that doesn't go over Tor, and the app says so before every call. Media
  always goes through a TURN relay server, so the other people on the call
  never learn your IP address (the relay's operator does). Calls are
  end-to-end encrypted under a key shared inside MLS. Set a TURN server in
  Settings → Calls, or join using the caller's; `securetext-turn` is one
  you can run yourself.
- **Automatic updates, privately.** The app checks GitHub Releases over
  Tor at random times and installs only updates signed by the SecureText
  release key, when you choose to restart (Settings → Updates).

## Getting SecureText

Installers (Windows `.exe`/`.msi`, Ubuntu `.deb`/`.AppImage`, Fedora
`.rpm`) are built by the release pipeline and published on
[GitHub Releases](https://github.com/erietechsolutions/SecureText/releases).
No release has been published yet. Until the first one is, build from
source. How releases are made and signed: [docs/releasing.md](docs/releasing.md).

### Building from source

You need a Rust toolchain ([rustup](https://rustup.rs)).

```sh
cargo test --workspace   # the core crates (needs ALSA headers and CMake for calls; no GUI packages)
```

The desktop app is a [Tauri 2](https://tauri.app) app and needs its system
prerequisites (see Tauri's prerequisites guide for the full list):

- **Fedora:** `sudo dnf install webkit2gtk4.1-devel libsoup3-devel gtk3-devel openssl-devel librsvg2-devel alsa-lib-devel cmake`
- **Ubuntu:** `sudo apt install libwebkit2gtk-4.1-dev libsoup-3.0-dev libgtk-3-dev build-essential libssl-dev librsvg2-dev libasound2-dev cmake`
- **Windows:** Microsoft C++ Build Tools, CMake, and WebView2 (preinstalled on Windows 11)

```sh
cd desktop
cargo run --release
```

The desktop app is its own Cargo workspace, so the core builds and tests
without these packages. Its profile lives in the platform app-data
directory; set `SECURETEXT_PROFILE_DIR` to use another location (for
example, to run two profiles side by side).

### Running an offline-delivery relay

A relay is a blind mailbox reachable only as a Tor onion service. Install
the `securetext-relay` `.deb`/`.rpm` from a release (it runs as a sandboxed
systemd service; the address is in `/var/lib/securetext-relay/address`),
use `packaging/relay/Containerfile`, or run it from source:

```sh
cargo run --release -p securetext-relay -- --dir /var/lib/securetext-relay
```

It prints a `securetext-relay1:…` address. Each user who wants offline
delivery pastes a relay address into the app (⚙ next to their name).

## Testing

```sh
cargo test --workspace                           # unit + integration tests (in-memory network)
cargo test -p securetext-net -- --ignored        # live Tor tests (needs network access)
python3 desktop/e2e/gui_e2e.py --binary desktop/target/debug/securetext-desktop [--turn …] [--relay securetext-relay1:…]
cargo +nightly fuzz run node_input -- -max_total_time=600   # coverage-guided fuzzing (six targets in fuzz/)
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
- `crates/securetext-update`: signed, Tor-only updates (and the `securetext-release` signing tool)
- `crates/securetext-call`: call engine (relay-only WebRTC, Opus, per-call media key) and `securetext-turn`
- `crates/securetext-cli`: proof-of-integration CLI and live-Tor demos
- `desktop/`: Tauri desktop client (own Cargo workspace), its web UI, and the GUI end-to-end test
- `packaging/`, `scripts/`, `.github/workflows/`: installers, relay packaging, release pipeline, CI and fuzzing
- `fuzz/`: coverage-guided fuzz targets (nightly, cargo-fuzz)

## Supported platforms

| Platform | Status |
|---|---|
| Ubuntu 22.04 LTS and newer | Supported (`.deb`, `.AppImage`) |
| Fedora 44 and newer | Supported (`.rpm`) · primary development platform |
| Windows 10 (21H2+) and Windows 11 | Supported (NSIS `.exe`, `.msi`); older Windows is refused by the installer |
| Android 12 and newer | Planned (Phases 10–11) |
| macOS, iOS | Not supported |

The offline-delivery relay can be hosted on Ubuntu Desktop 22.04+, Ubuntu
Server 20.04+, Debian 13+ and Fedora 44+. It ships as one static binary in
a `.deb` and an `.rpm`, so it has no glibc or OpenSSL version to match.

See [docs/platform-support.md](docs/platform-support.md) for details.

## Documents

- [docs/threat-model.md](docs/threat-model.md) — what SecureText protects against, and what it explicitly does not
- [docs/crypto-spec.md](docs/crypto-spec.md) — key management, 1:1 encryption, group encryption
- [docs/architecture.md](docs/architecture.md) — networking, invites, offline delivery, server/channel model
- [docs/tech-stack.md](docs/tech-stack.md) — libraries and tools chosen, with rationale and implementation findings
- [docs/platform-support.md](docs/platform-support.md) — supported platforms, packaging and CI notes
- [docs/releasing.md](docs/releasing.md) — installers, the release pipeline, and signing updates
- [docs/feature-parity.md](docs/feature-parity.md) — the Discord-like feature checklist and what each feature reveals
- [docs/security-review.md](docs/security-review.md) — security review: critical areas, threat-to-code map, findings, known limits
- [docs/roadmap.md](docs/roadmap.md) — phase-by-phase plan and verification status


## License

Apache License

Version 2.0, January 2004

http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   Copyright 2026 Lake Erie Technical Solutions LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
