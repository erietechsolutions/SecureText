# Development Roadmap

Each phase's exit criteria should be checked before starting the next —
this is a security-sensitive project where shortcuts compound.

## At a glance

| Phase | Scope | Status |
|---|---|---|
| 0 | Spec & threat model | ✅ Complete |
| 1 | 1:1 encrypted messaging over Tor | ✅ Live-verified on Linux · Windows pairing pending |
| 2 | Invite links & bridges | ✅ Live-verified on Linux · obfs4 bridge live test pending |
| 3 | Groups ("servers") & channels | ✅ Verified deterministically |
| 4 | Desktop client (Tauri) | ✅ Verified through the GUI over live Tor · real-user test pending |
| 5 | Offline delivery (relays) | ✅ Verified deterministically and over live Tor |
| 6 | Desktop installers & auto-updates | ✅ Built and verified locally · CI install runs and first signed release pending |
| 7 | Voice & video (the disclosed exception) | ✅ Built · verified via GUI with live-Tor signaling · real devices/networks pending |
| 8 | Rich features | Not started |
| 9 | Hardening & third-party audit | Not started · required before any production claim |
| 10 | Mobile core compatibility | Not started |
| 11 | Android app, export & updates | Not started |

**Renumbering note (2026-09-26):** Phases 6–11 were reorganised to add
installers/auto-updates and Android. Old → new: Voice & Video 6 → 7, Rich
Features 7 → 8, Hardening & Audit 8 → 9, Mobile Clients 9 → 10 (plus the
new 6 and 11). Commit messages from before this date use the old numbers.

## Phase 0 — Spec & Threat Model *(complete; remaining open items deferred to the phases that need them)*
- [x] Threat model (`threat-model.md`)
- [x] Cryptographic design (`crypto-spec.md`)
- [x] Network architecture (`architecture.md`)
- [x] Tech stack decisions (`tech-stack.md`)
- [x] Platform support matrix (`platform-support.md`)
- [x] Resolved: mandatory Tor v3 onion-service transport for all
      text/group/file traffic (no opt-out), OpenMLS as the single E2EE
      stack for both 1:1 and groups, calls on a separate disclosed path.
      See threat-model.md, architecture.md §1–2, crypto-spec.md §2.
- [ ] Remaining open items tracked in `tech-stack.md` §"Open items"
      (MLS-as-1:1 latency validation, SQLCipher-on-Windows, bridge UX,
      webrtc-rs coverage) — small spikes, not blocking Phase 1 start.
- **Exit criteria:** all five design docs reviewed, open items resolved or
  explicitly deferred with a rationale, before any Phase 1 code is written.

## Phase 1 — MVP: 1:1 Encrypted Messaging over Tor *(feature-complete and live-verified on Linux; cross-platform pairing verification pending — see exit criteria)*
- [x] Local identity generation (Ed25519 MLS signing keypair via
      `openmls_basic_credential`), persisted through `openmls_sqlite_storage`
      with whole-file Argon2id + ChaCha20-Poly1305 envelope encryption at
      rest (`crates/securetext-identity`, both round-trip and
      wrong-passphrase tests passing)
- [x] OpenMLS 2-member group established and used for 1:1 messaging
      (crypto-spec.md §2), verified with a real serialize/deserialize wire
      round trip in both directions (`crates/securetext-crypto`); local
      encrypt+decrypt throughput measured at ~5.7ms/message — not a
      bottleneck (tech-stack.md's implementation findings)
- [x] `arti`-based onion service hosting and outbound dialing
      (`crates/securetext-net`), **fully live-verified against the real Tor
      network in this dev environment**: bootstrap (~15s), a real `.onion`
      v3 address issued, and a complete two-party byte round trip — both
      as two `TorClient`s in one process and as two genuinely separate OS
      processes (`securetext net-listen` / `net-dial`). The apparent
      10+-minute "bootstrap stall" seen earlier was a red herring: it was
      actually a missing `.flush()` on the buffered `DataStream` writer
      (tech-stack.md's implementation findings) — fixed.
- [x] Proof-of-integration CLI (`securetext demo`) wiring identity + MLS +
      Tor together exactly as the real app would, **run and verified end
      to end**: two local identities form a 2-member MLS group, exchange a
      Welcome and an encrypted application message in both directions,
      entirely over live Tor onion services with no IP ever exchanged.
- [x] Noise_XX-secured transport session on top of the onion-service
      connection (crypto-spec.md §4), **live-verified**: each identity now
      has a persistent Noise static X25519 keypair (`securetext-identity`),
      `securetext-net` performs the full handshake and transport
      encryption (unit-tested locally over an in-memory pipe, no Tor
      needed for that check), and `securetext demo` / `net-dial` verify
      the peer's presented static key against the expected one obtained
      out-of-band before trusting the connection — real mutual
      authentication, not just "some onion service answered."
- [x] yamux multiplexing over the Noise session (architecture.md §6,
      tech-stack.md open item #6), **live-verified**: `SecureMux`
      (`crates/securetext-net/src/secure_mux.rs`) multiplexes logical
      streams over one Noise-encrypted onion-service connection via a
      background driver task and a "Noise pump." `securetext demo` now
      opens two multiplexed streams (control + chat) over a single
      connection, confirmed live against the real Tor network; a local
      test independently proves 3 concurrent streams work correctly.
- [x] MLS group state persistence across restarts (tech-stack.md open item
      #5), **verified via a full simulated restart**: `securetext
      restart-demo` seals identity stores to their encrypted files, drops
      everything, reopens from those files, reloads the MLS group by ID,
      and keeps messaging correctly in both directions
- [x] End-to-end latency benchmark combining MLS + a real Tor circuit
      (`securetext bench`), **measured**: 20 round trips over one
      established circuit came in at p50=3.09s, avg=3.46s (tech-stack.md
      open item #1) — usable for text chat, consistent with the disclosed
      "slower than Discord" tradeoff in architecture.md §6, not a surprise
- [ ] Manual address exchange only — invite links come in Phase 2 (this is
      by design, not a gap: Phase 1's scope was always "prove the crypto
      and transport stack works," with the invite mechanism explicitly
      deferred)
- **Exit criteria — status: functionally complete and live-verified on
  Linux; cross-platform pairing not yet verified (see below, action
  needed from you).**
  - ✅ Two instances exchange E2EE messages entirely over Tor with no
    direct IP exchange: verified repeatedly, including as two genuinely
    separate OS processes (`net-listen`/`net-dial`), with the full stack
    (identity + MLS + Noise + yamux + Tor) exercised together via
    `securetext demo` against the live Tor network.
  - ✅ MLS-as-1:1 benchmark results recorded and reviewed: p50=3.09s,
    avg=3.46s per round trip over an established circuit (tech-stack.md
    open item #1) — usable for text chat, consistent with the disclosed
    latency tradeoff.
  - ❌ **Not verified: a Linux-to-Windows pair (e.g., Fedora ↔ Windows
    11).** This development session ran entirely inside a single Linux
    sandbox with no Windows machine available — there was no way to
    actually test cross-platform wire compatibility, not just an
    oversight. Nothing in the design is Linux-specific (the whole stack is
    portable Rust: `arti`, `openmls`, `snow`, `yamux` all support Windows),
    but "should work" is exactly the kind of claim this phase exists to
    replace with a real verification. **Action needed:** build
    `securetext-cli` on a Windows machine (`cargo build -p securetext-cli`
    — see platform-support.md for the target matrix) and run
    `net-listen`/`net-dial` against a Linux instance before treating this
    exit criterion as met. This is the one piece of Phase 1 that
    genuinely requires hardware/an OS this environment doesn't have.

## Phase 2 — Invite Links & Bridges *(feature-complete on Linux; obfs4 live-connection verification pending, same category as Phase 1's Windows gap)*
- [x] Invite-link format encoding onion address + Noise static key + MLS
      key package (architecture.md §2) as a single shareable
      `securetext1:<base64>` string, replacing `net-listen`/`net-dial`'s
      manual three-argument exchange (new crate: `securetext-invite`).
      **Live-verified against the real Tor network**: `securetext invite
      --dir <path> --passphrase <pw>` prints a link; `securetext connect
      <link> --dir <path> --passphrase <pw>` (a genuinely separate process)
      parses it, dials the onion address, verifies the presented Noise key
      matches what the invite promised, adds the inviter to a new MLS
      group from their key package, and exchanges application messages
      correctly in both directions. Byte fields are base64-encoded within
      the JSON payload (not JSON's default number-array encoding) to keep
      the link reasonably compact.
      Unlike `demo`/`bench`/`net-listen`/`net-dial`, `invite`/`connect` use
      a **persistent** identity and Tor state directory (`--dir`), so the
      onion address stays stable across restarts and a previously-printed
      invite link keeps working later, not just within one process's
      lifetime.
- [x] Onion-address rotation + "I've moved" re-linking within existing MLS
      groups (architecture.md §2). `securetext rotate-demo` has alice host
      a group, exchange an initial message with bob, then rotate *both*
      her onion address and Noise static key together (rotating only one
      weakens the unlinkability rotation exists to provide), and notify
      bob via an `AppMessage::Moved` sent through their still-open
      MLS-encrypted connection -- not a fresh invite. Bob updates his
      stored contact record (new `Contact`/`upsert_contact`/`get_contact`
      in `securetext-identity`) and reconnects at alice's new address,
      with the Noise handshake verifying her rotated key matches what the
      Moved message promised before trusting the new connection.
      **Verification status:** one complete, fully successful live run
      against the real Tor network confirmed the entire mechanism end to
      end; two real bugs surfaced and were fixed from repeated live
      testing (a `tempfile::TempDir::keep()` leak in `bootstrap_for_this_run`
      that silently accumulated ~40MB per demo/bench/rotate-demo run with
      no cleanup -- found when it filled this sandbox's tmpfs and caused
      unrelated test failures; and a missing descriptor-propagation delay
      before dialing the *second* rotated address, which v1's dial had but
      v2's didn't). After both fixes, later live attempts were affected by
      what appears to be degraded Tor connectivity in this sandbox at the
      time (even a bare first dial, reliable all session, began taking
      many minutes) rather than a further code issue -- see tech-stack.md's
      implementation findings for the full account. The underlying
      persistence primitives (`Contact` storage, `rotate_noise_key`) are
      covered by fast, fully deterministic unit tests that always pass,
      independent of live network conditions.
- [x] Pluggable transport (obfs4) support via `arti`
      (`securetext_net::bootstrap_with_bridge` / `BridgeConfig`) — **config
      plumbing done and locally tested, live bridge connection not
      verified.** Built against arti's own real example
      (`arti-client/examples/snowflake.rs`, the closest verified reference
      since the crate ships no obfs4-specific example — it uses the
      identical `BridgeConfigBuilder`/`TransportConfigBuilder` API) and
      proven to construct a valid, buildable Tor client config from a
      bridge line + obfs4 transport declaration. **Not verified: an actual
      live obfs4 bridge connection.** This sandbox has no Go toolchain to
      build `obfs4proxy` from source and no real bridge relay to test
      against — the same category of gap as the Windows cross-platform
      item, flagged rather than glossed over. See
      `bootstrap_with_bridge`'s doc comment for exactly what's unverified.
- **Exit criteria:**
  - ✅ Two peers connect via invite link with no manual address exchange:
    verified live as described above.
  - 🔲 **A simulated Tor-blocked network condition overcome using a
    configured obfs4 bridge, verified end-to-end — not yet possible in
    this environment.** Action needed: on a machine with an `obfs4proxy`
    (or `lyrebird`) binary and a real bridge line (e.g. from
    bridges.torproject.org), call `securetext_net::bootstrap_with_bridge`
    and confirm it successfully bootstraps through the bridge.

## Phase 3 — Groups ("Servers") & Channels *(feature-complete, deterministically verified)*
- [x] MLS group creation/join/leave via OpenMLS, scaled beyond 2 members.
      **Verified deterministically** (`removed_member_cannot_decrypt_subsequent_messages`,
      `crates/securetext-crypto`, no live Tor needed for this proof): a
      3-member group (alice, bob, charlie) exchanges a message all three
      can read; alice removes bob and fans the removal commit out to
      charlie; a message alice encrypts *after* removal is readable by
      charlie but **fails to decrypt for bob** — checked by actually
      attempting the decrypt and asserting it errors, not assumed from the
      library. Along the way, fixed a real gap: `add_member` previously
      discarded the commit message entirely, which happened not to matter
      for Phase 1/2's 2-member scenarios (no third existing member to
      notify) but would silently desync any *other* existing member's view
      of the group once a group grew past two people. It now returns
      `(commit_bytes, welcome_bytes)`; all Phase 1/2 call sites updated.
- [x] Channel-level key partitioning within a group. **Verified
      deterministically** (`private_channel_excludes_non_members`):
      modeled as an independent MLS group per channel (a subset of the
      server's roster), not OpenMLS's native sub-group branching — see
      architecture.md §7 for the reasoning (branching's parent-epoch tie is
      real value given up, but avoids a much higher-risk implementation
      under time constraints). A server member excluded from a private
      channel is proven — by actually attempting the decrypt against his
      own (different) group state and checking it fails, not assumed — to
      be unable to read the channel's messages, while a real channel
      member reads them fine.
- [x] Signed role/permission capability tokens (post/invite/kick). New
      `Capability`/`Permission` (`crates/securetext-crypto`): issued by
      signing a payload with the issuer's existing MLS identity key (no
      new key type), verified by any peer via the group's own
      `OpenMlsCrypto::verify_signature` (no central authority contacted).
      Tested: a valid capability verifies for its real issuer; a tampered
      payload and a falsely-claimed issuer both correctly fail
      verification. **Integration-tested with real authorization, not just
      in isolation** (`authorized_moderator_can_remove_a_member`): alice
      delegates Kick authority to charlie via a capability; charlie
      verifies it's genuinely from alice, then uses his own MLS signing
      key to actually remove bob — composing cleanly with the removal
      mechanism above.
- **Exit criteria:** a 3+ member group can be created, a member removed
  loses access to subsequently-sent messages (verified directly, not just
  assumed from the library) — ✅ met, deterministically, above. "Entirely
  over the Tor transport from Phase 1" is not yet separately verified for
  this specific 3-member/removal scenario (the proof above is local,
  matching how Phase 1's own MLS correctness was first established before
  layering Tor underneath) — the underlying transport was already
  extensively live-verified in Phases 1-2, so this is about confirming the
  3-member case specifically, not a new transport risk.

## Phase 4 — Discord-like Client UI *(feature-complete; verified end to end through the real GUI over live Tor on Linux)*
- [x] Application core, UI-agnostic (`crates/securetext-app`): a long-running
      node per profile that owns the encrypted identity store, every MLS
      group, and an app database (peers, conversations, message history,
      other peers' key packages, outgoing queue) in the same
      envelope-encrypted SQLite file. One task owns all of it, so MLS group
      state is never mutated concurrently. Network I/O runs in
      per-connection tasks: onion service, then Noise_XX with key pinning,
      then yamux, then a small framed peer protocol (`wire.rs`).
- [x] Contacts and DMs from invite links. A DM is a 2-member MLS group, as
      before. Accepting an invite now also exchanges **signed contact
      cards** (label + onion address + Noise key, signed by the MLS
      identity key) and a pool of single-use key packages, which is what
      lets either side later add the other to a server without both being
      online at once.
- [x] Servers and channels on the Phase 3 primitives. Server = MLS group;
      each channel = its own MLS group; private channels include only the
      members picked. Joining a server delivers everyone's signed cards,
      and existing members get the newcomer's card inside the server
      group, so **members who never exchanged invites can still reach each
      other directly** (there's no server to relay through). The admin
      (the creator, architecture.md §7) invites, creates channels and
      removes members; removal re-keys the server and every channel the
      member was in. Whole-roster adds use a single commit
      (`Member::add_members`).
- [x] Offline behaviour for Phases 1–4 (architecture.md §4): every
      outgoing frame is persisted in the encrypted outbox before sending,
      retried with backoff, and flushed in order when the peer is next
      reachable. It survives restarts of either side. Messages that arrive
      ahead of the commit they depend on are held and retried, and groups
      keep `MAX_PAST_EPOCHS = 3` epochs of secrets so a message sent just
      before a membership change still decrypts (a small, deliberate
      forward-secrecy cost, documented at the constant).
- [x] Tauri desktop shell (`desktop/`, its own Cargo workspace so the core
      still builds and tests on machines without WebKitGTK) plus a
      framework-free HTML/CSS/JS frontend (`desktop/ui/`). It has a server
      rail, channel/DM sidebar, message view, member list with
      online/admin/remove, and dialogs for invites, contacts, servers,
      private channels and removal. The frontend loads nothing remote
      (strict CSP), because any request outside Tor would leak the user's
      IP.
- [x] Tor status in the UI: a persistent "Tor · onion-routed" indicator
      with a plain-language explainer (E2EE, Tor-only routing with no
      direct fallback, why the first message to someone can take up to a
      minute), a banner while Tor is bootstrapping or unavailable, and
      "Queued — sends automatically when … is reachable over Tor" on
      undelivered messages.
- **Verification:**
  - ✅ `crates/securetext-app/tests/app_flows.rs`: three real nodes (real
    encrypted profiles, MLS, Noise with key pinning, yamux, outbox) on an
    in-memory network standing in for Tor. Covers invite-to-DM both ways;
    a server where two members who never exchanged invites chat through
    the roster; a private channel the third member provably doesn't get;
    admin-only enforcement; removal (the removed member is told and stops
    receiving); offline queueing that survives restarts of both sides; a
    wrong passphrase; and an impostor holding a contact's onion address
    being refused by the Noise key check. Passed 5/5 repeated runs.
  - ✅ The real `securetext-desktop` binary built against WebKitGTK 4.1
    and launched headlessly (GTK Broadway backend, screenshot taken). The
    frontend loaded and its first call into Rust (`profile_info`)
    succeeded. (That run also appeared to show a WebKit layout bug; it was
    later traced to the headless Broadway display reporting a broken scale
    factor, not the app. See tech-stack.md's correction.)
  - ✅ **Full GUI-driven run of the exit criterion over live Tor.**
    `desktop/e2e/gui_e2e.py` drives two real `securetext-desktop` windows
    through WebDriver (WebKitWebDriver, what `tauri-driver` uses on Linux)
    on a headless virtual display: create both profiles, share and accept
    an invite, DM both ways, create a server, invite, chat in #general,
    create a private channel the friend can't see, remove the friend (who
    is told). **PASSED in about 60 seconds**, most of it Tor bootstrap; a
    first message on a fresh circuit took about 8–10s, later ones under 1s.
    Getting there found and fixed four real bugs no in-memory test had
    caught (tech-stack.md, "Phase 4/5 live-run findings"). The worst was a
    data-loss bug in Phase 1's Noise pump under simultaneous traffic.
- **Exit criteria:** a non-technical tester can create a server, invite a
  friend, and chat, without touching a CLI, and understands from the UI
  alone that their connection is Tor-routed. Every step of that is
  implemented in the GUI and has been verified through the GUI over live
  Tor (above). ✅ for the technical criterion. Still to do: a session with
  an actual non-technical tester (a scripted run can't judge
  understandability), and the cross-platform runs (Windows) required for
  every phase.

## Phase 5 — Offline Delivery *(feature-complete; verified deterministically and end to end over live Tor)*
- [x] Store-and-forward relay service (`crates/securetext-relay`, binary
      `securetext-relay --dir <path>`): reachable only as its own onion
      service, stable address across restarts, prints a
      `securetext-relay1:` address (onion + pinned Noise key). It is a blind
      mailbox and keeps its audit surface small: deposit (anyone with the
      mailbox ID), fetch and ack (only the mailbox secret's holder). It
      enforces per-blob, per-mailbox and global limits and a 14-day TTL,
      stores deposit times rounded to the hour, and uses SQLite
      `secure_delete`.
- [x] Client-side deposit and retrieval over Tor (`securetext-app`,
      `relay.rs`). When a direct dial fails, queued frames are sealed into
      envelopes (ChaCha20-Poly1305 under the recipient's mailbox key, padded
      to 1 KiB, signed by the sender's MLS key over the exact frames and
      recipient) and left at the recipient's relay. Mailboxes are polled,
      and what's collected goes through the same handlers as a direct
      connection. A throwaway Noise key is used per relay connection.
      Relay cards travel in contact cards and invite links, both
      backward-compatible (omitted when unset), and a relay change reaches
      connected contacts immediately.
- [x] Desktop UI: an "Offline delivery" setting (⚙ next to your name),
      messages left at a relay marked as such, and the relay shown in the
      Tor details dialog.
- **Verification:**
  - ✅ `crates/securetext-relay`: 9 tests covering storage round-trip,
    mailbox authorization (the mailbox ID can't read or delete; only the
    secret can), quotas and TTL, coarsened timestamps, Noise pinning of the
    relay's key, and oversized-deposit refusal.
  - ✅ `crates/securetext-app/tests/relay_flows.rs`: real nodes and a real
    relay server with on-disk storage. (1) Sender and recipient are **never
    online at the same time** and the message still arrives, then is
    deleted from the relay. (2) An invite is accepted while the inviter is
    offline, and the new conversation and first message are waiting when
    they return. (3) A relay chosen after befriending reaches the contact
    as a live card update. (4) **The relay's raw database file is inspected
    byte by byte** for the message text, both parties' labels, onion
    addresses, identity keys (raw/hex/base64), Noise key and group ID. None
    are present. A deliberately broken build that stored plaintext was
    confirmed to fail this check. (5) Every relay connection presented a
    distinct throwaway key, never an identity's.
  - ✅ Envelope unit tests: a blob opens only with its mailbox key and for
    its addressee, and a contact holding the mailbox key can't forge an
    envelope as someone else.
  - ✅ **Live-Tor run** with the real `securetext-relay` binary on its own
    onion service and two real desktop clients (the relay stage of
    `gui_e2e.py`). Bob sets the relay in the GUI and quits. Alice's message
    is marked "Left at Bob's relay". Alice quits. Bob reopens and collects
    it: **the two were never online at the same time.** The live relay's
    database file was then scanned and held none of the message text,
    names, onion addresses or server name. One uncollected blob remained;
    the relay can't say whose, which is the point, and it expires under
    the TTL.
  - ✅ A peer that vanishes *without closing its connection* (crash,
    sleep, network loss): found live, now covered by
    `a_peer_that_vanishes_mid_connection_still_gets_mail_via_relay`.
  - **"Never learns anyone's IP" is structural, not measured.** The relay
    has no listener except its onion service, and onion-service streams
    carry no client address, so there's nothing for it to log. No packet
    capture was taken.
- **Exit criteria:** a message sent while the recipient is offline is
  delivered once they come online, without the relay ever holding
  decryptable content or learning either party's real IP. ✅ Met:
  delivery (with both parties never online together) and relay-side
  storage are verified directly, deterministically and over live Tor. The
  IP property holds by construction, as noted above.

## Phase 6 — Desktop Installers & Auto-Updates *(built and verified locally; CI install runs and first real release pending)*
Goal: someone can install SecureText without a Rust toolchain and stay up
to date without doing anything, without weakening the anonymity
guarantees. This is also what makes Phase 4's pending real-user test
possible. Full procedure: releasing.md. Design: architecture.md §10.
- [x] Native installers from the Tauri bundler (`desktop/tauri.conf.json`):
      NSIS `.exe` (per-user, no admin) and `.msi` for Windows, `.deb` and
      `.AppImage` for Ubuntu, `.rpm` for Fedora, with a start-menu/desktop
      entry. The NSIS uninstaller's "delete app data" box is off by
      default, and package removal never touches the profile, so the
      encrypted profile is never silently deleted. The Linux package name is
      `secure-text` (Tauri derives it from the product name); the app is
      "SecureText" everywhere users see it.
- [x] Release pipeline (`.github/workflows/release.yml`), run on a version
      tag:
  - checks the tag matches the app version;
  - runs `cargo test --workspace` on Linux and Windows;
  - builds each installer natively (Ubuntu 22.04 for the oldest supported
    glibc, a Fedora 44 container, Windows);
  - **installs each one on a fresh runner** (Ubuntu 22.04 and 24.04,
    Fedora 44, Windows NSIS and MSI) and checks the app starts and stays
    up, then uninstalls;
  - publishes everything plus `SHA256SUMS` as a **draft** GitHub Release.
  
  The two-window GUI test over live Tor is an opt-in job. `ci.yml` runs
  the tests, a desktop build and a `cargo-deny` audit on every push.
- [x] **Auto-updates linked to GitHub Releases**, built as our own small
      updater (`crates/securetext-update` + `securetext-app/src/updates.rs`)
      rather than Tauri's updater plugin, which fetches over the clearnet.
      Each requirement is met as follows:
  - **Over Tor only.** Checks and downloads use Tor exit streams from the
    app's own arti client (`securetext_net::connect_exit`), with an
    isolation token per check. The host name is resolved at the exit. The
    HTTPS client has no socket code of its own, so there's no path to a
    direct connection.
  - **Signed with a dedicated key, verified before install.** An Ed25519
    signature (domain separated) covers the manifest's exact bytes. The
    public key is pinned in `desktop/update-signing.pub`, and more than one
    can be listed for rotation. Each installer's SHA-256 and size come from
    the signed manifest. They're checked while downloading and again right
    before installing.
  - **No downgrades.** Only strictly newer versions are offered, and
    pre-releases only to pre-release users.
  - **User control.** The release notes are shown, and nothing installs
    until the user clicks "Restart to update". Checks come at a random time
    10 minutes to 3 hours after start, then about daily with ±25% jitter.
    They can be turned off in Settings.
  - **The signing key is kept away from CI entirely.** CI only makes a
    draft. `scripts/sign-release.sh` signs the manifest offline with a
    passphrase-encrypted key (Argon2id + ChaCha20-Poly1305) and publishes.
    A GitHub account compromise therefore can't ship an update, which is
    stronger than the "key in a CI secret" the plan first described.
  - **Applying an update**, by install type:
    - AppImage: swapped atomically in place, then restarted.
    - NSIS: runs the new installer passively (`/P /R /UPDATE`), which
      relaunches the app.
    - MSI: `msiexec /passive`.
    - deb/rpm: handed to the system's software installer, which asks for
      the admin password. The app never asks for root itself.
    - Source builds: told a release exists, never updated.
    
    The install type comes from the bundle type Tauri stamps into the
    binary.
- [ ] Code signing: no Windows Authenticode certificate yet, so SmartScreen
      will warn. The workflow marks the step. There's no GPG signature over
      `SHA256SUMS` for manual installs yet.
- [x] Relay packaging:
  - `securetext-relay` as `.deb` (cargo-deb) and `.rpm`
    (cargo-generate-rpm) with a sandboxed systemd unit (`DynamicUser`,
    `ProtectSystem=strict`, no capabilities, syscall filter), enabled on
    install;
  - `--version`;
  - the relay address written to `<dir>/address`;
  - a container image (`packaging/relay/Containerfile`).
- **Verification:**
  - ✅ `crates/securetext-update` (14 tests), all run against a local TLS
    stand-in for GitHub:
    - a manifest altered in any way, or signed by another key, is refused;
    - a manifest for another product is refused;
    - version policy (no downgrades, pre-release rules);
    - key rotation;
    - the passphrase-encrypted key file is useless without its passphrase;
    - URL parsing is strict (https only, no credentials, no
      protocol-relative redirects);
    - a GitHub-style redirect to the CDN host is followed, and both
      `Content-Length` and chunked bodies work;
    - oversized bodies, redirects to foreign hosts and certificates from
      the wrong CA are refused;
    - a download that doesn't match its signed hash is deleted;
    - an AppImage swap is atomic, executable, and leaves no temp file.
  - ✅ `securetext-app/tests/update_flow.rs`, through a running node:
    - a scheduled check finds, downloads and verifies an update, and
      announces it by event, but doesn't install it;
    - turning auto-updates off persists across restarts and stops
      scheduled checks, while manual checks still work (a build without
      the auto-update guard was confirmed to fail this test);
    - a release signed by an unpinned key is reported and never
      downloaded.
  - ✅ **Live over Tor:** the updater's real client fetched a real GitHub
    release asset, including the redirect to GitHub's CDN host, through a
    Tor exit in 6.7 s (`fetches_a_real_github_release_asset_over_tor_live`).
  - ✅ The `.deb` and `.rpm` were built locally and inspected: files,
    permissions, desktop entry, icons and dependencies
    (`libwebkit2gtk-4.1-0`/`libgtk-3-0`; RPM requires the sonames). The
    RPM's requirements were confirmed resolvable from Fedora 44's repos.
    The relay's packages were inspected the same way. The packaged relay
    binary was run live: it published its onion service and wrote its
    address file.
  - ✅ The release CLI, end to end with a throwaway key:
    - keygen writes a 0600 encrypted key file;
    - it signs a manifest over the real installers;
    - verify passes;
    - the wrong passphrase and a wrong public key are both refused.
  - ✅ `cargo-deny` found a real advisory in rustls (RUSTSEC-2026-0285,
    TLS 1.3 message-boundary handling; low severity). Fixed by upgrading
    to 0.23.45 and requiring it in the updater. The remaining findings are
    documented as not applicable in `deny.toml`.
  - ⏳ **Not yet run:**
    - the release workflow's builds and clean-machine installs (the
      workflow files need a token with the `workflow` scope to push);
    - Windows installers built or installed at all;
    - an actual update applied to an installed copy (that needs the
      production signing key and a public repository);
    - a packet capture of update traffic (it's Tor-only by construction:
      the updater's only connector is the Tor exit one);
    - the relay's systemd unit under real systemd.
- **Exit criteria:** on clean Windows 10, Windows 11, Ubuntu and Fedora
  machines, a non-developer installs from a GitHub Release, the app runs,
  and an update published afterwards is detected, verified and applied
  over Tor. A packet capture confirms the update traffic never touches the
  clearnet. A tampered or wrongly signed update is refused. **Partly met:**
  - refusing tampered and wrongly signed updates is verified;
  - the Tor-only fetch is verified live;
  - installs on clean machines are automated in CI but haven't run yet;
  - the end-to-end update needs the maintainer's key (releasing.md) and a
    public repository.

## Phase 7 — Voice & Video (the disclosed exception) *(built; verified through the GUI with live-Tor signaling · real-network and real-device tests pending)*
Design as built: architecture.md §9.
- [x] Calls in DMs and channels: voice or video, one call at a time, a
      small mesh (each participant connects to each other one). Ring,
      accept/decline, join and leave, mute, camera on/off, and a ring
      timeout. Everyone else in a channel call carries on when one person
      leaves.
- [x] **Forced relay, never direct:**
  - `iceTransportPolicy = relay` with mDNS candidates off;
  - an SDP containing anything but relay candidates is refused before it
    leaves the device;
  - each person uses their own TURN server (Settings → Calls) or the
    caller's;
  - `securetext-turn` is a TURN server anyone can run (release asset).
- [x] **Keyed from MLS:**
  - signaling (including the DTLS fingerprints) travels as MLS messages in
    the conversation's group, sent live only and never queued or relayed;
  - a random per-call key, distributed only inside the MLS-encrypted ring,
    seals every audio and video frame (ChaCha20-Poly1305, bound to the call
    and media kind) on top of DTLS-SRTP.
- [x] **Disclosure before every call:** a dialog before starting or joining
      says calls don't go through Tor, names whose relay sees the IP, says
      the other participants don't see it, and says what stays private. The
      in-call panel shows "relayed via your/the caller's TURN server".
- [x] Media in Rust (webrtc-rs, Opus 48 kHz, cpal), because Ubuntu's and
      Fedora's WebKitGTK are built without WebRTC (tech-stack.md, Phase 7
      findings). Camera frames come from the webview and travel as sealed
      JPEGs over a data channel on the same relayed connection.
- [x] Screen sharing through the webview's `getDisplayMedia` (the system's
      screen picker), feeding the same frame path. **Unverified:** the
      picker can't be answered in the headless test environment; it's an
      opt-in step of the GUI test (`--screen-share`) for a real desktop.
- **Verification:**
  - ✅ `crates/securetext-call` (10 tests), two engines through a real TURN
    server:
    - each hears the other's tone at the right pitch after Opus → seal →
      SRTP → TURN → unseal → decode;
    - WebRTC's own stats show relay/relay;
    - video frames arrive intact;
    - mute sends silence;
    - a participant without the call key hears nothing;
    - no TURN server means no call;
    - unit tests cover the frame cipher (wrong key, call, kind, or a
      tampered frame all fail), Opus, the mixer, resampling, and the
      dropout-aware pitch analysis.
  - ✅ **Mutation checks.** With the relay-only ICE policy removed, the
    engine's SDP guard refuses to send host candidates and the test fails.
    With the guard removed as well, the test's own SDP check fails.
  - ✅ `securetext-app/tests/call_flows.rs`, with real nodes, real MLS
    signaling and a real TURN server:
    - a DM call rings, is accepted using the caller's TURN server, connects
      relay-to-relay, carries each voice to the other and no echo, mutes,
      and hang-up ends both sides with the reason given;
    - declining ends the caller's side;
    - **a three-person channel call:** everyone hears both others, never
      themselves, all relayed. The call's own signaling connected two
      members who had never been connected, which a first version got
      wrong (the fix holds live signals while dialing). When one person
      leaves, the other two carry on.
  - ✅ **GUI, with signaling over live Tor**
    (`gui_e2e.py --turn …`, apps using synthetic tones and WebKit's mock
    camera):
    - Alice sets a TURN server in Settings and starts a video call through
      the disclosure dialog; Bob joins from the incoming-call dialog;
    - both panels show the call connected, and stats show relay/relay with
      about 620 KB of media each way;
    - each app heard the other's tone at exactly its pitch (440/660 Hz)
      with no dropouts;
    - each side's camera frames were shown on the other;
    - hang-up ended the call for both.
    
    The rest of the Phase 4 flow still passes in the same run.
  - ⏳ **Not yet done:**
    - real microphones and speakers, and real cameras (tests used synthetic
      tones and WebKit's mock camera);
    - Windows;
    - a TURN server on another machine, across real NATs (the tests used
      loopback);
    - coturn interop;
    - a packet capture confirming no direct peer-to-peer traffic (the relay
      evidence is WebRTC's own stats plus the SDP check);
    - a clarity review of the disclosure text by someone other than its
      author;
    - screen sharing (see above);
    - echo cancellation (not implemented; headphones recommended).
- **Exit criteria:** a 1:1 call and a group call both work at usable
  quality; a network capture confirms media is relayed (never direct
  peer to peer) so participants don't learn each other's raw IP; the
  disclosure UI is reviewed for clarity, not just presence. **Partly met:**
  - 1:1 and group calls work end to end, with audio verified by pitch;
  - relay-only is enforced and verified from WebRTC's stats and the SDPs
    (not yet by packet capture);
  - "usable quality" with real devices on real networks, and an independent
    review of the disclosure text, are still to do.

## Phase 8 — Rich Features
- Encrypted file/image sharing, reactions, threads, presence/status,
  disappearing messages — all over the Tor transport from Phase 1
- **Exit criteria:** feature parity checklist against the "Discord-like"
  goal from the original vision, each new feature re-checked against
  threat-model.md for new metadata leakage before shipping.

## Phase 9 — Hardening & Third-Party Audit
- Independent security audit covering: the crypto implementation and
  protocol composition (MLS-for-1:1 included, since it's a less-common
  usage pattern than MLS-for-groups-only), and the Tor integration
  specifically (onion-service key handling, bridge configuration, the
  Phase 7 calls exception's actual exposure). The **update and release
  chain from Phase 6** is in scope too: signing-key handling, update
  verification, and Tor-only update fetching. A compromised updater
  bypasses every other protection.
- Address findings before any "production-ready" claim is made.
- **Exit criteria:** audit complete, critical/high findings remediated.
  **This phase is not optional and should not be skipped or compressed
  under schedule pressure** — see crypto-spec.md §8.

## Phase 10 — Mobile Core Compatibility
Goal: make the Rust core run correctly on mobile before building a mobile
app on it.
- [ ] Decide the mobile shell. Options: **Tauri 2's mobile support**
      (reuses `desktop/ui` and calls `securetext-app` directly with no FFI
      layer; the lowest-effort path now that the desktop app is Tauri), or
      the original plan of React Native/Flutter calling the core through
      UniFFI (tech-stack.md). Record the decision and why in tech-stack.md.
- [ ] Build the core crates for Android targets (`aarch64-linux-android`,
      `armv7-linux-androideabi`, `x86_64-linux-android` for emulators), and
      keep them building in CI.
- [ ] Mobile Tor research spike: arti on Android, keeping the onion
      service reachable under Doze/app-standby. Candidate designs: a
      foreground service with a persistent notification while "online",
      and relay-first delivery (Phase 5) while backgrounded, where the app
      collects from its mailbox when opened or on a scheduled job instead
      of being continuously reachable. Measure battery and data cost.
- [ ] Mobile-safe storage: the encrypted profile under app-private
      storage, with the key material optionally wrapped by the Android
      Keystore, which never weakens the passphrase model.
- [ ] Responsive UI: the desktop layout adapted to phone screens (single
      column with navigation between servers, channels, chat and members),
      touch targets, and the on-screen keyboard.
- **Exit criteria:** the core passes the same Phase 1/3/5 correctness
  checks on an Android device or emulator as on desktop, including the
  "no direct IP exchange" verification, and the background-reachability
  design is chosen with measured numbers.

## Phase 11 — Android App, Export & Updates
- [ ] Android client on the Phase 10 decisions, with feature parity with
      desktop for text, servers, channels, invites and offline delivery
      (calls follow Phase 7's design once it exists).
- [ ] **Exports:** signed release builds as `.apk` (direct install) and
      `.aab` (store upload), built in the Phase 6 GitHub Actions pipeline
      and published to GitHub Releases next to the desktop installers. The
      release signing key is kept offline, and its loss or leak is planned
      for (Android can't change an app's signing key casually).
- [ ] Distribution: GitHub Releases first; then F-Droid (reproducible
      builds, fits the project's privacy stance) and/or Obtainium users
      tracking GitHub Releases. Google Play is optional: weigh its
      account-identity requirements and Play Services dependencies against
      the threat model before choosing it.
- [ ] **Android updates:** Android doesn't allow silent self-updates of
      sideloaded apps. The app checks GitHub Releases **over Tor**
      (same rules as Phase 6), verifies the signed APK, and hands it to the
      system installer with the user's confirmation. Store-installed copies
      update through their store instead.
- [ ] Invite links shareable via Android's share sheet and QR codes
      (camera scan to add a contact), since phones are where people
      exchange them in person.
- **Exit criteria:** a signed APK installs on a stock Android phone,
  creates a profile, and chats with a desktop user through invites,
  servers and offline delivery over Tor. An in-app update from a newer
  GitHub Release installs correctly and a tampered APK is refused. A
  follow-up audit covers the Android-specific code before any production
  claim.

## Cross-cutting, ongoing throughout all phases

- **Every phase's exit criteria must be verified on Ubuntu, Fedora, and
  Windows 10/11** (see `platform-support.md`), not just the OS the code
  happened to be written on, and on Android once Phase 11 ships. macOS and
  iOS are not official v1 targets.
- **No feature ships that creates a direct IP exchange for text/group/file
  traffic**, per the mandatory-anonymity requirement in threat-model.md —
  this is a standing constraint to check new features against, not just a
  Phase 1 concern.
- Revisit `threat-model.md` whenever a new feature changes what data
  leaves a device unencrypted, or whenever a feature might reintroduce IP
  exposure outside the Phase 7 disclosed exception.
- No custom cryptographic protocol changes ship without review against
  `crypto-spec.md`'s "use a library, not a paper" rule.
- No new crypto/network-adjacent dependency is added without the vetting
  process in `tech-stack.md`'s standing rule (license, maintenance, audit
  history — verified directly, not assumed from name or popularity).
- Track the open items in `tech-stack.md` as they get resolved, and record
  *why* a decision was made (not just what), so later phases don't
  relitigate settled tradeoffs without new information.
