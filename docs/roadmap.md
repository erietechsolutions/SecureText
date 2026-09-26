# Development Roadmap

Each phase's exit criteria should be checked before starting the next —
this is a security-sensitive project where shortcuts compound.

## Phase 0 — Spec & Threat Model *(current phase)*
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

## Phase 6 — Voice & Video (the disclosed exception)
- WebRTC integration for calls and screen share, keyed from the existing
  MLS session material, using the forced-relay design from
  architecture.md §9 (never a direct peer connection for media)
- Calling UI explicitly discloses the reduced anonymity guarantee for
  calls before a call starts (threat-model.md)
- **Exit criteria:** a 1:1 call and a group call both work at usable
  quality; a network capture confirms media is relayed (never direct
  peer-to-peer) so participants don't learn each other's raw IP; the
  disclosure UI is reviewed for clarity, not just presence.

## Phase 7 — Rich Features
- Encrypted file/image sharing, reactions, threads, presence/status,
  disappearing messages — all over the Tor transport from Phase 1
- **Exit criteria:** feature parity checklist against the "Discord-like"
  goal from the original vision, each new feature re-checked against
  threat-model.md for new metadata leakage before shipping.

## Phase 8 — Hardening & Third-Party Audit
- Independent security audit covering: the crypto implementation and
  protocol composition (MLS-for-1:1 included, since it's a less-common
  usage pattern than MLS-for-groups-only), and the Tor integration
  specifically (onion-service key handling, bridge configuration, the
  Phase 6 calls exception's actual exposure).
- Address findings before any "production-ready" claim is made.
- **Exit criteria:** audit complete, critical/high findings remediated.
  **This phase is not optional and should not be skipped or compressed
  under schedule pressure** — see crypto-spec.md §8.

## Phase 9 — Mobile Clients
- React Native or Flutter mobile clients calling the Rust core via UniFFI
- Mobile-specific Tor integration considerations (background circuit
  maintenance under mobile OS power management, which is known to be
  harder than desktop — flag as a research spike early in this phase
  rather than assuming desktop's approach ports directly)
- **Exit criteria:** mobile clients pass the same Phase 1/3 correctness
  checks as desktop, including the "no direct IP exchange" verification.

## Cross-cutting, ongoing throughout all phases

- **Every phase's exit criteria must be verified on Ubuntu, Fedora, and
  Windows 10/11** (see `platform-support.md`), not just the OS the code
  happened to be written on. macOS is not an official v1 target.
- **No feature ships that creates a direct IP exchange for text/group/file
  traffic**, per the mandatory-anonymity requirement in threat-model.md —
  this is a standing constraint to check new features against, not just a
  Phase 1 concern.
- Revisit `threat-model.md` whenever a new feature changes what data
  leaves a device unencrypted, or whenever a feature might reintroduce IP
  exposure outside the Phase 6 disclosed exception.
- No custom cryptographic protocol changes ship without review against
  `crypto-spec.md`'s "use a library, not a paper" rule.
- No new crypto/network-adjacent dependency is added without the vetting
  process in `tech-stack.md`'s standing rule (license, maintenance, audit
  history — verified directly, not assumed from name or popularity).
- Track the open items in `tech-stack.md` as they get resolved, and record
  *why* a decision was made (not just what), so later phases don't
  relitigate settled tradeoffs without new information.
