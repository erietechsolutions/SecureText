# Audit Preparation

This is the starting point for the independent security audit (roadmap
Phase 9). SecureText has **not** been audited yet. Nobody should rely on
it for anything that matters until that audit is done and its critical
and high findings are fixed.

It covers:

- what to look at, in priority order, with file paths;
- how each threat in threat-model.md is handled, and where;
- what the project's own hardening pass found and fixed;
- the known weak spots and open questions we'd most like an auditor's
  view on;
- how to build, test and fuzz everything.

## 1. The system in one page

- **Identity.** No accounts. Each device holds:
  - an Ed25519 MLS signing key (its identity);
  - an X25519 Noise static key;
  - its own Tor v3 onion service.
  
  All of it is stored in one SQLite file, envelope-encrypted with
  Argon2id + ChaCha20-Poly1305 (crypto-spec.md §5).
- **Transport.** Every message travels over Tor onion services (arti). A
  Noise_XX session inside pins the peer's static key to their contact
  card, and yamux runs inside Noise. There's no clearnet path for
  messaging.
- **Encryption.** Everything is MLS (OpenMLS, RFC 9420), including 1:1
  chats (2-member groups). Servers and each of their channels are
  separate MLS groups. The admin is the creator.
- **Offline delivery.** Blind relays, themselves onion services, hold
  padded, sealed envelopes in mailboxes named by `SHA-256(context ‖
  secret)`.
- **Calls** are the disclosed exception to Tor: WebRTC forced through
  TURN, with signaling over MLS and a per-call media key distributed
  inside MLS.
- **Files** are encrypted under a per-file key carried inside MLS. They're
  fetched peer to peer over Tor and served only to members of the
  conversation.
- **Updates** come from GitHub Releases, over Tor exits only, as a
  manifest signed by an offline key pinned in the app.

Design documents: threat-model.md, crypto-spec.md, architecture.md
(§9 calls, §9a rich messaging, §10 updates), releasing.md, and
feature-parity.md (per-feature metadata review).

## 2. Scope, in priority order

| # | Area | Where | What we'd most like checked |
|---|---|---|---|
| 1 | MLS usage | `crates/securetext-crypto`, `crates/securetext-app/src/node.rs` (`on_welcome`, `on_mls`, `add_to_group`, `kick`) | MLS for 1:1 chats; Welcome validation (the sender must be a member and the admin, and a channel's admin must equal its server's admin); roster card handling; `MAX_PAST_EPOCHS = 3`; out-of-order handling (held messages); removal and re-keying |
| 2 | Identity-at-rest | `crates/securetext-identity` | Argon2id parameters (the crate defaults: 19 MiB, t=2, p=1); the whole-file envelope; the decrypted working copy (see finding P9-01/02); seal frequency and crash windows |
| 3 | Transport authentication | `crates/securetext-net` (`noise.rs`, `secure_mux.rs`), `node.rs` (`ensure_dial`, `spawn_accept`) | Noise_XX key pinning against contact cards; binding a card's signature to the connection's Noise key; mid-connection card updates; the dial path only reaching v3 onions |
| 4 | Update chain | `crates/securetext-update`, `scripts/sign-release.sh`, `.github/workflows/release.yml`, `desktop/src/main.rs` (`apply_update`) | Manifest signature and domain separation; the downgrade and freeze policy; hashing while streaming and again at apply time; per-platform apply (AppImage swap, NSIS/MSI invocation); key custody; the Tor-only fetch |
| 5 | Relay protocol | `crates/securetext-relay`, `crates/securetext-app/src/relay.rs` | Envelope sealing, padding and sender signatures; mailbox authorization; what the relay can learn (timing, counts); throwaway client keys |
| 6 | Calls | `crates/securetext-call`, `crates/securetext-app/src/node/calls.rs` | Enforcing relay-only (policy plus the SDP guard); the frame cipher's nonces and AAD; key distribution through the ring; TURN credential handling; glare and mesh logic; the removed-member key window |
| 7 | Files and rich messaging | `crates/securetext-app/src/node/rich.rs`, `store.rs` | File encryption and hash binding; member-only serving; chunk ordering and length checks; the `secure_delete` guarantees; inline image sniffing |
| 8 | Desktop shell and UI | `desktop/src/main.rs`, `desktop/tauri.conf.json`, `desktop/capabilities/`, `desktop/ui/` | CSP; the capability set; the webview's permission handler (camera and microphone only); HTML escaping across the UI; the test-only environment hooks (`SECURETEXT_MOCK_MEDIA`, `SECURETEXT_TEST_TONE`) |
| 9 | Tor integration | `crates/securetext-net/src/lib.rs`, `crates/securetext-app/src/lib.rs` | Onion-service key storage (arti keystore under the profile); bridge configuration (never tested live); exit-stream isolation for updates |

About 16,700 lines of Rust and JavaScript sit under `crates/`,
`desktop/src` and `desktop/ui`. There's no `unsafe` in our code: every
crate has `#![forbid(unsafe_code)]`.

## 3. Threat model → defenses → code

| Threat (threat-model.md) | Defense | Code | Tested by |
|---|---|---|---|
| Network eavesdropper | MLS for content; Tor + Noise for transport | `securetext-crypto`, `securetext-net` | `app_flows.rs`, live-Tor tests |
| Curious relay operator | Sealed, padded envelopes; anonymous mailboxes; throwaway client keys | `relay.rs`, `securetext-relay` | `relay_flows.rs` (byte-level scan of the relay's database) |
| Tampering / replay | MLS AEAD and epochs; signed contact cards; Noise | `wire.rs`, `node.rs` | `wire.rs` tests, `an_impostor_cannot_answer_for_a_contact` |
| Unauthorised membership changes | Admin checks on Welcome, roster and timer messages | `node.rs`, `rich.rs` | `app_flows.rs`, `rich_flows.rs` |
| Removed member reading on | MLS removal commits | `node.rs::kick` | `server_channels_membership_and_kick` |
| Stolen device | The encrypted profile; attachments encrypted at rest; `secure_delete` for expired messages | `securetext-identity`, `rich.rs` | identity tests, `an_expired_message_is_erased…` |
| IP / device correlation | Onion services only; dials refused for anything but v3 onions | `securetext-net::dial` | `only_v3_onion_addresses_are_dialable` |
| Tor blocking | obfs4 bridges | `securetext-net::bootstrap_with_bridge` | config only (**not live-tested**) |
| Malicious update | Offline-signed manifest, pinned key, hashes, no downgrades | `securetext-update` | `update_flow.rs`, crate tests |
| Update checks revealing users | Tor exits, isolation, random timing | `updates.rs` | live fetch over Tor |
| Calls exposing IP to participants | Forced relay plus the SDP guard | `securetext-call::engine` | `relay_call.rs` (with mutation checks), `call_flows.rs` |
| Resource exhaustion by strangers | Caps on streams, held messages, cards, handshakes, stranger connections, relay connections | `secure_mux.rs`, `node.rs`, relay `main.rs` | `a_stranger_cannot_make_us_hold_unbounded_state`, `a_flood_of_silent_connections_is_capped`, `a_connection_carries_at_most_max_streams` |

## 4. Internal hardening findings (Phase 9)

Found by the project's own review before the external audit. Severity is
our estimate.

| ID | Severity | Finding | Status |
|---|---|---|---|
| P9-01 | **High** | The decrypted working copy of the profile database sat in a temp directory created **0755** (`tempfile` follows the umask). While the app was unlocked, any other local user could read the identity keys, MLS state and message history. | **Fixed:** the directory is created 0700 and the file 0600 (created empty and private before SQLite opens it). Regression test `the_decrypted_working_copy_is_private_to_its_owner`; a build without the fix was confirmed to fail it. |
| P9-02 | Medium | That working copy is plaintext on disk until closed, and a crash leaves it behind. `/tmp` is on disk on many systems. | **Mitigated on Linux:** it now lives under `$XDG_RUNTIME_DIR` (tmpfs, per-user, wiped at logout). **Open on Windows:** %TEMP% is on disk. The real fix is SQLCipher-style page encryption (a Phase 1 open item). |
| P9-03 | Medium | yamux defaults (512 streams, a 1 GiB receive window) let anyone who can reach an onion address make a node buffer up to about 1 GiB per connection in streams it never reads. | **Fixed:** at most 4 streams and 16 MiB per connection. Test `a_connection_carries_at_most_max_streams`. |
| P9-04 | Medium | MLS messages for unknown groups were held with a per-group cap only. A stranger sending frames for invented groups could grow memory without bound (frames are up to 4 MiB each). | **Fixed:** at most 64 groups and 32 MiB in total. Test `a_stranger_cannot_make_us_hold_unbounded_state`. |
| P9-05 | Medium | No limit on concurrent inbound handshakes or on connections from peers who aren't contacts. | **Fixed:** 32 handshakes at once, 16 stranger connections. Test `a_flood_of_silent_connections_is_capped`; a build without the limit was confirmed to fail it. |
| P9-06 | Low | Contact cards presented by strangers were kept forever. | **Fixed:** at most 256, for up to 1 hour. |
| P9-07 | Low | The relay had no limit on concurrent connections. | **Fixed:** 256 at once; extra connections are dropped. |
| P9-08 | Low | A contact-supplied address (invite, card, relay) could name a clearnet host, making the node connect through a Tor exit. Still anonymous, but it broke the "messaging is onion-only" invariant. | **Fixed:** `securetext_net::dial` refuses anything but a well-formed v3 onion. |
| P9-09 | Info | Invite links weren't length-limited before decoding. | **Fixed:** 16 KiB cap. |
| P9-10 | Info | The profile and attachment directories were created with default permissions (names and sizes visible to other users; the contents were already encrypted). | **Fixed:** 0700. |
| Dep | Low | RUSTSEC-2026-0285 (rustls, TLS 1.3 message boundaries) | Fixed in Phase 6 (0.23.45 required). |
| Dep | Low | RUSTSEC-2026-0150 (`audiopus_sys` unmaintained; also a CMake 4 build break) | Fixed in Phase 7 (`opus` 0.4 / `opusic-sys`). |

The remaining `cargo-deny` notices are unmaintained build-time or
table-only crates, or RSA public-key verification inside arti. Each is
justified in `deny.toml` or `desktop/deny.toml`.

### Fuzzing

Coverage-guided fuzzing with libFuzzer and AddressSanitizer
(`fuzz/`, nightly). Each target ran for 10 minutes on 2026-09-26:

| Target | What it reaches | Executions | Crashes / panics |
|---|---|---|---|
| `wire` | Frame and payload parsing, `read_frame` | 9.1 M | none |
| `node_input` | A live node handling any frame from a stranger or a contact, and any MLS payload from a contact (chat, reactions, files, calls, timers, presence, roster) | 0.40 M (slower: each input runs real node logic; 19.6k coverage edges, the most of any target) | none |
| `relay_envelope` | The decrypted contents of a relay envelope | 10.2 M | none |
| `invite_and_relay` | Invite links, relay addresses, relay protocol requests and responses | 18.9 M | none |
| `update_manifest` | Signed-manifest parsing and verification, key files, URLs, versions | 2.2 M | none |
| `call_media` | Call frame decryption, the SDP guard, the Opus decoder | 4.5 M | none |

The first `node_input` run stopped on a LeakSanitizer report. It traced
to the fuzz harness itself (it deliberately leaked a channel). The
harness was fixed, the saved input replayed clean, and the full re-run
above found nothing.

After all the fixes, the whole GUI test passed again over live Tor:
messaging, servers, calls, files, reactions, threads, status, timers,
and relay delivery with the two users never online at the same time.

## 5. Known limits and open questions

Things we already know about and would like an auditor's view on:

1. **At-rest design.** A whole-file envelope with a plaintext working copy
   (P9-02), rather than page-level encryption. Also the Argon2id
   parameters: the crate defaults, the OWASP minimum. Raise them for
   desktops?
2. **MLS for 1:1.** It's a less common use of MLS. Is anything lost
   compared with a Double Ratchet (for example deniability)?
3. **The admin model.** One admin (the creator), with no transfer or
   recovery if their device is lost.
4. **Calls.**
   - A member removed mid-call keeps that call's key until the call ends.
   - The TURN operator sees IPs and timing (disclosed).
   - Echo cancellation is missing.
   - It hasn't been tested across real NATs or with coturn.
5. **Update freeze attacks.** An attacker controlling the release channel
   can withhold updates by serving an old, validly signed manifest. There
   are no staleness warnings yet. One key signs every platform.
6. **Metadata relays can observe:** deposit and fetch timing, and counts
   per mailbox. Envelopes are padded to 1 KiB multiples, not to a fixed
   size.
7. **Presence** reveals online, away and busy status plus a line of text
   to everyone you're connected to.
8. **Disappearing messages** can't be enforced against a modified client.
9. **Untested:**
   - live obfs4 bridges;
   - Windows (none of the code has run there yet);
   - screen sharing (the portal picker);
   - OS keyrings aren't used (the passphrase is the only key source).
10. **Builds aren't reproducible yet.** Users can't independently check
    that a release matches the source.
11. **No post-quantum protection.** The MLS ciphersuite is
    X25519/ChaCha20-Poly1305/Ed25519.

## 6. Build, test, fuzz

```sh
cargo test --workspace                       # everything, on the in-memory network
cargo test -p securetext-net -- --ignored    # live Tor tests
cargo test -p securetext-app --test update_flow -- --ignored   # live update fetch over Tor
cargo clippy --workspace --all-targets       # clean
cargo deny check advisories bans sources     # clean (and in desktop/)
cargo +nightly fuzz run node_input -- -max_total_time=600      # and the other five targets
python3 desktop/e2e/gui_e2e.py --binary <app> --turn … --relay …  # the full GUI test over live Tor
```

The GUI test needs WebKitWebDriver, a display, and (for calls) a TURN
server; see the script's header. releasing.md covers the release
pipeline.
