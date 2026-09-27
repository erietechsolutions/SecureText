# Feature Parity & Metadata Review

Roadmap Phase 8's exit criterion: a feature-parity checklist against the
original "Discord-like" goal, with each feature re-checked against
threat-model.md for new metadata leakage.

Legend: ✅ built and verified · 🟡 partly there · ⬜ not built

## Checklist

| Discord-like feature | SecureText | Notes |
|---|---|---|
| Direct messages | ✅ | 2-member MLS groups (Phases 1, 4) |
| Group DMs | 🟡 | Not a separate kind; a private channel in a small server does the job |
| Servers with channels | ✅ | Phase 3 |
| Private channels | ✅ | Their own MLS group, so non-members can't decrypt them |
| Roles & permissions | 🟡 | One role, the admin (the creator). No custom roles or moderators |
| Invites | ✅ | Single-use invite links for contacts; admins invite contacts to servers |
| Kick / remove | ✅ | Re-keys everything the member was in |
| Offline delivery | ✅ | Relays (Phase 5) |
| Voice calls | ✅ | Phase 7; the disclosed non-Tor exception |
| Video calls | ✅ | Phase 7; low resolution |
| Screen sharing | 🟡 | Built on the system picker; not verified |
| File & image sharing | ✅ | Up to 25 MB; images inline |
| Reactions | ✅ | |
| Threads / replies | ✅ | One level of threads |
| Presence & custom status | ✅ | Online / away / do not disturb, plus a short message |
| Disappearing messages | ✅ | Per conversation; 1 hour / 1 day / 1 week, or custom 1 min–30 days via the API |
| Editing & deleting messages | ⬜ | |
| Mentions & notifications | ⬜ | No @mentions and no OS notifications yet |
| Search | ⬜ | |
| Pins | ⬜ | |
| Custom emoji, stickers, GIFs | ⬜ | Any Unicode emoji works as a reaction |
| Bots / integrations | ⬜ | architecture.md §8 sketches client-side moderation bots |
| Multi-device (one account, several devices) | ⬜ | Each device is its own identity |
| Mobile apps | ⬜ | Phases 10–11 |

## Metadata review of the Phase 8 features

The question for each feature is what it reveals, to whom, beyond what
chat already did. The baseline:

- The members of a conversation see its messages and who sent them.
- Connected peers see that you're online (a live connection).
- Relays see only padded, sealed blobs in anonymous mailboxes.

| Feature | Who learns what | New leakage? | Why it's acceptable / mitigations |
|---|---|---|---|
| **Threads** | Members see which message a reply belongs to. | No | The link travels inside the MLS-encrypted message, like the text. |
| **Reactions** | Members see who reacted with what. | No | An MLS message in the group. Relays see only another padded blob. |
| **Disappearing timer** | Members see the timer and who changed it (shown as a note). | No | An MLS message. Expiry counts from **arrival**, so a sender's clock can't make a message vanish unseen or linger. Deleted rows are **overwritten** (SQLite `secure_delete`) before the next seal of the encrypted profile. Verified by scanning the database file for the text. |
| **Presence / status** | Peers you're *currently connected to* (contacts and co-members) see your status and status text. | Slight | Connected peers could already see you were online; status adds "away"/"busy" and a line of text. It goes only over the authenticated Noise session. It's never stored by the receiver, never queued, never relayed, and reads "offline" as soon as the connection drops. Users choose whether to set any text. |
| **Files** | Members get the file. Whoever serves a chunk learns that the requester wanted that file. | Slight | The file is encrypted under a key that exists only inside the MLS message. The ciphertext moves peer to peer over Tor (onion services), so no IP is exposed. Chunks are served **only to members** of the conversation (tested). A server learns which member downloaded which file, which a member could infer anyway. A peer serving a file sees its size, as the sender did. Relays never carry files. |
| **Images inline** | Nobody new. | No | The image is decoded locally. Only PNG, JPEG, GIF and WebP recognised **from the bytes themselves** are ever rendered (never SVG, never trusting the sender's MIME type). The app's content-security policy still forbids any remote load. |
| **Calls** (Phase 7) | The TURN relay operator sees participants' IPs and call timing. | **Yes (disclosed)** | The one deliberate exception (threat-model.md). Other participants never see your IP, and the user is told before every call. |

## Honest limits

- **Disappearing messages can't be forced on a recipient.** A modified app,
  a screenshot or a copy can keep a message; the UI says so. The same is
  true of every messenger with this feature.
- **Status text is visible** to everyone you're connected to, not
  per-contact.
- **File availability:** a file can be fetched only while someone who has
  it is online. There's no relay storage for files, by choice: they're
  large, and relays are meant to stay small and blind.
- **Timers apply per message.** Changing the timer doesn't retroactively
  change messages already received.
