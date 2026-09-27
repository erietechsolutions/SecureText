//! Rich messaging (Phase 8): threads, reactions, disappearing messages,
//! presence, and encrypted file sharing.
//!
//! What each one reveals, and to whom (docs/feature-parity.md has the
//! full review):
//!
//! - Threads, reactions and timer changes are ordinary MLS messages in the
//!   conversation's group, so only its members see them, exactly like
//!   chat.
//! - Presence goes only to peers this device is connected to (contacts and
//!   co-members), over their Noise sessions. It's never stored by the
//!   receiver, queued, or left at a relay.
//! - Files are encrypted once under a random key that travels only inside
//!   the MLS message. The ciphertext moves peer to peer over Tor, in chunks
//!   pulled by the downloader from anyone in the conversation who has it,
//!   and it's served only to members of that conversation. Relays never
//!   carry files: a download waits until someone who has the file is
//!   online.

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, KeyInit, Payload as AeadPayload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::{clamp_chars, now_ms, random_id, NodeState, Outgoing, MAX_MESSAGE_CHARS};
use crate::store::{AttachmentRow, MessageRow};
use crate::wire::{self, to_hex, AttachmentRef, ConversationKind, Payload, WireMessage};
use crate::{Event, MessageView};

pub const MAX_FILE_BYTES: u64 = 25 * 1024 * 1024;
const CHUNK: u64 = 256 * 1024;
/// Images up to this size download by themselves; everything else waits
/// for the user to ask.
const AUTO_DOWNLOAD_IMAGE: u64 = 8 * 1024 * 1024;
/// Re-ask (possibly someone else) if a chunk hasn't arrived by then.
const CHUNK_TIMEOUT: Duration = Duration::from_secs(20);
const MIN_DISAPPEAR: i64 = 60;
const MAX_DISAPPEAR: i64 = 30 * 24 * 3600;
const MAX_STATUS_TEXT: usize = 80;
const STATUSES: [&str; 3] = ["online", "away", "dnd"];
const INLINE_IMAGE_TYPES: [&str; 4] = ["image/png", "image/jpeg", "image/gif", "image/webp"];

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ReactionView {
    pub emoji: String,
    pub count: u32,
    /// We're one of the reactors (so clicking removes ours).
    pub mine: bool,
    pub by: Vec<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AttachmentView {
    pub file_id: String,
    pub name: String,
    pub mime: String,
    pub size: u64,
    /// "available", "downloading", "complete", "failed".
    pub state: String,
    pub received: u64,
    pub total: u64,
    /// Can be shown inline once downloaded.
    pub image: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AttachmentData {
    pub mime: String,
    /// Base64.
    pub data: String,
}

pub(crate) struct Download {
    source: Option<Vec<u8>>,
    asked: Option<Instant>,
    /// Peers who said they don't have it.
    tried: Vec<Vec<u8>>,
}

pub(crate) struct RichState {
    pub attachments_dir: PathBuf,
    /// Connected peers' statuses: (status, text). Memory only.
    pub presence: HashMap<Vec<u8>, (String, String)>,
    pub my_presence: (String, String),
    pub downloads: HashMap<String, Download>,
}

impl RichState {
    pub fn new(attachments_dir: PathBuf) -> Self {
        Self {
            attachments_dir,
            presence: HashMap::new(),
            my_presence: ("online".into(), String::new()),
            downloads: HashMap::new(),
        }
    }
}

fn file_cipher(key: &[u8]) -> anyhow::Result<ChaCha20Poly1305> {
    anyhow::ensure!(key.len() == 32, "attachment key must be 32 bytes");
    Ok(ChaCha20Poly1305::new(Key::from_slice(key)))
}

/// nonce ‖ ChaCha20-Poly1305(plaintext), bound to the file id.
pub fn encrypt_file(key: &[u8], file_id: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut nonce = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = file_cipher(key)?
        .encrypt(Nonce::from_slice(&nonce), AeadPayload { msg: plaintext, aad: file_id.as_bytes() })
        .map_err(|_| anyhow::anyhow!("encrypting the file failed"))?;
    let mut out = nonce.to_vec();
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_file(key: &[u8], file_id: &str, ciphertext: &[u8]) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(ciphertext.len() > 12, "file is truncated");
    let (nonce, ct) = ciphertext.split_at(12);
    file_cipher(key)?
        .decrypt(Nonce::from_slice(nonce), AeadPayload { msg: ct, aad: file_id.as_bytes() })
        .map_err(|_| anyhow::anyhow!("the file failed its integrity check"))
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().map(|b| format!("{b:02x}")).collect()
}

/// Recognise an image from its first bytes (never trust the sender's MIME
/// type for what gets rendered).
fn sniff_image(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        Some("image/png")
    } else if data.starts_with(b"\xff\xd8\xff") {
        Some("image/jpeg")
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        Some("image/gif")
    } else if data.len() > 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        Some("image/webp")
    } else {
        None
    }
}

/// A name safe to create in the downloads folder: no path separators, no
/// leading dots, no control characters.
pub fn safe_file_name(name: &str) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ' | '(' | ')') { c } else { '_' })
        .collect();
    let cleaned = cleaned.trim().trim_start_matches('.').to_string();
    let cleaned: String = cleaned.chars().take(100).collect();
    if cleaned.is_empty() {
        "attachment".into()
    } else {
        cleaned
    }
}

fn valid_emoji(e: &str) -> bool {
    !e.is_empty() && e.len() <= 32 && e.chars().count() <= 8 && !e.chars().any(|c| c.is_whitespace() || c.is_control())
}

impl NodeState {
    pub(crate) fn attachment_path(&self, file_id: &str, partial: bool) -> PathBuf {
        let safe: String = file_id.chars().filter(|c| c.is_ascii_hexdigit()).take(64).collect();
        self.rich.attachments_dir.join(format!("{safe}.{}", if partial { "part" } else { "bin" }))
    }

    // =================================================================
    // Views
    // =================================================================

    pub(crate) fn message_view(&self, m: &MessageRow) -> MessageView {
        let reactions = self.store.reactions(&m.group_id).unwrap_or_default();
        self.message_view_with(m, &reactions, None)
    }

    pub(crate) fn message_view_with(
        &self,
        m: &MessageRow,
        reactions: &[(String, Vec<u8>, String)],
        reply_count: Option<u32>,
    ) -> MessageView {
        let mut grouped: Vec<ReactionView> = Vec::new();
        for (target, sender, emoji) in reactions.iter().filter(|(t, _, _)| *t == m.id) {
            let _ = target;
            let label = self.label_for(sender);
            let mine = sender.as_slice() == self.my_key();
            match grouped.iter_mut().find(|r| r.emoji == *emoji) {
                Some(r) => {
                    r.count += 1;
                    r.mine |= mine;
                    r.by.push(label);
                }
                None => grouped.push(ReactionView { emoji: emoji.clone(), count: 1, mine, by: vec![label] }),
            }
        }
        let reply_count = reply_count.unwrap_or_else(|| {
            self.store
                .messages(&m.group_id, 1000)
                .map(|all| all.iter().filter(|x| x.reply_to.as_deref() == Some(m.id.as_str())).count() as u32)
                .unwrap_or(0)
        });
        let attachment = m.attachment.as_deref().and_then(|id| self.store.attachment(id).ok().flatten()).map(|a| AttachmentView {
            image: INLINE_IMAGE_TYPES.contains(&a.mime.as_str()),
            file_id: a.file_id,
            name: a.name,
            mime: a.mime,
            size: a.size,
            state: a.state,
            received: a.received,
            total: a.cipher_size,
        });
        MessageView {
            id: m.id.clone(),
            sender_key: to_hex(&m.sender_key),
            sender_label: self.label_for(&m.sender_key),
            body: m.body.clone(),
            sent_at: m.sent_at,
            outgoing: m.outgoing,
            status: m.status.clone(),
            reply_to: m.reply_to.clone(),
            reply_count,
            reactions: grouped,
            attachment,
            expires_at: m.expires_at,
        }
    }

    pub(crate) fn messages(&self, conversation_id: &str, limit: u32) -> anyhow::Result<Vec<MessageView>> {
        let gid = wire::from_hex(conversation_id)?;
        let rows = self.store.messages(&gid, limit.clamp(1, 1000))?;
        let reactions = self.store.reactions(&gid)?;
        let mut replies: HashMap<&str, u32> = HashMap::new();
        for r in &rows {
            if let Some(root) = r.reply_to.as_deref() {
                *replies.entry(root).or_default() += 1;
            }
        }
        Ok(rows
            .iter()
            .map(|m| self.message_view_with(m, &reactions, Some(*replies.get(m.id.as_str()).unwrap_or(&0))))
            .collect())
    }

    fn emit_message_updated(&self, gid: &[u8], message_id: &str) {
        if let Ok(Some(row)) = self.store.message(gid, message_id) {
            let view = self.message_view(&row);
            self.emit(Event::MessageUpdated { conversation_id: to_hex(gid), message: view });
        }
    }

    // =================================================================
    // Sending
    // =================================================================

    /// Post a message (optionally a thread reply, optionally with a file)
    /// to a DM or channel.
    pub(crate) fn post(
        &mut self,
        conversation_id: &str,
        body: &str,
        reply_to: Option<String>,
        attachment: Option<AttachmentRef>,
    ) -> anyhow::Result<MessageView> {
        let body = body.trim();
        anyhow::ensure!(!body.is_empty() || attachment.is_some(), "message is empty");
        anyhow::ensure!(
            body.chars().count() <= MAX_MESSAGE_CHARS,
            "message is longer than {MAX_MESSAGE_CHARS} characters"
        );
        let gid = wire::from_hex(conversation_id)?;
        let conversation = self.active_conversation(&gid)?;
        anyhow::ensure!(conversation.kind != ConversationKind::Server, "post in one of the server's channels");
        self.require_here(&gid, super::perms::SEND_MESSAGES, "send messages")?;
        if attachment.is_some() {
            self.require_here(&gid, super::perms::ATTACH_FILES, "attach files")?;
        }
        if let Some(root) = &reply_to {
            let root_row = self.store.message(&gid, root)?.ok_or_else(|| anyhow::anyhow!("that message is gone"))?;
            anyhow::ensure!(root_row.reply_to.is_none(), "threads don't nest; reply in the original thread");
        }
        let expires_in = self.store.disappear_secs(&gid)?;

        let id = random_id();
        let sent_at = now_ms();
        let payload = Payload::Chat {
            id: id.clone(),
            body: body.to_string(),
            sent_at,
            reply_to: reply_to.clone(),
            expires_in,
            attachment: attachment.clone(),
        };
        let group = self.groups.get_mut(&gid).ok_or_else(|| anyhow::anyhow!("group state missing"))?;
        let ciphertext = self.member.encrypt(group, &payload.to_bytes())?;

        let row = MessageRow {
            id: id.clone(),
            group_id: gid.clone(),
            sender_key: self.public.public_key.clone(),
            body: body.to_string(),
            sent_at,
            outgoing: true,
            status: "pending".into(),
            reply_to: reply_to.clone(),
            expires_at: expires_in.map(|s| sent_at + s * 1000),
            attachment: attachment.as_ref().map(|a| a.file_id.clone()),
        };
        self.store.insert_message(&row)?;
        let recipients = self.fan_out(&gid, &ciphertext, &[], Some(&id))?;
        let status = if recipients == 0 { "sent" } else { "pending" };
        if recipients == 0 {
            self.store.set_message_status(&id, "sent")?;
        }
        self.dirty = true;
        if let Some(root) = &reply_to {
            self.emit_message_updated(&gid, root);
        }
        Ok(self.message_view(&MessageRow { status: status.into(), ..row }))
    }

    /// Share a file: encrypt it under a fresh key, keep the ciphertext for
    /// members to fetch, and post a message carrying the key.
    pub(crate) fn send_file(
        &mut self,
        conversation_id: &str,
        name: &str,
        mime: &str,
        data: &[u8],
        caption: &str,
        reply_to: Option<String>,
    ) -> anyhow::Result<MessageView> {
        anyhow::ensure!(!data.is_empty(), "the file is empty");
        anyhow::ensure!(data.len() as u64 <= MAX_FILE_BYTES, "files are limited to {} MB", MAX_FILE_BYTES / (1024 * 1024));
        let gid = wire::from_hex(conversation_id)?;
        self.active_conversation(&gid)?;
        let file_id = random_id();
        let mut key = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let ciphertext = encrypt_file(&key, &file_id, data)?;
        std::fs::create_dir_all(&self.rich.attachments_dir)?;
        crate::private_dir(&self.rich.attachments_dir)?;
        std::fs::write(self.attachment_path(&file_id, false), &ciphertext)?;
        // Only trust a MIME type we can confirm; anything else is opaque.
        let mime = match sniff_image(data) {
            Some(m) => m.to_string(),
            None if mime.starts_with("image/") => "application/octet-stream".into(),
            None => clamp_chars(mime, 100),
        };
        let reference = AttachmentRef {
            file_id: file_id.clone(),
            name: clamp_chars(&safe_file_name(name), 100),
            mime,
            size: data.len() as u64,
            cipher_size: ciphertext.len() as u64,
            cipher_sha256: sha256_hex(&ciphertext),
            key: key.clone(),
        };
        let view = self.post(conversation_id, caption, reply_to, Some(reference.clone()))?;
        self.store.insert_attachment(&AttachmentRow {
            file_id,
            group_id: gid,
            message_id: view.id.clone(),
            sender_key: self.public.public_key.clone(),
            name: reference.name,
            mime: reference.mime,
            size: reference.size,
            cipher_size: reference.cipher_size,
            cipher_sha256: reference.cipher_sha256,
            key,
            state: "complete".into(),
            received: reference.cipher_size,
        })?;
        self.dirty = true;
        let row = self.store.message(&wire::from_hex(conversation_id)?, &view.id)?.expect("just stored");
        Ok(self.message_view(&row))
    }

    pub(crate) fn react(&mut self, conversation_id: &str, message_id: &str, emoji: &str, on: bool) -> anyhow::Result<MessageView> {
        anyhow::ensure!(valid_emoji(emoji), "that isn't a reaction");
        let gid = wire::from_hex(conversation_id)?;
        let conversation = self.active_conversation(&gid)?;
        self.require_here(&gid, super::perms::ADD_REACTIONS, "add reactions")?;
        anyhow::ensure!(conversation.kind != ConversationKind::Server, "no messages here");
        let row = self.store.message(&gid, message_id)?.ok_or_else(|| anyhow::anyhow!("that message is gone"))?;
        let payload = Payload::Reaction { target: message_id.to_string(), emoji: emoji.to_string(), on };
        let group = self.groups.get_mut(&gid).ok_or_else(|| anyhow::anyhow!("group state missing"))?;
        let ciphertext = self.member.encrypt(group, &payload.to_bytes())?;
        self.store.set_reaction(&gid, message_id, &self.public.public_key.clone(), emoji, on)?;
        self.fan_out(&gid, &ciphertext, &[], None)?;
        self.dirty = true;
        let view = self.message_view(&row);
        self.emit(Event::MessageUpdated { conversation_id: to_hex(&gid), message: view.clone() });
        Ok(view)
    }

    pub(crate) fn set_disappearing(&mut self, conversation_id: &str, secs: Option<i64>) -> anyhow::Result<()> {
        if let Some(s) = secs {
            anyhow::ensure!((MIN_DISAPPEAR..=MAX_DISAPPEAR).contains(&s), "pick between a minute and 30 days");
        }
        let gid = wire::from_hex(conversation_id)?;
        let conversation = self.active_conversation(&gid)?;
        match conversation.kind {
            ConversationKind::Server => anyhow::bail!("set it on a channel"),
            ConversationKind::Channel => self.require(&gid, super::perms::MANAGE_CHANNELS, "change channel timers")?,
            ConversationKind::Dm => {}
        }
        let payload = Payload::Disappear { secs };
        let group = self.groups.get_mut(&gid).ok_or_else(|| anyhow::anyhow!("group state missing"))?;
        let ciphertext = self.member.encrypt(group, &payload.to_bytes())?;
        self.store.set_disappear_secs(&gid, secs)?;
        self.fan_out(&gid, &ciphertext, &[], None)?;
        self.note(&gid, &self.public.public_key.clone(), secs);
        self.dirty = true;
        self.emit(Event::ConversationsChanged);
        Ok(())
    }

    /// A local, system-style line recording a timer change.
    fn note(&mut self, gid: &[u8], who: &[u8], secs: Option<i64>) {
        let body = match secs {
            Some(s) => format!("set messages to disappear after {}", describe_secs(s)),
            None => "turned off disappearing messages".into(),
        };
        let row = MessageRow {
            id: random_id(),
            group_id: gid.to_vec(),
            sender_key: who.to_vec(),
            body,
            sent_at: now_ms(),
            outgoing: who == self.my_key(),
            status: "system".into(),
            ..Default::default()
        };
        if self.store.insert_message(&row).unwrap_or(false) {
            let view = self.message_view(&row);
            self.emit(Event::Message { conversation_id: to_hex(gid), message: view });
        }
    }

    // =================================================================
    // Receiving
    // =================================================================

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_chat(
        &mut self,
        gid: &[u8],
        sender: &[u8],
        id: String,
        body: String,
        sent_at: i64,
        reply_to: Option<String>,
        expires_in: Option<i64>,
        attachment: Option<AttachmentRef>,
    ) -> anyhow::Result<()> {
        let id = clamp_chars(&id, 64);
        // The sender must be allowed to post here (channel rules), and to
        // attach files if there's one. A modified client could send
        // anyway; honest receivers drop it.
        let p = self.permissions_here(gid, sender);
        anyhow::ensure!(p & super::perms::SEND_MESSAGES != 0, "message from someone not allowed to post here");
        anyhow::ensure!(
            attachment.is_none() || p & super::perms::ATTACH_FILES != 0,
            "attachment from someone not allowed to attach files here"
        );
        // A timer from either the message or the conversation, whichever
        // is shorter: deleting early is the safe side of a disagreement.
        let local = self.store.disappear_secs(gid)?;
        let ttl = [expires_in.map(|s| s.clamp(MIN_DISAPPEAR, MAX_DISAPPEAR)), local].into_iter().flatten().min();
        let now = now_ms();
        let row = MessageRow {
            id: id.clone(),
            group_id: gid.to_vec(),
            sender_key: sender.to_vec(),
            body: clamp_chars(&body, MAX_MESSAGE_CHARS),
            sent_at,
            outgoing: false,
            status: "received".into(),
            reply_to: reply_to.map(|r| clamp_chars(&r, 64)),
            // Counted from arrival, so a sender's clock can't make it vanish
            // before it's seen (or linger).
            expires_at: ttl.map(|s| now + s * 1000),
            attachment: attachment.as_ref().map(|a| clamp_chars(&a.file_id, 64)),
        };
        if let Some(a) = &attachment {
            anyhow::ensure!(a.key.len() == 32 && a.cipher_sha256.len() == 64, "malformed attachment");
            anyhow::ensure!(a.size <= MAX_FILE_BYTES && a.cipher_size <= MAX_FILE_BYTES + 64, "attachment too large");
        }
        if !self.store.insert_message(&row)? {
            return Ok(());
        }
        if let Some(a) = attachment {
            let auto = INLINE_IMAGE_TYPES.contains(&a.mime.as_str()) && a.size <= AUTO_DOWNLOAD_IMAGE;
            self.store.insert_attachment(&AttachmentRow {
                file_id: row.attachment.clone().expect("set above"),
                group_id: gid.to_vec(),
                message_id: id.clone(),
                sender_key: sender.to_vec(),
                name: clamp_chars(&safe_file_name(&a.name), 100),
                mime: clamp_chars(&a.mime, 100),
                size: a.size,
                cipher_size: a.cipher_size,
                cipher_sha256: a.cipher_sha256.to_ascii_lowercase(),
                key: a.key,
                state: "available".into(),
                received: 0,
            })?;
            if auto {
                let _ = self.start_download(row.attachment.as_deref().expect("set above"));
            }
        }
        let view = self.message_view(&row);
        self.emit(Event::Message { conversation_id: to_hex(gid), message: view });
        if let Some(root) = &row.reply_to {
            self.emit_message_updated(gid, root);
        }
        Ok(())
    }

    pub(crate) fn on_reaction(&mut self, gid: &[u8], sender: &[u8], target: String, emoji: String, on: bool) -> anyhow::Result<()> {
        anyhow::ensure!(valid_emoji(&emoji), "invalid reaction");
        anyhow::ensure!(
            self.permissions_here(gid, sender) & super::perms::ADD_REACTIONS != 0,
            "reaction from someone not allowed to react here"
        );
        anyhow::ensure!(self.store.message(gid, &target)?.is_some(), "reaction to an unknown message");
        self.store.set_reaction(gid, &target, sender, &emoji, on)?;
        self.emit_message_updated(gid, &target);
        Ok(())
    }

    pub(crate) fn on_disappear(&mut self, gid: &[u8], sender: &[u8], secs: Option<i64>) -> anyhow::Result<()> {
        let conversation = self.store.conversation(gid)?.ok_or_else(|| anyhow::anyhow!("unknown conversation"))?;
        match conversation.kind {
            ConversationKind::Dm => {}
            ConversationKind::Channel => anyhow::ensure!(
                sender == conversation.admin_key || self.permissions_in(gid, sender) & super::perms::MANAGE_CHANNELS != 0,
                "timer change from someone without Manage Channels"
            ),
            ConversationKind::Server => anyhow::bail!("no timer on a server group"),
        }
        let secs = secs.map(|s| s.clamp(MIN_DISAPPEAR, MAX_DISAPPEAR));
        self.store.set_disappear_secs(gid, secs)?;
        self.note(gid, sender, secs);
        self.emit(Event::ConversationsChanged);
        Ok(())
    }

    /// Delete everything whose timer has run out (called every tick).
    pub(crate) fn expire_messages(&mut self) {
        let Ok(gone) = self.store.delete_expired(now_ms()) else { return };
        if gone.is_empty() {
            return;
        }
        let mut by_conv: HashMap<Vec<u8>, Vec<String>> = HashMap::new();
        for (gid, id, attachment) in gone {
            if let Some(file_id) = attachment {
                let _ = std::fs::remove_file(self.attachment_path(&file_id, false));
                let _ = std::fs::remove_file(self.attachment_path(&file_id, true));
                self.rich.downloads.remove(&file_id);
            }
            by_conv.entry(gid).or_default().push(id);
        }
        self.dirty = true;
        for (gid, ids) in by_conv {
            self.emit(Event::MessagesDeleted { conversation_id: to_hex(&gid), ids });
        }
    }

    // =================================================================
    // Presence
    // =================================================================

    pub(crate) fn set_presence(&mut self, status: &str, text: &str) -> anyhow::Result<(String, String)> {
        anyhow::ensure!(STATUSES.contains(&status), "status must be online, away or dnd");
        let text = clamp_chars(text.trim(), MAX_STATUS_TEXT);
        self.rich.my_presence = (status.to_string(), text.clone());
        self.store.set_setting("presence", &serde_json::to_string(&self.rich.my_presence)?)?;
        self.dirty = true;
        for conn in self.connections.values() {
            let _ = conn.tx.send(Outgoing {
                outbox_id: None,
                message: WireMessage::Presence { status: status.to_string(), text: text.clone() },
            });
        }
        Ok(self.rich.my_presence.clone())
    }

    pub(crate) fn load_presence(&mut self) {
        if let Ok(Some(json)) = self.store.get_setting("presence") {
            if let Ok(p) = serde_json::from_str::<(String, String)>(&json) {
                self.rich.my_presence = p;
            }
        }
    }

    pub(crate) fn my_presence_frame(&self) -> WireMessage {
        WireMessage::Presence { status: self.rich.my_presence.0.clone(), text: self.rich.my_presence.1.clone() }
    }

    pub(crate) fn on_presence(&mut self, from: &[u8], status: String, text: String) {
        if !STATUSES.contains(&status.as_str()) || self.store.peer(from).ok().flatten().is_none() {
            return;
        }
        let text = clamp_chars(&text, MAX_STATUS_TEXT);
        self.rich.presence.insert(from.to_vec(), (status.clone(), text.clone()));
        self.emit(Event::Presence { key: to_hex(from), status, text });
    }

    /// "offline", or what they last told us.
    pub(crate) fn presence_of(&self, key: &[u8]) -> (String, String) {
        if key == self.my_key() {
            return self.rich.my_presence.clone();
        }
        if !self.connections.contains_key(key) {
            return ("offline".into(), String::new());
        }
        self.rich.presence.get(key).cloned().unwrap_or_else(|| ("online".into(), String::new()))
    }

    // =================================================================
    // File transfer
    // =================================================================

    pub(crate) fn start_download(&mut self, file_id: &str) -> anyhow::Result<()> {
        let a = self.store.attachment(file_id)?.ok_or_else(|| anyhow::anyhow!("no such file"))?;
        if a.state == "complete" || self.rich.downloads.contains_key(file_id) {
            return Ok(());
        }
        std::fs::create_dir_all(&self.rich.attachments_dir)?;
        crate::private_dir(&self.rich.attachments_dir)?;
        std::fs::File::create(self.attachment_path(file_id, true))?;
        self.store.set_attachment_progress(file_id, "downloading", 0)?;
        self.rich.downloads.insert(file_id.to_string(), Download { source: None, asked: None, tried: Vec::new() });
        self.dirty = true;
        self.request_next_chunk(file_id);
        self.emit_message_updated(&a.group_id, &a.message_id);
        Ok(())
    }

    /// Ask someone who might have the file for the next piece: its sender
    /// first, then any other connected member of the conversation.
    fn request_next_chunk(&mut self, file_id: &str) {
        let Ok(Some(a)) = self.store.attachment(file_id) else { return };
        let Some(dl) = self.rich.downloads.get(file_id) else { return };
        let members = self.group_members(&a.group_id).unwrap_or_default();
        let mut candidates: Vec<Vec<u8>> = vec![a.sender_key.clone()];
        candidates.extend(members.into_iter().filter(|k| *k != a.sender_key));
        let me = self.public.public_key.clone();
        candidates.retain(|k| *k != me);
        let untried: Vec<Vec<u8>> = candidates.iter().filter(|k| !dl.tried.contains(k)).cloned().collect();
        // Prefer someone we haven't tried yet. "Tried" is only a
        // preference: if the only people connected are ones we tried
        // before (say, the sole holder whose connection blipped), ask them
        // again rather than never.
        let source = untried
            .iter()
            .find(|k| self.connections.contains_key(*k))
            .or_else(|| candidates.iter().find(|k| self.connections.contains_key(*k)))
            .cloned();
        let Some(source) = source else {
            // Nobody who might have it is connected: dial them (the sender
            // first), and ask as soon as one of them answers.
            for key in untried.iter().take(6) {
                self.ensure_dial(key);
            }
            if let Some(dl) = self.rich.downloads.get_mut(file_id) {
                dl.source = None;
                dl.asked = Some(Instant::now());
                if dl.tried.len() > 8 {
                    dl.tried.clear();
                }
            }
            return;
        };
        if let Some(conn) = self.connections.get(&source) {
            let _ = conn.tx.send(Outgoing {
                outbox_id: None,
                message: WireMessage::FileRequest { file_id: file_id.to_string(), offset: a.received },
            });
        }
        if let Some(dl) = self.rich.downloads.get_mut(file_id) {
            dl.source = Some(source);
            dl.asked = Some(Instant::now());
        }
    }

    /// Serve a piece of a file we hold, to a member of its conversation.
    pub(crate) fn on_file_request(&mut self, from: &[u8], file_id: String, offset: u64) {
        let reply = (|| -> anyhow::Result<WireMessage> {
            let a = self.store.attachment(&file_id)?.ok_or_else(|| anyhow::anyhow!("unknown"))?;
            anyhow::ensure!(a.state == "complete", "not downloaded");
            anyhow::ensure!(self.group_members(&a.group_id)?.iter().any(|k| k == from), "not a member");
            anyhow::ensure!(offset < a.cipher_size, "bad offset");
            let mut f = std::fs::File::open(self.attachment_path(&file_id, false))?;
            f.seek(SeekFrom::Start(offset))?;
            let mut data = vec![0u8; CHUNK.min(a.cipher_size - offset) as usize];
            f.read_exact(&mut data)?;
            Ok(WireMessage::FileChunk { file_id: file_id.clone(), offset, data })
        })()
        .unwrap_or(WireMessage::FileUnavailable { file_id: file_id.clone() });
        if let Some(conn) = self.connections.get(from) {
            let _ = conn.tx.send(Outgoing { outbox_id: None, message: reply });
        }
    }

    pub(crate) fn on_file_chunk(&mut self, from: &[u8], file_id: String, offset: u64, data: Vec<u8>) -> anyhow::Result<()> {
        if !self.rich.downloads.contains_key(&file_id) {
            return Ok(());
        }
        let a = self.store.attachment(&file_id)?.ok_or_else(|| anyhow::anyhow!("unknown file"))?;
        // Usually from the peer we asked last, but an earlier source's
        // reply can arrive after we switched. Any member's chunk at the
        // right offset is fine: the whole file is checked against its
        // MLS-carried hash at the end.
        anyhow::ensure!(self.group_members(&a.group_id)?.iter().any(|k| k == from), "file chunk from a non-member");
        anyhow::ensure!(offset == a.received, "out-of-order chunk");
        anyhow::ensure!(!data.is_empty() && a.received + data.len() as u64 <= a.cipher_size, "chunk overruns the file");
        let mut f = std::fs::OpenOptions::new().append(true).open(self.attachment_path(&file_id, true))?;
        f.write_all(&data)?;
        let received = a.received + data.len() as u64;
        if received < a.cipher_size {
            self.store.set_attachment_progress(&file_id, "downloading", received)?;
            self.request_next_chunk(&file_id);
            // Progress updates at most every ~1 MB, to keep the UI quiet.
            if received % (4 * CHUNK) < CHUNK {
                self.emit_message_updated(&a.group_id, &a.message_id);
            }
            return Ok(());
        }
        // Complete: it must be exactly what the MLS-authenticated message
        // described.
        f.sync_all()?;
        drop(f);
        self.rich.downloads.remove(&file_id);
        let partial = self.attachment_path(&file_id, true);
        let bytes = std::fs::read(&partial)?;
        if sha256_hex(&bytes) != a.cipher_sha256 {
            let _ = std::fs::remove_file(&partial);
            self.store.set_attachment_progress(&file_id, "failed", 0)?;
            self.emit_message_updated(&a.group_id, &a.message_id);
            anyhow::bail!("downloaded file doesn't match its hash; discarded");
        }
        std::fs::rename(&partial, self.attachment_path(&file_id, false))?;
        self.store.set_attachment_progress(&file_id, "complete", received)?;
        self.dirty = true;
        self.emit_message_updated(&a.group_id, &a.message_id);
        Ok(())
    }

    pub(crate) fn on_file_unavailable(&mut self, from: &[u8], file_id: String) {
        if let Some(dl) = self.rich.downloads.get_mut(&file_id) {
            if dl.source.as_deref() == Some(from) {
                dl.tried.push(from.to_vec());
                dl.source = None;
                self.request_next_chunk(&file_id);
            }
        }
    }

    /// A peer just connected: downloads waiting for someone to ask can ask
    /// now.
    pub(crate) fn downloads_on_connect(&mut self) {
        let waiting: Vec<String> =
            self.rich.downloads.iter().filter(|(_, d)| d.source.is_none()).map(|(k, _)| k.clone()).collect();
        for file_id in waiting {
            self.request_next_chunk(&file_id);
        }
    }

    /// A peer went away: any download it was serving moves on to someone
    /// else now, instead of waiting out `CHUNK_TIMEOUT` for a reply that
    /// can't come.
    pub(crate) fn downloads_on_disconnect(&mut self, peer: &[u8]) {
        let affected: Vec<String> = self
            .rich
            .downloads
            .iter()
            .filter(|(_, d)| d.source.as_deref() == Some(peer))
            .map(|(k, _)| k.clone())
            .collect();
        for file_id in affected {
            if let Some(d) = self.rich.downloads.get_mut(&file_id) {
                d.source = None;
                d.tried.push(peer.to_vec());
            }
            self.request_next_chunk(&file_id);
        }
    }

    /// Resume stalled downloads (called every tick).
    pub(crate) fn download_tick(&mut self) {
        let stalled: Vec<String> = self
            .rich
            .downloads
            .iter()
            .filter(|(_, d)| d.asked.is_none_or(|t| t.elapsed() > CHUNK_TIMEOUT) || d.source.is_none())
            .map(|(k, _)| k.clone())
            .collect();
        for file_id in stalled {
            if let Some(d) = self.rich.downloads.get_mut(&file_id) {
                if let Some(s) = d.source.take() {
                    d.tried.push(s);
                }
            }
            self.request_next_chunk(&file_id);
        }
    }

    /// Downloads interrupted by a restart pick up where they left off.
    pub(crate) fn resume_downloads(&mut self) {
        for file_id in self.store.downloading_attachments().unwrap_or_default() {
            let partial = self.attachment_path(&file_id, true);
            let have = std::fs::metadata(&partial).map(|m| m.len()).unwrap_or(0);
            let _ = self.store.set_attachment_progress(&file_id, "downloading", have);
            if have == 0 {
                let _ = std::fs::File::create(&partial);
            }
            self.rich.downloads.insert(file_id, Download { source: None, asked: None, tried: Vec::new() });
        }
    }

    fn decrypted(&self, file_id: &str) -> anyhow::Result<(AttachmentRow, Vec<u8>)> {
        let a = self.store.attachment(file_id)?.ok_or_else(|| anyhow::anyhow!("no such file"))?;
        anyhow::ensure!(a.state == "complete", "the file hasn't been downloaded yet");
        let ciphertext = std::fs::read(self.attachment_path(file_id, false))?;
        let plain = decrypt_file(&a.key, file_id, &ciphertext)?;
        Ok((a, plain))
    }

    /// An image's bytes for inline display. Only formats recognised from
    /// the data itself are returned.
    pub(crate) fn attachment_data(&self, file_id: &str) -> anyhow::Result<AttachmentData> {
        let (_, plain) = self.decrypted(file_id)?;
        let mime = sniff_image(&plain).ok_or_else(|| anyhow::anyhow!("not an image"))?;
        Ok(AttachmentData {
            mime: mime.into(),
            data: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, plain),
        })
    }

    /// Decrypt a file into the user's downloads folder (a fresh name if
    /// one is taken). Returns where it went.
    pub(crate) fn save_attachment(&self, file_id: &str, dir: Option<PathBuf>) -> anyhow::Result<String> {
        let (a, plain) = self.decrypted(file_id)?;
        let dir = dir
            .or_else(|| directories::UserDirs::new().and_then(|u| u.download_dir().map(PathBuf::from)))
            .or_else(|| directories::UserDirs::new().map(|u| u.home_dir().to_path_buf()))
            .ok_or_else(|| anyhow::anyhow!("no downloads folder found"))?;
        std::fs::create_dir_all(&dir)?;
        let name = safe_file_name(&a.name);
        let (stem, ext) = match name.rsplit_once('.') {
            Some((s, e)) if !s.is_empty() => (s.to_string(), format!(".{e}")),
            _ => (name.clone(), String::new()),
        };
        for n in 0..1000 {
            let candidate = if n == 0 { dir.join(&name) } else { dir.join(format!("{stem} ({n}){ext}")) };
            match std::fs::OpenOptions::new().write(true).create_new(true).open(&candidate) {
                Ok(mut f) => {
                    f.write_all(&plain)?;
                    return Ok(candidate.display().to_string());
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        anyhow::bail!("couldn't find a free file name in {}", dir.display())
    }
}

pub fn describe_secs(s: i64) -> String {
    match s {
        s if s % 86_400 == 0 => plural(s / 86_400, "day"),
        s if s % 3_600 == 0 => plural(s / 3_600, "hour"),
        s if s % 60 == 0 => plural(s / 60, "minute"),
        s => plural(s, "second"),
    }
}

fn plural(n: i64, unit: &str) -> String {
    if n == 1 {
        format!("1 {unit}")
    } else {
        format!("{n} {unit}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_decrypt_only_with_their_key_and_id() {
        let key = vec![7u8; 32];
        let ct = encrypt_file(&key, "f1", b"secret plans").unwrap();
        assert!(!ct.windows(12).any(|w| w == b"secret plans"));
        assert_eq!(decrypt_file(&key, "f1", &ct).unwrap(), b"secret plans");
        assert!(decrypt_file(&key, "f2", &ct).is_err(), "bound to its id");
        assert!(decrypt_file(&[8u8; 32], "f1", &ct).is_err(), "wrong key");
    }

    #[test]
    fn file_names_cannot_escape_the_downloads_folder() {
        assert_eq!(safe_file_name("../../.bashrc"), "_.._.bashrc");
        assert_eq!(safe_file_name(".hidden"), "hidden");
        assert_eq!(safe_file_name("a/b\\c.txt"), "a_b_c.txt");
        assert_eq!(safe_file_name(""), "attachment");
        assert_eq!(safe_file_name("photo (1).jpg"), "photo (1).jpg");
    }

    #[test]
    fn only_real_images_are_treated_as_images() {
        assert_eq!(sniff_image(b"\x89PNG\r\n\x1a\nrest"), Some("image/png"));
        assert_eq!(sniff_image(b"<svg onload=alert(1)>"), None, "SVG is never rendered inline");
        assert_eq!(sniff_image(b"GIF89a..."), Some("image/gif"));
    }

    #[test]
    fn reactions_are_short_and_printable() {
        assert!(valid_emoji("👍"));
        assert!(valid_emoji("❤️"));
        assert!(!valid_emoji(""));
        assert!(!valid_emoji("a b"));
        assert!(!valid_emoji(&"x".repeat(40)));
    }

    #[test]
    fn timers_read_naturally() {
        assert_eq!(describe_secs(86_400), "1 day");
        assert_eq!(describe_secs(7 * 86_400), "7 days");
        assert_eq!(describe_secs(3_600), "1 hour");
        assert_eq!(describe_secs(300), "5 minutes");
    }
}
