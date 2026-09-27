//! The application's own tables: peers, conversations, message history,
//! other peers' key packages, and the outgoing queue.
//!
//! They live in the same SQLite file as the identity keys and MLS group
//! state (`IdentityStore::db_path`), so they're covered by the same
//! whole-file Argon2id + ChaCha20-Poly1305 envelope at rest
//! (`securetext-identity`'s module docs). Message history is exactly the
//! kind of data a stolen device must not expose.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};

use securetext_invite::RelayCard;

use crate::wire::{ConversationInfo, ConversationKind, SignedCard, WireMessage};

pub struct Store {
    conn: Connection,
}

#[derive(Clone, Debug)]
pub struct PeerRow {
    pub mls_key: Vec<u8>,
    pub label: String,
    pub onion_address: String,
    pub noise_key: Vec<u8>,
    pub is_contact: bool,
    /// Where to leave messages for them while they're offline.
    pub relay: Option<RelayCard>,
}

#[derive(Clone, Debug)]
pub struct ConversationRow {
    pub group_id: Vec<u8>,
    pub kind: ConversationKind,
    pub name: String,
    pub server_id: Option<Vec<u8>>,
    pub admin_key: Vec<u8>,
    pub private: bool,
    pub removed: bool,
    pub created_at: i64,
}

impl ConversationRow {
    pub fn from_info(group_id: Vec<u8>, info: &ConversationInfo, created_at: i64) -> Self {
        Self {
            group_id,
            kind: info.kind,
            name: info.name.clone(),
            server_id: info.server_group_id.clone(),
            admin_key: info.admin_public_key.clone(),
            private: info.private,
            removed: false,
            created_at,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct MessageRow {
    pub id: String,
    pub group_id: Vec<u8>,
    pub sender_key: Vec<u8>,
    pub body: String,
    pub sent_at: i64,
    pub outgoing: bool,
    pub status: String,
    /// The thread this is a reply in (the root message's id).
    pub reply_to: Option<String>,
    /// When this message deletes itself (disappearing messages), ms.
    pub expires_at: Option<i64>,
    /// The attached file's id, if any.
    pub attachment: Option<String>,
}

/// A file shared in a conversation. The ciphertext lives outside the
/// database (`attachments/<id>.bin` in the profile), encrypted under `key`,
/// which only lives here, inside the encrypted profile.
#[derive(Clone, Debug)]
pub struct AttachmentRow {
    pub file_id: String,
    pub group_id: Vec<u8>,
    pub message_id: String,
    pub sender_key: Vec<u8>,
    pub name: String,
    pub mime: String,
    /// Plaintext size.
    pub size: u64,
    /// Ciphertext size and SHA-256 (hex): what a download must match.
    pub cipher_size: u64,
    pub cipher_sha256: String,
    pub key: Vec<u8>,
    /// "available" (known, not downloaded), "downloading", "complete",
    /// "failed".
    pub state: String,
    /// Ciphertext bytes received so far (while downloading).
    pub received: u64,
}

/// An expired message: (conversation, message id, attachment id).
pub type Expired = (Vec<u8>, String, Option<String>);

pub struct OutboxRow {
    pub id: i64,
    pub frame: WireMessage,
}

impl Store {
    pub fn open(db_path: &Path) -> anyhow::Result<Self> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS app_peers (
                mls_key BLOB PRIMARY KEY,
                label TEXT NOT NULL,
                onion_address TEXT NOT NULL,
                noise_key BLOB NOT NULL,
                card_json TEXT,
                is_contact INTEGER NOT NULL DEFAULT 0,
                relay_json TEXT
            );
            CREATE TABLE IF NOT EXISTS app_conversations (
                group_id BLOB PRIMARY KEY,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                server_id BLOB,
                admin_key BLOB NOT NULL,
                private INTEGER NOT NULL DEFAULT 0,
                removed INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS app_messages (
                group_id BLOB NOT NULL,
                id TEXT NOT NULL,
                sender_key BLOB NOT NULL,
                body TEXT NOT NULL,
                sent_at INTEGER NOT NULL,
                outgoing INTEGER NOT NULL,
                status TEXT NOT NULL,
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                UNIQUE (group_id, id)
            );
            CREATE TABLE IF NOT EXISTS app_peer_key_packages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_key BLOB NOT NULL,
                key_package BLOB NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS app_peer_key_packages_unique
                ON app_peer_key_packages (key_package);
            -- Key packages already used, so a late duplicate delivery of one
            -- can't put it back in the pool (they're single-use).
            CREATE TABLE IF NOT EXISTS app_used_key_packages (
                key_package BLOB PRIMARY KEY
            );
            CREATE TABLE IF NOT EXISTS app_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_key BLOB NOT NULL,
                frame TEXT NOT NULL,
                msg_ref TEXT,
                created_at INTEGER NOT NULL
            );",
        )?;
        // Columns added after the table first shipped (older profiles lack
        // them): relay cards (Phase 5); threads, disappearing messages and
        // attachments (Phase 8).
        for (table, column, ty) in [
            ("app_peers", "relay_json", "TEXT"),
            ("app_messages", "reply_to", "TEXT"),
            ("app_messages", "expires_at", "INTEGER"),
            ("app_messages", "attachment", "TEXT"),
            ("app_conversations", "disappear_secs", "INTEGER"),
        ] {
            if conn.prepare(&format!("SELECT {column} FROM {table} LIMIT 0")).is_err() {
                conn.execute_batch(&format!("ALTER TABLE {table} ADD COLUMN {column} {ty};"))?;
            }
        }
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS app_reactions (
                group_id BLOB NOT NULL,
                message_id TEXT NOT NULL,
                sender_key BLOB NOT NULL,
                emoji TEXT NOT NULL,
                PRIMARY KEY (group_id, message_id, sender_key, emoji)
            );
            CREATE TABLE IF NOT EXISTS app_attachments (
                file_id TEXT PRIMARY KEY,
                group_id BLOB NOT NULL,
                message_id TEXT NOT NULL,
                sender_key BLOB NOT NULL,
                name TEXT NOT NULL,
                mime TEXT NOT NULL,
                size INTEGER NOT NULL,
                cipher_size INTEGER NOT NULL,
                cipher_sha256 TEXT NOT NULL,
                key BLOB NOT NULL,
                state TEXT NOT NULL,
                received INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS app_messages_expiry ON app_messages (expires_at)
                WHERE expires_at IS NOT NULL;
            -- Deleted rows (expired messages above all) are overwritten,
            -- not just unlinked, before the profile is next sealed.
            PRAGMA secure_delete = ON;",
        )?;
        Ok(Self { conn })
    }

    pub fn get_setting(&self, key: &str) -> anyhow::Result<Option<String>> {
        Ok(self
            .conn
            .query_row("SELECT value FROM app_settings WHERE key = ?1", params![key], |r| r.get(0))
            .optional()?)
    }

    pub fn delete_setting(&self, key: &str) -> anyhow::Result<()> {
        self.conn.execute("DELETE FROM app_settings WHERE key = ?1", params![key])?;
        Ok(())
    }

    pub fn set_setting(&self, key: &str, value: &str) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO app_settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    // ---- peers ----

    pub fn upsert_peer(&self, peer: &PeerRow, card: Option<&SignedCard>) -> anyhow::Result<()> {
        let card_json = card.map(|c| serde_json::to_string(c).expect("SignedCard serializes"));
        let relay_json = peer.relay.as_ref().map(|r| serde_json::to_string(r).expect("RelayCard serializes"));
        self.conn.execute(
            "INSERT INTO app_peers (mls_key, label, onion_address, noise_key, card_json, is_contact, relay_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(mls_key) DO UPDATE SET
                label = excluded.label,
                onion_address = excluded.onion_address,
                noise_key = excluded.noise_key,
                card_json = COALESCE(excluded.card_json, app_peers.card_json),
                is_contact = MAX(app_peers.is_contact, excluded.is_contact),
                relay_json = excluded.relay_json",
            params![
                peer.mls_key,
                peer.label,
                peer.onion_address,
                peer.noise_key,
                card_json,
                peer.is_contact as i64,
                relay_json
            ],
        )?;
        Ok(())
    }

    pub fn peer(&self, mls_key: &[u8]) -> anyhow::Result<Option<PeerRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT mls_key, label, onion_address, noise_key, is_contact, relay_json FROM app_peers WHERE mls_key = ?1",
                params![mls_key],
                peer_from_row,
            )
            .optional()?)
    }

    pub fn peer_card(&self, mls_key: &[u8]) -> anyhow::Result<Option<SignedCard>> {
        let json: Option<Option<String>> = self
            .conn
            .query_row("SELECT card_json FROM app_peers WHERE mls_key = ?1", params![mls_key], |r| r.get(0))
            .optional()?;
        Ok(match json.flatten() {
            Some(json) => Some(serde_json::from_str(&json)?),
            None => None,
        })
    }

    pub fn peers(&self) -> anyhow::Result<Vec<PeerRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT mls_key, label, onion_address, noise_key, is_contact, relay_json FROM app_peers ORDER BY label COLLATE NOCASE",
        )?;
        let rows = stmt.query_map([], peer_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // ---- conversations ----

    pub fn insert_conversation(&self, row: &ConversationRow) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO app_conversations
                (group_id, kind, name, server_id, admin_key, private, removed, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                row.group_id,
                row.kind.as_str(),
                row.name,
                row.server_id,
                row.admin_key,
                row.private as i64,
                row.removed as i64,
                row.created_at
            ],
        )?;
        Ok(())
    }

    pub fn conversation(&self, group_id: &[u8]) -> anyhow::Result<Option<ConversationRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT group_id, kind, name, server_id, admin_key, private, removed, created_at
                 FROM app_conversations WHERE group_id = ?1",
                params![group_id],
                conversation_from_row,
            )
            .optional()?)
    }

    pub fn conversations(&self) -> anyhow::Result<Vec<ConversationRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id, kind, name, server_id, admin_key, private, removed, created_at
             FROM app_conversations ORDER BY created_at, name",
        )?;
        let rows = stmt.query_map([], conversation_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn channels_of(&self, server_id: &[u8]) -> anyhow::Result<Vec<ConversationRow>> {
        Ok(self
            .conversations()?
            .into_iter()
            .filter(|c| c.kind == ConversationKind::Channel && c.server_id.as_deref() == Some(server_id))
            .collect())
    }

    pub fn mark_removed(&self, group_id: &[u8]) -> anyhow::Result<()> {
        self.conn
            .execute("UPDATE app_conversations SET removed = 1 WHERE group_id = ?1", params![group_id])?;
        Ok(())
    }

    // ---- messages ----

    /// Returns false if a message with this id was already stored (a
    /// duplicate delivery, e.g. the same frame arriving both directly and
    /// via a relay).
    pub fn insert_message(&self, m: &MessageRow) -> anyhow::Result<bool> {
        let inserted = self.conn.execute(
            "INSERT OR IGNORE INTO app_messages
                (group_id, id, sender_key, body, sent_at, outgoing, status, reply_to, expires_at, attachment)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                m.group_id,
                m.id,
                m.sender_key,
                m.body,
                m.sent_at,
                m.outgoing as i64,
                m.status,
                m.reply_to,
                m.expires_at,
                m.attachment
            ],
        )?;
        Ok(inserted > 0)
    }

    pub fn set_message_status(&self, id: &str, status: &str) -> anyhow::Result<Option<Vec<u8>>> {
        let group_id: Option<Vec<u8>> = self
            .conn
            .query_row("SELECT group_id FROM app_messages WHERE id = ?1", params![id], |r| r.get(0))
            .optional()?;
        self.conn
            .execute("UPDATE app_messages SET status = ?2 WHERE id = ?1", params![id, status])?;
        Ok(group_id)
    }

    pub fn messages(&self, group_id: &[u8], limit: u32) -> anyhow::Result<Vec<MessageRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, group_id, sender_key, body, sent_at, outgoing, status, reply_to, expires_at, attachment FROM (
                SELECT * FROM app_messages WHERE group_id = ?1 ORDER BY seq DESC LIMIT ?2
             ) ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map(params![group_id, limit], message_from_row)?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    pub fn message(&self, group_id: &[u8], id: &str) -> anyhow::Result<Option<MessageRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, group_id, sender_key, body, sent_at, outgoing, status, reply_to, expires_at, attachment
                 FROM app_messages WHERE group_id = ?1 AND id = ?2",
                params![group_id, id],
                message_from_row,
            )
            .optional()?)
    }

    /// Delete every message whose time is up, with its reactions and
    /// attachment records. Returns (conversation, message id, attachment)
    /// for each, so the caller can remove attachment files and tell the UI.
    pub fn delete_expired(&self, now: i64) -> anyhow::Result<Vec<Expired>> {
        let mut stmt = self.conn.prepare(
            "SELECT group_id, id, attachment FROM app_messages WHERE expires_at IS NOT NULL AND expires_at <= ?1",
        )?;
        let gone: Vec<Expired> = stmt
            .query_map(params![now], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<Result<_, _>>()?;
        for (gid, id, attachment) in &gone {
            self.conn.execute("DELETE FROM app_messages WHERE group_id = ?1 AND id = ?2", params![gid, id])?;
            self.conn
                .execute("DELETE FROM app_reactions WHERE group_id = ?1 AND message_id = ?2", params![gid, id])?;
            if let Some(file_id) = attachment {
                self.conn.execute("DELETE FROM app_attachments WHERE file_id = ?1", params![file_id])?;
            }
        }
        Ok(gone)
    }

    #[cfg(test)]
    pub fn force_expired(&self, id: &str) -> anyhow::Result<()> {
        self.conn.execute("UPDATE app_messages SET expires_at = 1 WHERE id = ?1", params![id])?;
        Ok(())
    }

    // ---- conversation settings ----

    pub fn disappear_secs(&self, group_id: &[u8]) -> anyhow::Result<Option<i64>> {
        Ok(self
            .conn
            .query_row(
                "SELECT disappear_secs FROM app_conversations WHERE group_id = ?1",
                params![group_id],
                |r| r.get::<_, Option<i64>>(0),
            )
            .optional()?
            .flatten())
    }

    pub fn set_disappear_secs(&self, group_id: &[u8], secs: Option<i64>) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE app_conversations SET disappear_secs = ?2 WHERE group_id = ?1",
            params![group_id, secs],
        )?;
        Ok(())
    }

    // ---- reactions ----

    pub fn set_reaction(&self, group_id: &[u8], message_id: &str, sender: &[u8], emoji: &str, on: bool) -> anyhow::Result<()> {
        if on {
            self.conn.execute(
                "INSERT OR IGNORE INTO app_reactions (group_id, message_id, sender_key, emoji) VALUES (?1, ?2, ?3, ?4)",
                params![group_id, message_id, sender, emoji],
            )?;
        } else {
            self.conn.execute(
                "DELETE FROM app_reactions WHERE group_id = ?1 AND message_id = ?2 AND sender_key = ?3 AND emoji = ?4",
                params![group_id, message_id, sender, emoji],
            )?;
        }
        Ok(())
    }

    /// Every reaction in a conversation: (message id, sender, emoji).
    pub fn reactions(&self, group_id: &[u8]) -> anyhow::Result<Vec<(String, Vec<u8>, String)>> {
        let mut stmt = self
            .conn
            .prepare("SELECT message_id, sender_key, emoji FROM app_reactions WHERE group_id = ?1 ORDER BY rowid")?;
        let rows = stmt.query_map(params![group_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // ---- attachments ----

    pub fn insert_attachment(&self, a: &AttachmentRow) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO app_attachments
                (file_id, group_id, message_id, sender_key, name, mime, size, cipher_size, cipher_sha256, key, state, received)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                a.file_id,
                a.group_id,
                a.message_id,
                a.sender_key,
                a.name,
                a.mime,
                a.size as i64,
                a.cipher_size as i64,
                a.cipher_sha256,
                a.key,
                a.state,
                a.received as i64
            ],
        )?;
        Ok(())
    }

    pub fn attachment(&self, file_id: &str) -> anyhow::Result<Option<AttachmentRow>> {
        Ok(self
            .conn
            .query_row(
                "SELECT file_id, group_id, message_id, sender_key, name, mime, size, cipher_size, cipher_sha256, key, state, received
                 FROM app_attachments WHERE file_id = ?1",
                params![file_id],
                |r| {
                    Ok(AttachmentRow {
                        file_id: r.get(0)?,
                        group_id: r.get(1)?,
                        message_id: r.get(2)?,
                        sender_key: r.get(3)?,
                        name: r.get(4)?,
                        mime: r.get(5)?,
                        size: r.get::<_, i64>(6)? as u64,
                        cipher_size: r.get::<_, i64>(7)? as u64,
                        cipher_sha256: r.get(8)?,
                        key: r.get(9)?,
                        state: r.get(10)?,
                        received: r.get::<_, i64>(11)? as u64,
                    })
                },
            )
            .optional()?)
    }

    pub fn set_attachment_progress(&self, file_id: &str, state: &str, received: u64) -> anyhow::Result<()> {
        self.conn.execute(
            "UPDATE app_attachments SET state = ?2, received = ?3 WHERE file_id = ?1",
            params![file_id, state, received as i64],
        )?;
        Ok(())
    }

    /// Attachments currently being downloaded.
    pub fn downloading_attachments(&self) -> anyhow::Result<Vec<String>> {
        let mut stmt = self.conn.prepare("SELECT file_id FROM app_attachments WHERE state = 'downloading'")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // ---- other peers' key packages ----

    pub fn add_peer_key_package(&self, peer_key: &[u8], key_package: &[u8]) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO app_peer_key_packages (peer_key, key_package)
             SELECT ?1, ?2 WHERE NOT EXISTS (SELECT 1 FROM app_used_key_packages WHERE key_package = ?2)",
            params![peer_key, key_package],
        )?;
        Ok(())
    }

    pub fn peer_key_package_count(&self, peer_key: &[u8]) -> anyhow::Result<u32> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM app_peer_key_packages WHERE peer_key = ?1",
            params![peer_key],
            |r| r.get(0),
        )?)
    }

    /// Remove and return one of `peer_key`'s key packages. Key packages
    /// are single-use (RFC 9420 §10), so it's deleted whether or not the
    /// caller's add succeeds.
    pub fn take_peer_key_package(&self, peer_key: &[u8]) -> anyhow::Result<Option<Vec<u8>>> {
        let row: Option<(i64, Vec<u8>)> = self
            .conn
            .query_row(
                "SELECT id, key_package FROM app_peer_key_packages WHERE peer_key = ?1 ORDER BY id LIMIT 1",
                params![peer_key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        Ok(match row {
            Some((id, kp)) => {
                self.conn.execute("DELETE FROM app_peer_key_packages WHERE id = ?1", params![id])?;
                self.conn.execute(
                    "INSERT OR IGNORE INTO app_used_key_packages (key_package) VALUES (?1)",
                    params![kp],
                )?;
                Some(kp)
            }
            None => None,
        })
    }

    // ---- outbox ----

    pub fn enqueue(&self, peer_key: &[u8], frame: &WireMessage, msg_ref: Option<&str>, now: i64) -> anyhow::Result<i64> {
        self.conn.execute(
            "INSERT INTO app_outbox (peer_key, frame, msg_ref, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![peer_key, serde_json::to_string(frame)?, msg_ref, now],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    pub fn outbox_for(&self, peer_key: &[u8]) -> anyhow::Result<Vec<OutboxRow>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, frame FROM app_outbox WHERE peer_key = ?1 ORDER BY id",
        )?;
        let rows = stmt.query_map(params![peer_key], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?;
        let mut out = Vec::new();
        for row in rows {
            let (id, frame) = row?;
            out.push(OutboxRow { id, frame: serde_json::from_str(&frame)? });
        }
        Ok(out)
    }

    pub fn peers_with_outbox(&self) -> anyhow::Result<Vec<Vec<u8>>> {
        let mut stmt = self.conn.prepare("SELECT DISTINCT peer_key FROM app_outbox")?;
        let rows = stmt.query_map([], |r| r.get(0))?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Delete a delivered outbox entry, if it's one queued for `peer_key`
    /// (so one peer can't acknowledge away what's queued for another).
    /// Returns its `msg_ref` and how many entries for that same message
    /// are still undelivered.
    pub fn outbox_delivered(&self, id: i64, peer_key: &[u8]) -> anyhow::Result<Option<(String, u32)>> {
        let msg_ref: Option<Option<String>> = self
            .conn
            .query_row(
                "SELECT msg_ref FROM app_outbox WHERE id = ?1 AND peer_key = ?2",
                params![id, peer_key],
                |r| r.get(0),
            )
            .optional()?;
        self.conn
            .execute("DELETE FROM app_outbox WHERE id = ?1 AND peer_key = ?2", params![id, peer_key])?;
        match msg_ref.flatten() {
            Some(msg_ref) => {
                let remaining: u32 = self.conn.query_row(
                    "SELECT COUNT(*) FROM app_outbox WHERE msg_ref = ?1",
                    params![msg_ref],
                    |r| r.get(0),
                )?;
                Ok(Some((msg_ref, remaining)))
            }
            None => Ok(None),
        }
    }
}

fn peer_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<PeerRow> {
    Ok(PeerRow {
        mls_key: r.get(0)?,
        label: r.get(1)?,
        onion_address: r.get(2)?,
        noise_key: r.get(3)?,
        is_contact: r.get::<_, i64>(4)? != 0,
        relay: r
            .get::<_, Option<String>>(5)?
            .and_then(|json| serde_json::from_str(&json).ok()),
    })
}

fn message_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<MessageRow> {
    Ok(MessageRow {
        id: r.get(0)?,
        group_id: r.get(1)?,
        sender_key: r.get(2)?,
        body: r.get(3)?,
        sent_at: r.get(4)?,
        outgoing: r.get::<_, i64>(5)? != 0,
        status: r.get(6)?,
        reply_to: r.get(7)?,
        expires_at: r.get(8)?,
        attachment: r.get(9)?,
    })
}

fn conversation_from_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<ConversationRow> {
    let kind: String = r.get(1)?;
    Ok(ConversationRow {
        group_id: r.get(0)?,
        kind: ConversationKind::parse(&kind).unwrap_or(ConversationKind::Dm),
        name: r.get(2)?,
        server_id: r.get(3)?,
        admin_key: r.get(4)?,
        private: r.get::<_, i64>(5)? != 0,
        removed: r.get::<_, i64>(6)? != 0,
        created_at: r.get(7)?,
    })
}
