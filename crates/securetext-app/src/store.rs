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

#[derive(Clone, Debug)]
pub struct MessageRow {
    pub id: String,
    pub group_id: Vec<u8>,
    pub sender_key: Vec<u8>,
    pub body: String,
    pub sent_at: i64,
    pub outgoing: bool,
    pub status: String,
}

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
            CREATE TABLE IF NOT EXISTS app_outbox (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                peer_key BLOB NOT NULL,
                frame TEXT NOT NULL,
                msg_ref TEXT,
                created_at INTEGER NOT NULL
            );",
        )?;
        // Profiles created before Phase 5 lack the relay column.
        let has_relay_column = conn
            .prepare("SELECT relay_json FROM app_peers LIMIT 0")
            .is_ok();
        if !has_relay_column {
            conn.execute_batch("ALTER TABLE app_peers ADD COLUMN relay_json TEXT;")?;
        }
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
            "INSERT OR IGNORE INTO app_messages (group_id, id, sender_key, body, sent_at, outgoing, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![m.group_id, m.id, m.sender_key, m.body, m.sent_at, m.outgoing as i64, m.status],
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
            "SELECT id, group_id, sender_key, body, sent_at, outgoing, status FROM (
                SELECT * FROM app_messages WHERE group_id = ?1 ORDER BY seq DESC LIMIT ?2
             ) ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map(params![group_id, limit], |r| {
            Ok(MessageRow {
                id: r.get(0)?,
                group_id: r.get(1)?,
                sender_key: r.get(2)?,
                body: r.get(3)?,
                sent_at: r.get(4)?,
                outgoing: r.get::<_, i64>(5)? != 0,
                status: r.get(6)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    // ---- other peers' key packages ----

    pub fn add_peer_key_package(&self, peer_key: &[u8], key_package: &[u8]) -> anyhow::Result<()> {
        self.conn.execute(
            "INSERT INTO app_peer_key_packages (peer_key, key_package) VALUES (?1, ?2)",
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

    /// Delete a delivered outbox entry. Returns its `msg_ref` and how many
    /// entries for that same message are still undelivered.
    pub fn outbox_delivered(&self, id: i64) -> anyhow::Result<Option<(String, u32)>> {
        let msg_ref: Option<Option<String>> = self
            .conn
            .query_row("SELECT msg_ref FROM app_outbox WHERE id = ?1", params![id], |r| r.get(0))
            .optional()?;
        self.conn.execute("DELETE FROM app_outbox WHERE id = ?1", params![id])?;
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
