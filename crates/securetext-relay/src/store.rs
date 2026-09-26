//! The relay's on-disk mailbox store: blobs keyed by mailbox ID, with a
//! per-blob size cap, per-mailbox and global quotas, and a time-to-live.
//!
//! Not passphrase-encrypted like a client profile: a relay is an
//! unattended service, and everything it stores is already sealed by
//! senders with keys it never has. Encrypting it again under a key kept on
//! the same machine wouldn't protect anything.

use std::path::Path;
use std::time::Duration;

use rusqlite::{params, Connection, OptionalExtension};

use crate::{mailbox_id, RelayError, StoredBlob};

#[derive(Clone, Debug)]
pub struct Limits {
    pub max_blob: usize,
    pub max_per_mailbox: u32,
    pub max_total_bytes: u64,
    /// Blobs not collected within this long are deleted.
    pub ttl: Duration,
    /// Most bytes returned by one fetch.
    pub max_fetch_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_blob: 256 * 1024,
            max_per_mailbox: 1000,
            max_total_bytes: 512 * 1024 * 1024,
            ttl: Duration::from_secs(14 * 24 * 3600),
            max_fetch_bytes: 1024 * 1024,
        }
    }
}

pub struct RelayStore {
    conn: Connection,
    limits: Limits,
}

/// Deposit times are kept only to the hour: enough for the TTL, less
/// timing metadata sitting on disk.
const TIME_GRANULARITY_SECS: i64 = 3600;

impl RelayStore {
    pub fn open(path: &Path, limits: Limits) -> anyhow::Result<Self> {
        Self::from_connection(Connection::open(path)?, limits)
    }

    pub fn in_memory(limits: Limits) -> anyhow::Result<Self> {
        Self::from_connection(Connection::open_in_memory()?, limits)
    }

    fn from_connection(conn: Connection, limits: Limits) -> anyhow::Result<Self> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS blobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mailbox BLOB NOT NULL,
                blob BLOB NOT NULL,
                deposited_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS blobs_by_mailbox ON blobs (mailbox, id);
            -- Deleted blobs are overwritten, not just unlinked from the b-tree.
            PRAGMA secure_delete = ON;",
        )?;
        Ok(Self { conn, limits })
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn deposit(&self, mailbox: &[u8], blob: &[u8], now_secs: i64) -> anyhow::Result<Result<(), RelayError>> {
        if mailbox.len() != 32 || blob.len() > self.limits.max_blob {
            return Ok(Err(RelayError::TooLarge));
        }
        self.prune(now_secs)?;
        let in_mailbox: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM blobs WHERE mailbox = ?1",
            params![mailbox],
            |r| r.get(0),
        )?;
        if in_mailbox >= self.limits.max_per_mailbox {
            return Ok(Err(RelayError::MailboxFull));
        }
        let total: i64 = self
            .conn
            .query_row("SELECT COALESCE(SUM(LENGTH(blob)), 0) FROM blobs", [], |r| r.get(0))?;
        if total as u64 + blob.len() as u64 > self.limits.max_total_bytes {
            return Ok(Err(RelayError::RelayFull));
        }
        let rounded = now_secs - now_secs.rem_euclid(TIME_GRANULARITY_SECS);
        self.conn.execute(
            "INSERT INTO blobs (mailbox, blob, deposited_at) VALUES (?1, ?2, ?3)",
            params![mailbox, blob, rounded],
        )?;
        Ok(Ok(()))
    }

    /// Up to `limit` blobs (and at most `max_fetch_bytes`) for the mailbox
    /// `secret` opens, oldest first. Always returns at least one blob if
    /// any exist, even an oversized one, so a mailbox can't get stuck.
    pub fn fetch(&self, secret: &[u8], limit: u32) -> anyhow::Result<Vec<StoredBlob>> {
        let mailbox = mailbox_id(secret);
        let mut stmt = self
            .conn
            .prepare("SELECT id, blob FROM blobs WHERE mailbox = ?1 ORDER BY id LIMIT ?2")?;
        let rows = stmt.query_map(params![mailbox, limit.clamp(1, 500)], |r| {
            Ok(StoredBlob { id: r.get(0)?, blob: r.get(1)? })
        })?;
        let mut out = Vec::new();
        let mut bytes = 0;
        for row in rows {
            let item = row?;
            bytes += item.blob.len();
            if !out.is_empty() && bytes > self.limits.max_fetch_bytes {
                break;
            }
            out.push(item);
        }
        Ok(out)
    }

    /// Delete collected blobs. Only blobs in the mailbox `secret` opens
    /// can be deleted; other IDs are ignored.
    pub fn ack(&self, secret: &[u8], ids: &[i64]) -> anyhow::Result<u32> {
        let mailbox = mailbox_id(secret);
        let mut removed = 0;
        for id in ids {
            removed += self
                .conn
                .execute("DELETE FROM blobs WHERE id = ?1 AND mailbox = ?2", params![id, mailbox])?
                as u32;
        }
        Ok(removed)
    }

    pub fn prune(&self, now_secs: i64) -> anyhow::Result<u32> {
        let cutoff = now_secs - self.limits.ttl.as_secs() as i64;
        Ok(self.conn.execute("DELETE FROM blobs WHERE deposited_at < ?1", params![cutoff])? as u32)
    }

    pub fn count(&self, mailbox: &[u8]) -> anyhow::Result<u32> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM blobs WHERE mailbox = ?1", params![mailbox], |r| r.get(0))
            .optional()?
            .unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn store(limits: Limits) -> RelayStore {
        RelayStore::in_memory(limits).unwrap()
    }

    #[test]
    fn deposit_fetch_ack_round_trip() {
        let s = store(Limits::default());
        let secret = [7u8; 32];
        let mailbox = mailbox_id(&secret);
        s.deposit(&mailbox, b"one", NOW).unwrap().unwrap();
        s.deposit(&mailbox, b"two", NOW).unwrap().unwrap();

        let got = s.fetch(&secret, 10).unwrap();
        assert_eq!(got.iter().map(|b| b.blob.as_slice()).collect::<Vec<_>>(), vec![&b"one"[..], &b"two"[..]]);
        // Fetching doesn't delete; acking does.
        assert_eq!(s.fetch(&secret, 10).unwrap().len(), 2);
        assert_eq!(s.ack(&secret, &[got[0].id]).unwrap(), 1);
        assert_eq!(s.fetch(&secret, 10).unwrap().len(), 1);
    }

    #[test]
    fn only_the_secret_holder_can_read_or_delete() {
        let s = store(Limits::default());
        let secret = [7u8; 32];
        let mailbox = mailbox_id(&secret);
        s.deposit(&mailbox, b"private", NOW).unwrap().unwrap();
        let id = s.fetch(&secret, 1).unwrap()[0].id;

        // Knowing the mailbox ID (what depositors know) opens nothing.
        assert!(s.fetch(&mailbox, 10).unwrap().is_empty());
        assert_eq!(s.ack(&mailbox, &[id]).unwrap(), 0);
        // Nor does another mailbox's secret.
        assert_eq!(s.ack(&[8u8; 32], &[id]).unwrap(), 0);
        assert_eq!(s.count(&mailbox).unwrap(), 1);
    }

    #[test]
    fn quotas_and_ttl_are_enforced() {
        let s = store(Limits {
            max_blob: 8,
            max_per_mailbox: 2,
            max_total_bytes: 20,
            ttl: Duration::from_secs(7200),
            max_fetch_bytes: 1024,
        });
        let a = mailbox_id(&[1; 32]);
        let b = mailbox_id(&[2; 32]);
        assert_eq!(s.deposit(&a, b"123456789", NOW).unwrap(), Err(RelayError::TooLarge));
        s.deposit(&a, b"1234567", NOW).unwrap().unwrap();
        s.deposit(&a, b"1234567", NOW).unwrap().unwrap();
        assert_eq!(s.deposit(&a, b"x", NOW).unwrap(), Err(RelayError::MailboxFull));
        assert_eq!(s.deposit(&b, b"1234567", NOW).unwrap(), Err(RelayError::RelayFull));

        // Past the TTL, everything is gone and there's room again.
        let later = NOW + 3 * 3600;
        s.deposit(&b, b"1234567", later).unwrap().unwrap();
        assert_eq!(s.count(&a).unwrap(), 0);
    }

    #[test]
    fn deposit_times_are_coarsened() {
        let s = store(Limits::default());
        let mailbox = mailbox_id(&[3; 32]);
        s.deposit(&mailbox, b"x", NOW + 1234).unwrap().unwrap();
        let stored: i64 = s.conn.query_row("SELECT deposited_at FROM blobs", [], |r| r.get(0)).unwrap();
        assert_eq!(stored % 3600, 0);
        assert!(stored <= NOW + 1234 && stored > NOW + 1234 - 3600);
    }
}
