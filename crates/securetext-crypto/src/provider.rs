//! A persistent `OpenMlsProvider` backed by SQLite, so MLS group state
//! (and everything else OpenMLS writes through the storage trait --
//! ratchet/epoch secrets, key packages, proposals) survives a restart
//! instead of living only in memory.
//!
//! Composes `openmls_rust_crypto::RustCrypto` (crypto + randomness -- no
//! reason to reimplement this part, it's not what needed persisting) with
//! `openmls_sqlite_storage::SqliteStorageProvider` (storage), the same
//! officially-supported storage backend `securetext-identity` already uses
//! for the signing key. Per OpenMLS's own persistence docs: "OpenMLS treats
//! the StorageProvider as trusted... protect the storage backend itself,
//! for example with authenticated encryption" -- exactly what
//! `securetext-identity`'s envelope encryption already does, so sharing its
//! `rusqlite::Connection` (rather than opening a second, separately-secured
//! database) is the natural fit, not just a convenience.

use std::borrow::{Borrow, BorrowMut};

use openmls_rust_crypto::RustCrypto;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::OpenMlsProvider;
use rusqlite::Connection;
use serde::{de::DeserializeOwned, Serialize};

#[derive(Default)]
pub struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

/// An `OpenMlsProvider` whose storage is a SQLite connection instead of
/// the in-memory default. `ConnectionRef` is generic (mirroring
/// `SqliteStorageProvider` itself) so this can hold either an owned
/// `Connection` or a borrowed one shared with `securetext-identity`'s
/// already-open connection for the same identity.
pub struct PersistentProvider<ConnectionRef: Borrow<Connection>> {
    crypto: RustCrypto,
    storage: SqliteStorageProvider<JsonCodec, ConnectionRef>,
}

impl<ConnectionRef: Borrow<Connection>> PersistentProvider<ConnectionRef> {
    /// Wrap `connection` as a persistent MLS provider. Call
    /// [`Self::run_migrations`] once per fresh database before using it
    /// (mirrors `openmls_sqlite_storage`'s own required setup step).
    pub fn new(connection: ConnectionRef) -> Self {
        Self {
            crypto: RustCrypto::default(),
            storage: SqliteStorageProvider::new(connection),
        }
    }
}

impl<ConnectionRef: Borrow<Connection> + BorrowMut<Connection>> PersistentProvider<ConnectionRef> {
    /// Create the tables this provider needs. Safe to call on an
    /// already-migrated database (idempotent, like
    /// `securetext_identity`'s own migration step).
    pub fn run_migrations(&mut self) -> Result<(), refinery::Error> {
        self.storage.run_migrations()
    }
}

impl<ConnectionRef: Borrow<Connection>> OpenMlsProvider for PersistentProvider<ConnectionRef> {
    type CryptoProvider = RustCrypto;
    type RandProvider = RustCrypto;
    type StorageProvider = SqliteStorageProvider<JsonCodec, ConnectionRef>;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}
