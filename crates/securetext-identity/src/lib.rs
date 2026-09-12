//! Local identity generation and encrypted-at-rest storage.
//!
//! An "identity" here is:
//! - the long-term MLS signing keypair (`openmls_basic_credential::SignatureKeyPair`,
//!   Ed25519), used for MLS group membership and message authentication;
//! - a long-term Noise static X25519 keypair, used only for the transport
//!   defense-in-depth layer (crypto-spec.md §4) — kept separate from the
//!   MLS key deliberately, since it serves a different purpose (transport
//!   authentication, not group cryptography) and Noise's XX pattern wants
//!   an X25519 key, not the Ed25519 signing key;
//! - a human-readable local label.
//!
//! Both keys are deliberately separate from the Tor onion-service key
//! (architecture.md §2), which `securetext-net` manages on its own.
//!
//! ## At-rest encryption approach (Phase 1 interim design)
//!
//! The signing key is persisted via `openmls_sqlite_storage`, which is the
//! officially supported route (the crate's own raw-private-key accessor is
//! gated behind a `test-utils` feature and not meant for application use).
//! SQLCipher-level row encryption isn't wired in yet (tracked in
//! tech-stack.md's open items — `openmls_sqlite_storage` pins its own
//! `rusqlite` dependency, and getting a SQLCipher build to feature-unify
//! with it needs a small dedicated spike). As an interim measure that still
//! satisfies "a stolen device shouldn't expose the identity key"
//! (threat-model.md), the *entire SQLite database file* is envelope-encrypted
//! as one opaque blob with Argon2id + ChaCha20-Poly1305 (crypto-spec.md §5):
//! decrypted to a private temp file while the app runs, re-encrypted back to
//! the persistent path on [`IdentityStore::seal`]. Call `seal()` after every
//! meaningful write, not just at shutdown — a crash between a write and a
//! `seal()` call loses that write (the on-disk copy is only ever as fresh as
//! the last seal).

use std::path::{Path, PathBuf};

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_sqlite_storage::{Codec, SqliteStorageProvider};
use openmls_traits::types::SignatureScheme;
use rand::RngCore;
use rusqlite::Connection;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// Must match `securetext_net::NOISE_PATTERN` exactly — this is the pattern
/// under which the static keypair generated here is valid.
const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";

#[derive(thiserror::Error, Debug)]
pub enum IdentityError {
    #[error("key derivation failed: {0}")]
    Kdf(String),
    #[error("encryption/decryption failed (wrong passphrase, or corrupted file)")]
    Crypto,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("migration error: {0}")]
    Migration(#[from] refinery::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("stored file is malformed or truncated")]
    Malformed,
    #[error("no identity found in this store; call create_identity first")]
    NoIdentity,
}

/// Non-secret information about an identity, safe to display or hand to
/// other modules (e.g. to build an MLS credential) without touching the
/// private key material directly.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicIdentity {
    pub label: String,
    pub public_key: Vec<u8>,
    pub signature_scheme_id: u16,
    /// The Noise static public key (X25519), for the transport
    /// defense-in-depth layer (crypto-spec.md §4). Share this out-of-band
    /// alongside an onion address/invite so the peer can pin and verify it
    /// during the Noise handshake, the same way the onion address itself
    /// is shared in Phase 1's manual-exchange model.
    pub noise_public_key: Vec<u8>,
}

impl PublicIdentity {
    pub fn signature_scheme(&self) -> Result<SignatureScheme, IdentityError> {
        signature_scheme_from_u16(self.signature_scheme_id)
    }
}

/// An open, decrypted identity store backed by a temporary plaintext SQLite
/// file. Holds the Argon2id-derived symmetric key for the session so
/// `seal()` can be called repeatedly without re-prompting for a passphrase.
pub struct IdentityStore {
    enc_path: PathBuf,
    tmp_dir: tempfile::TempDir,
    tmp_db_path: PathBuf,
    connection: Connection,
    session_key: SessionKey,
}

#[derive(ZeroizeOnDrop)]
struct SessionKey([u8; 32]);

#[derive(Default)]
struct JsonCodec;

impl Codec for JsonCodec {
    type Error = serde_json::Error;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, Self::Error> {
        serde_json::to_vec(value)
    }

    fn from_slice<T: DeserializeOwned>(slice: &[u8]) -> Result<T, Self::Error> {
        serde_json::from_slice(slice)
    }
}

impl IdentityStore {
    /// Create a brand new identity store at `enc_path`, generating a fresh
    /// Ed25519 signing keypair, and seal it to disk immediately.
    pub fn create(
        enc_path: &Path,
        label: impl Into<String>,
        passphrase: &str,
    ) -> Result<(Self, PublicIdentity), IdentityError> {
        let mut salt = [0u8; SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        let session_key = derive_key(passphrase, &salt)?;

        let tmp_dir = tempfile::tempdir()?;
        let tmp_db_path = tmp_dir.path().join("identity.db");
        let mut connection = Connection::open(&tmp_db_path)?;
        run_migrations(&mut connection)?;
        create_meta_table(&connection)?;

        let key_pair = SignatureKeyPair::new(SignatureScheme::ED25519)
            .map_err(|e| IdentityError::Kdf(format!("{e:?}")))?;
        let storage = SqliteStorageProvider::<JsonCodec, &Connection>::new(&connection);
        key_pair.store(&storage).map_err(IdentityError::Sqlite)?;

        let noise_keypair = snow::Builder::new(NOISE_PATTERN.parse().expect("valid noise pattern"))
            .generate_keypair()
            .map_err(|e| IdentityError::Kdf(format!("noise keygen: {e:?}")))?;
        write_noise_keys(&connection, &noise_keypair.public, &noise_keypair.private)?;

        let public = PublicIdentity {
            label: label.into(),
            public_key: key_pair.to_public_vec(),
            signature_scheme_id: SignatureScheme::ED25519 as u16,
            noise_public_key: noise_keypair.public,
        };
        write_meta(&connection, &public)?;

        let mut store = Self {
            enc_path: enc_path.to_path_buf(),
            tmp_dir,
            tmp_db_path,
            connection,
            session_key: SessionKey(session_key),
        };
        store.seal_with_salt(&salt)?;

        Ok((store, public))
    }

    /// Open an existing identity store, decrypting it into a private temp
    /// file for the duration of this session.
    pub fn open(enc_path: &Path, passphrase: &str) -> Result<(Self, PublicIdentity), IdentityError> {
        let file_bytes = std::fs::read(enc_path)?;
        let on_disk: OnDiskFile = serde_json::from_slice(&file_bytes)?;
        if on_disk.salt.len() != SALT_LEN || on_disk.nonce.len() != NONCE_LEN {
            return Err(IdentityError::Malformed);
        }
        let session_key = derive_key(passphrase, &on_disk.salt)?;

        let cipher = ChaCha20Poly1305::new(Key::from_slice(&session_key));
        let plaintext_db_bytes = cipher
            .decrypt(Nonce::from_slice(&on_disk.nonce), on_disk.ciphertext.as_ref())
            .map_err(|_| IdentityError::Crypto)?;

        let tmp_dir = tempfile::tempdir()?;
        let tmp_db_path = tmp_dir.path().join("identity.db");
        std::fs::write(&tmp_db_path, &plaintext_db_bytes)?;

        let connection = Connection::open(&tmp_db_path)?;
        let public = read_meta(&connection)?.ok_or(IdentityError::NoIdentity)?;

        Ok((
            Self {
                enc_path: enc_path.to_path_buf(),
                tmp_dir,
                tmp_db_path,
                connection,
                session_key: SessionKey(session_key),
            },
            public,
        ))
    }

    /// Re-encrypt the current on-disk (temp, plaintext) database state back
    /// to `enc_path`. Call this after every meaningful write.
    pub fn seal(&mut self) -> Result<(), IdentityError> {
        // Force SQLite to flush everything to the temp file before we read
        // its raw bytes back for encryption.
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")?;
        let salt = derive_salt_from_on_disk_or(&self.enc_path)?;
        self.seal_with_salt(&salt)
    }

    fn seal_with_salt(&mut self, salt: &[u8]) -> Result<(), IdentityError> {
        self.connection
            .execute_batch("PRAGMA wal_checkpoint(FULL);")?;
        let mut db_bytes = std::fs::read(&self.tmp_db_path)?;

        let mut nonce_bytes = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.session_key.0));
        let ciphertext = cipher
            .encrypt(Nonce::from_slice(&nonce_bytes), db_bytes.as_ref())
            .map_err(|_| IdentityError::Crypto)?;
        db_bytes.zeroize();

        let on_disk = OnDiskFile {
            version: 1,
            salt: salt.to_vec(),
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        };
        let file_bytes = serde_json::to_vec_pretty(&on_disk)?;
        std::fs::write(&self.enc_path, file_bytes)?;
        Ok(())
    }

    /// Load the signing keypair for `public` from this store. Returns
    /// `None` if it isn't present (shouldn't happen for a store opened via
    /// `open`/`create`, which both guarantee exactly one identity exists).
    pub fn signing_key_pair(&self, public: &PublicIdentity) -> Result<Option<SignatureKeyPair>, IdentityError> {
        let storage = SqliteStorageProvider::<JsonCodec, _>::new(&self.connection);
        Ok(SignatureKeyPair::read(
            &storage,
            &public.public_key,
            public.signature_scheme()?,
        ))
    }

    /// The Noise static private key (X25519, raw bytes) for this identity,
    /// for use with `securetext_net`'s Noise handshake. Kept out of
    /// `PublicIdentity` deliberately since that type is meant to be safe to
    /// display/share — this is the one secret this crate hands out
    /// directly, mirroring how `signing_key_pair` hands out the MLS secret.
    pub fn noise_static_private_key(&self) -> Result<Vec<u8>, IdentityError> {
        let mut stmt = self
            .connection
            .prepare("SELECT private_key FROM securetext_noise_keys WHERE id = 0")?;
        let mut rows = stmt.query([])?;
        let row = rows.next()?.ok_or(IdentityError::NoIdentity)?;
        Ok(row.get(0)?)
    }

    /// Path to the decrypted, plaintext-for-this-session SQLite file
    /// backing this identity's tables (signature keys, Noise keys, our own
    /// metadata). Intended for `securetext-crypto`'s `PersistentProvider`
    /// to open its *own* connection to the same underlying file for MLS
    /// group storage, rather than sharing this store's live `Connection`
    /// by reference -- that would tie a `Member`'s lifetime to this
    /// store's borrow state (e.g. conflicting with `seal(&mut self)`).
    /// SQLite supports multiple connections to one file; both this store
    /// and any `PersistentProvider`s opened against this path get sealed
    /// together whenever `seal()` is called, since it re-encrypts the
    /// whole file regardless of which connection wrote what.
    pub fn db_path(&self) -> &Path {
        &self.tmp_db_path
    }
}

impl Drop for IdentityStore {
    fn drop(&mut self) {
        // Best-effort cleanup of the plaintext temp file. `tempfile::TempDir`
        // already removes its directory on drop; this just makes the intent
        // explicit and doesn't fail the drop if it can't.
        let _ = std::fs::remove_file(&self.tmp_db_path);
        let _ = &self.tmp_dir;
    }
}

fn run_migrations(connection: &mut Connection) -> Result<(), IdentityError> {
    let mut storage = SqliteStorageProvider::<JsonCodec, &mut Connection>::new(connection);
    storage.run_migrations()?;
    Ok(())
}

fn create_meta_table(connection: &Connection) -> Result<(), IdentityError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS securetext_identity_meta (
            id INTEGER PRIMARY KEY CHECK (id = 0),
            label TEXT NOT NULL,
            public_key BLOB NOT NULL,
            signature_scheme_id INTEGER NOT NULL,
            noise_public_key BLOB NOT NULL DEFAULT (x'')
        );
        CREATE TABLE IF NOT EXISTS securetext_noise_keys (
            id INTEGER PRIMARY KEY CHECK (id = 0),
            public_key BLOB NOT NULL,
            private_key BLOB NOT NULL
        );",
    )?;
    Ok(())
}

fn write_meta(connection: &Connection, public: &PublicIdentity) -> Result<(), IdentityError> {
    connection.execute(
        "INSERT OR REPLACE INTO securetext_identity_meta (id, label, public_key, signature_scheme_id, noise_public_key)
         VALUES (0, ?1, ?2, ?3, ?4)",
        rusqlite::params![
            public.label,
            public.public_key,
            public.signature_scheme_id,
            public.noise_public_key
        ],
    )?;
    Ok(())
}

fn write_noise_keys(connection: &Connection, public_key: &[u8], private_key: &[u8]) -> Result<(), IdentityError> {
    connection.execute(
        "INSERT OR REPLACE INTO securetext_noise_keys (id, public_key, private_key) VALUES (0, ?1, ?2)",
        rusqlite::params![public_key, private_key],
    )?;
    Ok(())
}

fn read_meta(connection: &Connection) -> Result<Option<PublicIdentity>, IdentityError> {
    create_meta_table(connection)?;
    let mut stmt = connection.prepare(
        "SELECT label, public_key, signature_scheme_id, noise_public_key FROM securetext_identity_meta WHERE id = 0",
    )?;
    let mut rows = stmt.query([])?;
    if let Some(row) = rows.next()? {
        Ok(Some(PublicIdentity {
            label: row.get(0)?,
            public_key: row.get(1)?,
            signature_scheme_id: row.get(2)?,
            noise_public_key: row.get(3)?,
        }))
    } else {
        Ok(None)
    }
}

fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], IdentityError> {
    let mut key_bytes = [0u8; 32];
    Argon2::default()
        .hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| IdentityError::Kdf(e.to_string()))?;
    Ok(key_bytes)
}

fn derive_salt_from_on_disk_or(enc_path: &Path) -> Result<Vec<u8>, IdentityError> {
    // `seal()` (as opposed to `seal_with_salt` at creation time) reuses the
    // salt already on disk rather than generating a new one, so the
    // Argon2id key stays derivable from the same passphrase across calls.
    let file_bytes = std::fs::read(enc_path)?;
    let on_disk: OnDiskFile = serde_json::from_slice(&file_bytes)?;
    Ok(on_disk.salt)
}

fn signature_scheme_from_u16(v: u16) -> Result<SignatureScheme, IdentityError> {
    if v == SignatureScheme::ED25519 as u16 {
        Ok(SignatureScheme::ED25519)
    } else {
        Err(IdentityError::Malformed)
    }
}

#[derive(Serialize, Deserialize)]
struct OnDiskFile {
    version: u8,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_seal_reopen_round_trip() {
        let dir = tempfile::tempdir().expect("tempdir");
        let enc_path = dir.path().join("identity.enc");

        let (store, public) = IdentityStore::create(&enc_path, "alice", "correct horse battery staple")
            .expect("create");
        let key_pair = store
            .signing_key_pair(&public)
            .expect("read key pair")
            .expect("key pair present");
        assert_eq!(key_pair.to_public_vec(), public.public_key);
        assert_eq!(public.noise_public_key.len(), 32, "X25519 public key is 32 bytes");
        let noise_private = store.noise_static_private_key().expect("noise private key");
        assert_eq!(noise_private.len(), 32, "X25519 private key is 32 bytes");
        drop(store);

        let (reopened, reopened_public) =
            IdentityStore::open(&enc_path, "correct horse battery staple").expect("open");
        assert_eq!(reopened_public.label, "alice");
        assert_eq!(reopened_public.public_key, public.public_key);
        assert_eq!(reopened_public.noise_public_key, public.noise_public_key);
        let reopened_key_pair = reopened
            .signing_key_pair(&reopened_public)
            .expect("read key pair")
            .expect("key pair present");
        assert_eq!(reopened_key_pair.to_public_vec(), public.public_key);
        assert_eq!(
            reopened.noise_static_private_key().expect("noise private key"),
            noise_private,
            "noise static key survives seal/reopen"
        );
    }

    #[test]
    fn wrong_passphrase_fails_to_decrypt() {
        let dir = tempfile::tempdir().expect("tempdir");
        let enc_path = dir.path().join("identity.enc");
        let (store, _public) = IdentityStore::create(&enc_path, "bob", "right passphrase").expect("create");
        drop(store);

        let result = IdentityStore::open(&enc_path, "wrong passphrase");
        assert!(matches!(result, Err(IdentityError::Crypto)));
    }
}
