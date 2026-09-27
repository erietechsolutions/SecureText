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

#![forbid(unsafe_code)]

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

/// Where the decrypted working copy of the database lives while the
/// profile is open.
///
/// - **Private.** The directory is created mode 0700 and the file 0600.
///   `tempfile`'s default follows the umask (usually 0755), which made
///   the working copy readable by other local users before Phase 9.
/// - **Off disk where possible.** It's deleted on close, but a crash or
///   power cut leaves it behind. So on Linux it goes under
///   `$XDG_RUNTIME_DIR`, which is per-user, in memory (tmpfs) and wiped at
///   logout. Elsewhere it falls back to the system temp directory; Windows'
///   %TEMP% is on disk (docs/security-review.md, P9-02).
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)?.write_all(bytes)
}

fn working_dir() -> std::io::Result<tempfile::TempDir> {
    let builder = {
        let mut b = tempfile::Builder::new();
        b.prefix("securetext-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            b.permissions(std::fs::Permissions::from_mode(0o700));
        }
        b
    };
    #[cfg(target_os = "linux")]
    {
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from) {
            if runtime.is_absolute() && runtime.is_dir() {
                if let Ok(dir) = builder.tempdir_in(&runtime) {
                    return Ok(dir);
                }
            }
        }
    }
    builder.tempdir()
}

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

/// How to currently reach a peer this identity has an established
/// relationship with (e.g. a shared MLS group) -- kept separate from the
/// group's own state because it can change independently: architecture.md
/// §2 describes rotating an onion address/Noise key for unlinkability
/// without losing group membership continuity, which means "how do I
/// currently reach this peer" has to be an updatable record, not baked
/// into the invite that first established the relationship.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Contact {
    /// The peer's long-term MLS identity public key -- stable across
    /// address/Noise-key rotation, so this is the lookup key for "this is
    /// still the same person, just reachable differently now."
    pub peer_mls_public_key: Vec<u8>,
    pub peer_label: String,
    pub onion_address: String,
    pub noise_public_key: Vec<u8>,
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

        let tmp_dir = working_dir()?;
        let tmp_db_path = tmp_dir.path().join("identity.db");
        // Created empty and private first, so SQLite (and the journal
        // files it derives from it) never have a wider mode.
        write_private(&tmp_db_path, &[])?;
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

        let tmp_dir = working_dir()?;
        let tmp_db_path = tmp_dir.path().join("identity.db");
        write_private(&tmp_db_path, &plaintext_db_bytes)?;

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

    /// Rotate this identity's Noise static keypair (architecture.md §2's
    /// unlinkability rotation), replacing it for all future connections.
    /// Callers must also launch a new onion service and tell existing
    /// contacts about both the new address and this new key -- typically
    /// via an `AppMessage::Moved` sent through each existing MLS group
    /// (crypto-spec.md/`securetext-crypto`) -- since rotating only one of
    /// the two would weaken the unlinkability this exists to provide.
    /// Reseals the store to disk before returning; callers don't need to
    /// call `seal()` separately for this specific change.
    pub fn rotate_noise_key(&mut self) -> Result<Vec<u8>, IdentityError> {
        let new_keypair = snow::Builder::new(NOISE_PATTERN.parse().expect("valid noise pattern"))
            .generate_keypair()
            .map_err(|e| IdentityError::Kdf(format!("noise keygen: {e:?}")))?;
        write_noise_keys(&self.connection, &new_keypair.public, &new_keypair.private)?;
        self.connection.execute(
            "UPDATE securetext_identity_meta SET noise_public_key = ?1 WHERE id = 0",
            rusqlite::params![new_keypair.public],
        )?;
        self.seal()?;
        Ok(new_keypair.public)
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
    /// Change the display label (a self-chosen name, never trusted by
    /// anyone else). Persisted with the identity; `seal` to write it out.
    pub fn set_label(&mut self, public: &mut PublicIdentity, label: impl Into<String>) -> Result<(), IdentityError> {
        let mut updated = public.clone();
        updated.label = label.into();
        write_meta(&self.connection, &updated)?;
        *public = updated;
        Ok(())
    }

    pub fn db_path(&self) -> &Path {
        &self.tmp_db_path
    }

    /// Record or update how to reach a contact, keyed by their stable MLS
    /// identity public key. Call this when processing a `Moved` message
    /// (architecture.md §2) so future connection attempts use the
    /// contact's current onion address/Noise key instead of a stale one.
    pub fn upsert_contact(&self, contact: &Contact) -> Result<(), IdentityError> {
        create_contacts_table(&self.connection)?;
        self.connection.execute(
            "INSERT INTO securetext_contacts (peer_mls_public_key, peer_label, onion_address, noise_public_key)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(peer_mls_public_key) DO UPDATE SET
                peer_label = excluded.peer_label,
                onion_address = excluded.onion_address,
                noise_public_key = excluded.noise_public_key",
            rusqlite::params![
                contact.peer_mls_public_key,
                contact.peer_label,
                contact.onion_address,
                contact.noise_public_key
            ],
        )?;
        Ok(())
    }

    /// Look up how to currently reach a contact by their stable MLS
    /// identity public key. Returns `None` if this identity has no
    /// contact record for that peer yet.
    pub fn get_contact(&self, peer_mls_public_key: &[u8]) -> Result<Option<Contact>, IdentityError> {
        create_contacts_table(&self.connection)?;
        let mut stmt = self.connection.prepare(
            "SELECT peer_mls_public_key, peer_label, onion_address, noise_public_key
             FROM securetext_contacts WHERE peer_mls_public_key = ?1",
        )?;
        let mut rows = stmt.query(rusqlite::params![peer_mls_public_key])?;
        if let Some(row) = rows.next()? {
            Ok(Some(Contact {
                peer_mls_public_key: row.get(0)?,
                peer_label: row.get(1)?,
                onion_address: row.get(2)?,
                noise_public_key: row.get(3)?,
            }))
        } else {
            Ok(None)
        }
    }
}

fn create_contacts_table(connection: &Connection) -> Result<(), IdentityError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS securetext_contacts (
            peer_mls_public_key BLOB PRIMARY KEY,
            peer_label TEXT NOT NULL,
            onion_address TEXT NOT NULL,
            noise_public_key BLOB NOT NULL
        );",
    )?;
    Ok(())
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

    /// Regression test for a Phase 9 finding: the decrypted working copy
    /// used to sit in a 0755 directory, readable by every local user.
    #[cfg(unix)]
    #[test]
    fn the_decrypted_working_copy_is_private_to_its_owner() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("id.enc");
        let (mut store, _) = IdentityStore::create(&path, "alice", "correct horse").unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(store.db_path().parent().unwrap()), 0o700, "working directory (new profile)");
        assert_eq!(mode(store.db_path()) & 0o077, 0, "working copy (new profile)");
        store.seal().unwrap();
        drop(store);
        let (store, _) = IdentityStore::open(&path, "correct horse").unwrap();
        assert_eq!(mode(store.db_path().parent().unwrap()), 0o700, "working directory");
        assert_eq!(mode(store.db_path()) & 0o077, 0, "working copy must not be group/world readable");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_plaintext_working_copy_lives_in_the_runtime_dir_when_there_is_one() {
        // XDG_RUNTIME_DIR is process-wide; this test sets it only for
        // the duration of one call, so it doesn't race other tests.
        let runtime = tempfile::tempdir().expect("tempdir");
        let previous = std::env::var_os("XDG_RUNTIME_DIR");
        // SAFETY-free: `set_var` is only unsafe in edition 2024.
        std::env::set_var("XDG_RUNTIME_DIR", runtime.path());
        let dir = working_dir().unwrap();
        match previous {
            Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
        assert!(dir.path().starts_with(runtime.path()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777, 0o700);
        }
    }

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
    fn contacts_can_be_recorded_and_updated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let enc_path = dir.path().join("identity.enc");
        let (store, _public) = IdentityStore::create(&enc_path, "alice", "pw").expect("create");

        let peer_key = vec![1, 2, 3, 4];
        assert_eq!(store.get_contact(&peer_key).expect("lookup"), None);

        store
            .upsert_contact(&Contact {
                peer_mls_public_key: peer_key.clone(),
                peer_label: "bob".to_string(),
                onion_address: "old-address.onion".to_string(),
                noise_public_key: vec![9, 9, 9],
            })
            .expect("insert contact");
        let found = store.get_contact(&peer_key).expect("lookup").expect("present");
        assert_eq!(found.onion_address, "old-address.onion");

        // Simulate processing a Moved message: same peer, new reachability.
        store
            .upsert_contact(&Contact {
                peer_mls_public_key: peer_key.clone(),
                peer_label: "bob".to_string(),
                onion_address: "new-address.onion".to_string(),
                noise_public_key: vec![7, 7, 7],
            })
            .expect("update contact");
        let updated = store.get_contact(&peer_key).expect("lookup").expect("present");
        assert_eq!(updated.onion_address, "new-address.onion");
        assert_eq!(updated.noise_public_key, vec![7, 7, 7]);
    }

    #[test]
    fn rotate_noise_key_replaces_it_and_persists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let enc_path = dir.path().join("identity.enc");
        let (mut store, original_public) = IdentityStore::create(&enc_path, "alice", "pw").expect("create");
        let original_noise_key = original_public.noise_public_key.clone();

        let rotated_public_key = store.rotate_noise_key().expect("rotate");
        assert_ne!(rotated_public_key, original_noise_key);
        assert_eq!(rotated_public_key.len(), 32);

        let rotated_private = store.noise_static_private_key().expect("private key after rotate");
        assert_eq!(rotated_private.len(), 32);
        drop(store);

        // Reopen and confirm the rotation survived a full close/reopen,
        // and that PublicIdentity's copy of the key was updated too.
        let (reopened, reopened_public) = IdentityStore::open(&enc_path, "pw").expect("reopen");
        assert_eq!(reopened_public.noise_public_key, rotated_public_key);
        assert_eq!(
            reopened.noise_static_private_key().expect("private key after reopen"),
            rotated_private
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
