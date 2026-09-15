//! Durable node-identity persistence (R1-001).
//!
//! This is the API the `sharenet-id` binary calls today and the future
//! ShareNet daemon will call at node startup:
//!
//! ```text
//! IdentityStore::load_or_create(dir, display_name)
//! ```
//!
//! # Identity file format
//!
//! Strict canonical CBOR map:
//!
//! ```text
//! {1: seed (32-byte bstr), 2: node_identity (NodeIdentity map)}
//! ```
//!
//! File name: [`IDENTITY_FILE_NAME`] (`node.sharenet-identity`) inside the
//! caller-provided directory. The directory is injectable (tests use
//! tempdirs; the daemon will use its state directory).
//!
//! # Persistence and security guarantees
//!
//! - **Durable write**: temp file in the same directory + `fsync(file)` +
//!   `rename` + `fsync(parent dir)`. A crash cannot leave a half-written
//!   identity file under the final name.
//! - **Permissions**: the file is created with mode 0600 (unix) and the
//!   permissions are enforced again after writing, regardless of umask.
//! - **Fail-closed load**: any corruption, tampering, structural violation,
//!   seed/object mismatch, or insecure permissions (anything other than
//!   exactly 0600 on unix) is a hard error. The store NEVER silently
//!   overwrites, recreates, or partially accepts an identity file.
//! - **Zeroization**: file bytes and decoded CBOR values are scrubbed
//!   (zeroized) after use; the seed lives only in zeroize-on-drop types.
//!   `LoadedIdentity` zeroizes its signing key on drop.
//!
//! # What tampering is and is not detected
//!
//! The seed and the recorded public key are cross-checked on every load, so
//! tampering with either is detected (fail closed). `display_name` and
//! `created_at_unix` are deliberately UNBOUND mutable metadata: they can be
//! edited without breaking the file, and the derived `node_id` is unchanged
//! (see `identity` module docs). Tampering with the scheme version or the
//! object structure is rejected. An attacker who replaces the ENTIRE file
//! (seed + object consistently) with a different identity is not detectable
//! from the file alone — that is inherent to local file storage.
//!
//! # Known limits (honest)
//!
//! - No file locking: two concurrent `load_or_create` calls in the same
//!   directory may both create; the last atomic rename wins (v1 assumes one
//!   daemon per identity directory).
//! - Symlinks are followed; the permissions of the target are checked.

use crate::cbor::{self, Value};
use crate::identity::{
    IdentityError, NodeIdentity, NodeSigningKey, SEED_LEN,
};
use std::fmt;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use crate::cbor::MapBuilder;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

/// Name of the identity file inside the identity directory.
pub const IDENTITY_FILE_NAME: &str = "node.sharenet-identity";

/// A loaded node identity: the public [`NodeIdentity`] plus the in-memory
/// signing key (zeroized on drop). The seed is never exposed.
pub struct LoadedIdentity {
    signing: NodeSigningKey,
    identity: NodeIdentity,
}

impl LoadedIdentity {
    /// The public identity object.
    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    /// The derived node id as lowercase hex.
    pub fn node_id_hex(&self) -> String {
        self.identity.node_id_hex()
    }

    /// Produces a detached signature over an arbitrary payload.
    pub fn sign(&self, payload: &[u8]) -> [u8; 64] {
        self.signing.sign(payload)
    }
}

impl fmt::Debug for LoadedIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Public data only; never the secret key.
        f.debug_struct("LoadedIdentity")
            .field("identity", &self.identity)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Typed store failure. All variants are actionable.
#[derive(Debug)]
pub enum StoreError {
    /// Underlying filesystem error with context.
    Io {
        path: PathBuf,
        context: &'static str,
        source: std::io::Error,
    },
    /// The identity file bytes are not strict canonical CBOR.
    Cbor(cbor::DecodeError),
    /// The identity file is structurally invalid (not the expected map).
    InvalidFileStructure { reason: String },
    /// The embedded NodeIdentity object is invalid.
    Identity(IdentityError),
    /// The seed does not derive the recorded public key (corruption,
    /// tampering, or a swapped seed/object).
    PublicKeyMismatch {
        derived_from_seed: String,
        recorded_in_object: String,
    },
    /// File permissions are not exactly 0600 (unix).
    InsecurePermissions { path: PathBuf, mode: u32 },
    /// The display name given at creation time was invalid.
    DisplayName(IdentityError),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io {
                path,
                context,
                source,
            } => write!(f, "{context} for {}: {source}", path.display()),
            StoreError::Cbor(e) => write!(
                f,
                "identity file is not strict canonical CBOR (fail closed): {e}"
            ),
            StoreError::InvalidFileStructure { reason } => write!(
                f,
                "identity file structure invalid (fail closed): {reason}"
            ),
            StoreError::Identity(e) => {
                write!(f, "identity object invalid (fail closed): {e}")
            }
            StoreError::PublicKeyMismatch {
                derived_from_seed,
                recorded_in_object,
            } => write!(
                f,
                "identity file is inconsistent (fail closed): the seed derives public key \
                 {derived_from_seed} but the file records {recorded_in_object}; the file may be \
                 corrupted or tampered with — refusing to load or recreate"
            ),
            StoreError::InsecurePermissions { path, mode } => write!(
                f,
                "identity file {} has permissions {:o} but exactly 0600 is required \
                 (fail closed); fix with: chmod 600 {}",
                path.display(),
                mode,
                path.display()
            ),
            StoreError::DisplayName(e) => write!(f, "invalid display name: {e}"),
        }
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            StoreError::Io { source, .. } => Some(source),
            StoreError::Cbor(e) => Some(e),
            StoreError::Identity(e) => Some(e),
            StoreError::DisplayName(e) => Some(e),
            _ => None,
        }
    }
}

/// Durable identity store. All methods take an injectable directory/path.
pub struct IdentityStore;

impl IdentityStore {
    /// Loads the identity from `dir`/`IDENTITY_FILE_NAME`, or — only if the
    /// file is entirely ABSENT — generates a new identity and durably writes
    /// it.
    ///
    /// Returns the loaded identity plus a flag telling whether a new
    /// identity was created (`true`) or an existing one was loaded (`false`).
    ///
    /// Any existing file that fails validation (corruption, tampering,
    /// insecure permissions) is a hard error: the store never silently
    /// recreates or overwrites.
    #[cfg_attr(
        all(target_arch = "wasm32", target_os = "unknown"),
        allow(unused_variables)
    )]
    pub fn load_or_create(
        dir: &Path,
        display_name: Option<&str>,
    ) -> Result<(LoadedIdentity, bool), StoreError> {
        let path = Self::identity_path(dir);
        match Self::load_path(&path) {
            Ok(loaded) => Ok((loaded, false)),
            #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
            Err(StoreError::Io { ref source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                let created = Self::create(dir, display_name)?;
                Ok((created, true))
            }
            #[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
            Err(StoreError::Io { ref source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
                // Bare wasm has no OS CSPRNG; key generation is unavailable.
                Err(StoreError::Io {
                    path,
                    context: "identity file is missing and key generation is unavailable on this target",
                    source: std::io::Error::new(
                        std::io::ErrorKind::Unsupported,
                        "no OS entropy source on wasm32-unknown-unknown; use from_seed with host entropy",
                    ),
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Loads and fully validates an existing identity (fail closed).
    pub fn load(dir: &Path) -> Result<LoadedIdentity, StoreError> {
        Self::load_path(&Self::identity_path(dir))
    }

    /// Re-validates an identity file without keeping the key in memory.
    /// Returns the public identity.
    pub fn verify_file(path: &Path) -> Result<NodeIdentity, StoreError> {
        let (_seed, identity) = Self::read_and_validate(path)?;
        Ok(identity)
    }

    /// The canonical path of the identity file for a directory.
    pub fn identity_path(dir: &Path) -> PathBuf {
        dir.join(IDENTITY_FILE_NAME)
    }

    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn create(dir: &Path, display_name: Option<&str>) -> Result<LoadedIdentity, StoreError> {
        let signing = NodeSigningKey::generate();
        let created_at = crate::identity::unix_now().map_err(StoreError::DisplayName)?;
        let identity = signing
            .node_identity(display_name, created_at)
            .map_err(StoreError::DisplayName)?;
        Self::write_atomic(dir, &signing, &identity)?;
        Ok(LoadedIdentity { signing, identity })
    }

    /// Reads, permission-checks and strictly validates the identity file.
    /// Both the seed and the public identity are returned; the seed is
    /// wrapped in a zeroize-on-drop buffer.
    fn read_and_validate(path: &Path) -> Result<(Zeroizing<[u8; SEED_LEN]>, NodeIdentity), StoreError> {
        Self::check_permissions(path)?;

        // Zeroize-on-drop file bytes.
        let raw = Zeroizing::new(Self::read_file(path)?);

        let mut decoded = cbor::decode(&raw).map_err(StoreError::Cbor)?;
        // Run extraction/validation on a borrow, then scrub the decoded
        // value (which contains the raw seed) no matter the outcome.
        let outcome = Self::extract_identity(&decoded);
        scrub_value(&mut decoded);
        drop(decoded);

        let (seed, identity) = outcome?;
        Ok((seed, identity))
    }

    fn read_file(path: &Path) -> Result<Vec<u8>, StoreError> {
        std::fs::read(path).map_err(|source| StoreError::Io {
            path: path.to_path_buf(),
            context: "reading identity file",
            source,
        })
    }

    #[cfg(unix)]
    fn check_permissions(path: &Path) -> Result<(), StoreError> {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)
            .map_err(|source| StoreError::Io {
                path: path.to_path_buf(),
                context: "stat identity file",
                source,
            })?
            .permissions()
            .mode();
        let perm_bits = mode & 0o7777;
        if perm_bits != 0o600 {
            return Err(StoreError::InsecurePermissions {
                path: path.to_path_buf(),
                mode: perm_bits,
            });
        }
        Ok(())
    }

    #[cfg(not(unix))]
    fn check_permissions(_path: &Path) -> Result<(), StoreError> {
        // Permission bits are a unix concept; nothing to check elsewhere.
        Ok(())
    }

    /// Structural extraction + full validation of the decoded file value.
    fn extract_identity(
        v: &Value,
    ) -> Result<(Zeroizing<[u8; SEED_LEN]>, NodeIdentity), StoreError> {
        let entries = v.as_map().ok_or_else(|| StoreError::InvalidFileStructure {
            reason: "top-level value must be a CBOR map".into(),
        })?;
        for (k, _) in entries {
            if !matches!(k.as_int(), Some(1..=2)) {
                return Err(StoreError::InvalidFileStructure {
                    reason: format!(
                        "unknown key {:?}; the identity file v1 has exactly keys 1 (seed) and 2 (node identity)",
                        k
                    ),
                });
            }
        }
        let seed_bytes = v
            .get_by_int(1)
            .ok_or_else(|| StoreError::InvalidFileStructure {
                reason: "key 1 (seed) is missing".into(),
            })?
            .as_bytes()
            .ok_or_else(|| StoreError::InvalidFileStructure {
                reason: "key 1 (seed) must be a byte string".into(),
            })?;
        if seed_bytes.len() != SEED_LEN {
            return Err(StoreError::InvalidFileStructure {
                reason: format!(
                    "key 1 (seed) must be {SEED_LEN} bytes, found {}",
                    seed_bytes.len()
                ),
            });
        }
        let mut seed = Zeroizing::new([0u8; SEED_LEN]);
        seed.copy_from_slice(seed_bytes);

        let identity = NodeIdentity::from_wire(
            v.get_by_int(2)
                .ok_or_else(|| StoreError::InvalidFileStructure {
                    reason: "key 2 (node identity) is missing".into(),
                })?,
        )
        .map_err(StoreError::Identity)?;

        // Cryptographic cross-check: the seed must derive exactly the public
        // key recorded in the identity object.
        let derived = NodeSigningKey::from_seed(&seed);
        if derived.public_key() != *identity.public_key() {
            return Err(StoreError::PublicKeyMismatch {
                derived_from_seed: crate::hex::encode(&derived.public_key()),
                recorded_in_object: identity.public_key_hex(),
            });
        }

        Ok((seed, identity))
    }

    /// Durable write: temp file (0600) + fsync + rename + parent fsync.
    ///
    /// Part of the local key-creation path (unavailable on bare wasm, where
    /// there is no OS entropy source).
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn write_atomic(
        dir: &Path,
        signing: &NodeSigningKey,
        identity: &NodeIdentity,
    ) -> Result<(), StoreError> {
        std::fs::create_dir_all(dir).map_err(|source| StoreError::Io {
            path: dir.to_path_buf(),
            context: "creating identity directory",
            source,
        })?;

        let seed = signing.seed(); // Zeroizing<[u8; 32]>, crate-private path
        let mut file_value = MapBuilder::new()
            .insert_int(1, Value::Bytes(seed.to_vec()))
            .insert_int(2, identity.to_wire())
            .build()
            .map_err(StoreError::from_encode)?;
        let bytes = cbor::encode(&file_value).map_err(StoreError::from_encode)?;
        // Scrub the seed copy inside the decoded value (defense in depth:
        // the only live copy remains in the zeroizing buffer above).
        scrub_value(&mut file_value);
        drop(file_value);

        let final_path = Self::identity_path(dir);
        let tmp_path = dir.join(format!(
            "{IDENTITY_FILE_NAME}.tmp.{}",
            std::process::id()
        ));

        {
            #[cfg(unix)]
            let mut options = {
                use std::os::unix::fs::OpenOptionsExt;
                let mut o = std::fs::OpenOptions::new();
                o.mode(0o600);
                o
            };
            #[cfg(not(unix))]
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            let mut file = options
                .open(&tmp_path)
                .map_err(|source| StoreError::Io {
                    path: tmp_path.clone(),
                    context: "creating identity temp file",
                    source,
                })?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|source| StoreError::Io {
                    path: tmp_path.clone(),
                    context: "writing/fsyncing identity temp file",
                    source,
                })?;
        }

        // Enforce exactly 0600 regardless of umask.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600)).map_err(
                |source| StoreError::Io {
                    path: tmp_path.clone(),
                    context: "setting identity file permissions to 0600",
                    source,
                },
            )?;
        }

        std::fs::rename(&tmp_path, &final_path).map_err(|source| StoreError::Io {
            path: tmp_path.clone(),
            context: "renaming identity file into place",
            source,
        })?;

        // fsync the parent directory so the rename itself is durable.
        #[cfg(unix)]
        {
            let dir_file = std::fs::File::open(dir).map_err(|source| StoreError::Io {
                path: dir.to_path_buf(),
                context: "opening identity directory for fsync",
                source,
            })?;
            dir_file.sync_all().map_err(|source| StoreError::Io {
                path: dir.to_path_buf(),
                context: "fsyncing identity directory",
                source,
            })?;
        }

        Ok(())
    }

    fn load_path(path: &Path) -> Result<LoadedIdentity, StoreError> {
        let (seed, identity) = Self::read_and_validate(path)?;
        let signing = NodeSigningKey::from_seed(&seed);
        Ok(LoadedIdentity { signing, identity })
    }
}

impl StoreError {
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    fn from_encode(e: cbor::EncodeError) -> StoreError {
        // Encoding the identity file cannot fail structurally; surface it as
        // an invalid structure error if it ever does.
        StoreError::InvalidFileStructure {
            reason: format!("internal encode failure: {e}"),
        }
    }
}

/// Recursively zeroizes every byte string inside a decoded CBOR value.
///
/// Used so the seed material that passes through `Value::Bytes` during
/// load/store never remains in ordinary heap buffers after we are done.
fn scrub_value(v: &mut Value) {
    match v {
        Value::Bytes(b) => b.zeroize(),
        Value::Array(items) => {
            for item in items {
                scrub_value(item);
            }
        }
        Value::Map(entries) => {
            for (k, value) in entries {
                scrub_value(k);
                scrub_value(value);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;

    #[test]
    fn create_then_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let (created, was_created) =
            IdentityStore::load_or_create(dir.path(), Some("node-a")).unwrap();
        assert!(was_created);
        let node_id = created.node_id_hex();

        let (loaded, was_created_again) =
            IdentityStore::load_or_create(dir.path(), Some("ignored-on-load")).unwrap();
        assert!(!was_created_again);
        assert_eq!(loaded.node_id_hex(), node_id);
        assert_eq!(loaded.identity().display_name(), Some("node-a"));

        // File exists with exactly 0600.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(IdentityStore::identity_path(dir.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o7777, 0o600);
        }
    }

    #[test]
    fn no_temp_files_left_behind() {
        let dir = tempfile::tempdir().unwrap();
        IdentityStore::load_or_create(dir.path(), None).unwrap();
        let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
        assert_eq!(entries.len(), 1, "only the identity file should remain");
    }

    #[test]
    fn seed_never_in_debug_output() {
        let dir = tempfile::tempdir().unwrap();
        let (loaded, _) = IdentityStore::load_or_create(dir.path(), None).unwrap();
        let dbg = format!("{loaded:?}");
        // We cannot read the seed, but we assert the debug is redacted.
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("seed"));
    }

    #[test]
    fn tampered_public_key_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (created, _) = IdentityStore::load_or_create(dir.path(), None).unwrap();
        let path = IdentityStore::identity_path(dir.path());

        let raw = std::fs::read(&path).unwrap();
        let pk_hex = created.identity().public_key_hex();
        let pk_bytes = hex::decode(&pk_hex).unwrap();
        // The public key bytes appear inside the file; flip one occurrence.
        let needle = pk_bytes[1..].to_vec();
        let pos = find_subslice(&raw, &needle).expect("pk bytes present");
        let mut tampered = raw.clone();
        tampered[pos] ^= 0x01;
        std::fs::write(&path, &tampered).unwrap();

        let err = IdentityStore::load(dir.path()).unwrap_err();
        assert!(
            matches!(err, StoreError::PublicKeyMismatch { .. }),
            "expected PublicKeyMismatch, got: {err}"
        );
    }

    #[test]
    fn tampered_seed_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let (_, _) = IdentityStore::load_or_create(dir.path(), None).unwrap();
        let path = IdentityStore::identity_path(dir.path());
        let raw = std::fs::read(&path).unwrap();
        // The seed is the first bstr payload: file starts A2 01 58 20 <seed>.
        // Flip one seed byte (offset 4).
        let mut tampered = raw.clone();
        tampered[4] ^= 0xFF;
        std::fs::write(&path, &tampered).unwrap();
        assert!(matches!(
            IdentityStore::load(dir.path()).unwrap_err(),
            StoreError::PublicKeyMismatch { .. }
        ));
    }

    #[test]
    fn tampered_display_name_still_loads_with_same_node_id() {
        // display_name is deliberately unbound metadata: editing it does not
        // invalidate the file and does not change node_id.
        let dir = tempfile::tempdir().unwrap();
        let (created, _) = IdentityStore::load_or_create(dir.path(), Some("name-a")).unwrap();
        let node_id = created.node_id_hex();
        let path = IdentityStore::identity_path(dir.path());

        // Rewrite the file with a different (valid) display name but the
        // same seed: decode, descend into the embedded NodeIdentity map
        // (file key 2, object key 4), modify, re-encode.
        let raw = std::fs::read(&path).unwrap();
        let v = crate::cbor::decode(&raw).unwrap();
        let mut file_entries = v.as_map().unwrap().to_vec();
        for (k, val) in file_entries.iter_mut() {
            if k.as_int() == Some(2) {
                let mut object_entries = val.as_map().unwrap().to_vec();
                for (object_key, object_val) in object_entries.iter_mut() {
                    if object_key.as_int() == Some(4) {
                        *object_val = Value::Text("name-b".into());
                    }
                }
                *val = crate::cbor::canonicalize_map(object_entries).unwrap();
            }
        }
        let rebuilt = crate::cbor::canonicalize_map(file_entries).unwrap();
        let bytes = crate::cbor::encode(&rebuilt).unwrap();
        std::fs::write(&path, &bytes).unwrap();

        let (loaded, was_created) = IdentityStore::load_or_create(dir.path(), None).unwrap();
        assert!(!was_created, "must not recreate");
        assert_eq!(loaded.node_id_hex(), node_id);
        assert_eq!(loaded.identity().display_name(), Some("name-b"));
    }

    #[test]
    fn swapped_seed_and_object_fails_closed() {
        let dir_a = tempfile::tempdir().unwrap();
        let dir_b = tempfile::tempdir().unwrap();
        let _ = IdentityStore::load_or_create(dir_a.path(), None).unwrap();
        let _ = IdentityStore::load_or_create(dir_b.path(), None).unwrap();

        let raw_a = std::fs::read(IdentityStore::identity_path(dir_a.path())).unwrap();
        let raw_b = std::fs::read(IdentityStore::identity_path(dir_b.path())).unwrap();
        let v_a = crate::cbor::decode(&raw_a).unwrap();
        let v_b = crate::cbor::decode(&raw_b).unwrap();
        let seed_a = v_a.get_by_int(1).unwrap().clone();
        let object_b = v_b.get_by_int(2).unwrap().clone();

        let swapped = MapBuilder::new()
            .insert(Value::Int(1), seed_a)
            .insert(Value::Int(2), object_b)
            .build()
            .unwrap();
        let bytes = crate::cbor::encode(&swapped).unwrap();
        std::fs::write(IdentityStore::identity_path(dir_a.path()), &bytes).unwrap();

        assert!(matches!(
            IdentityStore::load(dir_a.path()).unwrap_err(),
            StoreError::PublicKeyMismatch { .. }
        ));
    }

    #[test]
    fn loose_permissions_fail_closed() {
        use std::os::unix::fs::PermissionsExt;
        for mode in [0o644, 0o666, 0o640, 0o777, 0o400, 0o604] {
            let dir = tempfile::tempdir().unwrap();
            IdentityStore::load_or_create(dir.path(), None).unwrap();
            let path = IdentityStore::identity_path(dir.path());
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            let err = IdentityStore::load(dir.path()).unwrap_err();
            assert!(
                matches!(err, StoreError::InsecurePermissions { mode: m, .. } if m == mode),
                "mode {:o} must fail closed, got: {err}",
                mode
            );
            // And load_or_create must NOT silently recreate either.
            assert!(matches!(
                IdentityStore::load_or_create(dir.path(), None).unwrap_err(),
                StoreError::InsecurePermissions { .. }
            ));
        }
    }

    #[test]
    fn corrupt_and_truncated_files_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        IdentityStore::load_or_create(dir.path(), None).unwrap();
        let path = IdentityStore::identity_path(dir.path());
        let raw = std::fs::read(&path).unwrap();

        // Every truncation must fail.
        for cut in 0..raw.len() {
            std::fs::write(&path, &raw[..cut]).unwrap();
            let err = IdentityStore::load(dir.path()).unwrap_err();
            assert!(!matches!(err, StoreError::Io { .. }), "truncation at {cut} must not be treated as missing file");
        }

        // Restore the pristine file before the flip loop.
        std::fs::write(&path, &raw).unwrap();

        // Single-byte flips: everything in the cryptographically/structurally
        // bound region must fail closed. Layout (no display name):
        //   A2 01 58 20 | seed(32) | 02 A3 01 01 02 58 20 | pk(32) | 03 1A ts(4)
        //   offsets:       4..35       36 37 38 39 40 41 42   43..74    75 76 77..80
        // The created_at VALUE bytes (77..80) are deliberately unbound
        // metadata: flipping them may keep the file loadable — but then the
        // node_id MUST be unchanged.
        let node_id_before = IdentityStore::load(dir.path()).unwrap().node_id_hex();
        let created_value_start = 4 + 32 + 1 + 1 + 2 + 3 + 32 + 2; // = 77
        for i in 0..raw.len() {
            let mut flipped = raw.clone();
            flipped[i] ^= 0x80;
            std::fs::write(&path, &flipped).unwrap();
            match IdentityStore::load(dir.path()) {
                Err(_) => {
                    if i >= created_value_start {
                        // Fine: a structural rejection of the timestamp bytes
                        // (e.g. the length byte flip) is also fail-closed.
                    }
                }
                Ok(loaded) => {
                    assert!(
                        i >= created_value_start,
                        "flip at byte {i} (bound region) must fail closed"
                    );
                    assert_eq!(
                        loaded.node_id_hex(),
                        node_id_before,
                        "unbound-metadata flip may load, but node_id must not change"
                    );
                }
            }
        }

        // Restore and confirm the file loads again.
        std::fs::write(&path, &raw).unwrap();
        assert!(IdentityStore::load(dir.path()).is_ok());
    }

    #[test]
    fn scheme_version_mismatch_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        IdentityStore::load_or_create(dir.path(), None).unwrap();
        let path = IdentityStore::identity_path(dir.path());
        let raw = std::fs::read(&path).unwrap();
        // Layout: A2 01 58 20 || seed(32) || 02 A3 01 <scheme> ...
        //         offsets 0..3    4..35         36 37 38 39
        let mut tampered = raw.clone();
        let scheme_pos = 4 + 32 + 3; // = 39, the scheme value byte
        tampered[scheme_pos] = 0x02; // scheme_version = 2
        std::fs::write(&path, &tampered).unwrap();
        assert!(matches!(
            IdentityStore::load(dir.path()).unwrap_err(),
            StoreError::Identity(IdentityError::UnsupportedSchemeVersion { found: 2 })
        ));
    }

    #[test]
    fn created_file_has_expected_wire_shape() {
        let dir = tempfile::tempdir().unwrap();
        let (loaded, _) = IdentityStore::load_or_create(dir.path(), Some("shape-check")).unwrap();
        let path = IdentityStore::identity_path(dir.path());
        let raw = std::fs::read(&path).unwrap();
        let v = crate::cbor::decode(&raw).unwrap();

        assert!(v.get_by_int(1).unwrap().as_bytes().unwrap().len() == 32);
        let object = v.get_by_int(2).unwrap();
        assert_eq!(object.get_by_int(1).unwrap().as_int(), Some(1));
        assert_eq!(
            object.get_by_int(2).unwrap().as_bytes().unwrap(),
            loaded.identity().public_key().as_slice()
        );
        assert!(object.get_by_int(3).unwrap().as_int().is_some());
        assert_eq!(
            object.get_by_int(4).unwrap().as_text(),
            Some("shape-check")
        );
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        if needle.is_empty() {
            return None;
        }
        haystack
            .windows(needle.len())
            .position(|w| w == needle)
    }
}
