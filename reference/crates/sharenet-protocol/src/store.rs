//! Durable, fail-closed identity persistence (work item R1-001).
//!
//! The identity file is strict-canonical CBOR:
//!
//! ```text
//! {1: seed (32-byte bstr), 2: NodeIdentity map}
//! ```
//!
//! # Persistence guarantees
//!
//! - **Atomic writes**: the file is written to a same-directory temporary file, fsynced,
//!   installed without clobbering (hard-link-then-unlink, with an exists-check + rename
//!   fallback on filesystems without hard links), and the parent directory is fsynced.
//! - **0600 from creation** (unix): the temporary file is created with mode 0600 and the
//!   permissions are pinned to exactly 0600 before install, regardless of umask.
//! - **Fail-closed loads**: the file must be a regular file (symlinks are refused), no
//!   more permissive than 0600, at most [`MAX_FILE_BYTES`] long, strict-canonical CBOR
//!   with the exact expected shape, and the seed must derive the public key embedded in
//!   the `NodeIdentity` object. ANY violation is an error. The store NEVER silently
//!   overwrites, recreates, or partially accepts a tampered file.
//!
//! The identity directory itself is created with mode 0700 (unix) when the store has to
//! make it; an existing directory's permissions are not enforced.
//!
//! # Expected production callers
//!
//! The `sharenet-id` bin (create/show/verify/sign/verify-signature) runs on this store
//! today, and the future ShareNet daemon will call [`IdentityStore::load_or_create`] at
//! node startup through this exact API.

use core::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::{Zeroize, Zeroizing};

use crate::cbor::{self, Value};
use crate::identity::{Identity, IdentityError, NodeIdentity};
use ed25519_dalek::SigningKey;

/// Name of the identity file inside the store directory.
pub const IDENTITY_FILE_NAME: &str = "identity.cbor";

/// Upper bound on identity file size (~120 bytes is typical; 4 KiB is generous).
pub const MAX_FILE_BYTES: u64 = 4096;

/// A directory-backed identity store.
#[derive(Debug, Clone)]
pub struct IdentityStore {
    dir: PathBuf,
}

impl IdentityStore {
    /// Open (logically) the identity store rooted at `dir`.
    pub fn new<P: AsRef<Path>>(dir: P) -> Self {
        IdentityStore {
            dir: dir.as_ref().to_path_buf(),
        }
    }

    /// Path of the identity file.
    pub fn identity_path(&self) -> PathBuf {
        self.dir.join(IDENTITY_FILE_NAME)
    }

    /// Strictly load and validate the identity, or fail closed.
    pub fn load(&self) -> Result<Identity, StoreError> {
        load_identity_file(&self.identity_path())
    }

    /// Generate a fresh identity and write it. Refuses to overwrite an existing file.
    pub fn create(&self, display_name: Option<&str>) -> Result<Identity, StoreError> {
        let path = self.identity_path();
        if std::fs::symlink_metadata(&path).is_ok() {
            return Err(StoreError::AlreadyExists { path });
        }
        let created = crate::identity::now_unix();
        let id =
            Identity::generate(created, display_name.map(str::to_string)).map_err(|source| {
                StoreError::Identity {
                    path: path.clone(),
                    source,
                }
            })?;
        write_atomic(&self.dir, &path, identity_file_bytes(&id))?;
        Ok(id)
    }

    /// Load the identity if present; otherwise generate it once and write it.
    ///
    /// Corrupt, tampered or loosely-permitted existing files FAIL CLOSED here too —
    /// there is no path that silently recreates an identity over an existing file.
    pub fn load_or_create(&self, display_name: Option<&str>) -> Result<Identity, StoreError> {
        let path = self.identity_path();
        match std::fs::symlink_metadata(&path) {
            Ok(_) => self.load(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => match self.create(display_name) {
                Ok(id) => Ok(id),
                // Lost a creation race: the winner's identity now exists — load it.
                Err(StoreError::AlreadyExists { .. }) => self.load(),
                Err(e) => Err(e),
            },
            Err(e) => Err(StoreError::Io {
                op: "stat identity",
                path,
                source: e,
            }),
        }
    }
}

/// Strictly load and validate an identity from an explicit file path.
///
/// Same guarantees as [`IdentityStore::load`]: symlink refusal, permission check,
/// strict CBOR, exact shape, seed↔object cross-check.
pub fn load_identity_file(path: &Path) -> Result<Identity, StoreError> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => StoreError::IdentityFileNotFound {
            path: path.to_path_buf(),
        },
        _ => StoreError::Io {
            op: "stat identity",
            path: path.to_path_buf(),
            source: e,
        },
    })?;
    if meta.file_type().is_symlink() {
        return Err(StoreError::RefusedSymlink {
            path: path.to_path_buf(),
        });
    }
    if !meta.is_file() {
        return Err(StoreError::NotARegularFile {
            path: path.to_path_buf(),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode() & 0o777;
        if mode & !0o600 != 0 {
            return Err(StoreError::LoosePermissions {
                path: path.to_path_buf(),
                mode,
            });
        }
    }
    if meta.len() > MAX_FILE_BYTES {
        return Err(StoreError::FileTooLarge {
            path: path.to_path_buf(),
            len: meta.len(),
        });
    }
    let bytes = std::fs::read(path).map_err(|e| StoreError::Io {
        op: "read identity",
        path: path.to_path_buf(),
        source: e,
    })?;
    parse_identity_bytes(&bytes, path)
}

/// Parse and fully validate identity file bytes.
fn parse_identity_bytes(bytes: &[u8], path: &Path) -> Result<Identity, StoreError> {
    let v = cbor::decode(bytes).map_err(|source| StoreError::Decode {
        path: path.to_path_buf(),
        source,
    })?;
    let Value::Map(entries) = &v else {
        return Err(StoreError::FileNotMap {
            path: path.to_path_buf(),
        });
    };
    let mut seed: Option<[u8; crate::identity::SEED_LEN]> = None;
    let mut node_value: Option<&Value> = None;
    for (k, val) in entries {
        let Value::Int(key) = k else {
            return Err(StoreError::FileKeyNotInteger {
                path: path.to_path_buf(),
            });
        };
        let key = *key;
        match key {
            1 => {
                if seed.is_some() {
                    return Err(StoreError::FileDuplicateField {
                        path: path.to_path_buf(),
                        key: 1,
                    });
                }
                let Value::Bytes(b) = val else {
                    return Err(StoreError::FileFieldWrongType {
                        path: path.to_path_buf(),
                        key: 1,
                    });
                };
                if b.len() != crate::identity::SEED_LEN {
                    return Err(StoreError::FileSeedWrongLength {
                        path: path.to_path_buf(),
                        len: b.len(),
                    });
                }
                seed = Some(b.as_slice().try_into().expect("checked length"));
            }
            2 => {
                if node_value.is_some() {
                    return Err(StoreError::FileDuplicateField {
                        path: path.to_path_buf(),
                        key: 2,
                    });
                }
                node_value = Some(val);
            }
            other => {
                return Err(StoreError::FileUnknownField {
                    path: path.to_path_buf(),
                    key: other,
                })
            }
        }
    }
    let seed = seed.ok_or(StoreError::FileMissingField {
        path: path.to_path_buf(),
        key: 1,
    })?;
    let node = NodeIdentity::from_wire(node_value.ok_or(StoreError::FileMissingField {
        path: path.to_path_buf(),
        key: 2,
    })?)
    .map_err(|source| StoreError::Identity {
        path: path.to_path_buf(),
        source,
    })?;

    // Cross-check: the seed must derive exactly the public key bytes in the object
    // (byte equality, not just point equality — combined with the canonical-encoding
    // check in NodeIdentity::from_wire this pins one unique key image per node_id).
    // This is what makes seed↔object swapping detectable (fail closed).
    let signing = SigningKey::from_bytes(&seed);
    if signing.verifying_key().to_bytes() != node.public_key_bytes() {
        return Err(StoreError::SeedMismatch {
            path: path.to_path_buf(),
        });
    }
    Ok(Identity::from_parts(seed, node))
}

/// Canonical bytes of the durable identity file, wrapped for zeroizing on drop.
fn identity_file_bytes(id: &Identity) -> Zeroizing<Vec<u8>> {
    let seed = id.seed(); // zeroize-on-drop copy
    let mut v = Value::Map(vec![
        (Value::Int(1), Value::Bytes(seed.to_vec())),
        (Value::Int(2), id.node_identity().to_wire()),
    ]);
    // The fixed two-entry map with distinct int keys always encodes.
    let wire = Zeroizing::new(cbor::encode(&v).expect("identity file shape always encodes"));
    // Scrub the seed copy that remains inside the intermediate value.
    if let Value::Map(entries) = &mut v {
        if let Some((_, Value::Bytes(b))) = entries.first_mut() {
            b.zeroize();
        }
    }
    wire
}

/// Ensure the identity directory exists, creating every missing component with mode
/// 0700 on unix (a component that already exists keeps its permissions).
fn ensure_dir(dir: &Path) -> Result<(), StoreError> {
    if dir.as_os_str().is_empty() || dir.exists() {
        return Ok(());
    }
    if let Some(parent) = dir.parent() {
        ensure_dir(parent)?;
    }
    let res = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(dir)
        }
        #[cfg(not(unix))]
        {
            std::fs::DirBuilder::new().create(dir)
        }
    };
    match res {
        Ok(()) => Ok(()),
        // Lost a race with a concurrent creator; that is fine.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(StoreError::Io {
            op: "create identity dir",
            path: dir.to_path_buf(),
            source: e,
        }),
    }
}

/// Atomic, no-clobber install of identity file bytes: tmp + fsync + link/unlink
/// (or exists+rename fallback) + parent-dir fsync.
fn write_atomic(dir: &Path, path: &Path, bytes: Zeroizing<Vec<u8>>) -> Result<(), StoreError> {
    ensure_dir(dir)?;

    let mut attempt = 0u32;
    loop {
        let tmp_name = format!(".{IDENTITY_FILE_NAME}.tmp.{}.{attempt}", std::process::id());
        let tmp = dir.join(tmp_name);
        let write_one = |tmp: &Path| -> Result<(), StoreError> {
            let mut f = {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(tmp)
                }
                #[cfg(not(unix))]
                {
                    std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(tmp)
                }
            }
            .map_err(|e| StoreError::Io {
                op: "create identity tmp",
                path: tmp.to_path_buf(),
                source: e,
            })?;
            f.write_all(&bytes).map_err(|e| StoreError::Io {
                op: "write identity tmp",
                path: tmp.to_path_buf(),
                source: e,
            })?;
            f.sync_all().map_err(|e| StoreError::Io {
                op: "fsync identity tmp",
                path: tmp.to_path_buf(),
                source: e,
            })?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                // Pin exactly 0600 even if umask stripped bits (umask can only remove).
                std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(0o600)).map_err(
                    |e| StoreError::Io {
                        op: "set identity perms",
                        path: tmp.to_path_buf(),
                        source: e,
                    },
                )?;
            }
            Ok(())
        };
        match write_one(&tmp) {
            Ok(()) => {
                install_no_clobber(&tmp, path)?;
                let _ = std::fs::remove_file(&tmp); // the durable file is the link target
                fsync_dir(dir)?;
                return Ok(());
            }
            Err(e) => {
                let _ = std::fs::remove_file(&tmp);
                if attempt >= 8 {
                    return Err(e);
                }
                attempt += 1; // e.g. a stale tmp with the same name; retry with a new suffix
            }
        }
    }
}

/// Install `tmp` at `path` without clobbering an existing file.
///
/// Prefers `hard_link` + `unlink` (fails atomically with EEXIST if the destination
/// exists). Falls back to an exists-check + `rename` on filesystems without hard links
/// (documented TOCTOU window in that fallback).
fn install_no_clobber(tmp: &Path, path: &Path) -> Result<(), StoreError> {
    match std::fs::hard_link(tmp, path) {
        Ok(()) => return Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(StoreError::AlreadyExists {
                path: path.to_path_buf(),
            });
        }
        Err(_) => { /* fall through to the rename fallback */ }
    }
    if path.exists() {
        return Err(StoreError::AlreadyExists {
            path: path.to_path_buf(),
        });
    }
    match std::fs::rename(tmp, path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(StoreError::AlreadyExists {
            path: path.to_path_buf(),
        }),
        Err(e) => Err(StoreError::Io {
            op: "install identity",
            path: path.to_path_buf(),
            source: e,
        }),
    }
}

fn fsync_dir(dir: &Path) -> Result<(), StoreError> {
    let f = std::fs::File::open(dir).map_err(|e| StoreError::Io {
        op: "open identity dir for fsync",
        path: dir.to_path_buf(),
        source: e,
    })?;
    f.sync_all().map_err(|e| StoreError::Io {
        op: "fsync identity dir",
        path: dir.to_path_buf(),
        source: e,
    })
}

/// Typed store violations. All of them fail closed: no silent recreation, no partial
/// acceptance, no overwrite.
#[derive(Debug)]
pub enum StoreError {
    /// Underlying I/O failure while performing `op` on `path`.
    Io {
        /// What was being done.
        op: &'static str,
        /// The file or directory involved.
        path: PathBuf,
        /// The I/O error.
        source: std::io::Error,
    },
    /// The identity file bytes are not strict-canonical CBOR.
    Decode {
        /// The file.
        path: PathBuf,
        /// The violation.
        source: cbor::DecodeError,
    },
    /// The `NodeIdentity` object inside the file is invalid.
    Identity {
        /// The file.
        path: PathBuf,
        /// The violation.
        source: IdentityError,
    },
    /// The file's top level is not a map.
    FileNotMap {
        /// The file.
        path: PathBuf,
    },
    /// A file map key is not an integer.
    FileKeyNotInteger {
        /// The file.
        path: PathBuf,
    },
    /// A required file field is missing.
    FileMissingField {
        /// The file.
        path: PathBuf,
        /// The missing field number.
        key: i64,
    },
    /// A file field appears twice.
    FileDuplicateField {
        /// The file.
        path: PathBuf,
        /// The duplicated field number.
        key: i64,
    },
    /// A file field has the wrong value type.
    FileFieldWrongType {
        /// The file.
        path: PathBuf,
        /// The offending field number.
        key: i64,
    },
    /// The file contains an unknown field.
    FileUnknownField {
        /// The file.
        path: PathBuf,
        /// The unknown field number.
        key: i64,
    },
    /// The seed in the file is not 32 bytes.
    FileSeedWrongLength {
        /// The file.
        path: PathBuf,
        /// The length that was found.
        len: usize,
    },
    /// The seed does not derive the public key in the `NodeIdentity` object.
    SeedMismatch {
        /// The file.
        path: PathBuf,
    },
    /// The identity file does not exist.
    IdentityFileNotFound {
        /// The expected file path.
        path: PathBuf,
    },
    /// The identity file is a symlink.
    RefusedSymlink {
        /// The refused path.
        path: PathBuf,
    },
    /// The identity path is not a regular file.
    NotARegularFile {
        /// The path.
        path: PathBuf,
    },
    /// The file has permission bits beyond 0600 (unix).
    LoosePermissions {
        /// The file.
        path: PathBuf,
        /// The full permission bits that were found (lower 9 bits).
        mode: u32,
    },
    /// The file exceeds [`MAX_FILE_BYTES`].
    FileTooLarge {
        /// The file.
        path: PathBuf,
        /// The size that was found.
        len: u64,
    },
    /// An identity file already exists (creation refused).
    AlreadyExists {
        /// The existing file.
        path: PathBuf,
    },
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io { op, path, source } => {
                write!(f, "failed to {op} at {}: {source}", path.display())
            }
            StoreError::Decode { path, source } => {
                write!(f, "identity file {} is not canonical CBOR: {source}", path.display())
            }
            StoreError::Identity { path, source } => {
                write!(f, "identity file {} has an invalid NodeIdentity: {source}", path.display())
            }
            StoreError::FileNotMap { path } => {
                write!(f, "identity file {} must be a CBOR map", path.display())
            }
            StoreError::FileKeyNotInteger { path } => {
                write!(f, "identity file {} has a non-integer map key", path.display())
            }
            StoreError::FileMissingField { path, key } => {
                write!(f, "identity file {} is missing field {key}", path.display())
            }
            StoreError::FileDuplicateField { path, key } => {
                write!(f, "identity file {} duplicates field {key}", path.display())
            }
            StoreError::FileFieldWrongType { path, key } => {
                write!(f, "identity file {} field {key} has the wrong type", path.display())
            }
            StoreError::FileUnknownField { path, key } => {
                write!(f, "identity file {} contains unknown field {key}", path.display())
            }
            StoreError::FileSeedWrongLength { path, len } => write!(
                f,
                "identity file {} seed must be {} bytes, found {len}",
                path.display(),
                crate::identity::SEED_LEN
            ),
            StoreError::SeedMismatch { path } => write!(
                f,
                "identity file {}: seed does not match the public key in the NodeIdentity object",
                path.display()
            ),
            StoreError::IdentityFileNotFound { path } => write!(
                f,
                "identity file not found: {} (create it first with `sharenet-id create --dir <dir>`)",
                path.display()
            ),
            StoreError::RefusedSymlink { path } => {
                write!(f, "refusing symlink identity file: {}", path.display())
            }
            StoreError::NotARegularFile { path } => {
                write!(f, "identity path is not a regular file: {}", path.display())
            }
            StoreError::LoosePermissions { path, mode } => write!(
                f,
                "identity file {} has permissions {mode:o}; refusing anything beyond 0600",
                path.display()
            ),
            StoreError::FileTooLarge { path, len } => write!(
                f,
                "identity file {} is {len} bytes (limit {MAX_FILE_BYTES})",
                path.display()
            ),
            StoreError::AlreadyExists { path } => write!(
                f,
                "identity file already exists: {} (refusing to overwrite)",
                path.display()
            ),
        }
    }
}

impl std::error::Error for StoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_file_bytes_shape() {
        let id = Identity::from_seed([7u8; 32], 12345, Some("unit-test".into())).unwrap();
        let bytes = identity_file_bytes(&id);
        let v = cbor::decode(&bytes).unwrap();
        // Round-trip through the strict parser.
        let parsed = parse_identity_bytes(&bytes, Path::new("<memory>")).unwrap();
        assert_eq!(parsed.node_id(), id.node_id());
        assert_eq!(parsed.node_identity().created_at_unix(), 12345);
        assert_eq!(parsed.node_identity().display_name(), Some("unit-test"));
        let _ = v;
    }
}
