//! Node identity binding (R1-001).
//!
//! A ShareNet node identity is an Ed25519 (RFC 8032) key pair plus a small
//! canonical wire object:
//!
//! ```text
//! NodeIdentity = {1: scheme_version (uint, =1),
//!                 2: public_key (32-byte bstr),
//!                 3: created_at_unix (uint),
//!                 4: display_name (optional text, <= 64 bytes)}
//! ```
//!
//! The `node_id` is DERIVED, never caller-chosen (architecture lock L013
//! applies the same principle to route identity):
//!
//! ```text
//! node_id = SHA-256(canonical_cbor({1: scheme_version, 2: public_key}))
//! ```
//!
//! `display_name` and `created_at_unix` are mutable metadata and are NOT part
//! of the derivation: the identity is self-certifying — knowing the node_id
//! binds you to the key material and the scheme, while the name/timestamp can
//! change without changing the node_id.
//!
//! Signatures are detached Ed25519 signatures over arbitrary byte payloads,
//! verified strictly (malleable and non-canonical signatures are rejected).

use crate::cbor::{self, MapBuilder, Value};
use crate::hex;
use ed25519_dalek::{Signature, Signer, SigningKey as DalekSigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;
#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
use zeroize::Zeroizing;

/// The only supported identity scheme version (wire key 1).
pub const SCHEME_VERSION: u64 = 1;

/// Ed25519 public key length in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 seed length in bytes.
pub const SEED_LEN: usize = 32;

/// Ed25519 detached signature length in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Maximum byte length of the optional display name.
pub const MAX_DISPLAY_NAME_BYTES: usize = 64;

/// A ShareNet node identity (public wire object).
///
/// Construct via [`NodeIdentity::new`], [`NodeSigningKey::node_identity`] or
/// parse from the wire with [`NodeIdentity::from_wire`].
#[derive(Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    scheme_version: u64,
    public_key: [u8; PUBLIC_KEY_LEN],
    created_at_unix: u64,
    display_name: Option<String>,
}

impl NodeIdentity {
    /// Creates and validates a node identity object from public data.
    pub fn new(
        public_key: [u8; PUBLIC_KEY_LEN],
        created_at_unix: u64,
        display_name: Option<&str>,
    ) -> Result<Self, IdentityError> {
        let id = Self {
            scheme_version: SCHEME_VERSION,
            public_key,
            created_at_unix,
            display_name: display_name.map(|s| s.to_string()),
        };
        id.validate()?;
        Ok(id)
    }

    /// Scheme version (always [`SCHEME_VERSION`] after validation).
    pub fn scheme_version(&self) -> u64 {
        self.scheme_version
    }

    /// The Ed25519 public key bytes.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public_key
    }

    /// The Ed25519 public key as lowercase hex.
    pub fn public_key_hex(&self) -> String {
        hex::encode(&self.public_key)
    }

    /// Creation time in seconds since the Unix epoch.
    pub fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    /// The optional display name (mutable metadata; not part of `node_id`).
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// Validates all invariants (scheme, name length, timestamp range).
    pub fn validate(&self) -> Result<(), IdentityError> {
        if self.scheme_version != SCHEME_VERSION {
            return Err(IdentityError::UnsupportedSchemeVersion {
                found: self.scheme_version as i64,
            });
        }
        if let Some(name) = &self.display_name {
            if name.len() > MAX_DISPLAY_NAME_BYTES {
                return Err(IdentityError::DisplayNameTooLong {
                    bytes: name.len(),
                    max: MAX_DISPLAY_NAME_BYTES,
                });
            }
        }
        if self.created_at_unix > i64::MAX as u64 {
            return Err(IdentityError::TimestampOutOfRange {
                found: self.created_at_unix as i128,
            });
        }
        Ok(())
    }

    /// Serializes to the canonical CBOR wire value.
    pub fn to_wire(&self) -> Value {
        let mut builder = MapBuilder::new()
            .insert_int(1, Value::Int(SCHEME_VERSION as i64))
            .insert_int(2, Value::Bytes(self.public_key.to_vec()))
            .insert_int(3, Value::Int(self.created_at_unix as i64));
        if let Some(name) = &self.display_name {
            builder = builder.insert_int(4, Value::Text(name.clone()));
        }
        // Keys 1..=4 are distinct integers; encoding cannot fail.
        builder
            .build()
            .expect("NodeIdentity wire map has unique keys")
    }

    /// Serializes to canonical CBOR bytes.
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        cbor::encode(&self.to_wire()).expect("canonical encode of NodeIdentity cannot fail")
    }

    /// Parses and strictly validates a NodeIdentity from a CBOR wire value.
    ///
    /// Unknown keys, wrong types, a scheme version other than 1, a wrong-size
    /// public key, or an over-long display name are all rejected (fail
    /// closed).
    pub fn from_wire(v: &Value) -> Result<Self, IdentityError> {
        let entries = v.as_map().ok_or(IdentityError::NotAMap)?;
        for (k, _) in entries {
            if !matches!(k.as_int(), Some(1..=4)) {
                return Err(IdentityError::UnknownWireKey);
            }
        }
        let scheme = required_int(v, 1)?;
        if scheme < 0 || scheme as u64 != SCHEME_VERSION {
            return Err(IdentityError::UnsupportedSchemeVersion { found: scheme });
        }
        let pk_bytes = v
            .get_by_int(2)
            .ok_or(IdentityError::MissingKey(2))?
            .as_bytes()
            .ok_or(IdentityError::WrongType {
                key: 2,
                expected: "32-byte byte string",
            })?;
        if pk_bytes.len() != PUBLIC_KEY_LEN {
            return Err(IdentityError::InvalidPublicKeyLength {
                found: pk_bytes.len(),
            });
        }
        let mut public_key = [0u8; PUBLIC_KEY_LEN];
        public_key.copy_from_slice(pk_bytes);

        let created = required_int(v, 3)?;
        if created < 0 {
            return Err(IdentityError::TimestampOutOfRange {
                found: created as i128,
            });
        }

        let display_name = match v.get_by_int(4) {
            None => None,
            Some(t) => Some(
                t.as_text()
                    .ok_or(IdentityError::WrongType {
                        key: 4,
                        expected: "text string",
                    })?
                    .to_string(),
            ),
        };

        let id = Self {
            scheme_version: SCHEME_VERSION,
            public_key,
            created_at_unix: created as u64,
            display_name,
        };
        id.validate()?;
        Ok(id)
    }

    /// DERIVED node identifier: SHA-256 over the canonical CBOR of
    /// `{1: scheme_version, 2: public_key}`.
    ///
    /// This is never caller-chosen and never includes mutable metadata.
    pub fn node_id(&self) -> [u8; 32] {
        let id_material = MapBuilder::new()
            .insert_int(1, Value::Int(self.scheme_version as i64))
            .insert_int(2, Value::Bytes(self.public_key.to_vec()))
            .build()
            .expect("id material map has unique keys");
        let bytes = cbor::encode(&id_material).expect("canonical encode cannot fail");
        let digest = Sha256::digest(&bytes);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    /// The derived node id as lowercase hex (64 characters).
    pub fn node_id_hex(&self) -> String {
        hex::encode(&self.node_id())
    }
}

fn required_int(v: &Value, key: i64) -> Result<i64, IdentityError> {
    let value = v.get_by_int(key).ok_or(IdentityError::MissingKey(key))?;
    value.as_int().ok_or(IdentityError::WrongType {
        key,
        expected: "integer",
    })
}

impl fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NodeIdentity contains only public data; a full Debug is safe and
        // useful for diagnostics.
        f.debug_struct("NodeIdentity")
            .field("scheme_version", &self.scheme_version)
            .field("public_key", &self.public_key_hex())
            .field("node_id", &self.node_id_hex())
            .field("created_at_unix", &self.created_at_unix)
            .field("display_name", &self.display_name)
            .finish()
    }
}

/// The node's Ed25519 signing key. Secret material is zeroized on drop.
///
/// There is deliberately NO public accessor for the seed bytes: only
/// [`crate::store::IdentityStore`] (inside this crate) ever materializes the
/// seed, and only to persist the identity file with 0600 permissions.
pub struct NodeSigningKey {
    inner: DalekSigningKey,
}

impl NodeSigningKey {
    /// Generates a fresh key from the operating system CSPRNG.
    ///
    /// Not available on `wasm32-unknown-unknown` (no OS entropy source on
    /// bare wasm); on that target, construct keys from a host-provided seed
    /// with [`NodeSigningKey::from_seed`].
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub fn generate() -> Self {
        Self {
            inner: DalekSigningKey::generate(&mut rand::rngs::OsRng),
        }
    }

    /// Reconstructs a signing key from a 32-byte seed.
    ///
    /// Accepting seed bytes as *input* is required to load persisted
    /// identities; the inverse (extracting the seed) is crate-private.
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        Self {
            inner: DalekSigningKey::from_bytes(seed),
        }
    }

    /// The public key of this signing key.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        *self.inner.verifying_key().as_bytes()
    }

    /// Produces a detached Ed25519 signature over an arbitrary payload.
    pub fn sign(&self, payload: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.inner.sign(payload).to_bytes()
    }

    /// Builds the public [`NodeIdentity`] for this key.
    pub fn node_identity(
        &self,
        display_name: Option<&str>,
        created_at_unix: u64,
    ) -> Result<NodeIdentity, IdentityError> {
        NodeIdentity::new(self.public_key(), created_at_unix, display_name)
    }

    /// Seed bytes, for the store's exclusive use (never public).
    #[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
    pub(crate) fn seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        Zeroizing::new(self.inner.to_bytes())
    }
}

impl fmt::Debug for NodeSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // NEVER print secret material.
        f.debug_struct("NodeSigningKey")
            .field("public_key", &hex::encode(&self.public_key()))
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// Current wall-clock time in seconds since the Unix epoch.
pub fn unix_now() -> Result<u64, IdentityError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| IdentityError::ClockBeforeEpoch)
}

/// Strictly verifies a detached Ed25519 signature.
///
/// Strict verification rejects malleable signatures (e.g. non-canonical `s`
/// scalars) in addition to performing the normal RFC 8032 checks.
pub fn verify_detached(
    public_key: &[u8; PUBLIC_KEY_LEN],
    payload: &[u8],
    signature: &[u8],
) -> Result<(), IdentityError> {
    if signature.len() != SIGNATURE_LEN {
        return Err(IdentityError::SignatureMalformed {
            len: signature.len(),
        });
    }
    let vk = VerifyingKey::from_bytes(public_key).map_err(|_| IdentityError::InvalidPublicKey)?;
    let sig = Signature::from_bytes(signature.try_into().expect("length checked above"));
    vk.verify_strict(payload, &sig)
        .map_err(|_| IdentityError::SignatureVerificationFailed)
}

/// Typed identity failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// Wire value was not a CBOR map.
    NotAMap,
    /// A required wire key was absent.
    MissingKey(i64),
    /// A wire key had the wrong type.
    WrongType { key: i64, expected: &'static str },
    /// An unknown key appeared in a strict v1 object.
    UnknownWireKey,
    /// Scheme version is not 1.
    UnsupportedSchemeVersion { found: i64 },
    /// Public key byte string was not 32 bytes.
    InvalidPublicKeyLength { found: usize },
    /// Public key bytes are not a valid Ed25519 point.
    InvalidPublicKey,
    /// `created_at_unix` was negative or out of range.
    TimestampOutOfRange { found: i128 },
    /// Display name exceeded [`MAX_DISPLAY_NAME_BYTES`].
    DisplayNameTooLong { bytes: usize, max: usize },
    /// The system clock is before the Unix epoch.
    ClockBeforeEpoch,
    /// Signature byte length was not 64.
    SignatureMalformed { len: usize },
    /// Strict Ed25519 verification failed.
    SignatureVerificationFailed,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::NotAMap => write!(f, "wire object is not a CBOR map"),
            IdentityError::MissingKey(k) => write!(f, "required wire key {k} is missing"),
            IdentityError::WrongType { key, expected } => {
                write!(f, "wire key {key} has the wrong type; expected {expected}")
            }
            IdentityError::UnknownWireKey => write!(
                f,
                "unknown wire key: NodeIdentity v1 allows only keys 1..=4"
            ),
            IdentityError::UnsupportedSchemeVersion { found } => write!(
                f,
                "unsupported identity scheme version {found} (expected {SCHEME_VERSION})"
            ),
            IdentityError::InvalidPublicKeyLength { found } => write!(
                f,
                "public key must be a {PUBLIC_KEY_LEN}-byte string, found {found} bytes"
            ),
            IdentityError::InvalidPublicKey => {
                write!(f, "public key bytes are not a valid Ed25519 verification key")
            }
            IdentityError::TimestampOutOfRange { found } => write!(
                f,
                "created_at_unix {found} is negative or exceeds the i64 range"
            ),
            IdentityError::DisplayNameTooLong { bytes, max } => write!(
                f,
                "display name is {bytes} bytes; maximum is {max} bytes"
            ),
            IdentityError::ClockBeforeEpoch => {
                write!(f, "system clock is before the Unix epoch")
            }
            IdentityError::SignatureMalformed { len } => write!(
                f,
                "signature must be {SIGNATURE_LEN} bytes, found {len}"
            ),
            IdentityError::SignatureVerificationFailed => write!(
                f,
                "Ed25519 signature verification failed (strict mode)"
            ),
        }
    }
}

impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 §7.1 test vector 1.
    const RFC8032_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec,
        0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03,
        0x1c, 0xae, 0x7f, 0x60,
    ];
    const RFC8032_PK: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64,
        0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68,
        0xf7, 0x07, 0x51, 0x1a,
    ];

    #[test]
    fn rfc8032_seed_to_public_key() {
        let sk = NodeSigningKey::from_seed(&RFC8032_SEED);
        assert_eq!(sk.public_key(), RFC8032_PK);
    }

    #[test]
    fn node_id_is_deterministic_and_metadata_independent() {
        let a = NodeIdentity::new(RFC8032_PK, 1_700_000_000, Some("alpha")).unwrap();
        let b = NodeIdentity::new(RFC8032_PK, 999, None).unwrap();
        assert_eq!(a.node_id(), b.node_id());
        // Different key -> different node_id.
        let mut other_pk = RFC8032_PK;
        other_pk[0] ^= 1;
        let c = NodeIdentity::new(other_pk, 1_700_000_000, Some("alpha")).unwrap();
        assert_ne!(a.node_id(), c.node_id());
    }

    #[test]
    fn node_id_independent_cross_check() {
        // Independent hand-computed expectation:
        // canonical CBOR of {1: 1, 2: h'<pk>} = A2 01 01 02 58 20 || pk
        let mut material = Vec::new();
        material.extend_from_slice(&[0xA2, 0x01, 0x01, 0x02, 0x58, 0x20]);
        material.extend_from_slice(&RFC8032_PK);
        let digest = Sha256::digest(&material);
        let id = NodeIdentity::new(RFC8032_PK, 0, None).unwrap();
        assert_eq!(&digest[..], &id.node_id()[..]);
    }

    #[test]
    fn display_name_limits() {
        let name_64 = "x".repeat(64);
        assert!(NodeIdentity::new(RFC8032_PK, 0, Some(&name_64)).is_ok());
        let name_65 = "x".repeat(65);
        assert_eq!(
            NodeIdentity::new(RFC8032_PK, 0, Some(&name_65)),
            Err(IdentityError::DisplayNameTooLong {
                bytes: 65,
                max: 64
            })
        );
        // Byte length, not char count: 'ü' is 2 UTF-8 bytes, so 33 chars
        // = 66 bytes > 64.
        let multibyte = "ü".repeat(33);
        assert_eq!(multibyte.len(), 66);
        assert_eq!(
            NodeIdentity::new(RFC8032_PK, 0, Some(&multibyte)),
            Err(IdentityError::DisplayNameTooLong { bytes: 66, max: 64 })
        );
        // 32 chars = 64 bytes: exactly at the limit.
        let at_limit = "ü".repeat(32);
        assert_eq!(at_limit.len(), 64);
        assert!(NodeIdentity::new(RFC8032_PK, 0, Some(&at_limit)).is_ok());
    }

    #[test]
    fn sign_verify_roundtrip_and_failures() {
        let sk = NodeSigningKey::from_seed(&RFC8032_SEED);
        let payload = b"sharenet bridge payload";
        let sig = sk.sign(payload);
        assert_eq!(sig.len(), 64);
        assert!(verify_detached(&sk.public_key(), payload, &sig).is_ok());

        // Different payload (replay against wrong payload).
        assert_eq!(
            verify_detached(&sk.public_key(), b"other payload", &sig),
            Err(IdentityError::SignatureVerificationFailed)
        );
        // Different key.
        let other = NodeSigningKey::generate();
        assert_eq!(
            verify_detached(&other.public_key(), payload, &sig),
            Err(IdentityError::SignatureVerificationFailed)
        );
        // Wrong lengths.
        assert_eq!(
            verify_detached(&sk.public_key(), payload, &sig[..63]),
            Err(IdentityError::SignatureMalformed { len: 63 })
        );
        assert_eq!(
            verify_detached(&sk.public_key(), payload, &[0u8; 65]),
            Err(IdentityError::SignatureMalformed { len: 65 })
        );
    }

    #[test]
    fn debug_output_never_contains_seed() {
        let sk = NodeSigningKey::from_seed(&RFC8032_SEED);
        let dbg = format!("{sk:?}");
        assert!(!dbg.contains(&hex::encode(&RFC8032_SEED)));
        assert!(dbg.contains("<redacted>"));
    }

    #[test]
    fn wire_roundtrip() {
        let id = NodeIdentity::new(RFC8032_PK, 1_700_000_000, Some("gateway-alpha")).unwrap();
        let wire = id.to_wire();
        let parsed = NodeIdentity::from_wire(&wire).unwrap();
        assert_eq!(parsed, id);
        assert_eq!(parsed.node_id(), id.node_id());
    }
}
