//! Cryptographic node identity binding (work item R1-001).
//!
//! A ShareNet node's identity is an Ed25519 (RFC 8032) key pair. The wire object is the
//! [`NodeIdentity`] map; the `node_id` is DERIVED, never caller-chosen:
//!
//! ```text
//! node_id = SHA-256(canonical_cbor({1: scheme_version, 2: public_key}))
//! ```
//!
//! The identity is therefore self-certifying: knowing `node_id` binds you to the exact key
//! material and scheme version. `display_name` and `created_at_unix` are mutable metadata
//! and are deliberately NOT part of the derivation (see the adversarial tests).
//!
//! # Wire object (canonical CBOR map)
//!
//! ```text
//! {1: scheme_version (uint, =1),
//!  2: public_key (32-byte bstr),
//!  3: created_at_unix (uint, seconds since UNIX epoch),
//!  4: display_name (optional text, at most 64 bytes of UTF-8)}
//! ```
//!
//! # Signatures
//!
//! Detached signatures over arbitrary byte payloads use the node key, take and return
//! raw bytes, and are verified STRICTLY (malleable signatures with a non-canonical `S`
//! component are rejected).
//!
//! # Zeroization
//!
//! Secret key material lives only in zeroize-on-drop types:
//!
//! - the seed copy held by [`Identity`] is a `Zeroizing<[u8; 32]>`;
//! - the expanded signing key (`ed25519_dalek::SigningKey`) zeroizes on drop via the
//!   `ed25519-dalek` `zeroize` feature enabled in this crate's manifest;
//! - seed transit buffers used by the store are wrapped in `Zeroizing` and scrubbed.
//!
//! No public API hands out raw secret bytes; only the store (same crate) can request the
//! seed, and it exists solely to write the 0600 identity file.

use core::fmt;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbor::{self, Value};

/// The only identity scheme version defined by this wave (`= 1`).
pub const SCHEME_VERSION: i64 = 1;

/// Maximum byte length of `display_name` (UTF-8 bytes, not characters).
pub const MAX_DISPLAY_NAME_BYTES: usize = 64;

/// Ed25519 seed length.
pub const SEED_LEN: usize = 32;

/// Ed25519 public key (compressed point) length.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 detached signature length.
pub const SIGNATURE_LEN: usize = 64;

/// Length of a derived node identifier (SHA-256 output).
pub const NODE_ID_LEN: usize = 32;

/// A derived node identifier: `SHA-256(canonical_cbor({1: scheme_version, 2: public_key}))`.
///
/// Public information (it only binds the scheme version and the public key); safe to
/// print, log and share.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId([u8; NODE_ID_LEN]);

impl NodeId {
    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; NODE_ID_LEN] {
        &self.0
    }

    /// Lowercase hex.
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", self.to_hex())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Lowercase hex encoding for public data (keys, ids, signatures). No dependency.
pub fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// RFC 8032 canonical-encoding check for a compressed Edwards point: the y coordinate
/// (low 255 bits, little-endian) must be strictly below the field prime
/// p = 2^255 - 19. Encodings with y >= p are non-canonical and MUST be rejected so
/// that a node_id (a hash over the exact bytes) always binds to one unique key
/// encoding. (`ed25519-dalek`'s decompression alone does not enforce this.)
fn is_canonical_ed25519_point_encoding(b: &[u8; PUBLIC_KEY_LEN]) -> bool {
    let mut y = *b;
    y[31] &= 0x7f; // strip the sign bit
                   // p in little-endian bytes: 0xed, then 0xff × 30, then 0x7f
                   // (p = 2^255 - 19 = 0x7fff..ffed, so the top byte is 0x7f).
    const P: [u8; PUBLIC_KEY_LEN] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ];
    // y < p, comparing from the most significant byte (index 31) downwards.
    for i in (0..PUBLIC_KEY_LEN).rev() {
        if y[i] > P[i] {
            return false;
        }
        if y[i] < P[i] {
            return true;
        }
    }
    false // y == p is also non-canonical
}

/// Derive a node identifier from the identity-binding inputs.
///
/// `node_id = SHA-256(canonical_cbor({1: scheme_version, 2: public_key}))`.
///
/// This is the single derivation point for node identity: the identifier is always
/// computed from protocol state, never accepted from a caller (architecture law:
/// never accept caller-controlled security facts when derivation is possible).
/// Exposed publicly so the conformance vectors and the future cross-language harness
/// (R1-003) can recompute it.
pub fn derive_node_id(scheme_version: i64, public_key: &[u8; PUBLIC_KEY_LEN]) -> NodeId {
    let wire = Value::Map(vec![
        (Value::Int(1), Value::Int(scheme_version)),
        (Value::Int(2), Value::Bytes(public_key.to_vec())),
    ]);
    // Fixed two-entry map with distinct int keys: encoding cannot fail.
    let bytes = cbor::encode(&wire).expect("fixed-shape identity map always encodes");
    NodeId(Sha256::digest(&bytes).into())
}

/// The public, self-certifying node identity wire object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    public_key: VerifyingKey,
    created_at_unix: u64,
    display_name: Option<String>,
}

impl NodeIdentity {
    /// Parse and validate a [`NodeIdentity`] from a decoded CBOR value.
    ///
    /// Strict: exactly the keys 1..=3 plus optional 4, `scheme_version == 1`, a
    /// 32-byte valid Ed25519 public key, a non-negative `created_at_unix`, and a
    /// `display_name` of at most [`MAX_DISPLAY_NAME_BYTES`] bytes.
    pub fn from_wire(v: &Value) -> Result<Self, IdentityError> {
        let Value::Map(entries) = v else {
            return Err(IdentityError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut public_key: Option<VerifyingKey> = None;
        let mut created_at: Option<u64> = None;
        let mut display_name: Option<String> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(IdentityError::KeyNotAnInteger);
            };
            match key {
                1 => {
                    if scheme.is_some() {
                        return Err(IdentityError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(IdentityError::FieldNotExpectedType { key: 1 });
                    };
                    let s = *s;
                    if s != SCHEME_VERSION {
                        return Err(IdentityError::SchemeVersionUnsupported { found: s });
                    }
                    scheme = Some(s);
                }
                2 => {
                    if public_key.is_some() {
                        return Err(IdentityError::DuplicateField { key: 2 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(IdentityError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != PUBLIC_KEY_LEN {
                        return Err(IdentityError::PublicKeyWrongLength { len: b.len() });
                    }
                    let arr: [u8; PUBLIC_KEY_LEN] =
                        b.as_slice().try_into().expect("checked length");
                    if !is_canonical_ed25519_point_encoding(&arr) {
                        return Err(IdentityError::PublicKeyInvalid);
                    }
                    let vk = VerifyingKey::from_bytes(&arr)
                        .map_err(|_| IdentityError::PublicKeyInvalid)?;
                    public_key = Some(vk);
                }
                3 => {
                    if created_at.is_some() {
                        return Err(IdentityError::DuplicateField { key: 3 });
                    }
                    let Value::Int(t) = val else {
                        return Err(IdentityError::FieldNotExpectedType { key: 3 });
                    };
                    let t = *t;
                    if t < 0 {
                        return Err(IdentityError::CreatedAtOutOfRange { found: t as i128 });
                    }
                    created_at = Some(t as u64);
                }
                4 => {
                    if display_name.is_some() {
                        return Err(IdentityError::DuplicateField { key: 4 });
                    }
                    let Value::Text(s) = val else {
                        return Err(IdentityError::FieldNotExpectedType { key: 4 });
                    };
                    if s.len() > MAX_DISPLAY_NAME_BYTES {
                        return Err(IdentityError::DisplayNameTooLong {
                            bytes: s.len(),
                            max: MAX_DISPLAY_NAME_BYTES,
                        });
                    }
                    display_name = Some(s.clone());
                }
                other => return Err(IdentityError::UnknownField { key: *other }),
            }
        }
        let public_key = public_key.ok_or(IdentityError::MissingField { key: 2 })?;
        let created_at = created_at.ok_or(IdentityError::MissingField { key: 3 })?;
        if scheme.is_none() {
            return Err(IdentityError::MissingField { key: 1 });
        }
        Ok(NodeIdentity {
            public_key,
            created_at_unix: created_at,
            display_name,
        })
    }

    /// The canonical CBOR wire form of this identity.
    pub fn to_wire(&self) -> Value {
        let mut entries = vec![
            (Value::Int(1), Value::Int(SCHEME_VERSION)),
            (
                Value::Int(2),
                Value::Bytes(self.public_key_bytes().to_vec()),
            ),
            (Value::Int(3), Value::Int(self.created_at_unix as i64)),
        ];
        if let Some(name) = &self.display_name {
            entries.push((Value::Int(4), Value::Text(name.clone())));
        }
        Value::Map(entries)
    }

    /// The Ed25519 verifying key.
    pub fn public_key(&self) -> &VerifyingKey {
        &self.public_key
    }

    /// The 32-byte compressed public key.
    pub fn public_key_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.public_key.to_bytes()
    }

    /// Seconds since the UNIX epoch, as set when the identity was created.
    pub fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    /// The optional display name (mutable metadata, not part of `node_id`).
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    /// The derived node identifier (recomputed, never stored).
    pub fn node_id(&self) -> NodeId {
        derive_node_id(SCHEME_VERSION, &self.public_key_bytes())
    }

    /// Strictly verify a detached Ed25519 signature over `payload`.
    pub fn verify_detached(&self, payload: &[u8], signature: &[u8]) -> Result<(), VerifyError> {
        verify_detached_with(&self.public_key, payload, signature)
    }
}

/// Strict detached verification with an explicit verifying key.
fn verify_detached_with(
    vk: &VerifyingKey,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), VerifyError> {
    let sig =
        Signature::from_slice(signature).map_err(|_| VerifyError::SignatureEncodingInvalid {
            len: signature.len(),
        })?;
    // verify_strict rejects malleable signatures (non-canonical S component) in
    // addition to performing ordinary RFC 8032 verification.
    vk.verify_strict(payload, &sig)
        .map_err(|_| VerifyError::VerificationFailed)
}

/// A node identity: the signing key plus its public [`NodeIdentity`].
///
/// The secret seed lives in a `Zeroizing` buffer; `Debug` is redacted; there is no
/// public accessor for the raw secret bytes (only the same-crate store can request it
/// to persist the 0600 identity file).
#[derive(Clone)]
pub struct Identity {
    seed: Zeroizing<[u8; SEED_LEN]>,
    signing: SigningKey,
    node: NodeIdentity,
}

impl PartialEq for Identity {
    fn eq(&self, other: &Self) -> bool {
        // The seed determines the signing key and the public object's key, so
        // comparing seeds plus the public metadata is complete.
        *self.seed == *other.seed
            && self.node.created_at_unix == other.node.created_at_unix
            && self.node.display_name == other.node.display_name
            && self.node.public_key_bytes() == other.node.public_key_bytes()
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("node_id", &self.node_id().to_hex())
            .field("seed", &"<redacted>")
            .finish()
    }
}

impl Identity {
    /// Build an identity from an explicit 32-byte Ed25519 seed.
    ///
    /// `created_at_unix` must fit the i64 wire range (any realistic epoch-second value
    /// does); `display_name`, if present, must be at most [`MAX_DISPLAY_NAME_BYTES`]
    /// bytes of UTF-8.
    pub fn from_seed(
        seed: [u8; SEED_LEN],
        created_at_unix: u64,
        display_name: Option<String>,
    ) -> Result<Self, IdentityError> {
        if created_at_unix > i64::MAX as u64 {
            return Err(IdentityError::CreatedAtOutOfRange {
                found: created_at_unix as i128,
            });
        }
        if let Some(name) = &display_name {
            if name.len() > MAX_DISPLAY_NAME_BYTES {
                return Err(IdentityError::DisplayNameTooLong {
                    bytes: name.len(),
                    max: MAX_DISPLAY_NAME_BYTES,
                });
            }
        }
        let signing = SigningKey::from_bytes(&seed);
        let public_key = signing.verifying_key();
        Ok(Identity {
            seed: Zeroizing::new(seed),
            signing,
            node: NodeIdentity {
                public_key,
                created_at_unix,
                display_name,
            },
        })
    }

    /// Generate a fresh identity using OS entropy.
    ///
    /// On unix hosts the seed comes from `/dev/urandom`. On platforms without a
    /// supported entropy source this fails with [`IdentityError::EntropyUnavailable`];
    /// callers there must provide a seed via [`Identity::from_seed`].
    pub fn generate(
        created_at_unix: u64,
        display_name: Option<String>,
    ) -> Result<Self, IdentityError> {
        let seed = os_entropy_32()?;
        Identity::from_seed(seed, created_at_unix, display_name)
    }

    /// The public identity object.
    pub fn node_identity(&self) -> &NodeIdentity {
        &self.node
    }

    /// The derived node identifier.
    pub fn node_id(&self) -> NodeId {
        self.node.node_id()
    }

    /// Detached-sign `payload` with the node key (RFC 8032 deterministic signing).
    pub fn sign_detached(&self, payload: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signing.sign(payload).to_bytes()
    }

    /// The seed, for the durable store only (same crate); returns a zeroize-on-drop copy.
    pub(crate) fn seed(&self) -> Zeroizing<[u8; SEED_LEN]> {
        Zeroizing::new(*self.seed)
    }

    /// Reassemble an identity from an already-validated seed and public object.
    ///
    /// Same-crate only (the store, after its seed↔object cross-check). The seed must be
    /// the one that derives `node.public_key()` — the caller asserts this.
    pub(crate) fn from_parts(seed: [u8; SEED_LEN], node: NodeIdentity) -> Self {
        Identity {
            seed: Zeroizing::new(seed),
            signing: SigningKey::from_bytes(&seed),
            node,
        }
    }
}

/// Read 32 bytes of OS entropy. Unix: `/dev/urandom`. Otherwise: fail closed.
#[cfg(unix)]
pub(crate) fn os_entropy_32() -> Result<[u8; SEED_LEN], IdentityError> {
    use std::io::Read;
    use zeroize::Zeroize;
    let mut buf = [0u8; SEED_LEN];
    let result = (|| -> std::io::Result<()> {
        let mut f = std::fs::File::open("/dev/urandom")?;
        f.read_exact(&mut buf)
    })();
    match result {
        Ok(()) => Ok(buf),
        Err(_) => {
            buf.zeroize();
            Err(IdentityError::EntropyUnavailable)
        }
    }
}

/// Non-unix hosts have no configured entropy source in this wave; fail closed.
#[cfg(not(unix))]
pub(crate) fn os_entropy_32() -> Result<[u8; SEED_LEN], IdentityError> {
    Err(IdentityError::EntropyUnavailable)
}

/// Current UNIX time in seconds (0 on a clock that reads before the epoch).
pub(crate) fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Typed violations of the [`NodeIdentity`] wire contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    /// The value was not a CBOR map.
    NotAMap,
    /// A map key was not an integer.
    KeyNotAnInteger,
    /// A required field was missing (`key` is the CBOR field number).
    MissingField {
        /// The missing field number.
        key: i64,
    },
    /// A field appeared twice.
    DuplicateField {
        /// The duplicated field number.
        key: i64,
    },
    /// An unknown field number appeared (strict profile: 1..=4 only).
    UnknownField {
        /// The unknown field number.
        key: i64,
    },
    /// A field's value had the wrong CBOR type.
    FieldNotExpectedType {
        /// The offending field number.
        key: i64,
    },
    /// `scheme_version` was not the supported version.
    SchemeVersionUnsupported {
        /// The version that was found.
        found: i64,
    },
    /// The public key was not 32 bytes.
    PublicKeyWrongLength {
        /// The length that was found.
        len: usize,
    },
    /// The public key bytes were not a valid Ed25519 point encoding.
    PublicKeyInvalid,
    /// `created_at_unix` was negative or outside the wire range.
    CreatedAtOutOfRange {
        /// The value that was found.
        found: i128,
    },
    /// `display_name` exceeded the byte limit.
    DisplayNameTooLong {
        /// The byte length that was found.
        bytes: usize,
        /// The allowed maximum.
        max: usize,
    },
    /// The OS entropy source is unavailable on this platform.
    EntropyUnavailable,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IdentityError::NotAMap => write!(f, "NodeIdentity must be a CBOR map"),
            IdentityError::KeyNotAnInteger => write!(f, "NodeIdentity map keys must be integers"),
            IdentityError::MissingField { key } => {
                write!(f, "NodeIdentity is missing required field {key}")
            }
            IdentityError::DuplicateField { key } => {
                write!(f, "NodeIdentity contains field {key} more than once")
            }
            IdentityError::UnknownField { key } => write!(
                f,
                "NodeIdentity contains unknown field {key} (scheme 1 allows fields 1..=4 only)"
            ),
            IdentityError::FieldNotExpectedType { key } => {
                write!(f, "NodeIdentity field {key} has the wrong value type")
            }
            IdentityError::SchemeVersionUnsupported { found } => write!(
                f,
                "NodeIdentity scheme_version {found} is not supported (expected {SCHEME_VERSION})"
            ),
            IdentityError::PublicKeyWrongLength { len } => write!(
                f,
                "NodeIdentity public key must be {PUBLIC_KEY_LEN} bytes, found {len}"
            ),
            IdentityError::PublicKeyInvalid => {
                write!(f, "NodeIdentity public key is not a valid Ed25519 point")
            }
            IdentityError::CreatedAtOutOfRange { found } => write!(
                f,
                "NodeIdentity created_at_unix {found} is outside the accepted range"
            ),
            IdentityError::DisplayNameTooLong { bytes, max } => write!(
                f,
                "NodeIdentity display_name is {bytes} bytes; the maximum is {max}"
            ),
            IdentityError::EntropyUnavailable => write!(
                f,
                "OS entropy source unavailable on this platform; provide a seed explicitly"
            ),
        }
    }
}

impl std::error::Error for IdentityError {}

/// Typed signature verification failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifyError {
    /// The signature bytes are not a well-formed Ed25519 signature (e.g. wrong length).
    SignatureEncodingInvalid {
        /// The byte length that was supplied.
        len: usize,
    },
    /// The signature is cryptographically invalid for this key and payload
    /// (includes malleable signatures and foreign keys).
    VerificationFailed,
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::SignatureEncodingInvalid { len } => write!(
                f,
                "signature is not a well-formed Ed25519 signature ({len} bytes; expected {SIGNATURE_LEN})"
            ),
            VerifyError::VerificationFailed => write!(
                f,
                "signature verification failed (wrong key, wrong payload, or malleable signature)"
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8032 §7.1 TEST 1.
    const RFC8032_1_SEED_HEX: &str =
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
    const RFC8032_1_PK_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    fn rfc8032_1_seed() -> [u8; 32] {
        crate::testutil::from_hex(RFC8032_1_SEED_HEX)
            .try_into()
            .expect("rfc seed length")
    }

    fn rfc8032_1_pk() -> [u8; 32] {
        crate::testutil::from_hex(RFC8032_1_PK_HEX)
            .try_into()
            .expect("rfc pk length")
    }

    #[test]
    fn rfc8032_public_key_derivation() {
        let id = Identity::from_seed(rfc8032_1_seed(), 0, None).unwrap();
        assert_eq!(id.node_identity().public_key_bytes(), rfc8032_1_pk());
    }

    #[test]
    fn node_id_changes_with_scheme_and_key() {
        let id = Identity::from_seed(rfc8032_1_seed(), 0, None).unwrap();
        let pk = id.node_identity().public_key_bytes();
        let base = derive_node_id(1, &pk);
        assert_eq!(id.node_id(), base);
        let mut pk2 = pk;
        pk2[0] ^= 1;
        assert_ne!(
            derive_node_id(1, &pk2),
            base,
            "key change must change node_id"
        );
        assert_ne!(
            derive_node_id(2, &pk),
            base,
            "scheme change must change node_id"
        );
    }

    #[test]
    fn display_name_is_metadata_not_id_input() {
        let a = Identity::from_seed(rfc8032_1_seed(), 1000, None).unwrap();
        let b = Identity::from_seed(rfc8032_1_seed(), 2000, Some("renamed".into())).unwrap();
        assert_eq!(a.node_id(), b.node_id());
        // created_at is likewise excluded from derivation
        assert_ne!(
            a.node_identity().created_at_unix(),
            b.node_identity().created_at_unix()
        );
    }

    #[test]
    fn debug_redacts_seed() {
        let id = Identity::from_seed(rfc8032_1_seed(), 0, None).unwrap();
        let dbg = format!("{id:?}");
        assert!(
            !dbg.contains(&to_hex(&rfc8032_1_seed())),
            "Debug must not leak the seed"
        );
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn non_canonical_point_encodings_are_rejected() {
        // 32 × 0xff encodes y = 2^255-1 >= p (non-canonical); decompression alone
        // would accept it, which would allow two different byte images of the same
        // point (and hence two node_ids) — the profile forbids that.
        let mut wire = Value::Map(vec![
            (Value::Int(1), Value::Int(SCHEME_VERSION)),
            (Value::Int(2), Value::Bytes(vec![0xffu8; 32])),
            (Value::Int(3), Value::Int(0)),
        ]);
        assert_eq!(
            NodeIdentity::from_wire(&wire),
            Err(IdentityError::PublicKeyInvalid)
        );
        // Find a canonically-encoded y that does not decompress (no square root):
        // at least one must exist among small candidates.
        let mut found = false;
        for y0 in 2u8..=40 {
            let mut candidate = vec![0u8; 32];
            candidate[0] = y0;
            wire = Value::Map(vec![
                (Value::Int(1), Value::Int(SCHEME_VERSION)),
                (Value::Int(2), Value::Bytes(candidate)),
                (Value::Int(3), Value::Int(0)),
            ]);
            if matches!(
                NodeIdentity::from_wire(&wire),
                Err(IdentityError::PublicKeyInvalid)
            ) {
                found = true;
                break;
            }
        }
        assert!(found, "some canonical y must fail decompression");
    }

    #[test]
    fn zeroize_primitives_act_on_live_buffers() {
        // Observable zeroization of the exact primitives this crate uses for secrets.
        use zeroize::Zeroize;
        let mut live: [u8; 32] = [0x5a; 32];
        live.zeroize();
        assert!(live.iter().all(|&b| b == 0));
        let mut z = Zeroizing::new([0x5au8; 32]);
        z.zeroize(); // the same call Zeroizing's Drop performs
        assert!(z.iter().all(|&b| b == 0));
        // [u8; 32] and Vec<u8> (seed transit buffers) both implement Zeroize.
        fn assert_zeroize<T: zeroize::Zeroize>() {}
        assert_zeroize::<[u8; 32]>();
        assert_zeroize::<Vec<u8>>();
        assert_zeroize::<Zeroizing<[u8; 32]>>();
    }

    #[test]
    fn sign_verify_roundtrip_and_strictness() {
        let id = Identity::from_seed(rfc8032_1_seed(), 0, None).unwrap();
        let payload = b"sharenet";
        let sig = id.sign_detached(payload);
        assert!(id.node_identity().verify_detached(payload, &sig).is_ok());
        // Deterministic RFC 8032 signing: identical payload -> identical signature.
        assert_eq!(id.sign_detached(payload), sig);
        // Any single-bit flip in the signature must fail.
        for i in [0usize, 31, 63] {
            let mut bad = sig;
            bad[i] ^= 0x01;
            assert!(id.node_identity().verify_detached(payload, &bad).is_err());
        }
        // Wrong lengths.
        assert!(id
            .node_identity()
            .verify_detached(payload, &sig[..63])
            .is_err());
        assert!(id
            .node_identity()
            .verify_detached(payload, &[0u8; 65][..])
            .is_err());
        assert!(id.node_identity().verify_detached(payload, &[]).is_err());
        // Payload substitution (replay against a different payload) must fail.
        assert!(id.node_identity().verify_detached(b"other", &sig).is_err());
    }
}
