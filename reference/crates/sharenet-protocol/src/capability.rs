//! Signed capability statements and admission (work item R1-004).
//!
//! A [`CapabilityStatement`] is the node-bound, Ed25519-signed declaration of
//! what a node claims it can do for the network (gateway, relay, DTN custodian,
//! infrastructure), together with an explicit validity window and optional
//! numeric limits. Per `spec/protocol-registry.yaml` the schema is:
//!
//! ```text
//! CapabilityStatement := canonical CBOR map {
//!     1: scheme_version  (=1, uint),
//!     2: node_id          (32-byte bstr, MUST equal the node_id derived from
//!                          the Ed25519 signing key per R1-001),
//!     3: capabilities     (array of text; the sorted known set — see below),
//!     4: issued_at_unix   (uint),
//!     5: expires_at_unix  (uint, > issued_at),
//!     6: limits           (optional map of text -> int),
//! }
//! ```
//!
//! The signature is an Ed25519 detached signature by the node's signing key
//! over the EXACT canonical encoding of the statement map. The carrying
//! envelope (how statement + signature travel together on a wire) is the
//! canonical CBOR map `{1: statement_bytes (bstr), 2: signature (64-byte
//! bstr)}` produced by [`SignedCapabilityStatement::to_envelope_bytes`].
//!
//! # Admission (the only consumption rule)
//!
//! [`admit`] decides whether a signed statement grants a requested capability
//! at time `now`. The check is, in order:
//!
//! 1. **Parse** — the statement bytes must decode under the canonical CBOR
//!    profile and satisfy every typed constraint above (fail-closed).
//! 2. **Binding** — `statement.node_id` MUST equal
//!    `derive_node_id(scheme_version, public_key)` for the verifying key the
//!    caller supplies (a statement cannot be replayed under a different key).
//! 3. **Signature** — strict Ed25519 verification (malleable S+L rejected,
//!    same strictness as R1-001) over the exact statement bytes.
//! 4. **Time window** — `issued_at <= now < expires_at`; before issue is
//!    [`AdmissionError::NotYetValid`], at/after expiry is
//!    [`AdmissionError::Expired`].
//! 5. **Lookup** — every requested capability must be present.
//!
//! There are NO caller-controlled trust booleans: the only inputs are the
//! bytes, the key, the time and the requested capabilities (architecture law:
//! security facts are derived from authenticated state, never asserted).
//!
//! # Determinism (byte-stability)
//!
//! - the capabilities array is canonicalized to the strictly ascending
//!   bytewise order of its wire texts (`dtn_custodian` < `gateway` <
//!   `infrastructure` < `relay`); unsorted, duplicated or empty arrays are
//!   REJECTED at parse, so exactly one byte image exists per logical statement
//!   and `encode(decode(B)) == B` holds;
//! - the limits map inherits canonical CBOR key ordering and uniqueness from
//!   the profile decoder, and is bounded ([`MAX_LIMITS_ENTRIES`] entries, keys
//!   of 1..=[`MAX_LIMIT_KEY_BYTES`] bytes) so adversarial inputs stay
//!   size-bounded;
//! - timestamps are bounded to the i64 range so the canonical-integer cast is
//!   total.
//!
//! # Persistence
//!
//! None in this module: statements are stateless wire objects. Durable
//! revocation state is R7-001 scope; admission here is purely a function of
//! the presented evidence.

use core::fmt;
use std::collections::BTreeMap;

use crate::cbor::{decode, encode, Value};
use crate::identity::{derive_node_id, Identity, NodeId};

/// Scheme version of the CapabilityStatement wire object (v1).
pub const CAP_SCHEME_VERSION: i64 = 1;
/// Maximum number of `limits` entries (adversarial size bound).
pub const MAX_LIMITS_ENTRIES: usize = 32;
/// Maximum length in bytes of one `limits` key.
pub const MAX_LIMIT_KEY_BYTES: usize = 64;

// ---------------------------------------------------------------------------
// Capability
// ---------------------------------------------------------------------------

/// A capability a node may claim. The wire texts are frozen by the registry
/// (initial set); unknown texts are rejected at parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    /// May bridge ShareNet traffic to the Internet.
    Gateway,
    /// May forward traffic between ShareNet peers.
    Relay,
    /// May hold and forward DTN content.
    DtnCustodian,
    /// May run shared infrastructure services.
    Infrastructure,
}

impl Capability {
    /// The frozen wire text for this capability.
    pub fn wire_text(&self) -> &'static str {
        match self {
            Capability::Gateway => "gateway",
            Capability::Relay => "relay",
            Capability::DtnCustodian => "dtn_custodian",
            Capability::Infrastructure => "infrastructure",
        }
    }

    /// All known capabilities, in ascending bytewise order of their wire
    /// texts (the canonical array order).
    pub const ALL: [Capability; 4] = [
        Capability::DtnCustodian,
        Capability::Gateway,
        Capability::Infrastructure,
        Capability::Relay,
    ];

    fn from_wire_text(text: &str) -> Result<Self, CapabilityError> {
        match text {
            "gateway" => Ok(Capability::Gateway),
            "relay" => Ok(Capability::Relay),
            "dtn_custodian" => Ok(Capability::DtnCustodian),
            "infrastructure" => Ok(Capability::Infrastructure),
            other => Err(CapabilityError::UnknownCapability {
                text: other.to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// CapabilityStatement
// ---------------------------------------------------------------------------

/// A parsed, validated capability statement (not yet verified — see
/// [`admit`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityStatement {
    node_id: NodeId,
    capabilities: Vec<Capability>, // strictly ascending wire-text order, non-empty
    issued_at_unix: u64,
    expires_at_unix: u64, // > issued_at
    limits: Option<BTreeMap<String, i64>>,
}

impl CapabilityStatement {
    /// Construct a statement, canonicalizing and validating it.
    ///
    /// `capabilities` may arrive in any order (duplicates collapse); the
    /// statement is stored in canonical order. `expires_at` must be strictly
    /// after `issued_at`; both must fit the canonical integer range.
    pub fn new(
        node_id: NodeId,
        capabilities: &[Capability],
        issued_at_unix: u64,
        expires_at_unix: u64,
        limits: Option<BTreeMap<String, i64>>,
    ) -> Result<Self, CapabilityError> {
        let mut caps: Vec<Capability> = capabilities.to_vec();
        if caps.is_empty() {
            return Err(CapabilityError::CapabilitiesEmpty);
        }
        // Canonical order = ascending bytewise order of wire texts. Capability
        // derives Ord on the enum declaration order, which is NOT the wire
        // order; sort explicitly by wire text.
        caps.sort_by(|a, b| a.wire_text().as_bytes().cmp(b.wire_text().as_bytes()));
        caps.dedup();
        if caps.is_empty() {
            return Err(CapabilityError::CapabilitiesEmpty);
        }
        if expires_at_unix <= issued_at_unix {
            return Err(CapabilityError::ExpiryNotAfterIssue {
                issued_at: issued_at_unix,
                expires_at: expires_at_unix,
            });
        }
        check_timestamp("issued_at", issued_at_unix)?;
        check_timestamp("expires_at", expires_at_unix)?;
        if let Some(lim) = &limits {
            check_limits(lim)?;
        }
        Ok(CapabilityStatement {
            node_id,
            capabilities: caps,
            issued_at_unix,
            expires_at_unix,
            limits,
        })
    }

    /// Parse a statement from an already-decoded CBOR value (strict).
    pub fn from_wire(v: &Value) -> Result<Self, CapabilityError> {
        let Value::Map(entries) = v else {
            return Err(CapabilityError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut node_id: Option<NodeId> = None;
        let mut capabilities: Option<Vec<Capability>> = None;
        let mut issued_at: Option<u64> = None;
        let mut expires_at: Option<u64> = None;
        let mut limits: Option<BTreeMap<String, i64>> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(CapabilityError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(CapabilityError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(CapabilityError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != CAP_SCHEME_VERSION {
                        return Err(CapabilityError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if node_id.is_some() {
                        return Err(CapabilityError::DuplicateField { key: 2 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(CapabilityError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != crate::identity::NODE_ID_LEN {
                        return Err(CapabilityError::NodeIdWrongLength { len: b.len() });
                    }
                    let arr: [u8; crate::identity::NODE_ID_LEN] =
                        b.as_slice().try_into().expect("checked length");
                    node_id = Some(NodeId::from_bytes(arr));
                }
                3 => {
                    if capabilities.is_some() {
                        return Err(CapabilityError::DuplicateField { key: 3 });
                    }
                    let Value::Array(items) = val else {
                        return Err(CapabilityError::FieldNotExpectedType { key: 3 });
                    };
                    if items.is_empty() {
                        return Err(CapabilityError::CapabilitiesEmpty);
                    }
                    let mut caps: Vec<Capability> = Vec::with_capacity(items.len());
                    for (i, item) in items.iter().enumerate() {
                        let Value::Text(t) = item else {
                            return Err(CapabilityError::CapabilityNotText);
                        };
                        if i > 0 {
                            let prev = caps[i - 1].wire_text().as_bytes();
                            if prev >= t.as_bytes() {
                                // covers both duplicates and unsorted arrays:
                                // canonical form is strictly ascending
                                return Err(CapabilityError::CapabilitiesNotSorted { at: i });
                            }
                        }
                        caps.push(Capability::from_wire_text(t)?);
                    }
                    capabilities = Some(caps);
                }
                4 => {
                    if issued_at.is_some() {
                        return Err(CapabilityError::DuplicateField { key: 4 });
                    }
                    let Value::Int(t) = val else {
                        return Err(CapabilityError::FieldNotExpectedType { key: 4 });
                    };
                    if *t < 0 {
                        return Err(CapabilityError::TimestampNegative {
                            field: "issued_at",
                            found: *t as i128,
                        });
                    }
                    issued_at = Some(*t as u64);
                }
                5 => {
                    if expires_at.is_some() {
                        return Err(CapabilityError::DuplicateField { key: 5 });
                    }
                    let Value::Int(t) = val else {
                        return Err(CapabilityError::FieldNotExpectedType { key: 5 });
                    };
                    if *t < 0 {
                        return Err(CapabilityError::TimestampNegative {
                            field: "expires_at",
                            found: *t as i128,
                        });
                    }
                    expires_at = Some(*t as u64);
                }
                6 => {
                    if limits.is_some() {
                        return Err(CapabilityError::DuplicateField { key: 6 });
                    }
                    let Value::Map(lim) = val else {
                        return Err(CapabilityError::FieldNotExpectedType { key: 6 });
                    };
                    let mut map: BTreeMap<String, i64> = BTreeMap::new();
                    if lim.len() > MAX_LIMITS_ENTRIES {
                        return Err(CapabilityError::LimitsTooManyEntries {
                            count: lim.len(),
                            max: MAX_LIMITS_ENTRIES,
                        });
                    }
                    for (lk, lv) in lim {
                        let (Value::Text(k), Value::Int(v)) = (lk, lv) else {
                            return Err(CapabilityError::LimitEntryMalformed);
                        };
                        if k.is_empty() || k.len() > MAX_LIMIT_KEY_BYTES {
                            return Err(CapabilityError::LimitKeyInvalid {
                                bytes: k.len(),
                                max: MAX_LIMIT_KEY_BYTES,
                            });
                        }
                        map.insert(k.clone(), *v);
                    }
                    limits = Some(map);
                }
                other => return Err(CapabilityError::UnknownField { key: other }),
            }
        }
        let node_id = node_id.ok_or(CapabilityError::MissingField { key: 2 })?;
        let capabilities = capabilities.ok_or(CapabilityError::MissingField { key: 3 })?;
        let issued_at = issued_at.ok_or(CapabilityError::MissingField { key: 4 })?;
        let expires_at = expires_at.ok_or(CapabilityError::MissingField { key: 5 })?;
        if scheme.is_none() {
            return Err(CapabilityError::MissingField { key: 1 });
        }
        if expires_at <= issued_at {
            return Err(CapabilityError::ExpiryNotAfterIssue {
                issued_at,
                expires_at,
            });
        }
        Ok(CapabilityStatement {
            node_id,
            capabilities,
            issued_at_unix: issued_at,
            expires_at_unix: expires_at,
            limits,
        })
    }

    /// The canonical CBOR wire form.
    pub fn to_wire(&self) -> Value {
        let mut entries: Vec<(Value, Value)> = vec![
            (Value::Int(1), Value::Int(CAP_SCHEME_VERSION)),
            (
                Value::Int(2),
                Value::Bytes(self.node_id.as_bytes().to_vec()),
            ),
            (
                Value::Int(3),
                Value::Array(
                    self.capabilities
                        .iter()
                        .map(|c| Value::Text(c.wire_text().to_string()))
                        .collect(),
                ),
            ),
            (Value::Int(4), Value::Int(self.issued_at_unix as i64)),
            (Value::Int(5), Value::Int(self.expires_at_unix as i64)),
        ];
        if let Some(limits) = &self.limits {
            entries.push((
                Value::Int(6),
                Value::Map(
                    limits
                        .iter()
                        .map(|(k, v)| (Value::Text(k.clone()), Value::Int(*v)))
                        .collect(),
                ),
            ));
        }
        Value::Map(entries)
    }

    /// The canonical wire bytes (the signature payload).
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile value: encode is total")
    }

    /// Parse from canonical wire bytes.
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, CapabilityError> {
        let v = decode(bytes).map_err(CapabilityError::Cbor)?;
        Self::from_wire(&v)
    }

    /// The bound node identifier.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// The claimed capabilities, in canonical (ascending wire-text) order.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Whether the statement claims `c`.
    pub fn has(&self, c: Capability) -> bool {
        self.capabilities.contains(&c)
    }

    /// Issuance time (seconds since the UNIX epoch).
    pub fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }

    /// Expiry time (seconds since the UNIX epoch; exclusive bound).
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    /// The optional numeric limits (consumer-interpreted; admission does not
    /// read them).
    pub fn limits(&self) -> Option<&BTreeMap<String, i64>> {
        self.limits.as_ref()
    }

    /// Sign this statement with `identity`; the identity's node_id MUST equal
    /// the statement's node_id (binding is enforced at admission, enforced
    /// here too so signers cannot construct unusable statements by accident).
    pub fn sign(&self, identity: &Identity) -> Result<SignedCapabilityStatement, CapabilityError> {
        let derived = identity.node_id();
        if derived != self.node_id {
            return Err(CapabilityError::SignerNodeMismatch {
                statement: self.node_id.to_hex(),
                signer: derived.to_hex(),
            });
        }
        let statement_bytes = self.to_wire_bytes();
        let signature = identity.sign_detached(&statement_bytes);
        Ok(SignedCapabilityStatement {
            statement_bytes,
            signature,
        })
    }
}

fn check_timestamp(field: &'static str, t: u64) -> Result<(), CapabilityError> {
    if t > i64::MAX as u64 {
        return Err(CapabilityError::TimestampOutOfRange {
            field,
            found: t as i128,
        });
    }
    Ok(())
}

fn check_limits(limits: &BTreeMap<String, i64>) -> Result<(), CapabilityError> {
    if limits.len() > MAX_LIMITS_ENTRIES {
        return Err(CapabilityError::LimitsTooManyEntries {
            count: limits.len(),
            max: MAX_LIMITS_ENTRIES,
        });
    }
    for k in limits.keys() {
        if k.is_empty() || k.len() > MAX_LIMIT_KEY_BYTES {
            return Err(CapabilityError::LimitKeyInvalid {
                bytes: k.len(),
                max: MAX_LIMIT_KEY_BYTES,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Signed statement (carrying envelope)
// ---------------------------------------------------------------------------

/// A statement plus its detached Ed25519 signature, in the exact bytes that
/// were signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCapabilityStatement {
    statement_bytes: Vec<u8>,
    signature: [u8; crate::identity::SIGNATURE_LEN],
}

impl SignedCapabilityStatement {
    /// The exact canonical statement bytes covered by the signature.
    pub fn statement_bytes(&self) -> &[u8] {
        &self.statement_bytes
    }

    /// The 64-byte detached signature.
    pub fn signature(&self) -> &[u8; crate::identity::SIGNATURE_LEN] {
        &self.signature
    }

    /// Parse the signed statement (without verifying).
    pub fn statement(&self) -> Result<CapabilityStatement, CapabilityError> {
        CapabilityStatement::from_wire_bytes(&self.statement_bytes)
    }

    /// The canonical carrying envelope:
    /// `{1: statement_bytes (bstr), 2: signature (64-byte bstr)}`.
    pub fn to_envelope_bytes(&self) -> Vec<u8> {
        let v = Value::Map(vec![
            (Value::Int(1), Value::Bytes(self.statement_bytes.clone())),
            (Value::Int(2), Value::Bytes(self.signature.to_vec())),
        ]);
        encode(&v).expect("in-profile value: encode is total")
    }

    /// Parse the canonical carrying envelope (strict; does not verify —
    /// use [`admit`] for the full check).
    pub fn from_envelope_bytes(bytes: &[u8]) -> Result<Self, CapabilityError> {
        let v = decode(bytes).map_err(CapabilityError::Cbor)?;
        let Value::Map(entries) = &v else {
            return Err(CapabilityError::NotAMap);
        };
        if entries.len() != 2 {
            return Err(CapabilityError::EnvelopeWrongEntryCount {
                count: entries.len(),
            });
        }
        let mut statement_bytes: Option<Vec<u8>> = None;
        let mut signature: Option<[u8; crate::identity::SIGNATURE_LEN]> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(CapabilityError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    let Value::Bytes(b) = val else {
                        return Err(CapabilityError::FieldNotExpectedType { key: 1 });
                    };
                    if statement_bytes.is_some() {
                        return Err(CapabilityError::DuplicateField { key: 1 });
                    }
                    statement_bytes = Some(b.clone());
                }
                2 => {
                    let Value::Bytes(b) = val else {
                        return Err(CapabilityError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != crate::identity::SIGNATURE_LEN {
                        return Err(CapabilityError::SignatureWrongLength { len: b.len() });
                    }
                    if signature.is_some() {
                        return Err(CapabilityError::DuplicateField { key: 2 });
                    }
                    signature = Some(b.as_slice().try_into().expect("checked length"));
                }
                other => return Err(CapabilityError::UnknownField { key: other }),
            }
        }
        let statement_bytes =
            statement_bytes.ok_or(CapabilityError::MissingField { key: 1 })?;
        let signature = signature.ok_or(CapabilityError::MissingField { key: 2 })?;
        Ok(SignedCapabilityStatement {
            statement_bytes,
            signature,
        })
    }
}

// ---------------------------------------------------------------------------
// Admission
// ---------------------------------------------------------------------------

/// What admission proved: the held capabilities (and the statement they came
/// from). No booleans the caller could have set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    statement: CapabilityStatement,
}

impl Admitted {
    /// The verified statement.
    pub fn statement(&self) -> &CapabilityStatement {
        &self.statement
    }

    /// The capabilities this admission proved (canonical order).
    pub fn capabilities(&self) -> &[Capability] {
        self.statement.capabilities()
    }

    /// Whether this admission proves `c` (convenience lookup).
    pub fn grants(&self, c: Capability) -> bool {
        self.statement.has(c)
    }
}

/// Why admission was refused. Every variant names the exact failed check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionError {
    /// The statement bytes did not parse (strict profile + typed checks).
    Statement(CapabilityError),
    /// The signature was not 64 bytes.
    SignatureEncodingInvalid { len: usize },
    /// Strict Ed25519 verification failed (wrong key, tampered bytes, or a
    /// malleable/non-canonical signature).
    VerificationFailed,
    /// The statement's node_id does not derive from the supplied public key.
    NodeIdMismatch {
        statement: String,
        derived: String,
    },
    /// `now` is before the statement's issued_at.
    NotYetValid { now: u64, issued_at: u64 },
    /// `now` is at or after the statement's expires_at.
    Expired { now: u64, expires_at: u64 },
    /// The statement does not claim a requested capability.
    CapabilityNotHeld {
        required: &'static str,
        held: Vec<&'static str>,
    },
}

impl fmt::Display for AdmissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdmissionError::Statement(e) => write!(f, "statement rejected: {e}"),
            AdmissionError::SignatureEncodingInvalid { len } => {
                write!(f, "signature must be 64 bytes, found {len}")
            }
            AdmissionError::VerificationFailed => {
                write!(f, "Ed25519 signature verification failed")
            }
            AdmissionError::NodeIdMismatch { statement, derived } => write!(
                f,
                "node_id binding failed: statement binds {statement}, key derives {derived}"
            ),
            AdmissionError::NotYetValid { now, issued_at } => write!(
                f,
                "statement not yet valid: now {now} < issued_at {issued_at}"
            ),
            AdmissionError::Expired { now, expires_at } => {
                write!(f, "statement expired: now {now} >= expires_at {expires_at}")
            }
            AdmissionError::CapabilityNotHeld { required, held } => write!(
                f,
                "capability {required:?} not held (statement holds {held:?})"
            ),
        }
    }
}

impl AdmissionError {
    /// Stable machine name (conformance vectors + cross-language harness).
    pub fn name(&self) -> String {
        match self {
            AdmissionError::Statement(e) => format!("statement:{}", e.name()),
            AdmissionError::SignatureEncodingInvalid { .. } => {
                "signature_encoding_invalid".to_string()
            }
            AdmissionError::VerificationFailed => "verification_failed".to_string(),
            AdmissionError::NodeIdMismatch { .. } => "node_id_mismatch".to_string(),
            AdmissionError::NotYetValid { .. } => "not_yet_valid".to_string(),
            AdmissionError::Expired { .. } => "expired".to_string(),
            AdmissionError::CapabilityNotHeld { .. } => "capability_not_held".to_string(),
        }
    }
}

impl std::error::Error for AdmissionError {}

/// Run the full admission check (parse, bind, verify, time-window, lookup).
///
/// `statement_bytes` are the EXACT bytes covered by `signature` (normally
/// `envelope[1]`). `public_key` is the Ed25519 verifying key of the claimed
/// node. `now_unix` is the caller's observation of time. `required` is the
/// set of capabilities that must be granted (empty = presence-only check).
pub fn admit(
    statement_bytes: &[u8],
    signature: &[u8],
    public_key: &[u8; crate::identity::PUBLIC_KEY_LEN],
    now_unix: u64,
    required: &[Capability],
) -> Result<Admitted, AdmissionError> {
    // 1. strict parse
    let statement = CapabilityStatement::from_wire_bytes(statement_bytes)
        .map_err(AdmissionError::Statement)?;
    // 2. node_id binding
    let derived = derive_node_id(CAP_SCHEME_VERSION, public_key);
    if *statement.node_id() != derived {
        return Err(AdmissionError::NodeIdMismatch {
            statement: statement.node_id().to_hex(),
            derived: derived.to_hex(),
        });
    }
    // 3. strict signature over the exact bytes
    let vk = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|_| AdmissionError::NodeIdMismatch {
            statement: statement.node_id().to_hex(),
            derived: derived.to_hex(),
        })?;
    if signature.len() != crate::identity::SIGNATURE_LEN {
        return Err(AdmissionError::SignatureEncodingInvalid {
            len: signature.len(),
        });
    }
    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|_| AdmissionError::SignatureEncodingInvalid {
            len: signature.len(),
        })?;
    vk.verify_strict(statement_bytes, &sig)
        .map_err(|_| AdmissionError::VerificationFailed)?;
    // 4. time window
    if now_unix < statement.issued_at_unix() {
        return Err(AdmissionError::NotYetValid {
            now: now_unix,
            issued_at: statement.issued_at_unix(),
        });
    }
    if now_unix >= statement.expires_at_unix() {
        return Err(AdmissionError::Expired {
            now: now_unix,
            expires_at: statement.expires_at_unix(),
        });
    }
    // 5. capability lookup
    for c in required {
        if !statement.has(*c) {
            return Err(AdmissionError::CapabilityNotHeld {
                required: c.wire_text(),
                held: statement
                    .capabilities()
                    .iter()
                    .map(|h| h.wire_text())
                    .collect(),
            });
        }
    }
    Ok(Admitted { statement })
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed construction/parse violations for capability statements.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    NotAMap,
    KeyNotAnInteger,
    FieldNotExpectedType { key: i64 },
    DuplicateField { key: i64 },
    UnknownField { key: i64 },
    MissingField { key: i64 },
    SchemeVersionUnsupported { found: i64 },
    NodeIdWrongLength { len: usize },
    SignatureWrongLength { len: usize },
    EnvelopeWrongEntryCount { count: usize },
    CapabilitiesEmpty,
    CapabilityNotText,
    UnknownCapability { text: String },
    CapabilitiesNotSorted { at: usize },
    TimestampNegative { field: &'static str, found: i128 },
    TimestampOutOfRange { field: &'static str, found: i128 },
    ExpiryNotAfterIssue { issued_at: u64, expires_at: u64 },
    LimitEntryMalformed,
    LimitKeyInvalid { bytes: usize, max: usize },
    LimitsTooManyEntries { count: usize, max: usize },
    SignerNodeMismatch { statement: String, signer: String },
    Cbor(crate::cbor::DecodeError),
}

impl CapabilityError {
    /// Stable machine name (conformance vectors + cross-language harness).
    pub fn name(&self) -> String {
        use CapabilityError::*;
        match self {
            NotAMap => "not_a_map",
            KeyNotAnInteger => "key_not_an_integer",
            FieldNotExpectedType { .. } => "field_not_expected_type",
            DuplicateField { .. } => "duplicate_field",
            UnknownField { .. } => "unknown_field",
            MissingField { .. } => "missing_field",
            SchemeVersionUnsupported { .. } => "scheme_version_unsupported",
            NodeIdWrongLength { .. } => "node_id_wrong_length",
            SignatureWrongLength { .. } => "signature_wrong_length",
            EnvelopeWrongEntryCount { .. } => "envelope_wrong_entry_count",
            CapabilitiesEmpty => "capabilities_empty",
            CapabilityNotText => "capability_not_text",
            UnknownCapability { .. } => "unknown_capability",
            CapabilitiesNotSorted { .. } => "capabilities_not_sorted",
            TimestampNegative { .. } => "timestamp_negative",
            TimestampOutOfRange { .. } => "timestamp_out_of_range",
            ExpiryNotAfterIssue { .. } => "expiry_not_after_issue",
            LimitEntryMalformed => "limit_entry_malformed",
            LimitKeyInvalid { .. } => "limit_key_invalid",
            LimitsTooManyEntries { .. } => "limits_too_many_entries",
            SignerNodeMismatch { .. } => "signer_node_mismatch",
            Cbor(e) => return format!("cbor:{}", e.name()),
        }
        .to_string()
    }
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use CapabilityError::*;
        match self {
            NotAMap => write!(f, "capability statement must be a CBOR map"),
            KeyNotAnInteger => write!(f, "map keys must be integers"),
            FieldNotExpectedType { key } => write!(f, "field {key} has the wrong CBOR type"),
            DuplicateField { key } => write!(f, "duplicate field {key}"),
            UnknownField { key } => write!(f, "unknown field {key}"),
            MissingField { key } => write!(f, "missing required field {key}"),
            SchemeVersionUnsupported { found } => {
                write!(f, "scheme_version {found} unsupported (expected {CAP_SCHEME_VERSION})")
            }
            NodeIdWrongLength { len } => {
                write!(f, "node_id must be 32 bytes, found {len}")
            }
            SignatureWrongLength { len } => write!(f, "signature must be 64 bytes, found {len}"),
            EnvelopeWrongEntryCount { count } => write!(
                f,
                "signed envelope must have exactly 2 entries, found {count}"
            ),
            CapabilitiesEmpty => write!(f, "capabilities array must be non-empty"),
            CapabilityNotText => write!(f, "capability entries must be text"),
            UnknownCapability { text } => write!(f, "unknown capability {text:?}"),
            CapabilitiesNotSorted { at } => write!(
                f,
                "capabilities must be strictly ascending by wire text (duplicate or unsorted at index {at})"
            ),
            TimestampNegative { field, found } => {
                write!(f, "{field} must be non-negative, found {found}")
            }
            TimestampOutOfRange { field, found } => write!(
                f,
                "{field} exceeds the canonical integer range, found {found}"
            ),
            ExpiryNotAfterIssue { issued_at, expires_at } => write!(
                f,
                "expires_at {expires_at} must be strictly after issued_at {issued_at}"
            ),
            LimitEntryMalformed => write!(f, "limits entries must be text -> integer"),
            LimitKeyInvalid { bytes, max } => write!(
                f,
                "limits key must be 1..={max} bytes, found {bytes}"
            ),
            LimitsTooManyEntries { count, max } => {
                write!(f, "limits may have at most {max} entries, found {count}")
            }
            SignerNodeMismatch { statement, signer } => write!(
                f,
                "cannot sign: statement binds node {statement}, signer identity is {signer}"
            ),
            Cbor(e) => write!(f, "CBOR profile violation: {e}"),
        }
    }
}

impl std::error::Error for CapabilityError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn node_id(byte: u8) -> NodeId {
        NodeId::from_bytes([byte; crate::identity::NODE_ID_LEN])
    }

    #[test]
    fn canonical_order_is_ascending_wire_text_and_dedups() {
        let st = CapabilityStatement::new(
            node_id(1),
            &[
                Capability::Relay,
                Capability::Gateway,
                Capability::Relay,
                Capability::Infrastructure,
                Capability::DtnCustodian,
            ],
            100,
            200,
            None,
        )
        .unwrap();
        assert_eq!(
            st.capabilities(),
            &[
                Capability::DtnCustodian,
                Capability::Gateway,
                Capability::Infrastructure,
                Capability::Relay,
            ]
        );
    }

    #[test]
    fn empty_capabilities_rejected() {
        assert!(matches!(
            CapabilityStatement::new(node_id(1), &[], 100, 200, None),
            Err(CapabilityError::CapabilitiesEmpty)
        ));
    }

    #[test]
    fn expiry_must_follow_issue() {
        assert!(matches!(
            CapabilityStatement::new(node_id(1), &[Capability::Gateway], 200, 200, None),
            Err(CapabilityError::ExpiryNotAfterIssue { .. })
        ));
        assert!(matches!(
            CapabilityStatement::new(node_id(1), &[Capability::Gateway], 201, 200, None),
            Err(CapabilityError::ExpiryNotAfterIssue { .. })
        ));
    }

    #[test]
    fn wire_roundtrip_with_limits() {
        let mut limits = BTreeMap::new();
        limits.insert("relay_max_mbps".to_string(), 100);
        limits.insert("dtn_storage_mb".to_string(), 4096);
        let st = CapabilityStatement::new(
            node_id(0xab),
            &[Capability::Gateway, Capability::DtnCustodian],
            1000,
            4600,
            Some(limits),
        )
        .unwrap();
        let bytes = st.to_wire_bytes();
        let back = CapabilityStatement::from_wire_bytes(&bytes).unwrap();
        assert_eq!(back, st);
        // byte-stability
        assert_eq!(back.to_wire_bytes(), bytes);
    }

    fn map(v: Vec<(Value, Value)>) -> Value {
        Value::Map(v)
    }

    #[test]
    fn unsorted_and_duplicate_capabilities_rejected() {
        let v = map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Bytes(vec![0u8; 32])),
            (
                Value::Int(3),
                Value::Array(vec![
                    Value::Text("relay".into()),
                    Value::Text("gateway".into()),
                ]),
            ),
            (Value::Int(4), Value::Int(1)),
            (Value::Int(5), Value::Int(2)),
        ]);
        assert!(matches!(
            CapabilityStatement::from_wire(&v),
            Err(CapabilityError::CapabilitiesNotSorted { at: 1 })
        ));
        let dup = map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Bytes(vec![0u8; 32])),
            (
                Value::Int(3),
                Value::Array(vec![
                    Value::Text("gateway".into()),
                    Value::Text("gateway".into()),
                ]),
            ),
            (Value::Int(4), Value::Int(1)),
            (Value::Int(5), Value::Int(2)),
        ]);
        assert!(matches!(
            CapabilityStatement::from_wire(&dup),
            Err(CapabilityError::CapabilitiesNotSorted { at: 1 })
        ));
    }

    #[test]
    fn unknown_capability_rejected() {
        let v = map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Bytes(vec![0u8; 32])),
            (
                Value::Int(3),
                Value::Array(vec![Value::Text("superuser".into())]),
            ),
            (Value::Int(4), Value::Int(1)),
            (Value::Int(5), Value::Int(2)),
        ]);
        assert!(matches!(
            CapabilityStatement::from_wire(&v),
            Err(CapabilityError::UnknownCapability { .. })
        ));
    }

    #[test]
    fn envelope_roundtrip() {
        let st = CapabilityStatement::new(
            node_id(7),
            &[Capability::Relay],
            10,
            20,
            None,
        )
        .unwrap();
        let mut sig = [0u8; 64];
        sig[0] = 1;
        let signed = SignedCapabilityStatement {
            statement_bytes: st.to_wire_bytes(),
            signature: sig,
        };
        let env = signed.to_envelope_bytes();
        let back = SignedCapabilityStatement::from_envelope_bytes(&env).unwrap();
        assert_eq!(back, signed);
    }
}
