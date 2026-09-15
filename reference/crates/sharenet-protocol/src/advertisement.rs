//! Advertisements and discovery (work item R3-002).
//!
//! An [`Advertisement`] is the signed, self-certifying announcement that
//! makes a node discoverable: who is announcing (its `NodeIdentity`), what
//! it can do (an optional signed `CapabilityStatement` envelope), where it
//! is reachable (transport descriptors), and for how long the announcement
//! is fresh. Discovery is the first control-plane consumer of the identity
//! (R1-001), capability (R1-004) and link (R3-001) foundations.
//!
//! # Verification model (registered in `spec/protocol-registry.yaml`)
//!
//! Receivers verify, in order: strict parse → signature against the
//! embedded identity's key → freshness window (`issued_at <= now <
//! expires_at`, window bounded by [`AD_MAX_WINDOW`]) → optional capability
//! admission. Identical retransmissions are IDEMPOTENT (discovery dedups by
//! `advertisement_id`, the SHA-256 of the canonical advertisement bytes —
//! retransmission is normal on broadcast transports). A CHANGED
//! advertisement from the same node supersedes the cached one only when
//! strictly fresher (greater `issued_at`), so stale replays cannot evict a
//! newer announcement.
//!
//! There are no caller-controlled trust booleans: the only inputs are the
//! bytes, the time, and (for capability lookup) the request.
//!
//! # Transport descriptors
//!
//! `{1: kind, 2: endpoint}` pairs. The kind set is frozen for v1
//! (`udp`, `nearby`, `wifi_aware`, `quic`); endpoint syntax is
//! kind-specific and owned by the matching transport adapter (L009: the
//! protocol layer treats endpoints as opaque text; the UDP adapter
//! documents "host:port"). Unknown kinds are rejected in v1 — the
//! scheme_version gates future sets.
//!
//! # Persistence
//!
//! None: discovery state is in-memory runtime state. Durable topology
//! evidence derived from verified advertisements is R3-003 scope.

use core::fmt;

use sha2::Digest;

use crate::cbor::{decode, encode, Value};
use crate::capability::SignedCapabilityStatement;
use crate::identity::{Identity, NodeIdentity};

/// Scheme version of the Advertisement wire object (v1).
pub const AD_SCHEME_VERSION: i64 = 1;
/// Maximum freshness window (`expires_at - issued_at`).
pub const AD_MAX_WINDOW: u64 = 600;
/// Maximum number of transport descriptors per advertisement.
pub const AD_MAX_TRANSPORTS: usize = 8;
/// Maximum endpoint text length in bytes.
pub const AD_MAX_ENDPOINT_BYTES: usize = 256;

/// The frozen transport kind set (v1).
pub const AD_TRANSPORT_KINDS: [&str; 4] = ["udp", "nearby", "wifi_aware", "quic"];

/// A transport descriptor: where the announcer is reachable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportDescriptor {
    pub kind: String,
    pub endpoint: String,
}

/// A parsed (not yet verified) advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advertisement {
    identity: NodeIdentity,
    capabilities: Option<Vec<u8>>, // SignedCapabilityStatement envelope bytes
    transports: Vec<TransportDescriptor>, // strictly ascending by (kind, endpoint)
    issued_at_unix: u64,
    expires_at_unix: u64, // > issued_at; window <= AD_MAX_WINDOW
}

/// A signed advertisement and its carrying envelope bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedAdvertisement {
    advertisement_bytes: Vec<u8>,
    signature: [u8; 64],
}

impl Advertisement {
    /// Build an advertisement from the announcer's live identity.
    ///
    /// `transports` may arrive in any order (duplicates collapse to a
    /// canonical strictly-ascending order); `validity_secs` is clamped by
    /// the caller to 1..=AD_MAX_WINDOW.
    pub fn new(
        identity: &Identity,
        capabilities: Option<Vec<u8>>,
        transports: Vec<TransportDescriptor>,
        issued_at_unix: u64,
        validity_secs: u64,
    ) -> Result<Self, AdvertisementError> {
        if transports.is_empty() {
            return Err(AdvertisementError::TransportsEmpty);
        }
        let mut seen: Vec<(String, String)> = transports
            .iter()
            .map(|t| (t.kind.clone(), t.endpoint.clone()))
            .collect();
        seen.sort();
        seen.dedup();
        if seen.len() != transports.len() {
            return Err(AdvertisementError::TransportsNotUnique);
        }
        let mut sorted = transports;
        sorted.sort_by(|a, b| {
            (a.kind.as_str(), a.endpoint.as_str()).cmp(&(b.kind.as_str(), b.endpoint.as_str()))
        });
        if sorted.len() > AD_MAX_TRANSPORTS {
            return Err(AdvertisementError::TransportsTooMany {
                count: sorted.len(),
                max: AD_MAX_TRANSPORTS,
            });
        }
        for t in &sorted {
            if !AD_TRANSPORT_KINDS.contains(&t.kind.as_str()) {
                return Err(AdvertisementError::TransportKindUnknown {
                    kind: t.kind.clone(),
                });
            }
            let endpoint_bytes = t.endpoint.len();
            if endpoint_bytes == 0 || endpoint_bytes > AD_MAX_ENDPOINT_BYTES {
                return Err(AdvertisementError::EndpointInvalid {
                    bytes: endpoint_bytes,
                    max: AD_MAX_ENDPOINT_BYTES,
                });
            }
        }
        if validity_secs == 0 || validity_secs > AD_MAX_WINDOW {
            return Err(AdvertisementError::WindowInvalid {
                validity: validity_secs,
                max: AD_MAX_WINDOW,
            });
        }
        let expires_at_unix = issued_at_unix
            .checked_add(validity_secs)
            .filter(|e| *e <= i64::MAX as u64)
            .ok_or(AdvertisementError::TimestampOutOfRange)?;
        Ok(Advertisement {
            identity: identity.node_identity().clone(),
            capabilities,
            transports: sorted,
            issued_at_unix,
            expires_at_unix,
        })
    }

    /// The canonical CBOR wire form.
    pub fn to_wire(&self) -> Value {
        let mut entries: Vec<(Value, Value)> = vec![
            (Value::Int(1), Value::Int(AD_SCHEME_VERSION)),
            (Value::Int(2), self.identity.to_wire()),
        ];
        if let Some(caps) = &self.capabilities {
            entries.push((Value::Int(3), Value::Bytes(caps.clone())));
        }
        entries.push((
            Value::Int(4),
            Value::Array(
                self.transports
                    .iter()
                    .map(|t| {
                        Value::Map(vec![
                            (Value::Int(1), Value::Text(t.kind.clone())),
                            (Value::Int(2), Value::Text(t.endpoint.clone())),
                        ])
                    })
                    .collect(),
            ),
        ));
        entries.push((Value::Int(5), Value::Int(self.issued_at_unix as i64)));
        entries.push((Value::Int(6), Value::Int(self.expires_at_unix as i64)));
        Value::Map(entries)
    }

    /// The canonical wire bytes (the signature payload).
    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    /// Parse from canonical wire bytes (strict).
    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, AdvertisementError> {
        let v = decode(bytes).map_err(AdvertisementError::Cbor)?;
        Self::from_wire(&v)
    }

    /// Parse from an already-decoded CBOR value (strict).
    pub fn from_wire(v: &Value) -> Result<Self, AdvertisementError> {
        let Value::Map(entries) = v else {
            return Err(AdvertisementError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut identity: Option<NodeIdentity> = None;
        let mut capabilities: Option<Vec<u8>> = None;
        let mut transports: Option<Vec<TransportDescriptor>> = None;
        let mut issued_at: Option<u64> = None;
        let mut expires_at: Option<u64> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(AdvertisementError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(AdvertisementError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(AdvertisementError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != AD_SCHEME_VERSION {
                        return Err(AdvertisementError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if identity.is_some() {
                        return Err(AdvertisementError::DuplicateField { key: 2 });
                    }
                    identity =
                        Some(NodeIdentity::from_wire(val).map_err(AdvertisementError::Identity)?);
                }
                3 => {
                    if capabilities.is_some() {
                        return Err(AdvertisementError::DuplicateField { key: 3 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(AdvertisementError::FieldNotExpectedType { key: 3 });
                    };
                    capabilities = Some(b.clone());
                }
                4 => {
                    if transports.is_some() {
                        return Err(AdvertisementError::DuplicateField { key: 4 });
                    }
                    let Value::Array(items) = val else {
                        return Err(AdvertisementError::FieldNotExpectedType { key: 4 });
                    };
                    if items.is_empty() {
                        return Err(AdvertisementError::TransportsEmpty);
                    }
                    if items.len() > AD_MAX_TRANSPORTS {
                        return Err(AdvertisementError::TransportsTooMany {
                            count: items.len(),
                            max: AD_MAX_TRANSPORTS,
                        });
                    }
                    let mut out: Vec<TransportDescriptor> = Vec::with_capacity(items.len());
                    for (i, item) in items.iter().enumerate() {
                        let Value::Map(t) = item else {
                            return Err(AdvertisementError::TransportMalformed);
                        };
                        let mut kind: Option<String> = None;
                        let mut endpoint: Option<String> = None;
                        for (tk, tv) in t {
                            let Value::Int(tkey) = tk else {
                                return Err(AdvertisementError::TransportMalformed);
                            };
                            match *tkey {
                                1 => {
                                    if kind.is_some() {
                                        return Err(AdvertisementError::TransportMalformed);
                                    }
                                    let Value::Text(k) = tv else {
                                        return Err(AdvertisementError::TransportMalformed);
                                    };
                                    kind = Some(k.clone());
                                }
                                2 => {
                                    if endpoint.is_some() {
                                        return Err(AdvertisementError::TransportMalformed);
                                    }
                                    let Value::Text(e) = tv else {
                                        return Err(AdvertisementError::TransportMalformed);
                                    };
                                    endpoint = Some(e.clone());
                                }
                                _ => return Err(AdvertisementError::TransportMalformed),
                            }
                        }
                        let kind = kind.ok_or(AdvertisementError::TransportMalformed)?;
                        let endpoint = endpoint.ok_or(AdvertisementError::TransportMalformed)?;
                        if !AD_TRANSPORT_KINDS.contains(&kind.as_str()) {
                            return Err(AdvertisementError::TransportKindUnknown { kind });
                        }
                        if endpoint.is_empty() || endpoint.len() > AD_MAX_ENDPOINT_BYTES {
                            return Err(AdvertisementError::EndpointInvalid {
                                bytes: endpoint.len(),
                                max: AD_MAX_ENDPOINT_BYTES,
                            });
                        }
                        if i > 0 {
                            let prev = &out[i - 1];
                            if (prev.kind.as_str(), prev.endpoint.as_str())
                                >= (kind.as_str(), endpoint.as_str())
                            {
                                return Err(AdvertisementError::TransportsNotSorted { at: i });
                            }
                        }
                        out.push(TransportDescriptor { kind, endpoint });
                    }
                    transports = Some(out);
                }
                5 => {
                    if issued_at.is_some() {
                        return Err(AdvertisementError::DuplicateField { key: 5 });
                    }
                    let Value::Int(t) = val else {
                        return Err(AdvertisementError::FieldNotExpectedType { key: 5 });
                    };
                    if *t < 0 {
                        return Err(AdvertisementError::TimestampNegative {
                            field: "issued_at",
                            found: *t as i128,
                        });
                    }
                    issued_at = Some(*t as u64);
                }
                6 => {
                    if expires_at.is_some() {
                        return Err(AdvertisementError::DuplicateField { key: 6 });
                    }
                    let Value::Int(t) = val else {
                        return Err(AdvertisementError::FieldNotExpectedType { key: 6 });
                    };
                    if *t < 0 {
                        return Err(AdvertisementError::TimestampNegative {
                            field: "expires_at",
                            found: *t as i128,
                        });
                    }
                    expires_at = Some(*t as u64);
                }
                other => return Err(AdvertisementError::UnknownField { key: other }),
            }
        }
        let identity = identity.ok_or(AdvertisementError::MissingField { key: 2 })?;
        let transports = transports.ok_or(AdvertisementError::MissingField { key: 4 })?;
        let issued_at = issued_at.ok_or(AdvertisementError::MissingField { key: 5 })?;
        let expires_at = expires_at.ok_or(AdvertisementError::MissingField { key: 6 })?;
        if scheme.is_none() {
            return Err(AdvertisementError::MissingField { key: 1 });
        }
        if expires_at <= issued_at {
            return Err(AdvertisementError::ExpiryNotAfterIssue {
                issued_at,
                expires_at,
            });
        }
        if expires_at - issued_at > AD_MAX_WINDOW {
            return Err(AdvertisementError::WindowInvalid {
                validity: expires_at - issued_at,
                max: AD_MAX_WINDOW,
            });
        }
        Ok(Advertisement {
            identity,
            capabilities,
            transports,
            issued_at_unix: issued_at,
            expires_at_unix: expires_at,
        })
    }

    /// Sign this advertisement with `identity` (whose key must derive the
    /// advertisement's node_id).
    pub fn sign(&self, identity: &Identity) -> Result<SignedAdvertisement, AdvertisementError> {
        if identity.node_id() != self.identity.node_id() {
            return Err(AdvertisementError::SignerNodeMismatch {
                advertisement: self.identity.node_id().to_hex(),
                signer: identity.node_id().to_hex(),
            });
        }
        let advertisement_bytes = self.to_wire_bytes();
        let signature = identity.sign_detached(&advertisement_bytes);
        Ok(SignedAdvertisement {
            advertisement_bytes,
            signature,
        })
    }

    pub fn identity(&self) -> &NodeIdentity {
        &self.identity
    }

    pub fn node_id(&self) -> crate::identity::NodeId {
        self.identity.node_id()
    }

    pub fn capabilities(&self) -> Option<&[u8]> {
        self.capabilities.as_deref()
    }

    pub fn transports(&self) -> &[TransportDescriptor] {
        &self.transports
    }

    pub fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

impl SignedAdvertisement {
    /// Re-assemble from raw parts (tests + cross-language harness paths).
    pub fn from_parts(
        advertisement_bytes: Vec<u8>,
        signature: [u8; 64],
    ) -> Self {
        SignedAdvertisement {
            advertisement_bytes,
            signature,
        }
    }

    pub fn advertisement_bytes(&self) -> &[u8] {
        &self.advertisement_bytes
    }

    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Parse the inner advertisement (without verifying).
    pub fn advertisement(&self) -> Result<Advertisement, AdvertisementError> {
        Advertisement::from_wire_bytes(&self.advertisement_bytes)
    }

    /// The content-derived advertisement identifier (SHA-256 of the
    /// canonical bytes).
    pub fn advertisement_id(&self) -> [u8; 32] {
        let mut id = [0u8; 32];
        id.copy_from_slice(&sha2::Sha256::digest(&self.advertisement_bytes));
        id
    }

    /// Carrying envelope: canonical CBOR {1: advertisement, 2: signature}.
    pub fn to_envelope_bytes(&self) -> Vec<u8> {
        let v = Value::Map(vec![
            (Value::Int(1), Value::Bytes(self.advertisement_bytes.clone())),
            (Value::Int(2), Value::Bytes(self.signature.to_vec())),
        ]);
        encode(&v).expect("in-profile")
    }

    /// Parse the carrying envelope (strict; does not verify).
    pub fn from_envelope_bytes(bytes: &[u8]) -> Result<Self, AdvertisementError> {
        let v = decode(bytes).map_err(AdvertisementError::Cbor)?;
        let Value::Map(entries) = &v else {
            return Err(AdvertisementError::NotAMap);
        };
        if entries.len() != 2 {
            return Err(AdvertisementError::EnvelopeWrongEntryCount {
                count: entries.len(),
            });
        }
        let mut advertisement_bytes: Option<Vec<u8>> = None;
        let mut signature: Option<[u8; 64]> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(AdvertisementError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    let Value::Bytes(b) = val else {
                        return Err(AdvertisementError::FieldNotExpectedType { key: 1 });
                    };
                    if advertisement_bytes.is_some() {
                        return Err(AdvertisementError::DuplicateField { key: 1 });
                    }
                    advertisement_bytes = Some(b.clone());
                }
                2 => {
                    let Value::Bytes(b) = val else {
                        return Err(AdvertisementError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != 64 {
                        return Err(AdvertisementError::SignatureWrongLength { len: b.len() });
                    }
                    if signature.is_some() {
                        return Err(AdvertisementError::DuplicateField { key: 2 });
                    }
                    signature = Some(b.as_slice().try_into().expect("checked"));
                }
                other => return Err(AdvertisementError::UnknownField { key: other }),
            }
        }
        Ok(SignedAdvertisement {
            advertisement_bytes: advertisement_bytes
                .ok_or(AdvertisementError::MissingField { key: 1 })?,
            signature: signature.ok_or(AdvertisementError::MissingField { key: 2 })?,
        })
    }
}

/// Why a received advertisement was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvertisementError {
    NotAMap,
    KeyNotAnInteger,
    FieldNotExpectedType { key: i64 },
    DuplicateField { key: i64 },
    UnknownField { key: i64 },
    MissingField { key: i64 },
    SchemeVersionUnsupported { found: i64 },
    Identity(crate::identity::IdentityError),
    Cbor(crate::cbor::DecodeError),
    TransportsEmpty,
    TransportsNotUnique,
    TransportsNotSorted { at: usize },
    TransportsTooMany { count: usize, max: usize },
    TransportKindUnknown { kind: String },
    TransportMalformed,
    EndpointInvalid { bytes: usize, max: usize },
    TimestampNegative { field: &'static str, found: i128 },
    TimestampOutOfRange,
    ExpiryNotAfterIssue { issued_at: u64, expires_at: u64 },
    WindowInvalid { validity: u64, max: u64 },
    SignatureWrongLength { len: usize },
    EnvelopeWrongEntryCount { count: usize },
    SignerNodeMismatch { advertisement: String, signer: String },
    /// Freshness: now < issued_at.
    NotYetValid { now: u64, issued_at: u64 },
    /// Freshness: now >= expires_at.
    Expired { now: u64, expires_at: u64 },
    /// Strict Ed25519 verification failed.
    SignatureInvalid,
    /// The optional capability envelope failed admission under the
    /// announcer's identity.
    CapabilityRejected { reason: String },
}

impl AdvertisementError {
    /// Stable machine name (conformance vectors + harness).
    pub fn name(&self) -> String {
        match self {
            AdvertisementError::NotAMap => "not_a_map",
            AdvertisementError::KeyNotAnInteger => "key_not_an_integer",
            AdvertisementError::FieldNotExpectedType { .. } => "field_not_expected_type",
            AdvertisementError::DuplicateField { .. } => "duplicate_field",
            AdvertisementError::UnknownField { .. } => "unknown_field",
            AdvertisementError::MissingField { .. } => "missing_field",
            AdvertisementError::SchemeVersionUnsupported { .. } => "scheme_version_unsupported",
            AdvertisementError::Identity(e) => return format!("identity:{}", e.name()),
            AdvertisementError::Cbor(e) => return format!("cbor:{}", e.name()),
            AdvertisementError::TransportsEmpty => "transports_empty",
            AdvertisementError::TransportsNotUnique => "transports_not_unique",
            AdvertisementError::TransportsNotSorted { .. } => "transports_not_sorted",
            AdvertisementError::TransportsTooMany { .. } => "transports_too_many",
            AdvertisementError::TransportKindUnknown { .. } => "transport_kind_unknown",
            AdvertisementError::TransportMalformed => "transport_malformed",
            AdvertisementError::EndpointInvalid { .. } => "endpoint_invalid",
            AdvertisementError::TimestampNegative { .. } => "timestamp_negative",
            AdvertisementError::TimestampOutOfRange => "timestamp_out_of_range",
            AdvertisementError::ExpiryNotAfterIssue { .. } => "expiry_not_after_issue",
            AdvertisementError::WindowInvalid { .. } => "window_invalid",
            AdvertisementError::SignatureWrongLength { .. } => "signature_wrong_length",
            AdvertisementError::EnvelopeWrongEntryCount { .. } => "envelope_wrong_entry_count",
            AdvertisementError::SignerNodeMismatch { .. } => "signer_node_mismatch",
            AdvertisementError::NotYetValid { .. } => "not_yet_valid",
            AdvertisementError::Expired { .. } => "expired",
            AdvertisementError::SignatureInvalid => "signature_invalid",
            AdvertisementError::CapabilityRejected { .. } => "capability_rejected",
        }
        .to_string()
    }
}

impl fmt::Display for AdvertisementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdvertisementError::NotAMap => write!(f, "advertisement must be a CBOR map"),
            AdvertisementError::KeyNotAnInteger => write!(f, "map keys must be integers"),
            AdvertisementError::FieldNotExpectedType { key } => {
                write!(f, "field {key} has the wrong CBOR type")
            }
            AdvertisementError::DuplicateField { key } => write!(f, "duplicate field {key}"),
            AdvertisementError::UnknownField { key } => write!(f, "unknown field {key}"),
            AdvertisementError::MissingField { key } => write!(f, "missing required field {key}"),
            AdvertisementError::SchemeVersionUnsupported { found } => {
                write!(f, "scheme_version {found} unsupported (expected {AD_SCHEME_VERSION})")
            }
            AdvertisementError::Identity(e) => write!(f, "announcer identity rejected: {e}"),
            AdvertisementError::Cbor(e) => write!(f, "CBOR profile violation: {e}"),
            AdvertisementError::TransportsEmpty => {
                write!(f, "transports array must be non-empty")
            }
            AdvertisementError::TransportsNotUnique => {
                write!(f, "duplicate transport descriptors are rejected")
            }
            AdvertisementError::TransportsNotSorted { at } => write!(
                f,
                "transports must be strictly ascending by (kind, endpoint) at index {at}"
            ),
            AdvertisementError::TransportsTooMany { count, max } => {
                write!(f, "at most {max} transports, found {count}")
            }
            AdvertisementError::TransportKindUnknown { kind } => write!(
                f,
                "unknown transport kind {kind:?} (v1: udp, nearby, wifi_aware, quic)"
            ),
            AdvertisementError::TransportMalformed => {
                write!(f, "transport descriptor must be {{1: kind, 2: endpoint}}")
            }
            AdvertisementError::EndpointInvalid { bytes, max } => {
                write!(f, "endpoint must be 1..={max} bytes, found {bytes}")
            }
            AdvertisementError::TimestampNegative { field, found } => {
                write!(f, "{field} must be non-negative, found {found}")
            }
            AdvertisementError::TimestampOutOfRange => {
                write!(f, "timestamps exceed the canonical integer range")
            }
            AdvertisementError::ExpiryNotAfterIssue { issued_at, expires_at } => write!(
                f,
                "expires_at {expires_at} must be strictly after issued_at {issued_at}"
            ),
            AdvertisementError::WindowInvalid { validity, max } => {
                write!(f, "validity {validity}s exceeds the {max}s bound")
            }
            AdvertisementError::SignatureWrongLength { len } => {
                write!(f, "signature must be 64 bytes, found {len}")
            }
            AdvertisementError::EnvelopeWrongEntryCount { count } => write!(
                f,
                "carrying envelope must have exactly 2 entries, found {count}"
            ),
            AdvertisementError::SignerNodeMismatch { advertisement, signer } => write!(
                f,
                "cannot sign: advertisement binds {advertisement}, signer is {signer}"
            ),
            AdvertisementError::NotYetValid { now, issued_at } => {
                write!(f, "advertisement not yet valid: now {now} < issued_at {issued_at}")
            }
            AdvertisementError::Expired { now, expires_at } => {
                write!(f, "advertisement expired: now {now} >= expires_at {expires_at}")
            }
            AdvertisementError::SignatureInvalid => {
                write!(f, "advertisement signature verification failed")
            }
            AdvertisementError::CapabilityRejected { reason } => {
                write!(f, "capability envelope rejected: {reason}")
            }
        }
    }
}

impl std::error::Error for AdvertisementError {}

// ---------------------------------------------------------------------------
// Discovery cache
// ---------------------------------------------------------------------------

/// What a receiver did with an incoming advertisement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryOutcome {
    /// First (or strictly fresher) verified advertisement from this node —
    /// the cache now holds it.
    Discovered,
    /// Byte-identical retransmission of the cached advertisement —
    /// idempotent, no state change.
    Duplicate,
    /// An advertisement from the same node with an OLDER-or-equal
    /// issued_at than the cached one — rejected without evicting the
    /// newer advertisement (stale replay protection).
    Stale,
}

/// In-memory discovery state: verified advertisements keyed by node_id,
/// with freshness bookkeeping. Persistence: none (runtime state; durable
/// topology evidence is R3-003).
#[derive(Debug, Default)]
pub struct DiscoveryCache {
    entries: std::collections::HashMap<[u8; 32], (u64, Vec<u8>)>, // node_id -> (issued_at, ad_id)
}

impl DiscoveryCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Full receiver-side verification + dedup for one signed
    /// advertisement.
    pub fn receive(
        &mut self,
        signed: &SignedAdvertisement,
        now_unix: u64,
    ) -> Result<DiscoveryOutcome, AdvertisementError> {
        // 1. strict parse
        let ad = signed.advertisement()?;
        // 2. signature against the embedded identity
        ad.identity()
            .verify_detached(&signed.advertisement_bytes, &signed.signature)
            .map_err(|_| AdvertisementError::SignatureInvalid)?;
        // 3. freshness window
        if now_unix < ad.issued_at_unix() {
            return Err(AdvertisementError::NotYetValid {
                now: now_unix,
                issued_at: ad.issued_at_unix(),
            });
        }
        if now_unix >= ad.expires_at_unix() {
            return Err(AdvertisementError::Expired {
                now: now_unix,
                expires_at: ad.expires_at_unix(),
            });
        }
        // 4. optional capability admission (binding + signature only;
        //    capability LOOKUP is the caller's concern)
        if let Some(env) = ad.capabilities() {
            let parsed = SignedCapabilityStatement::from_envelope_bytes(env)
                .map_err(|e| AdvertisementError::CapabilityRejected {
                    reason: e.to_string(),
                })?;
            let statement = parsed.statement().map_err(|e| {
                AdvertisementError::CapabilityRejected {
                    reason: e.to_string(),
                }
            })?;
            if statement.node_id() != &ad.identity().node_id() {
                return Err(AdvertisementError::CapabilityRejected {
                    reason: "capability envelope binds a different node".into(),
                });
            }
            ad.identity()
                .verify_detached(parsed.statement_bytes(), parsed.signature())
                .map_err(|_| AdvertisementError::CapabilityRejected {
                    reason: "capability envelope signature failed".into(),
                })?;
        }
        // 5. dedup / staleness
        let ad_id = signed.advertisement_id();
        let node_id = ad.identity().node_id();
        let key: [u8; 32] = *node_id.as_bytes();
        match self.entries.get(&key) {
            Some((cached_issued, cached_id)) => {
                if cached_id == &ad_id {
                    return Ok(DiscoveryOutcome::Duplicate);
                }
                if ad.issued_at_unix() <= *cached_issued {
                    return Ok(DiscoveryOutcome::Stale);
                }
            }
            None => {}
        }
        self.entries
            .insert(key, (ad.issued_at_unix(), ad_id.to_vec()));
        Ok(DiscoveryOutcome::Discovered)
    }

    /// Number of live cached advertisements.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop advertisements whose expiry has passed (housekeeping for the
    /// runtime loop).
    pub fn prune(&mut self, now_unix: u64, probe: impl Fn(&[u8; 32], &[u8]) -> Option<u64>) {
        // The cache stores ids, not full ads, to stay O(node count); the
        // caller-supplied probe resolves an id back to its expiry (or None
        // if unknown, which prunes it).
        let mut remove = Vec::new();
        for (node, (_, ad_id)) in &self.entries {
            match probe(node, ad_id) {
                Some(expiry) if expiry > now_unix => {}
                _ => remove.push(*node),
            }
        }
        for node in remove {
            self.entries.remove(&node);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> Identity {
        Identity::from_seed([seed; 32], 1_700_000_000, None).expect("identity")
    }

    fn udp_ad(id: &Identity, issued: u64, validity: u64) -> Advertisement {
        Advertisement::new(
            id,
            None,
            vec![TransportDescriptor {
                kind: "udp".into(),
                endpoint: "127.0.0.1:7001".into(),
            }],
            issued,
            validity,
        )
        .unwrap()
    }

    #[test]
    fn build_sign_verify_discover() {
        let id = identity(1);
        let ad = udp_ad(&id, 1_000, 60);
        let signed = ad.sign(&id).unwrap();
        let mut cache = DiscoveryCache::new();
        assert_eq!(
            cache.receive(&signed, 1_030).unwrap(),
            DiscoveryOutcome::Discovered
        );
        // idempotent retransmission
        assert_eq!(
            cache.receive(&signed, 1_031).unwrap(),
            DiscoveryOutcome::Duplicate
        );
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn stale_replay_cannot_evict_fresher() {
        let id = identity(2);
        // newer: issued 2000, expires 2060; older: issued 1990, expires 2050
        // (both still fresh at the test time; only the ORDER differs)
        let newer = udp_ad(&id, 2_000, 60);
        let signed_new = newer.sign(&id).unwrap();
        let older = udp_ad(&id, 1_990, 60);
        let signed_old = older.sign(&id).unwrap();
        let mut cache = DiscoveryCache::new();
        cache.receive(&signed_new, 2_030).unwrap();
        assert_eq!(
            cache.receive(&signed_old, 2_031).unwrap(),
            DiscoveryOutcome::Stale
        );
        // the newer one is still the cached advertisement
        assert_eq!(
            cache.receive(&signed_new, 2_032).unwrap(),
            DiscoveryOutcome::Duplicate
        );
    }

    #[test]
    fn expired_and_future_rejected() {
        let id = identity(3);
        let signed = udp_ad(&id, 1_000, 60).sign(&id).unwrap();
        let mut cache = DiscoveryCache::new();
        assert!(matches!(
            cache.receive(&signed, 1_060),
            Err(AdvertisementError::Expired { .. })
        ));
        assert!(matches!(
            cache.receive(&signed, 999),
            Err(AdvertisementError::NotYetValid { .. })
        ));
    }

    #[test]
    fn window_bound_enforced() {
        let id = identity(4);
        assert!(matches!(
            Advertisement::new(
                &id,
                None,
                vec![TransportDescriptor {
                    kind: "udp".into(),
                    endpoint: "127.0.0.1:1".into(),
                }],
                1_000,
                AD_MAX_WINDOW + 1,
            ),
            Err(AdvertisementError::WindowInvalid { .. })
        ));
    }

    #[test]
    fn unknown_transport_kind_rejected() {
        let id = identity(5);
        assert!(matches!(
            Advertisement::new(
                &id,
                None,
                vec![TransportDescriptor {
                    kind: "carrier_pigeon".into(),
                    endpoint: " coop".into(),
                }],
                1_000,
                60,
            ),
            Err(AdvertisementError::TransportKindUnknown { .. })
        ));
    }

    #[test]
    fn tampered_advertisement_fails_signature() {
        let id = identity(6);
        let ad = udp_ad(&id, 1_000, 60);
        let signed = ad.sign(&id).unwrap();
        let mut tampered = signed.advertisement_bytes().to_vec();
        // flip a byte inside the endpoint text
        let pos = tampered
            .windows(9)
            .position(|w| w == b"127.0.0.1")
            .expect("endpoint present");
        tampered[pos] = b'2';
        let bad = SignedAdvertisement {
            advertisement_bytes: tampered,
            signature: signed.signature,
        };
        let mut cache = DiscoveryCache::new();
        assert!(matches!(
            cache.receive(&bad, 1_030),
            Err(AdvertisementError::SignatureInvalid)
        ));
    }

    #[test]
    fn transports_canonicalized_and_strict() {
        let id = identity(7);
        let ad = Advertisement::new(
            &id,
            None,
            vec![
                TransportDescriptor {
                    kind: "quic".into(),
                    endpoint: "example.net:443".into(),
                },
                TransportDescriptor {
                    kind: "udp".into(),
                    endpoint: "10.0.0.1:7000".into(),
                },
                TransportDescriptor {
                    kind: "udp".into(),
                    endpoint: "10.0.0.2:7000".into(),
                },
            ],
            1_000,
            60,
        )
        .unwrap();
        // canonical order: quic > udp? 'q' < 'u' — quic first
        assert_eq!(ad.transports()[0].kind, "quic");
        // wire roundtrip is byte-stable
        let bytes = ad.to_wire_bytes();
        assert_eq!(Advertisement::from_wire_bytes(&bytes).unwrap(), ad);
    }

    #[test]
    fn envelope_roundtrip() {
        let id = identity(8);
        let signed = udp_ad(&id, 1_000, 60).sign(&id).unwrap();
        let env = signed.to_envelope_bytes();
        let back = SignedAdvertisement::from_envelope_bytes(&env).unwrap();
        assert_eq!(back, signed);
        assert_eq!(back.advertisement_id(), signed.advertisement_id());
    }
}
