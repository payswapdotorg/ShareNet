//! Circuit revocation — the durable failure record (work item R7-001).
//!
//! Relationship to [`crate::circuit::CircuitDestroy`] (the registry
//! status_note, verbatim in spirit): destroy is the RUNTIME teardown any
//! path member may trigger with terminal semantics; revocation is the
//! DURABLE record that failure detection (missed acks / evidence
//! timeouts / policy) PRODUCES and that recovery MUST consult before any
//! replacement attempt — recovery cannot resurrect a revoked circuit
//! (architecture §11 + lock L015).
//!
//! Three pieces live here:
//!
//! 1. [`CircuitRevocation`] — the registered wire object: a path
//!    member's signed, durable statement that a circuit is dead, with a
//!    frozen four-value reason vocabulary and a bounded honest evidence
//!    map. Carrying envelope = canonical CBOR
//!    `{1: revocation (bstr), 2: signature (64-byte bstr)}` (the
//!    established envelope pattern); [`SignedCircuitRevocation`] is the
//!    fully verified form (parse + signature on construction).
//! 2. [`FailureDetector`] — runtime state (NOT a wire object, per the
//!    registry): consumes link-quality/ack signals and EMITS typed
//!    [`FailureVerdict`]s with configurable thresholds. Deterministic,
//!    no wall clock (caller-supplied `now`, by the crate's law). It
//!    produces the INPUT to revocation construction, nothing more.
//! 3. [`RevocationLedger`] — the durable integration: admits
//!    revocations after verifying the revoker is in the revoked
//!    circuit's COMMITTED path (against a [`CircuitRegistry`] record,
//!    never caller-asserted), is idempotent per `(circuit_id, revoker)`,
//!    answers `is_revoked` authoritatively, and ENFORCES L015 through
//!    [`crate::circuit::CircuitRegistry::install_revocation_ledger`]:
//!    the registry's admission path refuses any setup/ack/frame/destroy
//!    for a revoked circuit id even if the runtime destroy state was
//!    somehow lost.
//!
//! # Wire object (canonical CBOR map, the registry schema)
//!
//! ```text
//! {1: scheme_version (=1, uint),
//!  2: circuit_id (32-byte bstr — the revoked circuit),
//!  3: revoker (NodeIdentity map — MUST be a committed path member of
//!      the revoked circuit, verified at ledger admission),
//!  4: reason (text; frozen v1 set: link_failure, evidence_timeout,
//!      policy, operator),
//!  5: evidence (optional map; see below),
//!  6: revoked_at_unix (uint)}
//! ```
//!
//! Detached Ed25519 signature by the revoker's key over the exact
//! canonical revocation bytes.
//!
//! ## Evidence map interpretation (Tech Lead review point)
//!
//! The registry says: *"evidence (map: failure_kind text + at most 8
//! integer/text evidence fields, e.g. missed_acks, stale_since_unix —
//! bounded, honest: absence of evidence fields is legal, a revocation on
//! policy grounds needs no telemetry)"*. This module implements that as:
//!
//! - field 5 MAY be absent (the zero-evidence form — a policy/operator
//!   revocation needs no telemetry);
//! - when present, the map MUST carry a `"failure_kind"` entry (text,
//!   1..=64 bytes — the fine-grained failure classifier; the coarse
//!   class is field 4) plus at most [`EVIDENCE_MAX_FIELDS`] further
//!   evidence entries with integer or text values;
//! - every key is 1..=64 bytes, every text value 1..=128 bytes
//!   (mirroring the capability-limits bounds), integers in the canonical
//!   i64 range — no floats, no nested structures, no unbounded fields.
//!
//! # Persistence seam (honest scope statement)
//!
//! [`RevocationLedger::to_snapshot_bytes`] /
//! [`RevocationLedger::from_snapshot_bytes`] model durability as a
//! serialized canonical snapshot: every recorded revocation is stored
//! as its full carrying envelope, and restore RE-PARSES and RE-VERIFIES
//! every record's signature (fail-closed on any tamper). Full durable
//! files (atomic append-only storage, retention, crash recovery) are
//! R7-002 scope; the seam is the honest in-memory boundary between the
//! two. A snapshot attack that DELETES whole records cannot be caught
//! by per-record signatures — R7-002 must use append-only durable
//! storage to close that hole (documented limitation, by design of the
//! seam).

use core::fmt;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::cbor::{decode, encode, Value};
use crate::circuit::CircuitRegistry;
use crate::identity::{Identity, IdentityError, NodeIdentity};
use crate::route::SignedEnvelope;

/// Scheme version of the CircuitRevocation wire object (v1).
pub const REVOCATION_SCHEME_VERSION: i64 = 1;
/// Frozen v1 revocation reasons (the §11/L015 failure vocabulary).
pub const REVOCATION_REASONS: [&str; 4] = ["link_failure", "evidence_timeout", "policy", "operator"];
/// The evidence map's mandatory classifier key when the map is present.
pub const EVIDENCE_FAILURE_KIND: &str = "failure_kind";
/// Maximum evidence fields beyond `failure_kind` (the registry bound).
pub const EVIDENCE_MAX_FIELDS: usize = 8;
/// Maximum byte length of one evidence key (the capability-limits bound).
pub const EVIDENCE_MAX_KEY_BYTES: usize = 64;
/// Maximum byte length of one text evidence value.
pub const EVIDENCE_MAX_TEXT_BYTES: usize = 128;
/// Snapshot format version (the persistence seam's wire version).
pub const REVOCATION_SNAPSHOT_VERSION: i64 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed errors of the revocation layer (stable machine names for the
/// cross-language conformance suite).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevocationError {
    Cbor(String),
    NotAMap,
    KeyNotAnInteger,
    DuplicateField { key: i64 },
    MissingField { key: i64 },
    FieldNotExpectedType { key: i64 },
    UnknownField { key: i64 },
    SchemeVersionUnsupported { found: i64 },
    Identity(IdentityError),
    CircuitIdWrongLength { len: usize },
    ReasonUnknown { found: String },
    EvidenceTooManyFields { count: usize, max: usize },
    EvidenceKeyInvalid { bytes: usize, max: usize },
    EvidenceTextTooLong { bytes: usize, max: usize },
    EvidenceEntryMalformed,
    FailureKindMissing,
    FailureKindNotText,
    TimestampOutOfRange,
    SignatureWrongLength { len: usize },
    EnvelopeWrongEntryCount { count: usize },
    SignatureInvalid,
    SignerMismatch { revocation: String, signer: String },
    RevokedAtInFuture { revoked_at: u64, now: u64 },
    CircuitUnknown,
    RevokerNotOnPath,
    SnapshotOrderInvalid,
    SnapshotDuplicateRecord,
    DetectorConfigInvalid { what: &'static str },
}

impl fmt::Display for RevocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RevocationError::Cbor(e) => write!(f, "cbor: {e}"),
            RevocationError::NotAMap => write!(f, "not a map"),
            RevocationError::KeyNotAnInteger => write!(f, "map key not an integer"),
            RevocationError::DuplicateField { key } => write!(f, "duplicate field {key}"),
            RevocationError::MissingField { key } => write!(f, "missing field {key}"),
            RevocationError::FieldNotExpectedType { key } => {
                write!(f, "field {key} not of expected type")
            }
            RevocationError::UnknownField { key } => write!(f, "unknown field {key}"),
            RevocationError::SchemeVersionUnsupported { found } => {
                write!(f, "scheme version {found} unsupported")
            }
            RevocationError::Identity(e) => write!(f, "identity: {e}"),
            RevocationError::CircuitIdWrongLength { len } => {
                write!(f, "circuit id must be 32 bytes, found {len}")
            }
            RevocationError::ReasonUnknown { found } => {
                write!(f, "revocation reason {found:?} unknown")
            }
            RevocationError::EvidenceTooManyFields { count, max } => {
                write!(f, "evidence map has {count} fields beyond failure_kind (max {max})")
            }
            RevocationError::EvidenceKeyInvalid { bytes, max } => {
                write!(f, "evidence key of {bytes} bytes outside 1..={max}")
            }
            RevocationError::EvidenceTextTooLong { bytes, max } => {
                write!(f, "evidence text value of {bytes} bytes exceeds the {max}-byte limit")
            }
            RevocationError::EvidenceEntryMalformed => {
                write!(f, "evidence entry is not an integer or text")
            }
            RevocationError::FailureKindMissing => {
                write!(f, "evidence map must carry a text failure_kind entry")
            }
            RevocationError::FailureKindNotText => {
                write!(f, "evidence failure_kind must be a text value")
            }
            RevocationError::TimestampOutOfRange => write!(f, "timestamp out of range"),
            RevocationError::SignatureWrongLength { len } => {
                write!(f, "envelope signature must be 64 bytes, found {len}")
            }
            RevocationError::EnvelopeWrongEntryCount { count } => {
                write!(f, "carrying envelope must have exactly 2 entries, found {count}")
            }
            RevocationError::SignatureInvalid => write!(f, "revocation signature invalid"),
            RevocationError::SignerMismatch { revocation, signer } => write!(
                f,
                "signer {signer} does not match the revoker {revocation}"
            ),
            RevocationError::RevokedAtInFuture { revoked_at, now } => write!(
                f,
                "revoked_at {revoked_at} is in the future (now {now})"
            ),
            RevocationError::CircuitUnknown => {
                write!(f, "circuit unknown (no committed path to verify against)")
            }
            RevocationError::RevokerNotOnPath => {
                write!(f, "revoker is not a member of the revoked circuit's committed path")
            }
            RevocationError::SnapshotOrderInvalid => {
                write!(f, "snapshot records are not in canonical ascending order")
            }
            RevocationError::SnapshotDuplicateRecord => {
                write!(f, "snapshot contains a duplicate (circuit, revoker) record")
            }
            RevocationError::DetectorConfigInvalid { what } => {
                write!(f, "failure detector config invalid: {what}")
            }
        }
    }
}

impl std::error::Error for RevocationError {}

impl RevocationError {
    /// Stable machine name (consumed by the cross-language suite).
    pub fn name(&self) -> &'static str {
        match self {
            RevocationError::Cbor(_) => "cbor",
            RevocationError::NotAMap => "not_a_map",
            RevocationError::KeyNotAnInteger => "key_not_an_integer",
            RevocationError::DuplicateField { .. } => "duplicate_field",
            RevocationError::MissingField { .. } => "missing_field",
            RevocationError::FieldNotExpectedType { .. } => "field_not_expected_type",
            RevocationError::UnknownField { .. } => "unknown_field",
            RevocationError::SchemeVersionUnsupported { .. } => "scheme_version_unsupported",
            RevocationError::Identity(_) => "identity_error",
            RevocationError::CircuitIdWrongLength { .. } => "circuit_id_wrong_length",
            RevocationError::ReasonUnknown { .. } => "reason_unknown",
            RevocationError::EvidenceTooManyFields { .. } => "evidence_too_many_fields",
            RevocationError::EvidenceKeyInvalid { .. } => "evidence_key_invalid",
            RevocationError::EvidenceTextTooLong { .. } => "evidence_text_too_long",
            RevocationError::EvidenceEntryMalformed => "evidence_entry_malformed",
            RevocationError::FailureKindMissing => "failure_kind_missing",
            RevocationError::FailureKindNotText => "failure_kind_not_text",
            RevocationError::TimestampOutOfRange => "timestamp_out_of_range",
            RevocationError::SignatureWrongLength { .. } => "signature_wrong_length",
            RevocationError::EnvelopeWrongEntryCount { .. } => "envelope_wrong_entry_count",
            RevocationError::SignatureInvalid => "signature_invalid",
            RevocationError::SignerMismatch { .. } => "signer_mismatch",
            RevocationError::RevokedAtInFuture { .. } => "revoked_at_in_future",
            RevocationError::CircuitUnknown => "circuit_unknown",
            RevocationError::RevokerNotOnPath => "revoker_not_on_path",
            RevocationError::SnapshotOrderInvalid => "snapshot_order_invalid",
            RevocationError::SnapshotDuplicateRecord => "snapshot_duplicate_record",
            RevocationError::DetectorConfigInvalid { .. } => "detector_config_invalid",
        }
    }
}

// ---------------------------------------------------------------------------
// Revocation reason (the frozen four)
// ---------------------------------------------------------------------------

/// The revocation reason — one of the frozen v1 set. `link_failure` and
/// `evidence_timeout` are telemetry verdicts (the detector's output);
/// `policy` and `operator` are local decisions (no telemetry required).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RevocationReason {
    /// "link_failure" — the link-quality verdict (missed acks).
    LinkFailure,
    /// "evidence_timeout" — the evidence-staleness verdict.
    EvidenceTimeout,
    /// "policy" — a local policy decision.
    Policy,
    /// "operator" — a human operator command.
    Operator,
}

impl RevocationReason {
    /// The frozen v1 set, in registry order.
    pub const ALL: [RevocationReason; 4] = [
        RevocationReason::LinkFailure,
        RevocationReason::EvidenceTimeout,
        RevocationReason::Policy,
        RevocationReason::Operator,
    ];

    /// Stable machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            RevocationReason::LinkFailure => "link_failure",
            RevocationReason::EvidenceTimeout => "evidence_timeout",
            RevocationReason::Policy => "policy",
            RevocationReason::Operator => "operator",
        }
    }

    /// Parse from the machine name — anything else is `None` (the wire
    /// surfaces that as the typed `reason_unknown`).
    pub fn from_name(name: &str) -> Option<RevocationReason> {
        match name {
            "link_failure" => Some(RevocationReason::LinkFailure),
            "evidence_timeout" => Some(RevocationReason::EvidenceTimeout),
            "policy" => Some(RevocationReason::Policy),
            "operator" => Some(RevocationReason::Operator),
            _ => None,
        }
    }
}

impl fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Evidence values (bounded, honest: int or text, nothing else)
// ---------------------------------------------------------------------------

/// One evidence value — an integer counter or a short text. The CBOR
/// profile forbids floats; nested structures are out of profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EvidenceValue {
    Int(i64),
    Text(String),
}

impl EvidenceValue {
    pub fn to_wire(&self) -> Value {
        match self {
            EvidenceValue::Int(v) => Value::Int(*v),
            EvidenceValue::Text(t) => Value::Text(t.clone()),
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            EvidenceValue::Int(v) => Some(*v),
            EvidenceValue::Text(_) => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            EvidenceValue::Int(_) => None,
            EvidenceValue::Text(t) => Some(t),
        }
    }
}

/// Validate the evidence map against the registry bounds (used at
/// construction AND re-enforced at parse — byte-stability requires
/// exactly one accepted form per logical revocation).
fn check_evidence(
    evidence: &BTreeMap<String, EvidenceValue>,
) -> Result<(), RevocationError> {
    match evidence.get(EVIDENCE_FAILURE_KIND) {
        Some(EvidenceValue::Text(t)) if !t.is_empty() && t.len() <= EVIDENCE_MAX_KEY_BYTES => {}
        Some(EvidenceValue::Text(_)) => {
            return Err(RevocationError::EvidenceKeyInvalid {
                bytes: evidence[EVIDENCE_FAILURE_KIND].as_text().map(|t| t.len()).unwrap_or(0),
                max: EVIDENCE_MAX_KEY_BYTES,
            });
        }
        Some(_) => return Err(RevocationError::FailureKindNotText),
        None => return Err(RevocationError::FailureKindMissing),
    }
    // failure_kind itself + at most EVIDENCE_MAX_FIELDS further fields.
    if evidence.len() > 1 + EVIDENCE_MAX_FIELDS {
        return Err(RevocationError::EvidenceTooManyFields {
            count: evidence.len() - 1,
            max: EVIDENCE_MAX_FIELDS,
        });
    }
    for (key, value) in evidence {
        if key.is_empty() || key.len() > EVIDENCE_MAX_KEY_BYTES {
            return Err(RevocationError::EvidenceKeyInvalid {
                bytes: key.len(),
                max: EVIDENCE_MAX_KEY_BYTES,
            });
        }
        if let EvidenceValue::Text(t) = value {
            if t.is_empty() || t.len() > EVIDENCE_MAX_TEXT_BYTES {
                return Err(RevocationError::EvidenceTextTooLong {
                    bytes: t.len(),
                    max: EVIDENCE_MAX_TEXT_BYTES,
                });
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CircuitRevocation (the wire object)
// ---------------------------------------------------------------------------

/// A parsed (not yet verified) circuit revocation.
///
/// Invariants are enforced at construction AND re-enforced at parse
/// (strict: exactly one accepted byte image per logical revocation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitRevocation {
    circuit_id: [u8; 32],
    revoker: NodeIdentity,
    reason: RevocationReason,
    evidence: Option<BTreeMap<String, EvidenceValue>>,
    revoked_at_unix: u64,
}

impl CircuitRevocation {
    /// Build a revocation over the revoker's live identity.
    ///
    /// Enforces the parse-time invariants up front: the reason is from
    /// the frozen set (via the typed [`RevocationReason`]), the evidence
    /// map respects the registry bounds, and `revoked_at_unix` fits the
    /// canonical integer range.
    pub fn new(
        revoker: &Identity,
        circuit_id: [u8; 32],
        reason: RevocationReason,
        evidence: Option<BTreeMap<String, EvidenceValue>>,
        revoked_at_unix: u64,
    ) -> Result<Self, RevocationError> {
        if revoked_at_unix > i64::MAX as u64 {
            return Err(RevocationError::TimestampOutOfRange);
        }
        if let Some(map) = &evidence {
            check_evidence(map)?;
        }
        Ok(CircuitRevocation {
            circuit_id,
            revoker: revoker.node_identity().clone(),
            reason,
            evidence,
            revoked_at_unix,
        })
    }

    /// Build a revocation from a failure-detector verdict — the
    /// detector's output is the revocation's input, nothing more.
    ///
    /// `LinkFailure{missed_acks}` → reason `link_failure` + evidence
    /// `{failure_kind, missed_acks}`; `EvidenceTimeout{stale_since_unix}`
    /// → reason `evidence_timeout` + evidence
    /// `{failure_kind, stale_since_unix}`; `Policy`/`Operator` carry no
    /// telemetry (no evidence map).
    pub fn from_verdict(
        revoker: &Identity,
        circuit_id: [u8; 32],
        verdict: &FailureVerdict,
        revoked_at_unix: u64,
    ) -> Result<Self, RevocationError> {
        CircuitRevocation::new(revoker, circuit_id, verdict.reason(), verdict.evidence(), revoked_at_unix)
    }

    /// Sign this revocation with the revoker's key (binding enforced).
    pub fn sign(&self, revoker: &Identity) -> Result<SignedCircuitRevocation, RevocationError> {
        if revoker.node_id() != self.revoker.node_id() {
            return Err(RevocationError::SignerMismatch {
                revocation: self.revoker.node_id().to_hex(),
                signer: revoker.node_id().to_hex(),
            });
        }
        let revocation_bytes = self.to_wire_bytes();
        let signature = revoker.sign_detached(&revocation_bytes);
        Ok(SignedCircuitRevocation {
            revocation: self.clone(),
            revocation_bytes,
            signature,
        })
    }

    /// The canonical CBOR wire form (the registry schema).
    pub fn to_wire(&self) -> Value {
        let mut entries: Vec<(Value, Value)> = vec![
            (Value::Int(1), Value::Int(REVOCATION_SCHEME_VERSION)),
            (Value::Int(2), Value::Bytes(self.circuit_id.to_vec())),
            (Value::Int(3), self.revoker.to_wire()),
            (Value::Int(4), Value::Text(self.reason.as_str().to_string())),
        ];
        if let Some(map) = &self.evidence {
            // BTreeMap iteration is bytewise-ascending key order, which is
            // exactly the canonical CBOR map-key order for text keys.
            entries.push((
                Value::Int(5),
                Value::Map(
                    map.iter()
                        .map(|(k, v)| (Value::Text(k.clone()), v.to_wire()))
                        .collect(),
                ),
            ));
        }
        entries.push((Value::Int(6), Value::Int(self.revoked_at_unix as i64)));
        Value::Map(entries)
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, RevocationError> {
        let v = decode(bytes).map_err(|e| RevocationError::Cbor(e.to_string()))?;
        Self::from_wire(&v)
    }

    /// Strict parse with the full parse-time invariant set (mirrors
    /// [`Self::new`]; anything else is refused — no lenient forms).
    pub fn from_wire(v: &Value) -> Result<Self, RevocationError> {
        let Value::Map(entries) = v else {
            return Err(RevocationError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut circuit_id: Option<[u8; 32]> = None;
        let mut revoker: Option<NodeIdentity> = None;
        let mut reason: Option<RevocationReason> = None;
        let mut evidence: Option<BTreeMap<String, EvidenceValue>> = None;
        let mut revoked_at: Option<u64> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(RevocationError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(RevocationError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(RevocationError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != REVOCATION_SCHEME_VERSION {
                        return Err(RevocationError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if circuit_id.is_some() {
                        return Err(RevocationError::DuplicateField { key: 2 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(RevocationError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != 32 {
                        return Err(RevocationError::CircuitIdWrongLength { len: b.len() });
                    }
                    circuit_id = Some(b.as_slice().try_into().expect("checked"));
                }
                3 => {
                    if revoker.is_some() {
                        return Err(RevocationError::DuplicateField { key: 3 });
                    }
                    revoker =
                        Some(NodeIdentity::from_wire(val).map_err(RevocationError::Identity)?);
                }
                4 => {
                    if reason.is_some() {
                        return Err(RevocationError::DuplicateField { key: 4 });
                    }
                    let Value::Text(t) = val else {
                        return Err(RevocationError::FieldNotExpectedType { key: 4 });
                    };
                    reason = Some(RevocationReason::from_name(t).ok_or_else(|| {
                        RevocationError::ReasonUnknown { found: t.clone() }
                    })?);
                }
                5 => {
                    if evidence.is_some() {
                        return Err(RevocationError::DuplicateField { key: 5 });
                    }
                    let Value::Map(map) = val else {
                        return Err(RevocationError::FieldNotExpectedType { key: 5 });
                    };
                    let mut out = BTreeMap::new();
                    for (ek, ev) in map {
                        let (Value::Text(k), value) = (ek, ev) else {
                            return Err(RevocationError::EvidenceEntryMalformed);
                        };
                        let value = match value {
                            Value::Int(i) => EvidenceValue::Int(*i),
                            Value::Text(t) => EvidenceValue::Text(t.clone()),
                            _ => return Err(RevocationError::EvidenceEntryMalformed),
                        };
                        out.insert(k.clone(), value);
                    }
                    evidence = Some(out);
                }
                6 => {
                    if revoked_at.is_some() {
                        return Err(RevocationError::DuplicateField { key: 6 });
                    }
                    let Value::Int(t) = val else {
                        return Err(RevocationError::FieldNotExpectedType { key: 6 });
                    };
                    let t = u64::try_from(*t).map_err(|_| RevocationError::TimestampOutOfRange)?;
                    revoked_at = Some(t);
                }
                other => return Err(RevocationError::UnknownField { key: other }),
            }
        }
        let _ = scheme;
        let circuit_id = circuit_id.ok_or(RevocationError::MissingField { key: 2 })?;
        let revoker = revoker.ok_or(RevocationError::MissingField { key: 3 })?;
        let reason = reason.ok_or(RevocationError::MissingField { key: 4 })?;
        let revoked_at = revoked_at.ok_or(RevocationError::MissingField { key: 6 })?;
        // Parse-time enforcement of the same invariants as construction.
        if let Some(map) = &evidence {
            check_evidence(map)?;
        }
        if revoked_at > i64::MAX as u64 {
            return Err(RevocationError::TimestampOutOfRange);
        }
        Ok(CircuitRevocation {
            circuit_id,
            revoker,
            reason,
            evidence,
            revoked_at_unix: revoked_at,
        })
    }

    pub fn circuit_id(&self) -> &[u8; 32] {
        &self.circuit_id
    }
    pub fn revoker_identity(&self) -> &NodeIdentity {
        &self.revoker
    }
    /// The R1-001 derived node id of the revoker (the idempotence key).
    pub fn revoker_node_id(&self) -> crate::identity::NodeId {
        self.revoker.node_id()
    }
    pub fn reason(&self) -> RevocationReason {
        self.reason
    }
    pub fn evidence(&self) -> Option<&BTreeMap<String, EvidenceValue>> {
        self.evidence.as_ref()
    }
    pub fn revoked_at_unix(&self) -> u64 {
        self.revoked_at_unix
    }
}

// ---------------------------------------------------------------------------
// SignedCircuitRevocation (the verified carrying form)
// ---------------------------------------------------------------------------

/// A signed circuit revocation in its carrying envelope — parse +
/// signature are verified on construction (the only ways to obtain one
/// are [`CircuitRevocation::sign`] and
/// [`SignedCircuitRevocation::from_envelope_bytes`], so the type is
/// always trustworthy; ledger admission still re-checks everything that
/// needs external state).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCircuitRevocation {
    revocation: CircuitRevocation,
    revocation_bytes: Vec<u8>,
    signature: [u8; 64],
}

impl SignedCircuitRevocation {
    /// The carrying envelope bytes (canonical CBOR
    /// `{1: revocation (bstr), 2: signature (64-byte bstr)}`).
    pub fn to_envelope_bytes(&self) -> Vec<u8> {
        encode(&Value::Map(vec![
            (Value::Int(1), Value::Bytes(self.revocation_bytes.clone())),
            (Value::Int(2), Value::Bytes(self.signature.to_vec())),
        ]))
        .expect("in-profile")
    }

    /// Strict parse of the carrying envelope + the inner revocation +
    /// the revoker's signature over the exact canonical bytes
    /// (self-certifying: the key is inside the signed bytes).
    pub fn from_envelope_bytes(bytes: &[u8]) -> Result<Self, RevocationError> {
        let v = decode(bytes).map_err(|e| RevocationError::Cbor(e.to_string()))?;
        let Value::Map(entries) = &v else {
            return Err(RevocationError::NotAMap);
        };
        if entries.len() != 2 {
            return Err(RevocationError::EnvelopeWrongEntryCount {
                count: entries.len(),
            });
        }
        let mut revocation_bytes: Option<Vec<u8>> = None;
        let mut signature: Option<[u8; 64]> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(RevocationError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    let Value::Bytes(b) = val else {
                        return Err(RevocationError::FieldNotExpectedType { key: 1 });
                    };
                    if revocation_bytes.is_some() {
                        return Err(RevocationError::DuplicateField { key: 1 });
                    }
                    revocation_bytes = Some(b.clone());
                }
                2 => {
                    let Value::Bytes(b) = val else {
                        return Err(RevocationError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != 64 {
                        return Err(RevocationError::SignatureWrongLength { len: b.len() });
                    }
                    if signature.is_some() {
                        return Err(RevocationError::DuplicateField { key: 2 });
                    }
                    signature = Some(b.as_slice().try_into().expect("checked"));
                }
                other => return Err(RevocationError::UnknownField { key: other }),
            }
        }
        let revocation_bytes =
            revocation_bytes.ok_or(RevocationError::MissingField { key: 1 })?;
        let signature = signature.ok_or(RevocationError::MissingField { key: 2 })?;
        let revocation = CircuitRevocation::from_wire_bytes(&revocation_bytes)?;
        revocation
            .revoker_identity()
            .verify_detached(&revocation_bytes, &signature)
            .map_err(|_| RevocationError::SignatureInvalid)?;
        Ok(SignedCircuitRevocation {
            revocation,
            revocation_bytes,
            signature,
        })
    }

    /// Re-assemble from verified parts (the conformance harness paths).
    pub fn from_parts(revocation: CircuitRevocation, signature: [u8; 64]) -> Self {
        let revocation_bytes = revocation.to_wire_bytes();
        SignedCircuitRevocation {
            revocation,
            revocation_bytes,
            signature,
        }
    }

    pub fn revocation(&self) -> &CircuitRevocation {
        &self.revocation
    }
    /// The exact canonical revocation bytes that were signed.
    pub fn revocation_bytes(&self) -> &[u8] {
        &self.revocation_bytes
    }
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// The route-family envelope form (for cross-object interop paths
    /// that consume `SignedEnvelope`).
    pub fn to_signed_envelope(&self) -> SignedEnvelope {
        SignedEnvelope::new(self.revocation_bytes.clone(), self.signature)
    }
}

// ---------------------------------------------------------------------------
// Failure detector (runtime state — NOT a wire object)
// ---------------------------------------------------------------------------

/// A failure verdict — the typed input to revocation construction.
///
/// `LinkFailure` and `EvidenceTimeout` are emitted by the
/// [`FailureDetector`] from telemetry; `Policy` and `Operator` are local
/// decisions (a policy evaluation or an operator command) — callers
/// construct those directly, since no telemetry can detect them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureVerdict {
    /// The missed-ack count reached the threshold.
    LinkFailure { missed_acks: u32 },
    /// The evidence window lapsed: the evidence has been timed out
    /// since `stale_since_unix` (= last evidence time + the configured
    /// staleness window — the earliest moment this verdict fires).
    EvidenceTimeout { stale_since_unix: u64 },
    /// A local policy decision (no telemetry).
    Policy,
    /// A human operator command (no telemetry).
    Operator,
}

impl FailureVerdict {
    /// The frozen reason this verdict maps onto.
    pub fn reason(&self) -> RevocationReason {
        match self {
            FailureVerdict::LinkFailure { .. } => RevocationReason::LinkFailure,
            FailureVerdict::EvidenceTimeout { .. } => RevocationReason::EvidenceTimeout,
            FailureVerdict::Policy => RevocationReason::Policy,
            FailureVerdict::Operator => RevocationReason::Operator,
        }
    }

    /// The evidence map this verdict contributes to a revocation
    /// (`None` for Policy/Operator — no telemetry, by the registry's
    /// honest-evidence rule).
    pub fn evidence(&self) -> Option<BTreeMap<String, EvidenceValue>> {
        let mut map = BTreeMap::new();
        match self {
            FailureVerdict::LinkFailure { missed_acks } => {
                map.insert(
                    EVIDENCE_FAILURE_KIND.to_string(),
                    EvidenceValue::Text(RevocationReason::LinkFailure.as_str().to_string()),
                );
                map.insert(
                    "missed_acks".to_string(),
                    EvidenceValue::Int(i64::from(*missed_acks)),
                );
            }
            FailureVerdict::EvidenceTimeout { stale_since_unix } => {
                if *stale_since_unix > i64::MAX as u64 {
                    return None; // construction will fail-closed instead
                }
                map.insert(
                    EVIDENCE_FAILURE_KIND.to_string(),
                    EvidenceValue::Text(RevocationReason::EvidenceTimeout.as_str().to_string()),
                );
                map.insert(
                    "stale_since_unix".to_string(),
                    EvidenceValue::Int(*stale_since_unix as i64),
                );
            }
            FailureVerdict::Policy | FailureVerdict::Operator => return None,
        }
        Some(map)
    }
}

/// Configurable detection thresholds (both >= 1; deterministic — no
/// wall clock anywhere in this module).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureDetectorConfig {
    /// Missed-ack count at which the LinkFailure verdict fires.
    pub missed_ack_threshold: u32,
    /// Evidence staleness window (seconds) at which the
    /// EvidenceTimeout verdict fires.
    pub evidence_staleness_secs: u64,
}

impl FailureDetectorConfig {
    pub fn new(
        missed_ack_threshold: u32,
        evidence_staleness_secs: u64,
    ) -> Result<Self, RevocationError> {
        if missed_ack_threshold == 0 {
            return Err(RevocationError::DetectorConfigInvalid {
                what: "missed_ack_threshold must be >= 1",
            });
        }
        if evidence_staleness_secs == 0 {
            return Err(RevocationError::DetectorConfigInvalid {
                what: "evidence_staleness_secs must be >= 1",
            });
        }
        Ok(FailureDetectorConfig {
            missed_ack_threshold,
            evidence_staleness_secs,
        })
    }
}

/// Per-circuit telemetry watch state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct LinkWatch {
    missed_acks: u32,
    last_ack_at_unix: Option<u64>,
    last_evidence_at_unix: Option<u64>,
}

/// The failure detector — runtime state that consumes link-quality/ack
/// signals and EMITS verdicts. It produces the INPUT to revocation
/// construction ([`CircuitRevocation::from_verdict`]), nothing more.
///
/// Determinism: every method takes the caller-supplied `now`; for any
/// fixed input sequence the outputs are fixed. Clock monotonicity is
/// the caller's responsibility (no wall clock in this crate, by law).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FailureDetector {
    config: FailureDetectorConfig,
    watches: HashMap<[u8; 32], LinkWatch>,
}

impl FailureDetector {
    pub fn new(config: FailureDetectorConfig) -> Self {
        FailureDetector {
            config,
            watches: HashMap::new(),
        }
    }

    pub fn config(&self) -> &FailureDetectorConfig {
        &self.config
    }

    /// An acknowledged frame arrived: the ack gap resets to zero.
    pub fn ack_received(&mut self, circuit_id: [u8; 32], now_unix: u64) {
        let watch = self.watches.entry(circuit_id).or_default();
        watch.missed_acks = 0;
        watch.last_ack_at_unix = Some(now_unix);
    }

    /// An expected ack did not arrive (one missed-ack interval).
    pub fn ack_missed(&mut self, circuit_id: [u8; 32]) {
        let watch = self.watches.entry(circuit_id).or_default();
        watch.missed_acks = watch.missed_acks.saturating_add(1);
    }

    /// Fresh link-quality/topology evidence arrived for the circuit.
    pub fn evidence_observed(&mut self, circuit_id: [u8; 32], now_unix: u64) {
        let watch = self.watches.entry(circuit_id).or_default();
        watch.last_evidence_at_unix = Some(now_unix);
    }

    /// The current verdict for a circuit (`None` = healthy).
    ///
    /// Evaluation order (deterministic): the ack-gap verdict first (the
    /// stronger, more local signal), then the evidence-staleness
    /// verdict. A circuit with no evidence yet cannot time out
    /// (nothing to time out).
    pub fn verdict(&self, circuit_id: &[u8; 32], now_unix: u64) -> Option<FailureVerdict> {
        let watch = self.watches.get(circuit_id)?;
        if watch.missed_acks >= self.config.missed_ack_threshold {
            return Some(FailureVerdict::LinkFailure {
                missed_acks: watch.missed_acks,
            });
        }
        if let Some(last_evidence) = watch.last_evidence_at_unix {
            let deadline = last_evidence.saturating_add(self.config.evidence_staleness_secs);
            if now_unix >= deadline {
                return Some(FailureVerdict::EvidenceTimeout {
                    stale_since_unix: deadline,
                });
            }
        }
        None
    }

    /// Current missed-ack count for a circuit (0 when never watched).
    pub fn missed_acks(&self, circuit_id: &[u8; 32]) -> u32 {
        self.watches.get(circuit_id).map_or(0, |w| w.missed_acks)
    }

    /// Last evidence observation time for a circuit, if any.
    pub fn last_evidence_at(&self, circuit_id: &[u8; 32]) -> Option<u64> {
        self.watches.get(circuit_id).and_then(|w| w.last_evidence_at_unix)
    }
}

// ---------------------------------------------------------------------------
// RevocationLedger (the durable integration)
// ---------------------------------------------------------------------------

/// The outcome of admitting a revocation to the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevocationAdmitOutcome {
    /// The first durable revocation for this circuit — it is now
    /// revoked (terminal forever, L015).
    First,
    /// A DIFFERENT path member's revocation — recorded, but the circuit
    /// was already revoked (never un-revokes).
    Additional,
    /// This (circuit, revoker) pair is already recorded — idempotent
    /// (the first recorded revocation wins; the duplicate is dropped).
    Duplicate,
}

impl RevocationAdmitOutcome {
    /// Stable machine name (vectors + harness).
    pub fn as_str(&self) -> &'static str {
        match self {
            RevocationAdmitOutcome::First => "first",
            RevocationAdmitOutcome::Additional => "additional",
            RevocationAdmitOutcome::Duplicate => "duplicate",
        }
    }
}

/// One recorded revocation (the durable record's in-memory form).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedRevocation {
    circuit_id: [u8; 32],
    revoker_node_id: [u8; 32],
    signed: SignedCircuitRevocation,
}

/// The shared durable state (the ledger clones cheaply and every clone
/// — including the one installed inside a [`CircuitRegistry`] — sees
/// the same authoritative view).
#[derive(Debug, Default)]
struct LedgerShared {
    /// circuit_id -> recorded revocations, in admission order.
    records: Mutex<BTreeMap<[u8; 32], Vec<RecordedRevocation>>>,
}

/// The durable circuit-revocation ledger — the L015 authority.
///
/// - **Admission** ([`Self::admit`]): strict parse + signature (the
///   [`SignedCircuitRevocation`] invariant) + the revoker's node_id MUST
///   appear in the revoked circuit's COMMITTED path, verified against a
///   [`CircuitRegistry`] record — never caller-asserted (a circuit
///   unknown to the registry is refused: its committed path cannot be
///   verified) + `revoked_at` not in the future.
/// - **Idempotence**: per `(circuit_id, revoker)` — duplicates are
///   dropped (the first recorded revocation wins); a second revoker is
///   recorded but never un-revokes.
/// - **Authority**: [`Self::is_revoked`] is the authoritative answer;
///   install the ledger into a registry
///   ([`CircuitRegistry::install_revocation_ledger`]) and its admission
///   path refuses revoked circuit ids even when runtime state was lost.
/// - **Persistence seam**: [`Self::to_snapshot_bytes`] /
///   [`Self::from_snapshot_bytes`] (see the module docs for the honest
///   scope: full durable files are R7-002).
#[derive(Debug, Clone, Default)]
pub struct RevocationLedger {
    shared: Arc<LedgerShared>,
}

impl RevocationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a verified revocation envelope against the circuit
    /// registry's committed-path record. See the struct docs for the
    /// full fail-closed chain.
    pub fn admit_envelope(
        &self,
        now_unix: u64,
        envelope_bytes: &[u8],
        registry: &CircuitRegistry,
    ) -> Result<RevocationAdmitOutcome, RevocationError> {
        let signed = SignedCircuitRevocation::from_envelope_bytes(envelope_bytes)?;
        self.admit(now_unix, &signed, registry)
    }

    /// Admit an already-verified signed revocation (the verification
    /// happened at [`SignedCircuitRevocation`] construction; this checks
    /// everything that needs external state).
    pub fn admit(
        &self,
        now_unix: u64,
        signed: &SignedCircuitRevocation,
        registry: &CircuitRegistry,
    ) -> Result<RevocationAdmitOutcome, RevocationError> {
        let revocation = signed.revocation();
        let circuit_id = revocation.circuit_id();
        // The committed path comes from the registry record — never
        // caller-asserted. A circuit unknown to the registry cannot be
        // verified, so it is refused (fail-closed; durable circuit
        // records that would let a fresh process re-verify the path are
        // R7-002 scope).
        let state = registry
            .circuit(circuit_id)
            .ok_or(RevocationError::CircuitUnknown)?;
        let revoker_node_id = *revocation.revoker_node_id().as_bytes();
        if !state.path().iter().any(|p| *p == revoker_node_id) {
            return Err(RevocationError::RevokerNotOnPath);
        }
        // revoked_at sanity: not in the future.
        let revoked_at = revocation.revoked_at_unix();
        if revoked_at > now_unix {
            return Err(RevocationError::RevokedAtInFuture {
                revoked_at,
                now: now_unix,
            });
        }
        // Idempotence per (circuit_id, revoker node_id): duplicates are
        // dropped (the first recorded revocation wins).
        let mut records = self
            .shared
            .records
            .lock()
            .expect("revocation ledger lock poisoned (a panic occurred mid-admission)");
        let entry = records.entry(*circuit_id).or_default();
        if entry
            .iter()
            .any(|r| r.revoker_node_id == revoker_node_id)
        {
            return Ok(RevocationAdmitOutcome::Duplicate);
        }
        let first_for_circuit = entry.is_empty();
        entry.push(RecordedRevocation {
            circuit_id: *circuit_id,
            revoker_node_id,
            signed: signed.clone(),
        });
        Ok(if first_for_circuit {
            RevocationAdmitOutcome::First
        } else {
            RevocationAdmitOutcome::Additional
        })
    }

    /// The authoritative revoked answer (L015): once true for a
    /// circuit id, true forever — there is no un-revoke.
    pub fn is_revoked(&self, circuit_id: &[u8; 32]) -> bool {
        let records = self
            .shared
            .records
            .lock()
            .expect("revocation ledger lock poisoned (a panic occurred mid-admission)");
        records.contains_key(circuit_id)
    }

    /// How many distinct path members have recorded revocations for a
    /// circuit (0 = not revoked).
    pub fn revoker_count(&self, circuit_id: &[u8; 32]) -> usize {
        let records = self
            .shared
            .records
            .lock()
            .expect("revocation ledger lock poisoned (a panic occurred mid-admission)");
        records.get(circuit_id).map_or(0, |v| v.len())
    }

    /// The number of distinct revoked circuits in the ledger.
    pub fn revoked_circuit_count(&self) -> usize {
        let records = self
            .shared
            .records
            .lock()
            .expect("revocation ledger lock poisoned (a panic occurred mid-admission)");
        records.len()
    }

    /// Serialize the durable state (the persistence seam). Canonical
    /// form: `{1: version (=1), 2: [carrying-envelope bstrs]}` with the
    /// records in ascending `(circuit_id, revoker node_id)` order.
    /// Deterministic for equal logical state.
    pub fn to_snapshot_bytes(&self) -> Vec<u8> {
        let records = self
            .shared
            .records
            .lock()
            .expect("revocation ledger lock poisoned (a panic occurred mid-admission)");
        let mut flat: Vec<&RecordedRevocation> = records.values().flatten().collect();
        flat.sort_by(|a, b| {
            a.circuit_id
                .cmp(&b.circuit_id)
                .then_with(|| a.revoker_node_id.cmp(&b.revoker_node_id))
        });
        let envelopes: Vec<Value> = flat
            .iter()
            .map(|r| Value::Bytes(r.signed.to_envelope_bytes()))
            .collect();
        encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(REVOCATION_SNAPSHOT_VERSION)),
            (Value::Int(2), Value::Array(envelopes)),
        ]))
        .expect("in-profile")
    }

    /// Restore from a snapshot (the persistence seam): every record is
    /// RE-PARSED and its signature RE-VERIFIED (fail-closed on any
    /// tamper); canonical record order and per-(circuit, revoker)
    /// uniqueness are enforced. See the module docs for what the seam
    /// honestly does NOT protect (whole-record deletion — R7-002 must
    /// close that with append-only durable storage).
    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, RevocationError> {
        let v = decode(bytes).map_err(|e| RevocationError::Cbor(e.to_string()))?;
        let Value::Map(entries) = &v else {
            return Err(RevocationError::NotAMap);
        };
        if entries.len() != 2 {
            return Err(RevocationError::EnvelopeWrongEntryCount {
                count: entries.len(),
            });
        }
        let mut version: Option<i64> = None;
        let mut envelopes: Option<&Vec<Value>> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(RevocationError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    let Value::Int(s) = val else {
                        return Err(RevocationError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != REVOCATION_SNAPSHOT_VERSION {
                        return Err(RevocationError::SchemeVersionUnsupported { found: *s });
                    }
                    version = Some(*s);
                }
                2 => {
                    let Value::Array(items) = val else {
                        return Err(RevocationError::FieldNotExpectedType { key: 2 });
                    };
                    envelopes = Some(items);
                }
                other => return Err(RevocationError::UnknownField { key: other }),
            }
        }
        let _ = version;
        let envelopes = envelopes.ok_or(RevocationError::MissingField { key: 2 })?;
        let ledger = RevocationLedger::new();
        {
            let mut records = ledger
                .shared
                .records
                .lock()
                .expect("revocation ledger lock poisoned (a panic occurred mid-admission)");
            let mut seen: HashSet<([u8; 32], [u8; 32])> = HashSet::new();
            let mut last_key: Option<([u8; 32], [u8; 32])> = None;
            for item in envelopes {
                let Value::Bytes(env_bytes) = item else {
                    return Err(RevocationError::EvidenceEntryMalformed);
                };
                // Full fail-closed re-verification of every record.
                let signed = SignedCircuitRevocation::from_envelope_bytes(env_bytes)?;
                let revocation = signed.revocation();
                let circuit_id = *revocation.circuit_id();
                let revoker = *revocation.revoker_node_id().as_bytes();
                let key = (circuit_id, revoker);
                if !seen.insert(key) {
                    return Err(RevocationError::SnapshotDuplicateRecord);
                }
                if let Some(prev) = last_key {
                    if prev >= key {
                        return Err(RevocationError::SnapshotOrderInvalid);
                    }
                }
                last_key = Some(key);
                records.entry(circuit_id).or_default().push(RecordedRevocation {
                    circuit_id,
                    revoker_node_id: revoker,
                    signed,
                });
            }
        }
        Ok(ledger)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::{CircuitSetup, CircuitSetupAck};
    use crate::route::{derive_proposal_id, RouteAcceptance, RouteProposal};

    fn ident(seed: u8, created: u64) -> Identity {
        Identity::from_seed([seed; 32], created, None).expect("identity")
    }

    /// A three-member world: proposer + two hops with a verified
    /// commitment (the same shape as the circuit tests).
    struct World {
        proposer: Identity,
        hop1: Identity,
        hop2: Identity,
        commitment: crate::route::RouteCommitment,
    }

    fn world(now: u64) -> World {
        let proposer = ident(0x11, now);
        let hop1 = ident(0x22, now);
        let hop2 = ident(0x33, now);
        let mut path: Vec<[u8; 32]> = [
            *proposer.node_id().as_bytes(),
            *hop1.node_id().as_bytes(),
            *hop2.node_id().as_bytes(),
        ]
        .to_vec();
        path.sort();
        let proposal =
            RouteProposal::new(&proposer, path, "live", now, 600, [0x42; 32]).expect("proposal");
        let proposal_env = proposal.sign(&proposer).expect("sign");
        let proposal_id = derive_proposal_id(proposal_env.bytes());
        let mut members: Vec<&Identity> = vec![&proposer, &hop1, &hop2];
        members.sort_by_key(|m| *m.node_id().as_bytes());
        let acceptance_envs: Vec<_> = members
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let a = RouteAcceptance::new(m, proposal_id, i as u64, now, 600).expect("acc");
                a.sign(m).expect("sign")
            })
            .collect();
        let commitment =
            crate::route::RouteCommitment::build(now, proposal_env, acceptance_envs).expect("com");
        World {
            proposer,
            hop1,
            hop2,
            commitment,
        }
    }

    /// An established circuit over a fresh nonce.
    fn established(
        now: u64,
        nonce: [u8; 32],
    ) -> (World, CircuitRegistry, [u8; 32]) {
        let w = world(now);
        let setup = CircuitSetup::new(&w.commitment, &w.proposer, nonce, now, 600).expect("setup");
        let setup_env = setup.sign(&w.proposer).expect("sign");
        let circuit_id = crate::circuit::derive_circuit_id(w.commitment.route_id(), &nonce);
        let mut registry = CircuitRegistry::new();
        registry.admit_setup(now, &setup_env).expect("admit");
        let path = w.commitment.verify(now).expect("v").proposal.path().to_vec();
        for (pos, want) in path.iter().enumerate() {
            let member = [&w.proposer, &w.hop1, &w.hop2]
                .into_iter()
                .find(|m| m.node_id().as_bytes() == want)
                .expect("member");
            let ack =
                CircuitSetupAck::new(circuit_id, &setup_env, member, pos as u64, now, 500)
                    .expect("ack");
            let env = ack.sign(member).expect("sign");
            registry.admit_ack(now, &env).expect("ack admit");
        }
        (w, registry, circuit_id)
    }

    fn link_failure_revocation(
        w: &World,
        circuit_id: [u8; 32],
        revoked_at: u64,
    ) -> SignedCircuitRevocation {
        let mut evidence = BTreeMap::new();
        evidence.insert(
            EVIDENCE_FAILURE_KIND.to_string(),
            EvidenceValue::Text("link_failure".to_string()),
        );
        evidence.insert("missed_acks".to_string(), EvidenceValue::Int(3));
        let revocation = CircuitRevocation::new(
            &w.hop1,
            circuit_id,
            RevocationReason::LinkFailure,
            Some(evidence),
            revoked_at,
        )
        .expect("revocation");
        revocation.sign(&w.hop1).expect("sign")
    }

    #[test]
    fn revocation_reason_round_trip() {
        for reason in RevocationReason::ALL {
            assert_eq!(RevocationReason::from_name(reason.as_str()), Some(reason));
        }
        assert_eq!(RevocationReason::from_name("completed"), None);
        assert_eq!(
            REVOCATION_REASONS,
            RevocationReason::ALL.map(|r| r.as_str())
        );
    }

    #[test]
    fn wire_round_trip_all_reasons_and_evidence_forms() {
        let now = 1_700_000_000u64;
        let (w, _registry, circuit_id) = established(now, [0x71; 32]);
        // int evidence / no evidence / text evidence
        let cases: Vec<(RevocationReason, Option<BTreeMap<String, EvidenceValue>>)> = vec![
            (
                RevocationReason::LinkFailure,
                Some(BTreeMap::from([
                    (
                        EVIDENCE_FAILURE_KIND.to_string(),
                        EvidenceValue::Text("link_failure".into()),
                    ),
                    ("missed_acks".to_string(), EvidenceValue::Int(4)),
                ])),
            ),
            (RevocationReason::Policy, None),
            (
                RevocationReason::Operator,
                Some(BTreeMap::from([
                    (
                        EVIDENCE_FAILURE_KIND.to_string(),
                        EvidenceValue::Text("operator_command".into()),
                    ),
                    ("operator".to_string(), EvidenceValue::Text("node-op-42".into())),
                ])),
            ),
            (RevocationReason::EvidenceTimeout, None),
        ];
        for (reason, evidence) in cases {
            let revocation =
                CircuitRevocation::new(&w.proposer, circuit_id, reason, evidence.clone(), now + 10)
                    .expect("build");
            let signed = revocation.sign(&w.proposer).expect("sign");
            let bytes = signed.to_envelope_bytes();
            let parsed = SignedCircuitRevocation::from_envelope_bytes(&bytes).expect("parse");
            assert_eq!(parsed.revocation().reason(), reason);
            assert_eq!(parsed.revocation().evidence(), evidence.as_ref());
            assert_eq!(parsed.revocation().circuit_id(), &circuit_id);
            assert_eq!(parsed.revocation().revoked_at_unix(), now + 10);
            // byte-stability: re-encode is identical
            assert_eq!(parsed.to_envelope_bytes(), bytes);
        }
    }

    #[test]
    fn detector_emits_verdicts_deterministically() {
        let config =
            FailureDetectorConfig::new(3, 60).expect("config");
        let mut detector = FailureDetector::new(config);
        let circuit = [0xAA; 32];
        // no watch: healthy
        assert_eq!(detector.verdict(&circuit, 1_000), None);
        // two missed acks: below threshold
        detector.ack_missed(circuit);
        detector.ack_missed(circuit);
        assert_eq!(detector.verdict(&circuit, 1_000), None);
        // third miss: LinkFailure carries the count
        detector.ack_missed(circuit);
        assert_eq!(
            detector.verdict(&circuit, 1_000),
            Some(FailureVerdict::LinkFailure { missed_acks: 3 })
        );
        // an ack resets the gap
        detector.ack_received(circuit, 1_010);
        assert_eq!(detector.verdict(&circuit, 1_011), None);
        // evidence staleness: observed at 1_000, window 60 -> deadline 1_060
        detector.evidence_observed(circuit, 1_000);
        assert_eq!(detector.verdict(&circuit, 1_059), None);
        assert_eq!(
            detector.verdict(&circuit, 1_060),
            Some(FailureVerdict::EvidenceTimeout {
                stale_since_unix: 1_060
            })
        );
        // the ack-gap verdict wins over staleness when both fire
        detector.ack_missed(circuit);
        detector.ack_missed(circuit);
        detector.ack_missed(circuit);
        assert_eq!(
            detector.verdict(&circuit, 2_000),
            Some(FailureVerdict::LinkFailure { missed_acks: 3 })
        );
        // config validation
        assert_eq!(
            FailureDetectorConfig::new(0, 60).unwrap_err().name(),
            "detector_config_invalid"
        );
        assert_eq!(
            FailureDetectorConfig::new(3, 0).unwrap_err().name(),
            "detector_config_invalid"
        );
    }

    #[test]
    fn verdict_feeds_revocation_construction() {
        let now = 1_700_000_000u64;
        let (w, _registry, circuit_id) = established(now, [0x72; 32]);
        let verdict = FailureVerdict::LinkFailure { missed_acks: 5 };
        let revocation =
            CircuitRevocation::from_verdict(&w.hop2, circuit_id, &verdict, now + 5)
                .expect("from verdict");
        assert_eq!(revocation.reason(), RevocationReason::LinkFailure);
        let evidence = revocation.evidence().expect("evidence");
        assert_eq!(
            evidence.get("missed_acks"),
            Some(&EvidenceValue::Int(5))
        );
        assert_eq!(
            evidence.get(EVIDENCE_FAILURE_KIND),
            Some(&EvidenceValue::Text("link_failure".into()))
        );
        // Policy carries no telemetry
        let policy = CircuitRevocation::from_verdict(&w.hop2, circuit_id, &FailureVerdict::Policy, now + 5)
            .expect("policy");
        assert_eq!(policy.reason(), RevocationReason::Policy);
        assert_eq!(policy.evidence(), None);
        // EvidenceTimeout maps with its timestamp
        let timeout = CircuitRevocation::from_verdict(
            &w.hop2,
            circuit_id,
            &FailureVerdict::EvidenceTimeout { stale_since_unix: now },
            now + 5,
        )
        .expect("timeout");
        assert_eq!(
            timeout.evidence().and_then(|e| e.get("stale_since_unix").cloned()),
            Some(EvidenceValue::Int(now as i64))
        );
    }

    #[test]
    fn ledger_admits_first_duplicate_additional() {
        let now = 1_700_000_000u64;
        let (w, registry, circuit_id) = established(now, [0x73; 32]);
        let ledger = RevocationLedger::new();
        assert!(!ledger.is_revoked(&circuit_id));
        let first = link_failure_revocation(&w, circuit_id, now + 10);
        let env_bytes = first.to_envelope_bytes();
        assert_eq!(
            ledger
                .admit_envelope(now + 10, &env_bytes, &registry)
                .unwrap(),
            RevocationAdmitOutcome::First
        );
        assert!(ledger.is_revoked(&circuit_id));
        // duplicate by the same revoker: idempotent
        assert_eq!(
            ledger
                .admit_envelope(now + 11, &env_bytes, &registry)
                .unwrap(),
            RevocationAdmitOutcome::Duplicate
        );
        assert_eq!(ledger.revoker_count(&circuit_id), 1);
        // a second, different revoker: recorded, still (only more) revoked
        let second = CircuitRevocation::new(
            &w.hop2,
            circuit_id,
            RevocationReason::Policy,
            None,
            now + 12,
        )
        .expect("second");
        let second_signed = second.sign(&w.hop2).expect("sign");
        assert_eq!(
            ledger.admit(now + 12, &second_signed, &registry).unwrap(),
            RevocationAdmitOutcome::Additional
        );
        assert_eq!(ledger.revoker_count(&circuit_id), 2);
        assert!(ledger.is_revoked(&circuit_id));
        // a third revocation by the FIRST revoker (different reason):
        // still a duplicate per (circuit, revoker)
        let third = CircuitRevocation::new(
            &w.hop1,
            circuit_id,
            RevocationReason::Operator,
            None,
            now + 13,
        )
        .expect("third");
        assert_eq!(
            ledger
                .admit(now + 13, &third.sign(&w.hop1).unwrap(), &registry)
                .unwrap(),
            RevocationAdmitOutcome::Duplicate
        );
        assert_eq!(ledger.revoker_count(&circuit_id), 2);
    }

    #[test]
    fn snapshot_round_trip_preserves_revocation() {
        let now = 1_700_000_000u64;
        let (w, registry, circuit_id) = established(now, [0x74; 32]);
        let ledger = RevocationLedger::new();
        let first = link_failure_revocation(&w, circuit_id, now + 10);
        ledger
            .admit(now + 10, &first, &registry)
            .expect("admit");
        let snapshot = ledger.to_snapshot_bytes();
        // round-trip: the restored ledger answers authoritatively
        let restored = RevocationLedger::from_snapshot_bytes(&snapshot).expect("restore");
        assert!(restored.is_revoked(&circuit_id));
        assert_eq!(restored.revoker_count(&circuit_id), 1);
        // determinism: same logical state -> identical snapshot bytes
        let snapshot2 = restored.to_snapshot_bytes();
        assert_eq!(snapshot, snapshot2);
        // a tampered snapshot fails closed (flip one byte inside the
        // first record's envelope)
        let mut tampered = snapshot.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(RevocationLedger::from_snapshot_bytes(&tampered).is_err());
    }

    #[test]
    fn evidence_bounds_enforced() {
        let now = 1_700_000_000u64;
        let w = world(now);
        // too many fields beyond failure_kind
        let mut too_many = BTreeMap::new();
        too_many.insert(
            EVIDENCE_FAILURE_KIND.to_string(),
            EvidenceValue::Text("x".into()),
        );
        for i in 0..=EVIDENCE_MAX_FIELDS {
            too_many.insert(format!("f{i}"), EvidenceValue::Int(i as i64));
        }
        assert_eq!(
            CircuitRevocation::new(&w.proposer, [0; 32], RevocationReason::Policy, Some(too_many), now)
                .unwrap_err()
                .name(),
            "evidence_too_many_fields"
        );
        // missing failure_kind
        let no_kind = BTreeMap::from([("missed_acks".to_string(), EvidenceValue::Int(1))]);
        assert_eq!(
            CircuitRevocation::new(&w.proposer, [0; 32], RevocationReason::Policy, Some(no_kind), now)
                .unwrap_err()
                .name(),
            "failure_kind_missing"
        );
        // failure_kind not text
        let bad_kind = BTreeMap::from([(
            EVIDENCE_FAILURE_KIND.to_string(),
            EvidenceValue::Int(7),
        )]);
        assert_eq!(
            CircuitRevocation::new(&w.proposer, [0; 32], RevocationReason::Policy, Some(bad_kind), now)
                .unwrap_err()
                .name(),
            "failure_kind_not_text"
        );
        // oversized key
        let long_key = BTreeMap::from([
            (
                EVIDENCE_FAILURE_KIND.to_string(),
                EvidenceValue::Text("x".into()),
            ),
            ("k".repeat(65), EvidenceValue::Int(1)),
        ]);
        assert_eq!(
            CircuitRevocation::new(&w.proposer, [0; 32], RevocationReason::Policy, Some(long_key), now)
                .unwrap_err()
                .name(),
            "evidence_key_invalid"
        );
        // oversized text value
        let long_text = BTreeMap::from([
            (
                EVIDENCE_FAILURE_KIND.to_string(),
                EvidenceValue::Text("x".into()),
            ),
            ("note".to_string(), EvidenceValue::Text("y".repeat(129))),
        ]);
        assert_eq!(
            CircuitRevocation::new(&w.proposer, [0; 32], RevocationReason::Policy, Some(long_text), now)
                .unwrap_err()
                .name(),
            "evidence_text_too_long"
        );
        // revoked_at out of canonical range
        assert_eq!(
            CircuitRevocation::new(
                &w.proposer,
                [0; 32],
                RevocationReason::Policy,
                None,
                i64::MAX as u64 + 1
            )
            .unwrap_err()
            .name(),
            "timestamp_out_of_range"
        );
    }
}
