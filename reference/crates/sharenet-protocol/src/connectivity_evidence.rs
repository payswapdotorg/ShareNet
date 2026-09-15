//! Signed connectivity observations (work item R5-004).
//!
//! A [`SignedConnectivityObservation`] is the wire form of an ADCOS
//! provider's claim about one connectivity contract's lifecycle: the
//! provider's ShareNet [`NodeIdentity`], the opaque
//! `ConnectivityContractRef`, one of the frozen six event kinds of the
//! `spec/integrations/adcos.md` event mapping, the observation time, a
//! strictly-increasing per-(provider node_id, contract_ref) sequence and
//! an optional map of integer execution counters.
//!
//! This is the trust boundary of the R5-003 durable projection: the
//! registry admission rule says *"UNSIGNED observations never enter durable
//! ShareNet state — the R5-003 store's trust boundary is exactly this
//! object's verification."* [`ObservationAdmission`] is that verification as
//! code: strict parse, R1-001 node_id derivation of the embedded provider
//! identity, strict Ed25519 signature verification over the exact
//! canonical observation bytes, the known-contract rule (an observation for
//! an unknown contract is never a trust grant), the wire-verifiable
//! monotonic sequence rule and the accepting node's freshness window.
//!
//! # Trust boundary (the honest limits)
//!
//! The signature binds the provider's ShareNet identity; it does NOT
//! attest ShareNet packet delivery and does NOT attest provider
//! fulfillment (adcos.md: "ADCOS does not attest ShareNet packet delivery.
//! ShareNet does not attest provider fulfillment."). The observation is the
//! provider's own claim about its contract lifecycle — nothing more. The
//! freshness window is NOT on the wire (unlike TopologyEvidence): per the
//! registry admission rule it is the ACCEPTING node's policy, supplied to
//! [`ObservationAdmission::new`] and applied at `receive` time against the
//! caller-supplied clock (no wall clock here, by the crate's law).
//!
//! # Wire object (canonical CBOR map, the registry schema)
//!
//! ```text
//! {1: scheme_version (=1, uint),
//!  2: provider (NodeIdentity map — the ADCOS provider's ShareNet identity),
//!  3: contract_ref (32-byte bstr — the opaque ConnectivityContractRef),
//!  4: kind (text; exactly one of the frozen six: contract_activated,
//!      execution_state_changed, degraded, assurance_available,
//!      failover_replan, terminated),
//!  5: observed_at_unix (uint),
//!  6: sequence (uint, >= 1 — strictly increasing per
//!      (provider node_id, contract_ref): the wire-verifiable form of the
//!      per-provider monotonic sequence),
//!  7: execution (optional map text -> int, at most 16 entries, non-empty
//!      keys of at most 64 bytes, integer counters only — no floats in the
//!      CBOR profile)}
//! ```
//!
//! Detached Ed25519 signature by the provider node key over the exact
//! canonical observation bytes; carrying envelope = canonical CBOR map
//! `{1: observation (bstr), 2: signature (64-byte bstr)}` — the
//! CapabilityStatement envelope pattern.
//!
//! # Kinds
//!
//! The frozen six are exactly the `spec/integrations/adcos.md` event
//! mapping the connectivity crate already implements
//! (`ContractState::from_observation_kind`); the machine names are shared
//! with the zero-dependency domain crate so the ADCOS adapter maps a wire
//! kind onto a domain kind by name, with no second vocabulary. This module
//! is an independent implementation of the same frozen list (ADR-001: the
//! protocol core imports nothing from the connectivity domain).

use core::fmt;
use std::collections::{BTreeMap, HashMap, HashSet};

use crate::cbor::{decode, encode, Value};
use crate::identity::{Identity, NodeIdentity};

/// Scheme version of the SignedConnectivityObservation wire object (v1).
pub const CONNECTIVITY_EVIDENCE_SCHEME_VERSION: i64 = 1;
/// Minimum observation sequence (providers count from 1, per the R5-001
/// trait contract; 0 is reserved and refused on the wire).
pub const SEQUENCE_MIN: u64 = 1;
/// Maximum number of entries in the optional execution map.
pub const EXECUTION_MAX_ENTRIES: usize = 16;
/// Maximum byte length of one execution-map key (the capability-limits
/// bound, mirrored — 1..=64 bytes of UTF-8).
pub const EXECUTION_MAX_KEY_BYTES: usize = 64;

// ---------------------------------------------------------------------------
// The frozen six event kinds (spec/integrations/adcos.md "Event mapping")
// ---------------------------------------------------------------------------

/// The observation kind — one of the six adcos.md events, with the machine
/// names shared with the connectivity domain crate's `ObservationKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EvidenceKind {
    /// "contract activated".
    ContractActivated,
    /// "execution state changed".
    ExecutionStateChanged,
    /// "degraded".
    Degraded,
    /// "assurance available".
    AssuranceAvailable,
    /// "failover/replan".
    FailoverReplan,
    /// "terminated".
    Terminated,
}

impl EvidenceKind {
    /// The frozen v1 set, in the adcos.md event-mapping order.
    pub const ALL: [EvidenceKind; 6] = [
        EvidenceKind::ContractActivated,
        EvidenceKind::ExecutionStateChanged,
        EvidenceKind::Degraded,
        EvidenceKind::AssuranceAvailable,
        EvidenceKind::FailoverReplan,
        EvidenceKind::Terminated,
    ];

    /// Stable machine name (shared with the connectivity domain crate).
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceKind::ContractActivated => "contract_activated",
            EvidenceKind::ExecutionStateChanged => "execution_state_changed",
            EvidenceKind::Degraded => "degraded",
            EvidenceKind::AssuranceAvailable => "assurance_available",
            EvidenceKind::FailoverReplan => "failover_replan",
            EvidenceKind::Terminated => "terminated",
        }
    }

    /// Parse from the machine name — anything else is `None` (the wire
    /// surfaces that as the typed `kind_unknown`).
    pub fn from_name(name: &str) -> Option<EvidenceKind> {
        match name {
            "contract_activated" => Some(EvidenceKind::ContractActivated),
            "execution_state_changed" => Some(EvidenceKind::ExecutionStateChanged),
            "degraded" => Some(EvidenceKind::Degraded),
            "assurance_available" => Some(EvidenceKind::AssuranceAvailable),
            "failover_replan" => Some(EvidenceKind::FailoverReplan),
            "terminated" => Some(EvidenceKind::Terminated),
            _ => None,
        }
    }
}

impl fmt::Display for EvidenceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// The observation statement (the signed bytes)
// ---------------------------------------------------------------------------

/// A provider's signed observation about one connectivity contract — the
/// parsed (not yet verified) statement form. Invariants are enforced at
/// construction AND re-enforced at parse (byte-stability requires exactly
/// one accepted form per logical observation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectivityObservationStatement {
    provider: NodeIdentity,
    contract_ref: [u8; 32],
    kind: EvidenceKind,
    observed_at_unix: u64,
    sequence: u64,
    execution: Option<BTreeMap<String, i64>>,
}

impl ConnectivityObservationStatement {
    /// Build an observation statement for the provider's live identity.
    ///
    /// Enforces the parse-time invariants up front: the sequence is at
    /// least [`SEQUENCE_MIN`], `observed_at_unix` fits the canonical
    /// integer range, and the optional execution map respects the
    /// entry/key bounds with integer counters only.
    pub fn new(
        provider: &Identity,
        contract_ref: [u8; 32],
        kind: EvidenceKind,
        observed_at_unix: u64,
        sequence: u64,
        execution: Option<BTreeMap<String, i64>>,
    ) -> Result<Self, ConnectivityEvidenceError> {
        if sequence < SEQUENCE_MIN {
            return Err(ConnectivityEvidenceError::SequenceBelowMinimum { found: sequence });
        }
        if observed_at_unix > i64::MAX as u64 {
            return Err(ConnectivityEvidenceError::TimestampOutOfRange);
        }
        if let Some(map) = &execution {
            check_execution(map)?;
        }
        Ok(ConnectivityObservationStatement {
            provider: provider.node_identity().clone(),
            contract_ref,
            kind,
            observed_at_unix,
            sequence,
            execution,
        })
    }

    /// The canonical CBOR wire form (the registry schema).
    pub fn to_wire(&self) -> Value {
        let mut entries: Vec<(Value, Value)> = vec![
            (Value::Int(1), Value::Int(CONNECTIVITY_EVIDENCE_SCHEME_VERSION)),
            (Value::Int(2), self.provider.to_wire()),
            (Value::Int(3), Value::Bytes(self.contract_ref.to_vec())),
            (Value::Int(4), Value::Text(self.kind.as_str().to_string())),
            (Value::Int(5), Value::Int(self.observed_at_unix as i64)),
            (Value::Int(6), Value::Int(self.sequence as i64)),
        ];
        if let Some(map) = &self.execution {
            // BTreeMap iteration is bytewise-ascending key order, which is
            // exactly the canonical CBOR map-key order for text keys.
            entries.push((
                Value::Int(7),
                Value::Map(
                    map.iter()
                        .map(|(k, v)| (Value::Text(k.clone()), Value::Int(*v)))
                        .collect(),
                ),
            ));
        }
        Value::Map(entries)
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ConnectivityEvidenceError> {
        let v = decode(bytes).map_err(ConnectivityEvidenceError::Cbor)?;
        Self::from_wire(&v)
    }

    /// Strict parse with the full parse-time invariant set (mirrors
    /// [`Self::new`]; anything else is refused — no lenient forms).
    pub fn from_wire(v: &Value) -> Result<Self, ConnectivityEvidenceError> {
        let Value::Map(entries) = v else {
            return Err(ConnectivityEvidenceError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut provider: Option<NodeIdentity> = None;
        let mut contract_ref: Option<[u8; 32]> = None;
        let mut kind: Option<EvidenceKind> = None;
        let mut observed_at: Option<u64> = None;
        let mut sequence: Option<u64> = None;
        let mut execution: Option<BTreeMap<String, i64>> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(ConnectivityEvidenceError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(ConnectivityEvidenceError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(ConnectivityEvidenceError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != CONNECTIVITY_EVIDENCE_SCHEME_VERSION {
                        return Err(ConnectivityEvidenceError::SchemeVersionUnsupported {
                            found: *s,
                        });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if provider.is_some() {
                        return Err(ConnectivityEvidenceError::DuplicateField { key: 2 });
                    }
                    provider = Some(NodeIdentity::from_wire(val).map_err(
                        ConnectivityEvidenceError::Identity,
                    )?);
                }
                3 => {
                    if contract_ref.is_some() {
                        return Err(ConnectivityEvidenceError::DuplicateField { key: 3 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(ConnectivityEvidenceError::FieldNotExpectedType { key: 3 });
                    };
                    if b.len() != 32 {
                        return Err(ConnectivityEvidenceError::ContractRefWrongLength {
                            len: b.len(),
                        });
                    }
                    contract_ref = Some(b.as_slice().try_into().expect("checked"));
                }
                4 => {
                    if kind.is_some() {
                        return Err(ConnectivityEvidenceError::DuplicateField { key: 4 });
                    }
                    let Value::Text(t) = val else {
                        return Err(ConnectivityEvidenceError::FieldNotExpectedType { key: 4 });
                    };
                    kind = Some(EvidenceKind::from_name(t).ok_or_else(
                        || ConnectivityEvidenceError::KindUnknown { found: t.clone() },
                    )?);
                }
                5 => {
                    if observed_at.is_some() {
                        return Err(ConnectivityEvidenceError::DuplicateField { key: 5 });
                    }
                    let Value::Int(t) = val else {
                        return Err(ConnectivityEvidenceError::FieldNotExpectedType { key: 5 });
                    };
                    if *t < 0 {
                        return Err(ConnectivityEvidenceError::TimestampNegative {
                            field: "observed_at",
                        });
                    }
                    observed_at = Some(*t as u64);
                }
                6 => {
                    if sequence.is_some() {
                        return Err(ConnectivityEvidenceError::DuplicateField { key: 6 });
                    }
                    let Value::Int(s) = val else {
                        return Err(ConnectivityEvidenceError::FieldNotExpectedType { key: 6 });
                    };
                    if *s < 0 {
                        return Err(ConnectivityEvidenceError::TimestampNegative {
                            field: "sequence",
                        });
                    }
                    sequence = Some(*s as u64);
                }
                7 => {
                    if execution.is_some() {
                        return Err(ConnectivityEvidenceError::DuplicateField { key: 7 });
                    }
                    let Value::Map(map) = val else {
                        return Err(ConnectivityEvidenceError::FieldNotExpectedType { key: 7 });
                    };
                    if map.len() > EXECUTION_MAX_ENTRIES {
                        return Err(ConnectivityEvidenceError::ExecutionTooManyEntries {
                            count: map.len(),
                            max: EXECUTION_MAX_ENTRIES,
                        });
                    }
                    let mut out = BTreeMap::new();
                    for (mk, mv) in map {
                        let (Value::Text(k), Value::Int(v)) = (mk, mv) else {
                            return Err(ConnectivityEvidenceError::ExecutionEntryMalformed);
                        };
                        if k.is_empty() || k.len() > EXECUTION_MAX_KEY_BYTES {
                            return Err(ConnectivityEvidenceError::ExecutionKeyInvalid {
                                bytes: k.len(),
                                max: EXECUTION_MAX_KEY_BYTES,
                            });
                        }
                        out.insert(k.clone(), *v);
                    }
                    execution = Some(out);
                }
                other => return Err(ConnectivityEvidenceError::UnknownField { key: other }),
            }
        }
        let _ = scheme;
        let provider = provider.ok_or(ConnectivityEvidenceError::MissingField { key: 2 })?;
        let contract_ref = contract_ref.ok_or(ConnectivityEvidenceError::MissingField { key: 3 })?;
        let kind = kind.ok_or(ConnectivityEvidenceError::MissingField { key: 4 })?;
        let observed_at = observed_at.ok_or(ConnectivityEvidenceError::MissingField { key: 5 })?;
        let sequence = sequence.ok_or(ConnectivityEvidenceError::MissingField { key: 6 })?;
        // parse-time enforcement of the same invariants as construction
        if sequence < SEQUENCE_MIN {
            return Err(ConnectivityEvidenceError::SequenceBelowMinimum { found: sequence });
        }
        if observed_at > i64::MAX as u64 {
            return Err(ConnectivityEvidenceError::TimestampOutOfRange);
        }
        Ok(ConnectivityObservationStatement {
            provider,
            contract_ref,
            kind,
            observed_at_unix: observed_at,
            sequence,
            execution,
        })
    }

    /// Sign this observation with the provider identity (binding enforced).
    pub fn sign(
        &self,
        provider: &Identity,
    ) -> Result<SignedConnectivityObservation, ConnectivityEvidenceError> {
        if provider.node_id() != self.provider.node_id() {
            return Err(ConnectivityEvidenceError::SignerMismatch {
                observation: self.provider.node_id().to_hex(),
                signer: provider.node_id().to_hex(),
            });
        }
        let observation_bytes = self.to_wire_bytes();
        let signature = provider.sign_detached(&observation_bytes);
        Ok(SignedConnectivityObservation {
            observation_bytes,
            signature,
        })
    }

    /// The embedded provider identity (self-certifying: the key that must
    /// verify the signature is inside the signed bytes).
    pub fn provider_identity(&self) -> &NodeIdentity {
        &self.provider
    }

    /// The R1-001 derived node id of the provider (the sequence namespace).
    pub fn provider_node_id(&self) -> crate::identity::NodeId {
        self.provider.node_id()
    }

    /// The opaque contract reference this observation is about.
    pub fn contract_ref(&self) -> &[u8; 32] {
        &self.contract_ref
    }

    /// Which adcos.md event this observation maps.
    pub fn kind(&self) -> EvidenceKind {
        self.kind
    }

    /// When the provider observed it (unix seconds, provider-assigned).
    pub fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
    }

    /// The per-(provider node_id, contract_ref) monotonic sequence.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// The optional execution counter map, if present.
    pub fn execution(&self) -> Option<&BTreeMap<String, i64>> {
        self.execution.as_ref()
    }
}

fn check_execution(map: &BTreeMap<String, i64>) -> Result<(), ConnectivityEvidenceError> {
    if map.len() > EXECUTION_MAX_ENTRIES {
        return Err(ConnectivityEvidenceError::ExecutionTooManyEntries {
            count: map.len(),
            max: EXECUTION_MAX_ENTRIES,
        });
    }
    for key in map.keys() {
        if key.is_empty() || key.len() > EXECUTION_MAX_KEY_BYTES {
            return Err(ConnectivityEvidenceError::ExecutionKeyInvalid {
                bytes: key.len(),
                max: EXECUTION_MAX_KEY_BYTES,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The carrying envelope (the CapabilityStatement envelope pattern)
// ---------------------------------------------------------------------------

/// A signed observation and its envelope parts: the exact canonical
/// observation bytes plus the detached Ed25519 signature by the provider
/// node key over those bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedConnectivityObservation {
    observation_bytes: Vec<u8>,
    signature: [u8; 64],
}

impl SignedConnectivityObservation {
    /// Re-assemble from raw parts (tests + cross-language harness paths).
    pub fn from_parts(observation_bytes: Vec<u8>, signature: [u8; 64]) -> Self {
        SignedConnectivityObservation {
            observation_bytes,
            signature,
        }
    }

    /// The exact canonical observation bytes that were signed.
    pub fn observation_bytes(&self) -> &[u8] {
        &self.observation_bytes
    }

    /// The detached provider signature.
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Strict parse of the embedded observation (not yet verified).
    pub fn observation(&self) -> Result<ConnectivityObservationStatement, ConnectivityEvidenceError> {
        ConnectivityObservationStatement::from_wire_bytes(&self.observation_bytes)
    }

    /// Strict parse + signature verification against the EMBEDDED provider
    /// identity (self-certifying, offline-verifiable). This is the
    /// cryptographic core of the registry admission rule; the full
    /// admission (known contract, sequence, freshness) is
    /// [`ObservationAdmission::receive`].
    pub fn verify(
        &self,
    ) -> Result<ConnectivityObservationStatement, ConnectivityEvidenceError> {
        let statement = self.observation()?;
        statement
            .provider_identity()
            .verify_detached(&self.observation_bytes, &self.signature)
            .map_err(|_| ConnectivityEvidenceError::SignatureInvalid)?;
        Ok(statement)
    }

    /// The carrying envelope bytes: canonical CBOR
    /// `{1: observation (bstr), 2: signature (64-byte bstr)}`.
    pub fn to_envelope_bytes(&self) -> Vec<u8> {
        let v = Value::Map(vec![
            (Value::Int(1), Value::Bytes(self.observation_bytes.clone())),
            (Value::Int(2), Value::Bytes(self.signature.to_vec())),
        ]);
        encode(&v).expect("in-profile")
    }

    /// Strict parse of the carrying envelope (exactly two entries, the
    /// right types, a 64-byte signature — anything else is refused).
    pub fn from_envelope_bytes(bytes: &[u8]) -> Result<Self, ConnectivityEvidenceError> {
        let v = decode(bytes).map_err(ConnectivityEvidenceError::Cbor)?;
        let Value::Map(entries) = &v else {
            return Err(ConnectivityEvidenceError::NotAMap);
        };
        if entries.len() != 2 {
            return Err(ConnectivityEvidenceError::EnvelopeWrongEntryCount {
                count: entries.len(),
            });
        }
        let mut observation_bytes: Option<Vec<u8>> = None;
        let mut signature: Option<[u8; 64]> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(ConnectivityEvidenceError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    let Value::Bytes(b) = val else {
                        return Err(ConnectivityEvidenceError::FieldNotExpectedType { key: 1 });
                    };
                    if observation_bytes.is_some() {
                        return Err(ConnectivityEvidenceError::DuplicateField { key: 1 });
                    }
                    observation_bytes = Some(b.clone());
                }
                2 => {
                    let Value::Bytes(b) = val else {
                        return Err(ConnectivityEvidenceError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != 64 {
                        return Err(ConnectivityEvidenceError::SignatureWrongLength {
                            len: b.len(),
                        });
                    }
                    if signature.is_some() {
                        return Err(ConnectivityEvidenceError::DuplicateField { key: 2 });
                    }
                    signature = Some(b.as_slice().try_into().expect("checked"));
                }
                other => return Err(ConnectivityEvidenceError::UnknownField { key: other }),
            }
        }
        Ok(SignedConnectivityObservation {
            observation_bytes: observation_bytes
                .ok_or(ConnectivityEvidenceError::MissingField { key: 1 })?,
            signature: signature.ok_or(ConnectivityEvidenceError::MissingField { key: 2 })?,
        })
    }
}

// ---------------------------------------------------------------------------
// Admission (the registry admission rule as code)
// ---------------------------------------------------------------------------

/// What the admission helper did with a signed observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionOutcome {
    /// Fully admitted: parsed, signature-verified, contract known,
    /// sequence strictly greater, fresh. The highest-seen sequence for
    /// (provider node_id, contract_ref) advanced.
    Admitted,
    /// The observation verified and the contract is known, but the
    /// sequence is not strictly greater than the highest previously
    /// accepted one for (provider node_id, contract_ref) — a redelivery
    /// or reorder, ignored exactly like the R5-001 cache's
    /// `IgnoredReplay` (provider redelivery is expected; no state moved).
    SequenceStale {
        /// The ignored sequence number.
        sequence: u64,
    },
}

/// The wire-verifiable admission state for signed connectivity
/// observations: the per-(provider node_id, contract_ref) highest-seen
/// sequence plus the known-contract set.
///
/// This is the registry admission rule, in the registry's order: strict
/// parse → R1-001 node_id derivation of the provider identity (inherent:
/// the id is derived from the embedded key) → strict signature
/// verification → the contract_ref is known to the accepting node → the
/// sequence is strictly greater than the highest previously accepted
/// observation for (provider node_id, contract_ref) → the freshness
/// window (the accepting node's policy, applied against the
/// caller-supplied clock — this crate has no wall clock by law).
///
/// It is deliberately minimal: the R5-003 durable store keeps the accepted
/// LOG and re-derives contract state; this helper owns only the
/// wire-verifiable admission facts (the monotonic sequence gate), so the
/// daemon composes the two without a second source of truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationAdmission {
    freshness_window_secs: u64,
    /// (provider node_id, contract_ref) -> highest accepted sequence.
    highest: HashMap<([u8; 32], [u8; 32]), u64>,
    /// The contracts this accepting node knows (registered locally).
    known: HashSet<[u8; 32]>,
}

impl ObservationAdmission {
    /// An admission tracker applying the accepting node's freshness window
    /// (observations are fresh for `freshness_window_secs` after their
    /// `observed_at_unix`, bound exclusive — the R5-001 cache policy).
    pub fn new(freshness_window_secs: u64) -> Self {
        ObservationAdmission {
            freshness_window_secs,
            highest: HashMap::new(),
            known: HashSet::new(),
        }
    }

    /// The configured freshness window (seconds).
    pub fn freshness_window_secs(&self) -> u64 {
        self.freshness_window_secs
    }

    /// Register a contract as KNOWN — an observation for an unknown
    /// contract is never a trust grant (the registry rule), so accepting
    /// nodes register the contracts they hold refs for.
    pub fn register_contract(&mut self, contract_ref: [u8; 32]) {
        self.known.insert(contract_ref);
    }

    /// Whether a contract is known to this accepting node.
    pub fn is_known_contract(&self, contract_ref: &[u8; 32]) -> bool {
        self.known.contains(contract_ref)
    }

    /// The highest accepted sequence for (provider node_id, contract_ref)
    /// — `None` when nothing was accepted yet for that pair.
    pub fn highest_sequence(
        &self,
        provider: &crate::identity::NodeId,
        contract_ref: &[u8; 32],
    ) -> Option<u64> {
        self.highest
            .get(&(*provider.as_bytes(), *contract_ref))
            .copied()
    }

    /// Full receiver-side admission of one signed observation (the
    /// registry order; fail-closed, no caller-controlled trust booleans).
    pub fn receive(
        &mut self,
        signed: &SignedConnectivityObservation,
        now_unix: u64,
    ) -> Result<AdmissionOutcome, ConnectivityEvidenceError> {
        // 1+2. strict parse (the provider identity parse IS the R1-001
        //     node_id derivation — the id is derived from the embedded key)
        let statement = signed.observation()?;
        let provider_node_id = statement.provider_node_id();
        // 3. strict signature verification against the embedded identity
        statement
            .provider_identity()
            .verify_detached(signed.observation_bytes(), signed.signature())
            .map_err(|_| ConnectivityEvidenceError::SignatureInvalid)?;
        // 4. the contract_ref is known to the accepting node
        if !self.known.contains(statement.contract_ref()) {
            return Err(ConnectivityEvidenceError::ContractUnknown {
                contract: *statement.contract_ref(),
            });
        }
        // 5. sequence strictly greater than the highest previously accepted
        //    for (provider node_id, contract_ref)
        let key = (*provider_node_id.as_bytes(), *statement.contract_ref());
        if let Some(&highest) = self.highest.get(&key) {
            if statement.sequence() <= highest {
                return Ok(AdmissionOutcome::SequenceStale {
                    sequence: statement.sequence(),
                });
            }
        }
        // 6. the freshness window (accepting node's policy, bound exclusive)
        if now_unix < statement.observed_at_unix() {
            return Err(ConnectivityEvidenceError::NotYetValid {
                now: now_unix,
                observed_at: statement.observed_at_unix(),
            });
        }
        let fresh_until = statement.observed_at_unix().checked_add(self.freshness_window_secs);
        match fresh_until {
            Some(bound) if now_unix < bound => {}
            Some(_) => {
                return Err(ConnectivityEvidenceError::Expired {
                    now: now_unix,
                    fresh_until: statement.observed_at_unix() + self.freshness_window_secs,
                })
            }
            None => return Err(ConnectivityEvidenceError::TimestampOutOfRange),
        }
        self.highest.insert(key, statement.sequence());
        Ok(AdmissionOutcome::Admitted)
    }
}

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

/// Typed failures of the signed connectivity observation wire object and
/// its admission. Stable machine names (`name()`) are the conformance
/// vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectivityEvidenceError {
    NotAMap,
    KeyNotAnInteger,
    FieldNotExpectedType { key: i64 },
    DuplicateField { key: i64 },
    UnknownField { key: i64 },
    MissingField { key: i64 },
    SchemeVersionUnsupported { found: i64 },
    Identity(crate::identity::IdentityError),
    Cbor(crate::cbor::DecodeError),
    ContractRefWrongLength { len: usize },
    KindUnknown { found: String },
    TimestampNegative { field: &'static str },
    TimestampOutOfRange,
    SequenceBelowMinimum { found: u64 },
    ExecutionEntryMalformed,
    ExecutionTooManyEntries { count: usize, max: usize },
    ExecutionKeyInvalid { bytes: usize, max: usize },
    SignatureWrongLength { len: usize },
    EnvelopeWrongEntryCount { count: usize },
    SignerMismatch { observation: String, signer: String },
    NotYetValid { now: u64, observed_at: u64 },
    Expired { now: u64, fresh_until: u64 },
    SignatureInvalid,
    ContractUnknown { contract: [u8; 32] },
}

impl ConnectivityEvidenceError {
    /// Stable machine name (vectors + harness).
    pub fn name(&self) -> String {
        match self {
            ConnectivityEvidenceError::NotAMap => "not_a_map",
            ConnectivityEvidenceError::KeyNotAnInteger => "key_not_an_integer",
            ConnectivityEvidenceError::FieldNotExpectedType { .. } => "field_not_expected_type",
            ConnectivityEvidenceError::DuplicateField { .. } => "duplicate_field",
            ConnectivityEvidenceError::UnknownField { .. } => "unknown_field",
            ConnectivityEvidenceError::MissingField { .. } => "missing_field",
            ConnectivityEvidenceError::SchemeVersionUnsupported { .. } => {
                "scheme_version_unsupported"
            }
            ConnectivityEvidenceError::Identity(e) => return format!("identity:{}", e.name()),
            ConnectivityEvidenceError::Cbor(e) => return format!("cbor:{}", e.name()),
            ConnectivityEvidenceError::ContractRefWrongLength { .. } => "contract_ref_wrong_length",
            ConnectivityEvidenceError::KindUnknown { .. } => "kind_unknown",
            ConnectivityEvidenceError::TimestampNegative { .. } => "timestamp_negative",
            ConnectivityEvidenceError::TimestampOutOfRange => "timestamp_out_of_range",
            ConnectivityEvidenceError::SequenceBelowMinimum { .. } => "sequence_below_minimum",
            ConnectivityEvidenceError::ExecutionEntryMalformed => "execution_entry_malformed",
            ConnectivityEvidenceError::ExecutionTooManyEntries { .. } => {
                "execution_too_many_entries"
            }
            ConnectivityEvidenceError::ExecutionKeyInvalid { .. } => "execution_key_invalid",
            ConnectivityEvidenceError::SignatureWrongLength { .. } => "signature_wrong_length",
            ConnectivityEvidenceError::EnvelopeWrongEntryCount { .. } => {
                "envelope_wrong_entry_count"
            }
            ConnectivityEvidenceError::SignerMismatch { .. } => "signer_mismatch",
            ConnectivityEvidenceError::NotYetValid { .. } => "not_yet_valid",
            ConnectivityEvidenceError::Expired { .. } => "expired",
            ConnectivityEvidenceError::SignatureInvalid => "signature_invalid",
            ConnectivityEvidenceError::ContractUnknown { .. } => "contract_unknown",
        }
        .to_string()
    }
}

impl fmt::Display for ConnectivityEvidenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectivityEvidenceError::NotAMap => {
                write!(f, "observation must be a CBOR map")
            }
            ConnectivityEvidenceError::KeyNotAnInteger => write!(f, "map keys must be integers"),
            ConnectivityEvidenceError::FieldNotExpectedType { key } => {
                write!(f, "field {key} has the wrong CBOR type")
            }
            ConnectivityEvidenceError::DuplicateField { key } => {
                write!(f, "duplicate field {key}")
            }
            ConnectivityEvidenceError::UnknownField { key } => write!(f, "unknown field {key}"),
            ConnectivityEvidenceError::MissingField { key } => {
                write!(f, "missing required field {key}")
            }
            ConnectivityEvidenceError::SchemeVersionUnsupported { found } => {
                write!(f, "scheme_version {found} unsupported")
            }
            ConnectivityEvidenceError::Identity(e) => {
                write!(f, "provider identity rejected: {e}")
            }
            ConnectivityEvidenceError::Cbor(e) => write!(f, "CBOR profile violation: {e}"),
            ConnectivityEvidenceError::ContractRefWrongLength { len } => {
                write!(f, "contract_ref must be 32 bytes, found {len}")
            }
            ConnectivityEvidenceError::KindUnknown { found } => {
                write!(f, "unknown observation kind {found:?}")
            }
            ConnectivityEvidenceError::TimestampNegative { field } => {
                write!(f, "{field} must be non-negative")
            }
            ConnectivityEvidenceError::TimestampOutOfRange => {
                write!(f, "timestamps exceed the canonical integer range")
            }
            ConnectivityEvidenceError::SequenceBelowMinimum { found } => {
                write!(f, "sequence {found} is below the minimum {SEQUENCE_MIN}")
            }
            ConnectivityEvidenceError::ExecutionEntryMalformed => {
                write!(f, "execution entries must be text -> integer")
            }
            ConnectivityEvidenceError::ExecutionTooManyEntries { count, max } => {
                write!(f, "execution map may have at most {max} entries, found {count}")
            }
            ConnectivityEvidenceError::ExecutionKeyInvalid { bytes, max } => {
                write!(f, "execution key must be 1..={max} bytes, found {bytes}")
            }
            ConnectivityEvidenceError::SignatureWrongLength { len } => {
                write!(f, "signature must be 64 bytes, found {len}")
            }
            ConnectivityEvidenceError::EnvelopeWrongEntryCount { count } => {
                write!(f, "envelope must have exactly 2 entries, found {count}")
            }
            ConnectivityEvidenceError::SignerMismatch { observation, signer } => write!(
                f,
                "cannot sign: observation binds provider {observation}, signer is {signer}"
            ),
            ConnectivityEvidenceError::NotYetValid { now, observed_at } => write!(
                f,
                "observation not yet valid: now {now} < observed_at {observed_at}"
            ),
            ConnectivityEvidenceError::Expired { now, fresh_until } => write!(
                f,
                "observation outside the freshness window: now {now} >= fresh_until {fresh_until}"
            ),
            ConnectivityEvidenceError::SignatureInvalid => {
                write!(f, "observation signature verification failed")
            }
            ConnectivityEvidenceError::ContractUnknown { contract } => write!(
                f,
                "observation for an unknown contract ({}); an unknown contract_ref is never a trust grant",
                crate::identity::to_hex(contract)
            ),
        }
    }
}

impl std::error::Error for ConnectivityEvidenceError {}

// ---------------------------------------------------------------------------
// Tests (unit level; the adversarial suite is tests/connectivity_evidence_adversarial.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(seed: u8) -> Identity {
        Identity::from_seed([seed; 32], 1_700_000_000, None).expect("identity")
    }

    fn contract(tag: u8) -> [u8; 32] {
        [tag; 32]
    }

    fn signed_obs(
        p: &Identity,
        tag: u8,
        kind: EvidenceKind,
        observed_at: u64,
        sequence: u64,
        execution: Option<BTreeMap<String, i64>>,
    ) -> SignedConnectivityObservation {
        ConnectivityObservationStatement::new(p, contract(tag), kind, observed_at, sequence, execution)
            .expect("builds")
            .sign(p)
            .expect("signs")
    }

    #[test]
    fn kinds_are_exactly_the_six_adcos_events() {
        for kind in EvidenceKind::ALL {
            assert_eq!(EvidenceKind::from_name(kind.as_str()), Some(kind));
        }
        assert_eq!(EvidenceKind::from_name("bogus"), None);
        assert_eq!(EvidenceKind::ALL.len(), 6, "the adcos.md mapping has exactly six events");
        // The machine names must match the connectivity domain crate's
        // frozen vocabulary (documented alignment; independent lists).
        let names: Vec<&str> = EvidenceKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(
            names,
            [
                "contract_activated",
                "execution_state_changed",
                "degraded",
                "assurance_available",
                "failover_replan",
                "terminated",
            ]
        );
    }

    #[test]
    fn wire_roundtrip_and_envelope() {
        let mut execution = BTreeMap::new();
        execution.insert("uplink_bytes".to_string(), 2048);
        execution.insert("active_sessions".to_string(), 1);
        let signed = signed_obs(
            &provider(1),
            0x01,
            EvidenceKind::ExecutionStateChanged,
            1_000,
            2,
            Some(execution),
        );
        let env = signed.to_envelope_bytes();
        let back = SignedConnectivityObservation::from_envelope_bytes(&env).unwrap();
        assert_eq!(back, signed);
        let statement = back.observation().unwrap();
        assert_eq!(back.observation().unwrap().to_wire_bytes(), signed.observation_bytes().to_vec());
        assert_eq!(statement.kind(), EvidenceKind::ExecutionStateChanged);
        assert_eq!(statement.sequence(), 2);
        assert_eq!(statement.contract_ref(), &contract(0x01));
        assert_eq!(
            statement.execution().map(|m| m.get("uplink_bytes").copied()),
            Some(Some(2048))
        );
    }

    #[test]
    fn verify_succeeds_and_rejects_wrong_key() {
        let signed = signed_obs(&provider(2), 0x02, EvidenceKind::Degraded, 1_000, 1, None);
        assert!(signed.verify().is_ok());
        // the same observation bytes signed by a DIFFERENT key
        let foreign = provider(3);
        let bad = SignedConnectivityObservation::from_parts(
            signed.observation_bytes().to_vec(),
            foreign.sign_detached(signed.observation_bytes()),
        );
        assert_eq!(bad.verify().unwrap_err(), ConnectivityEvidenceError::SignatureInvalid);
    }

    #[test]
    fn signer_binding_enforced() {
        let statement = ConnectivityObservationStatement::new(
            &provider(4),
            contract(0x04),
            EvidenceKind::AssuranceAvailable,
            1_000,
            1,
            None,
        )
        .unwrap();
        assert!(matches!(
            statement.sign(&provider(5)),
            Err(ConnectivityEvidenceError::SignerMismatch { .. })
        ));
    }

    #[test]
    fn admission_full_pipeline() {
        let mut admission = ObservationAdmission::new(600);
        admission.register_contract(contract(0x05));
        let p = provider(6);
        let first = signed_obs(&p, 0x05, EvidenceKind::ContractActivated, 1_000, 1, None);
        let second = signed_obs(&p, 0x05, EvidenceKind::Degraded, 1_010, 2, None);
        let replay = signed_obs(&p, 0x05, EvidenceKind::ContractActivated, 1_000, 1, None);
        assert_eq!(admission.receive(&first, 1_030).unwrap(), AdmissionOutcome::Admitted);
        // redelivery of the same sequence is ignored, not an error
        assert_eq!(
            admission.receive(&replay, 1_030).unwrap(),
            AdmissionOutcome::SequenceStale { sequence: 1 }
        );
        // reordered older observation: same
        assert_eq!(
            admission.receive(&replay, 1_030).unwrap(),
            AdmissionOutcome::SequenceStale { sequence: 1 }
        );
        assert_eq!(admission.receive(&second, 1_030).unwrap(), AdmissionOutcome::Admitted);
        assert_eq!(admission.highest_sequence(&p.node_id(), &contract(0x05)), Some(2));
        // freshness: before observed_at and past the bound
        let third = signed_obs(&p, 0x05, EvidenceKind::Terminated, 2_000, 3, None);
        assert!(matches!(
            admission.receive(&third, 1_999),
            Err(ConnectivityEvidenceError::NotYetValid { .. })
        ));
        assert!(matches!(
            admission.receive(&third, 2_600),
            Err(ConnectivityEvidenceError::Expired { .. })
        ));
        assert_eq!(admission.receive(&third, 2_100).unwrap(), AdmissionOutcome::Admitted);
        // unknown contract
        let foreign_contract = signed_obs(&p, 0x07, EvidenceKind::Degraded, 2_200, 4, None);
        assert!(matches!(
            admission.receive(&foreign_contract, 2_300),
            Err(ConnectivityEvidenceError::ContractUnknown { .. })
        ));
    }

    #[test]
    fn zero_window_is_accept_then_immediately_stale() {
        // The R5-001 zero-window policy, applied by the admission helper.
        let mut zero = ObservationAdmission::new(0);
        zero.register_contract(contract(0x0D));
        let p = provider(0x0E);
        let obs = signed_obs(&p, 0x0D, EvidenceKind::Degraded, 1_000, 1, None);
        // at now == observed_at the (exclusive) bound is already reached
        assert!(matches!(
            zero.receive(&obs, 1_000),
            Err(ConnectivityEvidenceError::Expired { .. })
        ));
        // a time-travel probe before the observation is not_yet_valid
        assert!(matches!(
            zero.receive(&obs, 999),
            Err(ConnectivityEvidenceError::NotYetValid { .. })
        ));
    }

    #[test]
    fn sequence_namespaces_are_per_provider_and_contract() {
        let mut admission = ObservationAdmission::new(600);
        admission.register_contract(contract(0x08));
        admission.register_contract(contract(0x09));
        let a = provider(0x0A);
        let b = provider(0x0B);
        // same provider, same sequence, different contracts: independent
        assert_eq!(
            admission
                .receive(&signed_obs(&a, 0x08, EvidenceKind::Degraded, 1_000, 5, None), 1_030)
                .unwrap(),
            AdmissionOutcome::Admitted
        );
        assert_eq!(
            admission
                .receive(&signed_obs(&a, 0x09, EvidenceKind::Degraded, 1_000, 5, None), 1_030)
                .unwrap(),
            AdmissionOutcome::Admitted,
            "cross-contract: the sequence namespaces are independent"
        );
        // different provider, same contract, same sequence: independent
        assert_eq!(
            admission
                .receive(&signed_obs(&b, 0x08, EvidenceKind::Degraded, 1_000, 5, None), 1_030)
                .unwrap(),
            AdmissionOutcome::Admitted,
            "cross-provider: the sequence namespaces are independent"
        );
    }

    #[test]
    fn build_invariants_enforced() {
        let p = provider(0x0C);
        // sequence 0 is reserved
        assert!(matches!(
            ConnectivityObservationStatement::new(
                &p,
                contract(0x0C),
                EvidenceKind::Degraded,
                1_000,
                0,
                None
            ),
            Err(ConnectivityEvidenceError::SequenceBelowMinimum { found: 0 })
        ));
        // oversized execution map
        let mut too_many = BTreeMap::new();
        for i in 0..17 {
            too_many.insert(format!("k{i:02}"), i);
        }
        assert!(matches!(
            ConnectivityObservationStatement::new(
                &p,
                contract(0x0C),
                EvidenceKind::Degraded,
                1_000,
                1,
                Some(too_many)
            ),
            Err(ConnectivityEvidenceError::ExecutionTooManyEntries { count: 17, .. })
        ));
        // overlong key
        let mut long_key = BTreeMap::new();
        long_key.insert("x".repeat(65), 1);
        assert!(matches!(
            ConnectivityObservationStatement::new(
                &p,
                contract(0x0C),
                EvidenceKind::Degraded,
                1_000,
                1,
                Some(long_key)
            ),
            Err(ConnectivityEvidenceError::ExecutionKeyInvalid { bytes: 65, .. })
        ));
    }
}
