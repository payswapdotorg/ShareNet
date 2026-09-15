//! Authenticated topology evidence (work item R3-003).
//!
//! A [`TopologyEvidence`] record is a signed, one-directional attestation:
//! an OBSERVER node states what it observed about a SUBJECT node — an
//! authenticated link (with quality) or a verified advertisement (with the
//! observed capability set). Routing (R3-004) and gateway selection consume
//! these records; per the anti-gaming rules a link counts as BILATERAL only
//! when fresh evidence from both endpoints exists.
//!
//! The record is self-certifying: the observer's `NodeIdentity` is inside
//! the signed bytes, so a record can be verified offline. Evidence is FRESH
//! within its window; collectors prune by `expires_at`.
//!
//! Quality fields (delivered/lost/RTT/jitter/loss) are caller-mapped from
//! the R2-004 `LinkQualitySummary` — the protocol core takes plain
//! integers (the canonical CBOR profile forbids floats, hence the
//! parts-per-million loss ratio).
//!
//! Persistence: none — runtime evidence; durable replay-safe receipts are
//! R8-001 scope.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::cbor::{decode, encode, Value};
use crate::identity::{Identity, NodeIdentity};

/// Scheme version of the TopologyEvidence wire object (v1).
pub const EVIDENCE_SCHEME_VERSION: i64 = 1;
/// Maximum evidence window (`expires_at - observed_at`).
pub const EVIDENCE_MAX_WINDOW: u64 = 3600;
/// Maximum loss ratio in parts-per-million (100%).
pub const LOSS_RATIO_PPM_MAX: u64 = 1_000_000;

const KIND_LINK: &str = "link";
const KIND_ADVERTISEMENT: &str = "advertisement";

/// Quality snapshot of an observed link (caller-mapped from R2-004).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkQualitySnapshot {
    pub delivered: u64,
    pub lost: u64,
    pub ewma_rtt_micros: u64,
    pub p50_rtt_micros: u64,
    pub p95_rtt_micros: u64,
    pub jitter_mad_micros: u64,
    /// Loss ratio in parts-per-million (0..=1_000_000).
    pub loss_ratio_ppm: u64,
}

/// The per-kind observation payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observation {
    Link {
        link_id: [u8; 32],
        established_at_unix: u64,
        quality: LinkQualitySnapshot,
    },
    Advertisement {
        advertisement_id: [u8; 32],
        capabilities: Vec<String>, // strictly ascending wire texts
    },
}

/// A parsed (not yet verified) topology evidence record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopologyEvidence {
    identity: NodeIdentity,
    subject_node_id: [u8; 32],
    observation: Observation,
    observed_at_unix: u64,
    expires_at_unix: u64,
}

/// A signed evidence record and its envelope bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTopologyEvidence {
    evidence_bytes: Vec<u8>,
    signature: [u8; 64],
}

impl TopologyEvidence {
    /// Build an evidence record from the observer's live identity.
    pub fn new(
        observer: &Identity,
        subject_node_id: [u8; 32],
        observation: Observation,
        observed_at_unix: u64,
        validity_secs: u64,
    ) -> Result<Self, TopologyError> {
        if subject_node_id == *observer.node_id().as_bytes() {
            return Err(TopologyError::SubjectIsObserver);
        }
        if validity_secs == 0 || validity_secs > EVIDENCE_MAX_WINDOW {
            return Err(TopologyError::WindowInvalid {
                validity: validity_secs,
                max: EVIDENCE_MAX_WINDOW,
            });
        }
        let expires_at_unix = observed_at_unix
            .checked_add(validity_secs)
            .filter(|e| *e <= i64::MAX as u64)
            .ok_or(TopologyError::TimestampOutOfRange)?;
        if let Observation::Link {
            established_at_unix,
            quality,
            ..
        } = &observation
        {
            if *established_at_unix > observed_at_unix {
                return Err(TopologyError::EstablishedAfterObserved);
            }
            if quality.p95_rtt_micros < quality.p50_rtt_micros {
                return Err(TopologyError::PercentilesUnordered);
            }
            if quality.loss_ratio_ppm > LOSS_RATIO_PPM_MAX {
                return Err(TopologyError::LossRatioOutOfRange {
                    ppm: quality.loss_ratio_ppm,
                });
            }
        }
        if let Observation::Advertisement { capabilities, .. } = &observation {
            let mut sorted = capabilities.clone();
            sorted.sort();
            sorted.dedup();
            if sorted.len() != capabilities.len() {
                return Err(TopologyError::CapabilitiesNotSorted);
            }
        }
        Ok(TopologyEvidence {
            identity: observer.node_identity().clone(),
            subject_node_id,
            observation,
            observed_at_unix,
            expires_at_unix,
        })
    }

    /// The canonical CBOR wire form.
    pub fn to_wire(&self) -> Value {
        let mut entries: Vec<(Value, Value)> = vec![
            (Value::Int(1), Value::Int(EVIDENCE_SCHEME_VERSION)),
            (Value::Int(2), self.identity.to_wire()),
            (Value::Int(3), Value::Bytes(self.subject_node_id.to_vec())),
        ];
        let (kind, obs_map) = match &self.observation {
            Observation::Link {
                link_id,
                established_at_unix,
                quality,
            } => (
                KIND_LINK,
                Value::Map(vec![
                    (Value::Int(1), Value::Bytes(link_id.to_vec())),
                    (Value::Int(2), Value::Int(*established_at_unix as i64)),
                    (Value::Int(3), Value::Int(quality.delivered as i64)),
                    (Value::Int(4), Value::Int(quality.lost as i64)),
                    (Value::Int(5), Value::Int(quality.ewma_rtt_micros as i64)),
                    (Value::Int(6), Value::Int(quality.p50_rtt_micros as i64)),
                    (Value::Int(7), Value::Int(quality.p95_rtt_micros as i64)),
                    (Value::Int(8), Value::Int(quality.jitter_mad_micros as i64)),
                    (Value::Int(9), Value::Int(quality.loss_ratio_ppm as i64)),
                ]),
            ),
            Observation::Advertisement {
                advertisement_id,
                capabilities,
            } => (
                KIND_ADVERTISEMENT,
                Value::Map(vec![
                    (Value::Int(1), Value::Bytes(advertisement_id.to_vec())),
                    (
                        Value::Int(2),
                        Value::Array(
                            capabilities.iter().map(|c| Value::Text(c.clone())).collect(),
                        ),
                    ),
                ]),
            ),
        };
        entries.push((Value::Int(4), Value::Text(kind.to_string())));
        entries.push((Value::Int(5), Value::Int(self.observed_at_unix as i64)));
        entries.push((Value::Int(6), Value::Int(self.expires_at_unix as i64)));
        entries.push((Value::Int(7), obs_map));
        Value::Map(entries)
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, TopologyError> {
        let v = decode(bytes).map_err(TopologyError::Cbor)?;
        Self::from_wire(&v)
    }

    pub fn from_wire(v: &Value) -> Result<Self, TopologyError> {
        let Value::Map(entries) = v else {
            return Err(TopologyError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut identity: Option<NodeIdentity> = None;
        let mut subject: Option<[u8; 32]> = None;
        let mut kind: Option<String> = None;
        let mut observed_at: Option<u64> = None;
        let mut expires_at: Option<u64> = None;
        let mut obs_map: Option<Value> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(TopologyError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(TopologyError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(TopologyError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != EVIDENCE_SCHEME_VERSION {
                        return Err(TopologyError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if identity.is_some() {
                        return Err(TopologyError::DuplicateField { key: 2 });
                    }
                    identity =
                        Some(NodeIdentity::from_wire(val).map_err(TopologyError::Identity)?);
                }
                3 => {
                    if subject.is_some() {
                        return Err(TopologyError::DuplicateField { key: 3 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(TopologyError::FieldNotExpectedType { key: 3 });
                    };
                    if b.len() != 32 {
                        return Err(TopologyError::SubjectWrongLength { len: b.len() });
                    }
                    subject = Some(b.as_slice().try_into().expect("checked"));
                }
                4 => {
                    if kind.is_some() {
                        return Err(TopologyError::DuplicateField { key: 4 });
                    }
                    let Value::Text(k) = val else {
                        return Err(TopologyError::FieldNotExpectedType { key: 4 });
                    };
                    if k != KIND_LINK && k != KIND_ADVERTISEMENT {
                        return Err(TopologyError::KindUnknown { found: k.clone() });
                    }
                    kind = Some(k.clone());
                }
                5 => {
                    if observed_at.is_some() {
                        return Err(TopologyError::DuplicateField { key: 5 });
                    }
                    let Value::Int(t) = val else {
                        return Err(TopologyError::FieldNotExpectedType { key: 5 });
                    };
                    if *t < 0 {
                        return Err(TopologyError::TimestampNegative { field: "observed_at" });
                    }
                    observed_at = Some(*t as u64);
                }
                6 => {
                    if expires_at.is_some() {
                        return Err(TopologyError::DuplicateField { key: 6 });
                    }
                    let Value::Int(t) = val else {
                        return Err(TopologyError::FieldNotExpectedType { key: 6 });
                    };
                    if *t < 0 {
                        return Err(TopologyError::TimestampNegative { field: "expires_at" });
                    }
                    expires_at = Some(*t as u64);
                }
                7 => {
                    if obs_map.is_some() {
                        return Err(TopologyError::DuplicateField { key: 7 });
                    }
                    obs_map = Some(val.clone());
                }
                other => return Err(TopologyError::UnknownField { key: other }),
            }
        }
        let identity = identity.ok_or(TopologyError::MissingField { key: 2 })?;
        let subject = subject.ok_or(TopologyError::MissingField { key: 3 })?;
        let kind = kind.ok_or(TopologyError::MissingField { key: 4 })?;
        let observed_at = observed_at.ok_or(TopologyError::MissingField { key: 5 })?;
        let expires_at = expires_at.ok_or(TopologyError::MissingField { key: 6 })?;
        let obs_map = obs_map.ok_or(TopologyError::MissingField { key: 7 })?;
        let Value::Map(obs_entries) = &obs_map else {
            return Err(TopologyError::ObservationMalformed);
        };
        let observation = match kind.as_str() {
            KIND_LINK => {
                let mut link_id: Option<[u8; 32]> = None;
                let mut established: Option<u64> = None;
                let mut delivered: Option<u64> = None;
                let mut lost: Option<u64> = None;
                let mut ewma: Option<u64> = None;
                let mut p50: Option<u64> = None;
                let mut p95: Option<u64> = None;
                let mut jitter: Option<u64> = None;
                let mut loss_ppm: Option<u64> = None;
                for (k, val) in obs_entries {
                    let Value::Int(key) = k else {
                        return Err(TopologyError::ObservationMalformed);
                    };
                    let u64_of = |v: &Value| -> Result<u64, TopologyError> {
                        if let Value::Int(i) = v {
                            if *i < 0 {
                                return Err(TopologyError::ObservationMalformed);
                            }
                            Ok(*i as u64)
                        } else {
                            Err(TopologyError::ObservationMalformed)
                        }
                    };
                    match *key {
                        1 => {
                            let Value::Bytes(b) = val else {
                                return Err(TopologyError::ObservationMalformed);
                            };
                            if b.len() != 32 {
                                return Err(TopologyError::LinkIdWrongLength { len: b.len() });
                            }
                            link_id = Some(b.as_slice().try_into().expect("checked"));
                        }
                        2 => established = Some(u64_of(val)?),
                        3 => delivered = Some(u64_of(val)?),
                        4 => lost = Some(u64_of(val)?),
                        5 => ewma = Some(u64_of(val)?),
                        6 => p50 = Some(u64_of(val)?),
                        7 => p95 = Some(u64_of(val)?),
                        8 => jitter = Some(u64_of(val)?),
                        9 => loss_ppm = Some(u64_of(val)?),
                        _ => return Err(TopologyError::ObservationMalformed),
                    }
                }
                let quality = LinkQualitySnapshot {
                    delivered: delivered.ok_or(TopologyError::ObservationMalformed)?,
                    lost: lost.ok_or(TopologyError::ObservationMalformed)?,
                    ewma_rtt_micros: ewma.ok_or(TopologyError::ObservationMalformed)?,
                    p50_rtt_micros: p50.ok_or(TopologyError::ObservationMalformed)?,
                    p95_rtt_micros: p95.ok_or(TopologyError::ObservationMalformed)?,
                    jitter_mad_micros: jitter.ok_or(TopologyError::ObservationMalformed)?,
                    loss_ratio_ppm: loss_ppm.ok_or(TopologyError::ObservationMalformed)?,
                };
                Observation::Link {
                    link_id: link_id.ok_or(TopologyError::ObservationMalformed)?,
                    established_at_unix: established.ok_or(TopologyError::ObservationMalformed)?,
                    quality,
                }
            }
            _ => {
                let mut advertisement_id: Option<[u8; 32]> = None;
                let mut capabilities: Option<Vec<String>> = None;
                for (k, val) in obs_entries {
                    let Value::Int(key) = k else {
                        return Err(TopologyError::ObservationMalformed);
                    };
                    match *key {
                        1 => {
                            let Value::Bytes(b) = val else {
                                return Err(TopologyError::ObservationMalformed);
                            };
                            if b.len() != 32 {
                                return Err(TopologyError::AdvertisementIdWrongLength {
                                    len: b.len(),
                                });
                            }
                            advertisement_id =
                                Some(b.as_slice().try_into().expect("checked"));
                        }
                        2 => {
                            let Value::Array(items) = val else {
                                return Err(TopologyError::ObservationMalformed);
                            };
                            let mut caps: Vec<String> = Vec::with_capacity(items.len());
                            for (i, item) in items.iter().enumerate() {
                                let Value::Text(t) = item else {
                                    return Err(TopologyError::ObservationMalformed);
                                };
                                if i > 0 && !(t > &caps[i - 1]) {
                                    return Err(TopologyError::CapabilitiesNotSorted);
                                }
                                caps.push(t.clone());
                            }
                            capabilities = Some(caps);
                        }
                        _ => return Err(TopologyError::ObservationMalformed),
                    }
                }
                Observation::Advertisement {
                    advertisement_id: advertisement_id
                        .ok_or(TopologyError::ObservationMalformed)?,
                    capabilities: capabilities.ok_or(TopologyError::ObservationMalformed)?,
                }
            }
        };
        if expires_at <= observed_at {
            return Err(TopologyError::ExpiryNotAfterIssue {
                issued_at: observed_at,
                expires_at,
            });
        }
        if expires_at - observed_at > EVIDENCE_MAX_WINDOW {
            return Err(TopologyError::WindowInvalid {
                validity: expires_at - observed_at,
                max: EVIDENCE_MAX_WINDOW,
            });
        }
        if subject == *identity.node_id().as_bytes() {
            return Err(TopologyError::SubjectIsObserver);
        }
        // parse-time enforcement of the same invariants as construction
        // (byte-stability requires exactly one accepted form per record)
        if let Observation::Link {
            established_at_unix,
            quality,
            ..
        } = &observation
        {
            if *established_at_unix > observed_at {
                return Err(TopologyError::EstablishedAfterObserved);
            }
            if quality.p95_rtt_micros < quality.p50_rtt_micros {
                return Err(TopologyError::PercentilesUnordered);
            }
            if quality.loss_ratio_ppm > LOSS_RATIO_PPM_MAX {
                return Err(TopologyError::LossRatioOutOfRange {
                    ppm: quality.loss_ratio_ppm,
                });
            }
        }
        Ok(TopologyEvidence {
            identity,
            subject_node_id: subject,
            observation,
            observed_at_unix: observed_at,
            expires_at_unix: expires_at,
        })
    }

    /// Sign this evidence with the observer identity (binding enforced).
    pub fn sign(&self, observer: &Identity) -> Result<SignedTopologyEvidence, TopologyError> {
        if observer.node_id() != self.identity.node_id() {
            return Err(TopologyError::SignerMismatch {
                evidence: self.identity.node_id().to_hex(),
                signer: observer.node_id().to_hex(),
            });
        }
        let evidence_bytes = self.to_wire_bytes();
        let signature = observer.sign_detached(&evidence_bytes);
        Ok(SignedTopologyEvidence {
            evidence_bytes,
            signature,
        })
    }

    pub fn observer_identity(&self) -> &NodeIdentity {
        &self.identity
    }

    pub fn observer_node_id(&self) -> crate::identity::NodeId {
        self.identity.node_id()
    }

    pub fn subject_node_id(&self) -> &[u8; 32] {
        &self.subject_node_id
    }

    pub fn observation(&self) -> &Observation {
        &self.observation
    }

    pub fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

impl SignedTopologyEvidence {
    /// Re-assemble from raw parts (tests + cross-language harness paths).
    pub fn from_parts(evidence_bytes: Vec<u8>, signature: [u8; 64]) -> Self {
        SignedTopologyEvidence {
            evidence_bytes,
            signature,
        }
    }

    pub fn evidence_bytes(&self) -> &[u8] {
        &self.evidence_bytes
    }

    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    pub fn evidence(&self) -> Result<TopologyEvidence, TopologyError> {
        TopologyEvidence::from_wire_bytes(&self.evidence_bytes)
    }

    /// Content-derived evidence identifier.
    pub fn evidence_id(&self) -> [u8; 32] {
        let mut id = [0u8; 32];
        id.copy_from_slice(&Sha256::digest(&self.evidence_bytes));
        id
    }

    pub fn to_envelope_bytes(&self) -> Vec<u8> {
        let v = Value::Map(vec![
            (Value::Int(1), Value::Bytes(self.evidence_bytes.clone())),
            (Value::Int(2), Value::Bytes(self.signature.to_vec())),
        ]);
        encode(&v).expect("in-profile")
    }

    pub fn from_envelope_bytes(bytes: &[u8]) -> Result<Self, TopologyError> {
        let v = decode(bytes).map_err(TopologyError::Cbor)?;
        let Value::Map(entries) = &v else {
            return Err(TopologyError::NotAMap);
        };
        if entries.len() != 2 {
            return Err(TopologyError::EnvelopeWrongEntryCount {
                count: entries.len(),
            });
        }
        let mut evidence_bytes: Option<Vec<u8>> = None;
        let mut signature: Option<[u8; 64]> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(TopologyError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    let Value::Bytes(b) = val else {
                        return Err(TopologyError::FieldNotExpectedType { key: 1 });
                    };
                    if evidence_bytes.is_some() {
                        return Err(TopologyError::DuplicateField { key: 1 });
                    }
                    evidence_bytes = Some(b.clone());
                }
                2 => {
                    let Value::Bytes(b) = val else {
                        return Err(TopologyError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != 64 {
                        return Err(TopologyError::SignatureWrongLength { len: b.len() });
                    }
                    if signature.is_some() {
                        return Err(TopologyError::DuplicateField { key: 2 });
                    }
                    signature = Some(b.as_slice().try_into().expect("checked"));
                }
                other => return Err(TopologyError::UnknownField { key: other }),
            }
        }
        Ok(SignedTopologyEvidence {
            evidence_bytes: evidence_bytes.ok_or(TopologyError::MissingField { key: 1 })?,
            signature: signature.ok_or(TopologyError::MissingField { key: 2 })?,
        })
    }
}

/// Typed topology evidence failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TopologyError {
    NotAMap,
    KeyNotAnInteger,
    FieldNotExpectedType { key: i64 },
    DuplicateField { key: i64 },
    UnknownField { key: i64 },
    MissingField { key: i64 },
    SchemeVersionUnsupported { found: i64 },
    Identity(crate::identity::IdentityError),
    Cbor(crate::cbor::DecodeError),
    SubjectWrongLength { len: usize },
    LinkIdWrongLength { len: usize },
    AdvertisementIdWrongLength { len: usize },
    KindUnknown { found: String },
    ObservationMalformed,
    TimestampNegative { field: &'static str },
    TimestampOutOfRange,
    ExpiryNotAfterIssue { issued_at: u64, expires_at: u64 },
    WindowInvalid { validity: u64, max: u64 },
    SubjectIsObserver,
    EstablishedAfterObserved,
    PercentilesUnordered,
    LossRatioOutOfRange { ppm: u64 },
    CapabilitiesNotSorted,
    SignatureWrongLength { len: usize },
    EnvelopeWrongEntryCount { count: usize },
    SignerMismatch { evidence: String, signer: String },
    NotYetValid { now: u64, observed_at: u64 },
    Expired { now: u64, expires_at: u64 },
    SignatureInvalid,
}

impl TopologyError {
    /// Stable machine name (vectors + harness).
    pub fn name(&self) -> String {
        match self {
            TopologyError::NotAMap => "not_a_map",
            TopologyError::KeyNotAnInteger => "key_not_an_integer",
            TopologyError::FieldNotExpectedType { .. } => "field_not_expected_type",
            TopologyError::DuplicateField { .. } => "duplicate_field",
            TopologyError::UnknownField { .. } => "unknown_field",
            TopologyError::MissingField { .. } => "missing_field",
            TopologyError::SchemeVersionUnsupported { .. } => "scheme_version_unsupported",
            TopologyError::Identity(e) => return format!("identity:{}", e.name()),
            TopologyError::Cbor(e) => return format!("cbor:{}", e.name()),
            TopologyError::SubjectWrongLength { .. } => "subject_wrong_length",
            TopologyError::LinkIdWrongLength { .. } => "link_id_wrong_length",
            TopologyError::AdvertisementIdWrongLength { .. } => "advertisement_id_wrong_length",
            TopologyError::KindUnknown { .. } => "kind_unknown",
            TopologyError::ObservationMalformed => "observation_malformed",
            TopologyError::TimestampNegative { .. } => "timestamp_negative",
            TopologyError::TimestampOutOfRange => "timestamp_out_of_range",
            TopologyError::ExpiryNotAfterIssue { .. } => "expiry_not_after_issue",
            TopologyError::WindowInvalid { .. } => "window_invalid",
            TopologyError::SubjectIsObserver => "subject_is_observer",
            TopologyError::EstablishedAfterObserved => "established_after_observed",
            TopologyError::PercentilesUnordered => "percentiles_unordered",
            TopologyError::LossRatioOutOfRange { .. } => "loss_ratio_out_of_range",
            TopologyError::CapabilitiesNotSorted => "capabilities_not_sorted",
            TopologyError::SignatureWrongLength { .. } => "signature_wrong_length",
            TopologyError::EnvelopeWrongEntryCount { .. } => "envelope_wrong_entry_count",
            TopologyError::SignerMismatch { .. } => "signer_mismatch",
            TopologyError::NotYetValid { .. } => "not_yet_valid",
            TopologyError::Expired { .. } => "expired",
            TopologyError::SignatureInvalid => "signature_invalid",
        }
        .to_string()
    }
}

impl fmt::Display for TopologyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TopologyError::NotAMap => write!(f, "evidence must be a CBOR map"),
            TopologyError::KeyNotAnInteger => write!(f, "map keys must be integers"),
            TopologyError::FieldNotExpectedType { key } => {
                write!(f, "field {key} has the wrong CBOR type")
            }
            TopologyError::DuplicateField { key } => write!(f, "duplicate field {key}"),
            TopologyError::UnknownField { key } => write!(f, "unknown field {key}"),
            TopologyError::MissingField { key } => write!(f, "missing required field {key}"),
            TopologyError::SchemeVersionUnsupported { found } => {
                write!(f, "scheme_version {found} unsupported")
            }
            TopologyError::Identity(e) => write!(f, "observer identity rejected: {e}"),
            TopologyError::Cbor(e) => write!(f, "CBOR profile violation: {e}"),
            TopologyError::SubjectWrongLength { len } => {
                write!(f, "subject node_id must be 32 bytes, found {len}")
            }
            TopologyError::LinkIdWrongLength { len } => {
                write!(f, "link_id must be 32 bytes, found {len}")
            }
            TopologyError::AdvertisementIdWrongLength { len } => {
                write!(f, "advertisement_id must be 32 bytes, found {len}")
            }
            TopologyError::KindUnknown { found } => {
                write!(f, "unknown observation kind {found:?}")
            }
            TopologyError::ObservationMalformed => write!(f, "observation payload malformed"),
            TopologyError::TimestampNegative { field } => {
                write!(f, "{field} must be non-negative")
            }
            TopologyError::TimestampOutOfRange => {
                write!(f, "timestamps exceed the canonical integer range")
            }
            TopologyError::ExpiryNotAfterIssue { issued_at, expires_at } => {
                write!(f, "expires_at {expires_at} must follow observed_at {issued_at}")
            }
            TopologyError::WindowInvalid { validity, max } => {
                write!(f, "validity {validity}s exceeds the {max}s bound")
            }
            TopologyError::SubjectIsObserver => {
                write!(f, "a node cannot attest evidence about itself (bilateral rule)")
            }
            TopologyError::EstablishedAfterObserved => {
                write!(f, "link established_at is after observed_at")
            }
            TopologyError::PercentilesUnordered => {
                write!(f, "p95 must be >= p50")
            }
            TopologyError::LossRatioOutOfRange { ppm } => {
                write!(f, "loss_ratio_ppm {ppm} exceeds 1_000_000")
            }
            TopologyError::CapabilitiesNotSorted => {
                write!(f, "capabilities must be strictly ascending")
            }
            TopologyError::SignatureWrongLength { len } => {
                write!(f, "signature must be 64 bytes, found {len}")
            }
            TopologyError::EnvelopeWrongEntryCount { count } => {
                write!(f, "envelope must have exactly 2 entries, found {count}")
            }
            TopologyError::SignerMismatch { evidence, signer } => write!(
                f,
                "cannot sign: evidence binds observer {evidence}, signer is {signer}"
            ),
            TopologyError::NotYetValid { now, observed_at } => {
                write!(f, "evidence not yet valid: now {now} < observed_at {observed_at}")
            }
            TopologyError::Expired { now, expires_at } => {
                write!(f, "evidence expired: now {now} >= expires_at {expires_at}")
            }
            TopologyError::SignatureInvalid => write!(f, "evidence signature verification failed"),
        }
    }
}

impl std::error::Error for TopologyError {}

// ---------------------------------------------------------------------------
// Topology store (collector)
// ---------------------------------------------------------------------------

/// A bilaterally-confirmed link (fresh evidence from BOTH endpoints about
/// the SAME link_id).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BilateralLink {
    pub link_id: [u8; 32],
    pub endpoints: [[u8; 32]; 2], // (observer_a, observer_b) node ids
    pub expires_at_unix: u64,
}

/// In-memory collector of VERIFIED topology evidence.
#[derive(Debug, Default)]
pub struct TopologyStore {
    /// node_id -> freshest verified link evidence BY THAT OBSERVER per link_id.
    links: std::collections::HashMap<([u8; 32], [u8; 32]), (u64, u64, [u8; 32])>, // (observer, link_id) -> (observed_at, expires_at, subject)
    /// node_id -> freshest verified advertisement evidence per advertisement_id.
    ads: std::collections::HashMap<([u8; 32], [u8; 32]), (u64, u64, [u8; 32])>,
}

impl TopologyStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Full receiver-side verification + collection of one signed record.
    pub fn receive(
        &mut self,
        signed: &SignedTopologyEvidence,
        now_unix: u64,
    ) -> Result<ReceiveOutcome, TopologyError> {
        let ev = signed.evidence()?;
        ev.observer_identity()
            .verify_detached(signed.evidence_bytes(), signed.signature())
            .map_err(|_| TopologyError::SignatureInvalid)?;
        if now_unix < ev.observed_at_unix() {
            return Err(TopologyError::NotYetValid {
                now: now_unix,
                observed_at: ev.observed_at_unix(),
            });
        }
        if now_unix >= ev.expires_at_unix() {
            return Err(TopologyError::Expired {
                now: now_unix,
                expires_at: ev.expires_at_unix(),
            });
        }
        let observer = *ev.observer_node_id().as_bytes();
        let key = match ev.observation() {
            Observation::Link { link_id, .. } => (observer, *link_id),
            Observation::Advertisement { advertisement_id, .. } => (observer, *advertisement_id),
        };
        let entry = (ev.observed_at_unix(), ev.expires_at_unix(), *ev.subject_node_id());
        let map = match ev.observation() {
            Observation::Link { .. } => &mut self.links,
            Observation::Advertisement { .. } => &mut self.ads,
        };
        match map.get(&key) {
            Some((cached_observed, _, _)) if *cached_observed >= ev.observed_at_unix() => {
                return Ok(ReceiveOutcome::Stale);
            }
            _ => {}
        }
        map.insert(key, entry);
        Ok(ReceiveOutcome::Collected)
    }

    /// Links with fresh, bilaterally-confirmed evidence (both endpoints
    /// attesting the same link_id within their windows).
    pub fn bilateral_links(&self, now_unix: u64) -> Vec<BilateralLink> {
        // index: link_id -> [(observer, subject, expires_at)]
        let mut by_link: std::collections::HashMap<
            [u8; 32],
            Vec<([u8; 32], [u8; 32], u64)>,
        > = std::collections::HashMap::new();
        for ((observer, link_id), (_, expires, subject)) in &self.links {
            if *expires > now_unix {
                by_link
                    .entry(*link_id)
                    .or_default()
                    .push((*observer, *subject, *expires));
            }
        }
        let mut out = Vec::new();
        for (link_id, sides) in by_link {
            if sides.len() != 2 {
                continue;
            }
            let (a, b) = (&sides[0], &sides[1]);
            // bilateral: each side's subject is the other side's observer
            if a.1 == b.0 && b.1 == a.0 {
                // canonical endpoint order: the pair is sorted so the output
                // is deterministic (HashMap iteration order must not leak
                // into the API — found by the Wave 10 flaky-test audit)
                let mut endpoints = [a.0, b.0];
                endpoints.sort();
                out.push(BilateralLink {
                    link_id,
                    endpoints,
                    expires_at_unix: a.2.min(b.2),
                });
            }
        }
        out.sort_by(|x, y| x.link_id.cmp(&y.link_id));
        out
    }

    /// Nodes with fresh advertisement evidence (latest observation wins).
    pub fn advertised_nodes(&self, now_unix: u64) -> Vec<([u8; 32], u64)> {
        let mut best: std::collections::HashMap<[u8; 32], ([u8; 32], u64)> =
            std::collections::HashMap::new(); // subject -> (ad_id, expires)
        for ((observer, ad_id), (_, expires, subject)) in &self.ads {
            if *expires > now_unix {
                match best.get(subject) {
                    Some((_, e)) if *e >= *expires => {}
                    _ => {
                        best.insert(*subject, (*ad_id, *expires));
                    }
                }
            }
            let _ = observer;
        }
        let mut out: Vec<([u8; 32], u64)> =
            best.into_iter().map(|(s, (_, e))| (s, e)).collect();
        out.sort();
        out
    }
}

/// What the collector did with a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiveOutcome {
    Collected,
    Stale,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> Identity {
        Identity::from_seed([seed; 32], 1_700_000_000, None).expect("identity")
    }

    fn subject_of(id: &Identity) -> [u8; 32] {
        *id.node_id().as_bytes()
    }

    fn link_obs(seed_a: u8, seed_b: u8, observed: u64, validity: u64) -> SignedTopologyEvidence {
        let a = identity(seed_a);
        let b = identity(seed_b);
        let ev = TopologyEvidence::new(
            &a,
            subject_of(&b),
            Observation::Link {
                link_id: [seed_a; 32],
                established_at_unix: observed - 10,
                quality: LinkQualitySnapshot {
                    delivered: 200,
                    lost: 3,
                    ewma_rtt_micros: 1_500,
                    p50_rtt_micros: 1_400,
                    p95_rtt_micros: 2_100,
                    jitter_mad_micros: 120,
                    loss_ratio_ppm: 15_000,
                },
            },
            observed,
            validity,
        )
        .unwrap();
        ev.sign(&a).unwrap()
    }

    #[test]
    fn bilateral_link_requires_both_sides() {
        let mut store = TopologyStore::new();
        // only A attests
        store.receive(&link_obs(1, 2, 1_000, 60), 1_030).unwrap();
        assert!(store.bilateral_links(1_030).is_empty());
        // B attests the same link_id about A
        let mut ev = {
            let a = identity(1);
            let b = identity(2);
            TopologyEvidence::new(
                &b,
                subject_of(&a),
                Observation::Link {
                    link_id: [1u8; 32],
                    established_at_unix: 990,
                    quality: LinkQualitySnapshot {
                        delivered: 198,
                        lost: 5,
                        ewma_rtt_micros: 1_600,
                        p50_rtt_micros: 1_500,
                        p95_rtt_micros: 2_200,
                        jitter_mad_micros: 130,
                        loss_ratio_ppm: 25_000,
                    },
                },
                1_001,
                60,
            )
            .unwrap()
        };
        let signed = ev.sign(&identity(2)).unwrap();
        let _ = &mut ev;
        store.receive(&signed, 1_031).unwrap();
        let links = store.bilateral_links(1_031);
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].link_id, [1u8; 32]);
        // endpoints are canonically sorted (deterministic output)
        let mut expected = [
            *identity(1).node_id().as_bytes(),
            *identity(2).node_id().as_bytes(),
        ];
        expected.sort();
        assert_eq!(links[0].endpoints, expected);
        // expires after both windows
        assert!(store.bilateral_links(1_061).is_empty());
    }

    #[test]
    fn self_attestation_rejected() {
        let a = identity(3);
        assert!(matches!(
            TopologyEvidence::new(
                &a,
                subject_of(&a),
                Observation::Advertisement {
                    advertisement_id: [7u8; 32],
                    capabilities: vec![],
                },
                1_000,
                60,
            ),
            Err(TopologyError::SubjectIsObserver)
        ));
    }

    #[test]
    fn tampered_evidence_fails_signature() {
        let signed = link_obs(4, 5, 1_000, 60);
        let mut tampered = signed.evidence_bytes().to_vec();
        // tamper the delivered count region: find "delivered" field 3 in the
        // observation map and flip a byte
        let pos = tampered.len() / 2;
        tampered[pos] ^= 0x01;
        let bad = SignedTopologyEvidence::from_parts(tampered, *signed.signature());
        let mut store = TopologyStore::new();
        assert!(matches!(
            store.receive(&bad, 1_030),
            Err(TopologyError::SignatureInvalid | TopologyError::Cbor(_))
        ));
    }

    #[test]
    fn expired_and_future_rejected() {
        let signed = link_obs(6, 7, 1_000, 60);
        let mut store = TopologyStore::new();
        assert!(matches!(
            store.receive(&signed, 1_060),
            Err(TopologyError::Expired { .. })
        ));
        assert!(matches!(
            store.receive(&signed, 999),
            Err(TopologyError::NotYetValid { .. })
        ));
    }

    #[test]
    fn quality_invariants_enforced() {
        let a = identity(8);
        let b = identity(9);
        // p95 < p50
        assert!(matches!(
            TopologyEvidence::new(
                &a,
                subject_of(&b),
                Observation::Link {
                    link_id: [1u8; 32],
                    established_at_unix: 990,
                    quality: LinkQualitySnapshot {
                        delivered: 1,
                        lost: 0,
                        ewma_rtt_micros: 1,
                        p50_rtt_micros: 100,
                        p95_rtt_micros: 99,
                        jitter_mad_micros: 1,
                        loss_ratio_ppm: 0,
                    },
                },
                1_000,
                60,
            ),
            Err(TopologyError::PercentilesUnordered)
        ));
        // loss ratio > 1e6
        assert!(matches!(
            TopologyEvidence::new(
                &a,
                subject_of(&b),
                Observation::Link {
                    link_id: [1u8; 32],
                    established_at_unix: 990,
                    quality: LinkQualitySnapshot {
                        delivered: 1,
                        lost: 0,
                        ewma_rtt_micros: 1,
                        p50_rtt_micros: 1,
                        p95_rtt_micros: 1,
                        jitter_mad_micros: 1,
                        loss_ratio_ppm: 1_000_001,
                    },
                },
                1_000,
                60,
            ),
            Err(TopologyError::LossRatioOutOfRange { .. })
        ));
    }

    #[test]
    fn stale_evidence_not_collected() {
        let mut store = TopologyStore::new();
        store.receive(&link_obs(10, 11, 2_000, 60), 2_030).unwrap();
        // older observation of the same (observer, link_id) is stale
        assert_eq!(
            store.receive(&link_obs(10, 11, 1_990, 60), 2_031).unwrap(),
            ReceiveOutcome::Stale
        );
    }

    #[test]
    fn wire_roundtrip_and_envelope() {
        let signed = link_obs(12, 13, 1_000, 60);
        let env = signed.to_envelope_bytes();
        let back = SignedTopologyEvidence::from_envelope_bytes(&env).unwrap();
        assert_eq!(back, signed);
        let ev = back.evidence().unwrap();
        assert_eq!(back.evidence_id(), signed.evidence_id());
        // wire byte-stability
        assert_eq!(ev.to_wire_bytes(), signed.evidence_bytes().to_vec());
    }
}
