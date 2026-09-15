//! Route commitment (work item R3-004).
//!
//! A route is derived, never asserted:
//!
//! ```text
//! RouteProposal (signed by the proposer, nonce makes every proposal new)
//!     + one signed RouteAcceptance per path position
//!     ↓ Merkle commitment over the acceptance bytes (ordered by position)
//! commitment_root
//!     ↓ SHA-256("sharenet-route-id-v1" || commitment_root)
//! route_id          (caller-selected route IDs are FORBIDDEN — L013)
//! ```
//!
//! Every replacement route is genuinely new: a fresh nonce produces a fresh
//! proposal, a fresh acceptance set, a fresh root, a fresh route id
//! (L014's replay-namespace rule applied at the route level). A failed or
//! revoked route is never resurrected — recovery (R7) builds a NEW route.
//!
//! Verification is fail-closed: proposal signature + invariants, each
//! acceptance's signature/position/binding/freshness, exact position
//! coverage, and re-derivation of both the Merkle root and the route id.
//!
//! Persistence: none — route commitments are computed and verified objects;
//! durable circuit state is R4/R7 scope.

use core::fmt;

use sha2::{Digest, Sha256};

use crate::cbor::{decode, encode, Value};
use crate::identity::{Identity, NodeIdentity};

/// Scheme version of the route wire objects (v1).
pub const ROUTE_SCHEME_VERSION: i64 = 1;
/// Maximum proposal/acceptance freshness window.
pub const ROUTE_MAX_WINDOW: u64 = 3600;
/// Maximum path length (hops).
pub const ROUTE_MAX_PATH: usize = 16;

const ROUTE_ID_CONTEXT: &[u8] = b"sharenet-route-id-v1";
pub const SERVICE_CLASSES: [&str; 3] = ["live", "opportunistic", "dtn"];

// ---------------------------------------------------------------------------
// RouteProposal
// ---------------------------------------------------------------------------

/// A parsed (not yet verified) route proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteProposal {
    identity: NodeIdentity,
    path: Vec<[u8; 32]>, // strictly ascending node ids
    service_class: String,
    proposed_at_unix: u64,
    expires_at_unix: u64,
    proposal_nonce: [u8; 32],
}

impl RouteProposal {
    pub fn new(
        proposer: &Identity,
        mut path: Vec<[u8; 32]>,
        service_class: impl Into<String>,
        proposed_at_unix: u64,
        validity_secs: u64,
        proposal_nonce: [u8; 32],
    ) -> Result<Self, RouteError> {
        let service_class = service_class.into();
        if path.is_empty() {
            return Err(RouteError::PathEmpty);
        }
        if path.len() > ROUTE_MAX_PATH {
            return Err(RouteError::PathTooLong {
                len: path.len(),
                max: ROUTE_MAX_PATH,
            });
        }
        if !SERVICE_CLASSES.contains(&service_class.as_str()) {
            return Err(RouteError::ServiceClassUnknown {
                found: service_class,
            });
        }
        if validity_secs == 0 || validity_secs > ROUTE_MAX_WINDOW {
            return Err(RouteError::WindowInvalid {
                validity: validity_secs,
                max: ROUTE_MAX_WINDOW,
            });
        }
        path.sort();
        path.dedup();
        if path.len() != path.len().max(0) && has_dup(&path) {
            return Err(RouteError::PathDuplicate);
        }
        let expires_at_unix = proposed_at_unix
            .checked_add(validity_secs)
            .filter(|e| *e <= i64::MAX as u64)
            .ok_or(RouteError::TimestampOutOfRange)?;
        Ok(RouteProposal {
            identity: proposer.node_identity().clone(),
            path,
            service_class,
            proposed_at_unix,
            expires_at_unix,
            proposal_nonce,
        })
    }

    pub fn to_wire(&self) -> Value {
        Value::Map(vec![
            (Value::Int(1), Value::Int(ROUTE_SCHEME_VERSION)),
            (Value::Int(2), self.identity.to_wire()),
            (
                Value::Int(3),
                Value::Array(self.path.iter().map(|p| Value::Bytes(p.to_vec())).collect()),
            ),
            (Value::Int(4), Value::Text(self.service_class.clone())),
            (Value::Int(5), Value::Int(self.proposed_at_unix as i64)),
            (Value::Int(6), Value::Int(self.expires_at_unix as i64)),
            (Value::Int(7), Value::Bytes(self.proposal_nonce.to_vec())),
        ])
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, RouteError> {
        let v = decode(bytes).map_err(RouteError::Cbor)?;
        Self::from_wire(&v)
    }

    pub fn from_wire(v: &Value) -> Result<Self, RouteError> {
        let Value::Map(entries) = v else {
            return Err(RouteError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut identity: Option<NodeIdentity> = None;
        let mut path: Option<Vec<[u8; 32]>> = None;
        let mut service_class: Option<String> = None;
        let mut proposed_at: Option<u64> = None;
        let mut expires_at: Option<u64> = None;
        let mut nonce: Option<[u8; 32]> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(RouteError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(RouteError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != ROUTE_SCHEME_VERSION {
                        return Err(RouteError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if identity.is_some() {
                        return Err(RouteError::DuplicateField { key: 2 });
                    }
                    identity =
                        Some(NodeIdentity::from_wire(val).map_err(RouteError::Identity)?);
                }
                3 => {
                    if path.is_some() {
                        return Err(RouteError::DuplicateField { key: 3 });
                    }
                    let Value::Array(items) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 3 });
                    };
                    if items.is_empty() {
                        return Err(RouteError::PathEmpty);
                    }
                    if items.len() > ROUTE_MAX_PATH {
                        return Err(RouteError::PathTooLong {
                            len: items.len(),
                            max: ROUTE_MAX_PATH,
                        });
                    }
                    let mut out: Vec<[u8; 32]> = Vec::with_capacity(items.len());
                    for (i, item) in items.iter().enumerate() {
                        let Value::Bytes(b) = item else {
                            return Err(RouteError::PathMalformed);
                        };
                        if b.len() != 32 {
                            return Err(RouteError::PathMalformed);
                        }
                        let arr: [u8; 32] = b.as_slice().try_into().expect("checked");
                        if i > 0 && arr <= out[i - 1] {
                            return Err(RouteError::PathUnsorted {
                                at: i,
                            });
                        }
                        out.push(arr);
                    }
                    path = Some(out);
                }
                4 => {
                    if service_class.is_some() {
                        return Err(RouteError::DuplicateField { key: 4 });
                    }
                    let Value::Text(s) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 4 });
                    };
                    if !SERVICE_CLASSES.contains(&s.as_str()) {
                        return Err(RouteError::ServiceClassUnknown { found: s.clone() });
                    }
                    service_class = Some(s.clone());
                }
                5 => {
                    if proposed_at.is_some() {
                        return Err(RouteError::DuplicateField { key: 5 });
                    }
                    let Value::Int(t) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 5 });
                    };
                    if *t < 0 {
                        return Err(RouteError::TimestampNegative {
                            field: "proposed_at",
                        });
                    }
                    proposed_at = Some(*t as u64);
                }
                6 => {
                    if expires_at.is_some() {
                        return Err(RouteError::DuplicateField { key: 6 });
                    }
                    let Value::Int(t) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 6 });
                    };
                    if *t < 0 {
                        return Err(RouteError::TimestampNegative {
                            field: "expires_at",
                        });
                    }
                    expires_at = Some(*t as u64);
                }
                7 => {
                    if nonce.is_some() {
                        return Err(RouteError::DuplicateField { key: 7 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 7 });
                    };
                    if b.len() != 32 {
                        return Err(RouteError::NonceWrongLength { len: b.len() });
                    }
                    nonce = Some(b.as_slice().try_into().expect("checked"));
                }
                other => return Err(RouteError::UnknownField { key: other }),
            }
        }
        let identity = identity.ok_or(RouteError::MissingField { key: 2 })?;
        let path = path.ok_or(RouteError::MissingField { key: 3 })?;
        let service_class = service_class.ok_or(RouteError::MissingField { key: 4 })?;
        let proposed_at = proposed_at.ok_or(RouteError::MissingField { key: 5 })?;
        let expires_at = expires_at.ok_or(RouteError::MissingField { key: 6 })?;
        let nonce = nonce.ok_or(RouteError::MissingField { key: 7 })?;
        if expires_at <= proposed_at {
            return Err(RouteError::ExpiryNotAfterIssue {
                issued_at: proposed_at,
                expires_at,
            });
        }
        if expires_at - proposed_at > ROUTE_MAX_WINDOW {
            return Err(RouteError::WindowInvalid {
                validity: expires_at - proposed_at,
                max: ROUTE_MAX_WINDOW,
            });
        }
        Ok(RouteProposal {
            identity,
            path,
            service_class,
            proposed_at_unix: proposed_at,
            expires_at_unix: expires_at,
            proposal_nonce: nonce,
        })
    }

    pub fn sign(&self, proposer: &Identity) -> Result<SignedEnvelope, RouteError> {
        if proposer.node_id() != self.identity.node_id() {
            return Err(RouteError::SignerMismatch {
                object: self.identity.node_id().to_hex(),
                signer: proposer.node_id().to_hex(),
            });
        }
        let bytes = self.to_wire_bytes();
        let signature = proposer.sign_detached(&bytes);
        Ok(SignedEnvelope { bytes, signature })
    }

    pub fn proposer_identity(&self) -> &NodeIdentity {
        &self.identity
    }

    pub fn path(&self) -> &[[u8; 32]] {
        &self.path
    }

    pub fn service_class(&self) -> &str {
        &self.service_class
    }

    pub fn proposed_at_unix(&self) -> u64 {
        self.proposed_at_unix
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    pub fn proposal_nonce(&self) -> &[u8; 32] {
        &self.proposal_nonce
    }
}

fn has_dup(sorted: &[[u8; 32]]) -> bool {
    sorted.windows(2).any(|w| w[0] == w[1])
}

// ---------------------------------------------------------------------------
// SignedEnvelope (generic carrying envelope for route objects)
// ---------------------------------------------------------------------------

/// A signed route-family object in its carrying envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnvelope {
    bytes: Vec<u8>,
    signature: [u8; 64],
}

impl SignedEnvelope {
    pub fn new(bytes: Vec<u8>, signature: [u8; 64]) -> Self {
        SignedEnvelope { bytes, signature }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    pub fn to_envelope_bytes(&self) -> Vec<u8> {
        let v = Value::Map(vec![
            (Value::Int(1), Value::Bytes(self.bytes.clone())),
            (Value::Int(2), Value::Bytes(self.signature.to_vec())),
        ]);
        encode(&v).expect("in-profile")
    }

    pub fn from_envelope_bytes(bytes: &[u8]) -> Result<Self, RouteError> {
        let v = decode(bytes).map_err(RouteError::Cbor)?;
        let Value::Map(entries) = &v else {
            return Err(RouteError::NotAMap);
        };
        if entries.len() != 2 {
            return Err(RouteError::EnvelopeWrongEntryCount {
                count: entries.len(),
            });
        }
        let mut inner: Option<Vec<u8>> = None;
        let mut signature: Option<[u8; 64]> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(RouteError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    let Value::Bytes(b) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 1 });
                    };
                    if inner.is_some() {
                        return Err(RouteError::DuplicateField { key: 1 });
                    }
                    inner = Some(b.clone());
                }
                2 => {
                    let Value::Bytes(b) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != 64 {
                        return Err(RouteError::SignatureWrongLength { len: b.len() });
                    }
                    if signature.is_some() {
                        return Err(RouteError::DuplicateField { key: 2 });
                    }
                    signature = Some(b.as_slice().try_into().expect("checked"));
                }
                other => return Err(RouteError::UnknownField { key: other }),
            }
        }
        Ok(SignedEnvelope {
            bytes: inner.ok_or(RouteError::MissingField { key: 1 })?,
            signature: signature.ok_or(RouteError::MissingField { key: 2 })?,
        })
    }
}

// ---------------------------------------------------------------------------
// RouteAcceptance
// ---------------------------------------------------------------------------

/// A parsed (not yet verified) hop acceptance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAcceptance {
    proposal_id: [u8; 32],
    identity: NodeIdentity,
    position: u64,
    accepted_at_unix: u64,
    expires_at_unix: u64,
}

impl RouteAcceptance {
    pub fn new(
        accepting: &Identity,
        proposal_id: [u8; 32],
        position: u64,
        accepted_at_unix: u64,
        validity_secs: u64,
    ) -> Result<Self, RouteError> {
        if validity_secs == 0 || validity_secs > ROUTE_MAX_WINDOW {
            return Err(RouteError::WindowInvalid {
                validity: validity_secs,
                max: ROUTE_MAX_WINDOW,
            });
        }
        let expires_at_unix = accepted_at_unix
            .checked_add(validity_secs)
            .filter(|e| *e <= i64::MAX as u64)
            .ok_or(RouteError::TimestampOutOfRange)?;
        Ok(RouteAcceptance {
            proposal_id,
            identity: accepting.node_identity().clone(),
            position,
            accepted_at_unix,
            expires_at_unix,
        })
    }

    pub fn to_wire(&self) -> Value {
        Value::Map(vec![
            (Value::Int(1), Value::Int(ROUTE_SCHEME_VERSION)),
            (Value::Int(2), Value::Bytes(self.proposal_id.to_vec())),
            (Value::Int(3), self.identity.to_wire()),
            (Value::Int(4), Value::Int(self.position as i64)),
            (Value::Int(5), Value::Int(self.accepted_at_unix as i64)),
            (Value::Int(6), Value::Int(self.expires_at_unix as i64)),
        ])
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, RouteError> {
        let v = decode(bytes).map_err(RouteError::Cbor)?;
        Self::from_wire(&v)
    }

    pub fn from_wire(v: &Value) -> Result<Self, RouteError> {
        let Value::Map(entries) = v else {
            return Err(RouteError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut proposal_id: Option<[u8; 32]> = None;
        let mut identity: Option<NodeIdentity> = None;
        let mut position: Option<u64> = None;
        let mut accepted_at: Option<u64> = None;
        let mut expires_at: Option<u64> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(RouteError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(RouteError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != ROUTE_SCHEME_VERSION {
                        return Err(RouteError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if proposal_id.is_some() {
                        return Err(RouteError::DuplicateField { key: 2 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != 32 {
                        return Err(RouteError::ProposalIdWrongLength { len: b.len() });
                    }
                    proposal_id = Some(b.as_slice().try_into().expect("checked"));
                }
                3 => {
                    if identity.is_some() {
                        return Err(RouteError::DuplicateField { key: 3 });
                    }
                    identity =
                        Some(NodeIdentity::from_wire(val).map_err(RouteError::Identity)?);
                }
                4 => {
                    if position.is_some() {
                        return Err(RouteError::DuplicateField { key: 4 });
                    }
                    let Value::Int(p) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 4 });
                    };
                    if *p < 0 {
                        return Err(RouteError::PositionNegative { found: *p });
                    }
                    position = Some(*p as u64);
                }
                5 => {
                    if accepted_at.is_some() {
                        return Err(RouteError::DuplicateField { key: 5 });
                    }
                    let Value::Int(t) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 5 });
                    };
                    if *t < 0 {
                        return Err(RouteError::TimestampNegative {
                            field: "accepted_at",
                        });
                    }
                    accepted_at = Some(*t as u64);
                }
                6 => {
                    if expires_at.is_some() {
                        return Err(RouteError::DuplicateField { key: 6 });
                    }
                    let Value::Int(t) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 6 });
                    };
                    if *t < 0 {
                        return Err(RouteError::TimestampNegative {
                            field: "expires_at",
                        });
                    }
                    expires_at = Some(*t as u64);
                }
                other => return Err(RouteError::UnknownField { key: other }),
            }
        }
        let proposal_id = proposal_id.ok_or(RouteError::MissingField { key: 2 })?;
        let identity = identity.ok_or(RouteError::MissingField { key: 3 })?;
        let position = position.ok_or(RouteError::MissingField { key: 4 })?;
        let accepted_at = accepted_at.ok_or(RouteError::MissingField { key: 5 })?;
        let expires_at = expires_at.ok_or(RouteError::MissingField { key: 6 })?;
        if expires_at <= accepted_at {
            return Err(RouteError::ExpiryNotAfterIssue {
                issued_at: accepted_at,
                expires_at,
            });
        }
        if expires_at - accepted_at > ROUTE_MAX_WINDOW {
            return Err(RouteError::WindowInvalid {
                validity: expires_at - accepted_at,
                max: ROUTE_MAX_WINDOW,
            });
        }
        Ok(RouteAcceptance {
            proposal_id,
            identity,
            position,
            accepted_at_unix: accepted_at,
            expires_at_unix: expires_at,
        })
    }

    pub fn sign(&self, accepting: &Identity) -> Result<SignedEnvelope, RouteError> {
        if accepting.node_id() != self.identity.node_id() {
            return Err(RouteError::SignerMismatch {
                object: self.identity.node_id().to_hex(),
                signer: accepting.node_id().to_hex(),
            });
        }
        let bytes = self.to_wire_bytes();
        let signature = accepting.sign_detached(&bytes);
        Ok(SignedEnvelope { bytes, signature })
    }

    pub fn proposal_id(&self) -> &[u8; 32] {
        &self.proposal_id
    }

    pub fn accepting_identity(&self) -> &NodeIdentity {
        &self.identity
    }

    pub fn position(&self) -> u64 {
        self.position
    }

    pub fn accepted_at_unix(&self) -> u64 {
        self.accepted_at_unix
    }

    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

// ---------------------------------------------------------------------------
// Merkle commitment
// ---------------------------------------------------------------------------

fn sha256_pair(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    h.finalize().into()
}

/// Merkle root over leaves: binary tree, duplicate-the-last-leaf when a
/// level has an odd count; a single leaf is hashed as its own pair
/// (leaf || leaf); an empty leaf set is rejected by callers (paths are
/// non-empty).
pub fn merkle_root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaves.is_empty() {
        return None;
    }
    // a single leaf is committed as its own pair (leaf || leaf)
    if leaves.len() == 1 {
        return Some(sha256_pair(&leaves[0], &leaves[0]));
    }
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity((level.len() + 1) / 2);
        let mut i = 0;
        while i < level.len() {
            let a = level[i];
            let b = if i + 1 < level.len() { level[i + 1] } else { level[i] };
            next.push(sha256_pair(&a, &b));
            i += 2;
        }
        level = next;
    }
    Some(level[0])
}

/// route_id = SHA-256("sharenet-route-id-v1" || commitment_root).
pub fn derive_route_id(commitment_root: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(ROUTE_ID_CONTEXT);
    h.update(commitment_root);
    h.finalize().into()
}

/// proposal_id = SHA-256(canonical proposal bytes).
pub fn derive_proposal_id(proposal_bytes: &[u8]) -> [u8; 32] {
    let mut id = [0u8; 32];
    id.copy_from_slice(&Sha256::digest(proposal_bytes));
    id
}

// ---------------------------------------------------------------------------
// RouteCommitment
// ---------------------------------------------------------------------------

/// A parsed (not yet verified) route commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCommitment {
    proposal_envelope: SignedEnvelope,
    acceptance_envelopes: Vec<SignedEnvelope>, // ordered by position
    commitment_root: [u8; 32],
    route_id: [u8; 32],
}

impl RouteCommitment {
    /// Build a commitment from the signed proposal and the signed
    /// acceptances (any input order; ordered by position internally).
    /// The proposer's signature on the proposal is verified here, and each
    /// acceptance's signature/binding/freshness is verified at build time
    /// — commitments are never constructed from unverified evidence.
    pub fn build(
        now_unix: u64,
        proposal_envelope: SignedEnvelope,
        mut acceptance_envelopes: Vec<SignedEnvelope>,
    ) -> Result<Self, RouteError> {
        let proposal = verify_proposal_envelope(&proposal_envelope, now_unix)?;
        let proposal_id = derive_proposal_id(proposal_envelope.bytes());
        let path = proposal.path().to_vec();
        // parse + verify every acceptance against the proposal
        let mut by_position: Vec<(u64, [u8; 32])> = Vec::with_capacity(acceptance_envelopes.len());
        let mut verified: Vec<(u64, SignedEnvelope)> =
            Vec::with_capacity(acceptance_envelopes.len());
        for env in acceptance_envelopes.drain(..) {
            let acceptance = RouteAcceptance::from_wire_bytes(env.bytes())?;
            if acceptance.proposal_id() != &proposal_id {
                return Err(RouteError::AcceptanceWrongProposal);
            }
            if acceptance.position() as usize >= path.len() {
                return Err(RouteError::AcceptancePositionOutOfRange {
                    position: acceptance.position(),
                    path_len: path.len(),
                });
            }
            if acceptance.accepting_identity().node_id().as_bytes() != &path[acceptance.position() as usize] {
                return Err(RouteError::AcceptanceIdentityMismatch {
                    position: acceptance.position(),
                });
            }
            acceptance
                .accepting_identity()
                .verify_detached(env.bytes(), env.signature())
                .map_err(|_| RouteError::AcceptanceSignatureInvalid {
                    position: acceptance.position(),
                })?;
            if now_unix < acceptance.accepted_at_unix() {
                return Err(RouteError::AcceptanceNotYetValid {
                    position: acceptance.position(),
                });
            }
            if now_unix >= acceptance.expires_at_unix() {
                return Err(RouteError::AcceptanceExpired {
                    position: acceptance.position(),
                });
            }
            by_position.push((acceptance.position(), derive_proposal_id(env.bytes())));
            verified.push((acceptance.position(), env));
        }
        // exact position coverage 0..len-1
        verified.sort_by_key(|(p, _)| *p);
        let positions: Vec<u64> = verified.iter().map(|(p, _)| *p).collect();
        for (i, expected) in (0..path.len() as u64).enumerate() {
            match positions.get(i) {
                Some(actual) if *actual == expected => {}
                _ => {
                    return Err(RouteError::PositionsNotCovered {
                        expected,
                        found: positions.clone(),
                    })
                }
            }
        }
        // Merkle root over acceptance bytes ordered by position
        let leaves: Vec<[u8; 32]> = verified
            .iter()
            .map(|(_, env)| {
                let mut l = [0u8; 32];
                l.copy_from_slice(&Sha256::digest(env.bytes()));
                l
            })
            .collect();
        let commitment_root = merkle_root(&leaves).ok_or(RouteError::PathEmpty)?;
        let route_id = derive_route_id(&commitment_root);
        let _ = &mut by_position;
        Ok(RouteCommitment {
            proposal_envelope,
            acceptance_envelopes: verified.into_iter().map(|(_, e)| e).collect(),
            commitment_root,
            route_id,
        })
    }

    /// Full re-verification of a received commitment (fail-closed): the
    /// same checks as `build`, plus root + route_id re-derivation.
    pub fn verify(&self, now_unix: u64) -> Result<VerifiedRoute, RouteError> {
        let rebuilt = RouteCommitment::build(
            now_unix,
            self.proposal_envelope.clone(),
            self.acceptance_envelopes.clone(),
        )?;
        if rebuilt.commitment_root != self.commitment_root {
            return Err(RouteError::CommitmentRootMismatch);
        }
        if rebuilt.route_id != self.route_id {
            return Err(RouteError::RouteIdMismatch);
        }
        let proposal =
            RouteProposal::from_wire_bytes(self.proposal_envelope.bytes())?;
        Ok(VerifiedRoute {
            route_id: self.route_id,
            commitment_root: self.commitment_root,
            proposal,
        })
    }

    pub fn to_wire(&self) -> Value {
        Value::Map(vec![
            (Value::Int(1), Value::Int(ROUTE_SCHEME_VERSION)),
            (
                Value::Int(2),
                Value::Bytes(self.proposal_envelope.to_envelope_bytes()),
            ),
            (
                Value::Int(3),
                Value::Array(
                    self.acceptance_envelopes
                        .iter()
                        .map(|e| Value::Bytes(e.to_envelope_bytes()))
                        .collect(),
                ),
            ),
            (Value::Int(4), Value::Bytes(self.commitment_root.to_vec())),
            (Value::Int(5), Value::Bytes(self.route_id.to_vec())),
        ])
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, RouteError> {
        let v = decode(bytes).map_err(RouteError::Cbor)?;
        Self::from_wire(&v)
    }

    pub fn from_wire(v: &Value) -> Result<Self, RouteError> {
        let Value::Map(entries) = v else {
            return Err(RouteError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut proposal_env: Option<SignedEnvelope> = None;
        let mut acceptance_envs: Option<Vec<SignedEnvelope>> = None;
        let mut root: Option<[u8; 32]> = None;
        let mut route_id: Option<[u8; 32]> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(RouteError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(RouteError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != ROUTE_SCHEME_VERSION {
                        return Err(RouteError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if proposal_env.is_some() {
                        return Err(RouteError::DuplicateField { key: 2 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 2 });
                    };
                    proposal_env = Some(SignedEnvelope::from_envelope_bytes(b)?);
                }
                3 => {
                    if acceptance_envs.is_some() {
                        return Err(RouteError::DuplicateField { key: 3 });
                    }
                    let Value::Array(items) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 3 });
                    };
                    let mut out = Vec::with_capacity(items.len());
                    for item in items {
                        let Value::Bytes(b) = item else {
                            return Err(RouteError::FieldNotExpectedType { key: 3 });
                        };
                        out.push(SignedEnvelope::from_envelope_bytes(b)?);
                    }
                    acceptance_envs = Some(out);
                }
                4 => {
                    if root.is_some() {
                        return Err(RouteError::DuplicateField { key: 4 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 4 });
                    };
                    if b.len() != 32 {
                        return Err(RouteError::RootWrongLength { len: b.len() });
                    }
                    root = Some(b.as_slice().try_into().expect("checked"));
                }
                5 => {
                    if route_id.is_some() {
                        return Err(RouteError::DuplicateField { key: 5 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(RouteError::FieldNotExpectedType { key: 5 });
                    };
                    if b.len() != 32 {
                        return Err(RouteError::RouteIdWrongLength { len: b.len() });
                    }
                    route_id = Some(b.as_slice().try_into().expect("checked"));
                }
                other => return Err(RouteError::UnknownField { key: other }),
            }
        }
        let proposal_env = proposal_env.ok_or(RouteError::MissingField { key: 2 })?;
        let acceptance_envs =
            acceptance_envs.ok_or(RouteError::MissingField { key: 3 })?;
        let root = root.ok_or(RouteError::MissingField { key: 4 })?;
        let route_id = route_id.ok_or(RouteError::MissingField { key: 5 })?;
        Ok(RouteCommitment {
            proposal_envelope: proposal_env,
            acceptance_envelopes: acceptance_envs,
            commitment_root: root,
            route_id,
        })
    }

    /// Re-assemble from parts (vectors/tests: construct tampered
    /// commitments that verification must reject).
    pub fn from_parts(
        proposal_envelope: SignedEnvelope,
        acceptance_envelopes: Vec<SignedEnvelope>,
        commitment_root: [u8; 32],
        route_id: [u8; 32],
    ) -> Self {
        RouteCommitment {
            proposal_envelope,
            acceptance_envelopes,
            commitment_root,
            route_id,
        }
    }

    pub fn commitment_root(&self) -> &[u8; 32] {
        &self.commitment_root
    }

    pub fn route_id(&self) -> &[u8; 32] {
        &self.route_id
    }

    pub fn proposal_envelope(&self) -> &SignedEnvelope {
        &self.proposal_envelope
    }

    pub fn acceptance_envelopes(&self) -> &[SignedEnvelope] {
        &self.acceptance_envelopes
    }
}

/// The result of verifying a commitment: the derived identity of a route.
#[derive(Debug, Clone)]
pub struct VerifiedRoute {
    pub route_id: [u8; 32],
    pub commitment_root: [u8; 32],
    pub proposal: RouteProposal,
}

fn verify_proposal_envelope(
    env: &SignedEnvelope,
    now_unix: u64,
) -> Result<RouteProposal, RouteError> {
    let proposal = RouteProposal::from_wire_bytes(env.bytes())?;
    proposal
        .proposer_identity()
        .verify_detached(env.bytes(), env.signature())
        .map_err(|_| RouteError::ProposalSignatureInvalid)?;
    if now_unix < proposal.proposed_at_unix() {
        return Err(RouteError::ProposalNotYetValid {
            now: now_unix,
            proposed_at: proposal.proposed_at_unix(),
        });
    }
    if now_unix >= proposal.expires_at_unix() {
        return Err(RouteError::ProposalExpired {
            now: now_unix,
            expires_at: proposal.expires_at_unix(),
        });
    }
    Ok(proposal)
}

/// Typed route errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteError {
    NotAMap,
    KeyNotAnInteger,
    FieldNotExpectedType { key: i64 },
    DuplicateField { key: i64 },
    UnknownField { key: i64 },
    MissingField { key: i64 },
    SchemeVersionUnsupported { found: i64 },
    Identity(crate::identity::IdentityError),
    Cbor(crate::cbor::DecodeError),
    PathEmpty,
    PathTooLong { len: usize, max: usize },
    PathMalformed,
    PathUnsorted { at: usize },
    PathDuplicate,
    ServiceClassUnknown { found: String },
    TimestampNegative { field: &'static str },
    TimestampOutOfRange,
    ExpiryNotAfterIssue { issued_at: u64, expires_at: u64 },
    WindowInvalid { validity: u64, max: u64 },
    NonceWrongLength { len: usize },
    ProposalIdWrongLength { len: usize },
    RootWrongLength { len: usize },
    RouteIdWrongLength { len: usize },
    PositionNegative { found: i64 },
    SignatureWrongLength { len: usize },
    EnvelopeWrongEntryCount { count: usize },
    SignerMismatch { object: String, signer: String },
    ProposalSignatureInvalid,
    ProposalNotYetValid { now: u64, proposed_at: u64 },
    ProposalExpired { now: u64, expires_at: u64 },
    AcceptanceSignatureInvalid { position: u64 },
    AcceptanceNotYetValid { position: u64 },
    AcceptanceExpired { position: u64 },
    AcceptanceWrongProposal,
    AcceptancePositionOutOfRange { position: u64, path_len: usize },
    AcceptanceIdentityMismatch { position: u64 },
    PositionsNotCovered { expected: u64, found: Vec<u64> },
    CommitmentRootMismatch,
    RouteIdMismatch,
}

impl RouteError {
    pub fn name(&self) -> String {
        match self {
            RouteError::NotAMap => "not_a_map",
            RouteError::KeyNotAnInteger => "key_not_an_integer",
            RouteError::FieldNotExpectedType { .. } => "field_not_expected_type",
            RouteError::DuplicateField { .. } => "duplicate_field",
            RouteError::UnknownField { .. } => "unknown_field",
            RouteError::MissingField { .. } => "missing_field",
            RouteError::SchemeVersionUnsupported { .. } => "scheme_version_unsupported",
            RouteError::Identity(e) => return format!("identity:{}", e.name()),
            RouteError::Cbor(e) => return format!("cbor:{}", e.name()),
            RouteError::PathEmpty => "path_empty",
            RouteError::PathTooLong { .. } => "path_too_long",
            RouteError::PathMalformed => "path_malformed",
            RouteError::PathUnsorted { .. } => "path_unsorted",
            RouteError::PathDuplicate => "path_duplicate",
            RouteError::ServiceClassUnknown { .. } => "service_class_unknown",
            RouteError::TimestampNegative { .. } => "timestamp_negative",
            RouteError::TimestampOutOfRange => "timestamp_out_of_range",
            RouteError::ExpiryNotAfterIssue { .. } => "expiry_not_after_issue",
            RouteError::WindowInvalid { .. } => "window_invalid",
            RouteError::NonceWrongLength { .. } => "nonce_wrong_length",
            RouteError::ProposalIdWrongLength { .. } => "proposal_id_wrong_length",
            RouteError::RootWrongLength { .. } => "root_wrong_length",
            RouteError::RouteIdWrongLength { .. } => "route_id_wrong_length",
            RouteError::PositionNegative { .. } => "position_negative",
            RouteError::SignatureWrongLength { .. } => "signature_wrong_length",
            RouteError::EnvelopeWrongEntryCount { .. } => "envelope_wrong_entry_count",
            RouteError::SignerMismatch { .. } => "signer_mismatch",
            RouteError::ProposalSignatureInvalid => "proposal_signature_invalid",
            RouteError::ProposalNotYetValid { .. } => "proposal_not_yet_valid",
            RouteError::ProposalExpired { .. } => "proposal_expired",
            RouteError::AcceptanceSignatureInvalid { .. } => "acceptance_signature_invalid",
            RouteError::AcceptanceNotYetValid { .. } => "acceptance_not_yet_valid",
            RouteError::AcceptanceExpired { .. } => "acceptance_expired",
            RouteError::AcceptanceWrongProposal => "acceptance_wrong_proposal",
            RouteError::AcceptancePositionOutOfRange { .. } => {
                "acceptance_position_out_of_range"
            }
            RouteError::AcceptanceIdentityMismatch { .. } => "acceptance_identity_mismatch",
            RouteError::PositionsNotCovered { .. } => "positions_not_covered",
            RouteError::CommitmentRootMismatch => "commitment_root_mismatch",
            RouteError::RouteIdMismatch => "route_id_mismatch",
        }
        .to_string()
    }
}

impl fmt::Display for RouteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "route error: {}", self.name())
    }
}

impl std::error::Error for RouteError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u8) -> Identity {
        Identity::from_seed([seed; 32], 1_700_000_000, None).expect("identity")
    }

    /// Build a proposal whose path = proposer + hops (CANONICALLY SORTED),
    /// and remember the sorted participant list for acceptances.
    fn participants(proposer: &Identity, hops: &[Identity]) -> Vec<Identity> {
        let mut all: Vec<Identity> = hops.to_vec();
        all.push(proposer.clone());
        all.sort_by_key(|i| *i.node_id().as_bytes());
        all
    }

    fn proposal_with_hops(proposer: &Identity, hops: &[Identity], nonce: [u8; 32]) -> SignedEnvelope {
        let path: Vec<[u8; 32]> = participants(proposer, hops)
            .iter()
            .map(|h| *h.node_id().as_bytes())
            .collect();
        let p = RouteProposal::new(proposer, path, "live", 1_000, 600, nonce).unwrap();
        p.sign(proposer).unwrap()
    }

    /// Acceptances for EVERY path position (the proposer included — every
    /// path member commits), positions aligned with the sorted path.
    fn acceptances_for(
        proposal_env: &SignedEnvelope,
        proposer: &Identity,
        hops: &[Identity],
        at: u64,
    ) -> Vec<SignedEnvelope> {
        let proposal_id = derive_proposal_id(proposal_env.bytes());
        participants(proposer, hops)
            .iter()
            .enumerate()
            .map(|(i, member)| {
                let a = RouteAcceptance::new(member, proposal_id, i as u64, at, 120).unwrap();
                a.sign(member).unwrap()
            })
            .collect()
    }

    #[test]
    fn full_route_commitment_lifecycle() {
        let proposer = identity(1);
        let hops = [identity(2), identity(3)];
        let env = proposal_with_hops(&proposer, &hops, [0x11; 32]);
        let acceptances = acceptances_for(&env, &proposer, &hops, 1_001);
        let commitment = RouteCommitment::build(1_100, env.clone(), acceptances).unwrap();
        let verified = commitment.verify(1_100).unwrap();
        assert_eq!(verified.route_id, *commitment.route_id());
        assert_eq!(verified.proposal.path().len(), 3);
        // byte-stability
        let bytes = commitment.to_wire_bytes();
        let back = RouteCommitment::from_wire_bytes(&bytes).unwrap();
        assert_eq!(back, commitment);
    }

    #[test]
    fn caller_selected_route_id_rejected_by_re_derivation() {
        let proposer = identity(4);
        let hops = [identity(5)];
        let env = proposal_with_hops(&proposer, &hops, [0x22; 32]);
        let acceptances = acceptances_for(&env, &proposer, &hops, 1_001);
        let mut commitment = RouteCommitment::build(1_100, env, acceptances).unwrap();
        // tamper the route_id (caller-selected): verification must fail
        commitment.route_id = [0xEE; 32];
        assert!(matches!(
            commitment.verify(1_100),
            Err(RouteError::RouteIdMismatch)
        ));
    }

    #[test]
    fn missing_acceptance_rejected() {
        let proposer = identity(6);
        let hops = [identity(7), identity(8)];
        let env = proposal_with_hops(&proposer, &hops, [0x33; 32]);
        let mut acceptances = acceptances_for(&env, &proposer, &hops, 1_001);
        acceptances.pop(); // drop position 1
        assert!(matches!(
            RouteCommitment::build(1_100, env, acceptances),
            Err(RouteError::PositionsNotCovered { .. })
        ));
    }

    #[test]
    fn acceptance_by_non_path_identity_rejected() {
        let proposer = identity(9);
        let hops = [identity(10)];
        let env = proposal_with_hops(&proposer, &hops, [0x44; 32]);
        let proposal_id = derive_proposal_id(env.bytes());
        let outsider = identity(11);
        let a = RouteAcceptance::new(&outsider, proposal_id, 0, 1_001, 600).unwrap();
        let signed = a.sign(&outsider).unwrap();
        assert!(matches!(
            RouteCommitment::build(1_100, env, vec![signed]),
            Err(RouteError::AcceptanceIdentityMismatch { position: 0 })
        ));
    }

    #[test]
    fn replacement_route_has_fresh_route_id() {
        let proposer = identity(12);
        let hops = [identity(13)];
        let env1 = proposal_with_hops(&proposer, &hops, [0x55; 32]);
        let env2 = proposal_with_hops(&proposer, &hops, [0x66; 32]); // fresh nonce
        let c1 = RouteCommitment::build(1_100, env1.clone(), acceptances_for(&env1, &proposer, &hops, 1_001))
            .unwrap();
        let c2 = RouteCommitment::build(1_100, env2.clone(), acceptances_for(&env2, &proposer, &hops, 1_002))
            .unwrap();
        assert_ne!(c1.route_id(), c2.route_id());
        assert_ne!(c1.commitment_root(), c2.commitment_root());
    }

    #[test]
    fn expired_acceptance_rejected() {
        let proposer = identity(14);
        let hops = [identity(15)];
        let env = proposal_with_hops(&proposer, &hops, [0x77; 32]);
        let acceptances = acceptances_for(&env, &proposer, &hops, 1_001); // expires 1601
        assert!(matches!(
            RouteCommitment::build(1_121, env, acceptances),
            Err(RouteError::AcceptanceExpired { .. })
        ));
    }

    #[test]
    fn tampered_proposal_rejected() {
        let proposer = identity(16);
        let hops = [identity(17)];
        let env = proposal_with_hops(&proposer, &hops, [0x88; 32]);
        let mut tampered = env.bytes().to_vec();
        let pos = tampered.windows(4).position(|w| w == b"live").expect("class");
        tampered[pos] = b'L';
        let bad = SignedEnvelope::new(tampered, *env.signature());
        assert!(RouteCommitment::build(1_100, bad, vec![]).is_err());
    }

    #[test]
    fn merkle_root_matches_reference_shape() {
        // leaves: [A] -> H(A||A); [A,B] -> H(A||B); [A,B,C] -> H(H(A||B)||H(C||C))
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        assert_eq!(
            merkle_root(&[a]).unwrap(),
            sha256_pair(&a, &a)
        );
        assert_eq!(
            merkle_root(&[a, b]).unwrap(),
            sha256_pair(&a, &b)
        );
        assert_eq!(
            merkle_root(&[a, b, c]).unwrap(),
            sha256_pair(&sha256_pair(&a, &b), &sha256_pair(&c, &c))
        );
        assert!(merkle_root(&[]).is_none());
    }
}
