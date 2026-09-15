//! Route-to-circuit binding (work item R4-002).
//!
//! A circuit is the live session bound to a committed route:
//!
//! ```text
//! RouteCommitment (verified per R3-004: route_id is commitment-derived)
//!     + a fresh setup_nonce from the circuit initiator
//!     ↓ SHA-256("sharenet-circuit-id-v1" || route_id || setup_nonce)
//! circuit_id        (caller-selected circuit IDs are FORBIDDEN — L013
//!                    discipline through the commitment-derived route_id)
//!     + one signed CircuitSetupAck per path position
//!     ↓ exact position coverage (the R3-004 rule mirrored)
//! ESTABLISHED circuit
//!     ↓ CircuitFrames (per-direction strictly monotonic seq from 0)
//! the circuit's replay namespace (L014)
//!     ↓ CircuitDestroy (any path member, terminal forever)
//! ```
//!
//! Every replacement circuit is genuinely new: a fresh nonce produces a
//! fresh circuit_id and fresh replay namespaces (L014). A destroyed
//! circuit is never resurrected (§11 recovery builds a NEW circuit over
//! a fresh setup).
//!
//! Integrity model (per architecture §9 relay privacy and ADR-002
//! standards-first): circuit frames are NOT individually signed or
//! MACed — hop-by-hop integrity comes from the carrying layers (R3-001
//! authenticated link AEAD frames, R4-001 node-pinned QUIC/TLS 1.3
//! tunnels) and end-to-end payload integrity is the content layer's
//! job (R6 content addressing). The frame wire object carries binding
//! and ordering only.
//!
//! Persistence: none — the [`CircuitRegistry`] is runtime verification
//! state; durable circuit state is R4-003/R4-004/R7 scope (the gateway
//! and VPN data planes, and durable invalidation).

use core::fmt;
use std::collections::{HashMap, HashSet};

use sha2::{Digest, Sha256};

use crate::cbor::{decode, encode, Value};
use crate::identity::{Identity, NodeIdentity};
use crate::route::{RouteCommitment, RouteError, SignedEnvelope};

/// Scheme version of the circuit wire objects (v1).
pub const CIRCUIT_SCHEME_VERSION: i64 = 1;
/// Maximum setup/ack freshness window (seconds).
pub const CIRCUIT_MAX_WINDOW: u64 = 3600;
/// Maximum circuit frame payload (2 MiB — mirrors the R4-001 tunnel
/// frame bound).
pub const CIRCUIT_MAX_PAYLOAD: usize = 2 * 1024 * 1024;
/// Maximum path length (mirrors the route bound).
pub const CIRCUIT_MAX_PATH: usize = 16;

const CIRCUIT_ID_CONTEXT: &[u8] = b"sharenet-circuit-id-v1";
/// Frame directions: 1 = initiator → exit, 2 = exit → initiator.
pub const DIRECTION_INITIATOR_TO_EXIT: u64 = 1;
pub const DIRECTION_EXIT_TO_INITIATOR: u64 = 2;
/// Frozen v1 destroy reasons (§11 recovery vocabulary).
pub const DESTROY_REASONS: [&str; 4] = ["link_failure", "policy", "completed", "replaced"];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed errors of the circuit layer (stable machine names for the
/// cross-language conformance suite).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitError {
    Cbor(String),
    NotAMap,
    KeyNotAnInteger,
    DuplicateField { key: i64 },
    MissingField { key: i64 },
    FieldNotExpectedType { key: i64 },
    UnknownField { key: i64 },
    SchemeVersionUnsupported { found: i64 },
    RouteError(RouteError),
    NonceWrongLength { len: usize },
    CircuitIdWrongLength { len: usize },
    DigestWrongLength { len: usize },
    WindowInvalid { validity: u64, max: u64 },
    TimestampOutOfRange,
    PositionOutOfRange { position: u64, path_len: usize },
    ReasonUnknown { found: String },
    DirectionUnknown { found: u64 },
    PayloadEmpty,
    PayloadTooLarge { len: usize, max: usize },
    SetupSignatureInvalid,
    AckSignatureInvalid,
    DestroySignatureInvalid,
    SetupNotYetValid,
    SetupExpired,
    SetupWindowExceeded,
    InitiatorNotProposer,
    AckNotYetValid,
    AckExpired,
    AckOutlivesSetup,
    SetupNonceReused,
    CircuitUnknown,
    CircuitDestroyed,
    CircuitNotEstablished { unacked: Vec<u64> },
    SetupDigestMismatch,
    AckPositionAlreadyTaken { position: u64 },
    AckIdentityMismatch { position: u64 },
    FrameSeqOutOfOrder { direction: u64, expected: u64, found: u64 },
    DestroySenderNotOnPath,
}

impl fmt::Display for CircuitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitError::Cbor(e) => write!(f, "cbor: {e}"),
            CircuitError::NotAMap => write!(f, "not a map"),
            CircuitError::KeyNotAnInteger => write!(f, "map key not an integer"),
            CircuitError::DuplicateField { key } => write!(f, "duplicate field {key}"),
            CircuitError::MissingField { key } => write!(f, "missing field {key}"),
            CircuitError::FieldNotExpectedType { key } => {
                write!(f, "field {key} not of expected type")
            }
            CircuitError::UnknownField { key } => write!(f, "unknown field {key}"),
            CircuitError::SchemeVersionUnsupported { found } => {
                write!(f, "scheme version {found} unsupported")
            }
            CircuitError::RouteError(e) => write!(f, "route: {e}"),
            CircuitError::NonceWrongLength { len } => {
                write!(f, "setup nonce must be 32 bytes, found {len}")
            }
            CircuitError::CircuitIdWrongLength { len } => {
                write!(f, "circuit id must be 32 bytes, found {len}")
            }
            CircuitError::DigestWrongLength { len } => {
                write!(f, "setup digest must be 32 bytes, found {len}")
            }
            CircuitError::WindowInvalid { validity, max } => {
                write!(f, "validity window {validity} invalid (max {max})")
            }
            CircuitError::TimestampOutOfRange => write!(f, "timestamp out of range"),
            CircuitError::PositionOutOfRange { position, path_len } => {
                write!(f, "position {position} out of range (path len {path_len})")
            }
            CircuitError::ReasonUnknown { found } => write!(f, "destroy reason {found:?} unknown"),
            CircuitError::DirectionUnknown { found } => write!(f, "direction {found} unknown"),
            CircuitError::PayloadEmpty => write!(f, "frame payload must be non-empty"),
            CircuitError::PayloadTooLarge { len, max } => {
                write!(f, "payload of {len} bytes exceeds the {max}-byte limit")
            }
            CircuitError::SetupSignatureInvalid => write!(f, "setup signature invalid"),
            CircuitError::AckSignatureInvalid => write!(f, "ack signature invalid"),
            CircuitError::DestroySignatureInvalid => write!(f, "destroy signature invalid"),
            CircuitError::SetupNotYetValid => write!(f, "setup issued in the future"),
            CircuitError::SetupExpired => write!(f, "setup expired"),
            CircuitError::SetupWindowExceeded => write!(f, "setup window exceeds the maximum"),
            CircuitError::InitiatorNotProposer => {
                write!(f, "setup initiator is not the route proposer")
            }
            CircuitError::AckNotYetValid => write!(f, "ack accepted in the future"),
            CircuitError::AckExpired => write!(f, "ack expired"),
            CircuitError::AckOutlivesSetup => write!(f, "ack accepted after the setup expired"),
            CircuitError::SetupNonceReused => {
                write!(f, "setup nonce already used for this route (replacement needs a fresh nonce)")
            }
            CircuitError::CircuitUnknown => write!(f, "circuit unknown"),
            CircuitError::CircuitDestroyed => write!(f, "circuit destroyed (terminal)"),
            CircuitError::CircuitNotEstablished { unacked } => {
                write!(f, "circuit not established (unacked positions {unacked:?})")
            }
            CircuitError::SetupDigestMismatch => write!(f, "ack setup digest mismatch"),
            CircuitError::AckPositionAlreadyTaken { position } => {
                write!(f, "position {position} already acknowledged")
            }
            CircuitError::AckIdentityMismatch { position } => {
                write!(f, "ack identity does not match path[{position}]")
            }
            CircuitError::FrameSeqOutOfOrder {
                direction,
                expected,
                found,
            } => write!(
                f,
                "frame seq out of order (direction {direction}): expected {expected}, found {found}"
            ),
            CircuitError::DestroySenderNotOnPath => {
                write!(f, "destroy sender is not on the committed path")
            }
        }
    }
}

impl std::error::Error for CircuitError {}

impl CircuitError {
    /// Stable machine name (consumed by the cross-language suite).
    pub fn name(&self) -> &'static str {
        match self {
            CircuitError::Cbor(_) => "cbor",
            CircuitError::NotAMap => "not_a_map",
            CircuitError::KeyNotAnInteger => "key_not_an_integer",
            CircuitError::DuplicateField { .. } => "duplicate_field",
            CircuitError::MissingField { .. } => "missing_field",
            CircuitError::FieldNotExpectedType { .. } => "field_not_expected_type",
            CircuitError::UnknownField { .. } => "unknown_field",
            CircuitError::SchemeVersionUnsupported { .. } => "scheme_version_unsupported",
            CircuitError::RouteError(_) => "route_error",
            CircuitError::NonceWrongLength { .. } => "nonce_wrong_length",
            CircuitError::CircuitIdWrongLength { .. } => "circuit_id_wrong_length",
            CircuitError::DigestWrongLength { .. } => "digest_wrong_length",
            CircuitError::WindowInvalid { .. } => "window_invalid",
            CircuitError::TimestampOutOfRange => "timestamp_out_of_range",
            CircuitError::PositionOutOfRange { .. } => "position_out_of_range",
            CircuitError::ReasonUnknown { .. } => "reason_unknown",
            CircuitError::DirectionUnknown { .. } => "direction_unknown",
            CircuitError::PayloadEmpty => "payload_empty",
            CircuitError::PayloadTooLarge { .. } => "payload_too_large",
            CircuitError::SetupSignatureInvalid => "setup_signature_invalid",
            CircuitError::AckSignatureInvalid => "ack_signature_invalid",
            CircuitError::DestroySignatureInvalid => "destroy_signature_invalid",
            CircuitError::SetupNotYetValid => "setup_not_yet_valid",
            CircuitError::SetupExpired => "setup_expired",
            CircuitError::SetupWindowExceeded => "setup_window_exceeded",
            CircuitError::InitiatorNotProposer => "initiator_not_proposer",
            CircuitError::AckNotYetValid => "ack_not_yet_valid",
            CircuitError::AckExpired => "ack_expired",
            CircuitError::AckOutlivesSetup => "ack_outlives_setup",
            CircuitError::SetupNonceReused => "setup_nonce_reused",
            CircuitError::CircuitUnknown => "circuit_unknown",
            CircuitError::CircuitDestroyed => "circuit_destroyed",
            CircuitError::CircuitNotEstablished { .. } => "circuit_not_established",
            CircuitError::SetupDigestMismatch => "setup_digest_mismatch",
            CircuitError::AckPositionAlreadyTaken { .. } => "ack_position_already_taken",
            CircuitError::AckIdentityMismatch { .. } => "ack_identity_mismatch",
            CircuitError::FrameSeqOutOfOrder { .. } => "frame_seq_out_of_order",
            CircuitError::DestroySenderNotOnPath => "destroy_sender_not_on_path",
        }
    }
}

impl From<RouteError> for CircuitError {
    fn from(e: RouteError) -> Self {
        CircuitError::RouteError(e)
    }
}

// ---------------------------------------------------------------------------
// circuit_id derivation
// ---------------------------------------------------------------------------

/// Derive the circuit id from a VERIFIED route id and the setup nonce.
///
/// circuit_id = SHA-256("sharenet-circuit-id-v1" || route_id ||
/// setup_nonce) — commitment-derived through the route_id (L013
/// discipline) and fresh per nonce (L014 fresh session identity).
pub fn derive_circuit_id(route_id: &[u8; 32], setup_nonce: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CIRCUIT_ID_CONTEXT);
    hasher.update(route_id);
    hasher.update(setup_nonce);
    let mut id = [0u8; 32];
    id.copy_from_slice(&hasher.finalize());
    id
}

/// SHA-256 of the canonical setup bytes (the ack binding digest).
pub fn setup_digest(setup_bytes: &[u8]) -> [u8; 32] {
    let mut d = [0u8; 32];
    d.copy_from_slice(&Sha256::digest(setup_bytes));
    d
}

// ---------------------------------------------------------------------------
// CircuitSetup
// ---------------------------------------------------------------------------

/// A parsed (not yet verified) circuit setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitSetup {
    route_commitment_bytes: Vec<u8>,
    setup_nonce: [u8; 32],
    initiator: NodeIdentity,
    issued_at_unix: u64,
    expires_at_unix: u64,
}

impl CircuitSetup {
    /// Build a setup over an ALREADY-BUILT (verified-at-build)
    /// [`RouteCommitment`]. The initiator must be the route's proposer
    /// — circuit authority binds to route authority (fail-closed at
    /// construction and again at admission).
    pub fn new(
        commitment: &RouteCommitment,
        initiator: &Identity,
        setup_nonce: [u8; 32],
        issued_at_unix: u64,
        validity_secs: u64,
    ) -> Result<Self, CircuitError> {
        if validity_secs == 0 || validity_secs > CIRCUIT_MAX_WINDOW {
            return Err(CircuitError::WindowInvalid {
                validity: validity_secs,
                max: CIRCUIT_MAX_WINDOW,
            });
        }
        // The initiator must be the proposer of the committed route.
        let proposal = crate::route::RouteProposal::from_wire_bytes(
            commitment.proposal_envelope().bytes(),
        )?;
        if proposal.proposer_identity().node_id() != initiator.node_identity().node_id() {
            return Err(CircuitError::InitiatorNotProposer);
        }
        let expires_at_unix = issued_at_unix
            .checked_add(validity_secs)
            .filter(|e| *e <= i64::MAX as u64)
            .ok_or(CircuitError::TimestampOutOfRange)?;
        Ok(CircuitSetup {
            route_commitment_bytes: commitment.to_wire_bytes(),
            setup_nonce,
            initiator: initiator.node_identity().clone(),
            issued_at_unix,
            expires_at_unix,
        })
    }

    /// The circuit id this setup derives once the embedded commitment
    /// is verified (callers must verify the commitment — this helper
    /// re-parses it strictly to extract the route id).
    pub fn circuit_id(&self) -> Result<[u8; 32], CircuitError> {
        let commitment = RouteCommitment::from_wire_bytes(&self.route_commitment_bytes)?;
        Ok(derive_circuit_id(commitment.route_id(), &self.setup_nonce))
    }

    /// Sign this setup with the initiator's key.
    pub fn sign(&self, initiator: &Identity) -> Result<SignedEnvelope, CircuitError> {
        let bytes = self.to_wire_bytes();
        let signature = initiator.sign_detached(&bytes);
        Ok(SignedEnvelope::new(bytes, signature))
    }

    pub fn to_wire(&self) -> Value {
        Value::Map(vec![
            (Value::Int(1), Value::Int(CIRCUIT_SCHEME_VERSION)),
            (
                Value::Int(2),
                Value::Bytes(self.route_commitment_bytes.clone()),
            ),
            (Value::Int(3), Value::Bytes(self.setup_nonce.to_vec())),
            (Value::Int(4), self.initiator.to_wire()),
            (Value::Int(5), Value::Int(self.issued_at_unix as i64)),
            (Value::Int(6), Value::Int(self.expires_at_unix as i64)),
        ])
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, CircuitError> {
        let v = decode(bytes).map_err(|e| CircuitError::Cbor(e.to_string()))?;
        Self::from_wire(&v)
    }

    pub fn from_wire(v: &Value) -> Result<Self, CircuitError> {
        let Value::Map(entries) = v else {
            return Err(CircuitError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut commitment_bytes: Option<Vec<u8>> = None;
        let mut nonce: Option<[u8; 32]> = None;
        let mut initiator: Option<NodeIdentity> = None;
        let mut issued: Option<u64> = None;
        let mut expires: Option<u64> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(CircuitError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(CircuitError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != CIRCUIT_SCHEME_VERSION {
                        return Err(CircuitError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if commitment_bytes.is_some() {
                        return Err(CircuitError::DuplicateField { key: 2 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 2 });
                    };
                    // The embedded commitment must at least parse.
                    RouteCommitment::from_wire_bytes(b)?;
                    commitment_bytes = Some(b.clone());
                }
                3 => {
                    if nonce.is_some() {
                        return Err(CircuitError::DuplicateField { key: 3 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 3 });
                    };
                    if b.len() != 32 {
                        return Err(CircuitError::NonceWrongLength { len: b.len() });
                    }
                    nonce = Some(b.as_slice().try_into().expect("checked"));
                }
                4 => {
                    if initiator.is_some() {
                        return Err(CircuitError::DuplicateField { key: 4 });
                    }
                    initiator = Some(
                        NodeIdentity::from_wire(val)
                            .map_err(|e| CircuitError::Cbor(e.to_string()))?,
                    );
                }
                5 => {
                    if issued.is_some() {
                        return Err(CircuitError::DuplicateField { key: 5 });
                    }
                    let Value::Int(t) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 5 });
                    };
                    let t = u64::try_from(*t).map_err(|_| CircuitError::TimestampOutOfRange)?;
                    issued = Some(t);
                }
                6 => {
                    if expires.is_some() {
                        return Err(CircuitError::DuplicateField { key: 6 });
                    }
                    let Value::Int(t) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 6 });
                    };
                    let t = u64::try_from(*t).map_err(|_| CircuitError::TimestampOutOfRange)?;
                    expires = Some(t);
                }
                other => return Err(CircuitError::UnknownField { key: other }),
            }
        }
        let commitment_bytes =
            commitment_bytes.ok_or(CircuitError::MissingField { key: 2 })?;
        let nonce = nonce.ok_or(CircuitError::MissingField { key: 3 })?;
        let initiator = initiator.ok_or(CircuitError::MissingField { key: 4 })?;
        let issued = issued.ok_or(CircuitError::MissingField { key: 5 })?;
        let expires = expires.ok_or(CircuitError::MissingField { key: 6 })?;
        if expires <= issued {
            return Err(CircuitError::WindowInvalid {
                validity: expires - issued,
                max: CIRCUIT_MAX_WINDOW,
            });
        }
        if expires - issued > CIRCUIT_MAX_WINDOW {
            return Err(CircuitError::SetupWindowExceeded);
        }
        Ok(CircuitSetup {
            route_commitment_bytes: commitment_bytes,
            setup_nonce: nonce,
            initiator,
            issued_at_unix: issued,
            expires_at_unix: expires,
        })
    }

    pub fn route_commitment_bytes(&self) -> &[u8] {
        &self.route_commitment_bytes
    }
    pub fn setup_nonce(&self) -> &[u8; 32] {
        &self.setup_nonce
    }
    pub fn initiator_identity(&self) -> &NodeIdentity {
        &self.initiator
    }
    pub fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }
}

// ---------------------------------------------------------------------------
// CircuitSetupAck
// ---------------------------------------------------------------------------

/// A parsed (not yet verified) per-hop circuit setup acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitSetupAck {
    circuit_id: [u8; 32],
    setup_digest: [u8; 32],
    accepting: NodeIdentity,
    position: u64,
    accepted_at_unix: u64,
    expires_at_unix: u64,
}

impl CircuitSetupAck {
    /// Build an ack for `position` over the signed setup envelope
    /// (the digest binds the ack to the exact setup bytes). The
    /// accepting hop's identity must be path[position] — checked at
    /// admission against the VERIFIED route.
    pub fn new(
        circuit_id: [u8; 32],
        setup_envelope: &SignedEnvelope,
        accepting: &Identity,
        position: u64,
        accepted_at_unix: u64,
        validity_secs: u64,
    ) -> Result<Self, CircuitError> {
        if validity_secs == 0 || validity_secs > CIRCUIT_MAX_WINDOW {
            return Err(CircuitError::WindowInvalid {
                validity: validity_secs,
                max: CIRCUIT_MAX_WINDOW,
            });
        }
        let expires_at_unix = accepted_at_unix
            .checked_add(validity_secs)
            .filter(|e| *e <= i64::MAX as u64)
            .ok_or(CircuitError::TimestampOutOfRange)?;
        Ok(CircuitSetupAck {
            circuit_id,
            setup_digest: setup_digest(setup_envelope.bytes()),
            accepting: accepting.node_identity().clone(),
            position,
            accepted_at_unix,
            expires_at_unix,
        })
    }

    /// Sign this ack with the accepting hop's key.
    pub fn sign(&self, accepting: &Identity) -> Result<SignedEnvelope, CircuitError> {
        let bytes = self.to_wire_bytes();
        let signature = accepting.sign_detached(&bytes);
        Ok(SignedEnvelope::new(bytes, signature))
    }

    pub fn to_wire(&self) -> Value {
        Value::Map(vec![
            (Value::Int(1), Value::Int(CIRCUIT_SCHEME_VERSION)),
            (Value::Int(2), Value::Bytes(self.circuit_id.to_vec())),
            (Value::Int(3), Value::Bytes(self.setup_digest.to_vec())),
            (Value::Int(4), self.accepting.to_wire()),
            (Value::Int(5), Value::Int(self.position as i64)),
            (Value::Int(6), Value::Int(self.accepted_at_unix as i64)),
            (Value::Int(7), Value::Int(self.expires_at_unix as i64)),
        ])
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, CircuitError> {
        let v = decode(bytes).map_err(|e| CircuitError::Cbor(e.to_string()))?;
        Self::from_wire(&v)
    }

    pub fn from_wire(v: &Value) -> Result<Self, CircuitError> {
        let Value::Map(entries) = v else {
            return Err(CircuitError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut circuit_id: Option<[u8; 32]> = None;
        let mut digest: Option<[u8; 32]> = None;
        let mut accepting: Option<NodeIdentity> = None;
        let mut position: Option<u64> = None;
        let mut accepted: Option<u64> = None;
        let mut expires: Option<u64> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(CircuitError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(CircuitError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != CIRCUIT_SCHEME_VERSION {
                        return Err(CircuitError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if circuit_id.is_some() {
                        return Err(CircuitError::DuplicateField { key: 2 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != 32 {
                        return Err(CircuitError::CircuitIdWrongLength { len: b.len() });
                    }
                    circuit_id = Some(b.as_slice().try_into().expect("checked"));
                }
                3 => {
                    if digest.is_some() {
                        return Err(CircuitError::DuplicateField { key: 3 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 3 });
                    };
                    if b.len() != 32 {
                        return Err(CircuitError::DigestWrongLength { len: b.len() });
                    }
                    digest = Some(b.as_slice().try_into().expect("checked"));
                }
                4 => {
                    if accepting.is_some() {
                        return Err(CircuitError::DuplicateField { key: 4 });
                    }
                    accepting = Some(
                        NodeIdentity::from_wire(val)
                            .map_err(|e| CircuitError::Cbor(e.to_string()))?,
                    );
                }
                5 => {
                    if position.is_some() {
                        return Err(CircuitError::DuplicateField { key: 5 });
                    }
                    let Value::Int(p) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 5 });
                    };
                    let p =
                        u64::try_from(*p).map_err(|_| CircuitError::TimestampOutOfRange)?;
                    position = Some(p);
                }
                6 => {
                    if accepted.is_some() {
                        return Err(CircuitError::DuplicateField { key: 6 });
                    }
                    let Value::Int(t) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 6 });
                    };
                    let t = u64::try_from(*t).map_err(|_| CircuitError::TimestampOutOfRange)?;
                    accepted = Some(t);
                }
                7 => {
                    if expires.is_some() {
                        return Err(CircuitError::DuplicateField { key: 7 });
                    }
                    let Value::Int(t) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 7 });
                    };
                    let t = u64::try_from(*t).map_err(|_| CircuitError::TimestampOutOfRange)?;
                    expires = Some(t);
                }
                other => return Err(CircuitError::UnknownField { key: other }),
            }
        }
        let circuit_id = circuit_id.ok_or(CircuitError::MissingField { key: 2 })?;
        let digest = digest.ok_or(CircuitError::MissingField { key: 3 })?;
        let accepting = accepting.ok_or(CircuitError::MissingField { key: 4 })?;
        let position = position.ok_or(CircuitError::MissingField { key: 5 })?;
        let accepted = accepted.ok_or(CircuitError::MissingField { key: 6 })?;
        let expires = expires.ok_or(CircuitError::MissingField { key: 7 })?;
        if expires <= accepted {
            return Err(CircuitError::WindowInvalid {
                validity: expires - accepted,
                max: CIRCUIT_MAX_WINDOW,
            });
        }
        if expires - accepted > CIRCUIT_MAX_WINDOW {
            return Err(CircuitError::SetupWindowExceeded);
        }
        Ok(CircuitSetupAck {
            circuit_id,
            setup_digest: digest,
            accepting,
            position,
            accepted_at_unix: accepted,
            expires_at_unix: expires,
        })
    }

    pub fn circuit_id(&self) -> &[u8; 32] {
        &self.circuit_id
    }
    pub fn setup_digest(&self) -> &[u8; 32] {
        &self.setup_digest
    }
    pub fn accepting_identity(&self) -> &NodeIdentity {
        &self.accepting
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
// CircuitFrame
// ---------------------------------------------------------------------------

/// A circuit data frame: binding + ordering only (see the module docs
/// for the integrity model).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitFrame {
    circuit_id: [u8; 32],
    direction: u64,
    seq: u64,
    payload: Vec<u8>,
}

impl CircuitFrame {
    pub fn new(
        circuit_id: [u8; 32],
        direction: u64,
        seq: u64,
        payload: Vec<u8>,
    ) -> Result<Self, CircuitError> {
        if direction != DIRECTION_INITIATOR_TO_EXIT && direction != DIRECTION_EXIT_TO_INITIATOR {
            return Err(CircuitError::DirectionUnknown { found: direction });
        }
        if payload.is_empty() {
            return Err(CircuitError::PayloadEmpty);
        }
        if payload.len() > CIRCUIT_MAX_PAYLOAD {
            return Err(CircuitError::PayloadTooLarge {
                len: payload.len(),
                max: CIRCUIT_MAX_PAYLOAD,
            });
        }
        Ok(CircuitFrame {
            circuit_id,
            direction,
            seq,
            payload,
        })
    }

    pub fn to_wire(&self) -> Value {
        Value::Map(vec![
            (Value::Int(1), Value::Int(CIRCUIT_SCHEME_VERSION)),
            (Value::Int(2), Value::Bytes(self.circuit_id.to_vec())),
            (Value::Int(3), Value::Int(self.direction as i64)),
            (Value::Int(4), Value::Int(self.seq as i64)),
            (Value::Int(5), Value::Bytes(self.payload.clone())),
        ])
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, CircuitError> {
        let v = decode(bytes).map_err(|e| CircuitError::Cbor(e.to_string()))?;
        Self::from_wire(&v)
    }

    pub fn from_wire(v: &Value) -> Result<Self, CircuitError> {
        let Value::Map(entries) = v else {
            return Err(CircuitError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut circuit_id: Option<[u8; 32]> = None;
        let mut direction: Option<u64> = None;
        let mut seq: Option<u64> = None;
        let mut payload: Option<Vec<u8>> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(CircuitError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(CircuitError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != CIRCUIT_SCHEME_VERSION {
                        return Err(CircuitError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if circuit_id.is_some() {
                        return Err(CircuitError::DuplicateField { key: 2 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != 32 {
                        return Err(CircuitError::CircuitIdWrongLength { len: b.len() });
                    }
                    circuit_id = Some(b.as_slice().try_into().expect("checked"));
                }
                3 => {
                    if direction.is_some() {
                        return Err(CircuitError::DuplicateField { key: 3 });
                    }
                    let Value::Int(d) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 3 });
                    };
                    direction =
                        Some(u64::try_from(*d).map_err(|_| CircuitError::TimestampOutOfRange)?);
                }
                4 => {
                    if seq.is_some() {
                        return Err(CircuitError::DuplicateField { key: 4 });
                    }
                    let Value::Int(s) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 4 });
                    };
                    seq = Some(u64::try_from(*s).map_err(|_| CircuitError::TimestampOutOfRange)?);
                }
                5 => {
                    if payload.is_some() {
                        return Err(CircuitError::DuplicateField { key: 5 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 5 });
                    };
                    payload = Some(b.clone());
                }
                other => return Err(CircuitError::UnknownField { key: other }),
            }
        }
        let circuit_id = circuit_id.ok_or(CircuitError::MissingField { key: 2 })?;
        let direction = direction.ok_or(CircuitError::MissingField { key: 3 })?;
        let seq = seq.ok_or(CircuitError::MissingField { key: 4 })?;
        let payload = payload.ok_or(CircuitError::MissingField { key: 5 })?;
        CircuitFrame::new(circuit_id, direction, seq, payload)
    }

    pub fn circuit_id(&self) -> &[u8; 32] {
        &self.circuit_id
    }
    pub fn direction(&self) -> u64 {
        self.direction
    }
    pub fn seq(&self) -> u64 {
        self.seq
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
}

// ---------------------------------------------------------------------------
// CircuitDestroy
// ---------------------------------------------------------------------------

/// A parsed (not yet verified) circuit destroy notice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitDestroy {
    circuit_id: [u8; 32],
    sender: NodeIdentity,
    reason: String,
    destroyed_at_unix: u64,
}

impl CircuitDestroy {
    pub fn new(
        circuit_id: [u8; 32],
        sender: &Identity,
        reason: impl Into<String>,
        destroyed_at_unix: u64,
    ) -> Result<Self, CircuitError> {
        let reason = reason.into();
        if !DESTROY_REASONS.contains(&reason.as_str()) {
            return Err(CircuitError::ReasonUnknown { found: reason });
        }
        Ok(CircuitDestroy {
            circuit_id,
            sender: sender.node_identity().clone(),
            reason,
            destroyed_at_unix,
        })
    }

    /// Sign this destroy with the sender's key.
    pub fn sign(&self, sender: &Identity) -> Result<SignedEnvelope, CircuitError> {
        let bytes = self.to_wire_bytes();
        let signature = sender.sign_detached(&bytes);
        Ok(SignedEnvelope::new(bytes, signature))
    }

    pub fn to_wire(&self) -> Value {
        Value::Map(vec![
            (Value::Int(1), Value::Int(CIRCUIT_SCHEME_VERSION)),
            (Value::Int(2), Value::Bytes(self.circuit_id.to_vec())),
            (Value::Int(3), self.sender.to_wire()),
            (Value::Int(4), Value::Text(self.reason.clone())),
            (Value::Int(5), Value::Int(self.destroyed_at_unix as i64)),
        ])
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, CircuitError> {
        let v = decode(bytes).map_err(|e| CircuitError::Cbor(e.to_string()))?;
        Self::from_wire(&v)
    }

    pub fn from_wire(v: &Value) -> Result<Self, CircuitError> {
        let Value::Map(entries) = v else {
            return Err(CircuitError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut circuit_id: Option<[u8; 32]> = None;
        let mut sender: Option<NodeIdentity> = None;
        let mut reason: Option<String> = None;
        let mut destroyed: Option<u64> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(CircuitError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(CircuitError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != CIRCUIT_SCHEME_VERSION {
                        return Err(CircuitError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if circuit_id.is_some() {
                        return Err(CircuitError::DuplicateField { key: 2 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != 32 {
                        return Err(CircuitError::CircuitIdWrongLength { len: b.len() });
                    }
                    circuit_id = Some(b.as_slice().try_into().expect("checked"));
                }
                3 => {
                    if sender.is_some() {
                        return Err(CircuitError::DuplicateField { key: 3 });
                    }
                    sender = Some(
                        NodeIdentity::from_wire(val)
                            .map_err(|e| CircuitError::Cbor(e.to_string()))?,
                    );
                }
                4 => {
                    if reason.is_some() {
                        return Err(CircuitError::DuplicateField { key: 4 });
                    }
                    let Value::Text(t) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 4 });
                    };
                    reason = Some(t.clone());
                }
                5 => {
                    if destroyed.is_some() {
                        return Err(CircuitError::DuplicateField { key: 5 });
                    }
                    let Value::Int(t) = val else {
                        return Err(CircuitError::FieldNotExpectedType { key: 5 });
                    };
                    let t = u64::try_from(*t).map_err(|_| CircuitError::TimestampOutOfRange)?;
                    destroyed = Some(t);
                }
                other => return Err(CircuitError::UnknownField { key: other }),
            }
        }
        let circuit_id = circuit_id.ok_or(CircuitError::MissingField { key: 2 })?;
        let sender = sender.ok_or(CircuitError::MissingField { key: 3 })?;
        let reason = reason.ok_or(CircuitError::MissingField { key: 4 })?;
        let destroyed = destroyed.ok_or(CircuitError::MissingField { key: 5 })?;
        if !DESTROY_REASONS.contains(&reason.as_str()) {
            return Err(CircuitError::ReasonUnknown { found: reason });
        }
        Ok(CircuitDestroy {
            circuit_id,
            sender,
            reason,
            destroyed_at_unix: destroyed,
        })
    }

    pub fn circuit_id(&self) -> &[u8; 32] {
        &self.circuit_id
    }
    pub fn sender_identity(&self) -> &NodeIdentity {
        &self.sender
    }
    pub fn reason(&self) -> &str {
        &self.reason
    }
    pub fn destroyed_at_unix(&self) -> u64 {
        self.destroyed_at_unix
    }
}

// ---------------------------------------------------------------------------
// CircuitRegistry — the runtime verifier/collector
// ---------------------------------------------------------------------------

/// Runtime admission state of one circuit.
#[derive(Debug, Clone)]
pub struct CircuitState {
    route_id: [u8; 32],
    path: Vec<[u8; 32]>,
    setup_digest: [u8; 32],
    setup_expires_at_unix: u64,
    acked: Vec<Option<[u8; 32]>>, // position -> acking node_id
    next_seq: [u64; 3],           // indexed by direction 1|2
    destroyed: bool,
    destroy_reason: Option<String>,
}

impl CircuitState {
    /// The positions not yet acknowledged (ascending).
    pub fn unacked_positions(&self) -> Vec<u64> {
        self.acked
            .iter()
            .enumerate()
            .filter(|(_, a)| a.is_none())
            .map(|(i, _)| i as u64)
            .collect()
    }

    /// True when every path position is acknowledged exactly once.
    pub fn established(&self) -> bool {
        self.acked.iter().all(|a| a.is_some())
    }

    pub fn route_id(&self) -> &[u8; 32] {
        &self.route_id
    }
    pub fn path(&self) -> &[[u8; 32]] {
        &self.path
    }
    pub fn destroyed(&self) -> bool {
        self.destroyed
    }
    pub fn destroy_reason(&self) -> Option<&str> {
        self.destroy_reason.as_deref()
    }
    /// Next expected sequence number for a direction (replay-namespace
    /// state).
    pub fn next_seq(&self, direction: u64) -> Option<u64> {
        match direction {
            DIRECTION_INITIATOR_TO_EXIT | DIRECTION_EXIT_TO_INITIATOR => {
                Some(self.next_seq[direction as usize])
            }
            _ => None,
        }
    }
}

/// The result of admitting an ack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckOutcome {
    /// The circuit is still waiting for these positions.
    Pending { unacked: Vec<u64> },
    /// The last needed position was just acknowledged.
    Established,
}

impl AckOutcome {
    /// True when the circuit is established after this ack.
    pub fn established(&self) -> bool {
        matches!(self, AckOutcome::Established)
    }
}

/// The runtime circuit registry: verifies setups (full R3-004 chain),
/// acks (exact position coverage → established), frames (per-direction
/// strictly monotonic replay namespaces) and destroys (terminal).
///
/// Fail-closed: no caller-controlled trust booleans anywhere.
#[derive(Debug, Default)]
pub struct CircuitRegistry {
    circuits: HashMap<[u8; 32], CircuitState>,
    used_nonces: HashSet<([u8; 32], [u8; 32])>, // (route_id, setup_nonce)
}

impl CircuitRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a signed setup envelope. Returns the derived circuit id.
    pub fn admit_setup(
        &mut self,
        now_unix: u64,
        envelope: &SignedEnvelope,
    ) -> Result<[u8; 32], CircuitError> {
        let setup = CircuitSetup::from_wire_bytes(envelope.bytes())?;
        setup
            .initiator_identity()
            .verify_detached(envelope.bytes(), envelope.signature())
            .map_err(|_| CircuitError::SetupSignatureInvalid)?;
        // Full R3-004 verification of the embedded commitment.
        let commitment = RouteCommitment::from_wire_bytes(setup.route_commitment_bytes())?;
        let verified = commitment.verify(now_unix)?;
        // Circuit authority binds to route authority.
        if verified.proposal.proposer_identity().node_id()
            != setup.initiator_identity().node_id()
        {
            return Err(CircuitError::InitiatorNotProposer);
        }
        // Freshness.
        if now_unix < setup.issued_at_unix() {
            return Err(CircuitError::SetupNotYetValid);
        }
        if now_unix >= setup.expires_at_unix() {
            return Err(CircuitError::SetupExpired);
        }
        let route_id = verified.route_id;
        let nonce = setup.setup_nonce();
        if !self.used_nonces.insert((route_id, *nonce)) {
            return Err(CircuitError::SetupNonceReused);
        }
        let circuit_id = derive_circuit_id(&route_id, nonce);
        let path = verified.proposal.path().to_vec();
        if path.len() > CIRCUIT_MAX_PATH {
            return Err(CircuitError::PositionOutOfRange {
                position: path.len() as u64,
                path_len: path.len(),
            });
        }
        self.circuits.insert(
            circuit_id,
            CircuitState {
                route_id,
                path: path.clone(),
                setup_digest: setup_digest(envelope.bytes()),
                setup_expires_at_unix: setup.expires_at_unix(),
                acked: vec![None; path.len()],
                next_seq: [0, 0, 0],
                destroyed: false,
                destroy_reason: None,
            },
        );
        Ok(circuit_id)
    }

    /// Admit a signed ack envelope for a known circuit.
    pub fn admit_ack(
        &mut self,
        now_unix: u64,
        envelope: &SignedEnvelope,
    ) -> Result<AckOutcome, CircuitError> {
        let ack = CircuitSetupAck::from_wire_bytes(envelope.bytes())?;
        ack.accepting_identity()
            .verify_detached(envelope.bytes(), envelope.signature())
            .map_err(|_| CircuitError::AckSignatureInvalid)?;
        let state = self
            .circuits
            .get_mut(ack.circuit_id())
            .ok_or(CircuitError::CircuitUnknown)?;
        if state.destroyed {
            return Err(CircuitError::CircuitDestroyed);
        }
        if ack.setup_digest() != &state.setup_digest {
            return Err(CircuitError::SetupDigestMismatch);
        }
        let position = ack.position() as usize;
        if position >= state.path.len() {
            return Err(CircuitError::PositionOutOfRange {
                position: ack.position(),
                path_len: state.path.len(),
            });
        }
        if state.acked[position].is_some() {
            return Err(CircuitError::AckPositionAlreadyTaken {
                position: ack.position(),
            });
        }
        if ack.accepting_identity().node_id().as_bytes() != &state.path[position] {
            return Err(CircuitError::AckIdentityMismatch {
                position: ack.position(),
            });
        }
        // Acks cannot outlive their setup.
        if ack.accepted_at_unix() >= state.setup_expires_at_unix {
            return Err(CircuitError::AckOutlivesSetup);
        }
        if now_unix < ack.accepted_at_unix() {
            return Err(CircuitError::AckNotYetValid);
        }
        if now_unix >= ack.expires_at_unix() {
            return Err(CircuitError::AckExpired);
        }
        let acking = *ack.accepting_identity().node_id().as_bytes();
        state.acked[position] = Some(acking);
        if state.established() {
            Ok(AckOutcome::Established)
        } else {
            Ok(AckOutcome::Pending {
                unacked: state.unacked_positions(),
            })
        }
    }

    /// Admit a frame: binding + ordering + bounds.
    pub fn admit_frame(&mut self, frame: &CircuitFrame) -> Result<(), CircuitError> {
        let state = self
            .circuits
            .get_mut(frame.circuit_id())
            .ok_or(CircuitError::CircuitUnknown)?;
        if state.destroyed {
            return Err(CircuitError::CircuitDestroyed);
        }
        if !state.established() {
            return Err(CircuitError::CircuitNotEstablished {
                unacked: state.unacked_positions(),
            });
        }
        let direction = frame.direction();
        let expected = state
            .next_seq(direction)
            .ok_or(CircuitError::DirectionUnknown { found: direction })?;
        if frame.seq() != expected {
            return Err(CircuitError::FrameSeqOutOfOrder {
                direction,
                expected,
                found: frame.seq(),
            });
        }
        state.next_seq[direction as usize] = expected
            .checked_add(1)
            .ok_or(CircuitError::TimestampOutOfRange)?;
        Ok(())
    }

    /// Admit a signed destroy envelope (any path member; idempotent).
    pub fn admit_destroy(
        &mut self,
        envelope: &SignedEnvelope,
    ) -> Result<(), CircuitError> {
        let destroy = CircuitDestroy::from_wire_bytes(envelope.bytes())?;
        destroy
            .sender_identity()
            .verify_detached(envelope.bytes(), envelope.signature())
            .map_err(|_| CircuitError::DestroySignatureInvalid)?;
        let state = self
            .circuits
            .get_mut(destroy.circuit_id())
            .ok_or(CircuitError::CircuitUnknown)?;
        let sender_node_id = *destroy.sender_identity().node_id().as_bytes();
        if !state.path.iter().any(|p| *p == sender_node_id) {
            return Err(CircuitError::DestroySenderNotOnPath);
        }
        if !state.destroyed {
            state.destroyed = true;
            state.destroy_reason = Some(destroy.reason().to_string());
        }
        // Duplicate destroys of the same circuit are idempotent.
        Ok(())
    }

    /// Look up runtime state (read-only view).
    pub fn circuit(&self, circuit_id: &[u8; 32]) -> Option<&CircuitState> {
        self.circuits.get(circuit_id)
    }

    /// Is the circuit known and established (all positions acked)?
    pub fn is_established(&self, circuit_id: &[u8; 32]) -> bool {
        self.circuits
            .get(circuit_id)
            .is_some_and(|s| s.established())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::route::{RouteAcceptance, RouteProposal};

    fn ident(seed: u8) -> Identity {
        Identity::from_seed([seed; 32], 1_700_000_000, None).expect("identity")
    }

    /// Build a verified 3-hop commitment (proposer + 2 hops).
    fn commitment(now: u64) -> (Identity, Vec<Identity>, RouteCommitment) {
        let proposer = ident(0x11);
        let hop1 = ident(0x22);
        let hop2 = ident(0x33);
        let mut path = vec![
            *proposer.node_identity().node_id().as_bytes(),
            *hop1.node_identity().node_id().as_bytes(),
            *hop2.node_identity().node_id().as_bytes(),
        ];
        path.sort();
        let proposal =
            RouteProposal::new(&proposer, path.clone(), "live", now, 600, [0xAB; 32])
                .expect("proposal");
        let proposal_env = proposal.sign(&proposer).expect("sign");
        let proposal_id =
            crate::route::derive_proposal_id(proposal_env.bytes());
        let mut envelopes = Vec::new();
        for hop in [&proposer, &hop1, &hop2] {
            let position = path
                .iter()
                .position(|p| p == hop.node_identity().node_id().as_bytes())
                .expect("position") as u64;
            let acceptance =
                RouteAcceptance::new(hop, proposal_id, position, now, 600)
                    .expect("acceptance");
            envelopes.push(acceptance.sign(hop).expect("sign"));
        }
        let commitment =
            RouteCommitment::build(now, proposal_env, envelopes).expect("commitment");
        (proposer, vec![hop1, hop2], commitment)
    }

    #[test]
    fn setup_ack_frame_destroy_happy_path() {
        let now = 1_700_000_000u64;
        let (proposer, hops, commitment) = commitment(now);
        let setup = CircuitSetup::new(&commitment, &proposer, [0xCD; 32], now, 600)
            .expect("setup");
        let setup_env = setup.sign(&proposer).expect("sign");
        let mut registry = CircuitRegistry::new();
        let circuit_id = registry.admit_setup(now, &setup_env).expect("admit");
        assert_eq!(circuit_id, setup.circuit_id().expect("id"));
        assert!(!registry.is_established(&circuit_id));

        // Frames before establishment are rejected.
        let early = CircuitFrame::new(circuit_id, 1, 0, b"early".to_vec()).expect("frame");
        assert!(matches!(
            registry.admit_frame(&early),
            Err(CircuitError::CircuitNotEstablished { .. })
        ));

        // Ack every position: the proposer is also a path member.
        let path = commitment
            .verify(now)
            .expect("verify")
            .proposal
            .path()
            .to_vec();
        let members: Vec<&Identity> = {
            let mut m: Vec<&Identity> = hops.iter().collect();
            m.push(&proposer);
            m
        };
        let mut last_outcome = AckOutcome::Pending {
            unacked: vec![0, 1, 2],
        };
        for member in &members {
            let position = path
                .iter()
                .position(|p| p == member.node_identity().node_id().as_bytes())
                .expect("position") as u64;
            let ack = CircuitSetupAck::new(
                circuit_id,
                &setup_env,
                member,
                position,
                now,
                600,
            )
            .expect("ack");
            let env = ack.sign(member).expect("sign");
            last_outcome = registry.admit_ack(now, &env).expect("ack admit");
        }
        assert_eq!(last_outcome, AckOutcome::Established);
        assert!(registry.is_established(&circuit_id));

        // Frames: per-direction strictly monotonic from 0.
        for seq in 0..3 {
            let f = CircuitFrame::new(circuit_id, 1, seq, vec![seq as u8; 64])
                .expect("frame");
            registry.admit_frame(&f).expect("frame admit");
        }
        let back = CircuitFrame::new(circuit_id, 2, 0, b"reply".to_vec()).expect("frame");
        registry.admit_frame(&back).expect("reverse direction ns");

        // Destroy by a path member is terminal.
        let destroy = CircuitDestroy::new(circuit_id, &hops[0], "link_failure", now + 10)
            .expect("destroy");
        let destroy_env = destroy.sign(&hops[0]).expect("sign");
        registry.admit_destroy(&destroy_env).expect("destroy");
        let post = CircuitFrame::new(circuit_id, 1, 3, b"late".to_vec()).expect("frame");
        assert_eq!(registry.admit_frame(&post), Err(CircuitError::CircuitDestroyed));
        // Idempotent duplicate destroy.
        registry.admit_destroy(&destroy_env).expect("idempotent");
    }

    #[test]
    fn replacement_circuit_is_fresh() {
        let now = 1_700_000_000u64;
        let (proposer, _hops, commitment) = commitment(now);
        let mut registry = CircuitRegistry::new();
        let setup_a = CircuitSetup::new(&commitment, &proposer, [0x01; 32], now, 600)
            .expect("setup");
        let env_a = setup_a.sign(&proposer).expect("sign");
        let id_a = registry.admit_setup(now, &env_a).expect("admit");
        // Same nonce again: refused (single-use).
        assert_eq!(
            registry.admit_setup(now, &env_a),
            Err(CircuitError::SetupNonceReused)
        );
        // Fresh nonce: fresh circuit id (L014).
        let setup_b = CircuitSetup::new(&commitment, &proposer, [0x02; 32], now, 600)
            .expect("setup");
        let env_b = setup_b.sign(&proposer).expect("sign");
        let id_b = registry.admit_setup(now, &env_b).expect("admit");
        assert_ne!(id_a, id_b);
    }

    #[test]
    fn non_proposer_initiator_refused() {
        let now = 1_700_000_000u64;
        let (proposer, _hops, commitment) = commitment(now);
        let other = ident(0x99);
        // Construction-time refusal.
        assert_eq!(
            CircuitSetup::new(&commitment, &other, [0x05; 32], now, 600),
            Err(CircuitError::InitiatorNotProposer)
        );
        // Admission-time refusal via a hand-built wire object (the
        // constructor cannot express it, so parse-from-wire is used).
        let setup = CircuitSetup::new(&commitment, &proposer, [0x05; 32], now, 600)
            .expect("setup");
        let mut wire = setup.to_wire();
        if let Value::Map(ref mut entries) = wire {
            for (k, v) in entries.iter_mut() {
                if let Value::Int(4) = k {
                    *v = other.node_identity().to_wire();
                }
            }
        }
        let bytes = encode(&wire).expect("encode");
        let env = SignedEnvelope::new(bytes.clone(), other.sign_detached(&bytes));
        let mut registry = CircuitRegistry::new();
        assert_eq!(
            registry.admit_setup(now, &env),
            Err(CircuitError::InitiatorNotProposer)
        );
    }

    #[test]
    fn frame_replay_namespace_enforced() {
        let now = 1_700_000_000u64;
        let (proposer, hops, commitment) = commitment(now);
        let setup = CircuitSetup::new(&commitment, &proposer, [0x07; 32], now, 600)
            .expect("setup");
        let setup_env = setup.sign(&proposer).expect("sign");
        let mut registry = CircuitRegistry::new();
        let circuit_id = registry.admit_setup(now, &setup_env).expect("admit");
        let path = commitment.verify(now).expect("v").proposal.path().to_vec();
        let members: Vec<&Identity> = {
            let mut m: Vec<&Identity> = hops.iter().collect();
            m.push(&proposer);
            m
        };
        for member in &members {
            let position = path
                .iter()
                .position(|p| p == member.node_identity().node_id().as_bytes())
                .expect("pos") as u64;
            let ack = CircuitSetupAck::new(circuit_id, &setup_env, member, position, now, 600)
                .expect("ack");
            let env = ack.sign(member).expect("sign");
            registry.admit_ack(now, &env).expect("ack");
        }
        let f0 = CircuitFrame::new(circuit_id, 1, 0, b"a".to_vec()).expect("frame");
        registry.admit_frame(&f0).expect("first");
        // Replay of seq 0: rejected.
        assert_eq!(
            registry.admit_frame(&f0),
            Err(CircuitError::FrameSeqOutOfOrder {
                direction: 1,
                expected: 1,
                found: 0
            })
        );
        // Gap (seq 2 when 1 expected): rejected.
        let f2 = CircuitFrame::new(circuit_id, 1, 2, b"c".to_vec()).expect("frame");
        assert_eq!(
            registry.admit_frame(&f2),
            Err(CircuitError::FrameSeqOutOfOrder {
                direction: 1,
                expected: 1,
                found: 2
            })
        );
        // Reverse namespace is independent (starts at 0).
        let r0 = CircuitFrame::new(circuit_id, 2, 0, b"r".to_vec()).expect("frame");
        registry.admit_frame(&r0).expect("reverse");
    }
}
