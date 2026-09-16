//! Contribution receipts — the signed cross-node contribution evidence
//! (work item R8-001; the `ContributionReceipt` registry entry is
//! normative).
//!
//! Architecture §13 ("Civic Points are earned only from verified useful
//! work") and §14 (the anti-gaming minimums) require authenticated
//! participants and durable replay-safe receipts before any valuation.
//! This module is that evidence's wire form:
//!
//! 1. [`ContributionReceipt`] — the registered wire object: the
//!    RECEIVING counterparty (the issuer) signs its acknowledgement that
//!    a named contributor moved a named content object to it. The
//!    bilateral-acknowledgement rule (§14: "bilateral/recipient
//!    acknowledgement") makes the recipient the signer — a node never
//!    issues receipts for its own contributions. Carrying envelope =
//!    canonical CBOR `{1: receipt (bstr), 2: signature (64-byte bstr)}`
//!    (the established envelope pattern); [`SignedContributionReceipt`]
//!    is the fully verified form (parse + signature on construction).
//!    `receipt_id` = SHA-256(canonical receipt bytes) — content-derived,
//!    caller-selected IDs forbidden (L013, the same law as `content_id`).
//! 2. [`ReceiptLedger`] — the durable integration (the R7-001
//!    [`RevocationLedger`](crate::revocation::RevocationLedger)
//!    pattern): admits receipts after the registry's full fail-closed
//!    chain (strict parse → issuer node_id derivation → signature →
//!    self-receipt exclusion → frozen kind set → not-future) and enforces
//!    the PER-(issuer, contributor) monotonic sequence law: an
//!    identical `receipt_id` is idempotent (the first recorded receipt
//!    wins), while a regressed or repeated sequence number is refused
//!    typed.
//!
//! # Trust boundary (the registry's trust_boundary_note, verbatim in
//! spirit)
//!
//! A receipt is the issuer's AUTHENTICATED claim that the contributor's
//! contribution reached it — it is NOT proof of useful work (valuation is
//! R8-002), NOT protection against Sybil multiplication or circular
//! traffic (the anti-gaming analysis is R8-005), and a receipt issued by
//! a key the contributor itself controls (the Sybil degenerate) is only
//! detectable at the valuation/analysis layers. This module carries
//! exactly the bilateral fact; per-counterparty and per-time-window
//! caps, anomaly detection and contribution-quality weighting live in
//! the economics subsystem, never here.
//!
//! # Offline-first (architecture §15)
//!
//! "ADCOS outage does not disable ... contribution evidence capture."
//! This module performs no I/O, consults no network, and reads no wall
//! clock (every time input is caller-supplied `now`, the crate's law):
//! receipt construction, verification and ledger admission are pure
//! local computation, so capture continues through any connectivity
//! loss.
//!
//! # Relationship to the R6-003 custody log
//!
//! The DTN custody records are UNSIGNED local facts (R6-003); this
//! object is their signed, cross-node form — the issuer-recipient signs
//! exactly the custody/delivery event it observed, and the receipt's
//! `content_id` binds it to the R6-001 named object that moved.
//!
//! # Persistence seam (honest scope statement)
//!
//! [`ReceiptLedger::to_snapshot_bytes`] /
//! [`ReceiptLedger::from_snapshot_bytes`] model durability as a
//! serialized canonical snapshot: every recorded receipt is stored as its
//! full carrying envelope, and restore RE-PARSES and RE-VERIFIES every
//! record's signature (fail-closed on any tamper). Full durable files
//! (atomic append-only storage, retention, crash recovery) are the
//! consuming R8-002 ledger layer's scope; the seam is the honest
//! in-memory boundary between the two. A snapshot attack that DELETES
//! whole records cannot be caught by per-record signatures — the durable
//! layer must use append-only storage to close that hole (documented
//! limitation, by design of the seam, mirroring R7-001).

use core::fmt;
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};

use sha2::{Digest, Sha256};

use crate::cbor::{decode, encode, Value};
use crate::content::ContentManifest;
use crate::identity::{Identity, IdentityError, NodeId, NodeIdentity};
use crate::route::SignedEnvelope;

/// Scheme version of the ContributionReceipt wire object (v1).
pub const CONTRIBUTION_SCHEME_VERSION: i64 = 1;
/// Frozen v1 contribution kinds (the registry's set: carried = the issuer
/// took custody from the contributor, DTN handover R6-003; delivered =
/// the issuer is the terminal destination consuming the content).
pub const CONTRIBUTION_KINDS: [&str; 2] = ["carried", "delivered"];
/// Upper bound of `delivered_bytes` (the registry: >= 1, <= 2^40).
pub const DELIVERED_BYTES_MAX: u64 = 1 << 40;
/// Minimum `receipt_seq` (issuers count from 1, the R5-004 convention).
pub const RECEIPT_SEQ_MIN: u64 = 1;
/// Snapshot format version (the persistence seam's wire version).
pub const CONTRIBUTION_SNAPSHOT_VERSION: i64 = 1;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Typed errors of the contribution-evidence layer (stable machine names
/// for the cross-language conformance suite).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    Cbor(String),
    NotAMap,
    KeyNotAnInteger,
    DuplicateField {
        key: i64,
    },
    MissingField {
        key: i64,
    },
    FieldNotExpectedType {
        key: i64,
    },
    UnknownField {
        key: i64,
    },
    SchemeVersionUnsupported {
        found: i64,
    },
    Identity(IdentityError),
    ContributorIdWrongLength {
        len: usize,
    },
    ContentIdWrongLength {
        len: usize,
    },
    /// contributor == issuer (the self-receipt exclusion).
    SelfReceipt {
        issuer: String,
        contributor: String,
    },
    KindUnknown {
        found: String,
    },
    DeliveredBytesOutOfRange {
        found: i64,
    },
    ReceiptSeqInvalid {
        found: i64,
    },
    TimestampOutOfRange,
    SignatureWrongLength {
        len: usize,
    },
    EnvelopeWrongEntryCount {
        count: usize,
    },
    SignatureInvalid,
    SignerMismatch {
        receipt: String,
        signer: String,
    },
    IssuedAtInFuture {
        issued_at: u64,
        now: u64,
    },
    /// The sequence law: receipt_seq not strictly greater than the pair's
    /// last ACCEPTED receipt (a regressed or repeated number).
    SequenceRegressed {
        found: u64,
        last: u64,
    },
    /// The manifest-binding check: the receipt names a different content
    /// object than the manifest in hand.
    ContentIdMismatch {
        receipt: String,
        manifest: String,
    },
    /// The manifest-binding check: the issuer counted more bytes than the
    /// named content object holds.
    DeliveredBytesExceedsTotal {
        delivered: u64,
        total: u64,
    },
    SnapshotOrderInvalid,
    SnapshotDuplicateRecord,
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceiptError::Cbor(e) => write!(f, "cbor: {e}"),
            ReceiptError::NotAMap => write!(f, "not a map"),
            ReceiptError::KeyNotAnInteger => write!(f, "map key not an integer"),
            ReceiptError::DuplicateField { key } => write!(f, "duplicate field {key}"),
            ReceiptError::MissingField { key } => write!(f, "missing field {key}"),
            ReceiptError::FieldNotExpectedType { key } => {
                write!(f, "field {key} not of expected type")
            }
            ReceiptError::UnknownField { key } => write!(f, "unknown field {key}"),
            ReceiptError::SchemeVersionUnsupported { found } => {
                write!(f, "scheme version {found} unsupported")
            }
            ReceiptError::Identity(e) => write!(f, "identity: {e}"),
            ReceiptError::ContributorIdWrongLength { len } => {
                write!(f, "contributor node id must be 32 bytes, found {len}")
            }
            ReceiptError::ContentIdWrongLength { len } => {
                write!(f, "content id must be 32 bytes, found {len}")
            }
            ReceiptError::SelfReceipt {
                issuer,
                contributor,
            } => write!(
                f,
                "contributor {contributor} equals the issuer {issuer} (self-receipt excluded)"
            ),
            ReceiptError::KindUnknown { found } => {
                write!(f, "contribution kind {found:?} unknown")
            }
            ReceiptError::DeliveredBytesOutOfRange { found } => write!(
                f,
                "delivered bytes {found} outside 1..={DELIVERED_BYTES_MAX}"
            ),
            ReceiptError::ReceiptSeqInvalid { found } => {
                write!(
                    f,
                    "receipt sequence {found} below the minimum {RECEIPT_SEQ_MIN}"
                )
            }
            ReceiptError::TimestampOutOfRange => write!(f, "timestamp out of range"),
            ReceiptError::SignatureWrongLength { len } => {
                write!(f, "envelope signature must be 64 bytes, found {len}")
            }
            ReceiptError::EnvelopeWrongEntryCount { count } => write!(
                f,
                "carrying envelope must have exactly 2 entries, found {count}"
            ),
            ReceiptError::SignatureInvalid => write!(f, "receipt signature invalid"),
            ReceiptError::SignerMismatch { receipt, signer } => {
                write!(f, "signer {signer} does not match the issuer {receipt}")
            }
            ReceiptError::IssuedAtInFuture { issued_at, now } => {
                write!(f, "issued_at {issued_at} is in the future (now {now})")
            }
            ReceiptError::SequenceRegressed { found, last } => write!(
                f,
                "receipt sequence {found} not strictly greater than the last accepted {last}"
            ),
            ReceiptError::ContentIdMismatch { receipt, manifest } => write!(
                f,
                "receipt content id {receipt} does not match the manifest {manifest}"
            ),
            ReceiptError::DeliveredBytesExceedsTotal { delivered, total } => write!(
                f,
                "delivered bytes {delivered} exceed the manifest total {total}"
            ),
            ReceiptError::SnapshotOrderInvalid => {
                write!(f, "snapshot records are not in canonical ascending order")
            }
            ReceiptError::SnapshotDuplicateRecord => {
                write!(f, "snapshot contains a duplicate receipt_id record")
            }
        }
    }
}

impl std::error::Error for ReceiptError {}

impl ReceiptError {
    /// Stable machine name (consumed by the cross-language suite).
    pub fn name(&self) -> &'static str {
        match self {
            ReceiptError::Cbor(_) => "cbor",
            ReceiptError::NotAMap => "not_a_map",
            ReceiptError::KeyNotAnInteger => "key_not_an_integer",
            ReceiptError::DuplicateField { .. } => "duplicate_field",
            ReceiptError::MissingField { .. } => "missing_field",
            ReceiptError::FieldNotExpectedType { .. } => "field_not_expected_type",
            ReceiptError::UnknownField { .. } => "unknown_field",
            ReceiptError::SchemeVersionUnsupported { .. } => "scheme_version_unsupported",
            ReceiptError::Identity(_) => "identity_error",
            ReceiptError::ContributorIdWrongLength { .. } => "contributor_id_wrong_length",
            ReceiptError::ContentIdWrongLength { .. } => "content_id_wrong_length",
            ReceiptError::SelfReceipt { .. } => "self_receipt",
            ReceiptError::KindUnknown { .. } => "kind_unknown",
            ReceiptError::DeliveredBytesOutOfRange { .. } => "delivered_bytes_out_of_range",
            ReceiptError::ReceiptSeqInvalid { .. } => "receipt_seq_invalid",
            ReceiptError::TimestampOutOfRange => "timestamp_out_of_range",
            ReceiptError::SignatureWrongLength { .. } => "signature_wrong_length",
            ReceiptError::EnvelopeWrongEntryCount { .. } => "envelope_wrong_entry_count",
            ReceiptError::SignatureInvalid => "signature_invalid",
            ReceiptError::SignerMismatch { .. } => "signer_mismatch",
            ReceiptError::IssuedAtInFuture { .. } => "issued_at_in_future",
            ReceiptError::SequenceRegressed { .. } => "sequence_regressed",
            ReceiptError::ContentIdMismatch { .. } => "content_id_mismatch",
            ReceiptError::DeliveredBytesExceedsTotal { .. } => "delivered_bytes_exceeds_total",
            ReceiptError::SnapshotOrderInvalid => "snapshot_order_invalid",
            ReceiptError::SnapshotDuplicateRecord => "snapshot_duplicate_record",
        }
    }
}

// ---------------------------------------------------------------------------
// ContributionKind (the frozen two)
// ---------------------------------------------------------------------------

/// The contribution kind — one of the frozen v1 set.
///
/// `Carried` = the issuer took custody from the contributor (a DTN
/// handover, R6-003); `Delivered` = the issuer is the terminal
/// destination consuming the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContributionKind {
    /// "carried" — custody accepted (the DTN handover).
    Carried,
    /// "delivered" — terminal consumption.
    Delivered,
}

impl ContributionKind {
    /// The frozen v1 set, in registry order.
    pub const ALL: [ContributionKind; 2] = [ContributionKind::Carried, ContributionKind::Delivered];

    /// Stable machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            ContributionKind::Carried => "carried",
            ContributionKind::Delivered => "delivered",
        }
    }

    /// Parse from the machine name — anything else is `None` (the wire
    /// surfaces that as the typed `kind_unknown`).
    pub fn from_name(name: &str) -> Option<ContributionKind> {
        match name {
            "carried" => Some(ContributionKind::Carried),
            "delivered" => Some(ContributionKind::Delivered),
            _ => None,
        }
    }
}

impl fmt::Display for ContributionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ContributionReceipt (the wire object)
// ---------------------------------------------------------------------------

/// A parsed (not yet verified) contribution receipt.
///
/// Invariants are enforced at construction AND re-enforced at parse
/// (strict: exactly one accepted byte image per logical receipt —
/// byte-stability).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContributionReceipt {
    issuer: NodeIdentity,
    contributor_node_id: [u8; 32],
    content_id: [u8; 32],
    kind: ContributionKind,
    delivered_bytes: u64,
    receipt_seq: u64,
    issued_at_unix: u64,
}

impl ContributionReceipt {
    /// Build a receipt over the issuer's live identity (the receiving
    /// counterparty acknowledges the contributor).
    ///
    /// Enforces the parse-time invariants up front: the contributor
    /// differs from the issuer (the self-receipt exclusion — a node never
    /// acknowledges itself), the kind is from the frozen set (via the
    /// typed [`ContributionKind`]), `delivered_bytes` is 1..=2^40,
    /// `receipt_seq` >= 1, and `issued_at_unix` fits the canonical
    /// integer range.
    pub fn new(
        issuer: &Identity,
        contributor_node_id: [u8; 32],
        content_id: [u8; 32],
        kind: ContributionKind,
        delivered_bytes: u64,
        receipt_seq: u64,
        issued_at_unix: u64,
    ) -> Result<Self, ReceiptError> {
        if contributor_node_id == *issuer.node_id().as_bytes() {
            return Err(ReceiptError::SelfReceipt {
                issuer: issuer.node_id().to_hex(),
                contributor: NodeId::from_bytes(contributor_node_id).to_hex(),
            });
        }
        if delivered_bytes == 0 || delivered_bytes > DELIVERED_BYTES_MAX {
            return Err(ReceiptError::DeliveredBytesOutOfRange {
                found: delivered_bytes as i64,
            });
        }
        if receipt_seq < RECEIPT_SEQ_MIN {
            return Err(ReceiptError::ReceiptSeqInvalid {
                found: receipt_seq as i64,
            });
        }
        if issued_at_unix > i64::MAX as u64 {
            return Err(ReceiptError::TimestampOutOfRange);
        }
        Ok(ContributionReceipt {
            issuer: issuer.node_identity().clone(),
            contributor_node_id,
            content_id,
            kind,
            delivered_bytes,
            receipt_seq,
            issued_at_unix,
        })
    }

    /// Sign this receipt with the issuer's key (binding enforced — only
    /// the recipient may issue its acknowledgement).
    pub fn sign(&self, issuer: &Identity) -> Result<SignedContributionReceipt, ReceiptError> {
        if issuer.node_id() != self.issuer.node_id() {
            return Err(ReceiptError::SignerMismatch {
                receipt: self.issuer.node_id().to_hex(),
                signer: issuer.node_id().to_hex(),
            });
        }
        let receipt_bytes = self.to_wire_bytes();
        let signature = issuer.sign_detached(&receipt_bytes);
        Ok(SignedContributionReceipt {
            receipt: self.clone(),
            receipt_bytes,
            signature,
        })
    }

    /// The commitment-derived receipt id: SHA-256 over the exact
    /// canonical receipt bytes (L013 — the receipt IS the named object;
    /// caller-selected ids are impossible by construction).
    pub fn receipt_id(&self) -> [u8; 32] {
        receipt_id_of(&self.to_wire_bytes())
    }

    /// The canonical CBOR wire form (the registry schema).
    pub fn to_wire(&self) -> Value {
        Value::Map(vec![
            (Value::Int(1), Value::Int(CONTRIBUTION_SCHEME_VERSION)),
            (Value::Int(2), self.issuer.to_wire()),
            (
                Value::Int(3),
                Value::Bytes(self.contributor_node_id.to_vec()),
            ),
            (Value::Int(4), Value::Bytes(self.content_id.to_vec())),
            (Value::Int(5), Value::Text(self.kind.as_str().to_string())),
            (Value::Int(6), Value::Int(self.delivered_bytes as i64)),
            (Value::Int(7), Value::Int(self.receipt_seq as i64)),
            (Value::Int(8), Value::Int(self.issued_at_unix as i64)),
        ])
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ReceiptError> {
        let v = decode(bytes).map_err(|e| ReceiptError::Cbor(e.to_string()))?;
        Self::from_wire(&v)
    }

    /// Strict parse with the full parse-time invariant set (mirrors
    /// [`Self::new`]; anything else is refused — no lenient forms).
    pub fn from_wire(v: &Value) -> Result<Self, ReceiptError> {
        let Value::Map(entries) = v else {
            return Err(ReceiptError::NotAMap);
        };
        let mut scheme: Option<i64> = None;
        let mut issuer: Option<NodeIdentity> = None;
        let mut contributor: Option<[u8; 32]> = None;
        let mut content_id: Option<[u8; 32]> = None;
        let mut kind: Option<ContributionKind> = None;
        let mut delivered_bytes: Option<u64> = None;
        let mut receipt_seq: Option<u64> = None;
        let mut issued_at: Option<u64> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(ReceiptError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(ReceiptError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(ReceiptError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != CONTRIBUTION_SCHEME_VERSION {
                        return Err(ReceiptError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if issuer.is_some() {
                        return Err(ReceiptError::DuplicateField { key: 2 });
                    }
                    issuer = Some(NodeIdentity::from_wire(val).map_err(ReceiptError::Identity)?);
                }
                3 => {
                    if contributor.is_some() {
                        return Err(ReceiptError::DuplicateField { key: 3 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(ReceiptError::FieldNotExpectedType { key: 3 });
                    };
                    if b.len() != 32 {
                        return Err(ReceiptError::ContributorIdWrongLength { len: b.len() });
                    }
                    contributor = Some(b.as_slice().try_into().expect("checked"));
                }
                4 => {
                    if content_id.is_some() {
                        return Err(ReceiptError::DuplicateField { key: 4 });
                    }
                    let Value::Bytes(b) = val else {
                        return Err(ReceiptError::FieldNotExpectedType { key: 4 });
                    };
                    if b.len() != 32 {
                        return Err(ReceiptError::ContentIdWrongLength { len: b.len() });
                    }
                    content_id = Some(b.as_slice().try_into().expect("checked"));
                }
                5 => {
                    if kind.is_some() {
                        return Err(ReceiptError::DuplicateField { key: 5 });
                    }
                    let Value::Text(t) = val else {
                        return Err(ReceiptError::FieldNotExpectedType { key: 5 });
                    };
                    kind = Some(
                        ContributionKind::from_name(t)
                            .ok_or_else(|| ReceiptError::KindUnknown { found: t.clone() })?,
                    );
                }
                6 => {
                    if delivered_bytes.is_some() {
                        return Err(ReceiptError::DuplicateField { key: 6 });
                    }
                    let Value::Int(n) = val else {
                        return Err(ReceiptError::FieldNotExpectedType { key: 6 });
                    };
                    let n = u64::try_from(*n)
                        .map_err(|_| ReceiptError::DeliveredBytesOutOfRange { found: *n })?;
                    if n == 0 || n > DELIVERED_BYTES_MAX {
                        return Err(ReceiptError::DeliveredBytesOutOfRange { found: n as i64 });
                    }
                    delivered_bytes = Some(n);
                }
                7 => {
                    if receipt_seq.is_some() {
                        return Err(ReceiptError::DuplicateField { key: 7 });
                    }
                    let Value::Int(n) = val else {
                        return Err(ReceiptError::FieldNotExpectedType { key: 7 });
                    };
                    let n = u64::try_from(*n)
                        .map_err(|_| ReceiptError::ReceiptSeqInvalid { found: *n })?;
                    if n < RECEIPT_SEQ_MIN {
                        return Err(ReceiptError::ReceiptSeqInvalid { found: n as i64 });
                    }
                    receipt_seq = Some(n);
                }
                8 => {
                    if issued_at.is_some() {
                        return Err(ReceiptError::DuplicateField { key: 8 });
                    }
                    let Value::Int(t) = val else {
                        return Err(ReceiptError::FieldNotExpectedType { key: 8 });
                    };
                    let t = u64::try_from(*t).map_err(|_| ReceiptError::TimestampOutOfRange)?;
                    issued_at = Some(t);
                }
                other => return Err(ReceiptError::UnknownField { key: other }),
            }
        }
        let _ = scheme;
        let issuer = issuer.ok_or(ReceiptError::MissingField { key: 2 })?;
        let contributor = contributor.ok_or(ReceiptError::MissingField { key: 3 })?;
        let content_id = content_id.ok_or(ReceiptError::MissingField { key: 4 })?;
        let kind = kind.ok_or(ReceiptError::MissingField { key: 5 })?;
        let delivered_bytes = delivered_bytes.ok_or(ReceiptError::MissingField { key: 6 })?;
        let receipt_seq = receipt_seq.ok_or(ReceiptError::MissingField { key: 7 })?;
        let issued_at = issued_at.ok_or(ReceiptError::MissingField { key: 8 })?;
        // Parse-time enforcement of the same invariants as construction.
        if contributor == *issuer.node_id().as_bytes() {
            return Err(ReceiptError::SelfReceipt {
                issuer: issuer.node_id().to_hex(),
                contributor: NodeId::from_bytes(contributor).to_hex(),
            });
        }
        if issued_at > i64::MAX as u64 {
            return Err(ReceiptError::TimestampOutOfRange);
        }
        Ok(ContributionReceipt {
            issuer,
            contributor_node_id: contributor,
            content_id,
            kind,
            delivered_bytes,
            receipt_seq,
            issued_at_unix: issued_at,
        })
    }

    pub fn issuer_identity(&self) -> &NodeIdentity {
        &self.issuer
    }
    /// The R1-001 derived node id of the issuer (the receiving signer).
    pub fn issuer_node_id(&self) -> NodeId {
        self.issuer.node_id()
    }
    pub fn contributor_node_id(&self) -> &[u8; 32] {
        &self.contributor_node_id
    }
    pub fn content_id(&self) -> &[u8; 32] {
        &self.content_id
    }
    pub fn kind(&self) -> ContributionKind {
        self.kind
    }
    pub fn delivered_bytes(&self) -> u64 {
        self.delivered_bytes
    }
    pub fn receipt_seq(&self) -> u64 {
        self.receipt_seq
    }
    pub fn issued_at_unix(&self) -> u64 {
        self.issued_at_unix
    }

    /// Verify the receipt against the manifest of the content it names
    /// (the registry's delivered_bytes rule: "the issuer counts what it
    /// actually received, verified against the content_id's manifest
    /// total when the manifest is in hand").
    ///
    /// A caller-side verification, NOT a ledger admission requirement —
    /// the ledger cannot require every manifest; whoever holds the
    /// manifest can make this check fail-closed.
    pub fn check_against_manifest(&self, manifest: &ContentManifest) -> Result<(), ReceiptError> {
        if manifest.content_id() != self.content_id {
            return Err(ReceiptError::ContentIdMismatch {
                receipt: NodeId::from_bytes(self.content_id).to_hex(),
                manifest: NodeId::from_bytes(manifest.content_id()).to_hex(),
            });
        }
        if self.delivered_bytes > manifest.total_length() {
            return Err(ReceiptError::DeliveredBytesExceedsTotal {
                delivered: self.delivered_bytes,
                total: manifest.total_length(),
            });
        }
        Ok(())
    }
}

/// receipt_id = SHA-256(canonical receipt bytes) — the shared derivation
/// (L013).
fn receipt_id_of(receipt_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(receipt_bytes);
    hasher.finalize().into()
}

// ---------------------------------------------------------------------------
// SignedContributionReceipt (the verified carrying form)
// ---------------------------------------------------------------------------

/// A signed contribution receipt in its carrying envelope — parse +
/// signature are verified on construction (the only ways to obtain one
/// are [`ContributionReceipt::sign`] and
/// [`SignedContributionReceipt::from_envelope_bytes`], so the type is
/// always trustworthy; ledger admission still checks everything that
/// needs external state — the verifying clock and the sequence law).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedContributionReceipt {
    receipt: ContributionReceipt,
    receipt_bytes: Vec<u8>,
    signature: [u8; 64],
}

impl SignedContributionReceipt {
    /// The carrying envelope bytes (canonical CBOR
    /// `{1: receipt (bstr), 2: signature (64-byte bstr)}`).
    pub fn to_envelope_bytes(&self) -> Vec<u8> {
        encode(&Value::Map(vec![
            (Value::Int(1), Value::Bytes(self.receipt_bytes.clone())),
            (Value::Int(2), Value::Bytes(self.signature.to_vec())),
        ]))
        .expect("in-profile")
    }

    /// Strict parse of the carrying envelope + the inner receipt + the
    /// issuer's signature over the exact canonical bytes
    /// (self-certifying: the key is inside the signed bytes).
    pub fn from_envelope_bytes(bytes: &[u8]) -> Result<Self, ReceiptError> {
        let v = decode(bytes).map_err(|e| ReceiptError::Cbor(e.to_string()))?;
        let Value::Map(entries) = &v else {
            return Err(ReceiptError::NotAMap);
        };
        if entries.len() != 2 {
            return Err(ReceiptError::EnvelopeWrongEntryCount {
                count: entries.len(),
            });
        }
        let mut receipt_bytes: Option<Vec<u8>> = None;
        let mut signature: Option<[u8; 64]> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(ReceiptError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    let Value::Bytes(b) = val else {
                        return Err(ReceiptError::FieldNotExpectedType { key: 1 });
                    };
                    if receipt_bytes.is_some() {
                        return Err(ReceiptError::DuplicateField { key: 1 });
                    }
                    receipt_bytes = Some(b.clone());
                }
                2 => {
                    let Value::Bytes(b) = val else {
                        return Err(ReceiptError::FieldNotExpectedType { key: 2 });
                    };
                    if b.len() != 64 {
                        return Err(ReceiptError::SignatureWrongLength { len: b.len() });
                    }
                    if signature.is_some() {
                        return Err(ReceiptError::DuplicateField { key: 2 });
                    }
                    signature = Some(b.as_slice().try_into().expect("checked"));
                }
                other => return Err(ReceiptError::UnknownField { key: other }),
            }
        }
        let receipt_bytes = receipt_bytes.ok_or(ReceiptError::MissingField { key: 1 })?;
        let signature = signature.ok_or(ReceiptError::MissingField { key: 2 })?;
        let receipt = ContributionReceipt::from_wire_bytes(&receipt_bytes)?;
        receipt
            .issuer_identity()
            .verify_detached(&receipt_bytes, &signature)
            .map_err(|_| ReceiptError::SignatureInvalid)?;
        Ok(SignedContributionReceipt {
            receipt,
            receipt_bytes,
            signature,
        })
    }

    /// Re-assemble from verified parts (the conformance harness paths).
    pub fn from_parts(receipt: ContributionReceipt, signature: [u8; 64]) -> Self {
        let receipt_bytes = receipt.to_wire_bytes();
        SignedContributionReceipt {
            receipt,
            receipt_bytes,
            signature,
        }
    }

    pub fn receipt(&self) -> &ContributionReceipt {
        &self.receipt
    }
    /// The exact canonical receipt bytes that were signed.
    pub fn receipt_bytes(&self) -> &[u8] {
        &self.receipt_bytes
    }
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }
    /// The commitment-derived receipt id over the exact signed bytes.
    pub fn receipt_id(&self) -> [u8; 32] {
        receipt_id_of(&self.receipt_bytes)
    }

    /// The route-family envelope form (for cross-object interop paths
    /// that consume `SignedEnvelope`).
    pub fn to_signed_envelope(&self) -> SignedEnvelope {
        SignedEnvelope::new(self.receipt_bytes.clone(), self.signature)
    }
}

// ---------------------------------------------------------------------------
// ReceiptLedger (the durable integration)
// ---------------------------------------------------------------------------

/// The outcome of admitting a receipt to the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptAdmitOutcome {
    /// The receipt verified and its sequence advanced the
    /// (issuer, contributor) pair's high-water mark — recorded.
    Admitted,
    /// An identical `receipt_id` is already recorded — idempotent (the
    /// first recorded receipt wins; the duplicate is dropped, no state
    /// moved). The registry: "identical receipt_ids are idempotent".
    Duplicate,
}

impl ReceiptAdmitOutcome {
    /// Stable machine name (vectors + harness).
    pub fn as_str(&self) -> &'static str {
        match self {
            ReceiptAdmitOutcome::Admitted => "admitted",
            ReceiptAdmitOutcome::Duplicate => "duplicate",
        }
    }
}

/// One recorded receipt (the durable record's in-memory form).
#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedReceipt {
    receipt_seq: u64,
    receipt_id: [u8; 32],
    signed: SignedContributionReceipt,
}

/// The shared durable state (the ledger clones cheaply and every clone
/// sees the same authoritative view).
#[derive(Debug, Default)]
struct LedgerShared {
    state: Mutex<LedgerState>,
}

#[derive(Debug, Default)]
struct LedgerState {
    /// (issuer node_id, contributor node_id) -> recorded receipts, in
    /// admission order (which is strictly ascending receipt_seq, by the
    /// sequence law).
    pairs: BTreeMap<([u8; 32], [u8; 32]), Vec<RecordedReceipt>>,
    /// Every recorded receipt_id — the cross-pair idempotency key (the
    /// bytes are the identity, L013).
    receipt_ids: HashSet<[u8; 32]>,
}

/// The contribution-receipt ledger — the replay-safe admission authority
/// (the R7-001 `RevocationLedger` pattern).
///
/// - **Admission** ([`Self::admit`]): the signed form's invariant
///   (strict parse + issuer node_id derivation + signature +
///   self-receipt exclusion + frozen kind set — all verified at
///   [`SignedContributionReceipt`] construction) plus the two checks
///   that need the verifying clock and the ledger state: `issued_at`
///   not in the future, then the PER-(issuer, contributor) monotonic
///   sequence law. No caller-controlled trust booleans anywhere.
/// - **Idempotency** (durable, §14): per receipt_id — the exact same
///   envelope re-delivered is a no-op `Duplicate` (the first recorded
///   receipt wins); a DIFFERENT receipt whose sequence number repeats
///   or regresses below the pair's high-water mark is refused typed
///   (`sequence_regressed`).
/// - **Offline-first** (§15): admission is pure local computation over
///   the caller-supplied clock — no ADCOS dependency.
/// - **Persistence seam**: [`Self::to_snapshot_bytes`] /
///   [`Self::from_snapshot_bytes`] (see the module docs for the honest
///   scope: full durable files are the R8-002+ consuming layer).
#[derive(Debug, Clone, Default)]
pub struct ReceiptLedger {
    shared: Arc<LedgerShared>,
}

impl ReceiptLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Admit a verified receipt envelope (strict parse + signature
    /// verified inside; then the clock and sequence-law checks).
    pub fn admit_envelope(
        &self,
        now_unix: u64,
        envelope_bytes: &[u8],
    ) -> Result<ReceiptAdmitOutcome, ReceiptError> {
        let signed = SignedContributionReceipt::from_envelope_bytes(envelope_bytes)?;
        self.admit(now_unix, &signed)
    }

    /// Admit an already-verified signed receipt (the verification
    /// happened at [`SignedContributionReceipt`] construction; this
    /// checks everything that needs external state).
    ///
    /// Evaluation order (deterministic, the registry's order): the
    /// future check first, then receipt_id idempotency, then the
    /// sequence law — an identical re-delivery is `Duplicate`, a
    /// different receipt at a repeated/regressed sequence is refused
    /// typed.
    pub fn admit(
        &self,
        now_unix: u64,
        signed: &SignedContributionReceipt,
    ) -> Result<ReceiptAdmitOutcome, ReceiptError> {
        let receipt = signed.receipt();
        // 1. the verifying clock: a future-dated receipt is refused
        //    typed (nothing recorded).
        let issued_at = receipt.issued_at_unix();
        if issued_at > now_unix {
            return Err(ReceiptError::IssuedAtInFuture {
                issued_at,
                now: now_unix,
            });
        }
        let receipt_id = signed.receipt_id();
        let pair = (
            *receipt.issuer_node_id().as_bytes(),
            *receipt.contributor_node_id(),
        );
        let mut state = self
            .shared
            .state
            .lock()
            .expect("receipt ledger lock poisoned (a panic occurred mid-admission)");
        // 2. durable idempotency by receipt_id: the first recorded
        //    receipt wins; the re-delivery is a no-op.
        if state.receipt_ids.contains(&receipt_id) {
            return Ok(ReceiptAdmitOutcome::Duplicate);
        }
        // 3. the per-(issuer, contributor) monotonic sequence law.
        if let Some(recorded) = state.pairs.get(&pair) {
            if let Some(last) = recorded.last() {
                if receipt.receipt_seq() <= last.receipt_seq {
                    return Err(ReceiptError::SequenceRegressed {
                        found: receipt.receipt_seq(),
                        last: last.receipt_seq,
                    });
                }
            }
        }
        state.pairs.entry(pair).or_default().push(RecordedReceipt {
            receipt_seq: receipt.receipt_seq(),
            receipt_id,
            signed: signed.clone(),
        });
        state.receipt_ids.insert(receipt_id);
        Ok(ReceiptAdmitOutcome::Admitted)
    }

    /// The pair's high-water sequence — what the ISSUER consults before
    /// issuing its next receipt (`next = last + 1`).
    pub fn last_seq(&self, issuer: &NodeId, contributor: &[u8; 32]) -> Option<u64> {
        let state = self
            .shared
            .state
            .lock()
            .expect("receipt ledger lock poisoned (a panic occurred mid-admission)");
        state
            .pairs
            .get(&(*issuer.as_bytes(), *contributor))
            .and_then(|v| v.last())
            .map(|r| r.receipt_seq)
    }

    /// How many receipts the ledger holds for one (issuer, contributor)
    /// pair.
    pub fn receipts_for(&self, issuer: &NodeId, contributor: &[u8; 32]) -> usize {
        let state = self
            .shared
            .state
            .lock()
            .expect("receipt ledger lock poisoned (a panic occurred mid-admission)");
        state
            .pairs
            .get(&(*issuer.as_bytes(), *contributor))
            .map_or(0, |v| v.len())
    }

    /// The total number of recorded receipts.
    pub fn receipt_count(&self) -> usize {
        let state = self
            .shared
            .state
            .lock()
            .expect("receipt ledger lock poisoned (a panic occurred mid-admission)");
        state.pairs.values().map(Vec::len).sum()
    }

    /// Whether a receipt_id is already recorded (the idempotency key).
    pub fn contains_receipt_id(&self, receipt_id: &[u8; 32]) -> bool {
        let state = self
            .shared
            .state
            .lock()
            .expect("receipt ledger lock poisoned (a panic occurred mid-admission)");
        state.receipt_ids.contains(receipt_id)
    }

    /// Serialize the durable state (the persistence seam). Canonical
    /// form: `{1: version (=1), 2: [carrying-envelope bstrs]}` with the
    /// records in ascending `(issuer node_id, contributor node_id,
    /// receipt_seq)` order — the BTreeMap's bytewise pair order plus the
    /// sequence law's admission-ascending per-pair sequence make the
    /// natural iteration already canonical (no explicit sort needed —
    /// and one sorted on seq alone would be WRONG across pairs).
    /// Deterministic for equal logical state.
    pub fn to_snapshot_bytes(&self) -> Vec<u8> {
        let state = self
            .shared
            .state
            .lock()
            .expect("receipt ledger lock poisoned (a panic occurred mid-admission)");
        let envelopes: Vec<Value> = state
            .pairs
            .values()
            .flatten()
            .map(|r| Value::Bytes(r.signed.to_envelope_bytes()))
            .collect();
        encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(CONTRIBUTION_SNAPSHOT_VERSION)),
            (Value::Int(2), Value::Array(envelopes)),
        ]))
        .expect("in-profile")
    }

    /// Restore from a snapshot (the persistence seam): every record is
    /// RE-PARSED and its signature RE-VERIFIED (fail-closed on any
    /// tamper); canonical record order (ascending
    /// (issuer, contributor, receipt_seq)) and receipt_id uniqueness
    /// are enforced. See the module docs for what the seam honestly
    /// does NOT protect (whole-record deletion — the durable layer must
    /// close that with append-only storage).
    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, ReceiptError> {
        let v = decode(bytes).map_err(|e| ReceiptError::Cbor(e.to_string()))?;
        let Value::Map(entries) = &v else {
            return Err(ReceiptError::NotAMap);
        };
        if entries.len() != 2 {
            return Err(ReceiptError::EnvelopeWrongEntryCount {
                count: entries.len(),
            });
        }
        let mut version: Option<i64> = None;
        let mut envelopes: Option<&Vec<Value>> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(ReceiptError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    let Value::Int(s) = val else {
                        return Err(ReceiptError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != CONTRIBUTION_SNAPSHOT_VERSION {
                        return Err(ReceiptError::SchemeVersionUnsupported { found: *s });
                    }
                    version = Some(*s);
                }
                2 => {
                    let Value::Array(items) = val else {
                        return Err(ReceiptError::FieldNotExpectedType { key: 2 });
                    };
                    envelopes = Some(items);
                }
                other => return Err(ReceiptError::UnknownField { key: other }),
            }
        }
        let _ = version;
        let envelopes = envelopes.ok_or(ReceiptError::MissingField { key: 2 })?;
        let ledger = ReceiptLedger::new();
        {
            let mut state = ledger
                .shared
                .state
                .lock()
                .expect("receipt ledger lock poisoned (a panic occurred mid-admission)");
            let mut seen_ids: HashSet<[u8; 32]> = HashSet::new();
            let mut last_key: Option<([u8; 32], [u8; 32], u64)> = None;
            for item in envelopes {
                let Value::Bytes(env_bytes) = item else {
                    return Err(ReceiptError::FieldNotExpectedType { key: 2 });
                };
                // Full fail-closed re-verification of every record.
                let signed = SignedContributionReceipt::from_envelope_bytes(env_bytes)?;
                let receipt = signed.receipt();
                let key = (
                    *receipt.issuer_node_id().as_bytes(),
                    *receipt.contributor_node_id(),
                    receipt.receipt_seq(),
                );
                let receipt_id = signed.receipt_id();
                if !seen_ids.insert(receipt_id) {
                    return Err(ReceiptError::SnapshotDuplicateRecord);
                }
                if let Some(prev) = last_key {
                    if prev >= key {
                        return Err(ReceiptError::SnapshotOrderInvalid);
                    }
                }
                last_key = Some(key);
                state
                    .pairs
                    .entry((key.0, key.1))
                    .or_default()
                    .push(RecordedReceipt {
                        receipt_seq: key.2,
                        receipt_id,
                        signed,
                    });
                state.receipt_ids.insert(receipt_id);
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

    fn ident(seed: u8, created: u64) -> Identity {
        Identity::from_seed([seed; 32], created, None).expect("identity")
    }

    fn manifest(now: u64) -> ContentManifest {
        ContentManifest::chunk(
            b"0123456789abcdefg",
            7,
            "application/octet-stream",
            None,
            now,
        )
        .expect("manifest")
        .0
    }

    fn receipt(
        issuer: &Identity,
        contributor: &Identity,
        content_id: [u8; 32],
        kind: ContributionKind,
        delivered_bytes: u64,
        seq: u64,
        issued_at: u64,
    ) -> Result<ContributionReceipt, ReceiptError> {
        ContributionReceipt::new(
            issuer,
            *contributor.node_id().as_bytes(),
            content_id,
            kind,
            delivered_bytes,
            seq,
            issued_at,
        )
    }

    #[test]
    fn kind_vocabulary_round_trip() {
        for kind in ContributionKind::ALL {
            assert_eq!(ContributionKind::from_name(kind.as_str()), Some(kind));
        }
        assert_eq!(ContributionKind::from_name("relayed"), None);
        assert_eq!(ContributionKind::from_name(""), None);
        assert_eq!(
            CONTRIBUTION_KINDS,
            ContributionKind::ALL.map(|k| k.as_str())
        );
    }

    #[test]
    fn wire_round_trip_and_byte_stability() {
        let now = 1_700_000_000u64;
        let issuer = ident(0x11, now);
        let contributor = ident(0x22, now);
        let manifest = manifest(now);
        for kind in ContributionKind::ALL {
            let r = receipt(
                &issuer,
                &contributor,
                manifest.content_id(),
                kind,
                18,
                3,
                now + 10,
            )
            .expect("build");
            let signed = r.sign(&issuer).expect("sign");
            let bytes = signed.to_envelope_bytes();
            let parsed = SignedContributionReceipt::from_envelope_bytes(&bytes).expect("parse");
            assert_eq!(parsed.receipt().kind(), kind);
            assert_eq!(
                parsed.receipt().contributor_node_id(),
                contributor.node_id().as_bytes()
            );
            assert_eq!(parsed.receipt().content_id(), &manifest.content_id());
            assert_eq!(parsed.receipt().delivered_bytes(), 18);
            assert_eq!(parsed.receipt().receipt_seq(), 3);
            assert_eq!(parsed.receipt().issued_at_unix(), now + 10);
            // byte-stability: re-encode is identical
            assert_eq!(parsed.to_envelope_bytes(), bytes);
            // the receipt_id is stable across the round trip
            assert_eq!(parsed.receipt_id(), signed.receipt_id());
        }
    }

    #[test]
    fn receipt_id_is_commitment_derived() {
        let now = 1_700_000_000u64;
        let issuer = ident(0x11, now);
        let contributor = ident(0x22, now);
        let manifest = manifest(now);
        let base = receipt(
            &issuer,
            &contributor,
            manifest.content_id(),
            ContributionKind::Carried,
            18,
            1,
            now,
        )
        .expect("build");
        // exactly SHA-256 over the canonical bytes (independent recompute)
        let mut hasher = Sha256::new();
        hasher.update(base.to_wire_bytes());
        let expect: [u8; 32] = hasher.finalize().into();
        assert_eq!(base.receipt_id(), expect);
        // byte-identical receipts are the same named object
        let same = receipt(
            &issuer,
            &contributor,
            manifest.content_id(),
            ContributionKind::Carried,
            18,
            1,
            now,
        )
        .expect("build");
        assert_eq!(base.receipt_id(), same.receipt_id());
        // any changed field is a different named object
        let variants = vec![
            receipt(
                &issuer,
                &ident(0x33, now),
                manifest.content_id(),
                ContributionKind::Carried,
                18,
                1,
                now,
            )
            .unwrap(),
            receipt(
                &issuer,
                &contributor,
                [0xAB; 32],
                ContributionKind::Carried,
                18,
                1,
                now,
            )
            .unwrap(),
            receipt(
                &issuer,
                &contributor,
                manifest.content_id(),
                ContributionKind::Delivered,
                18,
                1,
                now,
            )
            .unwrap(),
            receipt(
                &issuer,
                &contributor,
                manifest.content_id(),
                ContributionKind::Carried,
                9,
                1,
                now,
            )
            .unwrap(),
            receipt(
                &issuer,
                &contributor,
                manifest.content_id(),
                ContributionKind::Carried,
                18,
                2,
                now,
            )
            .unwrap(),
            receipt(
                &issuer,
                &contributor,
                manifest.content_id(),
                ContributionKind::Carried,
                18,
                1,
                now + 1,
            )
            .unwrap(),
        ];
        for v in variants {
            assert_ne!(base.receipt_id(), v.receipt_id());
        }
    }

    #[test]
    fn construction_invariants_typed() {
        let now = 1_700_000_000u64;
        let issuer = ident(0x11, now);
        let contributor = ident(0x22, now);
        let content_id = manifest(now).content_id();
        let build = |contributor: &Identity, bytes: u64, seq: u64, issued_at: u64| {
            receipt(
                &issuer,
                contributor,
                content_id,
                ContributionKind::Carried,
                bytes,
                seq,
                issued_at,
            )
        };
        // the self-receipt exclusion
        assert_eq!(
            build(&issuer, 18, 1, now).unwrap_err().name(),
            "self_receipt"
        );
        // delivered_bytes bounds (0 and 2^40 + 1)
        assert_eq!(
            build(&contributor, 0, 1, now).unwrap_err().name(),
            "delivered_bytes_out_of_range"
        );
        assert_eq!(
            build(&contributor, DELIVERED_BYTES_MAX + 1, 1, now)
                .unwrap_err()
                .name(),
            "delivered_bytes_out_of_range"
        );
        // the boundary itself is legal
        assert!(build(&contributor, DELIVERED_BYTES_MAX, 1, now).is_ok());
        // receipt_seq minimum
        assert_eq!(
            build(&contributor, 18, 0, now).unwrap_err().name(),
            "receipt_seq_invalid"
        );
        // issued_at out of the canonical integer range
        assert_eq!(
            build(&contributor, 18, 1, i64::MAX as u64 + 1)
                .unwrap_err()
                .name(),
            "timestamp_out_of_range"
        );
    }

    #[test]
    fn ledger_enforces_the_sequence_law() {
        let now = 1_700_000_000u64;
        let issuer = ident(0x11, now);
        let contributor = ident(0x22, now);
        let content_id = manifest(now).content_id();
        let ledger = ReceiptLedger::new();
        let mk = |seq: u64| {
            receipt(
                &issuer,
                &contributor,
                content_id,
                ContributionKind::Carried,
                18,
                seq,
                now,
            )
            .expect("build")
            .sign(&issuer)
            .expect("sign")
        };
        // first admission at seq 1
        let first = mk(1);
        assert_eq!(
            ledger.admit(now, &first).unwrap(),
            ReceiptAdmitOutcome::Admitted
        );
        assert_eq!(
            ledger.last_seq(&issuer.node_id(), contributor.node_id().as_bytes()),
            Some(1)
        );
        // the identical envelope re-delivered: idempotent
        assert_eq!(
            ledger.admit(now + 1, &first).unwrap(),
            ReceiptAdmitOutcome::Duplicate
        );
        // a DIFFERENT receipt at the same seq: refused typed
        let replay = receipt(
            &issuer,
            &contributor,
            content_id,
            ContributionKind::Carried,
            9,
            1,
            now,
        )
        .expect("build")
        .sign(&issuer)
        .expect("sign");
        assert_eq!(
            ledger.admit(now, &replay).unwrap_err().name(),
            "sequence_regressed"
        );
        // a regressed seq (below the high-water): refused typed — a
        // DIFFERENT receipt (distinct bytes -> distinct receipt_id) at
        // a lower sequence; re-delivering `mk(1)`'s exact bytes would
        // be the idempotent Duplicate instead
        assert_eq!(
            ledger.admit(now, &mk(2)).unwrap(),
            ReceiptAdmitOutcome::Admitted
        );
        assert_eq!(
            ledger.last_seq(&issuer.node_id(), contributor.node_id().as_bytes()),
            Some(2)
        );
        let regressed = receipt(
            &issuer,
            &contributor,
            content_id,
            ContributionKind::Carried,
            9,
            1,
            now,
        )
        .expect("build")
        .sign(&issuer)
        .expect("sign");
        assert_eq!(
            ledger.admit(now, &regressed).unwrap_err().name(),
            "sequence_regressed"
        );
        // a skipped-forward seq is legal (strictly greater, not +1)
        assert_eq!(
            ledger.admit(now, &mk(5)).unwrap(),
            ReceiptAdmitOutcome::Admitted
        );
        assert_eq!(
            ledger.receipts_for(&issuer.node_id(), contributor.node_id().as_bytes()),
            3
        );
        assert_eq!(ledger.receipt_count(), 3);
        // the receipt_id set drives the idempotency (cross-check)
        assert!(ledger.contains_receipt_id(&first.receipt_id()));
    }

    #[test]
    fn ledger_sequence_namespaces_are_per_pair() {
        let now = 1_700_000_000u64;
        let issuer = ident(0x11, now);
        let other_issuer = ident(0x22, now);
        let contributor = ident(0x33, now);
        let other_contributor = ident(0x44, now);
        let content_id = manifest(now).content_id();
        let ledger = ReceiptLedger::new();
        let mk = |issuer: &Identity, contributor: &Identity, seq: u64| {
            receipt(
                issuer,
                contributor,
                content_id,
                ContributionKind::Carried,
                18,
                seq,
                now,
            )
            .expect("build")
            .sign(issuer)
            .expect("sign")
        };
        // the same seq 1 from one issuer to two different contributors
        assert_eq!(
            ledger.admit(now, &mk(&issuer, &contributor, 1)).unwrap(),
            ReceiptAdmitOutcome::Admitted
        );
        assert_eq!(
            ledger
                .admit(now, &mk(&issuer, &other_contributor, 1))
                .unwrap(),
            ReceiptAdmitOutcome::Admitted
        );
        // the same seq 1 from a different issuer to the same contributor
        assert_eq!(
            ledger
                .admit(now, &mk(&other_issuer, &contributor, 1))
                .unwrap(),
            ReceiptAdmitOutcome::Admitted
        );
        // all three namespaces advanced independently
        assert_eq!(
            ledger.last_seq(&issuer.node_id(), contributor.node_id().as_bytes()),
            Some(1)
        );
        assert_eq!(
            ledger.last_seq(&issuer.node_id(), other_contributor.node_id().as_bytes()),
            Some(1)
        );
        assert_eq!(
            ledger.last_seq(&other_issuer.node_id(), contributor.node_id().as_bytes()),
            Some(1)
        );
        assert_eq!(ledger.receipt_count(), 3);
    }

    #[test]
    fn future_receipt_refused_and_records_nothing() {
        let now = 1_700_000_000u64;
        let issuer = ident(0x11, now);
        let contributor = ident(0x22, now);
        let content_id = manifest(now).content_id();
        let ledger = ReceiptLedger::new();
        let signed = receipt(
            &issuer,
            &contributor,
            content_id,
            ContributionKind::Delivered,
            18,
            1,
            now + 100,
        )
        .expect("build")
        .sign(&issuer)
        .expect("sign");
        // refused at a clock before issued_at
        assert_eq!(
            ledger.admit(now, &signed).unwrap_err().name(),
            "issued_at_in_future"
        );
        assert_eq!(ledger.receipt_count(), 0);
        // nothing was recorded: the same clock refuses again
        assert_eq!(
            ledger.admit(now + 1, &signed).unwrap_err().name(),
            "issued_at_in_future"
        );
        // once the clock reaches issued_at it admits (parse accepts the
        // timestamp; only the verifying clock refuses)
        assert_eq!(
            ledger.admit(now + 100, &signed).unwrap(),
            ReceiptAdmitOutcome::Admitted
        );
        // and from then on it is idempotent
        assert_eq!(
            ledger.admit(now + 200, &signed).unwrap(),
            ReceiptAdmitOutcome::Duplicate
        );
    }

    #[test]
    fn signer_binding_enforced() {
        let now = 1_700_000_000u64;
        let issuer = ident(0x11, now);
        let not_the_issuer = ident(0x22, now);
        let contributor = ident(0x33, now);
        let content_id = manifest(now).content_id();
        let r = receipt(
            &issuer,
            &contributor,
            content_id,
            ContributionKind::Carried,
            18,
            1,
            now,
        )
        .expect("build");
        // only the issuer (the recipient) may sign the acknowledgement
        assert_eq!(
            r.sign(&not_the_issuer).unwrap_err().name(),
            "signer_mismatch"
        );
    }

    #[test]
    fn snapshot_round_trip_is_deterministic_and_fail_closed() {
        let now = 1_700_000_000u64;
        let issuer = ident(0x11, now);
        let other_issuer = ident(0x22, now);
        let contributor = ident(0x33, now);
        let content_id = manifest(now).content_id();
        let ledger = ReceiptLedger::new();
        for (issuer, seqs) in [(&issuer, vec![1, 2]), (&other_issuer, vec![1, 4])] {
            for seq in seqs {
                let signed = receipt(
                    issuer,
                    &contributor,
                    content_id,
                    ContributionKind::Carried,
                    18,
                    seq,
                    now,
                )
                .expect("build")
                .sign(issuer)
                .expect("sign");
                ledger.admit(now, &signed).expect("admit");
            }
        }
        let snapshot = ledger.to_snapshot_bytes();
        // round-trip: the restored ledger answers the same queries
        let restored = ReceiptLedger::from_snapshot_bytes(&snapshot).expect("restore");
        assert_eq!(restored.receipt_count(), 4);
        assert_eq!(
            restored.last_seq(&issuer.node_id(), contributor.node_id().as_bytes()),
            Some(2)
        );
        assert_eq!(
            restored.last_seq(&other_issuer.node_id(), contributor.node_id().as_bytes()),
            Some(4)
        );
        // determinism: equal logical state -> identical snapshot bytes
        assert_eq!(restored.to_snapshot_bytes(), snapshot);
        // the restored ledger keeps enforcing the sequence law (a
        // DISTINCT receipt at an already-recorded sequence — re-delivering
        // the recorded bytes would be the idempotent Duplicate instead)
        let stale = receipt(
            &issuer,
            &contributor,
            content_id,
            ContributionKind::Carried,
            9,
            2,
            now,
        )
        .expect("build")
        .sign(&issuer)
        .expect("sign");
        assert_eq!(
            restored.admit(now, &stale).unwrap_err().name(),
            "sequence_regressed"
        );
        // a tampered snapshot fails closed (flip one byte)
        let mut tampered = snapshot.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(ReceiptLedger::from_snapshot_bytes(&tampered).is_err());
    }

    #[test]
    fn manifest_binding_checked() {
        let now = 1_700_000_000u64;
        let issuer = ident(0x11, now);
        let contributor = ident(0x22, now);
        let manifest = manifest(now);
        let other =
            ContentManifest::chunk(b"different content entirely", 8, "text/plain", None, now)
                .expect("manifest")
                .0;
        // the receipt names this manifest: full delivery checks out
        // (the test content is 17 bytes)
        let ok = receipt(
            &issuer,
            &contributor,
            manifest.content_id(),
            ContributionKind::Delivered,
            17,
            1,
            now,
        )
        .expect("build");
        assert!(ok.check_against_manifest(&manifest).is_ok());
        // partial custody also checks out (delivered <= total)
        let partial = receipt(
            &issuer,
            &contributor,
            manifest.content_id(),
            ContributionKind::Carried,
            9,
            2,
            now,
        )
        .expect("build");
        assert!(partial.check_against_manifest(&manifest).is_ok());
        // a different manifest: content_id mismatch
        assert_eq!(
            ok.check_against_manifest(&other).unwrap_err().name(),
            "content_id_mismatch"
        );
        // more bytes than the named object holds (17 total)
        let inflated = receipt(
            &issuer,
            &contributor,
            manifest.content_id(),
            ContributionKind::Delivered,
            18,
            3,
            now,
        )
        .expect("build");
        assert_eq!(
            inflated
                .check_against_manifest(&manifest)
                .unwrap_err()
                .name(),
            "delivered_bytes_exceeds_total"
        );
    }
}
