//! Typed errors of the durable recovery layer (stable machine names, the
//! house discipline). Every variant is fail-closed: no partial state is
//! ever served, and no revocation or attempt is ever admitted that could
//! not be made durable.

use std::fmt;
use std::path::PathBuf;

/// Which file operation an I/O error happened at (stable machine names;
/// the OS error is diagnostic detail, excluded from equality).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryIoOp {
    /// Reading a store file (`load`).
    ReadStore,
    /// Writing the append-only ledger record (append + fsync).
    AppendLedger,
    /// Truncating a torn tail found at ledger load (the load-time repair).
    RepairTruncate,
    /// Creating the flush temp file (attempt log).
    WriteTemp,
    /// fsync-ing the flush temp file (attempt log).
    SyncTemp,
    /// Renaming the temp file over the store path (attempt log).
    RenameIntoPlace,
    /// Creating a fresh store file (`create`).
    CreateStore,
}

impl RecoveryIoOp {
    /// Stable machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            RecoveryIoOp::ReadStore => "read_store",
            RecoveryIoOp::AppendLedger => "append_ledger",
            RecoveryIoOp::RepairTruncate => "repair_truncate",
            RecoveryIoOp::WriteTemp => "write_temp",
            RecoveryIoOp::SyncTemp => "sync_temp",
            RecoveryIoOp::RenameIntoPlace => "rename_into_place",
            RecoveryIoOp::CreateStore => "create_store",
        }
    }
}

impl fmt::Display for RecoveryIoOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed failures of the durable recovery layer.
#[derive(Debug)]
pub enum RecoveryError {
    /// Filesystem I/O failed. `source` is diagnostic only (excluded from
    /// `PartialEq` by the accessor discipline; tests assert on
    /// [`Self::name`] and [`Self::op`]).
    Io {
        op: RecoveryIoOp,
        source: std::io::Error,
    },
    /// `create` refuses to clobber an existing file (no silent data
    /// loss); `load` the existing file instead. Names the file.
    StoreAlreadyExists { path: PathBuf },
    /// The file does not start with the expected magic. `which` is
    /// `"ledger"` or `"attempts"`.
    BadMagic { which: &'static str, found: [u8; 4] },
    /// The file's format version is not accepted.
    VersionUnsupported { which: &'static str, found: u16 },
    /// The reserved header flags are nonzero.
    FlagsUnsupported { which: &'static str, found: u16 },
    /// The store file exceeds the hard size cap (bounded durable state).
    StoreTooLarge { which: &'static str, size: u64, max: u64 },
    /// The declared structure does not match the actual bytes
    /// (truncated / partial write / hostile length fields).
    LengthMismatch { which: &'static str, expected: usize, actual: usize },
    /// The file is longer than its declared structure.
    TrailingBytes { which: &'static str, extra: usize },
    /// A CRC-32 mismatch on a NON-final ledger record, or anywhere in
    /// the attempt-log image (the attempt log is a full-image store:
    /// every CRC failure is corruption, never a torn append).
    ChecksumMismatch { which: &'static str, record: usize },
    /// The ledger chain broke at `record`: the stored `prev_chain` does
    /// not equal `SHA-256(chain_context || chain(record-1) || payload(record-1))`.
    /// Deletion, reordering or replay of records — fail closed.
    ChainBroken { record: usize },
    /// A ledger record's envelope failed strict parse/signature
    /// re-verification on a NON-final record (torn tails are handled
    /// by truncation; this is corruption).
    LedgerEnvelopeInvalid { record: usize, source: sharenet_protocol::revocation::RevocationError },
    /// An envelope handed to `admit` failed strict parse or signature
    /// verification — nothing was admitted, nothing was written.
    AdmitEnvelopeInvalid { source: sharenet_protocol::revocation::RevocationError },
    /// The R7-001 admission chain refused the revocation (unknown
    /// circuit, revoker not on the committed path, `revoked_at` in the
    /// future) — nothing was admitted, nothing was written.
    RevocationAdmissionRefused { source: sharenet_protocol::revocation::RevocationError },
    /// The seam round-trip refused the reconstructed snapshot
    /// (order/duplicate/signature cross-checks of R7-001 itself).
    SnapshotInvalid { source: sharenet_protocol::revocation::RevocationError },
    /// A route commitment offered as fresh-route evidence failed
    /// R3-004 verification.
    RouteCommitmentInvalid { source: sharenet_protocol::route::RouteError },
    /// The offered fresh route is not fresh: it was proposed BEFORE the
    /// circuit was revoked (architecture §11 requires a fresh commitment;
    /// the anchor is the revocation's `revoked_at_unix`).
    RouteNotFresh { proposed_at: u64, revoked_at: u64 },
    /// §11 ordering refusal: the circuit is not durably revoked in the
    /// ledger — recovery attempts may only follow durable circuit
    /// invalidation (unknown circuits included).
    CircuitNotRevoked { circuit_id: [u8; 32] },
    /// The circuit's recovery is already complete: a fresh route
    /// commitment was durably recorded. "A failed circuit is never
    /// resurrected" — and a recovered one is not re-recovered (a new
    /// failure of the new circuit is a NEW revocation + NEW recovery).
    RecoveryAlreadyComplete {
        circuit_id: [u8; 32],
        attempt_seq: u64,
        fresh_route_id: [u8; 32],
    },
    /// Another attempt for this circuit is already in flight
    /// (single-flight policy: one pending attempt per revoked circuit).
    AttemptAlreadyPending { circuit_id: [u8; 32], attempt_seq: u64 },
    /// No pending attempt to finish for this circuit.
    NoPendingAttempt { circuit_id: [u8; 32] },
    /// The referenced attempt is not pending (already finished).
    AttemptNotPending {
        circuit_id: [u8; 32],
        attempt_seq: u64,
        state: AttemptStateTag,
    },
    /// The referenced attempt seq does not exist for this circuit
    /// (duplicate or out-of-range seq admission).
    AttemptSeqUnknown { circuit_id: [u8; 32], attempt_seq: u64 },
    /// A persisted attempt record violates the state machine (state tag
    /// vs. outcome fields vs. timestamps).
    AttemptRecordInvalid { what: &'static str },
    /// A persisted attempt sequence is not strictly increasing within
    /// its circuit section, or the circuit's `next_seq` high-water is
    /// behind its retained records.
    AttemptSequenceNotIncreasing { circuit: [u8; 32], previous: u64, next: u64 },
    /// The attempt log contains a succeeded attempt that is not the
    /// last-retained attempt for its circuit (success is terminal: no
    /// attempts may follow it).
    AttemptAfterSuccessPersisted { circuit: [u8; 32], attempt_seq: u64 },
    /// The in-memory state and the just-written durable image disagree —
    /// an internal invariant violation (a bug, surfaced fail-closed).
    InternalInconsistent { what: &'static str },
}

/// The persisted attempt-state tags (shared by the error surface for
/// diagnostics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptStateTag {
    Pending,
    Succeeded,
    Abandoned,
}

impl AttemptStateTag {
    pub fn as_str(&self) -> &'static str {
        match self {
            AttemptStateTag::Pending => "pending",
            AttemptStateTag::Succeeded => "succeeded",
            AttemptStateTag::Abandoned => "abandoned",
        }
    }
}

impl fmt::Display for AttemptStateTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RecoveryError {
    pub(crate) fn io(op: RecoveryIoOp, source: std::io::Error) -> Self {
        RecoveryError::Io { op, source }
    }

    /// Stable machine name (the typed-error discipline of the repo).
    pub fn name(&self) -> &'static str {
        match self {
            RecoveryError::Io { .. } => "recovery_io",
            RecoveryError::StoreAlreadyExists { .. } => "store_already_exists",
            RecoveryError::BadMagic { .. } => "store_bad_magic",
            RecoveryError::VersionUnsupported { .. } => "store_version_unsupported",
            RecoveryError::FlagsUnsupported { .. } => "store_flags_unsupported",
            RecoveryError::StoreTooLarge { .. } => "store_too_large",
            RecoveryError::LengthMismatch { .. } => "store_length_mismatch",
            RecoveryError::TrailingBytes { .. } => "store_trailing_bytes",
            RecoveryError::ChecksumMismatch { .. } => "store_checksum_mismatch",
            RecoveryError::ChainBroken { .. } => "ledger_chain_broken",
            RecoveryError::LedgerEnvelopeInvalid { .. } => "ledger_envelope_invalid",
            RecoveryError::AdmitEnvelopeInvalid { .. } => "admit_envelope_invalid",
            RecoveryError::RevocationAdmissionRefused { .. } => "revocation_admission_refused",
            RecoveryError::SnapshotInvalid { .. } => "ledger_snapshot_invalid",
            RecoveryError::RouteCommitmentInvalid { .. } => "route_commitment_invalid",
            RecoveryError::RouteNotFresh { .. } => "route_not_fresh",
            RecoveryError::CircuitNotRevoked { .. } => "circuit_not_revoked",
            RecoveryError::RecoveryAlreadyComplete { .. } => "recovery_already_complete",
            RecoveryError::AttemptAlreadyPending { .. } => "attempt_already_pending",
            RecoveryError::NoPendingAttempt { .. } => "no_pending_attempt",
            RecoveryError::AttemptNotPending { .. } => "attempt_not_pending",
            RecoveryError::AttemptSeqUnknown { .. } => "attempt_seq_unknown",
            RecoveryError::AttemptRecordInvalid { .. } => "attempt_record_invalid",
            RecoveryError::AttemptSequenceNotIncreasing { .. } => "attempt_sequence_not_increasing",
            RecoveryError::AttemptAfterSuccessPersisted { .. } => "attempt_after_success_persisted",
            RecoveryError::InternalInconsistent { .. } => "internal_inconsistent",
        }
    }

    /// The I/O operation context of an [`RecoveryError::Io`] (diagnostic
    /// accessor; other variants return `None`).
    pub fn op(&self) -> Option<RecoveryIoOp> {
        match self {
            RecoveryError::Io { op, .. } => Some(*op),
            _ => None,
        }
    }
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecoveryError::Io { op, source } => write!(f, "io at {op}: {source}"),
            RecoveryError::StoreAlreadyExists { path } => {
                write!(f, "refusing to clobber existing store file {path:?}")
            }
            RecoveryError::BadMagic { which, found } => {
                write!(f, "{which} file magic wrong: {:02x?}", found)
            }
            RecoveryError::VersionUnsupported { which, found } => {
                write!(f, "{which} file version {found} unsupported")
            }
            RecoveryError::FlagsUnsupported { which, found } => {
                write!(f, "{which} file flags {found} unsupported (must be 0)")
            }
            RecoveryError::StoreTooLarge { which, size, max } => {
                write!(f, "{which} store {size} bytes exceeds cap {max}")
            }
            RecoveryError::LengthMismatch { which, expected, actual } => {
                write!(f, "{which} structure declares {expected} bytes, found {actual}")
            }
            RecoveryError::TrailingBytes { which, extra } => {
                write!(f, "{which} file has {extra} unaccounted trailing bytes")
            }
            RecoveryError::ChecksumMismatch { which, record } => {
                write!(f, "{which} checksum mismatch at record {record}")
            }
            RecoveryError::ChainBroken { record } => {
                write!(f, "ledger chain broken at record {record}")
            }
            RecoveryError::LedgerEnvelopeInvalid { record, source } => {
                write!(f, "ledger record {record} envelope invalid: {source}")
            }
            RecoveryError::AdmitEnvelopeInvalid { source } => {
                write!(f, "admit: revocation envelope invalid: {source}")
            }
            RecoveryError::RevocationAdmissionRefused { source } => {
                write!(f, "admit: the R7-001 chain refused the revocation: {source}")
            }
            RecoveryError::SnapshotInvalid { source } => {
                write!(f, "R7-001 snapshot seam refused the reconstructed ledger: {source}")
            }
            RecoveryError::RouteCommitmentInvalid { source } => {
                write!(f, "fresh-route commitment failed R3-004 verification: {source}")
            }
            RecoveryError::RouteNotFresh { proposed_at, revoked_at } => write!(
                f,
                "route proposed at {proposed_at} predates the revocation at {revoked_at} (not fresh, §11)"
            ),
            RecoveryError::CircuitNotRevoked { circuit_id } => write!(
                f,
                "circuit {} is not durably revoked; recovery attempts follow durable invalidation (§11)",
                hex(circuit_id)
            ),
            RecoveryError::RecoveryAlreadyComplete { circuit_id, attempt_seq, fresh_route_id } => {
                write!(
                    f,
                    "recovery for circuit {} already complete (attempt {attempt_seq} -> route {})",
                    hex(circuit_id),
                    hex(fresh_route_id)
                )
            }
            RecoveryError::AttemptAlreadyPending { circuit_id, attempt_seq } => write!(
                f,
                "attempt {attempt_seq} for circuit {} is already in flight",
                hex(circuit_id)
            ),
            RecoveryError::NoPendingAttempt { circuit_id } => write!(
                f,
                "circuit {} has no pending attempt to finish",
                hex(circuit_id)
            ),
            RecoveryError::AttemptNotPending { circuit_id, attempt_seq, state } => write!(
                f,
                "attempt {attempt_seq} for circuit {} is {state}, not pending",
                hex(circuit_id)
            ),
            RecoveryError::AttemptSeqUnknown { circuit_id, attempt_seq } => write!(
                f,
                "attempt seq {attempt_seq} unknown for circuit {}",
                hex(circuit_id)
            ),
            RecoveryError::AttemptRecordInvalid { what } => {
                write!(f, "attempt record invalid: {what}")
            }
            RecoveryError::AttemptSequenceNotIncreasing { circuit, previous, next } => write!(
                f,
                "circuit {} attempt sequence {next} does not exceed {previous}",
                hex(circuit)
            ),
            RecoveryError::AttemptAfterSuccessPersisted { circuit, attempt_seq } => write!(
                f,
                "circuit {} has an attempt after the succeeded attempt {attempt_seq}",
                hex(circuit)
            ),
            RecoveryError::InternalInconsistent { what } => {
                write!(f, "internal invariant violated: {what}")
            }
        }
    }
}

impl std::error::Error for RecoveryError {}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
