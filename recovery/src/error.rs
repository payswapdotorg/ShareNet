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
    /// R7-003: no candidate in the supplied set was judged `Eligible` by
    /// the R5-005 admission policy (an empty set included) — fail-closed;
    /// the typed input to the R7-005 retry/backoff policy.
    NoEligibleGateway { candidate_count: usize },
    /// R7-003: the candidate set carries two candidates with the same
    /// gateway node id — ambiguous input; deterministic selection refuses
    /// rather than silently picking one of them.
    DuplicateGatewayCandidate { gateway_node_id: [u8; 32] },
    /// R7-003: the fresh-route material offered does not commit to the
    /// selected gateway (path membership, DERIVED from the verified
    /// commitment — never caller-asserted).
    GatewayNotOnRoute { gateway_node_id: [u8; 32], route_id: [u8; 32] },
    /// R7-003: the selected gateway's admission evidence expired before
    /// the fresh route was established (the R5-005 decision's
    /// `valid_until_unix` anchor — selection evidence must still hold at
    /// construction time).
    GatewayAdmissionExpired { now_unix: u64, valid_until_unix: u64 },
    /// R7-003: the recovery step names an attempt that is no longer the
    /// circuit's open one (a stale step held across a finish).
    StaleRecoveryStep {
        circuit_id: [u8; 32],
        step_attempt_seq: u64,
        open_attempt_seq: u64,
    },
    /// R7-004: the §11 zeroization step has not been recorded for the
    /// revoked circuit — the replacement circuit session may only
    /// follow the durable fact that the revoked circuit's key material
    /// was dropped.
    ZeroizationMissing { circuit_id: [u8; 32] },
    /// R7-004: the circuit is already zeroized — the durable fact stands
    /// once recorded; a second record never rewrites it.
    CircuitAlreadyZeroized { circuit_id: [u8; 32], zeroized_at_unix: u64 },
    /// R7-004: the zeroization timestamp predates the revocation anchor —
    /// §11 orders `zeroization` AFTER `durable circuit invalidation`.
    ZeroizationBeforeRevocation { zeroized_at: u64, revoked_at: u64 },
    /// R7-004: the circuit's recovery has no succeeded attempt — the
    /// replacement circuit may only ride a durably recorded fresh route.
    NoSucceededAttempt { circuit_id: [u8; 32] },
    /// R7-004: the offered fresh-route hand-off, or the setup envelope's
    /// embedded commitment, is not the circuit's durably recorded fresh
    /// route (a stale or foreign route — the revoked circuit's own
    /// route included).
    ReplacementRouteMismatch {
        circuit_id: [u8; 32],
        expected_route_id: [u8; 32],
        offered_route_id: [u8; 32],
    },
    /// R7-004 (L014): the replacement setup derives the REVOKED circuit's
    /// own id — a replacement circuit must carry fresh session identity,
    /// never the failed circuit's.
    ReplacementCircuitNotFresh {
        revoked_circuit_id: [u8; 32],
        replacement_circuit_id: [u8; 32],
    },
    /// R7-004: the offered replacement setup envelope failed strict
    /// parse or its embedded commitment failed R3-004 verification —
    /// nothing was admitted, nothing was written.
    ReplacementSetupInvalid { source: sharenet_protocol::circuit::CircuitError },
    /// R7-004: the gated registry's R4-002 admission chain refused the
    /// replacement's setup or ack envelope (forged signature, expired
    /// setup, initiator not the proposer, nonce reuse, L015 revocation…).
    CircuitAdmissionRefused { source: sharenet_protocol::circuit::CircuitError },
    /// R7-004: the ack set did not establish the replacement circuit
    /// (unacked positions remain — an incomplete session is never
    /// recorded as the replacement).
    ReplacementCircuitNotEstablished { circuit_id: [u8; 32], unacked_positions: Vec<u64> },
    /// R7-004: the circuit's recovery already has its replacement circuit
    /// — single replacement per succeeded attempt (a further failure of
    /// the replacement is a NEW revocation + NEW recovery, L014).
    /// R7-006 cleanup refused: the terminal record is too fresh (its
    /// full context is retained until the age bound elapses).
    CleanupTooEarly {
        /// The circuit.
        circuit_id: [u8; 32],
        /// When the terminal record finished.
        finished_at_unix: u64,
        /// The caller's clock at the refused cleanup.
        now_unix: u64,
    },
    /// The R7-005 gate refused: the backoff window has not elapsed
    /// (the earliest permitted time is the daemon's timer input).
    RetryNotPermitted {
        /// The earliest permitted next-attempt time (inclusive bound).
        retry_at_unix: u64,
        /// The caller's clock at the refused query.
        now_unix: u64,
    },
    /// The R7-005 policy's attempt budget is exhausted (terminal).
    RetryExhausted {
        /// The circuit whose recovery budget is spent.
        circuit_id: [u8; 32],
        /// The budget that was reached.
        abandoned: u64,
    },
    ReplacementAlreadyEstablished {
        circuit_id: [u8; 32],
        attempt_seq: u64,
        replacement_circuit_id: [u8; 32],
    },
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
            RecoveryError::NoEligibleGateway { .. } => "no_eligible_gateway",
            RecoveryError::DuplicateGatewayCandidate { .. } => "duplicate_gateway_candidate",
            RecoveryError::GatewayNotOnRoute { .. } => "gateway_not_on_route",
            RecoveryError::GatewayAdmissionExpired { .. } => "gateway_admission_expired",
            RecoveryError::StaleRecoveryStep { .. } => "stale_recovery_step",
            RecoveryError::ZeroizationMissing { .. } => "zeroization_missing",
            RecoveryError::CircuitAlreadyZeroized { .. } => "circuit_already_zeroized",
            RecoveryError::ZeroizationBeforeRevocation { .. } => "zeroization_before_revocation",
            RecoveryError::NoSucceededAttempt { .. } => "no_succeeded_attempt",
            RecoveryError::ReplacementRouteMismatch { .. } => "replacement_route_mismatch",
            RecoveryError::ReplacementCircuitNotFresh { .. } => "replacement_circuit_id_not_fresh",
            RecoveryError::ReplacementSetupInvalid { .. } => "replacement_setup_invalid",
            RecoveryError::CircuitAdmissionRefused { .. } => "circuit_admission_refused",
            RecoveryError::ReplacementCircuitNotEstablished { .. } => {
                "replacement_circuit_not_established"
            }
            RecoveryError::ReplacementAlreadyEstablished { .. } => "replacement_already_established",
            RecoveryError::RetryNotPermitted { .. } => "retry_not_yet",
            RecoveryError::CleanupTooEarly { .. } => "cleanup_too_early",
            RecoveryError::RetryExhausted { .. } => "retry_exhausted",
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
            RecoveryError::NoEligibleGateway { candidate_count } => write!(
                f,
                "no eligible gateway among {candidate_count} candidate(s); the R5-005 admission policy refused them all (§11 fresh gateway selection, fail-closed)"
            ),
            RecoveryError::DuplicateGatewayCandidate { gateway_node_id } => write!(
                f,
                "duplicate gateway candidate {} — ambiguous candidate set",
                hex(gateway_node_id)
            ),
            RecoveryError::GatewayNotOnRoute { gateway_node_id, route_id } => write!(
                f,
                "the fresh route {} does not commit to the selected gateway {} (path membership failed)",
                hex(route_id),
                hex(gateway_node_id)
            ),
            RecoveryError::GatewayAdmissionExpired { now_unix, valid_until_unix } => write!(
                f,
                "the selected gateway's admission expired at {valid_until_unix} before the fresh route was established at {now_unix}"
            ),
            RecoveryError::StaleRecoveryStep { circuit_id, step_attempt_seq, open_attempt_seq } => write!(
                f,
                "stale recovery step: attempt {step_attempt_seq} for circuit {} is not the open attempt {open_attempt_seq}",
                hex(circuit_id)
            ),
            RecoveryError::ZeroizationMissing { circuit_id } => write!(
                f,
                "circuit {} has no recorded zeroization; the replacement session may only follow the §11 zeroization step",
                hex(circuit_id)
            ),
            RecoveryError::CircuitAlreadyZeroized { circuit_id, zeroized_at_unix } => write!(
                f,
                "circuit {} was already zeroized at {zeroized_at_unix}; the durable fact stands",
                hex(circuit_id)
            ),
            RecoveryError::ZeroizationBeforeRevocation { zeroized_at, revoked_at } => write!(
                f,
                "zeroization at {zeroized_at} predates the revocation at {revoked_at} (§11: zeroization follows durable invalidation)"
            ),
            RecoveryError::NoSucceededAttempt { circuit_id } => write!(
                f,
                "circuit {} has no succeeded attempt; the replacement circuit rides a recorded fresh route",
                hex(circuit_id)
            ),
            RecoveryError::ReplacementRouteMismatch { circuit_id, expected_route_id, offered_route_id } => write!(
                f,
                "the offered route {} is not the recorded fresh route {} of circuit {}",
                hex(offered_route_id),
                hex(expected_route_id),
                hex(circuit_id)
            ),
            RecoveryError::ReplacementCircuitNotFresh { revoked_circuit_id, .. } => write!(
                f,
                "the replacement setup derives the revoked circuit's own id {} (L014: fresh session identity required)",
                hex(revoked_circuit_id)
            ),
            RecoveryError::ReplacementSetupInvalid { source } => {
                write!(f, "replacement setup envelope invalid: {source}")
            }
            RecoveryError::CircuitAdmissionRefused { source } => {
                write!(f, "the gated registry refused the replacement's circuit admission: {source}")
            }
            RecoveryError::ReplacementCircuitNotEstablished { circuit_id, unacked_positions } => write!(
                f,
                "replacement circuit {} was not established (unacked positions: {:?})",
                hex(circuit_id),
                unacked_positions
            ),
            RecoveryError::CleanupTooEarly { circuit_id, finished_at_unix, now_unix } => write!(
                f,
                "circuit {}'s terminal recovery finished at {finished_at_unix} — too fresh to clean at {now_unix}",
                hex(circuit_id)
            ),
            RecoveryError::RetryNotPermitted { retry_at_unix, now_unix } => write!(
                f,
                "the backoff window has not elapsed (retry at >= {retry_at_unix}, now {now_unix})"
            ),
            RecoveryError::RetryExhausted { circuit_id, abandoned } => write!(
                f,
                "circuit {} exhausted its {abandoned}-attempt recovery budget",
                hex(circuit_id)
            ),
            RecoveryError::ReplacementAlreadyEstablished { circuit_id, attempt_seq, replacement_circuit_id } => write!(
                f,
                "circuit {} already has its replacement circuit {} (attempt {attempt_seq})",
                hex(circuit_id),
                hex(replacement_circuit_id)
            ),
        }
    }
}

impl std::error::Error for RecoveryError {}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
