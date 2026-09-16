//! The durable, bounded recovery-attempt log — work items R7-002 + R7-004.
//!
//! Architecture §11: after `durable circuit invalidation` and
//! `zeroization`, recovery proceeds through `recovery attempt → fresh
//! gateway selection → fresh route commitment → fresh circuit session →
//! verification`. *"A failed circuit is never resurrected. Recovery state
//! is durable and bounded."* This module is the durable, bounded record
//! of the attempts — and, since R7-004, of the two §11 facts that frame
//! them: the **zeroization** of the revoked circuit (the step between
//! invalidation and the new session — §11's exact word) and the
//! **replacement circuit** established over a succeeded attempt's fresh
//! route (the fresh circuit session itself):
//!
//! - each attempt is a **per-revoked-circuit monotonic** record
//!   (`attempt_seq` 1, 2, 3, … with a persisted high-water mark that
//!   compaction can never lower);
//! - the log **enforces the §11 ordering**: an attempt record may only
//!   be admitted for a circuit the *durable* ledger (R7-001 through
//!   [`crate::DurableRevocationLedger`]) shows as revoked — no attempt
//!   may resurrect the revoked circuit, and recovery may only *follow*
//!   durable invalidation. Unknown and unrevoked circuits are refused
//!   typed. The check is read-then-act safe: revocation is append-only
//!   (monotone), so a circuit revoked at check time stays revoked;
//! - the attempt lifecycle is **pending → succeeded | abandoned**:
//!   single-flight (one pending attempt per circuit), success is
//!   terminal (no attempt after success — a new failure of the fresh
//!   circuit is a NEW revocation and a NEW recovery, L014 fresh session
//!   identity), and an abandoned attempt records the typed failure
//!   reason;
//! - a succeeded attempt records the **fresh route commitment ref**
//!   (the commitment-derived `route_id`, L013). When the caller can
//!   present the actual [`RouteCommitment`] it is VERIFIED here (full
//!   R3-004 chain) and checked for §11 freshness (`proposed_at` must
//!   not predate the revocation that started the recovery); a bare
//!   route_id ref is the documented R7-003 composition seam (verification
//!   is the caller's there);
//! - the log is **bounded**: at most [`MAX_ATTEMPT_RECORDS_PER_CIRCUIT`]
//!   retained attempts per circuit; on overflow the OLDEST abandoned
//!   attempts are compacted away (never the pending, never the
//!   succeeded); the whole file is capped at
//!   [`MAX_ATTEMPT_LOG_FILE_BYTES`];
//! - the **zeroization fact** (R7-004): a per-revoked-circuit, at-most-once
//!   durable record ([`ZeroizationRecord`]) that the revoked circuit's key
//!   material was dropped, ordered AFTER durable invalidation (the ledger
//!   anchor) and BEFORE any replacement circuit may be recorded. What is
//!   claimed and what is not: this layer holds no key material of its own
//!   — the honest scope is recording and ordering the FACT (see the
//!   [`ZeroizationRecord`] docs; the in-process zeroization of real session
//!   keys lives in the runtime layers — R3-001's link-frame key zeroizing
//!   on drop, R4-001's tunnel);
//! - the **replacement circuit fact** (R7-004, L014): the succeeded
//!   attempt of a revoked circuit may carry ONE replacement circuit id —
//!   the circuit the fresh route's setup derived
//!   (`SHA-256("sharenet-circuit-id-v1" || route_id || setup_nonce)`, the
//!   R4-002 binding) — and never the revoked circuit's own id. A second
//!   replacement for the same recovery is refused typed: a further
//!   failure of the replacement circuit is a NEW revocation and a NEW
//!   recovery (L014 fresh session identity).
//!
//! # File format (v2, node-local durable state — not a wire object)
//!
//! Full-image strict binary, little-endian (the R5-003 store discipline:
//! atomic flush = temp + fsync + rename; every mutation is durable
//! before it is visible in memory):
//!
//! ```text
//! offset  size  field
//! 0       4     magic = b"SNRA" (ShareNet Recovery Attempts)
//! 4       2     format_version = 2   (v1 = pre-R7-004: refused — no
//!                                     silent reinterpretation of the
//!                                     old 52/58-byte layout)
//! 6       2     flags = 0 (reserved; nonzero refused)
//! 8       4     circuit_count (u32)
//! 12      4     body_len (u32)
//! 16      body_len  circuit sections, sorted by circuit id bytes
//! 16+body_len  4   crc32 (u32) — CRC-32/IEEE of bytes [0 .. 16+body_len)
//!
//! circuit section (60 fixed bytes + 90 per retained attempt):
//! 0       32    revoked circuit id
//! 32      8     next_seq (u64) — the persisted high-water mark
//! 40      8     revoked_at_unix — the §11 freshness anchor (the revoked
//!               circuit's first recorded revocation time, taken from
//!               the durable ledger at first-attempt admission)
//! 48      8     zeroized_at_unix (u64; 0 iff the §11 zeroization fact is
//!               not recorded; nonzero → >= revoked_at_unix)
//! 56      4     attempt_count (u32)
//! 60      …     attempt records, strictly ascending seq
//!
//! attempt record (90 bytes):
//! 0       8     attempt_seq (u64)
//! 8       8     started_at_unix (u64)
//! 16      8     finished_at_unix (u64; 0 iff pending)
//! 24      1     state tag (0=pending 1=succeeded 2=abandoned)
//! 25      1     outcome tag (0=none 1=fresh_route 2..=7=failure reason)
//! 26      32    route_id (all-zero iff not succeeded)
//! 58      32    replacement_circuit_id (all-zero iff no replacement was
//!               established for this succeeded attempt; nonzero ONLY
//!               on a succeeded record — R7-004)
//! ```
//!
//! Every cross-check the mutation paths enforce is re-enforced on load
//! (canonical section order, state-machine consistency, strict seq
//! ascent, high-water correctness, single pending, terminal success, the
//! retained bound, the zeroization ordering, the replacement-only-on-
//! succeeded law, exact arithmetic) — the reloaded log is exactly as
//! lawful as the one that was flushed.
//!
//! # Honest limits
//!
//! - Attempt records are LOCAL decisions, not signed wire objects (the
//!   signed artifacts are the revocations in the ledger file). Tamper
//!   detection is the format's CRC-32 + semantic cross-checks: a
//!   sophisticated rewriter can forge attempt history, hurting only
//!   their own node's recovery bookkeeping — the L015 authority (the
//!   ledger file) is unaffected.
//! - `finished >= started` and the §11 freshness anchor assume the
//!   caller-supplied clock is sane (this crate has no wall clock, by
//!   law); the anchor itself comes from the ledger's verified record.
//! - Cross-check + anchor read-then-act: the two ledger reads happen
//!   before the attempt-log mutex is taken; revocation being append-only
//!   makes this safe (see the module doc above).

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sharenet_protocol::route::RouteCommitment;

use crate::error::{RecoveryError, RecoveryIoOp};
use crate::ledger::DurableRevocationLedger;

/// File magic: **SN**etnet **R**ecovery **A**ttempts.
pub const ATTEMPT_MAGIC: [u8; 4] = *b"SNRA";
/// The attempt-log format version this code writes and accepts. v2 adds
/// the R7-004 fields (the per-circuit `zeroized_at_unix` and the
/// per-succeeded-attempt `replacement_circuit_id`); a v1 image (the
/// pre-R7-004 52/58-byte layout) is refused typed — the old and new
/// layouts never mix silently.
pub const ATTEMPT_FORMAT_VERSION: u16 = 2;
/// Hard cap on the attempt-log file (read and write side) — bounded
/// durable state, fail-closed against hostile files.
pub const MAX_ATTEMPT_LOG_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// The retained-records bound per revoked circuit (the documented
/// compaction bound: old abandoned attempts are compacted away beyond
/// it; the pending and succeeded attempts are never compacted).
pub const MAX_ATTEMPT_RECORDS_PER_CIRCUIT: usize = 64;

const HEADER_LEN: usize = 16;
const CRC_LEN: usize = 4;
const SECTION_FIXED_LEN: usize = 32 + 8 + 8 + 8 + 4;
const ATTEMPT_RECORD_LEN: usize = 8 + 8 + 8 + 1 + 1 + 32 + 32;
/// Cap on `Vec::with_capacity` for a count read from the file (the
/// length arithmetic below does the real fail-closed check).
const MAX_PREALLOC: usize = 1024;

// ---------------------------------------------------------------------------
// Failure reasons (frozen v1 vocabulary, the §11 pipeline stages)
// ---------------------------------------------------------------------------

/// The typed failure reason of an abandoned attempt — the §11 pipeline
/// stages that can fail after the attempt opened (fresh gateway
/// selection is R7-003; the fresh circuit session is R7-004; the
/// vocabulary is frozen so later items can rely on the machine names).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptFailure {
    /// Fresh gateway selection found no admissible candidate.
    NoGatewayAvailable,
    /// The selected fresh gateway could not be reached.
    GatewayUnreachable,
    /// The fresh route commitment could not be established or verified.
    RouteCommitmentFailed,
    /// The fresh circuit session setup failed.
    CircuitSetupFailed,
    /// Post-setup verification of the fresh circuit failed.
    VerificationFailed,
    /// A local decision (operator/policy) stopped the attempt.
    AbortedLocal,
}

impl AttemptFailure {
    /// The frozen v1 set, in tag order.
    pub const ALL: [AttemptFailure; 6] = [
        AttemptFailure::NoGatewayAvailable,
        AttemptFailure::GatewayUnreachable,
        AttemptFailure::RouteCommitmentFailed,
        AttemptFailure::CircuitSetupFailed,
        AttemptFailure::VerificationFailed,
        AttemptFailure::AbortedLocal,
    ];

    /// Stable machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            AttemptFailure::NoGatewayAvailable => "no_gateway_available",
            AttemptFailure::GatewayUnreachable => "gateway_unreachable",
            AttemptFailure::RouteCommitmentFailed => "route_commitment_failed",
            AttemptFailure::CircuitSetupFailed => "circuit_setup_failed",
            AttemptFailure::VerificationFailed => "verification_failed",
            AttemptFailure::AbortedLocal => "aborted_local",
        }
    }

    /// Parse from the machine name.
    pub fn from_name(name: &str) -> Option<AttemptFailure> {
        AttemptFailure::ALL.iter().find(|f| f.as_str() == name).copied()
    }

    fn tag(&self) -> u8 {
        match self {
            AttemptFailure::NoGatewayAvailable => 2,
            AttemptFailure::GatewayUnreachable => 3,
            AttemptFailure::RouteCommitmentFailed => 4,
            AttemptFailure::CircuitSetupFailed => 5,
            AttemptFailure::VerificationFailed => 6,
            AttemptFailure::AbortedLocal => 7,
        }
    }

    fn from_tag(tag: u8) -> Option<AttemptFailure> {
        match tag {
            2 => Some(AttemptFailure::NoGatewayAvailable),
            3 => Some(AttemptFailure::GatewayUnreachable),
            4 => Some(AttemptFailure::RouteCommitmentFailed),
            5 => Some(AttemptFailure::CircuitSetupFailed),
            6 => Some(AttemptFailure::VerificationFailed),
            7 => Some(AttemptFailure::AbortedLocal),
            _ => None,
        }
    }
}

impl std::fmt::Display for AttemptFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Fresh-route evidence
// ---------------------------------------------------------------------------

/// The evidence a succeeded attempt records for its fresh route.
#[derive(Debug, Clone, Copy)]
pub enum FreshRouteEvidence<'a> {
    /// The fresh route commitment (RECOMMENDED): verified here (the
    /// full R3-004 chain — proposal, acceptances, Merkle root, route_id
    /// re-derivation) and §11-freshness-checked against the revocation
    /// anchor (`proposed_at >= revoked_at`).
    Commitment(&'a RouteCommitment),
    /// A commitment-derived route_id the CALLER verified (the R7-003
    /// composition seam: when the verifying component sits at a
    /// different process boundary). Recorded as-is; verification is the
    /// caller's documented responsibility there.
    RouteRef([u8; 32]),
}

// ---------------------------------------------------------------------------
// The §11 zeroization fact (R7-004)
// ---------------------------------------------------------------------------

/// The durable, typed fact that a revoked circuit's key material was
/// dropped — §11's `zeroization` step, the one word the architecture
/// places between `durable circuit invalidation` and the new session.
///
/// # What this records — and what it does NOT claim (the honesty boundary)
///
/// This layer holds NO key material of its own: the attempt log records
/// attempts and facts, never session keys. What
/// [`RecoveryAttemptLog::record_zeroization`] records and orders durably
/// is the FACT — *"the revoked circuit's key material was dropped at
/// `zeroized_at_unix`, after the circuit was durably revoked at
/// `revoked_at_unix`, and before any replacement circuit may be
/// established for it"* — so that a restarted process cannot skip the
/// step and the ordering survives crashes (fail-closed gates: the
/// replacement stage refuses without it).
///
/// It does NOT claim that any specific in-memory key bytes were actually
/// overwritten: the in-process zeroization of real session keys lives in
/// the runtime layers that own them (R3-001's link ChaCha20-Poly1305
/// session keys and ephemeral secrets zeroized on drop, R4-001's tunnel
/// state). This record is the durable ORDERING AND ACCOUNTABILITY fact
/// those layers' zeroization is reported through — the daemon records it
/// once the runtime layer dropped the revoked circuit's keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroizationRecord {
    /// The revoked circuit whose key material was dropped.
    pub(crate) revoked_circuit_id: [u8; 32],
    /// When (caller clock) the zeroization was recorded — never before the
    /// ledger's revocation anchor for the same circuit.
    pub(crate) zeroized_at_unix: u64,
}

impl ZeroizationRecord {
    /// The revoked circuit this zeroization is for.
    pub fn revoked_circuit_id(&self) -> &[u8; 32] {
        &self.revoked_circuit_id
    }
    /// When the zeroization was recorded (the durable ordering fact).
    pub fn zeroized_at_unix(&self) -> u64 {
        self.zeroized_at_unix
    }
}

impl std::fmt::Display for ZeroizationRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "circuit {} zeroized at {}",
            self.revoked_circuit_id.iter().map(|b| format!("{b:02x}")).collect::<String>(),
            self.zeroized_at_unix
        )
    }
}

// ---------------------------------------------------------------------------
// The in-memory record (read-only views)
// ---------------------------------------------------------------------------

/// The attempt lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttemptState {
    /// Opened, durable, awaiting the §11 pipeline's outcome.
    Pending,
    /// A fresh route commitment was recorded (terminal for the
    /// circuit's recovery).
    Succeeded,
    /// The attempt was abandoned with the typed failure reason.
    Abandoned,
}

impl AttemptState {
    /// Stable machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            AttemptState::Pending => "pending",
            AttemptState::Succeeded => "succeeded",
            AttemptState::Abandoned => "abandoned",
        }
    }
}

impl std::fmt::Display for AttemptState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One recovery-attempt record (the read-only view the log serves).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryAttempt {
    revoked_circuit_id: [u8; 32],
    attempt_seq: u64,
    started_at_unix: u64,
    finished_at_unix: Option<u64>,
    state: AttemptState,
    fresh_route_id: Option<[u8; 32]>,
    failure: Option<AttemptFailure>,
    /// The R7-004 replacement circuit established over this succeeded
    /// attempt's fresh route (Some iff the replacement was recorded).
    replacement_circuit_id: Option<[u8; 32]>,
}

impl RecoveryAttempt {
    pub fn revoked_circuit_id(&self) -> &[u8; 32] {
        &self.revoked_circuit_id
    }
    pub fn attempt_seq(&self) -> u64 {
        self.attempt_seq
    }
    pub fn started_at_unix(&self) -> u64 {
        self.started_at_unix
    }
    pub fn finished_at_unix(&self) -> Option<u64> {
        self.finished_at_unix
    }
    pub fn state(&self) -> AttemptState {
        self.state
    }
    /// The fresh route commitment ref (Some iff succeeded).
    pub fn fresh_route_id(&self) -> Option<&[u8; 32]> {
        self.fresh_route_id.as_ref()
    }
    /// The typed failure reason (Some iff abandoned).
    pub fn failure(&self) -> Option<AttemptFailure> {
        self.failure
    }
    /// The R7-004 replacement circuit id (Some iff a replacement circuit
    /// was established over this attempt's recorded fresh route).
    pub fn replacement_circuit_id(&self) -> Option<&[u8; 32]> {
        self.replacement_circuit_id.as_ref()
    }
}

/// The persisted per-circuit section.
#[derive(Debug, Clone)]
struct CircuitSection {
    /// The high-water mark: the next `attempt_seq` to hand out. Never
    /// decreases; survives compaction.
    next_seq: u64,
    /// The §11 freshness anchor (the revoked circuit's first recorded
    /// revocation time, from the durable ledger).
    revoked_at_unix: u64,
    /// The §11 zeroization fact (R7-004): when the revoked circuit's key
    /// material was dropped; `None` until recorded, at most once.
    zeroized_at_unix: Option<u64>,
    /// Retained attempt records, ascending seq.
    attempts: Vec<RecoveryAttempt>,
}

// ---------------------------------------------------------------------------
// The log
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct AttemptInner {
    sections: BTreeMap<[u8; 32], CircuitSection>,
}

/// The durable, bounded recovery-attempt log. Internally mutex-guarded
/// (`&self` mutation, the R7-001 posture); every mutation is made
/// durable (atomic temp + fsync + rename) before it becomes visible.
#[derive(Debug)]
pub struct RecoveryAttemptLog {
    path: PathBuf,
    inner: Mutex<AttemptInner>,
}

impl RecoveryAttemptLog {
    /// Create a fresh (empty) log file. Refuses to clobber an existing
    /// file (no silent data loss); `load` it instead.
    pub fn create(path: &Path) -> Result<Self, RecoveryError> {
        if path.exists() {
            return Err(RecoveryError::StoreAlreadyExists { path: path.to_path_buf() });
        }
        let empty = AttemptInner::default();
        write_atomic(path, &empty.to_bytes()?)?;
        Ok(Self { path: path.to_path_buf(), inner: Mutex::new(empty) })
    }

    /// Load the log from disk — the full fail-closed parse (magic,
    /// version, flags, arithmetic, CRC-32, and every semantic
    /// cross-check the mutation paths enforce).
    pub fn load(path: &Path) -> Result<Self, RecoveryError> {
        let bytes = fs::read(path).map_err(|e| RecoveryError::io(RecoveryIoOp::ReadStore, e))?;
        let inner = AttemptInner::from_bytes(&bytes)?;
        Ok(Self { path: path.to_path_buf(), inner: Mutex::new(inner) })
    }

    /// Load if the file exists, create if it does not.
    pub fn open_or_create(path: &Path) -> Result<Self, RecoveryError> {
        if path.exists() {
            Self::load(path)
        } else {
            Self::create(path)
        }
    }

    /// Open the next recovery attempt for a revoked circuit — the §11
    /// ordering gate: the durable ledger must show the circuit revoked
    /// before any attempt record referencing it may be admitted (a
    /// circuit unknown to the ledger is refused the same way). Returns
    /// the new per-circuit monotonic `attempt_seq`, now durable and
    /// pending.
    pub fn begin_attempt(
        &self,
        ledger: &DurableRevocationLedger,
        revoked_circuit_id: &[u8; 32],
        now_unix: u64,
    ) -> Result<u64, RecoveryError> {
        // The §11 cross-check — BEFORE anything is written. Read-then-
        // act safe: revocation is append-only, so a revoked circuit
        // stays revoked (the anchor below is equally stable).
        if !ledger.is_revoked(revoked_circuit_id) {
            return Err(RecoveryError::CircuitNotRevoked { circuit_id: *revoked_circuit_id });
        }
        let revoked_at = ledger
            .revoked_at(revoked_circuit_id)
            .expect("checked: a revoked circuit has a first revocation record");
        self.mutate(|inner| {
            let section = inner.section_mut(revoked_circuit_id, revoked_at);
            // Terminal-success and single-flight refusals.
            if let Some(last) = section.attempts.last() {
                match last.state {
                    AttemptState::Succeeded => {
                        return Err(RecoveryError::RecoveryAlreadyComplete {
                            circuit_id: *revoked_circuit_id,
                            attempt_seq: last.attempt_seq,
                            fresh_route_id: last
                                .fresh_route_id
                                .expect("succeeded attempts carry a route ref"),
                        });
                    }
                    AttemptState::Pending => {
                        return Err(RecoveryError::AttemptAlreadyPending {
                            circuit_id: *revoked_circuit_id,
                            attempt_seq: last.attempt_seq,
                        });
                    }
                    AttemptState::Abandoned => {}
                }
            }
            let seq = section.next_seq;
            let record = RecoveryAttempt {
                revoked_circuit_id: *revoked_circuit_id,
                attempt_seq: seq,
                started_at_unix: now_unix,
                finished_at_unix: None,
                state: AttemptState::Pending,
                fresh_route_id: None,
                failure: None,
                replacement_circuit_id: None,
            };
            section.next_seq = seq
                .checked_add(1)
                .ok_or(RecoveryError::AttemptRecordInvalid { what: "attempt seq overflow" })?;
            section.attempts.push(record);
            section.compact();
            Ok(seq)
        })
    }

    /// Finish the circuit's pending attempt as SUCCEEDED, recording the
    /// fresh route commitment evidence. Returns the attempt_seq.
    pub fn finish_attempt_with_route(
        &self,
        revoked_circuit_id: &[u8; 32],
        evidence: FreshRouteEvidence<'_>,
        now_unix: u64,
    ) -> Result<u64, RecoveryError> {
        // Route identity is derived from verified commitment bytes (L013)
        // whenever the commitment is in hand.
        let (route_id, proposed_at) = match evidence {
            FreshRouteEvidence::Commitment(commitment) => {
                let verified = commitment
                    .verify(now_unix)
                    .map_err(|source| RecoveryError::RouteCommitmentInvalid { source })?;
                (
                    verified.route_id,
                    Some(verified.proposal.proposed_at_unix()),
                )
            }
            FreshRouteEvidence::RouteRef(route_id) => (route_id, None),
        };
        if route_id == [0u8; 32] {
            return Err(RecoveryError::AttemptRecordInvalid {
                what: "the all-zero route id is reserved (never commitment-derived)",
            });
        }
        self.mutate(|inner| {
            let section = inner.pending_section_mut(revoked_circuit_id)?;
            // §11 freshness: a commitment presented for the fresh route
            // must not predate the revocation that started the recovery.
            if let Some(proposed_at) = proposed_at {
                if proposed_at < section.revoked_at_unix {
                    return Err(RecoveryError::RouteNotFresh {
                        proposed_at,
                        revoked_at: section.revoked_at_unix,
                    });
                }
            }
            let record = section
                .attempts
                .last_mut()
                .expect("pending_section_mut checked the tail");
            if now_unix < record.started_at_unix {
                return Err(RecoveryError::AttemptRecordInvalid {
                    what: "finish time predates the attempt's start",
                });
            }
            record.finished_at_unix = Some(now_unix);
            record.state = AttemptState::Succeeded;
            record.fresh_route_id = Some(route_id);
            record.failure = None;
            Ok(record.attempt_seq)
        })
    }

    /// Finish the circuit's pending attempt as ABANDONED with the typed
    /// failure reason. Returns the attempt_seq.
    pub fn finish_attempt_with_failure(
        &self,
        revoked_circuit_id: &[u8; 32],
        reason: AttemptFailure,
        now_unix: u64,
    ) -> Result<u64, RecoveryError> {
        self.mutate(|inner| {
            let section = inner.pending_section_mut(revoked_circuit_id)?;
            let record = section
                .attempts
                .last_mut()
                .expect("pending_section_mut checked the tail");
            if now_unix < record.started_at_unix {
                return Err(RecoveryError::AttemptRecordInvalid {
                    what: "finish time predates the attempt's start",
                });
            }
            record.finished_at_unix = Some(now_unix);
            record.state = AttemptState::Abandoned;
            record.fresh_route_id = None;
            record.failure = Some(reason);
            Ok(record.attempt_seq)
        })
    }

    // -- R7-004: the §11 zeroization fact + the replacement circuit fact ----

    /// Record the §11 `zeroization` step for a durably revoked circuit —
    /// the typed, durable fact that its key material was dropped (see
    /// [`ZeroizationRecord`] for the exact honesty boundary). The record is
    /// durable before it is visible, at most once per revoked circuit, and
    /// ordered AFTER the durable invalidation.
    ///
    /// Typed refusals: `circuit_not_revoked` (§11: zeroization follows
    /// durable invalidation — unknown and unrevoked circuits alike),
    /// `zeroization_before_revocation` (the caller clock predates the
    /// ledger's revocation anchor), `circuit_already_zeroized` (the fact
    /// stands; a second record never rewrites it).
    pub fn record_zeroization(
        &self,
        ledger: &DurableRevocationLedger,
        revoked_circuit_id: &[u8; 32],
        now_unix: u64,
    ) -> Result<ZeroizationRecord, RecoveryError> {
        // The §11 cross-check — BEFORE anything is written (read-then-act
        // safe: revocation is append-only, so a revoked circuit stays
        // revoked and the anchor below is equally stable).
        if !ledger.is_revoked(revoked_circuit_id) {
            return Err(RecoveryError::CircuitNotRevoked { circuit_id: *revoked_circuit_id });
        }
        let revoked_at = ledger
            .revoked_at(revoked_circuit_id)
            .expect("checked: a revoked circuit has a first revocation record");
        if now_unix < revoked_at {
            return Err(RecoveryError::ZeroizationBeforeRevocation {
                zeroized_at: now_unix,
                revoked_at,
            });
        }
        self.mutate(|inner| {
            let section = inner.section_mut(revoked_circuit_id, revoked_at);
            if let Some(at) = section.zeroized_at_unix {
                return Err(RecoveryError::CircuitAlreadyZeroized {
                    circuit_id: *revoked_circuit_id,
                    zeroized_at_unix: at,
                });
            }
            section.zeroized_at_unix = Some(now_unix);
            Ok(ZeroizationRecord {
                revoked_circuit_id: *revoked_circuit_id,
                zeroized_at_unix: now_unix,
            })
        })
    }

    /// The circuit's zeroization fact, if recorded (the durable query the
    /// replacement stage gates on — the ordering fact survives restarts).
    pub fn zeroization(&self, revoked_circuit_id: &[u8; 32]) -> Option<ZeroizationRecord> {
        lock(&self.inner)
            .sections
            .get(revoked_circuit_id)
            .and_then(|s| s.zeroized_at_unix)
            .map(|zeroized_at_unix| ZeroizationRecord {
                revoked_circuit_id: *revoked_circuit_id,
                zeroized_at_unix,
            })
    }

    /// Record the R7-004 replacement circuit on the circuit's SUCCEEDED
    /// attempt: the fresh-route hand-off must match the durable terminal
    /// record (the route the replacement rides), the zeroization fact must
    /// stand, and no earlier replacement may exist (single replacement per
    /// recovery — a further failure of the replacement circuit is a NEW
    /// revocation and a NEW recovery, L014). Returns the attempt_seq the
    /// replacement was recorded on.
    ///
    /// Typed refusals: `no_succeeded_attempt` (nothing succeeded — or no
    /// attempts at all), `replacement_route_mismatch` (the offered route
    /// is not the recorded fresh one), `zeroization_missing` (the §11 step
    /// between invalidation and the new session has not been recorded),
    /// `replacement_already_established` (single flight),
    /// `attempt_record_invalid` (clock-order sanity: the replacement time
    /// predates the zeroization or the route's own recording).
    pub fn record_replacement_circuit(
        &self,
        revoked_circuit_id: &[u8; 32],
        fresh_route_id: &[u8; 32],
        replacement_circuit_id: &[u8; 32],
        now_unix: u64,
    ) -> Result<u64, RecoveryError> {
        if *replacement_circuit_id == [0u8; 32] {
            return Err(RecoveryError::AttemptRecordInvalid {
                what: "the all-zero replacement circuit id is reserved",
            });
        }
        self.mutate(|inner| {
            let section = inner
                .sections
                .get_mut(revoked_circuit_id)
                .ok_or(RecoveryError::NoSucceededAttempt { circuit_id: *revoked_circuit_id })?;
            let record = section
                .attempts
                .last_mut()
                .ok_or(RecoveryError::NoSucceededAttempt { circuit_id: *revoked_circuit_id })?;
            if record.state != AttemptState::Succeeded {
                return Err(RecoveryError::NoSucceededAttempt { circuit_id: *revoked_circuit_id });
            }
            let recorded_route = record
                .fresh_route_id
                .expect("succeeded attempts carry a route ref");
            if &recorded_route != fresh_route_id {
                return Err(RecoveryError::ReplacementRouteMismatch {
                    circuit_id: *revoked_circuit_id,
                    expected_route_id: recorded_route,
                    offered_route_id: *fresh_route_id,
                });
            }
            if let Some(existing) = record.replacement_circuit_id {
                return Err(RecoveryError::ReplacementAlreadyEstablished {
                    circuit_id: *revoked_circuit_id,
                    attempt_seq: record.attempt_seq,
                    replacement_circuit_id: existing,
                });
            }
            // The §11 ordering fact: the replacement session strictly
            // follows the zeroization of the revoked circuit's keys.
            let zeroized_at = section
                .zeroized_at_unix
                .ok_or(RecoveryError::ZeroizationMissing { circuit_id: *revoked_circuit_id })?;
            let finished_at = record
                .finished_at_unix
                .expect("succeeded attempts carry a finish time");
            if now_unix < zeroized_at || now_unix < finished_at {
                return Err(RecoveryError::AttemptRecordInvalid {
                    what: "replacement time predates the zeroization or the route's recording",
                });
            }
            record.replacement_circuit_id = Some(*replacement_circuit_id);
            Ok(record.attempt_seq)
        })
    }

    // -- queries ----------------------------------------------------------

    /// The retained attempts for a circuit, ascending seq.
    pub fn attempts_for(&self, revoked_circuit_id: &[u8; 32]) -> Vec<RecoveryAttempt> {
        lock(&self.inner)
            .sections
            .get(revoked_circuit_id)
            .map(|s| s.attempts.clone())
            .unwrap_or_default()
    }

    /// R7-006: every circuit carrying attempt history, in the
    /// deterministic BTreeMap key order (the coordination view's
    /// iteration order — architecture §2).
    pub fn circuits_with_history(&self) -> Vec<[u8; 32]> {
        lock(&self.inner).sections.keys().copied().collect()
    }

    /// R7-006 cleanup: prune one terminal circuit's ABANDONED history,
    /// retaining exactly the terminal succeeded record (plus the
    /// high-water, the §11 anchor and the zeroization fact — the section
    /// itself always survives, so the terminal fact can never be
    /// resurrected away: a cleaned circuit stays `recovery_already_complete`).
    ///
    /// Laws (fail-closed, typed):
    /// - only a section whose LATEST attempt is `Succeeded` may be
    ///   cleaned (`NoSucceededAttempt` otherwise — pending and
    ///   abandoned-only recoveries keep their history);
    /// - the terminal record must have finished at least `min_age_s`
    ///   seconds before `now` (`CleanupTooEarly` — a fresh success keeps
    ///   its full context);
    /// - the high-water, the revoked-at anchor and the zeroization fact
    ///   are NEVER dropped.
    ///
    /// Returns whether anything was pruned.
    pub fn prune_terminal_history(
        &self,
        revoked_circuit_id: &[u8; 32],
        now_unix: u64,
        min_age_s: u64,
    ) -> Result<bool, RecoveryError> {
        self.mutate(|inner| {
            let section = inner
                .sections
                .get_mut(revoked_circuit_id)
                .ok_or(RecoveryError::NoSucceededAttempt {
                    circuit_id: *revoked_circuit_id,
                })?;
            let latest = section
                .attempts
                .last()
                .ok_or(RecoveryError::NoSucceededAttempt {
                    circuit_id: *revoked_circuit_id,
                })?;
            if latest.state != AttemptState::Succeeded {
                return Err(RecoveryError::NoSucceededAttempt {
                    circuit_id: *revoked_circuit_id,
                });
            }
            let finished = latest
                .finished_at_unix()
                .expect("succeeded records carry finished_at");
            if now_unix.saturating_sub(finished) < min_age_s {
                return Err(RecoveryError::CleanupTooEarly {
                    circuit_id: *revoked_circuit_id,
                    finished_at_unix: finished,
                    now_unix,
                });
            }
            let before = section.attempts.len();
            // Retain ONLY the terminal record (and any pending record —
            // impossible after the succeeded check, but the invariant is
            // cheap and explicit).
            section
                .attempts
                .retain(|r| r.state != AttemptState::Abandoned);
            Ok(section.attempts.len() < before)
        })
    }

    /// The newest retained attempt for a circuit, if any.
    pub fn latest_attempt(&self, revoked_circuit_id: &[u8; 32]) -> Option<RecoveryAttempt> {
        lock(&self.inner)
            .sections
            .get(revoked_circuit_id)
            .and_then(|s| s.attempts.last().cloned())
    }

    /// The circuit's pending attempt, if one is open.
    pub fn pending_attempt(&self, revoked_circuit_id: &[u8; 32]) -> Option<RecoveryAttempt> {
        lock(&self.inner)
            .sections
            .get(revoked_circuit_id)
            .and_then(|s| s.attempts.last().cloned())
            .filter(|a| a.state == AttemptState::Pending)
    }

    /// The next `attempt_seq` the circuit would receive (the persisted
    /// high-water; 1 for circuits with no attempts yet).
    pub fn next_attempt_seq(&self, revoked_circuit_id: &[u8; 32]) -> u64 {
        lock(&self.inner)
            .sections
            .get(revoked_circuit_id)
            .map_or(1, |s| s.next_seq)
    }

    /// The circuits with attempt records, sorted by id bytes.
    pub fn tracked_circuits(&self) -> Vec<[u8; 32]> {
        lock(&self.inner).sections.keys().copied().collect()
    }

    /// Total retained attempt records across circuits.
    pub fn record_count(&self) -> usize {
        lock(&self.inner).sections.values().map(|s| s.attempts.len()).sum()
    }

    /// The log file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // -- internals ----------------------------------------------------------

    /// The mutation discipline: clone → mutate → serialize → atomic
    /// write → swap. A mutation is only ever visible in memory after it
    /// is durable; a write failure leaves the pre-mutation state intact.
    fn mutate<T>(
        &self,
        f: impl FnOnce(&mut AttemptInner) -> Result<T, RecoveryError>,
    ) -> Result<T, RecoveryError> {
        let mut guard = lock(&self.inner);
        let mut candidate = guard.clone();
        let result = f(&mut candidate)?;
        let bytes = candidate.to_bytes()?;
        if bytes.len() as u64 > MAX_ATTEMPT_LOG_FILE_BYTES {
            return Err(RecoveryError::StoreTooLarge {
                which: "attempts",
                size: bytes.len() as u64,
                max: MAX_ATTEMPT_LOG_FILE_BYTES,
            });
        }
        write_atomic(&self.path, &bytes)?;
        *guard = candidate;
        Ok(result)
    }
}

fn lock(inner: &Mutex<AttemptInner>) -> std::sync::MutexGuard<'_, AttemptInner> {
    inner.lock().expect("recovery attempt log poisoned (a panic occurred mid-mutation)")
}

impl AttemptInner {
    /// The circuit's section (creating it with the ledger-sourced anchor
    /// at first use — the caller cross-checked revocation first).
    fn section_mut(
        &mut self,
        circuit_id: &[u8; 32],
        revoked_at_unix: u64,
    ) -> &mut CircuitSection {
        self.sections.entry(*circuit_id).or_insert(CircuitSection {
            next_seq: 1,
            revoked_at_unix,
            zeroized_at_unix: None,
            attempts: Vec::new(),
        })
    }

    /// The circuit's section with a PENDING tail attempt, or the typed
    /// refusal (unknown circuit / no pending attempt).
    fn pending_section_mut(
        &mut self,
        circuit_id: &[u8; 32],
    ) -> Result<&mut CircuitSection, RecoveryError> {
        let section = self
            .sections
            .get_mut(circuit_id)
            .ok_or(RecoveryError::NoPendingAttempt { circuit_id: *circuit_id })?;
        if !matches!(section.attempts.last(), Some(r) if r.state == AttemptState::Pending) {
            return Err(RecoveryError::NoPendingAttempt { circuit_id: *circuit_id });
        }
        Ok(section)
    }
}

impl CircuitSection {
    /// The documented compaction bound: retain at most
    /// [`MAX_ATTEMPT_RECORDS_PER_CIRCUIT`] attempts, dropping the OLDEST
    /// abandoned ones. The pending attempt and the (terminal) succeeded
    /// attempt are never dropped; the high-water mark is unaffected.
    /// Overflow is always droppable: success is terminal (nothing can
    /// follow it) and pending is always the last record, so an overflow
    /// set contains at least `MAX` abandoned records.
    fn compact(&mut self) {
        while self.attempts.len() > MAX_ATTEMPT_RECORDS_PER_CIRCUIT {
            let idx = self
                .attempts
                .iter()
                .position(|a| a.state == AttemptState::Abandoned)
                .expect("overflow is always droppable (see the doc comment)");
            self.attempts.remove(idx);
        }
    }

    /// Cross-check the section's invariants (the same laws the mutation
    /// paths enforce, re-enforced at parse).
    fn check(&self, circuit: &[u8; 32]) -> Result<(), RecoveryError> {
        // The §11 zeroization ordering: the durable fact never predates
        // the revocation anchor it follows.
        if let Some(zeroized_at) = self.zeroized_at_unix {
            if zeroized_at < self.revoked_at_unix {
                return Err(RecoveryError::AttemptRecordInvalid {
                    what: "zeroization predates the revocation anchor",
                });
            }
        }
        if self.attempts.len() > MAX_ATTEMPT_RECORDS_PER_CIRCUIT {
            return Err(RecoveryError::AttemptRecordInvalid {
                what: "retained attempt records exceed the compaction bound",
            });
        }
        let mut prev_seq = 0u64;
        let mut seen_success = false;
        for (i, record) in self.attempts.iter().enumerate() {
            if record.revoked_circuit_id != *circuit {
                return Err(RecoveryError::AttemptRecordInvalid {
                    what: "attempt record carries a foreign circuit id",
                });
            }
            if record.attempt_seq <= prev_seq
                || record.attempt_seq >= self.next_seq
            {
                return Err(RecoveryError::AttemptSequenceNotIncreasing {
                    circuit: *circuit,
                    previous: prev_seq.max(record.attempt_seq),
                    next: record.attempt_seq.min(self.next_seq),
                });
            }
            prev_seq = record.attempt_seq;
            match record.state {
                AttemptState::Pending => {
                    if record.finished_at_unix.is_some()
                        || record.fresh_route_id.is_some()
                        || record.failure.is_some()
                        || record.replacement_circuit_id.is_some()
                    {
                        return Err(RecoveryError::AttemptRecordInvalid {
                            what: "pending attempt carries completion fields",
                        });
                    }
                    if i + 1 != self.attempts.len() {
                        return Err(RecoveryError::AttemptRecordInvalid {
                            what: "a pending attempt must be the last retained record",
                        });
                    }
                }
                AttemptState::Succeeded => {
                    if record.finished_at_unix.is_none()
                        || record.fresh_route_id.is_none()
                        || record.failure.is_some()
                    {
                        return Err(RecoveryError::AttemptRecordInvalid {
                            what: "succeeded attempt lacks its route ref or finish time",
                        });
                    }
                    if seen_success {
                        return Err(RecoveryError::AttemptAfterSuccessPersisted {
                            circuit: *circuit,
                            attempt_seq: record.attempt_seq,
                        });
                    }
                    seen_success = true;
                }
                AttemptState::Abandoned => {
                    if record.finished_at_unix.is_none()
                        || record.fresh_route_id.is_some()
                        || record.failure.is_none()
                        || record.replacement_circuit_id.is_some()
                    {
                        return Err(RecoveryError::AttemptRecordInvalid {
                            what: "abandoned attempt lacks its failure reason or finish time",
                        });
                    }
                    if seen_success {
                        return Err(RecoveryError::AttemptAfterSuccessPersisted {
                            circuit: *circuit,
                            attempt_seq: record.attempt_seq,
                        });
                    }
                }
            }
            if let Some(finished) = record.finished_at_unix {
                if finished < record.started_at_unix {
                    return Err(RecoveryError::AttemptRecordInvalid {
                        what: "finish time predates the attempt's start",
                    });
                }
            }
        }
        if self.attempts.is_empty() && self.next_seq != 1 {
            return Err(RecoveryError::AttemptRecordInvalid {
                what: "empty section must carry the initial high-water mark",
            });
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Codec (strict, hand-rolled, zero dependencies)
// ---------------------------------------------------------------------------

impl AttemptInner {
    fn to_bytes(&self) -> Result<Vec<u8>, RecoveryError> {
        let mut body = Vec::new();
        for (circuit, section) in &self.sections {
            body.extend_from_slice(circuit);
            body.extend_from_slice(&section.next_seq.to_le_bytes());
            body.extend_from_slice(&section.revoked_at_unix.to_le_bytes());
            body.extend_from_slice(&section.zeroized_at_unix.unwrap_or(0).to_le_bytes());
            body.extend_from_slice(&(section.attempts.len() as u32).to_le_bytes());
            for record in &section.attempts {
                body.extend_from_slice(&record.attempt_seq.to_le_bytes());
                body.extend_from_slice(&record.started_at_unix.to_le_bytes());
                body.extend_from_slice(&record.finished_at_unix.unwrap_or(0).to_le_bytes());
                body.push(match record.state {
                    AttemptState::Pending => 0u8,
                    AttemptState::Succeeded => 1u8,
                    AttemptState::Abandoned => 2u8,
                });
                body.push(if let Some(failure) = record.failure {
                    failure.tag()
                } else if record.fresh_route_id.is_some() {
                    1u8
                } else {
                    0u8
                });
                body.extend_from_slice(
                    record.fresh_route_id.as_ref().map_or(&[0u8; 32], |r| r.as_slice()),
                );
                body.extend_from_slice(
                    record
                        .replacement_circuit_id
                        .as_ref()
                        .map_or(&[0u8; 32], |r| r.as_slice()),
                );
            }
        }
        let mut out = Vec::with_capacity(HEADER_LEN + body.len() + CRC_LEN);
        out.extend_from_slice(&ATTEMPT_MAGIC);
        out.extend_from_slice(&ATTEMPT_FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&(self.sections.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        let crc = crc32(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        Ok(out)
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, RecoveryError> {
        if bytes.len() as u64 > MAX_ATTEMPT_LOG_FILE_BYTES {
            return Err(RecoveryError::StoreTooLarge {
                which: "attempts",
                size: bytes.len() as u64,
                max: MAX_ATTEMPT_LOG_FILE_BYTES,
            });
        }
        if bytes.len() < HEADER_LEN {
            return Err(RecoveryError::LengthMismatch {
                which: "attempts",
                expected: HEADER_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0..4] != ATTEMPT_MAGIC {
            return Err(RecoveryError::BadMagic {
                which: "attempts",
                found: bytes[0..4].try_into().expect("4 bytes"),
            });
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != ATTEMPT_FORMAT_VERSION {
            return Err(RecoveryError::VersionUnsupported { which: "attempts", found: version });
        }
        let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
        if flags != 0 {
            return Err(RecoveryError::FlagsUnsupported { which: "attempts", found: flags });
        }
        let circuit_count = u32::from_le_bytes(bytes[8..12].try_into().expect("4")) as usize;
        let body_len = u32::from_le_bytes(bytes[12..16].try_into().expect("4")) as usize;
        let expected = HEADER_LEN
            .checked_add(body_len)
            .and_then(|e| e.checked_add(CRC_LEN))
            .ok_or(RecoveryError::LengthMismatch {
                which: "attempts",
                expected: usize::MAX,
                actual: bytes.len(),
            })?;
        if bytes.len() != expected {
            return Err(RecoveryError::LengthMismatch {
                which: "attempts",
                expected,
                actual: bytes.len(),
            });
        }
        let body = &bytes[HEADER_LEN..HEADER_LEN + body_len];
        let stored_crc =
            u32::from_le_bytes(bytes[expected - CRC_LEN..expected].try_into().expect("4"));
        if crc32(&bytes[..expected - CRC_LEN]) != stored_crc {
            return Err(RecoveryError::ChecksumMismatch { which: "attempts", record: 0 });
        }

        let mut sections = BTreeMap::new();
        let mut offset = 0usize;
        let mut last_circuit: Option<[u8; 32]> = None;
        for _ in 0..circuit_count {
            if body_len - offset < SECTION_FIXED_LEN {
                return Err(RecoveryError::LengthMismatch {
                    which: "attempts",
                    expected: offset + SECTION_FIXED_LEN,
                    actual: body_len,
                });
            }
            let circuit: [u8; 32] = body[offset..offset + 32].try_into().expect("32");
            // The format's canonical section order (ascending circuit id
            // bytes — what a flushed log always writes): an unsorted image
            // is not a log this code produced, fail closed.
            if last_circuit.is_some_and(|prev| circuit <= prev) {
                return Err(RecoveryError::AttemptRecordInvalid {
                    what: "circuit sections out of canonical ascending order",
                });
            }
            last_circuit = Some(circuit);
            let next_seq =
                u64::from_le_bytes(body[offset + 32..offset + 40].try_into().expect("8"));
            let revoked_at_unix =
                u64::from_le_bytes(body[offset + 40..offset + 48].try_into().expect("8"));
            let zeroized_raw =
                u64::from_le_bytes(body[offset + 48..offset + 56].try_into().expect("8"));
            let attempt_count =
                u32::from_le_bytes(body[offset + 56..offset + 60].try_into().expect("4")) as usize;
            offset += SECTION_FIXED_LEN;
            let needed = attempt_count
                .checked_mul(ATTEMPT_RECORD_LEN)
                .ok_or(RecoveryError::LengthMismatch {
                    which: "attempts",
                    expected: usize::MAX,
                    actual: body_len,
                })?;
            if body_len - offset < needed {
                return Err(RecoveryError::LengthMismatch {
                    which: "attempts",
                    expected: offset + needed,
                    actual: body_len,
                });
            }
            let mut attempts = Vec::with_capacity(attempt_count.min(MAX_PREALLOC));
            for _ in 0..attempt_count {
                let rec = &body[offset..offset + ATTEMPT_RECORD_LEN];
                let attempt_seq = u64::from_le_bytes(rec[0..8].try_into().expect("8"));
                let started_at_unix = u64::from_le_bytes(rec[8..16].try_into().expect("8"));
                let finished_raw = u64::from_le_bytes(rec[16..24].try_into().expect("8"));
                let state_tag = rec[24];
                let outcome_tag = rec[25];
                let route_id: [u8; 32] = rec[26..58].try_into().expect("32");
                let replacement_raw: [u8; 32] = rec[58..90].try_into().expect("32");
                let (state, finished_at_unix, fresh_route_id, failure, replacement_circuit_id) =
                    match state_tag {
                        0 => {
                            if outcome_tag != 0
                                || finished_raw != 0
                                || route_id != [0u8; 32]
                                || replacement_raw != [0u8; 32]
                            {
                                return Err(RecoveryError::AttemptRecordInvalid {
                                    what: "pending attempt carries completion fields",
                                });
                            }
                            (AttemptState::Pending, None, None, None, None)
                        }
                        1 => {
                            if outcome_tag != 1 || finished_raw == 0 || route_id == [0u8; 32] {
                                return Err(RecoveryError::AttemptRecordInvalid {
                                    what: "succeeded attempt lacks its route ref or finish time",
                                });
                            }
                            (
                                AttemptState::Succeeded,
                                Some(finished_raw),
                                Some(route_id),
                                None,
                                if replacement_raw == [0u8; 32] { None } else { Some(replacement_raw) },
                            )
                        }
                        2 => {
                            let failure = AttemptFailure::from_tag(outcome_tag).ok_or(
                                RecoveryError::AttemptRecordInvalid {
                                    what: "abandoned attempt carries an unknown failure tag",
                                },
                            )?;
                            if finished_raw == 0
                                || route_id != [0u8; 32]
                                || replacement_raw != [0u8; 32]
                            {
                                return Err(RecoveryError::AttemptRecordInvalid {
                                    what: "abandoned attempt lacks its failure reason or finish time",
                                });
                            }
                            (AttemptState::Abandoned, Some(finished_raw), None, Some(failure), None)
                        }
                        _ => {
                            return Err(RecoveryError::AttemptRecordInvalid {
                                what: "unknown attempt state tag",
                            })
                        }
                    };
                attempts.push(RecoveryAttempt {
                    revoked_circuit_id: circuit,
                    attempt_seq,
                    started_at_unix,
                    finished_at_unix,
                    state,
                    fresh_route_id,
                    failure,
                    replacement_circuit_id,
                });
                offset += ATTEMPT_RECORD_LEN;
            }
            let section = CircuitSection {
                next_seq,
                revoked_at_unix,
                zeroized_at_unix: if zeroized_raw == 0 { None } else { Some(zeroized_raw) },
                attempts,
            };
            section.check(&circuit)?;
            if sections.insert(circuit, section).is_some() {
                return Err(RecoveryError::AttemptRecordInvalid {
                    what: "duplicate circuit section",
                });
            }
        }
        if offset != body_len {
            return Err(RecoveryError::TrailingBytes {
                which: "attempts",
                extra: body_len - offset,
            });
        }
        Ok(AttemptInner { sections })
    }
}

/// CRC-32/IEEE — the same corruption detector as the R5-003 store.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Atomic flush: temp + fsync + rename (the R5-003 discipline).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), RecoveryError> {
    let mut os = path.as_os_str().to_os_string();
    os.push(".tmp");
    let tmp = PathBuf::from(os);
    let mut file = File::create(&tmp).map_err(|e| RecoveryError::io(RecoveryIoOp::WriteTemp, e))?;
    file.write_all(bytes).map_err(|e| RecoveryError::io(RecoveryIoOp::WriteTemp, e))?;
    file.sync_all().map_err(|e| RecoveryError::io(RecoveryIoOp::SyncTemp, e))?;
    drop(file);
    fs::rename(&tmp, path).map_err(|e| RecoveryError::io(RecoveryIoOp::RenameIntoPlace, e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests (the R7-002 "unit" verify level for the attempt log)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit as tk;

    /// A two-circuit log covering all three states, written through the
    /// public mutation paths, reloaded from disk: every record, seq,
    /// state, route ref and failure reason survives; the image is
    /// byte-deterministic (the same op sequence in a second directory
    /// produces the identical file).
    #[test]
    fn file_round_trip_all_states_and_deterministic() {
        let drive = |dir: &tk::TempDir| {
            let (ledger, w, registry, c1, c2) =
                tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
            // Both circuits are durably revoked (the §11 gate opens for both).
            ledger
                .admit(tk::NOW, &tk::policy_revocation(&w, c2, tk::NOW), &registry)
                .expect("revoke c2");
            let route_id = *w.commitment.route_id();
            let log = RecoveryAttemptLog::create(&dir.attempts_path()).expect("create");
            // c1: an abandoned attempt, then a successful one.
            assert_eq!(log.begin_attempt(&ledger, &c1, tk::NOW).unwrap(), 1);
            log.finish_attempt_with_failure(&c1, AttemptFailure::NoGatewayAvailable, tk::NOW + 1)
                .unwrap();
            assert_eq!(log.begin_attempt(&ledger, &c1, tk::NOW + 2).unwrap(), 2);
            log.finish_attempt_with_route(
                &c1,
                FreshRouteEvidence::Commitment(&w.commitment),
                tk::NOW + 3,
            )
            .unwrap();
            // c2: two abandoned attempts, then one still pending.
            assert_eq!(log.begin_attempt(&ledger, &c2, tk::NOW + 4).unwrap(), 1);
            log.finish_attempt_with_failure(&c2, AttemptFailure::GatewayUnreachable, tk::NOW + 5)
                .unwrap();
            assert_eq!(log.begin_attempt(&ledger, &c2, tk::NOW + 6).unwrap(), 2);
            log.finish_attempt_with_failure(&c2, AttemptFailure::CircuitSetupFailed, tk::NOW + 7)
                .unwrap();
            assert_eq!(log.begin_attempt(&ledger, &c2, tk::NOW + 8).unwrap(), 3);
            (log, c1, c2, route_id)
        };
        let dir = tk::TempDir::new("attempts-roundtrip");
        let (log, c1, c2, route_id) = drive(&dir);
        assert_eq!(log.record_count(), 5);
        assert_eq!(log.tracked_circuits(), {
            let mut v = vec![c1, c2];
            v.sort();
            v
        });

        // The in-memory views before the reload.
        let c1_attempts = log.attempts_for(&c1);
        assert_eq!(c1_attempts.len(), 2);
        assert_eq!(c1_attempts[0].attempt_seq(), 1);
        assert_eq!(c1_attempts[0].state(), AttemptState::Abandoned);
        assert_eq!(c1_attempts[0].failure(), Some(AttemptFailure::NoGatewayAvailable));
        assert_eq!(c1_attempts[1].attempt_seq(), 2);
        assert_eq!(c1_attempts[1].state(), AttemptState::Succeeded);
        assert_eq!(
            c1_attempts[1].fresh_route_id(),
            Some(&route_id) // derived from the verified commitment (L013)
        );
        assert_eq!(c1_attempts[1].finished_at_unix(), Some(tk::NOW + 3));
        let c2_latest = log.latest_attempt(&c2).expect("latest");
        assert_eq!(c2_latest.state(), AttemptState::Pending);
        assert_eq!(log.pending_attempt(&c2).expect("pending").attempt_seq(), 3);
        assert_eq!(log.next_attempt_seq(&c1), 3);
        assert_eq!(log.next_attempt_seq(&c2), 4);

        // Reload from disk: the whole state survives.
        let bytes_a = std::fs::read(dir.attempts_path()).unwrap();
        drop(log);
        let reloaded = RecoveryAttemptLog::load(&dir.attempts_path()).expect("load");
        assert_eq!(reloaded.attempts_for(&c1), c1_attempts);
        assert_eq!(reloaded.latest_attempt(&c2), Some(c2_latest));
        assert_eq!(reloaded.next_attempt_seq(&c1), 3);
        assert_eq!(reloaded.next_attempt_seq(&c2), 4);
        assert_eq!(reloaded.pending_attempt(&c1), None);

        // Determinism: an identical op sequence in a second directory
        // flushes the identical bytes.
        let dir_b = tk::TempDir::new("attempts-roundtrip-b");
        let (log_b, _, _, _) = drive(&dir_b);
        drop(log_b);
        assert_eq!(std::fs::read(dir_b.attempts_path()).unwrap(), bytes_a);    }

    /// The header regions: a wrong magic, an unsupported version, nonzero
    /// flags, a too-short file and an oversized file all fail closed.
    #[test]
    fn header_corruption_fails_closed() {
        let dir = tk::TempDir::new("attempts-header");
        let body = tk::attempt_section_bytes(&[0x01; 32], 1, tk::NOW, &[]);
        let good = tk::attempt_image(1, &body);

        let mut bad = good.clone();
        bad[0] = b'X';
        std::fs::write(dir.attempts_path(), &bad).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::BadMagic { which: "attempts", .. }));
        assert_eq!(err.name(), "store_bad_magic");

        let mut bad = good.clone();
        bad[4] = 9;
        std::fs::write(dir.attempts_path(), &bad).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::VersionUnsupported { which: "attempts", found: 9 }));

        let mut bad = good.clone();
        bad[6] = 2;
        std::fs::write(dir.attempts_path(), &bad).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::FlagsUnsupported { which: "attempts", found: 2 }));

        for cut in 0..HEADER_LEN {
            std::fs::write(dir.attempts_path(), &good[..cut]).unwrap();
            let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
            assert_eq!(err.name(), "store_length_mismatch", "cut {cut}: {err}");
        }

        let mut huge = good.clone();
        huge.resize(MAX_ATTEMPT_LOG_FILE_BYTES as usize + 1, 0u8);
        std::fs::write(dir.attempts_path(), &huge).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::StoreTooLarge { which: "attempts", .. }));
    }

    /// The structure regions: a lying circuit_count (both directions), a
    /// lying body_len, trailing body bytes, duplicate circuit sections
    /// and sections out of the canonical ascending order all fail closed.
    #[test]
    fn structure_lies_fail_closed() {
        let dir = tk::TempDir::new("attempts-structure");
        let s1 = tk::attempt_section_bytes(
            &[0x01; 32],
            2,
            tk::NOW,
            &[tk::abandoned_record(1, tk::NOW, 2)],
        );
        let s2 = tk::attempt_section_bytes(
            &[0x02; 32],
            1,
            tk::NOW,
            &[],
        );
        let body = [s1.clone(), s2.clone()].concat();

        // A circuit_count bigger than the body holds.
        std::fs::write(dir.attempts_path(), tk::attempt_image(3, &body)).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::LengthMismatch { which: "attempts", .. }));

        // A circuit_count smaller than the body holds (trailing sections).
        std::fs::write(dir.attempts_path(), tk::attempt_image(1, &body)).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::TrailingBytes { which: "attempts", .. }));
        assert_eq!(err.name(), "store_trailing_bytes");

        // A lying body_len (bigger than the file, then smaller).
        let mut bad = tk::attempt_image(2, &body);
        bad[12] = 0xFF;
        std::fs::write(dir.attempts_path(), &bad).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::LengthMismatch { which: "attempts", .. }));

        let good = tk::attempt_image(2, &body);
        let mut bad = good.clone();
        bad[12] = 0x01; // smaller body than the file holds
        std::fs::write(dir.attempts_path(), &bad).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::LengthMismatch { which: "attempts", .. }));

        // Extra bytes past the declared structure.
        let mut bad = good.clone();
        bad.push(0x00);
        std::fs::write(dir.attempts_path(), &bad).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::LengthMismatch { which: "attempts", .. }));

        // Duplicate circuit sections.
        let dup = [s1.clone(), s1.clone()].concat();
        std::fs::write(dir.attempts_path(), tk::attempt_image(2, &dup)).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::AttemptRecordInvalid { .. }));

        // Sections out of the canonical ascending circuit id order.
        let unsorted = [s2.clone(), s1.clone()].concat();
        std::fs::write(dir.attempts_path(), tk::attempt_image(2, &unsorted)).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(
            matches!(err, RecoveryError::AttemptRecordInvalid { .. }),
            "an unsorted section order must fail closed: {err}"
        );

        // A lying attempt_count inside a section (runs past the body) —
        // the count lives at section offset 56..60 in the v2 layout.
        let mut lying = tk::attempt_section_bytes(&[0x01; 32], 2, tk::NOW, &[]);
        lying[56..60].copy_from_slice(&9u32.to_le_bytes());
        std::fs::write(dir.attempts_path(), tk::attempt_image(1, &lying)).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::LengthMismatch { which: "attempts", .. }));

        // A body shorter than the section header alone.
        std::fs::write(dir.attempts_path(), tk::attempt_image(1, &[0u8; 10])).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::LengthMismatch { which: "attempts", .. }));
    }

    /// The record regions: every way a record can lie about its own state
    /// machine fails closed with the typed record error.
    #[test]
    fn record_corruption_fails_closed() {
        let dir = tk::TempDir::new("attempts-records");
        let circuit = [0x01; 32];
        let base = |records: &[[u8; tk::ATTEMPT_RECORD_LEN]]| {
            tk::attempt_image(1, &tk::attempt_section_bytes(&circuit, 99, tk::NOW, records))
        };

        let cases: Vec<(&str, Vec<[u8; tk::ATTEMPT_RECORD_LEN]>, &str)> = vec![
            ("unknown state tag", vec![{
                let mut r = tk::abandoned_record(1, tk::NOW, 2);
                r[24] = 3;
                r
            }], "unknown attempt state tag"),
            ("pending carries an outcome", vec![{
                let mut r = tk::pending_record(1, tk::NOW);
                r[25] = 2;
                r
            }], "pending attempt carries completion fields"),
            ("pending carries a finish time", vec![{
                let mut r = tk::pending_record(1, tk::NOW);
                r[16] = 1;
                r
            }], "pending attempt carries completion fields"),
            ("pending carries a route ref", vec![{
                let mut r = tk::pending_record(1, tk::NOW);
                r[26] = 1;
                r
            }], "pending attempt carries completion fields"),
            ("pending not last", vec![
                tk::pending_record(1, tk::NOW),
                tk::abandoned_record(2, tk::NOW, 2),
            ], "a pending attempt must be the last retained record"),
            ("succeeded without outcome tag", vec![{
                let mut r = tk::succeeded_record(1, tk::NOW, [0xA5; 32]);
                r[25] = 0;
                r
            }], "succeeded attempt lacks its route ref or finish time"),
            ("succeeded without finish time", vec![{
                let mut r = tk::succeeded_record(1, tk::NOW, [0xA5; 32]);
                r[16] = 0;
                r[17] = 0;
                r[18] = 0;
                r[19] = 0;
                r[20] = 0;
                r[21] = 0;
                r[22] = 0;
                r[23] = 0;
                r
            }], "succeeded attempt lacks its route ref or finish time"),
            ("succeeded with the zero route id", vec![{
                tk::succeeded_record(1, tk::NOW, [0u8; 32])
            }], "succeeded attempt lacks its route ref or finish time"),
            ("abandoned with an unknown failure tag", vec![{
                let mut r = tk::abandoned_record(1, tk::NOW, 2);
                r[25] = 8;
                r
            }], "abandoned attempt carries an unknown failure tag"),
            ("abandoned carrying a route ref", vec![{
                let mut r = tk::abandoned_record(1, tk::NOW, 2);
                r[26] = 0xA5;
                r
            }], "abandoned attempt lacks its failure reason or finish time"),
            ("abandoned without a finish time", vec![{
                let mut r = tk::abandoned_record(1, tk::NOW, 2);
                r[16] = 0;
                r[17] = 0;
                r[18] = 0;
                r[19] = 0;
                r[20] = 0;
                r[21] = 0;
                r[22] = 0;
                r[23] = 0;
                r
            }], "abandoned attempt lacks its failure reason or finish time"),
            ("finish predates the start", vec![{
                // started_at = NOW+2 while finished_at = NOW+1
                let mut s = tk::abandoned_record(1, tk::NOW, 2);
                s[8..16].copy_from_slice(&(tk::NOW + 2).to_le_bytes());
                s
            }], "finish time predates the attempt's start"),
        ];
        for (name, records, what) in cases {
            std::fs::write(dir.attempts_path(), base(&records)).unwrap();
            let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
            assert_eq!(err.name(), "attempt_record_invalid", "{name}: {err}");
            match err {
                RecoveryError::AttemptRecordInvalid { what: found } => assert_eq!(found, what, "{name}"),
                other => panic!("{name}: wrong variant {other:?}"),
            }
        }
    }

    /// The sequence regions: non-increasing seqs, a seq at or past the
    /// high-water mark, an empty section with a moved high-water, a
    /// retained-record count past the compaction bound, and attempts that
    /// follow a terminal success — all typed.
    #[test]
    fn sequence_and_bound_violations_fail_closed() {
        let dir = tk::TempDir::new("attempts-seq");
        let circuit = [0x01; 32];
        let base = |next_seq: u64, records: &[[u8; tk::ATTEMPT_RECORD_LEN]]| {
            tk::attempt_image(1, &tk::attempt_section_bytes(&circuit, next_seq, tk::NOW, records))
        };

        // A repeated seq.
        let records = vec![tk::abandoned_record(1, tk::NOW, 2), tk::abandoned_record(1, tk::NOW, 3)];
        std::fs::write(dir.attempts_path(), base(3, &records)).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert_eq!(err.name(), "attempt_sequence_not_increasing");

        // A seq at the high-water mark.
        let records = vec![tk::abandoned_record(1, tk::NOW, 2), tk::abandoned_record(2, tk::NOW, 3)];
        std::fs::write(dir.attempts_path(), base(2, &records)).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert_eq!(err.name(), "attempt_sequence_not_increasing");

        // An empty section whose high-water is not the initial 1.
        std::fs::write(dir.attempts_path(), base(5, &[])).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert_eq!(err.name(), "attempt_record_invalid");
        match err {
            RecoveryError::AttemptRecordInvalid { what } => {
                assert_eq!(what, "empty section must carry the initial high-water mark")
            }
            other => panic!("wrong variant {other:?}"),
        }

        // More retained records than the compaction bound allows.
        let records: Vec<_> = (1..=MAX_ATTEMPT_RECORDS_PER_CIRCUIT + 1)
            .map(|seq| tk::abandoned_record(seq as u64, tk::NOW, 2))
            .collect();
        std::fs::write(dir.attempts_path(), base(records.len() as u64 + 1, &records)).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        match err {
            RecoveryError::AttemptRecordInvalid { what } => {
                assert_eq!(what, "retained attempt records exceed the compaction bound")
            }
            other => panic!("wrong variant {other:?}"),
        }

        // An abandoned attempt after a terminal success.
        let records = vec![
            tk::succeeded_record(1, tk::NOW, [0xA5; 32]),
            tk::abandoned_record(2, tk::NOW, 2),
        ];
        std::fs::write(dir.attempts_path(), base(3, &records)).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::AttemptAfterSuccessPersisted { .. }));
        assert_eq!(err.name(), "attempt_after_success_persisted");

        // Two succeeded attempts.
        let records = vec![
            tk::succeeded_record(1, tk::NOW, [0xA5; 32]),
            tk::succeeded_record(2, tk::NOW, [0xA6; 32]),
        ];
        std::fs::write(dir.attempts_path(), base(3, &records)).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert_eq!(err.name(), "attempt_after_success_persisted");

        // Exactly the bound (63 abandoned + the terminal success) is legal.
        let mut records: Vec<_> = (1..=MAX_ATTEMPT_RECORDS_PER_CIRCUIT - 1)
            .map(|seq| tk::abandoned_record(seq as u64, tk::NOW, 2))
            .collect();
        records.push(tk::succeeded_record(MAX_ATTEMPT_RECORDS_PER_CIRCUIT as u64, tk::NOW, [0xA5; 32]));
        std::fs::write(dir.attempts_path(), base(records.len() as u64 + 1, &records)).unwrap();
        let log = RecoveryAttemptLog::load(&dir.attempts_path()).expect("at the bound is legal");
        assert_eq!(log.attempts_for(&circuit).len(), MAX_ATTEMPT_RECORDS_PER_CIRCUIT);
    }

    /// The CRC trailer guards the whole image: a flip anywhere — header,
    /// body, or the trailer itself — is a typed checksum mismatch and
    /// NOTHING loads.
    #[test]
    fn crc_trailer_guards_the_image() {
        let dir = tk::TempDir::new("attempts-crc");
        let body = tk::attempt_section_bytes(
            &[0x01; 32],
            2,
            tk::NOW,
            &[tk::abandoned_record(1, tk::NOW, 2)],
        );
        let good = tk::attempt_image(1, &body);
        // Every byte of the image EXCEPT the regions guarded by earlier,
        // more specific checks (magic/version/flags at 0..8, the body_len
        // at 12..16 whose corruption is a length mismatch) — so the CRC
        // is what fires — plus the trailer itself.
        for at in (8..good.len()).filter(|at| !(12..16).contains(at)) {
            let mut bad = good.clone();
            bad[at] ^= 0x01;
            std::fs::write(dir.attempts_path(), &bad).unwrap();
            let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
            assert_eq!(err.name(), "store_checksum_mismatch", "flip at {at}: {err}");
            assert!(matches!(err, RecoveryError::ChecksumMismatch { which: "attempts", .. }));
        }
    }

    /// The §11 ordering gate: an attempt for a circuit the durable ledger
    /// does not show revoked — unknown AND known-but-live — is refused
    /// typed, and NOTHING is written.
    #[test]
    fn begin_refuses_unrevoked_circuits() {
        let dir = tk::TempDir::new("attempts-gate");
        let (ledger, _w, _registry, _revoked, live) = tk::revoked_ledger(
            &dir.ledger_path(),
            tk::NOW,
        );
        let log = RecoveryAttemptLog::create(&dir.attempts_path()).expect("create");
        let before = std::fs::read(dir.attempts_path()).unwrap();

        let err = log.begin_attempt(&ledger, &[0xEE; 32], tk::NOW).unwrap_err();
        assert!(matches!(err, RecoveryError::CircuitNotRevoked { circuit_id } if circuit_id == [0xEE; 32]));
        assert_eq!(err.name(), "circuit_not_revoked");

        let err = log.begin_attempt(&ledger, &live, tk::NOW).unwrap_err();
        assert!(matches!(err, RecoveryError::CircuitNotRevoked { .. }));
        assert_eq!(err.name(), "circuit_not_revoked");

        assert_eq!(std::fs::read(dir.attempts_path()).unwrap(), before);
        assert_eq!(log.record_count(), 0);
        assert_eq!(log.tracked_circuits(), Vec::<[u8; 32]>::new());
    }

    /// The lifecycle refusals and the per-circuit monotonic numbering:
    /// single-flight while pending, terminal after success, continuation
    /// after abandonment — and independent numbering per circuit.
    #[test]
    fn lifecycle_refusals_and_monotonic_numbering() {
        let dir = tk::TempDir::new("attempts-lifecycle");
        let (ledger, w, _registry, revoked, live) = tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        let log = RecoveryAttemptLog::create(&dir.attempts_path()).expect("create");

        // Single flight: a second begin while the first is pending.
        assert_eq!(log.begin_attempt(&ledger, &revoked, tk::NOW).unwrap(), 1);
        let err = log.begin_attempt(&ledger, &revoked, tk::NOW + 1).unwrap_err();
        assert!(matches!(
            err,
            RecoveryError::AttemptAlreadyPending { circuit_id, attempt_seq: 1 } if circuit_id == revoked
        ));
        assert_eq!(err.name(), "attempt_already_pending");

        // Abandon, then the numbering continues at 2.
        log.finish_attempt_with_failure(&revoked, AttemptFailure::VerificationFailed, tk::NOW + 2)
            .unwrap();
        assert_eq!(log.begin_attempt(&ledger, &revoked, tk::NOW + 3).unwrap(), 2);

        // Success is terminal: no attempt after it, ever.
        log.finish_attempt_with_route(
            &revoked,
            FreshRouteEvidence::Commitment(&w.commitment),
            tk::NOW + 4,
        )
        .unwrap();
        let err = log.begin_attempt(&ledger, &revoked, tk::NOW + 5).unwrap_err();
        assert!(matches!(
            err,
            RecoveryError::RecoveryAlreadyComplete { circuit_id, attempt_seq: 2, fresh_route_id }
            if circuit_id == revoked && fresh_route_id == *w.commitment.route_id()
        ));
        assert_eq!(err.name(), "recovery_already_complete");

        // Nothing is pending to finish anymore.
        let err = log
            .finish_attempt_with_failure(&revoked, AttemptFailure::AbortedLocal, tk::NOW + 6)
            .unwrap_err();
        assert!(matches!(err, RecoveryError::NoPendingAttempt { .. }));

        // An independent circuit numbers independently — the moment it
        // is durably revoked (its own gate stays closed until then).
        assert_eq!(
            log.begin_attempt(&ledger, &live, tk::NOW).unwrap_err().name(),
            "circuit_not_revoked"
        );
        assert_eq!(log.next_attempt_seq(&revoked), 3);
        assert_eq!(log.attempts_for(&revoked).len(), 2);
    }

    /// The finish paths: typed refusals for no-pending, time inversion
    /// and the reserved zero route ref; abandonment records the reason
    /// durably; success records the route ref and the finish time.
    #[test]
    fn finish_paths_typed() {
        let dir = tk::TempDir::new("attempts-finish");
        let (ledger, _w, _registry, revoked, _live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);

        // No pending attempt on an unknown circuit.
        let log = RecoveryAttemptLog::create(&dir.attempts_path()).expect("create");
        let err = log
            .finish_attempt_with_failure(&[0xEE; 32], AttemptFailure::AbortedLocal, tk::NOW)
            .unwrap_err();
        assert!(matches!(err, RecoveryError::NoPendingAttempt { .. }));
        let err = log
            .finish_attempt_with_route(&[0xEE; 32], FreshRouteEvidence::RouteRef([1; 32]), tk::NOW)
            .unwrap_err();
        assert_eq!(err.name(), "no_pending_attempt");

        // A finish time before the attempt's start is typed.
        assert_eq!(log.begin_attempt(&ledger, &revoked, tk::NOW + 10).unwrap(), 1);
        let err = log
            .finish_attempt_with_failure(&revoked, AttemptFailure::AbortedLocal, tk::NOW + 9)
            .unwrap_err();
        match err {
            RecoveryError::AttemptRecordInvalid { what } => {
                assert_eq!(what, "finish time predates the attempt's start")
            }
            other => panic!("wrong variant {other:?}"),
        }
        // The refusal wrote nothing: the attempt is still pending.
        assert_eq!(log.pending_attempt(&revoked).expect("still pending").attempt_seq(), 1);

        // The reserved all-zero route ref is typed.
        let err = log
            .finish_attempt_with_route(&revoked, FreshRouteEvidence::RouteRef([0u8; 32]), tk::NOW + 20)
            .unwrap_err();
        assert_eq!(err.name(), "attempt_record_invalid");

        // A caller-verified route ref is recorded as-is (the R7-003 seam).
        let route = [0xB7; 32];
        log.finish_attempt_with_route(&revoked, FreshRouteEvidence::RouteRef(route), tk::NOW + 20)
            .unwrap();
        let record = log.latest_attempt(&revoked).expect("latest");
        assert_eq!(record.state(), AttemptState::Succeeded);
        assert_eq!(record.fresh_route_id(), Some(&route));
        assert_eq!(record.finished_at_unix(), Some(tk::NOW + 20));
    }

    /// The fresh-route evidence: a verified commitment is checked for
    /// §11 freshness against the revocation anchor; a stale or invalid
    /// commitment is refused typed while the attempt STAYS PENDING (a
    /// later, honest finish still works).
    #[test]
    fn fresh_route_evidence_verification() {
        let dir = tk::TempDir::new("attempts-fresh");
        // A revocation at NOW+100: the world's commitment (proposed at
        // NOW) predates it -> not fresh.
        let (ledger, w, mut registry, revoked, _live) = {
            let w = tk::world(tk::NOW);
            let mut registry = sharenet_protocol::circuit::CircuitRegistry::new();
            let revoked = tk::admit_circuit(&w, &mut registry, tk::NOW, [0x71; 32]);
            let live = tk::admit_circuit(&w, &mut registry, tk::NOW, [0x72; 32]);
            let store =
                crate::ledger::DurableRevocationLedger::create(&dir.ledger_path()).expect("create");
            store
                .admit(tk::NOW + 100, &tk::link_failure_revocation(&w, revoked, tk::NOW + 100), &registry)
                .unwrap();
            (store, w, registry, revoked, live)
        };
        let log = RecoveryAttemptLog::create(&dir.attempts_path()).expect("create");
        assert_eq!(log.begin_attempt(&ledger, &revoked, tk::NOW + 110).unwrap(), 1);

        // Stale: proposed before the revocation that started the recovery.
        let err = log
            .finish_attempt_with_route(
                &revoked,
                FreshRouteEvidence::Commitment(&w.commitment),
                tk::NOW + 110,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            RecoveryError::RouteNotFresh { proposed_at, revoked_at: anchor }
            if proposed_at == tk::NOW && anchor == tk::NOW + 100
        ));
        assert_eq!(err.name(), "route_not_fresh");
        // The refusal left the attempt open.
        assert_eq!(log.pending_attempt(&revoked).expect("still pending").attempt_seq(), 1);

        // Invalid: the commitment's verification window has closed by the
        // caller's now (proposed NOW, expires NOW+3600).
        let err = log
            .finish_attempt_with_route(
                &revoked,
                FreshRouteEvidence::Commitment(&w.commitment),
                tk::NOW + 7200,
            )
            .unwrap_err();
        assert_eq!(err.name(), "route_commitment_invalid");

        // A FRESH commitment (proposed after the revocation) verifies and
        // records: a new world whose route was proposed at NOW+120.
        let fresh_world = tk::world(tk::NOW + 120);
        let fresh_circuit = tk::admit_circuit(&fresh_world, &mut registry, tk::NOW + 120, [0x77; 32]);
        assert_ne!(fresh_circuit, revoked);
        log.finish_attempt_with_route(
            &revoked,
            FreshRouteEvidence::Commitment(&fresh_world.commitment),
            tk::NOW + 130,
        )
        .unwrap();
        let record = log.latest_attempt(&revoked).expect("latest");
        assert_eq!(record.state(), AttemptState::Succeeded);
        assert_eq!(record.fresh_route_id(), Some(fresh_world.commitment.route_id()));
    }

    /// The bounded-log compaction law: at most MAX_ATTEMPT_RECORDS_PER_
    /// CIRCUIT retained attempts, the OLDEST abandoned dropped first,
    /// the pending and the succeeded never dropped, and the persisted
    /// high-water mark never regresses (also across a reload).
    #[test]
    fn bounded_compaction_law() {
        let dir = tk::TempDir::new("attempts-compaction");
        let (ledger, w, _registry, revoked, _live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        let log = RecoveryAttemptLog::create(&dir.attempts_path()).expect("create");

        // MAX+6 abandoned attempts: the retained window is the last MAX.
        let total = MAX_ATTEMPT_RECORDS_PER_CIRCUIT + 6;
        for i in 0..total {
            assert_eq!(log.begin_attempt(&ledger, &revoked, tk::NOW + i as u64).unwrap(), i as u64 + 1);
            log.finish_attempt_with_failure(&revoked, AttemptFailure::GatewayUnreachable, tk::NOW + i as u64)
                .unwrap();
        }
        let attempts = log.attempts_for(&revoked);
        assert_eq!(attempts.len(), MAX_ATTEMPT_RECORDS_PER_CIRCUIT);
        let first_seq = (total - MAX_ATTEMPT_RECORDS_PER_CIRCUIT + 1) as u64;
        assert_eq!(attempts.first().unwrap().attempt_seq(), first_seq);
        assert_eq!(attempts.last().unwrap().attempt_seq(), total as u64);
        for (a, b) in attempts.iter().zip(attempts.iter().skip(1)) {
            assert!(b.attempt_seq() > a.attempt_seq());
        }
        assert_eq!(log.next_attempt_seq(&revoked), total as u64 + 1);

        // The pending attempt is never the compaction victim: opening a
        // new attempt keeps it while the OLDEST abandoned is dropped.
        assert_eq!(log.begin_attempt(&ledger, &revoked, tk::NOW + 100).unwrap(), total as u64 + 1);
        let attempts = log.attempts_for(&revoked);
        assert_eq!(attempts.len(), MAX_ATTEMPT_RECORDS_PER_CIRCUIT);
        assert_eq!(attempts.last().unwrap().state(), AttemptState::Pending);
        assert_eq!(attempts.last().unwrap().attempt_seq(), total as u64 + 1);
        assert_eq!(attempts.first().unwrap().attempt_seq(), first_seq + 1);

        // Success stays terminal inside a full window: the succeeded
        // record is retained, nothing follows it, and a reload agrees.
        log.finish_attempt_with_route(
            &revoked,
            FreshRouteEvidence::Commitment(&w.commitment),
            tk::NOW + 101,
        )
        .unwrap();
        let before = log.attempts_for(&revoked);
        assert_eq!(before.last().unwrap().state(), AttemptState::Succeeded);
        drop(log);
        let reloaded = RecoveryAttemptLog::load(&dir.attempts_path()).expect("load");
        assert_eq!(reloaded.attempts_for(&revoked), before);
        assert_eq!(reloaded.next_attempt_seq(&revoked), total as u64 + 2);
        // The high-water survives the reload: the next attempt (were the
        // circuit not recovered) would continue, never restart.
        let err = reloaded.begin_attempt(&ledger, &revoked, tk::NOW + 102).unwrap_err();
        assert_eq!(err.name(), "recovery_already_complete");
    }

    /// The hard file cap: a crafted-but-lawful image within the cap loads,
    /// an image past it refuses typed, and a mutation that would push the
    /// file past the cap refuses typed with NOTHING written and the
    /// in-memory state intact.
    #[test]
    fn file_cap_enforced_both_sides() {
        let dir = tk::TempDir::new("attempts-cap");
        let cap = MAX_ATTEMPT_LOG_FILE_BYTES as usize;
        let (ledger, _w, _registry, revoked, _live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);

        // A lawful near-cap image: the real revoked circuit's section with
        // MAX-1 abandoned records, plus empty filler sections (52 bytes
        // each) sized so one more record would overflow the cap.
        let records: Vec<_> = (1..MAX_ATTEMPT_RECORDS_PER_CIRCUIT)
            .map(|seq| tk::abandoned_record(seq as u64, tk::NOW, 2))
            .collect();
        let fixed = HEADER_LEN
            + CRC_LEN
            + (SECTION_FIXED_LEN + ATTEMPT_RECORD_LEN * records.len());
        let filler_count = (cap - fixed) / SECTION_FIXED_LEN;
        let mut sections: Vec<([u8; 32], Vec<u8>)> = vec![
            (
                revoked,
                tk::attempt_section_bytes(
                    &revoked,
                    MAX_ATTEMPT_RECORDS_PER_CIRCUIT as u64,
                    tk::NOW,
                    &records,
                ),
            ),
        ];
        for i in 1..=filler_count {
            // Ascending, distinct big-endian ids (never colliding with the
            // revoked circuit's hashed id in practice; guarded anyway).
            let mut id = [0u8; 32];
            id[16..32].copy_from_slice(&(i as u128).to_be_bytes());
            if id == revoked {
                continue;
            }
            sections.push((id, tk::attempt_section_bytes(&id, 1, tk::NOW, &[])));
        }
        sections.sort_by(|a, b| a.0.cmp(&b.0)); // the canonical ascending order
        let body: Vec<u8> = sections.iter().flat_map(|(_, s)| s.iter().copied()).collect();
        let near = tk::attempt_image(sections.len() as u32, &body);
        assert!(near.len() <= cap, "the crafted image must be inside the cap");
        assert!(near.len() + ATTEMPT_RECORD_LEN > cap, "one more record must overflow");
        std::fs::write(dir.attempts_path(), &near).unwrap();
        let log = RecoveryAttemptLog::load(&dir.attempts_path()).expect("near-cap loads");

        // Write side: the next begin on the revoked circuit would add one
        // record past the cap -> typed refusal, nothing written.
        let err = log.begin_attempt(&ledger, &revoked, tk::NOW + 1).unwrap_err();
        assert!(matches!(err, RecoveryError::StoreTooLarge { which: "attempts", .. }));
        assert_eq!(err.name(), "store_too_large");
        assert_eq!(std::fs::read(dir.attempts_path()).unwrap(), near);
        // The pre-mutation state is intact (the discipline: clone ->
        // mutate -> serialize -> refuse -> keep the old state).
        assert_eq!(log.next_attempt_seq(&revoked), MAX_ATTEMPT_RECORDS_PER_CIRCUIT as u64);
        assert_eq!(log.attempts_for(&revoked).len(), records.len());

        // Read side: an image past the cap refuses before parsing.
        let mut over = near.clone();
        over.resize(cap + 1, 0u8);
        std::fs::write(dir.path.join("over.store"), &over).unwrap();
        let err = RecoveryAttemptLog::load(&dir.path.join("over.store")).unwrap_err();
        assert!(matches!(err, RecoveryError::StoreTooLarge { which: "attempts", .. }));
    }

    /// `create` never clobbers and a missing file is a typed I/O error;
    /// the frozen failure vocabulary round-trips through its machine
    /// names (later items compose on these names).
    #[test]
    fn store_hygiene_and_frozen_vocabularies() {
        let dir = tk::TempDir::new("attempts-hygiene");
        let log = RecoveryAttemptLog::create(&dir.attempts_path()).expect("create");
        let err = RecoveryAttemptLog::create(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::StoreAlreadyExists { .. }));
        assert_eq!(err.name(), "store_already_exists");
        drop(log);

        let err = RecoveryAttemptLog::load(&dir.path.join("missing.store")).unwrap_err();
        assert!(matches!(err, RecoveryError::Io { .. }));
        assert_eq!(err.op(), Some(RecoveryIoOp::ReadStore));

        for failure in AttemptFailure::ALL {
            assert_eq!(AttemptFailure::from_name(failure.as_str()), Some(failure));
        }
        assert_eq!(AttemptFailure::from_name("nope"), None);
        assert_eq!(AttemptFailure::ALL.len(), 6);
        for state in [AttemptState::Pending, AttemptState::Succeeded, AttemptState::Abandoned] {
            assert_eq!(state.as_str(), format!("{state}"));
        }
    }

    /// The seq high-water is bounded arithmetic: a persisted high-water
    /// at u64::MAX refuses the next begin typed (no overflow, no wrap).
    #[test]
    fn seq_overflow_refused() {
        let dir = tk::TempDir::new("attempts-overflow");
        let (ledger, _w, _registry, revoked, _live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        let records = vec![tk::abandoned_record(u64::MAX - 1, tk::NOW, 2)];
        let body = tk::attempt_section_bytes(&revoked, u64::MAX, tk::NOW, &records);
        std::fs::write(dir.attempts_path(), tk::attempt_image(1, &body)).unwrap();
        let log = RecoveryAttemptLog::load(&dir.attempts_path()).expect("load");
        let err = log.begin_attempt(&ledger, &revoked, tk::NOW + 1).unwrap_err();
        match err {
            RecoveryError::AttemptRecordInvalid { what } => assert_eq!(what, "attempt seq overflow"),
            other => panic!("wrong variant {other:?}"),
        }
    }

    // -- R7-004: the zeroization fact + the replacement circuit fact ------

    /// The §11 zeroization fact: recorded only for durably revoked
    /// circuits, only after the revocation anchor, at most once — and the
    /// durable fact survives a full teardown/reload exactly.
    #[test]
    fn zeroization_round_trip_and_refusals() {
        let dir = tk::TempDir::new("attempts-zeroization");
        let (ledger, w, registry, revoked, live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        let log = RecoveryAttemptLog::create(&dir.attempts_path()).expect("create");

        // §11 ordering: zeroization follows durable invalidation — a
        // not-revoked circuit (and an unknown one) is refused typed.
        let err = log.record_zeroization(&ledger, &live, tk::NOW).unwrap_err();
        assert_eq!(err.name(), "circuit_not_revoked");
        let err = log.record_zeroization(&ledger, &[0xEE; 32], tk::NOW).unwrap_err();
        assert_eq!(err.name(), "circuit_not_revoked");

        // The clock predating the ledger's anchor is refused typed.
        // (The revoked circuit's anchor is NOW — the ledger was built
        // with revoked_at = NOW; the live sibling anchors the contrast.)
        let _ = w;
        let err = log.record_zeroization(&ledger, &revoked, tk::NOW - 1).unwrap_err();
        assert_eq!(err.name(), "zeroization_before_revocation");

        // The happy path: durable before visible, queryable.
        assert_eq!(log.zeroization(&revoked), None);
        let record = log.record_zeroization(&ledger, &revoked, tk::NOW + 2).expect("zeroize");
        assert_eq!(record.revoked_circuit_id(), &revoked);
        assert_eq!(record.zeroized_at_unix(), tk::NOW + 2);
        assert!(format!("{record}").contains("zeroized at"));
        assert_eq!(
            log.zeroization(&revoked),
            Some(ZeroizationRecord {
                revoked_circuit_id: revoked,
                zeroized_at_unix: tk::NOW + 2,
            })
        );

        // At most once: the durable fact stands.
        let err = log.record_zeroization(&ledger, &revoked, tk::NOW + 3).unwrap_err();
        assert!(matches!(
            err,
            RecoveryError::CircuitAlreadyZeroized { circuit_id, zeroized_at_unix }
                if circuit_id == revoked && zeroized_at_unix == tk::NOW + 2
        ));
        assert_eq!(err.name(), "circuit_already_zeroized");

        // The zeroization survives a full teardown/reload — the ordering
        // fact (invalidation -> zeroization) is durable.
        drop(log);
        let reloaded = RecoveryAttemptLog::load(&dir.attempts_path()).expect("reload");
        let fact = reloaded.zeroization(&revoked).expect("the durable fact");
        assert_eq!(fact.zeroized_at_unix(), tk::NOW + 2);
        assert!(fact.zeroized_at_unix() >= tk::NOW, "after the anchor");
        assert_eq!(reloaded.zeroization(&live), None);
        let _ = registry;
    }

    /// The replacement circuit fact: recorded on the SUCCEEDED attempt
    /// (bound to its recorded fresh route, only after zeroization, at
    /// most once) and it survives a full teardown/reload exactly.
    #[test]
    fn replacement_record_round_trip_and_refusals() {
        let dir = tk::TempDir::new("attempts-replacement");
        let (ledger, w, _registry, revoked, _live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        let log = RecoveryAttemptLog::create(&dir.attempts_path()).expect("create");

        // Nothing succeeded yet: no section, a pending tail, an abandoned
        // tail — all `no_succeeded_attempt`.
        let route = *w.commitment.route_id();
        let replacement = [0x99; 32];
        let err = log.record_replacement_circuit(&revoked, &route, &replacement, tk::NOW).unwrap_err();
        assert_eq!(err.name(), "no_succeeded_attempt");
        log.begin_attempt(&ledger, &revoked, tk::NOW).unwrap();
        let err = log.record_replacement_circuit(&revoked, &route, &replacement, tk::NOW).unwrap_err();
        assert_eq!(err.name(), "no_succeeded_attempt");
        log.finish_attempt_with_failure(&revoked, AttemptFailure::CircuitSetupFailed, tk::NOW + 1)
            .unwrap();
        let err = log.record_replacement_circuit(&revoked, &route, &replacement, tk::NOW).unwrap_err();
        assert_eq!(err.name(), "no_succeeded_attempt");

        // A succeeded attempt over the world's commitment — but the §11
        // zeroization fact is not recorded yet.
        log.begin_attempt(&ledger, &revoked, tk::NOW + 2).unwrap();
        log.finish_attempt_with_route(
            &revoked,
            FreshRouteEvidence::Commitment(&w.commitment),
            tk::NOW + 3,
        )
        .unwrap();
        let err = log.record_replacement_circuit(&revoked, &route, &replacement, tk::NOW + 4).unwrap_err();
        assert_eq!(err.name(), "zeroization_missing");

        // A foreign route is refused even with everything else in place.
        log.record_zeroization(&ledger, &revoked, tk::NOW + 5).unwrap();
        let foreign_route = [0xAB; 32];
        let err = log
            .record_replacement_circuit(&revoked, &foreign_route, &replacement, tk::NOW + 6)
            .unwrap_err();
        assert!(matches!(
            err,
            RecoveryError::ReplacementRouteMismatch { circuit_id, expected_route_id, offered_route_id }
                if circuit_id == revoked
                    && expected_route_id == route
                    && offered_route_id == foreign_route
        ));
        assert_eq!(err.name(), "replacement_route_mismatch");

        // The happy path: the replacement lands on the succeeded attempt.
        assert_eq!(
            log.record_replacement_circuit(&revoked, &route, &replacement, tk::NOW + 7).unwrap(),
            2
        );
        let latest = log.latest_attempt(&revoked).expect("latest");
        assert_eq!(latest.state(), AttemptState::Succeeded);
        assert_eq!(latest.replacement_circuit_id(), Some(&replacement));

        // Single replacement per recovery.
        let err =
            log.record_replacement_circuit(&revoked, &route, &[0x77; 32], tk::NOW + 8).unwrap_err();
        assert!(matches!(
            err,
            RecoveryError::ReplacementAlreadyEstablished {
                circuit_id,
                attempt_seq: 2,
                replacement_circuit_id,
            } if circuit_id == revoked && replacement_circuit_id == replacement
        ));
        assert_eq!(err.name(), "replacement_already_established");

        // The all-zero id is reserved (never a derived replacement).
        let err = log
            .record_replacement_circuit(&revoked, &route, &[0u8; 32], tk::NOW + 9)
            .unwrap_err();
        assert_eq!(err.name(), "attempt_record_invalid");

        // The whole fact set survives a full teardown/reload.
        drop(log);
        let reloaded = RecoveryAttemptLog::load(&dir.attempts_path()).expect("reload");
        let latest = reloaded.latest_attempt(&revoked).expect("latest");
        assert_eq!(latest.attempt_seq(), 2);
        assert_eq!(latest.replacement_circuit_id(), Some(&replacement));
        assert_eq!(reloaded.zeroization(&revoked).expect("fact").zeroized_at_unix(), tk::NOW + 5);
    }

    /// The v2 layout laws: an old (v1) image is refused typed (no silent
    /// reinterpretation of the 52/58-byte layout), the new zeroization
    /// and replacement regions round-trip through the public paths, and
    /// the crafted new-field corruptions fail closed.
    #[test]
    fn format_v2_old_layouts_and_new_fields_fail_closed() {
        let dir = tk::TempDir::new("attempts-v2");
        // A well-formed v2 body — offered with the v1 version bytes it is
        // the typed old/new mixup refusal.
        let body = tk::attempt_section_bytes(&[0x01; 32], 2, tk::NOW, &[]);
        let v1 = tk::attempt_image_with_version(1, &body, 1);
        std::fs::write(dir.attempts_path(), &v1).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::VersionUnsupported { which: "attempts", found: 1 }));
        assert_eq!(err.name(), "store_version_unsupported");

        // The zeroized + replaced shape round-trips (crafted, then loaded).
        let circuit = [0x02; 32];
        let route = [0xA5; 32];
        let replacement = [0x66; 32];
        let body = tk::attempt_section_bytes_with_zeroization(
            &circuit,
            3,
            tk::NOW,
            tk::NOW + 5,
            &[tk::succeeded_record_replaced(2, tk::NOW + 1, route, replacement)],
        );
        std::fs::write(dir.attempts_path(), tk::attempt_image(1, &body)).unwrap();
        let log = RecoveryAttemptLog::load(&dir.attempts_path()).expect("load");
        let latest = log.latest_attempt(&circuit).expect("latest");
        assert_eq!(latest.replacement_circuit_id(), Some(&replacement));
        assert_eq!(log.zeroization(&circuit).expect("zeroized").zeroized_at_unix(), tk::NOW + 5);

        // A zeroization predating the revocation anchor never loads.
        let body = tk::attempt_section_bytes_with_zeroization(
            &circuit,
            3,
            tk::NOW,
            tk::NOW - 1,
            &[tk::succeeded_record(2, tk::NOW + 1, route)],
        );
        std::fs::write(dir.attempts_path(), tk::attempt_image(1, &body)).unwrap();
        let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::AttemptRecordInvalid { .. }));
        assert_eq!(err.name(), "attempt_record_invalid");

        // A replacement field on a NON-succeeded record never loads.
        for state_tag in [0u8, 2u8] {
            let mut record = if state_tag == 0 {
                tk::pending_record(2, tk::NOW + 1)
            } else {
                tk::abandoned_record(2, tk::NOW + 1, 3)
            };
            record[58] = 0x66; // a nonzero replacement on a non-terminal record
            let body = tk::attempt_section_bytes(&circuit, 3, tk::NOW, &[record]);
            std::fs::write(dir.attempts_path(), tk::attempt_image(1, &body)).unwrap();
            let err = RecoveryAttemptLog::load(&dir.attempts_path()).unwrap_err();
            assert_eq!(err.name(), "attempt_record_invalid", "state tag {state_tag}");
        }
    }
}
