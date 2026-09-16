//! The recovery-driver skeleton — work item R7-002's composition layer.
//!
//! Architecture §11's failure pipeline:
//!
//! ```text
//! link failure
//!     ↓
//! durable circuit invalidation      ← R7-001 (the revocation)
//!     ↓
//! zeroization                       ← R7-004 (replacement circuit)
//!     ↓
//! recovery attempt                   ← THIS CRATE (durable, bounded)
//!     ↓
//! fresh gateway selection            ← R7-003 (the seam below)
//!     ↓
//! fresh route commitment             ← R7-003 (verified here when in hand)
//!     ↓
//! fresh circuit session              ← R7-004
//!     ↓
//! verification                       ← R7-003/R7-004
//! ```
//!
//! The driver owns the two durable stores (the ledger file + the attempt
//! log) and exposes the attempt lifecycle exactly as far as R7-002's
//! scope reaches:
//!
//! - [`Self::attempt_next`] — the §11 entry point: it cross-checks the
//!   DURABLE ledger (only a durably revoked circuit may enter
//!   recovery), refuses when recovery is already complete or an
//!   attempt is in flight, opens and DURABLY records the next
//!   per-circuit attempt (pending), and returns the typed next step —
//!   [`RecoveryStep::SelectFreshGateway`]. **Fresh gateway selection
//!   itself is R7-003 scope**: this is the documented seam. The caller
//!   (R7-003) selects a fresh gateway, builds the fresh route
//!   commitment, and reports back;
//! - [`Self::attempt_succeeded`] — the fresh route commitment evidence
//!   is recorded (verified in full when the commitment is in hand:
//!   R3-004 chain + §11 freshness vs. the revocation anchor);
//! - [`Self::attempt_failed`] — the typed failure reason is recorded
//!   and the attempt is abandoned (a LATER attempt may then be opened —
//!   R7-005 owns the retry/backoff policy);
//! - [`Self::revocation_ledger`] hands out the R7-001 ledger view to
//!   install into a `CircuitRegistry` (`install_revocation_ledger`) so
//!   the L015 gate is live for every circuit admission in this process.
//!
//! What the skeleton deliberately does NOT do: gateway selection,
//! route construction, circuit setup, verification driving (R7-003 +
//! R7-004), retry/backoff (R7-005), concurrent-recovery coordination
//! (R7-006). The seams are the typed parameters the callers bring back.

use std::path::{Path, PathBuf};

use sharenet_protocol::circuit::CircuitRegistry;
use sharenet_protocol::revocation::RevocationAdmitOutcome;

use crate::attempt::{FreshRouteEvidence, RecoveryAttemptLog, AttemptFailure};
use crate::error::RecoveryError;
use crate::ledger::{DurableRevocationLedger, LedgerLoadReport};

/// The ledger file name inside the driver's directory.
pub const LEDGER_FILE_NAME: &str = "revocations.log";
/// The attempt-log file name inside the driver's directory.
pub const ATTEMPT_LOG_FILE_NAME: &str = "recovery-attempts.store";

/// The typed next step of the §11 pipeline, as far as this crate's scope
/// reaches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryStep {
    /// A recovery attempt is now open and DURABLE (pending). The
    /// pipeline continues at FRESH GATEWAY SELECTION — the R7-003 seam.
    /// The R7-003 caller brings back either a fresh route commitment
    /// ([`RecoveryDriver::attempt_succeeded`]) or a typed failure
    /// ([`RecoveryDriver::attempt_failed`]).
    SelectFreshGateway {
        /// The revoked circuit this recovery is for (never resurrected —
        /// L015).
        revoked_circuit_id: [u8; 32],
        /// The per-circuit monotonic attempt number just opened.
        attempt_seq: u64,
    },
}

impl RecoveryStep {
    /// Stable machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            RecoveryStep::SelectFreshGateway { .. } => "select_fresh_gateway",
        }
    }
}

impl std::fmt::Display for RecoveryStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecoveryStep::SelectFreshGateway { revoked_circuit_id, attempt_seq } => write!(
                f,
                "select fresh gateway for revoked circuit {} (attempt {attempt_seq})",
                revoked_circuit_id.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ),
        }
    }
}

/// The recovery driver: the durable ledger + the durable attempt log +
/// the §11 lifecycle. Open it once per process from a directory; the
/// stores are internally mutex-guarded (`&self` everywhere).
#[derive(Debug)]
pub struct RecoveryDriver {
    ledger: DurableRevocationLedger,
    attempts: RecoveryAttemptLog,
}

impl RecoveryDriver {
    /// Open (or create) the recovery state in `dir` — the ledger file
    /// and the attempt log. The [`LedgerLoadReport`] surfaces any
    /// torn-tail repair the ledger load performed (crash residue, the
    /// only repair the durable layer ever does).
    pub fn open(dir: &Path) -> Result<(Self, LedgerLoadReport), RecoveryError> {
        let (ledger, report) =
            DurableRevocationLedger::open_or_create(&dir.join(LEDGER_FILE_NAME))?;
        let attempts = RecoveryAttemptLog::open_or_create(&dir.join(ATTEMPT_LOG_FILE_NAME))?;
        Ok((Self { ledger, attempts }, report))
    }

    /// The durable L015 authority (also via [`Self::revocation_ledger`]
    /// for the R7-001 view).
    pub fn is_revoked(&self, circuit_id: &[u8; 32]) -> bool {
        self.ledger.is_revoked(circuit_id)
    }

    /// Admit a revocation envelope to the durable ledger (durable-first:
    /// appended + fsynced before it becomes authoritative). The full
    /// R7-001 admission chain runs first (signature, committed-path
    /// membership against `registry`, `revoked_at` not in the future).
    pub fn admit_revocation_envelope(
        &self,
        now_unix: u64,
        envelope_bytes: &[u8],
        registry: &CircuitRegistry,
    ) -> Result<RevocationAdmitOutcome, RecoveryError> {
        self.ledger.admit_envelope(now_unix, envelope_bytes, registry)
    }

    /// Open the next recovery attempt for a durably revoked circuit and
    /// return the typed next §11 step (fresh gateway selection — the
    /// R7-003 seam). The attempt record is durable (pending) before
    /// this returns.
    ///
    /// Typed refusals: `circuit_not_revoked` (§11 ordering — including
    /// unknown circuits), `recovery_already_complete` (attempt after
    /// success), `attempt_already_pending` (single flight).
    pub fn attempt_next(
        &self,
        revoked_circuit_id: &[u8; 32],
        now_unix: u64,
    ) -> Result<RecoveryStep, RecoveryError> {
        let attempt_seq =
            self.attempts.begin_attempt(&self.ledger, revoked_circuit_id, now_unix)?;
        Ok(RecoveryStep::SelectFreshGateway {
            revoked_circuit_id: *revoked_circuit_id,
            attempt_seq,
        })
    }

    /// Report the fresh route commitment for the circuit's pending
    /// attempt (records it, verifies it when in hand — see
    /// [`FreshRouteEvidence`]).
    pub fn attempt_succeeded(
        &self,
        revoked_circuit_id: &[u8; 32],
        evidence: FreshRouteEvidence<'_>,
        now_unix: u64,
    ) -> Result<u64, RecoveryError> {
        self.attempts.finish_attempt_with_route(revoked_circuit_id, evidence, now_unix)
    }

    /// Report the typed failure that abandoned the circuit's pending
    /// attempt.
    pub fn attempt_failed(
        &self,
        revoked_circuit_id: &[u8; 32],
        reason: AttemptFailure,
        now_unix: u64,
    ) -> Result<u64, RecoveryError> {
        self.attempts.finish_attempt_with_failure(revoked_circuit_id, reason, now_unix)
    }

    /// The durable revocation ledger (the R7-002 durable layer).
    pub fn revocation_ledger(&self) -> &DurableRevocationLedger {
        &self.ledger
    }

    /// The durable, bounded attempt log.
    pub fn attempt_log(&self) -> &RecoveryAttemptLog {
        &self.attempts
    }

    /// The directory's file paths (diagnostics).
    pub fn paths(&self) -> (PathBuf, PathBuf) {
        (self.ledger.path().to_path_buf(), self.attempts.path().to_path_buf())
    }
}

// ---------------------------------------------------------------------------
// Unit tests (the R7-002 "unit" verify level for the composition layer)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attempt::AttemptFailure;
    use crate::error::RecoveryError;
    use crate::testkit as tk;

    /// `open` creates both files in the directory and the §11 lifecycle
    /// flows end to end: admit → attempt_next (the typed R7-003 seam) →
    /// attempt_failed (a LATER attempt opens) → attempt_succeeded (a route
    /// ref is durably recorded, terminal).
    #[test]
    fn open_creates_and_lifecycle_flows() {
        let dir = tk::TempDir::new("driver-lifecycle");
        let (driver, report) = RecoveryDriver::open(&dir.path).expect("open");
        assert_eq!(report, LedgerLoadReport::default());
        let (ledger_path, attempts_path) = driver.paths();
        assert_eq!(ledger_path, dir.path.join(LEDGER_FILE_NAME));
        assert_eq!(attempts_path, dir.path.join(ATTEMPT_LOG_FILE_NAME));
        assert!(ledger_path.exists() && attempts_path.exists());

        // The world: an established circuit, revoked by hop1.
        let w = tk::world(tk::NOW);
        let mut registry = CircuitRegistry::new();
        let revoked = tk::admit_circuit(&w, &mut registry, tk::NOW, [0x71; 32]);
        let env = tk::link_failure_revocation(&w, revoked, tk::NOW);
        assert_eq!(
            driver
                .admit_revocation_envelope(tk::NOW, &env.to_envelope_bytes(), &registry)
                .unwrap(),
            RevocationAdmitOutcome::First
        );
        assert!(driver.is_revoked(&revoked));

        // The typed next step: fresh gateway selection (the R7-003 seam).
        let step = driver.attempt_next(&revoked, tk::NOW + 1).expect("attempt");
        assert_eq!(
            step,
            RecoveryStep::SelectFreshGateway { revoked_circuit_id: revoked, attempt_seq: 1 }
        );
        assert_eq!(step.as_str(), "select_fresh_gateway");
        assert!(format!("{step}").contains("attempt 1"));

        // A second attempt while the first is pending: typed refusal.
        assert_eq!(
            driver.attempt_next(&revoked, tk::NOW + 2).unwrap_err().name(),
            "attempt_already_pending"
        );

        // The attempt fails: abandoned, typed reason, a later one opens.
        assert_eq!(
            driver
                .attempt_failed(&revoked, AttemptFailure::RouteCommitmentFailed, tk::NOW + 3)
                .unwrap(),
            1
        );
        let step = driver.attempt_next(&revoked, tk::NOW + 4).expect("attempt 2");
        assert_eq!(
            step,
            RecoveryStep::SelectFreshGateway { revoked_circuit_id: revoked, attempt_seq: 2 }
        );

        // The second attempt succeeds with the verified fresh commitment.
        assert_eq!(
            driver
                .attempt_succeeded(&revoked, crate::attempt::FreshRouteEvidence::Commitment(&w.commitment), tk::NOW + 5)
                .unwrap(),
            2
        );
        let latest = driver.attempt_log().latest_attempt(&revoked).expect("latest");
        assert_eq!(latest.attempt_seq(), 2);
        assert_eq!(latest.state(), crate::attempt::AttemptState::Succeeded);
        assert_eq!(latest.fresh_route_id(), Some(w.commitment.route_id()));

        // Terminal: no third attempt, no finish either.
        assert_eq!(
            driver.attempt_next(&revoked, tk::NOW + 6).unwrap_err().name(),
            "recovery_already_complete"
        );
        assert_eq!(
            driver
                .attempt_failed(&revoked, AttemptFailure::AbortedLocal, tk::NOW + 6)
                .unwrap_err()
                .name(),
            "no_pending_attempt"
        );

        // The store accessors hand out the same durable state.
        assert!(driver.revocation_ledger().is_revoked(&revoked));
        assert_eq!(driver.attempt_log().record_count(), 2);
    }

    /// The L015 gate end to end: the driver's ledger view, installed into
    /// a fresh `CircuitRegistry`, refuses a setup for the revoked circuit
    /// id while the live sibling circuit still admits.
    #[test]
    fn ledger_view_gates_a_fresh_registry() {
        let dir = tk::TempDir::new("driver-l015");
        let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
        let w = tk::world(tk::NOW);
        let mut registry = CircuitRegistry::new();
        let revoked = tk::admit_circuit(&w, &mut registry, tk::NOW, [0x71; 32]);
        let live = tk::admit_circuit(&w, &mut registry, tk::NOW, [0x72; 32]);
        let env = tk::link_failure_revocation(&w, revoked, tk::NOW);
        driver
            .admit_revocation_envelope(tk::NOW, &env.to_envelope_bytes(), &registry)
            .unwrap();

        let mut gated = CircuitRegistry::new();
        gated.install_revocation_ledger(&driver.revocation_ledger().ledger());
        let revoked_env = tk::setup_envelope_for(&w, tk::NOW, [0x71; 32]);
        let err = gated.admit_setup(tk::NOW, &revoked_env).unwrap_err();
        assert_eq!(err.name(), "circuit_revoked");
        // The live sibling still admits through the same gated registry.
        let live_env = tk::setup_envelope_for(&w, tk::NOW, [0x72; 32]);
        gated.admit_setup(tk::NOW, &live_env).expect("live circuit admits");
        let _ = live;
    }

    /// The driver's refusal surface is typed and leaves the durable state
    /// untouched: an attempt for a not-revoked circuit, and admits the
    /// R7-001 chain refuses — nothing lands in either file.
    #[test]
    fn refusals_are_typed_and_durable_state_unchanged() {
        let dir = tk::TempDir::new("driver-refuse");
        let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
        let w = tk::world(tk::NOW);
        let mut registry = CircuitRegistry::new();
        let revoked = tk::admit_circuit(&w, &mut registry, tk::NOW, [0x71; 32]);
        let live = tk::admit_circuit(&w, &mut registry, tk::NOW, [0x72; 32]);
        let (ledger_path, attempts_path) = driver.paths();
        let before = (std::fs::read(&ledger_path).unwrap(), std::fs::read(&attempts_path).unwrap());

        // §11 ordering: no attempt before durable invalidation.
        let err = driver.attempt_next(&revoked, tk::NOW).unwrap_err();
        assert!(matches!(err, RecoveryError::CircuitNotRevoked { circuit_id } if circuit_id == revoked));
        let err = driver.attempt_next(&[0xEE; 32], tk::NOW).unwrap_err();
        assert!(matches!(err, RecoveryError::CircuitNotRevoked { .. }));

        // The R7-001 chain refuses a future-dated revocation envelope.
        let future = tk::policy_revocation(&w, revoked, tk::NOW + 60);
        let err = driver
            .admit_revocation_envelope(tk::NOW, &future.to_envelope_bytes(), &registry)
            .unwrap_err();
        assert_eq!(err.name(), "revocation_admission_refused");

        assert_eq!(
            (std::fs::read(&ledger_path).unwrap(), std::fs::read(&attempts_path).unwrap()),
            before
        );
        let _ = live;
    }
}
