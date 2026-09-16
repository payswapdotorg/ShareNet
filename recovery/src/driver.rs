//! The recovery driver — the §11 composition layer.
//!
//! Architecture §11's failure pipeline:
//!
//! ```text
//! link failure
//!     ↓
//! durable circuit invalidation      ← R7-001 (the revocation)
//!     ↓
//! zeroization                       ← R7-004 (recorded + ordered HERE)
//!     ↓
//! recovery attempt                   ← R7-002 (durable, bounded)
//!     ↓
//! fresh gateway selection            ← R7-003 (gateway.rs — THIS CRATE)
//!     ↓
//! fresh route commitment             ← R7-003 (established + verified here)
//!     ↓
//! fresh circuit session              ← R7-004 (establish_replacement_circuit)
//!     ↓
//! verification                       ← R7-003/R7-004
//! ```
//!
//! The driver owns the two durable stores (the ledger file + the attempt
//! log) and exposes the attempt lifecycle:
//!
//! - [`Self::attempt_next`] — the §11 entry point: it cross-checks the
//!   DURABLE ledger (only a durably revoked circuit may enter
//!   recovery), refuses when recovery is already complete or an
//!   attempt is in flight, opens and DURABLY records the next
//!   per-circuit attempt (pending), and returns the typed next step —
//!   [`RecoveryStep::SelectFreshGateway`];
//! - [`Self::select_gateway`] — the R7-003 stage after that step: from a
//!   caller-supplied candidate set, only a gateway the R5-005 admission
//!   policy judges `Eligible` can be selected (the policy is COMPOSED,
//!   not rewritten — see [`crate::gateway`]), the tie-break is
//!   deterministic (ascending gateway node id), and the outcome is
//!   bound to the open attempt ([`SelectedGateway`]). When NO eligible
//!   gateway exists the typed refusal `no_eligible_gateway` is the
//!   input to the R7-005 retry policy — or, immediately, to
//!   [`Self::attempt_failed`] with [`AttemptFailure::NoGatewayAvailable`];
//! - [`Self::establish_fresh_route`] — the R7-003 construction stage:
//!   builds the fresh [`RouteCommitment`] from the signed R3-004
//!   material (proposal envelope + acceptance envelopes — every
//!   signature verified by the protocol core's build), DERIVES that the
//!   committed path actually contains the selected gateway (path
//!   membership, never caller-asserted), checks the selection's
//!   admission is still valid at construction time, and hands the
//!   commitment to [`Self::attempt_succeeded`] — which enforces the §11
//!   freshness law (the route must not predate the revocation anchor)
//!   and durably records the terminal success;
//! - [`Self::attempt_succeeded`] — the fresh route commitment evidence
//!   is recorded (verified in full when the commitment is in hand:
//!   R3-004 chain + §11 freshness vs. the revocation anchor);
//! - [`Self::attempt_failed`] — the typed failure reason is recorded
//!   and the attempt is abandoned (a LATER attempt may then be opened —
//!   R7-005 owns the retry/backoff policy);
//! - [`Self::revocation_ledger`] hands out the R7-001 ledger view to
//!   install into a `CircuitRegistry` (`install_revocation_ledger`) so
//!   the L015 gate is live for every circuit admission in this process;
//! - [`Self::record_zeroization`] — the §11 `zeroization` step between
//!   `durable circuit invalidation` and the new session: the typed,
//!   durable, at-most-once fact that the revoked circuit's key material
//!   was dropped ([`crate::ZeroizationRecord`]). Honest scope: this
//!   crate holds no key material of its own — the in-process zeroization
//!   of real session keys lives in the runtime layers (R3-001 link-frame
//!   keys, R4-001 tunnel state); what this records and orders durably is
//!   the FACT (the daemon records it once the runtime layer dropped the
//!   keys), and the replacement stage refuses without it;
//! - [`Self::establish_replacement_circuit`] — the §11 `fresh circuit
//!   session` stage (R7-004): builds the replacement over the fresh route
//!   hand-off ([`FreshRoute`]) — the caller-supplied signed `CircuitSetup`
//!   (+ every path member's `CircuitSetupAck`) is verified against the
//!   driver's own durable record (the setup's embedded commitment must
//!   BE the recorded fresh route), the derived circuit id must differ
//!   from the revoked one (L014 fresh session identity), admission runs
//!   through a `CircuitRegistry` the driver itself gates with its R7-001
//!   ledger view (the revoked old id still refused), exact position
//!   coverage must ESTABLISH the session, and the outcome is recorded
//!   durably on the succeeded attempt (single replacement per recovery).
//!
//! What the driver deliberately does NOT do: retry/backoff (R7-005),
//! concurrent-recovery coordination (R7-006), and post-setup data-plane
//! verification of the replacement circuit (liveness/frames is the
//! runtime layers' job — the R4-002 admission chain verified here is the
//! control-plane verification §11's stage rests on). The seams are the
//! typed parameters the callers bring back.

use std::path::{Path, PathBuf};

use sharenet_admission::{
    AdcosEvidenceAnchor, GatewayAdmissionPolicy, ShareNetEvidenceAnchor,
};
use sharenet_protocol::circuit::{derive_circuit_id, CircuitRegistry, CircuitSetup};
use sharenet_protocol::revocation::RevocationAdmitOutcome;
use sharenet_protocol::route::{RouteCommitment, SignedEnvelope};

use crate::attempt::{
    AttemptFailure, AttemptState, FreshRouteEvidence, RecoveryAttemptLog, ZeroizationRecord,
};
use crate::error::RecoveryError;
use crate::gateway::{select_eligible_gateway, GatewayCandidate, GatewaySelection};
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

    /// The revoked circuit this step names (the §11 binding).
    pub fn revoked_circuit_id(&self) -> &[u8; 32] {
        match self {
            RecoveryStep::SelectFreshGateway { revoked_circuit_id, .. } => revoked_circuit_id,
        }
    }

    /// The per-circuit attempt number this step opened.
    pub fn attempt_seq(&self) -> u64 {
        match self {
            RecoveryStep::SelectFreshGateway { attempt_seq, .. } => *attempt_seq,
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

    /// The R7-003 §11 stage `fresh gateway selection`: from the
    /// caller-supplied candidate set, select a gateway the R5-005
    /// admission `policy` judges `Eligible` at `now_unix`, bound to the
    /// attempt `step` opened (see [`RecoveryStep::SelectFreshGateway`]).
    ///
    /// The selection is the composed R5-005 verdict (every signature
    /// verified by the policy itself) plus the deterministic tie-break
    /// (ascending gateway node id); the returned [`SelectedGateway`]
    /// carries the verified evidence anchors and the binding to the open
    /// attempt. Selection is NOT durable state — it is the in-process
    /// input to [`Self::establish_fresh_route`]; a crash between the two
    /// stages leaves the attempt pending (a fresh selection may run
    /// after the restart; the durable outcome is the recorded route
    /// ref, which is commitment-derived).
    ///
    /// Typed refusals: `no_pending_attempt` (no open attempt for the
    /// step's circuit), `stale_recovery_step` (the step names an attempt
    /// that is no longer the open one), `no_eligible_gateway` (no
    /// eligible candidate — empty set included; feeds the R7-005 retry
    /// policy or `attempt_failed` with `NoGatewayAvailable`),
    /// `duplicate_gateway_candidate` (ambiguous set).
    pub fn select_gateway(
        &self,
        step: &RecoveryStep,
        candidates: &[GatewayCandidate<'_>],
        policy: &GatewayAdmissionPolicy,
        now_unix: u64,
    ) -> Result<SelectedGateway, RecoveryError> {
        let (revoked_circuit_id, step_attempt_seq) = match *step {
            RecoveryStep::SelectFreshGateway { revoked_circuit_id, attempt_seq } => {
                (revoked_circuit_id, attempt_seq)
            }
        };
        self.check_step_is_open(&revoked_circuit_id, step_attempt_seq)?;
        let selection: GatewaySelection =
            select_eligible_gateway(policy, candidates, now_unix)?;
        Ok(SelectedGateway {
            revoked_circuit_id,
            attempt_seq: step_attempt_seq,
            gateway_node_id: selection.gateway_node_id,
            sharenet: selection.sharenet,
            adcos: selection.adcos,
            valid_until_unix: selection.valid_until_unix,
        })
    }

    /// The R7-003 §11 stage `fresh route commitment`: build the fresh
    /// [`RouteCommitment`] for the selected gateway from the signed
    /// R3-004 material — the proposal envelope (the recovering node's
    /// signed route proposal) and the acceptance envelopes (every path
    /// member's signed acceptance, the selected gateway's included). The
    /// construction runs the protocol core's own chain: proposal
    /// signature, every acceptance's signature/binding/freshness,
    /// exact position coverage, the Merkle root and the derived
    /// `route_id` (L013).
    ///
    /// Then two DERIVED cross-checks before the durable record:
    ///
    /// - **path membership** — the committed path must contain the
    ///   selected gateway's node id (typed refusal `gateway_not_on_route`;
    ///   the claim is never taken from the caller);
    /// - **admission validity** — the selection's evidence must still hold
    ///   at construction time (`now_unix < valid_until_unix`; typed
    ///   refusal `gateway_admission_expired`).
    ///
    /// Finally the commitment is handed to [`Self::attempt_succeeded`],
    /// which re-verifies it in full and enforces the §11 freshness law
    /// (the route must not predate the revocation anchor — typed refusal
    /// `route_not_fresh`) before durably recording the terminal success.
    /// On ANY refusal the attempt stays pending and nothing is written.
    ///
    /// Returns the established route (its commitment-derived `route_id`,
    /// the attempt it succeeded, the gateway it goes through).
    pub fn establish_fresh_route(
        &self,
        selected: &SelectedGateway,
        proposal_envelope: &SignedEnvelope,
        acceptance_envelopes: &[SignedEnvelope],
        now_unix: u64,
    ) -> Result<FreshRoute, RecoveryError> {
        self.check_step_is_open(&selected.revoked_circuit_id, selected.attempt_seq)?;
        // The selection's evidence must still hold at construction time
        // (the R5-005 `valid_until_unix` anchor — exclusive bound).
        if now_unix >= selected.valid_until_unix {
            return Err(RecoveryError::GatewayAdmissionExpired {
                now_unix,
                valid_until_unix: selected.valid_until_unix,
            });
        }
        // The R3-004 chain: build verifies the proposal signature, every
        // acceptance signature/binding/freshness and the position
        // coverage, and derives the Merkle root + route_id (L013).
        let commitment = RouteCommitment::build(
            now_unix,
            proposal_envelope.clone(),
            acceptance_envelopes.to_vec(),
        )
        .map_err(|source| RecoveryError::RouteCommitmentInvalid { source })?;
        // The full re-verification a receiver runs (root + route_id
        // re-derivation) — construction is held to the same standard.
        let verified = commitment
            .verify(now_unix)
            .map_err(|source| RecoveryError::RouteCommitmentInvalid { source })?;
        // Path membership, DERIVED from the verified commitment.
        if !verified.proposal.path().contains(&selected.gateway_node_id) {
            return Err(RecoveryError::GatewayNotOnRoute {
                gateway_node_id: selected.gateway_node_id,
                route_id: *commitment.route_id(),
            });
        }
        // The durable terminal record (§11 freshness anchor enforced
        // inside: `route_not_fresh` if the route predates the revocation).
        self.attempts.finish_attempt_with_route(
            &selected.revoked_circuit_id,
            FreshRouteEvidence::Commitment(&commitment),
            now_unix,
        )?;
        Ok(FreshRoute {
            revoked_circuit_id: selected.revoked_circuit_id,
            route_id: *commitment.route_id(),
            attempt_seq: selected.attempt_seq,
            gateway_node_id: selected.gateway_node_id,
        })
    }

    /// The cross-check both R7-003 stages run: the step's attempt must be
    /// the circuit's OPEN one (pending). A circuit with no pending attempt
    /// is `no_pending_attempt`; a step naming a finished/superseded
    /// attempt is `stale_recovery_step`.
    fn check_step_is_open(
        &self,
        revoked_circuit_id: &[u8; 32],
        step_attempt_seq: u64,
    ) -> Result<(), RecoveryError> {
        let pending = self
            .attempts
            .pending_attempt(revoked_circuit_id)
            .ok_or(RecoveryError::NoPendingAttempt { circuit_id: *revoked_circuit_id })?;
        if pending.attempt_seq() != step_attempt_seq {
            return Err(RecoveryError::StaleRecoveryStep {
                circuit_id: *revoked_circuit_id,
                step_attempt_seq,
                open_attempt_seq: pending.attempt_seq(),
            });
        }
        Ok(())
    }

    // -- R7-004: the zeroization fact + the replacement circuit session --

    /// The §11 `zeroization` step between `durable circuit invalidation`
    /// and the new session: record the durable, at-most-once fact that
    /// the revoked circuit's key material was dropped (see
    /// [`ZeroizationRecord`] for the exact honesty boundary — the
    /// in-process zeroization of real session keys lives in the runtime
    /// layers; this records and orders the FACT).
    ///
    /// Typed refusals: `circuit_not_revoked` (§11: zeroization follows
    /// durable invalidation), `zeroization_before_revocation` (the clock
    /// predates the ledger's anchor), `circuit_already_zeroized` (the
    /// fact stands; single record per revoked circuit).
    pub fn record_zeroization(
        &self,
        revoked_circuit_id: &[u8; 32],
        now_unix: u64,
    ) -> Result<ZeroizationRecord, RecoveryError> {
        self.attempts.record_zeroization(&self.ledger, revoked_circuit_id, now_unix)
    }

    /// The circuit's zeroization fact, if recorded (the durable query
    /// the replacement stage gates on — it survives restarts).
    pub fn zeroization(&self, revoked_circuit_id: &[u8; 32]) -> Option<ZeroizationRecord> {
        self.attempts.zeroization(revoked_circuit_id)
    }

    /// The §11 `fresh circuit session` stage (R7-004): establish the
    /// REPLACEMENT circuit over the fresh route `route` (the
    /// [`FreshRoute`] hand-off of [`Self::establish_fresh_route`]) and
    /// retire the revoked one in the durable record.
    ///
    /// The caller brings the signed R4-002 material built over the fresh
    /// commitment — the setup envelope (the recovering node's signed
    /// `CircuitSetup`, whose embedded commitment must BE the recorded
    /// fresh route) and every path member's signed `CircuitSetupAck`.
    /// The driver then:
    ///
    /// 1. **gates on the zeroization fact** — the §11 step between
    ///    invalidation and the new session must be durably recorded
    ///    (`zeroization_missing` otherwise);
    /// 2. **binds to its own durable record** — the hand-off's route must
    ///    be the circuit's terminal succeeded attempt's recorded fresh
    ///    route (`no_succeeded_attempt` / `replacement_route_mismatch`;
    ///    a setup over the REVOKED circuit's own route, or any stale or
    ///    foreign route, is refused here);
    /// 3. **checks L014 fresh session identity** — the setup's derived
    ///    circuit id
    ///    (`SHA-256("sharenet-circuit-id-v1" || route_id || setup_nonce)`,
    ///    the R4-002 binding) must differ from the revoked circuit's id
    ///    (`replacement_circuit_id_not_fresh`);
    /// 4. **admits through the gated registry** — the driver installs its
    ///    own R7-001 ledger view into `registry` (the L015 gate is live by
    ///    construction, never caller-asserted: the revoked old id is
    ///    still refused, the replacement admits) and runs the full R4-002
    ///    chain — setup signature, embedded-commitment R3-004
    ///    verification, initiator-is-proposer, setup freshness,
    ///    single-use `(route_id, setup_nonce)` — then every ack (exact
    ///    position coverage) until the session is ESTABLISHED;
    /// 5. **records the outcome durably** — the succeeded attempt carries
    ///    the replacement circuit id (single replacement per recovery:
    ///    `replacement_already_established` on a second; a further failure
    ///    of the replacement is a NEW revocation + NEW recovery, L014).
    ///
    /// Typed refusals (besides the above): `replacement_setup_invalid`
    /// (the envelope failed strict parse or its commitment failed R3-004
    /// verification), `circuit_admission_refused` (the gated registry
    /// refused the setup or an ack — forged, expired, nonce-reused…),
    /// `replacement_circuit_not_established` (the ack set left positions
    /// unacked — an incomplete session is never the replacement).
    /// On ANY refusal nothing is written to the durable record.
    pub fn establish_replacement_circuit(
        &self,
        route: &FreshRoute,
        setup_envelope: &SignedEnvelope,
        ack_envelopes: &[SignedEnvelope],
        registry: &mut CircuitRegistry,
        now_unix: u64,
    ) -> Result<ReplacementCircuit, RecoveryError> {
        // 1. The §11 zeroization gate.
        self.zeroization(&route.revoked_circuit_id)
            .ok_or(RecoveryError::ZeroizationMissing {
                circuit_id: route.revoked_circuit_id,
            })?;

        // 2. The binding to the driver's OWN durable record: the terminal
        // succeeded attempt's recorded fresh route.
        let latest = self
            .attempts
            .latest_attempt(&route.revoked_circuit_id)
            .ok_or(RecoveryError::NoSucceededAttempt {
                circuit_id: route.revoked_circuit_id,
            })?;
        if latest.state() != AttemptState::Succeeded {
            return Err(RecoveryError::NoSucceededAttempt {
                circuit_id: route.revoked_circuit_id,
            });
        }
        let recorded_route = *latest
            .fresh_route_id()
            .expect("succeeded attempts carry a route ref");
        if recorded_route != route.route_id {
            return Err(RecoveryError::ReplacementRouteMismatch {
                circuit_id: route.revoked_circuit_id,
                expected_route_id: recorded_route,
                offered_route_id: route.route_id,
            });
        }

        // 3. The offered setup envelope: strict parse, the embedded
        // commitment verified in full (R3-004 — construction held to the
        // receiver's standard), and its route bound to the same fresh
        // route (the setup the replacement rides, never a foreign one).
        let setup = CircuitSetup::from_wire_bytes(setup_envelope.bytes())
            .map_err(|source| RecoveryError::ReplacementSetupInvalid { source })?;
        let commitment = RouteCommitment::from_wire_bytes(setup.route_commitment_bytes())
            .map_err(|source| RecoveryError::ReplacementSetupInvalid {
                source: source.into(),
            })?;
        let verified = commitment
            .verify(now_unix)
            .map_err(|source| RecoveryError::ReplacementSetupInvalid {
                source: source.into(),
            })?;
        if verified.route_id != recorded_route {
            return Err(RecoveryError::ReplacementRouteMismatch {
                circuit_id: route.revoked_circuit_id,
                expected_route_id: recorded_route,
                offered_route_id: verified.route_id,
            });
        }

        // 4. L014: fresh session identity — the derived replacement id
        // must never be the revoked circuit's own.
        let replacement_circuit_id =
            derive_circuit_id(&verified.route_id, setup.setup_nonce());
        if replacement_circuit_id == route.revoked_circuit_id {
            return Err(RecoveryError::ReplacementCircuitNotFresh {
                revoked_circuit_id: route.revoked_circuit_id,
                replacement_circuit_id,
            });
        }

        // 5. The gated registry: the driver installs its own R7-001
        // ledger view (L015 live by construction), then the full R4-002
        // admission chain runs — setup first.
        registry.install_revocation_ledger(&self.ledger.ledger());
        let admitted = registry
            .admit_setup(now_unix, setup_envelope)
            .map_err(|source| RecoveryError::CircuitAdmissionRefused { source })?;
        if admitted != replacement_circuit_id {
            return Err(RecoveryError::InternalInconsistent {
                what: "the registry derived a different replacement circuit id",
            });
        }
        // Then every ack (exact position coverage → established).
        for ack_envelope in ack_envelopes {
            registry
                .admit_ack(now_unix, ack_envelope)
                .map_err(|source| RecoveryError::CircuitAdmissionRefused { source })?;
        }
        if !registry.is_established(&replacement_circuit_id) {
            let unacked = registry
                .circuit(&replacement_circuit_id)
                .map(|state| state.unacked_positions().to_vec())
                .unwrap_or_default();
            return Err(RecoveryError::ReplacementCircuitNotEstablished {
                circuit_id: replacement_circuit_id,
                unacked_positions: unacked,
            });
        }

        // 6. The durable outcome: the succeeded attempt carries the
        // replacement circuit id (single replacement per recovery).
        let attempt_seq = self.attempts.record_replacement_circuit(
            &route.revoked_circuit_id,
            &recorded_route,
            &replacement_circuit_id,
            now_unix,
        )?;
        Ok(ReplacementCircuit {
            revoked_circuit_id: route.revoked_circuit_id,
            replacement_circuit_id,
            fresh_route_id: recorded_route,
            attempt_seq,
        })
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
// The R7-003 composition types
// ---------------------------------------------------------------------------

/// The selected fresh gateway, bound to the open §11 recovery attempt
/// (the output of [`RecoveryDriver::select_gateway`]): which gateway, the
/// verified R5-005 evidence anchors the selection rests on, and which
/// attempt of which revoked circuit it is for.
///
/// Not durable state by design (see `select_gateway`): the durable
/// outcome is the succeeded attempt's fresh-route ref.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectedGateway {
    /// The revoked circuit this recovery (and this selection) is for.
    pub revoked_circuit_id: [u8; 32],
    /// The per-circuit attempt the selection belongs to.
    pub attempt_seq: u64,
    /// The selected gateway's derived node id (deterministic tie-break
    /// winner among the eligible candidates).
    pub gateway_node_id: [u8; 32],
    /// The verified ShareNet-side link evidence anchor (R5-005).
    pub sharenet: ShareNetEvidenceAnchor,
    /// The verified ADCOS-side backhaul evidence anchor (R5-005).
    pub adcos: AdcosEvidenceAnchor,
    /// Until when (exclusive) the selection's evidence holds — the
    /// construction stage's admission-validity bound.
    pub valid_until_unix: u64,
}

/// The established fresh route (the output of
/// [`RecoveryDriver::establish_fresh_route`]): the commitment-derived
/// route id (L013), the attempt it durably succeeded, and the selected
/// gateway it goes through (the §11 pipeline's hand-off to R7-004's
/// fresh circuit session).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreshRoute {
    /// The revoked circuit this fresh route recovers (the replacement
    /// circuit will retire it — never resurrected, L015).
    pub revoked_circuit_id: [u8; 32],
    /// The fresh route's commitment-derived id (L013).
    pub route_id: [u8; 32],
    /// The recovery attempt this route succeeded.
    pub attempt_seq: u64,
    /// The selected gateway the committed path contains.
    pub gateway_node_id: [u8; 32],
}

/// The established replacement circuit (the output of
/// [`RecoveryDriver::establish_replacement_circuit`] — the §11 `fresh
/// circuit session` stage): the NEW circuit's R4-002 derived id (a
/// fresh session identity, never the revoked one — L014), the fresh
/// route it rides (the commitment-derived route id, L013), and the
/// succeeded recovery attempt the replacement was durably recorded on.
///
/// The registry state (`CircuitRegistry`) the session lives in is
/// RUNTIME state by R4-002 design; the durable facts (the replacement
/// id on the attempt record, the zeroization of the revoked circuit)
/// survive restarts in the driver's files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplacementCircuit {
    /// The revoked circuit this replacement retires (never resurrected
    /// — L015).
    pub revoked_circuit_id: [u8; 32],
    /// The replacement circuit's R4-002 derived id — DIFFERENT from the
    /// revoked one (L014 fresh session identity and replay namespace).
    pub replacement_circuit_id: [u8; 32],
    /// The fresh route the replacement rides (the commitment-derived
    /// route id, L013 — the succeeded attempt's recorded route).
    pub fresh_route_id: [u8; 32],
    /// The succeeded recovery attempt the replacement was recorded on.
    pub attempt_seq: u64,
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

    // -- R7-003: the §11 selection + construction stages -------------------

    /// The composed §11 pipeline end to end: admit → attempt_next →
    /// select_gateway (the R5-005 policy composed in — the eligible
    /// candidate wins over the ineligible ones) → establish_fresh_route
    /// (the R3-004 chain, the selected gateway DERIVED as a path member,
    /// the §11 freshness law) → the durable terminal record.
    #[test]
    fn r7003_select_and_establish_flow_end_to_end() {
        let dir = tk::TempDir::new("driver-r7003-flow");
        let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
        // The revoked circuit's world, with the revocation LATE (the
        // fresh route below must not predate it — and does not).
        let w = tk::world(tk::NOW);
        let mut registry = CircuitRegistry::new();
        let revoked = tk::admit_circuit(&w, &mut registry, tk::NOW, [0x76; 32]);
        let env = tk::link_failure_revocation(&w, revoked, tk::NOW + 1);
        driver
            .admit_revocation_envelope(tk::NOW + 1, &env.to_envelope_bytes(), &registry)
            .expect("admit");

        let step = driver.attempt_next(&revoked, tk::NOW + 2).expect("attempt");
        assert_eq!(step.attempt_seq(), 1);
        assert_eq!(step.revoked_circuit_id(), &revoked);

        // Fresh gateway selection over a mixed candidate set.
        let gw = tk::gateway_world(tk::NOW);
        let candidates = vec![
            gw.candidate_no_backhaul(),
            gw.candidate_wrong_subject(),
            gw.candidate_eligible(),
        ];
        let selected =
            driver.select_gateway(&step, &candidates, &tk::admission_policy(), tk::NOW + 3)
                .expect("selection");
        assert_eq!(selected.gateway_node_id, tk::node_id(&gw.g1));
        assert_eq!(selected.revoked_circuit_id, revoked);
        assert_eq!(selected.attempt_seq, 1);
        assert!(selected.valid_until_unix > tk::NOW + 3);

        // Fresh route construction through the selected gateway: the
        // recovering node proposes, both path members accept (the R3-004
        // seams), the driver builds + verifies + records.
        let material = tk::fresh_route_material(&gw, &selected, tk::NOW + 4);
        let route = driver
            .establish_fresh_route(&selected, &material.proposal_env, &material.acceptance_envs, tk::NOW + 4)
            .expect("fresh route");
        assert_eq!(route.attempt_seq, 1);
        assert_eq!(route.gateway_node_id, tk::node_id(&gw.g1));
        assert_eq!(route.route_id, material.route_id);

        // The durable terminal record carries the SAME commitment-derived
        // route id (L013) — and recovery is complete.
        let latest = driver.attempt_log().latest_attempt(&revoked).expect("latest");
        assert_eq!(latest.state(), crate::attempt::AttemptState::Succeeded);
        assert_eq!(latest.fresh_route_id(), Some(&route.route_id));
        assert_eq!(
            driver.attempt_next(&revoked, tk::NOW + 5).unwrap_err().name(),
            "recovery_already_complete"
        );
    }

    /// The R7-003 refusal surface around the two stages: selecting with no
    /// open attempt, a stale step, an expired admission, and a route that
    /// does not commit to the selected gateway — every refusal typed, and
    /// the durable attempt state untouched (still pending).
    #[test]
    fn r7003_stage_refusals_are_typed() {
        let dir = tk::TempDir::new("driver-r7003-refuse");
        let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
        let w = tk::world(tk::NOW);
        let mut registry = CircuitRegistry::new();
        let revoked = tk::admit_circuit(&w, &mut registry, tk::NOW, [0x77; 32]);
        driver
            .admit_revocation_envelope(
                tk::NOW + 1,
                &tk::link_failure_revocation(&w, revoked, tk::NOW + 1).to_envelope_bytes(),
                &registry,
            )
            .expect("admit");
        let step = driver.attempt_next(&revoked, tk::NOW + 2).expect("attempt");
        let gw = tk::gateway_world(tk::NOW);
        let policy = tk::admission_policy();
        let candidates = vec![gw.candidate_eligible()];
        let (_, attempts_path) = driver.paths();

        // A selection for a circuit with NO open attempt.
        let stranger_step = RecoveryStep::SelectFreshGateway {
            revoked_circuit_id: [0xEE; 32],
            attempt_seq: 1,
        };
        assert_eq!(
            driver
                .select_gateway(&stranger_step, &candidates, &policy, tk::NOW + 3)
                .unwrap_err()
                .name(),
            "no_pending_attempt"
        );

        // A stale step: attempt 1 finished and attempt 2 opened — the OLD
        // step must not select or establish anything for attempt 1.
        let selected =
            driver.select_gateway(&step, &candidates, &policy, tk::NOW + 3).expect("select");
        driver
            .attempt_failed(&revoked, AttemptFailure::GatewayUnreachable, tk::NOW + 3)
            .unwrap();
        // (no pending attempt at all yet: even a FRESH step is refused)
        assert_eq!(
            driver
                .select_gateway(&step, &candidates, &policy, tk::NOW + 3)
                .unwrap_err()
                .name(),
            "no_pending_attempt"
        );
        // The finished selection cannot establish either.
        let material = tk::fresh_route_material(&gw, &selected, tk::NOW + 4);
        assert_eq!(
            driver
                .establish_fresh_route(&selected, &material.proposal_env, &material.acceptance_envs, tk::NOW + 4)
                .unwrap_err()
                .name(),
            "no_pending_attempt"
        );
        let step2 = driver.attempt_next(&revoked, tk::NOW + 5).expect("attempt 2");
        assert_eq!(step2.attempt_seq(), 2);
        // THE stale step: attempt 2 is the open one, the old step (and
        // its attempt-1-bound selection) names a finished attempt.
        assert_eq!(
            driver
                .select_gateway(&step, &candidates, &policy, tk::NOW + 5)
                .unwrap_err()
                .name(),
            "stale_recovery_step"
        );

        // A fresh attempt, an expired admission (valid_until is NOW+592 —
        // construction after it is refused, the attempt stays pending).
        let selected2 =
            driver.select_gateway(&step2, &candidates, &policy, tk::NOW + 6).expect("select 2");
        let before = std::fs::read(&attempts_path).unwrap();
        let late = tk::fresh_route_material(&gw, &selected2, tk::NOW + 700);
        assert_eq!(
            driver
                .establish_fresh_route(&selected2, &late.proposal_env, &late.acceptance_envs, tk::NOW + 700)
                .unwrap_err()
                .name(),
            "gateway_admission_expired"
        );

        // A route that does not commit to the selected gateway: the
        // commitment is built for the recovering node + a DIFFERENT
        // member (gateway G1 absent from the path) — path membership is
        // derived, so the refusal names it.
        let through_other = tk::fresh_route_material_skipping_gateway(&gw, tk::NOW + 7);
        assert_eq!(
            driver
                .establish_fresh_route(&selected2, &through_other.proposal_env, &through_other.acceptance_envs, tk::NOW + 7)
                .unwrap_err()
                .name(),
            "gateway_not_on_route"
        );

        // Nothing above finished attempt 2: still pending, and neither
        // establish refusal wrote a byte (the last write was attempt 2's
        // open + the selection, which writes nothing by design).
        assert_eq!(
            driver.attempt_log().pending_attempt(&revoked).expect("pending").attempt_seq(),
            2
        );
        assert_eq!(std::fs::read(&attempts_path).unwrap(), before);
    }

    // -- R7-004: the zeroization fact + the replacement circuit session ----

    /// Drive the §11 pipeline through zeroization + the replacement
    /// circuit: revocation → zeroize (the step between invalidation and
    /// the new session) → attempt → select → fresh route → the
    /// replacement circuit established through a FRESH registry the
    /// driver itself gates. L014 verified (the replacement id differs
    /// from the revoked one), the durable record carries the outcome,
    /// and the gated registry still refuses the REVOKED circuit's setup.
    #[test]
    fn r7004_replacement_flow_end_to_end() {
        let dir = tk::TempDir::new("driver-r7004-flow");
        let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
        let w = tk::world(tk::NOW);
        let mut registry = CircuitRegistry::new();
        let revoked = tk::admit_circuit(&w, &mut registry, tk::NOW, [0x76; 32]);
        driver
            .admit_revocation_envelope(
                tk::NOW + 1,
                &tk::link_failure_revocation(&w, revoked, tk::NOW + 1).to_envelope_bytes(),
                &registry,
            )
            .expect("admit");

        // The §11 zeroization step: after the durable invalidation, before
        // anything else moves.
        let zeroization = driver.record_zeroization(&revoked, tk::NOW + 2).expect("zeroize");
        assert_eq!(zeroization.revoked_circuit_id(), &revoked);
        assert_eq!(driver.zeroization(&revoked).map(|z| z.zeroized_at_unix()), Some(tk::NOW + 2));

        let step = driver.attempt_next(&revoked, tk::NOW + 3).expect("attempt");
        let gw = tk::gateway_world(tk::NOW);
        let candidates = vec![gw.candidate_no_backhaul(), gw.candidate_eligible()];
        let selected =
            driver.select_gateway(&step, &candidates, &tk::admission_policy(), tk::NOW + 4)
                .expect("selection");
        let route_material = tk::fresh_route_material(&gw, &selected, tk::NOW + 5);
        let route = driver
            .establish_fresh_route(
                &selected,
                &route_material.proposal_env,
                &route_material.acceptance_envs,
                tk::NOW + 5,
            )
            .expect("fresh route");
        assert_eq!(route.revoked_circuit_id, revoked);

        // The replacement circuit: signed R4-002 material over the fresh
        // commitment, admitted through a FRESH registry (runtime state —
        // exactly what a restarted daemon holds).
        let replacement_material = tk::replacement_material_over(
            &route_material,
            &gw,
            &selected.gateway_node_id,
            [0x93; 32],
            tk::NOW + 5,
        );
        let mut replacement_registry = CircuitRegistry::new();
        let replacement = driver
            .establish_replacement_circuit(
                &route,
                &replacement_material.setup_env,
                &replacement_material.ack_envs,
                &mut replacement_registry,
                tk::NOW + 6,
            )
            .expect("replacement");
        assert_eq!(replacement.revoked_circuit_id, revoked);
        assert_eq!(replacement.fresh_route_id, route.route_id);
        assert_eq!(replacement.attempt_seq, 1);
        // L014: the replacement's id is the R4-002 derivation over the
        // FRESH route — never the revoked circuit's own.
        assert_eq!(replacement.replacement_circuit_id, replacement_material.circuit_id);
        assert_ne!(replacement.replacement_circuit_id, revoked);
        assert!(replacement_registry.is_established(&replacement.replacement_circuit_id));

        // The gated registry: the driver's own ledger view makes the
        // REVOKED circuit's setup refuse (L015) even in the fresh runtime.
        let revoked_env = tk::setup_envelope_for(&w, tk::NOW, [0x76; 32]);
        let err = replacement_registry.admit_setup(tk::NOW + 6, &revoked_env).unwrap_err();
        assert_eq!(err.name(), "circuit_revoked");

        // The durable record: the terminal attempt carries the replacement.
        let latest = driver.attempt_log().latest_attempt(&revoked).expect("latest");
        assert_eq!(latest.state(), crate::attempt::AttemptState::Succeeded);
        assert_eq!(latest.replacement_circuit_id(), Some(&replacement.replacement_circuit_id));
        assert_eq!(
            driver.attempt_next(&revoked, tk::NOW + 7).unwrap_err().name(),
            "recovery_already_complete"
        );

        // Recovery is terminal WITH its replacement: a second replacement
        // call is the typed single-flight refusal.
        let err = driver
            .establish_replacement_circuit(
                &route,
                &replacement_material.setup_env,
                &replacement_material.ack_envs,
                &mut CircuitRegistry::new(),
                tk::NOW + 8,
            )
            .unwrap_err();
        assert_eq!(err.name(), "replacement_already_established");
    }

    /// The R7-004 refusal surface, typed and leaving the durable state
    /// untouched: missing zeroization, no succeeded attempt, a stale or
    /// revoked-circuit route (mismatch), the L014 collision (a setup
    /// deriving the revoked id itself), a forged envelope, an expired
    /// setup, and an incomplete ack set.
    #[test]
    fn r7004_refusals_are_typed() {
        let dir = tk::TempDir::new("driver-r7004-refuse");
        let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
        let w = tk::world(tk::NOW);
        let mut registry = CircuitRegistry::new();
        let revoked = tk::admit_circuit(&w, &mut registry, tk::NOW, [0x77; 32]);
        driver
            .admit_revocation_envelope(
                tk::NOW + 1,
                &tk::link_failure_revocation(&w, revoked, tk::NOW + 1).to_envelope_bytes(),
                &registry,
            )
            .expect("admit");
        let (_, attempts_path) = driver.paths();

        // The §11 zeroization gate: a completed route but NO zeroization
        // fact → the replacement session never opens.
        let step = driver.attempt_next(&revoked, tk::NOW + 2).expect("attempt");
        let gw = tk::gateway_world(tk::NOW);
        let selected =
            driver.select_gateway(&step, &[gw.candidate_eligible()], &tk::admission_policy(), tk::NOW + 3)
                .expect("selection");
        let route_material = tk::fresh_route_material(&gw, &selected, tk::NOW + 4);
        let route = driver
            .establish_fresh_route(
                &selected,
                &route_material.proposal_env,
                &route_material.acceptance_envs,
                tk::NOW + 4,
            )
            .expect("fresh route");
        let good = tk::replacement_material_over(
            &route_material,
            &gw,
            &selected.gateway_node_id,
            [0x93; 32],
            tk::NOW + 4,
        );
        let err = driver
            .establish_replacement_circuit(
                &route,
                &good.setup_env,
                &good.ack_envs,
                &mut CircuitRegistry::new(),
                tk::NOW + 5,
            )
            .unwrap_err();
        assert_eq!(err.name(), "zeroization_missing");

        // Zeroized now — a second revoked circuit of the same driver (also
        // zeroized, but with NO attempt at all, let alone a succeeded one)
        // is the typed no-succeeded refusal.
        driver.record_zeroization(&revoked, tk::NOW + 5).expect("zeroize");
        let (w2, mut registry2, revoked2) = tk::established(tk::NOW, [0x87; 32]);
        driver
            .admit_revocation_envelope(
                tk::NOW + 5,
                &tk::link_failure_revocation(&w2, revoked2, tk::NOW + 5).to_envelope_bytes(),
                &registry2,
            )
            .expect("admit 2");
        driver.record_zeroization(&revoked2, tk::NOW + 5).expect("zeroize 2");
        let no_attempt_route = crate::driver::FreshRoute {
            revoked_circuit_id: revoked2,
            route_id: route.route_id,
            attempt_seq: 1,
            gateway_node_id: selected.gateway_node_id,
        };
        let err = driver
            .establish_replacement_circuit(
                &no_attempt_route,
                &good.setup_env,
                &good.ack_envs,
                &mut CircuitRegistry::new(),
                tk::NOW + 6,
            )
            .unwrap_err();
        assert_eq!(err.name(), "no_succeeded_attempt");
        let _ = (&w2, &mut registry2);

        // A STALE route: the hand-off names a route the record does not
        // carry (the revoked circuit's own world commitment).
        let stale_route = crate::driver::FreshRoute {
            revoked_circuit_id: revoked,
            route_id: *w.commitment.route_id(),
            attempt_seq: 1,
            gateway_node_id: selected.gateway_node_id,
        };
        let err = driver
            .establish_replacement_circuit(
                &stale_route,
                &good.setup_env,
                &good.ack_envs,
                &mut CircuitRegistry::new(),
                tk::NOW + 6,
            )
            .unwrap_err();
        assert_eq!(err.name(), "replacement_route_mismatch");

        // A setup over the REVOKED circuit's own (old) route: well-formed
        // and fully signed, but the binding to the recorded fresh route
        // refuses it.
        let revoked_route_setup = tk::replacement_material(
            &w.commitment,
            &w.proposer,
            &[&w.proposer, &w.hop1, &w.hop2],
            [0x78; 32],
            tk::NOW + 6,
        );
        let err = driver
            .establish_replacement_circuit(
                &route,
                &revoked_route_setup.setup_env,
                &revoked_route_setup.ack_envs,
                &mut CircuitRegistry::new(),
                tk::NOW + 6,
            )
            .unwrap_err();
        assert_eq!(err.name(), "replacement_route_mismatch");

        // A FORGED setup envelope (one signature byte flipped): the
        // gated registry's R4-002 chain refuses it.
        let mut forged_sig = *good.setup_env.signature();
        forged_sig[0] ^= 0x01;
        let forged = SignedEnvelope::new(good.setup_env.bytes().to_vec(), forged_sig);
        let err = driver
            .establish_replacement_circuit(
                &route,
                &forged,
                &good.ack_envs,
                &mut CircuitRegistry::new(),
                tk::NOW + 6,
            )
            .unwrap_err();
        assert_eq!(err.name(), "circuit_admission_refused");

        // Garbage bytes are the typed parse refusal (nothing admitted).
        let garbage = SignedEnvelope::new(vec![0xDE, 0xAD, 0xBE, 0xEF], [0u8; 64]);
        let err = driver
            .establish_replacement_circuit(
                &route,
                &garbage,
                &good.ack_envs,
                &mut CircuitRegistry::new(),
                tk::NOW + 6,
            )
            .unwrap_err();
        assert_eq!(err.name(), "replacement_setup_invalid");

        // An EXPIRED setup: issued at NOW+4 with a 1-second window, the
        // replacement arrives at NOW+6 → the registry refuses typed.
        let expired_setup = CircuitSetup::new(
            &tk::rebuilt_commitment(&route_material),
            &gw.recovering,
            [0x94; 32],
            tk::NOW + 4,
            1,
        )
        .expect("setup");
        let expired_env = expired_setup.sign(&gw.recovering).expect("sign");
        let err = driver
            .establish_replacement_circuit(
                &route,
                &expired_env,
                &[],
                &mut CircuitRegistry::new(),
                tk::NOW + 6,
            )
            .unwrap_err();
        assert_eq!(err.name(), "circuit_admission_refused");

        // An incomplete ack set: the setup admits but the session never
        // establishes (one of the two positions unacked).
        let err = driver
            .establish_replacement_circuit(
                &route,
                &good.setup_env,
                &good.ack_envs[..1],
                &mut CircuitRegistry::new(),
                tk::NOW + 6,
            )
            .unwrap_err();
        assert_eq!(err.name(), "replacement_circuit_not_established");

        // None of the refusals wrote a byte; the durable record still
        // carries no replacement.
        let latest = driver.attempt_log().latest_attempt(&revoked).expect("latest");
        assert_eq!(latest.replacement_circuit_id(), None);
        assert!(
            std::fs::read(&attempts_path).unwrap().len() > 0,
            "the store file exists (created by the successful route)"
        );

        // The honest replacement then succeeds on the first call.
        let replacement = driver
            .establish_replacement_circuit(
                &route,
                &good.setup_env,
                &good.ack_envs,
                &mut CircuitRegistry::new(),
                tk::NOW + 7,
            )
            .expect("replacement");
        assert_ne!(replacement.replacement_circuit_id, revoked);
    }

    /// L014 enforced at the driver: a setup that derives the REVOKED
    /// circuit's own id is refused even when the route binding would
    /// otherwise pass. The constructible path is the documented R7-003
    /// bare-`RouteRef` seam (caller-verified routes): a caller that
    /// recorded the revoked circuit's own route as "fresh" and then
    /// offers the revoked circuit's own (route, nonce) setup — the
    /// driver still refuses (never the failed circuit again).
    #[test]
    fn r7004_replacement_never_the_revoked_circuit() {
        let dir = tk::TempDir::new("driver-r7004-l014");
        let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
        let (w, registry, revoked) = tk::established(tk::NOW, [0x71; 32]);
        driver
            .admit_revocation_envelope(
                tk::NOW + 1,
                &tk::link_failure_revocation(&w, revoked, tk::NOW + 1).to_envelope_bytes(),
                &registry,
            )
            .expect("admit");
        driver.record_zeroization(&revoked, tk::NOW + 2).expect("zeroize");
        driver.attempt_next(&revoked, tk::NOW + 3).expect("attempt");
        // The caller-verified seam: a bare route ref pointing at the
        // revoked circuit's own commitment route (the documented trust
        // the seam leaves with the caller — exactly why the L014 check
        // below must live in the driver, not the caller).
        driver
            .attempt_succeeded(
                &revoked,
                crate::attempt::FreshRouteEvidence::RouteRef(*w.commitment.route_id()),
                tk::NOW + 4,
            )
            .expect("succeeded");
        let route = crate::driver::FreshRoute {
            revoked_circuit_id: revoked,
            route_id: *w.commitment.route_id(),
            attempt_seq: 1,
            gateway_node_id: [0u8; 32],
        };

        // The (route, nonce) of the REVOKED circuit derives exactly the
        // revoked id → the typed L014 refusal.
        let same = tk::replacement_material(
            &w.commitment,
            &w.proposer,
            &[&w.proposer, &w.hop1, &w.hop2],
            [0x71; 32],
            tk::NOW + 5,
        );
        assert_eq!(same.circuit_id, revoked, "the testkit derives the revoked circuit");
        let err = driver
            .establish_replacement_circuit(
                &route,
                &same.setup_env,
                &same.ack_envs,
                &mut CircuitRegistry::new(),
                tk::NOW + 6,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            RecoveryError::ReplacementCircuitNotFresh {
                revoked_circuit_id,
                replacement_circuit_id,
            } if revoked_circuit_id == revoked && replacement_circuit_id == revoked
        ));
        assert_eq!(err.name(), "replacement_circuit_id_not_fresh");

        // A FRESH nonce over the same route derives a different id — but
        // the driver's durable binding has the last word here only for
        // identity: it admits (the record, poisoned through the documented
        // seam, is the caller's responsibility; the L015 ledger view still
        // refuses the revoked circuit itself everywhere else).
        let fresh_nonce = tk::replacement_material(
            &w.commitment,
            &w.proposer,
            &[&w.proposer, &w.hop1, &w.hop2],
            [0x79; 32],
            tk::NOW + 5,
        );
        assert_ne!(fresh_nonce.circuit_id, revoked);
        let replacement = driver
            .establish_replacement_circuit(
                &route,
                &fresh_nonce.setup_env,
                &fresh_nonce.ack_envs,
                &mut CircuitRegistry::new(),
                tk::NOW + 6,
            )
            .expect("a fresh nonce over the recorded (seam-supplied) route");
        assert_ne!(replacement.replacement_circuit_id, revoked);
    }
}
