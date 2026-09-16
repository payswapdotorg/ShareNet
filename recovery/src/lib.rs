//! # sharenet-recovery — durable recovery attempts (R7-002) + fresh
//! gateway/route recovery (R7-003) + the replacement circuit (R7-004)
//!
//! The recovery layer of ShareNet's failure handling (architecture §11):
//! R7-002 built the durable-file foundation, R7-003 filled the
//! `SelectFreshGateway` seam, and R7-004 completes the pipeline's tail
//! — the §11 stages this crate now carries end to end are
//!
//! ```text
//! zeroization                       (R7-004 — the durable, typed fact
//!                                     that the revoked circuit's key
//!                                     material was dropped)
//!     ↓ record_zeroization
//! recovery attempt                   (R7-002 — durable, bounded)
//!     ↓ attempt_next → RecoveryStep::SelectFreshGateway
//! fresh gateway selection            (R7-003 — gateway.rs, R5-005 composed in)
//!     ↓ select_gateway → SelectedGateway
//! fresh route commitment             (R7-003 — establish_fresh_route, R3-004 chain)
//!     ↓ attempt_succeeded (the §11 freshness law, durable terminal record)
//! fresh circuit session              (R7-004 — establish_replacement_circuit:
//!                                     the R4-002 binding over the fresh
//!                                     commitment, gated registry admission,
//!                                     the durable replacement fact)
//!     ↓ verification (the R4-002 admission chain is the control-plane
//!       verification; data-plane liveness is the runtime layers')
//! ```
//!
//! Three laws anchor the crate:
//!
//! - **L015** — *"Revocation is durable and authoritative; recovery
//!   cannot resurrect a revoked circuit."* The durable ledger file
//!   ([`ledger::DurableRevocationLedger`]) is the L015 authority backed
//!   by an append-only, chain-verified log whose records are the R7-001
//!   signed revocation envelopes themselves (re-verified at every load,
//!   round-tripped through the R7-001 snapshot seam).
//! - **L021 / §11** — *"Recovery state is durable and bounded."* The
//!   attempt log ([`attempt::RecoveryAttemptLog`]) records every
//!   recovery attempt (revoked circuit, per-circuit monotonic seq,
//!   started_at, fresh route commitment ref or typed failure reason,
//!   pending/succeeded/abandoned) durably and bounded: at most
//!   [`attempt::MAX_ATTEMPT_RECORDS_PER_CIRCUIT`] retained attempts per
//!   circuit (oldest abandoned compacted) and a hard file cap.
//! - **§2 determinism** — *"The routing objective is deterministic for a
//!   fixed evidence snapshot."* Gateway selection
//!   ([`gateway::select_eligible_gateway`]) is a pure function of
//!   `(policy, candidates, now)`: the R5-005 verdict is derived per
//!   candidate (never a caller-supplied boolean), and the tie-break
//!   between eligible gateways is the fixed key of ascending gateway
//!   node-id bytes — input order never matters.
//!
//! And one ordering rule enforced at every admission: **no attempt may
//! resurrect the revoked circuit** — an attempt record referencing a
//! circuit the durable ledger does not show as revoked is refused typed
//! (`circuit_not_revoked`), and recovery only ever *follows* durable
//! invalidation. Success is terminal per circuit; a new failure of the
//! fresh circuit is a new revocation and a new recovery (L014: fresh
//! session identity). The fresh route itself must not predate the
//! revocation that started the recovery (the §11 freshness law,
//! `route_not_fresh`, enforced against the ledger-sourced anchor at
//! `attempt_succeeded`).
//!
//! The [`driver::RecoveryDriver`] composes the two stores and the §11
//! stages and exposes the recovery lifecycle:
//! `attempt_next → SelectFreshGateway → select_gateway →
//! establish_fresh_route → record_zeroization →
//! establish_replacement_circuit`, with `attempt_failed` recording
//! the typed reasons (including `no_gateway_available`, the consumption
//! of the `no_eligible_gateway` refusal). Retry/backoff policy is
//! R7-005; concurrent-recovery coordination is R7-006.
//!
//! # Dependency law (the R7-003 composition)
//!
//! `sharenet-protocol + sharenet-admission + sharenet-connectivity + std`
//! — all ShareNet, all deliberate. R7-002's original posture was
//! `sharenet-protocol + std` only; R7-003's work-item contract is that
//! only gateways the R5-005 admission policy judges `Eligible` may be
//! selected and that its math must not be rewritten, so the crate now
//! COMPOSES the real policy (`sharenet-admission`) instead of mirroring
//! it, and names the ADCOS boundary's projection types
//! (`sharenet-connectivity`) the admission evidence borrows. The
//! protocol core still supplies every authenticated fact (revocations,
//! committed paths, route commitments, signed evidence); everything here
//! is durability, ordering, bounds and composition — no second source of
//! truth for circuit terminal state (AGENTS.md), no wall clock
//! (caller-supplied `now`, by the crate law), no async runtime, no
//! serde. Native by design (durable files): there is no wasm story to
//! claim — the durable layer is the host's.
//!
//! # Verification levels
//!
//! - **R7-002 (unit, restart, concurrency)**: format/codec round-trips,
//!   corruption fail-closed at every region (both files), attempt-number
//!   monotonicity, the §11 cross-check refusals, state-machine
//!   consistency, full teardown → reload, multi-threaded interleavings.
//! - **R7-003 (adversarial, multiprocess)**: ineligible candidates never
//!   selected (even as the only candidate), lying evidence never
//!   selected, selection determinism, duplicate/empty sets, the §11
//!   freshness law end to end (a pre-revocation route is refused), path
//!   membership of the selected gateway derived from the commitment —
//!   and the whole §11 pipeline driven across REAL process boundaries
//!   through the `recovery_probe` binary (`src/bin/recovery_probe.rs`):
//!   process 1 admits a revocation + opens an attempt, process 2
//!   selects a gateway from candidates + succeeds the attempt, process
//!   3 reloads and sees the terminal state.
//! - **R7-004 (adversarial, multiprocess, restart)**: the replacement
//!   rides ONLY the recorded fresh route (the revoked circuit's own
//!   route, a stale route and any foreign route are refused typed); the
//!   derived replacement id is a FRESH session identity (L014 — and a
//!   setup deriving the revoked id itself is refused); the gated
//!   registry refuses forged/expired setup envelopes; double
//!   replacement is a typed single-flight refusal; the zeroization
//!   ordering fact survives crash+reload and gates the replacement —
//!   and the replacement is established across REAL process boundaries
//!   through `recovery_probe` (`zeroize` + `establish-replacement`),
//!   with the reload process seeing the terminal attempt + the
//!   replacement circuit fact.

pub mod attempt;
pub mod backoff;
pub mod driver;
pub mod error;
pub mod gateway;
pub mod ledger;
mod sha256;

// In-crate test scaffolding (the world builder + byte-crafting helpers
// shared by the unit suites) — never compiled into the library.
#[cfg(test)]
mod testkit;

pub use attempt::{
    AttemptFailure, AttemptState, FreshRouteEvidence, RecoveryAttempt, RecoveryAttemptLog,
    ZeroizationRecord, ATTEMPT_FORMAT_VERSION, ATTEMPT_MAGIC, MAX_ATTEMPT_LOG_FILE_BYTES,
    MAX_ATTEMPT_RECORDS_PER_CIRCUIT,
};
pub use backoff::{
    BackoffError, BackoffPolicy, BackoffSchedule, RetryDecision, TerminalReason,
};
pub use driver::{
    CircuitRecoveryStatus, FreshRoute, RecoveryDriver, RecoveryStep, RecoveryStatusState,
    ReplacementCircuit, SelectedGateway, ATTEMPT_LOG_FILE_NAME, LEDGER_FILE_NAME,
};
pub use error::{AttemptStateTag, RecoveryError, RecoveryIoOp};
pub use gateway::{select_eligible_gateway, GatewayCandidate, GatewaySelection};
pub use ledger::{
    DurableRevocationLedger, LedgerLoadReport, LEDGER_FORMAT_VERSION, LEDGER_MAGIC,
    MAX_LEDGER_FILE_BYTES,
};
