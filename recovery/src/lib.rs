//! # sharenet-recovery — durable recovery attempts (work item R7-002)
//!
//! The durable-file layer of ShareNet's failure handling (architecture
//! §11), completing what R7-001's snapshot seam deferred. Two laws anchor
//! the crate:
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
//!
//! And one ordering rule enforced at every admission: **no attempt may
//! resurrect the revoked circuit** — an attempt record referencing a
//! circuit the durable ledger does not show as revoked is refused typed
//! (`circuit_not_revoked`), and recovery only ever *follows* durable
//! invalidation. Success is terminal per circuit; a new failure of the
//! fresh circuit is a new revocation and a new recovery (L014: fresh
//! session identity).
//!
//! The [`driver::RecoveryDriver`] composes the two stores and exposes
//! the §11 lifecycle as far as R7-002's scope reaches:
//! `attempt_next → SelectFreshGateway` (the R7-003 seam) →
//! `attempt_succeeded` / `attempt_failed`. Gateway selection, route
//! construction, circuit setup and verification are R7-003/R7-004
//! scope; retry/backoff policy is R7-005; concurrent-recovery
//! coordination is R7-006.
//!
//! # Dependency law
//!
//! `sharenet-protocol + std` only. The protocol core supplies the
//! authenticated facts (signed revocations, committed paths, route
//! commitments); everything here is durability, ordering and bounds —
//! no second source of truth for circuit terminal state (AGENTS.md),
//! no wall clock (caller-supplied `now`, by the crate law), no async
//! runtime, no serde.
//!
//! # Verification levels (R7-002: unit, restart, concurrency)
//!
//! - **unit**: format/codec round-trips, corruption fail-closed at
//!   every region (both files), attempt-number monotonicity, the §11
//!   cross-check refusals (unknown circuit, attempt after success,
//!   duplicate/in-flight attempt), state-machine consistency, the
//!   SHA-256 chain construction against standard vectors;
//! - **restart**: full teardown → reload from disk — the ledger stays
//!   authoritative (a revoked circuit stays revoked across restarts,
//!   L015 END-TO-END), the attempt log continues its numbering, and
//!   the bounded log compacts old abandoned attempts;
//! - **concurrency**: multi-threaded admit/finish/begin interleavings
//!   against shared stores — no lost updates, no torn files (concurrent
//!   loads always succeed or fail typed, never parse garbage), and
//!   idempotence under racing threads.

pub mod attempt;
pub mod driver;
pub mod error;
pub mod ledger;
mod sha256;

// In-crate test scaffolding (the world builder + byte-crafting helpers
// shared by the three unit suites) — never compiled into the library.
#[cfg(test)]
mod testkit;

pub use attempt::{
    AttemptFailure, AttemptState, FreshRouteEvidence, RecoveryAttempt, RecoveryAttemptLog,
    ATTEMPT_FORMAT_VERSION, ATTEMPT_MAGIC, MAX_ATTEMPT_LOG_FILE_BYTES,
    MAX_ATTEMPT_RECORDS_PER_CIRCUIT,
};
pub use driver::{
    RecoveryDriver, RecoveryStep, ATTEMPT_LOG_FILE_NAME, LEDGER_FILE_NAME,
};
pub use error::{AttemptStateTag, RecoveryError, RecoveryIoOp};
pub use ledger::{
    DurableRevocationLedger, LedgerLoadReport, LEDGER_FORMAT_VERSION, LEDGER_MAGIC,
    MAX_LEDGER_FILE_BYTES,
};
