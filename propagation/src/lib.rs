//! ShareNet receiving-side cross-node propagation rules — work item
//! R6-004.
//!
//! `spec/architecture.md` §12: *"Propagation uses: deduplication;
//! integrity verification; TTL; priority; replication policy;
//! custody/delivery evidence; opportunistic forwarding; partial
//! transfer/resume."* R6-003 built the LOCAL half of that list (the
//! custody store) and said so explicitly: *"R6-004 owns the
//! receiving-side dedup/integrity/TTL admission rules; this crate is
//! the local half."* THIS crate is that receiving half — what THIS node
//! accepts when ANOTHER node propagates content to it (an offer of a
//! manifest + chunks, or a forward from a carrying peer), decided as a
//! PURE function of the offer evidence, the node's own durable state
//! (the R6-003 [`sharenet_dtn::DtnStoreImage`]) and the caller's clock. It is the
//! R5-005 two-factor style applied to the content plane: typed evidence
//! in, pure decision out, no I/O, no wall clock, no
//! propagation-local state.
//!
//! # The laws
//!
//! 1. **The store is the only state.** Every verdict is derived from
//!    the node's own durable store state — this crate holds no state of
//!    its own, so a decision made before a restart is a decision that
//!    holds identically after it (the restart verify level).
//! 2. **Dedup is the identity question.** Content is content-addressed
//!    and the id is RE-DERIVED from the offered bytes (L013 — never a
//!    claim); already-held content answers `already_held` /
//!    `already_complete` with the FIRST admission's own record, and a
//!    verified slot re-delivery is a `duplicate`. Re-delivery never
//!    creates a second record, never extends a TTL, never upgrades a
//!    priority (the R6-003 law, applied at the edge).
//! 3. **Integrity is the manifest's hash law.** Manifests strict-parse
//!    through the R6-001 seams; chunks verify through the STORE's own
//!    path (`verify_chunk`: length law before hash law). This crate
//!    never re-implements hashing policy and never duplicates the
//!    store — where a decision needs durable side effects it composes
//!    the store's APIs ([`PropagationPolicy::take_custody`],
//!    [`PropagationPolicy::receive_chunk`]).
//! 4. **TTL is caller-clocked and gates BEFORE priority.** No wall
//!    clock anywhere; expired offers are refused typed, offers below
//!    the policy's minimum remaining life are refused typed, and an
//!    expired `live` bundle NEVER outranks a fresh `dtn` one — no
//!    priority rescues a TTL failure, so no inversion is possible.
//! 5. **Priority is the frozen service class set.** The wire's class
//!    name parses only through `ServicePriority::from_name` — no
//!    second vocabulary, no future-class smuggling; accepted offers
//!    ingest in carry order (priority rank, expiry urgency, content
//!    id), the same order law the store uses for forwarding.
//! 6. **Replication policy is local.** A target below the store's
//!    minimum is refused; this node's replication count is its own
//!    fact (starts at 0 — peer-claimed counts are never even in the
//!    evidence); replication gates FORWARDING, not receiving — an
//!    at-target held bundle is still a duplicate verdict (not a
//!    refusal) and still completes its chunks.
//! 7. **Fail-closed, deterministic, typed.** Every tamper, lie,
//!    expiry, ambiguity or capacity pressure is a typed refusal with a
//!    stable machine name, and nothing is stored on the back of one.
//!    The evaluation order is fixed (see [`crate::verdict`]'s module docs);
//!    the same (offer, store, clock) always yields the same verdict
//!    (architecture §2).
//!
//! # What this crate deliberately does NOT do
//!
//! - **No forwarding policy.** WHERE accepted content goes next (and
//!   whether now is a good moment) is R6-005's opportunistic forwarder,
//!   composed with the R5-005 gateway admission policy — this crate is
//!   the RECEIVING edge of that composition, not the sending edge.
//! - **No carriage.** R6-002 owns the resumable transfer; this crate
//!   does not depend on it (the offer evidence mirrors exactly what an
//!   R6-002 session delivers — OFFER manifest bytes, CHUNK slot/bytes —
//!   but the rules are carriage-neutral, so a future BPv7 adapter or
//!   node-local IPC drives them identically).
//! - **No second store.** The R6-003 store owns all durable state; this
//!   crate only ever reads it (pure decisions) or mutates it through
//!   its own APIs (composed apply paths).
//! - **No signed receipts.** Custody evidence recorded on acceptance
//!   is the R6-003 unsigned local-fact log (the R8-001 seam);
//!   signatures, receipts and anti-gaming stay R8-001's layer.
//! - **No wire objects.** Verdicts and offers are node-local API
//!   types; the protocol registry governs nothing in this crate (the
//!   same reading as R5-003's store and R5-005's policy).
//! - **No wall clock.** Every time parameter — offer clocks, decision
//!   clocks, floors — is caller-supplied (the law of the connectivity
//!   boundary, the admission policy and the store, applied here).
//!
//! # Layout
//!
//! - [`evidence`]: [`ManifestOffer`], [`ChunkOffer`] — the typed offer
//!   evidence (claims in, re-derived by the policy before they matter).
//! - [`crate::verdict`]: [`ManifestVerdict`], [`ChunkVerdict`], the refusal
//!   vocabularies and the acceptance/held anchors — the typed output.
//! - [`policy`]: [`PropagationPolicy`], [`PropagationParams`] — the
//!   pure decision functions, the composed apply paths and the
//!   receiving-edge ingestion order.
//!
//! # Dependencies and platform independence
//!
//! Exactly two, both ShareNet: `sharenet-protocol` (R6-001 — the
//! manifest, its strict parse, its commitment-derived ids) and
//! `sharenet-dtn` (R6-003 — the store state, the frozen priority, the
//! read views, the custody evidence seam, the caps). No async runtime,
//! no serde, no wall clock, NO I/O anywhere in the lib.
//! `#![forbid(unsafe_code)]`. The whole crate compiles for
//! `wasm32-unknown-unknown` (the L007 discipline): on a wasm host the
//! same rules decide over the host's own `DtnStoreImage`.
//!
//! # Expected production callers
//!
//! - The ShareNet daemon's receive path: an R6-002 session (or any
//!   carriage) hands each OFFER/CHUNK to
//!   [`PropagationPolicy::decide_manifest`] / [`decide_chunk`](PropagationPolicy::decide_chunk)
//!   with the node's store and the daemon's clock; `Accept` anchors
//!   drive the store's admission, `AlreadyComplete` short-circuits the
//!   transfer with a completion signal, refusals answer the peer
//!   typed.
//! - R6-005's opportunistic forwarder on the SENDING side of the next
//!   hop: it composes this crate's verdicts at the receiving end of
//!   its hand-offs.

#![forbid(unsafe_code)]

pub mod contact;
pub mod evidence;
pub mod forwarder;
pub mod policy;
pub mod sim;
pub mod verdict;

pub use contact::{ContactBudget, ContactError, ContactOpportunity, GATEWAY_ID_LEN};
pub use evidence::{ChunkOffer, ManifestOffer};
pub use forwarder::{
    DeferredBundle, DeferralReason, ForwardError, ForwardRefusal, ForwardVerdict, ForwarderParams,
    HandoverMaterial, HandoverPlan, HandoverStep, OpportunisticForwarder, PlanApplication,
    DEFAULT_MIN_REMAINING_TTL_AT_CLOSE_SECS,
};
pub use policy::{
    PropagationParams, PropagationPolicy, DEFAULT_MIN_REMAINING_TTL_SECS,
};
pub use sim::{
    run_scenario, scenario_by_name, SimContact, SimEvent, SimNode, SimOutcome, SimScenario,
    SimStats, SimTrace, SimRng, SCENARIO_NAMES,
};
pub use verdict::{
    AcceptAnchor, ChunkAnchor, ChunkRefusal, ChunkVerdict, HeldAnchor, ManifestRefusal,
    ManifestVerdict,
};

/// The content id length — the store's own constant, re-exported for
/// caller convenience (never a second vocabulary).
pub use sharenet_dtn::CONTENT_ID_LEN;

#[cfg(test)]
mod lib_tests {
    // A cross-module sanity test: the crate's public surface is wired
    // and the pinned constants agree with the layers below.
    use crate::*;

    #[test]
    fn crate_surface_is_wired() {
        let params = PropagationParams::default();
        assert_eq!(params.min_remaining_ttl_secs(), DEFAULT_MIN_REMAINING_TTL_SECS);
        assert_eq!(DEFAULT_MIN_REMAINING_TTL_SECS, 60);
        assert_eq!(CONTENT_ID_LEN, 32);
        let policy = PropagationPolicy::default();
        assert_eq!(policy.params(), &params);
        // The frozen priority vocabulary is dtn's, re-used as-is.
        for name in sharenet_dtn::ServicePriority::from_name("live")
            .into_iter()
            .chain(sharenet_dtn::ServicePriority::from_name("opportunistic"))
            .chain(sharenet_dtn::ServicePriority::from_name("dtn"))
        {
            assert_eq!(name.as_str(), name.to_string());
        }
        assert!(sharenet_dtn::ServicePriority::from_name("bulk").is_none());
    }
}
