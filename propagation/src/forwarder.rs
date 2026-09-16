//! The opportunistic forwarder — work item R6-005: the sending-edge
//! policy layer that decides, at a contact opportunity with an
//! admitted gateway, WHICH held bundles move.
//!
//! R6-003's store named the seam precisely: *"[`DtnStoreImage::forward_candidates`]
//! says WHAT may move; WHERE it goes (and whether now is a good
//! moment) is the R6-005 opportunistic forwarder's decision, composed
//! with the R5-005 gateway admission policy — only an `Eligible`
//! gateway receives bundles."* THIS module is that decision:
//!
//! - **the contact** ([`crate::contact::ContactOpportunity`]) supplies
//!   the admitted gateway, the window and the window's carrying
//!   budget — an already-verified typed snapshot, its invariants
//!   carried by construction;
//! - **the candidates** come from the store's own
//!   `forward_candidates(now)` — the store computes the ORDER
//!   (priority rank, expiry urgency, content id — §2 determinism),
//!   so this layer never re-sorts and never disagrees;
//! - **the policy** decides BATCH COMPOSITION under the bounded
//!   contact budget: which candidates become handover steps now,
//!   which are deferred (typed, per bundle), and nothing else. A
//!   plan step is atomic: a bundle moves with its manifest and EVERY
//!   held slot, or it waits for the next contact.
//!
//! # The rules (fixed evaluation order, all typed)
//!
//! For each candidate, in the store's carry order:
//!
//! 1. **TTL at the window close** (hard): a bundle that is expired at
//!    the moment the window closes (`closes >= expires`) can never be
//!    useful to a receiver inside this window — deferred
//!    `expires_before_window_close`. This is the sending-edge twin of
//!    the store's "expired bundles never forward", evaluated against
//!    the LATEST arrival moment the window offers.
//! 2. **TTL floor at the window close** (policy parameter, default
//!    [`DEFAULT_MIN_REMAINING_TTL_AT_CLOSE_SECS`] = 60s): a bundle
//!    with less than the floor of remaining life AT THE CLOSE is not
//!    worth the window's bytes — the receiving edge (R6-004) applies
//!    the same floor at its own clock, so with equal floors the
//!    sender never offers what the receiver would refuse. Deferred
//!    `remaining_life_below_floor_at_close`.
//! 3. **One handover per (bundle, gateway)**: a bundle this store
//!    already handed to THIS gateway (its own `Forwarded` custody
//!    evidence names the gateway) is deferred `already_handed` —
//!    repeated contact with the same gateway never re-sprays the
//!    same bytes (the §14 spirit, derived from the sender's own
//!    durable facts; the receiver's state is never claimed).
//! 4. **Budget**: the step's byte cost (manifest bytes + present
//!    chunk bytes, exact) must fit the window's remaining byte bound
//!    and the window's bundle-count bound — else deferred
//!    `does_not_fit_budget` / `count_bound_reached`.
//!
//! Steps are taken greedily in carry order: higher-priority
//! candidates claim the budget first, and a candidate that does not
//! fit is SKIPPED (typed, visible) while later, smaller candidates
//! may still use the remaining budget. Scanning never re-orders —
//! the plan's steps are in the store's carry order by construction.
//!
//! The clock must be inside the window
//! ([`ForwardRefusal::ClockBeforeWindow`]/[`ForwardRefusal::ClockAfterWindow`]
//! — typed refusals, no plan, nothing moves); an empty candidate
//! list is the typed `NothingToForward` (distinct from a plan of
//! zero steps, which means candidates existed but this contact
//! served none — every deferral is per-bundle visible).
//!
//! # Determinism
//!
//! `plan` is a pure function of (params, contact, store, clock):
//! the candidate order is the store's (ordered), the walk is
//! in-order, every tie-break is a durable fact. The same inputs
//! always yield the same plan — proven by test, and by the seeded
//! simulation's byte-identical repeated traces.
//!
//! # Execution composition (apply)
//!
//! Applying a step composes the R6-003 store's own APIs — nothing is
//! re-implemented: the manifest's canonical bytes
//! (`DtnStoreImage::manifest_bytes`), every planned slot read back
//! with re-verification (`DtnStore::read_chunk` — the
//! trust-nothing law applies on every read), and exactly one
//! `note_forwarded` custody record for the gateway (the replication
//! count's evidence twin). The apply path RE-VERIFIES applicability
//! at its own clock — a plan made a moment ago never licenses a
//! handover now (verify-don't-trust, applied to ourselves). Durability
//! is the caller's flush point, as everywhere in this crate.
//!
//! The apply path needs the file-backed store (chunk reads), so it
//! is native-only, cfg-gated exactly like dtn's `DtnStore` (the
//! pure `plan` remains wasm-portable).

use sharenet_dtn::{
    BundleSummary, CustodyKind, DtnError, DtnStoreImage, CONTENT_ID_LEN,
};

use crate::contact::ContactOpportunity;

/// The default minimum remaining life a bundle must have AT THE
/// WINDOW CLOSE to be worth a handover (60s — the same number the
/// receiving edge's default floor uses, so both edges of a handover
/// agree by default and the sender never plans a handover the
/// receiver would refuse).
pub const DEFAULT_MIN_REMAINING_TTL_AT_CLOSE_SECS: u64 = 60;

/// The forwarder's tunable parameters (immutable; clone per
/// configuration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwarderParams {
    min_remaining_ttl_at_close_secs: u64,
}

impl ForwarderParams {
    /// Parameters requiring at least `min_remaining_ttl_at_close_secs`
    /// of remaining life at the window close (`0` disables the floor,
    /// leaving only the hard live-at-close gate).
    pub fn new(min_remaining_ttl_at_close_secs: u64) -> Self {
        ForwarderParams {
            min_remaining_ttl_at_close_secs,
        }
    }

    /// The configured minimum remaining life at the window close.
    pub fn min_remaining_ttl_at_close_secs(&self) -> u64 {
        self.min_remaining_ttl_at_close_secs
    }
}

impl Default for ForwarderParams {
    fn default() -> Self {
        ForwarderParams {
            min_remaining_ttl_at_close_secs: DEFAULT_MIN_REMAINING_TTL_AT_CLOSE_SECS,
        }
    }
}

/// The opportunistic forwarder: an immutable parameter set plus the
/// pure plan function and the composed apply paths over the node's
/// own store. Deterministic for a fixed (contact, store, clock)
/// triple (architecture §2) — a namespace for the rules, not a
/// mutable engine.
#[derive(Debug, Clone, Default)]
pub struct OpportunisticForwarder {
    params: ForwarderParams,
}

/// A typed reason a forwarder call refused to plan at all (no plan
/// is produced; nothing moves).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardRefusal {
    /// The decision clock is before the window opens.
    ClockBeforeWindow {
        /// The decision clock.
        now_unix: u64,
        /// The window's open (inclusive).
        opens_at_unix: u64,
    },
    /// The decision clock is at or past the window's close.
    ClockAfterWindow {
        /// The decision clock.
        now_unix: u64,
        /// The window's close (exclusive).
        closes_at_unix: u64,
    },
}

impl ForwardRefusal {
    /// The stable machine name.
    pub fn name(&self) -> &'static str {
        match self {
            ForwardRefusal::ClockBeforeWindow { .. } => "clock_before_window",
            ForwardRefusal::ClockAfterWindow { .. } => "clock_after_window",
        }
    }
}

impl std::fmt::Display for ForwardRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardRefusal::ClockBeforeWindow {
                now_unix,
                opens_at_unix,
            } => write!(f, "clock {now_unix} is before the window opens at {opens_at_unix}"),
            ForwardRefusal::ClockAfterWindow {
                now_unix,
                closes_at_unix,
            } => write!(f, "clock {now_unix} is at or past the window close {closes_at_unix}"),
        }
    }
}

/// A typed reason a candidate did not become a step in this contact's
/// plan (a deferral is a VERDICT about this contact, not a refusal of
/// the bundle — the next contact decides again).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferralReason {
    /// The bundle is expired (or expires exactly) at the moment the
    /// window closes — no receiver inside this window can use it.
    ExpiresBeforeWindowClose {
        /// The bundle's expiry bound.
        expires_at_unix: u64,
        /// The window's close.
        closes_at_unix: u64,
    },
    /// The bundle's remaining life at the window close is below the
    /// forwarder's floor (nearly-dead bundles are not worth the
    /// window's bytes — the receiving edge applies the same floor).
    RemainingLifeBelowFloorAtClose {
        /// `expires_at_unix - closes_at_unix`.
        remaining_secs: u64,
        /// The configured floor.
        minimum_secs: u64,
    },
    /// This store already handed this bundle to THIS gateway (its
    /// own Forwarded custody evidence) — one handover per (bundle,
    /// gateway); the same contact never re-sprays.
    AlreadyHanded,
    /// The step's byte cost exceeds the window's remaining byte
    /// bound.
    DoesNotFitBudget {
        /// The step's exact byte cost (manifest + present chunks).
        byte_cost: u64,
        /// The byte bound remaining when the candidate was scanned.
        remaining_bytes: u64,
    },
    /// The window's bundle-count bound is already fully claimed.
    CountBoundReached {
        /// The window's bundle count bound.
        max_bundles: u32,
    },
}

impl DeferralReason {
    /// The stable machine name.
    pub fn name(&self) -> &'static str {
        match self {
            DeferralReason::ExpiresBeforeWindowClose { .. } => "expires_before_window_close",
            DeferralReason::RemainingLifeBelowFloorAtClose { .. } => {
                "remaining_life_below_floor_at_close"
            }
            DeferralReason::AlreadyHanded => "already_handed",
            DeferralReason::DoesNotFitBudget { .. } => "does_not_fit_budget",
            DeferralReason::CountBoundReached { .. } => "count_bound_reached",
        }
    }
}

/// One planned handover: a bundle moving to the contact's gateway —
/// its manifest bytes plus EVERY held slot (a bundle moves whole in
/// a window, or not at all: completing a receiver's partial copy is
/// the R6-002 resume layer's business inside the transfer, and the
/// next contact is the coarser resume for the rest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverStep {
    summary: BundleSummary,
    slots: Vec<u32>,
    byte_cost: u64,
}

impl HandoverStep {
    /// The store's own read view of the bundle at plan time (id,
    /// priority, expiry, replication state, presence).
    pub fn summary(&self) -> &BundleSummary {
        &self.summary
    }

    /// The moving content id.
    pub fn content_id(&self) -> &[u8; CONTENT_ID_LEN] {
        self.summary.content_id()
    }

    /// The carry priority.
    pub fn priority(&self) -> sharenet_dtn::ServicePriority {
        self.summary.priority()
    }

    /// The expiry bound.
    pub fn expires_at_unix(&self) -> u64 {
        self.summary.expires_at_unix()
    }

    /// The present slots that move with the manifest (ascending).
    pub fn slots(&self) -> &[u32] {
        &self.slots
    }

    /// The exact byte cost: manifest canonical bytes + the present
    /// chunks' committed lengths.
    pub fn byte_cost(&self) -> u64 {
        self.byte_cost
    }
}

/// A candidate that did not become a step, with the typed reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeferredBundle {
    summary: BundleSummary,
    reason: DeferralReason,
}

impl DeferredBundle {
    /// The store's own read view of the deferred bundle.
    pub fn summary(&self) -> &BundleSummary {
        &self.summary
    }

    /// The deferred content id.
    pub fn content_id(&self) -> &[u8; CONTENT_ID_LEN] {
        self.summary.content_id()
    }

    /// The typed reason this contact did not serve it.
    pub fn reason(&self) -> &DeferralReason {
        &self.reason
    }
}

/// The ordered handover plan: which bundles move to the contact's
/// gateway, in the store's carry order, and which were deferred with
/// typed reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverPlan {
    gateway_node_id: [u8; 32],
    opens_at_unix: u64,
    closes_at_unix: u64,
    planned_at_unix: u64,
    steps: Vec<HandoverStep>,
    deferred: Vec<DeferredBundle>,
}

impl HandoverPlan {
    /// The gateway the plan hands over to.
    pub fn gateway_node_id(&self) -> &[u8; 32] {
        &self.gateway_node_id
    }

    /// The window the plan was composed for.
    pub fn opens_at_unix(&self) -> u64 {
        self.opens_at_unix
    }

    /// The window's close (exclusive).
    pub fn closes_at_unix(&self) -> u64 {
        self.closes_at_unix
    }

    /// The clock the plan was composed at.
    pub fn planned_at_unix(&self) -> u64 {
        self.planned_at_unix
    }

    /// The planned steps, in carry order (priority rank, expiry
    /// urgency, content id — the store's order).
    pub fn steps(&self) -> &[HandoverStep] {
        &self.steps
    }

    /// The deferred candidates with their typed reasons, in carry
    /// order.
    pub fn deferred(&self) -> &[DeferredBundle] {
        &self.deferred
    }

    /// The total planned payload bytes (the budget claimed).
    pub fn planned_bytes(&self) -> u64 {
        self.steps.iter().map(|step| step.byte_cost).sum()
    }
}

/// The verdict of a planning call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardVerdict {
    /// The ordered handover plan (possibly with zero steps — every
    /// candidate was deferred; the per-bundle reasons say why).
    Plan(HandoverPlan),
    /// The store has no forward candidates at the decision clock
    /// (nothing held is live/undelivered/with replication remaining).
    NothingToForward,
    /// Typed refusal: the decision clock is outside the contact's
    /// window (nothing moves).
    Refused(ForwardRefusal),
}

impl ForwardVerdict {
    /// Stable machine name: `plan` / `nothing_to_forward` / `refused`.
    pub fn name(&self) -> &'static str {
        match self {
            ForwardVerdict::Plan(_) => "plan",
            ForwardVerdict::NothingToForward => "nothing_to_forward",
            ForwardVerdict::Refused(_) => "refused",
        }
    }

    /// Whether this verdict carries a plan (a derived accessor, not
    /// a trust input).
    pub fn is_plan(&self) -> bool {
        matches!(self, ForwardVerdict::Plan(_))
    }

    /// The typed refusal (only meaningful on `Refused`).
    pub fn refusal(&self) -> Option<&ForwardRefusal> {
        match self {
            ForwardVerdict::Refused(reason) => Some(reason),
            _ => None,
        }
    }
}

/// A typed failure of an apply attempt (fail-closed: nothing was
/// noted, nothing was handed over).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardError {
    /// The bundle is no longer held (evicted between plan and apply).
    CandidateVanished {
        /// The vanished content id.
        content_id: [u8; CONTENT_ID_LEN],
    },
    /// The bundle expired between plan and apply.
    CandidateExpired {
        /// The content id.
        content_id: [u8; CONTENT_ID_LEN],
        /// The expiry bound that has passed.
        expires_at_unix: u64,
        /// The apply clock.
        now_unix: u64,
    },
    /// The bundle was terminally delivered between plan and apply.
    CandidateDelivered {
        /// The content id.
        content_id: [u8; CONTENT_ID_LEN],
    },
    /// The bundle's replication target was exhausted between plan and
    /// apply (another handover landed first).
    CandidateAtTarget {
        /// The content id.
        content_id: [u8; CONTENT_ID_LEN],
        /// The replication count at apply time.
        count: u32,
        /// The target.
        target: u32,
    },
    /// This store already handed this bundle to the gateway between
    /// plan and apply (a concurrent apply won).
    AlreadyHanded {
        /// The content id.
        content_id: [u8; CONTENT_ID_LEN],
    },
    /// A planned slot is no longer held (the store disagrees with the
    /// plan — fail-closed, nothing noted).
    SlotVanished {
        /// The content id.
        content_id: [u8; CONTENT_ID_LEN],
        /// The slot that is no longer held.
        slot: u32,
    },
    /// The store refused in a way the apply path does not model
    /// (fail-closed; carries the store error's machine name).
    Store {
        /// The `DtnError`'s stable machine name.
        name: String,
    },
}

impl ForwardError {
    /// The stable machine name.
    pub fn name(&self) -> &'static str {
        match self {
            ForwardError::CandidateVanished { .. } => "candidate_vanished",
            ForwardError::CandidateExpired { .. } => "candidate_expired",
            ForwardError::CandidateDelivered { .. } => "candidate_delivered",
            ForwardError::CandidateAtTarget { .. } => "candidate_at_target",
            ForwardError::AlreadyHanded { .. } => "already_handed",
            ForwardError::SlotVanished { .. } => "slot_vanished",
            ForwardError::Store { .. } => "store",
        }
    }
}

impl std::fmt::Display for ForwardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ForwardError::CandidateVanished { content_id } => {
                write!(f, "candidate {} is no longer held", id_hex(content_id))
            }
            ForwardError::CandidateExpired {
                content_id,
                expires_at_unix,
                now_unix,
            } => write!(
                f,
                "candidate {} expired at {expires_at_unix} before the {now_unix} apply",
                id_hex(content_id)
            ),
            ForwardError::CandidateDelivered { content_id } => {
                write!(f, "candidate {} was delivered", id_hex(content_id))
            }
            ForwardError::CandidateAtTarget {
                content_id,
                count,
                target,
            } => write!(
                f,
                "candidate {} is at target ({count}/{target})",
                id_hex(content_id)
            ),
            ForwardError::AlreadyHanded { content_id } => write!(
                f,
                "candidate {} was already handed to this gateway",
                id_hex(content_id)
            ),
            ForwardError::SlotVanished { content_id, slot } => {
                write!(f, "slot {slot} of {} is no longer held", id_hex(content_id))
            }
            ForwardError::Store { name } => write!(f, "store refused: {name}"),
        }
    }
}

fn id_hex(id: &[u8; CONTENT_ID_LEN]) -> String {
    sharenet_dtn::hex::encode(id)
}

impl OpportunisticForwarder {
    /// A forwarder with the given parameters.
    pub fn new(params: ForwarderParams) -> Self {
        OpportunisticForwarder { params }
    }

    /// The forwarder's parameters.
    pub fn params(&self) -> &ForwarderParams {
        &self.params
    }

    /// Whether `store`'s own custody evidence records a forward of
    /// `content_id` to `peer` (the one-handover-per-(bundle, gateway)
    /// law's fact — derived from durable state only).
    fn already_handed_to(store: &DtnStoreImage, content_id: &[u8; CONTENT_ID_LEN], peer: &str) -> bool {
        store
            .evidence_for(content_id)
            .iter()
            .any(|record| record.kind() == CustodyKind::Forwarded && record.peer().to_hex() == peer)
    }

    /// Compose the ordered handover plan for the contact at the
    /// caller's clock — a PURE decision over the store (see the module
    /// docs for the rule families and their fixed order).
    pub fn plan(
        &self,
        contact: &ContactOpportunity<'_>,
        store: &DtnStoreImage,
        now_unix: u64,
    ) -> ForwardVerdict {
        // The clock must be inside the window (typed refusals; the
        // contact invariants were proven at construction, the clock
        // is checked here because it is per-call).
        if now_unix < contact.opens_at_unix() {
            return ForwardVerdict::Refused(ForwardRefusal::ClockBeforeWindow {
                now_unix,
                opens_at_unix: contact.opens_at_unix(),
            });
        }
        if now_unix >= contact.closes_at_unix() {
            return ForwardVerdict::Refused(ForwardRefusal::ClockAfterWindow {
                now_unix,
                closes_at_unix: contact.closes_at_unix(),
            });
        }
        // The store's own carry list — the ORDER law is the store's
        // (priority rank, expiry urgency, content id).
        let candidates = store.forward_candidates(now_unix);
        if candidates.is_empty() {
            return ForwardVerdict::NothingToForward;
        }
        let gateway_peer = contact.peer_ref().to_hex();
        let mut steps: Vec<HandoverStep> = Vec::new();
        let mut deferred: Vec<DeferredBundle> = Vec::new();
        let mut remaining_bytes = contact.budget().max_bytes();
        for candidate in &candidates {
            let summary = candidate.summary().clone();
            let id = *summary.content_id();
            let expires_at = summary.expires_at_unix();
            // 1. TTL hard gate at the window close: expired (or
            //    expiring exactly) at close is never useful inside
            //    the window.
            if expires_at <= contact.closes_at_unix() {
                deferred.push(DeferredBundle {
                    summary,
                    reason: DeferralReason::ExpiresBeforeWindowClose {
                        expires_at_unix: expires_at,
                        closes_at_unix: contact.closes_at_unix(),
                    },
                });
                continue;
            }
            // 2. The remaining-life floor at the window close (the
            //    receiving edge's own floor, mirrored).
            let remaining_at_close = expires_at - contact.closes_at_unix();
            if remaining_at_close < self.params.min_remaining_ttl_at_close_secs {
                deferred.push(DeferredBundle {
                    summary,
                    reason: DeferralReason::RemainingLifeBelowFloorAtClose {
                        remaining_secs: remaining_at_close,
                        minimum_secs: self.params.min_remaining_ttl_at_close_secs,
                    },
                });
                continue;
            }
            // 3. One handover per (bundle, gateway) — the sender's
            //    own durable evidence decides.
            if Self::already_handed_to(store, &id, &gateway_peer) {
                deferred.push(DeferredBundle {
                    summary,
                    reason: DeferralReason::AlreadyHanded,
                });
                continue;
            }
            // The exact byte cost: the manifest's canonical bytes +
            // every held slot's committed length (read through the
            // store's own views; nothing is re-implemented).
            let manifest_bytes = store
                .manifest_bytes(&id)
                .expect("forward_candidates listed the bundle (held)");
            let slots: Vec<u32> = store
                .present_slots(&id)
                .expect("forward_candidates listed the bundle (held)")
                .to_vec();
            let manifest = store
                .manifest(&id)
                .expect("forward_candidates listed the bundle (parses)");
            let mut byte_cost = manifest_bytes.len() as u64;
            for slot in &slots {
                byte_cost += manifest
                    .expected_chunk_len(*slot as usize)
                    .expect("present slots are inside the manifest (store law)");
            }
            // 4. The budget: count bound, then byte bound.
            if steps.len() as u32 == contact.budget().max_bundles() {
                deferred.push(DeferredBundle {
                    summary,
                    reason: DeferralReason::CountBoundReached {
                        max_bundles: contact.budget().max_bundles(),
                    },
                });
                continue;
            }
            if byte_cost > remaining_bytes {
                deferred.push(DeferredBundle {
                    summary,
                    reason: DeferralReason::DoesNotFitBudget {
                        byte_cost,
                        remaining_bytes,
                    },
                });
                continue;
            }
            remaining_bytes -= byte_cost;
            steps.push(HandoverStep {
                summary,
                slots,
                byte_cost,
            });
        }
        ForwardVerdict::Plan(HandoverPlan {
            gateway_node_id: *contact.gateway_node_id(),
            opens_at_unix: contact.opens_at_unix(),
            closes_at_unix: contact.closes_at_unix(),
            planned_at_unix: now_unix,
            steps,
            deferred,
        })
    }

    // -------------------------------------------------------------------
    // The composed apply path (file-backed store; native only — the
    // pure plan above is the wasm-portable half, exactly like dtn's
    // DtnStore split).
    // -------------------------------------------------------------------

    /// Apply one plan step through the store's own APIs: re-verify
    /// applicability at THIS call's clock, read the manifest's
    /// canonical bytes, read every planned slot back with
    /// re-verification (`DtnStore::read_chunk` re-hashes on every
    /// read — trust nothing, not even ourselves), and note exactly
    /// one forward for the contact's gateway. Durability is the
    /// caller's flush point (the daemon's discipline, as everywhere
    /// in this crate).
    ///
    /// Fail-closed: on any typed failure NOTHING was noted and no
    /// handover happened. The returned [`HandoverMaterial`] is what
    /// the daemon (or an R6-002 session) puts on the wire.
    #[cfg(not(target_family = "wasm"))]
    pub fn apply_step(
        &self,
        store: &mut sharenet_dtn::DtnStore,
        contact: &ContactOpportunity<'_>,
        step: &HandoverStep,
        now_unix: u64,
    ) -> Result<HandoverMaterial, ForwardError> {
        let id = *step.content_id();
        // Verify-don't-trust, applied to our own plan: the store's
        // CURRENT state decides, at this call's clock.
        let Some(summary) = store.image().summary(&id) else {
            return Err(ForwardError::CandidateVanished { content_id: id });
        };
        if summary.delivered() {
            return Err(ForwardError::CandidateDelivered { content_id: id });
        }
        if now_unix >= summary.expires_at_unix() {
            return Err(ForwardError::CandidateExpired {
                content_id: id,
                expires_at_unix: summary.expires_at_unix(),
                now_unix,
            });
        }
        if summary.replication_count() >= summary.replication_target() {
            return Err(ForwardError::CandidateAtTarget {
                content_id: id,
                count: summary.replication_count(),
                target: summary.replication_target(),
            });
        }
        let gateway_peer = contact.peer_ref();
        if Self::already_handed_to(store.image(), &id, &gateway_peer.to_hex()) {
            return Err(ForwardError::AlreadyHanded { content_id: id });
        }
        // The material, read through the store's own APIs.
        let manifest_bytes = store
            .image()
            .manifest_bytes(&id)
            .map_err(map_store_error)?
            .to_vec();
        let mut chunks: Vec<(u32, Vec<u8>)> = Vec::with_capacity(step.slots.len());
        for slot in step.slots() {
            let bytes = store.read_chunk(&id, *slot).map_err(|err| match err {
                DtnError::SlotNotHeld { slot, .. } => ForwardError::SlotVanished {
                    content_id: id,
                    slot,
                },
                other => map_store_error(other),
            })?;
            chunks.push((*slot, bytes));
        }
        // Exactly one custody record for the handover (evidence +
        // the replication count's twin).
        store
            .note_forwarded(&id, now_unix, &gateway_peer)
            .map_err(map_store_error)?;
        Ok(HandoverMaterial {
            content_id: id,
            manifest_bytes,
            chunks,
        })
    }

    /// Apply every step of a plan, independently: successes carry
    /// their handover material, failures carry their typed error and
    /// changed nothing. Steps are applied in plan (carry) order.
    #[cfg(not(target_family = "wasm"))]
    pub fn apply_plan(
        &self,
        store: &mut sharenet_dtn::DtnStore,
        contact: &ContactOpportunity<'_>,
        plan: &HandoverPlan,
        now_unix: u64,
    ) -> PlanApplication {
        let mut applied = Vec::with_capacity(plan.steps.len());
        let mut failed = Vec::new();
        for step in plan.steps() {
            match self.apply_step(store, contact, step, now_unix) {
                Ok(material) => applied.push((step.clone(), material)),
                Err(error) => failed.push((step.clone(), error)),
            }
        }
        PlanApplication { applied, failed }
    }
}

/// What one applied handover produced: the manifest's canonical bytes
/// plus every planned slot's re-verified bytes — exactly what the
/// carriage (an R6-002 session, a future BPv7 adapter, node-local
/// IPC) puts on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoverMaterial {
    content_id: [u8; CONTENT_ID_LEN],
    manifest_bytes: Vec<u8>,
    chunks: Vec<(u32, Vec<u8>)>,
}

impl HandoverMaterial {
    /// The handed-over content id.
    pub fn content_id(&self) -> &[u8; CONTENT_ID_LEN] {
        &self.content_id
    }

    /// The manifest's canonical bytes (what the receiving edge
    /// strict-parses through R6-004).
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.manifest_bytes
    }

    /// The chunk bytes in slot order (each re-verified on read).
    pub fn chunks(&self) -> &[(u32, Vec<u8>)] {
        &self.chunks
    }

    /// The material's byte length (manifest + chunks — the budget's
    /// accounting unit).
    pub fn byte_len(&self) -> u64 {
        self.manifest_bytes.len() as u64
            + self.chunks.iter().map(|(_, bytes)| bytes.len() as u64).sum::<u64>()
    }
}

/// The outcome of applying a whole plan: per-step successes (with
/// their wire material) and per-step typed failures (fail-closed,
/// nothing noted for those).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApplication {
    applied: Vec<(HandoverStep, HandoverMaterial)>,
    failed: Vec<(HandoverStep, ForwardError)>,
}

impl PlanApplication {
    /// The applied steps in plan order, with their handover material.
    pub fn applied(&self) -> &[(HandoverStep, HandoverMaterial)] {
        &self.applied
    }

    /// The failed steps in plan order, with their typed errors.
    pub fn failed(&self) -> &[(HandoverStep, ForwardError)] {
        &self.failed
    }

    /// Whether nothing at all was applied.
    pub fn is_empty(&self) -> bool {
        self.applied.is_empty()
    }

    /// The total bytes that moved (the applied steps' costs).
    pub fn applied_bytes(&self) -> u64 {
        self.applied
            .iter()
            .map(|(_, material)| material.byte_len())
            .sum()
    }
}

/// Map a store error to the apply path's fail-closed carry-all (the
/// machine name rides along).
#[cfg(not(target_family = "wasm"))]
fn map_store_error(err: DtnError) -> ForwardError {
    ForwardError::Store {
        name: err.name().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contact::{ContactBudget, ContactError};
    use sharenet_admission::{
        AdmissionReason, AdcosEvidenceAnchor, GatewayAdmission, ShareNetEvidenceAnchor,
    };
    use sharenet_connectivity::{ContractState, ConnectivityContractRef};
    use sharenet_dtn::{DtnStore, PeerRef, ServicePriority};
    use sharenet_protocol::ContentManifest;

    const NOW: u64 = 1_700_000_500;
    const EXPIRY: u64 = NOW + 10_000;

    fn gateway_id(tag: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = tag;
        id
    }

    fn eligible(gateway: [u8; 32], valid_until: u64) -> GatewayAdmission {
        GatewayAdmission::Eligible {
            gateway_node_id: gateway,
            sharenet: ShareNetEvidenceAnchor {
                link_id: [1; 32],
                observer_node_id: [2; 32],
                observed_at_unix: NOW,
                expires_at_unix: valid_until,
                loss_ratio_ppm_effective: 0,
                p95_rtt_micros: 1_000,
                fresh_until_unix: valid_until,
            },
            adcos: AdcosEvidenceAnchor {
                contract: ConnectivityContractRef::from_id([3; 32]),
                state: ContractState::Active,
                fresh_until_unix: valid_until,
                last_observed_at_unix: NOW,
                last_sequence: 1,
                provider_node_id: [4; 32],
            },
            valid_until_unix: valid_until,
        }
    }

    /// A window [NOW, NOW + 100) with the given budget, evidence
    /// valid comfortably beyond it.
    fn contact<'a>(
        verdict: &'a GatewayAdmission,
        max_bytes: u64,
        max_bundles: u32,
    ) -> ContactOpportunity<'a> {
        ContactOpportunity::new(
            gateway_id(7),
            verdict,
            NOW,
            NOW + 100,
            ContactBudget::new(max_bytes, max_bundles).unwrap(),
        )
        .unwrap()
    }

    /// A manifest with `n` chunks of 8 bytes from real content.
    fn fixture(n: usize, seed: u8) -> (ContentManifest, Vec<Vec<u8>>) {
        let content: Vec<u8> = (0..(n * 8))
            .map(|i| (i as u8).wrapping_mul(3).wrapping_add(seed))
            .collect();
        ContentManifest::chunk(&content, 8, "app/test", None, NOW).expect("valid content")
    }

    /// A store holding one complete bundle per priority name (distinct
    /// sizes: live 2 chunks, opportunistic 4, dtn 1 — so byte budgets
    /// can distinguish them), all with the same comfortable expiry.
    fn stocked_store() -> DtnStoreImage {
        let mut store = DtnStoreImage::new();
        for (name, chunks_wanted, seed) in [
            ("live", 2usize, 0x42u8),
            ("opportunistic", 4, 0x41),
            ("dtn", 1, 0x40),
        ] {
            let (manifest, chunks) = fixture(chunks_wanted, seed);
            store
                .admit_manifest(
                    &manifest,
                    ServicePriority::from_name(name).unwrap(),
                    NOW,
                    EXPIRY,
                    2,
                )
                .unwrap();
            for (slot, chunk) in chunks.iter().enumerate() {
                store.admit_chunk(&manifest.content_id(), slot, chunk, NOW).unwrap();
            }
        }
        store
    }

    /// The happy path: everything fits, the plan is the whole carry
    /// list in the STORE's order, with exact byte costs.
    #[test]
    fn generous_budget_plans_everything_in_carry_order() {
        let store = stocked_store();
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        let contact = contact(&verdict, 1_000_000, 100);
        let forwarder = OpportunisticForwarder::default();
        let verdict = forwarder.plan(&contact, &store, NOW);
        let ForwardVerdict::Plan(plan) = verdict else {
            panic!("expected a plan, got {}", verdict.name());
        };
        assert_eq!(plan.steps().len(), 3);
        assert!(plan.deferred().is_empty());
        assert_eq!(plan.planned_at_unix(), NOW);
        assert_eq!(plan.gateway_node_id(), &gateway_id(7));
        // The store's carry order: live, then opportunistic, then dtn.
        assert_eq!(plan.steps()[0].priority(), ServicePriority::Live);
        assert_eq!(plan.steps()[1].priority(), ServicePriority::Opportunistic);
        assert_eq!(plan.steps()[2].priority(), ServicePriority::Dtn);
        // Each step: every held slot, byte cost = manifest bytes +
        // those chunks' committed lengths.
        for step in plan.steps() {
            assert_eq!(step.slots(), store.present_slots(step.content_id()).unwrap());
            let manifest = store.manifest(step.content_id()).unwrap();
            let expected = store.manifest_bytes(step.content_id()).unwrap().len() as u64
                + step
                    .slots()
                    .iter()
                    .map(|s| manifest.expected_chunk_len(*s as usize).unwrap())
                    .sum::<u64>();
            assert_eq!(step.byte_cost(), expected);
        }
        assert_eq!(plan.planned_bytes(), plan.steps().iter().map(|s| s.byte_cost()).sum());
    }

    /// The clock gates: before the window and at/after the close are
    /// typed refusals; nothing is planned.
    #[test]
    fn clocks_outside_the_window_are_refused() {
        let store = stocked_store();
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        let contact = contact(&verdict, 1_000_000, 100);
        let forwarder = OpportunisticForwarder::default();
        assert_eq!(
            forwarder.plan(&contact, &store, NOW - 1),
            ForwardVerdict::Refused(ForwardRefusal::ClockBeforeWindow {
                now_unix: NOW - 1,
                opens_at_unix: NOW,
            })
        );
        assert_eq!(
            forwarder.plan(&contact, &store, NOW + 100),
            ForwardVerdict::Refused(ForwardRefusal::ClockAfterWindow {
                now_unix: NOW + 100,
                closes_at_unix: NOW + 100,
            })
        );
        // The window's last tick still plans.
        assert!(forwarder.plan(&contact, &store, NOW + 99).is_plan());
        // The refusal vocabulary is machine-named and distinct.
        assert_eq!(
            ForwardRefusal::ClockBeforeWindow { now_unix: 0, opens_at_unix: 1 }.name(),
            "clock_before_window"
        );
        assert_eq!(
            ForwardRefusal::ClockAfterWindow { now_unix: 1, closes_at_unix: 1 }.name(),
            "clock_after_window"
        );
        assert_eq!(forwarder.plan(&contact, &store, NOW - 1).name(), "refused");
    }

    /// An empty store (or one with no live candidates) is the typed
    /// `nothing_to_forward`, distinct from a zero-step plan.
    #[test]
    fn no_candidates_is_nothing_to_forward() {
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        let contact = contact(&verdict, 1_000_000, 100);
        let forwarder = OpportunisticForwarder::default();
        assert_eq!(
            forwarder.plan(&contact, &DtnStoreImage::new(), NOW),
            ForwardVerdict::NothingToForward
        );
        assert_eq!(
            forwarder.plan(&contact, &DtnStoreImage::new(), NOW).name(),
            "nothing_to_forward"
        );
        // At-target, delivered and expired bundles are not candidates
        // (the store's law) — still nothing to forward.
        let mut store = DtnStoreImage::new();
        let (manifest, chunks) = fixture(1, 0x51);
        store
            .admit_manifest(&manifest, ServicePriority::Dtn, NOW, EXPIRY, 1)
            .unwrap();
        store.admit_chunk(&manifest.content_id(), 0, &chunks[0], NOW).unwrap();
        store
            .note_forwarded(&manifest.content_id(), NOW, &PeerRef::new(&[9]).unwrap())
            .unwrap();
        assert_eq!(
            forwarder.plan(&contact, &store, NOW),
            ForwardVerdict::NothingToForward
        );
    }

    /// A byte budget smaller than the demand: the head of the carry
    /// list claims it, the rest defer typed; a candidate that fits
    /// after a too-big one still moves (greedy in carry order, never
    /// re-ordered).
    #[test]
    fn tight_byte_budget_defers_the_rest_in_order() {
        let store = stocked_store();
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        let forwarder = OpportunisticForwarder::default();
        // Budget for exactly the live bundle + the dtn bundle but
        // NOT the opportunistic one in the middle: the opportunistic
        // defers (does_not_fit_budget) and the dtn one still fits.
        let live_cost = planned_cost(&store, 0);
        let opp_cost = planned_cost(&store, 1);
        let dtn_cost = planned_cost(&store, 2);
        let budget = live_cost + dtn_cost;
        let contact = contact(&verdict, budget, 100);
        let ForwardVerdict::Plan(plan) = forwarder.plan(&contact, &store, NOW) else {
            panic!("expected a plan");
        };
        assert_eq!(plan.steps().len(), 2, "{:?}", plan.deferred());
        assert_eq!(plan.steps()[0].priority(), ServicePriority::Live);
        assert_eq!(plan.steps()[1].priority(), ServicePriority::Dtn);
        assert_eq!(plan.planned_bytes(), budget);
        // The middle candidate deferred with the exact numbers.
        assert_eq!(plan.deferred().len(), 1);
        let deferred = &plan.deferred()[0];
        assert_eq!(deferred.summary().priority(), ServicePriority::Opportunistic);
        assert_eq!(
            deferred.reason(),
            &DeferralReason::DoesNotFitBudget {
                byte_cost: opp_cost,
                remaining_bytes: budget - live_cost,
            }
        );
        assert_eq!(deferred.reason().name(), "does_not_fit_budget");
    }

    /// The byte bound is inclusive: a budget exactly equal to a
    /// single bundle's cost plans it.
    #[test]
    fn exact_budget_fits_exactly() {
        let store = stocked_store();
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        let forwarder = OpportunisticForwarder::default();
        let cost = planned_cost(&store, 0);
        let contact = contact(&verdict, cost, 100);
        let ForwardVerdict::Plan(plan) = forwarder.plan(&contact, &store, NOW) else {
            panic!("expected a plan");
        };
        assert_eq!(plan.steps().len(), 1);
        assert_eq!(plan.planned_bytes(), cost);
    }

    /// The count bound caps the batch; the remainder defers typed.
    #[test]
    fn count_bound_defers_the_tail() {
        let store = stocked_store();
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        let forwarder = OpportunisticForwarder::default();
        let contact = contact(&verdict, 1_000_000, 2);
        let ForwardVerdict::Plan(plan) = forwarder.plan(&contact, &store, NOW) else {
            panic!("expected a plan");
        };
        assert_eq!(plan.steps().len(), 2);
        assert_eq!(plan.deferred().len(), 1);
        assert_eq!(
            plan.deferred()[0].reason(),
            &DeferralReason::CountBoundReached { max_bundles: 2 }
        );
        assert_eq!(plan.deferred()[0].reason().name(), "count_bound_reached");
    }

    /// The TTL gates: a bundle that expires at or before the window
    /// close defers `expires_before_window_close`; one with less
    /// than the floor of life AT the close defers
    /// `remaining_life_below_floor_at_close` (inclusive floor
    /// boundary pinned exactly).
    #[test]
    fn ttl_gates_at_the_window_close() {
        let mut store = DtnStoreImage::new();
        // Hard-gate case: expires exactly at the close.
        let (a, a_chunks) = fixture(1, 0x61);
        store
            .admit_manifest(&a, ServicePriority::Live, NOW, NOW + 100, 1)
            .unwrap();
        store.admit_chunk(&a.content_id(), 0, &a_chunks[0], NOW).unwrap();
        // Floor case: 60s of life at the close with the default
        // floor of 60 — exactly at the floor is PLANNED; 59 is not.
        let (b, b_chunks) = fixture(1, 0x62);
        store
            .admit_manifest(&b, ServicePriority::Live, NOW, NOW + 100 + 60, 1)
            .unwrap();
        store.admit_chunk(&b.content_id(), 0, &b_chunks[0], NOW).unwrap();
        let (c, c_chunks) = fixture(1, 0x63);
        store
            .admit_manifest(&c, ServicePriority::Live, NOW, NOW + 100 + 59, 1)
            .unwrap();
        store.admit_chunk(&c.content_id(), 0, &c_chunks[0], NOW).unwrap();
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        let contact = contact(&verdict, 1_000_000, 100);
        let forwarder = OpportunisticForwarder::default();
        let ForwardVerdict::Plan(plan) = forwarder.plan(&contact, &store, NOW) else {
            panic!("expected a plan");
        };
        // Only b moves (60s at the close, exactly at the floor).
        assert_eq!(plan.steps().len(), 1);
        assert_eq!(plan.steps()[0].content_id(), &b.content_id());
        // a: expires exactly at the close — hard-gated.
        assert_eq!(
            plan.deferred()[0].reason(),
            &DeferralReason::ExpiresBeforeWindowClose {
                expires_at_unix: NOW + 100,
                closes_at_unix: NOW + 100,
            }
        );
        assert_eq!(
            plan.deferred()[0].reason().name(),
            "expires_before_window_close"
        );
        // c: 59s at the close, below the floor.
        assert_eq!(
            plan.deferred()[1].reason(),
            &DeferralReason::RemainingLifeBelowFloorAtClose {
                remaining_secs: 59,
                minimum_secs: 60,
            }
        );
        // A floor of 0 disables the floor check (only the hard gate
        // remains): c now plans too.
        let disabled = OpportunisticForwarder::new(ForwarderParams::new(0));
        let ForwardVerdict::Plan(plan) = disabled.plan(&contact, &store, NOW) else {
            panic!("expected a plan");
        };
        assert_eq!(plan.steps().len(), 2);
        assert!(plan.steps().iter().any(|s| s.content_id() == &c.content_id()));
    }

    /// One handover per (bundle, gateway): a bundle already forwarded
    /// to THIS gateway defers `already_handed`; a forward to a
    /// DIFFERENT peer does not.
    #[test]
    fn one_handover_per_bundle_and_gateway() {
        let mut store = DtnStoreImage::new();
        let (manifest, chunks) = fixture(1, 0x71);
        store
            .admit_manifest(&manifest, ServicePriority::Dtn, NOW, EXPIRY, 3)
            .unwrap();
        store.admit_chunk(&manifest.content_id(), 0, &chunks[0], NOW).unwrap();
        // Handed to THIS gateway (its peer ref): the 32-byte node id.
        store
            .note_forwarded(&manifest.content_id(), NOW, &PeerRef::new(&gateway_id(7)).unwrap())
            .unwrap();
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        let contact = contact(&verdict, 1_000_000, 100);
        let forwarder = OpportunisticForwarder::default();
        let ForwardVerdict::Plan(plan) = forwarder.plan(&contact, &store, NOW) else {
            panic!("expected a plan");
        };
        assert!(plan.steps().is_empty());
        assert_eq!(plan.deferred().len(), 1);
        assert_eq!(plan.deferred()[0].reason(), &DeferralReason::AlreadyHanded);
        assert_eq!(plan.deferred()[0].reason().name(), "already_handed");
        // Handed to a DIFFERENT gateway: still a candidate.
        let mut other = DtnStoreImage::new();
        other
            .admit_manifest(&manifest, ServicePriority::Dtn, NOW, EXPIRY, 3)
            .unwrap();
        other.admit_chunk(&manifest.content_id(), 0, &chunks[0], NOW).unwrap();
        other
            .note_forwarded(&manifest.content_id(), NOW, &PeerRef::new(&gateway_id(8)).unwrap())
            .unwrap();
        let ForwardVerdict::Plan(plan2) = forwarder.plan(&contact, &other, NOW) else {
            panic!("expected a plan");
        };
        assert_eq!(plan2.steps().len(), 1);
    }

    /// Partial bundles move whole-as-held: manifest + the present
    /// slots (here 1 of 2), and the missing slot stays the receiving
    /// edge's business (already_held + chunk completion).
    #[test]
    fn partial_bundles_move_as_held() {
        let mut store = DtnStoreImage::new();
        let (manifest, chunks) = fixture(2, 0x81);
        store
            .admit_manifest(&manifest, ServicePriority::Dtn, NOW, EXPIRY, 1)
            .unwrap();
        store.admit_chunk(&manifest.content_id(), 0, &chunks[0], NOW).unwrap();
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        let contact = contact(&verdict, 1_000_000, 100);
        let forwarder = OpportunisticForwarder::default();
        let ForwardVerdict::Plan(plan) = forwarder.plan(&contact, &store, NOW) else {
            panic!("expected a plan");
        };
        assert_eq!(plan.steps().len(), 1);
        let step = &plan.steps()[0];
        assert_eq!(step.slots(), [0]);
        assert_eq!(step.summary().present_chunk_count(), 1);
        assert_eq!(step.summary().chunk_count(), 2);
    }

    /// Determinism (§2): the same (contact, store, clock) plans
    /// byte-equal plans, every time.
    #[test]
    fn planning_is_deterministic() {
        let store = stocked_store();
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        let contact = contact(&verdict, planned_cost(&store, 0) + planned_cost(&store, 2), 2);
        let forwarder = OpportunisticForwarder::default();
        let first = forwarder.plan(&contact, &store, NOW);
        for _ in 0..8 {
            assert_eq!(forwarder.plan(&contact, &store, NOW), first);
        }
    }

    // -- the apply path (file-backed; real stores) ----------------------

    /// The apply path: a real store, a plan, material read back with
    /// re-verification, exactly one Forwarded custody record, and
    /// the replication count incremented.
    #[test]
    #[cfg(not(target_family = "wasm"))]
    fn apply_step_composes_the_store_apis() {
        let dir = std::env::temp_dir().join(format!(
            "sharenet-prop-fwd-apply-{}",
            std::process::id()
        ));
        let (manifest, chunks) = fixture(2, 0x91);
        let mut store = DtnStore::create(&dir).unwrap();
        store
            .admit_manifest(&manifest, ServicePriority::Dtn, NOW, EXPIRY, 2)
            .unwrap();
        for (slot, chunk) in chunks.iter().enumerate() {
            store.admit_chunk(&manifest.content_id(), slot, chunk, NOW).unwrap();
        }
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        let contact = contact(&verdict, 1_000_000, 100);
        let forwarder = OpportunisticForwarder::default();
        let ForwardVerdict::Plan(plan) = forwarder.plan(&contact, store.image(), NOW) else {
            panic!("expected a plan");
        };
        assert_eq!(plan.steps().len(), 1);
        let material = forwarder
            .apply_step(&mut store, &contact, &plan.steps()[0], NOW)
            .unwrap();
        // The material is exactly what the wire would carry.
        assert_eq!(material.content_id(), &manifest.content_id());
        assert_eq!(material.manifest_bytes(), manifest.to_wire_bytes());
        assert_eq!(material.chunks().len(), 2);
        assert_eq!(material.chunks()[0], (0, chunks[0].clone()));
        assert_eq!(material.chunks()[1], (1, chunks[1].clone()));
        assert_eq!(material.byte_len(), plan.steps()[0].byte_cost());
        // Exactly one custody record: forwarded, to the gateway's
        // peer ref, naming the bundle.
        assert_eq!(store.image().evidence_count(), 1);
        let record = &store.image().evidence()[0];
        assert_eq!(record.kind().as_str(), "forwarded");
        assert_eq!(record.peer().as_bytes(), &gateway_id(7));
        assert_eq!(record.content_id(), &manifest.content_id());
        // The replication count moved with it.
        assert_eq!(
            store.image().summary(&manifest.content_id()).unwrap().replication_count(),
            1
        );
        // The re-plan for the SAME gateway defers already_handed
        // (one handover per bundle and gateway — durable now).
        let ForwardVerdict::Plan(plan2) = forwarder.plan(&contact, store.image(), NOW) else {
            panic!("expected a plan");
        };
        assert!(plan2.steps().is_empty());
        assert_eq!(plan2.deferred()[0].reason(), &DeferralReason::AlreadyHanded);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The apply path re-verifies at its own clock: an expired-by-then
    /// bundle, an at-target bundle and a re-applied step all fail
    /// typed, and NOTHING is noted on failure.
    #[test]
    #[cfg(not(target_family = "wasm"))]
    fn apply_step_reverifies_at_its_clock() {
        let dir = std::env::temp_dir().join(format!(
            "sharenet-prop-fwd-clock-{}",
            std::process::id()
        ));
        // A short-lived bundle and an at-target bundle.
        let (short, short_chunks) = fixture(1, 0x92);
        let (done, done_chunks) = fixture(1, 0x93);
        let mut store = DtnStore::create(&dir).unwrap();
        store
            .admit_manifest(&short, ServicePriority::Live, NOW, NOW + 200, 2)
            .unwrap();
        store.admit_chunk(&short.content_id(), 0, &short_chunks[0], NOW).unwrap();
        store
            .admit_manifest(&done, ServicePriority::Dtn, NOW, EXPIRY, 1)
            .unwrap();
        store.admit_chunk(&done.content_id(), 0, &done_chunks[0], NOW).unwrap();
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        // A window that outlives the short bundle's expiry is legal
        // for the CONTACT (the evidence still covers it); the PLAN
        // gates the short bundle by the window-close hard gate, and
        // the APPLY path re-verifies at its own clock below.
        let contact = ContactOpportunity::new(
            gateway_id(7),
            &verdict,
            NOW,
            NOW + 500,
            ContactBudget::new(1_000_000, 100).unwrap(),
        )
        .unwrap();
        let forwarder = OpportunisticForwarder::new(ForwarderParams::new(0));
        let ForwardVerdict::Plan(plan) = forwarder.plan(&contact, store.image(), NOW) else {
            panic!("expected a plan");
        };
        // The short bundle expires at NOW+200 <= close NOW+500 —
        // deferred by the hard gate; only the done bundle plans.
        assert_eq!(plan.steps().len(), 1);
        assert_eq!(plan.steps()[0].content_id(), &done.content_id());
        assert_eq!(
            plan.deferred()[0].reason(),
            &DeferralReason::ExpiresBeforeWindowClose {
                expires_at_unix: NOW + 200,
                closes_at_unix: NOW + 500,
            }
        );
        // Apply it, exhausting its target.
        forwarder
            .apply_step(&mut store, &contact, &plan.steps()[0], NOW)
            .unwrap();
        // Re-apply the SAME step: the bundle is at target (count 1 of
        // 1) AND already handed — the re-verification chain reports
        // the target exhaustion first (the more fundamental fact: the
        // bundle needs no handovers at all). Typed failure, nothing
        // noted.
        let err = forwarder
            .apply_step(&mut store, &contact, &plan.steps()[0], NOW + 1)
            .unwrap_err();
        assert_eq!(err.name(), "candidate_at_target");
        assert_eq!(
            err,
            ForwardError::CandidateAtTarget {
                content_id: done.content_id(),
                count: 1,
                target: 1,
            }
        );
        // A hand-crafted step for the short bundle, applied AFTER
        // its expiry: typed expired (verify-don't-trust, on
        // ourselves — the plan-time liveness is not a license).
        let short_step = HandoverStep {
            summary: store.image().summary(&short.content_id()).unwrap(),
            slots: vec![0],
            byte_cost: 1,
        };
        let err = forwarder
            .apply_step(&mut store, &contact, &short_step, NOW + 300)
            .unwrap_err();
        assert_eq!(err.name(), "candidate_expired");
        assert_eq!(
            err,
            ForwardError::CandidateExpired {
                content_id: short.content_id(),
                expires_at_unix: NOW + 200,
                now_unix: NOW + 300,
            }
        );
        // Failures noted nothing beyond the one legit forward.
        assert_eq!(store.image().evidence_count(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A vanished candidate: after eviction the same planned step
    /// fails typed `candidate_vanished` and nothing is noted.
    #[test]
    #[cfg(not(target_family = "wasm"))]
    fn apply_step_fails_typed_after_eviction() {
        let dir = std::env::temp_dir().join(format!(
            "sharenet-prop-fwd-gone-{}",
            std::process::id()
        ));
        let (manifest, chunks) = fixture(1, 0x94);
        let mut store = DtnStore::create(&dir).unwrap();
        store
            .admit_manifest(&manifest, ServicePriority::Dtn, NOW, NOW + 100, 2)
            .unwrap();
        store.admit_chunk(&manifest.content_id(), 0, &chunks[0], NOW).unwrap();
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        // Plan inside a short window that closes before expiry.
        let contact = ContactOpportunity::new(
            gateway_id(7),
            &verdict,
            NOW,
            NOW + 50,
            ContactBudget::new(1_000_000, 100).unwrap(),
        )
        .unwrap();
        let forwarder = OpportunisticForwarder::new(ForwarderParams::new(0));
        let ForwardVerdict::Plan(plan) = forwarder.plan(&contact, store.image(), NOW) else {
            panic!("expected a plan");
        };
        assert_eq!(plan.steps().len(), 1);
        // The bundle expires and is evicted before the apply.
        store.evict_expired(NOW + 200);
        let err = forwarder
            .apply_step(&mut store, &contact, &plan.steps()[0], NOW)
            .unwrap_err();
        assert_eq!(err.name(), "candidate_vanished");
        assert_eq!(
            err,
            ForwardError::CandidateVanished {
                content_id: manifest.content_id()
            }
        );
        assert_eq!(store.image().evidence_count(), 0, "nothing noted on failure");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// apply_plan applies independently per step: successes and
    /// typed failures collected in plan order.
    #[test]
    #[cfg(not(target_family = "wasm"))]
    fn apply_plan_collects_per_step_outcomes() {
        let dir = std::env::temp_dir().join(format!(
            "sharenet-prop-fwd-plan-{}",
            std::process::id()
        ));
        let mut store = DtnStore::create(&dir).unwrap();
        // Two bundles; plan both, apply twice — the second apply_plan
        // fails both steps (already handed / at target).
        let (a, a_chunks) = fixture(1, 0x95);
        let (b, b_chunks) = fixture(1, 0x96);
        for (manifest, chunks) in [(&a, &a_chunks), (&b, &b_chunks)] {
            store
                .admit_manifest(manifest, ServicePriority::Dtn, NOW, EXPIRY, 2)
                .unwrap();
            store.admit_chunk(&manifest.content_id(), 0, &chunks[0], NOW).unwrap();
        }
        let verdict = eligible(gateway_id(7), NOW + 1_000);
        let contact = contact(&verdict, 1_000_000, 100);
        let forwarder = OpportunisticForwarder::default();
        let ForwardVerdict::Plan(plan) = forwarder.plan(&contact, store.image(), NOW) else {
            panic!("expected a plan");
        };
        assert_eq!(plan.steps().len(), 2);
        let application = forwarder.apply_plan(&mut store, &contact, &plan, NOW);
        assert_eq!(application.applied().len(), 2);
        assert!(application.failed().is_empty());
        assert_eq!(application.applied_bytes(), plan.planned_bytes());
        assert!(!application.is_empty());
        // Second application of the same plan: both steps fail typed.
        let replay = forwarder.apply_plan(&mut store, &contact, &plan, NOW + 1);
        assert!(replay.applied().is_empty());
        assert_eq!(replay.failed().len(), 2);
        assert_eq!(replay.failed()[0].1.name(), "already_handed");
        assert_eq!(replay.failed()[1].1.name(), "already_handed");
        assert_eq!(
            store.image().evidence_count(),
            2,
            "exactly one forward per bundle was ever noted"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The refusal/deferral vocabularies are pinned distinct.
    #[test]
    fn deferral_names_are_distinct() {
        let all = [
            DeferralReason::ExpiresBeforeWindowClose {
                expires_at_unix: 1,
                closes_at_unix: 2,
            },
            DeferralReason::RemainingLifeBelowFloorAtClose {
                remaining_secs: 1,
                minimum_secs: 2,
            },
            DeferralReason::AlreadyHanded,
            DeferralReason::DoesNotFitBudget {
                byte_cost: 1,
                remaining_bytes: 0,
            },
            DeferralReason::CountBoundReached { max_bundles: 1 },
        ];
        let names: Vec<&str> = all.iter().map(|r| r.name()).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), all.len(), "names collide: {names:?}");
        let error_all = [
            ForwardError::CandidateVanished { content_id: [0; 32] },
            ForwardError::CandidateExpired {
                content_id: [0; 32],
                expires_at_unix: 1,
                now_unix: 2,
            },
            ForwardError::CandidateDelivered { content_id: [0; 32] },
            ForwardError::CandidateAtTarget {
                content_id: [0; 32],
                count: 2,
                target: 1,
            },
            ForwardError::AlreadyHanded { content_id: [0; 32] },
            ForwardError::SlotVanished {
                content_id: [0; 32],
                slot: 0,
            },
            ForwardError::Store {
                name: "store_io".into(),
            },
        ];
        let error_names: Vec<&str> = error_all.iter().map(|e| e.name()).collect();
        let mut sorted = error_names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), error_all.len());
        for error in &error_all {
            assert!(!error.to_string().is_empty());
        }
    }

    /// The forwarder's default floor equals the receiving edge's
    /// default floor — the two ends of a handover agree by default.
    #[test]
    fn both_edges_share_the_default_floor() {
        assert_eq!(
            DEFAULT_MIN_REMAINING_TTL_AT_CLOSE_SECS,
            crate::DEFAULT_MIN_REMAINING_TTL_SECS
        );
        assert_eq!(ForwarderParams::default().min_remaining_ttl_at_close_secs(), 60);
    }

    /// A contact that cannot be constructed (ineligible gateway) can
    /// never reach the forwarder — pinned here at the seam: the
    /// contact constructor's failure names are the forwarder's
    /// outermost gate.
    #[test]
    fn ineligible_contact_never_reaches_the_forwarder() {
        let verdict = GatewayAdmission::Ineligible {
            reasons: vec![AdmissionReason::ShareNetEvidenceMissing],
        };
        let err = ContactOpportunity::new(
            gateway_id(7),
            &verdict,
            NOW,
            NOW + 100,
            ContactBudget::new(1_000, 1).unwrap(),
        )
        .unwrap_err();
        assert_eq!(err.name(), "gateway_not_admitted");
        assert_eq!(
            err,
            ContactError::GatewayNotAdmitted {
                reasons: vec!["sharenet_evidence_missing"]
            }
        );
    }

    /// The i-th stocked bundle's exact planned byte cost (helper).
    fn planned_cost(store: &DtnStoreImage, i: usize) -> u64 {
        let candidates = store.forward_candidates(NOW);
        let id = candidates[i].content_id();
        let manifest_bytes = store.manifest_bytes(id).unwrap();
        let manifest = store.manifest(id).unwrap();
        manifest_bytes.len() as u64
            + store
                .present_slots(id)
                .unwrap()
                .iter()
                .map(|s| manifest.expected_chunk_len(*s as usize).unwrap())
                .sum::<u64>()
    }
}
