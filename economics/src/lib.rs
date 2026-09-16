//! ShareNet useful-work valuation — work item R8-002.
//!
//! `spec/architecture.md` §13: *"Civic Points are earned only from
//! verified useful work... A contribution is not valid merely because a
//! node reports it. Evidence requires authenticated participants and
//! durable replay-safe receipts... The economic formula is versioned and
//! explicit."*
//!
//! THIS crate is that formula and nothing else. Its input contract is
//! the R8-001 [`ContributionReceipt`] — the bilateral recipient-signed
//! acknowledgement whose signature, parse, self-receipt exclusion,
//! per-pair monotonic sequence and issued_at clock bounds were already
//! enforced by the [`sharenet_protocol::contribution::ReceiptLedger`]'s
//! admission (the valuation layer NEVER re-verifies signatures and
//! NEVER trusts caller-supplied identity: the issuer, contributor,
//! kind, byte count and receipt_id are re-derived from the receipt's
//! own parsed fields).
//!
//! # The formula (v1, explicit)
//!
//! ```text
//! billable(receipt)     = min(receipt.delivered_bytes, PER_RECEIPT_BYTE_CAP)
//! intrinsic(receipt)    = kind_weight_bp(receipt.kind) * billable(receipt) / 10_000
//! award(receipt)        = min(intrinsic,
//!                             pair_cap_remaining(issuer, contributor, window),
//!                             contributor_cap_remaining(contributor, window))
//! window(receipt)       = receipt.issued_at_unix / window_secs
//! ```
//!
//! `kind_weight_bp`: carried = 10_000 basis points (1.0×), delivered =
//! 15_000 basis points (1.5×) — terminal delivery is worth more than
//! intermediate custody, and integer division truncates (deterministic,
//! no floats anywhere).
//!
//! # The anti-gaming minimums this layer owns (§14)
//!
//! - **per-counterparty and per-time-window caps** — the
//!   `(issuer, contributor)` pair is capped per window AND the
//!   contributor is capped ACROSS ALL ISSUERS per window (the Sybil
//!   bound: k colluding issuers cannot amplify one contributor past the
//!   contributor cap; a circular pair of two acknowledging nodes cannot
//!   pass the pair cap);
//! - **contribution-quality weighting** — the frozen kind weights;
//! - **content/packet identity + duplicate receipts + replayed
//!   deliveries** — already impossible below this layer (the receipt's
//!   content_id, receipt_id idempotency and the per-pair sequence law);
//!   the engine keeps its own receipt_id idempotency anyway (defense in
//!   depth, first valuation wins).
//!
//! Anomaly DETECTION, Sybil IDENTIFICATION and audit trails are
//! R8-005's; durable storage is R8-003's (this engine is in-memory
//! policy); consuming points for perks is R8-004's.
//!
//! # The laws
//!
//! 1. **Versioned and explicit.** [`VALUATION_FORMULA_VERSION`] = 1;
//!    every verdict names the arithmetic that produced it.
//! 2. **Pure and caller-clocked.** No I/O, no wall clock, no unsafe;
//!    the caller supplies `now` and drives receipts in ledger order.
//! 3. **Caps bind awards, never evidence.** A capped receipt is still
//!    VALID evidence — the verdict reports the awarded points and the
//!    binding cap; nothing is deleted or refused (the receipt laws
//!    below this layer stay intact).
//! 4. **Defense in depth.** A future-dated receipt is refused typed
//!    here too (the ledger already refused it at admit time); a
//!    re-delivered receipt_id is a `Duplicate` (zero points moved).
//! 5. **Deterministic integer math.** Truncating division, saturating
//!    nowhere (bounds are validated so products cannot overflow),
//!    identical inputs → identical verdicts.

// `deny` (not `forbid`): the file-backed ledger contains exactly ONE
// unsafe block — an audited libc::fsync(2) on our own descriptor (the
// appliance-journal durability discipline), locally allowed with its
// SAFETY note. The valuation engine, the pure ledger and the simulation
// remain unsafe-free and wasm32-clean.
#![deny(unsafe_code)]

pub mod antigaming;
pub mod consumption;
pub mod ledger;
pub mod sim;

use std::collections::HashMap;
use std::fmt;

use sharenet_protocol::contribution::{ContributionKind, ContributionReceipt};
use sharenet_protocol::identity::NodeId;

/// The versioned economic formula (architecture §13: "The economic
/// formula is versioned and explicit"). A change to ANY constant or
/// rule in this crate is a new version.
pub const VALUATION_FORMULA_VERSION: u32 = 1;

/// The fixed-point denominator: 10_000 basis points = 1.0×.
pub const BP_DENOMINATOR: u64 = 10_000;
/// Kind weight — carried (custody handover): 1.0×.
pub const CARRIED_WEIGHT_BP: u64 = 10_000;
/// Kind weight — delivered (terminal consumption): 1.5×.
pub const DELIVERED_WEIGHT_BP: u64 = 15_000;

/// Default window length (one hour).
pub const DEFAULT_WINDOW_SECS: u64 = 3_600;
/// Default per-receipt billable byte base: 1 MiB (a single receipt can
/// inflate its byte count no further than this — the schema-level
/// bound; full manifest-binding remains the receipt layer's optional
/// check).
pub const DEFAULT_PER_RECEIPT_BYTE_CAP: u64 = 1 << 20;
/// Default per-(issuer, contributor)-pair, per-window point cap.
pub const DEFAULT_PER_PAIR_WINDOW_POINTS: u64 = 10_000_000;
/// Default per-contributor, per-window point cap ACROSS ALL ISSUERS
/// (the Sybil-multiplication bound; 5× the pair cap by default — a
/// policy knob, not a law).
pub const DEFAULT_PER_CONTRIBUTOR_WINDOW_POINTS: u64 = 50_000_000;

/// The receipt-level `delivered_bytes` maximum (2^40, the registry law).
pub const RECEIPT_BYTES_MAX: u64 = 1 << 40;

// ---------------------------------------------------------------------------
// Errors (typed, machine-named)
// ---------------------------------------------------------------------------

/// A policy-construction or valuation refusal (typed, fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValuationError {
    WindowZero,
    ByteCapOutOfRange { found: u64 },
    PairCapZero,
    ContributorCapZero,
    /// Defense in depth: the receipt is dated after the caller's clock.
    /// The R8-001 ledger already refuses these at admit time; a valuation
    /// pass fed outside the ledger contract gets the same refusal here.
    IssuedAtInFuture { issued_at: u64, now: u64 },
}

impl fmt::Display for ValuationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValuationError::WindowZero => {
                write!(f, "window_secs must be at least 1")
            }
            ValuationError::ByteCapOutOfRange { found } => write!(
                f,
                "per-receipt byte cap must be 1..={RECEIPT_BYTES_MAX}, found {found}"
            ),
            ValuationError::PairCapZero => {
                write!(f, "per-pair window points cap must be at least 1")
            }
            ValuationError::ContributorCapZero => {
                write!(f, "per-contributor window points cap must be at least 1")
            }
            ValuationError::IssuedAtInFuture { issued_at, now } => write!(
                f,
                "receipt issued_at {issued_at} is after the caller clock {now}"
            ),
        }
    }
}

impl std::error::Error for ValuationError {}

impl ValuationError {
    /// Stable machine name.
    pub fn name(&self) -> &'static str {
        match self {
            ValuationError::WindowZero => "window_zero",
            ValuationError::ByteCapOutOfRange { .. } => "byte_cap_out_of_range",
            ValuationError::PairCapZero => "pair_cap_zero",
            ValuationError::ContributorCapZero => "contributor_cap_zero",
            ValuationError::IssuedAtInFuture { .. } => "issued_at_in_future",
        }
    }
}

// ---------------------------------------------------------------------------
// Policy (validated bounds — the v1 knobs)
// ---------------------------------------------------------------------------

/// The valuation policy: every bound validated at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValuationPolicy {
    window_secs: u64,
    per_receipt_byte_cap: u64,
    per_pair_window_points: u64,
    per_contributor_window_points: u64,
}

impl Default for ValuationPolicy {
    fn default() -> Self {
        Self {
            window_secs: DEFAULT_WINDOW_SECS,
            per_receipt_byte_cap: DEFAULT_PER_RECEIPT_BYTE_CAP,
            per_pair_window_points: DEFAULT_PER_PAIR_WINDOW_POINTS,
            per_contributor_window_points: DEFAULT_PER_CONTRIBUTOR_WINDOW_POINTS,
        }
    }
}

impl ValuationPolicy {
    /// Validate the bounds (fail-closed, typed).
    pub fn new(
        window_secs: u64,
        per_receipt_byte_cap: u64,
        per_pair_window_points: u64,
        per_contributor_window_points: u64,
    ) -> Result<Self, ValuationError> {
        if window_secs == 0 {
            return Err(ValuationError::WindowZero);
        }
        if per_receipt_byte_cap == 0 || per_receipt_byte_cap > RECEIPT_BYTES_MAX {
            return Err(ValuationError::ByteCapOutOfRange {
                found: per_receipt_byte_cap,
            });
        }
        if per_pair_window_points == 0 {
            return Err(ValuationError::PairCapZero);
        }
        if per_contributor_window_points == 0 {
            return Err(ValuationError::ContributorCapZero);
        }
        Ok(Self {
            window_secs,
            per_receipt_byte_cap,
            per_pair_window_points,
            per_contributor_window_points,
        })
    }

    pub fn window_secs(&self) -> u64 {
        self.window_secs
    }
    pub fn per_receipt_byte_cap(&self) -> u64 {
        self.per_receipt_byte_cap
    }
    pub fn per_pair_window_points(&self) -> u64 {
        self.per_pair_window_points
    }
    pub fn per_contributor_window_points(&self) -> u64 {
        self.per_contributor_window_points
    }

    /// The window index of a timestamp (the bucket law).
    pub fn window_of(&self, issued_at_unix: u64) -> u64 {
        issued_at_unix / self.window_secs
    }

    /// The intrinsic (uncapped) points of one receipt — the formula's
    /// first half. Public so the simulation and tests can pin the
    /// arithmetic independently of cap state.
    pub fn intrinsic_points(&self, kind: ContributionKind, delivered_bytes: u64) -> u64 {
        let billable = delivered_bytes.min(self.per_receipt_byte_cap);
        let weight_bp = match kind {
            ContributionKind::Carried => CARRIED_WEIGHT_BP,
            ContributionKind::Delivered => DELIVERED_WEIGHT_BP,
        };
        weight_bp * billable / BP_DENOMINATOR
    }
}

// ---------------------------------------------------------------------------
// The verdict
// ---------------------------------------------------------------------------

/// Which cap bound an award (the report, never a refusal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapKind {
    /// The per-(issuer, contributor)-pair window cap.
    PairWindow,
    /// The per-contributor-across-all-issuers window cap.
    ContributorWindow,
}

impl CapKind {
    /// Stable machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            CapKind::PairWindow => "pair_window",
            CapKind::ContributorWindow => "contributor_window",
        }
    }
}

/// One valued receipt: the explicit arithmetic report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Award {
    /// The uncapped formula value (`weight_bp × billable / 10_000`).
    pub intrinsic_points: u64,
    /// What was actually awarded after the caps.
    pub awarded_points: u64,
    /// The binding cap, when `awarded < intrinsic`.
    pub bound_by: Option<CapKind>,
    /// The billable byte base after the per-receipt cap.
    pub billable_bytes: u64,
    /// The receipt's window index (`issued_at / window_secs`).
    pub window: u64,
}

/// The typed outcome of valuing one receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValuationVerdict {
    /// Valued (possibly for zero points when the caps were already
    /// exhausted — still an `Awarded`, never a refusal: capped receipts
    /// are valid evidence the formula declines to pay for again).
    Awarded(Award),
    /// The receipt_id was already valued — idempotent, nothing moved.
    Duplicate { receipt_id: [u8; 32] },
    /// `issued_at` is after the caller's clock (defense in depth; the
    /// ledger already refuses these at admit time).
    Refused(ValuationError),
}

impl ValuationVerdict {
    /// Stable machine name (tests + the simulation report).
    pub fn name(&self) -> &'static str {
        match self {
            ValuationVerdict::Awarded(_) => "awarded",
            ValuationVerdict::Duplicate { .. } => "duplicate",
            ValuationVerdict::Refused(_) => "refused",
        }
    }

    /// The awarded points (0 for duplicates/refusals).
    pub fn points(&self) -> u64 {
        match self {
            ValuationVerdict::Awarded(a) => a.awarded_points,
            _ => 0,
        }
    }
}

// ---------------------------------------------------------------------------
// The engine (the aggregating in-memory state; durability is R8-003)
// ---------------------------------------------------------------------------

/// The valuation engine: consumes verified receipts in (ledger) order,
/// applies the formula and the window caps, keeps the running totals.
///
/// Order-sensitive BY DESIGN (caps are consumed in valuation order);
/// the daemon values receipts in the order the R8-001 ledger admitted
/// them, which is deterministic per node.
#[derive(Debug, Default)]
pub struct ValuationEngine {
    policy: ValuationPolicy,
    /// Idempotency: the receipt_ids already valued (first wins).
    valued: std::collections::HashSet<[u8; 32]>,
    /// (issuer node_id, contributor node_id, window) → awarded points.
    pair_windows: HashMap<([u8; 32], [u8; 32], u64), u64>,
    /// (contributor node_id, window) → awarded points.
    contributor_windows: HashMap<([u8; 32], u64), u64>,
    receipts_valued: u64,
    receipts_capped: u64,
    total_points: u64,
}

impl ValuationEngine {
    /// Engine with the default policy.
    pub fn new() -> Self {
        Self::with_policy(ValuationPolicy::default())
    }

    /// Engine with an explicit (validated) policy.
    pub fn with_policy(policy: ValuationPolicy) -> Self {
        Self {
            policy,
            ..Self::default()
        }
    }

    pub fn policy(&self) -> &ValuationPolicy {
        &self.policy
    }

    /// Value one verified receipt at the caller's clock.
    ///
    /// The receipt's issuer/contributor/kind/bytes/receipt_id are
    /// re-derived from the receipt itself — never caller-supplied.
    pub fn value(&mut self, receipt: &ContributionReceipt, now_unix: u64) -> ValuationVerdict {
        let issued_at = receipt.issued_at_unix();
        if issued_at > now_unix {
            return ValuationVerdict::Refused(ValuationError::IssuedAtInFuture {
                issued_at,
                now: now_unix,
            });
        }
        let receipt_id = receipt.receipt_id();
        if !self.valued.insert(receipt_id) {
            return ValuationVerdict::Duplicate { receipt_id };
        }
        let window = self.policy.window_of(issued_at);
        let intrinsic = self
            .policy
            .intrinsic_points(receipt.kind(), receipt.delivered_bytes());
        let billable = receipt
            .delivered_bytes()
            .min(self.policy.per_receipt_byte_cap());
        let issuer: [u8; 32] = *receipt.issuer_node_id().as_bytes();
        let contributor: [u8; 32] = *receipt.contributor_node_id();
        let pair_key = (issuer, contributor, window);
        let contributor_key = (contributor, window);
        let pair_spent = *self.pair_windows.get(&pair_key).unwrap_or(&0);
        let contributor_spent = *self.contributor_windows.get(&contributor_key).unwrap_or(&0);
        let pair_remaining = self.policy.per_pair_window_points.saturating_sub(pair_spent);
        let contributor_remaining = self
            .policy
            .per_contributor_window_points
            .saturating_sub(contributor_spent);
        let awarded = intrinsic.min(pair_remaining).min(contributor_remaining);
        // The binding cap report: whichever remaining bound was the
        // smallest (the pair bound wins ties — the tighter, earlier
        // report; a tie is both caps binding at the same instant).
        let bound_by = if awarded < intrinsic {
            if pair_remaining <= contributor_remaining {
                Some(CapKind::PairWindow)
            } else {
                Some(CapKind::ContributorWindow)
            }
        } else {
            None
        };
        if awarded > 0 {
            *self.pair_windows.entry(pair_key).or_insert(0) += awarded;
            *self.contributor_windows.entry(contributor_key).or_insert(0) += awarded;
            self.total_points += awarded;
        }
        if bound_by.is_some() {
            self.receipts_capped += 1;
        }
        self.receipts_valued += 1;
        ValuationVerdict::Awarded(Award {
            intrinsic_points: intrinsic,
            awarded_points: awarded,
            bound_by,
            billable_bytes: billable,
            window,
        })
    }

    /// The points already awarded to one (issuer, contributor) pair in
    /// one window.
    pub fn pair_window_points(
        &self,
        issuer: &NodeId,
        contributor: &[u8; 32],
        window: u64,
    ) -> u64 {
        *self
            .pair_windows
            .get(&(*issuer.as_bytes(), *contributor, window))
            .unwrap_or(&0)
    }

    /// The points already awarded to one contributor across ALL issuers
    /// in one window.
    pub fn contributor_window_points(&self, contributor: &[u8; 32], window: u64) -> u64 {
        *self
            .contributor_windows
            .get(&(*contributor, window))
            .unwrap_or(&0)
    }

    /// Total distinct receipts valued (awarded + capped + duplicates do
    /// NOT count here — only receipts that produced an `Awarded`).
    pub fn receipts_valued(&self) -> u64 {
        self.receipts_valued
    }

    /// How many receipts were bound by a cap.
    pub fn receipts_capped(&self) -> u64 {
        self.receipts_capped
    }

    /// The total points awarded across all windows.
    pub fn total_points(&self) -> u64 {
        self.total_points
    }

    /// Reconstruct the engine's durable-relevant state from a log
    /// replay (R8-003's restart law: a restart must NOT reset the
    /// window caps or the receipt idempotency). `valued` are the
    /// receipt_ids already valued (the award log's ids); the window
    /// maps are the per-pair / per-contributor awarded totals per
    /// window. Zero-award receipts are absent from award logs by
    /// design — they only exist when caps were exhausted, so their
    /// absence cannot change the reconstructed totals (a re-valuation
    /// after reload awards 0 again).
    pub fn restore(
        policy: ValuationPolicy,
        valued: std::collections::HashSet<[u8; 32]>,
        pair_windows: HashMap<([u8; 32], [u8; 32], u64), u64>,
        contributor_windows: HashMap<([u8; 32], u64), u64>,
    ) -> Self {
        let receipts_valued = valued.len() as u64;
        let total_points: u64 = contributor_windows.values().sum();
        Self {
            policy,
            valued,
            pair_windows,
            contributor_windows,
            receipts_valued,
            receipts_capped: 0,
            total_points,
        }
    }

    /// The valued receipt_ids (a read view for durable-layer restores).
    pub fn valued_ids(&self) -> std::collections::HashSet<[u8; 32]> {
        self.valued.clone()
    }
}

// ---------------------------------------------------------------------------
// Unit tests (the formula arithmetic + the policy validation; the
// adversarial suite is tests/adversarial.rs, the simulation tests/sim.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use sharenet_protocol::identity::Identity;

    const NOW: u64 = 1_700_000_000;

    fn id(seed: u8) -> Identity {
        Identity::from_seed([seed; 32], NOW, None).expect("identity")
    }

    fn receipt(
        issuer: &Identity,
        contributor: &[u8; 32],
        kind: ContributionKind,
        bytes: u64,
        seq: u64,
        issued_at: u64,
    ) -> ContributionReceipt {
        ContributionReceipt::new(issuer, *contributor, [0xAB; 32], kind, bytes, seq, issued_at)
            .expect("receipt builds")
    }

    #[test]
    fn policy_validation_is_fail_closed_typed() {
        assert_eq!(
            ValuationPolicy::new(0, 1 << 20, 1, 1).unwrap_err().name(),
            "window_zero"
        );
        assert_eq!(
            ValuationPolicy::new(60, 0, 1, 1).unwrap_err().name(),
            "byte_cap_out_of_range"
        );
        assert_eq!(
            ValuationPolicy::new(60, (1 << 40) + 1, 1, 1).unwrap_err().name(),
            "byte_cap_out_of_range"
        );
        assert_eq!(
            ValuationPolicy::new(60, 1 << 20, 0, 1).unwrap_err().name(),
            "pair_cap_zero"
        );
        assert_eq!(
            ValuationPolicy::new(60, 1 << 20, 1, 0).unwrap_err().name(),
            "contributor_cap_zero"
        );
        ValuationPolicy::new(60, 1 << 40, 1, 1).expect("upper byte-cap edge is legal");
    }

    #[test]
    fn intrinsic_arithmetic_is_explicit_and_truncating() {
        let p = ValuationPolicy::default();
        // carried: 1.0x, byte-for-byte
        assert_eq!(p.intrinsic_points(ContributionKind::Carried, 1_000), 1_000);
        assert_eq!(p.intrinsic_points(ContributionKind::Carried, 0), 0);
        // delivered: 1.5x, truncating (3 bytes -> 4.5 -> 4)
        assert_eq!(p.intrinsic_points(ContributionKind::Delivered, 1_000), 1_500);
        assert_eq!(p.intrinsic_points(ContributionKind::Delivered, 3), 4);
        // the per-receipt byte cap binds the base
        let huge = p.intrinsic_points(ContributionKind::Carried, u32::MAX as u64);
        assert_eq!(huge, DEFAULT_PER_RECEIPT_BYTE_CAP);
    }

    #[test]
    fn windows_bucket_by_issuance_clock() {
        let p = ValuationPolicy::new(100, 1024, 10, 10).expect("policy");
        assert_eq!(p.window_of(0), 0);
        assert_eq!(p.window_of(99), 0);
        assert_eq!(p.window_of(100), 1);
        assert_eq!(p.window_of(199), 1);
        assert_eq!(p.window_of(200), 2);
    }

    #[test]
    fn honest_receipts_accrue_and_report() {
        let issuer = id(0x11);
        let contributor = [0x22; 32];
        let mut engine = ValuationEngine::new();
        let v = engine.value(
            &receipt(&issuer, &contributor, ContributionKind::Delivered, 1_000, 1, NOW),
            NOW + 10,
        );
        let ValuationVerdict::Awarded(a) = v else {
            panic!("honest receipt must be awarded, got {v:?}")
        };
        assert_eq!(a.intrinsic_points, 1_500);
        assert_eq!(a.awarded_points, 1_500);
        assert_eq!(a.bound_by, None);
        assert_eq!(a.billable_bytes, 1_000);
        assert_eq!(engine.total_points(), 1_500);
        assert_eq!(engine.receipts_valued(), 1);
        assert_eq!(engine.receipts_capped(), 0);
    }

    #[test]
    fn duplicate_receipts_are_idempotent_zero() {
        let issuer = id(0x11);
        let contributor = [0x22; 32];
        let mut engine = ValuationEngine::new();
        let r = receipt(&issuer, &contributor, ContributionKind::Carried, 10, 1, NOW);
        assert!(matches!(
            engine.value(&r, NOW + 10),
            ValuationVerdict::Awarded(_)
        ));
        // a DIFFERENT named object at the same content (re-built byte
        // identical) is the same receipt_id: the valuation idempotency
        let again = receipt(&issuer, &contributor, ContributionKind::Carried, 10, 1, NOW);
        assert!(matches!(
            engine.value(&again, NOW + 10),
            ValuationVerdict::Duplicate { .. }
        ));
        assert_eq!(engine.total_points(), 10);
        assert_eq!(engine.receipts_valued(), 1);
    }

    #[test]
    fn future_dated_receipts_are_refused_typed_here_too() {
        let issuer = id(0x11);
        let contributor = [0x22; 32];
        let mut engine = ValuationEngine::new();
        let r = receipt(&issuer, &contributor, ContributionKind::Carried, 10, 1, NOW + 500);
        match engine.value(&r, NOW) {
            ValuationVerdict::Refused(e) => {
                assert_eq!(e.name(), "issued_at_in_future");
            }
            other => panic!("future receipt must be refused, got {other:?}"),
        }
        assert_eq!(engine.total_points(), 0);
        // the SAME receipt at a later clock values normally (the ledger
        // admitted it then; the refusal moved nothing)
        assert!(matches!(
            engine.value(&r, NOW + 600),
            ValuationVerdict::Awarded(_)
        ));
    }

    #[test]
    fn pair_cap_exhausts_with_partial_award_and_bound_report() {
        let issuer = id(0x11);
        let contributor = [0x22; 32];
        let policy =
            ValuationPolicy::new(3_600, 1 << 20, 1_000, 1_000_000).expect("policy");
        let mut engine = ValuationEngine::with_policy(policy);
        // intrinsic 900 < cap 1000
        let a = engine.value(
            &receipt(&issuer, &contributor, ContributionKind::Carried, 900, 1, NOW),
            NOW,
        );
        assert_eq!(a.points(), 900);
        // intrinsic 400, remaining 100: awarded 100, bound by the pair cap
        let b = engine.value(
            &receipt(&issuer, &contributor, ContributionKind::Carried, 400, 2, NOW),
            NOW,
        );
        match &b {
            ValuationVerdict::Awarded(a) => {
                assert_eq!(a.intrinsic_points, 400);
                assert_eq!(a.awarded_points, 100);
                assert_eq!(a.bound_by, Some(CapKind::PairWindow));
            }
            other => panic!("capped receipt is still Awarded, got {other:?}"),
        }
        // exhausted: zero-point awards, still Awarded, never refused
        let c = engine.value(
            &receipt(&issuer, &contributor, ContributionKind::Delivered, 50, 3, NOW),
            NOW,
        );
        match &c {
            ValuationVerdict::Awarded(a) => {
                assert_eq!(a.awarded_points, 0);
                assert_eq!(a.bound_by, Some(CapKind::PairWindow));
            }
            other => panic!("exhausted receipt is a zero Awarded, got {other:?}"),
        }
        assert_eq!(engine.total_points(), 1_000);
        assert_eq!(engine.receipts_capped(), 2);
        // a fresh window pays again (the caps are per-window)
        let d = engine.value(
            &receipt(
                &issuer,
                &contributor,
                ContributionKind::Carried,
                10,
                4,
                NOW + 3_600,
            ),
            NOW + 3_600,
        );
        assert_eq!(d.points(), 10);
        assert_eq!(engine.total_points(), 1_010);
    }

    #[test]
    fn contributor_cap_binds_across_issuers_the_sybil_bound() {
        let issuer_a = id(0x11);
        let issuer_b = id(0x33);
        let issuer_c = id(0x44);
        let contributor = [0x22; 32];
        let policy =
            ValuationPolicy::new(3_600, 1 << 20, 100, 250).expect("policy");
        let mut engine = ValuationEngine::with_policy(policy);
        // three distinct issuers acknowledging the same contributor in
        // one window: the pair caps would allow 3 x 100 = 300, the
        // contributor cap stops at 250
        for (i, issuer) in [&issuer_a, &issuer_b, &issuer_c].iter().enumerate() {
            let v = engine.value(
                &receipt(issuer, &contributor, ContributionKind::Carried, 100, 1, NOW + i as u64),
                NOW + 10,
            );
            match &v {
                ValuationVerdict::Awarded(a) => {
                    if i < 2 {
                        assert_eq!(a.awarded_points, 100, "issuer {i} pays in full");
                        assert_eq!(a.bound_by, None);
                    } else {
                        assert_eq!(a.awarded_points, 50, "the contributor cap binds");
                        assert_eq!(a.bound_by, Some(CapKind::ContributorWindow));
                    }
                }
                other => panic!("issuer {i} must be Awarded, got {other:?}"),
            }
        }
        assert_eq!(
            engine.contributor_window_points(&contributor, engine.policy().window_of(NOW)),
            250
        );
        // every pair total is within its own cap too
        for issuer in [&issuer_a, &issuer_b, &issuer_c] {
            assert!(engine.pair_window_points(
                &issuer.node_id(),
                &contributor,
                engine.policy().window_of(NOW)
            ) <= 100);
        }
        assert_eq!(engine.total_points(), 250);
    }

    #[test]
    fn read_views_and_counters_agree() {
        let issuer = id(0x11);
        let contributor = [0x22; 32];
        let mut engine = ValuationEngine::new();
        for seq in 1..=3u64 {
            engine.value(
                &receipt(
                    &issuer,
                    &contributor,
                    ContributionKind::Carried,
                    100 * seq,
                    seq,
                    NOW,
                ),
                NOW,
            );
        }
        assert_eq!(engine.receipts_valued(), 3);
        assert_eq!(engine.total_points(), 100 + 200 + 300);
        let w = engine.policy().window_of(NOW);
        assert_eq!(
            engine.pair_window_points(&issuer.node_id(), &contributor, w),
            600
        );
        assert_eq!(engine.contributor_window_points(&contributor, w), 600);
        // another window: zero
        assert_eq!(
            engine.pair_window_points(&issuer.node_id(), &contributor, w + 1),
            0
        );
    }
}
