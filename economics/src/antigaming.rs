//! Anti-gaming anomaly detection and audit — work item R8-005.
//!
//! `spec/architecture.md` §14: the economics subsystem MUST prevent
//! circular traffic created solely to farm points and Sybil
//! multiplication of contribution, and MUST at minimum enforce — among
//! the receipts-layer and valuation-layer laws — **anomaly
//! detection**. Waves 17–20 delivered the BOUNDS (the R8-002 caps:
//! per-pair, per-contributor-across-issuers, per-receipt; the R8-003
//! restart law; the R8-004 exactly-once spend law). This module is
//! the layer that CATCHES: the §14 text places the bound and the
//! catch side by side, and the caps alone only ever hold the damage
//! down — they say nothing about WHO was trying.
//!
//! # What this module is
//!
//! A PURE, DETERMINISTIC audit pass over the ledger's own durable
//! records. It takes the `LedgerEntry` awards (and the `SpendEntry`
//! consumption records when available), re-derives every total from
//! the entries' own fields — never caller-supplied identity — and
//! emits an [`AuditReport`]: the registered `AntigamingAuditReport`
//! durable-state record. The same inputs MUST produce a byte-identical
//! report (the determinism law is the audit's own integrity: a report
//! that varied run to run could not be evidence of anything).
//!
//! # The v1 ruleset (frozen; thresholds are policy knobs, rules are law)
//!
//! Integrity (the ledger re-derivation — catches tampering and
//! version drift, not gaming):
//! 1. `ledger_invariant_violation` (HIGH): a per-(issuer,
//!    contributor, window) award total above the pair cap, a
//!    per-(contributor, window) total above the contributor cap, or a
//!    zero/negative award — records the ledger engine could not have
//!    appended (a tampered or foreign file).
//! 2. `unknown_formula_version` (HIGH): an entry priced by a formula
//!    version this node does not know (a version bump is a new
//!    pricing law; old entries never re-price, and unknown ones are
//!    flagged, not guessed at).
//! 3. `clock_regression` (LOW): the append clock moved backwards —
//!    an operational smell, not an attack class.
//! 4. `spend_invariant_violation` (HIGH): a derived negative balance,
//!    a zero-point spend, or a duplicate spend_id (the exactly-once
//!    law re-checked from the outside).
//!
//! Anomaly (the gaming patterns — every one a pattern the caps BOUND
//! but could not NAME):
//! 5. `cap_saturation_pair` (MEDIUM): one pair's per-window award
//!    total at ≥ the saturation ratio of the pair cap for ≥ N
//!    CONSECUTIVE windows. Legitimate pairs can have a heavy hour; a
//!    streak of them is farming.
//! 6. `cap_saturation_contributor` (HIGH): the same across ALL of a
//!    contributor's issuers — the k-issuer Sybil shape: no single
//!    pair looks guilty, but the contributor saturates the cap that
//!    exists precisely to bound Sybil multiplication.
//! 7. `reciprocal_ring` (HIGH): a strongly-connected component of ≥ 2
//!    nodes in the issuer→contributor award graph (Tarjan, iterated
//!    in sorted-node order for determinism) — circular traffic
//!    created solely to farm points, the exact §14 phrase. Two nodes
//!    acknowledging each other is the size-2 case.
//! 8. `repeated_identical_magnitude` (MEDIUM): the SAME intrinsic
//!    point value from one pair ≥ N times — real traffic varies;
//!    scripted acknowledgements repeat.
//! 9. `velocity_beyond_cap` (MEDIUM): the pre-cap intrinsic total
//!    EXCEEDED the awarded total for ≥ N CONSECUTIVE windows — the
//!    caps bounded the attempt, but `intrinsic_points` (the honest
//!    record of what the formula priced before the caps bound it —
//!    R8-003's field exists for exactly this) shows the contributor
//!    pushing past the policy window after window. Fully-capped
//!    receipts record nothing (the registry law), so the visible
//!    overshoot is the last partially-capped receipt's intrinsic —
//!    which is why the threshold is the comparison itself, not a
//!    ratio.
//! 10. `issuer_concentration` (LOW): one contributor earning ≥ the
//!     concentration share of their points from ONE issuer, in
//!     MATERIAL windows (≥ the floor AND ≥ the materiality ratio of
//!     the contributor cap — concentration at low volume is a single
//!     honest neighbor; concentration at scale is the
//!     fabricated-receipt economics), across ≥ N windows.
//!
//! # What this module is NOT
//!
//! Detection is not adjudication: the report revokes nothing, spends
//! nothing, admits nothing. Enforcement stays with the caps that
//! already bound the abuse (§14's belt) and with whatever
//! admission/revocation decision a deployment makes from this report
//! (its braces). There is no wire admission path in v1 — the report
//! is this node's own durable state, generated, never accepted.
//!
//! # Laws
//!
//! 1. **Versioned.** [`ANTIGAMING_RULESET_VERSION`] = 1; a change to
//!    any rule or threshold semantic is a new version.
//! 2. **Pure and caller-clocked.** No I/O, no wall clock, no unsafe;
//!    the caller supplies `now` and the detector folds only the
//!    entries/spends it is handed.
//! 3. **Deterministic.** Sorted iteration everywhere (BTree maps,
//!    sorted node subjects, findings ranked by a total order);
//!    identical inputs → byte-identical wire.
//! 4. **Fail-closed parse.** [`AuditReport::from_wire`] rejects
//!    unknown codes, malformed maps, trailing bytes — typed.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use sharenet_protocol::cbor::{decode, encode, Value};

use crate::ledger::{CivicPointLedger, LedgerEntry, SpendEntry};
use crate::{ValuationPolicy, VALUATION_FORMULA_VERSION, BP_DENOMINATOR};

/// The versioned anti-gaming ruleset (a change to ANY detection rule
/// or threshold semantic is a new version).
pub const ANTIGAMING_RULESET_VERSION: u32 = 1;

/// Default consecutive saturated windows before a cap-saturation
/// finding fires.
pub const DEFAULT_SATURATION_STREAK: u64 = 3;
/// Default saturation ratio (95% of the cap, in basis points).
pub const DEFAULT_SATURATION_RATIO_BP: u64 = 9_500;
/// Default minimum award entries before a directed edge enters the
/// reciprocal-ring graph (below this an exchange is ordinary traffic).
pub const DEFAULT_RING_MIN_EDGE_ENTRIES: u64 = 3;
/// Default repetitions of one identical intrinsic magnitude before
/// the fabricated-acknowledgement signal fires.
pub const DEFAULT_IDENTICAL_MAGNITUDE_MIN: u64 = 8;
/// Default consecutive windows whose intrinsic total EXCEEDED the
/// awarded total (the caps bound — the attempt is visible in the
/// intrinsic record) before the velocity finding fires.
pub const DEFAULT_VELOCITY_STREAK: u64 = 2;
/// Default issuer-concentration share (100% = one issuer supplies
/// every point, in basis points).
pub const DEFAULT_CONCENTRATION_SHARE_BP: u64 = 10_000;
/// Default consecutive concentrated windows before the finding fires.
pub const DEFAULT_CONCENTRATION_STREAK: u64 = 4;
/// Default minimum per-window awarded points before a window counts
/// toward concentration (a 1-point window is noise, not a feeder).
pub const DEFAULT_CONCENTRATION_MIN_WINDOW_POINTS: u64 = 1_000;
/// Default concentration materiality RELATIVE to the contributor cap
/// (10% — concentration at low volume is a single honest neighbor;
/// concentration at scale is the fabricated-receipt economics).
pub const DEFAULT_CONCENTRATION_MATERIAL_RATIO_BP: u64 = 1_000;
/// The evidence bound: at most this many receipt_ids per finding
/// (first N in entry order — the report is a pointer into the ledger,
/// not a copy of it).
pub const FINDING_EVIDENCE_BOUND: usize = 4;

// ---------------------------------------------------------------------------
// Policy (validated thresholds — the v1 knobs)
// ---------------------------------------------------------------------------

/// A detection-threshold construction refusal (typed, fail-closed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AntigamingError {
    StreakZero,
    RatioOutOfRange { found_bp: u64 },
    RingMinEdgeZero,
    IdenticalMinZero,
    ConcentrationStreakZero,
    ConcentrationMinWindowZero,
    /// The report bytes are not a valid AntigamingAuditReport.
    ReportMalformed { reason: String },
}

impl fmt::Display for AntigamingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AntigamingError::StreakZero => {
                write!(f, "saturation/concentration streaks must be at least 1")
            }
            AntigamingError::RatioOutOfRange { found_bp } => write!(
                f,
                "basis-point ratio must be 1..=1_000_000, found {found_bp}"
            ),
            AntigamingError::RingMinEdgeZero => {
                write!(f, "ring minimum edge entries must be at least 1")
            }
            AntigamingError::IdenticalMinZero => {
                write!(f, "identical magnitude minimum must be at least 1")
            }
            AntigamingError::ConcentrationStreakZero => {
                write!(f, "concentration streak must be at least 1")
            }
            AntigamingError::ConcentrationMinWindowZero => {
                write!(f, "concentration minimum window points must be at least 1")
            }
            AntigamingError::ReportMalformed { reason } => {
                write!(f, "audit report malformed: {reason}")
            }
        }
    }
}

impl std::error::Error for AntigamingError {}

impl AntigamingError {
    /// Stable machine name.
    pub fn name(&self) -> &'static str {
        match self {
            AntigamingError::StreakZero => "streak_zero",
            AntigamingError::RatioOutOfRange { .. } => "ratio_out_of_range",
            AntigamingError::RingMinEdgeZero => "ring_min_edge_zero",
            AntigamingError::IdenticalMinZero => "identical_min_zero",
            AntigamingError::ConcentrationStreakZero => "concentration_streak_zero",
            AntigamingError::ConcentrationMinWindowZero => "concentration_min_window_zero",
            AntigamingError::ReportMalformed { .. } => "report_malformed",
        }
    }
}

/// The detection thresholds (every bound validated at construction;
/// the RULESET is the frozen law, these are the knobs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntigamingPolicy {
    saturation_streak: u64,
    saturation_ratio_bp: u64,
    ring_min_edge_entries: u64,
    identical_magnitude_min: u64,
    velocity_streak: u64,
    concentration_share_bp: u64,
    concentration_streak: u64,
    concentration_min_window_points: u64,
    concentration_material_ratio_bp: u64,
}

impl Default for AntigamingPolicy {
    fn default() -> Self {
        Self {
            saturation_streak: DEFAULT_SATURATION_STREAK,
            saturation_ratio_bp: DEFAULT_SATURATION_RATIO_BP,
            ring_min_edge_entries: DEFAULT_RING_MIN_EDGE_ENTRIES,
            identical_magnitude_min: DEFAULT_IDENTICAL_MAGNITUDE_MIN,
            velocity_streak: DEFAULT_VELOCITY_STREAK,
            concentration_share_bp: DEFAULT_CONCENTRATION_SHARE_BP,
            concentration_streak: DEFAULT_CONCENTRATION_STREAK,
            concentration_min_window_points: DEFAULT_CONCENTRATION_MIN_WINDOW_POINTS,
            concentration_material_ratio_bp: DEFAULT_CONCENTRATION_MATERIAL_RATIO_BP,
        }
    }
}

impl AntigamingPolicy {
    /// Validate the bounds (fail-closed, typed).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        saturation_streak: u64,
        saturation_ratio_bp: u64,
        ring_min_edge_entries: u64,
        identical_magnitude_min: u64,
        velocity_streak: u64,
        concentration_share_bp: u64,
        concentration_streak: u64,
        concentration_min_window_points: u64,
        concentration_material_ratio_bp: u64,
    ) -> Result<Self, AntigamingError> {
        if saturation_streak == 0 || concentration_streak == 0 || velocity_streak == 0 {
            return Err(AntigamingError::StreakZero);
        }
        if saturation_ratio_bp == 0 || saturation_ratio_bp > 1_000_000 {
            return Err(AntigamingError::RatioOutOfRange {
                found_bp: saturation_ratio_bp,
            });
        }
        if concentration_share_bp == 0 || concentration_share_bp > BP_DENOMINATOR {
            return Err(AntigamingError::RatioOutOfRange {
                found_bp: concentration_share_bp,
            });
        }
        if concentration_material_ratio_bp == 0 || concentration_material_ratio_bp > BP_DENOMINATOR {
            return Err(AntigamingError::RatioOutOfRange {
                found_bp: concentration_material_ratio_bp,
            });
        }
        if ring_min_edge_entries == 0 {
            return Err(AntigamingError::RingMinEdgeZero);
        }
        if identical_magnitude_min == 0 {
            return Err(AntigamingError::IdenticalMinZero);
        }
        if concentration_min_window_points == 0 {
            return Err(AntigamingError::ConcentrationMinWindowZero);
        }
        Ok(Self {
            saturation_streak,
            saturation_ratio_bp,
            ring_min_edge_entries,
            identical_magnitude_min,
            velocity_streak,
            concentration_share_bp,
            concentration_streak,
            concentration_min_window_points,
            concentration_material_ratio_bp,
        })
    }

    /// A stable fingerprint of the thresholds (folded into every
    /// report — same inputs + same fingerprint = byte-identical
    /// report, else the comparison is meaningless).
    pub fn fingerprint(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for field in [
            self.saturation_streak,
            self.saturation_ratio_bp,
            self.ring_min_edge_entries,
            self.identical_magnitude_min,
            self.velocity_streak,
            self.concentration_share_bp,
            self.concentration_streak,
            self.concentration_min_window_points,
            self.concentration_material_ratio_bp,
        ] {
            h ^= field;
            h = h.wrapping_mul(0x1000_0000_01b3);
        }
        h
    }
}

// ---------------------------------------------------------------------------
// Findings
// ---------------------------------------------------------------------------

/// One detected pattern (integrity or anomaly). The frozen v1 set —
/// machine names are the stable surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FindingKind {
    /// A record the ledger engine could not have appended.
    LedgerInvariantViolation,
    /// An entry priced by an unknown formula version.
    UnknownFormulaVersion,
    /// The append clock moved backwards.
    ClockRegression,
    /// One pair at the saturation ratio of the pair cap for a streak.
    CapSaturationPair,
    /// One contributor (across all issuers) saturating for a streak.
    CapSaturationContributor,
    /// A ≥2-node strongly-connected component in the award graph.
    ReciprocalRing,
    /// The same intrinsic magnitude repeated from one pair.
    RepeatedIdenticalMagnitude,
    /// Pre-cap intrinsic velocity past the caps in one window.
    VelocityBeyondCap,
    /// One issuer supplying (nearly) all of a contributor's points.
    IssuerConcentration,
    /// A spend-side law broken from the outside.
    SpendInvariantViolation,
}

impl FindingKind {
    /// The registry machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingKind::LedgerInvariantViolation => "ledger_invariant_violation",
            FindingKind::UnknownFormulaVersion => "unknown_formula_version",
            FindingKind::ClockRegression => "clock_regression",
            FindingKind::CapSaturationPair => "cap_saturation_pair",
            FindingKind::CapSaturationContributor => "cap_saturation_contributor",
            FindingKind::ReciprocalRing => "reciprocal_ring",
            FindingKind::RepeatedIdenticalMagnitude => "repeated_identical_magnitude",
            FindingKind::VelocityBeyondCap => "velocity_beyond_cap",
            FindingKind::IssuerConcentration => "issuer_concentration",
            FindingKind::SpendInvariantViolation => "spend_invariant_violation",
        }
    }

    /// The registry wire code (the frozen v1 mapping).
    pub fn code(&self) -> u64 {
        match self {
            FindingKind::LedgerInvariantViolation => 1,
            FindingKind::UnknownFormulaVersion => 2,
            FindingKind::ClockRegression => 3,
            FindingKind::CapSaturationPair => 4,
            FindingKind::CapSaturationContributor => 5,
            FindingKind::ReciprocalRing => 6,
            FindingKind::RepeatedIdenticalMagnitude => 7,
            FindingKind::VelocityBeyondCap => 8,
            FindingKind::IssuerConcentration => 9,
            FindingKind::SpendInvariantViolation => 10,
        }
    }

    fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => FindingKind::LedgerInvariantViolation,
            2 => FindingKind::UnknownFormulaVersion,
            3 => FindingKind::ClockRegression,
            4 => FindingKind::CapSaturationPair,
            5 => FindingKind::CapSaturationContributor,
            6 => FindingKind::ReciprocalRing,
            7 => FindingKind::RepeatedIdenticalMagnitude,
            8 => FindingKind::VelocityBeyondCap,
            9 => FindingKind::IssuerConcentration,
            10 => FindingKind::SpendInvariantViolation,
            _ => return None,
        })
    }

    /// The severity (the frozen v1 mapping — deterministic by kind).
    pub fn severity(&self) -> Severity {
        match self {
            FindingKind::LedgerInvariantViolation
            | FindingKind::UnknownFormulaVersion
            | FindingKind::CapSaturationContributor
            | FindingKind::ReciprocalRing
            | FindingKind::SpendInvariantViolation => Severity::High,
            FindingKind::CapSaturationPair
            | FindingKind::RepeatedIdenticalMagnitude
            | FindingKind::VelocityBeyondCap => Severity::Medium,
            FindingKind::ClockRegression | FindingKind::IssuerConcentration => Severity::Low,
        }
    }
}

/// The finding severity (the frozen v1 set).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        }
    }

    fn code(&self) -> u64 {
        match self {
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
        }
    }

    fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => Severity::Low,
            2 => Severity::Medium,
            3 => Severity::High,
            _ => return None,
        })
    }
}

/// One finding: the pattern, the subjects, the window span, the count
/// and the exact-arithmetic detail — a pointer into the ledger, not a
/// copy of it (evidence bounded to [`FINDING_EVIDENCE_BOUND`]
/// receipt_ids in entry order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: FindingKind,
    /// The involved node_ids, sorted ascending.
    pub subjects: Vec<[u8; 32]>,
    /// The first window the pattern was observed in (0 for non-window
    /// findings).
    pub window_start: u64,
    /// The last window the pattern was observed in.
    pub window_end: u64,
    /// The repetition count (windows for streaks, entries for
    /// magnitudes, ring edges for rings).
    pub count: u64,
    /// The human-readable exact arithmetic.
    pub detail: String,
    /// The first receipt_ids backing the finding, in entry order.
    pub evidence: Vec<[u8; 32]>,
}

impl Finding {
    /// The total order over findings (determinism law): kind, then
    /// subjects, then span, then count, then detail.
    fn sort_key(&self) -> (FindingKind, Vec<[u8; 32]>, u64, u64, u64, String) {
        (
            self.kind,
            self.subjects.clone(),
            self.window_start,
            self.window_end,
            self.count,
            self.detail.clone(),
        )
    }
}

/// The overall audit verdict (derived, never caller-set).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditVerdict {
    /// Zero findings.
    Clean,
    /// Only low/medium findings.
    UnderReview,
    /// At least one high-severity finding.
    GamingSuspected,
}

impl AuditVerdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuditVerdict::Clean => "clean",
            AuditVerdict::UnderReview => "under_review",
            AuditVerdict::GamingSuspected => "gaming_suspected",
        }
    }

    fn code(&self) -> u64 {
        match self {
            AuditVerdict::Clean => 1,
            AuditVerdict::UnderReview => 2,
            AuditVerdict::GamingSuspected => 3,
        }
    }

    fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            1 => AuditVerdict::Clean,
            2 => AuditVerdict::UnderReview,
            3 => AuditVerdict::GamingSuspected,
            _ => return None,
        })
    }
}

/// The audit report — the registered `AntigamingAuditReport`
/// durable-state record. Pure function of (entries, spends, policies,
/// clock); byte-identical wire for identical inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditReport {
    pub generated_at_unix: u64,
    pub policy_fingerprint: u64,
    pub findings: Vec<Finding>,
    pub verdict: AuditVerdict,
}

impl AuditReport {
    /// Canonical CBOR (the registry schema).
    pub fn to_wire(&self) -> Vec<u8> {
        let findings: Vec<Value> = self
            .findings
            .iter()
            .map(|f| {
                Value::Map(vec![
                    (Value::Int(1), Value::Int(f.kind.code() as i64)),
                    (Value::Int(2), Value::Int(f.kind.severity().code() as i64)),
                    (
                        Value::Int(3),
                        Value::Array(
                            f.subjects
                                .iter()
                                .map(|s| Value::Bytes(s.to_vec()))
                                .collect(),
                        ),
                    ),
                    (Value::Int(4), Value::Int(f.window_start as i64)),
                    (Value::Int(5), Value::Int(f.window_end as i64)),
                    (Value::Int(6), Value::Int(f.count as i64)),
                    (Value::Int(7), Value::Text(f.detail.clone())),
                    (
                        Value::Int(8),
                        Value::Array(
                            f.evidence
                                .iter()
                                .map(|e| Value::Bytes(e.to_vec()))
                                .collect(),
                        ),
                    ),
                ])
            })
            .collect();
        encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(ANTIGAMING_RULESET_VERSION as i64)),
            (Value::Int(2), Value::Int(self.generated_at_unix as i64)),
            (Value::Int(3), Value::Int(self.policy_fingerprint as i64)),
            (Value::Int(4), Value::Int(self.verdict.code() as i64)),
            (Value::Int(5), Value::Array(findings)),
        ]))
        .expect("in-profile report")
    }

    /// Strict parse (fail-closed, typed).
    pub fn from_wire(bytes: &[u8]) -> Result<Self, AntigamingError> {
        let malformed = |reason: &str| AntigamingError::ReportMalformed {
            reason: reason.into(),
        };
        let v = decode(bytes).map_err(|e| malformed(&format!("cbor: {e}")))?;
        let Value::Map(fields) = v else {
            return Err(malformed("report not a map"));
        };
        let mut generated_at = None;
        let mut fingerprint = None;
        let mut verdict = None;
        let mut findings_raw = None;
        for (k, val) in fields {
            let Value::Int(key) = k else {
                return Err(malformed("non-integer report key"));
            };
            match key {
                1 => {
                    let Value::Int(v) = val else {
                        return Err(malformed("ruleset_version not an int"));
                    };
                    let v = u32::try_from(v).map_err(|_| malformed("version negative"))?;
                    if v != ANTIGAMING_RULESET_VERSION {
                        return Err(malformed("unknown ruleset version"));
                    }
                }
                2 => {
                    let Value::Int(v) = val else {
                        return Err(malformed("generated_at not an int"));
                    };
                    generated_at = Some(u64::try_from(v).map_err(|_| malformed("clock negative"))?);
                }
                3 => {
                    let Value::Int(v) = val else {
                        return Err(malformed("fingerprint not an int"));
                    };
                    fingerprint = Some(u64::try_from(v).map_err(|_| malformed("fingerprint negative"))?);
                }
                4 => {
                    let Value::Int(v) = val else {
                        return Err(malformed("verdict not an int"));
                    };
                    let v = u64::try_from(v).map_err(|_| malformed("verdict negative"))?;
                    verdict = Some(
                        AuditVerdict::from_code(v)
                            .ok_or_else(|| malformed("unknown verdict code"))?,
                    );
                }
                5 => {
                    let Value::Array(items) = val else {
                        return Err(malformed("findings not an array"));
                    };
                    let mut findings = Vec::with_capacity(items.len());
                    for item in items {
                        let Value::Map(f) = item else {
                            return Err(malformed("finding not a map"));
                        };
                        let mut kind = None;
                        let mut subjects = Vec::new();
                        let mut window_start = None;
                        let mut window_end = None;
                        let mut count = None;
                        let mut detail = None;
                        let mut evidence = Vec::new();
                        for (fk, fv) in f {
                            let Value::Int(fkey) = fk else {
                                return Err(malformed("non-integer finding key"));
                            };
                            match fkey {
                                1 => {
                                    let Value::Int(c) = fv else {
                                        return Err(malformed("kind not an int"));
                                    };
                                    let c = u64::try_from(c)
                                        .map_err(|_| malformed("kind negative"))?;
                                    kind = Some(
                                        FindingKind::from_code(c)
                                            .ok_or_else(|| malformed("unknown kind code"))?,
                                    );
                                }
                                2 => {
                                    let Value::Int(c) = fv else {
                                        return Err(malformed("severity not an int"));
                                    };
                                    let c = u64::try_from(c)
                                        .map_err(|_| malformed("severity negative"))?;
                                    let parsed = Severity::from_code(c)
                                        .ok_or_else(|| malformed("unknown severity code"))?;
                                    // The severity is DERIVED from the kind —
                                    // a mismatching wire is rejected, not
                                    // trusted.
                                    let kind_val = kind.ok_or_else(|| {
                                        malformed("severity before kind (key order)")
                                    })?;
                                    if parsed != kind_val.severity() {
                                        return Err(malformed(
                                            "severity does not match the kind's law",
                                        ));
                                    }
                                }
                                3 => {
                                    let Value::Array(subs) = fv else {
                                        return Err(malformed("subjects not an array"));
                                    };
                                    for s in subs {
                                        let Value::Bytes(b) = s else {
                                            return Err(malformed("subject not bytes"));
                                        };
                                        let arr: [u8; 32] = b
                                            .as_slice()
                                            .try_into()
                                            .map_err(|_| malformed("subject not 32 bytes"))?;
                                        subjects.push(arr);
                                    }
                                }
                                4 => {
                                    let Value::Int(c) = fv else {
                                        return Err(malformed("window_start not an int"));
                                    };
                                    window_start = Some(
                                        u64::try_from(c)
                                            .map_err(|_| malformed("window negative"))?,
                                    );
                                }
                                5 => {
                                    let Value::Int(c) = fv else {
                                        return Err(malformed("window_end not an int"));
                                    };
                                    window_end = Some(
                                        u64::try_from(c)
                                            .map_err(|_| malformed("window negative"))?,
                                    );
                                }
                                6 => {
                                    let Value::Int(c) = fv else {
                                        return Err(malformed("count not an int"));
                                    };
                                    count = Some(
                                        u64::try_from(c)
                                            .map_err(|_| malformed("count negative"))?,
                                    );
                                }
                                7 => {
                                    let Value::Text(t) = fv else {
                                        return Err(malformed("detail not text"));
                                    };
                                    detail = Some(t);
                                }
                                8 => {
                                    let Value::Array(evs) = fv else {
                                        return Err(malformed("evidence not an array"));
                                    };
                                    for e in evs {
                                        let Value::Bytes(b) = e else {
                                            return Err(malformed("evidence not bytes"));
                                        };
                                        let arr: [u8; 32] = b
                                            .as_slice()
                                            .try_into()
                                            .map_err(|_| malformed("evidence not 32 bytes"))?;
                                        evidence.push(arr);
                                    }
                                }
                                _ => return Err(malformed("unknown finding field")),
                            }
                        }
                        let kind = kind.ok_or_else(|| malformed("finding missing kind"))?;
                        findings.push(Finding {
                            kind,
                            subjects,
                            window_start: window_start
                                .ok_or_else(|| malformed("finding missing window_start"))?,
                            window_end: window_end
                                .ok_or_else(|| malformed("finding missing window_end"))?,
                            count: count.ok_or_else(|| malformed("finding missing count"))?,
                            detail: detail.ok_or_else(|| malformed("finding missing detail"))?,
                            evidence,
                        });
                    }
                    findings_raw = Some(findings);
                }
                _ => return Err(malformed("unknown report field")),
            }
        }
        Ok(AuditReport {
            generated_at_unix: generated_at
                .ok_or_else(|| malformed("missing generated_at"))?,
            policy_fingerprint: fingerprint
                .ok_or_else(|| malformed("missing policy_fingerprint"))?,
            verdict: verdict.ok_or_else(|| malformed("missing verdict"))?,
            findings: findings_raw.ok_or_else(|| malformed("missing findings"))?,
        })
    }
}

// ---------------------------------------------------------------------------
// The detector
// ---------------------------------------------------------------------------

/// The pure audit pass (one-shot; owns no state between audits).
#[derive(Debug, Clone, Default)]
pub struct AuditDetector {
    policy: AntigamingPolicy,
}

impl AuditDetector {
    pub fn new(policy: AntigamingPolicy) -> Self {
        Self { policy }
    }

    pub fn policy(&self) -> &AntigamingPolicy {
        &self.policy
    }

    /// Audit a live ledger (convenience — the pure core below is the
    /// law; this just hands it the ledger's own records and policy).
    pub fn audit_ledger(&self, ledger: &CivicPointLedger, now_unix: u64) -> AuditReport {
        self.audit(&ledger.entries(), &ledger.spends(), &ledger.policy(), now_unix)
    }

    /// The pure core: audit award entries + spend records under the
    /// valuation policy that priced them. Identical inputs → a
    /// byte-identical report.
    pub fn audit(
        &self,
        entries: &[LedgerEntry],
        spends: &[SpendEntry],
        valuation: &ValuationPolicy,
        now_unix: u64,
    ) -> AuditReport {
        let mut findings: Vec<Finding> = Vec::new();

        // ---- Aggregates (BTree = deterministic iteration) ----
        // pair-window -> awarded total; contributor-window -> awarded total.
        let mut pair_window: BTreeMap<([u8; 32], [u8; 32], u64), u64> = BTreeMap::new();
        // (contributor, issuer, window) -> awarded, for concentration.
        let mut contrib_issuer_window: BTreeMap<([u8; 32], [u8; 32], u64), u64> = BTreeMap::new();
        // contributor-window -> awarded total.
        let mut contrib_window: BTreeMap<([u8; 32], u64), u64> = BTreeMap::new();
        // contributor-window -> intrinsic total (the pre-cap record).
        let mut contrib_window_intrinsic: BTreeMap<([u8; 32], u64), u64> = BTreeMap::new();
        // (issuer, contributor) -> magnitude -> (count, first receipt ids).
        type Magnitudes = BTreeMap<([u8; 32], [u8; 32]), BTreeMap<u64, (u64, Vec<[u8; 32]>)>>;
        let mut pair_magnitudes: Magnitudes = BTreeMap::new();
        // The award graph: (issuer, contributor) -> entry count.
        let mut edges: BTreeMap<([u8; 32], [u8; 32]), u64> = BTreeMap::new();
        // receipt_id -> seen (evidence idempotency inside the audited set).
        let mut seen_receipts: BTreeSet<[u8; 32]> = BTreeSet::new();
        let mut unknown_versions: BTreeMap<u32, u64> = BTreeMap::new();
        let mut zero_or_bad_awards = 0u64;
        let mut clock_regressions = 0u64;
        let mut last_recorded: Option<u64> = None;

        for entry in entries {
            // Rule 3: the append clock must not move backwards.
            if let Some(prev) = last_recorded {
                if entry.recorded_at_unix < prev {
                    clock_regressions += 1;
                }
            }
            last_recorded = Some(entry.recorded_at_unix);

            // Rule 2: unknown formula versions are flagged, not guessed at.
            if entry.formula_version != VALUATION_FORMULA_VERSION {
                *unknown_versions.entry(entry.formula_version).or_insert(0) += 1;
            }

            // Rule 1 (pre): a non-positive award is not an engine record.
            if entry.awarded_points == 0 {
                zero_or_bad_awards += 1;
            }

            // Rule 1 (evidence idempotency): the same receipt_id twice
            // is a tampered log (the engine's exactly-once law).
            if !seen_receipts.insert(entry.receipt_id) {
                zero_or_bad_awards += 1;
            }

            *pair_window
                .entry((entry.issuer, entry.contributor, entry.window))
                .or_insert(0) += entry.awarded_points;
            *contrib_issuer_window
                .entry((entry.contributor, entry.issuer, entry.window))
                .or_insert(0) += entry.awarded_points;
            *contrib_window
                .entry((entry.contributor, entry.window))
                .or_insert(0) += entry.awarded_points;
            *contrib_window_intrinsic
                .entry((entry.contributor, entry.window))
                .or_insert(0) += entry.intrinsic_points;
            let mag = pair_magnitudes
                .entry((entry.issuer, entry.contributor))
                .or_default()
                .entry(entry.intrinsic_points)
                .or_insert((0, Vec::new()));
            mag.0 += 1;
            if mag.1.len() < FINDING_EVIDENCE_BOUND {
                mag.1.push(entry.receipt_id);
            }
            *edges.entry((entry.issuer, entry.contributor)).or_insert(0) += 1;
        }

        // ---- Integrity findings ----
        if zero_or_bad_awards > 0 {
            findings.push(Finding {
                kind: FindingKind::LedgerInvariantViolation,
                subjects: Vec::new(),
                window_start: 0,
                window_end: 0,
                count: zero_or_bad_awards,
                detail: format!(
                    "{zero_or_bad_awards} entries with zero awards or duplicated receipt_ids — \
                     the engine never appends these (tamper or foreign log)"
                ),
                evidence: Vec::new(),
            });
        }
        for (version, count) in &unknown_versions {
            findings.push(Finding {
                kind: FindingKind::UnknownFormulaVersion,
                subjects: Vec::new(),
                window_start: 0,
                window_end: 0,
                count: *count,
                detail: format!(
                    "{count} entries priced by unknown formula version {version} \
                     (known: {VALUATION_FORMULA_VERSION})"
                ),
                evidence: Vec::new(),
            });
        }
        if clock_regressions > 0 {
            findings.push(Finding {
                kind: FindingKind::ClockRegression,
                subjects: Vec::new(),
                window_start: 0,
                window_end: 0,
                count: clock_regressions,
                detail: format!(
                    "{clock_regressions} append-clock regressions (operational smell)"
                ),
                evidence: Vec::new(),
            });
        }

        // Rule 1 (cap totals): a per-(pair, window) total above the pair
        // cap — or a per-(contributor, window) total above the
        // contributor cap — is a record the engine could not append.
        let pair_cap = valuation.per_pair_window_points();
        let contrib_cap = valuation.per_contributor_window_points();
        let mut over_pair: u64 = 0;
        for (&(issuer, contributor, window), total) in &pair_window {
            if *total > pair_cap {
                over_pair += 1;
                let _ = (issuer, contributor, window);
            }
        }
        if over_pair > 0 {
            findings.push(Finding {
                kind: FindingKind::LedgerInvariantViolation,
                subjects: Vec::new(),
                window_start: 0,
                window_end: 0,
                count: over_pair,
                detail: format!(
                    "{over_pair} (pair, window) award totals above the pair cap {pair_cap}"
                ),
                evidence: Vec::new(),
            });
        }
        let mut over_contrib: u64 = 0;
        for (&(contributor, window), total) in &contrib_window {
            if *total > contrib_cap {
                over_contrib += 1;
                let _ = (contributor, window);
            }
        }
        if over_contrib > 0 {
            findings.push(Finding {
                kind: FindingKind::LedgerInvariantViolation,
                subjects: Vec::new(),
                window_start: 0,
                window_end: 0,
                count: over_contrib,
                detail: format!(
                    "{over_contrib} (contributor, window) award totals above the \
                     contributor cap {contrib_cap}"
                ),
                evidence: Vec::new(),
            });
        }

        // Rule 4: spend-side laws re-checked from the outside.
        let mut spend_violations = 0u64;
        let mut balances: BTreeMap<[u8; 32], i128> = BTreeMap::new();
        for ((contributor, _window), total) in &contrib_window {
            // Sum per contributor across windows.
            let e = balances.entry(*contributor).or_insert(0);
            *e += *total as i128;
        }
        let mut seen_spends: BTreeSet<[u8; 32]> = BTreeSet::new();
        for spend in spends {
            if spend.points == 0 || !seen_spends.insert(spend.spend_id) {
                spend_violations += 1;
            }
            *balances.entry(spend.contributor).or_insert(0) -= spend.points as i128;
        }
        for balance in balances.values() {
            if *balance < 0 {
                spend_violations += 1;
            }
        }
        if spend_violations > 0 {
            findings.push(Finding {
                kind: FindingKind::SpendInvariantViolation,
                subjects: Vec::new(),
                window_start: 0,
                window_end: 0,
                count: spend_violations,
                detail: format!(
                    "{spend_violations} spend-law violations (zero-point, duplicate \
                     spend_id, or derived negative balance)"
                ),
                evidence: Vec::new(),
            });
        }

        // ---- Anomaly findings ----
        let ap = &self.policy;

        // Rule 5/6: cap saturation streaks.
        let sat_pair = ap.saturation_ratio_bp.saturating_mul(pair_cap) / BP_DENOMINATOR;
        let sat_contrib = ap.saturation_ratio_bp.saturating_mul(contrib_cap) / BP_DENOMINATOR;
        // pair -> sorted windows -> saturated?
        let mut pair_sat_windows: BTreeMap<([u8; 32], [u8; 32]), BTreeSet<u64>> = BTreeMap::new();
        for ((issuer, contributor, window), total) in &pair_window {
            if *total >= sat_pair.max(1) {
                pair_sat_windows
                    .entry((*issuer, *contributor))
                    .or_default()
                    .insert(*window);
            }
        }
        for ((issuer, contributor), windows) in &pair_sat_windows {
            if let Some((start, end, len)) = longest_streak(windows, ap.saturation_streak) {
                findings.push(Finding {
                    kind: FindingKind::CapSaturationPair,
                    subjects: vec![*issuer, *contributor],
                    window_start: start,
                    window_end: end,
                    count: len,
                    detail: format!(
                        "pair at >= {} bp of the pair cap for {len} consecutive windows \
                         [{start}..{end}]",
                        ap.saturation_ratio_bp
                    ),
                    evidence: Vec::new(),
                });
            }
        }
        let mut contrib_sat_windows: BTreeMap<[u8; 32], BTreeSet<u64>> = BTreeMap::new();
        for ((contributor, window), total) in &contrib_window {
            if *total >= sat_contrib.max(1) {
                contrib_sat_windows.entry(*contributor).or_default().insert(*window);
            }
        }
        for (contributor, windows) in &contrib_sat_windows {
            if let Some((start, end, len)) = longest_streak(windows, ap.saturation_streak) {
                findings.push(Finding {
                    kind: FindingKind::CapSaturationContributor,
                    subjects: vec![*contributor],
                    window_start: start,
                    window_end: end,
                    count: len,
                    detail: format!(
                        "contributor at >= {} bp of the contributor cap across ALL issuers \
                         for {len} consecutive windows [{start}..{end}] — the Sybil shape",
                        ap.saturation_ratio_bp
                    ),
                    evidence: Vec::new(),
                });
            }
        }

        // Rule 7: reciprocal rings — SCC over the award graph.
        let nodes: BTreeSet<[u8; 32]> = edges
            .iter()
            .flat_map(|((issuer, contributor), _)| [issuer, contributor])
            .copied()
            .collect();
        let adjacency: BTreeMap<[u8; 32], Vec<[u8; 32]>> = nodes
            .iter()
            .map(|n| {
                (
                    *n,
                    edges
                        .iter()
                        .filter(|((issuer, contributor), weight)| {
                            issuer == n && **weight >= ap.ring_min_edge_entries && contributor != issuer
                        })
                        .map(|((_, contributor), _)| *contributor)
                        .collect::<Vec<_>>(),
                )
            })
            .collect();
        for component in tarjan_scc(nodes.iter().copied(), &adjacency) {
            if component.len() >= 2 {
                let mut subjects = component.clone();
                subjects.sort_unstable();
                let edge_entries: u64 = edges
                    .iter()
                    .filter(|((issuer, contributor), _)| {
                        component.contains(issuer) && component.contains(contributor)
                    })
                    .map(|(_, w)| *w)
                    .sum();
                findings.push(Finding {
                    kind: FindingKind::ReciprocalRing,
                    subjects,
                    window_start: 0,
                    window_end: 0,
                    count: component.len() as u64,
                    detail: format!(
                        "strongly-connected award ring of {} nodes with {edge_entries} \
                         award entries (>= {} per edge) — circular traffic",
                        component.len(),
                        ap.ring_min_edge_entries
                    ),
                    evidence: Vec::new(),
                });
            }
        }

        // Rule 8: repeated identical magnitudes.
        for ((issuer, contributor), magnitudes) in &pair_magnitudes {
            for (magnitude, (count, evidence)) in magnitudes {
                if *count >= ap.identical_magnitude_min {
                    findings.push(Finding {
                        kind: FindingKind::RepeatedIdenticalMagnitude,
                        subjects: vec![*issuer, *contributor],
                        window_start: 0,
                        window_end: 0,
                        count: *count,
                        detail: format!(
                            "identical intrinsic magnitude {magnitude} repeated {count} \
                             times (>= {}) — real traffic varies, scripts repeat",
                            ap.identical_magnitude_min
                        ),
                        evidence: evidence.clone(),
                    });
                }
            }
        }

        // Rule 9: intrinsic velocity past the caps — the caps BOUND the
        // awards, but the pre-cap intrinsic record shows the attempt.
        // A window where intrinsic > awarded is a window the caps
        // actually bound something; a STREAK of them is a contributor
        // pushing past the policy window after window. (Fully-capped
        // receipts record nothing by the registry law — the visible
        // overshoot is exactly the last partially-capped receipt's
        // intrinsic, which is why the threshold is the comparison
        // itself, not a ratio.)
        let mut capped_windows: BTreeMap<[u8; 32], BTreeSet<u64>> = BTreeMap::new();
        for ((contributor, window), intrinsic) in &contrib_window_intrinsic {
            let awarded = contrib_window
                .get(&(*contributor, *window))
                .copied()
                .unwrap_or(0);
            if *intrinsic > awarded {
                capped_windows.entry(*contributor).or_default().insert(*window);
            }
        }
        for (contributor, windows) in &capped_windows {
            if let Some((start, end, len)) = longest_streak(windows, ap.velocity_streak) {
                findings.push(Finding {
                    kind: FindingKind::VelocityBeyondCap,
                    subjects: vec![*contributor],
                    window_start: start,
                    window_end: end,
                    count: len,
                    detail: format!(
                        "pre-cap intrinsic EXCEEDED the awarded total for {len} consecutive \
                         windows [{start}..{end}] — the caps bounded the attempt, the \
                         intrinsic record shows it",
                    ),
                    evidence: Vec::new(),
                });
            }
        }

        // Rule 10: issuer concentration streaks. Material windows are
        // both ≥ the absolute floor AND ≥ the materiality ratio of the
        // contributor cap — concentration at low volume is a single
        // honest neighbor, concentration at scale is the
        // fabricated-receipt economics.
        let material_floor = (ap.concentration_material_ratio_bp * contrib_cap / BP_DENOMINATOR)
            .max(ap.concentration_min_window_points);
        let mut contrib_windows: BTreeMap<[u8; 32], BTreeSet<u64>> = BTreeMap::new();
        for ((contributor, window), total) in &contrib_window {
            if *total >= material_floor {
                contrib_windows.entry(*contributor).or_default().insert(*window);
            }
        }
        for (contributor, windows) in &contrib_windows {
            // Per material window: the top issuer's share.
            let mut concentrated_windows: BTreeSet<u64> = BTreeSet::new();
            for window in windows {
                let total: u64 = contrib_window
                    .get(&(*contributor, *window))
                    .copied()
                    .unwrap_or(0);
                let top = contrib_issuer_window
                    .iter()
                    .filter(|((c, _, w), _)| c == contributor && w == window)
                    .map(|(_, v)| *v)
                    .max()
                    .unwrap_or(0);
                if top.saturating_mul(BP_DENOMINATOR) >= ap.concentration_share_bp * total {
                    concentrated_windows.insert(*window);
                }
            }
            if let Some((start, end, len)) = longest_streak(&concentrated_windows, ap.concentration_streak)
            {
                findings.push(Finding {
                    kind: FindingKind::IssuerConcentration,
                    subjects: vec![*contributor],
                    window_start: start,
                    window_end: end,
                    count: len,
                    detail: format!(
                        "one issuer supplied >= {} bp of all awarded points for {len} \
                         consecutive material windows [{start}..{end}] (material >= {} \
                         points, the floor or {} bp of the contributor cap)",
                        ap.concentration_share_bp, material_floor,
                        ap.concentration_material_ratio_bp
                    ),
                    evidence: Vec::new(),
                });
            }
        }

        // ---- Deterministic order + verdict ----
        findings.sort_by_key(|a| a.sort_key());
        findings.dedup_by(|a, b| a.sort_key() == b.sort_key());
        let verdict = if findings
            .iter()
            .any(|f| f.kind.severity() == Severity::High)
        {
            AuditVerdict::GamingSuspected
        } else if findings.is_empty() {
            AuditVerdict::Clean
        } else {
            AuditVerdict::UnderReview
        };
        AuditReport {
            generated_at_unix: now_unix,
            policy_fingerprint: ap.fingerprint(),
            findings,
            verdict,
        }
    }
}

/// The longest run of CONSECUTIVE windows in the set with length >=
/// `min` (deterministic; returns (start, end, len) of the first
/// longest run).
fn longest_streak(windows: &BTreeSet<u64>, min: u64) -> Option<(u64, u64, u64)> {
    let mut best: Option<(u64, u64, u64)> = None;
    let mut run_start: Option<u64> = None;
    let mut prev: Option<u64> = None;
    for &w in windows {
        match (prev, run_start) {
            (Some(p), Some(s)) if w == p + 1 => {
                prev = Some(w);
                let len = w - s + 1;
                if best.map(|(_, _, l)| len > l).unwrap_or(true) && len >= min {
                    best = Some((s, w, len));
                }
            }
            _ => {
                run_start = Some(w);
                prev = Some(w);
                if min <= 1 && best.is_none() {
                    best = Some((w, w, 1));
                }
            }
        }
    }
    best.filter(|(_, _, len)| *len >= min)
}

/// Tarjan's strongly-connected components, iterated over nodes in
/// sorted order (deterministic output order).
fn tarjan_scc(nodes: impl Iterator<Item = [u8; 32]>, adjacency: &BTreeMap<[u8; 32], Vec<[u8; 32]>>) -> Vec<Vec<[u8; 32]>> {
    let mut index: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    let mut low: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    let mut on_stack: BTreeSet<[u8; 32]> = BTreeSet::new();
    let mut stack: Vec<[u8; 32]> = Vec::new();
    let mut components: Vec<Vec<[u8; 32]>> = Vec::new();
    let mut next_index: u64 = 0;

    #[allow(clippy::too_many_arguments)]
    fn strongconnect(
        v: [u8; 32],
        adjacency: &BTreeMap<[u8; 32], Vec<[u8; 32]>>,
        index: &mut BTreeMap<[u8; 32], u64>,
        low: &mut BTreeMap<[u8; 32], u64>,
        on_stack: &mut BTreeSet<[u8; 32]>,
        stack: &mut Vec<[u8; 32]>,
        components: &mut Vec<Vec<[u8; 32]>>,
        next_index: &mut u64,
    ) {
        index.insert(v, *next_index);
        low.insert(v, *next_index);
        *next_index += 1;
        stack.push(v);
        on_stack.insert(v);
        if let Some(neighbors) = adjacency.get(&v) {
            for &w in neighbors {
                if !index.contains_key(&w) {
                    strongconnect(
                        w, adjacency, index, low, on_stack, stack, components, next_index,
                    );
                    let lw = *low.get(&w).expect("low set");
                    let lv = *low.get(&v).expect("low set");
                    low.insert(v, lw.min(lv));
                } else if on_stack.contains(&w) {
                    let iw = *index.get(&w).expect("index set");
                    let lv = *low.get(&v).expect("low set");
                    low.insert(v, lv.min(iw));
                }
            }
        }
        if *low.get(&v).expect("low set") == *index.get(&v).expect("index set") {
            let mut component = Vec::new();
            loop {
                let w = stack.pop().expect("stack non-empty");
                on_stack.remove(&w);
                component.push(w);
                if w == v {
                    break;
                }
            }
            component.sort_unstable();
            components.push(component);
        }
    }

    for v in nodes {
        if !index.contains_key(&v) {
            strongconnect(
                v,
                adjacency,
                &mut index,
                &mut low,
                &mut on_stack,
                &mut stack,
                &mut components,
                &mut next_index,
            );
        }
    }
    components.sort();
    components
}

// ---------------------------------------------------------------------------
// The simulation verify level (the seeded adversarial scenario)
// ---------------------------------------------------------------------------

/// The `run_antigaming_simulation` report (the economics_sim pattern:
/// one deterministic line, the driver guards the invariants).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AntigamingSimReport {
    pub seed: u64,
    pub windows: u64,
    pub entries: u64,
    pub honest_entries: u64,
    pub findings: u64,
    /// Findings touching ONLY honest-mesh nodes (MUST be 0 — the
    /// false-positive law).
    pub false_positives: u64,
    /// Expected gaming-cohort finding kinds NOT present (MUST be 0 —
    /// the detection law).
    pub missed_cohorts: u64,
    /// Ledger-integrity findings (MUST be 0 — the sim drives the real
    /// engine, the log stays lawful).
    pub integrity_violations: u64,
    pub verdict: &'static str,
}

impl AntigamingSimReport {
    /// The machine-parsable one-line form (byte-identical across runs
    /// with the same seed).
    pub fn to_line(&self) -> String {
        format!(
            "seed={} windows={} entries={} honest={} findings={} false_positives={} missed_cohorts={} integrity={} verdict={}",
            self.seed,
            self.windows,
            self.entries,
            self.honest_entries,
            self.findings,
            self.false_positives,
            self.missed_cohorts,
            self.integrity_violations,
            self.verdict,
        )
    }
}

/// The seeded deterministic adversarial simulation: an honest mesh
/// plus six gaming cohorts (pair farmer, k-issuer Sybil family,
/// reciprocal ring, magnitude repeater, one-window blaster,
/// concentrated feeder) under one ledger. Every gaming cohort must be
/// NAMED by its expected rule; the honest mesh must stay CLEAN.
///
/// `windows` is the simulated window count; `k` is the Sybil family's
/// issuer count.
pub fn run_antigaming_simulation(
    seed: u64,
    windows: u64,
    k: u64,
    valuation: ValuationPolicy,
    antigaming: AntigamingPolicy,
) -> AntigamingSimReport {
    use crate::sim::Rng;
    use sharenet_protocol::contribution::{ContributionKind, ContributionReceipt};
    use sharenet_protocol::identity::Identity;

    let mut rng = Rng::new(seed);
    let window_secs = valuation.window_secs();
    let ledger = CivicPointLedger::with_policy(valuation);
    let now_base: u64 = 0;

    let id = |b: u8| Identity::from_seed([b; 32], now_base, None).expect("sim identity");
    let node_of = |b: u8| *id(b).node_id().as_bytes();

    let mut seq = 1u64;
    let mut honest_entries = 0u64;
    let emit = |ledger: &CivicPointLedger,
                    issuer: &Identity,
                    contributor: [u8; 32],
                    bytes: u64,
                    issued: u64,
                    seq: &mut u64| {
        let receipt = ContributionReceipt::new(
            issuer,
            contributor,
            [0xB5; 32],
            ContributionKind::Carried,
            bytes,
            *seq,
            issued,
        )
        .expect("sim receipt within the laws");
        *seq += 1;
        ledger.award(&receipt, issued).expect("sim award");
    };

    // Cohort node tags (seed regions kept disjoint):
    // 0x10..=0x1F honest issuers, 0x20..0x2F honest contributors,
    // 0x30 farmer, 0x40 sybil, 0x50 ring, 0x60 repeater, 0x70 blaster,
    // 0x80 feeder.
    let honest_issuers: Vec<Identity> = (0u8..3).map(|i| id(0x10 + i)).collect();
    let honest_contributors: Vec<[u8; 32]> = (0u8..4).map(|i| node_of(0x20 + i)).collect();
    let mut honest_nodes: Vec<[u8; 32]> = honest_issuers.iter().map(|i| *i.node_id().as_bytes()).collect();
    honest_nodes.extend(honest_contributors.iter().copied());

    let farmer_issuer = id(0x31);
    let farmer_contributor = node_of(0x32);
    let sybil_contributor = node_of(0x41);
    let sybil_issuers: Vec<Identity> = (0u8..k as u8).map(|i| id(0x42 + i)).collect();
    let ring: Vec<Identity> = (0u8..3).map(|i| id(0x50 + i)).collect();
    let repeater_issuer = id(0x61);
    let repeater_contributor = node_of(0x62);
    let blaster_contributor = node_of(0x71);
    let feeder_issuer = id(0x81);
    let feeder_contributor = node_of(0x82);

    for w in 0..windows {
        let issued = w * window_secs + 60;
        // Honest mesh: varied magnitudes, modest volume, 3 issuers
        // (no concentration), deterministic variation (no repeated
        // magnitudes).
        for issuer in &honest_issuers {
            for contributor in &honest_contributors {
                let n = 1 + rng.below(2);
                for _ in 0..n {
                    let bytes = 100 + (seq * 37) % 2_900;
                    emit(&ledger, issuer, *contributor, bytes, issued, &mut seq);
                    honest_entries += 1;
                }
            }
        }
        // Pair farmer: saturates the pair cap every window.
        for _ in 0..3 {
            emit(&ledger, &farmer_issuer, farmer_contributor, 10_000, issued, &mut seq);
        }
        // Sybil family: k issuers, one contributor, each pair below the
        // pair cap, the contributor saturating across all of them.
        for issuer in &sybil_issuers {
            for _ in 0..3 {
                emit(&ledger, issuer, sybil_contributor, 4_000, issued, &mut seq);
            }
        }
        // Reciprocal ring: A -> B -> C -> A.
        for _ in 0..3 {
            for i in 0..3usize {
                let (from, to) = (i, (i + 1) % 3);
                emit(&ledger, &ring[from], node_of(0x50 + to as u8), 300, issued, &mut seq);
            }
        }
        // Feeder: concentrated (one issuer, 100%), material (6_000
        // points per window >= 10% of the contributor cap), lawful.
        for _ in 0..3 {
            emit(&ledger, &feeder_issuer, feeder_contributor, 2_000, issued, &mut seq);
        }
        // Magnitude repeater: one identical acknowledgement per window
        // (windows 0..10; inside the loop so the append clock stays
        // monotonic — the ledger clock is the emit order here).
        if w < 10 {
            emit(&ledger, &repeater_issuer, repeater_contributor, 7_777, issued, &mut seq);
        }
        // Blaster: pushes past the contributor cap EVERY window — the
        // partial-cap shape (eight 7_000B receipts: 56_000 intrinsic,
        // 50_000 awarded) leaves the intrinsic > awarded record
        // window after window. Fresh issuers each window (0x90..
        // region).
        for i in 0..8u8 {
            let issuer = id(0x90 + (w as u8) * 8 + i);
            emit(&ledger, &issuer, blaster_contributor, 7_000, issued, &mut seq);
        }
    }

    let detector = AuditDetector::new(antigaming);
    let audit_clock = windows * window_secs;
    let report = detector.audit_ledger(&ledger, audit_clock);

    let mut false_positives = 0u64;
    for finding in &report.findings {
        // Subject-less integrity findings are attributed to the LOG,
        // not to a cohort — they are counted in integrity_violations
        // (asserted 0 separately), never as honest-cohort hits.
        if !finding.subjects.is_empty()
            && finding.subjects.iter().all(|s| honest_nodes.contains(s))
        {
            false_positives += 1;
        }
    }
    let expected = [
        FindingKind::CapSaturationPair,
        FindingKind::CapSaturationContributor,
        FindingKind::ReciprocalRing,
        FindingKind::RepeatedIdenticalMagnitude,
        FindingKind::VelocityBeyondCap,
        FindingKind::IssuerConcentration,
    ];
    let missed_cohorts = expected
        .iter()
        .filter(|k| !report.findings.iter().any(|f| f.kind == **k))
        .count() as u64;
    let integrity_violations = report
        .findings
        .iter()
        .filter(|f| {
            matches!(
                f.kind,
                FindingKind::LedgerInvariantViolation
                    | FindingKind::UnknownFormulaVersion
                    | FindingKind::ClockRegression
                    | FindingKind::SpendInvariantViolation
            )
        })
        .count() as u64;

    AntigamingSimReport {
        seed,
        windows,
        entries: ledger.entry_count() as u64,
        honest_entries,
        findings: report.findings.len() as u64,
        false_positives,
        missed_cohorts,
        integrity_violations,
        verdict: report.verdict.as_str(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consumption::PerkKind;
    use crate::ledger::FileCivicPointLedger;
    use crate::sim::Rng;
    use sharenet_protocol::contribution::{ContributionKind, ContributionReceipt};
    use sharenet_protocol::identity::Identity;

    const NOW: u64 = 1_800_000_000;

    fn identity(seed: u8) -> Identity {
        Identity::from_seed([seed; 32], NOW, None).expect("identity")
    }

    fn node(seed: u8) -> [u8; 32] {
        *identity(seed).node_id().as_bytes()
    }

    fn receipt(
        issuer: &Identity,
        contributor: [u8; 32],
        kind: ContributionKind,
        bytes: u64,
        seq: u64,
        issued_at: u64,
    ) -> ContributionReceipt {
        ContributionReceipt::new(
            issuer,
            contributor,
            [0xA7; 32],
            kind,
            bytes,
            seq,
            issued_at,
        )
        .expect("test receipt within the laws")
    }

    fn tight_policy() -> ValuationPolicy {
        // window 600s, per-receipt cap 10_000 B, pair cap 20_000, contrib cap 50_000.
        ValuationPolicy::new(600, 10_000, 20_000, 50_000).expect("policy")
    }

    /// The honest baseline: one modest pair, varied magnitudes, far
    /// below every cap → ZERO findings (the no-false-positives law).
    #[test]
    fn honest_baseline_is_clean() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy);
        let issuer = identity(0x11);
        let contributor = node(0x21);
        let mut seq = 1u64;
        for window in 0..12u64 {
            let issued = window * 600 + 60;
            for _ in 0..3 {
                let bytes = 100 + (seq * 37) % 900; // varied, far below caps
                ledger
                    .award(&receipt(&issuer, contributor, ContributionKind::Carried, bytes, seq, issued), issued)
                    .expect("award");
                seq += 1;
            }
        }
        let detector = AuditDetector::default();
        let report = detector.audit_ledger(&ledger, NOW);
        assert_eq!(report.verdict, AuditVerdict::Clean, "{:?}", report.findings);
        assert!(report.findings.is_empty());
    }

    /// The farmer: one pair saturating the pair cap every window for a
    /// streak → cap_saturation_pair (MEDIUM) + the saturation is
    /// contributor-level too if sustained hard enough (here it stays
    /// pair-level; the exact kind asserted).
    #[test]
    fn pair_cap_saturation_detected() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy);
        let issuer = identity(0x31);
        let contributor = node(0x32);
        let mut seq = 1u64;
        for window in 0..6u64 {
            let issued = window * 600 + 60;
            // 3 x 10_000B carried = 30_000 intrinsic > 20_000 pair cap → capped at 20_000.
            for _ in 0..3 {
                ledger
                    .award(&receipt(&issuer, contributor, ContributionKind::Carried, 10_000, seq, issued), issued)
                    .expect("award");
                seq += 1;
            }
        }
        let detector = AuditDetector::default();
        let report = detector.audit_ledger(&ledger, NOW);
        assert!(report.verdict != AuditVerdict::Clean);
        let sat = report
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::CapSaturationPair)
            .expect("cap_saturation_pair finding");
        assert_eq!(sat.subjects.len(), 2);
        assert!(sat.count >= 3);
        // The ledger itself stayed lawful: no integrity findings.
        assert!(!report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::LedgerInvariantViolation));
    }

    /// The Sybil family: k issuers, one contributor, each pair modest
    /// (NO pair saturates) but the contributor saturates across all
    /// issuers → cap_saturation_contributor (HIGH).
    #[test]
    fn sybil_family_contributor_saturation_detected() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy);
        let k = 5u64;
        let contributor = node(0x42);
        let mut seq = 1u64;
        for window in 0..5u64 {
            let issued = window * 600 + 60;
            for i in 0..k {
                let issuer = identity(0x50 + i as u8);
                // 3 x 4_000B = 12_000 intrinsic per pair per window
                // (< 20_000 pair cap), k=5 pairs → 60_000 intrinsic, capped at 50_000.
                for _ in 0..3 {
                    ledger
                        .award(&receipt(&issuer, contributor, ContributionKind::Carried, 4_000, seq, issued), issued)
                        .expect("award");
                    seq += 1;
                }
            }
        }
        let detector = AuditDetector::default();
        let report = detector.audit_ledger(&ledger, NOW);
        let sat = report
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::CapSaturationContributor)
            .expect("cap_saturation_contributor finding");
        assert_eq!(sat.subjects, vec![contributor]);
        assert!(sat.count >= 3);
    }

    /// The reciprocal ring: two nodes acknowledging each other with
    /// enough entries → reciprocal_ring (HIGH) — §14's exact phrase.
    #[test]
    fn reciprocal_ring_detected() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy);
        let a = identity(0x61);
        let b = identity(0x62);
        let mut seq = 1u64;
        for window in 0..4u64 {
            let issued = window * 600 + 60;
            for _ in 0..2 {
                ledger.award(&receipt(&a, node(0x62), ContributionKind::Carried, 500, seq, issued), issued).expect("award");
                seq += 1;
                ledger.award(&receipt(&b, node(0x61), ContributionKind::Carried, 500, seq, issued), issued).expect("award");
                seq += 1;
            }
        }
        let detector = AuditDetector::default();
        let report = detector.audit_ledger(&ledger, NOW);
        let ring = report
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::ReciprocalRing)
            .expect("reciprocal_ring finding");
        let mut subjects = ring.subjects.clone();
        subjects.sort_unstable();
        assert_eq!(subjects, {
            let mut s = vec![node(0x61), node(0x62)];
            s.sort_unstable();
            s
        });
        assert_eq!(ring.count, 2);
    }

    /// The size-3 cycle A→B→C→A (no pair is reciprocal!) is still one
    /// SCC → detected. This is why the detector uses SCC, not pairwise
    /// reciprocity.
    #[test]
    fn three_node_cycle_detected() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy);
        let a = identity(0x71);
        let b = identity(0x72);
        let c = identity(0x73);
        let mut seq = 1u64;
        for window in 0..3u64 {
            let issued = window * 600 + 60;
            for _ in 0..3 {
                ledger.award(&receipt(&a, node(0x72), ContributionKind::Carried, 300, seq, issued), issued).expect("award");
                seq += 1;
                ledger.award(&receipt(&b, node(0x73), ContributionKind::Carried, 300, seq, issued), issued).expect("award");
                seq += 1;
                ledger.award(&receipt(&c, node(0x71), ContributionKind::Carried, 300, seq, issued), issued).expect("award");
                seq += 1;
            }
        }
        let detector = AuditDetector::default();
        let report = detector.audit_ledger(&ledger, NOW);
        assert!(report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::ReciprocalRing && f.count == 3));
    }

    /// The scripted ack: the SAME magnitude repeated from one pair →
    /// repeated_identical_magnitude (MEDIUM).
    #[test]
    fn repeated_identical_magnitude_detected() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy);
        let issuer = identity(0x81);
        let contributor = node(0x82);
        for (seq, n) in (1u64..).zip(0..10u64) {
            let issued = n * 600 + 60;
            ledger.award(&receipt(&issuer, contributor, ContributionKind::Carried, 7_777, seq, issued), issued).expect("award");
        }
        let detector = AuditDetector::default();
        let report = detector.audit_ledger(&ledger, NOW);
        let mag = report
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::RepeatedIdenticalMagnitude)
            .expect("repeated_identical_magnitude finding");
        assert_eq!(mag.count, 10);
        assert!(!mag.evidence.is_empty());
    }

    /// The blaster: a contributor whose intrinsic exceeds the awarded
    /// total for a STREAK of windows (the caps bound; the intrinsic
    /// record shows the attempt) → velocity_beyond_cap (MEDIUM).
    #[test]
    fn velocity_beyond_cap_detected() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy);
        let contributor = node(0x92);
        let mut seq = 1u64;
        for window in 0..3u64 {
            let issued = window * 600 + 60;
            // Eight receipts of 7_000B from eight issuers: intrinsic
            // 56_000, awarded 50_000 (seven full + one partial — the
            // appended partial entry records intrinsic 7_000 > awarded
            // 1_000, the visible overshoot).
            for i in 0..8u8 {
                let issuer = identity(0x93 + i);
                ledger
                    .award(&receipt(&issuer, contributor, ContributionKind::Carried, 7_000, seq, issued), issued)
                    .expect("award");
                seq += 1;
            }
        }
        let detector = AuditDetector::default();
        let report = detector.audit_ledger(&ledger, NOW);
        let v = report
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::VelocityBeyondCap)
            .expect("velocity_beyond_cap finding");
        assert_eq!(v.count, 3);
        // A single capped window alone (streak < 2) does NOT fire.
        let ledger2 = CivicPointLedger::with_policy(tight_policy());
        let contributor2 = node(0x95);
        let issued = 60u64;
        for (seq2, i) in (1u64..).zip(0..8u8) {
            let issuer = identity(0x96 + i);
            ledger2
                .award(&receipt(&issuer, contributor2, ContributionKind::Carried, 7_000, seq2, issued), issued)
                .expect("award");
        }
        let report2 = detector.audit_ledger(&ledger2, NOW);
        assert!(!report2
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::VelocityBeyondCap && f.subjects == vec![contributor2]));
    }

    /// The concentrated feeder: one contributor, one issuer, MATERIAL
    /// windows (≥ max(floor, 10% of the contributor cap) points), a
    /// streak → issuer_concentration (LOW).
    #[test]
    fn issuer_concentration_detected() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy);
        let issuer = identity(0xA1);
        let contributor = node(0xA2);
        let mut seq = 1u64;
        for window in 0..5u64 {
            let issued = window * 600 + 60;
            // 3 x 2_000B = 6_000 points per window (material: >= 10% of
            // the 50_000 contributor cap, far below the caps).
            for _ in 0..3 {
                ledger.award(&receipt(&issuer, contributor, ContributionKind::Carried, 2_000, seq, issued), issued).expect("award");
                seq += 1;
            }
        }
        let detector = AuditDetector::default();
        let report = detector.audit_ledger(&ledger, NOW);
        let conc = report
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::IssuerConcentration)
            .expect("issuer_concentration finding");
        assert!(conc.count >= 4);
        // A single honest neighbor at LOW volume is NOT concentrated
        // (the materiality floor): 2 x 900B = 1_800/window < 5_000.
        let ledger2 = CivicPointLedger::with_policy(tight_policy());
        let issuer2 = identity(0xA3);
        let contributor2 = node(0xA4);
        let mut seq2 = 1u64;
        for window in 0..6u64 {
            let issued = window * 600 + 60;
            for _ in 0..2 {
                ledger2.award(&receipt(&issuer2, contributor2, ContributionKind::Carried, 900, seq2, issued), issued).expect("award");
                seq2 += 1;
            }
        }
        let report2 = detector.audit_ledger(&ledger2, NOW);
        assert!(!report2
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::IssuerConcentration && f.subjects == vec![contributor2]));
    }

    // ---- Integrity findings (tamper, not gaming) ----

    /// A tampered log: per-(pair, window) award total above the pair
    /// cap — the engine could not have appended these.
    #[test]
    fn tampered_pair_total_above_cap_flagged() {
        let policy = tight_policy();
        let issuer = node(0xB1);
        let contributor = node(0xB2);
        let entries = vec![LedgerEntry {
            contributor,
            issuer,
            awarded_points: 25_000, // > 20_000 pair cap
            intrinsic_points: 25_000,
            formula_version: VALUATION_FORMULA_VERSION,
            receipt_id: [0x11; 32],
            window: 7,
            recorded_at_unix: NOW,
        }];
        let detector = AuditDetector::default();
        let report = detector.audit(&entries, &[], &policy, NOW);
        assert!(report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::LedgerInvariantViolation));
        assert_eq!(report.verdict, AuditVerdict::GamingSuspected);
    }

    /// An entry priced by an unknown formula version → flagged HIGH,
    /// never guessed at.
    #[test]
    fn unknown_formula_version_flagged() {
        let policy = tight_policy();
        let issuer = node(0xB3);
        let contributor = node(0xB4);
        let entries = vec![LedgerEntry {
            contributor,
            issuer,
            awarded_points: 1_000,
            intrinsic_points: 1_000,
            formula_version: 99,
            receipt_id: [0x22; 32],
            window: 1,
            recorded_at_unix: NOW,
        }];
        let detector = AuditDetector::default();
        let report = detector.audit(&entries, &[], &policy, NOW);
        let f = report
            .findings
            .iter()
            .find(|f| f.kind == FindingKind::UnknownFormulaVersion)
            .expect("unknown_formula_version finding");
        assert!(f.detail.contains("99"));
    }

    /// The append clock moved backwards → clock_regression (LOW).
    #[test]
    fn clock_regression_flagged() {
        let policy = tight_policy();
        let issuer = node(0xB5);
        let contributor = node(0xB6);
        let entries = vec![
            LedgerEntry {
                contributor,
                issuer,
                awarded_points: 100,
                intrinsic_points: 100,
                formula_version: VALUATION_FORMULA_VERSION,
                receipt_id: [0x33; 32],
                window: 1,
                recorded_at_unix: NOW,
            },
            LedgerEntry {
                contributor,
                issuer,
                awarded_points: 100,
                intrinsic_points: 100,
                formula_version: VALUATION_FORMULA_VERSION,
                receipt_id: [0x44; 32],
                window: 2,
                recorded_at_unix: NOW - 10,
            },
        ];
        let detector = AuditDetector::default();
        let report = detector.audit(&entries, &[], &policy, NOW);
        assert!(report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::ClockRegression));
        assert_eq!(report.verdict, AuditVerdict::UnderReview);
    }

    /// A duplicated receipt_id inside the audited set → tamper.
    #[test]
    fn duplicate_receipt_id_flagged() {
        let policy = tight_policy();
        let issuer = node(0xB7);
        let contributor = node(0xB8);
        let base = LedgerEntry {
            contributor,
            issuer,
            awarded_points: 100,
            intrinsic_points: 100,
            formula_version: VALUATION_FORMULA_VERSION,
            receipt_id: [0x55; 32],
            window: 1,
            recorded_at_unix: NOW,
        };
        let detector = AuditDetector::default();
        let report = detector.audit(&[base.clone(), base], &[], &policy, NOW);
        assert!(report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::LedgerInvariantViolation));
    }

    // ---- Evasion attempts (the adversarial edge) ----

    /// Jitter farmer: varies every magnitude but still saturates —
    /// sum-based detection does not care about magnitudes.
    #[test]
    fn jitter_farmer_still_caught_by_saturation() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy);
        let issuer = identity(0xC1);
        let contributor = node(0xC2);
        let mut rng = Rng::new(7);
        let mut seq = 1u64;
        for window in 0..4u64 {
            let issued = window * 600 + 60;
            for _ in 0..3 {
                let jitter = rng.below(2_000);
                ledger.award(&receipt(&issuer, contributor, ContributionKind::Carried, 8_000 + jitter, seq, issued), issued).expect("award");
                seq += 1;
            }
        }
        let detector = AuditDetector::default();
        let report = detector.audit_ledger(&ledger, NOW);
        assert!(report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::CapSaturationPair));
        // No repeated magnitude fires (the jitter worked on THAT rule).
        assert!(!report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::RepeatedIdenticalMagnitude));
    }

    /// Below-threshold reciprocity: a small mutual exchange (ONE entry
    /// each way per window — 2 per edge total, under the ring
    /// threshold) with no other signal → ZERO findings (threshold
    /// honesty; no false positive).
    #[test]
    fn small_mutual_exchange_not_a_ring() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy);
        let a = identity(0xC3);
        let b = identity(0xC4);
        let mut seq = 1u64;
        for window in 0..2u64 {
            let issued = window * 600 + 60;
            ledger.award(&receipt(&a, node(0xC4), ContributionKind::Carried, 100 + seq, seq, issued), issued).expect("award");
            seq += 1;
            ledger.award(&receipt(&b, node(0xC3), ContributionKind::Carried, 100 + seq, seq, issued), issued).expect("award");
            seq += 1;
        }
        let detector = AuditDetector::default();
        let report = detector.audit_ledger(&ledger, NOW);
        assert_eq!(report.verdict, AuditVerdict::Clean, "{:?}", report.findings);
    }

    /// Alternating windows: the farmer saturates windows 0, 2, 4 —
    /// never a CONSECUTIVE streak. The streak rule stays silent
    /// (documented conservative threshold: the caps already bounded
    /// each individual window; only a STREAK is a farming pattern).
    #[test]
    fn alternating_window_saturation_not_a_streak() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy);
        let issuer = identity(0xC5);
        let contributor = node(0xC6);
        let mut seq = 1u64;
        for window in [0u64, 2, 4] {
            let issued = window * 600 + 60;
            for _ in 0..3 {
                ledger.award(&receipt(&issuer, contributor, ContributionKind::Carried, 9_000 + seq * 13, seq, issued), issued).expect("award");
                seq += 1;
            }
        }
        let detector = AuditDetector::default();
        let report = detector.audit_ledger(&ledger, NOW);
        assert!(!report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::CapSaturationPair));
    }

    // ---- Determinism + wire laws ----

    /// The determinism law: the same inputs → byte-identical report;
    /// the audit clock only moves generated_at (findings identical).
    #[test]
    fn audit_is_deterministic() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy);
        let issuer = identity(0xD1);
        let contributor = node(0xD2);
        let mut seq = 1u64;
        for window in 0..5u64 {
            let issued = window * 600 + 60;
            for _ in 0..3 {
                ledger.award(&receipt(&issuer, contributor, ContributionKind::Carried, 10_000, seq, issued), issued).expect("award");
                seq += 1;
            }
        }
        let detector = AuditDetector::default();
        let r1 = detector.audit_ledger(&ledger, NOW);
        let r2 = detector.audit_ledger(&ledger, NOW);
        assert_eq!(r1.to_wire(), r2.to_wire());
        let r3 = detector.audit_ledger(&ledger, NOW + 999);
        assert_ne!(r1.to_wire(), r3.to_wire()); // the clock moved
        assert_eq!(r1.findings, r3.findings); // the findings did not
        assert_eq!(r1.policy_fingerprint, r3.policy_fingerprint);
    }

    /// A different policy fingerprint → different report field (the
    /// comparison guard).
    #[test]
    fn policy_fingerprint_tracks_thresholds() {
        let a = AntigamingPolicy::default();
        let b = AntigamingPolicy::new(
            4, 9_500, 3, 8, 2, 10_000, 4, 1_000, 1_000,
        )
        .expect("policy");
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    /// Wire round-trip + strict rejects.
    #[test]
    fn report_wire_roundtrip_and_rejects() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy);
        let issuer = identity(0xE1);
        let contributor = node(0xE2);
        let mut seq = 1u64;
        for window in 0..4u64 {
            let issued = window * 600 + 60;
            for _ in 0..3 {
                ledger.award(&receipt(&issuer, contributor, ContributionKind::Carried, 10_000, seq, issued), issued).expect("award");
                seq += 1;
            }
        }
        let detector = AuditDetector::default();
        let report = detector.audit_ledger(&ledger, NOW);
        let wire = report.to_wire();
        let back = AuditReport::from_wire(&wire).expect("roundtrip");
        assert_eq!(back, report);
        // Trailing bytes rejected.
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(AuditReport::from_wire(&trailing).is_err());
        // Corruption rejected.
        let mut corrupt = wire.clone();
        let mid = corrupt.len() / 2;
        corrupt[mid] ^= 0xFF;
        assert!(AuditReport::from_wire(&corrupt).is_err());
        // Empty rejected.
        assert!(AuditReport::from_wire(&[]).is_err());
    }

    /// The spend side: a lawful spend adds no finding; the audit
    /// re-checks the exactly-once/no-overdraft laws from the outside.
    #[test]
    fn spend_side_audited() {
        let policy = tight_policy();
        let ledger = CivicPointLedger::with_policy(policy.clone());
        let issuer = identity(0xF1);
        let contributor = node(0xF2);
        for (seq, window) in (1u64..).zip(0..2u64) {
            let issued = window * 600 + 60;
            ledger.award(&receipt(&issuer, contributor, ContributionKind::Carried, 5_000, seq, issued), issued).expect("award");
        }
        // A lawful spend.
        ledger
            .spend(
                &contributor,
                PerkKind::PriorityScheduling,
                100,
                [0x99; 32],
                NOW,
                600,
            )
            .expect("spend");
        let detector = AuditDetector::default();
        let report = detector.audit_ledger(&ledger, NOW);
        assert!(!report
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::SpendInvariantViolation));

        // A tampered spend list: the SAME spend_id twice (the exactly-once
        // law broken from the outside) → HIGH.
        let entries = ledger.entries();
        let mut spends = ledger.spends();
        spends.push(spends[0].clone());
        let report2 = detector.audit(&entries, &spends, &policy, NOW);
        assert!(report2
            .findings
            .iter()
            .any(|f| f.kind == FindingKind::SpendInvariantViolation));
        assert_eq!(report2.verdict, AuditVerdict::GamingSuspected);
    }

    /// The restart law: audit → reload from disk → audit again → the
    /// byte-identical report (the durable audit is the same audit).
    #[test]
    fn audit_survives_restart_identically() {
        let dir = std::env::temp_dir().join(format!(
            "sharenet-audit-restart-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("ledger.cpl");
        let ledger = FileCivicPointLedger::open(&path, tight_policy()).expect("open");
        let issuer = identity(0x03);
        let contributor = node(0x04);
        let mut seq = 1u64;
        for window in 0..4u64 {
            let issued = window * 600 + 60;
            for _ in 0..3 {
                ledger.award(&receipt(&issuer, contributor, ContributionKind::Carried, 10_000, seq, issued), issued).expect("award");
                seq += 1;
            }
        }
        let detector = AuditDetector::default();
        let before = detector.audit_ledger(ledger.ledger(), NOW).to_wire();
        drop(ledger);
        let reloaded = FileCivicPointLedger::open(&path, tight_policy()).expect("reload");
        let after = detector.audit_ledger(reloaded.ledger(), NOW).to_wire();
        assert_eq!(before, after, "the audit is the same after restart");
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A randomized honest cohort across seeds: ZERO findings every
    /// time (the false-positive law, property-checked).
    #[test]
    fn honest_cohort_never_flagged_across_seeds() {
        for seed in 0..16u64 {
            let policy = tight_policy();
            let ledger = CivicPointLedger::with_policy(policy);
            let mut rng = Rng::new(seed);
            let issuers: Vec<Identity> = (0..3).map(|i| identity(0x10 + i)).collect();
            let contributors: Vec<[u8; 32]> = (0..4).map(node).collect();
            let mut seq = 1u64;
            for window in 0..8u64 {
                let issued = window * 600 + 60;
                for issuer in &issuers {
                    for contributor in &contributors {
                        let n = 1 + rng.below(2);
                        for _ in 0..n {
                            // Varied magnitudes, small volume: an honest mesh.
                            let bytes = 100 + rng.below(3_000);
                            ledger
                                .award(&receipt(issuer, *contributor, ContributionKind::Carried, bytes, seq, issued), issued)
                                .expect("award");
                            seq += 1;
                        }
                    }
                }
            }
            let detector = AuditDetector::default();
            let report = detector.audit_ledger(&ledger, NOW);
            assert_eq!(
                report.verdict,
                AuditVerdict::Clean,
                "seed {seed}: {:?}",
                report.findings
            );
        }
    }

    /// The streak helper's exact law (consecutive windows only).
    #[test]
    fn longest_streak_law() {
        let s: BTreeSet<u64> = [1u64, 2, 3, 5, 6, 9].into_iter().collect();
        assert_eq!(longest_streak(&s, 3), Some((1, 3, 3)));
        assert_eq!(longest_streak(&s, 4), None);
        let t: BTreeSet<u64> = [4u64].into_iter().collect();
        assert_eq!(longest_streak(&t, 1), Some((4, 4, 1)));
    }

    /// The simulation verify level: every gaming cohort named, the
    /// honest mesh never flagged, the log lawful — across seeds.
    #[test]
    fn antigaming_simulation_catches_every_cohort() {
        let valuation = ValuationPolicy::new(600, 10_000, 20_000, 50_000).expect("policy");
        for seed in [0u64, 1, 7, 42, 99, 1234] {
            let report = run_antigaming_simulation(
                seed,
                12,
                5,
                valuation.clone(),
                AntigamingPolicy::default(),
            );
            assert_eq!(report.false_positives, 0, "seed {seed}");
            assert_eq!(report.missed_cohorts, 0, "seed {seed}");
            assert_eq!(report.integrity_violations, 0, "seed {seed}");
            assert_eq!(report.verdict, "gaming_suspected", "seed {seed}");
            assert!(report.findings >= 6, "seed {seed}");
            assert!(report.entries > 0);
        }
        // Determinism: the same seed twice → the identical line.
        let a = run_antigaming_simulation(42, 12, 5, valuation.clone(), AntigamingPolicy::default());
        let b = run_antigaming_simulation(42, 12, 5, valuation.clone(), AntigamingPolicy::default());
        assert_eq!(a.to_line(), b.to_line());
        // A different seed → (very likely) different honest volume.
        let c = run_antigaming_simulation(43, 12, 5, valuation, AntigamingPolicy::default());
        assert!(a.honest_entries != c.honest_entries || a.findings == c.findings);
    }
}

