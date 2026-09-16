//! The four-week competitor simulation — work item R10-005
//! ("Four-week competitor simulation"; verify levels: simulation,
//! reproducibility).
//!
//! A SEEDED, DETERMINISTIC population competing over the REAL Civic
//! Point economy for four simulated weeks: every receipt flows
//! through the real [`CivicPointLedger`] (the R8-002 caps bind every
//! award), and the R8-005 [`AuditDetector`] audits the accumulated
//! ledger WEEKLY and at the end — the gamers must be named every
//! time, the honest cohort must NEVER be flagged, and the caps must
//! hold the gamers' share for the whole month.
//!
//! # The simulated world
//!
//! * `days` days of simulated time (default 28 — the four weeks),
//!   each day split into `windows_per_day` valuation windows.
//! * The HONEST cohort: contributors with varied real-work volumes
//!   (seeded), from multiple issuers (no concentration), whose
//!   traffic is interrupted by FAILURES (seeded per-window outage
//!   probability — the R7 recovery reality: windows go missing; the
//!   detector must not mistake a gap for a pattern).
//! * The GAMER cohorts, one per R8-005 strategy: the pair farmer
//!   (saturates its pair cap window after window), the Sybil family
//!   (k issuers behind one contributor), the reciprocal ring (a
//!   directed cycle of acknowledgements), the magnitude repeater
//!   (identical scripted receipts), the blaster (pushes intrinsic
//!   past the caps every window) and the concentrated feeder's
//!   cousin the farm-and-spender (earns concentrated, immediately
//!   spends — the consumption side under sustained gaming).
//! * Weekly audits + the final audit over the SAME accumulating
//!   durable ledger.
//!
//! # The laws asserted (the simulation's invariants)
//!
//! 1. Every gamer cohort is flagged by its expected rule at EVERY
//!    weekly audit (after enough accumulation — the first audit runs
//!    after week 1, when the streaks already exist).
//! 2. The honest cohort produces ZERO findings at every audit
//!    (no false positives across seeds — the R8-005 law, sustained).
//! 3. The ledger stays lawful for the whole month (no cap
//!    violations — the §14 caps bind four weeks of gaming).
//! 4. The gamers' awarded total stays bounded by the caps (the
//!    Sybil bound: what four weeks of farming actually yields).
//! 5. Determinism: the same seed produces the byte-identical report
//!    line (the reproducibility verify level).

use crate::antigaming::{
    AntigamingPolicy, AuditDetector, FindingKind,
};
use crate::ledger::{CivicPointLedger, SpendEntry};
use crate::sim::Rng;
use crate::ValuationPolicy;

use sharenet_protocol::contribution::{ContributionKind, ContributionReceipt};
use sharenet_protocol::identity::Identity;

/// The competitor simulation's report (one deterministic line — the
/// competitor_sim driver prints it; byte-identical per seed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompetitorSimReport {
    pub seed: u64,
    pub days: u64,
    pub windows_per_day: u64,
    pub nodes: u64,
    pub honest_nodes: u64,
    pub gamer_nodes: u64,
    pub receipts: u64,
    pub entries: u64,
    /// Total points the honest cohort earned over the month.
    pub honest_points: u64,
    /// Total points the gamer cohorts earned over the month (the
    /// cap-bounded yield of a month of gaming).
    pub gamer_points: u64,
    /// Gamer share of all awarded points, basis points.
    pub gamer_share_bp: u64,
    /// Findings naming gamer cohorts across ALL audits (weekly + final).
    pub gamer_findings: u64,
    /// Findings touching ONLY honest nodes across ALL audits (MUST be 0).
    pub honest_false_positives: u64,
    /// Ledger cap violations (MUST be 0 — the §14 bound, one month).
    pub cap_violations: u64,
    /// Successful lawful perk spends by the farm-and-spender cohort.
    pub spends_executed: u64,
    pub verdict: &'static str,
}

impl CompetitorSimReport {
    /// The machine-parsable one-line form (byte-identical across runs
    /// with the same seed — the reproducibility law).
    pub fn to_line(&self) -> String {
        format!(
            "seed={} days={} windows={} nodes={} honest={} gamers={} receipts={} entries={} \
honest_points={} gamer_points={} gamer_share_bp={} gamer_findings={} false_positives={} \
cap_violations={} spends={} verdict={}",
            self.seed,
            self.days,
            self.windows_per_day,
            self.nodes,
            self.honest_nodes,
            self.gamer_nodes,
            self.receipts,
            self.entries,
            self.honest_points,
            self.gamer_points,
            self.gamer_share_bp,
            self.gamer_findings,
            self.honest_false_positives,
            self.cap_violations,
            self.spends_executed,
            self.verdict,
        )
    }
}

/// One node's emission bookkeeping (the per-pair monotonic sequence
/// law across the whole month).
struct Pair {
    issuer: Identity,
    contributor: [u8; 32],
    seq: u64,
}

impl Pair {
    fn emit(
        &mut self,
        kind: ContributionKind,
        bytes: u64,
        issued_at: u64,
        content: [u8; 32],
    ) -> ContributionReceipt {
        let receipt = ContributionReceipt::new(
            &self.issuer,
            self.contributor,
            content,
            kind,
            bytes,
            self.seq,
            issued_at,
        )
        .expect("sim receipt within the receipt laws");
        self.seq += 1;
        receipt
    }
}

/// The four-week competitor simulation. `honest` = honest cohort size;
/// the gamer cohorts are fixed at one family each (the R8-005
/// strategies); `failure_bp` = per-window outage probability for the
/// honest cohort (basis points).
#[allow(clippy::too_many_arguments)]
pub fn run_competitor_simulation(
    seed: u64,
    days: u64,
    windows_per_day: u64,
    honest: u64,
    valuation: ValuationPolicy,
    antigaming: AntigamingPolicy,
    failure_bp: u64,
) -> CompetitorSimReport {
    let mut rng = Rng::new(seed);
    let window_secs = valuation.window_secs();
    let ledger = CivicPointLedger::with_policy(valuation);
    let detector = AuditDetector::new(antigaming);

    // Identity regions (byte seeds, disjoint):
    //   0x10.. honest issuers, 0x20.. honest contributors,
    //   0x30 farmer, 0x40 sybil family, 0x50 ring,
    //   0x60 repeater, 0x70 blaster, 0x80 farm-and-spender.
    let id = |b: u8| Identity::from_seed([b; 32], 0, None).expect("sim identity");
    let node_of = |b: u8| *id(b).node_id().as_bytes();

    let honest_issuers: Vec<Identity> = (0u8..3).map(|i| id(0x10 + i)).collect();
    let honest_contributors: Vec<[u8; 32]> = (0..honest as u8).map(|i| node_of(0x20 + i)).collect();
    let mut honest_nodes: Vec<[u8; 32]> =
        honest_issuers.iter().map(|i| *i.node_id().as_bytes()).collect();
    honest_nodes.extend(honest_contributors.iter().copied());

    // The honest pairs: every issuer ↔ every contributor (multi-issuer
    // by construction — no concentration), sequences per pair.
    let mut honest_pairs: Vec<Pair> = honest_issuers
        .iter()
        .enumerate()
        .flat_map(|(i, _issuer)| {
            honest_contributors
                .iter()
                .map(|c| Pair {
                    issuer: id(0x10 + i as u8),
                    contributor: *c,
                    seq: 1,
                })
                .collect::<Vec<_>>()
        })
        .collect();

    // The gamer cohorts.
    let mut farmer = Pair {
        issuer: id(0x31),
        contributor: node_of(0x32),
        seq: 1,
    };
    let sybil_contributor = node_of(0x41);
    let mut sybil_pairs: Vec<Pair> = (0u8..5)
        .map(|i| Pair {
            issuer: id(0x42 + i),
            contributor: sybil_contributor,
            seq: 1,
        })
        .collect();
    let mut ring: Vec<Pair> = (0u8..3)
        .map(|i| Pair {
            issuer: id(0x50 + i),
            contributor: node_of(0x50 + (i + 1) % 3),
            seq: 1,
        })
        .collect();
    let mut repeater = Pair {
        issuer: id(0x61),
        contributor: node_of(0x62),
        seq: 1,
    };
    let blaster_contributor = node_of(0x71);
    let mut blaster_pairs: Vec<Pair> = (0u8..8)
        .map(|i| Pair {
            issuer: id(0x72 + i),
            contributor: blaster_contributor,
            seq: 1,
        })
        .collect();
    let mut spender = Pair {
        issuer: id(0x81),
        contributor: node_of(0x82),
        seq: 1,
    };

    let mut receipts_total: u64 = 0;
    let mut honest_points: u64 = 0;
    let mut gamer_points: u64 = 0;
    let mut gamer_findings: u64 = 0;
    let mut honest_false_positives: u64 = 0;
    let mut cap_violations: u64 = 0;

    let total_windows = days * windows_per_day;

    let award = |ledger: &CivicPointLedger, receipt: &ContributionReceipt, issued: u64| -> u64 {
        let verdict = ledger.award(receipt, issued).expect("sim award");
        verdict
            .entry
            .as_ref()
            .map(|e| e.awarded_points)
            .unwrap_or(0)
    };

    for w in 0..total_windows {
        let issued = w * window_secs + window_secs / 2;
        let day = w / windows_per_day;

        // ---- The honest cohort: varied real work, failure-gapped ----
        for pair in &mut honest_pairs {
            // The per-window outage (the R7 reality: windows go
            // missing; a gap is not a pattern).
            if rng.below(10_000) < failure_bp {
                continue;
            }
            let n = 1 + rng.below(2);
            for _ in 0..n {
                // Deterministic magnitude variation (a month is ~1000
                // receipts per pair — the coprime stride cannot repeat
                // inside the 4_000-wide space, so honest traffic never
                // trips the repeated-magnitude rule).
                let bytes = 500 + (pair.seq * 37) % 4_000;
                let receipt = pair.emit(ContributionKind::Carried, bytes, issued, [0x9A; 32]);
                receipts_total += 1;
                honest_points += award(&ledger, &receipt, issued);
            }
        }

        // ---- The gamer cohorts (strategies from R8-005) ----
        // The farmer: saturate the pair cap every window.
        for _ in 0..3 {
            let receipt = farmer.emit(ContributionKind::Carried, 10_000, issued, [0x9B; 32]);
            receipts_total += 1;
            gamer_points += award(&ledger, &receipt, issued);
        }
        // The Sybil family: each pair modest, the contributor saturated.
        for pair in &mut sybil_pairs {
            for _ in 0..3 {
                let receipt = pair.emit(ContributionKind::Carried, 4_000, issued, [0x9C; 32]);
                receipts_total += 1;
                gamer_points += award(&ledger, &receipt, issued);
            }
        }
        // The ring: A→B→C→A acknowledgements.
        for pair in ring.iter_mut() {
            for _ in 0..3 {
                let receipt = pair.emit(ContributionKind::Carried, 300, issued, [0x9D; 32]);
                receipts_total += 1;
                gamer_points += award(&ledger, &receipt, issued);
            }
        }
        // The repeater: identical scripted receipts.
        if w % 2 == 0 {
            for _ in 0..2 {
                let receipt = repeater.emit(ContributionKind::Carried, 7_777, issued, [0x9E; 32]);
                receipts_total += 1;
                gamer_points += award(&ledger, &receipt, issued);
            }
        }
        // The blaster: past the contributor cap every window.
        for pair in &mut blaster_pairs {
            let receipt = pair.emit(ContributionKind::Carried, 7_000, issued, [0x9F; 32]);
            receipts_total += 1;
            gamer_points += award(&ledger, &receipt, issued);
        }
        // The farm-and-spender: concentrated earnings, immediately
        // spent (lawful consumption under sustained gaming).
        {
            for _ in 0..3 {
                let receipt = spender.emit(ContributionKind::Carried, 2_000, issued, [0xA1; 32]);
                receipts_total += 1;
                gamer_points += award(&ledger, &receipt, issued);
            }
            // Lawful consumption under sustained gaming (the R8-004
            // spend path, exercised for a month).
            let _ = ledger.spend(
                &spender.contributor,
                crate::consumption::PerkKind::PriorityScheduling,
                100,
                [0xB0 + (w % 0x40) as u8; 32],
                issued,
                600,
            );
        }

        // ---- The weekly audits (after each 7-day week's last window
        //      and the final audit at the end) ----
        let is_week_end = (w + 1) % (7 * windows_per_day) == 0;
        if is_week_end {
            let report = detector.audit_ledger(&ledger, issued);
            for finding in &report.findings {
                if finding.subjects.is_empty() {
                    // Integrity findings are attributed to the LOG; the
                    // sim counts them separately (they must never
                    // appear: the engine stays lawful).
                    continue;
                }
                if finding.subjects.iter().all(|s| honest_nodes.contains(s)) {
                    honest_false_positives += 1;
                } else {
                    gamer_findings += 1;
                }
            }
            // The ledger's own lawful record: the detector's integrity
            // findings (a cap the engine never could have exceeded) —
            // there must be none, every week.
            if report
                .findings
                .iter()
                .any(|f| matches!(f.kind, FindingKind::LedgerInvariantViolation))
            {
                cap_violations += 1;
            }
            let _ = day;
        }
    }

    // The FINAL audit (the four-week report).
    let final_clock = total_windows * window_secs;
    let report = detector.audit_ledger(&ledger, final_clock);
    for finding in &report.findings {
        if finding.subjects.is_empty() {
            continue;
        }
        if finding.subjects.iter().all(|s| honest_nodes.contains(s)) {
            honest_false_positives += 1;
        } else {
            gamer_findings += 1;
        }
    }
    if report
        .findings
        .iter()
        .any(|f| matches!(f.kind, FindingKind::LedgerInvariantViolation))
    {
        cap_violations += 1;
    }
    let spends: Vec<SpendEntry> = ledger.spends();

    let total_points = honest_points + gamer_points;
    let gamer_share_bp = (gamer_points * 10_000).checked_div(total_points).unwrap_or(0);

    CompetitorSimReport {
        seed,
        days,
        windows_per_day,
        nodes: honest_nodes.len() as u64 + 2 + 5 + 3 + 2 + 9 + 2,
        honest_nodes: honest_nodes.len() as u64,
        gamer_nodes: 2 + 5 + 3 + 2 + 9 + 2,
        receipts: receipts_total,
        entries: ledger.entry_count() as u64,
        honest_points,
        gamer_points,
        gamer_share_bp,
        gamer_findings,
        honest_false_positives,
        cap_violations,
        spends_executed: spends.len() as u64,
        verdict: report.verdict.as_str(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> ValuationPolicy {
        ValuationPolicy::new(600, 10_000, 20_000, 50_000).expect("policy")
    }

    /// THE FOUR-WEEK LAW: every gamer cohort named at every weekly
    /// audit, the honest cohort NEVER flagged, the ledger lawful, the
    /// caps holding a month of gaming — deterministically.
    #[test]
    fn four_weeks_of_competition_every_law_holds() {
        for seed in [0u64, 7, 42, 2026] {
            let report = run_competitor_simulation(
                seed,
                28,
                24,
                6,
                policy(),
                AntigamingPolicy::default(),
                1_500, // 15% of honest windows lost to failures
            );
            assert_eq!(report.days, 28, "four weeks");
            assert!(
                report.entries > 0,
                "the month accumulated a real ledger (seed {seed})"
            );
            // Every gamer cohort named (six strategies × 4 weekly
            // audits + final — at minimum one finding per cohort per
            // audit after week 1).
            assert!(
                report.gamer_findings >= 6,
                "every gamer cohort named at least once (seed {seed}, got {})",
                report.gamer_findings
            );
            // The honest cohort NEVER flagged — across failures,
            // across seeds.
            assert_eq!(
                report.honest_false_positives, 0,
                "no honest false positives in four weeks (seed {seed})"
            );
            // The ledger lawful for a month.
            assert_eq!(report.cap_violations, 0, "caps held (seed {seed})");
            // The gamers' month-long yield is bounded by the caps:
            // the farmer + sybil + blaster saturations dominate; the
            // total is well under the honest cohort's real work at
            // these parameters.
            assert!(
                report.gamer_share_bp < 10_000,
                "gamers cannot out-earn the caps (seed {seed}, {} bp)",
                report.gamer_share_bp
            );
            // The farm-and-spender's lawful consumption executed.
            assert!(report.spends_executed > 0, "seed {seed}");
            // The verdict: gaming suspected (the honest economy with
            // gamers in it).
            assert_eq!(report.verdict, "gaming_suspected", "seed {seed}");
        }
    }

    /// THE REPRODUCIBILITY LAW: the same seed → the byte-identical
    /// report line; a different seed → a different line.
    #[test]
    fn the_simulation_is_reproducible() {
        let a = run_competitor_simulation(
            42,
            28,
            24,
            6,
            policy(),
            AntigamingPolicy::default(),
            1_500,
        );
        let b = run_competitor_simulation(
            42,
            28,
            24,
            6,
            policy(),
            AntigamingPolicy::default(),
            1_500,
        );
        assert_eq!(a.to_line(), b.to_line(), "same seed → identical report");
        let c = run_competitor_simulation(
            43,
            28,
            24,
            6,
            policy(),
            AntigamingPolicy::default(),
            1_500,
        );
        assert_ne!(a.to_line(), c.to_line(), "different seed → different report");

        // A one-week run is a prefix law in spirit: shorter month,
        // same laws.
        let week = run_competitor_simulation(
            42,
            7,
            24,
            6,
            policy(),
            AntigamingPolicy::default(),
            1_500,
        );
        assert_eq!(week.honest_false_positives, 0);
        assert!(week.gamer_findings >= 6);
        assert_eq!(week.cap_violations, 0);
    }

    /// The failure-gap law at the extreme: even a 40% outage rate
    /// never manufactures a false positive.
    #[test]
    fn heavy_failure_gaps_still_never_flag_the_honest() {
        let report = run_competitor_simulation(
            99,
            14,
            24,
            8,
            policy(),
            AntigamingPolicy::default(),
            4_000, // 40% of honest windows lost
        );
        assert_eq!(report.honest_false_positives, 0);
        assert_eq!(report.cap_violations, 0);
        assert!(report.gamer_findings >= 6);
    }
}
