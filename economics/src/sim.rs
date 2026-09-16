//! The R8-002 simulation verify level: a seeded, deterministic
//! adversarial simulation of the valuation policy (the propagation_sim
//! precedent — discrete steps, no wall clock, byte-identical run to
//! run for a given seed).
//!
//! # What it models
//!
//! One valuing node (`ValuationEngine`) receiving receipt streams over
//! `windows` windows from four agent families, every stream respecting
//! the RECEIPT-layer laws (per-pair strictly-increasing sequence,
//! issued_at in the past):
//!
//! - **honest**: one issuer acknowledging one contributor, modest byte
//!   flow (the baseline the caps never bind);
//! - **sybil_ring**: `k` colluding issuer identities all acknowledging
//!   the SAME contributor with maximal receipts — the §14 "Sybil
//!   multiplication of contribution" attack;
//! - **circular_pair**: two nodes taking turns acknowledging each other
//!   (A→B and B→A are two distinct pairs) — the §14 "circular traffic
//!   created solely to farm points" attack;
//! - **window_straddler**: one pair timing its receipts at the last
//!   instant of one window and the first of the next — the boundary
//!   discipline (caps are per-window; boundary timing accrues at most
//!   each window's own cap, never double).
//!
//! # What it proves (the properties asserted every step)
//!
//! 1. **The cap invariant**: no (pair, window) total ever exceeds the
//!    per-pair cap and no (contributor, window) total ever exceeds the
//!    per-contributor cap — under ANY of the adversarial flows.
//! 2. **The Sybil bound is real**: the ring's un-capped potential is
//!    `k × per_pair_cap` per window; the actual award is bounded by
//!    the contributor cap — the simulation reports the bound factor.
//! 3. **Determinism**: identical seed → identical report (the sim is a
//!    pure function of its inputs).
//!
//! # What it does NOT prove (honest limits)
//!
//! This is a directional policy simulation over SYNTHETIC receipts, not
//! field evidence, not a market survey, and not anomaly DETECTION
//! (R8-005 owns detection — here the caps merely BOUND the abuse; the
//! ring's capped points are still paid). Monetary value is a separate
//! settlement program entirely (§13).

use crate::{ValuationEngine, ValuationPolicy};
use sharenet_protocol::contribution::{ContributionKind, ContributionReceipt};
use sharenet_protocol::identity::Identity;

/// Deterministic xorshift64* PRNG (simulation scaffolding only — never
/// a protocol input).
#[derive(Debug, Clone)]
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Seeded construction (0 is mapped to the splitmix constant so
    /// every seed yields a full-period stream).
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed },
        }
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform-ish below `n` (simulation quality is enough for a
    /// directional model; no statistical claims).
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// The deterministic simulation report (byte-stable field order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimReport {
    pub seed: u64,
    pub windows: u64,
    pub steps: u64,
    pub receipts_valued: u64,
    pub receipts_capped: u64,
    /// Points paid to the honest family (per window average).
    pub honest_window_points: u64,
    /// Points paid to the sybil ring's contributor (per window).
    pub sybil_window_points: u64,
    /// The ring's UN-CAPPED potential per window (k × pair cap).
    pub sybil_uncapped_potential: u64,
    /// Points paid to the circular pair (both directions, per window).
    pub circular_window_points: u64,
    /// Points paid to the straddler (per window).
    pub straddler_window_points: u64,
    /// Cap violations observed (MUST be 0 — the invariant).
    pub cap_violations: u64,
}

impl SimReport {
    /// The machine-parsable one-line form (the sim binary prints this;
    /// byte-identical across runs with the same seed).
    pub fn to_line(&self) -> String {
        format!(
            "seed={} windows={} steps={} valued={} capped={} honest={} sybil={} potential={} circular={} straddler={} violations={}",
            self.seed,
            self.windows,
            self.steps,
            self.receipts_valued,
            self.receipts_capped,
            self.honest_window_points,
            self.sybil_window_points,
            self.sybil_uncapped_potential,
            self.circular_window_points,
            self.straddler_window_points,
            self.cap_violations,
        )
    }
}

/// One emission strategy's bookkeeping (the per-pair sequence law).
struct Pair {
    issuer: Identity,
    contributor: [u8; 32],
    seq: u64,
}

impl Pair {
    fn new(issuer: Identity, contributor: [u8; 32]) -> Self {
        Self {
            issuer,
            contributor,
            seq: 1,
        }
    }

    fn emit(&mut self, kind: ContributionKind, bytes: u64, issued_at: u64) -> ContributionReceipt {
        let receipt = ContributionReceipt::new(
            &self.issuer,
            self.contributor,
            [0x5A; 32],
            kind,
            bytes,
            self.seq,
            issued_at,
        )
        .expect("sim receipt builds within the receipt laws");
        self.seq += 1;
        receipt
    }
}

/// Run the deterministic simulation.
///
/// `k` = the sybil ring's issuer count; `flow` = receipts each family
/// emits per window; `max_bytes` = the byte ceiling per receipt the
/// adversarial families use (the honest family stays far below it).
pub fn run_simulation(
    seed: u64,
    windows: u64,
    k: u64,
    flow: u64,
    max_bytes: u64,
    policy: ValuationPolicy,
) -> SimReport {
    let mut rng = Rng::new(seed);
    let pair_cap = policy.per_pair_window_points();
    let contributor_cap = policy.per_contributor_window_points();
    let mut engine = ValuationEngine::with_policy(policy);
    // Window-grid-aligned base: sim window w spans EXACTLY the engine's
    // absolute window w (window_of(now_base + w*window_secs + off) == w
    // for every off < window_secs) — the sim's per-window accounting and
    // the engine's window law agree by construction.
    let now_base: u64 = 0;
    let window_secs = engine.policy().window_secs();

    // The honest family: one modest pair.
    let mut honest = Pair::new(Identity::from_seed([0x11; 32], now_base, None).unwrap(), [0x21; 32]);
    // The sybil ring: k issuer identities, ONE contributor.
    let sybil_contributor = [0x22; 32];
    let mut ring: Vec<Pair> = (0..k)
        .map(|i| {
            Pair::new(
                Identity::from_seed([0x30 + i as u8; 32], now_base, None).unwrap(),
                sybil_contributor,
            )
        })
        .collect();
    // The circular pair: two nodes acknowledging each other.
    let mut a_to_b = Pair::new(Identity::from_seed([0x41; 32], now_base, None).unwrap(), [0x42; 32]);
    let mut b_to_a = Pair::new(Identity::from_seed([0x42; 32], now_base, None).unwrap(), [0x41; 32]);
    // The straddler: one pair riding window boundaries.
    let mut straddler = Pair::new(Identity::from_seed([0x55; 32], now_base, None).unwrap(), [0x56; 32]);

    let mut steps: u64 = 0;
    let mut honest_total: u64 = 0;
    let mut sybil_total: u64 = 0;
    let mut circular_total: u64 = 0;
    let mut straddler_total: u64 = 0;

    for w in 0..windows {
        let window_start = now_base + w * window_secs;
        // The valuing node runs at the end of the observed span (the
        // caller clock; all receipts are past-dated by construction).
        let now = now_base + (w + 1) * window_secs;
        for _ in 0..flow {
            // honest: modest flow, far below any cap
            let at = window_start + rng.below(window_secs);
            let bytes = 100 + rng.below(400);
            let kind = if rng.below(2) == 0 {
                ContributionKind::Carried
            } else {
                ContributionKind::Delivered
            };
            let v = engine.value(&honest.emit(kind, bytes, at), now);
            honest_total += v.points();
            steps += 1;
            // sybil ring: every issuer maxes its receipts this window
            for pair in ring.iter_mut() {
                let at = window_start + rng.below(window_secs);
                let bytes = max_bytes;
                let v = engine.value(
                    &pair.emit(ContributionKind::Delivered, bytes, at),
                    now,
                );
                sybil_total += v.points();
                steps += 1;
            }
            // circular pair: alternating directions, max bytes
            let at = window_start + rng.below(window_secs);
            let v = engine.value(
                &a_to_b.emit(ContributionKind::Carried, max_bytes, at),
                now,
            );
            circular_total += v.points();
            let at = window_start + rng.below(window_secs);
            let v = engine.value(
                &b_to_a.emit(ContributionKind::Carried, max_bytes, at),
                now,
            );
            circular_total += v.points();
            steps += 2;
            // straddler: LAST slot of this window and FIRST of the next
            // (only when a next window exists)
            let last_slot = window_start + window_secs.saturating_sub(1);
            let v = engine.value(
                &straddler.emit(ContributionKind::Delivered, max_bytes, last_slot),
                now,
            );
            straddler_total += v.points();
            steps += 1;
            if w + 1 < windows {
                let first_slot = window_start + window_secs;
                let next_now = now_base + (w + 2) * window_secs;
                let v = engine.value(
                    &straddler.emit(ContributionKind::Delivered, max_bytes, first_slot),
                    next_now,
                );
                straddler_total += v.points();
                steps += 1;
            }
        }
    }

    // The cap invariant: walk every tracked pair/contributor window and
    // verify the engine's own read views stayed within the caps.
    let mut violations: u64 = 0;
    // (re-derive the tracked pairs from the agents)
    let mut pairs: Vec<(Vec<u8>, [u8; 32])> = vec![
        (honest.issuer.node_id().as_bytes().to_vec(), honest.contributor),
        (a_to_b.issuer.node_id().as_bytes().to_vec(), a_to_b.contributor),
        (b_to_a.issuer.node_id().as_bytes().to_vec(), b_to_a.contributor),
        (straddler.issuer.node_id().as_bytes().to_vec(), straddler.contributor),
    ];
    for pair in ring.iter() {
        pairs.push((pair.issuer.node_id().as_bytes().to_vec(), pair.contributor));
    }
    for w in 0..windows {
        for (issuer, contributor) in pairs.iter() {
            let issuer_id = sharenet_protocol::identity::NodeId::from_bytes(
                issuer.as_slice().try_into().expect("32 bytes"),
            );
            let spent = engine.pair_window_points(&issuer_id, contributor, w);
            if spent > pair_cap {
                violations += 1;
            }
        }
        // the sybil contributor
        if engine.contributor_window_points(&sybil_contributor, w) > contributor_cap {
            violations += 1;
        }
        // the circular pair's two contributors
        for c in [a_to_b.contributor, b_to_a.contributor] {
            if engine.contributor_window_points(&c, w) > contributor_cap {
                violations += 1;
            }
        }
        if engine.contributor_window_points(&honest.contributor, w) > contributor_cap {
            violations += 1;
        }
        if engine.contributor_window_points(&straddler.contributor, w) > contributor_cap {
            violations += 1;
        }
    }

    let windows_eff = windows.max(1);
    SimReport {
        seed,
        windows,
        steps,
        receipts_valued: engine.receipts_valued(),
        receipts_capped: engine.receipts_capped(),
        honest_window_points: honest_total / windows_eff,
        sybil_window_points: sybil_total / windows_eff,
        sybil_uncapped_potential: k.saturating_mul(pair_cap),
        circular_window_points: circular_total / windows_eff,
        straddler_window_points: straddler_total / windows_eff,
        cap_violations: violations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario(seed: u64) -> SimReport {
        // A tight policy so the caps bind inside the sim: window 600s,
        // byte cap 10_000, pair cap 20_000 points, contributor cap
        // 50_000 points; k=8 ring issuers, 5 receipts per family per
        // window, adversarial bytes at the cap.
        run_simulation(
            seed,
            24,
            8,
            5,
            10_000,
            ValuationPolicy::new(600, 10_000, 20_000, 50_000).unwrap(),
        )
    }

    #[test]
    fn cap_invariant_holds_under_every_adversarial_flow() {
        for seed in [1u64, 2, 42, 1_000_007] {
            let report = scenario(seed);
            assert_eq!(
                report.cap_violations, 0,
                "seed {seed}: the caps must never be exceeded"
            );
        }
    }

    #[test]
    fn the_sybil_ring_is_bounded_by_the_contributor_cap() {
        let report = scenario(42);
        // The ring's 8 issuers could have paid 8 x 20_000 = 160_000 per
        // window; the contributor cap bounds the actual award to 50_000.
        assert_eq!(report.sybil_uncapped_potential, 160_000);
        assert!(
            report.sybil_window_points <= 50_000,
            "the ring's per-window award must respect the contributor cap, got {}",
            report.sybil_window_points
        );
        // and it is not trivially zero: the ring DOES collect up to the
        // cap in every window (the first receipts pay in full)
        assert!(
            report.sybil_window_points > 0,
            "the ring's early receipts must pay"
        );
    }

    #[test]
    fn the_circular_pair_is_bounded_by_two_pair_caps() {
        let report = scenario(7);
        // Two directions = two pairs = at most 2 x pair cap per window.
        assert!(
            report.circular_window_points <= 40_000,
            "circular traffic is bounded by the two directional pair caps, got {}",
            report.circular_window_points
        );
        assert!(report.circular_window_points > 0);
    }

    #[test]
    fn identical_seeds_produce_identical_reports() {
        assert_eq!(scenario(1234), scenario(1234));
        assert_eq!(scenario(1234).to_line(), scenario(1234).to_line());
        // and the line form is stable-shaped (the pinned field order)
        assert!(scenario(1234).to_line().starts_with("seed=1234 windows=24"));
    }

    #[test]
    fn different_seeds_still_respect_every_bound() {
        for seed in 1_000u64..1_020 {
            let report = scenario(seed);
            assert_eq!(report.cap_violations, 0);
            assert!(report.sybil_window_points <= 50_000);
            assert!(report.circular_window_points <= 40_000);
            assert!(report.straddler_window_points <= 20_000);
            assert!(report.honest_window_points <= 20_000);
        }
    }
}
