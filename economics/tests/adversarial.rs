//! R8-002 adversarial tests: the valuation formula under attacks that
//! respect the receipt-layer laws (every receipt here is a
//! well-formed, well-signed-when-it-came-from-the-ledger object — the
//! attacks aim at the VALUATION layer's own arithmetic: cap evasion,
//! window games, Sybil rings, circular traffic, byte inflation,
//! re-valuation replays and clock games).
//!
//! The central properties under attack:
//!
//! - the caps are UNCONDITIONAL: no ordering, no timing, no identity
//!   arrangement lets any (pair, window) or (contributor, window)
//!   total exceed its cap;
//! - the formula is EXPLICIT: every award reports the exact arithmetic;
//! - the engine is idempotent (re-valuation pays nothing) and
//!   future-closed (a clock-ahead receipt refuses);
//! - the anti-gaming minimums (§14) hold numerically.

mod common;

use common::*;
use sharenet_economics::{
    CapKind, ValuationEngine, ValuationPolicy, ValuationVerdict, VALUATION_FORMULA_VERSION,
};
use sharenet_protocol::contribution::ContributionKind;
use sharenet_protocol::identity::Identity;
use sharenet_protocol::contribution::ContributionReceipt;

const NOW: u64 = 1_700_000_000;

/// A tight policy for adversarial play: 100s windows, 1_000-byte
/// per-receipt cap, 500-point pair cap, 800-point contributor cap.
fn tight_policy() -> ValuationPolicy {
    ValuationPolicy::new(100, 1_000, 500, 800).expect("tight policy")
}

#[test]
fn the_formula_version_is_pinned() {
    // The versioned-formula law: this suite is written against v1.
    assert_eq!(VALUATION_FORMULA_VERSION, 1);
}

#[test]
fn byte_inflation_is_capped_per_receipt() {
    // The attacker issues maximal receipts (2^40 bytes — the receipt
    // law's own ceiling): each one bills at most the per-receipt cap.
    let issuer = id(0x11);
    let contributor = [0x22; 32];
    let mut engine = ValuationEngine::with_policy(tight_policy());
    let v = engine.value(
        &receipt(&issuer, &contributor, ContributionKind::Delivered, 1 << 40, 1, NOW),
        NOW + 10,
    );
    match &v {
        ValuationVerdict::Awarded(a) => {
            // intrinsic = 1.5x * min(2^40, 1000) = 1500 points
            assert_eq!(a.intrinsic_points, 1_500);
            assert_eq!(a.billable_bytes, 1_000);
        }
        other => panic!("inflated receipt is still valued, got {other:?}"),
    }
}

#[test]
fn the_sybil_ring_cannot_multiply_past_the_contributor_cap() {
    // Twelve colluding issuers, ONE contributor, maximal receipts, all
    // in one window: the pair caps would allow 12 x 500 = 6000; the
    // contributor cap stops the total at 800 exactly.
    let contributor = [0x22; 32];
    let mut engine = ValuationEngine::with_policy(tight_policy());
    let issuers: Vec<_> = (0u8..12).map(|i| id(0x30 + i)).collect();
    for (round, issuer) in issuers.iter().enumerate() {
        let v = engine.value(
            &receipt(issuer, &contributor, ContributionKind::Delivered, 1_000, 1, NOW),
            NOW,
        );
        // each issuer's own pair pays at most 500 (its own pair cap)
        let w = engine.policy().window_of(NOW);
        assert!(
            engine.pair_window_points(&issuer.node_id(), &contributor, w) <= 500,
            "round {round}: pair cap broken"
        );
    }
    let w = engine.policy().window_of(NOW);
    assert_eq!(
        engine.contributor_window_points(&contributor, w),
        800,
        "the ring must stop exactly at the contributor cap"
    );
    // the per-pair totals sum to far more than the contributor got:
    // the caps did their job, the excess receipts are zero-awards
    assert!(engine.receipts_capped() > 0);
}

#[test]
fn circular_traffic_is_bounded_by_the_directional_pair_caps() {
    // A acknowledges B; B acknowledges A. Two pairs, one goal: farm
    // points by trading bytes. Each direction pays at most its pair
    // cap; NEITHER contributor can exceed the contributor cap either.
    let node_a = id(0x41);
    let node_b = id(0x42);
    let a_bytes = *node_b.node_id().as_bytes();
    let b_bytes = *node_a.node_id().as_bytes();
    let mut engine = ValuationEngine::with_policy(tight_policy());
    for round in 1..=8u64 {
        engine.value(
            &receipt(&node_a, &a_bytes, ContributionKind::Carried, 1_000, round, NOW),
            NOW,
        );
        engine.value(
            &receipt(&node_b, &b_bytes, ContributionKind::Carried, 1_000, round, NOW),
            NOW,
        );
    }
    let w = engine.policy().window_of(NOW);
    assert_eq!(
        engine.pair_window_points(&node_a.node_id(), &a_bytes, w),
        500,
        "direction A->B stops at its pair cap"
    );
    assert_eq!(
        engine.pair_window_points(&node_b.node_id(), &b_bytes, w),
        500,
        "direction B->A stops at its pair cap"
    );
    assert_eq!(engine.contributor_window_points(&a_bytes, w), 500);
    assert_eq!(engine.contributor_window_points(&b_bytes, w), 500);
    // total farmed by the pair: 1000, exactly 2 x pair cap — bounded.
    assert_eq!(engine.total_points(), 1_000);
}

#[test]
fn window_straddling_never_double_bills_one_window() {
    // Receipts at the LAST slot of window w and the FIRST slot of w+1:
    // legal, and each window accrues its OWN cap — but a receipt never
    // counts twice in one window, and no window's total exceeds its cap.
    let issuer = id(0x55);
    let contributor = [0x56; 32];
    let mut engine = ValuationEngine::with_policy(tight_policy());
    // window 0: [0, 100); boundary slot 99; window 1: [100, 200); slot 100
    let last = 99;
    let first = 100;
    engine.value(
        &receipt(&issuer, &contributor, ContributionKind::Delivered, 1_000, 1, last),
        NOW,
    );
    engine.value(
        &receipt(&issuer, &contributor, ContributionKind::Delivered, 1_000, 2, first),
        NOW,
    );
    // fill window 0 to the brim and past it
    for seq in 3..=10u64 {
        engine.value(
            &receipt(&issuer, &contributor, ContributionKind::Delivered, 1_000, seq, last),
            NOW,
        );
        engine.value(
            &receipt(&issuer, &contributor, ContributionKind::Delivered, 1_000, seq + 100, first),
            NOW,
        );
    }
    assert_eq!(engine.pair_window_points(&issuer.node_id(), &contributor, 0), 500);
    assert_eq!(engine.pair_window_points(&issuer.node_id(), &contributor, 1), 500);
    assert!(engine.total_points() <= 1_000, "two windows, two caps, no more");
    assert_eq!(engine.total_points(), 1_000);
}

#[test]
fn revaluation_replays_pay_nothing() {
    // The full replay family: the same receipt re-delivered many times,
    // and a byte-identical REBUILD (same fields) — all one receipt_id.
    let issuer = id(0x11);
    let contributor = [0x22; 32];
    let mut engine = ValuationEngine::new();
    let r = receipt(&issuer, &contributor, ContributionKind::Carried, 500, 1, NOW);
    let first = engine.value(&r, NOW);
    assert_eq!(first.points(), 500);
    for _ in 0..10 {
        let replay = receipt(&issuer, &contributor, ContributionKind::Carried, 500, 1, NOW);
        match engine.value(&replay, NOW) {
            ValuationVerdict::Duplicate { .. } => {}
            other => panic!("replay must be Duplicate, got {other:?}"),
        }
    }
    assert_eq!(engine.total_points(), 500);
    assert_eq!(engine.receipts_valued(), 1);
}

#[test]
fn sequence_splitting_spreads_windows_but_each_window_is_capped() {
    // The attacker spreads its flow across many windows (legal — the
    // caps are per-window). The valuation must pay each window up to
    // its cap and no more; the AMPLIFICATION is bounded by
    // windows x pair cap, never more.
    let issuer = id(0x66);
    let contributor = [0x77; 32];
    let mut engine = ValuationEngine::with_policy(tight_policy());
    let mut seq = 1u64;
    for w in 0..10u64 {
        for _ in 0..5 {
            let at = w * 100 + 50;
            engine.value(
                &receipt(&issuer, &contributor, ContributionKind::Delivered, 1_000, seq, at),
                at + 10,
            );
            seq += 1;
        }
        assert_eq!(
            engine.pair_window_points(&issuer.node_id(), &contributor, w),
            500,
            "window {w}"
        );
    }
    assert_eq!(engine.total_points(), 10 * 500);
}

#[test]
fn clock_games_are_refused_typed_and_reversible() {
    // A receipt dated ahead of the valuing clock refuses; the SAME
    // receipt values at a later clock (nothing was moved by the
    // refusal — the caps were not consumed by the refused attempt).
    let issuer = id0();
    let contributor = [0x88; 32];
    let mut engine = ValuationEngine::with_policy(tight_policy());
    let at = NOW + 1_000;
    let r = receipt(&issuer, &contributor, ContributionKind::Carried, 1_000, 1, at);
    match engine.value(&r, NOW) {
        ValuationVerdict::Refused(e) => assert_eq!(e.name(), "issued_at_in_future"),
        other => panic!("clock-ahead receipt must refuse, got {other:?}"),
    }
    assert_eq!(engine.total_points(), 0);
    // now the clock catches up: full pay (the refusal consumed nothing)
    let v = engine.value(&r, at + 1);
    assert_eq!(v.points(), 500);
}

#[test]
fn cap_remainder_exactness_and_bound_reports() {
    // The exact remainder law: intrinsic 400 with 250 remaining pays
    // exactly 250 and reports the binding cap; the NEXT receipt in the
    // same window pays 0 (still Awarded, still counted as evidence).
    let issuer = id0();
    let contributor = [0x99; 32];
    let mut engine = ValuationEngine::with_policy(tight_policy());
    // burn 250 of the 500 pair cap
    engine.value(
        &receipt(&issuer, &contributor, ContributionKind::Carried, 250, 1, NOW),
        NOW,
    );
    let v = engine.value(
        &receipt(&issuer, &contributor, ContributionKind::Carried, 400, 2, NOW),
        NOW,
    );
    match &v {
        ValuationVerdict::Awarded(a) => {
            assert_eq!(a.intrinsic_points, 400);
            assert_eq!(a.awarded_points, 250);
            assert_eq!(a.bound_by, Some(CapKind::PairWindow));
        }
        other => panic!("partial-cap receipt is Awarded, got {other:?}"),
    }
    let z = engine.value(
        &receipt(&issuer, &contributor, ContributionKind::Delivered, 700, 3, NOW),
        NOW,
    );
    match &z {
        ValuationVerdict::Awarded(a) => {
            assert_eq!(a.awarded_points, 0);
            assert!(a.bound_by.is_some());
        }
        other => panic!("exhausted receipt is a zero Awarded, got {other:?}"),
    }
    assert_eq!(engine.total_points(), 500);
    assert_eq!(engine.receipts_capped(), 2);
}

#[test]
fn kind_weighting_rewards_terminal_delivery_more() {
    // The contribution-quality weighting: equal bytes, delivered > carried.
    let issuer = id0();
    let c1 = [0xA1; 32];
    let c2 = [0xA2; 32];
    let mut engine = ValuationEngine::new();
    let carried = engine.value(
        &receipt(&issuer, &c1, ContributionKind::Carried, 1_000, 1, NOW),
        NOW,
    );
    let delivered = engine.value(
        &receipt(&issuer, &c2, ContributionKind::Delivered, 1_000, 1, NOW),
        NOW,
    );
    assert_eq!(carried.points(), 1_000);
    assert_eq!(delivered.points(), 1_500);
}

#[test]
fn determinism_identical_streams_identical_outcomes() {
    // The same receipt stream valued twice produces identical totals.
    let build = || {
        let issuer = id(0xB1);
        let contributor = [0xB2; 32];
        let mut engine = ValuationEngine::with_policy(tight_policy());
        for seq in 1..=12u64 {
            let at = (seq % 3) * 100 + 50;
            engine.value(
                &receipt(
                    &issuer,
                    &contributor,
                    if seq % 2 == 0 {
                        ContributionKind::Carried
                    } else {
                        ContributionKind::Delivered
                    },
                    100 * seq,
                    seq,
                    at,
                ),
                at + 10,
            );
        }
        engine
    };
    let a = build();
    let b = build();
    assert_eq!(a.total_points(), b.total_points());
    assert_eq!(a.receipts_valued(), b.receipts_valued());
    assert_eq!(a.receipts_capped(), b.receipts_capped());
    assert_eq!(a.total_points() > 0, true);
}

#[test]
fn many_issuers_one_contributor_exact_sybil_bound() {
    // The precise bound: with pair cap P and contributor cap C, k
    // issuers can pay the contributor at most C per window — no matter
    // how large k grows (the amplification SATURATES at C).
    let contributor = [0xC1; 32];
    for k in [2usize, 5, 20, 100] {
        let mut engine = ValuationEngine::with_policy(tight_policy());
        let issuers: Vec<_> = (0u8..k.min(200) as u8).map(|i| id(0xD0 + (i % 20))).collect();
        let issuers: Vec<_> = if k <= 20 {
            issuers
        } else {
            // beyond 20 distinct seed bytes, reuse identities via
            // distinct seed patterns
            (0..k)
                .map(|i| {
                    let mut seed = [0xD5u8; 32];
                    seed[0] = (i % 256) as u8;
                    seed[1] = ((i / 256) & 0xFF) as u8;
                    Identity::from_seed(seed, NOW, None).unwrap()
                })
                .collect()
        };
        for issuer in issuers.iter() {
            engine.value(
                &receipt(issuer, &contributor, ContributionKind::Delivered, 1_000, 1, NOW),
                NOW,
            );
        }
        let w = engine.policy().window_of(NOW);
        let paid = engine.contributor_window_points(&contributor, w);
        assert!(
            paid <= 800,
            "k={k}: the contributor cap is the hard bound, got {paid}"
        );
        // with k >= 1 max-byte receipts the cap is reached exactly
        if k >= 1 {
            assert_eq!(paid, 800, "k={k}: maximal flow reaches the cap exactly");
        }
    }
}

#[test]
fn negative_and_zero_policy_is_refused_typed() {
    // The policy constructor refuses degenerate bounds (fail-closed).
    assert!(ValuationPolicy::new(0, 100, 10, 10).is_err());
    assert!(ValuationPolicy::new(10, 0, 10, 10).is_err());
    assert!(ValuationPolicy::new(10, 100, 0, 10).is_err());
    assert!(ValuationPolicy::new(10, 100, 10, 0).is_err());
    assert!(ValuationPolicy::new(10, 100, 10, 10).is_ok());
}

/// The engine never panics on adversarial field arrangements it can
/// legally see (bounded bytes, extreme sequences, boundary clocks).
#[test]
fn extreme_legal_fields_never_panic() {
    let issuer = id(0xE1);
    let contributor = [0xE2; 32];
    let mut engine = ValuationEngine::with_policy(ValuationPolicy::new(1, 1 << 40, 1, u64::MAX / 4).unwrap());
    // window_secs = 1: every second is its own window
    for at in 0..50u64 {
        let v = engine.value(
            &receipt(&issuer, &contributor, ContributionKind::Delivered, 1 << 40, at + 1, at),
            at,
        );
        assert!(matches!(v, ValuationVerdict::Awarded(_)));
    }
    // all awards landed in distinct windows, each paid its tiny pair cap
    assert!(engine.total_points() > 0);
}
