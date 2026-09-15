//! Sliding-window statistics over [`LinkQualitySample`]s (R2-004).
//!
//! Pure functions: `&[LinkQualitySample] -> LinkQualitySummary`. No clocks,
//! no I/O, no state — **deterministic** (the same input slice always yields
//! the same summary, which is why the R3-003 topology evidence layer can
//! re-derive summaries from raw samples and get identical results).
//!
//! ## Pipeline (documented, applied in this order)
//!
//! 1. **Empty input** → typed error [`TelemetryError::EmptyWindow`] (a caller
//!    that never measured must not receive a plausible zero summary).
//! 2. **Stable sort by `seq`** — out-of-order insertion cannot change the
//!    result; summaries are identical to sorted input.
//! 3. **Dedup by `seq`** — duplicates (buggy inserters, stream replays) are
//!    collapsed: if a seq has both lost and delivered variants, the
//!    DELIVERED one wins (a pong did come back — more truthful); otherwise
//!    the first occurrence in stable order wins. Exactly one sample survives
//!    per seq.
//! 4. **Clock-skew check** — a DELIVERED sample with `rtt_micros == 0` means
//!    the pong was timestamped at or before the ping. That is skew evidence:
//!    the whole summary is refused with [`TelemetryError::ClockSkew`] naming
//!    the offending seq. Never clamped, never silently dropped.
//! 5. Lost samples count toward `loss_ratio` and are **excluded** from all
//!    RTT statistics; their payloads count toward neither throughput nor
//!    delivered bytes.
//!
//! ## EWMA (documented formula and its bounded influence)
//!
//! Over delivered samples in seq order:
//!
//! ```text
//! ewma_0 = x_0
//! ewma_i = alpha * x_i + (1 - alpha) * ewma_(i-1)
//! ```
//!
//! with the default `alpha = `[`DEFAULT_EWMA_ALPHA`]` = 0.2. Expanding, the
//! final EWMA is a convex combination of the delivered RTTs, where the weight
//! of every sample except the first is exactly
//! `alpha * (1-alpha)^(n-1-i) <= alpha`. Consequences (tested):
//!
//! * a single outlier can move the EWMA by at most `alpha * (outlier -
//!   current)` — with the default alpha, 20% of the gap, never the full gap;
//! * the outlier's influence decays geometrically (`(1-alpha)^k` after k
//!   further samples);
//! * the EWMA always stays within `[min(rtt), max(rtt)]` of the delivered
//!   samples (convex combination).
//!
//! ## Percentiles (documented method)
//!
//! Order statistics with linear interpolation (the standard "linear" /
//! numpy-default method): for the sorted delivered RTTs `x_0..x_(n-1)` and
//! percentile `q`, position `p = (n-1) * q / 100`, value
//! `x_floor(p) + (p - floor(p)) * (x_ceil(p) - x_floor(p))`, rounded to the
//! nearest microsecond. The interpolant is monotone in `q`, so
//! **`p95 >= p50` always holds** (the ordering invariant asserted by the
//! integration tests).
//!
//! ## Jitter (documented)
//!
//! Median absolute deviation (MAD) of the delivered RTTs: the median of
//! `|x_i - median(x)|`, using the same percentile method at q=50.
//!
//! ## Throughput (documented, honestly an *estimate*)
//!
//! `throughput_bps = 8 * sum(delivered payload_bytes) / window_seconds`,
//! where the window is `max(sent_at) - min(sent_at)` over ALL deduped
//! samples (delivered and lost — lost attempts still occupy measurement
//! time). This is the **observed delivered-payload rate of the probe
//! traffic**, NOT a link capacity measurement (capacity would require bulk
//! transfer, which is future tunnel-layer work). When the window is 0
//! (single sample, or all samples share a timestamp) the estimate is
//! reported as `0` — a division by zero is never silently faked.
//!
//! ## All-lost windows
//!
//! A window where every probe was lost is REAL evidence and summarizes
//! successfully: `delivered == 0`, `loss_ratio == 1.0`, and all RTT fields
//! are `0` (documented: callers must check `delivered > 0` before reading
//! RTT fields).

use crate::error::{Result, TelemetryError};
use crate::sample::LinkQualitySample;

/// Default EWMA smoothing factor (weight of the newest sample).
pub const DEFAULT_EWMA_ALPHA: f64 = 0.2;

/// Summary of one link quality window.
///
/// RTT fields (`ewma_rtt_micros`, `p50_rtt_micros`, `p95_rtt_micros`,
/// `jitter_mad_micros`) are meaningful only when `delivered > 0`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LinkQualitySummary {
    /// Number of deduped samples with a pong.
    pub delivered: usize,
    /// Number of deduped samples with no pong within the retry budget.
    pub lost: usize,
    /// EWMA of delivered RTTs (microseconds), default alpha.
    pub ewma_rtt_micros: u64,
    /// Median absolute deviation of delivered RTTs (microseconds).
    pub jitter_mad_micros: u64,
    /// lost / total over deduped samples.
    pub loss_ratio: f64,
    /// 50th percentile of delivered RTTs (microseconds).
    pub p50_rtt_micros: u64,
    /// 95th percentile of delivered RTTs (microseconds). `>= p50`.
    pub p95_rtt_micros: u64,
    /// Observed delivered-payload rate of the probe traffic (bits/second).
    /// 0 when the window has no time span.
    pub throughput_bps: u64,
}

impl LinkQualitySummary {
    /// Whether any RTT statistic in this summary is meaningful.
    pub fn has_rtt_stats(&self) -> bool {
        self.delivered > 0
    }
}

/// Summarize with the default EWMA alpha (0.2).
pub fn summarize(samples: &[LinkQualitySample]) -> Result<LinkQualitySummary> {
    summarize_with_alpha(samples, DEFAULT_EWMA_ALPHA)
}

/// Summarize with an explicit EWMA alpha (must be in `(0.0, 1.0]`).
pub fn summarize_with_alpha(samples: &[LinkQualitySample], alpha: f64) -> Result<LinkQualitySummary> {
    if samples.is_empty() {
        return Err(TelemetryError::EmptyWindow);
    }
    if !(alpha > 0.0 && alpha <= 1.0) {
        return Err(TelemetryError::InvalidAlpha { alpha });
    }

    // (2) stable sort by seq; (3) dedup: delivered beats lost, else first wins.
    let mut sorted: Vec<&LinkQualitySample> = samples.iter().collect();
    sorted.sort_by_key(|s| s.seq);
    let mut deduped: Vec<&LinkQualitySample> = Vec::with_capacity(sorted.len());
    for s in sorted {
        match deduped.last_mut() {
            Some(prev) if prev.seq == s.seq => {
                // Duplicate seq. Policy: a delivered variant replaces a lost
                // one (a pong came back — more truthful); anything else keeps
                // the first (stable, deterministic).
                if prev.lost && !s.lost {
                    *prev = s;
                }
            }
            _ => deduped.push(s),
        }
    }

    // (4) clock-skew check over DELIVERED samples (lost samples carry a
    // structural rtt of 0 and are excluded by construction).
    if let Some(s) = deduped.iter().find(|s| !s.lost && s.rtt_micros == 0) {
        return Err(TelemetryError::ClockSkew { seq: s.seq });
    }

    let delivered: Vec<&LinkQualitySample> = deduped.iter().copied().filter(|s| !s.lost).collect();
    let lost_count = deduped.len() - delivered.len();

    if delivered.is_empty() {
        // All-lost window: real evidence, summarized honestly.
        return Ok(LinkQualitySummary {
            delivered: 0,
            lost: lost_count,
            ewma_rtt_micros: 0,
            jitter_mad_micros: 0,
            loss_ratio: 1.0,
            p50_rtt_micros: 0,
            p95_rtt_micros: 0,
            throughput_bps: 0,
        });
    }

    // EWMA runs in SEQ order (temporal order — an exponential smoother over
    // time), NOT over the value-sorted array below.
    let ewma = ewma_over(delivered.iter().map(|s| s.rtt_micros), alpha);

    // Percentiles and MAD run over the value-sorted RTTs (order statistics).
    let mut rtts: Vec<u64> = delivered.iter().map(|s| s.rtt_micros).collect();
    rtts.sort_unstable();
    let p50 = percentile(&rtts, 50.0);
    let p95 = percentile(&rtts, 95.0);
    let mad = {
        let median = p50 as f64;
        let mut deviations: Vec<f64> = rtts.iter().map(|r| (*r as f64 - median).abs()).collect();
        deviations.sort_by(|a, b| a.partial_cmp(b).expect("deviations are finite (u64-derived)"));
        percentile_f64(&deviations, 50.0).round() as u64
    };

    let total = deduped.len() as f64;
    let loss_ratio = lost_count as f64 / total;

    // Throughput: delivered payload bytes over the full observation window.
    let min_sent = deduped.iter().map(|s| s.sent_at_unix_nanos).min().expect("non-empty");
    let max_sent = deduped.iter().map(|s| s.sent_at_unix_nanos).max().expect("non-empty");
    let window_nanos = max_sent.saturating_sub(min_sent);
    let delivered_bytes: u64 = delivered.iter().map(|s| s.payload_bytes as u64).sum();
    let throughput_bps = if window_nanos == 0 {
        0
    } else {
        let bits = (delivered_bytes as u128) * 8;
        let secs = window_nanos as f64 / 1_000_000_000.0;
        (bits as f64 / secs).round() as u64
    };

    Ok(LinkQualitySummary {
        delivered: delivered.len(),
        lost: lost_count,
        ewma_rtt_micros: ewma,
        jitter_mad_micros: mad,
        loss_ratio,
        p50_rtt_micros: p50,
        p95_rtt_micros: p95,
        throughput_bps,
    })
}

/// EWMA over delivered RTTs in the caller's order (seq/temporal order —
/// the documented semantics; a value sort would destroy the time axis).
fn ewma_over<I: IntoIterator<Item = u64>>(rtts: I, alpha: f64) -> u64 {
    let mut iter = rtts.into_iter();
    let mut ewma = match iter.next() {
        Some(x) => x as f64,
        None => return 0, // unreachable: callers guarantee non-empty delivered
    };
    for x in iter {
        ewma = alpha * (x as f64) + (1.0 - alpha) * ewma;
    }
    ewma.round() as u64
}

/// q-th percentile (0..=100) of a SORTED-ascending slice, linear
/// interpolation, rounded to nearest u64.
fn percentile(sorted: &[u64], q: f64) -> u64 {
    percentile_f64(
        &sorted.iter().map(|&x| x as f64).collect::<Vec<_>>(),
        q,
    )
    .round() as u64
}

/// q-th percentile of a SORTED-ascending f64 slice via linear interpolation
/// on the order statistics: position p = (n-1)*q/100.
fn percentile_f64(sorted: &[f64], q: f64) -> f64 {
    let n = sorted.len();
    debug_assert!(n > 0, "caller guarantees non-empty");
    if n == 1 {
        return sorted[0];
    }
    let p = (n as f64 - 1.0) * q / 100.0;
    let lo = p.floor() as usize;
    let hi = p.ceil() as usize;
    if lo == hi {
        sorted[lo]
    } else {
        let frac = p - lo as f64;
        sorted[lo] + frac * (sorted[hi] - sorted[lo])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::LinkQualitySample;

    fn d(seq: u64, rtt: u64, sent_nanos: u64, bytes: u32) -> LinkQualitySample {
        LinkQualitySample::delivered(0, seq, sent_nanos, rtt, bytes)
    }

    fn l(seq: u64, sent_nanos: u64, bytes: u32) -> LinkQualitySample {
        LinkQualitySample::lost(0, seq, sent_nanos, bytes)
    }

    #[test]
    fn empty_window_is_typed_error() {
        assert!(matches!(summarize(&[]), Err(TelemetryError::EmptyWindow)));
    }

    #[test]
    fn invalid_alpha_is_typed_error() {
        let s = vec![d(0, 100, 0, 64)];
        for bad in [0.0, -0.1, 1.5, f64::NAN] {
            assert!(
                matches!(summarize_with_alpha(&s, bad), Err(TelemetryError::InvalidAlpha { .. })),
                "alpha {bad} must be rejected"
            );
        }
    }

    #[test]
    fn single_sample_summary() {
        let s = summarize(&[d(0, 120, 5_000, 64)]).unwrap();
        assert_eq!(s.delivered, 1);
        assert_eq!(s.lost, 0);
        assert_eq!(s.ewma_rtt_micros, 120);
        assert_eq!(s.p50_rtt_micros, 120);
        assert_eq!(s.p95_rtt_micros, 120);
        assert_eq!(s.jitter_mad_micros, 0);
        assert_eq!(s.loss_ratio, 0.0);
        assert_eq!(s.throughput_bps, 0, "zero time span -> throughput 0");
        assert!(s.has_rtt_stats());
    }

    #[test]
    fn out_of_order_input_matches_sorted_input() {
        let sorted = vec![d(0, 100, 0, 64), d(1, 150, 1_000, 64), d(2, 120, 2_000, 64)];
        let shuffled = vec![sorted[2].clone(), sorted[0].clone(), sorted[1].clone()];
        assert_eq!(summarize(&sorted).unwrap(), summarize(&shuffled).unwrap());
    }

    #[test]
    fn duplicate_seq_dedup_delivered_beats_lost() {
        // seq=1 appears twice: lost first, delivered second -> delivered wins.
        let s = summarize(&[l(1, 0, 64), d(1, 200, 0, 64)]).unwrap();
        assert_eq!(s.delivered, 1, "delivered duplicate must win");
        assert_eq!(s.lost, 0);
        assert_eq!(s.ewma_rtt_micros, 200);
        // And the reverse insertion order gives the same answer (determinism).
        let s2 = summarize(&[d(1, 200, 0, 64), l(1, 0, 64)]).unwrap();
        assert_eq!(s, s2);
    }

    #[test]
    fn duplicate_seq_both_delivered_keeps_first() {
        let s = summarize(&[d(1, 100, 0, 64), d(1, 900, 0, 64)]).unwrap();
        assert_eq!(s.delivered, 1);
        assert_eq!(s.ewma_rtt_micros, 100, "stable policy: first occurrence wins");
    }

    #[test]
    fn delivered_rtt_zero_is_rejected_as_clock_skew() {
        let err = summarize(&[d(0, 50, 0, 64), d(1, 0, 1_000, 64)]).unwrap_err();
        match err {
            TelemetryError::ClockSkew { seq } => assert_eq!(seq, 1),
            other => panic!("expected ClockSkew, got {other:?}"),
        }
    }

    #[test]
    fn lost_samples_count_in_loss_but_not_rtt() {
        let s = summarize(&[d(0, 100, 0, 64), l(1, 1_000, 64), d(2, 300, 2_000, 64), l(3, 3_000, 64)])
            .unwrap();
        assert_eq!(s.delivered, 2);
        assert_eq!(s.lost, 2);
        assert!((s.loss_ratio - 0.5).abs() < 1e-12);
        // EWMA over [100, 300] in seq order: 100 then 0.2*300+0.8*100 = 140.
        assert_eq!(s.ewma_rtt_micros, 140);
        // Percentiles over delivered only: sorted [100, 300].
        assert_eq!(s.p50_rtt_micros, 200);
        // p95: position (2-1)*0.95 = 0.95 -> 100 + 0.95*200 = 290.
        assert_eq!(s.p95_rtt_micros, 290);
    }

    #[test]
    fn all_lost_window_summarizes_with_full_loss() {
        let s = summarize(&[l(0, 0, 64), l(1, 1_000, 64)]).unwrap();
        assert_eq!(s.delivered, 0);
        assert_eq!(s.lost, 2);
        assert!((s.loss_ratio - 1.0).abs() < 1e-12);
        assert_eq!(s.p95_rtt_micros, 0);
        assert!(!s.has_rtt_stats());
        assert_eq!(s.throughput_bps, 0);
    }

    #[test]
    fn giant_outlier_influence_is_bounded_by_alpha() {
        // 20 normal samples at 100us -> ewma exactly 100.
        let mut samples: Vec<LinkQualitySample> = (0..20).map(|i| d(i, 100, i as u64 * 1_000, 64)).collect();
        let before = summarize(&samples).unwrap().ewma_rtt_micros;
        assert_eq!(before, 100);
        // One giant outlier (60 seconds) as the LAST sample.
        samples.push(d(20, 60_000_000, 20_000, 64));
        let after = summarize(&samples).unwrap().ewma_rtt_micros;
        // Exact bound for a last-position sample: alpha*outlier + (1-alpha)*before.
        let bound = 0.2 * 60_000_000.0 + 0.8 * 100.0;
        assert!(
            after as f64 <= bound + 1.0,
            "EWMA after outlier {after} must stay <= alpha*outlier + (1-alpha)*prev = {bound}"
        );
        assert!(after < 60_000_000, "outlier must not dominate the estimate");
        // Influence decays: 10 further normal samples shrink it geometrically.
        for i in 21..31 {
            samples.push(d(i, 100, i as u64 * 1_000, 64));
        }
        let decayed = summarize(&samples).unwrap().ewma_rtt_micros;
        let expected = 0.8f64.powi(10) * bound + (1.0 - 0.8f64.powi(10)) * 100.0;
        assert!(
            (decayed as f64 - expected).abs() < 5.0,
            "decayed {decayed} should approach {expected}"
        );
    }

    #[test]
    fn ewma_is_within_min_max_of_delivered_samples() {
        let samples = vec![d(0, 50, 0, 64), d(1, 5_000, 1_000, 64), d(2, 80, 2_000, 64), d(3, 9_000, 3_000, 64)];
        let s = summarize(&samples).unwrap();
        assert!(s.ewma_rtt_micros >= 50 && s.ewma_rtt_micros <= 9_000);
    }

    #[test]
    fn p95_is_at_least_p50() {
        // Distinct values so interpolation matters.
        let samples: Vec<LinkQualitySample> = (0..10).map(|i| d(i, 100 + i * 10, i * 1_000, 64)).collect();
        let s = summarize(&samples).unwrap();
        assert!(s.p95_rtt_micros >= s.p50_rtt_micros, "p95 {} < p50 {}", s.p95_rtt_micros, s.p50_rtt_micros);
    }

    #[test]
    fn throughput_is_delivered_bytes_over_window() {
        // 10 delivered samples of 1000 bytes, window = 1 second.
        let samples: Vec<LinkQualitySample> =
            (0..10).map(|i| d(i, 100, i * 100_000_000, 1_000)).collect();
        let s = summarize(&samples).unwrap();
        // bytes 10_000 over 0.9s window (0..9 * 100ms): 10_000/0.9 * 8
        let expected = (10_000.0_f64 / 0.9 * 8.0).round() as u64;
        assert_eq!(s.throughput_bps, expected);
        // One lost sample INSIDE the window: delivered bytes (and the
        // window) are unchanged -> same throughput; lost payload bytes
        // never count as delivered.
        let mut with_loss = samples.clone();
        with_loss.push(l(10, 450_000_000, 1_000));
        let s2 = summarize(&with_loss).unwrap();
        assert_eq!(s2.throughput_bps, expected, "lost payload must not count as delivered bytes");
        assert_eq!(s2.lost, 1);
        // A trailing lost sample extends the observation window (it occupied
        // measurement time) -> the same delivered bytes spread wider.
        let mut trailing = samples.clone();
        trailing.push(l(10, 950_000_000, 1_000));
        let s3 = summarize(&trailing).unwrap();
        let expected_wide = (10_000.0_f64 / 0.95 * 8.0).round() as u64;
        assert_eq!(s3.throughput_bps, expected_wide);
    }

    #[test]
    fn determinism_same_input_same_output() {
        let samples: Vec<LinkQualitySample> = (0..50)
            .map(|i| if i % 7 == 3 { l(i, i * 1_000, 64) } else { d(i, 80 + (i % 5) * 25, i * 1_000, 64) })
            .collect();
        let a = summarize(&samples).unwrap();
        let b = summarize(&samples).unwrap();
        assert_eq!(a, b);
        // And a re-shuffled copy still summarizes identically.
        let mut shuffled = samples.clone();
        shuffled.reverse();
        assert_eq!(a, summarize(&shuffled).unwrap());
    }

    #[test]
    fn percentile_interpolation_matches_order_statistics() {
        // 4 sorted values [100, 200, 300, 400]:
        // p50 -> position 1.5 -> 250; p95 -> position 2.85 -> 385.
        let samples = vec![d(0, 100, 0, 64), d(1, 200, 1, 64), d(2, 300, 2, 64), d(3, 400, 3, 64)];
        let s = summarize(&samples).unwrap();
        assert_eq!(s.p50_rtt_micros, 250);
        assert_eq!(s.p95_rtt_micros, 385);
        // MAD: median=250, deviations [150,50,50,150], median = 100.
        assert_eq!(s.jitter_mad_micros, 100);
    }
}
