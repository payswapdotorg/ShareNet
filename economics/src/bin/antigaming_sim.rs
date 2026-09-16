//! `antigaming_sim` — the R8-005 "simulation" verify level's driver
//! (the economics_sim pattern): one seed → the deterministic report
//! line on stdout, byte-identical run to run.
//!
//! The scenario (antigaming.rs's `run_antigaming_simulation`): an
//! honest mesh, a pair farmer, a k-issuer Sybil family, a reciprocal
//! ring, a magnitude repeater, a one-window blaster and a concentrated
//! feeder, all under the tight policy — the detector must name every
//! gaming cohort and NEVER the honest one.

use sharenet_economics::antigaming::{run_antigaming_simulation, AntigamingPolicy};
use sharenet_economics::ValuationPolicy;

fn main() {
    let seed: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(42);
    // The same tight policy as the economics_sim scenario (comparable
    // magnitudes): window 600s, per-receipt byte cap 10_000, pair cap
    // 20_000, contributor cap 50_000.
    let valuation = ValuationPolicy::new(600, 10_000, 20_000, 50_000).expect("sim policy");
    let antigaming = AntigamingPolicy::default();
    let report = run_antigaming_simulation(seed, 12, 5, valuation, antigaming);
    println!("{}", report.to_line());
    if report.false_positives != 0 || report.missed_cohorts != 0 {
        eprintln!(
            "DETECTION FAILURE: false_positives={} missed_cohorts={}",
            report.false_positives, report.missed_cohorts
        );
        std::process::exit(1);
    }
}
