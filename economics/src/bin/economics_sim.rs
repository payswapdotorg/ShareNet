//! `economics_sim` — the R8-002 "simulation" verify level's driver (the
//! propagation_sim pattern): one seed → the deterministic report line on
//! stdout, byte-identical run to run.
//!
//! Usage: `economics_sim [SEED]` (default seed 42). The scenario is the
//! sim.rs test scenario: 24 windows, an 8-issuer sybil ring, a circular
//! pair, a window straddler and an honest baseline, under the tight
//! policy documented below.

use sharenet_economics::sim::run_simulation;
use sharenet_economics::ValuationPolicy;

fn main() {
    let seed: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(42);
    // The sim.rs scenario policy: window 600s, per-receipt byte cap
    // 10_000, pair cap 20_000, contributor cap 50_000.
    let policy = ValuationPolicy::new(600, 10_000, 20_000, 50_000).expect("sim policy");
    let report = run_simulation(seed, 24, 8, 5, 10_000, policy);
    println!("{}", report.to_line());
    if report.cap_violations != 0 {
        // The driver is also a guard: a cap violation fails the run.
        eprintln!(
            "CAP VIOLATIONS: {} — the simulation invariant is broken",
            report.cap_violations
        );
        std::process::exit(1);
    }
}
