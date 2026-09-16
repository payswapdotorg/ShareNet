//! `competitor_sim` — the R10-005 "simulation + reproducibility" verify
//! level's driver (the economics_sim/antigaming_sim pattern): one seed
//! → the deterministic four-week report line on stdout, byte-identical
//! run to run.
//!
//! The scenario (competitor_sim.rs's `run_competitor_simulation`): a
//! month of competition between an honest, failure-gapped cohort and
//! the six R8-005 gamer strategies, over the REAL ledger (the caps
//! bind) with WEEKLY audits by the REAL detector. The driver is also
//! a guard: any false positive on the honest cohort, any missed gamer
//! cohort, or any cap violation fails the run.

use sharenet_economics::antigaming::AntigamingPolicy;
use sharenet_economics::competitor_sim::run_competitor_simulation;
use sharenet_economics::ValuationPolicy;

fn main() {
    let seed: u64 = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(42);
    // The four-week profile under the tight policy (window 600 s,
    // per-receipt byte cap 10_000, pair cap 20_000, contributor cap
    // 50_000): 28 days × 24 windows/day, six honest contributors, 15%
    // of honest windows lost to failures.
    let valuation = ValuationPolicy::new(600, 10_000, 20_000, 50_000).expect("sim policy");
    let report = run_competitor_simulation(
        seed,
        28,
        24,
        6,
        valuation,
        AntigamingPolicy::default(),
        1_500,
    );
    println!("{}", report.to_line());
    if report.honest_false_positives != 0
        || report.cap_violations != 0
        || report.gamer_findings < 6
    {
        eprintln!(
            "SIMULATION INVARIANT BROKEN: false_positives={} cap_violations={} gamer_findings={}",
            report.honest_false_positives, report.cap_violations, report.gamer_findings
        );
        std::process::exit(1);
    }
}
