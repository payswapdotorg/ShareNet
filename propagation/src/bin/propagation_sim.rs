//! `propagation_sim` — the R6-005 "simulation" verify level's
//! driver: runs one named scenario with one seed and prints the
//! deterministic trace to stdout (byte-identical across runs, by
//! construction and by test).
//!
//! Usage:
//!
//! ```text
//! propagation_sim <scenario> <seed>
//! propagation_sim all <seed>
//! ```
//!
//! Scenarios: `intermittent-gateway`, `expiry`, `tight-budget`,
//! `ineligible-gateway`, `edge-floors`. Exit codes: 0 ok; 2 usage
//! (unknown scenario / bad seed).

use std::process::ExitCode;

use sharenet_propagation::{run_scenario, scenario_by_name, SCENARIO_NAMES};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [scenario, seed_s] = args.as_slice() else {
        usage();
        return ExitCode::from(2);
    };
    let seed = match seed_s.parse::<u64>() {
        Ok(seed) => seed,
        Err(_) => {
            eprintln!("error: seed must be a u64");
            return ExitCode::from(2);
        }
    };
    if scenario == "all" {
        for name in SCENARIO_NAMES {
            let spec = scenario_by_name(name, seed).expect("named scenario exists");
            print!("{}", run_scenario(spec).trace.render());
        }
        return ExitCode::SUCCESS;
    }
    let Some(spec) = scenario_by_name(scenario, seed) else {
        usage();
        return ExitCode::from(2);
    };
    print!("{}", run_scenario(spec).trace.render());
    ExitCode::SUCCESS
}

fn usage() {
    eprintln!("usage: propagation_sim <scenario> <seed>");
    eprintln!("       propagation_sim all <seed>");
    eprintln!("scenarios: {}", SCENARIO_NAMES.join(", "));
}
