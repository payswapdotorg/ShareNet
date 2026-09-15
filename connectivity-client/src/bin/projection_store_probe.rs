//! `projection_store_probe` — TEST SCAFFOLDING for the R5-003 "restart"
//! verification: a REAL separate process that loads the durable local
//! health projection from disk, reports its re-derived state + typed
//! freshness, and (for the `accept` subcommand) continues the projection by
//! accepting one observation and flushing — proving the store survives a
//! process boundary with state intact and no sequence regression.
//!
//! The ShareNet daemon restart is modeled as: epoch 1 writes the store,
//! epoch 2 (THIS binary, a fresh process) reloads it from disk only.
//!
//! Usage:
//!
//! ```text
//! projection_store_probe inspect <path> <now_unix>
//! projection_store_probe accept  <path> <now_unix> <contract_hex> \
//!                                <kind_name> <observed_at_unix> <sequence>
//! ```
//!
//! `<kind_name>` is an `ObservationKind` machine name
//! (`contract_activated` | `execution_state_changed` | `degraded` |
//! `assurance_available` | `failover_replan` | `terminated`);
//! `<contract_hex>` is 64 lowercase hex characters.
//!
//! stdout protocol (machine-parsable, one record per line):
//!
//! ```text
//! LOADED <contract_count>
//! HEALTH <contract_hex> <state> <freshness> <fresh_until> <obs_count> <last_seq> <last_observed_at>
//! OUTCOME accepted|ignored_replay        (accept only)
//! ERROR <store_error_machine_name>       (on any store failure)
//! ```
//!
//! `freshness` is `no_observation` | `fresh` | `stale` (the typed
//! reload-time re-validation at `now_unix`); `fresh_until`,
//! `last_observed_at` and `last_seq` are `0` when inapplicable.
//!
//! Exit codes: 0 ok; 2 usage error; 3 store error (fail-closed, printed
//! typed).

use std::path::PathBuf;
use std::process::ExitCode;

use sharenet_connectivity::{
    ConnectivityContractRef, ConnectivityObservation, DurableProjectionStore, ObservationKind,
    ProjectionFreshness, RefKind, StoreError,
};
use sharenet_connectivity_client::hex::decode_lower_hex_32;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.as_slice() {
        [cmd, path, now, rest @ ..] if cmd == "inspect" || cmd == "accept" => run(cmd, path, now, rest),
        _ => {
            eprintln!("usage: projection_store_probe inspect <path> <now_unix>");
            eprintln!("       projection_store_probe accept <path> <now_unix> <contract_hex> <kind_name> <observed_at_unix> <sequence>");
            return ExitCode::from(2);
        }
    };
    code
}

fn run(cmd: &str, path: &str, now: &str, rest: &[String]) -> ExitCode {
    let path = PathBuf::from(path);
    let Ok(now) = now.parse::<u64>() else {
        eprintln!("error: now_unix must be a u64");
        return ExitCode::from(2);
    };
    let observation = match (cmd, rest) {
        ("inspect", []) => None,
        ("accept", [contract_hex, kind_name, observed_at, sequence]) => {
            let id = match decode_lower_hex_32(contract_hex) {
                Ok(id) => id,
                Err(_) => {
                    eprintln!("error: contract id must be 64 lowercase hex characters");
                    return ExitCode::from(2);
                }
            };
            // The kind-validated reconstruction seam — same as the store's
            // own codec: an id of another kind is refused, never re-typed.
            let contract = match ConnectivityContractRef::from_parts(RefKind::Contract, id) {
                Ok(contract) => contract,
                Err(_) => {
                    eprintln!("error: id is not a contract id");
                    return ExitCode::from(2);
                }
            };
            let kind = match ObservationKind::from_name(kind_name) {
                Some(kind) => kind,
                None => {
                    eprintln!("error: unknown observation kind {kind_name:?}");
                    return ExitCode::from(2);
                }
            };
            let Ok(observed_at) = observed_at.parse::<u64>() else {
                eprintln!("error: observed_at_unix must be a u64");
                return ExitCode::from(2);
            };
            let Ok(sequence) = sequence.parse::<u64>() else {
                eprintln!("error: sequence must be a u64");
                return ExitCode::from(2);
            };
            Some(ConnectivityObservation::new(kind, observed_at, contract, sequence))
        }
        _ => {
            eprintln!("error: wrong argument count for {cmd:?}");
            return ExitCode::from(2);
        }
    };

    // The restart moment: a NEW process, loading ONLY from disk.
    let mut store = match DurableProjectionStore::load(&path, now) {
        Ok(store) => store,
        Err(error) => return store_error(error),
    };
    println!("LOADED {}", store.contracts().len());

    if let Some(observation) = &observation {
        let outcome = store.accept(observation);
        match outcome {
            sharenet_connectivity::AcceptOutcome::Accepted => println!("OUTCOME accepted"),
            sharenet_connectivity::AcceptOutcome::IgnoredReplay { sequence } => {
                println!("OUTCOME ignored_replay {sequence}");
            }
        }
        if let Err(error) = store.flush() {
            return store_error(error);
        }
    }

    for contract in store.contracts() {
        let Some(health) = store.health(&contract) else {
            continue;
        };
        let (freshness, fresh_until, last_observed_at) = match health.freshness(now) {
            ProjectionFreshness::NoObservation => ("no_observation", 0, 0),
            ProjectionFreshness::Fresh { fresh_until_unix } => {
                ("fresh", fresh_until_unix, health.last_accepted().unwrap().observation().observed_at_unix())
            }
            ProjectionFreshness::Stale {
                fresh_until_unix,
                last_observed_at_unix,
            } => ("stale", fresh_until_unix, last_observed_at_unix),
        };
        println!(
            "HEALTH {} {} {} {} {} {} {}",
            contract.to_hex(),
            health.state().as_str(),
            freshness,
            fresh_until,
            health.observations().len(),
            health.highest_sequence().unwrap_or(0),
            last_observed_at,
        );
    }
    ExitCode::SUCCESS
}

fn store_error(error: StoreError) -> ExitCode {
    // Fail-closed, typed: the machine name is the parsable surface.
    println!("ERROR {}", error.name());
    eprintln!("projection_store_probe: {error}");
    ExitCode::from(3)
}
