//! Integration test: R7-003's multiprocess verify level — the whole §11
//! gateway-recovery pipeline driven across REAL process boundaries
//! through the `recovery_probe` binary, each invocation seeing the
//! recovery state ONLY through the bytes on disk (no in-process
//! shortcuts, no shared state beyond the durable directory).
//!
//! The ShareNet daemon is modeled as the work item's three roles:
//!
//! - process 1 (`setup` + `open-attempt`): admits the revocation for the
//!   deterministically derived circuit and opens the recovery attempt;
//! - process 2 (`select` + `establish`): selects a fresh gateway from the
//!   probe's candidate set (the composed R5-005 policy verifying every
//!   signature in a NEW process) and succeeds the attempt with a fresh
//!   route commitment through the selected gateway;
//! - process 3 (`state`): reloads and sees the terminal state.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_recovery_probe");

/// The probe's fixed evidence-timeline base (its candidates' evidence is
/// built relative to this; the `now` args are decision clocks).
const BASE: u64 = 1_700_000_000;

fn probe(args: &[&str]) -> (i32, Vec<String>) {
    let out = Command::new(BIN).args(args).output().expect("spawn recovery_probe");
    let lines = String::from_utf8(out.stdout)
        .expect("utf8 stdout")
        .lines()
        .map(String::from)
        .collect();
    (out.status.code().unwrap_or(-1), lines)
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sharenet-r7003-mpr-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// The work item's multiprocess evidence: process 1 admits a revocation
/// and opens an attempt; process 2 selects a gateway from candidates and
/// succeeds the attempt; process 3 reloads and sees the terminal state.
#[test]
fn gateway_recovery_across_three_process_roles() {
    let dir = temp_dir("happy");
    let d = dir.to_str().unwrap().to_string();

    // -- Process 1: the durable revocation + the open attempt -------------
    let (code, out) = probe(&["setup", &d, &(BASE + 10).to_string()]);
    assert_eq!(code, 0, "{out:?}");
    let circuit_line =
        out.iter().find(|l| l.starts_with("CIRCUIT ")).expect("CIRCUIT line").clone();
    let circuit = circuit_line.split(' ').nth(1).expect("circuit hex").to_string();
    assert!(circuit_line.ends_with(&format!(" {}", BASE + 10)), "revoked_at: {circuit_line}");
    assert!(out.iter().any(|l| l == "OUTCOME first"), "{out:?}");

    let (code, out) = probe(&["open-attempt", &d, &(BASE + 11).to_string()]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(
        out[0],
        format!("STEP select_fresh_gateway {circuit} 1"),
        "the typed §11 hand-off, across the process boundary"
    );

    // -- Process 2: select a fresh gateway from candidates -----------------
    let (code, out) = probe(&["select", &d, &(BASE + 12).to_string()]);
    assert_eq!(code, 0, "{out:?}");
    // The candidate set: two eligible (G1, G4), two refused (G2 no
    // backhaul, G3 wrong subject) — the composed policy judged all four
    // in THIS process, on real signed evidence.
    let candidates: Vec<(String, &str)> = out
        .iter()
        .filter(|l| l.starts_with("CANDIDATE "))
        .map(|l| {
            let mut parts = l.split(' ');
            let _ = parts.next();
            (parts.next().unwrap().to_string(), parts.next().unwrap())
        })
        .collect();
    assert_eq!(candidates.len(), 4, "{out:?}");
    let eligible: Vec<&str> =
        candidates.iter().filter(|(_, v)| *v == "eligible").map(|(id, _)| id.as_str()).collect();
    let ineligible: Vec<&str> =
        candidates.iter().filter(|(_, v)| *v == "ineligible").map(|(id, _)| id.as_str()).collect();
    assert_eq!(eligible.len(), 2, "{out:?}");
    assert_eq!(ineligible.len(), 2, "{out:?}");
    let selected_line =
        out.iter().find(|l| l.starts_with("SELECTED ")).expect("SELECTED line").clone();
    let selected = selected_line.split(' ').nth(1).expect("gateway hex").to_string();
    let valid_until: u64 =
        selected_line.split(' ').nth(2).expect("valid_until").parse().expect("u64");
    assert_eq!(valid_until, BASE + 592, "the earlier of the two anchors' bounds");
    // The selection is one of the ELIGIBLE candidates (never a refused
    // one) — and the deterministic tie-break picked the lower node id.
    let mut sorted_eligible = eligible.clone();
    sorted_eligible.sort();
    assert_eq!(selected, sorted_eligible[0], "{out:?}");

    // Determinism ACROSS processes: a second `select` invocation (a whole
    // new process, same candidate set + clock) selects the same gateway.
    let (code, out) = probe(&["select", &d, &(BASE + 12).to_string()]);
    assert_eq!(code, 0, "{out:?}");
    let again = out.iter().find(|l| l.starts_with("SELECTED ")).expect("SELECTED line").clone();
    assert_eq!(again, selected_line, "selection is deterministic across processes");

    // -- Process 2 (part B): succeed the attempt with the fresh route -----
    // The establish subcommand RE-DERIVES the selection in yet another
    // process (same set + clock → same gateway; a mismatch would be its
    // typed failure), builds the R3-004 material and durably succeeds.
    let (code, out) = probe(&["establish", &d, &(BASE + 13).to_string(), &selected]);
    assert_eq!(code, 0, "{out:?}");
    let route_line = out.iter().find(|l| l.starts_with("ROUTE ")).expect("ROUTE line").clone();
    let route = route_line.split(' ').nth(1).expect("route hex").to_string();
    assert_eq!(route.len(), 64, "a commitment-derived route id (L013): {route_line}");
    assert!(out.iter().any(|l| l == "ATTEMPT succeeded 1"), "{out:?}");
    assert!(out.iter().any(|l| l == &format!("GATEWAY {selected}")), "{out:?}");

    // -- Process 3: reload and see the terminal state -----------------------
    let (code, out) = probe(&["state", &d]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], format!("LATEST succeeded 1 {route}"), "{out:?}");
    assert!(out.iter().any(|l| l == "REVOKED yes"), "L015 across every boundary: {out:?}");
    assert!(out.iter().any(|l| l == "ATTEMPTS 1"), "{out:?}");

    // A later process cannot open a new attempt (success is terminal).
    let (code, out) = probe(&["open-attempt", &d, &(BASE + 20).to_string()]);
    assert_eq!(code, 3, "{out:?}");
    assert!(out.iter().any(|l| l == "ERROR recovery_already_complete"), "{out:?}");

    std::fs::remove_dir_all(&dir).ok();
}

/// The typed-refusal leg across processes: when every candidate is
/// ineligible, process 2's selection fails typed (`no_eligible_gateway`,
/// exit 3), the attempt survives as pending, and process 3 sees exactly
/// that — the R7-005 retry policy's future input, durable.
#[test]
fn no_eligible_gateway_across_processes() {
    let dir = temp_dir("refused");
    let d = dir.to_str().unwrap().to_string();

    let (code, out) = probe(&["setup", &d, &(BASE + 10).to_string()]);
    assert_eq!(code, 0, "{out:?}");
    let (code, out) = probe(&["open-attempt", &d, &(BASE + 11).to_string()]);
    assert_eq!(code, 0, "{out:?}");

    // Process 2: only the two ineligible candidates are offered.
    let (code, out) = probe(&["select-none", &d, &(BASE + 12).to_string()]);
    assert_eq!(code, 3, "{out:?}");
    let refused: Vec<&str> = out
        .iter()
        .filter(|l| l.starts_with("CANDIDATE "))
        .map(|l| l.split(' ').nth(2).unwrap())
        .collect();
    assert_eq!(refused.len(), 2, "{out:?}");
    assert!(refused.iter().all(|v| *v == "ineligible"), "{out:?}");
    assert!(out.iter().any(|l| l == "ERROR no_eligible_gateway"), "{out:?}");

    // Process 3: the attempt is STILL PENDING — the refusal wrote nothing.
    let (code, out) = probe(&["state", &d]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], "LATEST pending 1 -", "{out:?}");
    assert!(out.iter().any(|l| l == "REVOKED yes"), "{out:?}");
    assert!(out.iter().any(|l| l == "ATTEMPTS 1"), "{out:?}");

    std::fs::remove_dir_all(&dir).ok();
}

/// The R7-004 replacement-circuit flow across REAL process boundaries:
/// the durable revocation + §11 zeroization + attempt in process roles
/// 1-2 (as in the gateway test), then the replacement established by a
/// LATER process, its facts surviving into a final reload — and the
/// cross-boundary single-flight refusal.
#[test]
fn replacement_circuit_across_process_boundaries() {
    let dir = temp_dir("replacement");
    let d = dir.to_str().unwrap().to_string();

    // -- Process role 1: revocation + the §11 zeroization fact ----------
    let (code, out) = probe(&["setup", &d, &(BASE + 10).to_string()]);
    assert_eq!(code, 0, "{out:?}");
    let circuit = out
        .iter()
        .find_map(|l| l.strip_prefix("CIRCUIT "))
        .expect("CIRCUIT line")
        .split(' ')
        .next()
        .expect("circuit hex")
        .to_string();

    let (code, out) = probe(&["zeroize", &d, &(BASE + 11).to_string()]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], format!("ZEROIZED {circuit} {}", BASE + 11), "{out:?}");

    // The attempt opens only AFTER the durable invalidation (§11 order).
    let (code, out) = probe(&["open-attempt", &d, &(BASE + 12).to_string()]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], format!("STEP select_fresh_gateway {circuit} 1"), "{out:?}");

    // -- Process role 2: selection + the fresh route (as in the gateway
    // test — the establish subcommand re-derives everything
    // deterministically). ------------------------------------------------
    let (code, out) = probe(&["select", &d, &(BASE + 13).to_string()]);
    assert_eq!(code, 0, "{out:?}");
    let selected = out
        .iter()
        .find_map(|l| l.strip_prefix("SELECTED "))
        .expect("SELECTED line")
        .split(' ')
        .next()
        .expect("gateway hex")
        .to_string();

    let (code, out) = probe(&["establish", &d, &(BASE + 14).to_string(), &selected]);
    assert_eq!(code, 0, "{out:?}");
    let route = out
        .iter()
        .find_map(|l| l.strip_prefix("ROUTE "))
        .expect("ROUTE line")
        .to_string();
    assert!(out.iter().any(|l| l == "ATTEMPT succeeded 1"), "{out:?}");

    // -- Process role 3: the replacement circuit over the recorded fresh
    // route (rebuilt deterministically from the durable record; a wrong
    // route_at is the probe's own typed failure). --------------------------
    let (code, out) =
        probe(&["establish-replacement", &d, &(BASE + 15).to_string(), &(BASE + 14).to_string()]);
    assert_eq!(code, 0, "{out:?}");
    let replacement = out
        .iter()
        .find_map(|l| l.strip_prefix("REPLACEMENT "))
        .expect("REPLACEMENT line")
        .to_string();
    assert_ne!(replacement, circuit, "L014: a fresh circuit id, never the revoked one");
    assert_eq!(out.iter().find_map(|l| l.strip_prefix("ROUTE ")), Some(route.as_str()), "{out:?}");
    assert!(out.iter().any(|l| l == "REPLACEMENT-ATTEMPT 1"), "{out:?}");
    assert!(out.iter().any(|l| l == "ESTABLISHED yes"), "{out:?}");

    // -- Process role 4: the reload sees every durable fact ----------------
    let (code, out) = probe(&["state", &d]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], format!("LATEST succeeded 1 {route}"), "{out:?}");
    assert!(out.iter().any(|l| l == "REVOKED yes"), "L015 across every boundary: {out:?}");
    assert!(
        out.iter().any(|l| l.as_str() == format!("ZEROIZED {}", BASE + 11)),
        "the §11 zeroization fact survived: {out:?}"
    );
    assert!(
        out.iter().any(|l| l.as_str() == format!("REPLACEMENT {replacement}")),
        "the replacement fact survived: {out:?}"
    );
    assert!(out.iter().any(|l| l == "ATTEMPTS 1"), "{out:?}");

    // The cross-boundary single flight: a LATER process cannot replace
    // again (typed, exit 3) — the durable record keeps the first.
    let (code, out) = probe(&[
        "establish-replacement",
        &d,
        &(BASE + 20).to_string(),
        &(BASE + 14).to_string(),
    ]);
    assert_eq!(code, 3, "{out:?}");
    assert!(
        out.iter().any(|l| l == "ERROR replacement_already_established"),
        "{out:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
