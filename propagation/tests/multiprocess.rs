//! Integration test: R6-005's multiprocess verify level — an
//! opportunistic handover flowing across REAL process boundaries
//! through the `propagation_probe` binary. The ShareNet daemon is
//! modeled as a sequence of probe invocations: the sender's custody
//! store lives in one process, the contact plan + handover in another,
//! and the RECEIVING edge in a third — a different node's store, taking
//! custody through the R6-004 rules, with the handover material passing
//! between them ONLY as machine-parsable bytes on stdout/stdin.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_propagation_probe");
const NOW: u64 = 1_700_000_000;
const GW: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PEER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn run(args: &[&str], stdin_data: Option<&str>) -> (i32, Vec<String>) {
    let mut cmd = Command::new(BIN);
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::null());
    if stdin_data.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd.spawn().expect("spawn propagation_probe");
    if let Some(data) = stdin_data {
        child
            .stdin
            .take()
            .expect("piped stdin")
            .write_all(data.as_bytes())
            .expect("write stdin");
    }
    let out = child.wait_with_output().expect("wait");
    let lines = String::from_utf8(out.stdout)
        .expect("utf8 stdout")
        .lines()
        .map(String::from)
        .collect();
    (out.status.code().unwrap_or(-1), lines)
}

fn probe(args: &[&str]) -> (i32, Vec<String>) {
    run(args, None)
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sharenet-prop-mpr-{}-{}-{}",
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

/// The full cross-process handover: a partial bundle seeded in one
/// process is planned for a contact in a second, handed over as bytes,
/// and taken into custody by a DIFFERENT node's store in a third — with
/// the receiving edge's dedup proving itself on a re-delivery, and both
/// stores' custody evidence and live status visible to later processes.
#[test]
fn opportunistic_handover_across_processes() {
    let sender = temp_dir("send");
    let receiver = temp_dir("recv");
    let s = sender.to_str().unwrap().to_string();
    let r = receiver.to_str().unwrap().to_string();

    // Process 1: the sender's store — a partial bundle (2 of 4 chunks,
    // replication target 2, dtn class, far expiry).
    let (code, out) = probe(&["seed", &s, "7", "dtn", &NOW.to_string(), &(NOW + 3_600).to_string(), "2", "2"]);
    assert_eq!(code, 0, "{out:?}");
    let seeded = out.iter().find(|l| l.starts_with("SEEDED ")).expect("SEEDED");
    let id = seeded.split(' ').nth(1).expect("content hex").to_string();
    assert!(seeded.ends_with(" 4"), "4 chunks for seed 7: {seeded}");

    // Process 2: the contact — a plan over an admitted-gateway window.
    let (code, out) = probe(&[
        "plan", &s, &(NOW + 10).to_string(), GW,
        &(NOW - 10).to_string(), &(NOW + 500).to_string(),
        &(NOW + 590).to_string(), "1000000", "10",
    ]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], "VERDICT plan", "{out:?}");
    let step = out.iter().find(|l| l.starts_with("STEP ")).expect("STEP line");
    assert!(
        step.contains(&id) && step.contains(" dtn ") && step.contains("0/2 2/4"),
        "the partial bundle, its class and replication state: {step}"
    );
    assert!(out.iter().any(|l| l == "DONE 1 0"), "{out:?}");

    // Process 3: the handover — the plan applied, custody noted on the
    // sender, the material printed as bytes.
    let (code, out) = probe(&[
        "handover", &s, &(NOW + 11).to_string(), GW,
        &(NOW - 10).to_string(), &(NOW + 500).to_string(),
        &(NOW + 590).to_string(), "1000000", "10",
    ]);
    assert_eq!(code, 0, "{out:?}");
    assert!(
        out.iter().any(|l| l.as_str() == format!("HANDOVER {id} NOTED 1")),
        "custody noted at replication 1: {out:?}"
    );
    let material: String = out
        .iter()
        .map(|l| format!("{l}\n"))
        .collect();

    // Process 4: the RECEIVING edge — a different node's store, taking
    // custody through the R6-004 rules (the piped-through protocol
    // lines are skipped; the material is the authority).
    let (code, out) = run(
        &["receive", &r, &(NOW + 12).to_string(), PEER],
        Some(&material),
    );
    assert_eq!(code, 0, "{out:?}");
    assert!(
        out.iter().any(|l| l.as_str() == format!("RECEIVED {id} accept chunks=2/0/0")),
        "both chunks taken custody: {out:?}"
    );
    assert!(out.iter().any(|l| l == "DONE 1"), "{out:?}");

    // Process 5: the re-delivery — the receiving edge's DEDUP across
    // processes (nothing re-stored, the verdict is `already_held`).
    let (code, out) = run(
        &["receive", &r, &(NOW + 13).to_string(), PEER],
        Some(&material),
    );
    assert_eq!(code, 0, "{out:?}");
    assert!(
        out.iter().any(|l| l.as_str() == format!("RECEIVED {id} already_held chunks=0/2/0")),
        "dedup at the receiving edge: {out:?}"
    );

    // Later processes: both stores show the bundle LIVE, and each side's
    // custody evidence names its facts (the sender: received + the
    // forward to the gateway; the receiver: the receipt from the peer).
    let (code, out) = probe(&["status", &s, &(NOW + 14).to_string(), &id]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], "STATUS live", "{out:?}");
    let (code, out) = probe(&["status", &r, &(NOW + 15).to_string(), &id]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], "STATUS live", "{out:?}");

    let (code, out) = probe(&["evidence", &s]);
    assert_eq!(code, 0, "{out:?}");
    assert!(
        out.iter().any(|l| l.starts_with("EVIDENCE received") && l.ends_with(&id)),
        "{out:?}"
    );
    assert!(
        out.iter()
            .any(|l| l.starts_with("EVIDENCE forwarded") && l.contains(GW) && l.ends_with(&id)),
        "the forward names the gateway: {out:?}"
    );

    std::fs::remove_dir_all(&sender).ok();
    std::fs::remove_dir_all(&receiver).ok();
}

/// The TTL gate across processes: a short-lived bundle is plannable for
/// a contact whose window closes before its expiry — and after the
/// expiry NOTHING forwards (the store's `forward_candidates` excludes
/// it; the plan is honestly empty).
#[test]
fn ttl_gates_the_contact_across_processes() {
    let dir = temp_dir("ttl");
    let d = dir.to_str().unwrap().to_string();

    // A `live`-class bundle expiring at NOW+600 (past the policy's 60s
    // minimum-remaining-life floor for the window below), fully chunked.
    let (code, out) = probe(&["seed", &d, "5", "live", &NOW.to_string(), &(NOW + 600).to_string(), "1"]);
    assert_eq!(code, 0, "{out:?}");
    let id = out
        .iter()
        .find_map(|l| l.strip_prefix("SEEDED "))
        .expect("SEEDED")
        .split(' ')
        .next()
        .expect("content hex")
        .to_string();

    // Before expiry, for a window that CLOSES before the bundle expires
    // with remaining life above the floor (closes NOW+50, expires
    // NOW+600 → 550s left at close): plannable.
    let (code, out) = probe(&[
        "plan", &d, &(NOW + 10).to_string(), GW,
        &(NOW - 10).to_string(), &(NOW + 50).to_string(),
        &(NOW + 590).to_string(), "1000000", "10",
    ]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], "VERDICT plan", "{out:?}");
    assert!(out.iter().any(|l| l.starts_with("STEP ") && l.contains(&id)), "{out:?}");
    assert!(out.iter().any(|l| l == "DONE 1 0"), "{out:?}");

    // The same bundle one tick past its expiry: nothing to forward —
    // TTL gates BEFORE priority, in a real process.
    let (code, out) = probe(&[
        "plan", &d, &(NOW + 601).to_string(), GW,
        &(NOW + 55).to_string(), &(NOW + 610).to_string(),
        &(NOW + 620).to_string(), "1000000", "10",
    ]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], "VERDICT nothing_to_forward", "{out:?}");
    assert_eq!(out[1], "DONE 0 0", "{out:?}");

    std::fs::remove_dir_all(&dir).ok();
}
