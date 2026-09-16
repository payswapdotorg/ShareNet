//! Integration test: R6-003's multiprocess verify level — custody
//! continued across REAL process boundaries through the `dtn_probe`
//! binary, each invocation seeing the store ONLY through the bytes on
//! disk (no in-process shortcuts, no shared state).
//!
//! The ShareNet daemon is modeled as a sequence of probe invocations:
//! node A seeds a partial bundle; a later process completes it; later
//! processes forward, exhaust replication, read back, and finally let
//! TTL expiry evict — with the custody evidence surviving every step.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_dtn_probe");

const NOW: u64 = 1_700_000_500;
const EXPIRY: u64 = NOW + 3_600;

fn probe(args: &[&str]) -> (i32, Vec<String>) {
    let out = Command::new(BIN).args(args).output().expect("spawn dtn_probe");
    let lines = String::from_utf8(out.stdout)
        .expect("utf8 stdout")
        .lines()
        .map(String::from)
        .collect();
    (out.status.code().unwrap_or(-1), lines)
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sharenet-dtn-mpr-{}-{}-{}",
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

#[test]
fn custody_continues_across_processes() {
    let dir = temp_dir("carry");
    let d = dir.to_str().unwrap().to_string();

    // Process 1: seed a PARTIAL bundle (2 of 4 chunks) with a Received
    // record — a node that just accepted a bundle off a contact.
    let (code, out) = probe(&[
        "seed", &d, "7", "dtn", &NOW.to_string(), &EXPIRY.to_string(), "2", "2",
    ]);
    assert_eq!(code, 0, "{out:?}");
    let seeded = out.iter().find(|l| l.starts_with("SEEDED ")).expect("SEEDED");
    let id = seeded.split(' ').nth(1).expect("content id").to_string();
    assert!(seeded.ends_with(" 4"), "4 chunks for seed 7: {seeded}");

    // Process 2: continue custody — complete the bundle from disk (the
    // process-boundary resume: the later process re-derives the SAME
    // content id from the SAME seed and fills the missing slots).
    let (code, out) = probe(&["fill-chunks", &d, "7"]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], format!("FILLED {id} 4/4"), "{out:?}");

    // Process 3: the carry-forward list names it (dtn class, 0/2
    // replication, complete presence).
    let (code, out) = probe(&["forward-list", &d, "1700000900"]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], format!("FORWARD dtn {EXPIRY} 0/2 4/4 {id}"));
    assert_eq!(out[1], "DONE 1");

    // Processes 4-5: two forwards to distinct peers — replication 2.
    let (code, out) = probe(&["forward-one", &d, "1700000901", "aabb"]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], format!("FORWARDED {id} 1"));
    let (code, out) = probe(&["forward-one", &d, "1700000902", "ccdd"]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], format!("FORWARDED {id} 2"));

    // Process 6: replication target exhausted — never a candidate again.
    let (code, out) = probe(&["forward-list", &d, "1700000903"]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], "DONE 0");

    // Process 7: the custody log survived every process boundary, in
    // append order, every record naming the bundle.
    let (code, out) = probe(&["evidence", &d]);
    assert_eq!(code, 0, "{out:?}");
    let kinds: Vec<&str> = out
        .iter()
        .filter(|l| l.starts_with("EVIDENCE "))
        .map(|l| l.split(' ').nth(1).unwrap())
        .collect();
    assert_eq!(kinds, ["received", "forwarded", "forwarded"], "{out:?}");
    assert!(out.iter().any(|l| l == "DONE 3"));

    // Process 8: byte-exact re-verified read from a later process.
    let (code, out) = probe(&["read-chunk", &d, "7", "0"]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], "CHUNK 0 12");

    // Process 9: status shows the replication-exhausted carry state (the
    // honest terminal-carry verdict, visible across processes).
    let (code, out) = probe(&["status", &d, "1700000904", &id]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], "STATUS replication_exhausted");

    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn ttl_expiry_never_forwards_and_eviction_survives_across_processes() {
    let dir = temp_dir("ttl");
    let d = dir.to_str().unwrap().to_string();

    // A dominant-priority bundle with a SHORT TTL.
    let (code, out) = probe(&[
        "seed", &d, "9", "live", &NOW.to_string(), &(NOW + 100).to_string(), "1",
    ]);
    assert_eq!(code, 0, "{out:?}");
    let seeded = out.iter().find(|l| l.starts_with("SEEDED ")).expect("SEEDED");
    let id = seeded.split(' ').nth(1).expect("content id").to_string();

    // Before expiry: it is the forward candidate (dominant priority).
    let (code, out) = probe(&["forward-list", &d, &(NOW + 99).to_string()]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(
        out.iter().filter(|l| l.starts_with("FORWARD ")).count(),
        1,
        "unexpired carries: {out:?}"
    );

    // AT the exclusive bound: NEVER forwards — TTL gates before priority.
    let (code, out) = probe(&["forward-list", &d, &(NOW + 100).to_string()]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], "DONE 0", "expired never forwards: {out:?}");

    // Eviction from a later process at expiry.
    let (code, out) = probe(&["evict", &d, &(NOW + 101).to_string()]);
    assert_eq!(code, 0, "{out:?}");
    assert_eq!(out[0], format!("EVICTED {id}"));
    assert_eq!(out[1], "DONE 1");

    // The bundle is gone — typed refusal (exit 3 + ERROR line)…
    let (code, out) = probe(&["status", &d, &(NOW + 102).to_string(), &id]);
    assert_eq!(code, 3, "typed failure exit: {out:?}");
    assert!(out[0].starts_with("ERROR "), "{out:?}");

    // …but its custody evidence SURVIVED the eviction (the R8 seam).
    let (code, out) = probe(&["evidence", &d]);
    assert_eq!(code, 0, "{out:?}");
    assert!(
        out.iter()
            .any(|l| l.starts_with("EVIDENCE received") && l.ends_with(&id)),
        "evidence outlives the bundle: {out:?}"
    );

    std::fs::remove_dir_all(&dir).ok();
}
