//! R8-003 concurrency tests: concurrent award paths through ONE ledger
//! (the interior-mutex construction) — exactly-once per receipt_id and
//! exact totals under racing threads, on the pure ledger AND on the
//! file-backed durable form (real fsync'd appends).

mod common;

use common::*;
use sharenet_economics::ledger::{CivicPointLedger, FileCivicPointLedger};
use sharenet_economics::{ValuationPolicy, ValuationVerdict};
use sharenet_protocol::contribution::ContributionKind;
use sharenet_protocol::identity::Identity;

const NOW: u64 = 1_700_000_000;

fn policy() -> ValuationPolicy {
    // generous caps so the assertions are about CONCURRENCY (exactly-once,
    // exact totals), not about cap binding
    ValuationPolicy::new(3_600, 1 << 20, 1 << 40, 1 << 40).unwrap()
}

#[test]
fn racing_threads_exactly_once_per_receipt() {
    let issuer = id(0x11);
    let contributor = [0x22; 32];
    let ledger = std::sync::Arc::new(CivicPointLedger::with_policy(policy()));
    // the SAME receipt raced by many threads: exactly one award
    let receipt = receipt(&issuer, &contributor, ContributionKind::Delivered, 1_000, 1, NOW);
    let raced = std::sync::Arc::new(receipt);
    let mut handles = Vec::new();
    for _ in 0..16 {
        let ledger = ledger.clone();
        let raced = raced.clone();
        handles.push(std::thread::spawn(move || {
            ledger.award(&raced, NOW).unwrap()
        }));
    }
    let mut awarded = 0;
    let mut duplicates = 0;
    for h in handles {
        let v = h.join().expect("thread");
        match v.valuation {
            ValuationVerdict::Awarded(_) => awarded += 1,
            ValuationVerdict::Duplicate { .. } => duplicates += 1,
            other => panic!("racing award must not refuse: {other:?}"),
        }
    }
    assert_eq!(awarded, 1, "exactly one award");
    assert_eq!(duplicates, 15, "the rest are duplicates");
    assert_eq!(ledger.entry_count(), 1);
    assert_eq!(ledger.balance(&contributor), 1_500); // 1.5x x 1000
    assert_eq!(ledger.total_points(), 1_500);
}

#[test]
fn racing_distinct_receipts_exact_totals() {
    let issuer = id(0x11);
    let contributor_a = [0x22; 32];
    let contributor_b = [0x33; 32];
    let ledger = std::sync::Arc::new(CivicPointLedger::with_policy(policy()));
    let mut handles = Vec::new();
    // thread 0..8: contributor A receipts seq 1..=8 (100 bytes each)
    // thread 8..16: contributor B receipts seq 1..=8 (200 bytes each)
    for t in 0..16u64 {
        let ledger = ledger.clone();
        let issuer = issuer_seed();
        handles.push(std::thread::spawn(move || {
            let contributor = if t < 8 { [0x22; 32] } else { [0x33; 32] };
            let bytes = if t < 8 { 100 } else { 200 };
            let seq = t % 8 + 1;
            let r = sharenet_protocol::contribution::ContributionReceipt::new(
                &issuer,
                contributor,
                [0xF0; 32],
                ContributionKind::Carried,
                bytes,
                seq,
                NOW,
            )
            .unwrap();
            ledger.award(&r, NOW).unwrap()
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
    assert_eq!(ledger.entry_count(), 16);
    assert_eq!(ledger.balance(&contributor_a), 8 * 100);
    assert_eq!(ledger.balance(&contributor_b), 8 * 200);
    assert_eq!(ledger.total_points(), 8 * 100 + 8 * 200);
}

#[test]
fn file_backed_racing_awards_are_durable_and_exact() {
    let dir = std::env::temp_dir().join(format!(
        "sharenet-civic-conc-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("civic-ledger.cbor");
    let issuer = id(0x11);
    let contributor = [0x22; 32];
    let file_ledger = std::sync::Arc::new(FileCivicPointLedger::open(&path, policy()).unwrap());
    let mut handles = Vec::new();
    for t in 0..12u64 {
        let ledger = file_ledger.clone();
        handles.push(std::thread::spawn(move || {
            let r = sharenet_protocol::contribution::ContributionReceipt::new(
                &issuer_seed(),
                [0x22; 32],
                [0xF0; 32],
                ContributionKind::Delivered,
                100,
                t + 1,
                NOW,
            )
            .unwrap();
            ledger.award(&r, NOW).unwrap()
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }
    assert_eq!(file_ledger.ledger().entry_count(), 12);
    assert_eq!(file_ledger.ledger().balance(&contributor), 12 * 150);
    // the durable reload (after all the racing fsync'd appends) replays
    // exactly: 12 entries, the same balance
    let reloaded = FileCivicPointLedger::open(&path, policy()).unwrap();
    assert_eq!(reloaded.ledger().entry_count(), 12);
    assert_eq!(reloaded.ledger().balance(&contributor), 12 * 150);
    let _ = issuer;
    std::fs::remove_dir_all(&dir).ok();
}
