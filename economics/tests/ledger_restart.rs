//! R8-003 restart tests: the ledger's durable forms survive teardown
//! and reload exactly — the image-level snapshot AND the file-backed
//! append log (fsync'd per entry; the reload replays the log and
//! re-derives the balances).

mod common;

use common::*;
use sharenet_economics::ledger::{CivicPointLedger, FileCivicPointLedger};
use sharenet_economics::{ValuationPolicy, ValuationVerdict};
use sharenet_protocol::contribution::ContributionKind;
use sharenet_protocol::identity::Identity;

const NOW: u64 = 1_700_000_000;

fn policy() -> ValuationPolicy {
    ValuationPolicy::new(600, 10_000, 20_000, 50_000).unwrap()
}

#[test]
fn snapshot_survives_teardown_and_reload_exact() {
    let issuer = id(0x11);
    let contributor_a = [0x22; 32];
    let contributor_b = [0x33; 32];
    let ledger = CivicPointLedger::with_policy(policy());
    for seq in 1..=5u64 {
        ledger
            .award(
                &receipt(&issuer, &contributor_a, ContributionKind::Delivered, 1_000, seq, NOW),
                NOW,
            )
            .unwrap();
    }
    for seq in 1..=3u64 {
        ledger
            .award(
                &receipt(&issuer, &contributor_b, ContributionKind::Carried, 500, seq, NOW + 60),
                NOW + 60,
            )
            .unwrap();
    }
    let balance_a = ledger.balance(&contributor_a);
    let balance_b = ledger.balance(&contributor_b);
    let total = ledger.total_points();
    let entries = ledger.entries();

    // teardown + reload from the snapshot (image-level restart)
    let snap = ledger.to_snapshot_bytes();
    let reloaded = CivicPointLedger::from_snapshot_bytes(&snap).unwrap();
    assert_eq!(reloaded.balance(&contributor_a), balance_a);
    assert_eq!(reloaded.balance(&contributor_b), balance_b);
    assert_eq!(reloaded.total_points(), total);
    assert_eq!(reloaded.entries(), entries);
    // the reload keeps PRICING with the same policy
    let v = reloaded
        .award(
            &receipt(&issuer, &contributor_a, ContributionKind::Carried, 10, 6, NOW + 700),
            NOW + 700,
        )
        .unwrap();
    assert!(matches!(v.valuation, ValuationVerdict::Awarded(_)));
    // and a fresh window opened (the caps reset per window)
    assert!(v.entry.is_some());
}

#[test]
fn file_backed_ledger_survives_process_restart() {
    let dir = std::env::temp_dir().join(format!(
        "sharenet-civic-restart-{}-{}",
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

    let (total_before, balance_before, entries_before);
    {
        let file_ledger = FileCivicPointLedger::open(&path, policy()).unwrap();
        for seq in 1..=4u64 {
            file_ledger
                .award(
                    &receipt(&issuer, &contributor, ContributionKind::Delivered, 1_000, seq, NOW),
                    NOW,
                )
                .unwrap();
        }
        total_before = file_ledger.ledger().total_points();
        balance_before = file_ledger.ledger().balance(&contributor);
        entries_before = file_ledger.ledger().entries();
    }
    // "process restart": a brand-new handle over the same file
    let reloaded = FileCivicPointLedger::open(&path, policy()).unwrap();
    assert_eq!(reloaded.ledger().total_points(), total_before);
    assert_eq!(reloaded.ledger().balance(&contributor), balance_before);
    assert_eq!(reloaded.ledger().entries(), entries_before);
    // exactly-once across the restart boundary
    let replay = reloaded
        .award(
            &receipt(&issuer, &contributor, ContributionKind::Delivered, 1_000, 1, NOW),
            NOW,
        )
        .unwrap();
    assert!(matches!(replay.valuation, ValuationVerdict::Duplicate { .. }));
    assert!(replay.entry.is_none());
    // new awards keep appending durably
    let fresh = reloaded
        .award(
            &receipt(&issuer, &contributor, ContributionKind::Carried, 100, 5, NOW + 601),
            NOW + 601,
        )
        .unwrap();
    assert!(fresh.entry.is_some());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn file_backed_reload_fails_closed_on_tampering() {
    let dir = std::env::temp_dir().join(format!(
        "sharenet-civic-tamper-{}-{}",
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
    {
        let file_ledger = FileCivicPointLedger::open(&path, policy()).unwrap();
        file_ledger
            .award(
                &receipt(&issuer, &contributor, ContributionKind::Delivered, 1_000, 1, NOW),
                NOW,
            )
            .unwrap();
    }
    let bytes = std::fs::read(&path).unwrap();
    // structural tampering: a flipped length prefix / truncation /
    // trailing garbage all refuse the reload
    let mut flipped = bytes.clone();
    flipped[0] ^= 0x01;
    std::fs::write(&path, flipped).unwrap();
    assert!(FileCivicPointLedger::open(&path, policy()).is_err());

    let truncated = &bytes[..bytes.len() - 2];
    std::fs::write(&path, truncated).unwrap();
    assert!(FileCivicPointLedger::open(&path, policy()).is_err());

    let mut garbage = bytes.clone();
    garbage.push(0x00);
    std::fs::write(&path, garbage).unwrap();
    assert!(FileCivicPointLedger::open(&path, policy()).is_err());

    // a duplicate receipt_id splice: two copies of the one entry
    let mut dup = bytes.clone();
    dup.extend_from_slice(&bytes);
    std::fs::write(&path, dup).unwrap();
    assert!(FileCivicPointLedger::open(&path, policy()).is_err());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn snapshot_tampering_fails_closed_typed() {
    let ledger = CivicPointLedger::with_policy(policy());
    let snap = ledger.to_snapshot_bytes();
    // STRUCTURAL tampering fails closed: the map header (a byte flip
    // breaks the canonical form), truncation, trailing garbage.
    let mut flipped = snap.clone();
    flipped[0] ^= 0x01;
    assert!(CivicPointLedger::from_snapshot_bytes(&flipped).is_err());
    let mut garbage = snap.clone();
    garbage.push(0x00);
    assert!(CivicPointLedger::from_snapshot_bytes(&garbage).is_err());
    // a truncated tail
    assert!(CivicPointLedger::from_snapshot_bytes(&snap[..snap.len() - 2]).is_err());
}

/// ADVERSARIAL: a restart must NOT reset the window caps — the farming
/// vector ("restart to farm again") is closed by the engine-state
/// restore. The pair cap spent before the restart still binds after.
#[test]
fn restart_does_not_reset_the_caps_the_farming_vector() {
    let dir = std::env::temp_dir().join(format!(
        "sharenet-civic-farm-{}-{}",
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
    // a TIGHT pair cap: 150 points per window
    let policy = ValuationPolicy::new(600, 10_000, 150, 100_000).unwrap();
    let policy2 = policy.clone();
    {
        let file_ledger = FileCivicPointLedger::open(&path, policy).unwrap();
        // spend the whole pair cap in the window
        let v = file_ledger
            .award(
                &receipt(&issuer, &contributor, ContributionKind::Delivered, 100, 1, NOW),
                NOW,
            )
            .unwrap();
        assert_eq!(v.entry.as_ref().unwrap().awarded_points, 150);
        assert_eq!(file_ledger.ledger().balance(&contributor), 150);
    }
    // the "restart": reopen the same file — the cap must still bind
    let reloaded = FileCivicPointLedger::open(&path, policy2).unwrap();
    let v = reloaded
        .award(
            &receipt(&issuer, &contributor, ContributionKind::Delivered, 100, 2, NOW),
            NOW,
        )
        .unwrap();
    let ValuationVerdict::Awarded(a) = &v.valuation else {
        panic!("post-restart award must be Awarded");
    };
    assert_eq!(
        a.awarded_points, 0,
        "the pair cap SURVIVES the restart — no farming by restarting"
    );
    assert!(v.entry.is_none());
    assert_eq!(reloaded.ledger().balance(&contributor), 150);
    // and a NEW window still pays (the caps are per-window, not global)
    let v = reloaded
        .award(
            &receipt(&issuer, &contributor, ContributionKind::Delivered, 100, 3, NOW + 600),
            NOW + 600,
        )
        .unwrap();
    assert_eq!(v.entry.as_ref().unwrap().awarded_points, 150);
    assert_eq!(reloaded.ledger().balance(&contributor), 300);
    std::fs::remove_dir_all(&dir).ok();
}

/// ADVERSARIAL: balances never decrease — there is no code path that
/// decrements (spending is R8-004's, deliberately absent).
#[test]
fn balances_only_ever_increase() {
    let issuer = id(0x11);
    let contributor = [0x22; 32];
    let policy = ValuationPolicy::new(600, 10_000, 10_000, 10_000).unwrap();
    let ledger = CivicPointLedger::with_policy(policy);
    let mut last = 0u64;
    for seq in 1..=10u64 {
        // a mix of full, capped, duplicate and future-refused calls
        let bytes = match seq % 4 {
            0 => 5_000,
            _ => 100,
        };
        let at = NOW + (seq % 3) * 600;
        let r = receipt(&issuer, &contributor, ContributionKind::Carried, bytes, seq, at);
        let _ = ledger.award(&r, at).unwrap();
        let _ = ledger.award(&r, at).unwrap(); // duplicate: no-op
        let b = ledger.balance(&contributor);
        assert!(b >= last, "balance must never decrease: {b} < {last}");
        last = b;
    }
    assert!(last > 0);
    assert_eq!(ledger.total_points(), last);
}
