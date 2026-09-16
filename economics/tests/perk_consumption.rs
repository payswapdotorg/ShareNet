//! R8-004 verification: the perk-consumption layer — the INTEGRATION
//! leg (the priority grant composed with the DTN store's own carry
//! order — the frozen ServicePriority vocabulary, no re-implemented
//! ordering) and the ADVERSARIAL legs (overspend, double-spend, expired
//! grants, spend durability across restart).

mod common;

use common::*;
use sharenet_economics::consumption::PerkKind;
use sharenet_economics::ledger::{CivicPointLedger, FileCivicPointLedger};
use sharenet_economics::consumption::SpendError;
use sharenet_economics::{ValuationPolicy, ValuationVerdict};
use sharenet_protocol::content::ContentManifest;
use sharenet_protocol::contribution::ContributionKind;
use sharenet_protocol::identity::Identity;
use sharenet_dtn::priority::ServicePriority;
use sharenet_dtn::DtnStoreImage as DtnStore;

const NOW: u64 = 1_700_000_000;

fn policy() -> ValuationPolicy {
    ValuationPolicy::new(3_600, 1 << 20, 1 << 30, 1 << 30).unwrap()
}

/// THE INTEGRATION LEG: a contributor holding an ACTIVE
/// priority_scheduling grant gets their bundle admitted at the `live`
/// service class — the DTN store's own carry order then carries it
/// FIRST; a contributor without the grant stays at the `dtn` class.
#[test]
fn priority_grant_elevates_the_dtn_carry_order() {
    let issuer = id(0x11);
    let granted = [0x22; 32];
    let ungranted = [0x33; 32];

    // Earn points for the granted contributor.
    let ledger = CivicPointLedger::with_policy(policy());
    for seq in 1..=4u64 {
        ledger
            .award(
                &receipt(&issuer, &granted, ContributionKind::Delivered, 1_000, seq, NOW),
                NOW,
            )
            .unwrap();
    }
    assert!(ledger.balance(&granted) >= 100, "earned a spendable balance");

    // Spend on the perk (the only balance-decreasing path).
    let spend_id = [0x50; 32];
    let entry = ledger
        .spend(&granted, PerkKind::PriorityScheduling, 100, spend_id, NOW, 3_600)
        .unwrap()
        .expect("the spend records");
    assert_eq!(entry.points, 100);
    assert!(ledger.has_grant(&granted, PerkKind::PriorityScheduling, NOW + 1));

    // The daemon's composition: the grant maps onto the DTN's OWN
    // frozen priority vocabulary at admit time (no second ordering).
    let mut store = DtnStore::new();
    let (manifest_granted, _) =
        ContentManifest::chunk(b"granted-contributor-bundle", 8, "application/octet-stream", None, NOW)
            .unwrap();
    let (manifest_ungranted, _) =
        ContentManifest::chunk(b"plain-contributor-bundle", 8, "application/octet-stream", None, NOW)
            .unwrap();
    // admit the UNGRANTED bundle FIRST (the carry order must still put
    // the granted one first — priority, not insertion order)
    store
        .admit_manifest(&manifest_ungranted, ServicePriority::Dtn, NOW, NOW + 3_600, 1)
        .unwrap();
    let granted_class = if ledger.has_grant(&granted, PerkKind::PriorityScheduling, NOW) {
        ServicePriority::Live
    } else {
        ServicePriority::Dtn
    };
    store
        .admit_manifest(&manifest_granted, granted_class, NOW, NOW + 3_600, 1)
        .unwrap();
    let candidates = store.forward_candidates(NOW);
    assert_eq!(
        candidates[0].content_id(),
        &manifest_granted.content_id(),
        "the granted contributor's bundle carries FIRST (live > dtn)"
    );
    assert_eq!(
        candidates[1].content_id(),
        &manifest_ungranted.content_id(),
        "the ungranted bundle carries second despite being admitted first"
    );
    // the same store WITHOUT the grant's elevation: insertion order holds
    let mut plain_store = DtnStore::new();
    plain_store
        .admit_manifest(&manifest_ungranted, ServicePriority::Dtn, NOW, NOW + 3_600, 1)
        .unwrap();
    plain_store
        .admit_manifest(&manifest_granted, ServicePriority::Dtn, NOW, NOW + 3_600, 1)
        .unwrap();
    let candidates = plain_store.forward_candidates(NOW);
    assert_eq!(candidates[0].content_id(), &manifest_ungranted.content_id());
}

/// ADVERSARIAL: no overdraft — a spend beyond the balance refuses
/// typed and moves nothing.
#[test]
fn overspend_is_refused_typed_and_moves_nothing() {
    let issuer = id(0x11);
    let contributor = [0x22; 32];
    let ledger = CivicPointLedger::with_policy(policy());
    ledger
        .award(
            &receipt(&issuer, &contributor, ContributionKind::Carried, 100, 1, NOW),
            NOW,
        )
        .unwrap();
    assert_eq!(ledger.available_balance(&contributor), 100);
    match ledger.spend(&contributor, PerkKind::GatewayPreference, 101, [1; 32], NOW, 60) {
        Err(e) => {
            assert_eq!(e.name(), "insufficient_balance");
            assert_eq!(
                e.to_string(),
                "insufficient balance: 100 < 101"
            );
        }
        Ok(_) => panic!("overspend must refuse"),
    }
    assert_eq!(ledger.available_balance(&contributor), 100);
    assert!(ledger.spends().is_empty());
}

/// ADVERSARIAL: exactly-once per spend_id — a re-delivered spend is a
/// typed duplicate, not a second deduction.
#[test]
fn double_spend_is_exactly_once() {
    let issuer = id(0x11);
    let contributor = [0x22; 32];
    let ledger = CivicPointLedger::with_policy(policy());
    ledger
        .award(
            &receipt(&issuer, &contributor, ContributionKind::Carried, 1_000, 1, NOW),
            NOW,
        )
        .unwrap();
    let spend_id = [0x99; 32];
    ledger
        .spend(&contributor, PerkKind::PriorityScheduling, 400, spend_id, NOW, 600)
        .unwrap()
        .expect("first spend");
    match ledger.spend(&contributor, PerkKind::PriorityScheduling, 400, spend_id, NOW, 600) {
        Err(e) => assert_eq!(e.name(), "duplicate_spend"),
        Ok(_) => panic!("double spend must refuse"),
    }
    assert_eq!(ledger.available_balance(&contributor), 600);
    assert_eq!(ledger.spends().len(), 1);
}

/// ADVERSARIAL: grants expire at the caller's clock — the read view
/// enforces the window; an expired grant gates nothing.
#[test]
fn expired_grants_gate_nothing() {
    let issuer = id(0x11);
    let contributor = [0x22; 32];
    let ledger = CivicPointLedger::with_policy(policy());
    ledger
        .award(
            &receipt(&issuer, &contributor, ContributionKind::Carried, 1_000, 1, NOW),
            NOW,
        )
        .unwrap();
    ledger
        .spend(&contributor, PerkKind::PriorityScheduling, 100, [0x77; 32], NOW, 300)
        .unwrap()
        .expect("spend");
    assert!(ledger.has_grant(&contributor, PerkKind::PriorityScheduling, NOW));
    assert!(ledger.has_grant(&contributor, PerkKind::PriorityScheduling, NOW + 299));
    assert!(
        !ledger.has_grant(&contributor, PerkKind::PriorityScheduling, NOW + 300),
        "the grant expires at its bound (half-open interval)"
    );
    assert!(ledger.grants(&contributor, NOW + 300).is_empty());
    // and a DIFFERENT contributor never had one
    assert!(!ledger.has_grant(&[0x33; 32], PerkKind::PriorityScheduling, NOW));
}

/// ADVERSARIAL + RESTART: spends survive the durable reload — the
/// available balance and the exactly-once spend_id set persist.
#[test]
fn spends_survive_the_durable_restart() {
    let dir = std::env::temp_dir().join(format!(
        "sharenet-perk-restart-{}-{}",
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
                &receipt(&issuer, &contributor, ContributionKind::Carried, 1_000, 1, NOW),
                NOW,
            )
            .unwrap();
        file_ledger
            .spend(&contributor, PerkKind::PriorityScheduling, 250, [0x88; 32], NOW, 600)
            .unwrap()
            .expect("durable spend");
        assert_eq!(file_ledger.ledger().available_balance(&contributor), 750);
    }
    // the restart: the reload replays awards AND spends
    let reloaded = FileCivicPointLedger::open(&path, policy()).unwrap();
    assert_eq!(reloaded.ledger().available_balance(&contributor), 750);
    assert!(reloaded.ledger().has_grant(&contributor, PerkKind::PriorityScheduling, NOW + 1));
    // the spent spend_id is still exactly-once across the restart
    match reloaded.spend(&contributor, PerkKind::PriorityScheduling, 250, [0x88; 32], NOW, 600) {
        Err(e) => assert_eq!(e.name(), "duplicate_spend"),
        Ok(_) => panic!("replayed spend must refuse"),
    }
    // zero/duration validation refuses typed
    assert_eq!(
        reloaded
            .spend(&contributor, PerkKind::PriorityScheduling, 0, [1; 32], NOW, 60)
            .unwrap_err()
            .name(),
        "points_zero"
    );
    assert_eq!(
        reloaded
            .spend(&contributor, PerkKind::PriorityScheduling, 10, [2; 32], NOW, 0)
            .unwrap_err()
            .name(),
        "duration_zero"
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// ADVERSARIAL: the balance can never go negative and awards still
/// accrue into the AVAILABLE balance after spends.
#[test]
fn available_balance_never_negative_and_awards_accrue() {
    let issuer = id(0x11);
    let contributor = [0x22; 32];
    let ledger = CivicPointLedger::with_policy(policy());
    ledger
        .award(
            &receipt(&issuer, &contributor, ContributionKind::Carried, 500, 1, NOW),
            NOW,
        )
        .unwrap();
    ledger
        .spend(&contributor, PerkKind::GatewayPreference, 500, [3; 32], NOW, 60)
        .unwrap()
        .expect("full spend");
    assert_eq!(ledger.available_balance(&contributor), 0);
    match ledger.spend(&contributor, PerkKind::GatewayPreference, 1, [4; 32], NOW, 60) {
        Err(e) => assert_eq!(e.name(), "insufficient_balance"),
        Ok(_) => panic!("no overdraft"),
    }
    // a new award accrues into the available balance
    let v = ledger
        .award(
            &receipt(&issuer, &contributor, ContributionKind::Delivered, 100, 2, NOW + 3_600),
            NOW + 3_600,
        )
        .unwrap();
    assert!(matches!(v.valuation, ValuationVerdict::Awarded(_)));
    assert_eq!(ledger.available_balance(&contributor), 150);
}

/// The snapshot round-trips spends too (the durable image form).
#[test]
fn snapshot_round_trips_spends() {
    let issuer = id(0x11);
    let contributor = [0x22; 32];
    let ledger = CivicPointLedger::with_policy(policy());
    ledger
        .award(
            &receipt(&issuer, &contributor, ContributionKind::Carried, 1_000, 1, NOW),
            NOW,
        )
        .unwrap();
    ledger
        .spend(&contributor, PerkKind::PriorityScheduling, 300, [6; 32], NOW, 1_200)
        .unwrap()
        .expect("spend");
    let snap = ledger.to_snapshot_bytes();
    let reloaded = CivicPointLedger::from_snapshot_bytes(&snap).unwrap();
    assert_eq!(reloaded.available_balance(&contributor), 700);
    assert_eq!(reloaded.spends().len(), 1);
    assert!(reloaded.has_grant(&contributor, PerkKind::PriorityScheduling, NOW + 1));
    assert_eq!(reloaded.to_snapshot_bytes(), snap, "deterministic");
}
