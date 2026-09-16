//! R7-002 "restart" verification: the durable recovery state is torn down
//! completely (the `RecoveryDriver` and both stores dropped) and reloaded
//! from disk only — the two files in the driver's directory are the whole
//! truth. What is proven, per the work item's verify level:
//!
//! - **L015 END-TO-END** — a circuit revoked before the restart STAYS
//!   revoked after it: the reloaded ledger is the authority, and its
//!   R7-001 view installed into a fresh `CircuitRegistry` refuses setups
//!   for the revoked id while live siblings still admit;
//! - **the attempt log continues its per-circuit numbering** — the
//!   persisted high-water and the §11 freshness anchor (the revocation's
//!   `revoked_at`) survive the boundary, a pending attempt is still
//!   pending, and abandoned history is retained;
//! - **bounded compaction is visible across the boundary** — the retained
//!   window and the high-water survive the reload;
//! - **crash residue across a restart** — a torn ledger tail loads with
//!   the verified prefix intact and the residue reported, and the next
//!   append repairs the file.

mod common;

use common::{
    admit_circuit, established, link_failure_revocation, operator_revocation, policy_revocation,
    setup_envelope_for, TempDir, NOW,
};
use sharenet_protocol::circuit::CircuitRegistry;
use sharenet_recovery::{
    AttemptFailure, AttemptState, FreshRouteEvidence, RecoveryDriver, RecoveryStep,
};

/// L015 end to end across a full teardown: the revocation, its durable
/// record and the §11 gate on a fresh registry all survive; recovery
/// itself continues for the still-revoked circuit.
#[test]
fn revoked_stays_revoked_across_restart() {
    let dir = TempDir::new("restart-l015");
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
    let (w, mut registry, revoked) = established(NOW, [0x71; 32]);
    let live = admit_circuit(&w, &mut registry, NOW, [0x72; 32]);
    driver
        .admit_revocation_envelope(
            NOW,
            &link_failure_revocation(&w, revoked, NOW).to_envelope_bytes(),
            &registry,
        )
        .expect("admit");
    assert_eq!(driver.attempt_next(&revoked, NOW + 1).unwrap().as_str(), "select_fresh_gateway");
    driver.attempt_failed(&revoked, AttemptFailure::NoGatewayAvailable, NOW + 2).unwrap();
    drop(driver); // the full teardown — nothing but the two files remains

    let (driver, report) = RecoveryDriver::open(&dir.path).expect("reopen");
    assert_eq!(report.records_loaded, 1);
    assert_eq!(report.truncated_tail_bytes, 0);

    // The circuit is STILL revoked; the live sibling is not.
    assert!(driver.is_revoked(&revoked));
    assert!(!driver.is_revoked(&live));
    assert_eq!(driver.revocation_ledger().revoker_count(&revoked), 1);

    // The L015 gate on a FRESH registry through the reloaded ledger's
    // R7-001 view: the revoked id is refused, the sibling still admits.
    let mut gated = CircuitRegistry::new();
    gated.install_revocation_ledger(&driver.revocation_ledger().ledger());
    let err = gated.admit_setup(NOW, &setup_envelope_for(&w, NOW, [0x71; 32])).unwrap_err();
    assert_eq!(err.name(), "circuit_revoked");
    gated.admit_setup(NOW, &setup_envelope_for(&w, NOW, [0x72; 32])).expect("live admits");

    // Recovery itself continues: the abandoned attempt is history, the
    // next one opens at seq 2 and can succeed with a fresh commitment.
    let step = driver.attempt_next(&revoked, NOW + 3).expect("attempt 2");
    assert_eq!(
        step,
        RecoveryStep::SelectFreshGateway { revoked_circuit_id: revoked, attempt_seq: 2 }
    );
    driver
        .attempt_succeeded(&revoked, FreshRouteEvidence::Commitment(&w.commitment), NOW + 4)
        .unwrap();
    let attempts = driver.attempt_log().attempts_for(&revoked);
    assert_eq!(attempts.len(), 2);
    assert_eq!(attempts[0].state(), AttemptState::Abandoned);
    assert_eq!(attempts[1].state(), AttemptState::Succeeded);
    assert_eq!(attempts[1].fresh_route_id(), Some(w.commitment.route_id()));
}

/// The attempt log continues its per-circuit numbering across the
/// boundary: the pending attempt survives as pending, the abandoned
/// history with its reasons survives, and the §11 freshness anchor (the
/// revocation time, from the ledger) still refuses stale commitments.
#[test]
fn attempt_numbering_continues_across_restart() {
    let dir = TempDir::new("restart-numbering");
    // The world's commitment is proposed at NOW; the revocation lands
    // at NOW+100 — so the commitment PREDATES the revocation and the
    // stale-commitment leg of this test has a real anchor on disk.
    let (w, registry, revoked) = established(NOW, [0x73; 32]);
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
    driver
        .admit_revocation_envelope(
            NOW + 100,
            &link_failure_revocation(&w, revoked, NOW + 100).to_envelope_bytes(),
            &registry,
        )
        .expect("admit");
    driver.attempt_next(&revoked, NOW + 101).unwrap();
    driver
        .attempt_failed(&revoked, AttemptFailure::GatewayUnreachable, NOW + 102)
        .unwrap();
    driver.attempt_next(&revoked, NOW + 103).unwrap();
    driver
        .attempt_failed(&revoked, AttemptFailure::CircuitSetupFailed, NOW + 104)
        .unwrap();
    let step = driver.attempt_next(&revoked, NOW + 105).unwrap();
    let RecoveryStep::SelectFreshGateway { attempt_seq, .. } = step;
    assert_eq!(attempt_seq, 3);
    drop(driver); // teardown with attempt 3 pending

    let (driver, _) = RecoveryDriver::open(&dir.path).expect("reopen");
    // The pending attempt is still pending, the history is intact.
    let pending = driver.attempt_log().pending_attempt(&revoked).expect("pending survived");
    assert_eq!(pending.attempt_seq(), 3);
    assert_eq!(pending.started_at_unix(), NOW + 105);
    let history = driver.attempt_log().attempts_for(&revoked);
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].failure(), Some(AttemptFailure::GatewayUnreachable));
    assert_eq!(history[1].failure(), Some(AttemptFailure::CircuitSetupFailed));

    // The §11 freshness anchor survived on disk: the commitment proposed
    // BEFORE the revocation is still refused after the restart.
    let err = driver
        .attempt_succeeded(&revoked, FreshRouteEvidence::Commitment(&w.commitment), NOW + 110)
        .unwrap_err();
    assert_eq!(err.name(), "route_not_fresh");
    // The attempt stays pending; finish it honestly, then the next one
    // numbers at 4 (the high-water never regresses).
    driver.attempt_failed(&revoked, AttemptFailure::VerificationFailed, NOW + 111).unwrap();
    let RecoveryStep::SelectFreshGateway { attempt_seq, .. } =
        driver.attempt_next(&revoked, NOW + 112).unwrap();
    assert_eq!(attempt_seq, 4);
}

/// The bounded log compacts across the boundary: after MAX+6 abandoned
/// attempts the reload retains the last MAX, and the next attempt
/// continues at the persisted high-water.
#[test]
fn compaction_and_high_water_across_restart() {
    let dir = TempDir::new("restart-compaction");
    let (w, registry, revoked) = established(NOW, [0x74; 32]);
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
    driver
        .admit_revocation_envelope(
            NOW,
            &link_failure_revocation(&w, revoked, NOW).to_envelope_bytes(),
            &registry,
        )
        .expect("admit");
    let total = 64 + 6;
    for i in 0..total {
        driver.attempt_next(&revoked, NOW + i).unwrap();
        driver
            .attempt_failed(&revoked, AttemptFailure::GatewayUnreachable, NOW + i)
            .unwrap();
    }
    drop(driver);

    // Reload: the retained window is the last 64, the oldest six are gone.
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("reopen");
    let attempts = driver.attempt_log().attempts_for(&revoked);
    assert_eq!(attempts.len(), 64);
    assert_eq!(attempts.first().unwrap().attempt_seq(), 7);
    assert_eq!(attempts.last().unwrap().attempt_seq(), total as u64);

    // The high-water continues: the next attempt is 71, then success is
    // terminal across this boundary too.
    let step = driver.attempt_next(&revoked, NOW + 100).expect("attempt 71");
    assert_eq!(
        step,
        RecoveryStep::SelectFreshGateway { revoked_circuit_id: revoked, attempt_seq: 71 }
    );
    driver
        .attempt_succeeded(&revoked, FreshRouteEvidence::Commitment(&w.commitment), NOW + 101)
        .unwrap();
    drop(driver);
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("reopen 2");
    assert_eq!(
        driver.attempt_next(&revoked, NOW + 102).unwrap_err().name(),
        "recovery_already_complete"
    );
    let attempts = driver.attempt_log().attempts_for(&revoked);
    assert_eq!(attempts.last().unwrap().state(), AttemptState::Succeeded);
    assert_eq!(attempts.last().unwrap().attempt_seq(), 71);
}

/// Crash residue across a restart: a torn tail in the ledger file (a
/// crash mid-append) loads with the verified prefix intact, the residue
/// is reported, and the NEXT append repairs the file — the driver's
/// `open` path surfaces the whole story.
#[test]
fn torn_tail_crash_residue_across_restart() {
    let dir = TempDir::new("restart-torn");
    let (w, registry, revoked) = established(NOW, [0x75; 32]);
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
    driver
        .admit_revocation_envelope(
            NOW,
            &link_failure_revocation(&w, revoked, NOW).to_envelope_bytes(),
            &registry,
        )
        .expect("admit");
    driver
        .admit_revocation_envelope(
            NOW,
            &policy_revocation(&w, revoked, NOW).to_envelope_bytes(),
            &registry,
        )
        .expect("admit");
    drop(driver);

    // The crash: half a record frame lands on disk.
    let ledger_path = {
        let (probe, _) = RecoveryDriver::open(&dir.path).expect("probe paths");
        probe.paths().0
    };
    let mut torn = std::fs::read(&ledger_path).expect("read");
    let clean_len = torn.len() as u64;
    torn.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55]);
    std::fs::write(&ledger_path, &torn).expect("write torn");

    // Restart: the load reports the residue and keeps the verified prefix.
    let (driver, report) = RecoveryDriver::open(&dir.path).expect("reopen");
    assert_eq!(report.records_loaded, 2);
    assert_eq!(report.truncated_tail_bytes, 5);
    assert!(driver.is_revoked(&revoked));
    assert_eq!(driver.revocation_ledger().revoker_count(&revoked), 2);
    let _ = clean_len;

    // The next append repairs the tail (the only repair the durable layer
    // ever does), and the third revoker's record lands cleanly.
    driver
        .admit_revocation_envelope(
            NOW,
            &operator_revocation(&w, revoked, NOW).to_envelope_bytes(),
            &registry,
        )
        .expect("admit");
    drop(driver);
    let (driver, report) = RecoveryDriver::open(&dir.path).expect("reopen 2");
    assert_eq!(report.records_loaded, 3);
    assert_eq!(report.truncated_tail_bytes, 0);
    assert_eq!(driver.revocation_ledger().revoker_count(&revoked), 3);
}
