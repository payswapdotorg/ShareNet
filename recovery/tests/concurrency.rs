//! R7-002 "concurrency" verification: multi-threaded admit/finish/begin
//! interleavings against SHARED stores (the crate's own prescribed
//! pattern — the stores are internally mutex-guarded with `&self`
//! mutation, the R7-001 posture; cross-PROCESS single-writer discipline
//! is the caller's and is honestly out of scope here). What is proven:
//!
//! - **single flight under racing begins** — exactly one thread opens an
//!   attempt for a revoked circuit, every other thread gets the typed
//!   `attempt_already_pending` (no duplicate pending records, ever);
//! - **exactly-once finish under racing finishes** — exactly one thread
//!   finishes the pending attempt; the losers are typed `no_pending`;
//!   the winner's outcome is what the disk shows (no lost updates);
//! - **idempotence + no lost updates under racing admits** — the same
//!   envelope racing itself collapses to one record; three distinct
//!   revokers all land; the reloaded chain verifies everything;
//! - **concurrent loads during mutation never parse garbage** — readers
//!   racing appends only ever see a complete image or a torn TAIL
//!   (reported), never a corrupted middle;
//! - **full lifecycles interleaved over one shared driver** — several
//!   circuits recover concurrently; every refusal is typed and the
//!   final state reloads consistent.

mod common;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread::scope;
use std::time::{Duration, Instant};

use common::{
    admit_circuit, established, link_failure_revocation, operator_revocation, policy_revocation,
    TempDir, NOW,
};
use sharenet_recovery::{
    AttemptFailure, AttemptState, DurableRevocationLedger, FreshRouteEvidence, RecoveryDriver,
    RecoveryStep,
};

/// Racing begins on one revoked circuit: exactly one wins (seq 1), the
/// rest are typed `attempt_already_pending`, and the durable log holds
/// exactly one pending record.
#[test]
fn concurrent_begin_single_flight() {
    let dir = TempDir::new("conc-begin");
    let (w, registry, revoked) = established(NOW, [0x71; 32]);
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
    driver
        .admit_revocation_envelope(
            NOW,
            &link_failure_revocation(&w, revoked, NOW).to_envelope_bytes(),
            &registry,
        )
        .expect("admit");

    let driver = &driver;
    let results = scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|i| s.spawn(move || driver.attempt_next(&revoked, NOW + 1 + i)))
            .collect();
        handles.into_iter().map(|h| h.join().expect("thread")).collect::<Vec<_>>()
    });

    let wins = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(wins, 1, "exactly one begin may win");
    for result in &results {
        match result {
            Ok(RecoveryStep::SelectFreshGateway { attempt_seq, revoked_circuit_id }) => {
                assert_eq!(*attempt_seq, 1);
                assert_eq!(*revoked_circuit_id, revoked);
            }
            Err(err) => assert_eq!(err.name(), "attempt_already_pending"),
        }
    }
    // The durable state: exactly one pending record.
    let attempts = driver.attempt_log().attempts_for(&revoked);
    assert_eq!(attempts.len(), 1);
    assert_eq!(attempts[0].state(), AttemptState::Pending);
    assert_eq!(attempts[0].attempt_seq(), 1);
}

#[derive(Debug)]
enum Finish {
    Failure(AttemptFailure),
    Route([u8; 32]),
}

/// Racing finishes of one pending attempt (mixed success/failure
/// outcomes): exactly one thread wins, the losers are typed
/// `no_pending_attempt`, and the reloaded-from-disk state carries the
/// WINNER's outcome (no lost updates, no double-finish).
#[test]
fn concurrent_finish_exactly_once() {
    let dir = TempDir::new("conc-finish");
    let (w, registry, revoked) = established(NOW, [0x72; 32]);
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
    driver
        .admit_revocation_envelope(
            NOW,
            &link_failure_revocation(&w, revoked, NOW).to_envelope_bytes(),
            &registry,
        )
        .expect("admit");
    let RecoveryStep::SelectFreshGateway { attempt_seq, .. } =
        driver.attempt_next(&revoked, NOW + 1).expect("begin");
    assert_eq!(attempt_seq, 1);

    let driver = &driver;
    let winners = AtomicUsize::new(0);
    let results = scope(|s| {
        let handles: Vec<_> = (0..8)
            .map(|i| {
                s.spawn(move || {
                    let finish = if i % 2 == 0 {
                        Finish::Failure(AttemptFailure::from_name("gateway_unreachable").unwrap())
                    } else {
                        Finish::Route([0xC3; 32])
                    };
                    let result = match finish {
                        Finish::Failure(reason) => {
                            driver.attempt_failed(&revoked, reason, NOW + 10)
                        }
                        Finish::Route(route) => driver.attempt_succeeded(
                            &revoked,
                            FreshRouteEvidence::RouteRef(route),
                            NOW + 10,
                        ),
                    };
                    (finish, result)
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("thread")).collect::<Vec<_>>()
    });
    for (finish, result) in &results {
        match result {
            Ok(seq) => {
                assert_eq!(*seq, 1);
                winners.fetch_add(1, Ordering::SeqCst);
            }
            Err(err) => assert_eq!(err.name(), "no_pending_attempt", "{finish:?}: {err}"),
        }
    }
    assert_eq!(winners.load(Ordering::SeqCst), 1, "exactly one finish may win");

    // The winner's outcome is what the DISK says (reload the log file
    // fresh — no shared memory with the live driver).
    let attempts_path = dir.path.join("recovery-attempts.store");
    let reloaded = sharenet_recovery::RecoveryAttemptLog::load(&attempts_path).expect("reload");
    let record = reloaded.latest_attempt(&revoked).expect("record");
    assert_eq!(record.attempt_seq(), 1);
    let winning = results
        .iter()
        .find(|(_, r)| r.is_ok())
        .map(|(f, _)| f)
        .expect("the winner");
    match winning {
        Finish::Failure(reason) => {
            assert_eq!(record.state(), AttemptState::Abandoned);
            assert_eq!(record.failure(), Some(*reason));
            assert_eq!(record.fresh_route_id(), None);
        }
        Finish::Route(route) => {
            assert_eq!(record.state(), AttemptState::Succeeded);
            assert_eq!(record.fresh_route_id(), Some(route));
            assert_eq!(record.failure(), None);
        }
    }
}

/// Racing admits: the same envelope from many threads collapses to one
/// durable record (idempotence under racing threads), three distinct
/// revokers all land (no lost updates), and the reloaded chain verifies
/// every record — the file was never torn.
#[test]
fn concurrent_admits_no_lost_updates() {
    let dir = TempDir::new("conc-admit");
    let (w, registry, revoked) = established(NOW, [0x73; 32]);
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
    let envelopes = [
        link_failure_revocation(&w, revoked, NOW).to_envelope_bytes(),
        policy_revocation(&w, revoked, NOW).to_envelope_bytes(),
        operator_revocation(&w, revoked, NOW).to_envelope_bytes(),
    ];

    let driver = &driver;
    let registry = &registry;
    let results = scope(|s| {
        let handles: Vec<_> = (0..9)
            .map(|i| {
                let env = envelopes[i % envelopes.len()].as_slice();
                s.spawn(move || driver.admit_revocation_envelope(NOW, env, registry))
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("thread")).collect::<Vec<_>>()
    });

    let mut counts = std::collections::BTreeMap::new();
    for result in &results {
        let outcome = result.as_ref().expect("admit").as_str();
        *counts.entry(outcome).or_insert(0) += 1;
    }
    // Each (circuit, revoker) is admitted once (its first thread gets
    // First-or-Additional depending on order, the rest Duplicate); three
    // distinct revokers land exactly three records.
    assert_eq!(counts.get("duplicate"), Some(&6));
    let firsts = counts.get("first").copied().unwrap_or(0)
        + counts.get("additional").copied().unwrap_or(0);
    assert_eq!(firsts, 3);
    assert_eq!(driver.revocation_ledger().record_count(), 3);
    assert_eq!(driver.revocation_ledger().revoker_count(&revoked), 3);

    // Reload from disk: the chain re-verifies everything (load re-checks
    // CRCs, signatures and the chain — a torn or interleaved write would
    // refuse typed).
    let (reloaded, report) =
        DurableRevocationLedger::load(&dir.path.join("revocations.log")).expect("reload");
    assert_eq!(report.records_loaded, 3);
    assert_eq!(report.truncated_tail_bytes, 0);
    assert!(reloaded.is_revoked(&revoked));
    assert_eq!(reloaded.revoker_count(&revoked), 3);
}

/// Concurrent loads racing real appends: every load sees a complete
/// image (possibly with a torn TAIL — reported, never resurrected) or a
/// typed refusal; nothing parses as garbage, and the final state fully
/// verifies after the writer joins.
#[test]
fn concurrent_loads_never_parse_garbage() {
    let dir = TempDir::new("conc-loads");
    let (w, mut registry, base) = established(NOW, [0x74; 32]);
    // Five circuits, three revokers each: 15 real appends for the writer.
    let mut circuits = vec![base];
    for i in 0..4 {
        circuits.push(admit_circuit(&w, &mut registry, NOW, [0x80 + i; 32]));
    }
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
    let ledger_path = dir.path.join("revocations.log");
    let done = AtomicBool::new(false);
    let loads = AtomicUsize::new(0);

    let driver = &driver;
    let w = &w;
    let registry = &registry;
    let circuits = &circuits;
    let ledger_path = ledger_path.as_path();
    let done = &done;
    let loads = &loads;
    scope(|s| {
        // The writer: 15 durable appends (each append+fsync serialized by
        // the store's own mutex — the prescribed single-writer posture).
        // The admission clock must cover every revoked_at (the ledger
        // refuses future-dated revocations — that typed refusal is
        // itself tested in the unit suite).
        s.spawn(move || {
            for (i, circuit) in circuits.iter().enumerate() {
                let envelopes = [
                    link_failure_revocation(w, *circuit, NOW + i as u64).to_envelope_bytes(),
                    policy_revocation(w, *circuit, NOW + i as u64).to_envelope_bytes(),
                    operator_revocation(w, *circuit, NOW + i as u64).to_envelope_bytes(),
                ];
                for env in &envelopes {
                    driver
                        .admit_revocation_envelope(NOW + 10, env, registry)
                        .expect("admit");
                }
            }
            done.store(true, Ordering::SeqCst);
        });
        // The readers: full fail-closed loads of a file being appended
        // to. Bounded: a writer failure surfaces as a test failure (the
        // scope propagates its panic) instead of an infinite spin.
        for _ in 0..3 {
            s.spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(30);
                while !done.load(Ordering::SeqCst) {
                    if Instant::now() > deadline {
                        panic!("reader raced past its deadline (writer stuck or failed)");
                    }
                    match DurableRevocationLedger::load(ledger_path) {
                        Ok((_, report)) => {
                            // Any torn tail is at the TAIL only: a
                            // consistent prefix, reported, never garbage.
                            assert!(report.truncated_tail_bytes == 0 || report.records_loaded >= 1);
                        }
                        Err(err) => panic!("a racing load must fail typed, got: {err}"),
                    }
                    loads.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });
    assert!(loads.load(Ordering::SeqCst) > 3, "the readers actually raced");

    // The final state fully verifies.
    let (reloaded, report) = DurableRevocationLedger::load(ledger_path).expect("final load");
    assert_eq!(report.records_loaded, 15);
    assert_eq!(report.truncated_tail_bytes, 0);
    assert_eq!(reloaded.revoked_circuit_count(), 5);
    for circuit in circuits {
        assert!(reloaded.is_revoked(circuit));
        assert_eq!(reloaded.revoker_count(circuit), 3);
    }
}

/// Full §11 lifecycles interleaved over ONE shared driver: four revoked
/// circuits recover concurrently (fail-then-retry-then-succeed), a
/// duplicate-admit thread races the ledger, and every refusal along the
/// way is typed. The reloaded final state is exactly the sum of the
/// winners.
#[test]
fn shared_driver_interleaved_lifecycles() {
    let dir = TempDir::new("conc-driver");
    let (w, mut registry, base) = established(NOW, [0x75; 32]);
    let mut circuits = vec![base];
    for i in 0..3 {
        circuits.push(admit_circuit(&w, &mut registry, NOW, [0x90 + i; 32]));
    }
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
    for circuit in &circuits {
        driver
            .admit_revocation_envelope(
                NOW,
                &link_failure_revocation(&w, *circuit, NOW).to_envelope_bytes(),
                &registry,
            )
            .expect("admit");
    }
    let duplicate_env = link_failure_revocation(&w, base, NOW).to_envelope_bytes();

    let driver = &driver;
    let w = &w;
    let registry = &registry;
    let circuits = &circuits;
    scope(|s| {
        // One recovery worker per circuit: attempt -> fail -> attempt ->
        // succeed (each thread's refusals along the way are typed).
        for circuit in circuits {
            s.spawn(move || {
                let RecoveryStep::SelectFreshGateway { attempt_seq, .. } =
                    driver.attempt_next(circuit, NOW + 1).expect("first attempt");
                assert_eq!(attempt_seq, 1);
                // A racing second begin on the same circuit is refused.
                let err = driver.attempt_next(circuit, NOW + 2).unwrap_err();
                assert_eq!(err.name(), "attempt_already_pending");
                driver
                    .attempt_failed(circuit, AttemptFailure::NoGatewayAvailable, NOW + 3)
                    .expect("abandon 1");
                let RecoveryStep::SelectFreshGateway { attempt_seq, .. } =
                    driver.attempt_next(circuit, NOW + 4).expect("second attempt");
                assert_eq!(attempt_seq, 2);
                driver
                    .attempt_succeeded(
                        circuit,
                        FreshRouteEvidence::Commitment(&w.commitment),
                        NOW + 5,
                    )
                    .expect("succeed");
            });
        }
        // A duplicate admit racing everything: idempotent, no new record.
        s.spawn(move || {
            for _ in 0..4 {
                let outcome = driver
                    .admit_revocation_envelope(NOW, &duplicate_env, registry)
                    .expect("duplicate admit");
                assert_eq!(outcome.as_str(), "duplicate");
            }
        });
    });

    // The reloaded state is exactly the winners': every circuit has two
    // attempts (1 abandoned, 2 succeeded), the ledger has four records.
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("reload driver");
    assert_eq!(driver.revocation_ledger().record_count(), 4);
    for circuit in circuits {
        assert!(driver.is_revoked(circuit));
        let attempts = driver.attempt_log().attempts_for(circuit);
        assert_eq!(attempts.len(), 2, "circuit {circuit:02x?}");
        assert_eq!(attempts[0].state(), AttemptState::Abandoned);
        assert_eq!(attempts[0].failure(), Some(AttemptFailure::NoGatewayAvailable));
        assert_eq!(attempts[1].state(), AttemptState::Succeeded);
        assert_eq!(attempts[1].fresh_route_id(), Some(w.commitment.route_id()));
        // Terminal after the restart, too.
        assert_eq!(
            driver.attempt_next(circuit, NOW + 6).unwrap_err().name(),
            "recovery_already_complete"
        );
    }
}
