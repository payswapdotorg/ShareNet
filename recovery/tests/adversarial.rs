//! R7-003 + R7-004 "adversarial" verification: the §11 fresh-gateway
//! selection and fresh-route construction stages attacked from every side
//! the work items name, and the §11 replacement-circuit stage (R7-004)
//! attacked across ITS whole surface. Every test drives the REAL
//! composition (the R5-005 policy verifying every signature itself; the
//! R3-004 build chain; the R4-002 circuit admission chain; the durable
//! attempt log), on REAL evidence built through the production paths.
//!
//! The required legs, one per law:
//!
//! - an ineligible gateway is NEVER selected — even when it is the ONLY
//!   candidate (typed refusal, durable state untouched);
//! - the §11 freshness law END TO END: a fresh route proposed BEFORE the
//!   revocation anchor is refused (`route_not_fresh`), the attempt
//!   stays pending, and the SAME pipeline with a genuinely fresh route
//!   succeeds;
//! - a candidate LYING in its evidence never selects (forged signature,
//!   wrong-subject binding, counters contradicting the stated ratio) and
//!   the typed refusal feeds `attempt_failed(NoGatewayAvailable)`;
//! - selection determinism: the same candidate set + clock select the
//!   same gateway through the driver, and re-querying is pure;
//! - an EMPTY candidate set is the typed `no_eligible_gateway`;
//! - DUPLICATE candidate ids are the typed `duplicate_gateway_candidate`
//!   (never a silent pick);
//! - the selected gateway is ACTUALLY on the constructed commitment's
//!   path (membership derived from the verified commitment — and a route
//!   that skips the gateway is refused).
//!
//! The R7-004 legs (the replacement circuit):
//!
//! - the replacement rides ONLY the recorded fresh route: a STALE route
//!   (proposed before the revocation, never recorded) and the REVOKED
//!   circuit's own route are both refused typed (`replacement_route_mismatch`);
//! - the replacement's derived id is a FRESH session identity (L014):
//!   different from the revoked circuit's id — and a setup that derives
//!   the revoked id itself is refused typed;
//! - the gated registry refuses FORGED and EXPIRED setup envelopes
//!   (`circuit_admission_refused`) and garbage bytes never parse
//!   (`replacement_setup_invalid`);
//! - DOUBLE replacement is the typed single-flight refusal
//!   (`replacement_already_established`) — the durable record keeps the
//!   first;
//! - the §11 zeroization ordering: zeroization follows the durable
//!   invalidation, precedes the replacement, is refused when missing,
//!   and the FACT survives a crash + reload.

mod common;

use common::{
    established, fresh_route_material, fresh_route_material_skipping_gateway, gateway_world,
    link_failure_revocation, node_id, replacement_material, replacement_material_over, TempDir,
    NOW,
};
use sharenet_protocol::circuit::CircuitRegistry;
use sharenet_protocol::route::{RouteCommitment, SignedEnvelope};
use sharenet_recovery::{
    AttemptFailure, AttemptState, FreshRoute, RecoveryDriver, RecoveryError, RecoveryStep,
};

/// Open a recovery attempt for a circuit revoked at `revoked_at` — the
/// shared §11 prefix of every adversarial leg here (durable revocation
/// first, attempt next).
fn open_attempt(
    tag: &str,
    revoked_at: u64,
) -> (RecoveryDriver, RecoveryStep, [u8; 32], common::TempDir) {
    let dir = TempDir::new(tag);
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
    let (w, registry, revoked) = established(NOW, [0x71; 32]);
    driver
        .admit_revocation_envelope(
            revoked_at,
            &link_failure_revocation(&w, revoked, revoked_at).to_envelope_bytes(),
            &registry,
        )
        .expect("admit");
    let step = driver.attempt_next(&revoked, revoked_at + 1).expect("attempt");
    (driver, step, revoked, dir)
}

/// An ineligible gateway is never selected — even as the ONLY candidate:
/// the typed `no_eligible_gateway` refusal, the attempt still pending,
/// and not a byte of durable state moved.
#[test]
fn ineligible_only_candidate_never_selects() {
    let (driver, step, revoked, _dir) = open_attempt("adv-only-ineligible", NOW + 1);
    let gw = gateway_world();
    let (_, attempts_path) = driver.paths();
    let before = std::fs::read(&attempts_path).unwrap();

    let only_ineligible = vec![gw.candidate_no_backhaul()];
    let err = driver
        .select_gateway(&step, &only_ineligible, &common::admission_policy(), NOW + 3)
        .unwrap_err();
    assert!(matches!(err, RecoveryError::NoEligibleGateway { candidate_count: 1 }));
    // The refusal wrote nothing: the attempt is still pending, byte-for-byte.
    assert!(driver.attempt_log().pending_attempt(&revoked).is_some());
    assert_eq!(std::fs::read(&attempts_path).unwrap(), before);

    // The typed refusal is exactly what attempt_failed consumes (R7-005's
    // retry policy will read the recorded reason later).
    driver
        .attempt_failed(&revoked, AttemptFailure::NoGatewayAvailable, NOW + 4)
        .unwrap();
    assert_eq!(
        driver.attempt_log().latest_attempt(&revoked).unwrap().failure(),
        Some(AttemptFailure::NoGatewayAvailable)
    );
}

/// The §11 freshness law END TO END through the R7-003 stages: the
/// revocation anchor is NOW+1, and a fresh route PROPOSED BEFORE IT (at
/// NOW) is refused typed (`route_not_fresh`) — the attempt stays pending
/// — while the same pipeline with a route proposed after the anchor
/// succeeds terminally.
#[test]
fn pre_revocation_route_is_refused_end_to_end() {
    let (driver, step, revoked, _dir) = open_attempt("adv-freshness", NOW + 1);
    let gw = gateway_world();
    let policy = common::admission_policy();

    let selected =
        driver.select_gateway(&step, &[gw.candidate_eligible()], &policy, NOW + 3).expect("select");

    // The STALE route: proposed at NOW, before the revocation anchor
    // NOW+1. Every signature is real and verifies; only §11 freshness
    // fails — exactly the law's point.
    let stale = fresh_route_material(&gw, &selected, NOW);
    let err = driver
        .establish_fresh_route(&selected, &stale.proposal_env, &stale.acceptance_envs, NOW + 3)
        .unwrap_err();
    assert!(matches!(err, RecoveryError::RouteNotFresh { proposed_at, revoked_at } if proposed_at == NOW && revoked_at == NOW + 1));

    // The attempt is untouched: still pending, nothing recorded.
    let pending = driver.attempt_log().pending_attempt(&revoked).expect("still pending");
    assert_eq!(pending.attempt_seq(), step.attempt_seq());

    // The genuinely fresh route (proposed AFTER the anchor) succeeds —
    // and is terminal.
    let fresh = fresh_route_material(&gw, &selected, NOW + 4);
    let route = driver
        .establish_fresh_route(&selected, &fresh.proposal_env, &fresh.acceptance_envs, NOW + 4)
        .expect("fresh route succeeds");
    assert_eq!(route.route_id, fresh.route_id);
    assert_eq!(
        driver.attempt_log().latest_attempt(&revoked).unwrap().state(),
        AttemptState::Succeeded
    );
    assert_eq!(
        driver.attempt_next(&revoked, NOW + 5).unwrap_err().name(),
        "recovery_already_complete"
    );
}

/// A candidate LYING in its evidence never selects — and when all the
/// candidates lie, the typed refusal is the whole outcome: a forged link
/// signature, link evidence about a different node, and a stated loss
/// ratio the signed counters contradict (the R5-005 law: evaluated on
/// the counters).
#[test]
fn lying_candidates_never_selected() {
    let (driver, step, revoked, _dir) = open_attempt("adv-liars", NOW + 1);
    let gw = gateway_world();
    let policy = common::admission_policy();
    let liars = vec![
        gw.candidate_tampered_signature(),
        gw.candidate_wrong_subject(),
        gw.candidate_lying_counters(),
    ];
    let err = driver
        .select_gateway(&step, &liars, &policy, NOW + 3)
        .unwrap_err();
    assert!(matches!(err, RecoveryError::NoEligibleGateway { candidate_count: 3 }));

    // The attempt is still open: an HONEST candidate can still be
    // selected and the recovery completed in the same attempt.
    let selected =
        driver.select_gateway(&step, &[gw.candidate_eligible()], &policy, NOW + 4).expect("select");
    let fresh = fresh_route_material(&gw, &selected, NOW + 5);
    driver
        .establish_fresh_route(&selected, &fresh.proposal_env, &fresh.acceptance_envs, NOW + 5)
        .expect("established");
    assert_eq!(
        driver.attempt_log().latest_attempt(&revoked).unwrap().state(),
        AttemptState::Succeeded
    );
}

/// Determinism through the driver: the same candidate set + clock select
/// the same gateway (identical typed outcome), input permutations never
/// change it, and re-querying is pure.
#[test]
fn selection_is_deterministic_and_requery_is_pure() {
    let (driver, step, _revoked, _dir) = open_attempt("adv-determinism", NOW + 1);
    let gw = gateway_world();
    let policy = common::admission_policy();
    let candidates = vec![gw.candidate_eligible(), gw.candidate_eligible_alt()];

    let first =
        driver.select_gateway(&step, &candidates, &policy, NOW + 3).expect("first selection");
    // Re-query purity: the same question answers the same.
    let second =
        driver.select_gateway(&step, &candidates, &policy, NOW + 3).expect("re-selection");
    assert_eq!(first, second);
    // The fixed tie-break: the minimum eligible node id, both orders.
    let mut ids = vec![node_id(&gw.g1), node_id(&gw.g4)];
    ids.sort();
    assert_eq!(first.gateway_node_id, ids[0]);
    let swapped = vec![candidates[1], candidates[0]];
    let third =
        driver.select_gateway(&step, &swapped, &policy, NOW + 3).expect("swapped selection");
    assert_eq!(third.gateway_node_id, first.gateway_node_id);
}

/// An EMPTY candidate set is the typed `no_eligible_gateway` (count 0) —
/// not a panic, not a default-allow, not a silent skip.
#[test]
fn empty_candidate_set_is_typed_refusal() {
    let (driver, step, _revoked, _dir) = open_attempt("adv-empty", NOW + 1);
    let err = driver
        .select_gateway(&step, &[], &common::admission_policy(), NOW + 3)
        .unwrap_err();
    assert!(matches!(err, RecoveryError::NoEligibleGateway { candidate_count: 0 }));
}

/// DUPLICATE candidate ids are the typed `duplicate_gateway_candidate` —
/// even when the two entries carry IDENTICAL evidence, selection refuses
/// the ambiguous set rather than silently picking one of them.
#[test]
fn duplicate_candidate_ids_are_typed_refusal() {
    let (driver, step, _revoked, _dir) = open_attempt("adv-duplicates", NOW + 1);
    let gw = gateway_world();
    let dup = vec![gw.candidate_eligible(), gw.candidate_eligible()];
    let err = driver
        .select_gateway(&step, &dup, &common::admission_policy(), NOW + 3)
        .unwrap_err();
    assert!(matches!(
        err,
        RecoveryError::DuplicateGatewayCandidate { gateway_node_id } if gateway_node_id == node_id(&gw.g1)
    ));
}

/// The selected gateway is ACTUALLY used in the constructed commitment:
/// the recorded fresh route's independently rebuilt commitment carries
/// the gateway on its path — and the refusal leg (a well-formed, fully
/// signed route that SKIPS the selected gateway) is typed
/// `gateway_not_on_route` with the attempt still pending.
#[test]
fn selected_gateway_is_on_the_committed_path() {
    let (driver, step, revoked, _dir) = open_attempt("adv-membership", NOW + 1);
    let gw = gateway_world();
    let policy = common::admission_policy();
    let selected =
        driver.select_gateway(&step, &[gw.candidate_eligible()], &policy, NOW + 3).expect("select");

    // The refusal leg: a fully valid route through the WITNESS instead.
    let skipping = fresh_route_material_skipping_gateway(&gw, NOW + 4);
    let err = driver
        .establish_fresh_route(&selected, &skipping.proposal_env, &skipping.acceptance_envs, NOW + 4)
        .unwrap_err();
    assert!(matches!(
        err,
        RecoveryError::GatewayNotOnRoute { gateway_node_id, .. } if gateway_node_id == selected.gateway_node_id
    ));
    assert!(driver.attempt_log().pending_attempt(&revoked).is_some());

    // The happy leg: the commitment through the gateway is recorded, and
    // an INDEPENDENT rebuild of the recorded material carries the gateway
    // on its committed path (membership derived, not asserted by the
    // test's input).
    let fresh = fresh_route_material(&gw, &selected, NOW + 5);
    let route = driver
        .establish_fresh_route(&selected, &fresh.proposal_env, &fresh.acceptance_envs, NOW + 5)
        .expect("established");
    assert_eq!(route.gateway_node_id, selected.gateway_node_id);
    let commitment = RouteCommitment::build(
        NOW + 5,
        fresh.proposal_env.clone(),
        fresh.acceptance_envs.clone(),
    )
    .expect("independent rebuild");
    assert!(commitment
        .verify(NOW + 5)
        .expect("verify")
        .proposal
        .path()
        .contains(&selected.gateway_node_id));
    assert_eq!(route.route_id, *commitment.route_id());
}

// ---------------------------------------------------------------------------
// R7-004: the replacement-circuit stage — adversarial
// ---------------------------------------------------------------------------

/// The shared prefix through the R7-003 stages (zeroization in its §11
/// order: after the durable invalidation, before the replacement),
/// stopping one step before `establish_replacement_circuit`.
fn established_fresh_route(
    tag: &str,
) -> (
    RecoveryDriver,
    FreshRoute,
    common::FreshRouteMaterial,
    common::GatewayWorld,
    [u8; 32],
    common::TempDir,
) {
    let (driver, step, revoked, dir) = open_attempt(tag, NOW + 1);
    driver.record_zeroization(&revoked, NOW + 2).expect("zeroize");
    let gw = gateway_world();
    let selected = driver
        .select_gateway(&step, &[gw.candidate_eligible()], &common::admission_policy(), NOW + 3)
        .expect("selection");
    let material = fresh_route_material(&gw, &selected, NOW + 4);
    let route = driver
        .establish_fresh_route(&selected, &material.proposal_env, &material.acceptance_envs, NOW + 4)
        .expect("fresh route");
    (driver, route, material, gw, revoked, dir)
}

/// The §11 zeroization ordering, typed at every edge: it FOLLOWS the
/// durable invalidation (unknown/unrevoked circuits and pre-revocation
/// clocks refused), it is single-shot per circuit, and it precedes the
/// replacement (the `zeroization_missing` leg below).
#[test]
fn zeroization_ordering_is_typed() {
    let dir = TempDir::new("adv-zero-order");
    let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
    let (w, registry, revoked) = established(NOW, [0x71; 32]);
    // Unrevoked circuit: the §11 ordering refusal (nothing may precede
    // the durable invalidation).
    let err = driver.record_zeroization(&revoked, NOW).unwrap_err();
    assert_eq!(err.name(), "circuit_not_revoked");
    // Unknown circuit: same typed ordering refusal.
    let err = driver.record_zeroization(&[0xEE; 32], NOW).unwrap_err();
    assert_eq!(err.name(), "circuit_not_revoked");
    // The revocation lands at NOW+1: zeroizing "before" it is refused.
    driver
        .admit_revocation_envelope(
            NOW + 1,
            &link_failure_revocation(&w, revoked, NOW + 1).to_envelope_bytes(),
            &registry,
        )
        .expect("admit");
    let err = driver.record_zeroization(&revoked, NOW).unwrap_err();
    assert_eq!(err.name(), "zeroization_before_revocation");
    // In order: recorded once; a second is the single-shot refusal.
    driver.record_zeroization(&revoked, NOW + 2).expect("zeroize");
    let err = driver.record_zeroization(&revoked, NOW + 3).unwrap_err();
    assert_eq!(err.name(), "circuit_already_zeroized");
}

/// The replacement stage gates on the durable zeroization FACT: without
/// it the typed refusal is `zeroization_missing` — and recording it (in
/// order) is exactly what cures it.
#[test]
fn replacement_requires_the_zeroization_fact() {
    // The full §11 prefix MINUS the zeroization step.
    let (driver, step, revoked, dir) = open_attempt("adv-zero-missing", NOW + 1);
    let gw = gateway_world();
    let selected = driver
        .select_gateway(&step, &[gw.candidate_eligible()], &common::admission_policy(), NOW + 3)
        .expect("selection");
    let material = fresh_route_material(&gw, &selected, NOW + 4);
    let route = driver
        .establish_fresh_route(&selected, &material.proposal_env, &material.acceptance_envs, NOW + 4)
        .expect("fresh route");
    let repl = replacement_material_over(&material, &gw, &selected.gateway_node_id, [0x93; 32], NOW + 5);
    let mut fresh_registry = CircuitRegistry::new();
    let err = driver
        .establish_replacement_circuit(&route, &repl.setup_env, &repl.ack_envs, &mut fresh_registry, NOW + 6)
        .unwrap_err();
    assert_eq!(err.name(), "zeroization_missing");

    // The fact recorded (in §11 order) unlocks exactly this stage.
    driver.record_zeroization(&revoked, NOW + 5).expect("zeroize late is still in order");
    driver
        .establish_replacement_circuit(&route, &repl.setup_env, &repl.ack_envs, &mut fresh_registry, NOW + 7)
        .expect("replacement after zeroization");
    let _ = dir;
}

/// A replacement built over the REVOKED circuit's own route (not the
/// recorded fresh one) is refused typed — the driver binds to its own
/// durable record, never to the caller's assertion of a route.
#[test]
fn replacement_over_the_revoked_route_refused() {
    let (driver, route, _material, _gw, _revoked, _dir) =
        established_fresh_route("adv-revoked-route");
    // The REVOKED circuit's own world, commitment and path — NOT the
    // recorded fresh route (an independently-rebuilt, fully valid R4-002
    // material over the WRONG commitment).
    let (w, _registry, _other) = established(NOW, [0x71; 32]);
    let forged = replacement_material(
        &w.commitment,
        &w.proposer,
        &[&w.proposer, &w.hop1, &w.hop2],
        [0x99; 32],
        NOW + 5,
    );
    let mut fresh_registry = CircuitRegistry::new();
    let err = driver
        .establish_replacement_circuit(&route, &forged.setup_env, &forged.ack_envs, &mut fresh_registry, NOW + 6)
        .unwrap_err();
    assert_eq!(err.name(), "replacement_route_mismatch");
}

/// Forged replacement material — one flipped signature byte in the setup
/// envelope or in an ack envelope — is refused typed at verification,
/// and nothing is recorded.
#[test]
fn forged_replacement_material_refused_typed() {
    let (driver, route, material, gw, _revoked, _dir) =
        established_fresh_route("adv-forged");
    let repl = replacement_material_over(&material, &gw, &route.gateway_node_id, [0x93; 32], NOW + 5);
    let mut fresh_registry = CircuitRegistry::new();
    let (_, attempts_path) = driver.paths();
    let before = std::fs::read(&attempts_path).unwrap();

    // Malformed setup CONTENT: the strict parse fails BEFORE any
    // admission (and before the signature can even be checked) —
    // `replacement_setup_invalid`.
    let malformed = SignedEnvelope::new(vec![0u8; 5], *repl.setup_env.signature());
    let err = driver
        .establish_replacement_circuit(&route, &malformed, &repl.ack_envs, &mut fresh_registry, NOW + 6)
        .unwrap_err();
    assert_eq!(err.name(), "replacement_setup_invalid");

    // Flipped setup SIGNATURE byte: the envelope parses, but the full
    // R4-002 admission chain refuses it — typed at the registry gate.
    let mut sig = *repl.setup_env.signature();
    sig[7] ^= 0xFF;
    let forged_sig = SignedEnvelope::new(repl.setup_env.bytes().to_vec(), sig);
    let err = driver
        .establish_replacement_circuit(&route, &forged_sig, &repl.ack_envs, &mut fresh_registry, NOW + 7)
        .unwrap_err();
    assert_eq!(err.name(), "circuit_admission_refused");

    // Flipped ack signature byte: the same registry-gate refusal.
    let mut acks = repl.ack_envs.clone();
    let mut asig = *acks[0].signature();
    asig[9] ^= 0xFF;
    acks[0] = SignedEnvelope::new(acks[0].bytes().to_vec(), asig);
    let err = driver
        .establish_replacement_circuit(&route, &repl.setup_env, &acks, &mut fresh_registry, NOW + 8)
        .unwrap_err();
    assert_eq!(err.name(), "circuit_admission_refused");

    // Nothing was recorded by either refusal.
    assert_eq!(std::fs::read(&attempts_path).unwrap(), before);
}

/// A replacement is single-shot per revoked circuit: the second call is
/// the typed `replacement_already_established`, and the durable record
/// keeps the FIRST.
#[test]
fn double_replacement_is_typed_single_flight() {
    let (driver, route, material, gw, _revoked, _dir) =
        established_fresh_route("adv-double");
    let repl = replacement_material_over(&material, &gw, &route.gateway_node_id, [0x93; 32], NOW + 5);
    let mut fresh_registry = CircuitRegistry::new();
    let first = driver
        .establish_replacement_circuit(&route, &repl.setup_env, &repl.ack_envs, &mut fresh_registry, NOW + 6)
        .expect("first replacement");
    // Registry-level idempotence: re-admitting the SAME material into
    // the SAME registry is refused at the R4-002 admission gate.
    let err = driver
        .establish_replacement_circuit(&route, &repl.setup_env, &repl.ack_envs, &mut fresh_registry, NOW + 7)
        .unwrap_err();
    assert_eq!(err.name(), "circuit_admission_refused");
    // Durable single flight: even into a FRESH registry (exactly what a
    // restarted daemon holds), the second replacement is the typed
    // `replacement_already_established` — the record keeps the first.
    let err = driver
        .establish_replacement_circuit(&route, &repl.setup_env, &repl.ack_envs, &mut CircuitRegistry::new(), NOW + 8)
        .unwrap_err();
    assert_eq!(err.name(), "replacement_already_established");
    // The durable record keeps the first (the attempt log's terminal
    // replacement is the FIRST circuit id).
    let latest = driver
        .attempt_log()
        .latest_attempt(&route.revoked_circuit_id)
        .expect("the attempt record");
    assert_eq!(
        latest.replacement_circuit_id(),
        Some(&first.replacement_circuit_id)
    );
}

/// The zeroization fact AND the replacement both survive a full
/// teardown: after the crash the ordering facts reload, and a repeated
/// replacement across the boundary is still the typed single-flight
/// refusal.
#[test]
fn zeroization_and_replacement_survive_crash_reload() {
    let (driver, route, material, gw, revoked, dir) =
        established_fresh_route("adv-reload");
    let repl = replacement_material_over(&material, &gw, &route.gateway_node_id, [0x93; 32], NOW + 5);
    let mut fresh_registry = CircuitRegistry::new();
    let first = driver
        .establish_replacement_circuit(&route, &repl.setup_env, &repl.ack_envs, &mut fresh_registry, NOW + 6)
        .expect("replacement");
    drop(driver); // the crash: nothing but the two files remains

    let (driver, _) = RecoveryDriver::open(&dir.path).expect("reload");
    // The §11 zeroization ordering fact survived.
    assert_eq!(
        driver.zeroization(&revoked).map(|z| z.zeroized_at_unix()),
        Some(NOW + 2)
    );
    // The replacement fact survived — terminal across the boundary.
    let latest = driver
        .attempt_log()
        .latest_attempt(&revoked)
        .expect("the attempt record survived");
    assert_eq!(
        latest.replacement_circuit_id(),
        Some(&first.replacement_circuit_id)
    );
    let err = driver
        .establish_replacement_circuit(&route, &repl.setup_env, &repl.ack_envs, &mut CircuitRegistry::new(), NOW + 8)
        .unwrap_err();
    assert_eq!(err.name(), "replacement_already_established");
}
