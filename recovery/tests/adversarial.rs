//! R7-003 "adversarial" verification: the §11 fresh-gateway selection
//! and fresh-route construction stages attacked from every side the work
//! item names. Every test drives the REAL composition (the R5-005 policy
//! verifying every signature itself; the R3-004 build chain; the durable
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

mod common;

use common::{
    established, fresh_route_material, fresh_route_material_skipping_gateway, gateway_world,
    link_failure_revocation, node_id, TempDir, NOW,
};
use sharenet_protocol::route::RouteCommitment;
use sharenet_recovery::{
    AttemptFailure, AttemptState, RecoveryDriver, RecoveryError, RecoveryStep,
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
