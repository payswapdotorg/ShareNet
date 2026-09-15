//! R5-005 "Gateway admission" INTEGRATION verification: the full
//! composition over the REAL primitives of all three predecessor work
//! items — R3-003 topology evidence, R5-004 signed observations + their
//! admission, R5-003 durable projection store — with NO fakes.
//!
//! What is proven, per the work item's verify levels:
//!
//! - **the full composition admits** — a real `TopologyEvidence` link
//!   observation built + signed + collector-verified through the R3-003
//!   API, real `SignedConnectivityObservation`s admitted through the
//!   R5-004 `ObservationAdmission` (signature, known contract, sequence
//!   gate, freshness), mapped into the domain, accepted + flushed + RELOADED
//!   by a real `DurableProjectionStore` on a real temp file → the policy
//!   decides `Eligible` with the exact evidence anchors;
//! - **degrade cases fail closed with typed reasons and exact math** —
//!   stale ShareNet evidence (`sharenet_evidence_stale`, both the
//!   cryptographic window and the policy window), unfresh projection
//!   (`projection_stale`, with the store's ORIGINAL no-re-anchoring
//!   metadata), non-active contracts (`adcos_contract_not_active`);
//! - **the quality floor and latency bound edges** — the exact floor
//!   passes, one ppm above fails, the exact microsecond bound passes,
//!   one microsecond above fails, and the integer ppm math is asserted
//!   including the counter cross-check that catches an understating
//!   observer;
//! - **redeliveries still admit** — the provider's redelivery shape (the
//!   same signed observation twice in the evidence set, the `get_assurance`
//!   residue) is not a contradiction.

mod common;

use common::{
    admission_for, canonical_link, canonical_stream, contract, fed_store, full_request,
    good_quality, identity, link_evidence, link_quality, node_id, policy, signed_observation, T,
    TempStore, STORE_WINDOW_SECS,
};
use sharenet_admission::{AdmissionReason, GatewayAdmission, GatewayAdmissionPolicy};
use sharenet_connectivity::{ContractState, DurableProjectionStore};
use sharenet_protocol::{AdmissionOutcome, EvidenceKind, ReceiveOutcome, TopologyStore};

/// The policy under test in the composition tests: 300 s evidence-age
/// window, 10,000 ppm loss floor, 50 ms latency bound.
fn default_policy() -> GatewayAdmissionPolicy {
    policy(300, 10_000, 50)
}

#[test]
fn full_composition_admits_the_gateway_through_the_real_stack() {
    let observer = identity(1);
    let gateway = identity(2);
    let provider = identity(3);
    let link = canonical_link();
    let gateway_id = node_id(&gateway);

    // The ShareNet-side evidence is REAL collector evidence: a real
    // R3-003 TopologyStore verifies + collects it at the decision clock.
    let mut topology = TopologyStore::new();
    assert_eq!(topology.receive(&link, T), Ok(ReceiveOutcome::Collected));

    // The ADCOS-side evidence: the canonical stream, admitted through the
    // R5-004 admission rule, mapped to the domain, fed to a REAL durable
    // store, flushed, and RELOADED from disk (the daemon restart path).
    let contract = contract(0xA1);
    let signed = canonical_stream(&provider, contract);
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("compose");
    {
        let store = fed_store(&temp.path, &mut admission, &signed, T);
        assert_eq!(
            store.health(&contract).expect("health").state(),
            ContractState::Active
        );
    }
    let reloaded = DurableProjectionStore::load(&temp.path, T).expect("reload from disk");
    let health = reloaded.health(&contract).expect("tracked after reload");
    assert_eq!(health.state(), ContractState::Active, "re-derived from the log");

    // The decision, over the reloaded projection:
    let decision = default_policy().decide(full_request(gateway_id, T, &link, &health, &signed));
    match &decision {
        GatewayAdmission::Eligible {
            gateway_node_id,
            sharenet,
            adcos,
            valid_until_unix,
        } => {
            assert_eq!(*gateway_node_id, gateway_id);
            // The ShareNet anchor: exactly what was admitted.
            assert_eq!(sharenet.link_id, [7; 32]);
            assert_eq!(sharenet.observer_node_id, node_id(&observer));
            assert_eq!(sharenet.observed_at_unix, T - 8);
            assert_eq!(sharenet.expires_at_unix, T + 52);
            assert_eq!(sharenet.loss_ratio_ppm_effective, 5_000);
            assert_eq!(sharenet.p95_rtt_micros, 45_000);
            // The effective freshness bound: the earlier of the
            // observer's expiry (T+52) and the policy window (T-8+300).
            assert_eq!(sharenet.fresh_until_unix, T + 52);
            // The ADCOS anchor: the store's typed projection, bound to the
            // signing provider.
            assert_eq!(adcos.contract, contract);
            assert_eq!(adcos.state, ContractState::Active);
            assert_eq!(adcos.fresh_until_unix, T - 5 + STORE_WINDOW_SECS);
            assert_eq!(adcos.last_observed_at_unix, T - 5);
            assert_eq!(adcos.last_sequence, 2);
            assert_eq!(adcos.provider_node_id, node_id(&provider));
            // The decision's own horizon: the earlier bound wins.
            assert_eq!(*valid_until_unix, T + 52);
        }
        other => panic!("expected Eligible, got {other:?}"),
    }
}

#[test]
fn stale_sharenet_evidence_is_ineligible() {
    let gateway_id = node_id(&identity(2));
    let provider = identity(3);
    let link = canonical_link();
    let contract = contract(0xB2);
    let signed = canonical_stream(&provider, contract);
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("sn-stale");
    let store = fed_store(&temp.path, &mut admission, &signed, T);
    let health = store.health(&contract).expect("health");

    // Case 1 — the observer's cryptographic window has passed: the
    // evidence expired at T+52 while the policy window (T+292) holds and
    // the ADCOS projection is still fresh until T+595. Only the ShareNet
    // factor fails, with the exact bound that fired.
    let decision = default_policy().decide(full_request(gateway_id, T + 60, &link, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::ShareNetEvidenceStale {
            now_unix: T + 60,
            expires_at_unix: T + 52,
            policy_bound_unix: T + 292,
        }],
        "the cryptographic expiry binds; the reason reports both bounds"
    );

    // Case 2 — the POLICY's freshness window binds instead: a 5 s window
    // makes the T-8 evidence stale at T (bound T-3 < T) even though the
    // observer granted validity until T+52.
    let strict = policy(5, 10_000, 50);
    let decision = strict.decide(full_request(gateway_id, T, &link, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::ShareNetEvidenceStale {
            now_unix: T,
            expires_at_unix: T + 52,
            policy_bound_unix: T - 3,
        }],
        "the policy window binds (the earlier bound wins)"
    );
}

#[test]
fn unfresh_projection_is_ineligible_projection_stale() {
    let gateway_id = node_id(&identity(2));
    let observer = identity(1);
    let provider = identity(3);
    // A LONG-lived ShareNet factor (validity 3000 s, window 3000 s) so the
    // ONLY failing factor at T+600 is the ADCOS projection, whose store
    // window is 600 s (fresh until T+595).
    let link = link_evidence(&observer, gateway_id, [7; 32], T - 8, 3_000, good_quality());
    let contract = contract(0xC3);
    let signed = canonical_stream(&provider, contract);
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("proj-stale");
    let store = fed_store(&temp.path, &mut admission, &signed, T);
    let health = store.health(&contract).expect("health");

    let decision = policy(3_000, 10_000, 50).decide(full_request(gateway_id, T + 600, &link, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::ProjectionStale {
            fresh_until_unix: T - 5 + STORE_WINDOW_SECS,
            last_observed_at_unix: T - 5,
        }],
        "the store's ORIGINAL (never re-anchored) metadata is reported"
    );
    // The projection itself still serves the last accepted observation
    // (no fabrication — it is the typed staleness, not missing data).
    assert_eq!(health.state(), ContractState::Active);
    assert_eq!(health.observations().len(), 2);
}

#[test]
fn terminated_and_degraded_contracts_are_ineligible_not_active() {
    let gateway_id = node_id(&identity(2));
    let observer = identity(1);
    let provider = identity(3);
    let link = link_evidence(&observer, gateway_id, [7; 32], T - 8, 60, good_quality());

    // Terminated: the provider revokes the contract (sequence 3).
    let terminated_contract = contract(0xD4);
    let mut signed = canonical_stream(&provider, terminated_contract);
    signed.push(signed_observation(
        &provider,
        terminated_contract,
        EvidenceKind::Terminated,
        T - 2,
        3,
        None,
    ));
    let mut admission = admission_for(&terminated_contract);
    let temp = TempStore::new("terminated");
    let store = fed_store(&temp.path, &mut admission, &signed, T);
    let health = store.health(&terminated_contract).expect("health");
    assert_eq!(health.state(), ContractState::Terminated);
    let decision = default_policy().decide(full_request(gateway_id, T, &link, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::AdcosContractNotActive {
            state: ContractState::Terminated,
        }]
    );

    // Degraded: the frozen event mapping has no recovery transition, so a
    // degraded backhaul stays ineligible until a NEW contract.
    let degraded_contract = contract(0xD5);
    let mut signed = canonical_stream(&provider, degraded_contract);
    signed.push(signed_observation(
        &provider,
        degraded_contract,
        EvidenceKind::Degraded,
        T - 2,
        3,
        None,
    ));
    let mut admission = admission_for(&degraded_contract);
    let temp = TempStore::new("degraded");
    let store = fed_store(&temp.path, &mut admission, &signed, T);
    let health = store.health(&degraded_contract).expect("health");
    assert_eq!(health.state(), ContractState::Degraded);
    let decision = default_policy().decide(full_request(gateway_id, T, &link, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::AdcosContractNotActive {
            state: ContractState::Degraded,
        }]
    );
}

#[test]
fn quality_floor_and_latency_bound_edges_are_exact_integer_math() {
    let gateway_id = node_id(&identity(2));
    let provider = identity(3);
    let contract = contract(0xE6);
    let signed = canonical_stream(&provider, contract);
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("quality");
    let store = fed_store(&temp.path, &mut admission, &signed, T);
    let health = store.health(&contract).expect("health");

    // Exact ppm: 10,000 lost of 1,000,000 total = exactly 10,000 ppm,
    // counters agreeing with the stated ratio.
    let quality = link_quality(990_000, 10_000, 10_000, 45_000);
    let link = link_evidence(&identity(1), gateway_id, [7; 32], T - 8, 60, quality);

    // The exact floor passes (10,000 ppm <= 10,000 ppm floor).
    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &link, &health, &signed));
    assert!(decision.is_eligible(), "the exact floor passes: {decision:?}");

    // One ppm above the floor fails, carrying the exact integers.
    let decision = policy(300, 9_999, 50).decide(full_request(gateway_id, T, &link, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::QualityBelowFloor {
            loss_ppm: 10_000,
            floor_ppm: 9_999,
        }]
    );

    // The counter cross-check: an observer UNDERSTATING its loss ratio
    // (stated 0 ppm) while its own counters say 50% is evaluated on the
    // counters — an internally inconsistent snapshot never admits.
    let liar = link_evidence(
        &identity(1),
        gateway_id,
        [7; 32],
        T - 8,
        60,
        link_quality(500_000, 500_000, 0, 45_000),
    );
    let decision = policy(300, 100_000, 50).decide(full_request(gateway_id, T, &liar, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::QualityBelowFloor {
            loss_ppm: 500_000,
            floor_ppm: 100_000,
        }],
        "the derived ppm (500,000) wins over the stated 0"
    );

    // The exact latency bound passes: p95 = 50,000 us = exactly 50 ms.
    let edge = link_evidence(
        &identity(1),
        gateway_id,
        [7; 32],
        T - 8,
        60,
        link_quality(995_000, 5_000, 5_000, 50_000),
    );
    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &edge, &health, &signed));
    assert!(decision.is_eligible(), "the exact bound passes: {decision:?}");

    // One MICROSECOND above the bound fails (integer math in micros, no
    // rounding at the ms seam).
    let over = link_evidence(
        &identity(1),
        gateway_id,
        [7; 32],
        T - 8,
        60,
        link_quality(995_000, 5_000, 5_000, 50_001),
    );
    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &over, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::LatencyAboveBound {
            p95_rtt_micros: 50_001,
            bound_micros: 50_000,
        }]
    );
}

#[test]
fn redelivered_signed_evidence_still_admits() {
    let gateway_id = node_id(&identity(2));
    let provider = identity(3);
    let contract = contract(0xF7);
    let stream = canonical_stream(&provider, contract);
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("redelivery");

    // The realistic get_assurance shape: the provider redelivers the whole
    // verified log, duplicates included. The R5-004 sequence gate answers
    // SequenceStale for the redelivery (verified, ignored by the store's
    // dedup), and the daemon feeds both to the store.
    let mut store = DurableProjectionStore::create(&temp.path, STORE_WINDOW_SECS)
        .expect("create store");
    let mut bundle = Vec::new();
    for observation in stream.iter().chain(stream.iter()) {
        let domain = common::verified_domain_observation(&mut admission, observation, T)
            .expect("verified (redeliveries verify too)");
        store.accept(&domain);
        bundle.push(observation.clone());
    }
    store.flush().expect("flush");
    let health = store.health(&contract).expect("health");
    assert_eq!(health.observations().len(), 2, "the store deduped the redelivery");

    // The identical duplicate in the evidence set is NOT a collision —
    // the policy admits.
    let link = canonical_link();
    let decision = default_policy().decide(full_request(gateway_id, T, &link, &health, &bundle));
    assert!(
        decision.is_eligible(),
        "an identical redelivery is expected provider behavior: {decision:?}"
    );
    let _ = AdmissionOutcome::Admitted; // (the R5-004 outcome vocabulary)
}
