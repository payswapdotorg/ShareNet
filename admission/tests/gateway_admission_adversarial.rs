//! R5-005 "Gateway admission" ADVERSARIAL verification.
//!
//! The attack surface of an admission policy is exactly its evidence
//! binding: WHO and WHAT each piece of evidence is about, whether it was
//! really signed, and whether the durable projection was really fed
//! through the verified path. Every test here fails the gateway closed
//! with the typed reason:
//!
//! - **binding** — evidence about a DIFFERENT node (or a different
//!   contract, byte-for-byte identical kind/time/sequence) never admits;
//! - **tampered evidence** — a mutated signature, a rewritten statement or
//!   corrupted bytes are typed refusals, and a store fed OFF the verified
//!   path (fabricated domain observations with no signed form) can never
//!   reach `Eligible`;
//! - **both sides required** — one-sided evidence never admits, in every
//!   combination, in the documented reason order;
//! - **determinism** — the same fixed snapshot decides identically, twice,
//!   and around an interleaved different decision;
//! - **temporal attacks** — future-dated evidence is not-yet-valid;
//! - **contradictory signed evidence** — a provider that signed two
//!   different claims at the same sequence, and evidence that ran ahead
//!   of the projection, are both refused;
//! - **kind confusion** — advertisement evidence is not link evidence.

mod common;

use common::{
    admission_for, canonical_link, canonical_stream, contract, fed_store, full_request,
    good_quality, identity, link_evidence, node_id, policy, reason_names, signed_observation,
    verified_domain_observation, T, TempStore, STORE_WINDOW_SECS,
};
use sharenet_admission::{
    AdmissionReason, AdcosBackhaulEvidence, GatewayAdmissionRequest,
};
use sharenet_connectivity::{
    ConnectivityObservation, ConnectivityContractRef, ObservationKind, RefKind,
};
use sharenet_protocol::{
    ConnectivityObservationStatement, EvidenceKind, SignedConnectivityObservation,
    SignedTopologyEvidence, TopologyEvidence,
};
use sharenet_connectivity::{AcceptOutcome, ContractState, DurableProjectionStore};

#[test]
fn evidence_about_a_different_node_never_admits() {
    let gateway_id = node_id(&identity(2));
    let other_id = node_id(&identity(4));
    let provider = identity(3);
    // Perfectly valid, perfectly fresh link evidence — about ANOTHER node.
    let link = link_evidence(&identity(1), other_id, [7; 32], T - 8, 60, good_quality());
    let contract = contract(0x11);
    let signed = canonical_stream(&provider, contract);
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("binding-node");
    let store = fed_store(&temp.path, &mut admission, &signed, T);
    let health = store.health(&contract).expect("health");

    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &link, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::ShareNetEvidenceWrongSubject {
            subject_node_id: other_id,
            gateway_node_id: gateway_id,
        }],
        "evidence never transfers between nodes"
    );
}

#[test]
fn tampered_sharenet_evidence_is_refused() {
    let gateway_id = node_id(&identity(2));
    let provider = identity(3);
    let link = canonical_link();
    let contract = contract(0x22);
    let signed = canonical_stream(&provider, contract);
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("tamper-sn");
    let store = fed_store(&temp.path, &mut admission, &signed, T);
    let health = store.health(&contract).expect("health");

    // (a) A valid parse with a FORGED signature: the bytes describe a real
    //     observation, but the observer never signed THIS form.
    let mut forged = *link.signature();
    forged[0] ^= 0x01;
    let tampered = SignedTopologyEvidence::from_parts(link.evidence_bytes().to_vec(), forged);
    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &tampered, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::ShareNetEvidenceUnverified {
            cause: "signature_invalid".to_string()
        }]
    );

    // (b) A REWRITTEN observation carrying the original signature: build
    //     a second real evidence record (different observed_at) and pair
    //     it with the first one's signature — parses clean, verifies as a
    //     forgery.
    let rewritten_record = link_evidence(&identity(1), gateway_id, [7; 32], T - 5, 60, good_quality());
    let swapped = SignedTopologyEvidence::from_parts(
        rewritten_record.evidence_bytes().to_vec(),
        *link.signature(),
    );
    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &swapped, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::ShareNetEvidenceUnverified {
            cause: "signature_invalid".to_string()
        }]
    );

    // (c) Corrupted bytes: a typed parse failure (the machine name of the
    //     CBOR profile violation is carried verbatim).
    let garbage = SignedTopologyEvidence::from_parts(vec![0x9f], *link.signature());
    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &garbage, &health, &signed));
    match decision.reasons() {
        [AdmissionReason::ShareNetEvidenceUnverified { cause }] => {
            assert!(cause.starts_with("cbor:"), "typed parse cause, got {cause}");
        }
        other => panic!("expected the typed parse failure, got {other:?}"),
    }
}

#[test]
fn tampered_adcos_evidence_is_refused_and_never_admits() {
    let gateway_id = node_id(&identity(2));
    let provider = identity(3);
    let link = canonical_link();
    let contract = contract(0x33);
    let signed = canonical_stream(&provider, contract);
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("tamper-adcos");
    let store = fed_store(&temp.path, &mut admission, &signed, T);
    let health = store.health(&contract).expect("health");

    // (a) A signed observation REWRITTEN: a second real statement (same
    //     provider, same contract, different observed_at) carrying the
    //     first one's signature — parses clean, signature-verification
    //     fails, the whole set is poisoned.
    let rewritten = ConnectivityObservationStatement::new(
        &provider,
        *contract.id(),
        EvidenceKind::AssuranceAvailable,
        T - 1,
        2,
        None,
    )
    .expect("statement")
    .sign(&provider)
    .expect("signed");
    // Rewrite: present the NEW bytes with the OLD (valid-for-old) signature.
    let tampered = SignedConnectivityObservation::from_parts(
        rewritten.observation_bytes().to_vec(),
        *signed[1].signature(),
    );
    let bundle = vec![signed[0].clone(), tampered];
    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &link, &health, &bundle));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::AdcosEvidenceUnverified {
            cause: "signature_invalid".to_string()
        }]
    );
}

#[test]
fn a_store_fed_off_the_verified_path_never_admits() {
    let gateway_id = node_id(&identity(2));
    let provider = identity(3);
    let link = canonical_link();
    let contract = contract(0x44);
    let signed = canonical_stream(&provider, contract);
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("bypass");

    // The verify-then-feed BYPASS: the store is fed a fabricated domain
    // observation (kind assurance_available — a state-preserving kind so
    // the projection stays Active and fresh) that has NO signed form
    // anywhere. This is exactly the "such a caller owns that decision"
    // path connectivity/README warns about — the policy closes it.
    let mut store = fed_store(&temp.path, &mut admission, &signed, T);
    let fabricated = ConnectivityObservation::new(
        ObservationKind::AssuranceAvailable,
        T - 1,
        ConnectivityContractRef::from_parts(RefKind::Contract, *contract.id()).expect("ref"),
        3,
    );
    assert_eq!(store.accept(&fabricated), AcceptOutcome::Accepted);
    store.flush().expect("flush");
    let health = store.health(&contract).expect("health");
    assert_eq!(health.observations().len(), 3, "the fabricated entry IS in the log");
    assert_eq!(health.state(), ContractState::Active, "the state was preserved by design");

    // The signed set covers only sequences 1-2; the projection's tail (3)
    // is uncovered — the R5-004 trust boundary, DERIVED at decision time.
    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &link, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::AdcosProjectionLogUnverified { sequence: 3 }],
        "an off-the-record log entry is not admissible evidence"
    );
}

#[test]
fn signed_evidence_for_a_different_contract_covers_nothing() {
    let gateway_id = node_id(&identity(2));
    let provider = identity(3);
    let link = canonical_link();
    let contract_a = contract(0x55);
    let contract_b = contract(0x5E);
    let mut admission = admission_for(&contract_a);
    let temp = TempStore::new("binding-contract");
    let store = fed_store(&temp.path, &mut admission, &canonical_stream(&provider, contract_a), T);
    let health = store.health(&contract_a).expect("health");

    // Contract B's observations are VALIDLY SIGNED and carry the SAME
    // (kind, observed_at, sequence) as contract A's log entries — an
    // aliasing attack on the coverage match. The contract filter must
    // exclude them: same claim shape, different contract, zero coverage.
    let aliased = canonical_stream(&provider, contract_b);
    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &link, &health, &aliased));
    assert_eq!(
        decision.reasons(),
        &[
            AdmissionReason::AdcosProjectionLogUnverified { sequence: 1 },
            AdmissionReason::AdcosProjectionLogUnverified { sequence: 2 },
        ],
        "evidence for a different contract never covers this projection"
    );
}

#[test]
fn one_sided_evidence_never_admits() {
    let gateway_id = node_id(&identity(2));
    let provider = identity(3);
    let link = canonical_link();
    let contract = contract(0x66);
    let signed = canonical_stream(&provider, contract);
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("one-sided");
    let store = fed_store(&temp.path, &mut admission, &signed, T);
    let health = store.health(&contract).expect("health");
    let policy = policy(300, 10_000, 50);

    // ShareNet-side evidence alone: no ADCOS-backed external connectivity.
    let only_sharenet = GatewayAdmissionRequest {
        gateway_node_id: gateway_id,
        now_unix: T,
        sharenet_link: Some(&link),
        adcos_backhaul: None,
    };
    assert_eq!(
        reason_names(&policy.decide(only_sharenet)),
        &["adcos_evidence_missing"],
        "ADR-005: ShareNet protocol eligibility alone is not enough"
    );

    // ADCOS-side evidence alone: no authenticated ShareNet link evidence.
    let only_adcos = GatewayAdmissionRequest {
        gateway_node_id: gateway_id,
        now_unix: T,
        sharenet_link: None,
        adcos_backhaul: Some(AdcosBackhaulEvidence {
            health: Some(&health),
            signed_observations: &signed,
        }),
    };
    assert_eq!(
        reason_names(&policy.decide(only_adcos)),
        &["sharenet_evidence_missing"],
        "ADR-005: an ADCOS contract cannot make a node a trusted gateway"
    );

    // Neither side: both reasons, in the documented evaluation order.
    let neither = GatewayAdmissionRequest {
        gateway_node_id: gateway_id,
        now_unix: T,
        sharenet_link: None,
        adcos_backhaul: None,
    };
    assert_eq!(
        reason_names(&policy.decide(neither)),
        &["sharenet_evidence_missing", "adcos_evidence_missing"]
    );

    // Untracked and never-observed contracts are equally evidenceless.
    let untracked = GatewayAdmissionRequest {
        gateway_node_id: gateway_id,
        now_unix: T,
        sharenet_link: Some(&link),
        adcos_backhaul: Some(AdcosBackhaulEvidence {
            health: None,
            signed_observations: &signed,
        }),
    };
    assert_eq!(reason_names(&policy.decide(untracked)), &["adcos_evidence_missing"]);

    let mut registered_only =
        DurableProjectionStore::create(&TempStore::new("registered-only").path, STORE_WINDOW_SECS)
            .expect("store");
    registered_only.register(&contract);
    let empty_health = registered_only.health(&contract).expect("registered");
    let unobserved = GatewayAdmissionRequest {
        gateway_node_id: gateway_id,
        now_unix: T,
        sharenet_link: Some(&link),
        adcos_backhaul: Some(AdcosBackhaulEvidence {
            health: Some(&empty_health),
            signed_observations: &[],
        }),
    };
    assert_eq!(
        reason_names(&policy.decide(unobserved)),
        &["adcos_evidence_missing"],
        "a registered-but-never-observed contract is no evidence"
    );
}

#[test]
fn the_policy_is_deterministic_for_a_fixed_snapshot() {
    let gateway_id = node_id(&identity(2));
    let other_id = node_id(&identity(5));
    let provider = identity(3);
    let link = canonical_link();
    let contract = contract(0x77);
    let signed = canonical_stream(&provider, contract);
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("determinism");
    let store = fed_store(&temp.path, &mut admission, &signed, T);
    let health = store.health(&contract).expect("health");
    let policy = policy(300, 10_000, 50);

    let first = policy.decide(full_request(gateway_id, T, &link, &health, &signed));
    // An interleaved DIFFERENT decision must not disturb the next one
    // (the policy is stateless — no hidden carry-over).
    let other_evidence = link_evidence(&identity(1), other_id, [9; 32], T - 8, 60, good_quality());
    let _ = policy.decide(full_request(other_id, T, &other_evidence, &health, &signed));
    let second = policy.decide(full_request(gateway_id, T, &link, &health, &signed));
    // And a fresh request struct over CLONED evidence (a different
    // allocation of the same snapshot).
    let cloned: Vec<SignedConnectivityObservation> = signed.clone();
    let third = policy.decide(full_request(gateway_id, T, &link, &health, &cloned));

    assert_eq!(first, second, "same snapshot, same decision");
    assert_eq!(second, third, "cloned evidence, same decision");
    assert!(first.is_eligible());
}

#[test]
fn future_dated_sharenet_evidence_is_not_yet_valid() {
    let gateway_id = node_id(&identity(2));
    let provider = identity(3);
    // An otherwise perfect evidence record observed 100 s IN THE FUTURE
    // (a clock-skew or replay probe).
    let link = link_evidence(&identity(1), gateway_id, [7; 32], T + 100, 60, good_quality());
    let contract = contract(0x88);
    let signed = canonical_stream(&provider, contract);
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("future");
    let store = fed_store(&temp.path, &mut admission, &signed, T);
    let health = store.health(&contract).expect("health");

    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &link, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::ShareNetEvidenceNotYetValid {
            now_unix: T,
            observed_at_unix: T + 100,
        }]
    );
}

#[test]
fn advertisement_evidence_is_not_link_evidence() {
    let gateway_id = node_id(&identity(2));
    let provider = identity(3);
    // A valid, fresh, SIGNED advertisement observation about the gateway —
    // but gateway admission needs LINK evidence (with a quality snapshot).
    let ad = TopologyEvidence::new(
        &identity(1),
        gateway_id,
        sharenet_protocol::Observation::Advertisement {
            advertisement_id: [3; 32],
            capabilities: vec!["live".to_string(), "quic".to_string()],
        },
        T - 8,
        60,
    )
    .expect("evidence")
    .sign(&identity(1))
    .expect("signed");
    let contract = contract(0x99);
    let signed = canonical_stream(&provider, contract);
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("not-a-link");
    let store = fed_store(&temp.path, &mut admission, &signed, T);
    let health = store.health(&contract).expect("health");

    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &ad, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::ShareNetEvidenceNotALink],
        "an advertisement observation carries no link quality to admit on"
    );
}

#[test]
fn contradictory_signed_claims_at_one_sequence_are_refused() {
    let gateway_id = node_id(&identity(2));
    let provider = identity(3);
    let link = canonical_link();
    let contract = contract(0xAA);

    // The provider signs TWO DIFFERENT observations at sequence 2: the
    // real activated claim (T-5) and a mutated terminated claim (T-4).
    // The R5-004 sequence gate admits one and answers SequenceStale for
    // the other (each individually verifies); the policy sees BOTH in the
    // evidence set and refuses the contradiction.
    let activated = canonical_stream(&provider, contract);
    let mutated = signed_observation(
        &provider,
        contract,
        EvidenceKind::Terminated,
        T - 4,
        2,
        None,
    );
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("collision");
    let mut store =
        DurableProjectionStore::create(&temp.path, STORE_WINDOW_SECS).expect("store");
    for observation in [&activated[0], &activated[1], &mutated] {
        let domain = verified_domain_observation(&mut admission, observation, T)
            .expect("each claim verifies individually");
        store.accept(&domain); // the second seq-2 is a store-level replay
    }
    store.flush().expect("flush");
    let health = store.health(&contract).expect("health");
    assert_eq!(health.state(), ContractState::Active, "the store took the first claim");

    let bundle = vec![activated[0].clone(), activated[1].clone(), mutated];
    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &link, &health, &bundle));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::AdcosEvidenceSequenceCollision {
            provider_node_id: node_id(&provider),
            sequence: 2,
        }],
        "a provider that signed two claims at one sequence signed a contradiction"
    );
}

#[test]
fn verified_evidence_ahead_of_the_projection_is_refused() {
    let gateway_id = node_id(&identity(2));
    let provider = identity(3);
    let link = canonical_link();
    let contract = contract(0xBB);

    // The daemon holds verified evidence (sequence 3, terminated) that it
    // never fed to the store — a self-inconsistent snapshot (evidence the
    // caller has but did not project). Feed the store first, then decide.
    let mut signed = canonical_stream(&provider, contract);
    signed.push(signed_observation(
        &provider,
        contract,
        EvidenceKind::Terminated,
        T - 2,
        3,
        None,
    ));
    let mut admission = admission_for(&contract);
    let temp = TempStore::new("lags");
    // Feed only the first TWO (the canonical stream)...
    let store = fed_store(&temp.path, &mut admission, &signed[..2], T);
    let health = store.health(&contract).expect("health");

    // ...but decide over the full THREE-observation verified set.
    let decision = policy(300, 10_000, 50).decide(full_request(gateway_id, T, &link, &health, &signed));
    assert_eq!(
        decision.reasons(),
        &[AdmissionReason::AdcosProjectionLagsEvidence {
            verified_sequence: 3,
            projection_sequence: 2,
        }],
        "the snapshot must be self-consistent — feed the store, then decide"
    );
}
