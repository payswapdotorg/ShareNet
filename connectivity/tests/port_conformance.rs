//! Unit-level trait conformance suite for `ConnectivityPort` over the
//! in-memory fake — work item R5-001.
//!
//! Two layers:
//!
//! - [`conformance_core`] — everything provable through the TRAIT alone.
//!   The future R5-002 ADCOS client must pass the same core against its
//!   provider-backed implementation.
//! - fake-specific tests — the deterministic affordances (event mapping,
//!   failure modes, redelivery, determinism) that pin the fake's documented
//!   policies and the adcos.md failure semantics.
//!
//! No I/O: this is a pure domain crate; everything runs against the
//! deterministic in-memory provider.

use sharenet_connectivity::{
    ConnectivityIntentRef, ConnectivityOfferRef, ConnectivityPort, ConnectivityRequirement,
    ContractState, FailureMode, InMemoryConnectivityPort, ObservationCache, ObservationKind,
    PortError, RefKind, ServiceClass, DEFAULT_FRESHNESS_WINDOW_SECS, DEFAULT_OFFERS_PER_INTENT,
};

/// Everything provable through the trait alone (no fake affordances).
///
/// A future `ConnectivityPort` implementation (the R5-002 ADCOS client)
/// must pass this against its provider-backed instance.
fn conformance_core<T: ConnectivityPort>(port: &T) {
    // create → discover → accept → get contract → assurance → execution →
    // terminate (idempotent) → terminal state remains queryable.
    let requirement = ConnectivityRequirement::new(ServiceClass::Live)
        .with_max_cost_hint(1000)
        .with_max_latency_ms_hint(250)
        .with_region_hint("eu-central");
    let intent = port.create_intent(requirement).expect("create_intent");

    let offers = port.discover_offers(&intent).expect("discover_offers");
    assert!(!offers.is_empty(), "at least one offer per intent");
    let mut distinct = std::collections::HashSet::new();
    for offer in &offers {
        assert_eq!(offer.kind(), RefKind::Offer);
        assert!(distinct.insert(*offer.id()), "offers must be distinct");
    }

    let contract = port.accept_offer(&intent, &offers[0]).expect("accept_offer");
    assert_eq!(contract.kind(), RefKind::Contract);
    assert_eq!(intent.kind(), RefKind::Intent);

    let projection = port.get_contract(&contract).expect("get_contract");
    assert_eq!(projection.contract(), &contract);
    assert!(
        projection.valid_from_unix() < projection.valid_until_unix(),
        "validity window invariant"
    );

    let execution = port.get_execution(&contract).expect("get_execution");
    assert_eq!(execution.contract(), &contract);

    let assurance = port.get_assurance(&contract).expect("get_assurance");
    for observation in &assurance {
        assert_eq!(observation.contract(), &contract);
    }
    // After dedup by sequence the remaining observations are in strictly
    // increasing sequence order (the monotonic per-provider replay ordering).
    let mut highest = 0;
    let mut seen = std::collections::HashSet::new();
    for observation in &assurance {
        if seen.insert(observation.sequence()) {
            assert!(observation.sequence() > highest, "sequence order after dedup");
            highest = observation.sequence();
        }
    }

    // terminate is idempotent by trait contract...
    port.terminate(&contract).expect("terminate");
    port.terminate(&contract).expect("terminate is idempotent");
    // ...and the terminal state remains queryable (never fabricated away).
    assert_eq!(
        port.get_contract(&contract)
            .expect("get_contract after terminate")
            .state(),
        ContractState::Terminated
    );
}

/// Drive a full deterministic lifecycle on any fake and return the essence
/// (for cross-instance determinism comparison).
struct LifecycleEssence {
    intent_hex: String,
    offer_hexes: Vec<String>,
    contract_hex: String,
    sequences: Vec<u64>,
    states: Vec<ContractState>,
    freshness: Vec<u64>,
}

fn drive_lifecycle(port: &InMemoryConnectivityPort) -> LifecycleEssence {
    let requirement = ConnectivityRequirement::new(ServiceClass::Opportunistic)
        .with_region_hint("test-region")
        .with_max_latency_ms_hint(500);
    let intent = port.create_intent(requirement).unwrap();
    let offers = port.discover_offers(&intent).unwrap();
    let contract = port.accept_offer(&intent, &offers[0]).unwrap();
    port.emit_observation(&contract, ObservationKind::ContractActivated)
        .unwrap();
    port.set_execution(&contract, "active", 42_000_000, 37).unwrap();
    port.emit_observation(&contract, ObservationKind::Degraded).unwrap();
    port.emit_observation(&contract, ObservationKind::FailoverReplan).unwrap();
    port.emit_observation(&contract, ObservationKind::AssuranceAvailable)
        .unwrap();
    port.emit_observation(&contract, ObservationKind::ContractActivated)
        .unwrap();
    port.terminate(&contract).unwrap();

    let mut sequences = Vec::new();
    let mut states = Vec::new();
    let mut freshness = Vec::new();
    for observation in port.get_assurance(&contract).unwrap() {
        sequences.push(observation.sequence());
        if let Some(state) = ContractState::from_observation_kind(observation.kind()) {
            states.push(state);
        }
        freshness.push(observation.observed_at_unix());
    }
    LifecycleEssence {
        intent_hex: intent.to_hex(),
        offer_hexes: offers.iter().map(|o| o.to_hex()).collect(),
        contract_hex: contract.to_hex(),
        sequences,
        states,
        freshness,
    }
}

#[test]
fn in_memory_port_passes_core_conformance() {
    conformance_core(&InMemoryConnectivityPort::new());
    // And with non-default knobs.
    conformance_core(&InMemoryConnectivityPort::new().with_offers_per_intent(1));
    conformance_core(
        &InMemoryConnectivityPort::new()
            .with_offers_per_intent(7)
            .with_contract_window_secs(10)
            .with_freshness_window_secs(60),
    );
}

#[test]
fn full_lifecycle_with_event_mapping() {
    let port = InMemoryConnectivityPort::new();
    let intent = port.create_intent(ConnectivityRequirement::new(ServiceClass::Live)).unwrap();
    let offers = port.discover_offers(&intent).unwrap();
    assert_eq!(offers.len(), DEFAULT_OFFERS_PER_INTENT);
    // Deterministic offer set: re-discovery returns the same refs in order.
    assert_eq!(port.discover_offers(&intent).unwrap(), offers);

    let contract = port.accept_offer(&intent, &offers[0]).unwrap();
    // Accepted but not yet activated.
    assert_eq!(port.get_contract(&contract).unwrap().state(), ContractState::Projected);
    assert!(port.get_assurance(&contract).unwrap().is_empty());

    // contract activated → Active.
    port.emit_observation(&contract, ObservationKind::ContractActivated).unwrap();
    assert_eq!(port.get_contract(&contract).unwrap().state(), ContractState::Active);

    // execution state changed → observation + counters readable.
    port.set_execution(&contract, "active", 42_000_000, 37).unwrap();
    let execution = port.get_execution(&contract).unwrap();
    assert_eq!(execution.state(), "active");
    assert_eq!(execution.throughput_bps(), 42_000_000);
    assert_eq!(execution.latency_ms(), 37);

    // degraded → Degraded.
    port.emit_observation(&contract, ObservationKind::Degraded).unwrap();
    assert_eq!(port.get_contract(&contract).unwrap().state(), ContractState::Degraded);
    // failover/replan + assurance do NOT move the contract state.
    port.emit_observation(&contract, ObservationKind::FailoverReplan).unwrap();
    port.emit_observation(&contract, ObservationKind::AssuranceAvailable).unwrap();
    assert_eq!(port.get_contract(&contract).unwrap().state(), ContractState::Degraded);

    // terminate → Terminated, with the exact observation sequence in order.
    port.terminate(&contract).unwrap();
    let kinds: Vec<ObservationKind> = port
        .get_assurance(&contract)
        .unwrap()
        .iter()
        .map(|o| o.kind())
        .collect();
    assert_eq!(
        kinds,
        vec![
            ObservationKind::ContractActivated,
            ObservationKind::ExecutionStateChanged,
            ObservationKind::Degraded,
            ObservationKind::FailoverReplan,
            ObservationKind::AssuranceAvailable,
            ObservationKind::Terminated,
        ]
    );
    let projection = port.get_contract(&contract).unwrap();
    assert_eq!(projection.state(), ContractState::Terminated);
    assert!(projection.valid_from_unix() < projection.valid_until_unix());
    // Execution remains queryable after termination (terminal, not erased).
    assert_eq!(port.get_execution(&contract).unwrap().state(), "active");
}

#[test]
fn deterministic_across_instances() {
    let a = drive_lifecycle(&InMemoryConnectivityPort::new());
    let b = drive_lifecycle(&InMemoryConnectivityPort::new());
    assert_eq!(a.intent_hex, b.intent_hex);
    assert_eq!(a.offer_hexes, b.offer_hexes);
    assert_eq!(a.contract_hex, b.contract_hex);
    assert_eq!(a.sequences, b.sequences);
    assert_eq!(a.states, b.states);
    assert_eq!(a.freshness, b.freshness);

    // A different seed decorrelates the ids but keeps the structure.
    let c = drive_lifecycle(&InMemoryConnectivityPort::with_seed(7));
    assert_ne!(a.intent_hex, c.intent_hex);
    assert_ne!(a.contract_hex, c.contract_hex);
    assert_eq!(a.sequences, c.sequences, "sequence assignment is seed-independent");
    assert_eq!(a.states, c.states);
}

#[test]
fn observation_sequence_is_monotonic_per_provider() {
    let port = InMemoryConnectivityPort::new();
    let intent = port.create_intent(ConnectivityRequirement::new(ServiceClass::Dtn)).unwrap();
    let offers = port.discover_offers(&intent).unwrap();
    let contract_a = port.accept_offer(&intent, &offers[0]).unwrap();
    let contract_b = port.accept_offer(&intent, &offers[1]).unwrap();

    // Interleave events across the two contracts.
    port.emit_observation(&contract_a, ObservationKind::ContractActivated).unwrap();
    port.emit_observation(&contract_b, ObservationKind::ContractActivated).unwrap();
    port.emit_observation(&contract_a, ObservationKind::Degraded).unwrap();
    port.set_execution(&contract_b, "active", 1, 1).unwrap();
    port.emit_observation(&contract_b, ObservationKind::AssuranceAvailable).unwrap();
    port.terminate(&contract_a).unwrap();

    let mut all_sequences = Vec::new();
    for contract in [&contract_a, &contract_b] {
        let observations = port.get_assurance(contract).unwrap();
        let sequences: Vec<u64> = observations.iter().map(|o| o.sequence()).collect();
        // Per contract strictly increasing...
        assert!(
            sequences.windows(2).all(|w| w[0] < w[1]),
            "per-contract sequences strictly increase: {sequences:?}"
        );
        all_sequences.extend(sequences);
    }
    // ...and the provider-wide assignment is a single monotonic counter:
    // every sequence from 1..=N appears exactly once across all contracts.
    all_sequences.sort_unstable();
    assert_eq!(all_sequences, (1..=all_sequences.len() as u64).collect::<Vec<u64>>());
}

#[test]
fn duplicate_observations_are_deduped_by_sequence() {
    let port = InMemoryConnectivityPort::new();
    let intent = port.create_intent(ConnectivityRequirement::new(ServiceClass::Live)).unwrap();
    let offers = port.discover_offers(&intent).unwrap();
    let contract = port.accept_offer(&intent, &offers[0]).unwrap();
    port.emit_observation(&contract, ObservationKind::ContractActivated).unwrap();
    port.emit_observation(&contract, ObservationKind::Degraded).unwrap();
    port.emit_observation(&contract, ObservationKind::AssuranceAvailable).unwrap();

    let original = port.get_assurance(&contract).unwrap();
    let original_len = original.len();

    // Provider redelivery of the newest and of an older observation.
    let newest = original.last().unwrap().sequence();
    let oldest = original.first().unwrap().sequence();
    let redelivered_new = port
        .replay_observation(&contract, newest)
        .unwrap()
        .expect("newest exists");
    let redelivered_old = port
        .replay_observation(&contract, oldest)
        .unwrap()
        .expect("oldest exists");
    // Redelivery is byte-identical (same sequence, same observed_at).
    assert_eq!(Some(redelivered_new.sequence()), Some(newest));
    assert_eq!(Some(redelivered_old.sequence()), Some(oldest));
    assert!(port.get_assurance(&contract).unwrap().contains(&redelivered_new));
    // A sequence that never existed for this contract is honestly reported.
    assert_eq!(port.replay_observation(&contract, 999).unwrap(), None);

    let after = port.get_assurance(&contract).unwrap();
    assert_eq!(after.len(), original_len + 2, "two redeliveries appended");

    // Consumer side: dedup by sequence keeps exactly the original set.
    let mut cache = ObservationCache::new(DEFAULT_FRESHNESS_WINDOW_SECS);
    let mut accepted = 0;
    for observation in &after {
        if let sharenet_connectivity::AcceptOutcome::Accepted = cache.accept(observation) {
            accepted += 1;
        }
    }
    assert_eq!(accepted, original_len, "replayed duplicates are ignored");
    assert_eq!(
        cache.last_accepted(&contract).unwrap().observation().sequence(),
        newest
    );
    // The deduped view (keep the first occurrence of each sequence) equals
    // the pre-redelivery log — replays added nothing.
    let mut seen_sequences = std::collections::HashSet::new();
    let deduped: Vec<_> = after
        .iter()
        .filter(|o| seen_sequences.insert(o.sequence()))
        .cloned()
        .collect();
    assert_eq!(deduped, original);
}

#[test]
fn provider_unavailable_carries_freshness_and_cache_semantics() {
    let port = InMemoryConnectivityPort::new()
        .with_freshness_window_secs(DEFAULT_FRESHNESS_WINDOW_SECS);
    let intent = port.create_intent(ConnectivityRequirement::new(ServiceClass::Live)).unwrap();
    let offers = port.discover_offers(&intent).unwrap();
    let contract = port.accept_offer(&intent, &offers[0]).unwrap();
    port.emit_observation(&contract, ObservationKind::ContractActivated).unwrap();
    port.set_execution(&contract, "active", 1_000_000, 12).unwrap();

    // The caller accepted everything the provider emitted so far.
    let observations = port.get_assurance(&contract).unwrap();
    let mut cache = ObservationCache::new(DEFAULT_FRESHNESS_WINDOW_SECS);
    for observation in &observations {
        cache.accept(observation);
    }

    // Outage.
    port.set_failure_mode(FailureMode::ProviderUnavailable);

    // Every trait method fails with ProviderUnavailable — no fabricated state.
    assert!(matches!(
        port.create_intent(ConnectivityRequirement::new(ServiceClass::Dtn)).unwrap_err(),
        PortError::ProviderUnavailable { .. }
    ));
    assert!(matches!(
        port.discover_offers(&intent).unwrap_err(),
        PortError::ProviderUnavailable { .. }
    ));
    assert!(matches!(
        port.accept_offer(&intent, &offers[1]).unwrap_err(),
        PortError::ProviderUnavailable { .. }
    ));
    let assurance_err = port.get_assurance(&contract).unwrap_err();
    assert!(matches!(assurance_err, PortError::ProviderUnavailable { .. }));
    assert!(matches!(
        port.get_contract(&contract).unwrap_err(),
        PortError::ProviderUnavailable { .. }
    ));
    assert!(matches!(
        port.get_execution(&contract).unwrap_err(),
        PortError::ProviderUnavailable { .. }
    ));
    assert!(matches!(
        port.terminate(&contract).unwrap_err(),
        PortError::ProviderUnavailable { .. }
    ));
    // Provider-side event emission is down too.
    assert!(matches!(
        port.emit_observation(&contract, ObservationKind::Degraded).unwrap_err(),
        PortError::ProviderUnavailable { .. }
    ));

    // The error carries the freshness bound of the last accepted observation:
    // observed_at + window, agreeing with the caller's cache.
    let PortError::ProviderUnavailable {
        last_observation_fresh_until_unix,
    } = assurance_err
    else {
        unreachable!("checked above")
    };
    let last_observed_at = observations.last().unwrap().observed_at_unix();
    assert_eq!(
        last_observation_fresh_until_unix,
        Some(last_observed_at + DEFAULT_FRESHNESS_WINDOW_SECS)
    );
    assert_eq!(
        last_observation_fresh_until_unix,
        cache.last_observation_fresh_until_unix(&contract)
    );

    // Fresh at the current clock...
    assert!(cache.is_fresh(&contract, port.clock_unix()));
    // ...not fresh after the bound passes...
    port.advance_clock(DEFAULT_FRESHNESS_WINDOW_SECS + 1);
    assert!(!cache.is_fresh(&contract, port.clock_unix()));
    // ...and the outage never destroyed local state: the cached observation
    // is still exactly what was accepted, and recovery works.
    assert_eq!(cache.last_accepted(&contract).unwrap().observation(), observations.last().unwrap());
    port.set_failure_mode(FailureMode::Available);
    assert_eq!(port.get_assurance(&contract).unwrap(), observations);
}

#[test]
fn acquisition_unauthorized_blocks_only_acquisition() {
    let port = InMemoryConnectivityPort::new();
    let intent = port.create_intent(ConnectivityRequirement::new(ServiceClass::Live)).unwrap();
    let offers = port.discover_offers(&intent).unwrap();
    let contract = port.accept_offer(&intent, &offers[0]).unwrap();

    port.set_failure_mode(FailureMode::AcquisitionUnauthorized);

    // New acquisition is prevented...
    assert_eq!(
        port.create_intent(ConnectivityRequirement::new(ServiceClass::Dtn)).unwrap_err(),
        PortError::AcquisitionUnauthorized
    );
    assert_eq!(
        port.discover_offers(&intent).unwrap_err(),
        PortError::AcquisitionUnauthorized
    );
    assert_eq!(
        port.accept_offer(&intent, &offers[1]).unwrap_err(),
        PortError::AcquisitionUnauthorized
    );
    // ...queries and termination remain available (local/DTN operation continues).
    assert!(port.get_contract(&contract).is_ok());
    assert!(port.get_assurance(&contract).is_ok());
    assert!(port.get_execution(&contract).is_ok());
    assert!(port.terminate(&contract).is_ok());
}

#[test]
fn terminate_is_idempotent_and_refuses_further_acquisition() {
    let port = InMemoryConnectivityPort::new();
    let intent = port.create_intent(ConnectivityRequirement::new(ServiceClass::Live)).unwrap();
    let offers = port.discover_offers(&intent).unwrap();
    let contract = port.accept_offer(&intent, &offers[0]).unwrap();

    port.terminate(&contract).unwrap();
    let observation_count = port.get_assurance(&contract).unwrap().len();
    // Idempotent: second terminate is Ok and adds nothing.
    port.terminate(&contract).unwrap();
    assert_eq!(port.get_assurance(&contract).unwrap().len(), observation_count);
    // Exactly one Terminated observation.
    assert_eq!(
        port.get_assurance(&contract)
            .unwrap()
            .iter()
            .filter(|o| o.kind() == ObservationKind::Terminated)
            .count(),
        1
    );

    // Further acquisition on the terminated contract refuses.
    assert_eq!(
        port.accept_offer(&intent, &offers[0]).unwrap_err(),
        PortError::ContractTerminated { contract }
    );
    // Provider events on the terminated contract refuse (terminal).
    assert_eq!(
        port.emit_observation(&contract, ObservationKind::Degraded).unwrap_err(),
        PortError::ContractTerminated { contract }
    );
    assert!(matches!(
        port.set_execution(&contract, "x", 1, 1).unwrap_err(),
        PortError::ContractTerminated { .. }
    ));
    // Queries still report the terminal state.
    assert_eq!(port.get_contract(&contract).unwrap().state(), ContractState::Terminated);
    assert!(matches!(
        port.get_assurance(&contract).unwrap().last().map(|o| o.kind()),
        Some(ObservationKind::Terminated)
    ));

    // A different offer of the same intent is still acceptable.
    let second = port.accept_offer(&intent, &offers[1]).unwrap();
    assert_ne!(second, contract);
    // And that live offer is single-use.
    assert!(matches!(
        port.accept_offer(&intent, &offers[1]).unwrap_err(),
        PortError::OfferAlreadyConsumed { .. }
    ));
}

#[test]
fn unknown_and_mismatched_refs_are_rejected() {
    let port = InMemoryConnectivityPort::new();
    let intent = port.create_intent(ConnectivityRequirement::new(ServiceClass::Live)).unwrap();
    let offers = port.discover_offers(&intent).unwrap();
    let contract = port.accept_offer(&intent, &offers[0]).unwrap();

    // Unknown refs of every kind.
    let bogus_intent = ConnectivityIntentRef::from_id([7u8; 32]);
    assert!(matches!(
        port.discover_offers(&bogus_intent).unwrap_err(),
        PortError::IntentUnknown { .. }
    ));
    let bogus_offer = ConnectivityOfferRef::from_id([7u8; 32]);
    assert!(matches!(
        port.accept_offer(&intent, &bogus_offer).unwrap_err(),
        PortError::OfferUnknown { .. }
    ));
    let bogus_contract = sharenet_connectivity::ConnectivityContractRef::from_id([7u8; 32]);
    assert!(matches!(
        port.get_contract(&bogus_contract).unwrap_err(),
        PortError::ContractUnknown { .. }
    ));
    assert!(matches!(
        port.get_assurance(&bogus_contract).unwrap_err(),
        PortError::ContractUnknown { .. }
    ));
    assert!(matches!(
        port.get_execution(&bogus_contract).unwrap_err(),
        PortError::ContractUnknown { .. }
    ));
    assert!(matches!(
        port.terminate(&bogus_contract).unwrap_err(),
        PortError::ContractUnknown { .. }
    ));

    // Offer binding: intent 2's offer cannot be accepted under intent 1.
    let intent2 = port.create_intent(ConnectivityRequirement::new(ServiceClass::Dtn)).unwrap();
    let offers2 = port.discover_offers(&intent2).unwrap();
    assert!(matches!(
        port.accept_offer(&intent, &offers2[0]).unwrap_err(),
        PortError::OfferNotForIntent { .. }
    ));

    // A live accepted offer is single-use.
    let ref_contract = contract;
    let consumed_err = port.accept_offer(&intent, &offers[0]).unwrap_err();
    assert!(matches!(
        &consumed_err,
        PortError::OfferAlreadyConsumed { contract, .. } if *contract == ref_contract
    ));
}

#[test]
fn projections_and_observations_are_read_only_data() {
    // The read-only law, proven at the seam: consuming queries, cloning them
    // and feeding every observation through the caller-side cache changes
    // NOTHING on the provider side — and the projected types expose no
    // mutation API (private fields, getters only), so a snapshot cannot be
    // tampered with and written back.
    let port = InMemoryConnectivityPort::new();
    let intent = port.create_intent(ConnectivityRequirement::new(ServiceClass::Live)).unwrap();
    let offers = port.discover_offers(&intent).unwrap();
    let contract = port.accept_offer(&intent, &offers[0]).unwrap();
    port.emit_observation(&contract, ObservationKind::ContractActivated).unwrap();
    port.set_execution(&contract, "active", 5_000_000, 20).unwrap();

    let contract_before = port.get_contract(&contract).unwrap();
    let execution_before = port.get_execution(&contract).unwrap();
    let assurance_before = port.get_assurance(&contract).unwrap();

    // Read them again, clone them around, cache every observation.
    let mut cache = ObservationCache::new(DEFAULT_FRESHNESS_WINDOW_SECS);
    for observation in &assurance_before {
        cache.accept(observation);
    }
    let _clones = (
        port.get_contract(&contract).unwrap(),
        port.get_execution(&contract).unwrap(),
        port.get_assurance(&contract).unwrap(),
    );

    // Provider-side state is untouched by all that consumption.
    assert_eq!(port.get_contract(&contract).unwrap(), contract_before);
    assert_eq!(port.get_execution(&contract).unwrap(), execution_before);
    assert_eq!(port.get_assurance(&contract).unwrap(), assurance_before);

    // Owned snapshots: two queries of unchanged state are equal values.
    assert_eq!(port.get_contract(&contract).unwrap(), contract_before.clone());

    // The fake's minted refs carry their typed kinds (the refs module's
    // from_parts seam is covered by its own unit tests).
    assert_eq!(intent.kind(), RefKind::Intent);
    assert_eq!(offers[0].kind(), RefKind::Offer);
    assert_eq!(contract.kind(), RefKind::Contract);
}

#[test]
fn requirement_validation_is_enforced_at_the_port() {
    let port = InMemoryConnectivityPort::new();
    let mut bad_version = ConnectivityRequirement::new(ServiceClass::Live);
    bad_version.version = 99;
    assert_eq!(
        port.create_intent(bad_version).unwrap_err(),
        PortError::RequirementVersionUnsupported { found: 99 }
    );
    let bad_region = ConnectivityRequirement::new(ServiceClass::Live)
        .with_region_hint("x".repeat(sharenet_connectivity::MAX_REGION_HINT_BYTES + 1));
    assert!(matches!(
        port.create_intent(bad_region).unwrap_err(),
        PortError::RegionHintTooLong { .. }
    ));
    // Nothing was created: the fake's clock only advanced for successes.
    assert_eq!(port.clock_unix(), sharenet_connectivity::FAKE_CLOCK_START_UNIX);
}

#[test]
fn freshness_and_validity_track_the_virtual_clock() {
    let port = InMemoryConnectivityPort::new().with_contract_window_secs(100);
    let before = port.clock_unix();
    let intent = port.create_intent(ConnectivityRequirement::new(ServiceClass::Live)).unwrap();
    let offers = port.discover_offers(&intent).unwrap();
    let accepted_at = port.clock_unix();
    let contract = port.accept_offer(&intent, &offers[0]).unwrap();

    let projection = port.get_contract(&contract).unwrap();
    assert_eq!(projection.valid_from_unix(), accepted_at);
    assert_eq!(projection.valid_until_unix(), accepted_at + 100);
    assert!(before < accepted_at, "mutating calls advance the virtual clock");

    // Freshness reflects the time of the last provider-side event.
    port.advance_clock(50);
    port.emit_observation(&contract, ObservationKind::ContractActivated).unwrap();
    let projection = port.get_contract(&contract).unwrap();
    let activated_at = projection.freshness_unix();
    assert!(activated_at >= accepted_at + 50);
}
