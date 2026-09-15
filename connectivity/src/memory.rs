//! `InMemoryConnectivityPort` — **TEST VEHICLE** (like `MemoryTunPair` in
//! `transport/linux`): a deterministic in-memory fake ADCOS provider.
//!
//! It never performs I/O, never touches a network, never speaks the real
//! ADCOS developer API (that is R5-002's job) and has **no security
//! properties**. What it does have:
//!
//! - **determinism** — a fixed virtual clock (`FAKE_CLOCK_START_UNIX`,
//!   advanced 1 s per mutating call, plus the test-controlled
//!   [`InMemoryConnectivityPort::advance_clock`]) and id/sequence derivation
//!   from a seed and a counter: the same call script always yields the same
//!   refs, sequences, projections and observations;
//! - **the adcos.md event mapping** — observation kinds move the projected
//!   contract state exactly per [`crate::projection::ContractState::from_observation_kind`];
//! - **injectable failure modes** — [`FailureMode::ProviderUnavailable`] /
//!   [`FailureMode::AcquisitionUnauthorized`] to exercise the
//!   `spec/integrations/adcos.md` failure semantics;
//! - **provider redelivery** —
//!   [`InMemoryConnectivityPort::replay_observation`] re-delivers an already
//!   emitted observation (identical sequence), so consumers can prove
//!   dedup-by-sequence.
//!
//! # Fake policies (the fake's, NOT claims about real ADCOS)
//!
//! - Offers are minted on first discovery (a stable set per intent:
//!   re-discovery returns the same refs in the same order) and are
//!   single-use: an offer accepted once refuses re-acceptance.
//! - Contracts start `Projected` with validity
//!   `[accept time, accept time + contract_window_secs)` and become `Active`
//!   / `Degraded` / `Terminated` only through the corresponding observation
//!   kinds (event mapping). The mapping is permissive (a second
//!   `ContractActivated` re-activates, mirroring failover/replan
//!   recovery), but `Terminated` is terminal: emissions and execution
//!   updates on a terminated contract refuse, and further acquisition on
//!   its offer refuses.
//! - `AcquisitionUnauthorized` blocks only the three acquisition methods
//!   (`createIntent`/`discoverOffers`/`acceptOffer`); queries and
//!   `terminate` stay available. `ProviderUnavailable` fails every trait
//!   method — including queries — carrying the provider-side freshness
//!   bound of the last emitted observation (scoped to the contract when
//!   the failing call names one).

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use crate::error::PortError;
use crate::observation::{ConnectivityObservation, ObservationKind};
use crate::port::ConnectivityPort;
use crate::projection::{
    ConnectivityContractProjection, ConnectivityExecutionProjection, ContractState,
};
use crate::refs::{
    ConnectivityContractRef, ConnectivityIntentRef, ConnectivityOfferRef, RefKind, REF_ID_LEN,
};
use crate::requirement::ConnectivityRequirement;

/// Fixed start of the fake's deterministic virtual clock (2025-01-01T00:00:00Z).
pub const FAKE_CLOCK_START_UNIX: u64 = 1_735_689_600;

/// Default observation freshness window (seconds) the fake applies when
/// reporting [`PortError::ProviderUnavailable`].
pub const DEFAULT_FRESHNESS_WINDOW_SECS: u64 = 600;

/// Default number of offers minted per intent on first discovery.
pub const DEFAULT_OFFERS_PER_INTENT: usize = 3;

/// Default contract validity window (seconds) applied at acceptance.
pub const DEFAULT_CONTRACT_WINDOW_SECS: u64 = 3600;

/// Injectable provider failure mode — the `spec/integrations/adcos.md`
/// "Failure semantics" test affordances.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureMode {
    /// Provider healthy.
    Available,
    /// ADCOS unreachable: every trait method fails
    /// [`PortError::ProviderUnavailable`] (the provider cannot answer
    /// queries either — no fabricated state). Callers fall back to their
    /// cached last accepted observation.
    ProviderUnavailable,
    /// Acquisition authorization cannot be established:
    /// `createIntent`/`discoverOffers`/`acceptOffer` refuse with
    /// [`PortError::AcquisitionUnauthorized`]; queries and `terminate`
    /// remain available.
    AcquisitionUnauthorized,
}

#[derive(Debug)]
struct IntentRecord {
    requirement: ConnectivityRequirement,
    offers_minted: bool,
    offers: Vec<ConnectivityOfferRef>,
}

#[derive(Debug)]
struct OfferRecord {
    intent: ConnectivityIntentRef,
    consumed_by: Option<ConnectivityContractRef>,
}

#[derive(Debug)]
struct ContractRecord {
    state: ContractState,
    valid_from_unix: u64,
    valid_until_unix: u64,
    freshness_unix: u64,
    observations: Vec<ConnectivityObservation>,
    execution: ConnectivityExecutionProjection,
}

/// Immutable post-construction configuration.
#[derive(Debug)]
struct Config {
    seed: u64,
    offers_per_intent: usize,
    contract_window_secs: u64,
    freshness_window_secs: u64,
}

/// All mutable fake state behind one lock.
#[derive(Debug)]
struct State {
    counter: u64,
    clock_unix: u64,
    sequence: u64,
    failure_mode: FailureMode,
    intents: HashMap<[u8; REF_ID_LEN], IntentRecord>,
    offers: HashMap<[u8; REF_ID_LEN], OfferRecord>,
    contracts: HashMap<[u8; REF_ID_LEN], ContractRecord>,
    last_observation_at: Option<u64>,
}

impl State {
    fn mint_id(&mut self, kind: RefKind, seed: u64) -> [u8; REF_ID_LEN] {
        self.counter += 1;
        fake_ref_id(kind, self.counter, seed)
    }

    /// Next per-provider observation sequence (starts at 1).
    fn next_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    /// Every successful mutating trait call advances the virtual clock 1 s.
    fn advance_clock(&mut self) {
        self.clock_unix = self.clock_unix.saturating_add(1);
    }

    /// Build the outage error. When the failing call names a known contract,
    /// the freshness bound is that contract's last emitted observation;
    /// otherwise the provider-wide last emission (the per-provider sequence
    /// scope). `None` when nothing has ever been emitted.
    fn unavailable_error(
        &self,
        contract: Option<&ConnectivityContractRef>,
        window_secs: u64,
    ) -> PortError {
        let at = contract
            .and_then(|c| self.contracts.get(c.id()))
            .and_then(|rec| rec.observations.last())
            .map(|obs| obs.observed_at_unix())
            .or(self.last_observation_at);
        PortError::ProviderUnavailable {
            last_observation_fresh_until_unix: at.map(|t| t.saturating_add(window_secs)),
        }
    }
}

/// **TEST VEHICLE** — deterministic in-memory fake ADCOS provider
/// implementing [`ConnectivityPort`]. No I/O, no network, no ADCOS wire
/// protocol, no security properties (see the module docs for the exact fake
/// policies). Backs the unit tests and is the seam the future R5-002 ADCOS
/// client will be tested against.
#[derive(Debug)]
pub struct InMemoryConnectivityPort {
    config: Config,
    state: Mutex<State>,
}

impl Default for InMemoryConnectivityPort {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryConnectivityPort {
    /// The standard deterministic fake (seed 0, default knobs).
    pub fn new() -> Self {
        Self::with_seed(0)
    }

    /// A deterministic fake with a different id-derivation seed (same call
    /// script still yields a reproducible, but distinct, ref set).
    pub fn with_seed(seed: u64) -> Self {
        Self {
            config: Config {
                seed,
                offers_per_intent: DEFAULT_OFFERS_PER_INTENT,
                contract_window_secs: DEFAULT_CONTRACT_WINDOW_SECS,
                freshness_window_secs: DEFAULT_FRESHNESS_WINDOW_SECS,
            },
            state: Mutex::new(State {
                counter: 0,
                clock_unix: FAKE_CLOCK_START_UNIX,
                sequence: 0,
                failure_mode: FailureMode::Available,
                intents: HashMap::new(),
                offers: HashMap::new(),
                contracts: HashMap::new(),
                last_observation_at: None,
            }),
        }
    }

    /// Builder: how many offers each intent mints on first discovery (≥ 1).
    pub fn with_offers_per_intent(mut self, offers: usize) -> Self {
        assert!(offers >= 1, "offers_per_intent must be at least 1");
        self.config.offers_per_intent = offers;
        self
    }

    /// Builder: contract validity window in seconds (≥ 1: the validity
    /// invariant requires `valid_from_unix < valid_until_unix`).
    pub fn with_contract_window_secs(mut self, secs: u64) -> Self {
        assert!(secs >= 1, "contract_window_secs must be at least 1");
        self.config.contract_window_secs = secs;
        self
    }

    /// Builder: observation freshness window in seconds applied when
    /// reporting `ProviderUnavailable` (mirror it in the caller's
    /// [`crate::ObservationCache`] to cross-check bounds).
    pub fn with_freshness_window_secs(mut self, secs: u64) -> Self {
        self.config.freshness_window_secs = secs;
        self
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .expect("in-memory connectivity port lock poisoned")
    }

    /// The requirement an intent was created with, if the intent is known
    /// (test affordance — the fake remembers what it was handed).
    pub fn requirement(&self, intent: &ConnectivityIntentRef) -> Option<ConnectivityRequirement> {
        self.lock()
            .intents
            .get(intent.id())
            .map(|record| record.requirement.clone())
    }

    /// The current virtual clock (unix seconds).
    pub fn clock_unix(&self) -> u64 {
        self.lock().clock_unix
    }

    /// Advance the virtual clock (test control for freshness/validity aging).
    pub fn advance_clock(&self, secs: u64) {
        let mut state = self.lock();
        state.clock_unix = state.clock_unix.saturating_add(secs);
    }

    /// The current failure mode.
    pub fn failure_mode(&self) -> FailureMode {
        self.lock().failure_mode
    }

    /// Inject a failure mode (see [`FailureMode`] for exactly what each
    /// mode blocks).
    pub fn set_failure_mode(&self, mode: FailureMode) {
        self.lock().failure_mode = mode;
    }

    /// Emit a provider observation for a contract (the adcos.md event
    /// mapping applied to the fake's projected state), assigning the next
    /// per-provider sequence and the current virtual clock as
    /// `observed_at_unix`.
    ///
    /// Refuses unknown contracts (`ContractUnknown`), terminated contracts
    /// (`ContractTerminated` — terminal) and, while the provider is down
    /// (`ProviderUnavailable`), everything.
    pub fn emit_observation(
        &self,
        contract: &ConnectivityContractRef,
        kind: ObservationKind,
    ) -> Result<ConnectivityObservation, PortError> {
        let mut state = self.lock();
        if state.failure_mode == FailureMode::ProviderUnavailable {
            return Err(state.unavailable_error(Some(contract), self.config.freshness_window_secs));
        }
        if !state.contracts.contains_key(contract.id()) {
            return Err(PortError::ContractUnknown { contract: *contract });
        }
        if state.contracts.get(contract.id()).map(|r| r.state) == Some(ContractState::Terminated) {
            return Err(PortError::ContractTerminated { contract: *contract });
        }
        let now = state.clock_unix;
        let sequence = state.next_sequence();
        let observation = ConnectivityObservation::new(kind, now, *contract, sequence);
        let record = state
            .contracts
            .get_mut(contract.id())
            .expect("existence checked above");
        if let Some(next) = ContractState::from_observation_kind(kind) {
            record.state = next;
        }
        record.freshness_unix = now;
        record.observations.push(observation.clone());
        state.last_observation_at = Some(now);
        state.advance_clock();
        Ok(observation)
    }

    /// Set the provider-reported execution state for a contract (emitting
    /// the `ExecutionStateChanged` observation), with plain `u64` counters.
    ///
    /// Refuses unknown/terminated contracts and the `ProviderUnavailable`
    /// mode, like [`Self::emit_observation`].
    pub fn set_execution(
        &self,
        contract: &ConnectivityContractRef,
        state_text: &str,
        throughput_bps: u64,
        latency_ms: u64,
    ) -> Result<(), PortError> {
        let mut state = self.lock();
        if state.failure_mode == FailureMode::ProviderUnavailable {
            return Err(state.unavailable_error(Some(contract), self.config.freshness_window_secs));
        }
        if !state.contracts.contains_key(contract.id()) {
            return Err(PortError::ContractUnknown { contract: *contract });
        }
        if state.contracts.get(contract.id()).map(|r| r.state) == Some(ContractState::Terminated) {
            return Err(PortError::ContractTerminated { contract: *contract });
        }
        let now = state.clock_unix;
        let sequence = state.next_sequence();
        let execution =
            ConnectivityExecutionProjection::new(*contract, state_text, throughput_bps, latency_ms, now)?;
        let record = state
            .contracts
            .get_mut(contract.id())
            .expect("existence checked above");
        record.execution = execution;
        record.freshness_unix = now;
        record
            .observations
            .push(ConnectivityObservation::new(
                ObservationKind::ExecutionStateChanged,
                now,
                *contract,
                sequence,
            ));
        state.last_observation_at = Some(now);
        state.advance_clock();
        Ok(())
    }

    /// Re-deliver an already emitted observation for a contract (identical
    /// sequence, identical `observed_at_unix`) — the provider-redelivery
    /// affordance for dedup-by-sequence tests.
    ///
    /// `Ok(None)` when no observation with that sequence exists for the
    /// contract; `ContractUnknown` for an unknown contract; the
    /// `ProviderUnavailable` mode refuses (the provider is down).
    pub fn replay_observation(
        &self,
        contract: &ConnectivityContractRef,
        sequence: u64,
    ) -> Result<Option<ConnectivityObservation>, PortError> {
        let mut state = self.lock();
        if state.failure_mode == FailureMode::ProviderUnavailable {
            return Err(state.unavailable_error(Some(contract), self.config.freshness_window_secs));
        }
        let Some(record) = state.contracts.get_mut(contract.id()) else {
            return Err(PortError::ContractUnknown { contract: *contract });
        };
        let Some(observation) = record
            .observations
            .iter()
            .find(|obs| obs.sequence() == sequence)
            .cloned()
        else {
            return Ok(None);
        };
        // Duplicate delivery: same bytes appended to the log again.
        record.observations.push(observation.clone());
        Ok(Some(observation))
    }
}

impl ConnectivityPort for InMemoryConnectivityPort {
    fn create_intent(
        &self,
        requirement: ConnectivityRequirement,
    ) -> Result<ConnectivityIntentRef, PortError> {
        // Local validation precedes provider errors (it needs no round trip).
        requirement.validate()?;
        let mut state = self.lock();
        match state.failure_mode {
            FailureMode::ProviderUnavailable => {
                return Err(state.unavailable_error(None, self.config.freshness_window_secs));
            }
            FailureMode::AcquisitionUnauthorized => return Err(PortError::AcquisitionUnauthorized),
            FailureMode::Available => {}
        }
        let id = state.mint_id(RefKind::Intent, self.config.seed);
        let intent = ConnectivityIntentRef::from_id(id);
        state.intents.insert(
            id,
            IntentRecord {
                requirement,
                offers_minted: false,
                offers: Vec::new(),
            },
        );
        state.advance_clock();
        Ok(intent)
    }

    fn discover_offers(
        &self,
        intent: &ConnectivityIntentRef,
    ) -> Result<Vec<ConnectivityOfferRef>, PortError> {
        let mut state = self.lock();
        match state.failure_mode {
            FailureMode::ProviderUnavailable => {
                return Err(state.unavailable_error(None, self.config.freshness_window_secs));
            }
            FailureMode::AcquisitionUnauthorized => return Err(PortError::AcquisitionUnauthorized),
            FailureMode::Available => {}
        }
        if !state.intents.contains_key(intent.id()) {
            return Err(PortError::IntentUnknown { intent: *intent });
        }
        if !state
            .intents
            .get(intent.id())
            .is_some_and(|record| record.offers_minted)
        {
            // First discovery: mint the deterministic offer set.
            let mut minted = Vec::with_capacity(self.config.offers_per_intent);
            for _ in 0..self.config.offers_per_intent {
                let id = state.mint_id(RefKind::Offer, self.config.seed);
                state.offers.insert(
                    id,
                    OfferRecord {
                        intent: *intent,
                        consumed_by: None,
                    },
                );
                minted.push(ConnectivityOfferRef::from_id(id));
            }
            let record = state
                .intents
                .get_mut(intent.id())
                .expect("existence checked above");
            record.offers = minted;
            record.offers_minted = true;
        }
        Ok(state
            .intents
            .get(intent.id())
            .expect("existence checked above")
            .offers
            .clone())
    }

    fn accept_offer(
        &self,
        intent: &ConnectivityIntentRef,
        offer: &ConnectivityOfferRef,
    ) -> Result<ConnectivityContractRef, PortError> {
        let mut state = self.lock();
        match state.failure_mode {
            FailureMode::ProviderUnavailable => {
                return Err(state.unavailable_error(None, self.config.freshness_window_secs));
            }
            FailureMode::AcquisitionUnauthorized => return Err(PortError::AcquisitionUnauthorized),
            FailureMode::Available => {}
        }
        if !state.intents.contains_key(intent.id()) {
            return Err(PortError::IntentUnknown { intent: *intent });
        }
        let Some(offer_record) = state.offers.get(offer.id()) else {
            return Err(PortError::OfferUnknown { offer: *offer });
        };
        if offer_record.intent != *intent {
            return Err(PortError::OfferNotForIntent {
                offer: *offer,
                passed_intent: *intent,
            });
        }
        if let Some(existing) = offer_record.consumed_by {
            // Single-use offers: refuse re-acceptance; if the contract it
            // produced is terminated, this is exactly "further acquisition on
            // the terminated contract refuses".
            let terminated = state
                .contracts
                .get(existing.id())
                .map(|record| record.state)
                == Some(ContractState::Terminated);
            return Err(if terminated {
                PortError::ContractTerminated { contract: existing }
            } else {
                PortError::OfferAlreadyConsumed {
                    offer: *offer,
                    contract: existing,
                }
            });
        }
        let now = state.clock_unix;
        let id = state.mint_id(RefKind::Contract, self.config.seed);
        let contract = ConnectivityContractRef::from_id(id);
        let execution = ConnectivityExecutionProjection::new(contract, "projected", 0, 0, now)?;
        state.contracts.insert(
            id,
            ContractRecord {
                state: ContractState::Projected,
                valid_from_unix: now,
                valid_until_unix: now.saturating_add(self.config.contract_window_secs),
                freshness_unix: now,
                observations: Vec::new(),
                execution,
            },
        );
        state
            .offers
            .get_mut(offer.id())
            .expect("existence checked above")
            .consumed_by = Some(contract);
        state.advance_clock();
        Ok(contract)
    }

    fn get_contract(
        &self,
        contract: &ConnectivityContractRef,
    ) -> Result<ConnectivityContractProjection, PortError> {
        let state = self.lock();
        if state.failure_mode == FailureMode::ProviderUnavailable {
            return Err(state.unavailable_error(Some(contract), self.config.freshness_window_secs));
        }
        let Some(record) = state.contracts.get(contract.id()) else {
            return Err(PortError::ContractUnknown { contract: *contract });
        };
        ConnectivityContractProjection::new(
            *contract,
            record.state,
            record.valid_from_unix,
            record.valid_until_unix,
            record.freshness_unix,
        )
    }

    fn get_assurance(
        &self,
        contract: &ConnectivityContractRef,
    ) -> Result<Vec<ConnectivityObservation>, PortError> {
        let state = self.lock();
        if state.failure_mode == FailureMode::ProviderUnavailable {
            return Err(state.unavailable_error(Some(contract), self.config.freshness_window_secs));
        }
        let Some(record) = state.contracts.get(contract.id()) else {
            return Err(PortError::ContractUnknown { contract: *contract });
        };
        Ok(record.observations.clone())
    }

    fn get_execution(
        &self,
        contract: &ConnectivityContractRef,
    ) -> Result<ConnectivityExecutionProjection, PortError> {
        let state = self.lock();
        if state.failure_mode == FailureMode::ProviderUnavailable {
            return Err(state.unavailable_error(Some(contract), self.config.freshness_window_secs));
        }
        let Some(record) = state.contracts.get(contract.id()) else {
            return Err(PortError::ContractUnknown { contract: *contract });
        };
        Ok(record.execution.clone())
    }

    fn terminate(&self, contract: &ConnectivityContractRef) -> Result<(), PortError> {
        let mut state = self.lock();
        if state.failure_mode == FailureMode::ProviderUnavailable {
            return Err(state.unavailable_error(Some(contract), self.config.freshness_window_secs));
        }
        if !state.contracts.contains_key(contract.id()) {
            return Err(PortError::ContractUnknown { contract: *contract });
        }
        if state.contracts.get(contract.id()).map(|r| r.state) == Some(ContractState::Terminated) {
            // Idempotent: no new effects, no new observation.
            return Ok(());
        }
        let now = state.clock_unix;
        let sequence = state.next_sequence();
        let record = state
            .contracts
            .get_mut(contract.id())
            .expect("existence checked above");
        record.state = ContractState::Terminated;
        record.freshness_unix = now;
        record.observations.push(ConnectivityObservation::new(
            ObservationKind::Terminated,
            now,
            *contract,
            sequence,
        ));
        state.last_observation_at = Some(now);
        state.advance_clock();
        Ok(())
    }
}

/// Derive a deterministic 32-byte fake id.
///
/// **Structured, non-cryptographic, unique by construction** — the domain
/// byte plus the counter (bytes 1..9) make ids unique per object; the seed
/// mixes decorrelated bytes; byte 25 (`0xF1`) marks fake-provider ids visibly.
/// These are TEST VEHICLE ids: a real ADCOS provider assigns its own opaque
/// bytes, and NOTHING (including ShareNet code) may parse these.
fn fake_ref_id(kind: RefKind, counter: u64, seed: u64) -> [u8; REF_ID_LEN] {
    let domain = match kind {
        RefKind::Intent => 1u8,
        RefKind::Offer => 2u8,
        RefKind::Contract => 3u8,
    };
    let mut id = [0u8; REF_ID_LEN];
    id[0] = domain;
    id[1..9].copy_from_slice(&counter.to_be_bytes());
    id[9..17].copy_from_slice(&mix64(seed).to_le_bytes());
    id[17..25].copy_from_slice(&mix64(seed ^ counter).to_le_bytes());
    id[25] = 0xF1;
    id
}

/// SplitMix64 finalizer — a small bijective mixer for decorrelation only
/// (no cryptographic claim).
fn mix64(mut z: u64) -> u64 {
    z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn fake_ids_are_unique_by_construction() {
        let mut seen = HashSet::new();
        for kind in [RefKind::Intent, RefKind::Offer, RefKind::Contract] {
            for counter in 1..=2000u64 {
                assert!(seen.insert(fake_ref_id(kind, counter, 42)), "collision");
            }
        }
    }

    #[test]
    fn fake_ids_depend_on_seed_but_not_on_call_order() {
        assert_ne!(
            fake_ref_id(RefKind::Intent, 1, 0),
            fake_ref_id(RefKind::Intent, 1, 1)
        );
        // Same inputs, same id — pure function, no hidden state.
        assert_eq!(
            fake_ref_id(RefKind::Contract, 7, 99),
            fake_ref_id(RefKind::Contract, 7, 99)
        );
    }

    #[test]
    fn clock_starts_at_the_fixed_epoch() {
        let port = InMemoryConnectivityPort::new();
        assert_eq!(port.clock_unix(), FAKE_CLOCK_START_UNIX);
        assert_eq!(port.failure_mode(), FailureMode::Available);
    }
}
