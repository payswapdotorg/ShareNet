//! Provider observations — READ-ONLY data — plus the caller-side caching
//! policy type for ADCOS-unavailable periods.
//!
//! The kinds are EXACTLY the `spec/integrations/adcos.md` "Event mapping"
//! list, which ADCOS observations are mapped into this ShareNet operational
//! projection. The law:
//!
//! > "An observation is not permitted to mutate ShareNet's authoritative
//! > circuit, route, identity or content state without independent ShareNet
//! > protocol verification."
//!
//! This crate enforces that at the design level: [`ConnectivityObservation`]
//! is plain data with getters and no mutation API, no port method accepts an
//! observation as input, and the only type that stores observations
//! ([`ObservationCache`]) touches nothing but its own storage. Observation
//! authenticity (signatures) is R5-004 scope — until then observations are
//! provider-asserted data, and this crate deliberately gives them no power.

use std::collections::HashMap;
use std::fmt;

use crate::refs::ConnectivityContractRef;

/// Observation kinds — exactly the `spec/integrations/adcos.md` event
/// mapping list, in the same order:
///
/// - contract activated;
/// - execution state changed;
/// - degraded;
/// - assurance available;
/// - failover/replan;
/// - terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObservationKind {
    /// "contract activated".
    ContractActivated,
    /// "execution state changed".
    ExecutionStateChanged,
    /// "degraded".
    Degraded,
    /// "assurance available".
    AssuranceAvailable,
    /// "failover/replan".
    FailoverReplan,
    /// "terminated".
    Terminated,
}

impl ObservationKind {
    /// Stable machine name (the adcos.md event names, snake_cased).
    pub fn as_str(&self) -> &'static str {
        match self {
            ObservationKind::ContractActivated => "contract_activated",
            ObservationKind::ExecutionStateChanged => "execution_state_changed",
            ObservationKind::Degraded => "degraded",
            ObservationKind::AssuranceAvailable => "assurance_available",
            ObservationKind::FailoverReplan => "failover_replan",
            ObservationKind::Terminated => "terminated",
        }
    }

    /// Parse from the machine name — the seam the future R5-002 ADCOS
    /// client's event mapper uses.
    pub fn from_name(name: &str) -> Option<ObservationKind> {
        match name {
            "contract_activated" => Some(ObservationKind::ContractActivated),
            "execution_state_changed" => Some(ObservationKind::ExecutionStateChanged),
            "degraded" => Some(ObservationKind::Degraded),
            "assurance_available" => Some(ObservationKind::AssuranceAvailable),
            "failover_replan" => Some(ObservationKind::FailoverReplan),
            "terminated" => Some(ObservationKind::Terminated),
            _ => None,
        }
    }
}

impl fmt::Display for ObservationKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One provider observation, mapped into this ShareNet operational
/// projection — READ-ONLY data.
///
/// Constructing or holding an observation changes nothing anywhere; the
/// fields are private with getters. The `sequence` is assigned by the
/// provider from a monotonic per-provider counter (the fake starts at 1), so
/// consumers can order and deduplicate redeliveries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectivityObservation {
    kind: ObservationKind,
    observed_at_unix: u64,
    contract: ConnectivityContractRef,
    sequence: u64,
}

impl ConnectivityObservation {
    /// Plain construction — the provider assigns every field; there is no
    /// local invariant to enforce beyond what the types already guarantee
    /// (monotonicity is a provider-side property).
    pub fn new(
        kind: ObservationKind,
        observed_at_unix: u64,
        contract: ConnectivityContractRef,
        sequence: u64,
    ) -> Self {
        Self {
            kind,
            observed_at_unix,
            contract,
            sequence,
        }
    }

    /// Which adcos.md event this observation maps.
    pub fn kind(&self) -> ObservationKind {
        self.kind
    }

    /// When the provider observed it (unix seconds, provider-assigned).
    pub fn observed_at_unix(&self) -> u64 {
        self.observed_at_unix
    }

    /// The contract this observation belongs to.
    pub fn contract(&self) -> &ConnectivityContractRef {
        &self.contract
    }

    /// Monotonic per-provider sequence number (replay ordering).
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// The last accepted observation plus its freshness metadata — what a caller
/// retains while ADCOS is unavailable.
///
/// `spec/integrations/adcos.md` ("cache the last accepted observation with
/// freshness metadata") as a type, not as caller judgment: the cached entry
/// is exactly the observation the caller accepted and a freshness bound
/// derived from it. It can never *fabricate* contract state (it stores only
/// provider-issued observations) and it can never license destroying local
/// P2P state (it is inert data).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedObservation {
    observation: ConnectivityObservation,
    fresh_until_unix: u64,
}

impl CachedObservation {
    /// Construct from parts — the durable-store seam (R5-003 rebuilds the
    /// cached entry from persisted bytes).
    ///
    /// `fresh_until_unix` is normally `observed_at_unix +
    /// freshness_window_secs` (the policy every cache in this crate
    /// applies); it is stored and served verbatim so a reloaded entry keeps
    /// its ORIGINAL freshness metadata — never re-anchored to the reload
    /// time (the adcos.md no-fabrication law).
    pub fn new(observation: ConnectivityObservation, fresh_until_unix: u64) -> Self {
        Self {
            observation,
            fresh_until_unix,
        }
    }

    /// The cached (last accepted) observation.
    pub fn observation(&self) -> &ConnectivityObservation {
        &self.observation
    }

    /// Until when (exclusive) the cached observation may still be treated as
    /// fresh evidence: `observed_at_unix + freshness_window_secs`.
    pub fn fresh_until_unix(&self) -> u64 {
        self.fresh_until_unix
    }
}

/// Outcome of feeding an observation to [`ObservationCache::accept`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// The observation's sequence was strictly greater than the cached one
    /// for its contract — cached.
    Accepted,
    /// The sequence was not strictly greater (duplicate or reordered replay
    /// of something already cached) — ignored. Carries the ignored sequence.
    IgnoredReplay {
        /// The sequence number that was ignored.
        sequence: u64,
    },
}

/// The caller-side caching policy type for ADCOS-unavailable periods.
///
/// Implements the `spec/integrations/adcos.md` failure semantics as code:
///
/// - **cache the last accepted observation with freshness metadata** — exactly
///   one cached observation per contract, stamped with a freshness bound;
/// - **replayed/duplicate observations are deduped by sequence** — only a
///   strictly greater sequence is accepted, so provider redelivery cannot
///   double-apply anything (the monotonic replay-ordering rule);
/// - **never fabricate contract state** — the cache only stores provider-
///   issued observations and derived freshness bounds, nothing more;
/// - **never destroy local state** — the cache touches nothing but its own
///   storage; an outage shrinks it by nothing.
///
/// A window of `0` seconds is a valid "accept then immediately stale"
/// policy. R5-004 will extend acceptance with signature verification before
/// an observation may be trusted; until then this cache only orders and
/// bounds provider-asserted data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservationCache {
    freshness_window_secs: u64,
    per_contract: HashMap<ConnectivityContractRef, CachedObservation>,
}

impl ObservationCache {
    /// A cache treating accepted observations as fresh for
    /// `freshness_window_secs` after their `observed_at_unix`.
    pub fn new(freshness_window_secs: u64) -> Self {
        Self {
            freshness_window_secs,
            per_contract: HashMap::new(),
        }
    }

    /// The configured freshness window (seconds).
    pub fn freshness_window_secs(&self) -> u64 {
        self.freshness_window_secs
    }

    /// Accept an observation into the cache if its sequence is strictly
    /// greater than the cached one for its contract; ignore replays.
    ///
    /// Because the provider assigns a monotonic per-provider sequence, a
    /// lower-or-equal sequence arriving later is a redelivery, not a new
    /// fact — it is ignored (dedup by sequence). This method mutates only
    /// the cache itself.
    pub fn accept(&mut self, observation: &ConnectivityObservation) -> AcceptOutcome {
        let fresh_until = observation
            .observed_at_unix()
            .saturating_add(self.freshness_window_secs);
        match self.per_contract.get(observation.contract()) {
            Some(cached) if cached.observation().sequence() >= observation.sequence() => {
                AcceptOutcome::IgnoredReplay {
                    sequence: observation.sequence(),
                }
            }
            _ => {
                self.per_contract.insert(
                    *observation.contract(),
                    CachedObservation {
                        observation: observation.clone(),
                        fresh_until_unix: fresh_until,
                    },
                );
                AcceptOutcome::Accepted
            }
        }
    }

    /// The cached (last accepted) observation for a contract, if any.
    pub fn last_accepted(&self, contract: &ConnectivityContractRef) -> Option<&CachedObservation> {
        self.per_contract.get(contract)
    }

    /// The freshness bound of the cached observation for a contract
    /// (mirrors the `last_observation_fresh_until_unix` field of
    /// [`crate::PortError::ProviderUnavailable`], which the provider reports
    /// for its side).
    pub fn last_observation_fresh_until_unix(&self, contract: &ConnectivityContractRef) -> Option<u64> {
        self.per_contract.get(contract).map(|c| c.fresh_until_unix())
    }

    /// Whether the cached observation for a contract is still fresh at
    /// `now_unix` (fresh strictly before its bound).
    pub fn is_fresh(&self, contract: &ConnectivityContractRef, now_unix: u64) -> bool {
        self.last_observation_fresh_until_unix(contract)
            .is_some_and(|fresh_until| now_unix < fresh_until)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::AcceptOutcome;
    use crate::refs::REF_ID_LEN;

    fn contract(tag: u8) -> ConnectivityContractRef {
        ConnectivityContractRef::from_id([tag; REF_ID_LEN])
    }

    fn obs(sequence: u64, at: u64, tag: u8) -> ConnectivityObservation {
        ConnectivityObservation::new(
            ObservationKind::AssuranceAvailable,
            at,
            contract(tag),
            sequence,
        )
    }

    #[test]
    fn cache_dedupes_replays_by_sequence() {
        let mut cache = ObservationCache::new(600);
        assert_eq!(cache.accept(&obs(1, 1000, 1)), AcceptOutcome::Accepted);
        assert_eq!(cache.accept(&obs(2, 1010, 1)), AcceptOutcome::Accepted);
        // Exact duplicate...
        assert_eq!(
            cache.accept(&obs(2, 1010, 1)),
            AcceptOutcome::IgnoredReplay { sequence: 2 }
        );
        // ...and a reordered replay of an older sequence.
        assert_eq!(
            cache.accept(&obs(1, 1000, 1)),
            AcceptOutcome::IgnoredReplay { sequence: 1 }
        );
        // The cache keeps the highest-sequence observation.
        assert_eq!(cache.last_accepted(&contract(1)).unwrap().observation().sequence(), 2);
        // Contracts are independent.
        assert_eq!(cache.accept(&obs(1, 1000, 2)), AcceptOutcome::Accepted);
        assert_eq!(
            cache.last_accepted(&contract(2)).unwrap().observation().sequence(),
            1
        );
    }

    #[test]
    fn cache_freshness_semantics() {
        let mut cache = ObservationCache::new(600);
        cache.accept(&obs(7, 1000, 3));
        assert_eq!(
            cache.last_observation_fresh_until_unix(&contract(3)),
            Some(1600)
        );
        assert!(cache.is_fresh(&contract(3), 1599));
        assert!(!cache.is_fresh(&contract(3), 1600), "bound is exclusive");
        // No observation cached for another contract → no freshness claim.
        assert_eq!(cache.last_observation_fresh_until_unix(&contract(4)), None);
        assert!(!cache.is_fresh(&contract(4), 0));
        // A zero window is a valid accept-then-immediately-stale policy.
        let mut zero = ObservationCache::new(0);
        zero.accept(&obs(1, 1000, 5));
        assert!(!zero.is_fresh(&contract(5), 1000));
    }

    #[test]
    fn observation_kinds_are_exactly_the_adcos_event_list() {
        let all = [
            ObservationKind::ContractActivated,
            ObservationKind::ExecutionStateChanged,
            ObservationKind::Degraded,
            ObservationKind::AssuranceAvailable,
            ObservationKind::FailoverReplan,
            ObservationKind::Terminated,
        ];
        for kind in all {
            assert_eq!(ObservationKind::from_name(kind.as_str()), Some(kind));
        }
        assert_eq!(ObservationKind::from_name("bogus"), None);
        assert_eq!(all.len(), 6, "the adcos.md mapping has exactly six events");
    }
}
