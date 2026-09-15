//! Read-only local projections of ADCOS-managed state.
//!
//! Per `spec/integrations/adcos.md`: "ShareNet MUST NOT recreate ADCOS
//! contract semantics" — a [`ConnectivityContractProjection`] is a *local
//! operational projection*, never a competing contract authority. ADCOS
//! remains the only authority for the `ConnectivityContract`; if ADCOS is
//! unreachable there is NO projection to build (never fabricate contract
//! state — see [`crate::error::PortError::ProviderUnavailable`]).

use crate::error::PortError;
use crate::observation::ObservationKind;
use crate::refs::ConnectivityContractRef;

/// Maximum byte length of the provider-reported execution state text.
pub const MAX_EXECUTION_STATE_TEXT_BYTES: usize = 128;

/// Projected lifecycle state of an ADCOS contract, derived from the
/// `spec/integrations/adcos.md` event mapping:
///
/// | observation | projected state |
/// |---|---|
/// | (accepted offer, nothing yet observed) | `Projected` |
/// | contract activated | `Active` |
/// | degraded | `Degraded` |
/// | terminated | `Terminated` |
///
/// Execution/assurance/failover events do not move the contract state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContractState {
    /// The contract exists (locally projected) but no activation event has
    /// been observed yet.
    Projected,
    /// A contract-activated observation has been mapped.
    Active,
    /// A degraded observation has been mapped.
    Degraded,
    /// A terminated observation has been mapped (terminal).
    Terminated,
}

impl ContractState {
    /// Stable machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            ContractState::Projected => "projected",
            ContractState::Active => "active",
            ContractState::Degraded => "degraded",
            ContractState::Terminated => "terminated",
        }
    }

    /// The `spec/integrations/adcos.md` event mapping as a state effect:
    /// which observation kinds move the projected contract state (and which
    /// do not). This is the one place the mapping lives in code.
    pub fn from_observation_kind(kind: ObservationKind) -> Option<ContractState> {
        match kind {
            ObservationKind::ContractActivated => Some(ContractState::Active),
            ObservationKind::Degraded => Some(ContractState::Degraded),
            ObservationKind::Terminated => Some(ContractState::Terminated),
            ObservationKind::ExecutionStateChanged
            | ObservationKind::AssuranceAvailable
            | ObservationKind::FailoverReplan => None,
        }
    }
}

/// Read-only local projection of an ADCOS `ConnectivityContract`.
///
/// NEVER a competing contract authority (ADR-001, architecture lock L002):
/// this is a snapshot of what the provider last reported, carrying the
/// opaque reference, the projected state, the validity window and the
/// freshness timestamp of the data. All fields are private with getters —
/// a projection can be inspected and cloned, but not tampered with and
/// written back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectivityContractProjection {
    contract: ConnectivityContractRef,
    state: ContractState,
    valid_from_unix: u64,
    valid_until_unix: u64,
    freshness_unix: u64,
}

impl ConnectivityContractProjection {
    /// Construct a projection, enforcing `valid_from_unix < valid_until_unix`.
    ///
    /// An empty or inverted validity window is refused — a contract that is
    /// never valid must not be projected as if it were.
    pub fn new(
        contract: ConnectivityContractRef,
        state: ContractState,
        valid_from_unix: u64,
        valid_until_unix: u64,
        freshness_unix: u64,
    ) -> Result<Self, PortError> {
        if valid_from_unix >= valid_until_unix {
            return Err(PortError::ValidityWindowInvalid {
                valid_from_unix,
                valid_until_unix,
            });
        }
        Ok(Self {
            contract,
            state,
            valid_from_unix,
            valid_until_unix,
            freshness_unix,
        })
    }

    /// The opaque contract reference this projection belongs to.
    pub fn contract(&self) -> &ConnectivityContractRef {
        &self.contract
    }

    /// The projected lifecycle state.
    pub fn state(&self) -> ContractState {
        self.state
    }

    /// Validity window start (unix seconds, provider-reported).
    pub fn valid_from_unix(&self) -> u64 {
        self.valid_from_unix
    }

    /// Validity window end (unix seconds, provider-reported); strictly after
    /// [`Self::valid_from_unix`] by construction.
    pub fn valid_until_unix(&self) -> u64 {
        self.valid_until_unix
    }

    /// Freshness timestamp: when the provider data this projection reflects
    /// was last current (unix seconds). Consumers compare this against their
    /// own clock to decide staleness; a stale projection is evidence, not
    /// authority.
    pub fn freshness_unix(&self) -> u64 {
        self.freshness_unix
    }
}

/// Read-only local projection of provider execution state for a contract.
///
/// Throughput/latency are plain `u64` counters — provider-reported numbers
/// with no floats and no unit machinery (throughput in bits/second, latency
/// in milliseconds; the units are this boundary's documented convention).
/// The state is provider text (bounded), because execution state vocabulary
/// belongs to the provider, not to ShareNet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectivityExecutionProjection {
    contract: ConnectivityContractRef,
    state: String,
    throughput_bps: u64,
    latency_ms: u64,
    freshness_unix: u64,
}

impl ConnectivityExecutionProjection {
    /// Construct an execution projection, enforcing the state-text bound.
    pub fn new(
        contract: ConnectivityContractRef,
        state: impl Into<String>,
        throughput_bps: u64,
        latency_ms: u64,
        freshness_unix: u64,
    ) -> Result<Self, PortError> {
        let state = state.into();
        let len = state.as_bytes().len();
        if len > MAX_EXECUTION_STATE_TEXT_BYTES {
            return Err(PortError::ExecutionStateTextTooLong {
                len,
                max: MAX_EXECUTION_STATE_TEXT_BYTES,
            });
        }
        Ok(Self {
            contract,
            state,
            throughput_bps,
            latency_ms,
            freshness_unix,
        })
    }

    /// The opaque contract reference this execution belongs to.
    pub fn contract(&self) -> &ConnectivityContractRef {
        &self.contract
    }

    /// Provider-reported execution state text (bounded; empty is tolerated —
    /// the provider reported nothing).
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Provider-reported throughput in bits/second.
    pub fn throughput_bps(&self) -> u64 {
        self.throughput_bps
    }

    /// Provider-reported latency in milliseconds.
    pub fn latency_ms(&self) -> u64 {
        self.latency_ms
    }

    /// Freshness timestamp (unix seconds) of this execution data.
    pub fn freshness_unix(&self) -> u64 {
        self.freshness_unix
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> ConnectivityContractRef {
        ConnectivityContractRef::from_id([0x42u8; crate::refs::REF_ID_LEN])
    }

    #[test]
    fn validity_window_is_enforced_at_construction() {
        let c = contract();
        // Empty window refused.
        assert_eq!(
            ConnectivityContractProjection::new(c, ContractState::Active, 100, 100, 100),
            Err(PortError::ValidityWindowInvalid {
                valid_from_unix: 100,
                valid_until_unix: 100,
            })
        );
        // Inverted window refused.
        assert_eq!(
            ConnectivityContractProjection::new(c, ContractState::Active, 200, 100, 100),
            Err(PortError::ValidityWindowInvalid {
                valid_from_unix: 200,
                valid_until_unix: 100,
            })
        );
        // Strictly ordered window accepted and exposed.
        let projection =
            ConnectivityContractProjection::new(c, ContractState::Active, 100, 101, 100).unwrap();
        assert_eq!(projection.contract(), &c);
        assert_eq!(projection.state(), ContractState::Active);
        assert_eq!(projection.valid_from_unix(), 100);
        assert_eq!(projection.valid_until_unix(), 101);
        assert_eq!(projection.freshness_unix(), 100);
    }

    #[test]
    fn execution_state_text_bound_is_enforced() {
        let c = contract();
        ConnectivityExecutionProjection::new(c, "active", 1, 2, 3).unwrap();
        let long = "x".repeat(MAX_EXECUTION_STATE_TEXT_BYTES + 1);
        assert_eq!(
            ConnectivityExecutionProjection::new(c, long, 1, 2, 3),
            Err(PortError::ExecutionStateTextTooLong {
                len: MAX_EXECUTION_STATE_TEXT_BYTES + 1,
                max: MAX_EXECUTION_STATE_TEXT_BYTES,
            })
        );
        let exactly_at_bound = "y".repeat(MAX_EXECUTION_STATE_TEXT_BYTES);
        let projection =
            ConnectivityExecutionProjection::new(c, exactly_at_bound, 7, 8, 9).unwrap();
        assert_eq!(projection.throughput_bps(), 7);
        assert_eq!(projection.latency_ms(), 8);
        assert_eq!(projection.freshness_unix(), 9);
        assert_eq!(projection.state().len(), MAX_EXECUTION_STATE_TEXT_BYTES);
    }

    #[test]
    fn contract_state_event_mapping_is_exactly_the_adcos_mapping() {
        use crate::observation::ObservationKind as K;
        assert_eq!(
            ContractState::from_observation_kind(K::ContractActivated),
            Some(ContractState::Active)
        );
        assert_eq!(
            ContractState::from_observation_kind(K::Degraded),
            Some(ContractState::Degraded)
        );
        assert_eq!(
            ContractState::from_observation_kind(K::Terminated),
            Some(ContractState::Terminated)
        );
        // Execution/assurance/failover events never move the contract state.
        assert_eq!(ContractState::from_observation_kind(K::ExecutionStateChanged), None);
        assert_eq!(ContractState::from_observation_kind(K::AssuranceAvailable), None);
        assert_eq!(ContractState::from_observation_kind(K::FailoverReplan), None);
        assert_eq!(ContractState::Projected.as_str(), "projected");
        assert_eq!(ContractState::Terminated.as_str(), "terminated");
    }
}
