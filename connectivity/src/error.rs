//! The typed port error — same style as the protocol core's typed errors
//! (stable machine names, no panic paths, no strings-as-errors).

use core::fmt;

use crate::refs::{ConnectivityContractRef, ConnectivityIntentRef, ConnectivityOfferRef, RefKind};

/// Typed violations of the `ConnectivityPort` contract, including the
/// ADCOS-unavailable failure semantics of `spec/integrations/adcos.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortError {
    /// The requirement's struct version is not the one this port speaks
    /// (future-extensibility enforcement at the seam).
    RequirementVersionUnsupported {
        /// The version that was found.
        found: u32,
    },
    /// The region hint exceeded its byte bound.
    RegionHintTooLong {
        /// The byte length that was found.
        len: usize,
        /// The allowed maximum.
        max: usize,
    },
    /// A contract projection was requested with an invalid validity window
    /// (`valid_from_unix >= valid_until_unix`); the window is enforced at
    /// construction.
    ValidityWindowInvalid {
        /// The window start that was supplied.
        valid_from_unix: u64,
        /// The window end that was supplied.
        valid_until_unix: u64,
    },
    /// The execution state text exceeded its byte bound.
    ExecutionStateTextTooLong {
        /// The byte length that was found.
        len: usize,
        /// The allowed maximum.
        max: usize,
    },
    /// A reference reconstructed from raw parts carried the wrong kind tag.
    RefKindMismatch {
        /// The kind the receiving type requires.
        expected: RefKind,
        /// The kind that was found.
        found: RefKind,
    },
    /// The intent reference is not known to the provider.
    IntentUnknown {
        /// The unknown intent reference.
        intent: ConnectivityIntentRef,
    },
    /// The offer reference is not known to the provider.
    OfferUnknown {
        /// The unknown offer reference.
        offer: ConnectivityOfferRef,
    },
    /// The offer exists but belongs to a different intent than the one
    /// passed to `acceptOffer`.
    OfferNotForIntent {
        /// The offer that was passed.
        offer: ConnectivityOfferRef,
        /// The intent the offer does NOT belong to.
        passed_intent: ConnectivityIntentRef,
    },
    /// The offer was already consumed by a live `acceptOffer` (offers are
    /// single-use); the resulting contract is carried for diagnosis.
    OfferAlreadyConsumed {
        /// The offer that was passed.
        offer: ConnectivityOfferRef,
        /// The contract the earlier acceptance produced.
        contract: ConnectivityContractRef,
    },
    /// The contract reference is not known to the provider.
    ContractUnknown {
        /// The unknown contract reference.
        contract: ConnectivityContractRef,
    },
    /// The contract is terminated — terminal. Further acquisition on it
    /// refuses; queries still report the terminal state.
    ContractTerminated {
        /// The terminated contract reference.
        contract: ConnectivityContractRef,
    },
    /// ADCOS is unreachable (`spec/integrations/adcos.md` "Failure
    /// semantics").
    ///
    /// Callers: cache the last accepted observation with freshness metadata
    /// (see [`crate::ObservationCache`]); do not destroy valid local P2P
    /// state solely because of the outage; do not fabricate a contract
    /// state; continue local/DTN operations.
    ProviderUnavailable {
        /// Until when (exclusive, unix seconds) the last accepted
        /// observation may still be treated as fresh, as the provider's
        /// side knows it. `None` means no freshness claim exists.
        last_observation_fresh_until_unix: Option<u64>,
    },
    /// Authorization for new acquisition could not be established
    /// ("prevent new acquisition if authorization cannot be established") —
    /// `createIntent` / `discoverOffers` / `acceptOffer` refuse; queries and
    /// termination are unaffected.
    AcquisitionUnauthorized,
}

impl PortError {
    /// Stable machine name (the same discipline as the protocol core's
    /// typed errors — usable in tests, logs and the future R5-002 client's
    /// error mapping).
    pub fn name(&self) -> &'static str {
        match self {
            PortError::RequirementVersionUnsupported { .. } => "requirement_version_unsupported",
            PortError::RegionHintTooLong { .. } => "region_hint_too_long",
            PortError::ValidityWindowInvalid { .. } => "validity_window_invalid",
            PortError::ExecutionStateTextTooLong { .. } => "execution_state_text_too_long",
            PortError::RefKindMismatch { .. } => "ref_kind_mismatch",
            PortError::IntentUnknown { .. } => "intent_unknown",
            PortError::OfferUnknown { .. } => "offer_unknown",
            PortError::OfferNotForIntent { .. } => "offer_not_for_intent",
            PortError::OfferAlreadyConsumed { .. } => "offer_already_consumed",
            PortError::ContractUnknown { .. } => "contract_unknown",
            PortError::ContractTerminated { .. } => "contract_terminated",
            PortError::ProviderUnavailable { .. } => "provider_unavailable",
            PortError::AcquisitionUnauthorized => "acquisition_unauthorized",
        }
    }
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortError::RequirementVersionUnsupported { found } => {
                write!(f, "requirement version {found} is not supported (expected {})", crate::requirement::REQUIREMENT_VERSION)
            }
            PortError::RegionHintTooLong { len, max } => {
                write!(f, "region hint is {len} bytes, max is {max}")
            }
            PortError::ValidityWindowInvalid {
                valid_from_unix,
                valid_until_unix,
            } => write!(
                f,
                "contract validity window is invalid: valid_from_unix {valid_from_unix} must be strictly before valid_until_unix {valid_until_unix}"
            ),
            PortError::ExecutionStateTextTooLong { len, max } => {
                write!(f, "execution state text is {len} bytes, max is {max}")
            }
            PortError::RefKindMismatch { expected, found } => write!(
                f,
                "reference kind mismatch: expected {expected}, found {found} (an id of one kind cannot be re-typed as another)"
            ),
            PortError::IntentUnknown { intent } => {
                write!(f, "intent {} is unknown to the provider", intent.to_hex())
            }
            PortError::OfferUnknown { offer } => {
                write!(f, "offer {} is unknown to the provider", offer.to_hex())
            }
            PortError::OfferNotForIntent { offer, passed_intent } => write!(
                f,
                "offer {} does not belong to intent {}",
                offer.to_hex(),
                passed_intent.to_hex()
            ),
            PortError::OfferAlreadyConsumed { offer, contract } => write!(
                f,
                "offer {} was already consumed by contract {}",
                offer.to_hex(),
                contract.to_hex()
            ),
            PortError::ContractUnknown { contract } => write!(
                f,
                "contract {} is unknown to the provider",
                contract.to_hex()
            ),
            PortError::ContractTerminated { contract } => write!(
                f,
                "contract {} is terminated: acquisition on it refuses; queries still report the terminal state",
                contract.to_hex()
            ),
            PortError::ProviderUnavailable {
                last_observation_fresh_until_unix,
            } => {
                match last_observation_fresh_until_unix {
                    Some(until) => write!(
                        f,
                        "ADCOS provider unavailable: cache the last accepted observation (fresh until unix {until}), do not destroy local P2P state, do not fabricate contract state"
                    ),
                    None => write!(
                        f,
                        "ADCOS provider unavailable: no freshness claim exists, do not destroy local P2P state, do not fabricate contract state"
                    ),
                }
            }
            PortError::AcquisitionUnauthorized => write!(
                f,
                "acquisition authorization could not be established: new acquisition is prevented"
            ),
        }
    }
}

impl std::error::Error for PortError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_names_are_stable_snake_case() {
        let errors = [
            PortError::RequirementVersionUnsupported { found: 2 },
            PortError::RegionHintTooLong { len: 65, max: 64 },
            PortError::ValidityWindowInvalid {
                valid_from_unix: 1,
                valid_until_unix: 1,
            },
            PortError::ExecutionStateTextTooLong { len: 129, max: 128 },
            PortError::RefKindMismatch {
                expected: RefKind::Contract,
                found: RefKind::Offer,
            },
            PortError::AcquisitionUnauthorized,
        ];
        let names: Vec<&str> = errors.iter().map(|e| e.name()).collect();
        assert_eq!(
            names,
            [
                "requirement_version_unsupported",
                "region_hint_too_long",
                "validity_window_invalid",
                "execution_state_text_too_long",
                "ref_kind_mismatch",
                "acquisition_unauthorized",
            ]
        );
        for error in &errors {
            assert!(!error.to_string().is_empty());
        }
        // The provider-unavailable names too.
        assert_eq!(
            PortError::ProviderUnavailable {
                last_observation_fresh_until_unix: None
            }
            .name(),
            "provider_unavailable"
        );
    }
}
