//! The `ConnectivityPort` trait — the ONLY ShareNet-to-ADCOS boundary.
//!
//! This is `spec/integrations/adcos.md` "Interface", Rust-ified with owned
//! types, `&self` and a typed [`PortError`] (following the typed-error style
//! of the protocol core):
//!
//! ```text
//! interface ConnectivityPort {
//!     createIntent(requirement): ConnectivityIntentRef
//!     discoverOffers(intent): ConnectivityOfferRef[]
//!     acceptOffer(intent, offer): ConnectivityContractRef
//!     getContract(contract): ConnectivityContractProjection
//!     getAssurance(contract): ConnectivityObservation[]
//!     getExecution(contract): ConnectivityExecutionProjection
//!     terminate(contract): void
//! }
//! ```
//!
//! `&self` (interior mutability is the implementor's business) keeps the
//! trait implementable both by the in-memory fake and by a future real ADCOS
//! developer-API client (R5-002) behind any runtime it likes — the actual
//! wire client speaks the ADCOS developer API; this domain does not import
//! ADCOS server internals.
//!
//! # Laws every implementation must uphold
//!
//! 1. **Read-only observations.** `getAssurance` returns plain data; no
//!    method accepts an observation as input, and nothing an observation can
//!    reach through this trait may mutate ShareNet's authoritative circuit,
//!    route, identity or content state. The port exposes only queries plus
//!    the intent lifecycle.
//! 2. **No second contract authority.** `getContract` returns a local
//!    projection; the ADCOS `ConnectivityContract` stays the canonical
//!    durable object. Implementations never fabricate contract state —
//!    when the provider cannot answer, they return
//!    [`PortError::ProviderUnavailable`] and the caller falls back to its
//!    cached last accepted observation.
//! 3. **Failure semantics** (`spec/integrations/adcos.md`): when ADCOS is
//!    unreachable, valid local P2P state must not be destroyed, contract
//!    state must not be fabricated, the last accepted observation is cached
//!    with freshness metadata ([`PortError::ProviderUnavailable`] carries the
//!    provider-side bound; [`crate::ObservationCache`] is the caller side),
//!    and new acquisition is prevented when authorization cannot be
//!    established ([`PortError::AcquisitionUnauthorized`] — blocking
//!    acquisition only; queries and termination stay available).
//! 4. **`terminate` is idempotent**: terminating an already-terminated
//!    contract returns `Ok(())` with no new effects; terminating an unknown
//!    contract is [`PortError::ContractUnknown`]. After termination, further
//!    acquisition on that contract refuses
//!    ([`PortError::ContractTerminated`]) while queries still report the
//!    terminal state.
//! 5. **Opaque references.** Intent/offer/contract references are compared
//!    and echoed, never parsed (see [`crate::refs`]).
//!
//! # Conformance
//!
//! `tests/port_conformance.rs` holds the trait conformance suite over the
//! in-memory fake; the future R5-002 ADCOS client runs the same suite against
//! its provider-backed implementation.

use crate::error::PortError;
use crate::observation::ConnectivityObservation;
use crate::projection::{ConnectivityContractProjection, ConnectivityExecutionProjection};
use crate::refs::{ConnectivityContractRef, ConnectivityIntentRef, ConnectivityOfferRef};
use crate::requirement::ConnectivityRequirement;

/// Technology-neutral acquisition of external connectivity outcomes from
/// ADCOS — the boundary named by ADR-001 and `spec/architecture.md` §6.
///
/// See the [module documentation](self) for the interface contract and the
/// laws every implementation must uphold.
pub trait ConnectivityPort {
    /// `createIntent(requirement): ConnectivityIntentRef` — state what
    /// outcome is wanted ([`ConnectivityRequirement`]).
    ///
    /// The requirement is validated locally first (version + bounds), then
    /// handed to the provider. New acquisition: blocked by
    /// [`PortError::AcquisitionUnauthorized`] when authorization cannot be
    /// established, and by [`PortError::ProviderUnavailable`] during an
    /// outage.
    fn create_intent(
        &self,
        requirement: ConnectivityRequirement,
    ) -> Result<ConnectivityIntentRef, PortError>;

    /// `discoverOffers(intent): ConnectivityOfferRef[]` — discover the offer
    /// set for an intent. Offer details stay provider-side; ShareNet only
    /// gets opaque references.
    fn discover_offers(
        &self,
        intent: &ConnectivityIntentRef,
    ) -> Result<Vec<ConnectivityOfferRef>, PortError>;

    /// `acceptOffer(intent, offer): ConnectivityContractRef` — accept one
    /// discovered offer and receive the reference to the ADCOS contract that
    /// now owns the acquisition.
    ///
    /// Further acquisition on a terminated contract refuses
    /// ([`PortError::ContractTerminated`]); an offer already consumed by a
    /// live acceptance refuses ([`PortError::OfferAlreadyConsumed`]).
    fn accept_offer(
        &self,
        intent: &ConnectivityIntentRef,
        offer: &ConnectivityOfferRef,
    ) -> Result<ConnectivityContractRef, PortError>;

    /// `getContract(contract): ConnectivityContractProjection` — read-only
    /// local projection of the contract (state per the adcos.md event
    /// mapping, validity window, freshness timestamp). Never a competing
    /// contract authority; never fabricated during an outage.
    fn get_contract(
        &self,
        contract: &ConnectivityContractRef,
    ) -> Result<ConnectivityContractProjection, PortError>;

    /// `getAssurance(contract): ConnectivityObservation[]` — the observation
    /// log for a contract, in emission order.
    ///
    /// Observations are READ-ONLY data: duplicates from provider redelivery
    /// may appear (identical sequence numbers); consumers dedupe by sequence
    /// (see [`crate::ObservationCache`]). After dedup the sequence order is
    /// strictly increasing — the monotonic per-provider replay ordering.
    fn get_assurance(
        &self,
        contract: &ConnectivityContractRef,
    ) -> Result<Vec<ConnectivityObservation>, PortError>;

    /// `getExecution(contract): ConnectivityExecutionProjection` — read-only
    /// provider-reported execution state (plain `u64` throughput/latency
    /// counters, bounded state text, freshness timestamp).
    fn get_execution(
        &self,
        contract: &ConnectivityContractRef,
    ) -> Result<ConnectivityExecutionProjection, PortError>;

    /// `terminate(contract): void` — end the acquisition. Idempotent:
    /// terminating an already-terminated contract is `Ok(())` with no new
    /// effects. The terminal state remains queryable.
    fn terminate(&self, contract: &ConnectivityContractRef) -> Result<(), PortError>;
}
