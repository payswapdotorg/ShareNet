//! ShareNet ADCOS boundary — work item R5-001 (`ConnectivityPort`).
//!
//! This crate IS the `connectivity/` layer named by `spec/architecture.md` §6
//! and mandated by `AGENTS.md`: "`connectivity/` is the boundary to ADCOS."
//! It contains the technology-neutral seam through which ShareNet acquires
//! external connectivity outcomes, per ADR-001:
//!
//! > "ShareNet consumes technology-neutral connectivity outcomes through
//! > `ConnectivityPort`."
//!
//! # The boundary law
//!
//! From `spec/integrations/adcos.md` (THE interface contract) and
//! `spec/adrs/001-adcos-boundary.md`:
//!
//! - ADCOS owns `ConnectivityContract` — the canonical durable object.
//!   ShareNet stores only a [`ConnectivityContractRef`] and local operational
//!   projections. "ShareNet MUST NOT recreate ADCOS contract semantics."
//!   Nothing in this crate is a contract authority.
//! - The interface is exactly the [`ConnectivityPort`] trait:
//!   `createIntent` / `discoverOffers` / `acceptOffer` / `getContract` /
//!   `getAssurance` / `getExecution` / `terminate`.
//! - "The actual wire client speaks the ADCOS developer API. The domain does
//!   not import ADCOS server internals." The real client is R5-002; this
//!   crate defines the trait it will implement, plus the in-memory test
//!   vehicle ([`memory::InMemoryConnectivityPort`]) it will be tested against.
//! - Provider-native SDKs, gNB/UPF APIs, carrier SDKs, Wi-Fi operator
//!   proprietary APIs and tunnel-provider objects are forbidden inside this
//!   crate (architecture lock L006: "Provider-native APIs/SDK types cannot
//!   cross `ConnectivityPort`").
//! - Observations are READ-ONLY data: "An observation is not permitted to
//!   mutate ShareNet's authoritative circuit, route, identity or content
//!   state without independent ShareNet protocol verification." No API in
//!   this crate lets an observation mutate anything — the port exposes only
//!   queries plus the intent lifecycle, and the only consumer-side type that
//!   stores observations ([`observation::ObservationCache`]) touches nothing
//!   but its own storage.
//!
//! # Failure semantics (ADCOS unavailable)
//!
//! `spec/integrations/adcos.md` requires, when ADCOS is unreachable:
//! do not destroy valid local P2P state solely because of the outage; do not
//! fabricate a contract state; cache the last accepted observation with
//! freshness metadata; prevent new acquisition if authorization cannot be
//! established; continue local/DTN operations. These are carried by
//! [`PortError::ProviderUnavailable`] / [`PortError::AcquisitionUnauthorized`]
//! and the caller-side caching policy type
//! [`observation::ObservationCache`].
//!
//! # Platform independence
//!
//! No dependencies at all (std only): no protocol-core import, no async
//! runtime, no I/O, no wall clock (implementations supply unix timestamps —
//! the fake uses a deterministic virtual clock). The crate therefore
//! compiles for `wasm32-unknown-unknown` (the L007 discipline of the protocol
//! core, applied to the boundary), keeping R5-001 independently freezable
//! from the circuit implementation — which is exactly what
//! `tools/architecture_check.py` enforces for this work item's dependency
//! set.
//!
//! # What is deliberately NOT here
//!
//! - No canonical CBOR, no signatures, no wire encoding. The reference
//!   objects here are opaque provider-assigned ids and local read-only
//!   projections — NOT protocol wire objects (see [`refs`]). Signed
//!   observations are R5-004.
//! - No real ADCOS wire client (R5-002), no provider federation, no
//!   persistence of projections (runtime state only; durable refs are
//!   R5-003 scope).
//! - [`memory::InMemoryConnectivityPort`] is a TEST VEHICLE (like
//!   `MemoryTunPair` in `transport/linux`): a deterministic fake provider,
//!   not an ADCOS implementation.
//!
//! # Modules
//!
//! - [`refs`]: the three opaque capability reference types.
//! - [`requirement`]: the intent input (`ConnectivityRequirement`).
//! - [`projection`]: read-only contract / execution projections.
//! - [`observation`]: provider observations + the caching policy type.
//! - [`error`]: the typed [`PortError`].
//! - [`port`]: the [`ConnectivityPort`] trait.
//! - [`memory`]: the in-memory TEST VEHICLE provider.

#![forbid(unsafe_code)]

pub mod error;
pub mod memory;
pub mod observation;
pub mod port;
pub mod projection;
pub mod refs;
pub mod requirement;

pub use error::PortError;
pub use memory::{
    FailureMode, InMemoryConnectivityPort, DEFAULT_CONTRACT_WINDOW_SECS,
    DEFAULT_FRESHNESS_WINDOW_SECS, DEFAULT_OFFERS_PER_INTENT, FAKE_CLOCK_START_UNIX,
};
pub use observation::{
    AcceptOutcome, CachedObservation, ConnectivityObservation, ObservationCache, ObservationKind,
};
pub use port::ConnectivityPort;
pub use projection::{
    ConnectivityContractProjection, ConnectivityExecutionProjection, ContractState,
    MAX_EXECUTION_STATE_TEXT_BYTES,
};
pub use refs::{
    ConnectivityContractRef, ConnectivityIntentRef, ConnectivityOfferRef, RefKind, REF_ID_LEN,
};
pub use requirement::{
    ConnectivityRequirement, ServiceClass, MAX_REGION_HINT_BYTES, REQUIREMENT_VERSION,
    SERVICE_CLASSES,
};
