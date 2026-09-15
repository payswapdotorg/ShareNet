//! The fixed evidence snapshot — the policy's input.
//!
//! A [`GatewayAdmissionRequest`] borrows everything it needs; the policy
//! clones nothing and mutates nothing (the observation read-only law). It
//! contains ONLY evidence and identifiers — there is no trust boolean, no
//! "verified" flag, no override anywhere in the API: every security-critical
//! fact is re-derived from the supplied signed evidence and typed
//! projections at decision time.
//!
//! The caller supplies `now_unix` (this crate has no wall clock, by the same
//! law as the two domain crates) — the timestamp is part of the snapshot,
//! which is what makes the decision deterministic for a fixed snapshot.

use sharenet_connectivity::ContractHealth;
use sharenet_protocol::{SignedConnectivityObservation, SignedTopologyEvidence};

/// One admission evaluation: the gateway under review, the decision clock,
/// and the two evidence factors.
///
/// `sharenet_link` is the R3-003 signed link evidence ABOUT the gateway
/// node (the observer attests a link whose subject is the gateway). The
/// policy verifies it itself — a caller that already ran it through
/// `TopologyStore::receive` passes the SAME signed record; verification is
/// idempotent and never trusted, only derived.
///
/// `adcos_backhaul` is the gateway's ADCOS-side evidence bundle.
#[derive(Debug, Clone, Copy)]
pub struct GatewayAdmissionRequest<'a> {
    /// The node under admission review — the subject every piece of
    /// evidence must bind to.
    pub gateway_node_id: [u8; 32],
    /// The decision clock (unix seconds, caller-supplied; no wall clock
    /// in this crate).
    pub now_unix: u64,
    /// Factor 1: the signed ShareNet link evidence about the gateway
    /// (`None` = no evidence supplied).
    pub sharenet_link: Option<&'a SignedTopologyEvidence>,
    /// Factor 2: the ADCOS-backed backhaul evidence (`None` = no evidence
    /// supplied).
    pub adcos_backhaul: Option<AdcosBackhaulEvidence<'a>>,
}

/// The ADCOS-side evidence bundle for one gateway's backhaul contract.
///
/// - `health` is the R5-003 durable store's health view for the contract
///   (`store.health(&contract)`); `None` means the contract is not tracked
///   at all (never registered / never observed) — which is no evidence.
/// - `signed_observations` is the evidence set the projection was fed
///   from — the verified-path residue (in a real daemon this is exactly
///   what `get_assurance` returned: the provider's full signed log,
///   redeliveries included). The policy verifies every signature itself
///   and requires the projection's accepted log to be exactly covered by
///   the verified set, so a store fed off the verified path cannot admit.
///
/// The set may legitimately contain observations for OTHER contracts (a
/// caller's bundle); those are ignored — but any member that fails
/// signature verification poisons the decision (fail-closed).
#[derive(Debug, Clone, Copy)]
pub struct AdcosBackhaulEvidence<'a> {
    /// The durable projection's health for the gateway's backhaul contract
    /// (`None` = not tracked).
    pub health: Option<&'a ContractHealth>,
    /// The signed observations for the contract (the verified-path
    /// evidence the projection was fed from).
    pub signed_observations: &'a [SignedConnectivityObservation],
}
