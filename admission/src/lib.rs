//! ShareNet gateway admission/backhaul policy — work item R5-005.
//!
//! `spec/integrations/adcos.md` ("Gateway admission") is THE governing rule:
//!
//! > "A gateway becomes ShareNet-eligible only when BOTH exist:
//! > 1. authenticated ShareNet node/link evidence;
//! > 2. acceptable ADCOS-backed external connectivity evidence."
//!
//! This crate is that rule as a **pure, deterministic, typed decision
//! function**. It composes the two evidence domains that ShareNet already
//! owns — no new evidence is invented here:
//!
//! - **Factor 1 (ShareNet side)** — a [`SignedTopologyEvidence`] link
//!   observation about the gateway node (R3-003). The policy VERIFIES it
//!   itself (strict parse, Ed25519 signature against the embedded observer
//!   identity, kind, node binding, temporal window) — exactly the
//!   [`sharenet_protocol::TopologyStore::receive`] verification steps minus
//!   collection. Per AGENTS.md ("Security-critical facts must be derived
//!   from authenticated protocol state, cryptographic evidence, and durable
//!   state. Never accept caller-controlled security booleans when the fact
//!   can be derived"), the policy accepts no trust assertion it can derive.
//! - **Factor 2 (ADCOS side)** — the R5-003 durable local health projection
//!   ([`ContractHealth`] + the typed [`ProjectionFreshness`]) for the
//!   gateway's backhaul contract, PLUS the R5-004
//!   [`SignedConnectivityObservation`]s the projection was fed from. The
//!   policy re-verifies every signature and requires the projection's
//!   accepted log to be exactly covered by that verified evidence — the
//!   "UNSIGNED observations never enter durable ShareNet state" trust
//!   boundary, *derived* at decision time rather than trusted.
//!
//! # The decision
//!
//! [`GatewayAdmissionPolicy::decide`] returns a typed
//! [`GatewayAdmission`]:
//!
//! - `Eligible { gateway_node_id, sharenet, adcos, valid_until_unix }` —
//!   both factors verified, fresh, within the quality floor; the anchors
//!   carry exactly what was admitted (link id, observer, quality; contract,
//!   state, freshness) and `valid_until_unix` is the earlier of the two
//!   factors' freshness bounds.
//! - `Ineligible { reasons }` — a deterministic, ordered list of typed
//!   machine-named reasons ([`AdmissionReason`]). Either side missing,
//!   stale or unverified is `Ineligible`: **fail-closed, never a
//!   default-allow**. There is no partial credit and no override.
//!
//! # Determinism (architecture §2)
//!
//! > "The routing objective is deterministic for a fixed evidence snapshot.
//! > Hard constraints may not be overridden by an optimizer."
//!
//! `decide` is a pure function of `(AdmissionParams, GatewayAdmissionRequest)`:
//! no wall clock (the caller supplies `now_unix` inside the request), no I/O,
//! no iteration-order dependence (no hash maps; the verified-evidence set is
//! walked in input order, the projection log in acceptance order, and reasons
//! are pushed in a fixed evaluation order). The same snapshot always yields
//! the same decision — proven by test.
//!
//! # The honest boundary (what an `Eligible` decision is NOT)
//!
//! adcos.md states the law twice, and this crate's decision grants neither:
//!
//! > "ADCOS does not attest ShareNet packet delivery. ShareNet does not
//! > attest provider fulfillment."
//!
//! An `Eligible` decision is the typed INPUT to gateway selection: it says
//! "this gateway's two-factor evidence is present, cryptographically
//! verified, fresh, and within the policy's quality floor at `now_unix`".
//! It is NOT a promise that the gateway will deliver ShareNet packets, and
//! NOT a promise that the provider is fulfilling its contract — those are
//! runtime facts only the data plane and continued observations can speak
//! to. Selection (R3-004 routing and its gateway scoring), revocation on
//! failure (R7-001), and Civic Points overlays (R8) consume this decision;
//! they do not get more from it than it honestly carries.
//!
//! # Layout
//!
//! - [`params`]: [`AdmissionParams`] — the policy knobs (freshness window,
//!   loss-ratio floor in integer ppm, latency bound in ms) with typed
//!   construction validation.
//! - [`evidence`]: [`GatewayAdmissionRequest`] + [`AdcosBackhaulEvidence`] —
//!   the fixed evidence snapshot (borrowed; the policy clones nothing).
//! - [`decision`]: [`GatewayAdmission`], [`AdmissionReason`] and the
//!   eligibility anchors.
//! - [`policy`]: [`GatewayAdmissionPolicy`] — the engine.
//!
//! # Dependencies and platform independence
//!
//! Exactly two, both ShareNet: `sharenet-protocol` (authenticated evidence
//! types + verification) and `sharenet-connectivity` (the typed ADCOS
//! projection). The `connectivity/` boundary itself stays zero-dependency
//! (ADR-001) — this crate lives OUTSIDE it, in the same composition
//! position as `connectivity-client/`. No async runtime, no serde, no I/O,
//! no wall clock; the lib compiles for `wasm32-unknown-unknown` (the L007
//! discipline) — only the integration tests touch the file-backed
//! `DurableProjectionStore`, which is native-only by design.
//!
//! # What is deliberately NOT here
//!
//! - **No gateway selection.** The decision is the input to selection, not
//!   selection itself (architecture: "gateway selection" is the control
//!   plane's job, on top of per-gateway admission).
//! - **No bilateral-link requirement.** The ShareNet-side input is ONE
//!   verified one-directional link evidence about the gateway node —
//!   exactly what adcos.md's "authenticated ShareNet node/link evidence"
//!   names. R3-003's bilateral anti-gaming rule (fresh evidence from BOTH
//!   endpoints) is the routing layer's concern; gateway selection may
//!   compose it on top.
//! - **No new wire objects.** The decision is a local typed policy output,
//!   never serialized or signed — so the protocol registry governs nothing
//!   here (no pre-registration needed).
//! - **No provider pinning.** Each signed observation's signature is
//!   verified against its embedded provider identity, but the policy does
//!   not pin WHICH provider may observe a given contract (the
//!   contract→provider binding is not on any ShareNet wire — refs are
//!   opaque by law). A daemon that wants a pin pre-filters the signed
//!   evidence set it passes in; see the README's honest-gaps section.
//! - **No packet-delivery or fulfillment attestation** — see above.

#![forbid(unsafe_code)]

pub mod decision;
pub mod evidence;
pub mod params;
pub mod policy;

pub use decision::{
    AdmissionReason, AdcosEvidenceAnchor, GatewayAdmission, ShareNetEvidenceAnchor,
};
pub use evidence::{AdcosBackhaulEvidence, GatewayAdmissionRequest};
pub use params::{AdmissionParams, AdmissionParamsError};
pub use policy::GatewayAdmissionPolicy;
