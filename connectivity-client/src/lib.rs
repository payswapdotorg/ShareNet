//! ShareNet ADCOS wire client — work item R5-002 (`connectivity-client/`).
//!
//! `spec/integrations/adcos.md`:
//!
//! > "The actual wire client speaks the ADCOS developer API. The domain
//! > does not import ADCOS server internals."
//!
//! This crate IS that wire client: [`AdcosClient`] implements the parent
//! crate's [`sharenet_connectivity::ConnectivityPort`] trait against a
//! minimal JSON-over-HTTP/1.1 mapping of the ADCOS developer API, over std
//! TCP. It is the boundary ADAPTER — the only place in ShareNet that knows
//! the ADCOS transport format ("Only the ADCOS adapter may know the ADCOS
//! developer API transport format").
//!
//! # Layout
//!
//! - [`wire`]: the wire shape — DTOs, endpoint request builders, response
//!   parsers, and the typed error envelope (the `PortError` machine names
//!   are the wire error vocabulary).
//! - [`http`]: the minimal hand-rolled HTTP/1.1 codec (request/response
//!   serialization + strict parsing; no HTTP framework).
//! - [`hex`]: strict lowercase-hex for the 32-byte opaque reference ids.
//! - [`error`]: [`AdcosError`] — the full typed error surface, flattened
//!   into `PortError` at the trait boundary.
//! - [`transport`]: std-TCP dial/write/read with timeouts and a
//!   method-aware retry policy (host-only).
//! - [`client`]: [`AdcosClient`] — the `ConnectivityPort` implementation.
//!
//! # Platform independence
//!
//! The domain mapping ([`wire`], [`http`], [`hex`], [`error`]) is pure data
//! — no sockets — and compiles for `wasm32-unknown-unknown`, so the mapping
//! can be unit-tested and frozen independently of the socket layer. The
//! TCP transport and the client itself are gated behind
//! `#[cfg(not(target_family = "wasm"))]` (std sockets need an OS; on wasm
//! hosts the same mapping would ride a host HTTP API — see the README).
//!
//! # Dependencies (deliberately tiny)
//!
//! `sharenet-connectivity` (the boundary being implemented — the whole
//! point of R5-002) plus `serde`/`serde_json` for the JSON bodies. No
//! protocol core, no async runtime, no HTTP framework, no TLS (documented
//! as future hardening in the README).
//!
//! # Test scaffolding
//!
//! `src/bin/adcos_test_server.rs` is a TEST SCAFFOLDING binary (same
//! discipline as `transport/ice`'s `stun_server`): a real std::TCP server
//! speaking exactly this wire shape over a deterministic in-memory store,
//! with injectable fault modes (drop connection, provider-unavailable,
//! slow response, unauthorized acquisition, adversarial response shapes)
//! and test-control endpoints. It backs the integration suite
//! (`tests/adcos_integration.rs`), which re-runs the parent crate's
//! generic `conformance_core` battery against this client.

#![forbid(unsafe_code)]

pub mod error;
pub mod hex;
pub mod http;
pub mod wire;

#[cfg(not(target_family = "wasm"))]
pub mod client;
#[cfg(not(target_family = "wasm"))]
pub mod transport;

pub use error::{AdcosError, MalformedReason};

#[cfg(not(target_family = "wasm"))]
pub use client::{AdcosClient, AdcosConfig};
#[cfg(not(target_family = "wasm"))]
pub use transport::{TransportConfig, TransportLimits};
