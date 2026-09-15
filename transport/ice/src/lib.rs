//! ShareNet ICE/TURN transport (work item R4-005).
//!
//! The NAT-traversal / relay layer per `spec/architecture-lock.md` L011
//! ("ICE/STUN/TURN/MASQUE should be reused before custom NAT/proxy
//! protocols are invented") and L012 ("relays forward opaque end-to-end
//! tunnel traffic whenever possible"):
//!
//! - **STUN** (RFC 5389 subset): a strict in-crate codec + UDP client for
//!   the standard Binding exchange — no external STUN dependency, no new
//!   protocol. XOR-MAPPED-ADDRESS feeds server-reflexive candidates.
//! - **Candidates** (RFC 8445 concepts): host / server-reflexive /
//!   relayed candidates with the standard priority and foundation
//!   formulas, gathering, and priority-ordered pairing. No full agent
//!   state machine — nomination is future R4-006/R4-007 scope.
//! - **TURN-style relay** (RFC 8656 concepts over UDP): per-5-tuple
//!   allocations with relayed addresses that forward OPAQUE datagrams
//!   between the allocation's client and peers. The tiny binary control
//!   framing is explicitly TEST/LOCAL scope (no TURN auth — future
//!   R4-006); the payloads are never parsed (L012).
//! - **QUIC integration** (R4-001): gathered candidates are the address
//!   source for node-pinned QUIC tunnels, and a full pinned tunnel rides
//!   the relay transparently (`bridge::tunnel_connect`).
//!
//! This crate is the platform adapter layer (L009): it contains NO
//! protocol semantics — no identity, links, routing, circuits or
//! content. Node authentication happens in the QUIC/TLS layer it hands
//! addresses to; ShareNet-level authentication rides inside the tunnel.
//!
//! ```text
//! application / link frames
//!     ↓ length-framed tunnel session (transport/quic, R4-001)
//! QUIC + TLS 1.3 (quinn), node-id pinned
//!     ↓ candidate addresses from this crate (host / srflx / relayed)
//! UDP — directly, or through TURN-style relays forwarding opaque
//! datagrams (L012)
//!     ↓
//! gateway → Internet
//! ```
//!
//! # Persistence
//!
//! None: candidates, allocations and relays are runtime state (durable
//! circuit state is R4-002/R7 scope).
//!
//! # Test scaffolding
//!
//! The sandbox cannot reach external STUN/TURN servers, so verification
//! runs LOCAL real ones — `stun_server` and `turn_relay` are real
//! separate processes over real loopback UDP (the same honest pattern as
//! the two-process tests of the sibling crates). They are clearly marked
//! TEST SCAFFOLDING.

pub mod bridge;
pub mod candidate;
mod entropy;
pub mod error;
pub mod relay;
pub mod stun;

pub use bridge::tunnel_connect;
pub use candidate::{
    gather, pair_candidates, Candidate, CandidatePair, CandidateType, GatherConfig, Gathered,
};
pub use error::IceError;
pub use relay::{
    check_datagram_limit, ControlFrame, RelayClient, RelayServer, RelayServerAdapter,
    MAX_RELAY_DATAGRAM,
};
pub use stun::{
    binding_request, connectivity_check, Attribute, BindingOutcome, DatagramPipe, MessageClass,
    StunConfig, StunMessage, TransactionId, ATTR_SOFTWARE, ATTR_XOR_MAPPED_ADDRESS, MAGIC_COOKIE,
    METHOD_BINDING, SOFTWARE_MAX_BYTES,
};
