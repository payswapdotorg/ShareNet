//! # sharenet-transport-linux
//!
//! ShareNet Linux transport foundation (work item **R2-003**).
//!
//! ## What this crate is
//!
//! A *platform adapter layer* for Linux, per `spec/architecture-lock.md` **L009**:
//! platform transports are adapters, never protocol semantics. This crate
//! therefore contains **no** ShareNet identity, link, routing, circuit, content,
//! contribution, or cryptographic logic — those live in the protocol core
//! (`reference/`, owned by Worker 1). It provides exactly three things:
//!
//! 1. [`tun`]: a synchronous [`TunDevice`](tun::TunDevice) abstraction with a
//!    real `/dev/net/tun` implementation (`SystemTunDevice`, via raw `ioctl`
//!    `TUNSETIFF`) and an in-memory duplex pair for tests (`MemoryTunDevice`,
//!    clearly marked test vehicle).
//! 2. [`probe`]: an honest runtime capability probe
//!    ([`probe_tun()`](probe::probe_tun)) reporting whether TUN is usable on
//!    this host.
//! 3. [`udp`]: a raw local [`UdpTransport`](udp::UdpTransport) with
//!    length-framed datagrams, non-blocking support, and typed errors.
//! 4. [`telemetry_bridge`]: the R2-004 quality-telemetry seam — implements
//!    the telemetry crate's `FrameTransport` for [`UdpTransport`] and
//!    offers [`udp_prober`](telemetry_bridge::udp_prober), the one-call
//!    active RTT prober used by the `probe-rtt` subcommand.
//!
//! ## What this crate is NOT
//!
//! - Not the QUIC/TLS tunnel (R4-001, a later work item that will *consume*
//!   this crate).
//! - Not gateway forwarding (R4-003).
//! - Not a protocol implementation; frames are opaque payload bytes plus a
//!   framing envelope. No protocol semantics are interpreted here.
//!
//! ## Persistence
//!
//! None. This crate is a stateless foundation: sockets and TUN file
//! descriptors are process-local kernel objects and nothing is written to
//! durable storage.
//!
//! ## Async
//!
//! Deliberately synchronous (std only). The async wrapper is R4-001 scope.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod appliance;
pub mod gateway;
pub mod probe;
pub mod telemetry_bridge;
pub mod tun;
pub mod udp;

pub use probe::{probe_tun, TunAvailability};
pub use telemetry_bridge::udp_prober;
pub use tun::{MemoryTunDevice, MemoryTunPair, SystemTunDevice, TunDevice, TunError};
pub use udp::{decode_frame, encode_frame_into, Frame, UdpError, UdpTransport};

/// Crate version, for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
