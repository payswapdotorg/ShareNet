//! The Android bridge — R10-002, the Rust side of the VpnService's
//! [`TunnelBackhaul`] seam.
//!
//! R4-004 froze the seam deliberately: "the production implementation
//! is a JNI bridge to the Rust tunnel … which requires the NDK —
//! deliberately absent from this wave's build". This crate IS that
//! bridge: a [`GatewayClient`] participant session (pinned QUIC tunnel
//! + R4-002 circuit admission + the R4-003 data plane — the exact
//! session the R10-001 two-process loopback proved) exposed behind a
//! JNI surface the Kotlin `JniTunnelBackhaul` binds to.
//!
//! # Layers
//!
//! 1. [`bridge::BridgeSession`] — the pure-Rust core: open
//!    (identity seed + gateway addr + pinned gateway node id +
//!    bounded idle timeout), `forward(packet) -> Vec<Vec<u8>>`
//!    (send_packet + recv_response per the uplink's request/response
//!    semantics), `destroy(reason)`. Host-testable: the tests drive a
//!    REAL in-process `GatewayServer` with a real loopback uplink —
//!    no protocol fakes.
//! 2. [`jni_surface`] — the thin JNI binding (org.sharenet.transport.
//!    vpn.BridgeNative): byte-array in, byte-array-array out, errors
//!    mapped to a typed Java exception (fail closed — a half-dead VPN
//!    that silently swallows traffic is worse than a visible dead
//!    one, the seam's own law).
//!
//! # The honest scope
//!
//! The cdylib compiles on the host and the core is verified against
//! the real stack; the ON-DEVICE leg (NDK cross-build, install,
//! ACTION_START with the session extras, a real network's packets
//! crossing a real phone's TUN) is the operator runbook recorded in
//! `transport/android/vpn/README.md` — this build sandbox has no
//! Android NDK and no physical device, and the wave record says so.

pub mod bridge;
pub mod jni_surface;

pub use bridge::{BridgeError, BridgeSession, BRIDGE_API_VERSION};
