//! # sharenet-transport-telemetry
//!
//! ShareNet transport quality telemetry (work item **R2-004**) — the
//! measurement layer over the Wave 1 transports: active RTT probes,
//! throughput sampling, loss estimation, and a typed **LinkQuality**
//! evidence stream. These are the raw measurements the architecture's
//! reliability model (`spec/architecture.md` §2 — "route availability,
//! per-hop health, observed throughput, packet loss and RTT") will consume
//! for routing (R3-003 topology evidence) and gateway admission (R5-005).
//!
//! **Measurement only.** No routing decisions, no policy, no gateway
//! admission logic — those are R3/R5 scope. And per `spec/architecture-lock.md`
//! **L009**: this crate contains no ShareNet protocol semantics (no
//! identity, no link authentication, no routing state, no cryptographic
//! authority). The telemetry types are **transport-internal and are NOT
//! registered wire objects** — they never appear in `spec/protocol-registry.yaml`.
//!
//! ## Layout
//!
//! * [`sample`]: [`LinkQualitySample`](sample::LinkQualitySample) (the raw
//!   evidence unit) and [`LinkQualityStream`](sample::LinkQualityStream)
//!   (bounded, thread-safe, drop-oldest window).
//! * [`stats`]: pure, deterministic sliding-window statistics →
//!   [`LinkQualitySummary`](stats::LinkQualitySummary) (EWMA RTT, MAD
//!   jitter, p50/p95 order statistics, loss ratio, throughput estimate).
//! * [`probe`]: the active prober ([`Prober`](probe::Prober)) driving any
//!   [`FrameTransport`](probe::FrameTransport) with ping/pong correlation
//!   ids, per-attempt timeouts, retries and fixed-cadence pacing.
//! * [`error`]: typed errors ([`TelemetryError`]) — no raw OS errors leak.
//!
//! ## Dependency direction (why the prober is generic)
//!
//! The prober drives the Wave 1 transports through the small
//! [`FrameTransport`](probe::FrameTransport) seam, and the concrete
//! implementation for `sharenet_transport_linux::UdpTransport` lives in the
//! **linux crate** (`telemetry_bridge` module), because cargo forbids the
//! dependency cycle that a concrete-type prober here would require (the
//! linux binary — the production `probe-rtt` caller — must depend on this
//! crate). This crate dev-depends on the linux crate so its TESTS run the
//! prober over the REAL `UdpTransport` (real sockets, real syscalls) — the
//! same dev-cycle shape as serde/serde_json.
//!
//! ## Persistence
//!
//! **None.** Telemetry is in-memory, process-local streaming state by
//! design. Durable evidence capture is R8-001's concern (contribution
//! evidence), explicitly not the measurement layer's.

#![forbid(unsafe_op_in_unsafe_fn)]

pub mod error;
pub mod probe;
pub mod sample;
pub mod stats;

pub use error::{Result, TelemetryError};
pub use probe::{
    decode_probe, encode_ping, encode_pong, ProbeConfig, ProbeDecode, ProbeFrame, ProbeRun, Prober,
    FrameTransport, DEFAULT_PROBE_INTERVAL, DEFAULT_PROBE_PAYLOAD_BYTES, DEFAULT_PROBE_RETRIES,
    DEFAULT_PROBE_TIMEOUT, PROBE_HEADER_LEN, PROBE_KIND_PING, PROBE_KIND_PONG, PROBE_MAGIC,
};
pub use sample::{LinkQualitySample, LinkQualityStream, SharedLinkQualityStream};
pub use stats::{
    summarize, summarize_with_alpha, LinkQualitySummary, DEFAULT_EWMA_ALPHA,
};

/// Crate version, for diagnostics.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
