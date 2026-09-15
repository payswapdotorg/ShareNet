//! Typed errors for the transport quality telemetry layer (R2-004).
//!
//! Every failure mode of this crate names itself; no raw OS or foreign error
//! types leak. `Display` is human-readable, `source` chains where a source
//! exists (this crate is std-only, so sources are descriptions, not wrapped
//! errors — the bridge in `sharenet-transport-linux` classifies transport
//! errors BEFORE they cross into this crate).

use std::fmt;

/// Typed telemetry error.
#[derive(Debug)]
pub enum TelemetryError {
    // ---- stream errors -----------------------------------------------------
    /// [`LinkQualityStream`](crate::sample::LinkQualityStream) was constructed
    /// with capacity 0. A window must hold at least one sample.
    ZeroCapacity,
    /// The sample window is empty — no summary can be computed.
    ///
    /// Documented policy: empty input is a *typed error*, not a
    /// default-valued summary. A caller that has never measured anything must
    /// not be handed a plausible-looking zero summary.
    EmptyWindow,
    // ---- stats errors ------------------------------------------------------
    /// A delivered sample carries `rtt_micros == 0` — evidence of clock skew
    /// (a pong timestamped at or before its ping). The offending sample is
    /// named; the summary is refused. Samples are never silently clamped.
    ClockSkew { seq: u64 },
    /// EWMA alpha outside the legal range `(0.0, 1.0]`.
    InvalidAlpha { alpha: f64 },
    // ---- probe errors ------------------------------------------------------
    /// The probe configuration is unusable (zero probes, payload smaller than
    /// the probe header, payload larger than the transport allows, zero
    /// timeout, ...). `detail` names the exact problem.
    InvalidConfig { detail: String },
    /// Sending a probe frame failed. The run aborts: without a working send
    /// path there is nothing to measure.
    SendFailed { peer: String, detail: String },
    /// Receiving failed in a way that is not a timeout and not a closed
    /// transport. The prober counts these and keeps waiting until the probe
    /// deadline; this error surfaces only from callers misusing the transport
    /// directly (the prober converts receive failures into counters).
    RecvFailed { detail: String },
    /// Setting the receive timeout failed.
    TimeoutSetup { detail: String },
    /// The transport was closed underneath the prober. The run aborts.
    TransportClosed,
    /// No frame is available now (non-blocking mode or read-timeout
    /// expiry — the Wave 1 `UdpTransport` reports both as `EAGAIN`). The
    /// prober treats this as "nothing yet" and re-checks its own deadline;
    /// it never escapes a run as an error.
    TransportWouldBlock,
    /// The prober is being reused after a completed run (a `Prober` runs once).
    ProberFinished,
}

impl fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TelemetryError::ZeroCapacity => write!(f, "link quality stream capacity must be > 0"),
            TelemetryError::EmptyWindow => {
                write!(f, "sample window is empty: no link quality summary exists")
            }
            TelemetryError::ClockSkew { seq } => write!(
                f,
                "clock skew evidence: delivered sample seq={seq} has rtt_micros=0 (pong at or before ping); refusing summary"
            ),
            TelemetryError::InvalidAlpha { alpha } => {
                write!(f, "ewma alpha must be in (0.0, 1.0], got {alpha}")
            }
            TelemetryError::InvalidConfig { detail } => write!(f, "invalid probe config: {detail}"),
            TelemetryError::SendFailed { peer, detail } => {
                write!(f, "probe send to {peer} failed: {detail}")
            }
            TelemetryError::RecvFailed { detail } => write!(f, "probe receive failed: {detail}"),
            TelemetryError::TimeoutSetup { detail } => {
                write!(f, "setting receive timeout failed: {detail}")
            }
            TelemetryError::TransportClosed => write!(f, "transport closed under the prober"),
            TelemetryError::TransportWouldBlock => {
                write!(f, "no frame available now (non-blocking or read timeout elapsed)")
            }
            TelemetryError::ProberFinished => {
                write!(f, "prober already ran; construct a new prober for another run")
            }
        }
    }
}

impl std::error::Error for TelemetryError {}

/// Convenience alias used across the crate.
pub type Result<T> = std::result::Result<T, TelemetryError>;
