//! The admission policy parameters — the hard constraints.
//!
//! Three knobs, all plain integers (the canonical CBOR profile forbids
//! floats, and a policy that must be deterministic cannot reason about
//! floats):
//!
//! - `freshness_window_secs` — the accepting node's bound on the AGE of the
//!   ShareNet link evidence: evidence is policy-fresh strictly before
//!   `observed_at_unix + freshness_window_secs` (the exclusive-bound
//!   convention every freshness check in this codebase uses). This is
//!   INDEPENDENT of the observer's own cryptographic window
//!   (`expires_at_unix`): an observer may grant up to
//!   [`sharenet_protocol::EVIDENCE_MAX_WINDOW`] (3600 s), while admission —
//!   a high-stakes decision — may demand much fresher measurements. The
//!   effective bound is the EARLIER of the two.
//! - `loss_ppm_floor` — the maximum acceptable effective link loss ratio in
//!   integer parts-per-million (0..=[`sharenet_protocol::LOSS_RATIO_PPM_MAX`]).
//!   A link passes when its effective loss ratio is `<=` the floor (the
//!   exact floor passes; floor+1 does not).
//! - `latency_bound_ms` — the maximum acceptable link latency in
//!   milliseconds, compared against the evidence's `p95_rtt_micros` (the
//!   tail is what breaks interactive service) after an exact conversion to
//!   microseconds (`* 1000`, saturating).
//!
//! A `freshness_window_secs` of `0` is a valid, deliberately fail-closed
//! policy: no evidence is ever policy-fresh, so nothing ever admits.
//!
//! The ADCOS side's freshness is NOT parameterized here: it is the R5-003
//! store's typed [`sharenet_connectivity::ProjectionFreshness`] (the
//! provider's window, persisted at store creation, never re-anchored — the
//! no-fabrication law). One freshness authority per evidence domain; this
//! crate does not create a second one.

use core::fmt;

use sharenet_protocol::LOSS_RATIO_PPM_MAX;

/// The gateway admission policy's hard constraints.
///
/// Constructed through [`AdmissionParams::new`] (which validates the loss
/// floor against the protocol core's frozen maximum), so a value of this
/// type is always in-range. Immutable and `Copy` — a policy is a fixed set
/// of constraints, not mutable state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdmissionParams {
    freshness_window_secs: u64,
    loss_ppm_floor: u64,
    latency_bound_ms: u64,
}

/// Typed construction failures for [`AdmissionParams`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionParamsError {
    /// The loss-ratio floor exceeds 100% (1,000,000 ppm) — out of the
    /// protocol core's frozen range.
    LossFloorOutOfRange { floor_ppm: u64, max_ppm: u64 },
}

impl AdmissionParamsError {
    /// Stable machine name.
    pub fn name(&self) -> &str {
        match self {
            AdmissionParamsError::LossFloorOutOfRange { .. } => "loss_floor_out_of_range",
        }
    }
}

impl fmt::Display for AdmissionParamsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdmissionParamsError::LossFloorOutOfRange { floor_ppm, max_ppm } => write!(
                f,
                "loss_ppm_floor {floor_ppm} exceeds the frozen maximum {max_ppm}"
            ),
        }
    }
}

impl std::error::Error for AdmissionParamsError {}

impl AdmissionParams {
    /// Build the parameter set, validating the loss floor against the
    /// protocol core's frozen ppm range.
    ///
    /// `freshness_window_secs == 0` and any `latency_bound_ms` are accepted
    /// (documented, deliberately fail-closed / boundless semantics); a loss
    /// floor above 1,000,000 ppm is out of range and refused.
    pub fn new(
        freshness_window_secs: u64,
        loss_ppm_floor: u64,
        latency_bound_ms: u64,
    ) -> Result<Self, AdmissionParamsError> {
        if loss_ppm_floor > LOSS_RATIO_PPM_MAX {
            return Err(AdmissionParamsError::LossFloorOutOfRange {
                floor_ppm: loss_ppm_floor,
                max_ppm: LOSS_RATIO_PPM_MAX,
            });
        }
        Ok(Self {
            freshness_window_secs,
            loss_ppm_floor,
            latency_bound_ms,
        })
    }

    /// The accepting node's bound on ShareNet link evidence age (seconds;
    /// the evidence's `expires_at_unix` may be earlier — the effective
    /// bound is the earlier of the two).
    pub fn freshness_window_secs(&self) -> u64 {
        self.freshness_window_secs
    }

    /// The maximum acceptable effective link loss ratio, in integer ppm.
    pub fn loss_ppm_floor(&self) -> u64 {
        self.loss_ppm_floor
    }

    /// The maximum acceptable link latency, in milliseconds (compared
    /// against the evidence's `p95_rtt_micros` after exact conversion).
    pub fn latency_bound_ms(&self) -> u64 {
        self.latency_bound_ms
    }

    /// The latency bound converted to microseconds (exact; saturating on
    /// bounds beyond ~1.8e16 ms, which are effectively boundless).
    pub(crate) fn latency_bound_micros(&self) -> u64 {
        self.latency_bound_ms.saturating_mul(1_000)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loss_floor_above_one_million_is_refused() {
        for bad in [1_000_001u64, u64::MAX] {
            assert_eq!(
                AdmissionParams::new(600, bad, 50),
                Err(AdmissionParamsError::LossFloorOutOfRange {
                    floor_ppm: bad,
                    max_ppm: LOSS_RATIO_PPM_MAX,
                })
            );
        }
        // The full-range floor (accept any loss) is a legal, if reckless,
        // policy — it does not skip the range check.
        assert!(AdmissionParams::new(600, LOSS_RATIO_PPM_MAX, 50).is_ok());
    }

    #[test]
    fn zero_window_and_any_latency_bound_are_legal_fail_closed_params() {
        // A zero freshness window is the documented admits-nothing policy.
        let params = AdmissionParams::new(0, 0, 0).expect("valid");
        assert_eq!(params.freshness_window_secs(), 0);
        assert_eq!(params.loss_ppm_floor(), 0);
        assert_eq!(params.latency_bound_ms(), 0);
        assert_eq!(params.latency_bound_micros(), 0);
        // ms -> micros is exact where it fits, saturating beyond u64.
        let big = AdmissionParams::new(1, 1, u64::MAX).expect("valid");
        assert_eq!(big.latency_bound_micros(), u64::MAX.saturating_mul(1_000));
        let exact = AdmissionParams::new(1, 1, 1_800_000_000_000_000).expect("valid");
        assert_eq!(exact.latency_bound_micros(), 1_800_000_000_000_000_000);
    }

    #[test]
    fn params_error_machine_name_is_stable() {
        assert_eq!(
            AdmissionParamsError::LossFloorOutOfRange { floor_ppm: 2, max_ppm: 1 }.name(),
            "loss_floor_out_of_range"
        );
    }
}
