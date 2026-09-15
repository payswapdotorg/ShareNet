//! The typed admission decision — the policy's output.
//!
//! [`GatewayAdmission::Eligible`] carries the evidence anchors (what exactly
//! was admitted, for gateway selection and audit); `Ineligible` carries a
//! deterministic, ordered list of typed reasons. There is no boolean and no
//! partial state: eligibility is the conjunction of two independently
//! verified factors, and any failure anywhere is fail-closed.
//!
//! ## Reason evaluation order (deterministic)
//!
//! Reasons are pushed in a fixed order so the same evidence snapshot always
//! produces the same decision:
//!
//! 1. ShareNet-side link evidence: missing → unverified → not-a-link →
//!    wrong-subject → not-yet-valid → stale (one reason at most — the chain
//!    stops at the first failure, because later checks depend on earlier
//!    ones);
//! 2. ADCOS-side backhaul evidence: missing → unverified →
//!    sequence-collision → projection-log-unverified (one per uncovered
//!    log entry, in acceptance order) → projection-lags → not-active →
//!    stale (these accumulate — they are independent);
//! 3. The quality floor and the latency bound (only over an otherwise
//!    admitted link's quality snapshot; both accumulate).

use core::fmt;

use sharenet_connectivity::ContractState;
use sharenet_connectivity::ConnectivityContractRef;

/// The ShareNet-side evidence anchor of an eligible decision: exactly what
/// was admitted, derived from the VERIFIED link evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareNetEvidenceAnchor {
    /// The authenticated link's id (from the signed observation).
    pub link_id: [u8; 32],
    /// The observer's derived node id — who attested the link.
    pub observer_node_id: [u8; 32],
    /// When the observer observed the link.
    pub observed_at_unix: u64,
    /// The observer's own cryptographic expiry (`expires_at_unix`).
    pub expires_at_unix: u64,
    /// The effective loss ratio the decision rests on: the worse of the
    /// snapshot's stated `loss_ratio_ppm` and the ppm derived from the
    /// signed `delivered`/`lost` counters (see the policy's ppm math).
    pub loss_ratio_ppm_effective: u64,
    /// The observed `p95_rtt_micros` the decision rests on.
    pub p95_rtt_micros: u64,
    /// Until when (exclusive) the ShareNet-side evidence is acceptable: the
    /// EARLIER of the observer's `expires_at_unix` and the policy's
    /// freshness bound (`observed_at_unix + freshness_window_secs`).
    pub fresh_until_unix: u64,
}

/// The ADCOS-side evidence anchor of an eligible decision: exactly what the
/// durable projection said, bound to the signature-verified evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdcosEvidenceAnchor {
    /// The gateway's backhaul contract (opaque, ADCOS-owned).
    pub contract: ConnectivityContractRef,
    /// The projected contract lifecycle state (always `Active` for an
    /// eligible decision — re-derived from the verified log).
    pub state: ContractState,
    /// The store's ORIGINAL freshness bound for the last accepted
    /// observation (the provider's window, never re-anchored).
    pub fresh_until_unix: u64,
    /// When the provider observed the last accepted observation.
    pub last_observed_at_unix: u64,
    /// The last accepted observation's per-provider sequence.
    pub last_sequence: u64,
    /// The derived node id of the provider whose signature-verified
    /// observation is the projection's tail (the freshness anchor).
    pub provider_node_id: [u8; 32],
}

/// The gateway admission decision. `Eligible` is the typed INPUT to gateway
/// selection — it grants no packet-delivery and no provider-fulfillment
/// attestation (adcos.md: "ADCOS does not attest ShareNet packet delivery.
/// ShareNet does not attest provider fulfillment.").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayAdmission {
    /// Both factors verified, fresh and within the quality floor at the
    /// decision's `now_unix`.
    Eligible {
        /// The gateway this decision is about.
        gateway_node_id: [u8; 32],
        /// The verified ShareNet-side link evidence anchor.
        sharenet: ShareNetEvidenceAnchor,
        /// The verified ADCOS-side backhaul evidence anchor.
        adcos: AdcosEvidenceAnchor,
        /// Until when (exclusive) this decision's evidence holds: the
        /// earlier of the two anchors' freshness bounds.
        valid_until_unix: u64,
    },
    /// Fail-closed: at least one typed reason. Either side missing, stale
    /// or unverified lands here — never a default-allow.
    Ineligible {
        /// The deterministic, ordered, typed reasons (see the module docs
        /// for the fixed evaluation order).
        reasons: Vec<AdmissionReason>,
    },
}

impl GatewayAdmission {
    /// Whether this is an `Eligible` decision (a derived accessor over the
    /// typed verdict — not a trust input).
    pub fn is_eligible(&self) -> bool {
        matches!(self, GatewayAdmission::Eligible { .. })
    }

    /// The typed reasons of an `Ineligible` decision (empty for `Eligible`).
    pub fn reasons(&self) -> &[AdmissionReason] {
        match self {
            GatewayAdmission::Eligible { .. } => &[],
            GatewayAdmission::Ineligible { reasons } => reasons,
        }
    }
}

impl fmt::Display for GatewayAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatewayAdmission::Eligible {
                gateway_node_id,
                sharenet,
                adcos,
                valid_until_unix,
            } => write!(
                f,
                "gateway {} admitted until {} (link observed {} by {}, loss {} ppm, p95 {} us; contract {}, active, fresh until {})",
                hex(gateway_node_id),
                valid_until_unix,
                sharenet.observed_at_unix,
                hex(&sharenet.observer_node_id),
                sharenet.loss_ratio_ppm_effective,
                sharenet.p95_rtt_micros,
                adcos.contract.to_hex(),
                adcos.fresh_until_unix,
            ),
            GatewayAdmission::Ineligible { reasons } => {
                write!(f, "gateway refused:")?;
                for reason in reasons {
                    write!(f, " [{reason}]")?;
                }
                Ok(())
            }
        }
    }
}

/// A typed machine-named reason a gateway was refused admission. The
/// variant names are the vocabulary; [`AdmissionReason::as_str`] is the
/// stable machine name (the same discipline as the protocol core's typed
/// errors — grep-able, assert-able, never a boolean).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionReason {
    /// No ShareNet link evidence was supplied for the gateway.
    ShareNetEvidenceMissing,
    /// The supplied ShareNet evidence failed strict parsing or Ed25519
    /// signature verification (`cause` is the typed failure's machine name).
    ShareNetEvidenceUnverified { cause: String },
    /// The evidence is a verified advertisement observation — not link
    /// evidence, so it carries no quality snapshot to admit on.
    ShareNetEvidenceNotALink,
    /// The evidence attests a link about a DIFFERENT node than the gateway
    /// under evaluation (the binding rule — evidence never transfers).
    ShareNetEvidenceWrongSubject {
        subject_node_id: [u8; 32],
        gateway_node_id: [u8; 32],
    },
    /// The evidence was observed in the future relative to the decision
    /// clock (a clock-skew or replay probe; never admissible).
    ShareNetEvidenceNotYetValid {
        now_unix: u64,
        observed_at_unix: u64,
    },
    /// The evidence's freshness bound has passed. The effective bound is
    /// the EARLIER of the observer's cryptographic expiry
    /// (`expires_at_unix`) and the policy's window bound
    /// (`observed_at_unix + freshness_window_secs`, reported as
    /// `policy_bound_unix`); both are carried for honest reporting.
    ShareNetEvidenceStale {
        now_unix: u64,
        expires_at_unix: u64,
        policy_bound_unix: u64,
    },
    /// No ADCOS backhaul evidence was supplied, or the contract is not
    /// tracked / has never been observed (a registered-but-unobserved
    /// contract is no evidence).
    AdcosEvidenceMissing,
    /// A supplied signed connectivity observation failed strict parsing or
    /// Ed25519 signature verification (`cause` is the typed failure's
    /// machine name). One broken member poisons the set — fail-closed.
    AdcosEvidenceUnverified { cause: String },
    /// The verified evidence contains two DIFFERENT claims (differing kind
    /// or `observed_at_unix`) from the same provider at the same
    /// per-(provider, contract) sequence — contradictory signed statements.
    /// An identical redelivery of the same observation is NOT this (it is
    /// the expected provider behavior); a mutated same-sequence claim is.
    AdcosEvidenceSequenceCollision {
        provider_node_id: [u8; 32],
        sequence: u64,
    },
    /// The durable projection's accepted log contains an entry (by
    /// sequence) that no signature-verified observation in the supplied
    /// evidence covers — the projection was NOT fed through the verified
    /// path (the R5-004 trust boundary, derived rather than trusted).
    AdcosProjectionLogUnverified { sequence: u64 },
    /// The supplied verified evidence is AHEAD of the durable projection:
    /// the latest verified sequence exceeds the projection's tail. The
    /// decision snapshot is self-inconsistent (evidence the caller holds
    /// but did not project) — feed the store first, then decide.
    AdcosProjectionLagsEvidence {
        verified_sequence: u64,
        projection_sequence: u64,
    },
    /// The projected contract lifecycle is not `Active` (`Projected` —
    /// never activated; `Degraded` — the provider reported degradation and
    /// the frozen event mapping has no recovery transition; `Terminated`).
    AdcosContractNotActive { state: ContractState },
    /// The R5-003 store's typed freshness verdict for the projection is
    /// `Stale` at the decision clock — the last accepted observation's
    /// ORIGINAL (never re-anchored) freshness bound has passed.
    ProjectionStale {
        fresh_until_unix: u64,
        last_observed_at_unix: u64,
    },
    /// The admitted link's effective loss ratio exceeded the policy's
    /// floor (the quality fell below the floor).
    QualityBelowFloor { loss_ppm: u64, floor_ppm: u64 },
    /// The admitted link's `p95_rtt_micros` exceeded the policy's latency
    /// bound (exact microseconds: `latency_bound_ms * 1000`, saturating).
    LatencyAboveBound {
        p95_rtt_micros: u64,
        bound_micros: u64,
    },
}

impl AdmissionReason {
    /// The stable machine name (vocabulary for logs, metrics and tests).
    pub fn as_str(&self) -> &'static str {
        match self {
            AdmissionReason::ShareNetEvidenceMissing => "sharenet_evidence_missing",
            AdmissionReason::ShareNetEvidenceUnverified { .. } => "sharenet_evidence_unverified",
            AdmissionReason::ShareNetEvidenceNotALink => "sharenet_evidence_not_a_link",
            AdmissionReason::ShareNetEvidenceWrongSubject { .. } => {
                "sharenet_evidence_wrong_subject"
            }
            AdmissionReason::ShareNetEvidenceNotYetValid { .. } => {
                "sharenet_evidence_not_yet_valid"
            }
            AdmissionReason::ShareNetEvidenceStale { .. } => "sharenet_evidence_stale",
            AdmissionReason::AdcosEvidenceMissing => "adcos_evidence_missing",
            AdmissionReason::AdcosEvidenceUnverified { .. } => "adcos_evidence_unverified",
            AdmissionReason::AdcosEvidenceSequenceCollision { .. } => {
                "adcos_evidence_sequence_collision"
            }
            AdmissionReason::AdcosProjectionLogUnverified { .. } => {
                "adcos_projection_log_unverified"
            }
            AdmissionReason::AdcosProjectionLagsEvidence { .. } => {
                "adcos_projection_lags_evidence"
            }
            AdmissionReason::AdcosContractNotActive { .. } => "adcos_contract_not_active",
            AdmissionReason::ProjectionStale { .. } => "projection_stale",
            AdmissionReason::QualityBelowFloor { .. } => "quality_below_floor",
            AdmissionReason::LatencyAboveBound { .. } => "latency_above_bound",
        }
    }
}

impl fmt::Display for AdmissionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AdmissionReason::ShareNetEvidenceMissing => {
                write!(f, "no ShareNet link evidence supplied")
            }
            AdmissionReason::ShareNetEvidenceUnverified { cause } => {
                write!(f, "ShareNet evidence failed verification ({cause})")
            }
            AdmissionReason::ShareNetEvidenceNotALink => {
                write!(f, "ShareNet evidence is not a link observation")
            }
            AdmissionReason::ShareNetEvidenceWrongSubject {
                subject_node_id,
                gateway_node_id,
            } => write!(
                f,
                "evidence is about node {}, not the gateway {}",
                hex(subject_node_id),
                hex(gateway_node_id)
            ),
            AdmissionReason::ShareNetEvidenceNotYetValid {
                now_unix,
                observed_at_unix,
            } => write!(
                f,
                "evidence observed at {observed_at_unix} is in the future at {now_unix}"
            ),
            AdmissionReason::ShareNetEvidenceStale {
                now_unix,
                expires_at_unix,
                policy_bound_unix,
            } => write!(
                f,
                "ShareNet evidence stale at {now_unix} (expires {expires_at_unix}, policy bound {policy_bound_unix})"
            ),
            AdmissionReason::AdcosEvidenceMissing => {
                write!(f, "no ADCOS-backed connectivity evidence")
            }
            AdmissionReason::AdcosEvidenceUnverified { cause } => {
                write!(f, "ADCOS evidence failed verification ({cause})")
            }
            AdmissionReason::AdcosEvidenceSequenceCollision {
                provider_node_id,
                sequence,
            } => write!(
                f,
                "provider {} signed contradictory observations at sequence {sequence}",
                hex(provider_node_id)
            ),
            AdmissionReason::AdcosProjectionLogUnverified { sequence } => write!(
                f,
                "projection log entry {sequence} is not covered by verified evidence"
            ),
            AdmissionReason::AdcosProjectionLagsEvidence {
                verified_sequence,
                projection_sequence,
            } => write!(
                f,
                "verified evidence is at sequence {verified_sequence} but the projection is at {projection_sequence}"
            ),
            AdmissionReason::AdcosContractNotActive { state } => {
                write!(f, "projected contract state is {}", state.as_str())
            }
            AdmissionReason::ProjectionStale {
                fresh_until_unix,
                last_observed_at_unix,
            } => write!(
                f,
                "projection stale (fresh until {fresh_until_unix}, last observed {last_observed_at_unix})"
            ),
            AdmissionReason::QualityBelowFloor { loss_ppm, floor_ppm } => write!(
                f,
                "link loss {loss_ppm} ppm exceeds the floor {floor_ppm} ppm"
            ),
            AdmissionReason::LatencyAboveBound {
                p95_rtt_micros,
                bound_micros,
            } => write!(
                f,
                "link p95 RTT {p95_rtt_micros} us exceeds the bound {bound_micros} us"
            ),
        }
    }
}

/// Lowercase hex (private debug helper; same shape the protocol core uses).
fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reason_machine_names_are_stable() {
        // The full vocabulary — grep-able and frozen.
        let all: Vec<(&'static str, AdmissionReason)> = vec![
            (
                "sharenet_evidence_missing",
                AdmissionReason::ShareNetEvidenceMissing,
            ),
            (
                "sharenet_evidence_unverified",
                AdmissionReason::ShareNetEvidenceUnverified { cause: "x".into() },
            ),
            (
                "sharenet_evidence_not_a_link",
                AdmissionReason::ShareNetEvidenceNotALink,
            ),
            (
                "sharenet_evidence_wrong_subject",
                AdmissionReason::ShareNetEvidenceWrongSubject {
                    subject_node_id: [0; 32],
                    gateway_node_id: [1; 32],
                },
            ),
            (
                "sharenet_evidence_not_yet_valid",
                AdmissionReason::ShareNetEvidenceNotYetValid { now_unix: 0, observed_at_unix: 1 },
            ),
            (
                "sharenet_evidence_stale",
                AdmissionReason::ShareNetEvidenceStale {
                    now_unix: 0,
                    expires_at_unix: 0,
                    policy_bound_unix: 0,
                },
            ),
            (
                "adcos_evidence_missing",
                AdmissionReason::AdcosEvidenceMissing,
            ),
            (
                "adcos_evidence_unverified",
                AdmissionReason::AdcosEvidenceUnverified { cause: "y".into() },
            ),
            (
                "adcos_evidence_sequence_collision",
                AdmissionReason::AdcosEvidenceSequenceCollision {
                    provider_node_id: [2; 32],
                    sequence: 7,
                },
            ),
            (
                "adcos_projection_log_unverified",
                AdmissionReason::AdcosProjectionLogUnverified { sequence: 3 },
            ),
            (
                "adcos_projection_lags_evidence",
                AdmissionReason::AdcosProjectionLagsEvidence {
                    verified_sequence: 5,
                    projection_sequence: 4,
                },
            ),
            (
                "adcos_contract_not_active",
                AdmissionReason::AdcosContractNotActive {
                    state: ContractState::Terminated,
                },
            ),
            (
                "projection_stale",
                AdmissionReason::ProjectionStale {
                    fresh_until_unix: 9,
                    last_observed_at_unix: 8,
                },
            ),
            (
                "quality_below_floor",
                AdmissionReason::QualityBelowFloor { loss_ppm: 1, floor_ppm: 0 },
            ),
            (
                "latency_above_bound",
                AdmissionReason::LatencyAboveBound {
                    p95_rtt_micros: 2,
                    bound_micros: 1,
                },
            ),
        ];
        for (name, reason) in &all {
            assert_eq!(reason.as_str(), *name);
            assert!(!reason.to_string().is_empty(), "{name} has no Display");
        }
        // The vocabulary is unique (no two variants share a machine name).
        let mut names: Vec<&str> = all.iter().map(|(n, _)| *n).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), all.len());
    }

    #[test]
    fn decision_accessors() {
        let ineligible = GatewayAdmission::Ineligible {
            reasons: vec![AdmissionReason::ShareNetEvidenceMissing],
        };
        assert!(!ineligible.is_eligible());
        assert_eq!(ineligible.reasons().len(), 1);
        let eligible = GatewayAdmission::Eligible {
            gateway_node_id: [9; 32],
            sharenet: ShareNetEvidenceAnchor {
                link_id: [1; 32],
                observer_node_id: [2; 32],
                observed_at_unix: 10,
                expires_at_unix: 20,
                loss_ratio_ppm_effective: 0,
                p95_rtt_micros: 0,
                fresh_until_unix: 20,
            },
            adcos: AdcosEvidenceAnchor {
                contract: ConnectivityContractRef::from_id([3; 32]),
                state: ContractState::Active,
                fresh_until_unix: 30,
                last_observed_at_unix: 10,
                last_sequence: 1,
                provider_node_id: [4; 32],
            },
            valid_until_unix: 20,
        };
        assert!(eligible.is_eligible());
        assert!(eligible.reasons().is_empty());
        assert!(eligible.to_string().contains("admitted"));
        assert!(ineligible.to_string().contains("refused"));
    }
}
