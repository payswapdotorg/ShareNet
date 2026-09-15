//! The gateway admission policy engine (R5-005).
//!
//! [`GatewayAdmissionPolicy::decide`] is the pure decision function: it
//! re-derives every security-critical fact from the supplied evidence and
//! never trusts a caller assertion (AGENTS.md: "Never accept
//! caller-controlled security booleans when the fact can be derived").
//!
//! ## ShareNet-side verification (factor 1)
//!
//! Exactly the [`sharenet_protocol::TopologyStore::receive`] steps minus
//! collection, in the same order: strict parse → Ed25519 verification
//! against the embedded observer identity → link kind → subject binding
//! (the evidence must be ABOUT the gateway node) → temporal window. On
//! top of the protocol core's own invariants, the policy applies its
//! freshness window: the effective bound is the EARLIER of the observer's
//! `expires_at_unix` and `observed_at_unix + freshness_window_secs`.
//!
//! ## ADCOS-side verification (factor 2)
//!
//! The R5-003 projection is consumed through its typed surface
//! (`ContractHealth` + `ProjectionFreshness`), and the R5-004 trust
//! boundary is DERIVED rather than trusted:
//!
//! 1. every supplied signed observation is parsed and Ed25519-verified
//!    (one bad signature poisons the set);
//! 2. the verified observations for THIS contract must carry unique
//!    `(provider, sequence)` pairs — a provider that signed two different
//!    observations at the same sequence has signed a contradiction;
//! 3. every entry of the projection's accepted log must be covered by a
//!    verified observation (same kind, `observed_at_unix` and sequence for
//!    this contract) — a store fed off the verified path cannot admit;
//! 4. the verified evidence must not be AHEAD of the projection (the
//!    snapshot must be self-consistent — feed the store, then decide);
//! 5. the projected state must be `Active` and the store's typed
//!    freshness at the decision clock must be `Fresh`.
//!
//! ## The quality floor (integer ppm math)
//!
//! The link's effective loss ratio is the WORSE of the snapshot's signed
//! `loss_ratio_ppm` and the ratio derived from its signed counters,
//! `lost * 1_000_000 / (delivered + lost)` in exact integer arithmetic
//! (u128 intermediates; no floats, no overflow). An observer whose stated
//! ratio disagrees with its own counters is evaluated on the counters —
//! an internally inconsistent snapshot never admits. Latency is compared
//! in exact microseconds: `p95_rtt_micros` vs `latency_bound_ms * 1000`
//! (saturating).

use sharenet_connectivity::{ContractState, ProjectionFreshness};
use sharenet_protocol::{
    ConnectivityObservationStatement, LinkQualitySnapshot, Observation, SignedTopologyEvidence,
    TopologyError,
};

use crate::decision::{
    AdmissionReason, AdcosEvidenceAnchor, GatewayAdmission, ShareNetEvidenceAnchor,
};
use crate::evidence::{AdcosBackhaulEvidence, GatewayAdmissionRequest};
use crate::params::AdmissionParams;

/// The gateway admission/backhaul policy: an immutable parameter set plus
/// the pure decision function.
///
/// Deterministic for a fixed evidence snapshot (architecture §2): no wall
/// clock (the caller supplies `now_unix`), no I/O, no hash-map iteration
/// order in any output — the same `(params, request)` always yields the
/// same [`GatewayAdmission`]. Hard constraints are never overridden:
/// there is no optimizer here to override them.
#[derive(Debug, Clone)]
pub struct GatewayAdmissionPolicy {
    params: AdmissionParams,
}

impl GatewayAdmissionPolicy {
    /// A policy applying the given hard constraints.
    pub fn new(params: AdmissionParams) -> Self {
        Self { params }
    }

    /// The policy's hard constraints.
    pub fn params(&self) -> &AdmissionParams {
        &self.params
    }

    /// Decide gateway admission for one fixed evidence snapshot.
    ///
    /// Both factors are REQUIRED: `Eligible` needs a verified, fresh,
    /// in-floor ShareNet link evidence about the gateway AND a verified,
    /// active, fresh ADCOS-backed projection covered by signature-verified
    /// observations. Anything else is `Ineligible` with the typed,
    /// ordered reasons — fail-closed, never a default-allow.
    pub fn decide(&self, request: GatewayAdmissionRequest<'_>) -> GatewayAdmission {
        let mut reasons: Vec<AdmissionReason> = Vec::new();

        // ---- Factor 1: ShareNet-side link evidence (chain: one reason) --
        let mut sharenet: Option<ShareNetEvidenceAnchor> = None;
        match request.sharenet_link {
            None => reasons.push(AdmissionReason::ShareNetEvidenceMissing),
            Some(signed) => match verify_sharenet_link(
                signed,
                &request.gateway_node_id,
                request.now_unix,
                self.params.freshness_window_secs(),
            ) {
                Ok(anchor) => sharenet = Some(anchor),
                Err(reason) => reasons.push(reason),
            },
        }

        // ---- Factor 2: ADCOS-backed external connectivity (accumulates) --
        let mut adcos: Option<AdcosEvidenceAnchor> = None;
        match request.adcos_backhaul {
            None => reasons.push(AdmissionReason::AdcosEvidenceMissing),
            Some(backhaul) => match verify_adcos_backhaul(&backhaul, request.now_unix) {
                Ok(anchor) => adcos = Some(anchor),
                Err(mut found) => reasons.append(&mut found),
            },
        }

        // ---- The quality floor + latency bound (over the admitted link) --
        if let Some(anchor) = &sharenet {
            if anchor.loss_ratio_ppm_effective > self.params.loss_ppm_floor() {
                reasons.push(AdmissionReason::QualityBelowFloor {
                    loss_ppm: anchor.loss_ratio_ppm_effective,
                    floor_ppm: self.params.loss_ppm_floor(),
                });
            }
            let bound_micros = self.params.latency_bound_micros();
            if anchor.p95_rtt_micros > bound_micros {
                reasons.push(AdmissionReason::LatencyAboveBound {
                    p95_rtt_micros: anchor.p95_rtt_micros,
                    bound_micros,
                });
            }
        }

        if reasons.is_empty() {
            // Both factors verified — the anchors are present by
            // construction (each is Some exactly when its checks passed).
            let sharenet = sharenet
                .expect("no reasons implies the ShareNet anchor was built");
            let adcos = adcos.expect("no reasons implies the ADCOS anchor was built");
            GatewayAdmission::Eligible {
                gateway_node_id: request.gateway_node_id,
                sharenet,
                adcos,
                valid_until_unix: sharenet.fresh_until_unix.min(adcos.fresh_until_unix),
            }
        } else {
            GatewayAdmission::Ineligible { reasons }
        }
    }
}

// ---------------------------------------------------------------------------
// Factor 1: the ShareNet-side link evidence
// ---------------------------------------------------------------------------

/// Verify one signed link evidence about the gateway: the exact
/// `TopologyStore::receive` steps (parse → signature → temporal) plus the
/// link-kind, subject-binding and policy-window checks. Returns the
/// evidence anchor on success, or the single typed reason the chain
/// failed at (later checks depend on earlier ones, so the chain stops).
fn verify_sharenet_link(
    signed: &SignedTopologyEvidence,
    gateway_node_id: &[u8; 32],
    now_unix: u64,
    freshness_window_secs: u64,
) -> Result<ShareNetEvidenceAnchor, AdmissionReason> {
    // 1. strict parse of the signed bytes.
    let evidence = signed.evidence().map_err(sharenet_unverified)?;
    // 2. Ed25519 verification against the embedded observer identity
    //    (self-certifying: the key is inside the signed bytes).
    evidence
        .observer_identity()
        .verify_detached(signed.evidence_bytes(), signed.signature())
        .map_err(|_| {
            sharenet_unverified(TopologyError::SignatureInvalid)
        })?;
    // 3. link evidence only — an advertisement observation carries no
    //    quality snapshot to admit a gateway on.
    let (link_id, quality) = match evidence.observation() {
        Observation::Link { link_id, quality, .. } => (*link_id, quality),
        Observation::Advertisement { .. } => {
            return Err(AdmissionReason::ShareNetEvidenceNotALink)
        }
    };
    // 4. binding: the evidence must be ABOUT the gateway under review —
    //    evidence about a different node never transfers.
    if evidence.subject_node_id() != gateway_node_id {
        return Err(AdmissionReason::ShareNetEvidenceWrongSubject {
            subject_node_id: *evidence.subject_node_id(),
            gateway_node_id: *gateway_node_id,
        });
    }
    // 5. temporal window: not from the future...
    let observed_at = evidence.observed_at_unix();
    if now_unix < observed_at {
        return Err(AdmissionReason::ShareNetEvidenceNotYetValid {
            now_unix,
            observed_at_unix: observed_at,
        });
    }
    // ...and fresh strictly before the EARLIER of the observer's
    // cryptographic expiry and the policy's freshness window bound.
    let policy_bound = observed_at.saturating_add(freshness_window_secs);
    let expires_at = evidence.expires_at_unix();
    let fresh_until = expires_at.min(policy_bound);
    if now_unix >= fresh_until {
        return Err(AdmissionReason::ShareNetEvidenceStale {
            now_unix,
            expires_at_unix: expires_at,
            policy_bound_unix: policy_bound,
        });
    }
    Ok(ShareNetEvidenceAnchor {
        link_id,
        observer_node_id: *evidence.observer_node_id().as_bytes(),
        observed_at_unix: observed_at,
        expires_at_unix: expires_at,
        loss_ratio_ppm_effective: effective_loss_ppm(quality),
        p95_rtt_micros: quality.p95_rtt_micros,
        fresh_until_unix: fresh_until,
    })
}

/// Map a typed topology failure onto the unverified reason (machine name
/// carried verbatim — the caller can distinguish a parse failure from a
/// signature failure without string matching).
fn sharenet_unverified(error: TopologyError) -> AdmissionReason {
    AdmissionReason::ShareNetEvidenceUnverified { cause: error.name() }
}

// ---------------------------------------------------------------------------
// Factor 2: the ADCOS-backed backhaul evidence
// ---------------------------------------------------------------------------

/// Verify the ADCOS-side bundle and derive the anchor. Accumulates the
/// independent typed reasons (see the module docs for the order).
fn verify_adcos_backhaul(
    backhaul: &AdcosBackhaulEvidence<'_>,
    now_unix: u64,
) -> Result<AdcosEvidenceAnchor, Vec<AdmissionReason>> {
    let mut reasons: Vec<AdmissionReason> = Vec::new();

    // No tracked projection = no ADCOS-backed evidence. A contract that
    // was never observed (registered only, or `NoObservation` freshness)
    // is equally evidenceless.
    let Some(health) = backhaul.health else {
        return Err(vec![AdmissionReason::AdcosEvidenceMissing]);
    };
    if health.observations().is_empty() {
        return Err(vec![AdmissionReason::AdcosEvidenceMissing]);
    }
    let contract_id = *health.contract().id();

    // 1. verify every supplied signed observation; keep the ones for THIS
    //    contract (a caller's bundle may hold other contracts — those are
    //    not evidence here). One broken signature anywhere poisons the
    //    set: fail-closed.
    let mut verified: Vec<ConnectivityObservationStatement> = Vec::new();
    for signed in backhaul.signed_observations {
        let statement = signed.verify().map_err(|e| {
            vec![AdmissionReason::AdcosEvidenceUnverified { cause: e.name() }]
        })?;
        if *statement.contract_ref() == contract_id {
            verified.push(statement);
        }
    }

    // 2. (provider, sequence) consistency within the verified evidence for
    //    this contract: the same (provider, sequence) may legitimately
    //    appear twice (a provider redelivery returns the identical signed
    //    observation), but two DIFFERENT claims — differing kind or
    //    observed_at — at the same (provider, sequence) are contradictory
    //    signed statements and never admissible. (The R5-004 sequence gate
    //    at accept time sees only one of them; the policy sees the whole
    //    set the caller holds, and refuses the contradiction.)
    let mut first_claim: Vec<(([u8; 32], u64), (&'static str, u64))> = Vec::new();
    let mut collisions: Vec<([u8; 32], u64)> = Vec::new();
    for statement in &verified {
        let key = (*statement.provider_node_id().as_bytes(), statement.sequence());
        let claim = (statement.kind().as_str(), statement.observed_at_unix());
        match first_claim.iter().find(|(k, _)| *k == key) {
            Some((_, first)) if *first != claim => {
                if !collisions.contains(&key) {
                    collisions.push(key);
                }
            }
            Some(_) => {} // the identical redelivery — fine
            None => first_claim.push((key, claim)),
        }
    }
    for (provider_node_id, sequence) in collisions {
        reasons.push(AdmissionReason::AdcosEvidenceSequenceCollision {
            provider_node_id,
            sequence,
        });
    }

    // 3. the projection's accepted log must be covered by verified
    //    evidence: every entry (kind, observed_at, sequence) must match a
    //    signature-verified observation for this contract. The R5-004
    //    "UNSIGNED observations never enter durable ShareNet state" trust
    //    boundary — derived at decision time, not trusted. The last match
    //    also binds the projection's tail (the freshness anchor) to its
    //    signing provider.
    let mut tail_provider: Option<[u8; 32]> = None;
    for entry in health.observations() {
        let matched = verified.iter().find(|statement| {
            statement.kind().as_str() == entry.kind().as_str()
                && statement.observed_at_unix() == entry.observed_at_unix()
                && statement.sequence() == entry.sequence()
        });
        match matched {
            Some(statement) => {
                tail_provider = Some(*statement.provider_node_id().as_bytes());
            }
            None => reasons.push(AdmissionReason::AdcosProjectionLogUnverified {
                sequence: entry.sequence(),
            }),
        }
    }

    // 4. the verified evidence must not be AHEAD of the projection — the
    //    snapshot must be self-consistent (the daemon feeds the store,
    //    then decides).
    let projection_sequence =
        health.observations().last().map(|o| o.sequence()).unwrap_or(0);
    let verified_sequence = verified.iter().map(|s| s.sequence()).max().unwrap_or(0);
    if verified_sequence > projection_sequence {
        reasons.push(AdmissionReason::AdcosProjectionLagsEvidence {
            verified_sequence,
            projection_sequence,
        });
    }

    // 5. the projected lifecycle state must be Active...
    let state = health.state();
    if state != ContractState::Active {
        reasons.push(AdmissionReason::AdcosContractNotActive { state });
    }
    // ...and the store's typed freshness at the decision clock must be
    //    Fresh (the provider's own window, ORIGINAL metadata — never
    //    re-anchored; this crate adds no second freshness authority).
    let fresh_until = match health.freshness(now_unix) {
        ProjectionFreshness::Fresh { fresh_until_unix } => fresh_until_unix,
        ProjectionFreshness::Stale {
            fresh_until_unix,
            last_observed_at_unix,
        } => {
            reasons.push(AdmissionReason::ProjectionStale {
                fresh_until_unix,
                last_observed_at_unix,
            });
            fresh_until_unix
        }
        // Unreachable after the empty-log check; kept fail-closed anyway.
        ProjectionFreshness::NoObservation => {
            reasons.push(AdmissionReason::AdcosEvidenceMissing);
            0
        }
    };

    if !reasons.is_empty() {
        return Err(reasons);
    }
    let last = health.observations().last().expect("non-empty log checked above");
    Ok(AdcosEvidenceAnchor {
        contract: *health.contract(),
        state,
        fresh_until_unix: fresh_until,
        last_observed_at_unix: last.observed_at_unix(),
        last_sequence: last.sequence(),
        provider_node_id: tail_provider
            .expect("a non-empty fully-covered log has a tail provider"),
    })
}

// ---------------------------------------------------------------------------
// The quality floor math (pure, integer, overflow-free)
// ---------------------------------------------------------------------------

/// The effective loss ratio of a link quality snapshot, in integer ppm:
/// the WORSE of the stated `loss_ratio_ppm` and the ratio derived from the
/// signed counters, `lost * 1_000_000 / (delivered + lost)` (exact integer
/// arithmetic via u128 intermediates — `lost <= delivered + lost` always,
/// so the derived ratio is in 0..=1_000_000 and fits u64).
///
/// A snapshot with no counters at all (`delivered == lost == 0`) has
/// nothing to derive — the stated ratio stands alone.
pub(crate) fn effective_loss_ppm(quality: &LinkQualitySnapshot) -> u64 {
    let stated = quality.loss_ratio_ppm;
    let total = u128::from(quality.delivered) + u128::from(quality.lost);
    if total == 0 {
        return stated;
    }
    let derived = (u128::from(quality.lost) * 1_000_000u128 / total) as u64;
    stated.max(derived)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quality(delivered: u64, lost: u64, stated_ppm: u64) -> LinkQualitySnapshot {
        LinkQualitySnapshot {
            delivered,
            lost,
            ewma_rtt_micros: 30_000,
            p50_rtt_micros: 20_000,
            p95_rtt_micros: 45_000,
            jitter_mad_micros: 1_000,
            loss_ratio_ppm: stated_ppm,
        }
    }

    #[test]
    fn effective_loss_takes_the_worse_of_stated_and_derived() {
        // Consistent snapshot: 10k lost of 1M total = exactly 10_000 ppm.
        assert_eq!(effective_loss_ppm(&quality(990_000, 10_000, 10_000)), 10_000);
        // An observer understating its own counters: derived wins.
        assert_eq!(effective_loss_ppm(&quality(990_000, 10_000, 0)), 10_000);
        // An honest pessimist: stated wins (max, not min).
        assert_eq!(effective_loss_ppm(&quality(990_000, 10_000, 12_345)), 12_345);
        // Zero counters: nothing derivable, stated stands.
        assert_eq!(effective_loss_ppm(&quality(0, 0, 7_777)), 7_777);
        // No loss at all.
        assert_eq!(effective_loss_ppm(&quality(1_000, 0, 0)), 0);
        // Total loss.
        assert_eq!(effective_loss_ppm(&quality(0, 5, 1_000_000)), 1_000_000);
    }

    #[test]
    fn effective_loss_integer_math_is_exact_and_overflow_free() {
        // One lost frame of three: 333_333 ppm (floor division), stated 0.
        assert_eq!(effective_loss_ppm(&quality(2, 1, 0)), 333_333);
        // Huge counters (u64 range) must not overflow: all lost = 1M ppm.
        assert_eq!(
            effective_loss_ppm(&quality(0, u64::MAX, 0)),
            1_000_000
        );
        // Huge delivered, one lost: derived is ~0, stated stands.
        assert_eq!(effective_loss_ppm(&quality(u64::MAX - 1, 1, 42)), 42);
        // Huge both, half lost: exactly 500_000 ppm in u128 math.
        assert_eq!(effective_loss_ppm(&quality(u64::MAX / 2, u64::MAX / 2, 0)), 500_000);
    }

    #[test]
    fn sharenet_freshness_bound_is_the_earlier_of_window_and_expiry() {
        // (observed_at, expires_at, window) -> effective bound
        let cases: [(u64, u64, u64, u64); 4] = [
            (1_000, 1_3600, 600, 1_600), // policy window binds (earlier)
            (1_000, 1_500, 600, 1_500),  // cryptographic expiry binds
            (1_000, 1_600, 0, 1_000),    // zero window: never fresh
            (1_000, 1_600, 4_000, 1_600), // window beyond expiry: expiry binds
        ];
        for (observed, expires, window, expected) in cases {
            let bound = observed.saturating_add(window).min(expires);
            assert_eq!(bound, expected);
        }
    }
}
