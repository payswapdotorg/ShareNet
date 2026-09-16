//! The fresh-gateway selection stage — work item R7-003, the first of the
//! two §11 stages this crate now owns after `recovery attempt`:
//!
//! ```text
//! recovery attempt                   ← R7-002 (durable, bounded)
//!     ↓
//! fresh gateway selection            ← THIS MODULE (R5-005 composed in)
//!     ↓
//! fresh route commitment             ← driver.rs `establish_fresh_route`
//!     ↓
//! fresh circuit session              ← R7-004
//!     ↓
//! verification                       ← R7-003/R7-004
//! ```
//!
//! Architecture §5 names the eligibility dimensions ("a gateway becomes
//! ShareNet-eligible only when BOTH exist: authenticated ShareNet
//! node/link evidence AND acceptable ADCOS-backed external connectivity
//! evidence" — `spec/integrations/adcos.md`) and §11 makes fresh gateway
//! selection the stage that follows a durable revocation. R5-005 already
//! encodes §5's two dimensions as the pure decision engine
//! ([`sharenet_admission::GatewayAdmissionPolicy`]); this module is the
//! SELECTION layer on top of it, and it deliberately does not rewrite the
//! admission math — it COMPOSES the policy:
//!
//! - a [`GatewayCandidate`] is exactly the R5-005 evidence snapshot shape
//!   (the gateway's node id + the two borrowed evidence factors); nothing
//!   is invented, nothing is copied — the types are the admission crate's
//!   own, so the two stages cannot drift apart;
//! - [`select_eligible_gateway`] runs the REAL policy per candidate
//!   (verifying every signature itself, per AGENTS.md: no caller-supplied
//!   "eligible" boolean is ever accepted — the verdict is derived at
//!   selection time), and only an `Eligible` verdict can be selected;
//! - the tie-break between eligible gateways is DETERMINISTIC (§2: "the
//!   routing objective is deterministic for a fixed evidence snapshot"):
//!   ascending gateway node-id bytes, independent of input order. No
//!   scoring, no quality ranking — a hard-constraint filter plus a fixed
//!   key (the optimizer layers of R3-004 routing sit elsewhere and may
//!   compose on top);
//! - ambiguous input fails closed: two candidates with the same node id
//!   are a typed refusal ([`RecoveryError::DuplicateGatewayCandidate`]),
//!   never a silent pick;
//! - when no candidate is eligible — including an EMPTY candidate set —
//!   the typed refusal is [`RecoveryError::NoEligibleGateway`], the
//!   machine name the R7-005 retry/backoff policy will consume later.
//!
//! The function is PURE: no I/O, no wall clock (`now_unix` is part of the
//! evidence snapshot), no durable state (the caller —
//! [`crate::RecoveryDriver::select_gateway`] — binds the outcome to the
//! open §11 attempt). The same `(policy, candidates, now)` always yields
//! the same selection, proven by test including across input
//! permutations.
//!
//! # The honest boundary (inherited from R5-005, unchanged here)
//!
//! An `Eligible` verdict is the typed INPUT to selection — it says the
//! gateway's two-factor evidence is present, cryptographically verified,
//! fresh and within the quality floor at `now_unix`. It is NOT a promise
//! that the gateway will deliver ShareNet packets and NOT a promise that
//! the provider is fulfilling its contract. A selected gateway can still
//! fail (that is what [`crate::AttemptFailure::GatewayUnreachable`] and
//! the next revocation are for); selection only guarantees that the
//! §11 pipeline proceeds on verified evidence, never on assertion.

use sharenet_admission::{
    AdcosBackhaulEvidence, AdcosEvidenceAnchor, GatewayAdmissionPolicy, GatewayAdmissionRequest,
    ShareNetEvidenceAnchor,
};
use sharenet_protocol::topology::SignedTopologyEvidence;

use crate::error::RecoveryError;

/// One gateway candidate for §11 fresh-gateway selection: the gateway's
/// derived node id plus the R5-005 two-factor evidence it presents, in
/// exactly the admission crate's shape (borrowed; selection clones
/// nothing — the same read-only law `GatewayAdmissionRequest` follows).
///
/// A candidate with a missing factor is legal input — it simply cannot
/// be selected (the policy judges it `Ineligible`, fail-closed).
#[derive(Debug, Clone, Copy)]
pub struct GatewayCandidate<'a> {
    /// The gateway under selection — the subject every piece of evidence
    /// must bind to (derived from the node's `NodeIdentity`).
    pub gateway_node_id: [u8; 32],
    /// Factor 1 (ShareNet side): the R3-003 signed link evidence about
    /// the gateway node. `None` = presented no evidence.
    pub sharenet_link: Option<&'a SignedTopologyEvidence>,
    /// Factor 2 (ADCOS side): the R5-003/R5-004 backhaul evidence bundle
    /// (the durable projection's health view + the signed observations it
    /// was fed from). `None` = presented no evidence.
    pub adcos_backhaul: Option<AdcosBackhaulEvidence<'a>>,
}

impl<'a> GatewayCandidate<'a> {
    /// Assemble the R5-005 admission request for this candidate at
    /// `now_unix` (the same fixed snapshot the policy decides on).
    fn admission_request(&self, now_unix: u64) -> GatewayAdmissionRequest<'a> {
        GatewayAdmissionRequest {
            gateway_node_id: self.gateway_node_id,
            now_unix,
            sharenet_link: self.sharenet_link,
            adcos_backhaul: self.adcos_backhaul,
        }
    }
}

/// The outcome of a successful selection: the winning gateway and exactly
/// the verified evidence anchors the R5-005 `Eligible` verdict rested on
/// (for audit, for the construction stage's freshness anchor, and for
/// honest reporting — the anchors carry no more than the verdict does).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewaySelection {
    /// The selected gateway's derived node id.
    pub gateway_node_id: [u8; 32],
    /// The verified ShareNet-side link evidence anchor.
    pub sharenet: ShareNetEvidenceAnchor,
    /// The verified ADCOS-side backhaul evidence anchor.
    pub adcos: AdcosEvidenceAnchor,
    /// Until when (exclusive) the selection's evidence holds (the earlier
    /// of the two anchors' freshness bounds — the R5-005 law).
    pub valid_until_unix: u64,
    /// How many candidates were evaluated (diagnostics; the refused
    /// candidates' typed reasons are NOT retained — bounded output).
    pub evaluated: usize,
}

/// Select the fresh gateway from `candidates` under the R5-005 admission
/// `policy` at `now_unix` — the §11 stage after the recovery attempt
/// opened.
///
/// Only a gateway the policy judges `Eligible` can be selected; ties
/// between eligible gateways break deterministically by ascending gateway
/// node-id bytes (input order never matters). Typed refusals:
/// [`RecoveryError::DuplicateGatewayCandidate`] (ambiguous set — the same
/// gateway twice, even with identical evidence) and
/// [`RecoveryError::NoEligibleGateway`] (no eligible candidate, empty set
/// included).
pub fn select_eligible_gateway(
    policy: &GatewayAdmissionPolicy,
    candidates: &[GatewayCandidate<'_>],
    now_unix: u64,
) -> Result<GatewaySelection, RecoveryError> {
    // Ambiguity first: a duplicated gateway id makes the set's meaning
    // order-dependent (which of the two entries' evidence "counts"?), so
    // selection refuses rather than guess. The scan is over input order;
    // the REFUSAL (the id) is order-independent.
    let mut seen: Vec<[u8; 32]> = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        if seen.contains(&candidate.gateway_node_id) {
            return Err(RecoveryError::DuplicateGatewayCandidate {
                gateway_node_id: candidate.gateway_node_id,
            });
        }
        seen.push(candidate.gateway_node_id);
    }

    // The real R5-005 decision per candidate (every signature verified
    // inside `decide` — the verdict is derived, never trusted). The best
    // eligible candidate is the minimum node id among the eligible —
    // a fixed key, independent of input order (§2 determinism).
    let mut best: Option<GatewaySelection> = None;
    for candidate in candidates {
        let decision = policy.decide(candidate.admission_request(now_unix));
        if let sharenet_admission::GatewayAdmission::Eligible {
            gateway_node_id,
            sharenet,
            adcos,
            valid_until_unix,
        } = decision
        {
            let selection = GatewaySelection {
                gateway_node_id,
                sharenet,
                adcos,
                valid_until_unix,
                evaluated: candidates.len(),
            };
            let better = best
                .as_ref()
                .map_or(true, |b| selection.gateway_node_id < b.gateway_node_id);
            if better {
                best = Some(selection);
            }
        }
        // Ineligible: fail-closed, the candidate is simply not
        // selectable. The typed reasons are the policy's output, not
        // selection's (bounded: nothing is accumulated here).
    }
    best.ok_or(RecoveryError::NoEligibleGateway { candidate_count: candidates.len() })
}

// ---------------------------------------------------------------------------
// Unit tests (the pure selection policy, before any driver binding)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit as tk;

    /// The full happy path: one eligible candidate among ineligible ones
    /// is selected, carrying exactly the verified anchors.
    #[test]
    fn selects_the_eligible_candidate() {
        let w = tk::gateway_world(tk::NOW);
        let candidates = vec![w.candidate_no_backhaul(), w.candidate_eligible()];
        let policy = tk::admission_policy();
        let selection =
            select_eligible_gateway(&policy, &candidates, tk::NOW + 3).expect("selection");
        assert_eq!(selection.gateway_node_id, tk::node_id(&w.g1));
        assert_eq!(selection.evaluated, 2);
        // The anchors are the verified evidence's own values.
        assert_eq!(selection.sharenet.link_id, tk::LINK_ID);
        assert_eq!(selection.adcos.contract, tk::contract_g1());
        // valid_until = the earlier of the two freshness bounds (the
        // link's NOW-8+600 window here — see the testkit's timeline).
        assert_eq!(selection.valid_until_unix, tk::NOW - 8 + 600);
    }

    /// Determinism: the same set + clock always selects the same gateway,
    /// and the INPUT ORDER never matters (the tie-break is id bytes).
    #[test]
    fn selection_is_deterministic_and_order_independent() {
        let w = tk::gateway_world(tk::NOW);
        let policy = tk::admission_policy();
        let candidates = vec![w.candidate_eligible(), w.candidate_eligible_alt()];
        let expected = select_eligible_gateway(&policy, &candidates, tk::NOW + 3)
            .expect("selection")
            .gateway_node_id;
        // The fixed tie-break: the minimum eligible node id, whichever
        // way the set is permuted.
        let mut ids = vec![tk::node_id(&w.g1), tk::node_id(&w.g4)];
        ids.sort();
        assert_eq!(expected, ids[0]);
        for permutation in
            [vec![w.candidate_eligible(), w.candidate_eligible_alt()], vec![w.candidate_eligible_alt(), w.candidate_eligible()]]
        {
            let got = select_eligible_gateway(&policy, &permutation, tk::NOW + 3)
                .expect("selection")
                .gateway_node_id;
            assert_eq!(got, expected, "input order must not change the selection");
        }
        // Re-query purity: asking again answers identically.
        let again = select_eligible_gateway(&policy, &candidates, tk::NOW + 3)
            .expect("re-selection");
        assert_eq!(again.gateway_node_id, expected);
        assert_eq!(again, select_eligible_gateway(&policy, &candidates, tk::NOW + 3).unwrap());
    }

    /// Fail-closed refusals: an empty set, an all-ineligible set (even a
    /// single ineligible candidate), and a duplicated gateway id.
    #[test]
    fn refusals_are_typed_and_fail_closed() {
        let w = tk::gateway_world(tk::NOW);
        let policy = tk::admission_policy();

        let err = select_eligible_gateway(&policy, &[], tk::NOW).unwrap_err();
        assert!(matches!(err, RecoveryError::NoEligibleGateway { candidate_count: 0 }));

        // The ONLY candidate is ineligible: never selected, typed refusal.
        let only = vec![w.candidate_no_backhaul()];
        let err = select_eligible_gateway(&policy, &only, tk::NOW + 3).unwrap_err();
        assert!(matches!(err, RecoveryError::NoEligibleGateway { candidate_count: 1 }));

        let both = vec![w.candidate_no_backhaul(), w.candidate_wrong_subject()];
        let err = select_eligible_gateway(&policy, &both, tk::NOW + 3).unwrap_err();
        assert!(matches!(err, RecoveryError::NoEligibleGateway { candidate_count: 2 }));

        let dup = vec![w.candidate_eligible(), w.candidate_eligible()];
        let err = select_eligible_gateway(&policy, &dup, tk::NOW + 3).unwrap_err();
        assert_eq!(err.name(), "duplicate_gateway_candidate");
        assert!(matches!(
            err,
            RecoveryError::DuplicateGatewayCandidate { gateway_node_id } if gateway_node_id == tk::node_id(&w.g1)
        ));
    }

    /// A candidate lying in its evidence never selects: a mutated
    /// signature (verification fails), evidence about a DIFFERENT node
    /// (the binding rule), and counters that contradict the stated loss
    /// ratio (evaluated on the counters — the R5-005 law).
    #[test]
    fn lying_candidates_never_select() {
        let w = tk::gateway_world(tk::NOW);
        let policy = tk::admission_policy();

        let liars = vec![
            w.candidate_tampered_signature(),
            w.candidate_wrong_subject(),
            w.candidate_lying_counters(),
        ];
        for liar in &liars {
            let decision = policy.decide(liar.admission_request(tk::NOW + 3));
            assert!(!decision.is_eligible(), "a liar must be ineligible");
        }
        // All three together: typed refusal, never a partial pick.
        let err = select_eligible_gateway(&policy, &liars, tk::NOW + 3).unwrap_err();
        assert_eq!(err.name(), "no_eligible_gateway");
    }
}
