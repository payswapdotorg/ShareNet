//! Shared scaffolding for the R5-005 integration + adversarial suites.
//!
//! Everything here is REAL: real `Identity`s (Ed25519), real R3-003
//! `TopologyEvidence` built and signed through the protocol core's public
//! API, real R5-004 `SignedConnectivityObservation`s admitted through the
//! protocol core's `ObservationAdmission` (the registry admission rule —
//! signature, known contract, sequence gate, freshness window) and mapped
//! into the connectivity domain exactly the way the ADCOS adapter does
//! (fields from the SIGNED statement), and a real R5-003
//! `DurableProjectionStore` on a real temp file.
//!
//! No fakes, no mocks, no network — but no shortcuts either: every
//! cryptographic and durability step is the production path.

#![allow(dead_code)] // shared across the two suites; each uses a subset

use std::collections::BTreeMap;

use sharenet_admission::{
    AdcosBackhaulEvidence, AdmissionParams, GatewayAdmissionPolicy, GatewayAdmissionRequest,
};
use sharenet_connectivity::{
    AcceptOutcome, ConnectivityContractRef, ConnectivityObservation, ContractHealth,
    DurableProjectionStore, ObservationKind, RefKind,
};
use sharenet_protocol::{
    ConnectivityEvidenceError, ConnectivityObservationStatement, EvidenceKind, Identity,
    LinkQualitySnapshot, Observation, ObservationAdmission, SignedConnectivityObservation,
    SignedTopologyEvidence, TopologyEvidence,
};

/// The fixed decision clock for the composition tests (a virtual "now" —
/// the policy has no wall clock; determinism starts here).
pub const T: u64 = 1_700_000_000;
/// The R5-003 store's freshness window (the PROVIDER's bound, persisted in
/// the store header — this is the ADCOS-side freshness authority).
pub const STORE_WINDOW_SECS: u64 = 600;

/// A deterministic identity from an explicit seed (test nodes).
pub fn identity(seed: u8) -> Identity {
    Identity::from_seed([seed; 32], T - 86_400, None).expect("identity from seed")
}

/// A node's derived id bytes.
pub fn node_id(identity: &Identity) -> [u8; 32] {
    *identity.node_id().as_bytes()
}

/// A policy from the three hard constraints.
pub fn policy(
    freshness_window_secs: u64,
    loss_ppm_floor: u64,
    latency_bound_ms: u64,
) -> GatewayAdmissionPolicy {
    GatewayAdmissionPolicy::new(
        AdmissionParams::new(freshness_window_secs, loss_ppm_floor, latency_bound_ms)
            .expect("valid params"),
    )
}

/// A link quality snapshot (p50 is always half of p95, so the protocol's
/// `p95 >= p50` invariant holds for any p95).
pub fn link_quality(
    delivered: u64,
    lost: u64,
    stated_ppm: u64,
    p95_micros: u64,
) -> LinkQualitySnapshot {
    LinkQualitySnapshot {
        delivered,
        lost,
        ewma_rtt_micros: p95_micros / 2 + 1_000,
        p50_rtt_micros: p95_micros / 2,
        p95_rtt_micros: p95_micros,
        jitter_mad_micros: 500,
        loss_ratio_ppm: stated_ppm,
    }
}

/// The default good quality: 5,000 ppm effective loss (counters agree with
/// the stated ratio), 45 ms p95.
pub fn good_quality() -> LinkQualitySnapshot {
    link_quality(995_000, 5_000, 5_000, 45_000)
}

/// Build + sign real link evidence: `observer` attests a link to `subject`
/// with the given quality. `established_at` is 100s before `observed_at`.
pub fn link_evidence(
    observer: &Identity,
    subject_node_id: [u8; 32],
    link_id: [u8; 32],
    observed_at: u64,
    validity_secs: u64,
    quality: LinkQualitySnapshot,
) -> SignedTopologyEvidence {
    TopologyEvidence::new(
        observer,
        subject_node_id,
        Observation::Link {
            link_id,
            established_at_unix: observed_at.saturating_sub(100),
            quality,
        },
        observed_at,
        validity_secs,
    )
    .expect("evidence")
    .sign(observer)
    .expect("signed by the observer")
}

/// A contract ref from a tag byte.
pub fn contract(tag: u8) -> ConnectivityContractRef {
    ConnectivityContractRef::from_id([tag; 32])
}

/// Build + sign a real provider observation.
pub fn signed_observation(
    provider: &Identity,
    contract: ConnectivityContractRef,
    kind: EvidenceKind,
    observed_at: u64,
    sequence: u64,
    execution: Option<BTreeMap<String, i64>>,
) -> SignedConnectivityObservation {
    ConnectivityObservationStatement::new(
        provider,
        *contract.id(),
        kind,
        observed_at,
        sequence,
        execution,
    )
    .expect("statement")
    .sign(provider)
    .expect("signed by the provider")
}

/// The daemon's verified path (exactly the R5-002 adapter's mapping,
/// re-implemented here because the adapter crate is not a dependency):
/// full protocol-core admission first, then the domain observation whose
/// fields all come from the SIGNED statement.
pub fn verified_domain_observation(
    admission: &mut ObservationAdmission,
    signed: &SignedConnectivityObservation,
    now_unix: u64,
) -> Result<ConnectivityObservation, ConnectivityEvidenceError> {
    // The registry admission order: strict parse, signature, known
    // contract, sequence gate, freshness window.
    admission.receive(signed, now_unix)?;
    let statement = signed.observation()?;
    let kind =
        ObservationKind::from_name(statement.kind().as_str()).expect("the frozen six by name");
    let contract = ConnectivityContractRef::from_parts(RefKind::Contract, *statement.contract_ref())
        .expect("kind-validated seam");
    Ok(ConnectivityObservation::new(
        kind,
        statement.observed_at_unix(),
        contract,
        statement.sequence(),
    ))
}

/// A fresh admission tracker with the contract registered (the daemon
/// wiring: the accepting node knows the contracts it holds refs for).
pub fn admission_for(contract: &ConnectivityContractRef) -> ObservationAdmission {
    let mut admission = ObservationAdmission::new(STORE_WINDOW_SECS);
    admission.register_contract(*contract.id());
    admission
}

/// The canonical two-observation ADCOS stream for a contract:
/// `contract_activated` at `T-10` (sequence 1) then `assurance_available`
/// with execution counters at `T-5` (sequence 2).
pub fn canonical_stream(
    provider: &Identity,
    contract: ConnectivityContractRef,
) -> Vec<SignedConnectivityObservation> {
    vec![
        signed_observation(
            provider,
            contract,
            EvidenceKind::ContractActivated,
            T - 10,
            1,
            None,
        ),
        signed_observation(
            provider,
            contract,
            EvidenceKind::AssuranceAvailable,
            T - 5,
            2,
            Some(BTreeMap::from([
                ("throughput_bps".to_string(), 10_000_000),
                ("latency_ms".to_string(), 40),
            ])),
        ),
    ]
}

/// Feed the store through the verified path and return the store (the
/// daemon wiring: admission -> domain mapping -> durable accept -> flush).
pub fn fed_store(
    path: &std::path::Path,
    admission: &mut ObservationAdmission,
    signed: &[SignedConnectivityObservation],
    now_unix: u64,
) -> DurableProjectionStore {
    let mut store =
        DurableProjectionStore::create(path, STORE_WINDOW_SECS).expect("create store");
    for observation in signed {
        let domain = verified_domain_observation(admission, observation, now_unix)
            .expect("verified observation");
        let outcome = store.accept(&domain);
        assert_eq!(outcome, AcceptOutcome::Accepted, "fresh stream accepted");
    }
    store.flush().expect("flush");
    store
}

/// A unique store path per test (tag) + process, cleaned up on drop
/// (including any leftover flush temp file).
pub struct TempStore {
    pub path: std::path::PathBuf,
}

impl TempStore {
    pub fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sharenet-r5005-it-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self {
            path: dir.join(format!("{tag}.store")),
        }
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let mut os = self.path.clone().into_os_string();
        os.push(".tmp");
        let _ = std::fs::remove_file(std::path::PathBuf::from(os));
        let _ = std::fs::remove_dir(self.path.parent().expect("parent"));
    }
}

/// The canonical ShareNet-side evidence: the observer (seed 1) attests the
/// gateway's (seed 2) link at `T-8`, cryptographically valid 60 s, with
/// the default good quality.
pub fn canonical_link() -> SignedTopologyEvidence {
    link_evidence(&identity(1), node_id(&identity(2)), [7; 32], T - 8, 60, good_quality())
}

/// The default full request: link evidence + the store's health + the
/// signed set (the caller's verified-path residue).
pub fn full_request<'a>(
    gateway_node_id: [u8; 32],
    now_unix: u64,
    link: &'a SignedTopologyEvidence,
    health: &'a ContractHealth,
    signed: &'a [SignedConnectivityObservation],
) -> GatewayAdmissionRequest<'a> {
    GatewayAdmissionRequest {
        gateway_node_id,
        now_unix,
        sharenet_link: Some(link),
        adcos_backhaul: Some(AdcosBackhaulEvidence {
            health: Some(health),
            signed_observations: signed,
        }),
    }
}

/// Collect the reason machine names of an Ineligible decision (panics on
/// Eligible — callers assert eligibility explicitly first).
pub fn reason_names(decision: &sharenet_admission::GatewayAdmission) -> Vec<&'static str> {
    assert!(!decision.is_eligible(), "expected Ineligible, got {decision}");
    decision.reasons().iter().map(|r| r.as_str()).collect()
}
