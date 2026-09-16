//! Shared test scaffolding for the R7-002 + R7-003 suites — the same world
//! shape as the protocol core's revocation tests (identities → committed
//! route → established circuit → revocation), plus the R7-003
//! gateway-candidate world (real signed R3-003 link evidence, real R5-004
//! provider observations admitted through the protocol core's registry
//! and projected through a real R5-003 durable store), plus temp-dir
//! helpers.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use sharenet_admission::{
    AdcosBackhaulEvidence, AdmissionParams, GatewayAdmissionPolicy,
};
use sharenet_connectivity::{
    AcceptOutcome, ConnectivityContractRef, ConnectivityObservation, DurableProjectionStore,
    ObservationKind, RefKind,
};
use sharenet_protocol::circuit::{derive_circuit_id, CircuitRegistry, CircuitSetup, CircuitSetupAck};
use sharenet_protocol::identity::Identity;
use sharenet_protocol::revocation::{
    CircuitRevocation, EvidenceValue, RevocationReason, SignedCircuitRevocation,
    EVIDENCE_FAILURE_KIND,
};
use sharenet_protocol::route::{
    derive_proposal_id, RouteAcceptance, RouteCommitment, RouteProposal, SignedEnvelope,
};
use sharenet_protocol::topology::SignedTopologyEvidence;
use sharenet_recovery::GatewayCandidate;
use sharenet_protocol::{
    ConnectivityObservationStatement, EvidenceKind, LinkQualitySnapshot, Observation,
    ObservationAdmission, SignedConnectivityObservation, TopologyEvidence,
};

/// A deterministic base time for all test timestamps.
pub const NOW: u64 = 1_700_000_000;
/// The R5-003 store window the gateway world's health views are built with.
pub const STORE_WINDOW_SECS: u64 = 600;

pub fn ident(seed: u8, created: u64) -> Identity {
    Identity::from_seed([seed; 32], created, None).expect("identity")
}

/// A three-member world: proposer + two hops with a verified
/// commitment (the same shape as the protocol core's revocation tests).
pub struct World {
    pub proposer: Identity,
    pub hop1: Identity,
    pub hop2: Identity,
    pub commitment: RouteCommitment,
    pub proposed_at: u64,
}

pub fn world(now: u64) -> World {
    let proposer = ident(0x11, now);
    let hop1 = ident(0x22, now);
    let hop2 = ident(0x33, now);
    let mut path: Vec<[u8; 32]> = [
        *proposer.node_id().as_bytes(),
        *hop1.node_id().as_bytes(),
        *hop2.node_id().as_bytes(),
    ]
    .to_vec();
    path.sort();
    let proposal =
        RouteProposal::new(&proposer, path, "live", now, 3600, [0x42; 32]).expect("proposal");
    let proposal_env = proposal.sign(&proposer).expect("sign");
    let proposal_id = derive_proposal_id(proposal_env.bytes());
    let mut members: Vec<&Identity> = vec![&proposer, &hop1, &hop2];
    members.sort_by_key(|m| *m.node_id().as_bytes());
    let acceptance_envs: Vec<_> = members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let a = RouteAcceptance::new(m, proposal_id, i as u64, now, 3600).expect("acc");
            a.sign(m).expect("sign")
        })
        .collect();
    let commitment =
        RouteCommitment::build(now, proposal_env, acceptance_envs).expect("com");
    World { proposer, hop1, hop2, commitment, proposed_at: now }
}

/// An established circuit over a fresh nonce.
pub fn established(now: u64, nonce: [u8; 32]) -> (World, CircuitRegistry, [u8; 32]) {
    let w = world(now);
    let mut registry = CircuitRegistry::new();
    let circuit_id = admit_circuit(&w, &mut registry, now, nonce);
    (w, registry, circuit_id)
}

/// Establish another circuit of the SAME world in the registry (a live
/// sibling, or a second revoked circuit).
pub fn admit_circuit(
    w: &World,
    registry: &mut CircuitRegistry,
    now: u64,
    nonce: [u8; 32],
) -> [u8; 32] {
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, nonce, now, 600).expect("setup");
    let setup_env = setup.sign(&w.proposer).expect("sign");
    let circuit_id = derive_circuit_id(w.commitment.route_id(), &nonce);
    registry.admit_setup(now, &setup_env).expect("admit");
    let path = w.commitment.verify(now).expect("v").proposal.path().to_vec();
    for (pos, want) in path.iter().enumerate() {
        let member = [&w.proposer, &w.hop1, &w.hop2]
            .into_iter()
            .find(|m| m.node_id().as_bytes() == want)
            .expect("member");
        let ack = CircuitSetupAck::new(circuit_id, &setup_env, member, pos as u64, now, 500)
            .expect("ack");
        let env = ack.sign(member).expect("sign");
        registry.admit_ack(now, &env).expect("ack admit");
    }
    circuit_id
}

/// The setup envelope of a circuit of `w` over `nonce` (for re-admission
/// attempts against a revoked id — the L015 end-to-end gate).
pub fn setup_envelope_for(w: &World, now: u64, nonce: [u8; 32]) -> sharenet_protocol::route::SignedEnvelope {
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, nonce, now, 600).expect("setup");
    setup.sign(&w.proposer).expect("sign")
}

/// A link-failure revocation by hop1 over `circuit_id`.
pub fn link_failure_revocation(
    w: &World,
    circuit_id: [u8; 32],
    revoked_at: u64,
) -> SignedCircuitRevocation {
    let mut evidence = BTreeMap::new();
    evidence.insert(
        EVIDENCE_FAILURE_KIND.to_string(),
        EvidenceValue::Text("link_failure".to_string()),
    );
    evidence.insert("missed_acks".to_string(), EvidenceValue::Int(3));
    let revocation = CircuitRevocation::new(
        &w.hop1,
        circuit_id,
        RevocationReason::LinkFailure,
        Some(evidence),
        revoked_at,
    )
    .expect("revocation");
    revocation.sign(&w.hop1).expect("sign")
}

/// A policy revocation by hop2 over `circuit_id` (a second revoker).
pub fn policy_revocation(
    w: &World,
    circuit_id: [u8; 32],
    revoked_at: u64,
) -> SignedCircuitRevocation {
    let revocation = CircuitRevocation::new(
        &w.hop2,
        circuit_id,
        RevocationReason::Policy,
        None,
        revoked_at,
    )
    .expect("revocation");
    revocation.sign(&w.hop2).expect("sign")
}

/// An operator revocation by the proposer (a third revoker).
pub fn operator_revocation(
    w: &World,
    circuit_id: [u8; 32],
    revoked_at: u64,
) -> SignedCircuitRevocation {
    let revocation = CircuitRevocation::new(
        &w.proposer,
        circuit_id,
        RevocationReason::Operator,
        None,
        revoked_at,
    )
    .expect("revocation");
    revocation.sign(&w.proposer).expect("sign")
}

// ---------------------------------------------------------------------------
// Temp dirs
// ---------------------------------------------------------------------------

static DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique temp directory, removed on drop.
pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let n = DIR_COUNTER.fetch_add(1, Ordering::SeqCst);
        let path = std::env::temp_dir().join(format!(
            "sharenet-r7002-{}-{}-{}",
            tag,
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&path).expect("temp dir");
        TempDir { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------
// The R7-003 gateway-candidate world (the same shape as the admission
// crate's integration scaffolding — everything REAL)
// ---------------------------------------------------------------------------

/// The link id every gateway-world link evidence carries.
pub const LINK_ID: [u8; 32] = [0x51; 32];

/// A node's derived id bytes.
pub fn node_id(identity: &Identity) -> [u8; 32] {
    *identity.node_id().as_bytes()
}

/// The suite's admission policy: 600 s evidence-freshness window, a
/// 50_000 ppm loss floor, a 200 ms latency bound.
pub fn admission_policy() -> GatewayAdmissionPolicy {
    GatewayAdmissionPolicy::new(
        AdmissionParams::new(600, 50_000, 200).expect("valid admission params"),
    )
}

fn link_quality(delivered: u64, lost: u64, stated_ppm: u64, p95_micros: u64) -> LinkQualitySnapshot {
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

/// Build + sign real R3-003 link evidence (established 100 s before the
/// observation, valid 600 s).
pub fn link_evidence(
    observer: &Identity,
    subject_node_id: [u8; 32],
    quality: LinkQualitySnapshot,
) -> SignedTopologyEvidence {
    TopologyEvidence::new(
        observer,
        subject_node_id,
        Observation::Link {
            link_id: LINK_ID,
            established_at_unix: NOW - 108,
            quality,
        },
        NOW - 8,
        600,
    )
    .expect("evidence")
    .sign(observer)
    .expect("signed by the observer")
}

fn signed_observation(
    provider: &Identity,
    contract: &ConnectivityContractRef,
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

fn canonical_stream(
    provider: &Identity,
    contract: &ConnectivityContractRef,
) -> Vec<SignedConnectivityObservation> {
    vec![
        signed_observation(provider, contract, EvidenceKind::ContractActivated, NOW - 10, 1, None),
        signed_observation(
            provider,
            contract,
            EvidenceKind::AssuranceAvailable,
            NOW - 5,
            2,
            Some(BTreeMap::from([
                ("throughput_bps".to_string(), 10_000_000),
                ("latency_ms".to_string(), 40),
            ])),
        ),
    ]
}

/// Feed a real R5-003 durable store through the verified path and return
/// the contract's health view (the daemon's selection input).
fn verified_health(
    signed: &[SignedConnectivityObservation],
    contract: &ConnectivityContractRef,
    path: &std::path::Path,
) -> sharenet_connectivity::ContractHealth {
    let mut admission = ObservationAdmission::new(STORE_WINDOW_SECS);
    admission.register_contract(*contract.id());
    let mut store = DurableProjectionStore::create(path, STORE_WINDOW_SECS).expect("store");
    for observation in signed {
        admission.receive(observation, NOW).expect("registry admission");
        let statement = observation.observation().expect("statement");
        let kind =
            ObservationKind::from_name(statement.kind().as_str()).expect("the frozen six");
        let domain = ConnectivityObservation::new(
            kind,
            statement.observed_at_unix(),
            ConnectivityContractRef::from_parts(RefKind::Contract, *statement.contract_ref())
                .expect("kind-validated seam"),
            statement.sequence(),
        );
        assert_eq!(store.accept(&domain), AcceptOutcome::Accepted);
    }
    store.flush().expect("flush");
    store.health(contract).expect("the contract is tracked")
}

/// The R7-003 gateway-candidate world: a recovering node, a witness, two
/// observers, two providers and four candidate gateways, with every
/// candidate's evidence built through the REAL production paths. The
/// timeline is fixed to [`NOW`] (links at NOW-8 valid 600 s; streams
/// activated NOW-10 / assured NOW-5) — an eligible decision at NOW+3
/// carries `valid_until_unix = NOW+592`.
pub struct GatewayWorld {
    /// The node performing the recovery (proposes the fresh route).
    pub recovering: Identity,
    /// A non-gateway path member (routes that must NOT carry the gateway).
    pub witness: Identity,
    /// G1: the fully eligible gateway.
    pub g1: Identity,
    /// G2: a good link but no ADCOS backhaul evidence.
    pub g2: Identity,
    /// G3: presents link evidence about a DIFFERENT node.
    pub g3: Identity,
    /// G4: a second fully eligible gateway (the tie-break tests).
    pub g4: Identity,
    // owned evidence (the candidate builders borrow it)
    link_g1: SignedTopologyEvidence,
    link_g1_tampered: SignedTopologyEvidence,
    link_g2: SignedTopologyEvidence,
    link_g3_wrong_subject: SignedTopologyEvidence,
    link_g4: SignedTopologyEvidence,
    link_g4_lying: SignedTopologyEvidence,
    signed_g1: Vec<SignedConnectivityObservation>,
    signed_g3: Vec<SignedConnectivityObservation>,
    signed_g4: Vec<SignedConnectivityObservation>,
    health_g1: sharenet_connectivity::ContractHealth,
    health_g3: sharenet_connectivity::ContractHealth,
    health_g4: sharenet_connectivity::ContractHealth,
}

/// G1's backhaul contract.
pub fn contract_g1() -> ConnectivityContractRef {
    ConnectivityContractRef::from_id([0xD1; 32])
}
/// G3's backhaul contract.
pub fn contract_g3() -> ConnectivityContractRef {
    ConnectivityContractRef::from_id([0xD3; 32])
}
/// G4's backhaul contract.
pub fn contract_g4() -> ConnectivityContractRef {
    ConnectivityContractRef::from_id([0xD4; 32])
}

pub fn gateway_world() -> GatewayWorld {
    let dir = TempDir::new("gateway-world");
    let recovering = ident(0xA1, NOW);
    let witness = ident(0xA2, NOW);
    let observer = ident(0xC0, NOW);
    let g1 = ident(0xC1, NOW);
    let provider1 = ident(0xC2, NOW);
    let g2 = ident(0xC3, NOW);
    let g3 = ident(0xC4, NOW);
    let observer2 = ident(0xC5, NOW);
    let g4 = ident(0xC6, NOW);
    let provider2 = ident(0xC7, NOW);

    // The good quality (counters agree with the stated ratio) and the
    // LYING quality (stated 1 ppm, counters say 200,000 ppm).
    let good = link_quality(995_000, 5_000, 5_000, 45_000);
    let lying = link_quality(800_000, 200_000, 1, 45_000);

    let link_g1 = link_evidence(&observer, node_id(&g1), good.clone());
    let mut tampered_sig = *link_g1.signature();
    tampered_sig[0] ^= 0x01;
    let link_g1_tampered =
        SignedTopologyEvidence::from_parts(link_g1.evidence_bytes().to_vec(), tampered_sig);
    let link_g2 = link_evidence(&observer, node_id(&g2), good.clone());
    let link_g3_wrong_subject = link_evidence(&observer2, node_id(&g2), good.clone());
    let link_g4 = link_evidence(&observer2, node_id(&g4), good.clone());
    let link_g4_lying = link_evidence(&observer2, node_id(&g4), lying);

    let signed_g1 = canonical_stream(&provider1, &contract_g1());
    let signed_g3 = canonical_stream(&provider1, &contract_g3());
    let signed_g4 = canonical_stream(&provider2, &contract_g4());
    let health_g1 = verified_health(&signed_g1, &contract_g1(), &dir.path.join("g1.store"));
    let health_g3 = verified_health(&signed_g3, &contract_g3(), &dir.path.join("g3.store"));
    let health_g4 = verified_health(&signed_g4, &contract_g4(), &dir.path.join("g4.store"));

    GatewayWorld {
        recovering,
        witness,
        g1,
        g2,
        g3,
        g4,
        link_g1,
        link_g1_tampered,
        link_g2,
        link_g3_wrong_subject,
        link_g4,
        link_g4_lying,
        signed_g1,
        signed_g3,
        signed_g4,
        health_g1,
        health_g3,
        health_g4,
    }
}

impl GatewayWorld {
    /// The gateway identity for a selected node id.
    pub fn gateway_identity(&self, gateway_node_id: &[u8; 32]) -> &Identity {
        [&self.g1, &self.g2, &self.g3, &self.g4]
            .into_iter()
            .find(|g| g.node_id().as_bytes() == gateway_node_id)
            .expect("a world gateway")
    }

    /// G1's candidate: fully eligible.
    pub fn candidate_eligible(&self) -> GatewayCandidate<'_> {
        GatewayCandidate {
            gateway_node_id: node_id(&self.g1),
            sharenet_link: Some(&self.link_g1),
            adcos_backhaul: Some(AdcosBackhaulEvidence {
                health: Some(&self.health_g1),
                signed_observations: &self.signed_g1,
            }),
        }
    }

    /// G1's candidate presenting FORGED link evidence.
    pub fn candidate_tampered_signature(&self) -> GatewayCandidate<'_> {
        GatewayCandidate {
            gateway_node_id: node_id(&self.g1),
            sharenet_link: Some(&self.link_g1_tampered),
            adcos_backhaul: Some(AdcosBackhaulEvidence {
                health: Some(&self.health_g1),
                signed_observations: &self.signed_g1,
            }),
        }
    }

    /// G2's candidate: no ADCOS backhaul evidence.
    pub fn candidate_no_backhaul(&self) -> GatewayCandidate<'_> {
        GatewayCandidate {
            gateway_node_id: node_id(&self.g2),
            sharenet_link: Some(&self.link_g2),
            adcos_backhaul: None,
        }
    }

    /// G3's candidate: link evidence about a DIFFERENT node (G2's).
    pub fn candidate_wrong_subject(&self) -> GatewayCandidate<'_> {
        GatewayCandidate {
            gateway_node_id: node_id(&self.g3),
            sharenet_link: Some(&self.link_g3_wrong_subject),
            adcos_backhaul: Some(AdcosBackhaulEvidence {
                health: Some(&self.health_g3),
                signed_observations: &self.signed_g3,
            }),
        }
    }

    /// G4's candidate: a second fully eligible gateway.
    pub fn candidate_eligible_alt(&self) -> GatewayCandidate<'_> {
        GatewayCandidate {
            gateway_node_id: node_id(&self.g4),
            sharenet_link: Some(&self.link_g4),
            adcos_backhaul: Some(AdcosBackhaulEvidence {
                health: Some(&self.health_g4),
                signed_observations: &self.signed_g4,
            }),
        }
    }

    /// G4's candidate presenting COUNTER-DISAGREEING quality evidence.
    pub fn candidate_lying_counters(&self) -> GatewayCandidate<'_> {
        GatewayCandidate {
            gateway_node_id: node_id(&self.g4),
            sharenet_link: Some(&self.link_g4_lying),
            adcos_backhaul: Some(AdcosBackhaulEvidence {
                health: Some(&self.health_g4),
                signed_observations: &self.signed_g4,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// The R7-003 fresh-route material (the R3-004 seams)
// ---------------------------------------------------------------------------

/// The signed R3-004 material for a fresh route, plus the route id an
/// independent build derives (the tests' expected value).
pub struct FreshRouteMaterial {
    pub proposal_env: SignedEnvelope,
    pub acceptance_envs: Vec<SignedEnvelope>,
    pub route_id: [u8; 32],
}

fn build_route_material(
    proposer: &Identity,
    members: &[&Identity],
    at: u64,
    nonce: [u8; 32],
) -> FreshRouteMaterial {
    let mut path: Vec<[u8; 32]> = members.iter().map(|m| node_id(m)).collect();
    path.sort();
    path.dedup();
    let proposal = RouteProposal::new(proposer, path, "live", at, 3600, nonce).expect("proposal");
    let proposal_env = proposal.sign(proposer).expect("sign");
    let proposal_id = derive_proposal_id(proposal_env.bytes());
    let mut sorted: Vec<&Identity> = members.to_vec();
    sorted.sort_by_key(|m| node_id(m));
    let acceptance_envs: Vec<_> = sorted
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let acceptance =
                RouteAcceptance::new(m, proposal_id, i as u64, at, 3600).expect("acceptance");
            acceptance.sign(m).expect("sign")
        })
        .collect();
    let commitment =
        RouteCommitment::build(at, proposal_env.clone(), acceptance_envs.clone()).expect("com");
    FreshRouteMaterial { proposal_env, acceptance_envs, route_id: *commitment.route_id() }
}

/// The fresh-route material through the selected gateway (the recovering
/// node + the gateway; both sign acceptances). `at` is the proposal time
/// — the §11 freshness anchor is exactly what varies with it.
pub fn fresh_route_material(
    w: &GatewayWorld,
    selected: &sharenet_recovery::SelectedGateway,
    at: u64,
) -> FreshRouteMaterial {
    let gateway = w.gateway_identity(&selected.gateway_node_id);
    build_route_material(&w.recovering, &[&w.recovering, gateway], at, [0x43; 32])
}

/// Fresh-route material for a route that does NOT carry the selected
/// gateway (the recovering node + the witness).
pub fn fresh_route_material_skipping_gateway(w: &GatewayWorld, at: u64) -> FreshRouteMaterial {
    build_route_material(&w.recovering, &[&w.recovering, &w.witness], at, [0x44; 32])
}
