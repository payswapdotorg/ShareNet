//! In-module test scaffolding for the R7-002 UNIT suites (`#[cfg(test)]`
//! modules of `ledger.rs` / `attempt.rs` / `driver.rs`) — the same world
//! shape as `tests/common/mod.rs` serves the integration suites: seeded
//! identities → verified route commitment → established circuit →
//! revocations, plus the byte-crafting helpers the fail-closed corruption
//! tests need (CRC-32, ledger frame offsets, attempt-image builders).
//!
//! Nothing here is compiled into the production library.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
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
use sharenet_protocol::{
    ConnectivityObservationStatement, EvidenceKind, LinkQualitySnapshot, Observation,
    ObservationAdmission, SignedConnectivityObservation, TopologyEvidence,
};

use crate::driver::SelectedGateway;
use crate::gateway::GatewayCandidate;
use crate::ledger::DurableRevocationLedger;

/// A deterministic base time for all test timestamps.
pub const NOW: u64 = 1_700_000_000;

pub fn ident(seed: u8, created: u64) -> Identity {
    Identity::from_seed([seed; 32], created, None).expect("identity")
}

/// A three-member world: proposer + two hops with a verified commitment
/// (the same shape as the protocol core's revocation tests).
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
/// sibling for the not-revoked refusals).
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
pub fn setup_envelope_for(w: &World, now: u64, nonce: [u8; 32]) -> SignedEnvelope {
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, nonce, now, 600).expect("setup");
    setup.sign(&w.proposer).expect("sign")
}

/// The setup envelope of a fresh world (the deterministic-seed twin of
/// `established(now, nonce)` — same seeds, same world).
pub fn setup_envelope(now: u64, nonce: [u8; 32]) -> SignedEnvelope {
    setup_envelope_for(&world(now), now, nonce)
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

/// A revocation by an identity that is NOT on any committed path (the
/// R7-001 admission refusal leg).
pub fn off_path_revocation(now: u64, circuit_id: [u8; 32]) -> SignedCircuitRevocation {
    let stranger = ident(0x44, now);
    let revocation = CircuitRevocation::new(
        &stranger,
        circuit_id,
        RevocationReason::Policy,
        None,
        now,
    )
    .expect("revocation");
    revocation.sign(&stranger).expect("sign")
}

/// A durable ledger at `path` with one circuit revoked (link failure by
/// hop1) — the minimal world every §11 attempt-log test starts from.
/// Returns the store, the world, the registry that established the
/// circuit, and the (now durably revoked) circuit id. A second, LIVE
/// circuit of the same world is established in the registry for the
/// not-revoked refusals.
pub fn revoked_ledger(
    path: &Path,
    now: u64,
) -> (DurableRevocationLedger, World, CircuitRegistry, [u8; 32], [u8; 32]) {
    let w = world(now);
    let mut registry = CircuitRegistry::new();
    let revoked = admit_circuit(&w, &mut registry, now, [0x71; 32]);
    let live = admit_circuit(&w, &mut registry, now, [0x72; 32]);
    let store = DurableRevocationLedger::create(path).expect("create ledger");
    store
        .admit(now, &link_failure_revocation(&w, revoked, now), &registry)
        .expect("admit revocation");
    (store, w, registry, revoked, live)
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
            "sharenet-r7002-unit-{}-{}-{}",
            tag,
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&path).expect("temp dir");
        TempDir { path }
    }

    pub fn ledger_path(&self) -> PathBuf {
        self.path.join("revocations.log")
    }

    pub fn attempts_path(&self) -> PathBuf {
        self.path.join("recovery-attempts.store")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Byte-crafting helpers (the corruption suites)
// ---------------------------------------------------------------------------

/// CRC-32/IEEE — the same corruption detector the two file formats use
/// (re-implemented here so the tests pin the format independently).
pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// The fixed ledger record prefix (payload_len + payload_crc32 +
/// prev_chain) — `4 + 4 + 32`.
pub const LEDGER_RECORD_PREFIX_LEN: usize = 40;
/// The immutable ledger header length.
pub const LEDGER_HEADER_LEN: usize = 8;

/// Start offsets of every COMPLETE record frame in a ledger file image
/// (frames are `prefix(40) + payload_len`).
pub fn ledger_frame_offsets(bytes: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut off = LEDGER_HEADER_LEN;
    while off + LEDGER_RECORD_PREFIX_LEN <= bytes.len() {
        let payload_len =
            u32::from_le_bytes(bytes[off..off + 4].try_into().expect("4")) as usize;
        let end = off + LEDGER_RECORD_PREFIX_LEN + payload_len;
        if end > bytes.len() {
            break;
        }
        out.push(off);
        off = end;
    }
    out
}

/// The attempt-log layout, pinned independently of `attempt.rs`'s private
/// constants (the crafting helpers below build every region of it).
pub const ATTEMPT_HEADER_LEN: usize = 16;
pub const ATTEMPT_CRC_LEN: usize = 4;
pub const ATTEMPT_SECTION_FIXED_LEN: usize = 52;
pub const ATTEMPT_RECORD_LEN: usize = 58;

/// Wrap an attempt-log body into a full image (header + body + CRC-32).
pub fn attempt_image(circuit_count: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ATTEMPT_HEADER_LEN + body.len() + ATTEMPT_CRC_LEN);
    out.extend_from_slice(b"SNRA");
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&circuit_count.to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    let crc = crc32(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    out
}

/// One circuit section: id(32) + next_seq(8) + revoked_at(8) +
/// attempt_count(4) + records.
pub fn attempt_section_bytes(
    circuit: &[u8; 32],
    next_seq: u64,
    revoked_at: u64,
    records: &[[u8; ATTEMPT_RECORD_LEN]],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ATTEMPT_SECTION_FIXED_LEN + records.len() * ATTEMPT_RECORD_LEN);
    out.extend_from_slice(circuit);
    out.extend_from_slice(&next_seq.to_le_bytes());
    out.extend_from_slice(&revoked_at.to_le_bytes());
    out.extend_from_slice(&(records.len() as u32).to_le_bytes());
    for record in records {
        out.extend_from_slice(record);
    }
    out
}

/// One attempt record: seq(8) + started(8) + finished(8) + state(1) +
/// outcome(1) + route_id(32).
pub fn attempt_record_bytes(
    attempt_seq: u64,
    started_at: u64,
    finished_at: u64,
    state_tag: u8,
    outcome_tag: u8,
    route_id: [u8; 32],
) -> [u8; ATTEMPT_RECORD_LEN] {
    let mut out = [0u8; ATTEMPT_RECORD_LEN];
    out[0..8].copy_from_slice(&attempt_seq.to_le_bytes());
    out[8..16].copy_from_slice(&started_at.to_le_bytes());
    out[16..24].copy_from_slice(&finished_at.to_le_bytes());
    out[24] = state_tag;
    out[25] = outcome_tag;
    out[26..58].copy_from_slice(&route_id);
    out
}

/// A well-formed abandoned record (state 2, reason tag `failure_tag`).
pub fn abandoned_record(attempt_seq: u64, at: u64, failure_tag: u8) -> [u8; ATTEMPT_RECORD_LEN] {
    attempt_record_bytes(attempt_seq, at, at + 1, 2, failure_tag, [0u8; 32])
}

/// A well-formed pending record (state 0).
pub fn pending_record(attempt_seq: u64, at: u64) -> [u8; ATTEMPT_RECORD_LEN] {
    attempt_record_bytes(attempt_seq, at, 0, 0, 0, [0u8; 32])
}

/// A well-formed succeeded record (state 1, route ref).
pub fn succeeded_record(attempt_seq: u64, at: u64, route_id: [u8; 32]) -> [u8; ATTEMPT_RECORD_LEN] {
    attempt_record_bytes(attempt_seq, at, at + 1, 1, 1, route_id)
}

// ---------------------------------------------------------------------------
// The R7-003 gateway-candidate world (the same shape as the admission
// crate's integration scaffolding: REAL identities, REAL signed link
// evidence, REAL provider observations admitted through the protocol
// core's registry and projected through a REAL R5-003 durable store).
// ---------------------------------------------------------------------------

/// The link id every testkit link evidence carries (a fixed test value).
pub const LINK_ID: [u8; 32] = [0x51; 32];
/// The R5-003 store's provider freshness window (the testkit timeline:
/// links observed at NOW-8 valid 600 s; streams activated NOW-10 and
/// assured NOW-5 → every candidate is fresh around NOW, and the
/// eligible decision's `valid_until` is the link bound NOW+592).
pub const STORE_WINDOW_SECS: u64 = 600;

/// A node's derived id bytes.
pub fn node_id(identity: &Identity) -> [u8; 32] {
    *identity.node_id().as_bytes()
}

/// The testkit admission policy: a 600 s evidence-freshness window, a
/// 50_000 ppm loss floor and a 200 ms latency bound — generous enough for
/// the good-quality links, tight enough for the lying ones to fail.
pub fn admission_policy() -> GatewayAdmissionPolicy {
    GatewayAdmissionPolicy::new(
        AdmissionParams::new(600, 50_000, 200).expect("valid admission params"),
    )
}

/// A link quality snapshot (p50 always half of p95 — the protocol's
/// `p95 >= p50` invariant).
pub fn link_quality(delivered: u64, lost: u64, stated_ppm: u64, p95_micros: u64) -> LinkQualitySnapshot {
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

/// Build + sign real R3-003 link evidence: `observer` attests a link to
/// `subject_node_id` (established 100 s before the observation).
pub fn link_evidence(
    observer: &Identity,
    subject_node_id: [u8; 32],
    observed_at: u64,
    quality: LinkQualitySnapshot,
) -> SignedTopologyEvidence {
    TopologyEvidence::new(
        observer,
        subject_node_id,
        Observation::Link {
            link_id: LINK_ID,
            established_at_unix: observed_at.saturating_sub(100),
            quality,
        },
        observed_at,
        600,
    )
    .expect("evidence")
    .sign(observer)
    .expect("signed by the observer")
}

/// Build + sign a real R5-004 provider observation.
pub fn signed_observation(
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

/// The canonical two-observation ADCOS stream for a contract
/// (`contract_activated` then `assurance_available` with counters) — the
/// same stream shape the admission crate's own tests use.
pub fn canonical_stream(
    provider: &Identity,
    contract: &ConnectivityContractRef,
    now: u64,
) -> Vec<SignedConnectivityObservation> {
    vec![
        signed_observation(provider, contract, EvidenceKind::ContractActivated, now - 10, 1, None),
        signed_observation(
            provider,
            contract,
            EvidenceKind::AssuranceAvailable,
            now - 5,
            2,
            Some(BTreeMap::from([
                ("throughput_bps".to_string(), 10_000_000),
                ("latency_ms".to_string(), 40),
            ])),
        ),
    ]
}

/// Feed a REAL R5-003 durable store through the verified path (the
/// protocol core's `ObservationAdmission` first, then the domain
/// mapping, then `accept` + `flush`) and return the contract's health
/// view — the exact evidence object a daemon's selection caller holds.
pub fn verified_health(
    signed: &[SignedConnectivityObservation],
    contract: &ConnectivityContractRef,
    now: u64,
    path: &Path,
) -> sharenet_connectivity::ContractHealth {
    let mut admission = ObservationAdmission::new(STORE_WINDOW_SECS);
    admission.register_contract(*contract.id());
    let mut store = DurableProjectionStore::create(path, STORE_WINDOW_SECS).expect("store");
    for observation in signed {
        admission.receive(observation, now).expect("registry admission");
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

/// The deterministic R7-003 world: a recovering node, a witness (a path
/// member that is not a gateway), four candidate gateways, two observers
/// and two backhaul providers — with every candidate's evidence built
/// through the REAL production paths (R3-003 signing, R5-004 registry
/// admission, R5-003 durable projection).
///
/// The timeline (relative to `now`): links observed at `now-8` (valid
/// 600 s → `now+592`), streams activated `now-10` / assured `now-5`
/// (window 600 s → `now+595`) — so an eligible decision at `now+3`
/// carries `valid_until_unix = now+592` (the earlier bound).
pub struct GatewayWorld {
    /// The node performing the recovery (proposes the fresh route).
    pub recovering: Identity,
    /// A non-gateway path member (for routes that must NOT carry the
    /// selected gateway — the path-membership refusal leg).
    pub witness: Identity,
    /// The observer attesting the G1/G2 links (factor 1).
    pub observer: Identity,
    /// G1: the fully eligible gateway.
    pub g1: Identity,
    /// G1's backhaul provider (factor 2).
    pub provider1: Identity,
    /// G2: a gateway with no ADCOS backhaul evidence.
    pub g2: Identity,
    /// G3: a gateway presenting link evidence about a DIFFERENT node.
    pub g3: Identity,
    /// The observer attesting the G3/G4 links.
    pub observer2: Identity,
    /// G4: a second fully eligible gateway (the tie-break tests).
    pub g4: Identity,
    /// G4's backhaul provider.
    pub provider2: Identity,
    // -- owned evidence (the candidate builders borrow it) -----------------
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

/// G1's backhaul contract (opaque provider-assigned id).
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

pub fn gateway_world(now: u64) -> GatewayWorld {
    let dir = TempDir::new("gateway-world");
    let recovering = ident(0xA1, now);
    let witness = ident(0xA2, now);
    let observer = ident(0xC0, now);
    let g1 = ident(0xC1, now);
    let provider1 = ident(0xC2, now);
    let g2 = ident(0xC3, now);
    let g3 = ident(0xC4, now);
    let observer2 = ident(0xC5, now);
    let g4 = ident(0xC6, now);
    let provider2 = ident(0xC7, now);

    // The good quality: 5,000 ppm effective loss (counters agree with
    // the stated ratio), 45 ms p95 — inside the testkit policy's floor.
    let good = link_quality(995_000, 5_000, 5_000, 45_000);
    // The lying quality: the STATED ratio is 1 ppm, the signed counters
    // say 200,000 ppm — the policy evaluates on the counters (R5-005).
    let lying = link_quality(800_000, 200_000, 1, 45_000);

    let link_g1 = link_evidence(&observer, node_id(&g1), now - 8, good.clone());
    // G1's evidence with one flipped SIGNATURE byte — the Ed25519
    // verification must fail (a candidate presenting forged evidence).
    let mut tampered_sig = *link_g1.signature();
    tampered_sig[0] ^= 0x01;
    let link_g1_tampered =
        SignedTopologyEvidence::from_parts(link_g1.evidence_bytes().to_vec(), tampered_sig);
    let link_g2 = link_evidence(&observer, node_id(&g2), now - 8, good.clone());
    // G3 presents evidence ABOUT G2's node (wrong subject — evidence
    // never transfers between gateways).
    let link_g3_wrong_subject = link_evidence(&observer2, node_id(&g2), now - 8, good.clone());
    let link_g4 = link_evidence(&observer2, node_id(&g4), now - 8, good.clone());
    let link_g4_lying = link_evidence(&observer2, node_id(&g4), now - 8, lying);

    let signed_g1 = canonical_stream(&provider1, &contract_g1(), now);
    let signed_g3 = canonical_stream(&provider1, &contract_g3(), now);
    let signed_g4 = canonical_stream(&provider2, &contract_g4(), now);
    let health_g1 = verified_health(&signed_g1, &contract_g1(), now, &dir.path.join("g1.store"));
    let health_g3 = verified_health(&signed_g3, &contract_g3(), now, &dir.path.join("g3.store"));
    let health_g4 = verified_health(&signed_g4, &contract_g4(), now, &dir.path.join("g4.store"));

    GatewayWorld {
        recovering,
        witness,
        observer,
        g1,
        provider1,
        g2,
        g3,
        observer2,
        g4,
        provider2,
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
    /// The gateway identity for a selected node id (the testkit's own
    /// gateways; panics on anything else — a test bug, not a case).
    pub fn gateway_identity(&self, gateway_node_id: &[u8; 32]) -> &Identity {
        [&self.g1, &self.g2, &self.g3, &self.g4]
            .into_iter()
            .find(|g| g.node_id().as_bytes() == gateway_node_id)
            .expect("a testkit gateway")
    }

    /// G1's candidate: the fully eligible gateway (both factors verified,
    /// in floor).
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

    /// G1's candidate presenting FORGED link evidence (one signature byte
    /// flipped): never selectable.
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

    /// G2's candidate: a good link but NO ADCOS backhaul evidence —
    /// ineligible (`adcos_evidence_missing`).
    pub fn candidate_no_backhaul(&self) -> GatewayCandidate<'_> {
        GatewayCandidate {
            gateway_node_id: node_id(&self.g2),
            sharenet_link: Some(&self.link_g2),
            adcos_backhaul: None,
        }
    }

    /// G3's candidate: link evidence about a DIFFERENT node (G2's) plus a
    /// healthy backhaul — ineligible (`sharenet_evidence_wrong_subject`).
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

    /// G4's candidate: a second fully eligible gateway (independent
    /// observer, provider and contract — for the tie-break tests).
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

    /// G4's candidate presenting COUNTER-DISAGREEING quality evidence
    /// (the stated ratio lies low; the signed counters say 20% loss) —
    /// ineligible (`quality_below_floor`), the R5-005 law.
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
// The R7-003 fresh-route material (the R3-004 seams: proposal →
// acceptances → commitment; every signature real)
// ---------------------------------------------------------------------------

/// The signed R3-004 material for a fresh route: the recovering node's
/// signed proposal, every path member's signed acceptance, and the
/// commitment-derived route id an INDEPENDENT build yields (the tests'
/// expected value).
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
    let proposal =
        RouteProposal::new(proposer, path, "live", at, 3600, nonce).expect("proposal");
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

/// The fresh-route material through the selected gateway: the recovering
/// node proposes a two-member route (itself + the gateway), both members
/// sign acceptances. `at` is the proposal time — the §11 freshness
/// (`proposed_at` vs. the revocation anchor) is exactly what varies with
/// it.
pub fn fresh_route_material(
    w: &GatewayWorld,
    selected: &SelectedGateway,
    at: u64,
) -> FreshRouteMaterial {
    let gateway = w.gateway_identity(&selected.gateway_node_id);
    build_route_material(&w.recovering, &[&w.recovering, gateway], at, [0x43; 32])
}

/// Fresh-route material for a route that does NOT carry the selected
/// gateway (the recovering node + the witness): a well-formed, fully
/// signed commitment the path-membership cross-check must refuse.
pub fn fresh_route_material_skipping_gateway(
    w: &GatewayWorld,
    at: u64,
) -> FreshRouteMaterial {
    build_route_material(&w.recovering, &[&w.recovering, &w.witness], at, [0x44; 32])
}
