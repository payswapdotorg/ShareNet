//! Shared test scaffolding for the R7-002 suites — the same world shape
//! as the protocol core's revocation tests (identities → committed
//! route → established circuit → revocation), plus temp-dir helpers.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use sharenet_protocol::circuit::{derive_circuit_id, CircuitRegistry, CircuitSetup, CircuitSetupAck};
use sharenet_protocol::identity::Identity;
use sharenet_protocol::revocation::{
    CircuitRevocation, EvidenceValue, RevocationReason, SignedCircuitRevocation,
    EVIDENCE_FAILURE_KIND,
};
use sharenet_protocol::route::{
    derive_proposal_id, RouteAcceptance, RouteCommitment, RouteProposal,
};

/// A deterministic base time for all test timestamps.
pub const NOW: u64 = 1_700_000_000;

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
