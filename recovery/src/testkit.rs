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

use sharenet_protocol::circuit::{derive_circuit_id, CircuitRegistry, CircuitSetup, CircuitSetupAck};
use sharenet_protocol::identity::Identity;
use sharenet_protocol::revocation::{
    CircuitRevocation, EvidenceValue, RevocationReason, SignedCircuitRevocation,
    EVIDENCE_FAILURE_KIND,
};
use sharenet_protocol::route::{
    derive_proposal_id, RouteAcceptance, RouteCommitment, RouteProposal, SignedEnvelope,
};

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
