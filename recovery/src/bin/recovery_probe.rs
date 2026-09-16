//! `recovery_probe` — TEST SCAFFOLDING for the R7-003 + R7-004
//! "multiprocess" verify levels: a REAL separate process per §11 pipeline
//! stage, each seeing the recovery state ONLY through the bytes on disk
//! (the two durable files in the driver's directory). The ShareNet daemon
//! is modeled as a sequence of probe invocations:
//!
//! - process 1 (`setup`, `zeroize`, `open-attempt`) admits a revocation
//!   for a deterministically derived circuit, records the §11
//!   zeroization fact, and opens the recovery attempt;
//! - process 2 (`select`, `establish`) selects a fresh gateway from a
//!   deterministically built candidate set (real R3-003/R5-004/R5-003
//!   evidence, verified by the composed R5-005 policy) and succeeds the
//!   attempt with a fresh route commitment through the selected gateway;
//! - process 3 (`establish-replacement`) builds the signed R4-002
//!   replacement material over the recorded fresh route (rebuilt
//!   deterministically — a mismatch with the durable record is the
//!   probe's own typed failure) and establishes the replacement circuit
//!   through a fresh registry the driver itself gates with its R7-001
//!   ledger view;
//! - process 4 (`state`) reloads from disk and reports the terminal
//!   state, the zeroization fact, and the replacement circuit fact.
//!
//! Everything is DETERMINISTIC: identities come from fixed seeds, so
//! every invocation of every subcommand re-derives the same world (the
//! same circuit id, the same candidate set, the same selection) — the
//! only cross-process state is the durable directory.
//!
//! Usage:
//!
//! ```text
//! recovery_probe setup                 <dir> <now>
//! recovery_probe zeroize               <dir> <now>
//! recovery_probe open-attempt          <dir> <now>
//! recovery_probe select                <dir> <now>
//! recovery_probe select-none           <dir> <now>
//! recovery_probe establish             <dir> <now> <gateway_hex>
//! recovery_probe establish-replacement <dir> <now> <route_at>
//! recovery_probe state                  <dir>
//! ```
//!
//! stdout protocol (machine-parsable, one record per line):
//!
//! ```text
//! CIRCUIT <hex> <revoked_at>                     (setup)
//! STEP select_fresh_gateway <circuit_hex> <attempt_seq>   (open-attempt)
//! CANDIDATE <hex> eligible|ineligible           (select/select-none, per candidate)
//! SELECTED <hex> <valid_until_unix>              (select)
//! ROUTE <hex>                                    (establish / establish-replacement)
//! ATTEMPT succeeded <attempt_seq>               (establish)
//! GATEWAY <hex>                                  (establish)
//! ZEROIZED <circuit_hex> <at>                    (zeroize)
//! REPLACEMENT <circuit_hex>                      (establish-replacement)
//! REPLACEMENT-ATTEMPT <attempt_seq>             (establish-replacement)
//! ESTABLISHED yes                                 (establish-replacement)
//! LATEST <state> <attempt_seq> <route_hex|->     (state)
//! REVOKED yes|no                                 (state)
//! ZEROIZED <at>|no                                (state)
//! REPLACEMENT <hex>|-                            (state)
//! ATTEMPTS <count>                               (state)
//! ERROR <recovery_error_machine_name>            (on any typed failure)
//! ```
//!
//! Exit codes: 0 ok; 2 usage error; 3 typed failure (fail-closed,
//! printed typed — including the probe-level `selected_gateway_mismatch`
//! when the `establish` argument disagrees with the deterministic
//! re-derivation of the selection, and `route_rebuild_mismatch` when the
//! `establish-replacement` rebuild of the recorded fresh route derives a
//! different route id).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;

use sharenet_admission::{
    AdcosBackhaulEvidence, AdmissionParams, GatewayAdmissionPolicy, GatewayAdmissionRequest,
};
use sharenet_connectivity::{
    AcceptOutcome, ConnectivityContractRef, ConnectivityObservation, DurableProjectionStore,
    ObservationKind, RefKind,
};
use sharenet_recovery::{select_eligible_gateway, 
    FreshRoute, GatewayCandidate, RecoveryDriver, RecoveryError, RecoveryStep, SelectedGateway,
};
use sharenet_protocol::circuit::{derive_circuit_id, CircuitRegistry, CircuitSetup, CircuitSetupAck};
use sharenet_protocol::identity::Identity;
use sharenet_protocol::revocation::{
    CircuitRevocation, EvidenceValue, RevocationReason, EVIDENCE_FAILURE_KIND,
};
use sharenet_protocol::route::{
    derive_proposal_id, RouteAcceptance, RouteCommitment, RouteProposal, SignedEnvelope,
};
use sharenet_protocol::topology::SignedTopologyEvidence;
use sharenet_protocol::{
    ConnectivityObservationStatement, EvidenceKind, LinkQualitySnapshot, Observation,
    ObservationAdmission, SignedConnectivityObservation, TopologyEvidence,
};

/// The fixed evidence timeline base: every candidate's evidence is built
/// relative to this constant (links observed BASE-8, streams activated
/// BASE-10 / assured BASE-5) so any decision clock in
/// (BASE, BASE+592) sees the same eligibility — the `now` ARG is purely
/// the decision clock, exactly like the library API.
const BASE: u64 = 1_700_000_000;
/// The R5-003 store window the probe's health views are built with.
const STORE_WINDOW_SECS: u64 = 600;

// The deterministic world's seeds (identical in every invocation).
const SEED_RECOVERING: u8 = 0xB1;
const SEED_HOP1: u8 = 0xB2;
const SEED_HOP2: u8 = 0xB3;
const SEED_OBSERVER: u8 = 0xC0;
const SEED_G1: u8 = 0xC1;
const SEED_PROVIDER1: u8 = 0xC2;
const SEED_G2: u8 = 0xC3;
const SEED_G3: u8 = 0xC4;
const SEED_OBSERVER2: u8 = 0xC5;
const SEED_G4: u8 = 0xC6;
const SEED_PROVIDER2: u8 = 0xC7;
/// The nonce of the (to-be-revoked) circuit.
const CIRCUIT_NONCE: [u8; 32] = [0x91; 32];
/// The setup nonce of the REPLACEMENT circuit (a different nonce over
/// the fresh route — L014 fresh session identity).
const REPLACEMENT_NONCE: [u8; 32] = [0x92; 32];

fn ident(seed: u8) -> Identity {
    Identity::from_seed([seed; 32], BASE - 86_400, None).expect("identity from seed")
}

fn node_id(identity: &Identity) -> [u8; 32] {
    *identity.node_id().as_bytes()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    let bytes = s.as_bytes();
    if bytes.len() != 64 || !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[2 * i] as char).to_digit(16)?;
        let lo = (bytes[2 * i + 1] as char).to_digit(16)?;
        *slot = (hi * 16 + lo) as u8;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// The deterministic revoked-circuit world (process 1)
// ---------------------------------------------------------------------------

/// The three-member committed route of the to-be-revoked circuit
/// (recovering node + two hops), built through the R3-004 seams.
fn revoked_world_route() -> (Identity, SignedEnvelope, Vec<SignedEnvelope>) {
    let recovering = ident(SEED_RECOVERING);
    let hop1 = ident(SEED_HOP1);
    let hop2 = ident(SEED_HOP2);
    let mut path: Vec<[u8; 32]> =
        [node_id(&recovering), node_id(&hop1), node_id(&hop2)].to_vec();
    path.sort();
    let proposal =
        RouteProposal::new(&recovering, path, "live", BASE, 3600, [0x42; 32]).expect("proposal");
    let proposal_env = proposal.sign(&recovering).expect("sign");
    let proposal_id = derive_proposal_id(proposal_env.bytes());
    let mut members: Vec<&Identity> = vec![&recovering, &hop1, &hop2];
    members.sort_by_key(|m| node_id(m));
    let acceptance_envs: Vec<_> = members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let acceptance =
                RouteAcceptance::new(m, proposal_id, i as u64, BASE, 3600).expect("acceptance");
            acceptance.sign(m).expect("sign")
        })
        .collect();
    (recovering, proposal_env, acceptance_envs)
}

/// The revoked circuit's id (deterministic: same seeds → same id in every
/// process).
fn revoked_circuit_id() -> [u8; 32] {
    let (_recovering, proposal_env, acceptance_envs) = revoked_world_route();
    let commitment =
        RouteCommitment::build(BASE, proposal_env, acceptance_envs).expect("commitment");
    derive_circuit_id(commitment.route_id(), &CIRCUIT_NONCE)
}

/// The registry with the circuit established (admit_setup + every member
/// ack) — what the R7-001 admission chain verifies the revoker's path
/// membership against.
fn established_registry() -> CircuitRegistry {
    let (recovering, proposal_env, acceptance_envs) = revoked_world_route();
    let commitment =
        RouteCommitment::build(BASE, proposal_env, acceptance_envs).expect("commitment");
    let mut registry = CircuitRegistry::new();
    let setup =
        CircuitSetup::new(&commitment, &recovering, CIRCUIT_NONCE, BASE, 600).expect("setup");
    let setup_env = setup.sign(&recovering).expect("sign");
    let circuit_id = derive_circuit_id(commitment.route_id(), &CIRCUIT_NONCE);
    registry.admit_setup(BASE, &setup_env).expect("admit setup");
    let path = commitment.verify(BASE).expect("verify").proposal.path().to_vec();
    let hop1 = ident(SEED_HOP1);
    let hop2 = ident(SEED_HOP2);
    for (pos, want) in path.iter().enumerate() {
        let member = [&recovering, &hop1, &hop2]
            .into_iter()
            .find(|m| m.node_id().as_bytes() == want)
            .expect("member");
        let ack =
            CircuitSetupAck::new(circuit_id, &setup_env, member, pos as u64, BASE, 500).expect("ack");
        let env = ack.sign(member).expect("sign");
        registry.admit_ack(BASE, &env).expect("admit ack");
    }
    registry
}

// ---------------------------------------------------------------------------
// The deterministic candidate set (process 2)
// ---------------------------------------------------------------------------

struct CandidateMaterial {
    node_id: [u8; 32],
    link: SignedTopologyEvidence,
    health: Option<sharenet_connectivity::ContractHealth>,
    signed: Vec<SignedConnectivityObservation>,
}

impl CandidateMaterial {
    fn candidate(&self) -> GatewayCandidate<'_> {
        GatewayCandidate {
            gateway_node_id: self.node_id,
            sharenet_link: Some(&self.link),
            adcos_backhaul: self.health.as_ref().map(|health| AdcosBackhaulEvidence {
                health: Some(health),
                signed_observations: &self.signed,
            }),
        }
    }
}

fn good_quality() -> LinkQualitySnapshot {
    LinkQualitySnapshot {
        delivered: 995_000,
        lost: 5_000,
        ewma_rtt_micros: 23_500,
        p50_rtt_micros: 22_500,
        p95_rtt_micros: 45_000,
        jitter_mad_micros: 500,
        loss_ratio_ppm: 5_000,
    }
}

fn link_evidence(
    observer: &Identity,
    subject_node_id: [u8; 32],
) -> SignedTopologyEvidence {
    TopologyEvidence::new(
        observer,
        subject_node_id,
        Observation::Link {
            link_id: [0x51; 32],
            established_at_unix: BASE - 108,
            quality: good_quality(),
        },
        BASE - 8,
        600,
    )
    .expect("evidence")
    .sign(observer)
    .expect("signed")
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
    .expect("signed")
}

fn canonical_stream(
    provider: &Identity,
    contract: &ConnectivityContractRef,
) -> Vec<SignedConnectivityObservation> {
    vec![
        signed_observation(provider, contract, EvidenceKind::ContractActivated, BASE - 10, 1, None),
        signed_observation(
            provider,
            contract,
            EvidenceKind::AssuranceAvailable,
            BASE - 5,
            2,
            Some(BTreeMap::from([
                ("throughput_bps".to_string(), 10_000_000),
                ("latency_ms".to_string(), 40),
            ])),
        ),
    ]
}

/// Feed a real R5-003 durable store through the verified path (the
/// protocol core's registry admission → the domain mapping → accept →
/// flush) and return the health view — the daemon's selection input.
fn verified_health(
    signed: &[SignedConnectivityObservation],
    contract: &ConnectivityContractRef,
    path: &std::path::Path,
) -> sharenet_connectivity::ContractHealth {
    let mut admission = ObservationAdmission::new(STORE_WINDOW_SECS);
    admission.register_contract(*contract.id());
    let mut store = DurableProjectionStore::create(path, STORE_WINDOW_SECS).expect("store");
    for observation in signed {
        admission.receive(observation, BASE).expect("registry admission");
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
    store.health(contract).expect("tracked contract")
}

/// The default candidate set: G1 (eligible), G2 (no ADCOS backhaul),
/// G3 (link evidence about a different node) and G4 (a second eligible
/// gateway) — the selection's deterministic tie-break picks the lower
/// node id among {G1, G4}.
fn default_candidates(store_dir: &std::path::Path) -> Vec<CandidateMaterial> {
    let observer = ident(SEED_OBSERVER);
    let observer2 = ident(SEED_OBSERVER2);
    let g1 = ident(SEED_G1);
    let provider1 = ident(SEED_PROVIDER1);
    let g2 = ident(SEED_G2);
    let g3 = ident(SEED_G3);
    let g4 = ident(SEED_G4);
    let provider2 = ident(SEED_PROVIDER2);
    let contract_g1 = ConnectivityContractRef::from_id([0xD1; 32]);
    let contract_g3 = ConnectivityContractRef::from_id([0xD3; 32]);
    let contract_g4 = ConnectivityContractRef::from_id([0xD4; 32]);

    let signed_g1 = canonical_stream(&provider1, &contract_g1);
    let health_g1 = verified_health(&signed_g1, &contract_g1, &store_dir.join("g1.store"));
    let signed_g3 = canonical_stream(&provider1, &contract_g3);
    let health_g3 = verified_health(&signed_g3, &contract_g3, &store_dir.join("g3.store"));
    let signed_g4 = canonical_stream(&provider2, &contract_g4);
    let health_g4 = verified_health(&signed_g4, &contract_g4, &store_dir.join("g4.store"));

    vec![
        // G1: the fully eligible gateway.
        CandidateMaterial {
            node_id: node_id(&g1),
            link: link_evidence(&observer, node_id(&g1)),
            health: Some(health_g1),
            signed: signed_g1,
        },
        // G2: a good link, but no ADCOS backhaul evidence.
        CandidateMaterial {
            node_id: node_id(&g2),
            link: link_evidence(&observer, node_id(&g2)),
            health: None,
            signed: Vec::new(),
        },
        // G3: link evidence about G2's node (wrong subject).
        CandidateMaterial {
            node_id: node_id(&g3),
            link: link_evidence(&observer2, node_id(&g2)),
            health: Some(health_g3),
            signed: signed_g3,
        },
        // G4: a second fully eligible gateway.
        CandidateMaterial {
            node_id: node_id(&g4),
            link: link_evidence(&observer2, node_id(&g4)),
            health: Some(health_g4),
            signed: signed_g4,
        },
    ]
}

/// The ineligible-only candidate set (G2 + G3).
fn ineligible_candidates(store_dir: &std::path::Path) -> Vec<CandidateMaterial> {
    default_candidates(store_dir)
        .into_iter()
        .filter(|c| c.node_id == node_id(&ident(SEED_G2)) || c.node_id == node_id(&ident(SEED_G3)))
        .collect()
}

fn admission_policy() -> GatewayAdmissionPolicy {
    GatewayAdmissionPolicy::new(
        AdmissionParams::new(600, 50_000, 200).expect("valid admission params"),
    )
}

/// A unique temp directory for the probe's projection stores, removed on
/// drop.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "sharenet-r7003-probe-{}-{}",
            tag,
            std::process::id()
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

/// The selected gateway for the open attempt, derived by running the
/// library's own selection over the deterministic candidate set at
/// `now`.
fn select_from(
    driver: &RecoveryDriver,
    step: &RecoveryStep,
    store_dir: &std::path::Path,
    now: u64,
) -> Result<(SelectedGateway, Vec<CandidateMaterial>), RecoveryError> {
    let material = default_candidates(store_dir);
    let candidates: Vec<GatewayCandidate<'_>> = material.iter().map(|c| c.candidate()).collect();
    driver
        .select_gateway(step, &candidates, &admission_policy(), now)
        .map(|selected| (selected, material))
}

// ---------------------------------------------------------------------------
// The subcommands
// ---------------------------------------------------------------------------

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd, rest @ ..] => dispatch(cmd, rest),
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}

fn usage() {
    eprintln!("usage: recovery_probe setup <dir> <now>");
    eprintln!("       recovery_probe zeroize <dir> <now>");
    eprintln!("       recovery_probe open-attempt <dir> <now>");
    eprintln!("       recovery_probe select <dir> <now>");
    eprintln!("       recovery_probe select-none <dir> <now>");
    eprintln!("       recovery_probe establish <dir> <now> <gateway_hex>");
    eprintln!("       recovery_probe establish-replacement <dir> <now> <route_at>");
    eprintln!("       recovery_probe state <dir>");
}

fn dispatch(cmd: &str, rest: &[String]) -> ExitCode {
    match cmd {
        "setup" => cmd_setup(rest),
        "zeroize" => cmd_zeroize(rest),
        "open-attempt" => cmd_open_attempt(rest),
        "select" => cmd_select(rest, false),
        "select-none" => cmd_select(rest, true),
        "establish" => cmd_establish(rest),
        "establish-replacement" => cmd_establish_replacement(rest),
        "state" => cmd_state(rest),
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}

/// Report a typed library failure (machine name + exit 3).
fn fail(error: &RecoveryError) -> ExitCode {
    println!("ERROR {}", error.name());
    ExitCode::from(3)
}

fn parse_now(s: &str) -> Option<u64> {
    s.parse::<u64>().ok()
}

/// Process 1a: build the deterministic world, establish the circuit in a
/// registry, admit hop1's link-failure revocation at `now`.
fn cmd_setup(rest: &[String]) -> ExitCode {
    let [dir, now_s] = rest else {
        usage();
        return ExitCode::from(2);
    };
    let Some(now) = parse_now(now_s) else {
        usage();
        return ExitCode::from(2);
    };
    let (driver, _) = match RecoveryDriver::open(std::path::Path::new(dir)) {
        Ok(opened) => opened,
        Err(err) => return fail(&err),
    };
    let circuit = revoked_circuit_id();
    let hop1 = ident(SEED_HOP1);
    let mut evidence = BTreeMap::new();
    evidence.insert(
        EVIDENCE_FAILURE_KIND.to_string(),
        EvidenceValue::Text("link_failure".to_string()),
    );
    evidence.insert("missed_acks".to_string(), EvidenceValue::Int(3));
    let revocation = CircuitRevocation::new(
        &hop1,
        circuit,
        RevocationReason::LinkFailure,
        Some(evidence),
        now,
    )
    .expect("revocation");
    let signed = revocation.sign(&hop1).expect("sign");
    match driver.admit_revocation_envelope(now, &signed.to_envelope_bytes(), &established_registry())
    {
        Ok(outcome) => {
            println!("CIRCUIT {} {}", hex(&circuit), now);
            println!("OUTCOME {}", outcome.as_str());
            ExitCode::SUCCESS
        }
        Err(err) => fail(&err),
    }
}

/// Process 1b: open the next recovery attempt for the (derived) revoked
/// circuit.
fn cmd_open_attempt(rest: &[String]) -> ExitCode {
    let [dir, now_s] = rest else {
        usage();
        return ExitCode::from(2);
    };
    let Some(now) = parse_now(now_s) else {
        usage();
        return ExitCode::from(2);
    };
    let (driver, _) = match RecoveryDriver::open(std::path::Path::new(dir)) {
        Ok(opened) => opened,
        Err(err) => return fail(&err),
    };
    let circuit = revoked_circuit_id();
    match driver.attempt_next(&circuit, now) {
        Ok(step) => {
            let RecoveryStep::SelectFreshGateway { attempt_seq, .. } = step;
            println!("STEP select_fresh_gateway {} {}", hex(&circuit), attempt_seq);
            ExitCode::SUCCESS
        }
        Err(err) => fail(&err),
    }
}

/// Process 2a: select a fresh gateway from the deterministic candidate
/// set (`ineligible_only` swaps in the refused-only set — the typed
/// refusal leg).
fn cmd_select(rest: &[String], ineligible_only: bool) -> ExitCode {
    let [dir, now_s] = rest else {
        usage();
        return ExitCode::from(2);
    };
    let Some(now) = parse_now(now_s) else {
        usage();
        return ExitCode::from(2);
    };
    let (driver, _) = match RecoveryDriver::open(std::path::Path::new(dir)) {
        Ok(opened) => opened,
        Err(err) => return fail(&err),
    };
    let stores = TempDir::new("select");
    let material = if ineligible_only {
        ineligible_candidates(&stores.path)
    } else {
        default_candidates(&stores.path)
    };
    let candidates: Vec<GatewayCandidate<'_>> = material.iter().map(|c| c.candidate()).collect();
    let policy = admission_policy();
    // The per-candidate verdicts (the evidence, machine-parsable).
    for candidate in &candidates {
        let decision = policy.decide(GatewayAdmissionRequest {
            gateway_node_id: candidate.gateway_node_id,
            now_unix: now,
            sharenet_link: candidate.sharenet_link,
            adcos_backhaul: candidate.adcos_backhaul,
        });
        let verdict = if decision.is_eligible() { "eligible" } else { "ineligible" };
        println!("CANDIDATE {} {}", hex(&candidate.gateway_node_id), verdict);
    }
    // The circuit's open attempt (the last-retained pending one).
    let circuit = revoked_circuit_id();
    let Some(pending) = driver.attempt_log().pending_attempt(&circuit) else {
        println!("ERROR no_pending_attempt");
        return ExitCode::from(3);
    };
    let step = RecoveryStep::SelectFreshGateway {
        revoked_circuit_id: circuit,
        attempt_seq: pending.attempt_seq(),
    };
    match driver.select_gateway(&step, &candidates, &policy, now) {
        Ok(selected) => {
            println!("SELECTED {} {}", hex(&selected.gateway_node_id), selected.valid_until_unix);
            ExitCode::SUCCESS
        }
        Err(err) => fail(&err),
    }
}

/// Process 2b: re-derive the selection (deterministic: the same candidate
/// set + clock in a NEW process must select the same gateway — a
/// mismatch with `<gateway_hex>` is the probe-level typed failure), build
/// the fresh route through the selected gateway (the R3-004 seams) and
/// durably succeed the attempt.
fn cmd_establish(rest: &[String]) -> ExitCode {
    let [dir, now_s, gateway_hex] = rest else {
        usage();
        return ExitCode::from(2);
    };
    let Some(now) = parse_now(now_s) else {
        usage();
        return ExitCode::from(2);
    };
    let Some(gateway) = parse_hex32(gateway_hex) else {
        usage();
        return ExitCode::from(2);
    };
    let (driver, _) = match RecoveryDriver::open(std::path::Path::new(dir)) {
        Ok(opened) => opened,
        Err(err) => return fail(&err),
    };
    let stores = TempDir::new("establish");
    let circuit = revoked_circuit_id();
    let Some(pending) = driver.attempt_log().pending_attempt(&circuit) else {
        println!("ERROR no_pending_attempt");
        return ExitCode::from(3);
    };
    let step = RecoveryStep::SelectFreshGateway {
        revoked_circuit_id: circuit,
        attempt_seq: pending.attempt_seq(),
    };
    let (selected, _material) =
        match select_from(&driver, &step, &stores.path, now) {
            Ok(found) => found,
            Err(err) => return fail(&err),
        };
    if selected.gateway_node_id != gateway {
        println!("ERROR selected_gateway_mismatch");
        return ExitCode::from(3);
    }
    // The fresh route: the recovering node proposes the two-member route
    // (itself + the selected gateway), both members sign acceptances.
    let gateway_identity = [ident(SEED_G1), ident(SEED_G2), ident(SEED_G3), ident(SEED_G4)]
        .into_iter()
        .find(|g| node_id(g) == selected.gateway_node_id)
        .expect("a probe gateway");
    let recovering = ident(SEED_RECOVERING);
    let mut path: Vec<[u8; 32]> = [node_id(&recovering), selected.gateway_node_id].to_vec();
    path.sort();
    let proposal =
        RouteProposal::new(&recovering, path, "live", now, 3600, [0x43; 32]).expect("proposal");
    let proposal_env = proposal.sign(&recovering).expect("sign");
    let proposal_id = derive_proposal_id(proposal_env.bytes());
    let mut members: Vec<&Identity> = vec![&recovering, &gateway_identity];
    members.sort_by_key(|m| node_id(m));
    let acceptance_envs: Vec<SignedEnvelope> = members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let acceptance =
                RouteAcceptance::new(m, proposal_id, i as u64, now, 3600).expect("acceptance");
            acceptance.sign(m).expect("sign")
        })
        .collect();
    match driver.establish_fresh_route(&selected, &proposal_env, &acceptance_envs, now) {
        Ok(route) => {
            println!("ROUTE {}", hex(&route.route_id));
            println!("ATTEMPT succeeded {}", route.attempt_seq);
            println!("GATEWAY {}", hex(&route.gateway_node_id));
            ExitCode::SUCCESS
        }
        Err(err) => fail(&err),
    }
}

/// Process 1b: record the §11 `zeroization` fact for the (derived)
/// revoked circuit — the durable, at-most-once step between durable
/// invalidation and the new session.
fn cmd_zeroize(rest: &[String]) -> ExitCode {
    let [dir, now_s] = rest else {
        usage();
        return ExitCode::from(2);
    };
    let Some(now) = parse_now(now_s) else {
        usage();
        return ExitCode::from(2);
    };
    let (driver, _) = match RecoveryDriver::open(std::path::Path::new(dir)) {
        Ok(opened) => opened,
        Err(err) => return fail(&err),
    };
    let circuit = revoked_circuit_id();
    match driver.record_zeroization(&circuit, now) {
        Ok(record) => {
            println!("ZEROIZED {} {}", hex(&circuit), record.zeroized_at_unix());
            ExitCode::SUCCESS
        }
        Err(err) => fail(&err),
    }
}

/// Process 3: establish the REPLACEMENT circuit (R7-004, the §11 `fresh
/// circuit session` stage) over the recorded fresh route. The fresh
/// route's R3-004 material is REBUILT deterministically at `route_at`
/// (the clock the `establish` invocation committed the route at) and
/// cross-checked against the DURABLE record — a mismatch is the probe's
/// own typed failure, proving the rebuild is faithful. The signed
/// R4-002 material (the recovering node's `CircuitSetup` over the fresh
/// commitment + every path member's `CircuitSetupAck`, all with the
/// fixed `REPLACEMENT_NONCE` — a DIFFERENT nonce from the revoked
/// circuit's, L014 fresh session identity) is then admitted through a
/// FRESH registry the driver itself gates with its R7-001 ledger view.
fn cmd_establish_replacement(rest: &[String]) -> ExitCode {
    let [dir, now_s, route_at_s] = rest else {
        usage();
        return ExitCode::from(2);
    };
    let Some(now) = parse_now(now_s) else {
        usage();
        return ExitCode::from(2);
    };
    let Some(route_at) = parse_now(route_at_s) else {
        usage();
        return ExitCode::from(2);
    };
    let (driver, _) = match RecoveryDriver::open(std::path::Path::new(dir)) {
        Ok(opened) => opened,
        Err(err) => return fail(&err),
    };
    let circuit = revoked_circuit_id();
    // The durable record's terminal attempt — the fresh-route hand-off
    // is constructed from the record itself, never from thin air.
    let latest = match driver.attempt_log().latest_attempt(&circuit) {
        Some(latest) => latest,
        None => {
            println!("ERROR no_succeeded_attempt");
            return ExitCode::from(3);
        }
    };
    let Some(recorded_route) = latest.fresh_route_id().copied() else {
        println!("ERROR no_succeeded_attempt");
        return ExitCode::from(3);
    };
    let route = FreshRoute {
        revoked_circuit_id: circuit,
        route_id: recorded_route,
        attempt_seq: latest.attempt_seq(),
        gateway_node_id: [0u8; 32],
    };

    // Rebuild the selection + fresh-route material exactly as the
    // `establish` invocation built it (deterministic seeds + clocks).
    // Re-derive the gateway through the PURE selection layer (the same
    // deterministic policy + evidence + clock the original `establish`
    // re-derivation used). The attempt-bound `select_gateway` cannot run
    // here BY DESIGN: the attempt is terminal (succeeded), and the
    // replacement stage composes over the DURABLE record, never over a
    // re-opened attempt.
    let stores = TempDir::new("replace");
    let material = default_candidates(&stores.path);
    let candidates: Vec<GatewayCandidate<'_>> = material.iter().map(|c| c.candidate()).collect();
    let selected = match select_eligible_gateway(&admission_policy(), &candidates, route_at) {
        Ok(found) => found,
        Err(err) => return fail(&err),
    };
    let gateway_identity = [ident(SEED_G1), ident(SEED_G2), ident(SEED_G3), ident(SEED_G4)]
        .into_iter()
        .find(|g| node_id(g) == selected.gateway_node_id)
        .expect("a probe gateway");
    let recovering = ident(SEED_RECOVERING);
    let mut path: Vec<[u8; 32]> = [node_id(&recovering), selected.gateway_node_id].to_vec();
    path.sort();
    let proposal =
        RouteProposal::new(&recovering, path, "live", route_at, 3600, [0x43; 32])
            .expect("proposal");
    let proposal_env = proposal.sign(&recovering).expect("sign");
    let proposal_id = derive_proposal_id(proposal_env.bytes());
    let mut members: Vec<&Identity> = vec![&recovering, &gateway_identity];
    members.sort_by_key(|m| node_id(m));
    let acceptance_envs: Vec<SignedEnvelope> = members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let acceptance =
                RouteAcceptance::new(m, proposal_id, i as u64, route_at, 3600)
                    .expect("acceptance");
            acceptance.sign(m).expect("sign")
        })
        .collect();
    let commitment =
        RouteCommitment::build(route_at, proposal_env, acceptance_envs).expect("commitment");
    if *commitment.route_id() != recorded_route {
        // The rebuild did not reproduce the durable record's route — the
        // probe's own typed failure (a wrong `route_at` argument).
        println!("ERROR route_rebuild_mismatch");
        return ExitCode::from(3);
    }

    // The signed R4-002 replacement material over the rebuilt fresh
    // commitment (the recovering node is the route's proposer; every path
    // member acks its position).
    let setup =
        CircuitSetup::new(&commitment, &recovering, REPLACEMENT_NONCE, now, 600)
            .expect("setup");
    let setup_env = setup.sign(&recovering).expect("sign setup");
    let replacement_id = derive_circuit_id(commitment.route_id(), &REPLACEMENT_NONCE);
    let ack_envs: Vec<SignedEnvelope> = members
        .iter()
        .enumerate()
        .map(|(pos, member)| {
            let ack =
                CircuitSetupAck::new(replacement_id, &setup_env, member, pos as u64, now, 500)
                    .expect("ack");
            ack.sign(member).expect("sign ack")
        })
        .collect();
    // A fresh runtime registry — exactly what a restarted daemon holds;
    // the driver installs its own ledger view (the L015 gate).
    let mut registry = CircuitRegistry::new();
    match driver.establish_replacement_circuit(&route, &setup_env, &ack_envs, &mut registry, now)
    {
        Ok(replacement) => {
            println!("ROUTE {}", hex(&replacement.fresh_route_id));
            println!("REPLACEMENT {}", hex(&replacement.replacement_circuit_id));
            println!("REPLACEMENT-ATTEMPT {}", replacement.attempt_seq);
            println!("ESTABLISHED {}", if registry.is_established(&replacement.replacement_circuit_id) { "yes" } else { "no" });
            ExitCode::SUCCESS
        }
        Err(err) => fail(&err),
    }
}

/// Process 3: reload from disk and report the circuit's terminal state.
fn cmd_state(rest: &[String]) -> ExitCode {
    let [dir] = rest else {
        usage();
        return ExitCode::from(2);
    };
    let (driver, report) = match RecoveryDriver::open(std::path::Path::new(dir)) {
        Ok(opened) => opened,
        Err(err) => return fail(&err),
    };
    let circuit = revoked_circuit_id();
    match driver.attempt_log().latest_attempt(&circuit) {
        Some(latest) => {
            let route = latest
                .fresh_route_id()
                .map_or("-".to_string(), |r| hex(r));
            println!(
                "LATEST {} {} {}",
                latest.state().as_str(),
                latest.attempt_seq(),
                route
            );
        }
        None => println!("LATEST none 0 -"),
    }
    println!("REVOKED {}", if driver.is_revoked(&circuit) { "yes" } else { "no" });
    println!(
        "ZEROIZED {}",
        driver
            .zeroization(&circuit)
            .map_or("no".to_string(), |z| z.zeroized_at_unix().to_string())
    );
    println!(
        "REPLACEMENT {}",
        driver
            .attempt_log()
            .latest_attempt(&circuit)
            .and_then(|a| a.replacement_circuit_id().copied())
            .map_or("-".to_string(), |r| hex(&r))
    );
    println!("ATTEMPTS {}", driver.attempt_log().record_count());
    let _ = report; // the load report is diagnostics (torn tails etc.)
    ExitCode::SUCCESS
}
