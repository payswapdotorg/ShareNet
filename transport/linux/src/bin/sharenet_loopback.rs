//! `sharenet_loopback` — the R10-001 two-process Linux loopback
//! bridge, PARTICIPANT role (work item: "Two-process Linux loopback";
//! verify level: multiprocess).
//!
//! The mission proof this binary exists to carry (handoff §Mission):
//!
//! ```text
//! connected Linux node (the `gateway` binary)
//!         ↓
//! nearby node with no Internet (THIS participant)
//!         ↓
//! authenticated ShareNet bridge (QUIC tunnel + R4-002 circuit)
//!         ↓
//! data flows (loopback "Internet" or a real DNS uplink)
//!         ↓
//! INDUCED gateway death (the test SIGKILLs gateway A)
//!         ↓
//! automatic replacement (R7-001 revocation → R7-003 selection →
//!                       R7-004 replacement circuit — durable)
//!         ↓
//! data continues (session on gateway B)
//! ```
//!
//! # The composition that is NEW here
//!
//! Waves 4/7/9 proved each stage in isolation. This binary composes
//! them IN ONE PROCESS RUN against REAL gateway processes: the live
//! [`GatewayClient`] session's OWN wire evidence — the exact signed
//! route proposal/acceptances and circuit setup/acks exchanged on the
//! tunnel's control stream (exposed as
//! [`ParticipantSession::wire_evidence`]) — is fed into the durable
//! [`RecoveryDriver`] pipeline, so the recovery record describes the
//! circuit that ACTUALLY carries the bytes, and the recorded
//! replacement circuit id IS the live session's circuit id.
//!
//! # Output protocol (machine-parsable, one line per phase)
//!
//! ```text
//! LOOPBACK_IDENTITY <node-hex>
//! LOOPBACK_CONNECTED_A <circuit-hex>
//! LOOPBACK_A_EXCHANGED <sent> <received>
//! LOOPBACK_FAILURE_DETECTED <error>
//! LOOPBACK_REVOKED <circuit-hex> <outcome>
//! LOOPBACK_ATTEMPT <seq>
//! LOOPBACK_SELECTED <gateway-hex>
//! LOOPBACK_CONNECTED_B <circuit-hex>
//! LOOPBACK_ROUTE <route-hex>
//! LOOPBACK_ZEROIZED <circuit-hex>
//! LOOPBACK_REPLACEMENT <circuit-hex> <attempt-seq>
//! LOOPBACK_B_EXCHANGED <sent> <received>
//! LOOPBACK_DESTROYED_B
//! LOOPBACK_LAST_RESPONSE <hex>            (only with --emit-last-response)
//! LOOPBACK_DONE <total-sent> <total-received> <replacements>
//! ```
//!
//! Exit codes: 0 = the bridge completed incl. replacement; 2 = usage;
//! 3 = runtime failure (LOOPBACK_ERROR on stdout names it).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use sharenet_admission::{AdcosBackhaulEvidence, AdmissionParams, GatewayAdmissionPolicy};
use sharenet_connectivity::{
    AcceptOutcome, ConnectivityContractRef, ConnectivityObservation, DurableProjectionStore,
    ObservationKind, RefKind,
};
use sharenet_recovery::{
    FreshRoute, GatewayCandidate, RecoveryDriver, RecoveryStep, SelectedGateway,
};
use sharenet_protocol::identity::Identity;
use sharenet_protocol::revocation::{
    CircuitRevocation, EvidenceValue, RevocationReason, EVIDENCE_FAILURE_KIND,
};
use sharenet_protocol::topology::SignedTopologyEvidence;
use sharenet_protocol::{
    ConnectivityObservationStatement, EvidenceKind, LinkQualitySnapshot, Observation,
    ObservationAdmission, SignedConnectivityObservation, TopologyEvidence,
};

use sharenet_transport_linux::gateway::GatewayClient;

/// The R5-003 store window the candidate's health view is built with
/// (the recovery_probe convention).
const STORE_WINDOW_SECS: u64 = 600;
/// The evidence freshness offsets relative to the decision clock
/// (probe convention: links observed -8, streams activated -10 /
/// assured -5 — eligible for a (BASE, BASE+592)-shaped window).
const LINK_OBSERVED_OFFSET: u64 = 8;
const ACTIVATED_OFFSET: u64 = 10;
const ASSURED_OFFSET: u64 = 5;
/// The evidence identities (deterministic seeds; the observer and the
/// ADCOS provider are fixtures of the candidate's evidence set, the
/// way the R3-003/R5-003 stores would present them).
const SEED_OBSERVER: u8 = 0xC0;
const SEED_PROVIDER: u8 = 0xC2;

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock after the epoch")
        .as_secs()
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

fn parse_hex_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..s.len() / 2)
        .map(|i| {
            let hi = (s.as_bytes()[2 * i] as char).to_digit(16)? as u8;
            let lo = (s.as_bytes()[2 * i + 1] as char).to_digit(16)? as u8;
            Some(hi * 16 + lo)
        })
        .collect()
}

/// One-line-safe error text (newlines and spaces fold to underscores).
fn one_line(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .collect()
}

// ---------------------------------------------------------------------------
// The replacement candidate's evidence (the R3-003 link + R5-003/R5-004
// ADCOS backhaul, now-relative — what the stores would feed selection)
// ---------------------------------------------------------------------------

struct CandidateMaterial {
    node_id: [u8; 32],
    link: SignedTopologyEvidence,
    health: sharenet_connectivity::ContractHealth,
    signed: Vec<SignedConnectivityObservation>,
}

impl CandidateMaterial {
    fn candidate(&self) -> GatewayCandidate<'_> {
        GatewayCandidate {
            gateway_node_id: self.node_id,
            sharenet_link: Some(&self.link),
            adcos_backhaul: Some(AdcosBackhaulEvidence {
                health: Some(&self.health),
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

/// Build the eligible-candidate evidence for `gateway_node_id`,
/// timestamps relative to `now` (the decision clock).
fn candidate_material(
    gateway_node_id: [u8; 32],
    now: u64,
    store_dir: &std::path::Path,
) -> CandidateMaterial {
    let observer = Identity::from_seed([SEED_OBSERVER; 32], now - 86_400, None)
        .expect("observer identity");
    let provider = Identity::from_seed([SEED_PROVIDER; 32], now - 86_400, None)
        .expect("provider identity");
    let contract = ConnectivityContractRef::from_id([0xD1; 32]);

    let link = TopologyEvidence::new(
        &observer,
        gateway_node_id,
        Observation::Link {
            link_id: [0x51; 32],
            established_at_unix: now - 108,
            quality: good_quality(),
        },
        now - LINK_OBSERVED_OFFSET,
        600,
    )
    .expect("evidence")
    .sign(&observer)
    .expect("signed link evidence");

    let signed = vec![
        signed_observation(&provider, &contract, EvidenceKind::ContractActivated, now - ACTIVATED_OFFSET, 1, None),
        signed_observation(
            &provider,
            &contract,
            EvidenceKind::AssuranceAvailable,
            now - ASSURED_OFFSET,
            2,
            Some(BTreeMap::from([
                ("throughput_bps".to_string(), 10_000_000),
                ("latency_ms".to_string(), 40),
            ])),
        ),
    ];

    // Feed a real R5-003 durable store through the verified path (the
    // recovery_probe convention) and read the health view back.
    let mut admission = ObservationAdmission::new(STORE_WINDOW_SECS);
    admission.register_contract(*contract.id());
    let mut store = DurableProjectionStore::create(&store_dir.join("b.store"), STORE_WINDOW_SECS)
        .expect("projection store");
    for observation in &signed {
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
    let health = store.health(&contract).expect("tracked contract");

    CandidateMaterial {
        node_id: gateway_node_id,
        link,
        health,
        signed,
    }
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

fn admission_policy() -> GatewayAdmissionPolicy {
    GatewayAdmissionPolicy::new(
        AdmissionParams::new(600, 50_000, 200).expect("valid admission params"),
    )
}

// ---------------------------------------------------------------------------
// The participant flow
// ---------------------------------------------------------------------------

struct GatewayArg {
    addr: SocketAddr,
    node: [u8; 32],
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  sharenet_loopback participant --seed-hex <64hex> --state-dir DIR \\");
    eprintln!("      --gateway ADDR#NODEHEX [--gateway ADDR#NODEHEX ...] \\");
    eprintln!("      [--packets-before N] [--packets-after N] [--payload BYTES] \\");
    eprintln!("      [--payload-hex HEX] [--idle-ms M] [--probe-rounds R] [--emit-last-response]");
}

fn fail(msg: &str) -> ExitCode {
    println!("LOOPBACK_ERROR {}", one_line(msg));
    eprintln!("LOOPBACK_ERROR {msg}");
    ExitCode::from(3)
}

fn cmd_participant(rest: &[String]) -> ExitCode {
    let mut seed = None;
    let mut state_dir: Option<PathBuf> = None;
    let mut gateways: Vec<GatewayArg> = Vec::new();
    let mut packets_before = 4u64;
    let mut packets_after = 4u64;
    let mut payload_len = 512usize;
    let mut payload_hex: Option<Vec<u8>> = None;
    let mut idle_ms = 2_000u64;
    let mut probe_rounds = 64u64;
    let mut emit_last_response = false;

    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--seed-hex" => {
                i += 1;
                let Some(v) = rest.get(i).and_then(|s| parse_hex32(s)) else {
                    usage();
                    return ExitCode::from(2);
                };
                seed = Some(v);
            }
            "--state-dir" => {
                i += 1;
                let Some(v) = rest.get(i) else {
                    usage();
                    return ExitCode::from(2);
                };
                state_dir = Some(PathBuf::from(v));
            }
            "--gateway" => {
                i += 1;
                let Some(v) = rest.get(i) else {
                    usage();
                    return ExitCode::from(2);
                };
                let Some((addr_s, node_s)) = v.split_once('#') else {
                    usage();
                    return ExitCode::from(2);
                };
                let Ok(addr) = addr_s.parse::<SocketAddr>() else {
                    usage();
                    return ExitCode::from(2);
                };
                let Some(node) = parse_hex32(node_s) else {
                    usage();
                    return ExitCode::from(2);
                };
                gateways.push(GatewayArg { addr, node });
            }
            "--packets-before" => {
                i += 1;
                let Some(v) = rest.get(i).and_then(|s| s.parse().ok()) else {
                    usage();
                    return ExitCode::from(2);
                };
                packets_before = v;
            }
            "--packets-after" => {
                i += 1;
                let Some(v) = rest.get(i).and_then(|s| s.parse().ok()) else {
                    usage();
                    return ExitCode::from(2);
                };
                packets_after = v;
            }
            "--payload" => {
                i += 1;
                let Some(v) = rest.get(i).and_then(|s| s.parse().ok()) else {
                    usage();
                    return ExitCode::from(2);
                };
                payload_len = v;
            }
            "--payload-hex" => {
                i += 1;
                let Some(v) = rest.get(i).and_then(|s| parse_hex_bytes(s)) else {
                    usage();
                    return ExitCode::from(2);
                };
                payload_hex = Some(v);
            }
            "--idle-ms" => {
                i += 1;
                let Some(v) = rest.get(i).and_then(|s| s.parse().ok()) else {
                    usage();
                    return ExitCode::from(2);
                };
                idle_ms = v;
            }
            "--probe-rounds" => {
                i += 1;
                let Some(v) = rest.get(i).and_then(|s| s.parse().ok()) else {
                    usage();
                    return ExitCode::from(2);
                };
                probe_rounds = v;
            }
            "--emit-last-response" => emit_last_response = true,
            _ => {
                usage();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }

    let Some(seed) = seed else {
        usage();
        return ExitCode::from(2);
    };
    let Some(state_dir) = state_dir else {
        usage();
        return ExitCode::from(2);
    };
    if gateways.len() < 2 {
        eprintln!("need at least two gateways (primary + replacement)");
        usage();
        return ExitCode::from(2);
    }
    if packets_before == 0 || packets_after == 0 || probe_rounds == 0 {
        eprintln!("packet counts and probe rounds must be >= 1");
        return ExitCode::from(2);
    }
    if let Some(bytes) = &payload_hex {
        if bytes.is_empty() || bytes.len() > 65_500 {
            eprintln!("payload-hex must be 1..=65500 bytes");
            return ExitCode::from(2);
        }
    } else if payload_len == 0 || payload_len > 65_500 {
        eprintln!("payload must be 1..=65500 bytes");
        return ExitCode::from(2);
    }

    std::fs::create_dir_all(&state_dir).expect("state dir");

    let identity =
        Identity::from_seed(seed, 0, None).expect("participant identity from seed");
    println!("LOOPBACK_IDENTITY {}", hex(identity.node_id().as_bytes()));

    // With an exact payload (--payload-hex) the uplink is NOT an echo
    // (the real-Internet leg: a DNS reply legitimately differs from its
    // query — the TEST asserts the reply's shape); with generated
    // pattern payloads the exchange is a strict echo (the loopback leg).
    let strict_echo = payload_hex.is_none();

    let payload = |round: u64| -> Vec<u8> {
        if let Some(bytes) = &payload_hex {
            bytes.clone()
        } else {
            // Varied, deterministic, self-verifying pattern.
            let mut packet = vec![0u8; payload_len];
            for (j, slot) in packet.iter_mut().enumerate() {
                *slot = ((round as usize + j) % 251) as u8;
            }
            packet
        }
    };

    // ---- Phase 1: the primary session on gateway A ----
    let a = &gateways[0];
    let client_a = GatewayClient::new(seed, a.addr, a.node);
    let mut session_a = match client_a.connect_with_idle_timeout(idle_ms) {
        Ok(s) => s,
        Err(err) => return fail(&format!("connect A: {err}")),
    };
    let circuit_a = *session_a.circuit_id();
    println!("LOOPBACK_CONNECTED_A {}", hex(&circuit_a));

    for round in 0..packets_before {
        let packet = payload(round);
        if let Err(err) = session_a.send_packet(&packet) {
            return fail(&format!("A send {round}: {err}"));
        }
        match session_a.recv_response() {
            Ok(response) if !strict_echo || response == packet => {}
            Ok(_) => return fail(&format!("A round {round}: non-echo response")),
            Err(err) => return fail(&format!("A recv {round}: {err}")),
        }
    }
    println!("LOOPBACK_A_EXCHANGED {packets_before} {packets_before}");

    // ---- Phase 2: probe until the (test-induced) gateway death ----
    // SIGKILL leaves no UDP RST — the bounded idle timeout is what
    // turns the silent death into a typed error.
    let mut failure: Option<String> = None;
    let mut probes_used = 0u64;
    for round in 0..probe_rounds {
        probes_used = round + 1;
        let packet = payload(10_000 + round);
        match session_a.send_packet(&packet) {
            Err(err) => {
                failure = Some(format!("send: {err}"));
                break;
            }
            Ok(()) => match session_a.recv_response() {
                Ok(_) => continue,
                Err(err) => {
                    failure = Some(format!("recv: {err}"));
                    break;
                }
            },
        }
    }
    let Some(failure) = failure else {
        return fail("gateway A never failed within the probe budget");
    };
    println!("LOOPBACK_FAILURE_DETECTED {}", one_line(&failure));

    // ---- Phase 3: durable revocation of the dead circuit (R7-001) ----
    let now = now_unix();
    // The evidence value bound is 64 bytes (the R7-001 wire law) —
    // fold the typed error into it, truncated.
    let mut error_text = format!("quic_stream_error:{}", one_line(&failure));
    error_text.truncate(60);
    let mut revocation_evidence = BTreeMap::new();
    revocation_evidence.insert(
        EVIDENCE_FAILURE_KIND.to_string(),
        EvidenceValue::Text(error_text),
    );
    revocation_evidence.insert("missed_acks".to_string(), EvidenceValue::Int(1));
    let revocation =
        CircuitRevocation::new(&identity, circuit_a, RevocationReason::LinkFailure, Some(revocation_evidence), now)
            .expect("revocation builds");
    let signed_revocation = revocation.sign(&identity).expect("sign revocation");

    let (driver, _) = match RecoveryDriver::open(&state_dir) {
        Ok(v) => v,
        Err(err) => return fail(&format!("driver open: {err}")),
    };
    let outcome = match driver.admit_revocation_envelope(
        now,
        &signed_revocation.to_envelope_bytes(),
        session_a.registry(),
    ) {
        Ok(o) => o,
        Err(err) => return fail(&format!("revocation admission: {err}")),
    };
    println!("LOOPBACK_REVOKED {} {}", hex(&circuit_a), outcome.as_str());

    // ---- Phase 4: attempt + fresh-gateway selection (R7-003) ----
    // The candidate set is the caller's LIVE knowledge: gateway A is
    // dead (the failure above) and is not presented; the replacement
    // B carries its verified evidence (the R3-003/R5-003 shape).
    let step = match driver.attempt_next(&circuit_a, now) {
        Ok(s) => s,
        Err(err) => return fail(&format!("attempt: {err}")),
    };
    let RecoveryStep::SelectFreshGateway {
        attempt_seq, ..
    } = &step;
    println!("LOOPBACK_ATTEMPT {attempt_seq}");

    let b = &gateways[1];
    let material = candidate_material(b.node, now, &state_dir);
    let candidates = [material.candidate()];
    let selected: SelectedGateway =
        match driver.select_gateway(&step, &candidates, &admission_policy(), now) {
            Ok(s) => s,
            Err(err) => return fail(&format!("selection: {err}")),
        };
    if selected.gateway_node_id != b.node {
        return fail("selection did not pick the replacement gateway");
    }
    println!("LOOPBACK_SELECTED {}", hex(&selected.gateway_node_id));

    // ---- Phase 5: the LIVE replacement session on gateway B ----
    let client_b = GatewayClient::new(seed, b.addr, b.node);
    let mut session_b = match client_b.connect_with_idle_timeout(idle_ms) {
        Ok(s) => s,
        Err(err) => return fail(&format!("connect B: {err}")),
    };
    let evidence_b = session_b.wire_evidence().clone();
    println!("LOOPBACK_CONNECTED_B {}", hex(&evidence_b.circuit_id));

    // ---- Phase 6: the durable recovery record from the REAL wire ----
    // The driver's fresh route, zeroization and replacement circuit are
    // established from the envelopes ACTUALLY exchanged with gateway B
    // (not re-derived stand-ins) — the composition this work item exists
    // to prove.
    let route: FreshRoute = match driver.establish_fresh_route(
        &selected,
        &evidence_b.proposal_env,
        &[
            evidence_b.participant_acceptance_env.clone(),
            evidence_b.gateway_acceptance_env.clone(),
        ],
        now,
    ) {
        Ok(r) => r,
        Err(err) => return fail(&format!("fresh route: {err}")),
    };
    println!("LOOPBACK_ROUTE {}", hex(&route.route_id));

    let zeroization = match driver.record_zeroization(&circuit_a, now) {
        Ok(z) => z,
        Err(err) => return fail(&format!("zeroization: {err}")),
    };
    println!("LOOPBACK_ZEROIZED {}", hex(zeroization.revoked_circuit_id()));

    let mut fresh_registry = sharenet_protocol::circuit::CircuitRegistry::new();
    let replacement = match driver.establish_replacement_circuit(
        &route,
        &evidence_b.setup_env,
        &[
            evidence_b.own_ack_env.clone(),
            evidence_b.gateway_ack_env.clone(),
        ],
        &mut fresh_registry,
        now,
    ) {
        Ok(r) => r,
        Err(err) => return fail(&format!("replacement circuit: {err}")),
    };
    println!(
        "LOOPBACK_REPLACEMENT {} {}",
        hex(&replacement.replacement_circuit_id),
        replacement.attempt_seq
    );
    // The composition law: the durable record's replacement circuit IS
    // the live wire circuit carrying the bytes on gateway B.
    if replacement.replacement_circuit_id != evidence_b.circuit_id {
        return fail(&format!(
            "durable replacement {} != live circuit {}",
            hex(&replacement.replacement_circuit_id),
            hex(&evidence_b.circuit_id)
        ));
    }
    if replacement.fresh_route_id != evidence_b.route_id {
        return fail("durable route id != live wire route id");
    }

    // ---- Phase 7: data continues on the replacement ----
    let mut last_response: Option<Vec<u8>> = None;
    for round in 0..packets_after {
        let packet = payload(20_000 + round);
        if let Err(err) = session_b.send_packet(&packet) {
            return fail(&format!("B send {round}: {err}"));
        }
        match session_b.recv_response() {
            Ok(response) if !strict_echo || response == packet => last_response = Some(response),
            Ok(other) => {
                return fail(&format!("B round {round}: non-echo response ({} bytes)", other.len()))
            }
            Err(err) => return fail(&format!("B recv {round}: {err}")),
        }
    }
    println!("LOOPBACK_B_EXCHANGED {packets_after} {packets_after}");

    if let Err(err) = session_b.destroy(&identity, "completed") {
        return fail(&format!("destroy B: {err}"));
    }
    println!("LOOPBACK_DESTROYED_B");

    if emit_last_response {
        if let Some(response) = last_response {
            println!("LOOPBACK_LAST_RESPONSE {}", hex(&response));
        }
    }

    let total_sent = packets_before + probes_used + packets_after;
    let total_received = packets_before + packets_after;
    println!("LOOPBACK_DONE {total_sent} {total_received} 1");
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("participant") {
        cmd_participant(&args[1..])
    } else {
        usage();
        ExitCode::from(2)
    }
}
