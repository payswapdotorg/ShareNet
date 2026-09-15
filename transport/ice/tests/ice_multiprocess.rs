//! R4-005 multiprocess verification: REAL separate processes over REAL
//! loopback UDP — a STUN server, a TURN-style relay, and an echo peer
//! behind the relay — exercising candidate gathering, opaque datagram
//! relay, and a full node-pinned QUIC/TLS 1.3 tunnel riding the relay
//! transparently (L012: the relay never parses the tunnel's packets).
//!
//! Adversarial coverage lives here too: wrong-transaction-id STUN
//! responses, fail-closed evil STUN responses, garbage control frames
//! to the relay (it must never die), duplicate-allocation rules, and
//! malformed/oversize relayed datagrams.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use sharenet_transport_ice::agent::{AgentConfig, PathKind, RelayEndpoint};
use sharenet_transport_ice::candidate::{
    gather, Candidate, CandidateType, GatherConfig,
};
use sharenet_transport_ice::relay::{
    ControlFrame, RelayClient, RelayCredential, MAX_RELAY_DATAGRAM, MSG_ALLOCATE,
    MSG_ALLOCATE_SUCCESS, MSG_DATA, MSG_RELAY_ERROR, MSG_SEND, RELAY_MAGIC,
};
use sharenet_transport_ice::stun::{binding_request, StunConfig};
use sharenet_transport_ice::IceError;

const STUN_BIN: &str = env!("CARGO_BIN_EXE_stun_server");
const RELAY_BIN: &str = env!("CARGO_BIN_EXE_turn_relay");
const CLIENT_BIN: &str = env!("CARGO_BIN_EXE_turn_client");

const STUN_SOFTWARE: &str = "sharenet-stun-server/0.1";
const PEER_SEED_HEX: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";
const CLIENT_SEED: [u8; 32] = [0x66; 32];

/// A spawned scaffolding process: stdout is drained on a thread (the
/// READY line is consumed synchronously at spawn); Drop KILLS the child
/// so a failed or panicking test can never leak a hung process.
struct Proc {
    child: Child,
    reader: Option<std::thread::JoinHandle<Vec<String>>>,
}

impl Proc {
    fn spawn(bin: &str, args: &[&str]) -> (Proc, String) {
        let mut child = Command::new(bin)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap_or_else(|e| panic!("spawn {bin}: {e}"));
        let stdout = child.stdout.take().expect("stdout");
        let mut reader = BufReader::new(stdout);
        let mut first = String::new();
        reader.read_line(&mut first).expect("READY line");
        let handle = std::thread::spawn(move || {
            let mut lines = Vec::new();
            for line in reader.lines() {
                match line {
                    Ok(l) => lines.push(l),
                    Err(_) => break,
                }
            }
            lines
        });
        let first = first.trim().to_string();
        (Proc { child, reader: Some(handle) }, first)
    }

    /// Wait for the process to exit on its own and return
    /// (success, remaining stdout lines).
    fn finish(mut self) -> (bool, Vec<String>) {
        let status = self.child.wait().expect("child exit");
        let lines = self.reader.take().expect("reader").join().expect("reader");
        (status.success(), lines)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn spawn_stun(extra: &[&str]) -> (Proc, SocketAddr) {
    let mut args = vec!["--requests", "1"];
    args.extend_from_slice(extra);
    let (proc, ready) = Proc::spawn(STUN_BIN, &args);
    let addr = ready
        .strip_prefix("READY ")
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("bad stun READY line: {ready:?}"));
    (proc, addr)
}

fn spawn_relay() -> (Proc, SocketAddr) {
    let (proc, ready) = Proc::spawn(RELAY_BIN, &[]);
    let addr = ready
        .strip_prefix("READY ")
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("bad relay READY line: {ready:?}"));
    (proc, addr)
}

/// Spawn the relay demanding the long-term credential `user:secret`.
fn spawn_relay_with_auth(user: &str, secret: &str) -> (Proc, SocketAddr) {
    let auth = format!("{user}:{secret}");
    let (proc, ready) = Proc::spawn(RELAY_BIN, &["--auth", &auth]);
    let addr = ready
        .strip_prefix("READY ")
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("bad auth relay READY line: {ready:?}"));
    (proc, addr)
}

fn fast_stun_config() -> StunConfig {
    StunConfig {
        software: "sharenet-transport-ice-test".to_string(),
        attempts: 3,
        attempt_timeout: Duration::from_millis(400),
    }
}

// ---------------------------------------------------------------------------
// STUN against the REAL stun_server process
// ---------------------------------------------------------------------------

#[test]
fn stun_binding_and_gather_against_real_stun_server() {
    // 1. A direct Binding exchange: the mapped address must be the
    //    client socket's REAL local address as observed by the server.
    //    (A fresh one-request server per step: each answers its single
    //    request and exits deterministically.)
    let (stun_a, server_a) = spawn_stun(&[]);
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let local = sock.local_addr().expect("addr");
    let outcome = binding_request(&sock, server_a, &fast_stun_config()).expect("binding");
    assert_eq!(outcome.server, server_a);
    assert_eq!(outcome.mapped, local, "loopback NAT is identity");
    assert_eq!(outcome.software.as_deref(), Some(STUN_SOFTWARE));
    drop(sock);
    let (ok, lines) = stun_a.finish();
    assert!(ok, "stun_server failed");
    assert!(lines.iter().any(|l| l == "STUN_DONE"), "lines: {lines:?}");

    // 2. Gathering with a fresh server: host + server-reflexive
    //    candidates, srflx address = the host socket's real address.
    let (stun_b, server_b) = spawn_stun(&[]);
    let mut config = GatherConfig::default();
    config.stun_server = Some(server_b);
    let gathered = gather(&config).expect("gather");
    assert_eq!(gathered.candidates.len(), 2);
    assert_eq!(gathered.candidates[0].candidate_type(), CandidateType::Host);
    assert_eq!(
        gathered.candidates[1].candidate_type(),
        CandidateType::ServerReflexive
    );
    let host_local = gathered.host_socket.local_addr().expect("addr");
    assert_eq!(gathered.candidates[0].transport_addr(), host_local);
    assert_eq!(gathered.candidates[1].transport_addr(), host_local);
    assert_eq!(gathered.candidates[1].base_addr(), host_local);
    let (ok, lines) = stun_b.finish();
    assert!(ok, "stun_server failed");
    assert!(lines.iter().any(|l| l == "STUN_DONE"), "lines: {lines:?}");

    // 3. An ICE connectivity check over the same socket (RFC 8445 §7
    //    subset): the check returns the address the target observed.
    let (stun_c, server_c) = spawn_stun(&[]);
    let observed =
        sharenet_transport_ice::stun::connectivity_check(&gathered.host_socket, server_c)
            .expect("connectivity check");
    assert_eq!(observed, host_local);
    drop(gathered);
    let (ok, lines) = stun_c.finish();
    assert!(ok, "stun_server failed");
    assert!(lines.iter().any(|l| l == "STUN_DONE"), "lines: {lines:?}");
}

#[test]
fn stun_wrong_transaction_id_response_is_ignored() {
    let (server_proc, server) = spawn_stun(&["--evil", "wrong-txid"]);
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let local = sock.local_addr().expect("addr");
    // The server first answers with a VALID response carrying a WRONG
    // transaction id and the bogus mapped address 203.0.113.7:9999, then
    // answers correctly. The client must discard the mismatched
    // response and accept the matching one.
    let outcome = binding_request(&sock, server, &fast_stun_config())
        .expect("the correct response must be accepted after the evil one");
    assert_eq!(
        outcome.mapped, local,
        "the wrong-transaction-id response (mapped 203.0.113.7:9999) must never satisfy the exchange"
    );
    let (ok, lines) = server_proc.finish();
    assert!(ok, "stun_server failed");
    assert!(lines.iter().any(|l| l == "STUN_DONE"), "lines: {lines:?}");
}

#[test]
fn stun_fail_closed_on_evil_responses() {
    for (mode, expected) in [
        ("bad-cookie", IceError::StunBadMagicCookie { found: 0x2112_A443 }),
        (
            "trailing-garbage",
            // The response carries 40 attribute bytes (XOR-MAPPED-ADDRESS
            // + SOFTWARE) and the server appends 2 garbage bytes: the
            // strict parse reports the header's claim vs the datagram's
            // actual post-header size.
            IceError::StunBadMessageLength { claimed: 40, available: 42 },
        ),
        (
            "unknown-required",
            IceError::StunUnknownRequiredAttribute { attr_type: 0x7FFF },
        ),
    ] {
        let (server_proc, server) = spawn_stun(&["--evil", mode]);
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        // A datagram from the queried server that fails the strict
        // parse fails the whole operation closed — no fallback.
        let result = binding_request(&sock, server, &fast_stun_config());
        assert_eq!(result, Err(expected), "evil mode {mode}");
        let (ok, lines) = server_proc.finish();
        assert!(ok, "stun_server failed for mode {mode}");
        assert!(lines.iter().any(|l| l == "STUN_DONE"), "lines: {lines:?}");
    }
}

// ---------------------------------------------------------------------------
// Relay: opaque datagrams through the REAL turn_relay process
// ---------------------------------------------------------------------------

#[test]
fn relay_echo_between_processes_via_relayed_addresses() {
    let (relay_proc, relay_addr) = spawn_relay();
    let (echo_proc, ready) = Proc::spawn(
        CLIENT_BIN,
        &["--relay", &relay_addr.to_string()],
    );
    let echo_relayed: SocketAddr = ready
        .strip_prefix("READY ")
        .and_then(|a| a.parse().ok())
        .unwrap_or_else(|| panic!("bad turn_client READY line: {ready:?}"));

    // The test process gathers with the relay configured — the relayed
    // candidate's address is its own allocation's relayed address.
    let mut config = GatherConfig::default();
    config.relay = Some(relay_addr);
    let gathered = gather(&config).expect("gather");
    assert_eq!(gathered.candidates.len(), 2);
    assert_eq!(gathered.candidates[0].candidate_type(), CandidateType::Host);
    assert_eq!(gathered.candidates[1].candidate_type(), CandidateType::Relayed);
    let client = gathered.relay.as_ref().expect("relay candidate");
    assert_eq!(gathered.candidates[1].transport_addr(), client.relayed_addr());
    client
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("timeout");

    // Opaque datagrams, both directions through the relay process: the
    // payloads are arbitrary bytes the relay never parses (L012).
    let mut buf = vec![0u8; 65_536];
    for payload in [
        b"relay-echo-1".to_vec(),
        vec![0x00, 0xFF, 0x53, 0x4E, 0x00, 0x01],
        b"x".repeat(1024),
    ] {
        client
            .send_to(echo_relayed, &payload)
            .expect("send through relay");
        let (peer, n) = client.recv_from(&mut buf).expect("echo through relay");
        assert_eq!(peer, echo_relayed, "the echo returns from the peer's relayed address");
        assert_eq!(&buf[..n], &payload[..], "verbatim opaque echo");
    }

    // Application-level done exchange so process exit never races
    // in-flight datagrams (the sibling crates' pattern).
    client.send_to(echo_relayed, b"done").expect("done");
    let (peer, n) = client.recv_from(&mut buf).expect("done-ack");
    assert_eq!(peer, echo_relayed);
    assert_eq!(&buf[..n], b"done-ack");

    let (ok, lines) = echo_proc.finish();
    assert!(ok, "turn_client failed");
    assert!(lines.iter().any(|l| l == "CLIENT_DONE"), "lines: {lines:?}");
    drop(relay_proc);
}

#[test]
fn gather_all_three_candidate_types_from_real_processes() {
    let (stun_proc, stun_addr) = spawn_stun(&["--requests", "1"]);
    let (relay_proc, relay_addr) = spawn_relay();

    let mut config = GatherConfig::default();
    config.stun_server = Some(stun_addr);
    config.relay = Some(relay_addr);
    let gathered = gather(&config).expect("gather");
    assert_eq!(gathered.candidates.len(), 3);
    let types: Vec<CandidateType> = gathered
        .candidates
        .iter()
        .map(|c| c.candidate_type())
        .collect();
    assert_eq!(
        types,
        [CandidateType::Host, CandidateType::ServerReflexive, CandidateType::Relayed]
    );
    // Priority ordering: host > srflx > relayed (RFC 8445 recommended
    // preferences with equal local preference and component).
    let priorities: Vec<u32> = gathered.candidates.iter().map(|c| c.priority()).collect();
    assert_eq!(
        priorities,
        [2_130_706_431, 1_694_498_815, 16_777_215]
    );
    // Distinct foundations (type differs) and distinct addresses.
    let foundations: Vec<&str> =
        gathered.candidates.iter().map(|c| c.foundation()).collect();
    assert_eq!(foundations.len(), 3);
    assert_ne!(foundations[0], foundations[1]);
    assert_ne!(foundations[1], foundations[2]);
    assert_eq!(
        gathered.candidates[1].transport_addr(),
        gathered.host_socket.local_addr().expect("addr")
    );
    assert_eq!(
        gathered.candidates[2].transport_addr(),
        gathered.relay.as_ref().expect("relay").relayed_addr()
    );

    let (ok, lines) = stun_proc.finish();
    assert!(ok, "stun_server failed");
    assert!(lines.iter().any(|l| l == "STUN_DONE"), "lines: {lines:?}");
    drop(relay_proc);
}

// ---------------------------------------------------------------------------
// QUIC tunnel through the relay (R4-001 composition)
// ---------------------------------------------------------------------------

fn spawn_quic_peer(relay_addr: SocketAddr, frames: usize) -> (Proc, SocketAddr, [u8; 32]) {
    let (proc, ready) = Proc::spawn(
        CLIENT_BIN,
        &[
            "--relay",
            &relay_addr.to_string(),
            "--mode",
            "quic",
            "--seed-hex",
            PEER_SEED_HEX,
            "--frames",
            &frames.to_string(),
        ],
    );
    let mut parts = ready
        .strip_prefix("READY ")
        .unwrap_or_else(|| panic!("bad turn_client READY line: {ready:?}"))
        .split(' ');
    let relayed: SocketAddr = parts.next().unwrap().parse().expect("relayed addr");
    let node_hex = parts.next().expect("node id hex");
    assert_eq!(node_hex.len(), 64, "node id hex: {node_hex}");
    let mut node_id = [0u8; 32];
    for (i, byte) in node_id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&node_hex[2 * i..2 * i + 2], 16).expect("hex");
    }
    (proc, relayed, node_id)
}

#[test]
fn quic_tunnel_through_real_relay_is_transparent() {
    let (relay_proc, relay_addr) = spawn_relay();
    let (echo_proc, relayed, node_id) = spawn_quic_peer(relay_addr, 2);

    // A relayed candidate (the peer's relayed address, reported via the
    // documented READY line) is the address source for a node-pinned
    // QUIC tunnel — the bridge only consumes the candidate's transport
    // address; every authentication property is the tunnel layer's.
    let candidate = Candidate::new(CandidateType::Relayed, relayed, relay_addr, 1, 65_535)
        .expect("candidate");
    assert_eq!(candidate.transport_addr(), relayed);
    let mut stream =
        sharenet_transport_ice::tunnel_connect(&candidate, CLIENT_SEED, node_id)
            .expect("pinned QUIC connect through the relay");

    // A full QUIC/TLS 1.3 handshake plus framed session rides the relay
    // transparently: the relay forwarded only opaque datagrams (L012).
    for payload in [b"quic-through-relay-1".to_vec(), b"quic-through-relay-2".to_vec()] {
        stream.send_frame(&payload).expect("send");
        let echoed = stream.recv_frame().expect("recv");
        let mut want = b"echo:".to_vec();
        want.extend_from_slice(&payload);
        assert_eq!(echoed, want);
    }
    stream.send_frame(b"done").expect("client done");
    let _ = stream.finish();

    let (ok, lines) = echo_proc.finish();
    assert!(ok, "turn_client failed");
    assert!(lines.iter().any(|l| l == "CLIENT_DONE"), "lines: {lines:?}");
    drop(relay_proc);
}

#[test]
fn wrong_node_pin_through_relay_fails_closed_and_relay_survives() {
    let (relay_proc, relay_addr) = spawn_relay();
    let (echo_proc, relayed, _node_id) = spawn_quic_peer(relay_addr, 1);

    let candidate = Candidate::new(CandidateType::Relayed, relayed, relay_addr, 1, 65_535)
        .expect("candidate");
    let wrong_pin = [0xEE; 32];
    let result = sharenet_transport_ice::tunnel_connect(&candidate, CLIENT_SEED, wrong_pin);
    assert!(result.is_err(), "a wrong node pin must never complete a tunnel");

    // The relay must keep serving after the failed QUIC handshake's
    // traffic crossed it: a fresh allocation works.
    let fresh = RelayClient::allocate(relay_addr, "127.0.0.1:0".parse().expect("addr"));
    assert!(fresh.is_ok(), "relay must survive adversarial tunnel traffic: {fresh:?}");
    drop(echo_proc);
    drop(relay_proc);
}

// ---------------------------------------------------------------------------
// Relay adversarial: garbage control frames, duplicate allocations,
// malformed relayed datagrams, oversize rejection
// ---------------------------------------------------------------------------

#[test]
fn relay_survives_adversarial_control_frames() {
    let (relay_proc, relay_addr) = spawn_relay();
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    sock.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");

    // 1. Pure garbage: random-looking bytes, no relay magic — silently
    //    dropped (never a reply to a spoofable garbage source).
    for garbage in [
        vec![0u8; 64],
        (0u8..=255).collect::<Vec<u8>>(),
        vec![0x53],
        b"SN".to_vec(),
        vec![0x53, 0x4E, 0x00, 0x01, 0x00],
    ] {
        sock.send_to(&garbage, relay_addr).expect("send garbage");
    }
    // 2. Valid magic, unknown message type: gets a RELAY-ERROR reply
    //    (consumed here — every other send's reply must be drained in
    //    order or the following recvs would read the leftover).
    let bogus = ControlFrame { msg_type: 0xBEEF, allocation_id: 1, payload: vec![0; 4] };
    sock.send_to(&bogus.encode(), relay_addr).expect("send bogus type");
    let mut buf = [0u8; 1024];
    let (n, _) = sock.recv_from(&mut buf).expect("RELAY-ERROR reply for bogus type");
    let reply = ControlFrame::parse(&buf[..n]).expect("reply parses");
    assert_eq!(reply.msg_type, MSG_RELAY_ERROR);
    let code = u16::from_be_bytes([reply.payload[0], reply.payload[1]]);
    assert_eq!(code, 1, "ERR_MALFORMED expected for unknown type");

    // 3. Server→client message types sent BY a client: misuse.
    for msg_type in [MSG_ALLOCATE_SUCCESS, MSG_DATA, MSG_RELAY_ERROR] {
        let frame = ControlFrame { msg_type, allocation_id: 9, payload: Vec::new() };
        sock.send_to(&frame.encode(), relay_addr).expect("send server type");
        let (n, _) = sock.recv_from(&mut buf).expect("RELAY-ERROR reply");
        let reply = ControlFrame::parse(&buf[..n]).expect("reply parses");
        assert_eq!(reply.msg_type, MSG_RELAY_ERROR);
        let code = u16::from_be_bytes([reply.payload[0], reply.payload[1]]);
        assert_eq!(code, 1, "ERR_MALFORMED expected, payload: {:?}", reply.payload);
    }

    // 4. SEND for an unknown allocation.
    let mut payload = sharenet_transport_ice::relay::encode_address("127.0.0.1:9".parse().expect("addr"));
    payload.extend_from_slice(b"x");
    let frame = ControlFrame { msg_type: MSG_SEND, allocation_id: 0xDEAD, payload };
    sock.send_to(&frame.encode(), relay_addr).expect("send");
    let mut buf = [0u8; 1024];
    let (n, _) = sock.recv_from(&mut buf).expect("RELAY-ERROR reply");
    let reply = ControlFrame::parse(&buf[..n]).expect("reply parses");
    let code = u16::from_be_bytes([reply.payload[0], reply.payload[1]]);
    assert_eq!(code, 2, "ERR_UNKNOWN_ALLOCATION expected");

    // 5. ALLOCATE with a non-empty payload.
    let frame = ControlFrame { msg_type: MSG_ALLOCATE, allocation_id: 7, payload: b"junk".to_vec() };
    sock.send_to(&frame.encode(), relay_addr).expect("send");
    let (n, _) = sock.recv_from(&mut buf).expect("RELAY-ERROR reply");
    let reply = ControlFrame::parse(&buf[..n]).expect("reply parses");
    let code = u16::from_be_bytes([reply.payload[0], reply.payload[1]]);
    assert_eq!(code, 1, "ERR_MALFORMED expected");

    // 6. The relay SURVIVED all of it: a fresh allocation works and
    //    forwards opaque datagrams.
    let client = RelayClient::allocate(relay_addr, "127.0.0.1:0".parse().expect("addr"))
        .expect("relay still serves allocations");
    assert!(client.relayed_addr().port() > 0);
    drop(relay_proc);
}

#[test]
fn relay_duplicate_allocation_rules_rfc8656() {
    let (relay_proc, relay_addr) = spawn_relay();

    // Raw control-socket view of the RFC 8656 allocation rules.
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
    sock.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
    let nonce = 0x1122_3344_5566_7788;

    // Fresh allocation.
    let allocate = ControlFrame { msg_type: MSG_ALLOCATE, allocation_id: nonce, payload: Vec::new() };
    sock.send_to(&allocate.encode(), relay_addr).expect("send");
    let mut buf = [0u8; 1024];
    let (n, _) = sock.recv_from(&mut buf).expect("ALLOCATE-SUCCESS");
    let success = ControlFrame::parse(&buf[..n]).expect("parse");
    assert_eq!(success.msg_type, MSG_ALLOCATE_SUCCESS);
    let first = success.clone();

    // Retransmission with the SAME nonce: the same allocation (the
    // byte-identical response).
    sock.send_to(&allocate.encode(), relay_addr).expect("send");
    let (n, _) = sock.recv_from(&mut buf).expect("ALLOCATE-SUCCESS");
    let retransmitted = ControlFrame::parse(&buf[..n]).expect("parse");
    assert_eq!(retransmitted, first, "same nonce must return the same allocation");

    // A NEW nonce on the same 5-tuple: RFC 8656 437 Allocation Mismatch.
    let conflicting = ControlFrame {
        msg_type: MSG_ALLOCATE,
        allocation_id: nonce ^ 1,
        payload: Vec::new(),
    };
    sock.send_to(&conflicting.encode(), relay_addr).expect("send");
    let (n, _) = sock.recv_from(&mut buf).expect("RELAY-ERROR");
    let reply = ControlFrame::parse(&buf[..n]).expect("parse");
    assert_eq!(reply.msg_type, MSG_RELAY_ERROR);
    let code = u16::from_be_bytes([reply.payload[0], reply.payload[1]]);
    assert_eq!(code, 437);

    // Library-level view: a second allocate_on with the same socket
    // (fresh nonce) is refused with the typed error.
    let control = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let client = RelayClient::allocate_on(control.try_clone().expect("clone"), relay_addr)
        .expect("first allocation");
    let second = RelayClient::allocate_on(control, relay_addr);
    let error = second.expect_err("second allocation on the same 5-tuple must fail");
    assert_eq!(
        error,
        IceError::RelayAllocateFailed {
            code: 437,
            reason: "allocation already exists for this 5-tuple (RFC 8656 437)".to_string(),
        }
    );
    assert!(client.relayed_addr().port() > 0);
    drop(relay_proc);
}

#[test]
fn relay_forwards_malformed_relayed_datagrams_opaquely() {
    let (relay_proc, relay_addr) = spawn_relay();
    let client = RelayClient::allocate(relay_addr, "127.0.0.1:0".parse().expect("addr"))
        .expect("allocate");
    client.activate().expect("activate");
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let relayed = client.relayed_addr();

    // Datagrams that "look malformed" to a protocol-aware middlebox are
    // OPAQUE bytes to the relay: garbage, a truncated relay control
    // frame's bytes, and STUN-looking bytes all cross unchanged (L012).
    let garbage_socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    let garbage_addr = garbage_socket.local_addr().expect("addr");
    let mut buf = vec![0u8; 65_536];
    for payload in [
        vec![0x53, 0x4E, 0x00, 0x01, 0x00], // truncated control frame
        vec![0x00; 64],                    // zeros
        b"not-a-stun-message".to_vec(),
    ] {
        garbage_socket.send_to(&payload, relayed).expect("send garbage");
        let (peer, n) = client.recv_from(&mut buf).expect("forwarded");
        assert_eq!(peer, garbage_addr);
        assert_eq!(&buf[..n], &payload[..]);
    }

    // A large (60 000-byte) datagram forwards unchanged — the 2 MiB
    // limit is the cap, not a shrink.
    let big = vec![0xA5; 60_000];
    garbage_socket.send_to(&big, relayed).expect("send big");
    let (peer, n) = client.recv_from(&mut buf).expect("forwarded big");
    assert_eq!(peer, garbage_addr);
    assert_eq!(n, big.len());
    assert_eq!(&buf[..n], &big[..]);

    // The library-side oversize rejection: datagrams over
    // MAX_RELAY_DATAGRAM are refused locally, never split (the
    // relay-side check is defense in depth — a single UDP datagram
    // cannot exceed ~65 507 bytes anyway).
    let oversize = vec![0x00; MAX_RELAY_DATAGRAM + 1];
    assert_eq!(
        client.send_to(garbage_addr, &oversize),
        Err(IceError::RelayDatagramTooLarge {
            len: MAX_RELAY_DATAGRAM + 1,
            max: MAX_RELAY_DATAGRAM,
        })
    );

    // The relay survived everything and still serves fresh allocations.
    let fresh = RelayClient::allocate(relay_addr, "127.0.0.1:0".parse().expect("addr"));
    assert!(fresh.is_ok(), "relay must survive: {fresh:?}");
    drop(relay_proc);
}

/// The relay's control-frame magic is "SN" (0x53 0x4E) — sanity-locked
/// so an accidental format change cannot go unnoticed.
#[test]
fn relay_control_magic_constant() {
    assert_eq!(RELAY_MAGIC, [0x53, 0x4E]);
}

// ---------------------------------------------------------------------------
// R4-006: the ICE agent — nomination with restrictive-network fallback,
// against the REAL ice_peer / turn_relay processes
// ---------------------------------------------------------------------------

const ICE_PEER_BIN: &str = env!("CARGO_BIN_EXE_ice_peer");

/// Spawn the ICE-lite peer and parse its `READY <addr> <node-id-hex>` line.
fn spawn_ice_peer(args: &[&str]) -> (Proc, SocketAddr, [u8; 32]) {
    let (proc, ready) = Proc::spawn(ICE_PEER_BIN, args);
    let mut parts = ready
        .strip_prefix("READY ")
        .unwrap_or_else(|| panic!("bad ice_peer READY line: {ready:?}"))
        .split(' ');
    let addr: SocketAddr = parts.next().unwrap().parse().expect("candidate addr");
    let node_hex = parts.next().expect("node id hex");
    assert_eq!(node_hex.len(), 64, "node id hex: {node_hex}");
    let mut node_id = [0u8; 32];
    for (i, byte) in node_id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&node_hex[2 * i..2 * i + 2], 16).expect("hex");
    }
    (proc, addr, node_id)
}

/// An unreachable host candidate: a loopback port with no listener.
fn dead_host_candidate() -> Candidate {
    let probe = UdpSocket::bind("127.0.0.1:0").expect("bind probe");
    let dead = probe.local_addr().expect("addr");
    drop(probe);
    Candidate::new(CandidateType::Host, dead, dead, 1, 65_535).expect("candidate")
}

#[test]
fn agent_nominates_direct_on_open_network_and_tunnel_completes() {
    let (peer_proc, addr, node_id) = spawn_ice_peer(&[
        "--mode",
        "direct",
        "--seed-hex",
        PEER_SEED_HEX,
        "--frames",
        "3",
    ]);

    let remote = [Candidate::new(CandidateType::Host, addr, addr, 1, 65_535).expect("candidate")];
    let mut config = AgentConfig::default();
    config.check = fast_stun_config(); // no relay configured at all
    let nomination = sharenet_transport_ice::agent::nominate(&config, &remote)
        .expect("agent must nominate on the open loopback network");

    assert_eq!(nomination.path, PathKind::Direct);
    assert!(!nomination.local_relay_used, "an open network must never touch the relay");
    assert!(nomination.attempts.is_empty(), "the first (host→host) pair must win");
    assert_eq!(nomination.pair.remote.transport_addr(), addr);

    // The nominated pair is the address source for the node-pinned QUIC
    // tunnel: full handshake + framed echo against the real peer process.
    let mut stream = sharenet_transport_ice::tunnel_connect(
        &nomination.pair.remote,
        CLIENT_SEED,
        node_id,
    )
    .expect("pinned QUIC connect on the nominated direct pair");
    for i in 1..=3u32 {
        let payload = format!("agent-direct-{i}").into_bytes();
        stream.send_frame(&payload).expect("send");
        let echoed = stream.recv_frame().expect("recv");
        let mut want = b"echo:".to_vec();
        want.extend_from_slice(&payload);
        assert_eq!(echoed, want);
    }
    stream.send_frame(b"done").expect("client done");
    let _ = stream.finish();

    let (ok, lines) = peer_proc.finish();
    assert!(ok, "ice_peer direct failed");
    assert!(lines.iter().any(|l| l == "CLIENT_DONE"), "lines: {lines:?}");
}

#[test]
fn agent_falls_back_to_relayed_pair_when_target_is_relay_only() {
    // The TARGET is restricted: it is reachable ONLY at its relayed
    // address (no direct candidate exists). The agent's pair walk finds
    // the lower-priority host→relayed pair and nominates it.
    let (relay_proc, relay_addr) = spawn_relay();
    let (peer_proc, relayed, node_id) = spawn_ice_peer(&[
        "--mode",
        "relay",
        "--relay",
        &relay_addr.to_string(),
        "--seed-hex",
        PEER_SEED_HEX,
        "--frames",
        "2",
    ]);

    let remote = [Candidate::new(CandidateType::Relayed, relayed, relayed, 1, 65_535)
        .expect("candidate")];
    let mut config = AgentConfig::default();
    config.check = fast_stun_config();
    config.relay = Some(RelayEndpoint {
        addr: relay_addr,
        credential: None,
    });
    let nomination = sharenet_transport_ice::agent::nominate(&config, &remote)
        .expect("the relay-only target must be nominated through its relayed pair");

    assert_eq!(nomination.path, PathKind::Relay, "relay-only target = relay path");
    assert!(!nomination.local_relay_used, "client side is open: no local allocation");

    let mut stream = sharenet_transport_ice::tunnel_connect(
        &nomination.pair.remote,
        CLIENT_SEED,
        node_id,
    )
    .expect("pinned QUIC connect through the relayed pair");
    for i in 1..=2u32 {
        let payload = format!("agent-relay-{i}").into_bytes();
        stream.send_frame(&payload).expect("send");
        let echoed = stream.recv_frame().expect("recv");
        let mut want = b"echo:".to_vec();
        want.extend_from_slice(&payload);
        assert_eq!(echoed, want);
    }
    stream.send_frame(b"done").expect("client done");
    let _ = stream.finish();

    let (ok, lines) = peer_proc.finish();
    assert!(ok, "ice_peer relay failed");
    assert!(lines.iter().any(|l| l == "CLIENT_DONE"), "lines: {lines:?}");
    drop(relay_proc);
}

#[test]
fn agent_continues_past_dead_direct_candidate_to_the_relayed_one() {
    // A hostile/dead higher-priority direct candidate must not poison
    // the walk: its typed failure is recorded, the relayed pair still
    // wins.
    let (relay_proc, relay_addr) = spawn_relay();
    let (peer_proc, relayed, node_id) = spawn_ice_peer(&[
        "--mode",
        "relay",
        "--relay",
        &relay_addr.to_string(),
        "--seed-hex",
        PEER_SEED_HEX,
        "--frames",
        "1",
    ]);

    let remote = [
        dead_host_candidate(),
        Candidate::new(CandidateType::Relayed, relayed, relayed, 1, 65_535)
            .expect("candidate"),
    ];
    let mut config = AgentConfig::default();
    config.check = fast_stun_config();
    config.relay = Some(RelayEndpoint {
        addr: relay_addr,
        credential: None,
    });
    let nomination = sharenet_transport_ice::agent::nominate(&config, &remote)
        .expect("the relayed pair must win after the dead direct candidate fails");

    assert_eq!(nomination.path, PathKind::Relay);
    assert_eq!(nomination.pair.remote.transport_addr(), relayed);
    assert!(
        nomination.attempts.iter().all(|a| a.outcome.is_err()),
        "the transcript records only the failed dead-direct attempt"
    );

    let mut stream = sharenet_transport_ice::tunnel_connect(
        &nomination.pair.remote,
        CLIENT_SEED,
        node_id,
    )
    .expect("tunnel on the post-fallback nomination");
    let payload = b"agent-fallback".to_vec();
    stream.send_frame(&payload).expect("send");
    let echoed = stream.recv_frame().expect("recv");
    let mut want = b"echo:".to_vec();
    want.extend_from_slice(&payload);
    assert_eq!(echoed, want);
    stream.send_frame(b"done").expect("client done");
    let _ = stream.finish();

    let (ok, lines) = peer_proc.finish();
    assert!(ok);
    assert!(lines.iter().any(|l| l == "CLIENT_DONE"), "lines: {lines:?}");
    drop(relay_proc);
}

#[test]
fn agent_local_relay_allocation_with_wrong_credential_fails_typed() {
    // Client-side fallback with the WRONG long-term credential: the
    // allocation is refused with the typed auth error (never a crash,
    // never a fabricated path), and the relay survives for a correct
    // credential afterwards.
    let (relay_proc, relay_addr) = spawn_relay_with_auth("alice", "wonderland");

    // All direct candidates dead → phase 2 (local relayed allocation).
    let remote = [dead_host_candidate()];
    let mut config = AgentConfig::default();
    config.check = fast_stun_config();
    config.relay = Some(RelayEndpoint {
        addr: relay_addr,
        credential: Some(
            RelayCredential::parse("alice:wrong-secret").expect("credential"),
        ),
    });
    let refused = sharenet_transport_ice::agent::nominate(&config, &remote);
    match refused.err().expect("wrong credential must refuse") {
        IceError::RelayAuthRejected { .. } => {}
        other => panic!("expected RelayAuthRejected, got {other:?}"),
    }

    // The relay survived: the CORRECT credential allocates fine.
    let good = RelayCredential::parse("alice:wonderland").expect("credential");
    let client =
        RelayClient::allocate_authenticated(relay_addr, "127.0.0.1:0".parse().expect("addr"), &good);
    assert!(client.is_ok(), "relay must survive refused auth: {client:?}");
    drop(relay_proc);
}

#[test]
fn authenticated_relay_serves_the_agent_path_end_to_end() {
    // The full authenticated dance over real processes: the peer sits
    // behind the credentialed relay; the agent's relay-only walk rides
    // the authenticated allocation transparently; the tunnel completes.
    let (relay_proc, relay_addr) = spawn_relay_with_auth("carol", "s3cret");
    let (peer_proc, relayed, node_id) = spawn_ice_peer(&[
        "--mode",
        "relay",
        "--relay",
        &relay_addr.to_string(),
        "--credential",
        "carol:s3cret",
        "--seed-hex",
        PEER_SEED_HEX,
        "--frames",
        "2",
    ]);

    let remote = [Candidate::new(CandidateType::Relayed, relayed, relayed, 1, 65_535)
        .expect("candidate")];
    let mut config = AgentConfig::default();
    config.check = fast_stun_config();
    config.relay = Some(RelayEndpoint {
        addr: relay_addr,
        credential: Some(
            RelayCredential::parse("carol:s3cret").expect("credential"),
        ),
    });
    let nomination = sharenet_transport_ice::agent::nominate(&config, &remote)
        .expect("nomination through the authenticated relay");

    assert_eq!(nomination.path, PathKind::Relay);

    let mut stream = sharenet_transport_ice::tunnel_connect(
        &nomination.pair.remote,
        CLIENT_SEED,
        node_id,
    )
    .expect("pinned QUIC connect through the authenticated relay path");
    for i in 1..=2u32 {
        let payload = format!("agent-auth-{i}").into_bytes();
        stream.send_frame(&payload).expect("send");
        let echoed = stream.recv_frame().expect("recv");
        let mut want = b"echo:".to_vec();
        want.extend_from_slice(&payload);
        assert_eq!(echoed, want);
    }
    stream.send_frame(b"done").expect("client done");
    let _ = stream.finish();

    let (ok, lines) = peer_proc.finish();
    assert!(ok);
    assert!(lines.iter().any(|l| l == "CLIENT_DONE"), "lines: {lines:?}");
    drop(relay_proc);
}
