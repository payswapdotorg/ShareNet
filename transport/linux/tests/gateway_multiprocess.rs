//! R4-003 multiprocess verification: a REAL gateway process and a REAL
//! participant (in-process client for the data-plane flow, and the real
//! `participant` binary for the CLI flow) over a REAL node-pinned
//! QUIC/TLS 1.3 tunnel on loopback, with circuit admission (R4-002)
//! verified on both ends, forwarding through a real UDP "Internet"
//! echo server. Adversarial coverage: wrong node pins fail closed,
//! unpinned participants refused, oversize packets rejected locally.

use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use sharenet_transport_linux::gateway::{
    GatewayClient, GatewayError, GatewayServer, GATEWAY_MAX_PACKET,
};
use sharenet_protocol::identity::Identity;

const LINUX_BIN: &str = env!("CARGO_BIN_EXE_sharenet_transport_linux");

const GATEWAY_SEED_HEX: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";
const PARTICIPANT_SEED: [u8; 32] = [0x50; 32];

fn hex_to_32(s: &str) -> [u8; 32] {
    (0..32)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect::<Vec<u8>>()
        .try_into()
        .expect("32")
}

fn gateway_node_id() -> [u8; 32] {
    let seed = hex_to_32(GATEWAY_SEED_HEX);
    Identity::from_seed(seed, 0, None)
        .expect("identity")
        .node_id()
        .as_bytes()
        .to_owned()
}

/// A spawned process: stdout drained on a thread (READY consumed
/// synchronously); Drop KILLS the child (a failed test never leaks a
/// hung process).
struct Proc {
    child: Child,
    reader: Option<std::thread::JoinHandle<Vec<String>>>,
}

impl Proc {
    fn spawn(args: &[&str]) -> (Proc, String) {
        let mut child = Command::new(LINUX_BIN)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn sharenet_transport_linux");
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
        (
            Proc {
                child,
                reader: Some(handle),
            },
            first.trim().to_string(),
        )
    }

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

/// A raw UDP echo server standing in for the Internet (in the TEST
/// PROCESS: it is the EXTERNAL network, not ShareNet — the ShareNet
/// multiprocess evidence is the gateway and participant processes).
fn spawn_internet_echo() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind echo");
    let addr = socket.local_addr().expect("addr");
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65_536];
        loop {
            match socket.recv_from(&mut buf) {
                Ok((n, peer)) => {
                    if socket.send_to(&buf[..n], peer).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    addr
}

fn spawn_gateway(uplink: std::net::SocketAddr) -> (Proc, std::net::SocketAddr, [u8; 32]) {
    let (proc, ready) = Proc::spawn(&[
        "gateway",
        "--seed-hex",
        GATEWAY_SEED_HEX,
        "--bind",
        "127.0.0.1:0",
        "--uplink",
        &uplink.to_string(),
    ]);
    let mut parts = ready
        .strip_prefix("READY ")
        .expect("gateway READY line")
        .split(' ');
    let addr: std::net::SocketAddr = parts.next().expect("addr").parse().expect("parse");
    let node_hex = parts.next().expect("node hex");
    (proc, addr, hex_to_32(node_hex))
}

#[test]
fn gateway_full_data_plane_two_process() {
    let internet = spawn_internet_echo();
    let (gateway_proc, gateway_addr, gateway_node) = spawn_gateway(internet);

    // The participant side runs through the SAME public API the future
    // daemon uses.
    let client = GatewayClient::new(PARTICIPANT_SEED, gateway_addr, gateway_node);
    let mut session = client.connect().expect("establish circuit");
    let identity = Identity::from_seed(PARTICIPANT_SEED, 0, None).expect("identity");

    for i in 0..5 {
        let packet = format!("ip-packet-{i}-payload").into_bytes();
        session.send_packet(&packet).expect("send");
        let response = session.recv_response().expect("recv");
        assert_eq!(response, packet, "the Internet echoed verbatim");
    }
    session.destroy(&identity, "completed").expect("destroy");

    let (ok, lines) = gateway_proc.finish();
    assert!(ok, "gateway exited cleanly");
    assert!(
        lines.iter().any(|l| l == "GATEWAY_DONE 5 completed"),
        "gateway summary: {lines:?}"
    );
}

#[test]
fn gateway_full_data_plane_two_binaries() {
    let internet = spawn_internet_echo();
    let (gateway_proc, gateway_addr, gateway_node) = spawn_gateway(internet);
    let node_hex: String = gateway_node.iter().map(|b| format!("{b:02x}")).collect();

    let (participant_proc, ready) = Proc::spawn(&[
        "participant",
        "--seed-hex",
        &PARTICIPANT_SEED
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "--gateway",
        &gateway_addr.to_string(),
        "--gateway-node",
        &node_hex,
        "--packets",
        "4",
    ]);
    assert_eq!(ready, "PARTICIPANT_DONE 4 4", "participant summary");

    let (ok, lines) = gateway_proc.finish();
    assert!(ok, "gateway exited cleanly");
    assert!(
        lines.iter().any(|l| l == "GATEWAY_DONE 4 completed"),
        "gateway summary: {lines:?}"
    );
    let _ = participant_proc.finish();
}

#[test]
fn wrong_gateway_pin_fails_closed() {
    let internet = spawn_internet_echo();
    let (_gateway_proc, gateway_addr, _node) = spawn_gateway(internet);
    let wrong_pin = [0xEE; 32];
    let client = GatewayClient::new(PARTICIPANT_SEED, gateway_addr, wrong_pin);
    assert!(
        client.connect().is_err(),
        "a wrong gateway node pin must never complete a circuit"
    );
}

#[test]
fn gateway_pins_participants_when_configured() {
    let internet = spawn_internet_echo();
    // The gateway pins a DIFFERENT participant than ours.
    let other_node = Identity::from_seed([0x99; 32], 0, None)
        .expect("identity")
        .node_id()
        .as_bytes()
        .to_owned();
    let other_hex: String = other_node.iter().map(|b| format!("{b:02x}")).collect();
    let (mut proc, ready) = Proc::spawn(&[
        "gateway",
        "--seed-hex",
        GATEWAY_SEED_HEX,
        "--bind",
        "127.0.0.1:0",
        "--uplink",
        &internet.to_string(),
        "--pin",
        &other_hex,
    ]);
    let mut parts = ready
        .strip_prefix("READY ")
        .expect("gateway READY line")
        .split(' ');
    let addr: std::net::SocketAddr = parts.next().expect("addr").parse().expect("parse");
    let node_hex = parts.next().expect("node hex");
    let node = hex_to_32(node_hex);

    let client = GatewayClient::new(PARTICIPANT_SEED, addr, node);
    // Refusal arrives as a connection failure or an abort on first use
    // (TLS 1.3 lets the client finish its handshake view first — the
    // tunnel crate's documented behavior).
    match client.connect() {
        Err(_) => {}
        Ok(mut session) => {
            session
                .send_packet(b"probe")
                .expect("queued locally");
            assert!(
                session.recv_response().is_err(),
                "the pinned gateway must abort the unpinned participant"
            );
        }
    }
    let _ = proc.finish();
}

#[test]
fn oversize_packet_rejected_locally() {
    let internet = spawn_internet_echo();
    let (gateway_proc, gateway_addr, gateway_node) = spawn_gateway(internet);
    let client = GatewayClient::new(PARTICIPANT_SEED, gateway_addr, gateway_node);
    let mut session = client.connect().expect("establish");
    assert!(matches!(
        session.send_packet(&vec![0u8; GATEWAY_MAX_PACKET + 1]),
        Err(GatewayError::Protocol(_))
    ));
    assert!(matches!(
        session.send_packet(b""),
        Err(GatewayError::Protocol(_))
    ));
    let identity = Identity::from_seed(PARTICIPANT_SEED, 0, None).expect("identity");
    session.destroy(&identity, "policy").expect("destroy");
    let _ = gateway_proc.finish();
}

#[test]
fn in_process_gateway_data_plane() {
    // The full server in a thread (no process boundary): the same
    // admission pipeline, fast signal for regressions.
    let internet = spawn_internet_echo();
    let gateway = GatewayServer::new(
        hex_to_32(GATEWAY_SEED_HEX),
        "127.0.0.1:0".parse().unwrap(),
        Some(vec![
            Identity::from_seed(PARTICIPANT_SEED, 0, None)
                .expect("identity")
                .node_id()
                .as_bytes()
                .to_owned(),
        ]),
        internet,
    )
    .expect("gateway bind");
    let addr = gateway.local_addr().expect("addr");
    let node = gateway.node_id();
    let server = std::thread::spawn(move || gateway.serve_once().expect("serve"));

    let client = GatewayClient::new(PARTICIPANT_SEED, addr, node);
    let mut session = client.connect().expect("establish");
    for i in 0..3 {
        let packet = format!("loop-{i}").into_bytes();
        session.send_packet(&packet).expect("send");
        assert_eq!(session.recv_response().expect("recv"), packet);
    }
    let identity = Identity::from_seed(PARTICIPANT_SEED, 0, None).expect("identity");
    session.destroy(&identity, "completed").expect("destroy");
    let stats = server.join().expect("server join");
    assert_eq!(stats.forwarded_up, 3);
    assert_eq!(stats.destroy_reason.as_deref(), Some("completed"));
}

#[test]
fn gateway_seed_hex_parser_rejects_garbage() {
    // The binary's argument hygiene (exit code 2 on bad input).
    for bad in ["", "xyz", &"a".repeat(63), &"g".repeat(64)] {
        let out = Command::new(LINUX_BIN)
            .args(["gateway", "--seed-hex", bad, "--uplink", "127.0.0.1:9"])
            .output()
            .expect("run");
        assert_eq!(out.status.code(), Some(2), "bad seed {bad:?} must exit 2");
    }
    let _ = Duration::from_secs(0); // keep the import when tests trim
}
