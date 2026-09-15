//! R4-001 multiprocess verification: a REAL client process and a REAL
//! server process exchange frames over a REAL QUIC/TLS 1.3 tunnel on
//! loopback, with the server's ShareNet node identity pinned by the
//! client; a wrong pin is rejected.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use sharenet_transport_quic::TunnelClient;

const PEER_BIN: &str = env!("CARGO_BIN_EXE_sharenet_quic_peer");
const PEER_SEED_HEX: &str = "7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a";

struct Peer {
    child: Child,
    reader: std::thread::JoinHandle<Vec<String>>,
}

fn spawn_peer(frames: usize) -> (Peer, std::net::SocketAddr) {
    spawn_peer_mode(frames, false)
}

fn spawn_peer_mode(frames: usize, evil: bool) -> (Peer, std::net::SocketAddr) {
    let mut cmd = Command::new(PEER_BIN);
    cmd.args(["--seed-hex", PEER_SEED_HEX, "--frames", &frames.to_string()]);
    if evil {
        cmd.args(["--evil", "oversize"]);
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn quic peer");
    let stdout = child.stdout.take().expect("stdout");
    let mut first = String::new();
    let mut reader = BufReader::new(stdout);
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
    let addr = first
        .trim()
        .strip_prefix("READY ")
        .expect("ready line")
        .parse()
        .expect("addr");
    (Peer { child, reader: handle }, addr)
}

fn peer_node_id() -> [u8; 32] {
    let seed: [u8; 32] = (0..32)
        .map(|i| u8::from_str_radix(&PEER_SEED_HEX[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap();
    sharenet_protocol::identity::Identity::from_seed(seed, 0, None)
        .unwrap()
        .node_id()
        .as_bytes()
        .to_owned()
}

#[test]
fn two_process_quic_tunnel_with_node_pinning() {
    let (mut peer, addr) = spawn_peer(3);
    let client = TunnelClient::new([0x33u8; 32]).expect("client");
    let mut tunnel = client
        .connect(addr, peer_node_id().try_into().unwrap())
        .expect("pinned connect");
    for payload in [b"tunnel-1".to_vec(), b"tunnel-2".to_vec(), b"tunnel-3".to_vec()] {
        tunnel.send_frame(&payload).expect("send");
        let echoed = tunnel.recv_frame().expect("recv");
        let mut want = b"echo:".to_vec();
        want.extend_from_slice(&payload);
        assert_eq!(echoed, want);
    }
    // confirm receipt so the peer can exit without losing in-flight data
    tunnel.send_frame(b"done").expect("client done");
    let _ = tunnel.finish();
    let status = peer.child.wait().expect("peer exit");
    let lines = peer.reader.join().expect("reader");
    assert!(status.success(), "peer failed: {status} {lines:?}");
    assert!(lines.iter().any(|l| l == "PEER_DONE"));
}

#[test]
fn wrong_node_pin_rejected() {
    let (mut peer, addr) = spawn_peer(0);
    let client = TunnelClient::new([0x44u8; 32]).expect("client");
    let wrong_pin: [u8; 32] = [0xEE; 32];
    let result = client.connect(addr, wrong_pin);
    assert!(
        result.is_err(),
        "connection with a wrong node pin must fail"
    );
    if let Err(e) = result {
        let msg = e.to_string();
        assert!(
            msg.contains("pin mismatch") || msg.contains("Certificate"),
            "expected pin mismatch failure, got: {msg}"
        );
    }
    // the peer never gets a valid connection; it idles — kill it
    let _ = peer.child.kill();
    let _ = peer.child.wait();
    let _ = peer.reader.join();
}

#[test]
fn adversarial_oversized_frame_header_rejected() {
    // The peer — after a fully authenticated handshake — writes a bogus
    // 0xFFFFFFFF length prefix. The client must refuse the frame with
    // FrameTooLarge instead of trying to buffer 4 GiB.
    let (mut peer, addr) = spawn_peer_mode(0, true);
    let client = TunnelClient::new([0x55u8; 32]).expect("client");
    let mut tunnel = client
        .connect(addr, peer_node_id().try_into().unwrap())
        .expect("pinned connect");
    // open the tunnel with a frame (QUIC signals remote streams only on
    // first use — the peer's accept needs the client's data to materialize)
    tunnel.send_frame(b"opener").expect("opener");
    match tunnel.recv_frame() {
        Err(sharenet_transport_quic::TunnelError::FrameTooLarge { len, max }) => {
            assert_eq!(len, 0xFFFF_FFFF);
            assert_eq!(max, sharenet_transport_quic::MAX_FRAME);
        }
        Err(other) => panic!("expected FrameTooLarge, got: {other}"),
        Ok(frame) => panic!("oversized frame must be rejected, got {} bytes", frame.len()),
    }
    // the rejection is local; the connection is still healthy — confirm
    // so the peer exits cleanly after the payload was observed
    tunnel.send_frame(b"done").expect("client done");
    let _ = tunnel.finish();
    let status = peer.child.wait().expect("peer exit");
    let lines = peer.reader.join().expect("reader");
    assert!(status.success(), "peer failed: {status} {lines:?}");
    assert!(lines.iter().any(|l| l == "PEER_DONE"));
}
