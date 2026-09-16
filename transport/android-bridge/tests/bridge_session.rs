//! The bridge core tests: a REAL in-process GatewayServer (pinned
//! QUIC tunnel, circuit admission, the R4-003 data plane) with a real
//! loopback uplink echo — the same stack the R10-001 two-process
//! loopback proved, now driven through the bridge seam.

use std::net::UdpSocket;

use sharenet_transport_linux::gateway::GatewayServer;

use sharenet_android_bridge::bridge::{BridgeError, BridgeSession, BRIDGE_API_VERSION};

const GATEWAY_SEED: [u8; 32] = [0x51; 32];
const PARTICIPANT_SEED: [u8; 32] = [0x52; 32];
const WRONG_PIN_SEED: [u8; 32] = [0x53; 32];

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

fn spawn_gateway(uplink: std::net::SocketAddr) -> (std::net::SocketAddr, [u8; 32]) {
    let gateway = GatewayServer::new(
        GATEWAY_SEED,
        "127.0.0.1:0".parse().expect("addr"),
        None,
        uplink,
    )
    .expect("gateway bind");
    let addr = gateway.local_addr().expect("tunnel addr");
    let node = gateway.node_id();
    std::thread::spawn(move || gateway.serve_once().expect("gateway serve_once"));
    (addr, node)
}

#[test]
fn bridge_session_forwards_through_a_real_gateway() {
    let internet = spawn_internet_echo();
    let (gateway_addr, gateway_node) = spawn_gateway(internet);

    let mut session = BridgeSession::open(
        PARTICIPANT_SEED,
        gateway_addr,
        gateway_node,
        5_000,
    )
    .expect("bridge session opens through the real stack");

    // A filter-shaped IP packet (the loop only hands the bridge
    // complete, filter-accepted packets — the seam contract).
    let packet = [
        0x45, 0x00, 0x00, 0x28, // IPv4, total length 40
        0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x00, 0x00,
        10, 0, 0, 1, 8, 8, 8, 8,
        // payload to fill the 40 bytes
        0xde, 0xad, 0xbe, 0xef, 0x00, 0x35, 0x00, 0x35,
        0x00, 0x14, 0x00, 0x00, 0xaa, 0xbb, 0xcc, 0xdd,
        0xee, 0xff, 0x11, 0x22,
    ];
    for round in 0..5 {
        let mut p = packet;
        p[4] = round; // vary the id field
        let responses = session.forward(&p).expect("forward");
        assert_eq!(responses.len(), 1, "one response per forward");
        assert_eq!(responses[0], p.to_vec(), "the uplink echoed verbatim");
    }
    assert_ne!(*session.circuit_id(), [0u8; 32]);
    session.destroy("completed").expect("destroy");
}

#[test]
fn wrong_pin_fails_closed() {
    let internet = spawn_internet_echo();
    let (gateway_addr, _node) = spawn_gateway(internet);
    let wrong_node = {
        // A DIFFERENT identity's node id (not the gateway's).
        let other = GatewayServer::new(
            WRONG_PIN_SEED,
            "127.0.0.1:0".parse().expect("addr"),
            None,
            internet,
        )
        .expect("other bind");
        other.node_id()
    };
    let err = match BridgeSession::open(PARTICIPANT_SEED, gateway_addr, wrong_node, 2_000) {
        Err(e) => e,
        Ok(_) => panic!("wrong pin must fail closed"),
    };
    assert!(matches!(err, BridgeError::Connect(_)), "{err}");
}

#[test]
fn forward_after_destroy_fails_closed() {
    let internet = spawn_internet_echo();
    let (gateway_addr, gateway_node) = spawn_gateway(internet);
    let mut session =
        BridgeSession::open(PARTICIPANT_SEED, gateway_addr, gateway_node, 5_000)
            .expect("open");
    session.destroy("completed").expect("destroy");
    assert_eq!(
        session.forward(b"still-alive-packet"),
        Err(BridgeError::NotOpen)
    );
    assert_eq!(session.destroy("again"), Err(BridgeError::NotOpen));
}

#[test]
fn version_is_frozen() {
    assert_eq!(BRIDGE_API_VERSION, 1);
}

/// The JNI surface symbols exist and are taken (compile-level ABI
/// verification — the JVM cross-call itself is the on-device runbook
/// leg; the symbols' presence is what loadLibrary resolves against).
#[test]
fn jni_export_surface_exists() {
    let version =
        sharenet_android_bridge::jni_surface::Java_org_sharenet_transport_vpn_BridgeNative_nativeVersion
            as unsafe extern "system" fn(
                jni::JNIEnv<'_>,
                jni::objects::JClass<'_>,
            ) -> jni::sys::jint;
    let _ = version as *const ();
}
