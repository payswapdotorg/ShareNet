//! R3-002 multiprocess verification: two REAL processes DISCOVER each
//! other via verified advertisements over REAL UDP sockets and then
//! establish an AUTHENTICATED LINK (R3-001) to the discovered endpoint —
//! the full discovery→link runtime path through the
//! `sharenet-discover` production caller.

use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use sharenet_protocol::advertisement::{
    Advertisement, DiscoveryCache, DiscoveryOutcome, SignedAdvertisement, TransportDescriptor,
};
use sharenet_protocol::identity::Identity;
use sharenet_protocol::store::IdentityStore;
use sharenet_protocol::link::LinkInitiator;

const DISCOVER_BIN: &str = env!("CARGO_BIN_EXE_sharenet-discover");

struct Peer {
    child: Child,
    reader: std::thread::JoinHandle<Vec<String>>,
}

fn spawn_listener(identity_dir: &str, bind: &str) -> (Peer, std::net::SocketAddr) {
    let mut child = Command::new(DISCOVER_BIN)
        .args([
            "listen",
            "--dir",
            identity_dir,
            "--bind",
            bind,
            "--ttl",
            "120",
            "--link",
            "--frames",
            "3",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("spawn sharenet-discover listener");
    let stdout = child.stdout.take().expect("listener stdout piped");
    let mut first = String::new();
    let mut reader = BufReader::new(stdout);
    reader
        .read_line(&mut first)
        .expect("read READY from listener");
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
    let ready = first.trim();
    let addr_str = ready
        .strip_prefix("READY ")
        .unwrap_or_else(|| panic!("unexpected ready line {ready:?}"));
    let addr: std::net::SocketAddr = addr_str
        .parse()
        .unwrap_or_else(|e| panic!("bad listener address {addr_str:?}: {e}"));
    (
        Peer {
            child,
            reader: handle,
        },
        addr,
    )
}

#[test]
fn two_process_discovery_then_authenticated_link_over_real_udp() {
    // Two identities on disk (the production store path).
    let tmp = tempfile_dir();
    let store_a = IdentityStore::new(&format!("{tmp}/a"));
    let store_b = IdentityStore::new(&format!("{tmp}/b"));
    let a = store_a.create(Some("discoverer".into())).expect("identity A");
    let b = store_b.create(Some("responder".into())).expect("identity B");
    let dir_b = format!("{tmp}/b");

    let (mut peer, peer_addr) = spawn_listener(&dir_b, "127.0.0.1:0");

    // Our socket: the initiator side of discovery + link.
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    socket
        .set_read_timeout(Some(Duration::from_millis(3000)))
        .expect("timeout");
    let my_addr = socket.local_addr().expect("local addr");

    // 1. Advertise ourselves to the listener.
    let ad = Advertisement::new(
        &a,
        None,
        vec![TransportDescriptor {
            kind: "udp".into(),
            endpoint: my_addr.to_string(),
        }],
        now(),
        120,
    )
    .expect("ad");
    let signed = ad.sign(&a).expect("sign ad");
    socket
        .send_to(&signed.to_envelope_bytes(), peer_addr)
        .expect("send advertisement");

    // 2. Receive the peer's reply advertisement (mutual discovery).
    let mut buf = [0u8; 65536];
    let (n, _) = socket.recv_from(&mut buf).expect("recv reply ad");
    let reply = SignedAdvertisement::from_envelope_bytes(&buf[..n]).expect("reply envelope");
    let mut cache = DiscoveryCache::new();
    match cache.receive(&reply, now()).expect("verified") {
        DiscoveryOutcome::Discovered => {}
        other => panic!("expected Discovered, got {other:?}"),
    }
    let reply_ad = reply.advertisement().expect("peer ad");
    assert_eq!(reply_ad.node_id(), b.node_id());

    // 3. The peer's advertised endpoint is the socket we've been talking to;
    //    establish an authenticated link to it.
    let udp_endpoint = reply_ad
        .transports()
        .iter()
        .find(|t| t.kind == "udp")
        .expect("udp transport in ad");
    let link_addr: std::net::SocketAddr = udp_endpoint
        .endpoint
        .parse()
        .unwrap_or_else(|e| panic!("advertised endpoint {:?}: {e}", udp_endpoint.endpoint));
    assert_eq!(link_addr, peer_addr, "advertised endpoint is the listener");

    let initiator = LinkInitiator::new(a, None).expect("fresh ephemeral");
    let msg1 = initiator.initiate();
    let msg1_bytes = msg1.to_wire_bytes();
    socket.send_to(&msg1_bytes, link_addr).expect("send msg1");
    let (n, _) = socket.recv_from(&mut buf).expect("recv msg2");
    let value = sharenet_protocol::cbor::decode(&buf[..n]).expect("msg2 cbor");
    let msg2 = sharenet_protocol::link::LinkRespond::from_wire(&value).expect("msg2");
    let msg2_bytes = buf[..n].to_vec();
    let (msg3, mut session) = initiator
        .confirm(&msg1_bytes, &msg2, &msg2_bytes)
        .expect("confirm");
    let msg3_bytes = msg3.to_wire_bytes();
    socket.send_to(&msg3_bytes, link_addr).expect("send msg3");

    // 4. Exchange frames through the discovered, authenticated link.
    for payload in [b"discover-1".as_slice(), b"discover-2".as_slice(), b"discover-3".as_slice()] {
        let sealed = session.seal(payload).expect("seal");
        socket.send_to(&sealed, link_addr).expect("send frame");
        let (n, _) = socket.recv_from(&mut buf).expect("recv echo");
        let opened = session.open(&buf[..n]).expect("open echo");
        let mut want = b"echo:".to_vec();
        want.extend_from_slice(payload);
        assert_eq!(opened, want);
    }

    // 5. The listener reports what it saw.
    let status = peer.child.wait().expect("listener exit");
    let lines = peer.reader.join().expect("reader join");
    assert!(status.success(), "listener failed: {status}; lines: {lines:?}");
    assert!(lines.iter().any(|l| l.starts_with("DISCOVERED ")));
    assert!(lines.iter().any(|l| l.starts_with("LINK_ESTABLISHED ")));
    assert!(lines.iter().any(|l| l.starts_with("ECHOED 3 frames")));
    assert!(lines.iter().any(|l| l == "LISTEN_DONE"));
}

#[test]
fn two_process_discovery_rejects_tampered_advertisement() {
    let tmp = tempfile_dir();
    let store_b = IdentityStore::new(&format!("{tmp}/b"));
    let _b = store_b.create(Some("responder-2".into())).expect("identity B");
    let dir_b = format!("{tmp}/b");
    let (mut peer, peer_addr) = spawn_listener(&dir_b, "127.0.0.1:0");

    // A tampered advertisement must be rejected by the listener (it prints
    // a rejection to stderr and keeps listening; the listener then idles out
    // cleanly).
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
    socket
        .set_read_timeout(Some(Duration::from_millis(1500)))
        .expect("timeout");
    let impostor = Identity::from_seed([0xEE; 32], 1_700_000_000, None).expect("identity");
    let ad = Advertisement::new(
        &impostor,
        None,
        vec![TransportDescriptor {
            kind: "udp".into(),
            endpoint: "127.0.0.1:1".into(),
        }],
        now(),
        120,
    )
    .expect("ad");
    let signed = ad.sign(&impostor).expect("sign");
    let mut tampered = signed.advertisement_bytes().to_vec();
    // flip a byte in the endpoint text (breaks the signature)
    if let Some(pos) = tampered.windows(9).position(|w| w == b"127.0.0.1") {
        tampered[pos] = b'9';
    }
    let bad = SignedAdvertisement::from_parts(tampered, *signed.signature());
    socket
        .send_to(&bad.to_envelope_bytes(), peer_addr)
        .expect("send tampered ad");
    // the listener rejects it and stays alive; let it idle out
    let status = peer.child.wait().expect("listener exit");
    assert!(status.success(), "listener must survive a tampered ad");
    let lines = peer.reader.join().expect("reader join");
    assert!(
        !lines.iter().any(|l| l.starts_with("DISCOVERED")),
        "tampered ad must not be discovered: {lines:?}"
    );
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn tempfile_dir() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!(
        "sharenet-r3002-{}-{:x}-{}",
        std::process::id(),
        now(),
        seq
    ));
    std::fs::create_dir_all(&d).expect("tempdir");
    d.display().to_string()
}
