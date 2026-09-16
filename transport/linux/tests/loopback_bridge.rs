//! R10-001 — the two-process Linux loopback bridge (verify level:
//! multiprocess). The mission proof, composed across REAL processes:
//!
//! gateway process A (the connected Linux node)
//!   → participant process (`sharenet_loopback`, the node without
//!     Internet)
//!   → authenticated ShareNet bridge (pinned QUIC tunnel + R4-002
//!     circuit, both processes on the wire)
//!   → data flows (a real loopback UDP echo standing in for the
//!     Internet — the established gateway_multiprocess pattern)
//!   → INDUCED gateway death (the test SIGKILLs gateway A)
//!   → automatic replacement INSIDE the participant process (R7-001
//!     revocation → R7-003 selection → R7-004 replacement circuit,
//!     durably recorded from the REAL wire evidence)
//!   → data continues on gateway process B
//!
//! What is NEW relative to every earlier test: the recovery pipeline
//! (previously exercised only through recovery_probe's files) is
//! driven by a LIVE participant session whose OWN wire evidence — the
//! exact signed envelopes exchanged with the gateway processes —
//! becomes the durable recovery record, and the recorded replacement
//! circuit id IS the live session's circuit id (asserted inside the
//! participant and again here).
//!
//! The companion `loopback_bridge_real_internet_crossing` re-runs the
//! whole flow with a REAL public resolver as the uplink (the R4-007
//! honest-skip discipline) — a real DNS response rides session B.

use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sharenet_protocol::identity::Identity;

const LINUX_BIN: &str = env!("CARGO_BIN_EXE_sharenet_transport_linux");
const LOOPBACK_BIN: &str = env!("CARGO_BIN_EXE_sharenet_loopback");

const GATEWAY_A_SEED: [u8; 32] = [0xA1; 32];
const GATEWAY_B_SEED: [u8; 32] = [0xB2; 32];
const PARTICIPANT_SEED: [u8; 32] = [0x3C; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (s.as_bytes()[2 * i] as char).to_digit(16).unwrap() as u8;
        let lo = (s.as_bytes()[2 * i + 1] as char).to_digit(16).unwrap() as u8;
        *slot = hi * 16 + lo;
    }
    out
}

type SharedLines = Arc<Mutex<Vec<String>>>;

/// A spawned process: stdout drained on a thread into a shared vec
/// (the appliance_endurance pattern — bounded `wait_for_line`
/// observation); Drop KILLS the child so a failed test never leaks a
/// hung process.
struct Proc {
    child: Child,
    all: SharedLines,
    drain: Option<std::thread::JoinHandle<()>>,
}

impl Proc {
    fn spawn(bin: &str, args: &[String]) -> Proc {
        let mut child = Command::new(bin)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn process");
        let stdout = child.stdout.take().expect("piped stdout");
        let reader = BufReader::new(stdout);
        let all: SharedLines = Arc::new(Mutex::new(Vec::new()));
        let sink = all.clone();
        let drain = std::thread::spawn(move || {
            for line in reader.lines() {
                match line {
                    Ok(l) => sink.lock().expect("lines lock").push(l),
                    Err(_) => break,
                }
            }
        });
        Proc {
            child,
            all,
            drain: Some(drain),
        }
    }

    /// Wait (bounded) for a line starting with `prefix`.
    fn wait_for_line(&self, prefix: &str, timeout: Duration) -> String {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            {
                let lines = self.all.lock().expect("lines lock");
                if let Some(l) = lines.iter().find(|l| l.starts_with(prefix)) {
                    return l.clone();
                }
            }
            if std::time::Instant::now() >= deadline {
                let lines = self.all.lock().expect("lines lock");
                panic!("line starting with {prefix:?} never arrived; have {lines:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn finish(mut self) -> (bool, Vec<String>) {
        let status = self.child.wait().expect("child exit");
        if let Some(handle) = self.drain.take() {
            handle.join().expect("drain");
        }
        let lines = self.all.lock().expect("lines lock").clone();
        (status.success(), lines)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.drain.take() {
            let _ = handle.join();
        }
    }
}

/// A raw UDP echo server standing in for the Internet (in the TEST
/// process: it is the EXTERNAL network, not ShareNet — the ShareNet
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

fn spawn_gateway(
    seed: [u8; 32],
    uplink: std::net::SocketAddr,
    pin: &str,
) -> (Proc, std::net::SocketAddr, [u8; 32]) {
    let args: Vec<String> = vec![
        "gateway".into(),
        "--seed-hex".into(),
        hex(&seed),
        "--bind".into(),
        "127.0.0.1:0".into(),
        "--uplink".into(),
        uplink.to_string(),
        "--pin".into(),
        pin.into(),
    ];
    let proc = Proc::spawn(LINUX_BIN, &args);
    let ready = proc.wait_for_line("READY ", Duration::from_secs(10));
    let mut parts = ready.strip_prefix("READY ").expect("gateway READY").split(' ');
    let addr: std::net::SocketAddr = parts.next().expect("addr").parse().expect("parse");
    let node_hex = parts.next().expect("node hex");
    (proc, addr, hex_to_32(node_hex))
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sharenet-r10001-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// The full two-process loopback bridge with the induced gateway death
/// and the in-participant replacement. `uplink` is the external
/// network (loopback echo, or a real resolver in the real-Internet
/// variant).
fn run_loopback_bridge(
    uplink: std::net::SocketAddr,
    tag: &str,
    payload_args: &[String],
) -> (Proc, Vec<String>) {
    let participant_identity =
        Identity::from_seed(PARTICIPANT_SEED, 0, None).expect("participant identity");
    let pin = hex(participant_identity.node_id().as_bytes());

    let (mut gateway_a, addr_a, node_a) = spawn_gateway(GATEWAY_A_SEED, uplink, &pin);
    let (gateway_b, addr_b, node_b) = spawn_gateway(GATEWAY_B_SEED, uplink, &pin);

    let state_dir = temp_dir(tag);
    let mut args: Vec<String> = vec![
        "participant".into(),
        "--seed-hex".into(),
        hex(&PARTICIPANT_SEED),
        "--state-dir".into(),
        state_dir.display().to_string(),
        "--gateway".into(),
        format!("{}#{}", addr_a, hex(&node_a)),
        "--gateway".into(),
        format!("{}#{}", addr_b, hex(&node_b)),
        "--packets-before".into(),
        "4".into(),
        "--packets-after".into(),
        "4".into(),
        "--idle-ms".into(),
        "1500".into(),
        "--probe-rounds".into(),
        "512".into(),
    ];
    args.extend_from_slice(payload_args);

    let mut participant = Proc::spawn(LOOPBACK_BIN, &args);

    // 1. The bridge works on gateway A: four full exchanges observed.
    participant.wait_for_line("LOOPBACK_A_EXCHANGED ", Duration::from_secs(20));

    // 2. INDUCED LINK/GATEWAY FAILURE: SIGKILL gateway A (silent
    //    death — no UDP RST; the participant's bounded idle timeout is
    //    what turns it into a typed error).
    gateway_a
        .child
        .kill()
        .expect("induce the gateway A death");
    let a_status = gateway_a.child.wait().expect("gateway A exit");
    assert!(
        a_status.code().is_none(),
        "gateway A must die by the induced signal, not a clean exit"
    );

    // 3. Automatic replacement and continued traffic, all inside the
    //    participant process.
    participant.wait_for_line("LOOPBACK_DONE ", Duration::from_secs(30));

    // 4. Gateway B exits cleanly having forwarded the after-packets.
    let (b_ok, b_lines) = gateway_b.finish();
    assert!(b_ok, "gateway B exited cleanly");
    assert!(
        b_lines.iter().any(|l| l == "GATEWAY_DONE 4 completed"),
        "gateway B summary: {b_lines:?}"
    );

    // 5. The durable recovery state exists on disk (the recovery
    //    record outlives the process that wrote it).
    assert!(
        state_dir.join("revocations.log").is_file(),
        "the durable revocation ledger exists"
    );
    assert!(
        state_dir.join("recovery-attempts.store").is_file(),
        "the durable recovery attempt log exists"
    );
    std::fs::remove_dir_all(&state_dir).ok();

    (participant, b_lines)
}

#[test]
fn two_process_loopback_bridge_survives_gateway_death() {
    let internet = spawn_internet_echo();
    let (participant, _b_lines) =
        run_loopback_bridge(internet, "loopback", &["--payload".into(), "700".into()]);

    let (ok, lines) = participant.finish();
    assert!(ok, "participant exited cleanly");
    let expected = [
        "LOOPBACK_IDENTITY ",
        "LOOPBACK_CONNECTED_A ",
        "LOOPBACK_A_EXCHANGED 4 4",
        "LOOPBACK_FAILURE_DETECTED ",
        "LOOPBACK_REVOKED ",
        "LOOPBACK_ATTEMPT 1",
        "LOOPBACK_SELECTED ",
        "LOOPBACK_CONNECTED_B ",
        "LOOPBACK_ROUTE ",
        "LOOPBACK_ZEROIZED ",
        "LOOPBACK_REPLACEMENT ",
        "LOOPBACK_B_EXCHANGED 4 4",
        "LOOPBACK_DESTROYED_B",
        "LOOPBACK_DONE ",
    ];
    let mut cursor = 0;
    for want in expected {
        let pos = lines[cursor..]
            .iter()
            .position(|l| l.starts_with(want))
            .unwrap_or_else(|| panic!("missing phase line {want:?} in order; have {lines:?}"));
        cursor += pos + 1;
    }
    // The failure WAS detected (typed, named).
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("LOOPBACK_FAILURE_DETECTED ")),
        "the induced death produced a typed failure"
    );

    // The composition law, verified from BOTH sides: the durable
    // replacement circuit the participant recorded IS the live circuit
    // that carried the bytes on gateway B (the participant asserts the
    // equality internally; here we pin that both ids were printed).
    let replacement = lines
        .iter()
        .find_map(|l| l.strip_prefix("LOOPBACK_REPLACEMENT "))
        .expect("replacement line");
    let connected_b = lines
        .iter()
        .find_map(|l| l.strip_prefix("LOOPBACK_CONNECTED_B "))
        .expect("connected B line");
    let replacement_id = replacement.split(' ').next().expect("replacement id");
    assert_eq!(
        replacement_id, connected_b,
        "the durable replacement circuit id == the live wire circuit id"
    );

    // The revoked circuit is NOT the replacement (L014: a failed
    // circuit is never resurrected; fresh nonce → fresh id).
    let revoked = lines
        .iter()
        .find_map(|l| l.strip_prefix("LOOPBACK_REVOKED "))
        .expect("revoked line");
    let revoked_id = revoked.split(' ').next().expect("revoked id");
    assert_ne!(revoked_id, replacement_id);

    // The summary line: sent = 4 (A) + probes + 4 (B); received = 8
    // (the echo rounds; the dead probe never answered).
    let done = lines
        .iter()
        .find_map(|l| l.strip_prefix("LOOPBACK_DONE "))
        .expect("done line");
    let mut fields = done.split(' ');
    let total_sent: u64 = fields.next().expect("sent").parse().expect("int");
    let total_received: u64 = fields.next().expect("received").parse().expect("int");
    let replacements: u64 = fields.next().expect("replacements").parse().expect("int");
    assert!(total_sent > 8, "at least one probe was sent at the dying A");
    assert_eq!(total_received, 8);
    assert_eq!(replacements, 1);
}

// ---------------------------------------------------------------------------
// The real-Internet variant (the R4-007 honest-skip discipline)
// ---------------------------------------------------------------------------

fn example_com_dns_query() -> Vec<u8> {
    let mut q = vec![
        0x56, 0x78, // transaction id
        0x01, 0x00, // flags: RD=1
        0x00, 0x01, // QD=1
        0x00, 0x00, // AN=0
        0x00, 0x00, // NS=0
        0x00, 0x00, // AR=0
    ];
    q.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
    q.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
    q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
    q
}

fn looks_like_our_dns_reply(query: &[u8], reply: &[u8]) -> bool {
    reply.len() >= 12
        && reply[0] == query[0]
        && reply[1] == query[1]
        && reply[2] & 0x80 != 0
        && reply[3] & 0x0F == 0
        && reply[4] == 0
        && reply[5] == 1
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A REAL DNS response through the WHOLE two-process bridge INCLUDING
/// the replacement: the query rides session A, gateway A dies, the
/// query rides session B — a real public resolver answered through
/// the replacement circuit. Honest gating: when this host's network
/// blocks UDP/53 to the public resolvers (the sandbox's restrictive
/// network), the typed reason prints and the test skips — the
/// loopback test above carries the composition evidence
/// unconditionally.
#[test]
fn loopback_bridge_real_internet_crossing() {
    const RESOLVERS: &[&str] = &["8.8.8.8:53", "9.9.9.9:53", "1.1.1.1:53", "8.8.4.4:53"];
    let query = example_com_dns_query();
    let mut uplink: Option<std::net::SocketAddr> = None;
    let probe_socket = UdpSocket::bind("0.0.0.0:0").expect("bind probe");
    probe_socket
        .set_read_timeout(Some(Duration::from_millis(1_500)))
        .expect("timeout");
    for candidate in RESOLVERS {
        let dest: std::net::SocketAddr = candidate.parse().expect("resolver addr");
        if probe_socket.send_to(&query, dest).is_err() {
            continue;
        }
        let mut buf = [0u8; 1_500];
        match probe_socket.recv_from(&mut buf) {
            Ok((n, _)) if looks_like_our_dns_reply(&query, &buf[..n]) => {
                uplink = Some(dest);
                break;
            }
            _ => continue,
        }
    }
    let uplink = match uplink {
        Some(addr) => addr,
        None => {
            println!(
                "REAL_INTERNET_UNAVAILABLE: no public resolver answered on UDP/53 from this \
                 host — the real-network loopback leg is skipped honestly (the loopback \
                 two-process composition ran unconditionally; see MISSION-GATE.md)"
            );
            return;
        }
    };
    println!("real-Internet uplink confirmed: {uplink}");

    // One query before the failure, one after — the second must ride
    // the REPLACEMENT session on gateway B.
    let (participant, _b_lines) = run_loopback_bridge(
        uplink,
        "real-internet",
        &[
            "--payload-hex".into(),
            hex_bytes(&query),
            "--emit-last-response".into(),
        ],
    );
    let (ok, lines) = participant.finish();
    assert!(ok, "participant exited cleanly");
    let response_hex = lines
        .iter()
        .find_map(|l| l.strip_prefix("LOOPBACK_LAST_RESPONSE "))
        .expect("the last response line");
    let reply = (0..response_hex.len() / 2)
        .map(|i| {
            let hi = (response_hex.as_bytes()[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (response_hex.as_bytes()[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            hi * 16 + lo
        })
        .collect::<Vec<u8>>();
    assert!(
        looks_like_our_dns_reply(&query, &reply),
        "the response through the REPLACEMENT session must be a REAL DNS reply to OUR \
         query (txid + QR + question echo), got {} bytes",
        reply.len()
    );
    println!(
        "real Internet response through the two-process bridge + replacement: {} bytes \
         from {uplink}",
        reply.len()
    );
}
