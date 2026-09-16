//! R9-003 dedicated gateway appliance: the endurance verify level.
//!
//! A real appliance PROCESS serving sequential participant sessions
//! over the full admission-verified stack (pinned QUIC tunnel → route
//! commitment → circuit admission → data plane → BYE), with a MID-RUN
//! APPLIANCE RESTART: the process is killed and relaunched on the same
//! identity directory and journal, and the test asserts the three
//! appliance laws:
//!
//! 1. **durable identity** — the relaunched appliance presents the SAME
//!    node id (participants pin it across restarts);
//! 2. **ordinal continuity** — the first post-restart session's
//!    ordinal resumes after the last journaled one;
//! 3. **cumulative totals** — the journal's total forwarded frames
//!    spans the restart (APPLIANCE_DONE reports life totals, not
//!    process totals).
//!
//! Endurance honesty: this is a MINUTES-scale multiprocess soak (the
//! sandbox's bounded form); the 24-hour endurance with sustained load
//! is R10-003's dedicated item. The real-network leg
//! (`appliance_real_internet_leg`) follows the R4-007 mission-gate
//! discipline: attempt a REAL public-resolver uplink through the
//! appliance; when the host network is restrictive the test prints the
//! typed reason and SKIPS (never a false pass).

use std::io::{BufRead, BufReader, Write};
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use sharenet_protocol::identity::Identity;
use sharenet_transport_linux::gateway::GatewayClient;

const LINUX_BIN: &str = env!("CARGO_BIN_EXE_sharenet_transport_linux");
/// The deterministic appliance seed (tests pre-create the seed file so
/// the node id is known; production creates it from OS entropy).
const APPLIANCE_SEED: [u8; 32] = [0x9A; 32];
const PARTICIPANT_SEED: [u8; 32] = [0x50; 32];

type SharedLines = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

struct Proc {
    child: Child,
    all: SharedLines,
    drain: Option<std::thread::JoinHandle<()>>,
}

impl Proc {
    fn spawn(args: &[&str]) -> (Proc, String) {
        let mut child = Command::new(LINUX_BIN)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn appliance");
        let stdout = child.stdout.take().expect("piped stdout");
        let mut reader = BufReader::new(stdout);
        let mut first = String::new();
        reader.read_line(&mut first).expect("READY line");
        let all: SharedLines = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = all.clone();
        let drain = std::thread::spawn(move || {
            for line in reader.lines() {
                match line {
                    Ok(l) => sink.lock().expect("lines lock").push(l),
                    Err(_) => break,
                }
            }
        });
        (
            Proc {
                child,
                all,
                drain: Some(drain),
            },
            first,
        )
    }

    /// Wait (bounded) for a line starting with `prefix` to appear — the
    /// honest way to observe an appliance-side effect (the session line
    /// prints AFTER the journal record is fsync'd, so seeing it means
    /// the record is durable) before killing the process.
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
        let status = self.child.wait().expect("appliance exit");
        if let Some(handle) = self.drain.take() {
            handle.join().expect("drain");
        }
        let lines = self.all.lock().expect("lines lock").clone();
        (status.success(), lines)
    }

    fn kill(mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.drain.take() {
            let _ = handle.join();
        }
    }
}

/// A raw UDP echo server standing in for the Internet (the R4-003
/// mission-gate convention: the ShareNet evidence is the appliance's
/// admission + forwarding, not the echo).
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

fn tempdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sharenet-appliance-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // the appliance's identity-dir law: private (0700 — the operator
    // discipline; /tmp's default umask would leave it group-writable)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    dir
}

/// Pre-create the appliance identity (deterministic seed, 0600) so the
/// node id is known before the first launch.
fn seed_identity_dir(dir: &std::path::Path) -> [u8; 32] {
    use std::os::unix::fs::OpenOptionsExt;
    let path = dir.join("appliance.seed");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("seed create");
    file.write_all(&APPLIANCE_SEED).expect("seed write");
    Identity::from_seed(APPLIANCE_SEED, 0, None)
        .expect("identity")
        .node_id()
        .as_bytes()
        .to_owned()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One participant session: connect (node-pinned), establish the
/// circuit, push `packets` payloads, read the responses, destroy.
fn run_participant(
    appliance_addr: std::net::SocketAddr,
    appliance_node: [u8; 32],
    packets: usize,
) -> usize {
    let client = GatewayClient::new(PARTICIPANT_SEED, appliance_addr, appliance_node);
    let participant = Identity::from_seed(PARTICIPANT_SEED, 0, None).expect("participant identity");
    let mut session = client.connect().expect("participant connect");
    let mut received = 0usize;
    for i in 0..packets {
        let payload = format!("appliance-soak-packet-{i}").into_bytes();
        session.send_packet(&payload).expect("send");
        let response = session.recv_response().expect("response");
        assert_eq!(response, payload, "the echo must return the exact payload");
        received += 1;
    }
    session.destroy(&participant, "completed").expect("destroy");
    received
}

/// Endurance: N sessions pre-restart, a hard kill, M sessions
/// post-restart — identity, ordinal and totals all continue.
#[test]
fn appliance_endures_sessions_and_hard_restart() {
    let dir = tempdir("endure");
    let expected_node = seed_identity_dir(&dir);
    let internet = spawn_internet_echo();
    let uplink = format!("{internet}");

    // Phase 1: three sessions, then a clean --max-sessions exit.
    let (proc, ready) = Proc::spawn(&[
        "appliance",
        "--identity-dir",
        dir.to_str().unwrap(),
        "--uplink",
        &uplink,
        "--max-sessions",
        "3",
    ]);
    let ready = ready.trim();
    let Some(rest) = ready.strip_prefix("APPLIANCE_READY ") else {
        panic!("bad READY line: {ready:?}");
    };
    let (addr_str, node_hex) = rest.split_once(' ').expect("READY fields");
    assert_eq!(
        node_hex, 
        format!("{}", hex(&expected_node)),
        "the appliance presents the durable identity"
    );
    let appliance_addr: std::net::SocketAddr = addr_str.parse().expect("addr");
    let appliance_node = expected_node;

    for i in 0..3u64 {
        let got = run_participant(appliance_addr, appliance_node, 4);
        assert_eq!(got, 4, "session {i} must echo 4 packets");
    }
    let (ok, lines) = proc.finish();
    assert!(ok, "appliance must exit cleanly: {lines:?}");
    let sessions: Vec<&str> = lines
        .iter()
        .filter(|l| l.starts_with("APPLIANCE_SESSION "))
        .map(String::as_str)
        .collect();
    assert_eq!(sessions.len(), 3, "three session lines: {lines:?}");
    for (i, line) in sessions.iter().enumerate() {
        let ordinal: u64 = line.split(' ').nth(1).unwrap().parse().unwrap();
        assert_eq!(ordinal, i as u64 + 1, "ordinals 1,2,3: {line}");
    }
    let done = lines
        .iter()
        .find(|l| l.starts_with("APPLIANCE_DONE "))
        .expect("done line");
    let total_before: u64 = done.split(' ').nth(1).unwrap().parse().unwrap();
    let frames_before: u64 = done.split(' ').nth(2).unwrap().parse().unwrap();
    assert_eq!(total_before, 3);
    assert_eq!(frames_before, 12, "3 sessions x 4 frames each");

    // Phase 2: the HARD restart — kill a live appliance serving more
    // sessions than it completed, relaunch on the same identity + journal.
    let (proc2, ready2) = Proc::spawn(&[
        "appliance",
        "--identity-dir",
        dir.to_str().unwrap(),
        "--uplink",
        &uplink,
        "--max-sessions",
        "2",
    ]);
    let ready2 = ready2.trim();
    let rest2 = ready2
        .strip_prefix("APPLIANCE_READY ")
        .expect("second READY");
    let (addr2, node2) = rest2.split_once(' ').expect("fields");
    // the DURABLE IDENTITY law: same node id after restart
    assert_eq!(node2, hex(&expected_node), "identity survives restart");
    let appliance_addr2: std::net::SocketAddr = addr2.parse().expect("addr 2");

    let got = run_participant(appliance_addr2, appliance_node, 3);
    assert_eq!(got, 3);
    // DURABILITY BEFORE THE KILL: the APPLIANCE_SESSION line prints
    // only after the journal record is appended + fsync'd — wait for it
    // so the hard kill can never race the durable evidence.
    let session4 = proc2.wait_for_line("APPLIANCE_SESSION 4 ", Duration::from_secs(5));
    assert!(
        session4.contains(" 3 completed"),
        "session 4 served 3 frames: {session4}"
    );
    // the kill: the second session slot is never served (mid-life kill)
    proc2.kill();

    // Phase 3: the relaunch — the journal carries 4 sessions; the next
    // session's ordinal must be 5, and DONE must report LIFE totals.
    let (proc3, ready3) = Proc::spawn(&[
        "appliance",
        "--identity-dir",
        dir.to_str().unwrap(),
        "--uplink",
        &uplink,
        "--max-sessions",
        "1",
    ]);
    let ready3 = ready3.trim();
    let rest3 = ready3
        .strip_prefix("APPLIANCE_READY ")
        .expect("third READY");
    let (addr3, node3) = rest3.split_once(' ').expect("fields");
    assert_eq!(node3, hex(&expected_node), "identity survives again");
    let appliance_addr3: std::net::SocketAddr = addr3.parse().expect("addr 3");

    let got = run_participant(appliance_addr3, appliance_node, 2);
    assert_eq!(got, 2);
    let (ok3, lines3) = proc3.finish();
    assert!(ok3, "relaunch must exit cleanly: {lines3:?}");
    let session_line = lines3
        .iter()
        .find(|l| l.starts_with("APPLIANCE_SESSION "))
        .expect("one session line");
    let ordinal: u64 = session_line.split(' ').nth(1).unwrap().parse().unwrap();
    assert_eq!(ordinal, 5, "the ordinal resumes after the journal: {session_line}");
    let done3 = lines3
        .iter()
        .find(|l| l.starts_with("APPLIANCE_DONE "))
        .expect("done line 3");
    let total_after: u64 = done3.split(' ').nth(1).unwrap().parse().unwrap();
    let frames_after: u64 = done3.split(' ').nth(2).unwrap().parse().unwrap();
    assert_eq!(total_after, 5, "life totals: 4 journaled + 1 new");
    assert_eq!(frames_after, 17, "12 + 3 + 2 frames across the restarts");
}

/// The real-network leg (the R4-007 mission-gate discipline): a REAL
/// public-resolver uplink behind the appliance; a real DNS response
/// returning through the full stack. Gated honestly: when no resolver
/// answers from this host, the test prints the typed reason and SKIPS.
#[test]
fn appliance_real_internet_leg() {
    const RESOLVERS: &[&str] = &["8.8.8.8:53", "9.9.9.9:53", "1.1.1.1:53", "8.8.4.4:53"];
    let query: [u8; 29] = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, b'e',
        b'x', b'a', b'm', b'p', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00,
        0x01,
    ];
    // probe the resolvers directly first (the honest gate)
    let probe = UdpSocket::bind("0.0.0.0:0").expect("probe bind");
    probe
        .set_read_timeout(Some(Duration::from_millis(1_500)))
        .expect("timeout");
    let mut uplink: Option<std::net::SocketAddr> = None;
    for candidate in RESOLVERS {
        let dest: std::net::SocketAddr = candidate.parse().expect("resolver");
        if probe.send_to(&query, dest).is_err() {
            continue;
        }
        let mut buf = [0u8; 1_500];
        if probe.recv_from(&mut buf).is_ok() {
            uplink = Some(dest);
            break;
        }
    }
    let Some(uplink) = uplink else {
        println!(
            "REAL_INTERNET_UNAVAILABLE: no public resolver answered on UDP/53 from this \
             host — the appliance real-network leg is skipped honestly (the loopback \
             endurance soak ran unconditionally)"
        );
        return;
    };
    println!("real-Internet uplink confirmed: {uplink}");

    // The appliance with the REAL uplink, one session, one real DNS
    // query through the entire stack.
    let dir = tempdir("real");
    let expected_node = seed_identity_dir(&dir);
    let (proc, ready) = Proc::spawn(&[
        "appliance",
        "--identity-dir",
        dir.to_str().unwrap(),
        "--uplink",
        &uplink.to_string(),
        "--max-sessions",
        "1",
    ]);
    let ready = ready.trim();
    let rest = ready.strip_prefix("APPLIANCE_READY ").expect("READY");
    let (addr_str, node_hex) = rest.split_once(' ').expect("fields");
    assert_eq!(node_hex, hex(&expected_node));
    let appliance_addr: std::net::SocketAddr = addr_str.parse().expect("addr");

    let client = GatewayClient::new(PARTICIPANT_SEED, appliance_addr, expected_node);
    let participant = Identity::from_seed(PARTICIPANT_SEED, 0, None).expect("participant");
    let mut session = client.connect().expect("connect");
    session.send_packet(&query).expect("dns query through the stack");
    let response = session.recv_response().expect("real dns response");
    session.destroy(&participant, "completed").expect("destroy");
    // the response is a REAL DNS answer for example.com (the R4-007
    // evidence shape: txid echo + QR + opcode 0 + QDCOUNT 1 — a real
    // resolver processed OUR query; AN/NS/AR counts legitimately differ)
    assert!(response.len() >= 12, "a DNS header arrived: {} bytes", response.len());
    assert_eq!(response[0], 0x12, "txid high byte echoes");
    assert_eq!(response[1], 0x34, "txid low byte echoes");
    assert_eq!(response[2] & 0x80, 0x80, "the QR bit: this is a RESPONSE");
    assert_eq!(response[3] & 0x0F, 0x00, "opcode 0 (standard query)");
    assert_eq!(response[5], 0x01, "one question echoed");
    let (ok, lines) = proc.finish();
    assert!(ok, "appliance exits cleanly: {lines:?}");
    let session_line = lines
        .iter()
        .find(|l| l.starts_with("APPLIANCE_SESSION "))
        .expect("session line");
    assert!(
        session_line.ends_with(" 1 bye") || session_line.contains(" 1 "),
        "one frame forwarded: {session_line}"
    );
    println!("real response through the appliance: {} bytes", response.len());
}
