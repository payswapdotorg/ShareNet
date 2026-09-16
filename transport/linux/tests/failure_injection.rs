//! R10-004 — failure injection / recovery validation (verify levels:
//! adversarial, multiprocess; the real-device leg is the operator
//! runbook — see the R10-002 record).
//!
//! The mission proof's failure semantics, INJECTED at the system level
//! against REAL processes:
//!
//!  * the LINK failure shape: gateway A stays ALIVE but its INTERNET
//!    dies (the uplink stops answering — the most realistic failure a
//!    connected node's bridge suffers: its own connectivity);
//!  * the TOTAL OUTAGE shape: both gateways die mid-session — the
//!    participant must fail CLOSED and BOUNDED (typed error, no
//!    hang), and the system must be usable again once gateways
//!    return;
//!  * the DEAD-ON-ARRIVAL shape: the gateway is already gone before
//!    the connect;
//!  * the GARBAGE uplink: a hostile/misbehaving Internet answering
//!    with garbage — carried, never crashed (the bridge is a data
//!    plane, not a parser).

use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const LINUX_BIN: &str = env!("CARGO_BIN_EXE_sharenet_transport_linux");
const LOOPBACK_BIN: &str = env!("CARGO_BIN_EXE_sharenet_loopback");

const GATEWAY_A_SEED: [u8; 32] = [0xDA; 32];
const GATEWAY_B_SEED: [u8; 32] = [0xDB; 32];
const PARTICIPANT_SEED: [u8; 32] = [0xDC; 32];

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

    fn wait_for_line(&self, prefix: &str, timeout: Duration) -> String {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let lines = self.all.lock().expect("lines lock");
                if let Some(l) = lines.iter().find(|l| l.starts_with(prefix)) {
                    return l.clone();
                }
            }
            if Instant::now() >= deadline {
                let lines = self.all.lock().expect("lines lock");
                panic!("line starting with {prefix:?} never arrived; have {lines:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn lines(&self) -> Vec<String> {
        self.all.lock().expect("lines lock").clone()
    }

    fn finish(mut self) -> (bool, Vec<String>) {
        let status = self.child.wait().expect("child exit");
        if let Some(handle) = self.drain.take() {
            handle.join().expect("drain");
        }
        (status.success(), self.all.lock().expect("lines lock").clone())
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

/// A CONTROLLABLE "Internet": an uplink echo whose responses can be
/// switched off (the link-failure shape) or replaced with garbage (the
/// hostile-uplink shape).
struct ControlledUplink {
    addr: std::net::SocketAddr,
    responding: Arc<AtomicBool>,
    garbage: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ControlledUplink {
    fn spawn() -> ControlledUplink {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let addr = socket.local_addr().expect("addr");
        let responding = Arc::new(AtomicBool::new(true));
        let garbage: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let r = responding.clone();
        let g = garbage.clone();
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 65_536];
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((n, peer)) => {
                        if !r.load(Ordering::SeqCst) {
                            continue; // the link died: swallow, never answer
                        }
                        let reply = g
                            .lock()
                            .expect("garbage lock")
                            .clone()
                            .unwrap_or_else(|| buf[..n].to_vec());
                        if socket.send_to(&reply, peer).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
        ControlledUplink {
            addr,
            responding,
            garbage,
        }
    }

    fn kill_link(&self) {
        self.responding.store(false, Ordering::SeqCst);
    }
}

fn spawn_gateway(
    seed: [u8; 32],
    uplink: std::net::SocketAddr,
) -> (Proc, std::net::SocketAddr, [u8; 32]) {
    let args: Vec<String> = vec![
        "gateway".into(),
        "--seed-hex".into(),
        hex(&seed),
        "--bind".into(),
        "127.0.0.1:0".into(),
        "--uplink".into(),
        uplink.to_string(),
    ];
    let proc = Proc::spawn(LINUX_BIN, &args);
    let ready = proc.wait_for_line("READY ", Duration::from_secs(10));
    let mut parts = ready.strip_prefix("READY ").expect("gateway READY").split(' ');
    let addr: std::net::SocketAddr = parts.next().expect("addr").parse().expect("parse");
    let node_hex = parts.next().expect("node hex");
    (proc, addr, hex_to_32(node_hex))
}

fn spawn_participant(
    state_dir: &std::path::Path,
    gateway_a: (std::net::SocketAddr, [u8; 32]),
    gateway_b: (std::net::SocketAddr, [u8; 32]),
    extra: &[&str],
) -> Proc {
    let mut args: Vec<String> = vec![
        "participant".into(),
        "--seed-hex".into(),
        hex(&PARTICIPANT_SEED),
        "--state-dir".into(),
        state_dir.display().to_string(),
        "--gateway".into(),
        format!("{}#{}", gateway_a.0, hex(&gateway_a.1)),
        "--gateway".into(),
        format!("{}#{}", gateway_b.0, hex(&gateway_b.1)),
        "--packets-before".into(),
        "4".into(),
        "--packets-after".into(),
        "4".into(),
        "--idle-ms".into(),
        "1500".into(),
        "--probe-rounds".into(),
        "512".into(),
    ];
    args.extend(extra.iter().map(|s| s.to_string()));
    Proc::spawn(LOOPBACK_BIN, &args)
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sharenet-r10004-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Bounded-wait for the participant's exit (the fail-closed law: a
/// dead system must produce a typed error, never a hang).
fn wait_exit(proc: &mut Proc, bound: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + bound;
    loop {
        match proc.child.try_wait().expect("alive or exited") {
            Some(status) => return status,
            None if Instant::now() >= deadline => {
                panic!("participant did not fail closed within {bound:?} — a hang, not a failure")
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    }
}

/// THE LINK-FAILURE SHAPE: gateway A lives, its INTERNET dies. The
/// participant's probe goes unanswered (A forwards into the void),
/// the bounded idle timeout turns the silence into a typed failure,
/// the revocation + replacement run, and data continues through
/// gateway B — whose uplink is ALIVE.
#[test]
fn uplink_death_mid_session_recovers_through_replacement() {
    let dead_internet = ControlledUplink::spawn();
    let live_internet = ControlledUplink::spawn();

    let (mut gateway_a, addr_a, node_a) = spawn_gateway(GATEWAY_A_SEED, dead_internet.addr);
    let (mut gateway_b, addr_b, node_b) = spawn_gateway(GATEWAY_B_SEED, live_internet.addr);

    let state_dir = temp_dir("uplink-death");
    let mut participant = spawn_participant(
        &state_dir,
        (addr_a, node_a),
        (addr_b, node_b),
        &["--payload", "600"],
    );

    participant.wait_for_line("LOOPBACK_A_EXCHANGED ", Duration::from_secs(20));
    // INJECT: the connected node's own Internet dies (the bridge is
    // alive; the LINK is not).
    dead_internet.kill_link();

    participant.wait_for_line("LOOPBACK_DONE ", Duration::from_secs(30));
    let status = wait_exit(&mut participant, Duration::from_secs(10));
    let lines = participant.lines();
    assert!(status.success(), "participant recovered; lines: {lines:?}");
    assert!(
        lines.iter().any(|l| l.starts_with("LOOPBACK_FAILURE_DETECTED ")),
        "the dead link produced a typed failure"
    );
    // The replacement carried the traffic through the OTHER uplink.
    let (b_ok, b_lines) = gateway_b.finish();
    assert!(b_ok);
    assert!(
        b_lines.iter().any(|l| l == "GATEWAY_DONE 4 completed"),
        "gateway B summary: {b_lines:?}"
    );
    // Gateway A served its (dead-uplink) session and ended by destroy
    // from the participant? No — the participant revoked and LEFT; A
    // sees the connection close. Drop it.
    drop(gateway_a);
    std::fs::remove_dir_all(&state_dir).ok();
}

/// THE TOTAL-OUTAGE SHAPE: both gateways die mid-session. The
/// participant must fail CLOSED, BOUNDED (typed error, no hang) — and
/// once gateways return, a fresh participant completes.
#[test]
fn total_outage_fails_closed_bounded_then_system_recovers() {
    let internet = ControlledUplink::spawn();
    let (mut gateway_a, addr_a, node_a) = spawn_gateway(GATEWAY_A_SEED, internet.addr);
    let (mut gateway_b, addr_b, node_b) = spawn_gateway(GATEWAY_B_SEED, internet.addr);

    let state_dir = temp_dir("total-outage");
    let mut participant = spawn_participant(
        &state_dir,
        (addr_a, node_a),
        (addr_b, node_b),
        &["--payload", "600"],
    );

    participant.wait_for_line("LOOPBACK_A_EXCHANGED ", Duration::from_secs(20));
    // INJECT: the total outage — EVERYTHING dies.
    gateway_a.child.kill().expect("kill A");
    gateway_b.child.kill().expect("kill B");
    let _ = gateway_a.child.wait();
    let _ = gateway_b.child.wait();

    // Fail closed, bounded: the participant errors out with a typed
    // LOOPBACK_ERROR (the replacement connect to the dead B fails
    // fast; the dead-A detection is bounded by the idle timeout).
    let started = Instant::now();
    participant.wait_for_line("LOOPBACK_ERROR ", Duration::from_secs(30));
    let status = wait_exit(&mut participant, Duration::from_secs(10));
    assert!(!status.success(), "a total outage is a FAILURE, not success");
    assert!(
        started.elapsed() < Duration::from_secs(30),
        "the total outage resolved in bounded time"
    );
    let lines = participant.lines();
    assert!(
        lines.iter().any(|l| l.starts_with("LOOPBACK_FAILURE_DETECTED ")),
        "the outage was detected as a typed failure: {lines:?}"
    );

    // The system recovers: fresh gateways, a fresh participant run
    // completes end-to-end (including a replacement).
    let (mut gateway_a2, addr_a2, node_a2) = spawn_gateway(GATEWAY_A_SEED, internet.addr);
    let (gateway_b2, addr_b2, node_b2) = spawn_gateway(GATEWAY_B_SEED, internet.addr);
    let mut participant2 = spawn_participant(
        &state_dir,
        (addr_a2, node_a2),
        (addr_b2, node_b2),
        &["--payload", "600"],
    );
    participant2.wait_for_line("LOOPBACK_A_EXCHANGED ", Duration::from_secs(20));
    gateway_a2.child.kill().expect("kill the fresh A");
    let _ = gateway_a2.child.wait();
    participant2.wait_for_line("LOOPBACK_DONE ", Duration::from_secs(30));
    let status2 = wait_exit(&mut participant2, Duration::from_secs(10));
    assert!(status2.success(), "the system recovered after total outage");
    let (b_ok, b_lines) = gateway_b2.finish();
    assert!(b_ok);
    assert!(b_lines.iter().any(|l| l == "GATEWAY_DONE 4 completed"));
    std::fs::remove_dir_all(&state_dir).ok();
}

/// THE DEAD-ON-ARRIVAL SHAPE: the gateway is already gone before the
/// connect — a fast, typed, bounded failure.
#[test]
fn dead_gateway_before_connect_fails_closed_fast() {
    let internet = ControlledUplink::spawn();
    let (mut gateway_a, addr_a, node_a) = spawn_gateway(GATEWAY_A_SEED, internet.addr);
    let (mut gateway_b, addr_b, node_b) = spawn_gateway(GATEWAY_B_SEED, internet.addr);

    // INJECT: A dies before the participant even starts.
    gateway_a.child.kill().expect("kill A");
    let _ = gateway_a.child.wait();

    let state_dir = temp_dir("dead-on-arrival");
    let mut participant = spawn_participant(
        &state_dir,
        (addr_a, node_a),
        (addr_b, node_b),
        &["--payload", "600"],
    );
    let started = Instant::now();
    let line = participant.wait_for_line("LOOPBACK_ERROR ", Duration::from_secs(15));
    let status = wait_exit(&mut participant, Duration::from_secs(10));
    assert!(!status.success());
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "dead-on-arrival failed fast"
    );
    assert!(line.contains("connect"), "the typed error names the connect: {line}");
    drop(gateway_b);
    std::fs::remove_dir_all(&state_dir).ok();
}

/// THE HOSTILE-UPLINK SHAPE: a garbage-answering Internet. The bridge
/// is a data plane, not a parser: the garbage is carried back through
/// the tunnel, the circuit completes, nothing crashes.
#[test]
fn garbage_uplink_responses_are_carried_not_crashed() {
    let garbage_internet = ControlledUplink::spawn();
    *garbage_internet.garbage.lock().expect("garbage lock") =
        Some(vec![0xC0, 0xFF, 0xEE, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]);

    let (mut gateway_a, addr_a, node_a) = spawn_gateway(GATEWAY_A_SEED, garbage_internet.addr);
    let (mut gateway_b, addr_b, node_b) = spawn_gateway(GATEWAY_B_SEED, garbage_internet.addr);

    let state_dir = temp_dir("garbage");
    // --payload-hex: the exact-packet mode (a hostile uplink is not an
    // echo — the run must not depend on echo semantics).
    let query = vec![0x11, 0x22, 0x33, 0x44];
    let mut participant = spawn_participant(
        &state_dir,
        (addr_a, node_a),
        (addr_b, node_b),
        &["--payload-hex", &hex(&query), "--emit-last-response"],
    );

    participant.wait_for_line("LOOPBACK_A_EXCHANGED ", Duration::from_secs(20));
    gateway_a.child.kill().expect("kill A");
    let _ = gateway_a.child.wait();
    participant.wait_for_line("LOOPBACK_DONE ", Duration::from_secs(30));
    let status = wait_exit(&mut participant, Duration::from_secs(10));
    assert!(status.success(), "garbage was carried, not crashed");
    let lines = participant.lines();
    let response = lines
        .iter()
        .find_map(|l| l.strip_prefix("LOOPBACK_LAST_RESPONSE "))
        .expect("the last response line");
    assert_eq!(
        response,
        &hex(&[0xC0, 0xFF, 0xEE, 0x00, 0xDE, 0xAD, 0xBE, 0xEF]),
        "the garbage response was carried back VERBATIM through the whole bridge"
    );
    let (b_ok, b_lines) = gateway_b.finish();
    assert!(b_ok);
    assert!(b_lines.iter().any(|l| l == "GATEWAY_DONE 4 completed"));
    std::fs::remove_dir_all(&state_dir).ok();
}
