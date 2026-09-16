//! Integration test: R6-002's restart evidence — a transfer interrupted
//! mid-flight over a REAL TCP socket between REAL processes, then
//! completed by a SECOND process pair resuming from the same durable
//! state dir.
//!
//! What this proves (the work item's verify levels: restart,
//! integration):
//!
//! 1. **Interrupted transfer persists verified progress.** Sender
//!    process #1 aborts the connection after a scripted number of chunk
//!    deliveries (`--stop-after-chunks`); receiver process #1 exits on
//!    the carriage loss with its verified chunks ON DISK.
//! 2. **Resume is exact.** A fresh receiver process re-opens the state
//!    dir: every chunk file re-verifies (RELOAD accepted == seen), the
//!    bitmap is re-derived from the verified set — and the second
//!    transfer fetches EXACTLY the complement (accepted == total - prior).
//! 3. **Delivery is byte-exact.** The reassembled content equals the
//!    original file byte for byte, and both processes agree on the
//!    content id (manifest-only trust binding across processes).
//!
//! The whole flow runs the REAL binary (`sharenet_transfer` recv/send)
//! through the REAL protocol code path — no in-process shortcuts.

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

const BIN: &str = env!("CARGO_BIN_EXE_sharenet_transfer");
const WAIT: Duration = Duration::from_secs(30);

/// A spawned binary with a line stream for its stdout.
struct Proc {
    child: Child,
    lines: Receiver<String>,
}

fn spawn(args: &[&str]) -> Proc {
    let mut child = Command::new(BIN)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sharenet_transfer");
    let stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            if tx.send(line.expect("line")).is_err() {
                break;
            }
        }
    });
    Proc {
        child,
        lines: rx,
    }
}

/// Wait until the receiver prints `READY <addr>` and return it.
fn wait_ready(proc: &mut Proc) -> String {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        match proc.lines.recv_timeout(Duration::from_millis(200)) {
            Ok(line) => {
                if let Some(addr) = line.strip_prefix("READY ") {
                    return addr.to_string();
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => continue,
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    panic!("receiver never printed READY");
}

/// Wait for the process to exit (with a deadline), returning its code
/// and every stdout line it produced.
fn wait_exit(proc: &mut Proc) -> (i32, Vec<String>) {
    let mut collected: Vec<String> = Vec::new();
    let deadline = Instant::now() + WAIT;
    loop {
        // Drain whatever has arrived.
        while let Ok(line) = proc.lines.try_recv() {
            collected.push(line);
        }
        match proc.child.try_wait().expect("try_wait") {
            Some(status) => {
                while let Ok(line) = proc.lines.try_recv() {
                    collected.push(line);
                }
                return (
                    status.code().unwrap_or(-1),
                    collected,
                );
            }
            None => {}
        }
        assert!(Instant::now() < deadline, "process did not exit in time");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve a port")
        .local_addr()
        .expect("addr")
        .port()
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sharenet-transfer-mpr-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

/// Deterministic non-trivial content: 1234 bytes over 64-byte chunks =
/// 20 chunks (last one short).
fn content() -> Vec<u8> {
    let mut x: u32 = 0x1234_5678;
    (0..1234)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x & 0xFF) as u8
        })
        .collect()
}

#[test]
fn interrupted_transfer_resumes_in_new_processes_byte_exact() {
    let dir = temp_dir("resume");
    let content_path = dir.join("content.bin");
    let state_dir = dir.join("state");
    std::fs::write(&content_path, content()).expect("write content");

    // ---- Session 1: interrupted after 6 of 20 chunks. ------------------
    let port1 = free_port().to_string();
    let mut recv1 = spawn(&[
        "recv",
        "--bind",
        &format!("127.0.0.1:{port1}"),
        "--state-dir",
        state_dir.to_str().unwrap(),
    ]);
    let addr1 = wait_ready(&mut recv1);
    assert!(addr1.contains(&port1), "READY line carries the bound addr");

    let mut send1 = spawn(&[
        "send",
        "--addr",
        &addr1,
        "--content-file",
        content_path.to_str().unwrap(),
        "--chunk-size",
        "64",
        "--stop-after-chunks",
        "6",
    ]);
    let (send1_code, send1_lines) = wait_exit(&mut send1);
    assert_eq!(send1_code, 0, "the scripted interruption exits 0: {send1_lines:?}");
    assert!(
        send1_lines.iter().any(|l| l == "OUTCOME interrupted sent=6"),
        "interruption evidence line: {send1_lines:?}"
    );
    // Receiver #1 dies on the carriage loss (honest, typed).
    let (recv1_code, _recv1_lines) = wait_exit(&mut recv1);
    assert_eq!(recv1_code, 1, "receiver exits 1 on the closed carriage");

    // ---- Session 2: two NEW processes resume from the SAME state dir. --
    let port2 = free_port().to_string();
    let mut recv2 = spawn(&[
        "recv",
        "--bind",
        &format!("127.0.0.1:{port2}"),
        "--state-dir",
        state_dir.to_str().unwrap(),
    ]);
    let addr2 = wait_ready(&mut recv2);

    let mut send2 = spawn(&[
        "send",
        "--addr",
        &addr2,
        "--content-file",
        content_path.to_str().unwrap(),
        "--chunk-size",
        "64",
    ]);
    let (send2_code, send2_lines) = wait_exit(&mut send2);
    let (recv2_code, recv2_lines) = wait_exit(&mut recv2);

    // Sender #2: DELIVERED, same content id as the manifest it offered.
    assert_eq!(send2_code, 0, "sender2 delivered: {send2_lines:?}");
    let delivered_id = send2_lines
        .iter()
        .find_map(|l| l.strip_prefix("OUTCOME delivered "))
        .expect("delivered line")
        .to_string();

    // Receiver #2: the reload re-verified the 6 persisted chunks…
    let reload = recv2_lines
        .iter()
        .find(|l| l.starts_with("RELOAD "))
        .expect("RELOAD line")
        .to_string();
    assert!(
        reload.contains("resumed=true"),
        "the store resumed, not re-created: {reload}"
    );
    assert!(
        reload.contains("seen=6") && reload.contains("accepted=6"),
        "all 6 persisted chunks re-verified on reload: {reload}"
    );
    assert!(
        reload.contains("evicted=0"),
        "no corruption to evict: {reload}"
    );

    // …and the second transfer fetched EXACTLY the missing 14.
    let outcome = recv2_lines
        .iter()
        .find(|l| l.starts_with("OUTCOME "))
        .expect("receiver OUTCOME line")
        .to_string();
    assert!(
        outcome.contains("accepted=14"),
        "exact resume: only the 14 missing slots were fetched: {outcome}"
    );
    assert!(
        outcome.contains("chunks=20"),
        "the manifest names all 20 chunks: {outcome}"
    );
    assert!(
        outcome.contains(&format!("delivered {delivered_id}")),
        "both processes agree on the content id: {outcome}"
    );
    assert_eq!(recv2_code, 0, "receiver2 completed: {recv2_lines:?}");

    // ---- Delivery is byte-exact. ---------------------------------------
    let delivered = std::fs::read(state_dir.join("content.bin")).expect("read delivered");
    assert_eq!(delivered, content(), "byte-exact across interruption");

    std::fs::remove_dir_all(&dir).ok();
}
