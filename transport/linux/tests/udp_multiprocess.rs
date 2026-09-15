//! Two-process UDP loopback test (R2-003 runtime evidence).
//!
//! Spawns the real `sharenet_transport_linux echo` binary as a **real second
//! process** (`std::process::Command`), sends frames over **real loopback UDP
//! sockets**, asserts every frame echoes back byte-identical, then asserts a
//! **clean shutdown** (exit code 0 + `ECHO_DONE` summary). No mocks, no fakes:
//! this exercises the same production code path the future sharenetd daemon
//! will use.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::time::Duration;

use sharenet_transport_linux::udp::UdpTransport;

/// Path to the freshly built binary (set by cargo for integration tests).
const BIN: &str = env!("CARGO_BIN_EXE_sharenet_transport_linux");

fn wait_with_timeout(child: &mut std::process::Child, secs: u64) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match child.try_wait().expect("try_wait on echo child") {
            Some(status) => return status,
            None => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    let status = child.wait().expect("wait after kill");
                    panic!("echo process did not exit within {secs}s (killed; status {status})");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

fn spawn_echo(
    max_frames: u64,
) -> (std::process::Child, SocketAddr, std::thread::JoinHandle<Vec<String>>) {
    let mut child = Command::new(BIN)
        .args(["echo", "--bind", "127.0.0.1:0", "--max-frames", &max_frames.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn echo child process");

    let stdout = child.stdout.take().expect("echo stdout piped");
    let mut reader = BufReader::new(stdout);
    let mut ready = String::new();
    reader
        .read_line(&mut ready)
        .expect("read READY line from echo stdout");
    let ready = ready.trim();
    let addr_str = ready
        .strip_prefix("READY ")
        .unwrap_or_else(|| panic!("echo printed unexpected ready line: {ready:?}"));
    let addr: SocketAddr = addr_str
        .parse()
        .unwrap_or_else(|e| panic!("echo READY address {addr_str:?} did not parse: {e}"));

    // Keep reading stdout on a background thread so the pipe never fills and
    // the child can always write its ECHO_DONE summary.
    let reader = std::thread::spawn(move || {
        let mut lines = Vec::new();
        for line in reader.lines() {
            match line {
                Ok(l) => lines.push(l),
                Err(_) => break,
            }
        }
        lines
    });

    (child, addr, reader)
}

#[test]
fn two_process_udp_echo_roundtrip_and_clean_shutdown() {
    const N: u64 = 64;
    let (mut child, echo_addr, stdout_thread) = spawn_echo(N);

    // Parent side: a real UDP transport.
    let mut client = UdpTransport::bind(&SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // Send N distinct frames with varying sizes (1..=2048 plus one large).
    let mut sent = Vec::with_capacity(N as usize);
    for i in 0..N {
        let size = match i % 4 {
            0 => 1,
            1 => 16,
            2 => 64,
            _ => 256,
        } as usize;
        let mut payload = format!("frame-{i:04}-").into_bytes();
        payload.extend(std::iter::repeat(b'x').take(size));
        if i == N - 1 {
            // One large frame (exercises the full datagram path).
            payload.extend(std::iter::repeat(b'L').take(60_000));
        }
        client.send_frame_to(echo_addr, &payload).unwrap();
        sent.push(payload);
    }

    // Collect all echoes. Loopback reorders rarely, but matching by payload
    // prefix index makes the assertion order-independent and exact.
    let mut received: Vec<Vec<u8>> = Vec::with_capacity(N as usize);
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while (received.len() as u64) < N {
        if std::time::Instant::now() > deadline {
            panic!("timeout: received only {}/{} echoes", received.len(), N);
        }
        let mut buf = vec![0u8; 70_000];
        match client.recv_frame_from(&mut buf) {
            Ok((frame, peer)) => {
                assert_eq!(peer, echo_addr, "echo reply must come from the echo process");
                received.push(frame.payload);
            }
            Err(e) => panic!("unexpected receive error while collecting echoes: {e}"),
        }
    }

    // Every sent frame came back byte-identical (set equality).
    let mut sent_sorted = sent.clone();
    sent_sorted.sort();
    let mut received_sorted = received.clone();
    received_sorted.sort();
    assert_eq!(sent_sorted, received_sorted, "echoed frames must match sent frames exactly");

    // Clean shutdown: the child exits by itself after N frames.
    let status = wait_with_timeout(&mut child, 10);
    assert_eq!(status.code(), Some(0), "echo must exit 0 after echoing N frames (got {status})");
    let lines = stdout_thread.join().expect("stdout reader thread");
    let done_line = lines.iter().find(|l| l.starts_with("ECHO_DONE")).unwrap_or_else(|| {
        panic!("echo printed no ECHO_DONE line; stdout was {lines:?}");
    });
    assert!(done_line.contains("frames=64"), "ECHO_DONE must report 64 frames: {done_line}");
    assert!(done_line.contains("status=ok"), "ECHO_DONE must report ok: {done_line}");
}

#[test]
fn two_process_echo_survives_malformed_datagrams() {
    // Adversarial: garbage datagrams (truncated headers, trailing bytes) must
    // not crash the echo process; it logs, drops, and keeps serving. Only
    // well-formed frames count toward --max-frames.
    const GOOD: u64 = 8;
    let (mut child, echo_addr, stdout_thread) = spawn_echo(GOOD);

    let raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let mut client = UdpTransport::bind(&SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();

    // 1. Header claims 100 bytes, datagram carries 5 (truncated frame).
    raw.send_to(&[0u8, 0, 0, 100, 1, 2, 3, 4, 5], echo_addr).unwrap();
    // 2. Complete frame plus trailing garbage (malformed framing).
    let mut wire = Vec::new();
    wire.extend_from_slice(&5u32.to_be_bytes());
    wire.extend_from_slice(b"hello");
    wire.extend_from_slice(b"GARBAGE");
    raw.send_to(&wire, echo_addr).unwrap();
    // 3. Shorter than a header at all.
    raw.send_to(&[1u8, 2, 3], echo_addr).unwrap();

    // Drain any (unexpected) replies to the raw socket with a short timeout.
    raw.set_read_timeout(Some(Duration::from_millis(200))).ok();
    let mut sink = [0u8; 2048];
    let _ = raw.recv_from(&mut sink);

    // Now send GOOD well-formed frames; every one must still be echoed.
    let mut sent = Vec::new();
    for i in 0..GOOD {
        let payload = format!("good-{i}").into_bytes();
        client.send_frame_to(echo_addr, &payload).unwrap();
        sent.push(payload);
    }
    let mut received = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while (received.len() as u64) < GOOD {
        if std::time::Instant::now() > deadline {
            panic!("timeout: echo stopped serving after malformed input ({}/{} good frames back)", received.len(), GOOD);
        }
        let mut buf = vec![0u8; 70_000];
        let (frame, _) = client.recv_frame_from(&mut buf).expect("well-formed echo must arrive");
        received.push(frame.payload);
    }
    let mut sent_sorted = sent;
    sent_sorted.sort();
    let mut received_sorted = received;
    received_sorted.sort();
    assert_eq!(sent_sorted, received_sorted);

    // The child must still exit cleanly, having counted the malformed ones.
    let status = wait_with_timeout(&mut child, 10);
    assert_eq!(status.code(), Some(0), "echo must survive malformed datagrams and exit 0 (got {status})");
    let lines = stdout_thread.join().expect("stdout reader thread");
    let done_line = lines.iter().find(|l| l.starts_with("ECHO_DONE")).unwrap_or_else(|| {
        panic!("echo printed no ECHO_DONE line; stdout was {lines:?}");
    });
    assert!(done_line.contains("malformed=3"), "ECHO_DONE must report the 3 malformed datagrams: {done_line}");
    assert!(done_line.contains("frames=8"), "ECHO_DONE must report 8 good frames: {done_line}");
}

#[test]
fn echo_bind_failure_exits_nonzero() {
    // Adversarial: binding a port that is already taken must fail loudly
    // with a non-zero exit code (typed AddrInUse inside the binary).
    let squatter = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let taken = squatter.local_addr().unwrap().to_string();

    let output = Command::new(BIN)
        .args(["echo", "--bind", &taken])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("run echo with occupied port");
    assert_ne!(output.status.code(), Some(0), "bind failure must not exit 0");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("bind failed"), "stderr should explain bind failure: {stderr}");
    assert!(stderr.contains("already in use"), "stderr should name AddrInUse: {stderr}");
}

#[test]
fn probe_subcommand_exits_0_or_2_and_never_crashes() {
    // The probe's exit contract: 0 when available, 2 when not — both are
    // legitimate host outcomes; a signal death would be a bug.
    let output = Command::new(BIN).arg("probe").output().expect("run probe subcommand");
    match output.status.code() {
        Some(0) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("TUN availability: available"), "stdout: {stdout}");
        }
        Some(2) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("absent") || stdout.contains("forbidden"),
                "stdout should explain the unavailability: {stdout}"
            );
        }
        other => panic!("probe exited with {other:?} (stdout {:?}, stderr {:?})",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)),
    }
}
