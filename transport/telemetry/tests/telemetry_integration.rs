//! R2-004 integration test — TWO-PROCESS REAL measurement over loopback UDP.
//!
//! Spawns the in-crate `telemetry_echo_child` binary (a REAL second process,
//! clearly-marked test scaffolding speaking the documented Wave 1 frame
//! format) and runs the REAL prober over the REAL `UdpTransport` against it:
//!
//! * Phase 1 (reliable loopback): N=200 probes, assert >= 95% delivered,
//!   `0 < ewma_rtt < 500ms`, `loss_ratio < 0.05`, `p95 >= p50` (ordering
//!   invariant), and cross-validate the child's own echo counters.
//! * Phase 2 (induced loss): the child drops every 3rd well-formed received
//!   frame (`--drop-every 3`); assert the MEASURED `loss_ratio` is within
//!   ±0.1 of 1/3, and cross-validate against the child's `dropped` counter.
//!
//! No mocks: every packet crosses real loopback sockets between two real
//! OS processes.

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use sharenet_transport_linux::udp_prober;

use sharenet_transport_telemetry::probe::ProbeConfig;

/// Path to the freshly built in-crate echo child (set by cargo).
const CHILD_BIN: &str = env!("CARGO_BIN_EXE_telemetry_echo_child");

/// Spawn the echo child and wait for its READY line.
fn spawn_echo_child(drop_every: Option<u64>) -> (Child, SocketAddr, std::thread::JoinHandle<Vec<String>>) {
    let mut cmd = Command::new(CHILD_BIN);
    cmd.args(["--bind", "127.0.0.1:0", "--idle-exit-ms", "750"]);
    if let Some(n) = drop_every {
        cmd.args(["--drop-every", &n.to_string()]);
    }
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn telemetry_echo_child process");

    let stdout = child.stdout.take().expect("child stdout piped");
    let mut reader = BufReader::new(stdout);
    let mut ready = String::new();
    reader
        .read_line(&mut ready)
        .expect("read READY line from child stdout");
    let ready = ready.trim();
    let addr_str = ready
        .strip_prefix("READY ")
        .unwrap_or_else(|| panic!("child printed unexpected ready line: {ready:?}"));
    let addr: SocketAddr = addr_str
        .parse()
        .unwrap_or_else(|e| panic!("child READY address {addr_str:?} did not parse: {e}"));

    // Drain stdout on a background thread so the pipe never fills and the
    // child can always print its CHILD_ECHO_DONE summary.
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

fn wait_with_timeout(child: &mut Child, secs: u64) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + Duration::from_secs(secs);
    loop {
        match child.try_wait().expect("try_wait on echo child") {
            Some(status) => return status,
            None => {
                if std::time::Instant::now() > deadline {
                    let _ = child.kill();
                    let status = child.wait().expect("wait after kill");
                    panic!("echo child did not exit within {secs}s (killed; status {status})");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}

/// Parse `key=value` fields out of the child's CHILD_ECHO_DONE line.
fn parse_done_counters(lines: &[String]) -> (u64, u64, u64, u64) {
    let done = lines
        .iter()
        .find(|l| l.starts_with("CHILD_ECHO_DONE"))
        .unwrap_or_else(|| panic!("child printed no CHILD_ECHO_DONE line; stdout was {lines:?}"));
    let mut echoed = None;
    let mut dropped = None;
    let mut received = None;
    let mut malformed = None;
    for part in done.split_whitespace() {
        if let Some(v) = part.strip_prefix("echoed=") {
            echoed = v.parse().ok();
        } else if let Some(v) = part.strip_prefix("dropped=") {
            dropped = v.parse().ok();
        } else if let Some(v) = part.strip_prefix("received=") {
            received = v.parse().ok();
        } else if let Some(v) = part.strip_prefix("malformed=") {
            malformed = v.parse().ok();
        }
    }
    (
        echoed.unwrap_or_else(|| panic!("no echoed= in {done:?}")),
        dropped.unwrap_or_else(|| panic!("no dropped= in {done:?}")),
        received.unwrap_or_else(|| panic!("no received= in {done:?}")),
        malformed.unwrap_or_else(|| panic!("no malformed= in {done:?}")),
    )
}

#[test]
fn two_process_reliable_loopback_measurement_200_probes() {
    const N: u64 = 200;
    let (mut child, peer, stdout_thread) = spawn_echo_child(None);

    let config = ProbeConfig {
        count: N,
        interval: Duration::from_millis(1),
        timeout: Duration::from_millis(250),
        retries: 0,
        payload_bytes: 64,
        channel_id: 0,
    };
    let mut prober = udp_prober(peer, config).expect("prober setup");
    let run = prober.run().expect("probe run against the echo child");

    // --- Sane-bounds assertions (assignment §4.1) ---
    let summary = run.summary().expect("summarize the reliable run");
    assert!(
        summary.delivered as f64 >= 0.95 * N as f64,
        "loopback is reliable: expected >= 95% delivered, got {} ({:.1}%)",
        summary.delivered,
        100.0 * summary.delivered as f64 / N as f64
    );
    assert!(
        summary.ewma_rtt_micros > 0 && summary.ewma_rtt_micros < 500_000,
        "ewma_rtt must be in (0, 500ms), got {}us",
        summary.ewma_rtt_micros
    );
    assert!(summary.loss_ratio < 0.05, "loss_ratio must be < 0.05, got {}", summary.loss_ratio);
    assert!(
        summary.p95_rtt_micros >= summary.p50_rtt_micros,
        "ordering invariant violated: p95 {} < p50 {}",
        summary.p95_rtt_micros,
        summary.p50_rtt_micros
    );

    // --- Clean child shutdown + counter cross-validation ---
    let status = wait_with_timeout(&mut child, 15);
    assert_eq!(status.code(), Some(0), "child must exit 0 on idle (got {status})");
    let lines = stdout_thread.join().expect("stdout reader thread");
    let (echoed, dropped, received, malformed) = parse_done_counters(&lines);
    assert_eq!(dropped, 0, "no induced loss in phase 1");
    assert_eq!(malformed, 0, "the prober only sends well-formed frames");
    assert_eq!(received, echoed, "every well-formed frame is echoed in phase 1");
    assert_eq!(
        echoed, run.delivered as u64,
        "child's echo count must equal the prober's delivered count (loopback loses nothing)"
    );
}

#[test]
fn two_process_induced_one_third_loss_is_measured_within_tolerance() {
    // The child drops every 3rd well-formed RECEIVED frame. With a
    // stop-and-wait prober (retries=0) each probe is exactly one received
    // frame on the child side, so the induced loss ratio is exactly 1/3.
    const N: u64 = 90; // 60 delivered, 30 dropped
    let (mut child, peer, stdout_thread) = spawn_echo_child(Some(3));

    let config = ProbeConfig {
        count: N,
        interval: Duration::from_millis(1),
        timeout: Duration::from_millis(250),
        retries: 0, // re-sends would be received as NEW frames by the child
        payload_bytes: 64,
        channel_id: 0,
    };
    let mut prober = udp_prober(peer, config).expect("prober setup");
    let run = prober.run().expect("probe run against the lossy echo child");

    let summary = run.summary().expect("summarize the induced-loss run");
    let expected = 1.0 / 3.0;
    assert!(
        (summary.loss_ratio - expected).abs() <= 0.1,
        "measured loss_ratio {:.4} must be within ±0.1 of 1/3 (delivered {}, lost {})",
        summary.loss_ratio,
        summary.delivered,
        summary.lost
    );
    // The delivered probes still produce sane RTT statistics.
    assert!(summary.delivered >= 40, "roughly 2/3 should be delivered, got {}", summary.delivered);
    assert!(summary.ewma_rtt_micros > 0 && summary.ewma_rtt_micros < 500_000);
    assert!(summary.p95_rtt_micros >= summary.p50_rtt_micros);

    // Cross-validate with the child's own counters.
    let status = wait_with_timeout(&mut child, 15);
    assert_eq!(status.code(), Some(0), "child must exit 0 on idle (got {status})");
    let lines = stdout_thread.join().expect("stdout reader thread");
    let (echoed, dropped, received, malformed) = parse_done_counters(&lines);
    assert_eq!(malformed, 0);
    assert_eq!(received, N, "every ping reached the child: {} received", received);
    assert_eq!(dropped, 30, "every 3rd of 90 well-formed frames is dropped: {}", dropped);
    assert_eq!(echoed, 60);
    assert_eq!(
        echoed, run.delivered as u64,
        "child's echo count must equal the prober's delivered count"
    );
    assert_eq!(dropped, run.lost as u64, "child's drop count must equal the prober's lost count");
}
