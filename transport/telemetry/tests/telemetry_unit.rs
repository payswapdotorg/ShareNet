//! R2-004 unit + adversarial tests — the prober over REAL loopback sockets.
//!
//! These tests drive the REAL `sharenet_transport_linux::UdpTransport`
//! through the REAL `FrameTransport` bridge (dev-dependency), against an
//! in-process responder thread that also uses real sockets — real syscalls,
//! real kernel loopback, no mock transports. The two-process measurement is
//! `tests/telemetry_integration.rs`; the fully-production binary path is
//! `transport/linux/tests/probe_rtt.rs`.
//!
//! Adversarial coverage (assignment §5):
//!  * K consecutive losses continue probing (no abort);
//!  * duplicate/late correlation ids ignored + counted (documented);
//!  * retries re-send the same correlation id;
//!  * malformed and oversized probe frames handled (typed errors, no panic);
//!  * foreign frames / wrong-address pongs ignored + counted;
//!  * prober reuse rejected;
//!  * config validated against the real transport's limits.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sharenet_transport_linux::udp::MAX_FRAME_PAYLOAD;
use sharenet_transport_linux::{udp_prober, UdpTransport};

use sharenet_transport_telemetry::probe::{decode_probe, ProbeConfig, ProbeDecode, PROBE_HEADER_LEN};
use sharenet_transport_telemetry::sample::LinkQualitySample;
use sharenet_transport_telemetry::{summarize, TelemetryError};

/// Spawn a scripted responder on a REAL loopback UdpTransport. `script`
/// receives the raw frame payload and the sender address and decides what
/// to send back. Returns the responder's address and a stop flag.
fn spawn_scripted_responder<F>(mut script: F) -> (SocketAddr, Arc<AtomicBool>, std::thread::JoinHandle<()>)
where
    F: FnMut(&mut UdpTransport, &[u8], SocketAddr) + Send + 'static,
{
    let mut responder =
        UdpTransport::bind(&SocketAddr::from(([127, 0, 0, 1], 0))).expect("responder bind");
    let addr = responder.local_addr();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_flag = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        let mut buf = vec![0u8; 4 + MAX_FRAME_PAYLOAD];
        responder
            .set_read_timeout(Some(Duration::from_millis(20)))
            .expect("responder read timeout");
        while !stop_flag.load(Ordering::Relaxed) {
            if let Ok((frame, from)) = responder.recv_frame_from(&mut buf) {
                let payload = frame.payload.clone();
                script(&mut responder, &payload, from);
            }
        }
    });
    (addr, stop, handle)
}

fn config(count: u64, interval_ms: u64, timeout_ms: u64) -> ProbeConfig {
    ProbeConfig {
        count,
        interval: Duration::from_millis(interval_ms),
        timeout: Duration::from_millis(timeout_ms),
        retries: 0,
        payload_bytes: 64,
        channel_id: 0,
    }
}

fn stop_responder(stop: &Arc<AtomicBool>, handle: std::thread::JoinHandle<()>) {
    stop.store(true, Ordering::Relaxed);
    handle.join().expect("responder thread");
}

#[test]
fn prober_measures_real_loopback_rtt_and_records_typed_samples() {
    let (addr, stop, handle) = spawn_scripted_responder(|t, payload, from| {
        let _ = t.send_frame_to(from, payload); // byte-identical echo
    });

    let cfg = config(8, 1, 500);
    let mut prober = udp_prober(addr, cfg).unwrap();
    let shared_stream = prober.stream();

    let run = prober.run().unwrap();
    stop_responder(&stop, handle);

    assert_eq!(run.delivered, 8, "loopback echo must deliver every probe");
    assert_eq!(run.lost, 0);
    assert_eq!(run.late_pongs, 0);
    assert_eq!(run.foreign_frames, 0);
    assert_eq!(run.recv_errors, 0);

    // The shared handle observed the same evidence (Arc identity + content).
    assert!(Arc::ptr_eq(&shared_stream, &run.stream));
    let samples = shared_stream.snapshot();
    assert_eq!(samples.len(), 8, "stream capacity == count: no eviction in a normal run");
    for (i, s) in samples.iter().enumerate() {
        assert_eq!(s.seq, i as u64, "samples must be recorded in probe order");
        assert!(!s.lost);
        assert_eq!(s.channel_id, 0);
        assert_eq!(s.payload_bytes, 64);
        assert!(s.rtt_micros > 0, "a real loopback RTT is always > 0us (got {})", s.rtt_micros);
        assert!(s.rtt_micros < 100_000, "loopback RTT must be sane (<100ms), got {}", s.rtt_micros);
    }

    let summary = run.summary().unwrap();
    assert_eq!(summary.delivered, 8);
    assert!(summary.ewma_rtt_micros > 0 && summary.ewma_rtt_micros < 100_000);
    assert!(summary.p95_rtt_micros >= summary.p50_rtt_micros, "ordering invariant");
    assert_eq!(summary.loss_ratio, 0.0);
}

#[test]
fn k_consecutive_losses_continue_probing_without_abort() {
    // The responder never replies: every probe must exhaust its budget, be
    // recorded lost, and the run must CONTINUE and complete normally.
    let (addr, stop, handle) = spawn_scripted_responder(|_t, _payload, _from| {
        // deliberate silence
    });

    let cfg = config(6, 2, 25);
    let mut prober = udp_prober(addr, cfg).unwrap();
    let run = prober.run().unwrap();
    stop_responder(&stop, handle);

    assert_eq!(run.delivered, 0, "silent peer: nothing can be delivered");
    assert_eq!(run.lost, 6, "all probes must be recorded lost");
    let samples = run.stream.snapshot();
    assert_eq!(samples.len(), 6);
    assert!(samples.iter().all(|s| s.lost), "all samples lost");
    // An all-lost window is real evidence and summarizes with full loss.
    let summary = run.summary().unwrap();
    assert_eq!(summary.delivered, 0);
    assert_eq!(summary.lost, 6);
    assert!((summary.loss_ratio - 1.0).abs() < 1e-12);
    assert!(!summary.has_rtt_stats());
}

#[test]
fn retries_resend_the_same_correlation_and_recover() {
    // The responder drops the FIRST copy of every correlation id and echoes
    // the second: with retries=1 every probe must still be delivered.
    let (addr, stop, handle) = spawn_scripted_responder(|t, payload, from| {
        static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<Vec<u8>>>> =
            std::sync::OnceLock::new();
        let seen = SEEN.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()));
        let first_time = seen.lock().unwrap().insert(payload.to_vec());
        if first_time {
            return; // drop the first attempt
        }
        let _ = t.send_frame_to(from, payload); // echo the re-send
    });

    let mut cfg = config(5, 2, 200);
    cfg.retries = 1;
    let mut prober = udp_prober(addr, cfg).unwrap();
    let run = prober.run().unwrap();
    stop_responder(&stop, handle);

    assert_eq!(run.delivered, 5, "retry with the same correlation id must recover each probe");
    assert_eq!(run.lost, 0);
    assert_eq!(run.late_pongs, 0);
}

#[test]
fn duplicate_pongs_are_counted_late_and_ignored() {
    // The responder echoes every ping TWICE. The first copy matches its
    // probe; the duplicate carries an earlier correlation id, must be
    // ignored (not mismatched onto the next probe) and counted.
    let (addr, stop, handle) = spawn_scripted_responder(|t, payload, from| {
        let _ = t.send_frame_to(from, payload);
        let _ = t.send_frame_to(from, payload);
    });

    let cfg = config(5, 2, 300);
    let mut prober = udp_prober(addr, cfg).unwrap();
    let run = prober.run().unwrap();
    stop_responder(&stop, handle);

    assert_eq!(run.delivered, 5, "duplicates must never break probe correlation");
    assert_eq!(
        run.late_pongs, 4,
        "the duplicate of probes 0..=3 is read during the next probe's wait; the last duplicate is never read (run ends)"
    );
    assert_eq!(run.lost, 0);
}

#[test]
fn malformed_oversized_and_foreign_frames_are_counted_never_fatal() {
    // Per ping the responder sends: a raw sub-header datagram (malformed),
    // a frame header claiming 70000 payload bytes with a short body
    // (oversized/truncated), a well-formed NON-probe frame (foreign), and
    // only then the real echo. All garbage must be counted, no panic, and
    // the probe still delivered.
    let raw = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let (addr, stop, handle) = spawn_scripted_responder(move |t, payload, from| {
        // 1. Malformed: shorter than a frame header.
        let _ = raw.send_to(&[1, 2, 3], from);
        // 2. Oversized claim: header declares 70000 bytes, body is tiny.
        let mut bogus = Vec::new();
        bogus.extend_from_slice(&70_000u32.to_be_bytes());
        bogus.extend_from_slice(&[9, 9, 9]);
        let _ = raw.send_to(&bogus, from);
        // 3. Foreign: a well-formed frame that is not a probe frame.
        let _ = t.send_frame_to(from, b"not-a-probe");
        // 4. The real echo.
        let _ = t.send_frame_to(from, payload);
    });

    let cfg = config(4, 2, 500);
    let mut prober = udp_prober(addr, cfg).unwrap();
    let run = prober.run().unwrap();
    stop_responder(&stop, handle);

    assert_eq!(run.delivered, 4, "garbage traffic must not prevent delivery");
    assert_eq!(
        run.recv_errors, 8,
        "per probe: one sub-header datagram + one oversized claim ({} counted)",
        run.recv_errors
    );
    assert_eq!(run.foreign_frames, 4, "the non-probe frames must be counted foreign");
    assert_eq!(run.late_pongs, 0);
    assert_eq!(run.lost, 0);
}

#[test]
fn pongs_from_the_wrong_address_are_foreign_not_matches() {
    // The responder answers from a DIFFERENT socket than the one the prober
    // measures: those pongs must not be credited (peer identity check).
    let stranger = Arc::new(std::net::UdpSocket::bind("127.0.0.1:0").unwrap());
    let stranger_addr = stranger.local_addr().unwrap();
    let (addr, stop, handle) = spawn_scripted_responder(move |_t, payload, from| {
        // Well-formed Wave 1 frame, but sent from the stranger's socket.
        let mut wire = Vec::with_capacity(4 + payload.len());
        wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(payload);
        let _ = stranger.send_to(&wire, from);
        let _ = stranger_addr; // captured for clarity
    });

    let cfg = config(2, 2, 40);
    let mut prober = udp_prober(addr, cfg).unwrap();
    let run = prober.run().unwrap();
    stop_responder(&stop, handle);

    assert_eq!(run.delivered, 0, "pongs from a different address must not match");
    assert_eq!(run.lost, 2);
    assert!(run.foreign_frames >= 2, "wrong-address pongs must be counted foreign");
}

#[test]
fn prober_rejects_reuse_after_a_completed_run() {
    let (addr, stop, handle) = spawn_scripted_responder(|t, payload, from| {
        let _ = t.send_frame_to(from, payload);
    });

    let mut prober = udp_prober(addr, config(2, 1, 300)).unwrap();
    let _ = prober.run().unwrap();
    match prober.run() {
        Err(TelemetryError::ProberFinished) => {}
        other => panic!("expected ProberFinished on reuse, got {other:?}"),
    }
    stop_responder(&stop, handle);
}

#[test]
fn udp_prober_validates_config_against_the_real_transport_limits() {
    let mut cfg = config(3, 1, 100);
    cfg.payload_bytes = MAX_FRAME_PAYLOAD + 1; // over the transport's limit
    match udp_prober(SocketAddr::from(([127, 0, 0, 1], 9)), cfg) {
        Err(TelemetryError::InvalidConfig { .. }) => {}
        other => panic!("expected InvalidConfig for oversized payload, got {other:?}"),
    }

    let mut cfg = config(0, 1, 100); // zero probes
    match udp_prober(SocketAddr::from(([127, 0, 0, 1], 9)), cfg) {
        Err(TelemetryError::InvalidConfig { .. }) => {}
        other => panic!("expected InvalidConfig for zero count, got {other:?}"),
    }

    let mut cfg = config(3, 1, 100);
    cfg.timeout = Duration::ZERO;
    match udp_prober(SocketAddr::from(([127, 0, 0, 1], 9)), cfg) {
        Err(TelemetryError::InvalidConfig { .. }) => {}
        other => panic!("expected InvalidConfig for zero timeout, got {other:?}"),
    }
}

#[test]
fn probe_frame_codec_rejects_short_and_foreign_payloads_without_panic() {
    // Fuzz-ish sweep over adversarial payloads: decode must classify, never
    // panic, and a real ping must round-trip.
    let mut wire = Vec::new();
    sharenet_transport_telemetry::encode_ping(&mut wire, 42, 7, 128).unwrap();
    assert_eq!(wire.len(), 128);
    match decode_probe(&wire) {
        ProbeDecode::Probe(pf) => {
            assert_eq!(pf.correlation_id, 42);
            assert_eq!(pf.seq, 7);
        }
        other => panic!("expected a decoded probe, got {other:?}"),
    }
    for garbage in [
        &[][..],
        &[0x53][..],
        &[0x53, 0x4E][..],                    // magic, nothing else
        &[0x53, 0x4E, 1][..],                 // kind, no ids
        &[0x00, 0x01, 0x02, 0x03, 0x04][..],  // foreign magic
    ] {
        match decode_probe(garbage) {
            ProbeDecode::NotAProbe | ProbeDecode::Malformed => {}
            ProbeDecode::Probe(_) => panic!("garbage {garbage:?} decoded as a probe"),
        }
    }
    // Full-length frame with an unknown kind byte.
    let mut bad_kind = wire[..PROBE_HEADER_LEN].to_vec();
    bad_kind[2] = 0xFF;
    assert_eq!(decode_probe(&bad_kind), ProbeDecode::Malformed);
}

#[test]
fn measured_samples_summarize_through_the_public_stats_api() {
    // End-to-end: a real measured run summarized through summarize() — the
    // exact path the R3-003 topology evidence layer will use.
    let (addr, stop, handle) = spawn_scripted_responder(|t, payload, from| {
        let _ = t.send_frame_to(from, payload);
    });

    let mut prober = udp_prober(addr, config(10, 1, 500)).unwrap();
    let run = prober.run().unwrap();
    stop_responder(&stop, handle);

    let snapshot: Vec<LinkQualitySample> = run.stream.snapshot();
    let summary = summarize(&snapshot).expect("measured samples must summarize");
    assert_eq!(summary.delivered, 10);
    assert!(summary.throughput_bps > 0, "10 probes over a real time span must estimate throughput");
    assert!(summary.p95_rtt_micros >= summary.p50_rtt_micros);
    assert!(summary.ewma_rtt_micros > 0);
}
