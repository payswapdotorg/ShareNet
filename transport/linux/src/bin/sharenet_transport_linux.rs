//! `sharenet-transport-linux` — real runtime entrypoint for R2-003 + R2-004.
//!
//! Subcommands:
//!
//! * `probe` — run the honest TUN capability probe and print the result.
//!   Exit code: `0` if TUN is [`TunAvailability::Available`], `2` otherwise
//!   (Absent/Forbidden). A non-zero probe is *correct behavior* on hosts
//!   without TUN; it is not a program failure.
//! * `echo --bind ADDR [--max-frames N] [--drop-every N]` — bind a
//!   [`UdpTransport`] and echo every well-formed frame back to its sender.
//!   Used by the two-process loopback tests and as a manual runtime path.
//!   Malformed frames are counted, logged to stderr, and dropped; the
//!   server keeps running (no crash). After `N` well-formed frames have
//!   been echoed it exits cleanly (exit code `0`), printing an `ECHO_DONE`
//!   summary.
//!   `--drop-every N` is a small, honest TEST AFFORDANCE added for R2-004:
//!   every Nth *well-formed received* frame is silently dropped instead of
//!   echoed (counted as `dropped`, not toward `--max-frames`), letting the
//!   telemetry integration tests induce a known loss ratio on loopback.
//! * `probe-rtt --peer ADDR [--count N] [--interval-ms M]` (R2-004) — run
//!   the active RTT prober from `sharenet-transport-telemetry` against a
//!   peer running `echo` and print the final `LinkQualitySummary`. Exit
//!   code `0` on a completed run (loss is a MEASUREMENT, not a failure);
//!   non-zero only on setup/transport errors.
//!
//! This binary is a *production caller* of the library crates: nothing here
//! fakes anything; it constructs the same transports and probers the future
//! sharenetd daemon and the R3-003 topology evidence layer will construct.

use std::io::Write;
use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use sharenet_transport_linux::udp::{UdpError, UdpTransport, MAX_FRAME_PAYLOAD};
use sharenet_transport_linux::{probe_tun, udp_prober, TunAvailability};

use sharenet_transport_telemetry::probe::ProbeConfig;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("probe") => cmd_probe(),
        Some("echo") => cmd_echo(&args[1..]),
        Some("probe-rtt") => cmd_probe_rtt(&args[1..]),
        Some("--help") | Some("-h") | Some("help") | None => {
            print_usage();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("error: unknown subcommand {other:?}");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    println!("sharenet-transport-linux — ShareNet Linux transport foundation (R2-003 + R2-004)");
    println!();
    println!("USAGE:");
    println!("  sharenet_transport_linux probe");
    println!("      Probe real TUN availability on this host.");
    println!("      Exit code 0 = available, 2 = absent/forbidden (host limitation, not a bug).");
    println!("  sharenet_transport_linux echo --bind ADDR [--max-frames N] [--drop-every N]");
    println!("      UDP frame echo server (real runtime path).");
    println!("      --bind ADDR       address to bind, e.g. 127.0.0.1:0 (port 0 = ephemeral;");
    println!("                        the bound address is printed as READY <addr>)");
    println!("      --max-frames N    exit cleanly after N well-formed frames echoed (default: run forever)");
    println!("      --drop-every N    test affordance (R2-004): silently drop every Nth well-formed");
    println!("                        received frame instead of echoing it (N >= 1; N=1 drops all).");
    println!("                        Dropped frames are counted separately, never toward --max-frames.");
    println!("  sharenet_transport_linux probe-rtt --peer ADDR [--count N] [--interval-ms M]");
    println!("      Active RTT/loss measurement (R2-004): send N probe frames to a peer running");
    println!("      `echo`, correlate pongs, print a LinkQualitySummary (exit 0 on any completed");
    println!("      run; measured loss is evidence, not failure).");
    println!("      --peer ADDR       peer address, e.g. 127.0.0.1:9000");
    println!("      --count N         number of probes (default 10)");
    println!("      --interval-ms M   pacing between probe starts (default 10)");
}

fn cmd_probe() -> ExitCode {
    let avail = probe_tun();
    println!("TUN availability: {avail}");
    let machine_readable = match &avail {
        TunAvailability::Available => "tun_probe:available=true reason=\"\"".to_string(),
        TunAvailability::Absent { reason } => {
            format!("tun_probe:available=false kind=absent reason={reason:?}")
        }
        TunAvailability::Forbidden => {
            "tun_probe:available=false kind=forbidden reason=\"open or TUNSETIFF denied (needs CAP_NET_ADMIN)\""
                .to_string()
        }
    };
    println!("{machine_readable}");
    match avail {
        TunAvailability::Available => ExitCode::SUCCESS,
        _ => ExitCode::from(2),
    }
}

fn cmd_echo(args: &[String]) -> ExitCode {
    let mut bind: Option<String> = None;
    let mut max_frames: Option<u64> = None;
    let mut drop_every: Option<u64> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                if let Some(v) = args.get(i + 1) {
                    bind = Some(v.clone());
                    i += 2;
                } else {
                    eprintln!("error: --bind requires a value");
                    return ExitCode::from(2);
                }
            }
            "--max-frames" => {
                if let Some(v) = args.get(i + 1) {
                    match v.parse::<u64>() {
                        Ok(n) => {
                            max_frames = Some(n);
                            i += 2;
                        }
                        Err(e) => {
                            eprintln!("error: --max-frames expects a number, got {v:?}: {e}");
                            return ExitCode::from(2);
                        }
                    }
                } else {
                    eprintln!("error: --max-frames requires a value");
                    return ExitCode::from(2);
                }
            }
            "--drop-every" => {
                if let Some(v) = args.get(i + 1) {
                    match v.parse::<u64>() {
                        Ok(n) if n >= 1 => {
                            drop_every = Some(n);
                            i += 2;
                        }
                        Ok(_) => {
                            eprintln!("error: --drop-every expects a number >= 1 (1 = drop all frames)");
                            return ExitCode::from(2);
                        }
                        Err(e) => {
                            eprintln!("error: --drop-every expects a number, got {v:?}: {e}");
                            return ExitCode::from(2);
                        }
                    }
                } else {
                    eprintln!("error: --drop-every requires a value");
                    return ExitCode::from(2);
                }
            }
            other => {
                eprintln!("error: unknown echo argument {other:?}");
                return ExitCode::from(2);
            }
        }
    }

    let bind = match bind {
        Some(b) => b,
        None => {
            eprintln!("error: echo requires --bind ADDR (e.g. --bind 127.0.0.1:0)");
            return ExitCode::from(2);
        }
    };

    let mut transport = match UdpTransport::bind_str(&bind) {
        Ok(t) => t,
        Err(e @ UdpError::AddrInUse { .. }) => {
            eprintln!("error: bind failed: {e}");
            return ExitCode::from(3);
        }
        Err(e) => {
            eprintln!("error: bind failed: {e}");
            return ExitCode::from(3);
        }
    };

    let local = transport.local_addr();
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "READY {local}");
    let _ = stdout.flush();
    drop(stdout);

    let mut echoed: u64 = 0;
    let mut malformed: u64 = 0;
    let mut dropped: u64 = 0;
    let mut received: u64 = 0;
    let mut bytes: u64 = 0;
    // Receive buffer sized for the largest legal datagram (header + max
    // payload), so legal frames are never truncated by the echo side.
    let mut buf = vec![0u8; 4 + MAX_FRAME_PAYLOAD];

    loop {
        match transport.recv_frame_from(&mut buf) {
            Ok((frame, peer)) => {
                received += 1;
                // Test affordance (R2-004): every Nth well-formed frame is
                // silently dropped — deterministic induced loss on loopback.
                if let Some(n) = drop_every {
                    if received % n == 0 {
                        dropped += 1;
                        eprintln!("echo: dropping well-formed frame #{received} (--drop-every {n})");
                        continue;
                    }
                }
                let n = frame.payload.len();
                if let Err(e) = transport.send_frame_to(peer, &frame.payload) {
                    eprintln!("echo: send failed to {peer}: {e}");
                    return ExitCode::from(4);
                }
                echoed += 1;
                bytes += n as u64;
                if let Some(max) = max_frames {
                    if echoed >= max {
                        break;
                    }
                }
            }
            Err(UdpError::WouldBlock) => {
                // Blocking socket: only reachable if built with nonblocking
                // semantics enabled; nothing to do, loop again.
                continue;
            }
            Err(e) => {
                eprintln!("echo: malformed or truncated datagram dropped ({e})");
                malformed += 1;
                // Adversarial robustness: the server keeps running after bad input.
            }
        }
    }

    println!(
        "ECHO_DONE frames={echoed} bytes={bytes} malformed={malformed} dropped={dropped} received={received} status=ok"
    );
    ExitCode::SUCCESS
}

fn cmd_probe_rtt(args: &[String]) -> ExitCode {
    let mut peer: Option<String> = None;
    let mut count: u64 = 10;
    let mut interval_ms: u64 = 10;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--peer" => {
                if let Some(v) = args.get(i + 1) {
                    peer = Some(v.clone());
                    i += 2;
                } else {
                    eprintln!("error: --peer requires a value (e.g. --peer 127.0.0.1:9000)");
                    return ExitCode::from(2);
                }
            }
            "--count" => {
                if let Some(v) = args.get(i + 1) {
                    match v.parse::<u64>() {
                        Ok(n) if n > 0 => {
                            count = n;
                            i += 2;
                        }
                        Ok(_) => {
                            eprintln!("error: --count expects a number > 0");
                            return ExitCode::from(2);
                        }
                        Err(e) => {
                            eprintln!("error: --count expects a number, got {v:?}: {e}");
                            return ExitCode::from(2);
                        }
                    }
                } else {
                    eprintln!("error: --count requires a value");
                    return ExitCode::from(2);
                }
            }
            "--interval-ms" => {
                if let Some(v) = args.get(i + 1) {
                    match v.parse::<u64>() {
                        Ok(n) => {
                            interval_ms = n;
                            i += 2;
                        }
                        Err(e) => {
                            eprintln!("error: --interval-ms expects a number, got {v:?}: {e}");
                            return ExitCode::from(2);
                        }
                    }
                } else {
                    eprintln!("error: --interval-ms requires a value");
                    return ExitCode::from(2);
                }
            }
            other => {
                eprintln!("error: unknown probe-rtt argument {other:?}");
                return ExitCode::from(2);
            }
        }
    }

    let peer_str = match peer {
        Some(p) => p,
        None => {
            eprintln!("error: probe-rtt requires --peer ADDR (a peer running `echo`)");
            return ExitCode::from(2);
        }
    };
    let peer: SocketAddr = match peer_str.parse() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: --peer {peer_str:?} is not a valid address: {e}");
            return ExitCode::from(2);
        }
    };

    let config = ProbeConfig {
        count,
        interval: Duration::from_millis(interval_ms),
        ..ProbeConfig::default()
    };

    let mut prober = match udp_prober(peer, config) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: prober setup failed: {e}");
            return ExitCode::from(3);
        }
    };

    eprintln!(
        "probe-rtt: measuring peer {peer} (count={count}, interval={interval_ms}ms, timeout={}ms, payload={}B, session={})",
        sharenet_transport_telemetry::probe::DEFAULT_PROBE_TIMEOUT.as_millis(),
        sharenet_transport_telemetry::probe::DEFAULT_PROBE_PAYLOAD_BYTES,
        prober.session_id()
    );

    let run = match prober.run() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: probe run failed: {e}");
            return ExitCode::from(4);
        }
    };

    let summary = match run.summary() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: summarizing the run failed: {e}");
            return ExitCode::from(5);
        }
    };

    println!(
        "PROBE_RTT_DONE session={} probes={} delivered={} lost={} late_pongs={} foreign={} recv_errors={} wall_ms={}",
        run.session_id,
        count,
        run.delivered,
        run.lost,
        run.late_pongs,
        run.foreign_frames,
        run.recv_errors,
        run.wall_time.as_millis()
    );
    println!("channel_id={}", 0u64);
    println!("delivered={}", summary.delivered);
    println!("lost={}", summary.lost);
    println!("ewma_rtt_micros={}", summary.ewma_rtt_micros);
    println!("p50_rtt_micros={}", summary.p50_rtt_micros);
    println!("p95_rtt_micros={}", summary.p95_rtt_micros);
    println!("jitter_mad_micros={}", summary.jitter_mad_micros);
    println!("loss_ratio={:.6}", summary.loss_ratio);
    println!("throughput_bps={}", summary.throughput_bps);
    ExitCode::SUCCESS
}
