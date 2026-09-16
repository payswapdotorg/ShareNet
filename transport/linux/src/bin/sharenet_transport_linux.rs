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
        Some("probe-uplink") => cmd_probe_uplink(&args[1..]),
        Some("gateway") => cmd_gateway(&args[1..]),
        Some("participant") => cmd_participant(&args[1..]),
        Some("appliance") => cmd_appliance(&args[1..]),
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
    println!("  sharenet_transport_linux probe-uplink --dest ADDR [--count N] [--timeout-ms M]");
    println!("      Real-Internet UDP egress probe (R4-007 mission-gate evidence): send N");
    println!("      probe datagrams to a REAL external destination and await any response.");
    println!("      Prints a typed outcome + machine-readable line. Exit 0 = egress confirmed");
    println!("      (a response returned); exit 3 = no response within the window (the host");
    println!("      network is restrictive for UDP — evidence, not a bug); exit 2 = usage.");
    println!("      --dest ADDR       real destination, e.g. 8.8.8.8:53");
    println!("      --count N         datagrams (default 3)");
    println!("      --timeout-ms M    per-datagram wait (default 1000)");
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

/// Real-Internet UDP egress probe (R4-007 mission-gate evidence): the
/// honest companion to the loopback mission-gate composition. Sends
/// small probe datagrams to a REAL external destination and awaits any
/// response with a bounded timeout — whatever the network does is the
/// evidence (this sandbox's network is expected to be restrictive:
/// allowlisted HTTP(S) only, no UDP egress; on an open network a DNS
/// or STUN destination responds and the exit code flips to 0).
fn cmd_probe_uplink(args: &[String]) -> ExitCode {
    let mut dest: Option<String> = None;
    let mut count: u32 = 3;
    let mut timeout_ms: u64 = 1_000;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--dest" => {
                i += 1;
                match args.get(i) {
                    Some(v) => dest = Some(v.clone()),
                    None => {
                        eprintln!("error: --dest requires a value (e.g. 8.8.8.8:53)");
                        return ExitCode::from(2);
                    }
                }
            }
            "--count" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u32>().ok()) {
                    Some(v) if v >= 1 => count = v,
                    _ => {
                        eprintln!("error: --count expects a number >= 1");
                        return ExitCode::from(2);
                    }
                }
            }
            "--timeout-ms" => {
                i += 1;
                match args.get(i).and_then(|v| v.parse::<u64>().ok()) {
                    Some(v) if v >= 1 => timeout_ms = v,
                    _ => {
                        eprintln!("error: --timeout-ms expects a number >= 1");
                        return ExitCode::from(2);
                    }
                }
            }
            other => {
                eprintln!("error: unknown probe-uplink argument {other:?}");
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let dest = match dest.and_then(|d| d.parse::<SocketAddr>().ok()) {
        Some(d) => d,
        None => {
            eprintln!("error: probe-uplink requires --dest ADDR (e.g. 8.8.8.8:53)");
            return ExitCode::from(2);
        }
    };

    let socket = match std::net::UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: bind: {e}");
            return ExitCode::from(1);
        }
    };
    if let Err(e) = socket.set_read_timeout(Some(Duration::from_millis(timeout_ms))) {
        eprintln!("error: timeout: {e}");
        return ExitCode::from(1);
    }

    // A DNS-shaped probe payload (a minimal A query for "sharenet.")
    // — well-formed UDP application data any resolver answers.
    let probe: [u8; 31] = [
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, b's',
        b'h', b'a', b'r', b'e', b'n', b'e', b't', 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
        0x29, 0x04, 0xd0,
    ];

    let mut buf = [0u8; 1_500];
    for attempt in 1..=count {
        if let Err(e) = socket.send_to(&probe, dest) {
            println!("uplink_probe:attempt={attempt} outcome=send_error error={e:?}");
            println!("UPLINK send error (typed): {e}");
            continue;
        }
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                println!(
                    "uplink_probe:attempt={attempt} outcome=reachable from={from} bytes={n}"
                );
                println!(
                    "UPLINK reachable: {n} bytes from {from} — real Internet UDP egress CONFIRMED"
                );
                return ExitCode::SUCCESS;
            }
            Err(e) => {
                println!("uplink_probe:attempt={attempt} outcome=no_response error_kind={:?} wait_ms={timeout_ms}", e.kind());
            }
        }
    }
    println!(
        "uplink_probe:outcome=unreachable dest={dest} attempts={count} wait_ms={timeout_ms}"
    );
    println!(
        "UPLINK unreachable: no response within {timeout_ms}ms x {count} — this host's network \
         is restrictive for UDP egress (evidence, not a failure: the mission gate's real-network \
         crossing must run on an open-UDP network; see transport/linux/MISSION-GATE.md)"
    );
    ExitCode::from(3)
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


// ---------------------------------------------------------------------------
// gateway / participant (R4-003) — TEST/DEMO entrypoints for the Linux
// gateway forwarding data plane; the same gateway module the future
// sharenet daemon will embed.
// ---------------------------------------------------------------------------

fn parse_hex_seed(s: &str) -> Result<[u8; 32], String> {
    if s.len() != 64 || !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("--seed-hex expects 64 hex chars, got {s:?}"));
    }
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(seed)
}

fn parse_hex_id(s: &str) -> Result<[u8; 32], String> {
    parse_hex_seed(s)
}

/// `gateway --seed-hex <64hex> --bind ADDR --uplink ADDR [--pin <64hex>]...`
///
/// Prints `READY <tunnel-addr> <gateway-node-id-hex>`, then serves ONE
/// participant connection (route acceptance, circuit setup/ack, frame
/// forwarding to the uplink, destroy) and prints
/// `GATEWAY_DONE <forwarded-up> <reason-or-bye>` on exit 0.
fn cmd_gateway(args: &[String]) -> ExitCode {
    let mut seed_hex: Option<String> = None;
    let mut bind: SocketAddr = "127.0.0.1:0".parse().expect("static");
    let mut uplink: Option<SocketAddr> = None;
    let mut pins: Vec<[u8; 32]> = Vec::new();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--seed-hex" => seed_hex = it.next().cloned(),
            "--bind" => match it.next().and_then(|a| a.parse().ok()) {
                Some(a) => bind = a,
                None => {
                    eprintln!("error: --bind needs a socket address");
                    return ExitCode::from(2);
                }
            },
            "--uplink" => match it.next().and_then(|a| a.parse().ok()) {
                Some(a) => uplink = Some(a),
                None => {
                    eprintln!("error: --uplink needs a socket address");
                    return ExitCode::from(2);
                }
            },
            "--pin" => match it.next().and_then(|a| parse_hex_id(a).ok()) {
                Some(id) => pins.push(id),
                None => {
                    eprintln!("error: --pin needs 64 hex chars");
                    return ExitCode::from(2);
                }
            },
            other => {
                eprintln!("error: unknown gateway argument {other:?}");
                return ExitCode::from(2);
            }
        }
    }
    let seed = match seed_hex.as_deref().map(parse_hex_seed) {
        Some(Ok(s)) => s,
        _ => {
            eprintln!("error: gateway needs --seed-hex <64 hex>");
            return ExitCode::from(2);
        }
    };
    let Some(uplink) = uplink else {
        eprintln!("error: gateway needs --uplink ADDR (the Internet-side target)");
        return ExitCode::from(2);
    };
    let gateway = match sharenet_transport_linux::gateway::GatewayServer::new(
        seed,
        bind,
        if pins.is_empty() { None } else { Some(pins) },
        uplink,
    ) {
        Ok(g) => g,
        Err(e) => {
            eprintln!("error: gateway bind: {e}");
            return ExitCode::from(1);
        }
    };
    let addr = match gateway.local_addr() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: local addr: {e}");
            return ExitCode::from(1);
        }
    };
    let node_hex: String = gateway
        .node_id()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("READY {addr} {node_hex}");
    let stats = match gateway.serve_once() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: gateway serve: {e}");
            return ExitCode::from(1);
        }
    };
    let reason = stats
        .destroy_reason
        .clone()
        .unwrap_or_else(|| if stats.bye { "bye".into() } else { "-".into() });
    println!(
        "GATEWAY_DONE {} {}",
        stats.forwarded_up, reason
    );
    ExitCode::SUCCESS
}

/// `appliance --identity-dir DIR --bind ADDR --uplink ADDR --journal PATH
/// [--pin <64hex>]... [--max-sessions N]`
///
/// The dedicated gateway appliance (R9-003): durable identity (created
/// once from OS entropy in DIR/appliance.seed, 0600), one stable bound
/// address, sequential admission-verified sessions, an append-only
/// session journal (canonical CBOR, fsync'd per record) that survives
/// restarts (ordinal + totals continue).
///
/// Output protocol:
///   `APPLIANCE_READY <addr> <node-id-hex>`
///   `APPLIANCE_SESSION <ordinal> <participant-hex> <forwarded> <reason>` (per session)
///   `APPLIANCE_DONE <sessions> <total-forwarded>` (exit 0 after --max-sessions)
fn cmd_appliance(args: &[String]) -> ExitCode {
    let mut identity_dir: Option<std::path::PathBuf> = None;
    let mut bind: SocketAddr = "127.0.0.1:0".parse().expect("static");
    let mut uplink: Option<SocketAddr> = None;
    let mut journal: Option<std::path::PathBuf> = None;
    let mut pins: Vec<[u8; 32]> = Vec::new();
    let mut max_sessions: Option<u64> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--identity-dir" => identity_dir = it.next().map(std::path::PathBuf::from),
            "--bind" => match it.next().and_then(|a| a.parse().ok()) {
                Some(a) => bind = a,
                None => {
                    eprintln!("error: --bind needs a socket address");
                    return ExitCode::from(2);
                }
            },
            "--uplink" => match it.next().and_then(|a| a.parse().ok()) {
                Some(a) => uplink = Some(a),
                None => {
                    eprintln!("error: --uplink needs a socket address");
                    return ExitCode::from(2);
                }
            },
            "--journal" => journal = it.next().map(std::path::PathBuf::from),
            "--pin" => match it.next().and_then(|a| parse_hex_id(a).ok()) {
                Some(id) => pins.push(id),
                None => {
                    eprintln!("error: --pin needs 64 hex chars");
                    return ExitCode::from(2);
                }
            },
            "--max-sessions" => match it.next().and_then(|a| a.parse::<u64>().ok()) {
                Some(n) => max_sessions = Some(n),
                None => {
                    eprintln!("error: --max-sessions needs an integer >= 1");
                    return ExitCode::from(2);
                }
            },
            other => {
                eprintln!("error: unknown appliance argument {other:?}");
                return ExitCode::from(2);
            }
        }
    }
    let Some(identity_dir) = identity_dir else {
        eprintln!("error: appliance needs --identity-dir DIR (the durable identity)");
        return ExitCode::from(2);
    };
    let Some(uplink) = uplink else {
        eprintln!("error: appliance needs --uplink ADDR (the Internet-side target)");
        return ExitCode::from(2);
    };
    let journal_path =
        journal.unwrap_or_else(|| identity_dir.join("appliance-journal.cbor"));
    use sharenet_transport_linux::appliance::{ApplianceConfig, GatewayAppliance};
    let mut appliance = match GatewayAppliance::open(ApplianceConfig {
        identity_dir: identity_dir.clone(),
        bind,
        uplink,
        journal_path,
        expected_clients: if pins.is_empty() { None } else { Some(pins) },
    }) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: appliance open: {e}");
            return ExitCode::from(1);
        }
    };
    let addr = match appliance.local_addr() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: appliance addr: {e}");
            return ExitCode::from(1);
        }
    };
    let node_hex: String = appliance
        .node_id()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    println!("APPLIANCE_READY {addr} {node_hex}");
    // --max-sessions counts THIS RUN's served sessions (the journal's
    // life totals may already be higher — a restarted appliance serves
    // N MORE, which is the operator expectation for the knob).
    let mut served_this_run: u64 = 0;
    loop {
        if let Some(limit) = max_sessions {
            if served_this_run >= limit {
                break;
            }
        }
        match appliance.serve_session() {
            Ok(outcome) => {
                served_this_run += 1;
                let r = &outcome.record;
                let participant_hex: String =
                    r.participant.iter().map(|b| format!("{b:02x}")).collect();
                println!(
                    "APPLIANCE_SESSION {} {} {} {}",
                    r.ordinal, participant_hex, r.forwarded_up, r.reason
                );
            }
            Err(e) => {
                eprintln!("error: appliance session: {e}");
                return ExitCode::from(1);
            }
        }
    }
    let stats = appliance.stats();
    println!("APPLIANCE_DONE {} {}", stats.sessions, stats.total_forwarded_up);
    ExitCode::SUCCESS
}

/// `participant --seed-hex <64hex> --gateway ADDR --gateway-node <64hex>
/// [--packets N] [--payload BYTES]`
///
/// Connects (node-pinned), establishes the circuit, sends N packets,
/// receives N responses, destroys the circuit (reason "completed") and
/// prints `PARTICIPANT_DONE <sent> <received>`.
fn cmd_participant(args: &[String]) -> ExitCode {
    let mut seed_hex: Option<String> = None;
    let mut gateway_addr: Option<SocketAddr> = None;
    let mut gateway_node: Option<[u8; 32]> = None;
    let mut packets: usize = 3;
    let mut payload: Vec<u8> = b"sharenet-gateway-packet".to_vec();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--seed-hex" => seed_hex = it.next().cloned(),
            "--gateway" => gateway_addr = it.next().and_then(|a| a.parse().ok()),
            "--gateway-node" => gateway_node = it.next().and_then(|a| parse_hex_id(a).ok()),
            "--packets" => packets = it.next().and_then(|a| a.parse().ok()).unwrap_or(3),
            "--payload" => {
                if let Some(p) = it.next() {
                    payload = p.as_bytes().to_vec();
                }
            }
            other => {
                eprintln!("error: unknown participant argument {other:?}");
                return ExitCode::from(2);
            }
        }
    }
    let seed = match seed_hex.as_deref().map(parse_hex_seed) {
        Some(Ok(s)) => s,
        _ => {
            eprintln!("error: participant needs --seed-hex <64 hex>");
            return ExitCode::from(2);
        }
    };
    let Some(gateway_addr) = gateway_addr else {
        eprintln!("error: participant needs --gateway ADDR");
        return ExitCode::from(2);
    };
    let Some(gateway_node) = gateway_node else {
        eprintln!("error: participant needs --gateway-node <64 hex>");
        return ExitCode::from(2);
    };
    let client = sharenet_transport_linux::gateway::GatewayClient::new(
        seed,
        gateway_addr,
        gateway_node,
    );
    let mut session = match client.connect() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: connect: {e}");
            return ExitCode::from(1);
        }
    };
    let identity =
        sharenet_protocol::identity::Identity::from_seed(seed, 0, None).expect("identity");
    let mut received = 0usize;
    for i in 0..packets {
        let mut packet = format!("{}-{}", String::from_utf8_lossy(&payload), i).into_bytes();
        packet.truncate(sharenet_transport_linux::gateway::GATEWAY_MAX_PACKET);
        if let Err(e) = session.send_packet(&packet) {
            eprintln!("error: send {i}: {e}");
            return ExitCode::from(1);
        }
        match session.recv_response() {
            Ok(response) => {
                if response != packet {
                    eprintln!("error: unexpected response {response:?}");
                    return ExitCode::from(1);
                }
                received += 1;
            }
            Err(e) => {
                eprintln!("error: recv {i}: {e}");
                return ExitCode::from(1);
            }
        }
    }
    if let Err(e) = session.destroy(&identity, "completed") {
        eprintln!("error: destroy: {e}");
        return ExitCode::from(1);
    }
    println!("PARTICIPANT_DONE {packets} {received}");
    ExitCode::SUCCESS
}
