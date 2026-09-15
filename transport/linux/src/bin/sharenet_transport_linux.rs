//! `sharenet-transport-linux` — real runtime entrypoint for R2-003.
//!
//! Subcommands:
//!
//! * `probe` — run the honest TUN capability probe and print the result.
//!   Exit code: `0` if TUN is [`TunAvailability::Available`], `2` otherwise
//!   (Absent/Forbidden). A non-zero probe is *correct behavior* on hosts
//!   without TUN; it is not a program failure.
//! * `echo --bind ADDR [--max-frames N]` — bind a [`UdpTransport`] and echo
//!   every well-formed frame back to its sender. Used by the two-process
//!   loopback test (`tests/udp_multiprocess.rs`) and as a manual runtime
//!   path. Malformed frames are counted, logged to stderr, and dropped; the
//!   server keeps running (no crash). After `N` well-formed frames have been
//!   echoed it exits cleanly (exit code `0`), printing an `ECHO_DONE` summary.
//!
//! This binary is a *production caller* of the library crate: nothing here
//! fakes anything; it constructs the same transports the future sharenetd
//! daemon and R4-001 QUIC tunnel will construct.

use std::io::Write;
use std::process::ExitCode;

use sharenet_transport_linux::udp::{UdpError, UdpTransport, MAX_FRAME_PAYLOAD};
use sharenet_transport_linux::{probe_tun, TunAvailability};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("probe") => cmd_probe(),
        Some("echo") => cmd_echo(&args[1..]),
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
    println!("sharenet-transport-linux — ShareNet Linux transport foundation (R2-003)");
    println!();
    println!("USAGE:");
    println!("  sharenet_transport_linux probe");
    println!("      Probe real TUN availability on this host.");
    println!("      Exit code 0 = available, 2 = absent/forbidden (host limitation, not a bug).");
    println!("  sharenet_transport_linux echo --bind ADDR [--max-frames N]");
    println!("      UDP frame echo server (real runtime path).");
    println!("      --bind ADDR       address to bind, e.g. 127.0.0.1:0 (port 0 = ephemeral;");
    println!("                        the bound address is printed as READY <addr>)");
    println!("      --max-frames N    exit cleanly after N well-formed frames echoed (default: run forever)");
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
    let mut bytes: u64 = 0;
    // Receive buffer sized for the largest legal datagram (header + max
    // payload), so legal frames are never truncated by the echo side.
    let mut buf = vec![0u8; 4 + MAX_FRAME_PAYLOAD];

    loop {
        match transport.recv_frame_from(&mut buf) {
            Ok((frame, peer)) => {
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

    println!("ECHO_DONE frames={echoed} bytes={bytes} malformed={malformed} status=ok");
    ExitCode::SUCCESS
}
