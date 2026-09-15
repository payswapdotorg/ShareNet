//! `telemetry-echo-child` — the tiny in-crate echo responder for the R2-004
//! two-process integration tests (TEST SCAFFOLDING, clearly marked).
//!
//! The assignment permits "the echo binary from transport/linux (or a tiny
//! in-crate child) as a REAL second process". This is that child: a REAL
//! standalone process speaking the DOCUMENTED Wave 1 UDP frame wire format
//! (`frame := u32be payload_len || payload[payload_len]`, one frame per
//! datagram — see `sharenet-transport-linux/src/udp.rs`) over REAL loopback
//! sockets. It is std-only and duplicates nothing but the 4-byte framing,
//! which is frozen public documentation; the PROBER side of every test rides
//! the REAL `UdpTransport` and its REAL frame codec via the
//! `telemetry_bridge`. The fully-production path (both sides the real
//! `sharenet_transport_linux` binaries) is separately exercised in
//! `transport/linux/tests/probe_rtt.rs`.
//!
//! Protocol (stdout contract used by the parent test):
//!
//! ```text
//! READY <addr>                      — bound address, one line, flushed
//! CHILD_ECHO_DONE echoed=N dropped=D received=R malformed=M status=ok
//!                                   — printed on idle exit; exit code 0
//! ```
//!
//! Flags:
//! * `--bind ADDR`        bind address (use `127.0.0.1:0` for ephemeral)
//! * `--drop-every N`     silently drop every Nth well-formed RECEIVED frame
//!                        (N >= 1; N=1 drops everything) — deterministic
//!                        induced loss for the integration test
//! * `--idle-exit-ms M`   exit cleanly after M ms with no inbound datagram
//!                        (default 2000)

use std::io::Write;
use std::net::UdpSocket;
use std::process::ExitCode;
use std::time::Duration;

/// Wave 1 documented frame format constants (mirror of the frozen
/// documentation in sharenet-transport-linux/src/udp.rs — test scaffolding
/// only; the production codec lives there).
const FRAME_HEADER_LEN: usize = 4;
/// Matches the Wave 1 transport's documented receive-buffer sizing policy.
const MAX_DATAGRAM: usize = 4 + 65_500;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut bind = String::from("127.0.0.1:0");
    let mut drop_every: Option<u64> = None;
    let mut idle_exit_ms: u64 = 2_000;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--bind" => {
                match args.get(i + 1) {
                    Some(v) => {
                        bind = v.clone();
                        i += 2;
                    }
                    None => {
                        eprintln!("error: --bind requires a value");
                        return ExitCode::from(2);
                    }
                }
            }
            "--drop-every" => {
                match args.get(i + 1).and_then(|v| v.parse::<u64>().ok()) {
                    Some(n) if n >= 1 => {
                        drop_every = Some(n);
                        i += 2;
                    }
                    _ => {
                        eprintln!("error: --drop-every requires a number >= 1");
                        return ExitCode::from(2);
                    }
                }
            }
            "--idle-exit-ms" => {
                match args.get(i + 1).and_then(|v| v.parse::<u64>().ok()) {
                    Some(n) => {
                        idle_exit_ms = n;
                        i += 2;
                    }
                    None => {
                        eprintln!("error: --idle-exit-ms requires a number");
                        return ExitCode::from(2);
                    }
                }
            }
            other => {
                eprintln!("error: unknown argument {other:?}");
                return ExitCode::from(2);
            }
        }
    }

    let socket = match UdpSocket::bind(&bind) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: bind {bind} failed: {e}");
            return ExitCode::from(3);
        }
    };
    let local = socket.local_addr().expect("local_addr after bind");
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "READY {local}");
    let _ = stdout.flush();
    drop(stdout);

    let mut echoed: u64 = 0;
    let mut dropped: u64 = 0;
    let mut received: u64 = 0;
    let mut malformed: u64 = 0;

    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        // Idle exit: when no datagram arrives for idle_exit_ms, finish
        // cleanly so the parent can cross-validate our counters.
        if socket.set_read_timeout(Some(Duration::from_millis(idle_exit_ms))).is_err() {
            eprintln!("error: set_read_timeout failed");
            return ExitCode::from(4);
        }
        match socket.recv_from(&mut buf) {
            Ok((n, peer)) => {
                if let Some((payload, consumed)) = decode_frame(&buf[..n]) {
                    if consumed != n {
                        malformed += 1; // trailing bytes after a complete frame
                        continue;
                    }
                    received += 1;
                    if let Some(every) = drop_every {
                        if received % every == 0 {
                            dropped += 1;
                            continue; // induced loss: no echo
                        }
                    }
                    let mut wire = Vec::with_capacity(FRAME_HEADER_LEN + payload.len());
                    wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                    wire.extend_from_slice(payload);
                    if socket.send_to(&wire, peer).is_err() {
                        eprintln!("error: echo send failed");
                        return ExitCode::from(5);
                    }
                    echoed += 1;
                } else {
                    malformed += 1;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // Idle window elapsed with no traffic: clean shutdown.
                println!(
                    "CHILD_ECHO_DONE echoed={echoed} dropped={dropped} received={received} malformed={malformed} status=ok"
                );
                return ExitCode::SUCCESS;
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                eprintln!("error: recv failed: {e}");
                return ExitCode::from(6);
            }
        }
    }
}

/// Decode one Wave 1 length-framed payload (documented format; returns None
/// when the datagram does not start with a well-formed frame header).
fn decode_frame(datagram: &[u8]) -> Option<(&[u8], usize)> {
    if datagram.len() < FRAME_HEADER_LEN {
        return None;
    }
    let declared = u32::from_be_bytes([datagram[0], datagram[1], datagram[2], datagram[3]]) as usize;
    let end = FRAME_HEADER_LEN.checked_add(declared)?;
    if end > datagram.len() {
        return None;
    }
    Some((&datagram[FRAME_HEADER_LEN..end], end))
}
