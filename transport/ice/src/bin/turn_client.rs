//! `turn_client` — TEST SCAFFOLDING for the R4-005 multiprocess
//! verification: a REAL second process behaving as a peer BEHIND the
//! TURN-style relay — it allocates a relayed address and then serves
//! everything through it, exactly like a real TURN-restricted node.
//!
//! Usage:
//!   turn_client --relay <addr> [--bind <addr>] [--mode echo]
//!   turn_client --relay <addr> --mode quic --seed-hex <64 hex> [--frames N]
//!
//! Protocol: prints READY <relayed-addr> (echo mode) or
//! READY <relayed-addr> <node-id-hex> (quic mode), then:
//!
//! - **echo mode** (default): echoes every datagram received through the
//!   relayed address back to its sender (opaque, verbatim — L012),
//!   until a `done` datagram arrives, which is answered with `done-ack`
//!   before printing CLIENT_DONE and exiting 0. The datagram exchange
//!   rides the relay control framing both ways;
//! - **quic mode**: hosts a REAL node-pinned QUIC tunnel server
//!   (transport/quic R4-001) made reachable at the relayed address via
//!   `RelayServerAdapter` — the relayed datagrams stay untouched, so a
//!   full QUIC/TLS 1.3 handshake and framed tunnel session ride the
//!   relay transparently. Echoes `--frames` frames with an `echo:`
//!   prefix, then waits for the tunnel `done` frame (the QUIC close
//!   discards in-flight frames, so process exit must never race data —
//!   the same done-exchange protocol as `sharenet_quic_peer`), prints
//!   CLIENT_DONE and exits 0.
//!
//! Exit codes: 0 = done exchange completed; 1 = runtime failure;
//! 2 = usage.

use std::net::SocketAddr;
use std::process::ExitCode;

use sharenet_transport_ice::relay::RelayClient;
use sharenet_transport_ice::RelayServerAdapter;
use sharenet_transport_quic::TunnelServer;

fn main() -> ExitCode {
    let mut relay_addr: Option<SocketAddr> = None;
    let mut bind: SocketAddr = "127.0.0.1:0".parse().expect("static addr");
    let mut mode = "echo".to_string();
    let mut seed_hex: Option<String> = None;
    let mut frames: usize = 4;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--relay" => match args.next().and_then(|a| a.parse().ok()) {
                Some(addr) => relay_addr = Some(addr),
                None => {
                    eprintln!("error: --relay needs a socket address");
                    return ExitCode::from(2);
                }
            },
            "--bind" => match args.next().and_then(|a| a.parse().ok()) {
                Some(addr) => bind = addr,
                None => {
                    eprintln!("error: --bind needs a socket address");
                    return ExitCode::from(2);
                }
            },
            "--mode" => match args.next() {
                Some(m) if m == "echo" || m == "quic" => mode = m,
                other => {
                    eprintln!("error: --mode must be echo or quic, got {other:?}");
                    return ExitCode::from(2);
                }
            },
            "--seed-hex" => seed_hex = args.next(),
            "--frames" => frames = args.next().and_then(|f| f.parse().ok()).unwrap_or(4),
            other => {
                eprintln!("error: unknown argument {other:?}");
                return ExitCode::from(2);
            }
        }
    }
    let relay_addr = match relay_addr {
        Some(addr) => addr,
        None => {
            eprintln!("error: --relay <addr> required");
            return ExitCode::from(2);
        }
    };

    // Allocate the relayed address this peer will be reachable on.
    let client = match RelayClient::allocate(relay_addr, bind) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: relay allocate on {relay_addr}: {e}");
            return ExitCode::from(1);
        }
    };
    let relayed = client.relayed_addr();
    eprintln!(
        "allocation {} ready: relayed {relayed} (control {})",
        client.allocation_id(),
        client.local_addr().map(|a| a.to_string()).unwrap_or_default()
    );

    if mode == "echo" {
        // Receive through the relayed address: the allocation must be
        // active first (permission-lite — the client sends before peers'
        // datagrams flow; see the relay module docs).
        if let Err(e) = client.activate() {
            eprintln!("error: activate: {e}");
            return ExitCode::from(1);
        }
        // allocate_on leaves a 400ms read timeout in place; the echo
        // loop must block until a datagram really arrives.
        if let Err(e) = client.set_read_timeout(None) {
            eprintln!("error: clear timeout: {e}");
            return ExitCode::from(1);
        }
        println!("READY {relayed}");
        match echo_loop(&client) {
            Ok(()) => {}
            Err(e) => {
                eprintln!("error: echo loop: {e}");
                return ExitCode::from(1);
            }
        }
        println!("CLIENT_DONE");
        ExitCode::SUCCESS
    } else {
        let seed_hex = match seed_hex {
            Some(s) if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) => s,
            _ => {
                eprintln!("error: --mode quic requires --seed-hex <64 hex>");
                return ExitCode::from(2);
            }
        };
        let seed: [u8; 32] = (0..32)
            .map(|i| u8::from_str_radix(&seed_hex[2 * i..2 * i + 2], 16).expect("hex"))
            .collect::<Vec<u8>>()
            .try_into()
            .expect("32");
        let server = match TunnelServer::bind("127.0.0.1:0".parse().expect("addr"), seed, None) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: quic bind: {e}");
                return ExitCode::from(1);
            }
        };
        let node_id = server.node_id();
        let server_addr = match server.local_addr() {
            Ok(a) => a,
            Err(e) => {
                eprintln!("error: server addr: {e}");
                return ExitCode::from(1);
            }
        };
        // Pump the relayed address to the real QUIC endpoint: peers'
        // datagrams reach it at {relayed} untouched (L012).
        let adapter = match RelayServerAdapter::start(client, server_addr) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("error: relay adapter: {e}");
                return ExitCode::from(1);
            }
        };
        let node_hex: String = node_id.iter().map(|b| format!("{b:02x}")).collect();
        println!("READY {relayed} {node_hex}");
        let mut stream = match server.accept() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: accept: {e}");
                return ExitCode::from(1);
            }
        };
        eprintln!("ACCEPTED tunnel via {relayed}");
        for _ in 0..frames {
            let frame = match stream.recv_frame() {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error: recv: {e}");
                    return ExitCode::from(1);
                }
            };
            let mut echoed = b"echo:".to_vec();
            echoed.extend_from_slice(&frame);
            if let Err(e) = stream.send_frame(&echoed) {
                eprintln!("error: send: {e}");
                return ExitCode::from(1);
            }
        }
        // Deterministic shutdown: the client confirms receipt with
        // "done" (QUIC close discards in-flight frames).
        match stream.recv_frame() {
            Ok(done) if done == b"done" => {}
            Ok(other) => {
                eprintln!("error: expected done, got {other:?}");
                return ExitCode::from(1);
            }
            Err(e) => {
                eprintln!("error: done: {e}");
                return ExitCode::from(1);
            }
        }
        let _ = stream.finish();
        adapter.stop();
        println!("CLIENT_DONE");
        ExitCode::SUCCESS
    }
}

/// Echo datagrams received through the relayed address back to their
/// sender, verbatim, until `done` arrives (answered with `done-ack`).
fn echo_loop(client: &RelayClient) -> Result<(), sharenet_transport_ice::IceError> {
    let mut buf = vec![0u8; 65_536];
    loop {
        let (peer, n) = client.recv_from(&mut buf)?;
        eprintln!("echoing {n} bytes back to {peer}");
        if &buf[..n] == b"done" {
            client.send_to(peer, b"done-ack")?;
            return Ok(());
        }
        client.send_to(peer, &buf[..n])?;
    }
}
