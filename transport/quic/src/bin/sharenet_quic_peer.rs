//! `sharenet_quic_peer` — TEST SCAFFOLDING for the R4-001 multiprocess
//! verification: a REAL second process running a QUIC tunnel server that
//! echoes frames back over the same tunnel.
//!
//! Usage: sharenet_quic_peer --seed-hex <64 hex> [--frames N] [--evil oversize]
//!
//! Protocol: prints READY <addr>, echoes N frames (or emits the evil
//! payload), then WAITS for the client's "done" frame before printing
//! PEER_DONE and exiting — the client only sends "done" after receiving
//! everything it needs, so process exit can never race in-flight frames
//! (quinn discards undelivered data on close).
//!
//! `--evil oversize`: instead of echoing, the peer writes a BOGUS frame
//! length prefix (0xFFFFFFFF) over the authenticated stream — the client
//! must reject it with FrameTooLarge. Adversarial scaffolding for the
//! receive-side frame limit.

use std::process::ExitCode;
use std::sync::Arc;

use sharenet_transport_quic::TunnelServer;

fn main() -> ExitCode {
    let mut seed_hex: Option<String> = None;
    let mut frames: usize = 4;
    let mut evil = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--seed-hex" => seed_hex = args.next(),
            "--frames" => frames = args.next().and_then(|f| f.parse().ok()).unwrap_or(4),
            "--evil" => {
                let mode = args.next().unwrap_or_default();
                match mode.as_str() {
                    "oversize" => evil = true,
                    other => {
                        eprintln!("error: unknown evil mode {other:?}");
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
    let seed_hex = match seed_hex {
        Some(s) if s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()) => s,
        _ => {
            eprintln!("error: --seed-hex <64 hex> required");
            return ExitCode::from(2);
        }
    };
    let seed: [u8; 32] = (0..32)
        .map(|i| u8::from_str_radix(&seed_hex[2 * i..2 * i + 2], 16).expect("hex"))
        .collect::<Vec<u8>>()
        .try_into()
        .expect("32");
    let server = match TunnelServer::bind("127.0.0.1:0".parse().unwrap(), seed, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: bind: {e}");
            return ExitCode::from(1);
        }
    };
    let addr = server.local_addr().expect("addr");
    println!("READY {addr}");
    let server = Arc::new(server);
    let mut stream = match server.accept() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: accept: {e}");
            return ExitCode::from(1);
        }
    };
    eprintln!("ACCEPTED");
    if evil {
        // Consume the client's opener frame first: QUIC only signals a
        // remote stream to this side when a frame references it, so the
        // client's protocol is to open the tunnel with a frame.
        match stream.recv_frame() {
            Ok(opener) => eprintln!("evil mode: consumed opener ({} bytes)", opener.len()),
            Err(e) => {
                eprintln!("error: opener: {e}");
                return ExitCode::from(1);
            }
        }
        eprintln!("evil mode: writing a bogus 0xFFFFFFFF length prefix");
        // 4 GiB length prefix over an otherwise valid TLS stream: the
        // receiver must refuse to allocate/await that much (FrameTooLarge)
        if let Err(e) = stream.send_raw(&0xFFFF_FFFFu32.to_be_bytes()) {
            eprintln!("error: evil send: {e}");
            return ExitCode::from(1);
        }
    } else {
        eprintln!("waiting for first frame");
        for _ in 0..frames {
            eprintln!("recv attempt");
            let frame = match stream.recv_frame() {
                Ok(f) => f,
                Err(e) => {
                    eprintln!("error: recv: {e}");
                    return ExitCode::from(1);
                }
            };
            let mut echoed = b"echo:".to_vec();
            echoed.extend_from_slice(&frame);
            eprintln!("echoing {} bytes", echoed.len());
            if let Err(e) = stream.send_frame(&echoed) {
                eprintln!("error: send: {e}");
                return ExitCode::from(1);
            }
        }
    }
    // Deterministic shutdown: the client confirms receipt with "done"
    // (QUIC close discards in-flight frames, so we must not exit first).
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
    println!("PEER_DONE");
    ExitCode::SUCCESS
}
