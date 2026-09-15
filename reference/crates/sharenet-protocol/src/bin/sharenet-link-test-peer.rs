//! `sharenet-link-test-peer` — TEST SCAFFOLDING for the R3-001 multiprocess
//! verification (a REAL second process over a REAL UDP socket).
//!
//! NOT PRODUCTION CODE. Speaks raw UDP datagrams (one handshake message or
//! link frame per datagram) with the test identity derived from --seed-hex,
//! runs the responder side of the authenticated-link handshake, then echoes
//! --frames link frames back to the initiator.
//!
//! Usage:
//!   sharenet-link-test-peer --bind 127.0.0.1:0 --seed-hex <64 hex> --frames N
//!
//! Prints READY <addr> on startup, LINK_OK <link_id_hex> once the session is
//! established, PEER_DONE on completion. Exits 0 on success.

use std::net::UdpSocket;
use std::process::ExitCode;

use sharenet_protocol::cbor::{decode, Value};
use sharenet_protocol::identity::Identity;
use sharenet_protocol::link::{LinkConfirm, LinkInitiate, LinkResponder, LinkSession};

fn main() -> ExitCode {
    let mut bind: Option<String> = None;
    let mut seed_hex: Option<String> = None;
    let mut frames: usize = 4;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => bind = args.next(),
            "--seed-hex" => seed_hex = args.next(),
            "--frames" => {
                frames = args
                    .next()
                    .and_then(|f| f.parse().ok())
                    .unwrap_or(4);
            }
            other => {
                eprintln!("error: unknown argument {other:?}");
                return ExitCode::from(2);
            }
        }
    }
    let bind = bind.unwrap_or_else(|| "127.0.0.1:0".into());
    let seed_hex = match seed_hex {
        Some(s) => s,
        None => {
            eprintln!("error: --seed-hex is required (TEST identity)");
            return ExitCode::from(2);
        }
    };
    let seed: [u8; 32] = match from_hex(&seed_hex) {
        Ok(b) if b.len() == 32 => b.try_into().expect("32"),
        _ => {
            eprintln!("error: --seed-hex must be 64 hex characters");
            return ExitCode::from(2);
        }
    };
    let identity = match Identity::from_seed(seed, 1_700_000_000, Some("link-test-peer".into())) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("error: test identity failed: {e}");
            return ExitCode::from(1);
        }
    };
    let socket = match UdpSocket::bind(&bind) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: bind {bind}: {e}");
            return ExitCode::from(1);
        }
    };
    socket
        .set_read_timeout(Some(std::time::Duration::from_millis(1500)))
        .expect("set read timeout");
    let local = socket.local_addr().expect("local addr");
    println!("READY {local}");

    // ---- responder side of the handshake ----
    let (peer, buf) = match recv_from(&socket) {
        Some(x) => x,
        None => {
            eprintln!("error: no msg1 received");
            return ExitCode::from(1);
        }
    };
    let msg1_value = match decode(&buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: msg1 CBOR: {e}");
            return ExitCode::from(1);
        }
    };
    let msg1 = match LinkInitiate::from_wire(&msg1_value) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: msg1 parse: {e}");
            return ExitCode::from(1);
        }
    };
    let msg1_bytes = buf.clone();
    let responder = LinkResponder::new(identity, None);
    let (msg2, pending) = match responder.respond(&msg1, &msg1_bytes) {
        Ok(x) => x,
        Err(e) => {
            eprintln!("error: respond: {e}");
            return ExitCode::from(1);
        }
    };
    let msg2_bytes = msg2.to_wire_bytes();
    if let Err(e) = send_to(&socket, &peer, &msg2_bytes) {
        eprintln!("error: send msg2: {e}");
        return ExitCode::from(1);
    }

    let (peer2, buf) = match recv_from(&socket) {
        Some(x) => x,
        None => {
            eprintln!("error: no msg3 received");
            return ExitCode::from(1);
        }
    };
    if peer2 != peer {
        eprintln!("error: msg3 from a different address");
        return ExitCode::from(1);
    }
    let msg3_value = match decode(&buf) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: msg3 CBOR: {e}");
            return ExitCode::from(1);
        }
    };
    let msg3 = match LinkConfirm::from_wire(&msg3_value) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("error: msg3 parse: {e}");
            return ExitCode::from(1);
        }
    };
    let msg3_bytes = buf.clone();
    let mut session: LinkSession = match pending.finish(&msg1_bytes, &msg2_bytes, &msg3, &msg3_bytes)
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: finish handshake: {e}");
            return ExitCode::from(1);
        }
    };
    let link_id_hex: String = session.link_id().iter().map(|b| format!("{b:02x}")).collect();
    println!("LINK_OK {link_id_hex}");

    // ---- echo frames back, then done ----
    let _ = &msg1; // silence dead code path differences across versions
    for _ in 0..frames {
        let (from, buf) = match recv_from(&socket) {
            Some(x) => x,
            None => {
                eprintln!("error: expected a frame, got silence");
                return ExitCode::from(1);
            }
        };
        if from != peer {
            eprintln!("error: frame from a different address");
            return ExitCode::from(1);
        }
        let payload = match session.open(&buf) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("error: frame open failed: {e}");
                return ExitCode::from(1);
            }
        };
        let mut echoed = b"echo:".to_vec();
        echoed.extend_from_slice(&payload);
        let sealed = match session.seal(&echoed) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: frame seal failed: {e}");
                return ExitCode::from(1);
            }
        };
        if let Err(e) = send_to(&socket, &peer, &sealed) {
            eprintln!("error: send echo: {e}");
            return ExitCode::from(1);
        }
    }
    println!("PEER_DONE");
    ExitCode::SUCCESS
}

fn recv_from(socket: &UdpSocket) -> Option<(std::net::SocketAddr, Vec<u8>)> {
    let mut buf = vec![0u8; 65536];
    match socket.recv_from(&mut buf) {
        Ok((n, from)) => {
            buf.truncate(n);
            Some((from, buf))
        }
        Err(_) => None,
    }
}

fn send_to(socket: &UdpSocket, to: &std::net::SocketAddr, bytes: &[u8]) -> std::io::Result<()> {
    socket.send_to(bytes, to)?;
    Ok(())
}

fn from_hex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let nib = |c: u8| -> Result<u8, ()> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(()),
        }
    };
    for pair in b.chunks(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Ok(out)
}

#[allow(dead_code)]
fn unused(_: &Value) {}
