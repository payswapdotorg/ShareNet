//! `stun_server` — TEST SCAFFOLDING for the R4-005 multiprocess
//! verification: a REAL second process running an RFC 5389 STUN server
//! that answers Binding Requests with XOR-MAPPED-ADDRESS over real
//! loopback UDP (the sandbox cannot reach external STUN servers, so the
//! tests run this local one).
//!
//! Usage: stun_server [--bind <addr>] [--requests N] [--evil <mode>]
//!
//! Protocol: prints READY <bind-addr>, then answers up to N Binding
//! Requests (default 1) — the XOR-MAPPED-ADDRESS is the observed source
//! address, plus a SOFTWARE attribute — and prints STUN_DONE before a
//! clean exit 0. Datagrams that are not a parseable Binding Request
//! (garbage, other classes, unsupported methods) are silently DROPPED
//! and do not count: the strict-subset policy of the library crate
//! applies to the server too (documented simplification — no RFC 5389
//! §7.4 error responses from this scaffolding).
//!
//! `--evil` modes (adversarial scaffolding, same honest pattern as the
//! QUIC peer's `--evil oversize`):
//!
//! - `wrong-txid`: answer with a syntactically VALID success response
//!   whose transaction id does NOT match the request and whose mapped
//!   address is the bogus TEST-NET-3 203.0.113.7:9999, and THEN answer
//!   the request correctly — the client must discard the first
//!   (mismatch refusal) and accept the second;
//! - `bad-cookie`: answer with a corrupted magic cookie (the client
//!   must fail closed with `StunBadMagicCookie`);
//! - `trailing-garbage`: append 2 bytes past the message length (the
//!   client must fail closed with `StunBadMessageLength`);
//! - `unknown-required`: append an unknown comprehension-required
//!   attribute 0x7FFF to a valid response (the client must fail closed
//!   with `StunUnknownRequiredAttribute`).
//!
//! Exit codes: 0 = answered N requests; 1 = runtime failure; 2 = usage.

use std::net::SocketAddr;
use std::process::ExitCode;

use sharenet_transport_ice::stun::{
    MessageClass, StunMessage, TransactionId, HEADER_LEN, MAGIC_COOKIE, METHOD_BINDING,
};

const SOFTWARE: &str = "sharenet-stun-server/0.1";
/// Bogus mapped address used by `--evil wrong-txid` (TEST-NET-3, RFC
/// 5737 — can never be a real loopback observation).
const EVIL_MAPPED: &str = "203.0.113.7:9999";

fn main() -> ExitCode {
    let mut bind: SocketAddr = "127.0.0.1:0".parse().expect("static addr");
    let mut requests: u64 = 1;
    let mut evil: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => match args.next().and_then(|a| a.parse().ok()) {
                Some(addr) => bind = addr,
                None => {
                    eprintln!("error: --bind needs a socket address");
                    return ExitCode::from(2);
                }
            },
            "--requests" => match args.next().and_then(|a| a.parse().ok()) {
                Some(n) => requests = n,
                None => {
                    eprintln!("error: --requests needs a positive integer");
                    return ExitCode::from(2);
                }
            },
            "--evil" => {
                let mode = args.next().unwrap_or_default();
                match mode.as_str() {
                    "wrong-txid" | "bad-cookie" | "trailing-garbage" | "unknown-required" => {
                        evil = Some(mode)
                    }
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
    if requests == 0 {
        eprintln!("error: --requests must be at least 1");
        return ExitCode::from(2);
    }

    let socket = match std::net::UdpSocket::bind(bind) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: bind {bind}: {e}");
            return ExitCode::from(1);
        }
    };
    let local = match socket.local_addr() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: local_addr: {e}");
            return ExitCode::from(1);
        }
    };
    println!("READY {local}");

    let mut answered: u64 = 0;
    let mut buf = vec![0u8; 65_536];
    while answered < requests {
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("error: recv: {e}");
                return ExitCode::from(1);
            }
        };
        // Strict parse of the request; anything else is dropped
        // (uncounted) — see the module docs.
        let request = match StunMessage::parse(&buf[..n]) {
            Ok(msg) if msg.class == MessageClass::Request && msg.method == METHOD_BINDING => msg,
            _ => {
                eprintln!("dropping non-Binding-Request datagram from {from}");
                continue;
            }
        };
        let correct = match StunMessage::binding_success(
            request.transaction_id,
            from,
            Some(SOFTWARE),
        )
        .and_then(|m| m.encode())
        {
            Ok(bytes) => bytes,
            Err(e) => {
                eprintln!("error: encoding response: {e}");
                return ExitCode::from(1);
            }
        };
        let response: Vec<u8> = match evil.as_deref() {
            None => correct,
            Some("wrong-txid") => {
                // First a valid response with a WRONG transaction id and
                // a bogus mapped address, then the correct one: the
                // client must discard the first and accept the second.
                let mut evil_id = request.transaction_id.as_bytes().clone();
                evil_id[0] ^= 0xFF;
                let evil_id = TransactionId(evil_id);
                let evil = match StunMessage::binding_success(
                    evil_id,
                    EVIL_MAPPED.parse().expect("static addr"),
                    Some(SOFTWARE),
                )
                .and_then(|m| m.encode())
                {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        eprintln!("error: encoding evil response: {e}");
                        return ExitCode::from(1);
                    }
                };
                if let Err(e) = socket.send_to(&evil, from) {
                    eprintln!("error: evil send: {e}");
                    return ExitCode::from(1);
                }
                eprintln!("evil mode: sent wrong-transaction-id response");
                correct
            }
            Some("bad-cookie") => {
                let mut bytes = correct;
                bytes[7] ^= 0x01; // corrupt the magic cookie's last byte
                eprintln!("evil mode: corrupted magic cookie");
                bytes
            }
            Some("trailing-garbage") => {
                let mut bytes = correct;
                bytes.extend_from_slice(b"XY"); // length NOT updated
                eprintln!("evil mode: appended trailing garbage");
                bytes
            }
            Some("unknown-required") => {
                let mut bytes = correct;
                // TLV: type 0x7FFF (comprehension-required, unknown to
                // the strict subset), length 4, value DEADBEEF — then
                // patch the header's message length to cover it.
                bytes.extend_from_slice(&0x7FFFu16.to_be_bytes());
                bytes.extend_from_slice(&4u16.to_be_bytes());
                bytes.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
                let new_len = (bytes.len() - HEADER_LEN) as u16;
                bytes[2..4].copy_from_slice(&new_len.to_be_bytes());
                eprintln!("evil mode: appended unknown required attribute");
                bytes
            }
            Some(other) => {
                eprintln!("error: unhandled evil mode {other:?}");
                return ExitCode::from(2);
            }
        };
        if let Err(e) = socket.send_to(&response, from) {
            eprintln!("error: send: {e}");
            return ExitCode::from(1);
        }
        answered += 1;
        eprintln!(
            "answered Binding Request from {from} (cookie {MAGIC_COOKIE:#010x}, {} bytes)",
            response.len()
        );
    }
    println!("STUN_DONE");
    ExitCode::SUCCESS
}
