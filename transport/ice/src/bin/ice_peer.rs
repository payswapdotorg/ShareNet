//! `ice_peer` — TEST SCAFFOLDING for the R4-006 multiprocess
//! verification: a REAL second process behaving as an ICE-LITE peer
//! (RFC 8445 §6.4): it answers STUN connectivity checks AND hosts a real
//! node-pinned QUIC tunnel server, both reachable through ONE candidate
//! address, demultiplexing STUN from the data protocol the way real ICE
//! agents do (RFC 7983-style: a datagram whose leading two bits are zero
//! is STUN; everything else is data).
//!
//! Usage:
//!   ice_peer --mode direct --seed-hex <64 hex> [--frames N]
//!   ice_peer --mode relay --relay <addr> [--credential user:secret]
//!            --seed-hex <64 hex> [--frames N]
//!
//! - **direct mode**: binds a host UDP socket S (the candidate address),
//!   runs the demux on it, and prints `READY <S-addr> <node-id-hex>`.
//! - **relay mode**: allocates a relayed address on the TURN-style relay
//!   (with the long-term credential when `--credential` is given — the
//!   R4-006 authenticated dance), runs the demux on the allocation, and
//!   prints `READY <relayed-addr> <node-id-hex>`. The control bind uses
//!   the relay's address family (a [::1] relay needs an IPv6 control
//!   socket).
//!
//! The demux (both modes): a datagram that strictly parses as a STUN
//! Binding Request is answered with a Binding success carrying the
//! observed source as XOR-MAPPED-ADDRESS (an ICE-lite check response),
//! sent back through the SAME candidate path (from S / through the
//! allocation — so the checker observes the candidate's address as the
//! responder). ANY other datagram is forwarded OPAQUELY (L012) to the
//! local QUIC tunnel server, and that server's responses are sent back
//! to the most recent data peer through the candidate path.
//!
//! After READY: accepts ONE tunnel, echoes `--frames` frames with an
//! `echo:` prefix, waits for the tunnel `done` frame (QUIC close
//! discards in-flight frames — the same done-exchange protocol as
//! `sharenet_quic_peer`/`turn_client`), prints CLIENT_DONE, exits 0.
//!
//! Exit codes: 0 = done exchange completed; 1 = runtime failure;
//! 2 = usage.

use std::net::{SocketAddr, UdpSocket};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sharenet_transport_ice::relay::{RelayClient, RelayCredential};
use sharenet_transport_ice::stun::{
    DatagramPipe, MessageClass, StunMessage, METHOD_BINDING,
};
use sharenet_transport_quic::TunnelServer;

const SOFTWARE: &str = "sharenet-ice-peer/0.1";
const POLL: Duration = Duration::from_millis(100);

fn main() -> ExitCode {
    let mut mode = "direct".to_string();
    let mut relay_addr: Option<SocketAddr> = None;
    let mut credential: Option<RelayCredential> = None;
    let mut seed_hex: Option<String> = None;
    let mut frames: usize = 4;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => match args.next() {
                Some(m) if m == "direct" || m == "relay" => mode = m,
                other => {
                    eprintln!("error: --mode must be direct or relay, got {other:?}");
                    return ExitCode::from(2);
                }
            },
            "--relay" => match args.next().and_then(|a| a.parse().ok()) {
                Some(addr) => relay_addr = Some(addr),
                None => {
                    eprintln!("error: --relay needs a socket address");
                    return ExitCode::from(2);
                }
            },
            "--credential" => match args.next() {
                Some(text) => match RelayCredential::parse(&text) {
                    Ok(c) => credential = Some(c),
                    Err(e) => {
                        eprintln!("error: --credential: {e}");
                        return ExitCode::from(2);
                    }
                },
                None => {
                    eprintln!("error: --credential needs user:secret");
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

    // The real node-pinned QUIC tunnel server (R4-001) this peer serves.
    let server = match TunnelServer::bind("127.0.0.1:0".parse().expect("addr"), seed, None) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: quic bind: {e}");
            return ExitCode::from(1);
        }
    };
    let node_id = server.node_id();
    let quic_addr = match server.local_addr() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: server addr: {e}");
            return ExitCode::from(1);
        }
    };

    // Run the ICE-lite demux on the candidate path.
    let (stop, threads): (Arc<AtomicBool>, Vec<std::thread::JoinHandle<()>>) = if mode == "direct"
    {
        let candidate =
            Arc::new(UdpSocket::bind("127.0.0.1:0").expect("bind candidate socket"));
        candidate
            .set_read_timeout(Some(POLL))
            .expect("timeout");
        let ready_addr = candidate.local_addr().expect("addr");
        let (stop, threads) = start_demux(candidate, quic_addr);
        let node_hex: String = node_id.iter().map(|b| format!("{b:02x}")).collect();
        println!("READY {ready_addr} {node_hex}");
        (stop, threads)
    } else {
        let relay_addr = match relay_addr {
            Some(a) => a,
            None => {
                eprintln!("error: --mode relay requires --relay <addr>");
                return ExitCode::from(2);
            }
        };
        // The control bind must share the relay's address family.
        let control_bind = if relay_addr.is_ipv4() {
            "127.0.0.1:0".parse().expect("addr")
        } else {
            "[::1]:0".parse().expect("addr")
        };
        let client = match &credential {
            Some(c) => {
                match RelayClient::allocate_authenticated(relay_addr, control_bind, c) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("error: authenticated allocate on {relay_addr}: {e}");
                        return ExitCode::from(1);
                    }
                }
            }
            None => match RelayClient::allocate(relay_addr, control_bind) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: allocate on {relay_addr}: {e}");
                    return ExitCode::from(1);
                }
            },
        };
        // Permission-lite: receive through the relayed address only after
        // this client has sent first.
        if let Err(e) = client.activate() {
            eprintln!("error: activate: {e}");
            return ExitCode::from(1);
        }
        if let Err(e) = client.set_read_timeout(Some(POLL)) {
            eprintln!("error: timeout: {e}");
            return ExitCode::from(1);
        }
        let relayed = client.relayed_addr();
        let (stop, threads) = start_demux(Arc::new(client), quic_addr);
        let node_hex: String = node_id.iter().map(|b| format!("{b:02x}")).collect();
        println!("READY {relayed} {node_hex}");
        (stop, threads)
    };

    eprintln!(
        "ice_peer: candidate serving checks + QUIC (server node {})",
        node_id.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );

    let mut stream = match server.accept() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: accept: {e}");
            return ExitCode::from(1);
        }
    };
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
    // Deterministic shutdown: the client confirms receipt with "done"
    // (QUIC close discards in-flight frames).
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
    stop.store(true, Ordering::SeqCst);
    for t in threads {
        let _ = t.join();
    }
    println!("CLIENT_DONE");
    ExitCode::SUCCESS
}

/// Start the ICE-lite demux loops over `pipe` (the candidate path — a
/// plain UDP socket in direct mode, a relay allocation in relay mode),
/// backhauling the data protocol to the QUIC server at `quic_addr`.
/// Returns the stop flag and the two loop threads.
fn start_demux<P>(
    pipe: Arc<P>,
    quic_addr: SocketAddr,
) -> (Arc<AtomicBool>, Vec<std::thread::JoinHandle<()>>)
where
    P: DatagramPipe + Send + Sync + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    // The backhaul socket the demux talks to the QUIC server through
    // (the QUIC server's responses return to it — the demux then sends
    // them on through the candidate path to the right peer).
    let backhaul = Arc::new(
        UdpSocket::bind(if quic_addr.is_ipv4() {
            "127.0.0.1:0".parse::<SocketAddr>().expect("addr")
        } else {
            "[::1]:0".parse::<SocketAddr>().expect("addr")
        })
        .expect("bind backhaul"),
    );
    backhaul.set_read_timeout(Some(POLL)).expect("timeout");
    let last_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let mut threads = Vec::with_capacity(2);

    // in-loop: candidate path → STUN answer / backhaul forward.
    {
        let pipe = pipe.clone();
        let backhaul = backhaul.clone();
        let stop = stop.clone();
        let last_peer = last_peer.clone();
        threads.push(
            std::thread::Builder::new()
                .name("ice-peer-in".into())
                .spawn(move || {
                    let mut buf = [0u8; 65_536];
                    while !stop.load(Ordering::SeqCst) {
                        match pipe.pipe_recv_from(&mut buf) {
                            Ok((peer, n)) => {
                                // RFC 7983-style demux: STUN messages
                                // have the leading two bits zero.
                                let maybe_stun = n > 0 && buf[0] < 0x40;
                                if maybe_stun {
                                    if let Ok(msg) = StunMessage::parse(&buf[..n]) {
                                        if msg.class == MessageClass::Request
                                            && msg.method == METHOD_BINDING
                                        {
                                            match StunMessage::binding_success(
                                                msg.transaction_id,
                                                peer,
                                                Some(SOFTWARE),
                                            )
                                            .and_then(|m| m.encode())
                                            {
                                                Ok(response) => {
                                                    if let Err(e) =
                                                        pipe.pipe_send_to(peer, &response)
                                                    {
                                                        eprintln!(
                                                            "ice-peer: check reply failed: {e}"
                                                        );
                                                    }
                                                    continue;
                                                }
                                                Err(e) => {
                                                    eprintln!(
                                                        "ice-peer: check reply encode: {e}"
                                                    );
                                                    continue;
                                                }
                                            }
                                        }
                                    }
                                }
                                // Not a check: opaque data → the QUIC
                                // server (L012 — never parsed).
                                *last_peer.lock().expect("last_peer") = Some(peer);
                                if let Err(e) = backhaul.send_to(&buf[..n], quic_addr) {
                                    eprintln!("ice-peer: backhaul forward failed: {e}");
                                }
                            }
                            Err(sharenet_transport_ice::IceError::TimedOut) => continue,
                            Err(e) => {
                                eprintln!("ice-peer: candidate receive failed: {e}");
                                return;
                            }
                        }
                    }
                })
                .expect("spawn ice-peer-in"),
        );
    }

    // out-loop: QUIC server responses → the candidate path.
    {
        let pipe = pipe.clone();
        let backhaul = backhaul.clone();
        let stop = stop.clone();
        let last_peer = last_peer.clone();
        threads.push(
            std::thread::Builder::new()
                .name("ice-peer-out".into())
                .spawn(move || {
                    let mut buf = [0u8; 65_536];
                    while !stop.load(Ordering::SeqCst) {
                        match backhaul.recv_from(&mut buf) {
                            Ok((n, from)) => {
                                if from != quic_addr {
                                    continue; // only the pinned server
                                }
                                let peer_guard = last_peer.lock().expect("last_peer");
                                if let Some(peer) = peer_guard.as_ref() {
                                    if let Err(e) = pipe.pipe_send_to(*peer, &buf[..n]) {
                                        eprintln!(
                                            "ice-peer: candidate send failed: {e}"
                                        );
                                    }
                                }
                            }
                            Err(e)
                                if matches!(
                                    e.kind(),
                                    std::io::ErrorKind::WouldBlock
                                        | std::io::ErrorKind::TimedOut
                                ) =>
                            {
                                continue
                            }
                            Err(e) => {
                                eprintln!("ice-peer: backhaul receive failed: {e}");
                                return;
                            }
                        }
                    }
                })
                .expect("spawn ice-peer-out"),
        );
    }

    (stop, threads)
}
