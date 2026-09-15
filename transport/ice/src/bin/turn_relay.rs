//! `turn_relay` — TEST SCAFFOLDING for the R4-005 multiprocess
//! verification: a REAL second process running the TURN-style relay
//! (allocation control + opaque datagram forwarding) over real loopback
//! UDP.
//!
//! Usage: turn_relay [--bind <addr>]
//!
//! Protocol: prints READY <control-addr>, then serves allocations until
//! the process is killed (tests kill it after their application-level
//! done exchange — the same cleanup the QUIC peer's tests use). Each
//! allocation is reported on STDERR as
//! `ALLOCATION <id> owner <addr> relayed <addr>`; the relayed address
//! itself reaches the allocating client through the documented control
//! framing (ALLOCATE-SUCCESS), not stdout.
//!
//! The relay parses ONLY the tiny control framing: relayed datagrams
//! are opaque bytes (architecture lock L012). Adversarial input never
//! kills it — unparseable datagrams are dropped, semantically invalid
//! control frames get a RELAY-ERROR reply, and the loop carries on.
//!
//! Exit code 1 if the control loop fails (it never exits 0 on its own).
//!
//! `--bind` MUST be a concrete address (127.0.0.1:0 by default): a
//! wildcard would produce unusable relayed addresses (the library
//! rejects it with `RelayBindUnspecified`).

use std::net::SocketAddr;
use std::process::ExitCode;

use sharenet_transport_ice::RelayServer;

fn main() -> ExitCode {
    let mut bind: SocketAddr = "127.0.0.1:0".parse().expect("static addr");
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
            other => {
                eprintln!("error: unknown argument {other:?}");
                return ExitCode::from(2);
            }
        }
    }
    let relay = match RelayServer::bind(bind) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("error: relay bind {bind}: {e}");
            return ExitCode::from(1);
        }
    };
    let control = match relay.control_addr() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: control_addr: {e}");
            return ExitCode::from(1);
        }
    };
    println!("READY {control}");
    eprintln!("relay: serving allocations on {control} until killed");
    match relay.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: relay loop: {e}");
            ExitCode::from(1)
        }
    }
}
