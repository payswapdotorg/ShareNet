//! `turn_relay` — TEST SCAFFOLDING for the R4-005/R4-006 multiprocess
//! verification: a REAL second process running the TURN-style relay
//! (allocation control + opaque datagram forwarding) over real loopback
//! UDP.
//!
//! Usage: turn_relay [--bind <addr>] [--realm <name>] [--auth <user:secret>]...
//!
//! Protocol: prints READY <control-addr>, then serves allocations until
//! the process is killed (tests kill it after their application-level
//! done exchange — the same cleanup the QUIC peer's tests use). Each
//! allocation is reported on STDERR as
//! `ALLOCATION <id> owner <addr> relayed <addr>`; the relayed address
//! itself reaches the allocating client through the documented control
//! framing (ALLOCATE-SUCCESS), not stdout.
//!
//! With one or more `--auth user:secret` flags the relay demands a
//! long-term-credential proof before allocating (R4-006; see the relay
//! module docs for the challenge/nonce + HMAC message-integrity model).
//! Without them the relay is the R4-005 unauthenticated TEST/LOCAL one.
//! `--realm` (default `sharenet.local`) names the protection domain.
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

use sharenet_transport_ice::relay::{RelayCredential, RelayServer};

fn main() -> ExitCode {
    let mut bind: SocketAddr = "127.0.0.1:0".parse().expect("static addr");
    let mut realm = "sharenet.local".to_string();
    let mut auth: Vec<(String, String)> = Vec::new();
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
            "--realm" => match args.next() {
                Some(r) => realm = r,
                None => {
                    eprintln!("error: --realm needs a name");
                    return ExitCode::from(2);
                }
            },
            "--auth" => {
                let text = match args.next() {
                    Some(t) => t,
                    None => {
                        eprintln!("error: --auth needs user:secret");
                        return ExitCode::from(2);
                    }
                };
                match RelayCredential::parse(&text) {
                    Ok(credential) => {
                        auth.push((credential.username, credential.secret));
                    }
                    Err(e) => {
                        eprintln!("error: --auth {text:?}: {e}");
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
    let relay = if auth.is_empty() {
        RelayServer::bind(bind)
    } else {
        RelayServer::bind_authenticated(bind, &realm, &auth)
    };
    let relay = match relay {
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
    if auth.is_empty() {
        eprintln!("relay: serving allocations on {control} until killed (unauthenticated)");
    } else {
        eprintln!(
            "relay: serving allocations on {control} until killed (realm {realm:?}, {} user(s) authenticated allocations only)",
            auth.len()
        );
    }
    match relay.run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: relay loop: {e}");
            ExitCode::from(1)
        }
    }
}
