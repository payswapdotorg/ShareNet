//! `sharenet-discover` — ShareNet discovery tool (runtime path of R3-002).
//!
//! A REAL process performing REAL socket I/O: announces the node's
//! advertisement, receives and verifies peers' advertisements, and (with
//! --link) establishes an authenticated link (R3-001) to a discovered
//! endpoint. The future daemon's discovery loop calls the same APIs.
//!
//! Exit codes: 0 success, 1 operational failure, 2 usage error.

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use sharenet_protocol::advertisement::{
    Advertisement, DiscoveryCache, DiscoveryOutcome, SignedAdvertisement, TransportDescriptor,
};
use sharenet_protocol::cbor::decode;
use sharenet_protocol::identity::Identity;
use sharenet_protocol::store::IdentityStore;
use sharenet_protocol::link::{LinkInitiator, LinkResponder, LinkSession};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    match run(argv) {
        Ok(()) => ExitCode::SUCCESS,
        Err((code, message)) => {
            eprintln!("error: {message}");
            code.into()
        }
    }
}

struct Flags {
    dir: Option<String>,
    bind: Option<String>,
    target: Option<String>,
    endpoint: Option<String>,
    ttl: u64,
    repeat: usize,
    link: bool,
    frames: usize,
}

impl Default for Flags {
    fn default() -> Self {
        Flags {
            dir: None,
            bind: None,
            target: None,
            endpoint: None,
            ttl: 300,
            repeat: 1,
            link: false,
            frames: 2,
        }
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn run(argv: Vec<String>) -> Result<(), (u8, String)> {
    let mut it = argv.into_iter();
    let _prog = it.next();
    let sub = it.next().ok_or((2u8, "a subcommand is required".to_string()))?;
    let mut flags = Flags::default();
    let mut args = it.peekable();
    while let Some(arg) = args.next() {
        if arg == "--link" {
            flags.link = true;
            continue;
        }
        let (name, inline) = match arg.split_once('=') {
            Some((n, v)) => (n.to_string(), Some(v.to_string())),
            None => (arg.clone(), None),
        };
        let value = inline
            .or_else(|| args.next())
            .ok_or((2u8, format!("'{name}' requires a value")))?;
        match name.as_str() {
            "--dir" => flags.dir = Some(value),
            "--bind" => flags.bind = Some(value),
            "--target" => flags.target = Some(value),
            "--endpoint" => flags.endpoint = Some(value),
            "--ttl" => flags.ttl = value.parse().map_err(|_| (2u8, "--ttl must be a number".to_string()))?,
            "--repeat" => flags.repeat = value.parse().map_err(|_| (2u8, "--repeat must be a number".to_string()))?,
            "--frames" => flags.frames = value.parse().map_err(|_| (2u8, "--frames must be a number".to_string()))?,
            other => return Err((2, format!("unknown argument '{other}'"))),
        }
    }
    match sub.as_str() {
        "advertise" => cmd_advertise(flags),
        "listen" => cmd_listen(flags),
        other => Err((2, format!("unknown subcommand '{other}'"))),
    }
}

fn load_identity(dir: &str) -> Result<Identity, (u8, String)> {
    let store = IdentityStore::new(dir);
    store.load().map_err(|e| (1u8, e.to_string()))
}

fn build_ad(
    identity: &Identity,
    endpoint: &str,
    ttl: u64,
) -> Result<SignedAdvertisement, (u8, String)> {
    let (kind, ep) = endpoint
        .split_once(':')
        .map(|(k, rest)| {
            if k == "udp" {
                (k.to_string(), rest.trim_start_matches("//").to_string())
            } else {
                (k.to_string(), rest.to_string())
            }
        })
        .unwrap_or_else(|| ("udp".to_string(), endpoint.to_string()));
    let ad = Advertisement::new(
        identity,
        None,
        vec![TransportDescriptor { kind, endpoint: ep }],
        now_unix(),
        ttl,
    )
    .map_err(|e| (1, format!("cannot build advertisement: {e}")))?;
    ad.sign(identity)
        .map_err(|e| (1, format!("cannot sign advertisement: {e}")))
}

fn cmd_advertise(f: Flags) -> Result<(), (u8, String)> {
    let dir = f.dir.ok_or((2, "'advertise' requires --dir".to_string()))?;
    let target = f
        .target
        .ok_or((2, "'advertise' requires --target ADDR (the discovery listener)".to_string()))?;
    let endpoint = f
        .endpoint
        .ok_or((2, "'advertise' requires --endpoint udp:HOST:PORT (your advertised address)".to_string()))?;
    let identity = load_identity(&dir)?;
    let signed = build_ad(&identity, &endpoint, f.ttl)?;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| (1, e.to_string()))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(2000)))
        .map_err(|e| (1, e.to_string()))?;
    let envelope = signed.to_envelope_bytes();
    for i in 0..f.repeat.max(1) {
        socket
            .send_to(&envelope, &target)
            .map_err(|e| (1, format!("send advertisement {i}: {e}")))?;
        // listen for the peer's reply advertisement (mutual discovery)
        let mut buf = [0u8; 65536];
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => {
                let reply = SignedAdvertisement::from_envelope_bytes(&buf[..n])
                    .map_err(|e| (1, format!("peer reply parse: {e}")))?;
                let mut cache = DiscoveryCache::new();
                match cache.receive(&reply, now_unix()) {
                    Ok(DiscoveryOutcome::Discovered) => {
                        let ad = reply.advertisement().map_err(|e| (1, e.to_string()))?;
                        println!(
                            "DISCOVERED {} via {}",
                            ad.node_id(),
                            ad.transports()
                                .iter()
                                .map(|t| format!("{}:{}", t.kind, t.endpoint))
                                .collect::<Vec<_>>()
                                .join(",")
                        );
                    }
                    Ok(DiscoveryOutcome::Duplicate) => println!("DUPLICATE"),
                    Ok(DiscoveryOutcome::Stale) => println!("STALE"),
                    Err(e) => return Err((1, format!("peer advertisement rejected: {e}"))),
                }
                let _ = from;
                break;
            }
            Err(_) => {
                eprintln!("no reply for attempt {i}");
            }
        }
    }
    println!("advertise complete");
    Ok(())
}

fn cmd_listen(f: Flags) -> Result<(), (u8, String)> {
    let dir = f.dir.ok_or((2, "'listen' requires --dir".to_string()))?;
    let bind = f
        .bind
        .ok_or((2, "'listen' requires --bind ADDR (the advertised address to listen on)".to_string()))?;
    let identity = load_identity(&dir)?;
    let socket = UdpSocket::bind(&bind).map_err(|e| (1, format!("bind {bind}: {e}")))?;
    socket
        .set_read_timeout(Some(Duration::from_millis(3000)))
        .map_err(|e| (1, e.to_string()))?;
    let local = socket.local_addr().map_err(|e| (1, e.to_string()))?;
    // --endpoint overrides what we advertise (default: the ACTUAL bound
    // address, so ephemeral ports advertise correctly)
    let endpoint = f.endpoint.clone().unwrap_or_else(|| local.to_string());
    let my_ad = build_ad(&identity, &format!("udp:{endpoint}"), f.ttl)?;
    println!("READY {local}");
    let mut cache = DiscoveryCache::new();
    let mut links_established = 0usize;
    let mut idle_rounds = 0usize;
    loop {
        let mut buf = [0u8; 65536];
        let (n, from) = match socket.recv_from(&mut buf) {
            Ok(x) => {
                idle_rounds = 0;
                x
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                idle_rounds += 1;
                println!("LISTEN_IDLE");
                // two consecutive idle rounds (6s) with nothing further:
                // the session is over either way
                if idle_rounds >= 2 {
                    println!("LISTEN_DONE");
                    return Ok(());
                }
                continue;
            }
            Err(e) => return Err((1, format!("recv: {e}"))),
        };
        // A datagram is either an advertisement envelope or (with --link)
        // the first message of a link handshake from a discovered peer.
        if let Ok(signed) = SignedAdvertisement::from_envelope_bytes(&buf[..n]) {
            match cache.receive(&signed, now_unix()) {
                Ok(DiscoveryOutcome::Discovered) | Ok(DiscoveryOutcome::Duplicate) => {
                    let ad = signed.advertisement().map_err(|e| (1, e.to_string()))?;
                    println!("DISCOVERED {} from {from}", ad.node_id());
                    // mutual discovery: reply with our advertisement
                    socket
                        .send_to(&my_ad.to_envelope_bytes(), from)
                        .map_err(|e| (1, format!("reply: {e}")))?;
                }
                Ok(DiscoveryOutcome::Stale) => println!("STALE from {from}"),
                Err(e) => eprintln!("rejected advertisement from {from}: {e}"),
            }
            continue;
        }
        if f.link {
            // try to interpret as msg1 of a link handshake
            if let Ok(value) = decode(&buf[..n]) {
                if let Ok(msg1) = sharenet_protocol::link::LinkInitiate::from_wire(&value) {
                    let msg1_bytes = buf[..n].to_vec();
                    let responder = LinkResponder::new(identity.clone(), None);
                    let (msg2, pending) = responder
                        .respond(&msg1, &msg1_bytes)
                        .map_err(|e| (1, format!("respond: {e}")))?;
                    let msg2_bytes = msg2.to_wire_bytes();
                    socket
                        .send_to(&msg2_bytes, from)
                        .map_err(|e| (1, format!("send msg2: {e}")))?;
                    // msg3
                    let (n3, from3) = socket
                        .recv_from(&mut buf)
                        .map_err(|e| (1, format!("recv msg3: {e}")))?;
                    let value3 = decode(&buf[..n3]).map_err(|e| (1, format!("msg3 cbor: {e}")))?;
                    let msg3 = sharenet_protocol::link::LinkConfirm::from_wire(&value3)
                        .map_err(|e| (1, format!("msg3 parse: {e}")))?;
                    let msg3_bytes = buf[..n3].to_vec();
                    if from3 != from {
                        return Err((1, "msg3 from a different address".into()));
                    }
                    let mut session: LinkSession = pending
                        .finish(&msg1_bytes, &msg2_bytes, &msg3, &msg3_bytes)
                        .map_err(|e| (1, format!("finish handshake: {e}")))?;
                    println!(
                        "LINK_ESTABLISHED {}",
                        session
                            .link_id()
                            .iter()
                            .map(|b| format!("{b:02x}"))
                            .collect::<String>()
                    );
                    // echo link frames
                    for _ in 0..f.frames {
                        let (nf, _from_f) = socket
                            .recv_from(&mut buf)
                            .map_err(|e| (1, format!("recv frame: {e}")))?;
                        let payload = session
                            .open(&buf[..nf])
                            .map_err(|e| (1, format!("frame open: {e}")))?;
                        let mut echoed = b"echo:".to_vec();
                        echoed.extend_from_slice(&payload);
                        let sealed = session
                            .seal(&echoed)
                            .map_err(|e| (1, format!("frame seal: {e}")))?;
                        socket
                            .send_to(&sealed, from)
                            .map_err(|e| (1, format!("send echo: {e}")))?;
                    }
                    links_established += 1;
                    println!("ECHOED {} frames", f.frames);
                }
            }
        }
    }
}
