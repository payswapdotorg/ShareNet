//! `adcos_test_server` — TEST SCAFFOLDING for the R5-002 integration
//! verification: a REAL HTTP server speaking exactly the ADCOS
//! developer-API wire shape this crate documents (the endpoint table
//! in `wire.rs`), backed by a deterministic in-memory store, with
//! injectable fault modes.
//!
//! Usage: adcos_test_server [--bind ADDR] [--fault MODE]
//!
//! Fault modes (adversarial affordances, one per server):
//!
//! - `503:N` — the first N requests answer `503 provider_unavailable`
//!   (with `last_observation_fresh_until_unix` when the addressed
//!   contract has observations), then the server recovers;
//! - `drop:N` — the first N connections are closed without any
//!   response (the client must surface a typed transport error and
//!   never fabricate state);
//! - `garbage:N` — the first N success responses carry non-JSON bytes
//!   with status 200 (the client must fail typed, never guess).
//!
//! Protocol: prints `READY <addr>` on stdout, then serves until killed
//! (the test harness kills the process; that is the documented
//! lifecycle). stderr carries a per-request trace.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::ExitCode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use sharenet_connectivity::{RefKind, REQUIREMENT_VERSION, SERVICE_CLASSES};
use sharenet_connectivity_client::http::{
    parse_request, serialize_response, HttpRequest, Method,
};
use sharenet_connectivity_client::wire::{
    ContractRefBody, CreateIntentBody, ExecutionBody, IntentRefBody, ObservationBody,
    ProjectionBody, WireErrorBody, WireErrorEnvelope, WireRef,
};

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_id(n: u64, salt: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[..8].copy_from_slice(&(n ^ ((salt as u64) << 56)).to_be_bytes());
    id[31] = salt;
    id
}

fn wire_ref(kind: RefKind, id: &[u8; 32]) -> WireRef {
    let text: String = id.iter().map(|b| format!("{b:02x}")).collect();
    WireRef {
        kind: match kind {
            RefKind::Intent => "intent",
            RefKind::Offer => "offer",
            RefKind::Contract => "contract",
        }
        .to_string(),
        id: text,
    }
}

struct Contract {
    state: String,
    valid_from_unix: u64,
    valid_until_unix: u64,
    observations: Vec<ObservationBody>,
    execution: (String, u64, u64), // state, throughput_bps, latency_ms
}

struct Store {
    intents: HashMap<[u8; 32], Vec<[u8; 32]>>, // intent -> offers
    offers: HashMap<[u8; 32], [u8; 32]>,     // offer -> owning intent
    accepted: HashMap<[u8; 32], [u8; 32]>,    // offer -> contract
    contracts: HashMap<[u8; 32], Contract>,
    next: AtomicU64,
    sequence: AtomicU64,
}

fn json_response(status: u16, body: &[u8]) -> Vec<u8> {
    serialize_response(status, "application/json", body)
}

fn error_body(code: &str) -> WireErrorBody {
    WireErrorBody {
        code: code.to_string(),
        intent: None,
        offer: None,
        passed_intent: None,
        contract: None,
        found: None,
        len: None,
        max: None,
        valid_from_unix: None,
        valid_until_unix: None,
        expected_kind: None,
        found_kind: None,
        last_observation_fresh_until_unix: None,
    }
}

fn error_response(status: u16, code: &str) -> Vec<u8> {
    let envelope = WireErrorEnvelope {
        error: error_body(code),
    };
    json_response(status, &serde_json::to_vec(&envelope).expect("serialize error"))
}

fn error_response_ref(status: u16, code: &str, kind: RefKind, id: &[u8; 32]) -> Vec<u8> {
    let mut body = error_body(code);
    let r = wire_ref(kind, id);
    match code {
        "intent_unknown" => body.intent = Some(r),
        "offer_unknown" => body.offer = Some(r),
        "contract_unknown" => body.contract = Some(r),
        _ => {}
    }
    let envelope = WireErrorEnvelope { error: body };
    json_response(status, &serde_json::to_vec(&envelope).expect("serialize error"))
}

fn error_response_with(status: u16, code: &str, fresh_until: u64) -> Vec<u8> {
    let mut body = error_body(code);
    body.last_observation_fresh_until_unix = Some(fresh_until);
    let envelope = WireErrorEnvelope { error: body };
    json_response(status, &serde_json::to_vec(&envelope).expect("serialize error"))
}

fn handle(store: &mut Store, request: &HttpRequest) -> Vec<u8> {
    let path = request.path.as_str();
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();
    let now = now_unix();
    match (request.method, segments.as_slice()) {
        (Method::Post, ["intents"]) => {
            let body: CreateIntentBody = match serde_json::from_slice(&request.body) {
                Ok(b) => b,
                Err(_) => return error_response(400, "malformed"),
            };
            if body.version != REQUIREMENT_VERSION {
                let mut error = error_body("requirement_version_unsupported");
                error.found = Some(body.version as u64);
                let envelope = WireErrorEnvelope { error };
                return json_response(
                    400,
                    &serde_json::to_vec(&envelope).expect("serialize"),
                );
            }
            if !SERVICE_CLASSES.contains(&body.service_class.as_str()) {
                return error_response(400, "service_class_unknown");
            }
            let n = store.next.fetch_add(1, Ordering::SeqCst);
            let intent = hex_id(n, 0x01);
            let offers = vec![hex_id(n, 0x02), hex_id(n + 1000, 0x02)];
            store.intents.insert(intent, offers.clone());
            for offer in offers {
                store.offers.insert(offer, intent);
            }
            let body = IntentRefBody {
                intent_ref: wire_ref(RefKind::Intent, &intent),
            };
            json_response(200, &serde_json::to_vec(&body).expect("serialize"))
        }
        (Method::Get, ["intents", id, "offers"]) => {
            let Ok(intent) = parse_id(id) else {
                return error_response_ref(404, "intent_unknown", RefKind::Intent, &[0xEE; 32]);
            };
            match store.intents.get(&intent) {
                Some(offers) => {
                    let body: Vec<WireRef> = offers
                        .iter()
                        .map(|o| wire_ref(RefKind::Offer, o))
                        .collect();
                    json_response(200, &serde_json::to_vec(&body).expect("serialize"))
                }
                None => error_response_ref(404, "intent_unknown", RefKind::Intent, &intent),
            }
        }
        (Method::Post, ["intents", intent_id, "offers", offer_id, "accept"]) => {
            let Ok(intent) = parse_id(intent_id) else {
                return error_response(404, "intent_unknown");
            };
            let Ok(offer) = parse_id(offer_id) else {
                return error_response(404, "offer_unknown");
            };
            if !store.intents.contains_key(&intent) {
                return error_response(404, "intent_unknown");
            }
            match store.offers.get(&offer) {
                None => return error_response(404, "offer_unknown"),
                Some(owner) if *owner != intent => {
                    return error_response(409, "offer_not_for_intent");
                }
                _ => {}
            }
            if let Some(contract) = store.accepted.get(&offer) {
                let mut error = error_body("offer_already_consumed");
                error.offer = Some(wire_ref(RefKind::Offer, &offer));
                error.contract = Some(wire_ref(RefKind::Contract, contract));
                let envelope = WireErrorEnvelope { error };
                return json_response(409, &serde_json::to_vec(&envelope).expect("serialize"));
            }
            let n = store.next.fetch_add(1, Ordering::SeqCst);
            let contract_id = hex_id(n, 0x03);
            let sequence = store.sequence.fetch_add(1, Ordering::SeqCst) + 1;
            store.accepted.insert(offer, contract_id);
            store.contracts.insert(
                contract_id,
                Contract {
                    state: "active".into(),
                    valid_from_unix: now,
                    valid_until_unix: now + 3600,
                    observations: vec![ObservationBody {
                        kind: "contract_activated".into(),
                        observed_at_unix: now,
                        contract: wire_ref(RefKind::Contract, &contract_id),
                        sequence,
                    }],
                    execution: ("running".into(), 1_000_000, 40),
                },
            );
            let body = ContractRefBody {
                contract_ref: wire_ref(RefKind::Contract, &contract_id),
            };
            json_response(200, &serde_json::to_vec(&body).expect("serialize"))
        }
        (Method::Get, ["contracts", id]) => {
            let Ok(contract_id) = parse_id(id) else {
                return error_response_ref(404, "contract_unknown", RefKind::Contract, &[0xEE; 32]);
            };
            match store.contracts.get(&contract_id) {
                None => error_response_ref(404, "contract_unknown", RefKind::Contract, &contract_id),
                Some(c) => {
                    let body = ProjectionBody {
                        contract_ref: wire_ref(RefKind::Contract, &contract_id),
                        state: c.state.clone(),
                        valid_from_unix: c.valid_from_unix,
                        valid_until_unix: c.valid_until_unix,
                        freshness_unix: now,
                    };
                    json_response(200, &serde_json::to_vec(&body).expect("serialize"))
                }
            }
        }
        (Method::Get, ["contracts", id, "assurance"]) => {
            let Ok(contract_id) = parse_id(id) else {
                return error_response_ref(404, "contract_unknown", RefKind::Contract, &[0xEE; 32]);
            };
            match store.contracts.get(&contract_id) {
                None => error_response_ref(404, "contract_unknown", RefKind::Contract, &contract_id),
                Some(c) => {
                    json_response(200, &serde_json::to_vec(&c.observations).expect("serialize"))
                }
            }
        }
        (Method::Get, ["contracts", id, "execution"]) => {
            let Ok(contract_id) = parse_id(id) else {
                return error_response_ref(404, "contract_unknown", RefKind::Contract, &[0xEE; 32]);
            };
            match store.contracts.get(&contract_id) {
                None => error_response_ref(404, "contract_unknown", RefKind::Contract, &contract_id),
                Some(c) => {
                    let body = ExecutionBody {
                        contract_ref: wire_ref(RefKind::Contract, &contract_id),
                        state: c.execution.0.clone(),
                        throughput_bps: c.execution.1,
                        latency_ms: c.execution.2,
                        freshness_unix: now,
                    };
                    json_response(200, &serde_json::to_vec(&body).expect("serialize"))
                }
            }
        }
        (Method::Post, ["contracts", id, "terminate"]) => {
            let Ok(contract_id) = parse_id(id) else {
                return error_response_ref(404, "contract_unknown", RefKind::Contract, &[0xEE; 32]);
            };
            match store.contracts.get_mut(&contract_id) {
                None => error_response_ref(404, "contract_unknown", RefKind::Contract, &contract_id),
                Some(c) => {
                    if c.state != "terminated" {
                        let sequence = store.sequence.fetch_add(1, Ordering::SeqCst) + 1;
                        c.state = "terminated".into();
                        c.observations.push(ObservationBody {
                            kind: "terminated".into(),
                            observed_at_unix: now,
                            contract: wire_ref(RefKind::Contract, &contract_id),
                            sequence,
                        });
                    }
                    json_response(200, b"{}")
                }
            }
        }
        _ => error_response(404, "not_found"),
    }
}

fn parse_id(text: &str) -> Result<[u8; 32], ()> {
    if text.len() != 64 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(());
    }
    let mut id = [0u8; 32];
    for (i, b) in id.iter_mut().enumerate() {
        *b = u8::from_str_radix(&text[2 * i..2 * i + 2], 16).map_err(|_| ())?;
    }
    Ok(id)
}

fn main() -> ExitCode {
    let mut bind: SocketAddr = "127.0.0.1:0".parse().expect("static addr");
    let mut fault: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => match args.next().and_then(|a| a.parse().ok()) {
                Some(a) => bind = a,
                None => {
                    eprintln!("error: --bind needs a socket address");
                    return ExitCode::from(2);
                }
            },
            "--fault" => fault = args.next(),
            other => {
                eprintln!("error: unknown argument {other:?}");
                return ExitCode::from(2);
            }
        }
    }
    // Fault mode: "MODE:N" — the first N requests are affected.
    let (fault_mode, fault_count) = match fault.as_deref() {
        None => (None, 0u64),
        Some(spec) => match spec.split_once(':') {
            Some((mode, n)) => match (mode, n.parse::<u64>()) {
                ("503", Ok(n)) => (Some("503"), n),
                ("drop", Ok(n)) => (Some("drop"), n),
                ("garbage", Ok(n)) => (Some("garbage"), n),
                _ => {
                    eprintln!("error: unknown fault {spec:?} (want 503:N | drop:N | garbage:N)");
                    return ExitCode::from(2);
                }
            },
            None => {
                eprintln!("error: --fault wants MODE:N (503:N | drop:N | garbage:N)");
                return ExitCode::from(2);
            }
        },
    };

    let listener = match TcpListener::bind(bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: bind {bind}: {e}");
            return ExitCode::from(1);
        }
    };
    let addr = listener.local_addr().expect("addr");
    println!("READY {addr}");

    let store = Arc::new(Mutex::new(Store {
        intents: HashMap::new(),
        offers: HashMap::new(),
        accepted: HashMap::new(),
        contracts: HashMap::new(),
        next: AtomicU64::new(1),
        sequence: AtomicU64::new(0),
    }));
    let served = Arc::new(AtomicU64::new(0));

    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { continue };
        let store = store.clone();
        let fault_mode = fault_mode.map(str::to_string);
        let served = served.clone();
        std::thread::spawn(move || {
            let request = match read_request(&mut stream) {
                Ok(Some(r)) => r,
                Ok(None) => return,
                Err(e) => {
                    eprintln!("server: bad request: {e:?}");
                    return;
                }
            };
            let index = served.fetch_add(1, Ordering::SeqCst);
            let mut store = store.lock().expect("store lock");
            let response = if index < fault_count {
                match fault_mode.as_deref() {
                    Some("drop") => {
                        eprintln!("server: fault drop #{index}");
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                        return;
                    }
                    Some("garbage") => {
                        eprintln!("server: fault garbage #{index}");
                        serialize_response(200, "text/plain", b"<html>not json</html>")
                    }
                    _ => {
                        eprintln!("server: fault 503 #{index}");
                        // A 503 for a contract-aware call carries the
                        // cached-observation freshness bound when known.
                        let fresh = request
                            .path
                            .trim_start_matches("/contracts/")
                            .split('/')
                            .next()
                            .and_then(|id| parse_id(id).ok())
                            .and_then(|id| store.contracts.get(&id))
                            .map(|c| c.valid_until_unix);
                        match fresh {
                            Some(f) => error_response_with(503, "provider_unavailable", f),
                            None => error_response(503, "provider_unavailable"),
                        }
                    }
                }
            } else {
                handle(&mut store, &request)
            };
            if let Err(e) = stream.write_all(&response) {
                eprintln!("server: write failed: {e}");
            }
            let _ = stream.flush();
        });
    }
    ExitCode::SUCCESS
}

/// One HTTP request per connection (Connection: close semantics — the
/// client crate's documented minimal subset).
fn read_request(stream: &mut TcpStream) -> Result<Option<HttpRequest>, String> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    // Read until the head terminator, then the content-length body.
    loop {
        if let Some(pos) = find_head_terminator(&buf) {
            let head_end = pos + 4;
            let (method_str, path, headers) = parse_head(&buf[..head_end])?;
            let content_length = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.parse::<usize>().ok())
                .unwrap_or(0);
            let mut body = buf[head_end..].to_vec();
            while body.len() < content_length {
                let n = stream
                    .read(&mut chunk)
                    .map_err(|e| e.to_string())?;
                if n == 0 {
                    return Err("connection closed mid-body".into());
                }
                body.extend_from_slice(&chunk[..n]);
            }
            body.truncate(content_length);
            let method = match method_str.as_str() {
                "GET" => Method::Get,
                "POST" => Method::Post,
                other => return Err(format!("unsupported method {other}")),
            };
            return Ok(Some(HttpRequest { method, path, body }));
        }
        let n = stream.read(&mut chunk).map_err(|e| e.to_string())?;
        if n == 0 {
            return if buf.is_empty() {
                Ok(None)
            } else {
                Err("connection closed mid-head".into())
            };
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 64 * 1024 {
            return Err("request too large".into());
        }
    }
}

fn find_head_terminator(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

fn parse_head(head: &[u8]) -> Result<(String, String, Vec<(String, String)>), String> {
    let text = String::from_utf8_lossy(head);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or("empty head")?;
    let mut parts = request_line.split(' ');
    let method = parts.next().ok_or("no method")?.to_string();
    let path = parts.next().ok_or("no path")?.to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok((method, path, headers))
}

// parse_request re-exported usage guard (the binary's HTTP parsing is
// its own minimal reader; the crate's parser is the CLIENT side).
#[allow(dead_code)]
fn _unused(_: Option<HttpRequest>) {
    let _ = parse_request;
}
