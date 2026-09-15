//! `sharenet-conformance` — the Rust leg of the R1-003 cross-language
//! conformance harness (architecture lock L022).
//!
//! Reads the committed vector files (`tests/vectors/*.json`) and prints one
//! canonical line per check to stdout. The TypeScript and Python legs print
//! byte-identical lines; `reference/conformance/run_harness.sh` diffs the
//! three outputs and fails on any divergence.
//!
//! Output format (frozen — a change here is a protocol-profile change and
//! must regenerate + re-review all three legs):
//!
//! ```text
//! CBOR_RT  <idx> <re-encoded hex>
//! CBOR_REJ <idx> <DecodeError name>
//! IDENT    <idx> pk=<hex> id=<hex> wire=<hex> sig=ok
//! CAP      <idx> pk=<hex> id=<hex> wire=<hex> sig=<signature hex>
//! ADMIT    <idx> now=<unix> require=<csv> <"ok" | AdmissionError name>
//! CAP_REJ  <idx> <CapabilityError name>
//! ```
//!
//! Every value is RE-DERIVED from the vector inputs (never copied from the
//! expected fields): public keys from seeds, node ids from keys, wire bytes
//! from field values, signatures from seeds. Exit code 0 only when every
//! in-language check passes; the cross-language byte-diff is the harness's
//! job.

use std::collections::BTreeMap;
use std::process::ExitCode;

use serde::Deserialize;

use sharenet_protocol::cbor::{decode, encode, Value};
use sharenet_protocol::topology::{
    LinkQualitySnapshot, Observation, ReceiveOutcome, SignedTopologyEvidence, TopologyEvidence,
    TopologyStore,
};
use sharenet_protocol::advertisement::{
    Advertisement, DiscoveryCache, DiscoveryOutcome, SignedAdvertisement, TransportDescriptor,
};
use sharenet_protocol::capability::{admit, Capability, CapabilityStatement};
use sharenet_protocol::identity::{derive_node_id, Identity};
use sharenet_protocol::link::{LinkInitiator, LinkResponder, LinkSession};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let vectors_dir = match args.next() {
        Some(d) => std::path::PathBuf::from(d),
        None => std::path::PathBuf::from(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../sharenet-protocol/tests/vectors"
        )),
    };
    let mut failures = 0usize;

    // ---------------- CBOR vectors ----------------
    #[derive(Deserialize)]
    struct CborFile {
        roundtrip: Vec<CborRt>,
        reject: Vec<CborRej>,
    }
    #[derive(Deserialize)]
    struct CborRt {
        hex: String,
    }
    #[derive(Deserialize)]
    struct CborRej {
        hex: String,
        error: String,
    }
    let cbor: CborFile = load_json(&vectors_dir.join("cbor_vectors.json"));
    for (i, case) in cbor.roundtrip.iter().enumerate() {
        let bytes = from_hex(&case.hex);
        match decode(&bytes) {
            Ok(v) => {
                let re = encode(&v).expect("in-profile value re-encodes");
                if re != bytes {
                    eprintln!("FAIL cbor roundtrip {i}: byte-stability broken");
                    failures += 1;
                }
                println!("CBOR_RT {i} {}", to_hex(&re));
            }
            Err(e) => {
                eprintln!("FAIL cbor roundtrip {i}: decode error {e}");
                failures += 1;
            }
        }
    }
    for (i, case) in cbor.reject.iter().enumerate() {
        let bytes = from_hex(&case.hex);
        match decode(&bytes) {
            Err(e) => {
                if e.name() != case.error {
                    eprintln!(
                        "FAIL cbor reject {i}: error {} != expected {}",
                        e.name(),
                        case.error
                    );
                    failures += 1;
                }
                println!("CBOR_REJ {i} {}", e.name());
            }
            Ok(_) => {
                eprintln!("FAIL cbor reject {i}: unexpectedly decoded");
                failures += 1;
            }
        }
    }

    // ---------------- identity vectors ----------------
    #[derive(Deserialize)]
    struct IdentFile {
        cases: Vec<IdentCase>,
    }
    #[derive(Deserialize)]
    struct IdentCase {
        seed_hex: String,
        created_at_unix: u64,
        display_name: Option<String>,
        payload_hex: String,
        signature_hex: String,
        #[allow(dead_code)]
        node_id_hex: String,
        #[allow(dead_code)]
        identity_wire_hex: String,
    }
    let ident: IdentFile = load_json(&vectors_dir.join("identity_vectors.json"));
    for (i, case) in ident.cases.iter().enumerate() {
        let seed: [u8; 32] = from_hex(&case.seed_hex).try_into().expect("seed len");
        let id = Identity::from_seed(seed, case.created_at_unix, case.display_name.clone())
            .expect("identity builds");
        let pk = id.node_identity().public_key_bytes();
        let node_id = derive_node_id(1, &pk);
        let wire = encode(&id.node_identity().to_wire()).expect("wire encodes");
        let payload = from_hex(&case.payload_hex);
        let sig = from_hex(&case.signature_hex);
        let sig_ok = id.node_identity().verify_detached(&payload, &sig).is_ok();
        if !sig_ok {
            eprintln!("FAIL identity {i}: signature did not verify");
            failures += 1;
        }
        println!(
            "IDENT {i} pk={} id={} wire={} sig={}",
            to_hex(&pk),
            to_hex(node_id.as_bytes()),
            to_hex(&wire),
            if sig_ok { "ok" } else { "fail" }
        );
    }

    // ---------------- capability vectors ----------------
    #[derive(Deserialize)]
    struct CapFile {
        cases: Vec<CapCase>,
        admit: Vec<AdmitCase>,
        parse_reject: Vec<CapRej>,
    }
    #[derive(Deserialize)]
    struct CapCase {
        seed_hex: String,
        capabilities: Vec<String>,
        issued_at_unix: u64,
        expires_at_unix: u64,
        limits: Option<BTreeMap<String, i64>>,
    }
    #[derive(Deserialize)]
    struct AdmitCase {
        case: usize,
        now_unix: u64,
        require: Vec<String>,
        /// Data-driven rule for which key performs verification:
        /// absent/null = the case's own key; "next" = the next case's key
        /// (the documented node_id_mismatch scenario).
        verify_key: Option<String>,
    }
    #[derive(Deserialize)]
    struct CapRej {
        hex: String,
    }
    let caps_file: CapFile = load_json(&vectors_dir.join("capability_vectors.json"));
    let parse_capability = |t: &str| -> Capability {
        match t {
            "gateway" => Capability::Gateway,
            "relay" => Capability::Relay,
            "dtn_custodian" => Capability::DtnCustodian,
            "infrastructure" => Capability::Infrastructure,
            other => panic!("bad capability text in vectors: {other}"),
        }
    };
    let identity_of = |case: &CapCase| -> Identity {
        let seed: [u8; 32] = from_hex(&case.seed_hex).try_into().expect("seed len");
        Identity::from_seed(seed, 0, None).expect("identity builds")
    };
    for (i, case) in caps_file.cases.iter().enumerate() {
        let id = identity_of(case);
        let caps: Vec<Capability> = case.capabilities.iter().map(|t| parse_capability(t)).collect();
        let st = CapabilityStatement::new(
            id.node_id(),
            &caps,
            case.issued_at_unix,
            case.expires_at_unix,
            case.limits.clone(),
        )
        .expect("statement builds");
        let wire = st.to_wire_bytes();
        let signed = st.sign(&id).expect("signs");
        println!(
            "CAP {i} pk={} id={} wire={} sig={}",
            to_hex(&id.node_identity().public_key_bytes()),
            id.node_id(),
            to_hex(&wire),
            to_hex(signed.signature()),
        );
    }
    for (i, a) in caps_file.admit.iter().enumerate() {
        let case = &caps_file.cases[a.case];
        let id = identity_of(case);
        let verifier = if a.verify_key.as_deref() == Some("next") {
            let next = &caps_file.cases[(a.case + 1) % caps_file.cases.len()];
            identity_of(next)
        } else {
            id.clone()
        };
        let require: Vec<Capability> = a.require.iter().map(|t| parse_capability(t)).collect();
        // Rebuild the statement wire (independent re-derivation).
        let caps: Vec<Capability> = case.capabilities.iter().map(|t| parse_capability(t)).collect();
        let st = CapabilityStatement::new(
            id.node_id(),
            &caps,
            case.issued_at_unix,
            case.expires_at_unix,
            case.limits.clone(),
        )
        .expect("statement builds");
        let signed = st.sign(&id).expect("signs");
        let outcome = match admit(
            signed.statement_bytes(),
            signed.signature(),
            &verifier.node_identity().public_key_bytes(),
            a.now_unix,
            &require,
        ) {
            Ok(_) => "ok".to_string(),
            Err(e) => e.name(),
        };
        println!(
            "ADMIT {i} now={} require={} {}",
            a.now_unix,
            a.require.join(","),
            outcome
        );
    }
    for (i, r) in caps_file.parse_reject.iter().enumerate() {
        let bytes = from_hex(&r.hex);
        match CapabilityStatement::from_wire_bytes(&bytes) {
            Err(e) => println!("CAP_REJ {i} {}", e.name()),
            Ok(_) => {
                eprintln!("FAIL capability parse_reject {i}: unexpectedly parsed");
                failures += 1;
            }
        }
    }

    // ---------------- link vectors ----------------
    #[derive(Deserialize)]
    struct LinkFile {
        cases: Vec<LinkCaseV>,
        frames: Vec<LinkFrameCaseV>,
    }
    #[derive(Deserialize)]
    struct LinkCaseV {
        initiator_seed_hex: String,
        responder_seed_hex: String,
        initiator_created_at_unix: u64,
        responder_created_at_unix: u64,
        initiator_scalar_hex: String,
        responder_scalar_hex: String,
    }
    #[derive(Deserialize)]
    struct LinkFrameCaseV {
        case: usize,
        direction: u8,
        seq: u64,
        #[allow(dead_code)]
        payload_hex: String,
    }
    let link_file: LinkFile = load_json(&vectors_dir.join("link_vectors.json"));
    let mut sessions: Vec<(LinkSession, LinkSession)> = Vec::new();
    for (i, c) in link_file.cases.iter().enumerate() {
        let seed_i: [u8; 32] = from_hex(&c.initiator_seed_hex).try_into().expect("seed");
        let seed_r: [u8; 32] = from_hex(&c.responder_seed_hex).try_into().expect("seed");
        let id_i = Identity::from_seed(seed_i, c.initiator_created_at_unix, None).expect("id");
        let id_r = Identity::from_seed(seed_r, c.responder_created_at_unix, None).expect("id");
        let scalar_i: [u8; 32] = from_hex(&c.initiator_scalar_hex).try_into().expect("scalar");
        let scalar_r: [u8; 32] = from_hex(&c.responder_scalar_hex).try_into().expect("scalar");
        let initiator = LinkInitiator::from_ephemeral_bytes(&scalar_i, id_i, None)
            .expect("initiator");
        let responder = LinkResponder::new(id_r, None);
        let msg1 = initiator.initiate();
        let msg1_bytes = msg1.to_wire_bytes();
        let (msg2, pending) = responder
            .respond_fixed(&msg1, &msg1_bytes, &scalar_r)
            .expect("respond");
        let msg2_bytes = msg2.to_wire_bytes();
        let (msg3, session_i) = initiator
            .confirm(&msg1_bytes, &msg2, &msg2_bytes)
            .expect("confirm");
        let msg3_bytes = msg3.to_wire_bytes();
        let session_r = pending
            .finish(&msg1_bytes, &msg2_bytes, &msg3, &msg3_bytes)
            .expect("finish");
        println!(
            "LINK {i} msg1={} msg2={} msg3={} id={}",
            to_hex(&msg1_bytes),
            to_hex(&msg2_bytes),
            to_hex(&msg3_bytes),
            to_hex(session_i.link_id()),
        );
        sessions.push((session_i, session_r));
    }
    for f in &link_file.frames {
        // direction 1 = initiator->responder (seals on the initiator
        // session's outgoing counter); direction 2 = responder->initiator.
        let session = &mut sessions[f.case].0;
        let session = if f.direction == 2 {
            &mut sessions[f.case].1
        } else {
            session
        };
        // re-seal at the exact sequence: seal() uses the internal counter,
        // which matches the vector's seq only if frames arrive in order.
        // The vector frames are generated in increasing seq per direction;
        // to be independent of call order we re-derive by sealing up to seq.
        let frame = reseal_at(session, f.direction, f.seq, &from_hex(&f.payload_hex));
        println!(
            "LINK_FRAME {} dir={} seq={} frame={}",
            f.case,
            f.direction,
            f.seq,
            to_hex(&frame)
        );
    }

    // ---------------- advertisement vectors ----------------
    #[derive(Deserialize)]
    struct AdFile {
        cases: Vec<AdCaseV>,
        receive: Vec<AdReceiveV>,
        parse_reject: Vec<AdRejectV>,
    }
    #[derive(Deserialize)]
    struct AdCaseV {
        seed_hex: String,
        created_at_unix: u64,
        capabilities_hex: Option<String>,
        transports: Vec<AdTransportV>,
        issued_at_unix: u64,
        validity_secs: u64,
        envelope_hex: String,
    }
    #[derive(Deserialize)]
    struct AdTransportV {
        kind: String,
        endpoint: String,
    }
    #[derive(Deserialize)]
    struct AdReceiveV {
        case: usize,
        now_unix: u64,
        #[allow(dead_code)]
        expect: String,
    }
    #[derive(Deserialize)]
    struct AdRejectV {
        hex: String,
    }
    let ad_file: AdFile = load_json(&vectors_dir.join("advertisement_vectors.json"));
    for (i, c) in ad_file.cases.iter().enumerate() {
        let seed: [u8; 32] = from_hex(&c.seed_hex).try_into().expect("seed");
        let id = Identity::from_seed(seed, c.created_at_unix, None).expect("identity");
        let capabilities = c.capabilities_hex.as_ref().map(|h| from_hex(h));
        let tds: Vec<TransportDescriptor> = c
            .transports
            .iter()
            .map(|t| TransportDescriptor {
                kind: t.kind.clone(),
                endpoint: t.endpoint.clone(),
            })
            .collect();
        let ad = Advertisement::new(&id, capabilities, tds, c.issued_at_unix, c.validity_secs)
            .expect("ad builds");
        let signed = ad.sign(&id).expect("signs");
        println!(
            "AD {i} wire={} sig={} id={} env={}",
            to_hex(signed.advertisement_bytes()),
            to_hex(signed.signature()),
            to_hex(&signed.advertisement_id()),
            to_hex(&signed.to_envelope_bytes()),
        );
    }
    {
        let mut caches: std::collections::HashMap<usize, DiscoveryCache> =
            std::collections::HashMap::new();
        for (i, r) in ad_file.receive.iter().enumerate() {
            let c = &ad_file.cases[r.case];
            let signed =
                SignedAdvertisement::from_envelope_bytes(&from_hex(&c.envelope_hex))
                    .expect("envelope");
            let cache = caches.entry(r.case).or_insert_with(DiscoveryCache::new);
            let outcome = match cache.receive(&signed, r.now_unix) {
                Ok(DiscoveryOutcome::Discovered) => "discovered".to_string(),
                Ok(DiscoveryOutcome::Duplicate) => "duplicate".to_string(),
                Ok(DiscoveryOutcome::Stale) => "stale".to_string(),
                Err(e) => e.name(),
            };
            println!("AD_RECV {i} now={} {}", r.now_unix, outcome);
        }
    }
    for (i, r) in ad_file.parse_reject.iter().enumerate() {
        let bytes = from_hex(&r.hex);
        match Advertisement::from_wire_bytes(&bytes) {
            Err(e) => println!("AD_REJ {i} {}", e.name()),
            Ok(_) => {
                eprintln!("FAIL advertisement parse_reject {i}: unexpectedly parsed");
                failures += 1;
            }
        }
    }

    // ---------------- topology evidence vectors ----------------
    #[derive(Deserialize)]
    struct TopoFile {
        cases: Vec<TopoCaseV>,
        receive: Vec<TopoReceiveV>,
        parse_reject: Vec<TopoRejectV>,
    }
    #[derive(Deserialize)]
    struct TopoCaseV {
        envelope_hex: String,
        seed_hex: String,
        created_at_unix: u64,
        subject_node_id_hex: String,
        kind: String,
        link_id_hex: Option<String>,
        established_at_unix: Option<u64>,
        quality: Option<JQualityV>,
        advertisement_id_hex: Option<String>,
        capabilities: Option<Vec<String>>,
        observed_at_unix: u64,
        validity_secs: u64,
    }
    #[derive(Deserialize)]
    struct JQualityV {
        delivered: u64,
        lost: u64,
        ewma_rtt_micros: u64,
        p50_rtt_micros: u64,
        p95_rtt_micros: u64,
        jitter_mad_micros: u64,
        loss_ratio_ppm: u64,
    }
    #[derive(Deserialize)]
    struct TopoReceiveV {
        case: usize,
        now_unix: u64,
        #[allow(dead_code)]
        expect: String,
    }
    #[derive(Deserialize)]
    struct TopoRejectV {
        hex: String,
    }
    let topo_file: TopoFile = load_json(&vectors_dir.join("topology_vectors.json"));
    for (i, c) in topo_file.cases.iter().enumerate() {
        let seed: [u8; 32] = from_hex(&c.seed_hex).try_into().expect("seed");
        let obs = Identity::from_seed(seed, c.created_at_unix, None).expect("identity");
        let subject: [u8; 32] = from_hex(&c.subject_node_id_hex)
            .try_into()
            .expect("subject");
        let observation = match c.kind.as_str() {
            "link" => Observation::Link {
                link_id: from_hex(c.link_id_hex.as_deref().unwrap())
                    .try_into()
                    .unwrap(),
                established_at_unix: c.established_at_unix.unwrap(),
                quality: {
                    let q = c.quality.as_ref().unwrap();
                    LinkQualitySnapshot {
                        delivered: q.delivered,
                        lost: q.lost,
                        ewma_rtt_micros: q.ewma_rtt_micros,
                        p50_rtt_micros: q.p50_rtt_micros,
                        p95_rtt_micros: q.p95_rtt_micros,
                        jitter_mad_micros: q.jitter_mad_micros,
                        loss_ratio_ppm: q.loss_ratio_ppm,
                    }
                },
            },
            "advertisement" => Observation::Advertisement {
                advertisement_id: from_hex(c.advertisement_id_hex.as_deref().unwrap())
                    .try_into()
                    .unwrap(),
                capabilities: c.capabilities.clone().unwrap_or_default(),
            },
            other => panic!("bad kind {other}"),
        };
        let ev = TopologyEvidence::new(&obs, subject, observation, c.observed_at_unix, c.validity_secs)
            .expect("builds");
        let signed = ev.sign(&obs).expect("signs");
        println!(
            "TOPO {i} wire={} sig={} id={} env={}",
            to_hex(signed.evidence_bytes()),
            to_hex(signed.signature()),
            to_hex(&signed.evidence_id()),
            to_hex(&signed.to_envelope_bytes()),
        );
    }
    {
        let mut stores: std::collections::HashMap<usize, TopologyStore> =
            std::collections::HashMap::new();
        for (i, r) in topo_file.receive.iter().enumerate() {
            let c = &topo_file.cases[r.case];
            let signed = SignedTopologyEvidence::from_envelope_bytes(&from_hex(&c.envelope_hex))
                .expect("envelope");
            let store = stores.entry(r.case).or_insert_with(TopologyStore::new);
            let outcome = match store.receive(&signed, r.now_unix) {
                Ok(ReceiveOutcome::Collected) => "collected".to_string(),
                Ok(ReceiveOutcome::Stale) => "stale".to_string(),
                Err(e) => e.name(),
            };
            println!("TOPO_RECV {i} now={} {}", r.now_unix, outcome);
        }
    }
    for (i, r) in topo_file.parse_reject.iter().enumerate() {
        let bytes = from_hex(&r.hex);
        match TopologyEvidence::from_wire_bytes(&bytes) {
            Err(e) => println!("TOPO_REJ {i} {}", e.name()),
            Ok(_) => {
                eprintln!("FAIL topology parse_reject {i}: unexpectedly parsed");
                failures += 1;
            }
        }
    }

    // ---------------- NodeIdentity decode spot check ----------------
    // The IDENT wire lines must decode back to the identity (guards the
    // encoder/decoder pair through the same public API).
    if let Some(first) = ident.cases.first() {
        let seed: [u8; 32] = from_hex(&first.seed_hex).try_into().expect("seed len");
        let id = Identity::from_seed(seed, first.created_at_unix, first.display_name.clone())
            .expect("identity builds");
        let wire = encode(&id.node_identity().to_wire()).unwrap();
        let v = decode(&wire).expect("wire decodes");
        let back = sharenet_protocol::identity::NodeIdentity::from_wire(&v).expect("parses");
        if back.node_id() != id.node_id() {
            eprintln!("FAIL identity wire roundtrip");
            failures += 1;
        }
    }
    let _ = Value::Null; // keep the cbor Value import exercised

    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        eprintln!("{failures} conformance check(s) failed");
        ExitCode::FAILURE
    }
}

/// Seal a frame at an exact outgoing sequence: `LinkSession::seal` uses an
/// internal monotonic counter per DIRECTION, and the conformance vectors
/// pin (direction, seq) pairs; advance the counter to the requested seq by
/// sealing (and discarding) intermediate frames.
fn reseal_at(
    session: &mut LinkSession,
    _direction: u8,
    seq: u64,
    payload: &[u8],
) -> Vec<u8> {
    let current = session.frames_sent();
    if seq < current {
        panic!("vector frames must be sealed in nondecreasing seq per direction");
    }
    while session.frames_sent() < seq {
        let _ = session.seal(b"").expect("seal filler");
    }
    session.seal(payload).expect("seal requested")
}

fn load_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> T {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("cannot parse {}: {e}", path.display()))
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len() % 2 == 0, "odd hex length");
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let nib = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => panic!("bad hex digit"),
        }
    };
    for p in b.chunks(2) {
        out.push((nib(p[0]) << 4) | nib(p[1]));
    }
    out
}
