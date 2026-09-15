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
use sharenet_protocol::capability::{admit, Capability, CapabilityStatement};
use sharenet_protocol::identity::{derive_node_id, Identity};

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
