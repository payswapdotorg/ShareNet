//! Machine-readable conformance vectors for the future cross-language harness
//! (R1-003, architecture lock L022: every normative wire object gets cross-language
//! conformance vectors).
//!
//! Two modes:
//!
//! - `cargo test -p sharenet-protocol --test test_vectors` — validates the COMMITTED
//!   vector files in `tests/vectors/` against this implementation. If the
//!   implementation drifts, these tests fail and the vectors must be consciously
//!   regenerated and re-reviewed.
//! - `cargo test -p sharenet-protocol --test test_vectors -- --ignored` — regenerates
//!   `tests/vectors/*.json` from the current implementation (run after intentional
//!   profile changes, then commit the new files).

mod common;

use common::from_hex;
use serde::{Deserialize, Serialize};
use sharenet_protocol::cbor::{decode, encode, Value};
use sharenet_protocol::identity::{
    Identity, NodeIdentity, SCHEME_VERSION, SEED_LEN, SIGNATURE_LEN,
};
use sharenet_protocol::store::{load_identity_file, IdentityStore};

const VECTORS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors");

// ---------------------------------------------------------------------------
// JSON model for CBOR values
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
enum JValue {
    Int { value: i64 },
    Bytes { hex: String },
    Text { value: String },
    Array { items: Vec<JValue> },
    Map { entries: Vec<JEntry> },
    Bool { value: bool },
    Null,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct JEntry {
    key: JValue,
    value: JValue,
}

impl From<&Value> for JValue {
    fn from(v: &Value) -> JValue {
        match v {
            Value::Int(i) => JValue::Int { value: *i },
            Value::Bytes(b) => JValue::Bytes { hex: common_hex(b) },
            Value::Text(s) => JValue::Text { value: s.clone() },
            Value::Array(items) => JValue::Array {
                items: items.iter().map(Into::into).collect(),
            },
            Value::Map(entries) => JValue::Map {
                entries: entries
                    .iter()
                    .map(|(k, v)| JEntry {
                        key: k.into(),
                        value: v.into(),
                    })
                    .collect(),
            },
            Value::Bool(b) => JValue::Bool { value: *b },
            Value::Null => JValue::Null,
        }
    }
}

impl From<&JValue> for Value {
    fn from(j: &JValue) -> Value {
        match j {
            JValue::Int { value } => Value::Int(*value),
            JValue::Bytes { hex } => Value::Bytes(from_hex(hex)),
            JValue::Text { value } => Value::Text(value.clone()),
            JValue::Array { items } => Value::Array(items.iter().map(Into::into).collect()),
            JValue::Map { entries } => Value::Map(
                entries
                    .iter()
                    .map(|e| ((&e.key).into(), (&e.value).into()))
                    .collect(),
            ),
            JValue::Bool { value } => Value::Bool(*value),
            JValue::Null => Value::Null,
        }
    }
}

fn common_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Vector file schemas
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct CborVectorsFile {
    profile: String,
    description: String,
    roundtrip: Vec<CborRoundtrip>,
    reject: Vec<CborReject>,
}

#[derive(Serialize, Deserialize)]
struct CborRoundtrip {
    hex: String,
    value: JValue,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CborReject {
    hex: String,
    error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct IdentityVectorsFile {
    scheme: String,
    node_id_derivation: String,
    description: String,
    cases: Vec<IdentityCase>,
}

#[derive(Serialize, Deserialize)]
struct IdentityCase {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    seed_hex: String,
    created_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_name: Option<String>,
    public_key_hex: String,
    /// canonical CBOR bytes of the map {1: scheme_version, 2: public_key} — the exact
    /// SHA-256 preimage for node_id.
    node_id_input_hex: String,
    node_id_hex: String,
    /// canonical CBOR bytes of the NodeIdentity map.
    identity_wire_hex: String,
    /// canonical CBOR bytes of the durable identity file map {1: seed, 2: identity}.
    file_wire_hex: String,
    payload_hex: String,
    /// detached Ed25519 signature (RFC 8032 deterministic) over payload.
    signature_hex: String,
}

// ---------------------------------------------------------------------------
// Vector generation (the single source of truth for the committed files)
// ---------------------------------------------------------------------------

fn cbor_vectors() -> CborVectorsFile {
    let rt = |hex: &str, note: Option<&str>| CborRoundtrip {
        hex: hex.to_string(),
        value: {
            let v = decode(&from_hex(hex)).expect("roundtrip vector decodes");
            (&v).into()
        },
        note: note.map(str::to_string),
    };
    let rej = |hex: &str, error: &str, note: Option<&str>| CborReject {
        hex: hex.to_string(),
        error: error.to_string(),
        note: note.map(str::to_string),
    };
    CborVectorsFile {
        profile: "sharenet-canonical-cbor-v1".into(),
        description: "ShareNet canonical CBOR profile v1 conformance vectors. \
Roundtrip cases MUST decode to `value` and re-encode to exactly `hex`. Reject cases \
MUST fail with the named typed error. Map keys sort by bytewise lexicographic order of \
their canonical encodings (see profile notes: this coincides with RFC 8949 deterministic \
ordering for equal-length key encodings)."
            .into(),
        roundtrip: vec![
            rt("00", None),
            rt("01", Some("int 1")),
            rt("17", Some("int 23 (last immediate)")),
            rt("1818", Some("int 24 (first 1-byte-arg)")),
            rt("1819", Some("int 25")),
            rt("1864", Some("int 100")),
            rt("18ff", Some("int 255 (last 1-byte-arg)")),
            rt("190100", Some("int 256")),
            rt("1903e8", Some("int 1000")),
            rt("19ffff", Some("int 65535")),
            rt("1a00010000", Some("int 65536")),
            rt("1a000f4240", Some("int 1000000")),
            rt("1affffffff", Some("int 4294967295")),
            rt("1b0000000100000000", Some("int 4294967296")),
            rt("1b000000e8d4a51000", Some("int 10^12")),
            rt("1b7fffffffffffffff", Some("int i64::MAX")),
            rt("20", Some("int -1")),
            rt("29", Some("int -10")),
            rt("37", Some("int -24")),
            rt("3818", Some("int -25")),
            rt("38ff", Some("int -256")),
            rt("390100", Some("int -257")),
            rt("3903e7", Some("int -1000")),
            rt("3b7fffffffffffffff", Some("int i64::MIN")),
            rt("f4", Some("false")),
            rt("f5", Some("true")),
            rt("f6", Some("null")),
            rt("40", Some("empty bstr")),
            rt("4401020304", Some("bstr 01020304")),
            rt("60", Some("empty text")),
            rt("6161", Some("text 'a'")),
            rt("6449455446", Some("text 'IETF'")),
            rt("62225c", Some("text quote+backslash")),
            rt("62c3bc", Some("text 'ü' (2 UTF-8 bytes)")),
            rt("63e6b0b4", Some("text '水' (3 UTF-8 bytes)")),
            rt("64f0908091", Some("text '𐀑' (4 UTF-8 bytes)")),
            rt("80", Some("empty array")),
            rt("83010203", Some("array [1,2,3]")),
            rt("8301820203820405", Some("nested arrays")),
            rt("a0", Some("empty map")),
            rt("a201020304", Some("map {1:2, 3:4}")),
            rt("a26161016162820203", Some("map {'a':1, 'b':[2,3]}")),
            rt(
                "a201022003",
                Some("map {1:2, -1:3}: bytewise key order (0x01 < 0x20)"),
            ),
            rt(
                "a21818022003",
                Some("map {24:2, -1:3}: bytewise key order (0x1818 < 0x20) — diverges from RFC 8949 length-first order"),
            ),
            rt(
                "a20102616103",
                Some("mixed-type keys {1:2, 'a':3}: bytewise (0x01 < 0x6161)"),
            ),
        ],
        reject: vec![
            rej("", "EmptyInput", Some("empty input")),
            rej("0000", "TrailingBytes", Some("int 0 then int 0")),
            rej("0102", "TrailingBytes", Some("two complete ints")),
            rej("18", "Truncated", Some("missing 1-byte argument")),
            rej("19", "Truncated", None),
            rej("41", "Truncated", Some("bstr claims 1 byte")),
            rej("44010203", "Truncated", Some("bstr claims 4, has 3")),
            rej("62 61".replace(' ', "").as_str(), "Truncated", Some("text claims 2, has 1")),
            rej("8201", "Truncated", Some("array claims 2 items")),
            rej("a101", "Truncated", Some("map claims 1 pair, value missing")),
            rej("1800", "NonMinimalInteger", Some("0 in 1-byte-arg form")),
            rej("1817", "NonMinimalInteger", Some("23 in 1-byte-arg form")),
            rej("190018", "NonMinimalInteger", Some("24 in 2-byte-arg form")),
            rej("1a000000ff", "NonMinimalInteger", None),
            rej("1b000000000000ffff", "NonMinimalInteger", None),
            rej("3817", "NonMinimalInteger", Some("-24 in 1-byte-arg form (immediate 0x37 exists)")),
            rej("5800", "NonMinimalInteger", Some("bstr length 0 in wide form")),
            rej("9800", "NonMinimalInteger", Some("array length 0 in wide form")),
            rej("b800", "NonMinimalInteger", Some("map length 0 in wide form")),
            rej("1bffffffffffffffff", "IntegerOutOfRange", Some("2^64-1 > i64::MAX")),
            rej("3bffffffffffffffff", "IntegerOutOfRange", Some("< i64::MIN")),
            rej("9f", "IndefiniteLength", Some("indefinite array")),
            rej("5f", "IndefiniteLength", Some("indefinite bstr")),
            rej("7f", "IndefiniteLength", Some("indefinite text")),
            rej("bf", "IndefiniteLength", Some("indefinite map")),
            rej("9f01ff", "IndefiniteLength", None),
            rej("a202010102", "UnsortedMapKeys", Some("{2:1, 1:2}")),
            rej("a2616201616101", "UnsortedMapKeys", Some("{'b':1,'a':1}")),
            rej("a201020103", "DuplicateMapKey", Some("{1:2, 1:3}")),
            rej("a2616101616102", "DuplicateMapKey", Some("{'a':1,'a':2}")),
            rej("c000", "TagNotAllowed", Some("tag 0 (date)")),
            rej("d86400", "TagNotAllowed", Some("tag 100")),
            rej("c24b00ffffffffffffffff", "TagNotAllowed", Some("positive bignum tag")),
            rej("c349010000000000000000", "TagNotAllowed", Some("negative bignum tag")),
            rej("f90000", "FloatNotAllowed", Some("f16 0.0")),
            rej("f93c00", "FloatNotAllowed", Some("f16 1.0")),
            rej("f93e00", "FloatNotAllowed", Some("f16 1.5")),
            rej("f97c00", "FloatNotAllowed", Some("f16 +Inf")),
            rej("f97e00", "FloatNotAllowed", Some("f16 NaN")),
            rej("fa47c35000", "FloatNotAllowed", Some("f32 100000.0")),
            rej("fb3ff199999999999a", "FloatNotAllowed", Some("f64 1.1")),
            rej("f7", "UndefinedNotAllowed", Some("undefined")),
            rej("e0", "SimpleValueNotAllowed", Some("simple 0")),
            rej("f3", "SimpleValueNotAllowed", Some("simple 19")),
            rej("f814", "SimpleValueNotAllowed", Some("two-byte false (non-canonical)")),
            rej("f8ff", "SimpleValueNotAllowed", Some("two-byte simple 255")),
            rej("ff", "BreakByteNotAllowed", Some("stray break")),
            rej("1c", "ReservedAdditionalInfo", None),
            rej("1f", "ReservedAdditionalInfo", None),
            rej("5c", "ReservedAdditionalInfo", None),
            rej("9e", "ReservedAdditionalInfo", None),
            rej("be", "ReservedAdditionalInfo", None),
            rej("dc", "ReservedAdditionalInfo", None),
            rej("fc", "ReservedAdditionalInfo", None),
            rej("61ff", "InvalidUtf8", None),
            rej("62c328", "InvalidUtf8", None),
            rej("63e6b0", "Truncated", Some("text claims 3, has 2 (truncated 水)")),
        ],
    }
}

fn identity_vectors() -> IdentityVectorsFile {
    // (seed hex, created_at, display_name, payload hex, note)
    let cases_in: &[(&str, u64, Option<&str>, &str, &str)] = &[
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            0,
            None,
            "",
            "RFC 8032 §7.1 TEST 1 seed; empty payload",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            1_700_000_000,
            None,
            "72",
            "RFC 8032 §7.1 TEST 2 seed; 1-byte payload",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            1_735_689_600,
            Some("bridge-gateway-alpha"),
            "af82",
            "RFC 8032 §7.1 TEST 3 seed; 2-byte payload",
        ),
        (
            "833fe62409237b9d62ec775ae113decbb0e30b7e2cd6e9de040a0ce9f0d4a556",
            1_700_000_001,
            Some("relay-node"),
            "53686172654e65742072656c6179207061796c6f6164",
            "deterministic generated case with name",
        ),
        (
            "0d4a556833fe62409237b9d62ec775ae113decbb0e30b7e2cd6e9de040a0ce9f",
            0,
            Some(&"é".repeat(32)),
            "00",
            "display_name with multi-byte UTF-8 (32 × 'é' = 64 bytes)",
        ),
    ];
    let mut cases = Vec::new();
    for (seed_hex, created_at, name, payload_hex, note) in cases_in {
        let seed: [u8; SEED_LEN] = from_hex(seed_hex).try_into().expect("seed length");
        let id = Identity::from_seed(seed, *created_at, name.map(str::to_string)).unwrap();
        let payload = from_hex(payload_hex);
        let sig = id.sign_detached(&payload);
        let pk = id.node_identity().public_key_bytes();
        let node_id_input = encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(SCHEME_VERSION)),
            (Value::Int(2), Value::Bytes(pk.to_vec())),
        ]))
        .unwrap();
        let identity_wire = encode(&id.node_identity().to_wire()).unwrap();
        let file_wire = encode(&Value::Map(vec![
            (Value::Int(1), Value::Bytes(seed.to_vec())),
            (Value::Int(2), id.node_identity().to_wire()),
        ]))
        .unwrap();
        cases.push(IdentityCase {
            note: Some(note.to_string()),
            seed_hex: seed_hex.to_string(),
            created_at_unix: *created_at,
            display_name: name.map(str::to_string),
            public_key_hex: common_hex(&pk),
            node_id_input_hex: common_hex(&node_id_input),
            node_id_hex: common_hex(id.node_id().as_bytes()),
            identity_wire_hex: common_hex(&identity_wire),
            file_wire_hex: common_hex(&file_wire),
            payload_hex: payload_hex.to_string(),
            signature_hex: common_hex(&sig),
        });
    }
    IdentityVectorsFile {
        scheme: "sharenet-node-identity-v1".into(),
        node_id_derivation: "node_id = SHA-256(canonical_cbor({1: scheme_version, 2: public_key}))"
            .into(),
        description: "Node identity binding vectors (R1-001). node_id_input_hex is the \
exact SHA-256 preimage; node_id_hex = SHA-256(node_id_input_hex). identity_wire_hex is \
the NodeIdentity map; file_wire_hex is the durable identity file (seed is TEST-ONLY, \
never use for production). signature_hex is the deterministic RFC 8032 detached \
signature over payload_hex with the given seed."
            .into(),
        cases,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn vectors_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(VECTORS_DIR).join(name)
}

#[test]
fn vectors_conformance() {
    let cbor_file: CborVectorsFile = serde_json::from_str(
        &std::fs::read_to_string(vectors_path("cbor_vectors.json"))
            .expect("cbor_vectors.json must exist (run the regenerate test if missing)"),
    )
    .expect("cbor_vectors.json parses");
    assert_eq!(cbor_file.profile, "sharenet-canonical-cbor-v1");

    for case in &cbor_file.roundtrip {
        let bytes = from_hex(&case.hex);
        let v = decode(&bytes)
            .unwrap_or_else(|e| panic!("roundtrip case {} failed to decode: {e}", case.hex));
        let expected: Value = (&case.value).into();
        assert_eq!(v, expected, "value mismatch for {}", case.hex);
        let re = encode(&v).unwrap();
        assert_eq!(re, bytes, "byte-stability for {}", case.hex);
        let v2 = decode(&re).unwrap();
        assert_eq!(v2, v);
    }
    assert!(
        cbor_file.roundtrip.len() >= 40,
        "expected a substantial roundtrip set"
    );

    for case in &cbor_file.reject {
        let bytes = from_hex(&case.hex);
        let err = match decode(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("reject case {} was accepted", case.hex),
        };
        assert_eq!(
            err.name(),
            case.error,
            "wrong error name for {} (got {}, want {})",
            case.hex,
            err.name(),
            case.error
        );
    }
    assert!(
        cbor_file.reject.len() >= 40,
        "expected a substantial reject set"
    );

    let id_file: IdentityVectorsFile = serde_json::from_str(
        &std::fs::read_to_string(vectors_path("identity_vectors.json"))
            .expect("identity_vectors.json must exist"),
    )
    .expect("identity_vectors.json parses");
    assert_eq!(id_file.scheme, "sharenet-node-identity-v1");
    for case in &id_file.cases {
        let seed: [u8; SEED_LEN] = from_hex(&case.seed_hex).try_into().expect("seed len");
        let id =
            Identity::from_seed(seed, case.created_at_unix, case.display_name.clone()).unwrap();

        // Public key derivation.
        assert_eq!(
            common_hex(&id.node_identity().public_key_bytes()),
            case.public_key_hex
        );

        // node_id: preimage bytes and hash recomputed independently.
        let preimage = from_hex(&case.node_id_input_hex);
        let preimage_value =
            decode(&preimage).unwrap_or_else(|e| panic!("node_id preimage must decode: {e}"));
        match &preimage_value {
            Value::Map(entries) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0].0, Value::Int(1));
                assert_eq!(entries[0].1, Value::Int(SCHEME_VERSION));
                assert_eq!(entries[1].0, Value::Int(2));
                assert_eq!(
                    entries[1].1,
                    Value::Bytes(id.node_identity().public_key_bytes().to_vec())
                );
            }
            other => panic!("node_id preimage must be a map, got {other:?}"),
        }
        let recomputed = sharenet_protocol::identity::derive_node_id(
            SCHEME_VERSION,
            &id.node_identity().public_key_bytes(),
        );
        assert_eq!(common_hex(recomputed.as_bytes()), case.node_id_hex);

        // Wire forms.
        let wire = encode(&id.node_identity().to_wire()).unwrap();
        assert_eq!(common_hex(&wire), case.identity_wire_hex);
        let parsed = NodeIdentity::from_wire(&decode(&wire).unwrap()).unwrap();
        assert_eq!(parsed.node_id(), id.node_id());

        // File form round-trips through the strict store parser.
        let file_wire = from_hex(&case.file_wire_hex);
        let tmp = common::TempDir::new("vectors-file");
        let file_path = tmp.join("identity.cbor");
        common::write_file(&file_path, &file_wire);
        #[cfg(unix)]
        common::set_mode(&file_path, 0o600);
        let loaded = load_identity_file(&file_path)
            .unwrap_or_else(|e| panic!("file_wire must load strictly: {e}"));
        assert_eq!(loaded.node_id(), id.node_id());
        assert_eq!(
            loaded.node_identity().display_name(),
            case.display_name.as_deref()
        );

        // Signature.
        let payload = from_hex(&case.payload_hex);
        let sig = id.sign_detached(&payload);
        assert_eq!(sig.len(), SIGNATURE_LEN);
        assert_eq!(common_hex(&sig), case.signature_hex);
        assert!(id.node_identity().verify_detached(&payload, &sig).is_ok());
    }
    assert!(id_file.cases.len() >= 5);
}

#[test]
#[ignore = "regenerates tests/vectors/*.json; run explicitly after intentional changes"]
fn regenerate_vectors() {
    std::fs::create_dir_all(VECTORS_DIR).expect("create vectors dir");
    let cbor_json = serde_json::to_string_pretty(&cbor_vectors()).unwrap() + "\n";
    std::fs::write(vectors_path("cbor_vectors.json"), cbor_json).expect("write cbor vectors");
    let id_json = serde_json::to_string_pretty(&identity_vectors()).unwrap() + "\n";
    std::fs::write(vectors_path("identity_vectors.json"), id_json).expect("write identity vectors");
    eprintln!("vectors regenerated under {VECTORS_DIR}");
}

#[test]
fn jvalue_json_roundtrip_is_lossless() {
    // The JSON value model itself must round-trip (guards the vector format).
    let samples: Vec<Value> = vec![
        Value::Int(-42),
        Value::Bytes(vec![0, 1, 254, 255]),
        Value::Text("水 \\ \" text".into()),
        Value::Array(vec![Value::Bool(true), Value::Null]),
        Value::Map(vec![
            (Value::Int(1), Value::Text("a".into())),
            (Value::Text("k".into()), Value::Array(vec![])),
        ]),
    ];
    for v in samples {
        let j: JValue = (&v).into();
        let json = serde_json::to_string(&j).unwrap();
        let back: JValue = serde_json::from_str(&json).unwrap();
        let v2: Value = (&back).into();
        assert_eq!(v, v2);
    }
}

#[test]
fn store_api_smoke_via_tempdir() {
    // One more end-to-end pass over the public store API (also used by the CLI).
    let tmp = common::TempDir::new("store-smoke");
    let store = IdentityStore::new(tmp.path());
    let id = store.load_or_create(Some("smoke")).unwrap();
    let again = store.load_or_create(None).unwrap();
    assert_eq!(id.node_id(), again.node_id());
    let sig = again.sign_detached(b"smoke");
    assert!(store
        .load()
        .unwrap()
        .node_identity()
        .verify_detached(b"smoke", &sig)
        .is_ok());
}
