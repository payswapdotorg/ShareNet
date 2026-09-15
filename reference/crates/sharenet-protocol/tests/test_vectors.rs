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
use sharenet_protocol::capability::{
    Capability, CapabilityStatement, SignedCapabilityStatement,
};
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
struct CapabilityVectorsFile {
    scheme: String,
    signature_rule: String,
    admission_rule: String,
    description: String,
    cases: Vec<CapabilityCase>,
    admit: Vec<AdmitCase>,
    parse_reject: Vec<CapabilityReject>,
}

#[derive(Serialize, Deserialize)]
struct CapabilityCase {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    seed_hex: String,
    public_key_hex: String,
    node_id_hex: String,
    capabilities: Vec<String>,
    issued_at_unix: u64,
    expires_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    limits: Option<std::collections::BTreeMap<String, i64>>,
    statement_wire_hex: String,
    signature_hex: String,
}

#[derive(Serialize, Deserialize)]
struct AdmitCase {
    case: usize,
    now_unix: u64,
    require: Vec<String>,
    /// "ok" or the stable AdmissionError name.
    expect: String,
    /// Which key performs verification: absent = the case's own key;
    /// "next" = the next case's key (the node_id_mismatch scenario).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    verify_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct CapabilityReject {
    hex: String,
    error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

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

fn capability_vectors() -> CapabilityVectorsFile {
    use sharenet_protocol::capability::Capability as Cap;
    let cap_text = |c: Cap| c.wire_text().to_string();
    // (seed byte pattern, capabilities, issued, expires, limits, note)
    let cases_in: Vec<(
        &str,
        Vec<Cap>,
        u64,
        u64,
        Option<Vec<(&str, i64)>>,
        &str,
    )> = vec![
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bcc8e0e6b9b0d",
            Capability::ALL.to_vec(),
            1_700_000_000,
            1_700_086_400,
            None,
            "all four capabilities, one-day window, no limits",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            vec![Cap::Gateway],
            1_700_000_000,
            1_700_003_600,
            Some(vec![("max_backhaul_mbps", 100), ("max_sessions", 4)]),
            "single capability with numeric limits",
        ),
        (
            "c5aa8df43f9f837bedb7472f960be3677c5a0e5e140718b32a6903607a8a0573",
            vec![Cap::DtnCustodian, Cap::Infrastructure],
            42,
            86_400,
            Some(vec![("dtn_storage_mb", -1)]),
            "early-epoch timestamps and a negative limit value (profile permits ints)",
        ),
        (
            "f67e23f4c2f7b0e6b1d54d1e8a3c9b0f6e2d4c5b8a7f6e5d4c3b2a1908f7e6d5",
            vec![Cap::Relay],
            0,
            1,
            None,
            "minimum one-second validity window at the epoch floor",
        ),
        (
            "8d3d3a3a9b9b7c7c6d6d5e5e4f4f303021212222323434555667778899aabbcc",
            vec![Cap::Infrastructure, Cap::Relay, Cap::Gateway, Cap::DtnCustodian],
            1_754_000_000,
            1_755_000_000,
            Some(vec![("a", 1), ("b", 2), ("c", 3), ("d", 4), ("e", 5)]),
            "scrambled input order canonicalizes; multiple sorted limit keys",
        ),
    ];
    let mut cases = Vec::new();
    for (seed_hex, caps, issued, expires, limits, note) in cases_in {
        let seed: [u8; SEED_LEN] = from_hex(seed_hex).try_into().expect("seed length");
        let id = Identity::from_seed(seed, 0, None).unwrap();
        let limits_map = limits.map(|kv| {
            kv.into_iter().map(|(k, v)| (k.to_string(), v)).collect()
        });
        let st = CapabilityStatement::new(
            id.node_id(),
            &caps,
            issued,
            expires,
            limits_map,
        )
        .unwrap();
        let signed = st.sign(&id).unwrap();
        cases.push(CapabilityCase {
            note: Some(note.to_string()),
            seed_hex: seed_hex.to_string(),
            public_key_hex: common_hex(&id.node_identity().public_key_bytes()),
            node_id_hex: id.node_id().to_hex(),
            capabilities: caps.iter().map(|&c| cap_text(c)).collect(),
            issued_at_unix: issued,
            expires_at_unix: expires,
            limits: st.limits().cloned(),
            statement_wire_hex: common_hex(signed.statement_bytes()),
            signature_hex: common_hex(signed.signature()),
        });
    }

    // Admission outcomes over the cases above (indices refer to `cases`).
    let admit = vec![
        AdmitCase {
            case: 0,
            now_unix: 1_700_040_000,
            require: vec!["gateway".into()],
            expect: "ok".into(),
            verify_key: None,
            note: Some("valid window, capability held".into()),
        },
        AdmitCase {
            case: 0,
            now_unix: 1_700_086_400,
            require: vec![],
            expect: "expired".into(),
            verify_key: None,
            note: Some("now == expires_at is expired (exclusive bound)".into()),
        },
        AdmitCase {
            case: 0,
            now_unix: 1_699_999_999,
            require: vec![],
            expect: "not_yet_valid".into(),
            verify_key: None,
            note: Some("now < issued_at".into()),
        },
        AdmitCase {
            case: 0,
            now_unix: 1_700_040_000,
            require: vec![],
            expect: "node_id_mismatch".into(),
            verify_key: Some("next".into()),
            note: Some("verify with a DIFFERENT key than the case's seed derives".into()),
        },
        AdmitCase {
            case: 1,
            now_unix: 1_700_001_800,
            require: vec!["relay".into()],
            expect: "capability_not_held".into(),
            verify_key: None,
            note: Some("gateway-only statement cannot admit relay".into()),
        },
        AdmitCase {
            case: 1,
            now_unix: 1_700_001_800,
            require: vec!["gateway".into(), "infrastructure".into()],
            expect: "capability_not_held".into(),
            verify_key: None,
            note: Some("multi-require fails if ANY capability is missing".into()),
        },
        AdmitCase {
            case: 2,
            now_unix: 100,
            require: vec!["dtn_custodian".into()],
            expect: "ok".into(),
            verify_key: None,
            note: Some("multi-capability lookup with dtn_custodian held".into()),
        },
        AdmitCase {
            case: 3,
            now_unix: 0,
            require: vec![],
            expect: "ok".into(),
            verify_key: None,
            note: Some("window opens exactly at the epoch floor".into()),
        },
        AdmitCase {
            case: 3,
            now_unix: 1,
            require: vec![],
            expect: "expired".into(),
            verify_key: None,
            note: Some("one-second window closes exactly at 1".into()),
        },
        AdmitCase {
            case: 4,
            now_unix: 1_754_500_000,
            require: vec!["infrastructure".into()],
            expect: "ok".into(),
            verify_key: None,
            note: Some("canonicalized order admits any held capability".into()),
        },
    ];

    // Typed parse rejections (statement bytes that must fail from_wire_bytes).
    let good = &cases[1]; // gateway + limits template
    let good_bytes = from_hex(&good.statement_wire_hex);
    let rej = |hex: String, error: &str, note: &str| CapabilityReject {
        hex,
        error: error.to_string(),
        note: Some(note.to_string()),
    };
    let mut parse_reject = Vec::new();
    {
        // unsorted capabilities array: swap [dtn_custodian, gateway] -> [gateway, dtn_custodian]
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Bytes(from_hex(&good.node_id_hex))),
            (
                Value::Int(3),
                Value::Array(vec![
                    Value::Text("gateway".into()),
                    Value::Text("dtn_custodian".into()),
                ]),
            ),
            (Value::Int(4), Value::Int(1)),
            (Value::Int(5), Value::Int(2)),
        ]);
        parse_reject.push(rej(
            common_hex(&encode(&v).unwrap()),
            "capabilities_not_sorted",
            "array must be strictly ascending by wire text",
        ));
        // unknown capability text
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Bytes(from_hex(&good.node_id_hex))),
            (
                Value::Int(3),
                Value::Array(vec![Value::Text("superuser".into())]),
            ),
            (Value::Int(4), Value::Int(1)),
            (Value::Int(5), Value::Int(2)),
        ]);
        parse_reject.push(rej(
            common_hex(&encode(&v).unwrap()),
            "unknown_capability",
            "only the frozen initial set is valid in v1",
        ));
        // empty capabilities array
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Bytes(from_hex(&good.node_id_hex))),
            (Value::Int(3), Value::Array(vec![])),
            (Value::Int(4), Value::Int(1)),
            (Value::Int(5), Value::Int(2)),
        ]);
        parse_reject.push(rej(
            common_hex(&encode(&v).unwrap()),
            "capabilities_empty",
            "a statement claiming nothing is meaningless and rejected",
        ));
        // expiry not after issue (parse-side enforcement)
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Bytes(from_hex(&good.node_id_hex))),
            (
                Value::Int(3),
                Value::Array(vec![Value::Text("gateway".into())]),
            ),
            (Value::Int(4), Value::Int(10)),
            (Value::Int(5), Value::Int(10)),
        ]);
        parse_reject.push(rej(
            common_hex(&encode(&v).unwrap()),
            "expiry_not_after_issue",
            "zero-length validity window is rejected",
        ));
        // missing required field (no key 5)
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Bytes(from_hex(&good.node_id_hex))),
            (
                Value::Int(3),
                Value::Array(vec![Value::Text("gateway".into())]),
            ),
            (Value::Int(4), Value::Int(1)),
        ]);
        parse_reject.push(rej(
            common_hex(&encode(&v).unwrap()),
            "missing_field",
            "expires_at is required",
        ));
        // wrong scheme version
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(2)),
            (Value::Int(2), Value::Bytes(from_hex(&good.node_id_hex))),
            (
                Value::Int(3),
                Value::Array(vec![Value::Text("gateway".into())]),
            ),
            (Value::Int(4), Value::Int(1)),
            (Value::Int(5), Value::Int(2)),
        ]);
        parse_reject.push(rej(
            common_hex(&encode(&v).unwrap()),
            "scheme_version_unsupported",
            "v2 statements are not v1",
        ));
        // limits with too many entries (33 > 32)
        let mut entries = vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Bytes(from_hex(&good.node_id_hex))),
            (
                Value::Int(3),
                Value::Array(vec![Value::Text("gateway".into())]),
            ),
            (Value::Int(4), Value::Int(1)),
            (Value::Int(5), Value::Int(2)),
        ];
        let mut limits = Vec::new();
        for i in 0..33 {
            limits.push((
                Value::Text(format!("k{i:02}")),
                Value::Int(i as i64),
            ));
        }
        entries.push((Value::Int(6), Value::Map(limits)));
        parse_reject.push(rej(
            common_hex(&encode(&Value::Map(entries)).unwrap()),
            "limits_too_many_entries",
            "adversarial size bound",
        ));
        // non-minimal integer in the wire (profile-level violation surfaced
        // through the statement parser): rebuild `good` with 0x18 0x01 for field 1
        let mut bad = Vec::with_capacity(good_bytes.len() + 1);
        bad.extend_from_slice(&good_bytes[..2]);
        bad.extend_from_slice(&[0x18, 0x01]);
        bad.extend_from_slice(&good_bytes[3..]);
        parse_reject.push(rej(
            common_hex(&bad),
            "cbor:NonMinimalInteger",
            "non-canonical integer rejected by the CBOR profile before parse",
        ));
    }

    CapabilityVectorsFile {
        scheme: "sharenet-capability-statement-v1".into(),
        signature_rule: "signature_hex is the RFC 8032 deterministic detached Ed25519 \
signature over statement_wire_hex (the exact canonical CBOR bytes of the statement map) \
produced from seed_hex; carrying envelope = canonical CBOR {1: statement bstr, \
2: signature bstr}".into(),
        admission_rule: "admission = strict parse + node_id binding \
(node_id = SHA-256(canonical_cbor({1: scheme_version, 2: public_key}))) + strict Ed25519 \
verification over statement_wire_hex + (issued_at <= now < expires_at) + capability \
lookup; no caller-controlled trust booleans".into(),
        description: "Signed capability statement vectors (R1-004). For every case \
the harness MUST: derive the public key from seed_hex, derive node_id and compare \
node_id_hex, rebuild the statement map from the fields, encode it canonically and \
compare statement_wire_hex byte-exactly, and reproduce signature_hex byte-exactly. \
admit[] cases run full admission and expect the named outcome (for node_id_mismatch \
the harness verifies with a DIFFERENT valid key, e.g. the seed of the next case). \
parse_reject[] bytes MUST fail CapabilityStatement parsing with the named typed error.".into(),
        cases,
        admit,
        parse_reject,
    }
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

    // ---- capability vectors ----
    let cap_file: CapabilityVectorsFile = serde_json::from_str(
        &std::fs::read_to_string(vectors_path("capability_vectors.json"))
            .expect("capability_vectors.json must exist"),
    )
    .expect("capability_vectors.json parses");
    assert_eq!(cap_file.scheme, "sharenet-capability-statement-v1");
    use sharenet_protocol::capability::{admit, AdmissionError, Capability as Cap};
    let parse_cap = |t: &str| -> Cap {
        match t {
            "gateway" => Cap::Gateway,
            "relay" => Cap::Relay,
            "dtn_custodian" => Cap::DtnCustodian,
            "infrastructure" => Cap::Infrastructure,
            other => panic!("bad capability text in vectors: {other}"),
        }
    };
    for (i, case) in cap_file.cases.iter().enumerate() {
        let seed: [u8; SEED_LEN] = from_hex(&case.seed_hex).try_into().expect("seed len");
        let id = Identity::from_seed(seed, 0, None).unwrap();
        assert_eq!(
            common_hex(&id.node_identity().public_key_bytes()),
            case.public_key_hex,
            "public key mismatch in case {i}"
        );
        assert_eq!(id.node_id().to_hex(), case.node_id_hex, "case {i}");
        let caps: Vec<Cap> = case.capabilities.iter().map(|t| parse_cap(t)).collect();
        let st = CapabilityStatement::new(
            id.node_id(),
            &caps,
            case.issued_at_unix,
            case.expires_at_unix,
            case.limits.clone(),
        )
        .unwrap_or_else(|e| panic!("case {i} must build: {e}"));
        assert_eq!(
            common_hex(&st.to_wire_bytes()),
            case.statement_wire_hex,
            "wire bytes mismatch in case {i}"
        );
        let signed = st.sign(&id).unwrap();
        assert_eq!(
            common_hex(signed.signature()),
            case.signature_hex,
            "signature mismatch in case {i}"
        );
    }
    for a in &cap_file.admit {
        let case = &cap_file.cases[a.case];
        let seed: [u8; SEED_LEN] = from_hex(&case.seed_hex).try_into().expect("seed len");
        let id = Identity::from_seed(seed, 0, None).unwrap();
        // For the node_id_mismatch expectation, verify under a DIFFERENT key
        // (deterministically: the key of the case after this one, wrapping).
        let other = if a.expect == "node_id_mismatch" {
            let o = &cap_file.cases[(a.case + 1) % cap_file.cases.len()];
            let oseed: [u8; SEED_LEN] = from_hex(&o.seed_hex).try_into().expect("seed len");
            Identity::from_seed(oseed, 0, None).unwrap()
        } else {
            id.clone()
        };
        let require: Vec<Cap> = a.require.iter().map(|t| parse_cap(t)).collect();
        let mut sig = from_hex(&case.signature_hex);
        if a.expect == "signature_encoding_invalid" {
            sig.truncate(63);
        }
        let result = admit(
            &from_hex(&case.statement_wire_hex),
            &sig,
            &other.node_identity().public_key_bytes(),
            a.now_unix,
            &require,
        );
        let name = match &result {
            Ok(_) => "ok".to_string(),
            Err(e) => e.name(),
        };
        assert_eq!(
            name, a.expect,
            "admit case {} (vector case {}) expected {} got {}",
            a.now_unix, a.case, a.expect, name
        );
    }
    for r in &cap_file.parse_reject {
        let bytes = from_hex(&r.hex);
        let err = match CapabilityStatement::from_wire_bytes(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("parse_reject case {} was accepted", r.hex),
        };
        assert_eq!(
            err.name(),
            r.error,
            "wrong error name for parse_reject {}",
            r.hex
        );
    }
}

#[test]
#[ignore = "regenerates tests/vectors/*.json; run explicitly after intentional changes"]
fn regenerate_vectors() {
    std::fs::create_dir_all(VECTORS_DIR).expect("create vectors dir");
    let cbor_json = serde_json::to_string_pretty(&cbor_vectors()).unwrap() + "\n";
    std::fs::write(vectors_path("cbor_vectors.json"), cbor_json).expect("write cbor vectors");
    let id_json = serde_json::to_string_pretty(&identity_vectors()).unwrap() + "\n";
    std::fs::write(vectors_path("identity_vectors.json"), id_json).expect("write identity vectors");
    let cap_json = serde_json::to_string_pretty(&capability_vectors()).unwrap() + "\n";
    std::fs::write(vectors_path("capability_vectors.json"), cap_json)
        .expect("write capability vectors");
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
