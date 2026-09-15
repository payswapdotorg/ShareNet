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
struct AdvertisementVectorsFile {
    scheme: String,
    description: String,
    cases: Vec<AdCase>,
    receive: Vec<AdReceiveCase>,
    parse_reject: Vec<AdReject>,
}

#[derive(Serialize, Deserialize)]
struct AdCase {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    seed_hex: String,
    created_at_unix: u64,
    /// optional capability envelope bytes carried in the advertisement
    capabilities_hex: Option<String>,
    transports: Vec<AdTransport>,
    issued_at_unix: u64,
    validity_secs: u64,
    advertisement_wire_hex: String,
    signature_hex: String,
    advertisement_id_hex: String,
    envelope_hex: String,
}

#[derive(Serialize, Deserialize)]
struct AdTransport {
    kind: String,
    endpoint: String,
}

#[derive(Serialize, Deserialize)]
struct AdReceiveCase {
    case: usize,
    now_unix: u64,
    /// "discovered" | "duplicate" | "stale" or the error name
    expect: String,
}

#[derive(Serialize, Deserialize)]
struct AdReject {
    hex: String,
    error: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct LinkVectorsFile {
    scheme: String,
    description: String,
    cases: Vec<LinkCase>,
    frames: Vec<LinkFrameCase>,
}

#[derive(Serialize, Deserialize)]
struct LinkCase {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    initiator_seed_hex: String,
    responder_seed_hex: String,
    initiator_created_at_unix: u64,
    responder_created_at_unix: u64,
    /// X25519 ephemeral scalar (clamped internally per RFC 7748).
    initiator_scalar_hex: String,
    responder_scalar_hex: String,
    msg1_hex: String,
    msg2_hex: String,
    msg3_hex: String,
    shared_secret_hex: String,
    link_id_hex: String,
    key_i2r_hex: String,
    key_r2i_hex: String,
}

#[derive(Serialize, Deserialize)]
struct LinkFrameCase {
    case: usize,
    /// 1 = initiator->responder, 2 = responder->initiator.
    direction: u8,
    seq: u64,
    payload_hex: String,
    frame_hex: String,
}

#[derive(Serialize, Deserialize)]
struct TopologyVectorsFile {
    scheme: String,
    description: String,
    cases: Vec<TopoCase>,
    receive: Vec<TopoReceive>,
    parse_reject: Vec<TopoReject>,
}

#[derive(Serialize, Deserialize)]
struct TopoCase {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    seed_hex: String,
    created_at_unix: u64,
    subject_node_id_hex: String,
    /// "link" or "advertisement"
    kind: String,
    /// link fields (kind = link)
    link_id_hex: Option<String>,
    established_at_unix: Option<u64>,
    quality: Option<JQuality>,
    /// advertisement fields (kind = advertisement)
    advertisement_id_hex: Option<String>,
    capabilities: Option<Vec<String>>,
    observed_at_unix: u64,
    validity_secs: u64,
    evidence_wire_hex: String,
    signature_hex: String,
    evidence_id_hex: String,
    envelope_hex: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct JQuality {
    delivered: u64,
    lost: u64,
    ewma_rtt_micros: u64,
    p50_rtt_micros: u64,
    p95_rtt_micros: u64,
    jitter_mad_micros: u64,
    loss_ratio_ppm: u64,
}

#[derive(Serialize, Deserialize)]
struct TopoReceive {
    case: usize,
    now_unix: u64,
    expect: String,
}

#[derive(Serialize, Deserialize)]
struct TopoReject {
    hex: String,
    error: String,
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
// Link vectors (R3-001)
// ---------------------------------------------------------------------------

fn link_vectors() -> LinkVectorsFile {
    use sharenet_protocol::link::{
        LinkInitiator, LinkResponder, LinkSession,
    };
    let mk = |seed_hex: &str, created: u64| -> Identity {
        let seed: [u8; SEED_LEN] = from_hex(seed_hex).try_into().expect("seed len");
        Identity::from_seed(seed, created, None).unwrap()
    };
    // (note, init seed, resp seed, init created, resp created, i-scalar, r-scalar)
    let cases_in: Vec<(&str, &str, &str, u64, u64, &str, &str)> = vec![
        (
            "identity-vector seeds, simple fixed scalars",
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            0,
            1_700_000_000,
            "1010101010101010101010101010101010101010101010101010101010101010",
            "2020202020202020202020202020202020202020202020202020202020202020",
        ),
        (
            "second seed pair, all-0x33/0x44 scalars",
            "c5aa8df43f9f837bedb7472f960be3677c5a0e5e140718b32a6903607a8a0573",
            "f67e23f4c2f7b0e6b1d54d1e8a3c9b0f6e2d4c5b8a7f6e5d4c3b2a1908f7e6d5",
            86_400,
            42,
            "3333333333333333333333333333333333333333333333333333333333333333",
            "4444444444444444444444444444444444444444444444444444444444444444",
        ),
        (
            "with a capability envelope carried by the responder",
            "8d3d3a3a9b9b7c7c6d6d5e5e4f4f303021212222323434555667778899aabbcc",
            "26924a9b5e6e6c6c7d7d4f4f303021212222323434555667778899aabbccddee",
            1_754_000_000,
            1_754_000_001,
            "5555555555555555555555555555555555555555555555555555555555555555",
            "6666666666666666666666666666666666666666666666666666666666666666",
        ),
    ];
    let mut cases = Vec::new();
    let mut envelopes: Vec<Option<Vec<u8>>> = Vec::new();
    for (note, iseed, rseed, icreated, rcreated, iscalar, rscalar) in &cases_in {
        let initiator_identity = mk(iseed, *icreated);
        let responder_identity = mk(rseed, *rcreated);
        let envelope = if note.contains("capability envelope") {
            let st = sharenet_protocol::capability::CapabilityStatement::new(
                responder_identity.node_id(),
                &[sharenet_protocol::capability::Capability::Gateway],
                1_700_000_000,
                1_700_086_400,
                None,
            )
            .unwrap();
            Some(st.sign(&responder_identity).unwrap().to_envelope_bytes())
        } else {
            None
        };
        envelopes.push(envelope.clone());
        let initiator = LinkInitiator::from_ephemeral_bytes(
            &from_hex(iscalar).try_into().unwrap(),
            initiator_identity,
            None,
        )
        .unwrap();
        let responder = LinkResponder::new(responder_identity, envelope);
        let msg1 = initiator.initiate();
        let msg1_bytes = msg1.to_wire_bytes();
        let (msg2, pending) = responder
            .respond_fixed(&msg1, &msg1_bytes, &from_hex(rscalar).try_into().unwrap())
            .unwrap();
        let msg2_bytes = msg2.to_wire_bytes();
        let (msg3, _session_i) = initiator.confirm(&msg1_bytes, &msg2, &msg2_bytes).unwrap();
        let msg3_bytes = msg3.to_wire_bytes();
        let _session_r = pending
            .finish(&msg1_bytes, &msg2_bytes, &msg3, &msg3_bytes)
            .unwrap();
        // recompute derivations via a fresh handshake to expose the session keys
        let initiator2 = LinkInitiator::from_ephemeral_bytes(
            &from_hex(iscalar).try_into().unwrap(),
            mk(iseed, *icreated),
            None,
        )
        .unwrap();
        let responder2 = LinkResponder::new(mk(rseed, *rcreated), envelopes.last().cloned().flatten());
        let m1 = initiator2.initiate();
        let m1b = m1.to_wire_bytes();
        let (m2, _p2) = responder2
            .respond_fixed(&m1, &m1b, &from_hex(rscalar).try_into().unwrap())
            .unwrap();
        let m2b = m2.to_wire_bytes();
        let (_m3, session) = initiator2.confirm(&m1b, &m2, &m2b).unwrap();
        cases.push(LinkCase {
            note: Some(note.to_string()),
            initiator_seed_hex: iseed.to_string(),
            responder_seed_hex: rseed.to_string(),
            initiator_created_at_unix: *icreated,
            responder_created_at_unix: *rcreated,
            initiator_scalar_hex: iscalar.to_string(),
            responder_scalar_hex: rscalar.to_string(),
            msg1_hex: common_hex(&msg1_bytes),
            msg2_hex: common_hex(&msg2_bytes),
            msg3_hex: common_hex(&msg3_bytes),
            shared_secret_hex: String::new(), // filled below via a shim
            link_id_hex: session.link_id().iter().map(|b| format!("{b:02x}")).collect(),
            key_i2r_hex: String::new(),
            key_r2i_hex: String::new(),
        });
    }
    // The session keys are private by design; the vector pins them through
    // the FRAME cases (a frame is a deterministic function of key+link_id+
    // direction+seq+payload). We do not export raw session keys.
    let mut frames = Vec::new();
    {
        // rebuild case 0 sessions to produce frames in both directions
        let a = mk(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            0,
        );
        let b = mk(
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            1_700_000_000,
        );
        let initiator = LinkInitiator::from_ephemeral_bytes(
            &from_hex("1010101010101010101010101010101010101010101010101010101010101010")
                .try_into()
                .unwrap(),
            a,
            None,
        )
        .unwrap();
        let responder = LinkResponder::new(b, None);
        let m1 = initiator.initiate();
        let m1b = m1.to_wire_bytes();
        let (m2, pending) = responder
            .respond_fixed(
                &m1,
                &m1b,
                &from_hex("2020202020202020202020202020202020202020202020202020202020202020")
                    .try_into()
                    .unwrap(),
            )
            .unwrap();
        let m2b = m2.to_wire_bytes();
        let (m3, mut si) = initiator.confirm(&m1b, &m2, &m2b).unwrap();
        let m3b = m3.to_wire_bytes();
        let mut sr = pending.finish(&m1b, &m2b, &m3, &m3b).unwrap();
        let payloads: [(&[u8], u8); 3] = [(b"hello", 1u8), (b"", 1u8), (b"welcome to sharenet", 2u8)];
        let mut seq_i = 0u64;
        let mut seq_r = 0u64;
        for (payload, direction) in payloads {
            if direction == 1 {
                let f = si.seal(payload).unwrap();
                frames.push(LinkFrameCase {
                    case: 0,
                    direction: 1,
                    seq: seq_i,
                    payload_hex: common_hex(payload),
                    frame_hex: common_hex(&f),
                });
                seq_i += 1;
            } else {
                let f = sr.seal(payload).unwrap();
                frames.push(LinkFrameCase {
                    case: 0,
                    direction: 2,
                    seq: seq_r,
                    payload_hex: common_hex(payload),
                    frame_hex: common_hex(&f),
                });
                seq_r += 1;
            }
        }
    }
    LinkVectorsFile {
        scheme: "sharenet-link-v1".into(),
        description: "Authenticated link handshake vectors (R3-001). For every case the \
harness MUST: rebuild both identities from seeds+created_at, run the full 3-message \
handshake with the fixed X25519 scalars, reproduce msg1/msg2/msg3 byte-exactly, \
derive the same link_id, and reproduce every frame byte-exactly from the derived \
session keys (frames pin key_i2r/key_r2i without exporting them). Scalars are \
TEST-ONLY.".into(),
        cases,
        frames,
    }
}

// ---------------------------------------------------------------------------
// Advertisement vectors (R3-002)
// ---------------------------------------------------------------------------

fn advertisement_vectors() -> AdvertisementVectorsFile {
    use sharenet_protocol::advertisement::{
        Advertisement as Ad, DiscoveryCache, DiscoveryOutcome, SignedAdvertisement,
        TransportDescriptor as T,
    };
    let mk = |seed_hex: &str, created: u64| -> Identity {
        let seed: [u8; SEED_LEN] = from_hex(seed_hex).try_into().expect("seed len");
        Identity::from_seed(seed, created, None).unwrap()
    };
    let cases_in: Vec<(&str, &str, u64, Option<Vec<(&str, i64)>>, Vec<(&str, &str)>, u64, u64)> = vec![
        (
            "single udp endpoint, no capabilities",
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            0,
            None,
            vec![("udp", "192.168.1.10:7000")],
            1_700_000_000,
            120,
        ),
        (
            "multi-transport with capability envelope, scrambled input order",
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            1_700_000_000,
            Some(vec![("max_backhaul_mbps", 50)]),
            vec![
                ("quic", "gw.example.net:443"),
                ("udp", "10.1.2.3:7000"),
                ("udp", "10.1.2.4:7000"),
            ],
            1_700_000_500,
            300,
        ),
        (
            "wifi_aware + nearby, max window",
            "c5aa8df43f9f837bedb7472f960be3677c5a0e5e140718b32a6903607a8a0573",
            42,
            None,
            vec![("nearby", "cluster-alpha"), ("wifi_aware", "aware-1")],
            1,
            600,
        ),
    ];
    let mut cases = Vec::new();
    for (note, seed_hex, created, caps_limits, transports, issued, validity) in &cases_in {
        let id = mk(seed_hex, *created);
        let capabilities = caps_limits.as_ref().map(|limits| {
            let mut m = std::collections::BTreeMap::new();
            for (k, v) in limits {
                m.insert(k.to_string(), *v);
            }
            let st = sharenet_protocol::capability::CapabilityStatement::new(
                id.node_id(),
                &[sharenet_protocol::capability::Capability::Gateway],
                1_700_000_000,
                1_700_086_400,
                Some(m),
            )
            .unwrap();
            st.sign(&id).unwrap().to_envelope_bytes()
        });
        let tds: Vec<T> = transports
            .iter()
            .map(|(k, e)| T {
                kind: k.to_string(),
                endpoint: e.to_string(),
            })
            .collect();
        let ad = Ad::new(&id, capabilities.clone(), tds, *issued, *validity).unwrap();
        let signed = ad.sign(&id).unwrap();
        cases.push(AdCase {
            note: Some(note.to_string()),
            seed_hex: seed_hex.to_string(),
            created_at_unix: *created,
            capabilities_hex: capabilities.map(|c| common_hex(&c)),
            transports: transports
                .iter()
                .map(|(k, e)| AdTransport {
                    kind: k.to_string(),
                    endpoint: e.to_string(),
                })
                .collect(),
            issued_at_unix: *issued,
            validity_secs: *validity,
            advertisement_wire_hex: common_hex(signed.advertisement_bytes()),
            signature_hex: common_hex(signed.signature()),
            advertisement_id_hex: common_hex(&signed.advertisement_id()),
            envelope_hex: common_hex(&signed.to_envelope_bytes()),
        });
    }
    // receive outcomes (freshness + dedup)
    let receive = vec![
        AdReceiveCase {
            case: 0,
            now_unix: 1_700_000_060,
            expect: "discovered".into(),
        },
        AdReceiveCase {
            case: 0,
            now_unix: 1_700_000_061,
            expect: "duplicate".into(),
        },
        AdReceiveCase {
            case: 0,
            now_unix: 1_700_000_120,
            expect: "expired".into(),
        },
        AdReceiveCase {
            case: 0,
            now_unix: 1_699_999_999,
            expect: "not_yet_valid".into(),
        },
        AdReceiveCase {
            case: 1,
            now_unix: 1_700_000_600,
            expect: "discovered".into(),
        },
        AdReceiveCase {
            case: 2,
            now_unix: 300,
            expect: "discovered".into(),
        },
    ];
    // typed parse rejections
    let good_id_hex = {
        let id = mk(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            0,
        );
        common_hex(id.node_id().as_bytes())
    };
    let rej = |hex: String, error: &str, note: &str| AdReject {
        hex,
        error: error.to_string(),
        note: Some(note.to_string()),
    };
    let mut parse_reject = Vec::new();
    {
        // unknown transport kind
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (
                Value::Int(2),
                mk("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", 0)
                    .node_identity()
                    .to_wire(),
            ),
            (
                Value::Int(4),
                Value::Array(vec![Value::Map(vec![
                    (Value::Int(1), Value::Text("bluetooth".into())),
                    (Value::Int(2), Value::Text("00:11:22:33:44:55".into())),
                ])]),
            ),
            (Value::Int(5), Value::Int(1)),
            (Value::Int(6), Value::Int(60)),
        ]);
        parse_reject.push(rej(
            common_hex(&encode(&v).unwrap()),
            "transport_kind_unknown",
            "only the frozen v1 kind set is valid",
        ));
        // unsorted transports
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (
                Value::Int(2),
                mk("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", 0)
                    .node_identity()
                    .to_wire(),
            ),
            (
                Value::Int(4),
                Value::Array(vec![
                    Value::Map(vec![
                        (Value::Int(1), Value::Text("udp".into())),
                        (Value::Int(2), Value::Text("10.0.0.2:1".into())),
                    ]),
                    Value::Map(vec![
                        (Value::Int(1), Value::Text("udp".into())),
                        (Value::Int(2), Value::Text("10.0.0.1:1".into())),
                    ]),
                ]),
            ),
            (Value::Int(5), Value::Int(1)),
            (Value::Int(6), Value::Int(60)),
        ]);
        parse_reject.push(rej(
            common_hex(&encode(&v).unwrap()),
            "transports_not_sorted",
            "canonical order is strictly ascending by (kind, endpoint)",
        ));
        // window too long
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (
                Value::Int(2),
                mk("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", 0)
                    .node_identity()
                    .to_wire(),
            ),
            (
                Value::Int(4),
                Value::Array(vec![Value::Map(vec![
                    (Value::Int(1), Value::Text("udp".into())),
                    (Value::Int(2), Value::Text("10.0.0.1:1".into())),
                ])]),
            ),
            (Value::Int(5), Value::Int(1)),
            (Value::Int(6), Value::Int(601 + 1)),
        ]);
        parse_reject.push(rej(
            common_hex(&encode(&v).unwrap()),
            "window_invalid",
            "validity window must be <= 600s",
        ));
        // empty transports
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (
                Value::Int(2),
                mk("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", 0)
                    .node_identity()
                    .to_wire(),
            ),
            (Value::Int(4), Value::Array(vec![])),
            (Value::Int(5), Value::Int(1)),
            (Value::Int(6), Value::Int(60)),
        ]);
        parse_reject.push(rej(
            common_hex(&encode(&v).unwrap()),
            "transports_empty",
            "an advertisement with no transports is meaningless",
        ));
        // missing expires_at
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (
                Value::Int(2),
                mk("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", 0)
                    .node_identity()
                    .to_wire(),
            ),
            (
                Value::Int(4),
                Value::Array(vec![Value::Map(vec![
                    (Value::Int(1), Value::Text("udp".into())),
                    (Value::Int(2), Value::Text("10.0.0.1:1".into())),
                ])]),
            ),
            (Value::Int(5), Value::Int(1)),
        ]);
        parse_reject.push(rej(
            common_hex(&encode(&v).unwrap()),
            "missing_field",
            "expires_at is required",
        ));
        let _ = good_id_hex;
    }
    AdvertisementVectorsFile {
        scheme: "sharenet-advertisement-v1".into(),
        description: "Advertisement/discovery vectors (R3-002). For every case the harness \
MUST: rebuild the announcer identity from seed+created_at, rebuild the \
advertisement (canonical transport order), re-derive the wire bytes and \
signature byte-exactly, and re-derive advertisement_id = SHA-256(wire). \
receive[] cases run the full receiver verification pipeline and expect the \
named outcome. parse_reject[] bytes MUST fail with the named typed error.".into(),
        cases,
        receive,
        parse_reject,
    }
}

// ---------------------------------------------------------------------------
// Topology vectors (R3-003)
// ---------------------------------------------------------------------------

fn topology_vectors() -> TopologyVectorsFile {
    use sharenet_protocol::topology::{
        LinkQualitySnapshot, Observation, TopologyEvidence as TE,
    };
    let mk = |seed_hex: &str, created: u64| -> Identity {
        let seed: [u8; SEED_LEN] = from_hex(seed_hex).try_into().expect("seed len");
        Identity::from_seed(seed, created, None).unwrap()
    };
    let quality = JQuality {
        delivered: 200,
        lost: 3,
        ewma_rtt_micros: 1_500,
        p50_rtt_micros: 1_400,
        p95_rtt_micros: 2_100,
        jitter_mad_micros: 120,
        loss_ratio_ppm: 15_000,
    };
    let observer_seeds: [(&str, u64); 2] = [
        ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", 0),
        ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", 1_700_000_000),
    ];
    let subject = mk("c5aa8df43f9f837bedb7472f960be3677c5a0e5e140718b32a6903607a8a0573", 42);
    let subject_hex = common_hex(subject.node_id().as_bytes());
    let mut cases = Vec::new();
    // case 0: link evidence
    {
        let (seed_hex, created) = observer_seeds[0];
        let obs = mk(seed_hex, created);
        let ev = TE::new(
            &obs,
            *subject.node_id().as_bytes(),
            Observation::Link {
                link_id: [0xAB; 32],
                established_at_unix: 999,
                quality: LinkQualitySnapshot {
                    delivered: quality.delivered,
                    lost: quality.lost,
                    ewma_rtt_micros: quality.ewma_rtt_micros,
                    p50_rtt_micros: quality.p50_rtt_micros,
                    p95_rtt_micros: quality.p95_rtt_micros,
                    jitter_mad_micros: quality.jitter_mad_micros,
                    loss_ratio_ppm: quality.loss_ratio_ppm,
                },
            },
            1_000,
            300,
        )
        .unwrap();
        let signed = ev.sign(&obs).unwrap();
        cases.push(TopoCase {
            note: Some("link evidence with quality snapshot".into()),
            seed_hex: seed_hex.to_string(),
            created_at_unix: created,
            subject_node_id_hex: subject_hex.clone(),
            kind: "link".into(),
            link_id_hex: Some(common_hex(&[0xAB; 32])),
            established_at_unix: Some(999),
            quality: Some(quality.clone()),
            advertisement_id_hex: None,
            capabilities: None,
            observed_at_unix: 1_000,
            validity_secs: 300,
            evidence_wire_hex: common_hex(signed.evidence_bytes()),
            signature_hex: common_hex(signed.signature()),
            evidence_id_hex: common_hex(&signed.evidence_id()),
            envelope_hex: common_hex(&signed.to_envelope_bytes()),
        });
    }
    // case 1: advertisement evidence (empty capability set)
    {
        let (seed_hex, created) = observer_seeds[1];
        let obs = mk(seed_hex, created);
        let ev = TE::new(
            &obs,
            *subject.node_id().as_bytes(),
            Observation::Advertisement {
                advertisement_id: [0xCD; 32],
                capabilities: vec![],
            },
            2_000,
            120,
        )
        .unwrap();
        let signed = ev.sign(&obs).unwrap();
        cases.push(TopoCase {
            note: Some("advertisement evidence, no capabilities observed".into()),
            seed_hex: seed_hex.to_string(),
            created_at_unix: created,
            subject_node_id_hex: subject_hex.clone(),
            kind: "advertisement".into(),
            link_id_hex: None,
            established_at_unix: None,
            quality: None,
            advertisement_id_hex: Some(common_hex(&[0xCD; 32])),
            capabilities: Some(vec![]),
            observed_at_unix: 2_000,
            validity_secs: 120,
            evidence_wire_hex: common_hex(signed.evidence_bytes()),
            signature_hex: common_hex(signed.signature()),
            evidence_id_hex: common_hex(&signed.evidence_id()),
            envelope_hex: common_hex(&signed.to_envelope_bytes()),
        });
    }
    // case 2: advertisement evidence with observed capabilities (sorted)
    {
        let (seed_hex, created) = observer_seeds[0];
        let obs = mk(seed_hex, created);
        let ev = TE::new(
            &obs,
            *subject.node_id().as_bytes(),
            Observation::Advertisement {
                advertisement_id: [0xEF; 32],
                capabilities: vec!["dtn_custodian".into(), "gateway".into()],
            },
            3_000,
            60,
        )
        .unwrap();
        let signed = ev.sign(&obs).unwrap();
        cases.push(TopoCase {
            note: Some("advertisement evidence with sorted capabilities".into()),
            seed_hex: seed_hex.to_string(),
            created_at_unix: created,
            subject_node_id_hex: subject_hex.clone(),
            kind: "advertisement".into(),
            link_id_hex: None,
            established_at_unix: None,
            quality: None,
            advertisement_id_hex: Some(common_hex(&[0xEF; 32])),
            capabilities: Some(vec!["dtn_custodian".into(), "gateway".into()]),
            observed_at_unix: 3_000,
            validity_secs: 60,
            evidence_wire_hex: common_hex(signed.evidence_bytes()),
            signature_hex: common_hex(signed.signature()),
            evidence_id_hex: common_hex(&signed.evidence_id()),
            envelope_hex: common_hex(&signed.to_envelope_bytes()),
        });
    }
    let receive = vec![
        TopoReceive {
            case: 0,
            now_unix: 1_100,
            expect: "collected".into(),
        },
        TopoReceive {
            case: 0,
            now_unix: 1_301,
            expect: "expired".into(),
        },
        TopoReceive {
            case: 1,
            now_unix: 2_050,
            expect: "collected".into(),
        },
        TopoReceive {
            case: 2,
            now_unix: 2_999,
            expect: "not_yet_valid".into(),
        },
    ];
    // parse rejects
    let mut parse_reject = Vec::new();
    {
        let subj = mk(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            0,
        );
        let subj_wire = subj.node_identity().to_wire();
        // self-attestation (subject == observer)
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), subj_wire.clone()),
            (Value::Int(3), Value::Bytes(subj.node_id().as_bytes().to_vec())),
            (Value::Int(4), Value::Text("link".into())),
            (Value::Int(5), Value::Int(1_000)),
            (Value::Int(6), Value::Int(1_060)),
            (
                Value::Int(7),
                Value::Map(vec![
                    (Value::Int(1), Value::Bytes(vec![1u8; 32])),
                    (Value::Int(2), Value::Int(990)),
                    (Value::Int(3), Value::Int(1)),
                    (Value::Int(4), Value::Int(0)),
                    (Value::Int(5), Value::Int(1)),
                    (Value::Int(6), Value::Int(1)),
                    (Value::Int(7), Value::Int(1)),
                    (Value::Int(8), Value::Int(1)),
                    (Value::Int(9), Value::Int(0)),
                ]),
            ),
        ]);
        parse_reject.push(TopoReject {
            hex: common_hex(&encode(&v).unwrap()),
            error: "subject_is_observer".into(),
        });
        // unknown kind
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), subj_wire.clone()),
            (Value::Int(3), Value::Bytes(vec![9u8; 32])),
            (Value::Int(4), Value::Text("gossip".into())),
            (Value::Int(5), Value::Int(1_000)),
            (Value::Int(6), Value::Int(1_060)),
            (Value::Int(7), Value::Map(vec![])),
        ]);
        parse_reject.push(TopoReject {
            hex: common_hex(&encode(&v).unwrap()),
            error: "kind_unknown".into(),
        });
        // window too long
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), subj_wire.clone()),
            (Value::Int(3), Value::Bytes(vec![9u8; 32])),
            (Value::Int(4), Value::Text("advertisement".into())),
            (Value::Int(5), Value::Int(1_000)),
            (Value::Int(6), Value::Int(1_000 + 3601)),
            (
                Value::Int(7),
                Value::Map(vec![
                    (Value::Int(1), Value::Bytes(vec![2u8; 32])),
                    (Value::Int(2), Value::Array(vec![])),
                ]),
            ),
        ]);
        parse_reject.push(TopoReject {
            hex: common_hex(&encode(&v).unwrap()),
            error: "window_invalid".into(),
        });
        // p95 < p50
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), subj_wire.clone()),
            (Value::Int(3), Value::Bytes(vec![9u8; 32])),
            (Value::Int(4), Value::Text("link".into())),
            (Value::Int(5), Value::Int(1_000)),
            (Value::Int(6), Value::Int(1_060)),
            (
                Value::Int(7),
                Value::Map(vec![
                    (Value::Int(1), Value::Bytes(vec![1u8; 32])),
                    (Value::Int(2), Value::Int(990)),
                    (Value::Int(3), Value::Int(1)),
                    (Value::Int(4), Value::Int(0)),
                    (Value::Int(5), Value::Int(1)),
                    (Value::Int(6), Value::Int(200)),
                    (Value::Int(7), Value::Int(100)),
                    (Value::Int(8), Value::Int(1)),
                    (Value::Int(9), Value::Int(0)),
                ]),
            ),
        ]);
        parse_reject.push(TopoReject {
            hex: common_hex(&encode(&v).unwrap()),
            error: "percentiles_unordered".into(),
        });
        // unsorted capabilities
        let v = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), subj_wire),
            (Value::Int(3), Value::Bytes(vec![9u8; 32])),
            (Value::Int(4), Value::Text("advertisement".into())),
            (Value::Int(5), Value::Int(1_000)),
            (Value::Int(6), Value::Int(1_060)),
            (
                Value::Int(7),
                Value::Map(vec![
                    (Value::Int(1), Value::Bytes(vec![2u8; 32])),
                    (
                        Value::Int(2),
                        Value::Array(vec![
                            Value::Text("gateway".into()),
                            Value::Text("dtn_custodian".into()),
                        ]),
                    ),
                ]),
            ),
        ]);
        parse_reject.push(TopoReject {
            hex: common_hex(&encode(&v).unwrap()),
            error: "capabilities_not_sorted".into(),
        });
    }
    TopologyVectorsFile {
        scheme: "sharenet-topology-evidence-v1".into(),
        description: "Topology evidence vectors (R3-003). For every case the harness MUST: \
rebuild the observer identity from seed+created_at, rebuild the evidence \
record from the fields, re-derive wire bytes + signature + evidence_id \
byte-exactly. receive[] cases run the full collector pipeline and expect \
the named outcome. parse_reject[] bytes MUST fail with the named typed \
error.".into(),
        cases,
        receive,
        parse_reject,
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

    // ---- link vectors ----
    let link_file: LinkVectorsFile = serde_json::from_str(
        &std::fs::read_to_string(vectors_path("link_vectors.json"))
            .expect("link_vectors.json must exist"),
    )
    .expect("link_vectors.json parses");
    assert_eq!(link_file.scheme, "sharenet-link-v1");
    use sharenet_protocol::link::{LinkInitiator, LinkResponder};
    let mk_link_id = |c: &LinkCase| {
        let a = {
            let seed: [u8; SEED_LEN] = from_hex(&c.initiator_seed_hex).try_into().expect("seed");
            Identity::from_seed(seed, c.initiator_created_at_unix, None).unwrap()
        };
        let b = {
            let seed: [u8; SEED_LEN] = from_hex(&c.responder_seed_hex).try_into().expect("seed");
            Identity::from_seed(seed, c.responder_created_at_unix, None).unwrap()
        };
        let envelope = if c.note.as_deref().is_some_and(|n| n.contains("capability envelope")) {
            let st = sharenet_protocol::capability::CapabilityStatement::new(
                b.node_id(),
                &[sharenet_protocol::capability::Capability::Gateway],
                1_700_000_000,
                1_700_086_400,
                None,
            )
            .unwrap();
            Some(st.sign(&b).unwrap().to_envelope_bytes())
        } else {
            None
        };
        let initiator = LinkInitiator::from_ephemeral_bytes(
            &from_hex(&c.initiator_scalar_hex).try_into().unwrap(),
            a,
            None,
        )
        .unwrap();
        let responder = LinkResponder::new(b, envelope);
        let msg1 = initiator.initiate();
        let msg1_bytes = msg1.to_wire_bytes();
        assert_eq!(common_hex(&msg1_bytes), c.msg1_hex, "msg1 mismatch");
        let (msg2, pending) = responder
            .respond_fixed(&msg1, &msg1_bytes, &from_hex(&c.responder_scalar_hex).try_into().unwrap())
            .unwrap();
        let msg2_bytes = msg2.to_wire_bytes();
        assert_eq!(common_hex(&msg2_bytes), c.msg2_hex, "msg2 mismatch");
        let (msg3, session_i) = initiator.confirm(&msg1_bytes, &msg2, &msg2_bytes).unwrap();
        let msg3_bytes = msg3.to_wire_bytes();
        assert_eq!(common_hex(&msg3_bytes), c.msg3_hex, "msg3 mismatch");
        let session_r = pending
            .finish(&msg1_bytes, &msg2_bytes, &msg3, &msg3_bytes)
            .unwrap();
        assert_eq!(session_i.link_id(), session_r.link_id());
        let link_id_hex: String = session_i.link_id().iter().map(|b| format!("{b:02x}")).collect();
        (link_id_hex, session_i, session_r)
    };
    let mut sessions: Vec<(String, sharenet_protocol::link::LinkSession, sharenet_protocol::link::LinkSession)> =
        Vec::new();
    for c in &link_file.cases {
        let (link_id_hex, si, sr) = mk_link_id(c);
        assert_eq!(link_id_hex, c.link_id_hex, "link_id mismatch");
        sessions.push((link_id_hex, si, sr));
    }
    for f in &link_file.frames {
        let entry = &mut sessions[f.case];
        let (si, sr) = (&mut entry.1, &mut entry.2);
        let payload = from_hex(&f.payload_hex);
        let frame = if f.direction == 1 {
            si.seal(&payload).unwrap()
        } else {
            sr.seal(&payload).unwrap()
        };
        assert_eq!(
            common_hex(&frame),
            f.frame_hex,
            "frame mismatch (case {}, dir {}, seq {})",
            f.case,
            f.direction,
            f.seq
        );
    }

    // ---- advertisement vectors ----
    let ad_file: AdvertisementVectorsFile = serde_json::from_str(
        &std::fs::read_to_string(vectors_path("advertisement_vectors.json"))
            .expect("advertisement_vectors.json must exist"),
    )
    .expect("advertisement_vectors.json parses");
    assert_eq!(ad_file.scheme, "sharenet-advertisement-v1");
    use sharenet_protocol::advertisement::{
        Advertisement as Ad, DiscoveryCache, DiscoveryOutcome, SignedAdvertisement,
        TransportDescriptor as T,
    };
    for (i, c) in ad_file.cases.iter().enumerate() {
        let seed: [u8; SEED_LEN] = from_hex(&c.seed_hex).try_into().expect("seed len");
        let id = Identity::from_seed(seed, c.created_at_unix, None).unwrap();
        let capabilities = c.capabilities_hex.as_ref().map(|h| from_hex(h));
        let tds: Vec<T> = c
            .transports
            .iter()
            .map(|t| T {
                kind: t.kind.clone(),
                endpoint: t.endpoint.clone(),
            })
            .collect();
        let ad = Ad::new(&id, capabilities, tds, c.issued_at_unix, c.validity_secs)
            .unwrap_or_else(|e| panic!("case {i} must build: {e}"));
        assert_eq!(
            common_hex(&ad.to_wire_bytes()),
            c.advertisement_wire_hex,
            "wire mismatch in case {i}"
        );
        let signed = ad.sign(&id).unwrap();
        assert_eq!(common_hex(signed.signature()), c.signature_hex, "case {i}");
        assert_eq!(common_hex(&signed.advertisement_id()), c.advertisement_id_hex, "case {i}");
        assert_eq!(common_hex(&signed.to_envelope_bytes()), c.envelope_hex, "case {i}");
    }
    // receive pipeline: one persistent cache per vector CASE (dedup
    // expectations require state across receive entries of the same case)
    let mut caches: std::collections::HashMap<usize, DiscoveryCache> =
        std::collections::HashMap::new();
    for (i, r) in ad_file.receive.iter().enumerate() {
        let c = &ad_file.cases[r.case];
        let signed = SignedAdvertisement::from_envelope_bytes(&from_hex(&c.envelope_hex)).unwrap();
        let cache = caches.entry(r.case).or_insert_with(DiscoveryCache::new);
        let outcome = match cache.receive(&signed, r.now_unix) {
            Ok(DiscoveryOutcome::Discovered) => "discovered".to_string(),
            Ok(DiscoveryOutcome::Duplicate) => "duplicate".to_string(),
            Ok(DiscoveryOutcome::Stale) => "stale".to_string(),
            Err(e) => e.name(),
        };
        assert_eq!(outcome, r.expect, "receive case {i} (case {})", r.case);
    }
    for r in &ad_file.parse_reject {
        let bytes = from_hex(&r.hex);
        let err = match Ad::from_wire_bytes(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("advertisement parse_reject {} was accepted", r.hex),
        };
        assert_eq!(err.name(), r.error, "parse_reject {}", r.hex);
    }

    // ---- topology evidence vectors ----
    let topo_file: TopologyVectorsFile = serde_json::from_str(
        &std::fs::read_to_string(vectors_path("topology_vectors.json"))
            .expect("topology_vectors.json must exist"),
    )
    .expect("topology_vectors.json parses");
    assert_eq!(topo_file.scheme, "sharenet-topology-evidence-v1");
    use sharenet_protocol::topology::{
        LinkQualitySnapshot, Observation, ReceiveOutcome, SignedTopologyEvidence,
        TopologyEvidence as TE, TopologyStore,
    };
    for (i, c) in topo_file.cases.iter().enumerate() {
        let seed: [u8; SEED_LEN] = from_hex(&c.seed_hex).try_into().expect("seed len");
        let obs = Identity::from_seed(seed, c.created_at_unix, None).unwrap();
        let subject: [u8; 32] = from_hex(&c.subject_node_id_hex)
            .try_into()
            .expect("subject len");
        let observation = match c.kind.as_str() {
            "link" => Observation::Link {
                link_id: from_hex(c.link_id_hex.as_deref().unwrap()).try_into().unwrap(),
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
        let ev = TE::new(&obs, subject, observation, c.observed_at_unix, c.validity_secs)
            .unwrap_or_else(|e| panic!("topo case {i} must build: {e}"));
        assert_eq!(
            common_hex(&ev.to_wire_bytes()),
            c.evidence_wire_hex,
            "wire mismatch in topo case {i}"
        );
        let signed = ev.sign(&obs).unwrap();
        assert_eq!(common_hex(signed.signature()), c.signature_hex, "topo {i}");
        assert_eq!(common_hex(&signed.evidence_id()), c.evidence_id_hex, "topo {i}");
        assert_eq!(common_hex(&signed.to_envelope_bytes()), c.envelope_hex, "topo {i}");
    }
    {
        let mut stores: std::collections::HashMap<usize, TopologyStore> =
            std::collections::HashMap::new();
        for (i, r) in topo_file.receive.iter().enumerate() {
            let c = &topo_file.cases[r.case];
            let signed =
                SignedTopologyEvidence::from_envelope_bytes(&from_hex(&c.envelope_hex)).unwrap();
            let store = stores.entry(r.case).or_insert_with(TopologyStore::new);
            let outcome = match store.receive(&signed, r.now_unix) {
                Ok(ReceiveOutcome::Collected) => "collected".to_string(),
                Ok(ReceiveOutcome::Stale) => "stale".to_string(),
                Err(e) => e.name(),
            };
            assert_eq!(outcome, r.expect, "topo receive {i}");
        }
    }
    for r in &topo_file.parse_reject {
        let bytes = from_hex(&r.hex);
        let err = match TE::from_wire_bytes(&bytes) {
            Err(e) => e,
            Ok(_) => panic!("topo parse_reject {} was accepted", r.hex),
        };
        assert_eq!(err.name(), r.error, "topo parse_reject {}", r.hex);
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
    let link_json = serde_json::to_string_pretty(&link_vectors()).unwrap() + "\n";
    std::fs::write(vectors_path("link_vectors.json"), link_json).expect("write link vectors");
    let ad_json = serde_json::to_string_pretty(&advertisement_vectors()).unwrap() + "\n";
    std::fs::write(vectors_path("advertisement_vectors.json"), ad_json)
        .expect("write advertisement vectors");
    let topo_json = serde_json::to_string_pretty(&topology_vectors()).unwrap() + "\n";
    std::fs::write(vectors_path("topology_vectors.json"), topo_json)
        .expect("write topology vectors");
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
