//! Conformance tests for the ShareNet Canonical CBOR Profile v1 (R1-002):
//!
//! - RFC 8949 core deterministic encoding examples (canonical subset);
//! - golden vectors from `tests/vectors/cbor_vectors.json` (byte-for-byte);
//! - deterministic pseudo-random property tests (round-trip, byte-stability,
//!   truncation resistance, fuzz resistance, mutation byte-stability);
//! - a sync test proving the committed vectors file matches the Rust source
//!   of truth (regenerate with `cargo test -- --ignored regenerate_cbor_vectors`).

#![forbid(unsafe_code)]

use serde_json::json;
use sharenet_protocol::cbor::{self, decode, encode, MapBuilder, Value};
use sharenet_protocol::hex;

// ---------------------------------------------------------------------------
// RFC 8949-derived conformance vectors (core deterministic encoding)
// ---------------------------------------------------------------------------

/// Canonical examples from RFC 8949 (IETF RFC 8949, §3.1 and §4.2.1).
/// Only canonical (in-profile) encodings are included; the RFC's
/// non-canonical illustration examples are tested as rejections in
/// `cbor_reject.rs`.
#[test]
fn rfc8949_canonical_vectors_round_trip_byte_stable() {
    let cases: Vec<(Value, &str)> = vec![
        (Value::Int(0), "00"),
        (Value::Int(1), "01"),
        (Value::Int(10), "0a"),
        (Value::Int(23), "17"),
        (Value::Int(24), "1818"),
        (Value::Int(25), "1819"),
        (Value::Int(100), "1864"),
        (Value::Int(1000), "1903e8"),
        (Value::Int(1000000), "1a000f4240"),
        (Value::Int(1000000000000), "1b000000e8d4a51000"),
        (Value::Int(255), "18ff"),
        (Value::Int(256), "190100"),
        (Value::Int(-1), "20"),
        (Value::Int(-10), "29"),
        (Value::Int(-100), "3863"),
        (Value::Int(-1000), "3903e7"),
        (Value::Int(-24), "37"),
        (Value::Int(-25), "3818"),
        (Value::Bool(false), "f4"),
        (Value::Bool(true), "f5"),
        (Value::Null, "f6"),
        (Value::Text("".into()), "60"),
        (Value::Text("a".into()), "6161"),
        (Value::Text("IETF".into()), "6449455446"),
        (Value::Text("ü".into()), "62c3bc"),
        (Value::Bytes(vec![]), "40"),
        (Value::Bytes(vec![0x01, 0x02, 0x03, 0x04]), "4401020304"),
        (Value::Array(vec![]), "80"),
        (Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]), "83010203"),
        (
            Value::Array(vec![
                Value::Int(1),
                Value::Array(vec![Value::Int(2), Value::Int(3)]),
                Value::Array(vec![Value::Int(4), Value::Int(5)]),
            ]),
            "8301820203820405",
        ),
        (
            Value::Array(vec![Value::Array(vec![]), Value::Array(vec![Value::Array(vec![])])]),
            "82808180",
        ),
        (
            Value::Array(vec![Value::Int(23), Value::Text("a".into()), Value::Bytes(vec![0xf0])]),
            "8317616141f0",
        ),
        (Value::Map(vec![]), "a0"),
        (
            Value::Map(vec![(Value::Int(1), Value::Int(2)), (Value::Int(3), Value::Int(4))]),
            "a201020304",
        ),
        (
            Value::Map(vec![
                (Value::Text("a".into()), Value::Int(1)),
                (Value::Text("b".into()), Value::Array(vec![Value::Int(2), Value::Int(3)])),
            ]),
            "a26161016162820203",
        ),
        // RFC 8949 "fun with integers" boundary values (derived).
        (Value::Int(4294967295), "1affffffff"),
        (Value::Int(4294967296), "1b0000000100000000"),
        (Value::Int(i64::MAX), "1b7fffffffffffffff"),
        (Value::Int(i64::MIN), "3b7fffffffffffffff"),
    ];

    for (value, hex_str) in cases {
        let expected = hex::decode(hex_str).unwrap();
        // Round-trip and byte-stability (the strictness law).
        let encoded = encode(&value).unwrap();
        assert_eq!(
            hex::encode(&encoded),
            hex_str,
            "encode({value:?}) must equal the canonical bytes"
        );
        let decoded = decode(&expected).unwrap();
        assert_eq!(decoded, value, "decode of {hex_str}");
        assert_eq!(
            encode(&decoded).unwrap(),
            expected,
            "byte-stability for {hex_str}"
        );
    }
}

// ---------------------------------------------------------------------------
// Golden vectors (tests/vectors/cbor_vectors.json)
// ---------------------------------------------------------------------------

/// Tagged-JSON encoding of the CBOR value model used by the vectors file
/// (consumed by the future R1-003 cross-language harness).
fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Int(i) => json!({"t": "int", "v": i}),
        Value::Bytes(b) => json!({"t": "bytes", "v": hex::encode(b)}),
        Value::Text(s) => json!({"t": "text", "v": s}),
        Value::Array(items) => json!({
            "t": "array",
            "v": items.iter().map(value_to_json).collect::<Vec<_>>(),
        }),
        Value::Map(entries) => json!({
            "t": "map",
            "v": entries
                .iter()
                .map(|(k, val)| json!([value_to_json(k), value_to_json(val)]))
                .collect::<Vec<_>>(),
        }),
        Value::Bool(b) => json!({"t": "bool", "v": b}),
        Value::Null => json!({"t": "null"}),
    }
}

fn json_to_value(j: &serde_json::Value) -> Value {
    let obj = j.as_object().expect("tagged value must be an object");
    let t = obj.get("t").and_then(|t| t.as_str()).expect("tagged value must have \"t\"");
    match t {
        "int" => Value::Int(
            obj.get("v")
                .and_then(|v| v.as_i64())
                .expect("int value must be an i64"),
        ),
        "bytes" => Value::Bytes(
            hex::decode(obj.get("v").and_then(|v| v.as_str()).expect("bytes value must be hex"))
                .expect("bytes hex must be valid"),
        ),
        "text" => Value::Text(
            obj.get("v")
                .and_then(|v| v.as_str())
                .expect("text value must be a string")
                .to_string(),
        ),
        "array" => Value::Array(
            obj.get("v")
                .and_then(|v| v.as_array())
                .expect("array value must be a list")
                .iter()
                .map(json_to_value)
                .collect(),
        ),
        "map" => {
            let pairs = obj.get("v").and_then(|v| v.as_array()).expect("map value must be a list");
            let mut entries = Vec::new();
            for pair in pairs {
                let kv = pair.as_array().expect("map entry must be [key, value]");
                assert_eq!(kv.len(), 2, "map entry must have exactly two elements");
                entries.push((json_to_value(&kv[0]), json_to_value(&kv[1])));
            }
            cbor::canonicalize_map(entries).expect("map keys in vectors must be unique")
        }
        "bool" => Value::Bool(
            obj.get("v")
                .and_then(|v| v.as_bool())
                .expect("bool value must be a boolean"),
        ),
        "null" => Value::Null,
        other => panic!("unknown value tag {other}"),
    }
}

fn error_kind(e: &cbor::DecodeError) -> &'static str {
    use cbor::DecodeError::*;
    match e {
        EmptyInput => "EmptyInput",
        UnexpectedEnd { .. } => "UnexpectedEnd",
        NonMinimalInteger { .. } => "NonMinimalInteger",
        IndefiniteLength { .. } => "IndefiniteLength",
        BreakCode { .. } => "BreakCode",
        ReservedAdditionalInfo { .. } => "ReservedAdditionalInfo",
        TagForbidden { .. } => "TagForbidden",
        FloatForbidden { .. } => "FloatForbidden",
        SimpleValueForbidden { .. } => "SimpleValueForbidden",
        InvalidUtf8 { .. } => "InvalidUtf8",
        UnsortedMapKeys { .. } => "UnsortedMapKeys",
        DuplicateMapKey { .. } => "DuplicateMapKey",
        IntegerOutOfRange { .. } => "IntegerOutOfRange",
        IntegerNegativeOutOfRange { .. } => "IntegerNegativeOutOfRange",
        DepthLimitExceeded { .. } => "DepthLimitExceeded",
        LengthExceedsInput { .. } => "LengthExceedsInput",
        TrailingBytes { .. } => "TrailingBytes",
    }
}

struct EncodeCase {
    name: &'static str,
    value: Value,
    hex: String,
}

struct RejectCase {
    name: &'static str,
    hex: &'static str,
    error: &'static str,
}

/// Source of truth for the committed golden vectors.
fn encode_cases() -> Vec<EncodeCase> {
    vec![
        EncodeCase { name: "int-zero", value: Value::Int(0), hex: "00".into() },
        EncodeCase { name: "int-23", value: Value::Int(23), hex: "17".into() },
        EncodeCase { name: "int-24", value: Value::Int(24), hex: "1818".into() },
        EncodeCase { name: "int-255", value: Value::Int(255), hex: "18ff".into() },
        EncodeCase { name: "int-256", value: Value::Int(256), hex: "190100".into() },
        EncodeCase { name: "int-65535", value: Value::Int(65535), hex: "19ffff".into() },
        EncodeCase { name: "int-65536", value: Value::Int(65536), hex: "1a00010000".into() },
        EncodeCase {
            name: "int-i64-max",
            value: Value::Int(i64::MAX),
            hex: "1b7fffffffffffffff".into(),
        },
        EncodeCase { name: "int-minus-1", value: Value::Int(-1), hex: "20".into() },
        EncodeCase { name: "int-minus-24", value: Value::Int(-24), hex: "37".into() },
        EncodeCase { name: "int-minus-25", value: Value::Int(-25), hex: "3818".into() },
        EncodeCase {
            name: "int-i64-min",
            value: Value::Int(i64::MIN),
            hex: "3b7fffffffffffffff".into(),
        },
        EncodeCase { name: "bool-false", value: Value::Bool(false), hex: "f4".into() },
        EncodeCase { name: "bool-true", value: Value::Bool(true), hex: "f5".into() },
        EncodeCase { name: "null", value: Value::Null, hex: "f6".into() },
        EncodeCase { name: "bytes-empty", value: Value::Bytes(vec![]), hex: "40".into() },
        EncodeCase {
            name: "bytes-01020304",
            value: Value::Bytes(vec![1, 2, 3, 4]),
            hex: "4401020304".into(),
        },
        EncodeCase {
            name: "bytes-32",
            value: Value::Bytes(vec![0xAB; 32]),
            hex: format!("5820{}", "ab".repeat(32)),
        },
        EncodeCase {
            name: "bytes-300",
            value: Value::Bytes(vec![0x5A; 300]),
            hex: format!("59{:04x}{}", 300, "5a".repeat(300)),
        },
        EncodeCase { name: "text-empty", value: Value::Text("".into()), hex: "60".into() },
        EncodeCase { name: "text-a", value: Value::Text("a".into()), hex: "6161".into() },
        EncodeCase { name: "text-ietf", value: Value::Text("IETF".into()), hex: "6449455446".into() },
        EncodeCase {
            name: "text-utf8-multibyte",
            value: Value::Text("ShareNet 中文 🌍".into()),
            // 20 UTF-8 bytes ("ShareNet" + " " + 中 + 文 + " " + 🌍).
            hex: "7453686172654e657420e4b8ade6968720f09f8c8d".into(),
        },
        EncodeCase { name: "array-empty", value: Value::Array(vec![]), hex: "80".into() },
        EncodeCase {
            name: "array-123",
            value: Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]),
            hex: "83010203".into(),
        },
        EncodeCase {
            name: "array-nested",
            value: Value::Array(vec![
                Value::Int(1),
                Value::Array(vec![Value::Int(2), Value::Int(3)]),
                Value::Array(vec![Value::Int(4), Value::Int(5)]),
            ]),
            hex: "8301820203820405".into(),
        },
        EncodeCase {
            name: "array-mixed",
            value: Value::Array(vec![
                Value::Int(23),
                Value::Text("a".into()),
                Value::Bytes(vec![0xf0]),
                Value::Bool(true),
                Value::Null,
            ]),
            hex: "8517616141f0f5f6".into(),
        },
        EncodeCase { name: "map-empty", value: Value::Map(vec![]), hex: "a0".into() },
        EncodeCase {
            name: "map-int-keys",
            value: MapBuilder::new()
                .insert_int(1, Value::Int(2))
                .insert_int(3, Value::Int(4))
                .build()
                .unwrap(),
            hex: "a201020304".into(),
        },
        EncodeCase {
            name: "map-text-keys",
            value: MapBuilder::new()
                .insert_text("a", Value::Int(1))
                .insert_text("b", Value::Array(vec![Value::Int(2), Value::Int(3)]))
                .build()
                .unwrap(),
            hex: "a26161016162820203".into(),
        },
        EncodeCase {
            name: "map-length-prefix-sorts-first",
            // enc("b") = 61 62 sorts before enc("ab") = 62 61 62 because the
            // length prefix is part of the canonical key encoding.
            value: MapBuilder::new()
                .insert_text("b", Value::Int(2))
                .insert_text("ab", Value::Int(1))
                .build()
                .unwrap(),
            hex: "a261620262616201".into(),
        },
        EncodeCase {
            name: "map-int-negative-key-sorts-after-zero",
            // enc(0) = 00 sorts before enc(-1) = 20.
            value: MapBuilder::new()
                .insert_int(-1, Value::Text("minus".into()))
                .insert_int(0, Value::Text("zero".into()))
                .build()
                .unwrap(),
            hex: "a200647a65726f20656d696e7573".into(),
        },
        EncodeCase {
            name: "nodeidentity-like-shape",
            value: MapBuilder::new()
                .insert_int(1, Value::Int(1))
                .insert_int(2, Value::Bytes(vec![0x42; 32]))
                .insert_int(3, Value::Int(1700000000))
                .build()
                .unwrap(),
            hex: format!("a30101025820{}031a6553f100", "42".repeat(32)),
        },
    ]
}

fn reject_cases() -> Vec<RejectCase> {
    vec![
        RejectCase { name: "non-minimal-int-0", hex: "1800", error: "NonMinimalInteger" },
        RejectCase { name: "non-minimal-int-23", hex: "1817", error: "NonMinimalInteger" },
        RejectCase { name: "non-minimal-int-24-uint16", hex: "190018", error: "NonMinimalInteger" },
        RejectCase { name: "non-minimal-int-255-uint16", hex: "1900ff", error: "NonMinimalInteger" },
        RejectCase { name: "non-minimal-neg-1", hex: "3800", error: "NonMinimalInteger" },
        RejectCase { name: "non-minimal-bstr-length", hex: "5803414244", error: "NonMinimalInteger" },
        RejectCase { name: "indefinite-int", hex: "1f", error: "IndefiniteLength" },
        RejectCase { name: "indefinite-bstr", hex: "5fff", error: "IndefiniteLength" },
        RejectCase { name: "indefinite-text", hex: "7f6161ff", error: "IndefiniteLength" },
        RejectCase { name: "indefinite-array", hex: "9f01ff", error: "IndefiniteLength" },
        RejectCase { name: "indefinite-map", hex: "bf0161afff", error: "IndefiniteLength" },
        RejectCase { name: "break-code", hex: "ff", error: "BreakCode" },
        RejectCase { name: "unsorted-map-keys", hex: "a203040102", error: "UnsortedMapKeys" },
        RejectCase { name: "duplicate-map-keys", hex: "a201020103", error: "DuplicateMapKey" },
        RejectCase { name: "tag-0", hex: "c000", error: "TagForbidden" },
        RejectCase { name: "tag-1-epoch", hex: "c11a514b67b0", error: "TagForbidden" },
        RejectCase { name: "tag-2-bignum", hex: "c2420100", error: "TagForbidden" },
        RejectCase { name: "tag-3-negbigint", hex: "c349010000000000000000", error: "TagForbidden" },
        RejectCase { name: "float-f16-zero", hex: "f90000", error: "FloatForbidden" },
        RejectCase { name: "float-f16-nan", hex: "f97e00", error: "FloatForbidden" },
        RejectCase { name: "float-f16-inf", hex: "f97c00", error: "FloatForbidden" },
        RejectCase { name: "float-f32", hex: "fa47c35000", error: "FloatForbidden" },
        RejectCase { name: "float-f64", hex: "fb3ff0000000000000", error: "FloatForbidden" },
        RejectCase { name: "undefined", hex: "f7", error: "SimpleValueForbidden" },
        RejectCase { name: "simple-16", hex: "f0", error: "SimpleValueForbidden" },
        RejectCase { name: "simple-2byte-0", hex: "f800", error: "SimpleValueForbidden" },
        RejectCase { name: "invalid-utf8", hex: "62c328", error: "InvalidUtf8" },
        RejectCase { name: "trailing-bytes", hex: "0000", error: "TrailingBytes" },
        RejectCase { name: "truncated-int-arg", hex: "18", error: "UnexpectedEnd" },
        RejectCase { name: "truncated-bstr", hex: "440102", error: "LengthExceedsInput" },
        RejectCase { name: "truncated-array", hex: "82ff", error: "LengthExceedsInput" },
        RejectCase { name: "empty-input", hex: "", error: "EmptyInput" },
        RejectCase {
            name: "uint-exceeds-i64",
            hex: "1bffffffffffffffff",
            error: "IntegerOutOfRange",
        },
        RejectCase {
            name: "negative-exceeds-i64",
            hex: "3bffffffffffffffff",
            error: "IntegerNegativeOutOfRange",
        },
        RejectCase { name: "reserved-info-28", hex: "1c", error: "ReservedAdditionalInfo" },
        RejectCase {
            name: "hostile-array-count",
            hex: "9affffffff",
            error: "LengthExceedsInput",
        },
    ]
}

fn vectors_document() -> serde_json::Value {
    let encode_json: Vec<_> = encode_cases()
        .into_iter()
        .map(|c| {
            json!({
                "name": c.name,
                "value": value_to_json(&c.value),
                "hex": c.hex,
            })
        })
        .collect();
    let reject_json: Vec<_> = reject_cases()
        .into_iter()
        .map(|c| json!({"name": c.name, "hex": c.hex, "error": c.error}))
        .collect();
    json!({
        "profile": "sharenet-cbor-v1",
        "description": "Golden vectors for the ShareNet Canonical CBOR Profile v1. \
Encode cases test both directions (value -> hex and hex -> value) plus byte-stability \
(encode(decode(hex)) == hex). Reject cases must be decoded to a typed error whose \
variant name is given in \"error\".",
        "value_encoding": {
            "int": {"t": "int", "v": "<i64>"},
            "bytes": {"t": "bytes", "v": "<hex>"},
            "text": {"t": "text", "v": "<utf-8 string>"},
            "array": {"t": "array", "v": ["<value>", "..."]},
            "map": {"t": "map", "v": [["<key>", "<value>"], "..."]},
            "bool": {"t": "bool", "v": "<true|false>"},
            "null": {"t": "null"}
        },
        "encode_cases": encode_json,
        "reject_cases": reject_json,
    })
}

fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("cbor_vectors.json")
}

#[test]
fn cbor_vectors_file_is_in_sync() {
    let rendered = format!("{}\n", serde_json::to_string_pretty(&vectors_document()).unwrap());
    let on_disk = std::fs::read_to_string(vectors_path())
        .expect("vectors file must exist; run `cargo test -- --ignored regenerate_cbor_vectors`");
    assert_eq!(
        on_disk, rendered,
        "cbor_vectors.json is out of sync with the Rust case tables; \
         regenerate with: cargo test --test cbor_conformance -- --ignored regenerate_cbor_vectors"
    );
}

#[test]
#[ignore = "run explicitly to regenerate the committed vectors file"]
fn regenerate_cbor_vectors() {
    let rendered = format!("{}\n", serde_json::to_string_pretty(&vectors_document()).unwrap());
    std::fs::write(vectors_path(), rendered).expect("write vectors file");
}

#[test]
fn golden_vectors_verify_byte_stability() {
    let on_disk = std::fs::read_to_string(vectors_path()).expect("vectors file");
    let doc: serde_json::Value = serde_json::from_str(&on_disk).expect("vectors file is JSON");
    assert_eq!(doc["profile"], "sharenet-cbor-v1");

    let encode_json = doc["encode_cases"].as_array().expect("encode_cases");
    assert!(encode_json.len() >= 25, "expected a substantial vector set");
    for case in encode_json {
        let name = case["name"].as_str().unwrap();
        let value = json_to_value(&case["value"]);
        let expected = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let encoded = encode(&value).unwrap();
        assert_eq!(
            hex::encode(&encoded),
            case["hex"].as_str().unwrap(),
            "encode case {name}"
        );
        let decoded = decode(&expected).unwrap_or_else(|e| panic!("decode case {name}: {e}"));
        assert_eq!(decoded, value, "decode case {name}");
        assert_eq!(
            encode(&decoded).unwrap(),
            expected,
            "byte-stability case {name}"
        );
    }

    let reject_json = doc["reject_cases"].as_array().expect("reject_cases");
    assert!(reject_json.len() >= 20);
    for case in reject_json {
        let name = case["name"].as_str().unwrap();
        let bytes = hex::decode(case["hex"].as_str().unwrap()).unwrap();
        let err = decode(&bytes)
            .err()
            .unwrap_or_else(|| panic!("reject case {name} must not decode"));
        assert_eq!(
            error_kind(&err),
            case["error"].as_str().unwrap(),
            "reject case {name}"
        );
    }
}

// ---------------------------------------------------------------------------
// Deterministic property tests
// ---------------------------------------------------------------------------

/// splitmix64 — small, reproducible PRNG (no rand dependency in tests).
struct Prng(u64);

impl Prng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

fn gen_int(rng: &mut Prng) -> i64 {
    match rng.below(20) {
        0 => 0,
        1 => 1,
        2 => 23,
        3 => 24,
        4 => 255,
        5 => 256,
        6 => 65535,
        7 => 65536,
        8 => 4294967295,
        9 => 4294967296,
        10 => i64::MAX,
        11 => i64::MAX - 1,
        12 => -1,
        13 => -24,
        14 => -25,
        15 => -256,
        16 => i64::MIN,
        17 => i64::MIN + 1,
        _ => rng.next_u64() as i64,
    }
}

fn gen_bytes(rng: &mut Prng) -> Vec<u8> {
    let len = rng.below(40) as usize;
    (0..len).map(|_| rng.next_u64() as u8).collect()
}

fn gen_text(rng: &mut Prng) -> String {
    let len = rng.below(12) as usize;
    let mut s = String::new();
    for _ in 0..len {
        match rng.below(7) {
            0 => s.push((b'a' + rng.below(26) as u8) as char),
            1 => s.push((b'A' + rng.below(26) as u8) as char),
            2 => s.push((b'0' + rng.below(10) as u8) as char),
            3 => s.push('ü'),
            4 => s.push(char::from_u32(0x4E00 + rng.below(200) as u32).unwrap()),
            5 => s.push('🌍'),
            _ => s.push('-'),
        }
    }
    s
}

fn gen_value(rng: &mut Prng, depth: usize) -> Value {
    if depth >= 5 {
        return match rng.below(5) {
            0 => Value::Int(gen_int(rng)),
            1 => Value::Bytes(gen_bytes(rng)),
            2 => Value::Text(gen_text(rng)),
            3 => Value::Bool(rng.below(2) == 0),
            _ => Value::Null,
        };
    }
    match rng.below(12) {
        0..=2 => Value::Int(gen_int(rng)),
        3 => Value::Bytes(gen_bytes(rng)),
        4 => Value::Text(gen_text(rng)),
        5 => Value::Bool(rng.below(2) == 0),
        6 => Value::Null,
        7..=8 => Value::Array(
            (0..rng.below(5)).map(|_| gen_value(rng, depth + 1)).collect(),
        ),
        9..=11 => {
            let n = rng.below(5) as usize;
            let int_keys = rng.below(2) == 0;
            let base = (rng.next_u64() % 1_000_000) as i64;
            let step = 1 + (rng.next_u64() % 7) as i64;
            let mut builder = MapBuilder::new();
            for i in 0..n {
                let value = gen_value(rng, depth + 1);
                let key_index = base + i as i64 * step;
                if int_keys {
                    builder = builder.insert_int(key_index, value);
                } else {
                    builder = builder.insert_text(&format!("k{key_index}"), value);
                }
            }
            builder.build().expect("generated keys are unique")
        }
        _ => unreachable!(),
    }
}

#[test]
fn property_round_trip_and_byte_stability() {
    for seed in [0x514B67B0, 0x0BADC0DE, 0xC0FFEE, 0x5EED_0001] {
        let mut rng = Prng::new(seed);
        for _ in 0..250 {
            let value = gen_value(&mut rng, 0);
            let bytes = encode(&value).expect("encode generated value");
            let decoded = decode(&bytes).expect("decode generated encoding");
            assert_eq!(decoded, value, "round-trip (seed {seed:#x})");
            assert_eq!(
                encode(&decoded).unwrap(),
                bytes,
                "byte-stability (seed {seed:#x})"
            );
        }
    }
}

#[test]
fn property_every_truncation_is_rejected() {
    // Any proper prefix of a definite-length canonical encoding is
    // incomplete and must be rejected.
    let mut rng = Prng::new(0x7EA5_1234);
    for _ in 0..150 {
        let value = gen_value(&mut rng, 0);
        let bytes = encode(&value).unwrap();
        for cut in 0..bytes.len() {
            assert!(
                decode(&bytes[..cut]).is_err(),
                "prefix of length {cut} must not decode (value {value:?})"
            );
        }
    }
}

#[test]
fn property_random_bytes_never_panic_and_stay_byte_stable() {
    // Fuzz: arbitrary bytes either fail typed or decode to a value whose
    // canonical re-encoding is byte-identical to the input.
    for seed in [1u64, 2, 3, 4, 5] {
        let mut rng = Prng::new(seed);
        for _ in 0..4000 {
            let len = rng.below(49) as usize;
            let bytes: Vec<u8> = (0..len).map(|_| rng.next_u64() as u8).collect();
            if let Ok(decoded) = decode(&bytes) {
                assert_eq!(
                    encode(&decoded).unwrap(),
                    bytes,
                    "byte-stability on accepted random input"
                );
            }
        }
    }
}

#[test]
fn property_single_byte_mutations_are_rejected_or_byte_stable() {
    // For every single-byte mutation of a valid encoding: if it still
    // decodes, it must be its own canonical encoding, and (by injectivity of
    // the canonical encoding) it must decode to a different value than the
    // original.
    let mut rng = Prng::new(0xABCD_EF01);
    for _ in 0..60 {
        let value = gen_value(&mut rng, 0);
        let bytes = encode(&value).unwrap();
        for i in 0..bytes.len() {
            let mut mutated = bytes.clone();
            mutated[i] ^= 1 << (rng.below(8));
            if let Ok(decoded) = decode(&mutated) {
                assert_eq!(
                    encode(&decoded).unwrap(),
                    mutated,
                    "accepted mutation must be canonical"
                );
                if mutated != bytes {
                    assert_ne!(
                        decoded, value,
                        "accepted non-identical mutation must decode to a different value"
                    );
                }
            }
        }
    }
}
