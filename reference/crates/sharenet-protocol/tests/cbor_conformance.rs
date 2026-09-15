//! Conformance tests for the ShareNet Canonical CBOR Profile v1 (R1-002).
//!
//! - Deterministic-encoding examples derived from RFC 8949 / RFC 7049 (all in-profile).
//! - The strictness law: byte-stability and round-trip, including property tests over
//!   seeded random values.
//! - Canonical map-key ordering (bytewise over full encodings), including cross-type
//!   and negative-vs-unsigned key pairs that distinguish bytewise from RFC 8949's
//!   length-first tie-break (documented deviation of this profile).

mod common;

use common::{from_hex, Rng};
use sharenet_protocol::cbor::{decode, encode, DecodeError, EncodeError, Value};

fn i(v: i64) -> Value {
    Value::Int(v)
}
fn b(v: &[u8]) -> Value {
    Value::Bytes(v.to_vec())
}
fn t(v: &str) -> Value {
    Value::Text(v.to_string())
}

/// (canonical hex, expected value) pairs derived from RFC 8949 deterministic encoding
/// examples (originally RFC 7049 §2.4.1); every entry is in-profile.
fn rfc_examples() -> Vec<(&'static str, Value)> {
    vec![
        ("00", i(0)),
        ("01", i(1)),
        ("10", i(16)),
        ("17", i(23)),
        ("1818", i(24)),
        ("1819", i(25)),
        ("1864", i(100)),
        ("1903e8", i(1000)),
        ("1a000f4240", i(1_000_000)),
        ("1b000000e8d4a51000", i(1_000_000_000_000)),
        ("1b7fffffffffffffff", i(i64::MAX)),
        ("20", i(-1)),
        ("29", i(-10)),
        ("37", i(-24)),
        ("3818", i(-25)),
        ("3863", i(-100)),
        ("3903e7", i(-1000)),
        ("3b7fffffffffffffff", i(i64::MIN)),
        ("f4", Value::Bool(false)),
        ("f5", Value::Bool(true)),
        ("f6", Value::Null),
        ("40", b(&[])),
        ("4401020304", b(&[0x01, 0x02, 0x03, 0x04])),
        ("60", t("")),
        ("6161", t("a")),
        ("6449455446", t("IETF")),
        ("62225c", t("\"\\")),
        ("62c3bc", t("\u{fc}")),        // ü
        ("63e6b0b4", t("\u{6c34}")),    // 水
        ("64f0908091", t("\u{10011}")), // 𐀑
        ("80", Value::Array(vec![])),
        ("83010203", Value::Array(vec![i(1), i(2), i(3)])),
        (
            "8301820203820405",
            Value::Array(vec![
                i(1),
                Value::Array(vec![i(2), i(3)]),
                Value::Array(vec![i(4), i(5)]),
            ]),
        ),
        ("a0", Value::Map(vec![])),
        ("a201020304", Value::Map(vec![(i(1), i(2)), (i(3), i(4))])),
        (
            "a26161016162820203",
            Value::Map(vec![
                (t("a"), i(1)),
                (t("b"), Value::Array(vec![i(2), i(3)])),
            ]),
        ),
        // Boundary integers around length classes.
        ("18ff", i(255)),
        ("190100", i(256)),
        ("19ffff", i(65_535)),
        ("1a00010000", i(65_536)),
        ("1affffffff", i(4_294_967_295)),
        ("1b0000000100000000", i(4_294_967_296)),
        ("38ff", i(-256)),
        ("390100", i(-257)),
        // Bytewise key ordering: 1 (0x01) sorts before -1 (0x20).
        ("a201022003", Value::Map(vec![(i(1), i(2)), (i(-1), i(3))])),
        // Bytewise key ordering across length classes: 24 (0x1818) before -1 (0x20).
        // (RFC 8949's length-first rule would order these the other way; the ShareNet
        // profile pins bytewise over the full encodings — see module docs.)
        (
            "a21818022003",
            Value::Map(vec![(i(24), i(2)), (i(-1), i(3))]),
        ),
        // Mixed-type keys sort by first byte: uint 1 (0x01) before text "a" (0x61 61).
        (
            "a20102616103",
            Value::Map(vec![(i(1), i(2)), (t("a"), i(3))]),
        ),
    ]
}

#[test]
fn rfc8949_examples_decode_encode_and_roundtrip() {
    for (hex, expected) in rfc_examples() {
        let bytes = from_hex(hex);
        let v = decode(&bytes).unwrap_or_else(|e| panic!("decode({hex}): {e}"));
        assert_eq!(v, expected, "decoded value mismatch for {hex}");
        // Strictness law, part 1: byte-stability.
        let re = encode(&v).unwrap_or_else(|e| panic!("encode({hex}): {e}"));
        assert_eq!(re, bytes, "byte-stability failed for {hex}");
        // Strictness law, part 2: round-trip.
        let v2 = decode(&re).unwrap();
        assert_eq!(v2, v, "round-trip failed for {hex}");
        // Encoding the expected value directly must produce the same bytes.
        let direct = encode(&expected).unwrap();
        assert_eq!(direct, bytes, "direct encode mismatch for {hex}");
    }
}

#[test]
fn encoder_sorts_unsorted_maps_into_canonical_order() {
    let unsorted = Value::Map(vec![
        (t("b"), i(2)),
        (t("a"), i(1)),
        (i(100), i(3)),
        (i(-1), i(4)),
    ]);
    let encoded = encode(&unsorted).unwrap();
    // Canonical order by key bytes: 0x1864 (100), 0x20 (-1), 0x6161 ("a"),
    // 0x6262 ("b") -> 100 < -1 < "a" < "b" bytewise.
    assert_eq!(encoded, from_hex("a41864032004616101616202"));
    // Round-trip yields the sorted map.
    let sorted = decode(&encoded).unwrap();
    match sorted {
        Value::Map(entries) => {
            let keys: Vec<Value> = entries.into_iter().map(|(k, _)| k).collect();
            let expected_order = vec![i(100), i(-1), t("a"), t("b")];
            assert_eq!(keys, expected_order);
        }
        other => panic!("expected map, got {other:?}"),
    }
}

#[test]
fn encoder_rejects_duplicate_keys() {
    let dup = Value::Map(vec![(t("a"), i(1)), (t("a"), i(2))]);
    match encode(&dup) {
        Err(EncodeError::DuplicateMapKey { .. }) => {}
        other => panic!("expected DuplicateMapKey, got {other:?}"),
    }
}

/// Deterministically generate a random in-profile value.
fn random_value(rng: &mut Rng, depth: u32) -> Value {
    let choices = if depth >= 4 { 4 } else { 7 };
    match rng.next_range(choices) {
        0 => Value::Int(rng.next_u64() as i64),
        1 => Value::Bytes((0..rng.next_range(9)).map(|_| rng.next_byte()).collect()),
        2 => {
            // Random valid UTF-8 built from a small safe alphabet.
            let len = rng.next_range(9) as usize;
            let s: String = (0..len)
                .map(|_| char::from_u32('a' as u32 + rng.next_range(26) as u32).unwrap())
                .collect();
            Value::Text(s)
        }
        3 => Value::Bool(rng.next_bool()),
        4 => Value::Null,
        5 => Value::Array(
            (0..rng.next_range(5))
                .map(|_| random_value(rng, depth + 1))
                .collect(),
        ),
        6 => {
            // Map with unique keys (so it is encodable): retry keys until unique.
            let n = rng.next_range(4) as usize;
            let mut entries: Vec<(Value, Value)> = Vec::new();
            while entries.len() < n {
                let k = random_value(rng, depth + 1);
                let already = entries.iter().any(|(k2, _)| *k2 == k);
                if !already {
                    let v = random_value(rng, depth + 1);
                    entries.push((k, v));
                }
            }
            // Deliberately leave the map unsorted: encoding must canonicalize.
            Value::Map(entries)
        }
        _ => unreachable!(),
    }
}

#[test]
fn roundtrip_property_random_values() {
    for seed in 0u64..50 {
        let mut rng = Rng::new(seed);
        for _ in 0..60 {
            let v = random_value(&mut rng, 0);
            let bytes = encode(&v).unwrap_or_else(|e| panic!("encode failed: {e}"));
            let back = decode(&bytes).unwrap_or_else(|e| panic!("decode failed: {e}"));
            assert_eq!(back, v, "round-trip mismatch (seed {seed})");
            let re = encode(&back).unwrap();
            assert_eq!(re, bytes, "byte-stability mismatch (seed {seed})");
        }
    }
}

#[test]
fn strictness_law_on_arbitrary_accepted_bytes() {
    // If random bytes happen to decode, they MUST re-encode to exactly themselves.
    for seed in 0u64..30 {
        let mut rng = Rng::new(seed ^ 0x5eed);
        for len in 0..=24usize {
            for _ in 0..40 {
                let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
                if let Ok(v) = decode(&bytes) {
                    let re = encode(&v)
                        .unwrap_or_else(|e| panic!("accepted bytes failed to encode: {e}"));
                    assert_eq!(
                        re,
                        bytes,
                        "accepted non-canonical bytes: {}",
                        common_hex(&bytes)
                    );
                }
            }
        }
    }
}

fn common_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn depth_limits_are_enforced_symmetrically() {
    // 127 nested arrays + int => depth 128: accepted.
    let mut ok = vec![0x81; 127];
    ok.push(0x00);
    assert!(decode(&ok).is_ok());
    // Encode side: same depth accepted.
    let mut deep = Value::Int(0);
    for _ in 0..127 {
        deep = Value::Array(vec![deep]);
    }
    assert!(encode(&deep).is_ok());
    // 128 nested arrays + int => depth 129: rejected on decode...
    let mut too_deep = vec![0x81; 128];
    too_deep.push(0x00);
    match decode(&too_deep) {
        Err(DecodeError::DepthLimitExceeded { limit, .. }) => assert_eq!(limit, 128),
        other => panic!("expected DepthLimitExceeded, got {other:?}"),
    }
    // ...and on encode.
    let mut deeper = Value::Int(0);
    for _ in 0..128 {
        deeper = Value::Array(vec![deeper]);
    }
    match encode(&deeper) {
        Err(EncodeError::DepthLimitExceeded { limit }) => assert_eq!(limit, 128),
        other => panic!("expected DepthLimitExceeded, got {other:?}"),
    }
}

#[test]
fn map_key_ordering_is_bytewise_over_full_encodings() {
    // Key 24 encodes as 1818; key 25 as 1819: canonical order is (24, 25).
    let ok = from_hex("a2181802181901");
    assert!(decode(&ok).is_ok());
    // Reversed order must be rejected as unsorted (the offending key is the
    // second key, at offset 4).
    let reversed = from_hex("a2181901181802");
    assert_eq!(
        decode(&reversed).unwrap_err(),
        DecodeError::UnsortedMapKeys { at: 4 }
    );
    // Same-length cross-major keys: uint 1 (0x01) before bytes h'ff' (0x41ff).
    assert!(decode(&from_hex("a2010241ff03")).is_ok());
    assert_eq!(
        decode(&from_hex("a241ff030102")).unwrap_err(),
        DecodeError::UnsortedMapKeys { at: 4 }
    );
}

#[test]
fn value_map_equality_is_order_insensitive_for_random_maps() {
    for seed in 0u64..20 {
        let mut rng = Rng::new(seed ^ 0xa11ce);
        let v1 = random_value(&mut rng, 0);
        // Re-encode + decode yields a canonical-order map; equality must hold.
        let bytes = encode(&v1).unwrap();
        let v2 = decode(&bytes).unwrap();
        assert_eq!(v1, v2, "order-insensitive equality (seed {seed})");
    }
}
