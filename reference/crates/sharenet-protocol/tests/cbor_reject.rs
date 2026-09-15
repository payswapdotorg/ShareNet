//! Adversarial rejection tests for the ShareNet Canonical CBOR Profile v1 (R1-002).
//!
//! Every out-of-profile input must be rejected with the exact typed error naming the
//! violation, and decoding must never panic on arbitrary bytes (fuzz below).

mod common;

use common::{from_hex, Rng};
use sharenet_protocol::cbor::{decode, DecodeError};

fn expect_reject(hex: &str, want: fn(usize) -> DecodeError) {
    let bytes = from_hex(hex);
    match decode(&bytes) {
        Err(e) => assert_eq!(e, want(hex.len()), "wrong error for {hex}: {e}"),
        Ok(v) => panic!("input {hex} was wrongly ACCEPTED as {v:?}"),
    }
}

#[test]
fn rejects_empty_and_trailing() {
    // Empty input.
    assert_eq!(decode(&[]), Err(DecodeError::EmptyInput));
    // Trailing garbage after a complete top-level item.
    expect_reject("0000", |_| DecodeError::TrailingBytes { at: 1, count: 1 });
    expect_reject("0102", |_| DecodeError::TrailingBytes { at: 1, count: 1 });
    expect_reject("f4f5", |_| DecodeError::TrailingBytes { at: 1, count: 1 });
    expect_reject("6061", |_| DecodeError::TrailingBytes { at: 1, count: 1 });
    expect_reject("44ff00000000", |_| DecodeError::TrailingBytes {
        at: 5,
        count: 1,
    });
}

#[test]
fn rejects_truncated_inputs() {
    // Header present, argument missing.
    expect_reject("18", |_| DecodeError::Truncated { at: 1 });
    expect_reject("19", |_| DecodeError::Truncated { at: 1 });
    expect_reject("1a", |_| DecodeError::Truncated { at: 1 });
    expect_reject("1b", |_| DecodeError::Truncated { at: 1 });
    // Byte string claims more than provided.
    expect_reject("41", |_| DecodeError::Truncated { at: 1 });
    expect_reject("43 0102".replace(' ', "").as_str(), |_| {
        DecodeError::Truncated { at: 1 }
    });
    expect_reject("44010203", |_| DecodeError::Truncated { at: 1 });
    // Text claims more than provided.
    expect_reject("62 61".replace(' ', "").as_str(), |_| {
        DecodeError::Truncated { at: 1 }
    });
    expect_reject("64 494554".replace(' ', "").as_str(), |_| {
        DecodeError::Truncated { at: 1 }
    });
    // Array claims more items than provided.
    expect_reject("8201", |_| DecodeError::Truncated { at: 2 });
    expect_reject("830102", |_| DecodeError::Truncated { at: 3 });
    // Map claims more pairs than provided.
    expect_reject("a101", |_| DecodeError::Truncated { at: 2 });
    expect_reject("a2010203", |_| DecodeError::Truncated { at: 4 });
    // Tag head with missing argument.
    expect_reject("d8", |_| DecodeError::Truncated { at: 1 });
    // Two-byte simple with missing payload.
    expect_reject("f8", |_| DecodeError::Truncated { at: 1 });
    // Float heads are rejected at the head byte, payload or not.
    expect_reject("fb3ff1", |_| DecodeError::FloatNotAllowed { at: 0 });
    // Immediate tag is complete (rejected as tag, not truncated).
    expect_reject("c100", |_| DecodeError::TagNotAllowed { at: 0, tag: 1 });
}

#[test]
fn rejects_non_minimal_integers() {
    // 0 encoded with a 1-byte argument.
    expect_reject("1800", |_| DecodeError::NonMinimalInteger { at: 0 });
    // 23 encoded with a 1-byte argument.
    expect_reject("1817", |_| DecodeError::NonMinimalInteger { at: 0 });
    // 24 with a 2-byte argument.
    expect_reject("190018", |_| DecodeError::NonMinimalInteger { at: 0 });
    // 255 with a 4-byte argument.
    expect_reject("1a000000ff", |_| DecodeError::NonMinimalInteger { at: 0 });
    // 65535 with an 8-byte argument.
    expect_reject("1b000000000000ffff", |_| DecodeError::NonMinimalInteger {
        at: 0,
    });
    // Negative: -24 fits in the immediate form (0x37), so 0x38 0x17 is non-minimal.
    // (Note: -25 is 0x38 0x18 — that IS minimal; the 1-byte-arg class starts at -25.)
    expect_reject("3817", |_| DecodeError::NonMinimalInteger { at: 0 });
    expect_reject("390018", |_| DecodeError::NonMinimalInteger { at: 0 });
    // Non-minimal lengths on strings/arrays/maps are equally rejected.
    expect_reject("5800", |_| DecodeError::NonMinimalInteger { at: 0 }); // bstr len 0, wide form
    expect_reject("9800", |_| DecodeError::NonMinimalInteger { at: 0 }); // array len 0, wide form
    expect_reject("b800", |_| DecodeError::NonMinimalInteger { at: 0 }); // map len 0, wide form
    expect_reject("d80000", |_| DecodeError::NonMinimalInteger { at: 0 }); // tag 0, wide form
}

#[test]
fn rejects_out_of_range_integers() {
    // 2^64-1 > i64::MAX.
    expect_reject("1bffffffffffffffff", |_| DecodeError::IntegerOutOfRange {
        at: 0,
    });
    // -2^64 < i64::MIN.
    expect_reject("3bffffffffffffffff", |_| DecodeError::IntegerOutOfRange {
        at: 0,
    });
}

#[test]
fn rejects_indefinite_lengths() {
    expect_reject("9f", |_| DecodeError::IndefiniteLength { at: 0 }); // array
    expect_reject("5f", |_| DecodeError::IndefiniteLength { at: 0 }); // bstr
    expect_reject("7f", |_| DecodeError::IndefiniteLength { at: 0 }); // tstr
    expect_reject("bf", |_| DecodeError::IndefiniteLength { at: 0 }); // map
                                                                      // Indefinite forms with content are still rejected at the head.
    expect_reject("9f01ff", |_| DecodeError::IndefiniteLength { at: 0 });
    expect_reject("7f6161ff", |_| DecodeError::IndefiniteLength { at: 0 });
    expect_reject("bf0102ff", |_| DecodeError::IndefiniteLength { at: 0 });
}

#[test]
fn rejects_unsorted_and_duplicate_map_keys() {
    // {2:1, 1:2}: unsorted (second key at offset 3).
    expect_reject("a202010102", |_| DecodeError::UnsortedMapKeys { at: 3 });
    // {1:2, 1:3}: duplicate (second key at offset 3).
    expect_reject("a201020103", |_| DecodeError::DuplicateMapKey { at: 3 });
    // {"b":1, "a":1}: unsorted text keys (second key at offset 4).
    expect_reject("a2616201616101", |_| DecodeError::UnsortedMapKeys { at: 4 });
    // {"a":1, "a":2}: duplicate text keys (second key at offset 4).
    expect_reject("a2616101616102", |_| DecodeError::DuplicateMapKey { at: 4 });
    // Negative key before smaller uint key: -1 (0x20) then 1 (0x01): unsorted at offset 3.
    expect_reject("a220030102", |_| DecodeError::UnsortedMapKeys { at: 3 });
    // Nested maps must be sorted too (second key of inner map at offset 4).
    expect_reject("81a202010102", |_| DecodeError::UnsortedMapKeys { at: 4 });
}

#[test]
fn rejects_tags() {
    // Tag 0 (date/time) over an int.
    expect_reject("c000", |_| DecodeError::TagNotAllowed { at: 0, tag: 0 });
    // Tag 1 (epoch seconds).
    expect_reject("c100", |_| DecodeError::TagNotAllowed { at: 0, tag: 1 });
    // Tag 100 in the 1-byte-argument form.
    expect_reject("d86400", |_| DecodeError::TagNotAllowed { at: 0, tag: 100 });
    // Positive bignum (tag 2): 18446744073709551615.
    expect_reject("c24b00ffffffffffffffff", |_| DecodeError::TagNotAllowed {
        at: 0,
        tag: 2,
    });
    // Negative bignum (tag 3).
    expect_reject("c349010000000000000000", |_| DecodeError::TagNotAllowed {
        at: 0,
        tag: 3,
    });
    // Nested tag.
    expect_reject("81c100", |_| DecodeError::TagNotAllowed { at: 1, tag: 1 });
}

#[test]
fn rejects_floats() {
    expect_reject("f90000", |_| DecodeError::FloatNotAllowed { at: 0 }); // 0.0 (f16)
    expect_reject("f93c00", |_| DecodeError::FloatNotAllowed { at: 0 }); // 1.0 (f16)
    expect_reject("f93e00", |_| DecodeError::FloatNotAllowed { at: 0 }); // 1.5 (f16)
    expect_reject("f97c00", |_| DecodeError::FloatNotAllowed { at: 0 }); // +Inf
    expect_reject("f9fc00", |_| DecodeError::FloatNotAllowed { at: 0 }); // -Inf
    expect_reject("f97e00", |_| DecodeError::FloatNotAllowed { at: 0 }); // NaN
    expect_reject("fa47c35000", |_| DecodeError::FloatNotAllowed { at: 0 }); // 100000.0 (f32)
    expect_reject("fb8000000000000000", |_| DecodeError::FloatNotAllowed {
        at: 0,
    }); // -0.0 (f64)
    expect_reject("fb3ff199999999999a", |_| DecodeError::FloatNotAllowed {
        at: 0,
    }); // 1.1
        // Nested float.
    expect_reject("81f97c00", |_| DecodeError::FloatNotAllowed { at: 1 });
}

#[test]
fn rejects_undefined_and_other_simple_values() {
    expect_reject("f7", |_| DecodeError::UndefinedNotAllowed { at: 0 });
    // Simple values 0..=19 in single-byte form.
    expect_reject("e0", |_| DecodeError::SimpleValueNotAllowed {
        at: 0,
        value: 0,
    });
    expect_reject("ef", |_| DecodeError::SimpleValueNotAllowed {
        at: 0,
        value: 15,
    });
    expect_reject("f3", |_| DecodeError::SimpleValueNotAllowed {
        at: 0,
        value: 19,
    });
    // Two-byte simple-value form (even for false/true/null payloads: non-canonical).
    expect_reject("f814", |_| DecodeError::SimpleValueNotAllowed {
        at: 0,
        value: 20,
    });
    expect_reject("f815", |_| DecodeError::SimpleValueNotAllowed {
        at: 0,
        value: 21,
    });
    expect_reject("f816", |_| DecodeError::SimpleValueNotAllowed {
        at: 0,
        value: 22,
    });
    expect_reject("f8ff", |_| DecodeError::SimpleValueNotAllowed {
        at: 0,
        value: 255,
    });
}

#[test]
fn rejects_break_byte_and_reserved_heads() {
    expect_reject("ff", |_| DecodeError::BreakByteNotAllowed { at: 0 });
    // Reserved additional-info 28-30 across major types.
    expect_reject("1c", |_| DecodeError::ReservedAdditionalInfo { at: 0 });
    expect_reject("1d", |_| DecodeError::ReservedAdditionalInfo { at: 0 });
    expect_reject("1e", |_| DecodeError::ReservedAdditionalInfo { at: 0 });
    expect_reject("1f", |_| DecodeError::ReservedAdditionalInfo { at: 0 });
    expect_reject("5c", |_| DecodeError::ReservedAdditionalInfo { at: 0 });
    expect_reject("7d", |_| DecodeError::ReservedAdditionalInfo { at: 0 });
    expect_reject("9e", |_| DecodeError::ReservedAdditionalInfo { at: 0 });
    expect_reject("be", |_| DecodeError::ReservedAdditionalInfo { at: 0 });
    expect_reject("dc", |_| DecodeError::ReservedAdditionalInfo { at: 0 });
    expect_reject("fc", |_| DecodeError::ReservedAdditionalInfo { at: 0 });
    expect_reject("fd", |_| DecodeError::ReservedAdditionalInfo { at: 0 });
    expect_reject("fe", |_| DecodeError::ReservedAdditionalInfo { at: 0 });
    // Stray break byte after a complete item (also trailing, but break is the
    // first violation encountered).
    expect_reject("00ff", |_| DecodeError::TrailingBytes { at: 1, count: 1 });
}

#[test]
fn rejects_invalid_utf8() {
    expect_reject("61ff", |_| DecodeError::InvalidUtf8 { at: 0 });
    expect_reject("62c328", |_| DecodeError::InvalidUtf8 { at: 0 }); // 0xc3 0x28
    expect_reject("62c0af", |_| DecodeError::InvalidUtf8 { at: 0 }); // overlong encoding start
    expect_reject("61f4", |_| DecodeError::InvalidUtf8 { at: 0 }); // lone 4-byte-sequence lead
    expect_reject("62e6b0", |_| DecodeError::InvalidUtf8 { at: 0 }); // truncated 水 sequence
}

#[test]
fn rejects_oversized_claims_without_allocating() {
    // A 2^61-1-length byte string with no payload must fail as Truncated, quickly.
    let huge = from_hex("5b7fffffffffffffff");
    assert!(matches!(decode(&huge), Err(DecodeError::Truncated { .. })));
    // Same for an array claiming a huge count with no items.
    let huge = from_hex("9b7fffffffffffffff");
    assert!(matches!(decode(&huge), Err(DecodeError::Truncated { .. })));
    let huge = from_hex("bb7fffffffffffffff");
    assert!(matches!(decode(&huge), Err(DecodeError::Truncated { .. })));
}

#[test]
fn fuzz_decode_never_panics_and_accepted_implies_canonical() {
    // Arbitrary random bytes: decode must return (not panic) and, if it accepts,
    // the strictness law must hold.
    let mut rng = Rng::new(0xC805);
    for len in 0..=48usize {
        for _ in 0..400 {
            let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
            if let Ok(v) = decode(&bytes) {
                let re = sharenet_protocol::cbor::encode(&v).unwrap();
                assert_eq!(
                    re,
                    bytes,
                    "accepted non-canonical bytes: {}",
                    bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
                );
            }
        }
    }
    // Some longer blobs too.
    for _ in 0..200 {
        let len = 49 + (rng.next_u64() % 512) as usize;
        let bytes: Vec<u8> = (0..len).map(|_| rng.next_byte()).collect();
        let _ = decode(&bytes); // must not panic
    }
}

#[test]
fn fuzz_mutated_valid_inputs_never_panic() {
    let seeds = [
        "a26161016162820203",
        "8301820203820405",
        "1b000000e8d4a51000",
        "a21818022003",
        "6449455446",
        "a2010241ff03",
    ];
    let mut rng = Rng::new(0xfeed);
    for s in seeds {
        let base = from_hex(s);
        // Truncations of every prefix length.
        for cut in 0..base.len() {
            let _ = decode(&base[..cut]);
        }
        // Appended garbage.
        for extra in 0..4 {
            let mut m = base.clone();
            m.extend(std::iter::repeat_n(0xff, extra));
            if let Ok(v) = decode(&m) {
                // Only the un-mutated base can be valid; any extension is trailing.
                assert!(extra == 0, "appended bytes were accepted for {s}");
                let _ = v;
            }
        }
        // Single-bit flips.
        for pos in 0..base.len() {
            for bit in 0..8u32 {
                let mut m = base.clone();
                m[pos] ^= 1 << bit;
                if let Ok(v) = decode(&m) {
                    let re = sharenet_protocol::cbor::encode(&v).unwrap();
                    assert_eq!(re, m, "non-canonical acceptance for mutated {s}");
                }
            }
        }
        let _ = rng.next_byte();
    }
}

#[test]
fn arbitrary_error_display_is_nonempty() {
    // Sanity: the typed errors render actionable text.
    let e = DecodeError::NonMinimalInteger { at: 7 };
    assert!(e.to_string().contains("minimally"));
    assert!(e.to_string().contains('7'));
}
