//! Adversarial rejection tests for the ShareNet Canonical CBOR Profile v1
//! (R1-002). Every out-of-profile input class must be rejected with the
//! exact typed error.

#![forbid(unsafe_code)]

use sharenet_protocol::cbor::{decode, DecodeError};
use sharenet_protocol::hex::decode as unhex;

fn rejects(hex: &str) -> DecodeError {
    let bytes = unhex(hex).expect("test hex is valid");
    match decode(&bytes) {
        Ok(v) => panic!("input {hex} must be rejected, decoded to {v:?}"),
        Err(e) => e,
    }
}

#[test]
fn empty_input_is_rejected() {
    assert_eq!(decode(&[]), Err(DecodeError::EmptyInput));
}

#[test]
fn non_minimal_integer_values_are_rejected() {
    // 0 in one-byte form must be 0x00.
    assert_eq!(
        rejects("1800"),
        DecodeError::NonMinimalInteger { at: 0 }
    );
    // 23 must be immediate.
    assert_eq!(rejects("1817"), DecodeError::NonMinimalInteger { at: 0 });
    // 24 must use uint8 form.
    assert_eq!(rejects("190018"), DecodeError::NonMinimalInteger { at: 0 });
    // 255 in uint16 form.
    assert_eq!(rejects("1900ff"), DecodeError::NonMinimalInteger { at: 0 });
    // 256 in uint32 form.
    assert_eq!(
        rejects("1a00000100"),
        DecodeError::NonMinimalInteger { at: 0 }
    );
    // 65536 in uint64 form.
    assert_eq!(
        rejects("1b0000000000010000"),
        DecodeError::NonMinimalInteger { at: 0 }
    );
    // -1 must be 0x20, not 0x38 0x00.
    assert_eq!(rejects("3800"), DecodeError::NonMinimalInteger { at: 0 });
    // -24 must be immediate 0x37.
    assert_eq!(rejects("3817"), DecodeError::NonMinimalInteger { at: 0 });
}

#[test]
fn non_minimal_definite_lengths_are_rejected() {
    // Byte string of length 3 must use 0x43.
    assert_eq!(
        rejects("5803414244"),
        DecodeError::NonMinimalInteger { at: 0 }
    );
    // Text of length 5 must use 0x65.
    assert_eq!(
        rejects("790068656c6c6f"),
        DecodeError::NonMinimalInteger { at: 0 }
    );
    // Array with 1 element must use 0x81.
    assert_eq!(
        rejects("980101"),
        DecodeError::NonMinimalInteger { at: 0 }
    );
    // Map with 1 entry must use 0xa1.
    assert_eq!(
        rejects("b8000102"),
        DecodeError::NonMinimalInteger { at: 0 }
    );
}

#[test]
fn indefinite_lengths_are_rejected_everywhere() {
    // Integer with additional-info 31.
    assert_eq!(rejects("1f"), DecodeError::IndefiniteLength { at: 0 });
    // Indefinite byte string (open + break).
    assert_eq!(rejects("5fff"), DecodeError::IndefiniteLength { at: 0 });
    // Indefinite byte string with a chunk.
    assert_eq!(
        rejects("5f420102ff"),
        DecodeError::IndefiniteLength { at: 0 }
    );
    // Indefinite text string.
    assert_eq!(rejects("7f6161ff"), DecodeError::IndefiniteLength { at: 0 });
    // Indefinite array.
    assert_eq!(rejects("9f01ff"), DecodeError::IndefiniteLength { at: 0 });
    // Indefinite array with several items.
    assert_eq!(
        rejects("9f010203ff"),
        DecodeError::IndefiniteLength { at: 0 }
    );
    // Indefinite map.
    assert_eq!(
        rejects("bf0161afff"),
        DecodeError::IndefiniteLength { at: 0 }
    );
}

#[test]
fn break_code_is_rejected() {
    assert_eq!(rejects("ff"), DecodeError::BreakCode { at: 0 });
    // Break inside a definite structure.
    assert_eq!(rejects("81ff"), DecodeError::BreakCode { at: 1 });
}

#[test]
fn unsorted_map_keys_are_rejected() {
    // {3: 4, 1: 2}
    assert_eq!(rejects("a203040102"), DecodeError::UnsortedMapKeys { at: 3 });
    // {"b": 1, "a": 2}: enc("b") = 61 62, enc("a") = 61 61 — the second key
    // (header at offset 4) sorts lower bytewise.
    assert_eq!(
        rejects("a2616201616102"),
        DecodeError::UnsortedMapKeys { at: 4 }
    );
    // Nested: outer sorted, inner unsorted; inner second key at offset 6.
    assert_eq!(
        rejects("a20102a203040102"),
        DecodeError::UnsortedMapKeys { at: 6 }
    );
}

#[test]
fn duplicate_map_keys_are_rejected() {
    // {1: 2, 1: 3}
    assert_eq!(rejects("a201020103"), DecodeError::DuplicateMapKey { at: 3 });
    // {1: {1: 2}, 2: {1: 2, 1: 3}}; the inner duplicate key sits at
    // offset 9.
    assert_eq!(
        rejects("a201a1010202a201020103"),
        DecodeError::DuplicateMapKey { at: 9 }
    );
}

#[test]
fn tags_are_rejected() {
    assert_eq!(rejects("c000"), DecodeError::TagForbidden { at: 0, tag: 0 });
    assert_eq!(rejects("c10a"), DecodeError::TagForbidden { at: 0, tag: 1 });
    assert_eq!(rejects("ca00"), DecodeError::TagForbidden { at: 0, tag: 10 });
    // Bignum (tag 2): would decode as 256 in permissive decoders.
    assert_eq!(
        rejects("c2420100"),
        DecodeError::TagForbidden { at: 0, tag: 2 }
    );
    // Negative bignum (tag 3).
    assert_eq!(
        rejects("c349010000000000000000"),
        DecodeError::TagForbidden { at: 0, tag: 3 }
    );
    // Tag 1 (epoch time) over an integer.
    assert_eq!(
        rejects("c11a514b67b0"),
        DecodeError::TagForbidden { at: 0, tag: 1 }
    );
}

#[test]
fn floats_are_rejected_at_all_widths() {
    assert_eq!(
        rejects("f90000"),
        DecodeError::FloatForbidden { at: 0, width_bytes: 2 }
    );
    assert_eq!(
        rejects("fa00000000"),
        DecodeError::FloatForbidden { at: 0, width_bytes: 4 }
    );
    assert_eq!(
        rejects("fb0000000000000000"),
        DecodeError::FloatForbidden { at: 0, width_bytes: 8 }
    );
}

#[test]
fn nan_and_infinity_are_rejected() {
    // f16 NaN and ±Inf.
    assert_eq!(
        rejects("f97e00"),
        DecodeError::FloatForbidden { at: 0, width_bytes: 2 }
    );
    assert_eq!(
        rejects("f97c00"),
        DecodeError::FloatForbidden { at: 0, width_bytes: 2 }
    );
    assert_eq!(
        rejects("f9fc00"),
        DecodeError::FloatForbidden { at: 0, width_bytes: 2 }
    );
    // f64 NaN.
    assert_eq!(
        rejects("fb7ff8000000000000"),
        DecodeError::FloatForbidden { at: 0, width_bytes: 8 }
    );
    // f32 +Inf.
    assert_eq!(
        rejects("fa7f800000"),
        DecodeError::FloatForbidden { at: 0, width_bytes: 4 }
    );
}

#[test]
fn undefined_is_rejected() {
    assert_eq!(
        rejects("f7"),
        DecodeError::SimpleValueForbidden { at: 0, value: 23 }
    );
    // undefined inside an array.
    assert_eq!(
        rejects("81f7"),
        DecodeError::SimpleValueForbidden { at: 1, value: 23 }
    );
}

#[test]
fn other_simple_values_are_rejected() {
    // Unassigned immediate simple values.
    assert_eq!(
        rejects("e0"),
        DecodeError::SimpleValueForbidden { at: 0, value: 0 }
    );
    assert_eq!(
        rejects("f3"),
        DecodeError::SimpleValueForbidden { at: 0, value: 19 }
    );
    // Two-byte simple value 0.
    assert_eq!(
        rejects("f800"),
        DecodeError::SimpleValueForbidden { at: 0, value: 0 }
    );
    // Two-byte simple value 32.
    assert_eq!(
        rejects("f820"),
        DecodeError::SimpleValueForbidden { at: 0, value: 32 }
    );
}

#[test]
fn invalid_utf8_text_is_rejected() {
    // 0xC3 0x28 is not valid UTF-8.
    assert_eq!(rejects("62c328"), DecodeError::InvalidUtf8 { at: 0 });
    // Overlong encoding 0xC0 0x80.
    assert_eq!(rejects("62c080"), DecodeError::InvalidUtf8 { at: 0 });
    // Lone continuation byte.
    assert_eq!(rejects("6180"), DecodeError::InvalidUtf8 { at: 0 });
    // Truncated multi-byte sequence as the whole text.
    assert_eq!(rejects("61c3"), DecodeError::InvalidUtf8 { at: 0 });
    // Invalid UTF-8 inside a map key (text header at offset 1).
    assert_eq!(
        rejects("a161806161"),
        DecodeError::InvalidUtf8 { at: 1 }
    );
}

#[test]
fn trailing_garbage_is_rejected() {
    assert_eq!(
        rejects("0000"),
        DecodeError::TrailingBytes { at: 1, count: 1 }
    );
    assert_eq!(
        rejects("01ff"),
        DecodeError::TrailingBytes { at: 1, count: 1 }
    );
    // A complete map followed by a complete int.
    assert_eq!(
        rejects("a00101"),
        DecodeError::TrailingBytes { at: 1, count: 2 }
    );
    // Trailing whitespace is still trailing.
    assert_eq!(
        rejects("0120"),
        DecodeError::TrailingBytes { at: 1, count: 1 }
    );
}

#[test]
fn truncated_inputs_are_rejected() {
    // Missing argument byte.
    assert_eq!(
        rejects("18"),
        DecodeError::UnexpectedEnd { at: 0, needed: 1 }
    );
    // Half of a uint16 argument.
    assert_eq!(
        rejects("1903"),
        DecodeError::UnexpectedEnd { at: 0, needed: 2 }
    );
    // Byte string body shorter than declared.
    assert_eq!(
        rejects("440102"),
        DecodeError::LengthExceedsInput { at: 0, declared: 4 }
    );
    // Array header with element count exceeding remaining bytes.
    assert_eq!(
        rejects("82ff"),
        DecodeError::LengthExceedsInput { at: 0, declared: 2 }
    );
    // Map value missing.
    assert_eq!(
        rejects("a101"),
        DecodeError::UnexpectedEnd { at: 2, needed: 1 }
    );
    // Float payload missing.
    assert_eq!(
        rejects("fb0000"),
        DecodeError::UnexpectedEnd { at: 0, needed: 8 }
    );
    // Text body missing entirely.
    assert_eq!(
        rejects("65"),
        DecodeError::LengthExceedsInput { at: 0, declared: 5 }
    );
}

#[test]
fn integers_out_of_i64_range_are_rejected() {
    // u64::MAX as unsigned.
    assert_eq!(
        rejects("1bffffffffffffffff"),
        DecodeError::IntegerOutOfRange {
            at: 0,
            raw: u64::MAX
        }
    );
    // -(u64::MAX + 1).
    assert_eq!(
        rejects("3bffffffffffffffff"),
        DecodeError::IntegerNegativeOutOfRange {
            at: 0,
            raw: u64::MAX
        }
    );
    // 2^63 as unsigned (i64::MAX + 1).
    assert_eq!(
        rejects("1b8000000000000000"),
        DecodeError::IntegerOutOfRange {
            at: 0,
            raw: 1u64 << 63
        }
    );
}

#[test]
fn reserved_additional_info_is_rejected() {
    assert_eq!(
        rejects("1c"),
        DecodeError::ReservedAdditionalInfo { at: 0, info: 28 }
    );
    assert_eq!(
        rejects("5c00010203"),
        DecodeError::ReservedAdditionalInfo { at: 0, info: 28 }
    );
    assert_eq!(
        rejects("1d"),
        DecodeError::ReservedAdditionalInfo { at: 0, info: 29 }
    );
    assert_eq!(
        rejects("1e"),
        DecodeError::ReservedAdditionalInfo { at: 0, info: 30 }
    );
}

#[test]
fn hostile_declared_lengths_fail_closed() {
    // Array claiming 2^32-1 elements.
    assert_eq!(
        rejects("9affffffff"),
        DecodeError::LengthExceedsInput {
            at: 0,
            declared: 4294967295
        }
    );
    // Map claiming 2^64-1 entries (0xBB = map + uint64 count).
    assert_eq!(
        rejects("bbffffffffffffffff"),
        DecodeError::LengthExceedsInput {
            at: 0,
            declared: u64::MAX
        }
    );
    // Byte string claiming 2^64-1 bytes.
    assert_eq!(
        rejects("5bffffffffffffffff"),
        DecodeError::LengthExceedsInput {
            at: 0,
            declared: u64::MAX
        }
    );
}

#[test]
fn depth_limit_is_enforced() {
    let mut bytes = vec![0x81u8; sharenet_protocol::cbor::MAX_DEPTH + 1];
    bytes.push(0x01);
    assert_eq!(
        decode(&bytes),
        Err(DecodeError::DepthLimitExceeded {
            at: sharenet_protocol::cbor::MAX_DEPTH + 1
        })
    );
}
