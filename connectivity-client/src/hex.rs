//! Strict lowercase-hex for reference ids — the only byte encoding this
//! wire shape uses for the 32-byte opaque ids (the same shape the parent
//! crate's `to_hex()` emits).
//!
//! Strict means: exactly 64 characters, `0-9a-f` only. Uppercase,
//! odd-length, non-hex and over-long inputs are typed errors, not
//! best-effort parses — a reference id is opaque identity, and identity
//! must round-trip exactly.

use crate::error::MalformedReason;

/// Encode 32 bytes as exactly 64 lowercase hex characters.
pub fn encode_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0F) as usize] as char);
    }
    out
}

/// Decode exactly 64 lowercase hex characters into 32 bytes.
pub fn decode_lower_hex_32(text: &str) -> Result<[u8; 32], MalformedReason> {
    if text.len() != 64 {
        return Err(MalformedReason::BadRefId);
    }
    let mut out = [0u8; 32];
    let bytes = text.as_bytes();
    for i in 0..32 {
        let hi = hex_digit(bytes[2 * i]).ok_or(MalformedReason::BadRefId)?;
        let lo = hex_digit(bytes[2 * i + 1]).ok_or(MalformedReason::BadRefId)?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

/// Decode a lowercase-hex byte string of any (even) length — the variable
///-length form the R5-004 signed-observation envelope rides as. Strict in
/// the same way: `0-9a-f` only, no odd lengths. The error is undecorated
/// (`()`) so each caller maps it to its own typed reason.
pub fn decode_lower_hex(text: &str) -> Result<Vec<u8>, ()> {
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = hex_digit(pair[0]).ok_or(())?;
        let lo = hex_digit(pair[1]).ok_or(())?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Lowercase hex digit only (`0-9a-f`).
fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_is_exact() {
        let bytes: Vec<u8> = (0..=255u8).chain([0xAB, 0x00, 0xFF]).collect();
        let mut id = [0u8; 32];
        for (i, b) in bytes.iter().take(32).enumerate() {
            id[i] = *b;
        }
        let text = encode_lower_hex(&id);
        assert_eq!(text.len(), 64);
        assert!(text.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        assert_eq!(decode_lower_hex_32(&text).unwrap(), id);
        // Matches the parent crate's to_hex byte-for-byte.
        assert_eq!(
            text,
            sharenet_connectivity::ConnectivityContractRef::from_id(id).to_hex()
        );
    }

    #[test]
    fn hex_decode_is_strict() {
        assert_eq!(decode_lower_hex_32(""), Err(MalformedReason::BadRefId));
        assert_eq!(
            decode_lower_hex_32(&"0".repeat(63)),
            Err(MalformedReason::BadRefId)
        );
        assert_eq!(
            decode_lower_hex_32(&"0".repeat(65)),
            Err(MalformedReason::BadRefId)
        );
        assert_eq!(
            decode_lower_hex_32(&"a".repeat(64).to_uppercase()),
            Err(MalformedReason::BadRefId),
            "uppercase is refused"
        );
        assert_eq!(
            decode_lower_hex_32(&"g".repeat(64)),
            Err(MalformedReason::BadRefId)
        );
        assert_eq!(
            decode_lower_hex_32(&format!("{}z", "0".repeat(63))),
            Err(MalformedReason::BadRefId)
        );
        // 64 lowercase hex characters pass.
        assert!(decode_lower_hex_32(&"f".repeat(64)).is_ok());
    }

    #[test]
    fn variable_length_hex_is_strict() {
        assert_eq!(decode_lower_hex(""), Ok(Vec::new()));
        assert_eq!(decode_lower_hex("00ff10"), Ok(vec![0x00, 0xff, 0x10]));
        // odd length, uppercase, non-hex — all refused
        assert_eq!(decode_lower_hex("0"), Err(()));
        assert_eq!(decode_lower_hex("0F"), Err(()));
        assert_eq!(decode_lower_hex("0g"), Err(()));
        // round-trips with encode_lower_hex
        let bytes: Vec<u8> = (0..=77u8).collect();
        let text = encode_lower_hex(&bytes);
        assert_eq!(decode_lower_hex(&text), Ok(bytes));
    }
}
