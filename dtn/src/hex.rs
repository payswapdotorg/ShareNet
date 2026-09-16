//! Lowercase hex (probe output + diagnostics). Tiny, dependency-free,
//! allocation-only — the store itself never needs hex (all ids stay raw
//! bytes on every internal path).

/// Encode as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

/// Decode lowercase hex (accepts uppercase too); `Err(())` on any bad
/// length or bad digit. Not a security boundary — a convenience for the
/// probe and tests.
pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
    let s = s.as_bytes();
    if s.len() % 2 != 0 {
        return Err(());
    }
    let nib = |c: u8| -> Result<u8, ()> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(()),
        }
    };
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in s.chunks(2) {
        out.push((nib(pair[0])? << 4) | nib(pair[1])?);
    }
    Ok(out)
}

/// Decode exactly 32 bytes (a content id) from hex.
pub fn decode_32(s: &str) -> Result<[u8; 32], ()> {
    let v = decode(s)?;
    if v.len() != 32 {
        return Err(());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        assert_eq!(encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(decode("000fa5ff").unwrap(), vec![0x00, 0x0f, 0xa5, 0xff]);
        assert_eq!(decode("000FA5FF").unwrap(), vec![0x00, 0x0f, 0xa5, 0xff]);
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn hex_decode_rejects_garbage() {
        assert!(decode("0").is_err());
        assert!(decode("0g").is_err());
        assert!(decode("zz").is_err());
        assert!(decode_32("00").is_err());
        assert!(decode_32(&"ab".repeat(31)).is_err());
        assert!(decode_32(&"ab".repeat(33)).is_err());
        assert!(decode_32(&"0a".repeat(32)).is_ok());
    }
}
