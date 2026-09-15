//! Minimal lowercase-hex helpers (no external hex dependency).

use core::fmt;

/// Encodes bytes as lowercase hex.
pub fn encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// Error returned by [`decode`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HexError {
    /// The input length was not a multiple of two.
    OddLength,
    /// A character was not a hex digit.
    InvalidCharacter { index: usize, ch: char },
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HexError::OddLength => write!(f, "hex string has odd length"),
            HexError::InvalidCharacter { index, ch } => {
                write!(f, "invalid hex character '{ch}' at index {index}")
            }
        }
    }
}

impl std::error::Error for HexError {}

/// Decodes lowercase or uppercase hex into bytes.
pub fn decode(s: &str) -> Result<Vec<u8>, HexError> {
    if !s.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    fn nibble(c: u8) -> Result<u8, HexError> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            b'A'..=b'F' => Ok(c - b'A' + 10),
            _ => Err(HexError::InvalidCharacter {
                index: 0,
                ch: c as char,
            }),
        }
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for i in (0..bytes.len()).step_by(2) {
        let hi = nibble(bytes[i]).map_err(|mut e| {
            if let HexError::InvalidCharacter { index, .. } = &mut e {
                *index = i;
            }
            e
        })?;
        let lo = nibble(bytes[i + 1]).map_err(|mut e| {
            if let HexError::InvalidCharacter { index, .. } = &mut e {
                *index = i + 1;
            }
            e
        })?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let data: Vec<u8> = (0u8..=255).collect();
        let s = encode(&data);
        assert_eq!(s.len(), 512);
        assert_eq!(decode(&s).unwrap(), data);
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_errors() {
        assert_eq!(decode("abc"), Err(HexError::OddLength));
        assert_eq!(
            decode("zz"),
            Err(HexError::InvalidCharacter { index: 0, ch: 'z' })
        );
    }
}
