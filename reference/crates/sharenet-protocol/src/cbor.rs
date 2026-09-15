//! ShareNet Canonical CBOR Profile v1 (work item R1-002).
//!
//! This is the ONE wire serialization path for ShareNet: every normative wire object that
//! follows in the protocol registry (Advertisement, LinkAuthentication, RouteProposal,
//! RouteAcceptance, RouteCommitment, Circuit*, Contribution*, ...) MUST serialize through
//! [`encode`] and parse through [`decode`] so the whole network shares one canonical byte
//! image per object. The future cross-language conformance harness (R1-003) pins this
//! profile with the JSON vectors under `tests/vectors/`.
//!
//! # Profile (normative)
//!
//! Value model (the only things that exist on the wire):
//!
//! - [`Value::Int`] — signed 64-bit integer range
//! - [`Value::Bytes`] — byte string
//! - [`Value::Text`] — UTF-8 text string
//! - [`Value::Array`] — array
//! - [`Value::Map`] — map with unique keys, canonically sorted
//! - [`Value::Bool`] — false / true
//! - [`Value::Null`] — null
//!
//! Encoding rules (RFC 8949 core deterministic encoding, restricted by this profile):
//!
//! - integers: minimal-length encoding only (including lengths and tag-number arguments);
//! - strings, arrays and maps: definite lengths only;
//! - map keys: sorted by bytewise lexicographic order of their canonical encodings,
//!   duplicates forbidden. (Note: plain bytewise comparison of the full key encodings is
//!   the ShareNet rule. It coincides with RFC 8949's "shorter key first, then bytewise"
//!   ordering whenever key encodings have equal length, and differs only for
//!   mixed-length key pairs such as `24` vs `-1`; all ShareNet objects use small unsigned
//!   integer keys, where both rules agree. The rule is pinned by the exported vectors.)
//! - text: must be valid UTF-8;
//! - allowed simple values: `false`, `true`, `null` only, each in its single-byte form.
//!
//! Forbidden on the wire (the encoder never produces these; the decoder rejects them with
//! a typed error naming the violation):
//!
//! - tags of any kind (including bignums);
//! - all floats (f16/f32/f64, NaN, infinity);
//! - indefinite lengths (`undefined`-style streaming);
//! - `undefined` and any other simple value;
//! - trailing bytes after a complete top-level item;
//! - non-minimal integer encodings, unsorted or duplicate map keys, invalid UTF-8,
//!   truncated input, empty input.
//!
//! # Strictness law (tested)
//!
//! For every in-profile byte string `B`:
//!
//! - byte-stability: `encode(decode(B)) == B`, and
//! - round-trip: for every encodable value `x`: `decode(encode(x)) == x`.
//!
//! Anything outside the profile is rejected with a typed error ([`DecodeError`] /
//! [`EncodeError`]) that names the violation.
//!
//! # Implementation notes
//!
//! Hand-rolled encoder/decoder over the explicit [`Value`] model: no codec dependency,
//! no `unsafe`, and full control over strictness. Nesting depth is capped at
//! [`MAX_DEPTH`] in both directions so adversarial inputs can be rejected with a typed
//! error instead of exhausting the stack.

use core::fmt;

/// Maximum nesting depth accepted on the wire (and on encode).
///
/// ShareNet wire objects are shallow; a generous fixed cap keeps adversarial deep-nesting
/// inputs from exhausting the stack while still being far above anything legitimate.
pub const MAX_DEPTH: usize = 128;

/// The ShareNet canonical CBOR profile v1 value model.
///
/// Maps are stored as entry lists; the *canonical* form (the only form decoding ever
/// produces, and the form encoding always emits) has entries sorted by the bytewise
/// lexicographic order of the canonical key encodings, with unique keys.
///
/// [`PartialEq`] for the `Map` variant is deliberately order-insensitive (multiset
/// equality over entries), so `decode(encode(x)) == x` holds for every encodable `x`
/// regardless of the order the map was built in.
#[derive(Debug, Clone)]
pub enum Value {
    /// Signed integer (CBOR majors 0/1), i64 range.
    Int(i64),
    /// Byte string (CBOR major 2), definite length.
    Bytes(Vec<u8>),
    /// UTF-8 text string (CBOR major 3), definite length.
    Text(String),
    /// Array (CBOR major 4), definite length.
    Array(Vec<Value>),
    /// Map (CBOR major 5), definite length, canonical key order, unique keys.
    Map(Vec<(Value, Value)>),
    /// `false` / `true` (CBOR simple values 20/21).
    Bool(bool),
    /// `null` (CBOR simple value 22).
    Null,
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Int(a), Value::Int(b)) => a == b,
            (Value::Bytes(a), Value::Bytes(b)) => a == b,
            (Value::Text(a), Value::Text(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b.iter()).all(|(x, y)| x == y)
            }
            (Value::Map(a), Value::Map(b)) => map_entries_eq(a, b),
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Null, Value::Null) => true,
            _ => false,
        }
    }
}

/// Multiset equality for map entries (order-insensitive, duplicate-aware).
fn map_entries_eq(a: &[(Value, Value)], b: &[(Value, Value)]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    fn count(hay: &[(Value, Value)], k: &Value, v: &Value) -> usize {
        hay.iter().filter(|(k2, v2)| k2 == k && v2 == v).count()
    }
    a.iter().all(|(k, v)| count(a, k, v) == count(b, k, v))
}

/// Typed decode violation. Every variant names the exact profile rule that was broken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The input was empty.
    EmptyInput,
    /// More bytes were required to complete the claimed item.
    Truncated {
        /// Byte offset where the incomplete item started (or where input ran out).
        at: usize,
    },
    /// A complete top-level item was followed by extra bytes.
    TrailingBytes {
        /// Offset of the first trailing byte.
        at: usize,
        /// How many trailing bytes were present.
        count: usize,
    },
    /// The header used additional-information bits 28-30, which are reserved.
    ReservedAdditionalInfo {
        /// Offset of the invalid header byte.
        at: usize,
    },
    /// An indefinite-length item was encountered.
    IndefiniteLength {
        /// Offset of the indefinite-length head.
        at: usize,
    },
    /// An integer (or length/tag argument) was not minimally encoded.
    NonMinimalInteger {
        /// Offset of the offending integer head.
        at: usize,
    },
    /// A map key sorted before its predecessor (not canonically sorted).
    UnsortedMapKeys {
        /// Offset of the offending key.
        at: usize,
    },
    /// A map contained the same key twice.
    DuplicateMapKey {
        /// Offset of the duplicate key.
        at: usize,
    },
    /// An integer outside the i64 range accepted by the profile.
    IntegerOutOfRange {
        /// Offset of the offending integer head.
        at: usize,
    },
    /// A CBOR tag (major 6) was encountered.
    TagNotAllowed {
        /// Offset of the tag head.
        at: usize,
        /// The tag number that was found.
        tag: u64,
    },
    /// A floating-point value (f16/f32/f64, incl. NaN/Inf) was encountered.
    FloatNotAllowed {
        /// Offset of the float head.
        at: usize,
    },
    /// The `undefined` simple value (23) was encountered.
    UndefinedNotAllowed {
        /// Offset of the value byte.
        at: usize,
    },
    /// A simple value other than false/true/null (or the two-byte simple form) was found.
    SimpleValueNotAllowed {
        /// Offset of the value byte.
        at: usize,
        /// The simple value that was found.
        value: u8,
    },
    /// A break byte (0xff) appeared outside any indefinite-length context.
    BreakByteNotAllowed {
        /// Offset of the break byte.
        at: usize,
    },
    /// A text string was not valid UTF-8.
    InvalidUtf8 {
        /// Offset of the text head.
        at: usize,
    },
    /// Nesting exceeded [`MAX_DEPTH`].
    DepthLimitExceeded {
        /// Offset of the item that went over the limit.
        at: usize,
        /// The limit that was exceeded.
        limit: usize,
    },
}

impl DecodeError {
    /// Stable machine name of the violation (used by the exported conformance vectors).
    pub fn name(&self) -> &'static str {
        match self {
            DecodeError::EmptyInput => "EmptyInput",
            DecodeError::Truncated { .. } => "Truncated",
            DecodeError::TrailingBytes { .. } => "TrailingBytes",
            DecodeError::ReservedAdditionalInfo { .. } => "ReservedAdditionalInfo",
            DecodeError::IndefiniteLength { .. } => "IndefiniteLength",
            DecodeError::NonMinimalInteger { .. } => "NonMinimalInteger",
            DecodeError::UnsortedMapKeys { .. } => "UnsortedMapKeys",
            DecodeError::DuplicateMapKey { .. } => "DuplicateMapKey",
            DecodeError::IntegerOutOfRange { .. } => "IntegerOutOfRange",
            DecodeError::TagNotAllowed { .. } => "TagNotAllowed",
            DecodeError::FloatNotAllowed { .. } => "FloatNotAllowed",
            DecodeError::UndefinedNotAllowed { .. } => "UndefinedNotAllowed",
            DecodeError::SimpleValueNotAllowed { .. } => "SimpleValueNotAllowed",
            DecodeError::BreakByteNotAllowed { .. } => "BreakByteNotAllowed",
            DecodeError::InvalidUtf8 { .. } => "InvalidUtf8",
            DecodeError::DepthLimitExceeded { .. } => "DepthLimitExceeded",
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::EmptyInput => write!(f, "empty input: exactly one canonical CBOR data item is required"),
            DecodeError::Truncated { at } => write!(f, "truncated input at byte offset {at}: more bytes are required to complete the data item"),
            DecodeError::TrailingBytes { at, count } => write!(f, "trailing bytes after the top-level data item: {count} extra byte(s) starting at offset {at}"),
            DecodeError::ReservedAdditionalInfo { at } => write!(f, "reserved additional-information bits in the header at offset {at}"),
            DecodeError::IndefiniteLength { at } => write!(f, "indefinite-length encoding at offset {at} is forbidden by the ShareNet canonical CBOR profile"),
            DecodeError::NonMinimalInteger { at } => write!(f, "integer or length at offset {at} is not minimally encoded"),
            DecodeError::UnsortedMapKeys { at } => write!(f, "map keys are not canonically sorted (key at offset {at} sorts before its predecessor)"),
            DecodeError::DuplicateMapKey { at } => write!(f, "duplicate map key at offset {at}"),
            DecodeError::IntegerOutOfRange { at } => write!(f, "integer at offset {at} is outside the i64 range accepted by the ShareNet profile"),
            DecodeError::TagNotAllowed { at, tag } => write!(f, "CBOR tag {tag} at offset {at} is forbidden by the ShareNet canonical CBOR profile"),
            DecodeError::FloatNotAllowed { at } => write!(f, "floating-point value at offset {at} is forbidden by the ShareNet canonical CBOR profile"),
            DecodeError::UndefinedNotAllowed { at } => write!(f, "`undefined` at offset {at} is forbidden by the ShareNet canonical CBOR profile"),
            DecodeError::SimpleValueNotAllowed { at, value } => write!(f, "simple value {value} at offset {at} is not one of false/true/null, or uses the forbidden two-byte simple form"),
            DecodeError::BreakByteNotAllowed { at } => write!(f, "unexpected break byte 0xff at offset {at}"),
            DecodeError::InvalidUtf8 { at } => write!(f, "text string at offset {at} is not valid UTF-8"),
            DecodeError::DepthLimitExceeded { at, limit } => write!(f, "nesting depth exceeds the profile limit of {limit} (item at offset {at})"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Typed encode violation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodeError {
    /// The value contained two map keys with the same canonical encoding.
    DuplicateMapKey {
        /// Index of the duplicate entry in the source map.
        index: usize,
    },
    /// The value nests deeper than [`MAX_DEPTH`].
    DepthLimitExceeded {
        /// The limit that was exceeded.
        limit: usize,
    },
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::DuplicateMapKey { index } => {
                write!(
                    f,
                    "map contains duplicate key(s) (duplicate at entry index {index})"
                )
            }
            EncodeError::DepthLimitExceeded { limit } => {
                write!(f, "value nests deeper than the profile limit of {limit}")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// Encode a value to its canonical ShareNet CBOR byte image.
///
/// Maps are canonicalized: entries are emitted sorted by the bytewise lexicographic order
/// of their encoded keys, regardless of the order they were inserted in. Duplicate keys
/// (identical canonical encodings) are an [`EncodeError::DuplicateMapKey`].
pub fn encode(value: &Value) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    write_value(value, &mut out, 1)?;
    Ok(out)
}

/// Decode exactly one canonical ShareNet CBOR data item from `bytes`.
///
/// Every profile rule is enforced (see the module documentation). On success the decoded
/// value is guaranteed to re-encode to exactly the input bytes.
pub fn decode(bytes: &[u8]) -> Result<Value, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::EmptyInput);
    }
    let mut r = Reader { buf: bytes, pos: 0 };
    let value = read_value(&mut r, 1)?;
    if r.pos != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            at: r.pos,
            count: bytes.len() - r.pos,
        });
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

fn write_value(value: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), EncodeError> {
    if depth > MAX_DEPTH {
        return Err(EncodeError::DepthLimitExceeded { limit: MAX_DEPTH });
    }
    match value {
        Value::Int(i) => {
            if *i >= 0 {
                write_head(0, *i as u64, out);
            } else {
                // -1 - i is in [0, 2^63-1] for every negative i64; no overflow occurs
                // because the mathematical result always fits (i64::MIN maps to 2^63-1).
                write_head(1, (-1 - *i) as u64, out);
            }
        }
        Value::Bytes(b) => {
            write_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            let b = s.as_bytes();
            write_head(3, b.len() as u64, out);
            out.extend_from_slice(b);
        }
        Value::Array(items) => {
            write_head(4, items.len() as u64, out);
            for item in items {
                write_value(item, out, depth + 1)?;
            }
        }
        Value::Map(entries) => {
            // Canonicalize: encode each key, sort by canonical key bytes, reject duplicates.
            let mut keyed: Vec<(Vec<u8>, usize)> = Vec::with_capacity(entries.len());
            for (i, (k, _)) in entries.iter().enumerate() {
                let mut kb = Vec::new();
                write_value(k, &mut kb, depth + 1)?;
                keyed.push((kb, i));
            }
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            for pair in keyed.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(EncodeError::DuplicateMapKey { index: pair[1].1 });
                }
            }
            write_head(5, entries.len() as u64, out);
            for (key_bytes, i) in keyed {
                out.extend_from_slice(&key_bytes);
                let (_, v) = &entries[i];
                write_value(v, out, depth + 1)?;
            }
        }
        Value::Bool(true) => out.push(0xf5),
        Value::Bool(false) => out.push(0xf4),
        Value::Null => out.push(0xf6),
    }
    Ok(())
}

/// Minimal-length head for a given major type and unsigned argument.
fn write_head(major: u8, arg: u64, out: &mut Vec<u8>) {
    let m = major << 5;
    if arg <= 23 {
        out.push(m | arg as u8);
    } else if arg <= 0xFF {
        out.push(m | 24);
        out.push(arg as u8);
    } else if arg <= 0xFFFF {
        out.push(m | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xFFFF_FFFF {
        out.push(m | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(m | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self) -> Result<u8, DecodeError> {
        let b = *self
            .buf
            .get(self.pos)
            .ok_or(DecodeError::Truncated { at: self.pos })?;
        self.pos += 1;
        Ok(b)
    }

    /// Take exactly `n` bytes, failing with a typed truncation error if unavailable.
    /// `n` is only ever a length that fits in the remaining input (checked by callers),
    /// so this never attempts oversized allocations.
    fn take_n(&mut self, n: u64) -> Result<&'a [u8], DecodeError> {
        let avail = (self.buf.len() - self.pos) as u64;
        if n > avail {
            return Err(DecodeError::Truncated { at: self.pos });
        }
        let n = n as usize; // <= avail <= isize::MAX
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

/// Read the unsigned argument that follows a head byte.
///
/// Enforces the minimal-length rule for every argument class (integers, lengths,
/// tag numbers): a wider encoding that could have used a narrower one is rejected.
fn read_arg(r: &mut Reader<'_>, ai: u8, at: usize) -> Result<u64, DecodeError> {
    match ai {
        0..=23 => Ok(ai as u64),
        24 => {
            let b = r.take()?;
            if b <= 23 {
                return Err(DecodeError::NonMinimalInteger { at });
            }
            Ok(b as u64)
        }
        25 => {
            let s = r.take_n(2)?;
            let v = u16::from_be_bytes([s[0], s[1]]) as u64;
            if v <= 0xFF {
                return Err(DecodeError::NonMinimalInteger { at });
            }
            Ok(v)
        }
        26 => {
            let s = r.take_n(4)?;
            let v = u32::from_be_bytes([s[0], s[1], s[2], s[3]]) as u64;
            if v <= 0xFFFF {
                return Err(DecodeError::NonMinimalInteger { at });
            }
            Ok(v)
        }
        27 => {
            let s = r.take_n(8)?;
            let v = u64::from_be_bytes([s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7]]);
            if v <= 0xFFFF_FFFF {
                return Err(DecodeError::NonMinimalInteger { at });
            }
            Ok(v)
        }
        28..=30 => Err(DecodeError::ReservedAdditionalInfo { at }),
        // 31: for major types 0/1 this is not a valid argument form; majors 2-5 have
        // already been routed to read_len, major 6 lands here, major 7 handles its own.
        31 => Err(DecodeError::ReservedAdditionalInfo { at }),
        _ => unreachable!("additional info is 5 bits"),
    }
}

/// Read a length (or count) argument for major types 2-5: definite only.
fn read_len(r: &mut Reader<'_>, ai: u8, at: usize) -> Result<u64, DecodeError> {
    if ai == 31 {
        return Err(DecodeError::IndefiniteLength { at });
    }
    read_arg(r, ai, at)
}

fn read_value(r: &mut Reader<'_>, depth: usize) -> Result<Value, DecodeError> {
    if depth > MAX_DEPTH {
        return Err(DecodeError::DepthLimitExceeded {
            at: r.pos,
            limit: MAX_DEPTH,
        });
    }
    let at = r.pos;
    let ib = r.take()?;
    let major = ib >> 5;
    let ai = ib & 0x1f;
    match major {
        0 => {
            let n = read_arg(r, ai, at)?;
            if n > i64::MAX as u64 {
                return Err(DecodeError::IntegerOutOfRange { at });
            }
            Ok(Value::Int(n as i64))
        }
        1 => {
            let n = read_arg(r, ai, at)?;
            if n > i64::MAX as u64 {
                return Err(DecodeError::IntegerOutOfRange { at });
            }
            // -1 - n with n <= i64::MAX always lands in i64 range (i64::MIN at worst).
            Ok(Value::Int(-1 - n as i64))
        }
        2 => {
            let len = read_len(r, ai, at)?;
            let bytes = r.take_n(len)?;
            Ok(Value::Bytes(bytes.to_vec()))
        }
        3 => {
            let len = read_len(r, ai, at)?;
            let bytes = r.take_n(len)?;
            let s =
                String::from_utf8(bytes.to_vec()).map_err(|_| DecodeError::InvalidUtf8 { at })?;
            Ok(Value::Text(s))
        }
        4 => {
            let n = read_len(r, ai, at)?;
            // Never preallocate from the claimed count: items are read one at a time and
            // truncation fails fast, so a huge claimed length cannot force a huge alloc.
            let mut items = Vec::new();
            for _ in 0..n {
                items.push(read_value(r, depth + 1)?);
            }
            Ok(Value::Array(items))
        }
        5 => {
            let n = read_len(r, ai, at)?;
            let mut entries: Vec<(Value, Value)> = Vec::new();
            let mut prev_key: Option<(usize, usize)> = None; // byte range of previous key
            for _ in 0..n {
                let key_start = r.pos;
                let k = read_value(r, depth + 1)?;
                let key_end = r.pos;
                if let Some((ps, pe)) = prev_key {
                    let prev = &r.buf[ps..pe];
                    let cur = &r.buf[key_start..key_end];
                    // The key items themselves are strict-canonical (decoded recursively),
                    // so their raw wire bytes are exactly their canonical encodings.
                    if cur == prev {
                        return Err(DecodeError::DuplicateMapKey { at: key_start });
                    }
                    if cur < prev {
                        return Err(DecodeError::UnsortedMapKeys { at: key_start });
                    }
                }
                let v = read_value(r, depth + 1)?;
                entries.push((k, v));
                prev_key = Some((key_start, key_end));
            }
            Ok(Value::Map(entries))
        }
        6 => {
            let tag = read_arg(r, ai, at)?;
            Err(DecodeError::TagNotAllowed { at, tag })
        }
        7 => match ai {
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            23 => Err(DecodeError::UndefinedNotAllowed { at }),
            24 => {
                // Two-byte simple-value form: forbidden entirely (it is also the
                // non-canonical encoding of false/true/null when the payload is 20/21/22).
                let v = r.take()?;
                Err(DecodeError::SimpleValueNotAllowed { at, value: v })
            }
            25..=27 => Err(DecodeError::FloatNotAllowed { at }),
            28..=30 => Err(DecodeError::ReservedAdditionalInfo { at }),
            31 => Err(DecodeError::BreakByteNotAllowed { at }),
            _ => Err(DecodeError::SimpleValueNotAllowed { at, value: ai }),
        },
        _ => unreachable!("major type is 3 bits"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(hex: &str, expected: &Value) {
        let bytes = crate::testutil::from_hex(hex);
        let v = decode(&bytes).unwrap_or_else(|e| panic!("decode({hex}) failed: {e}"));
        assert_eq!(&v, expected, "decoded value for {hex}");
        let re = encode(&v).unwrap_or_else(|e| panic!("encode of {hex} failed: {e}"));
        assert_eq!(re, bytes, "byte-stability for {hex}");
        let v2 = decode(&re).unwrap();
        assert_eq!(v2, v);
    }

    #[test]
    fn basic_vectors_roundtrip() {
        rt("00", &Value::Int(0));
        rt("01", &Value::Int(1));
        rt("17", &Value::Int(23));
        rt("1818", &Value::Int(24));
        rt("1903e8", &Value::Int(1000));
        rt("20", &Value::Int(-1));
        rt("3863", &Value::Int(-100));
        rt("f4", &Value::Bool(false));
        rt("f5", &Value::Bool(true));
        rt("f6", &Value::Null);
        rt("4401020304", &Value::Bytes(vec![1, 2, 3, 4]));
        rt("6449455446", &Value::Text("IETF".to_string()));
        rt("80", &Value::Array(vec![]));
        rt(
            "83010203",
            &Value::Array(vec![Value::Int(1), Value::Int(2), Value::Int(3)]),
        );
        rt(
            "a201020304",
            &Value::Map(vec![
                (Value::Int(1), Value::Int(2)),
                (Value::Int(3), Value::Int(4)),
            ]),
        );
    }

    #[test]
    fn i64_boundaries() {
        rt("1b7fffffffffffffff", &Value::Int(i64::MAX));
        rt("3b7fffffffffffffff", &Value::Int(i64::MIN));
        assert_eq!(
            decode(&[0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Err(DecodeError::IntegerOutOfRange { at: 0 })
        );
        assert_eq!(
            decode(&[0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            Err(DecodeError::IntegerOutOfRange { at: 0 })
        );
    }

    #[test]
    fn map_encode_sorts_and_rejects_dups() {
        let unsorted = Value::Map(vec![
            (Value::Int(3), Value::Int(4)),
            (Value::Int(1), Value::Int(2)),
        ]);
        assert_eq!(
            encode(&unsorted).unwrap(),
            crate::testutil::from_hex("a201020304")
        );
        let dup = Value::Map(vec![
            (Value::Int(1), Value::Int(2)),
            (Value::Int(1), Value::Int(3)),
        ]);
        assert_eq!(encode(&dup), Err(EncodeError::DuplicateMapKey { index: 1 }));
    }

    #[test]
    fn map_equality_is_order_insensitive() {
        let a = Value::Map(vec![
            (Value::Int(1), Value::Int(2)),
            (Value::Int(3), Value::Int(4)),
        ]);
        let b = Value::Map(vec![
            (Value::Int(3), Value::Int(4)),
            (Value::Int(1), Value::Int(2)),
        ]);
        assert_eq!(a, b);
    }

    #[test]
    fn empty_and_trailing() {
        assert_eq!(decode(&[]), Err(DecodeError::EmptyInput));
        assert_eq!(
            decode(&[0x00, 0x00]),
            Err(DecodeError::TrailingBytes { at: 1, count: 1 })
        );
    }

    #[test]
    fn deep_nesting_enforced() {
        let ok = {
            let mut b = vec![0x81; 127];
            b.push(0x00);
            b
        };
        assert!(decode(&ok).is_ok());
        let too_deep = {
            let mut b = vec![0x81; 128];
            b.push(0x00);
            b
        };
        match decode(&too_deep) {
            Err(DecodeError::DepthLimitExceeded { limit, .. }) => assert_eq!(limit, MAX_DEPTH),
            other => panic!("expected DepthLimitExceeded, got {other:?}"),
        }
    }
}
