//! ShareNet Canonical CBOR Profile v1 — strict encoder/decoder.
//!
//! This is the single canonical wire encoding for every ShareNet normative
//! wire object (see `spec/protocol-registry.yaml`: NodeIdentity, Advertisement,
//! LinkAuthentication, Route*, Contribution*, ...). Every future wire object
//! MUST serialize through this module. There is no second encoder.
//!
//! # Value model
//!
//! ```text
//! Int (i64 range) | Bytes | Text | Array | Map (keys unique, canonically sorted)
//! | Bool | Null
//! ```
//!
//! # Wire rules (RFC 8949 core deterministic encoding + ShareNet profile)
//!
//! - integers: minimal-length encoding only;
//! - byte strings, text strings, arrays, maps: definite lengths only;
//! - map keys: unique, sorted by bytewise lexicographic order of their
//!   canonical encodings;
//! - text: must be valid UTF-8;
//! - allowed simple values: `false`, `true`, `null` ONLY;
//! - forbidden on the wire (decoder rejects, encoder cannot produce):
//!   tags (including bignums), all floats (f16/f32/f64, NaN, ±Inf),
//!   indefinite lengths, `undefined`, other simple values, and trailing
//!   bytes after a complete top-level item.
//!
//! # Strictness law
//!
//! For every in-profile byte string `B`:
//!
//! ```text
//! encode(decode(B)) == B        (byte-stability)
//! decode(encode(x)) == x        (round-trip)
//! ```
//!
//! Anything out of profile is rejected with a typed [`DecodeError`] naming the
//! violation. The encoder is canonical by construction: the value model cannot
//! represent floats, tags, indefinite lengths or `undefined`, and map entries
//! are emitted sorted with duplicate keys rejected.
//!
//! # Implementation protection
//!
//! The decoder enforces a structural depth limit ([`MAX_DEPTH`]) and rejects
//! declared definite lengths that exceed the remaining input, so hostile
//! inputs fail closed instead of exhausting memory or the stack. Inputs deeper
//! than [`MAX_DEPTH`] are rejected with [`DecodeError::DepthLimitExceeded`].

use core::fmt;

/// Maximum structural nesting depth accepted by the encoder and decoder.
///
/// This is an implementation-level DoS protection; it does not loosen any
/// canonicality rule. Wire objects defined by ShareNet are shallow maps.
pub const MAX_DEPTH: usize = 256;

/// A ShareNet canonical-CBOR value.
///
/// `Value::Map` entries are stored in canonical order (keys sorted by the
/// bytewise lexicographic order of their canonical encodings, no duplicates)
/// when produced by [`MapBuilder::build`], [`decode`] or [`canonicalize_map`].
/// [`encode`] always emits canonically sorted keys and rejects duplicates,
/// regardless of entry order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// Integer in the i64 range (major types 0 and 1).
    Int(i64),
    /// Definite-length byte string.
    Bytes(Vec<u8>),
    /// Definite-length text string (always valid UTF-8).
    Text(String),
    /// Definite-length array.
    Array(Vec<Value>),
    /// Definite-length map with unique, canonically sorted keys.
    Map(Vec<(Value, Value)>),
    /// Boolean (`false`/`true`).
    Bool(bool),
    /// Null.
    Null,
}

impl Value {
    /// Returns the integer value if this is `Value::Int`.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    /// Returns the byte string if this is `Value::Bytes`.
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    /// Returns the text if this is `Value::Text`.
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(s) => Some(s),
            _ => None,
        }
    }

    /// Returns the array elements if this is `Value::Array`.
    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    /// Returns the map entries if this is `Value::Map`.
    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(entries) => Some(entries),
            _ => None,
        }
    }

    /// Returns `true` if this is `Value::Null`.
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    /// Looks up an integer-keyed map entry.
    ///
    /// Intended for ShareNet wire objects that use compact integer keys
    /// (e.g. NodeIdentity keys 1..=4).
    pub fn get_by_int(&self, key: i64) -> Option<&Value> {
        let entries = self.as_map()?;
        entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Int(i) if *i == key))
            .map(|(_, v)| v)
    }

    /// Looks up a text-keyed map entry.
    pub fn get_by_text(&self, key: &str) -> Option<&Value> {
        let entries = self.as_map()?;
        entries
            .iter()
            .find(|(k, _)| matches!(k, Value::Text(s) if s == key))
            .map(|(_, v)| v)
    }
}

/// Builds a canonical `Value::Map` (sorted unique keys).
///
/// Example:
///
/// ```
/// use sharenet_protocol::cbor::{MapBuilder, Value};
///
/// let v = MapBuilder::new()
///     .insert_int(1, Value::Int(1))
///     .insert_int(2, Value::Bytes(vec![0xAA; 32]))
///     .insert_text("note", Value::Text("hello".into()))
///     .build()
///     .unwrap();
/// ```
#[derive(Clone, Debug, Default)]
pub struct MapBuilder {
    entries: Vec<(Value, Value)>,
}

impl MapBuilder {
    /// Creates an empty map builder.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Appends an integer-keyed entry.
    pub fn insert_int(mut self, key: i64, value: Value) -> Self {
        self.entries.push((Value::Int(key), value));
        self
    }

    /// Appends a text-keyed entry.
    pub fn insert_text(self, key: &str, value: Value) -> Self {
        self.insert(Value::Text(key.to_string()), value)
    }

    /// Appends an arbitrary-keyed entry.
    pub fn insert(mut self, key: Value, value: Value) -> Self {
        self.entries.push((key, value));
        self
    }

    /// Finishes the map, returning a [`Value::Map`] with canonically sorted,
    /// unique keys, or a typed error on duplicate keys.
    pub fn build(self) -> Result<Value, EncodeError> {
        canonicalize_map(self.entries)
    }
}

/// Sorts map entries canonically and rejects duplicate keys.
///
/// Returns a `Value::Map` whose entries are ordered by the bytewise
/// lexicographic order of the canonical encodings of the keys. Duplicate keys
/// are rejected with [`EncodeError::DuplicateMapKey`].
pub fn canonicalize_map(mut entries: Vec<(Value, Value)>) -> Result<Value, EncodeError> {
    let mut keyed: Vec<(Vec<u8>, usize)> = Vec::with_capacity(entries.len());
    for (idx, (k, _)) in entries.iter().enumerate() {
        let mut bytes = Vec::new();
        encode_at(k, &mut bytes, 0)?;
        keyed.push((bytes, idx));
    }
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    for pair in keyed.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(EncodeError::DuplicateMapKey);
        }
    }
    let mut sorted: Vec<(Value, Value)> = Vec::with_capacity(entries.len());
    for (_, idx) in keyed {
        sorted.push(std::mem::replace(
            &mut entries[idx],
            (Value::Null, Value::Null),
        ));
    }
    Ok(Value::Map(sorted))
}

/// Typed encoder failure. The encoder cannot produce out-of-profile bytes;
/// the only possible failures are duplicate map keys or exceeding
/// [`MAX_DEPTH`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// Two entries of a map encode to the same canonical key bytes.
    DuplicateMapKey,
    /// The value nests deeper than [`MAX_DEPTH`].
    DepthLimitExceeded,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EncodeError::DuplicateMapKey => write!(
                f,
                "duplicate map key: map keys must be unique in the ShareNet CBOR profile"
            ),
            EncodeError::DepthLimitExceeded => write!(
                f,
                "value exceeds maximum nesting depth {MAX_DEPTH}"
            ),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Typed decoder failure. Every variant names the exact profile violation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The input is empty.
    EmptyInput,
    /// The input ends in the middle of an item that declared more bytes.
    UnexpectedEnd { at: usize, needed: usize },
    /// An integer argument (value or definite length) was not minimally encoded.
    NonMinimalInteger { at: usize },
    /// An indefinite length (additional info 31) was found; forbidden.
    IndefiniteLength { at: usize },
    /// A break stop code (0xFF) appeared outside an indefinite item.
    BreakCode { at: usize },
    /// Additional info 28..=30 is reserved in RFC 8949 and rejected here.
    ReservedAdditionalInfo { at: usize, info: u8 },
    /// A tag (major type 6) was found; tags are forbidden on the wire.
    TagForbidden { at: usize, tag: u64 },
    /// A float (f16/f32/f64) was found; all floats are forbidden.
    FloatForbidden { at: usize, width_bytes: usize },
    /// A simple value other than false/true/null was found (includes `undefined`).
    SimpleValueForbidden { at: usize, value: u8 },
    /// A text string contained invalid UTF-8.
    InvalidUtf8 { at: usize },
    /// Map keys were not in canonical bytewise sorted order.
    UnsortedMapKeys { at: usize },
    /// A map contained two entries with identical canonical key encodings.
    DuplicateMapKey { at: usize },
    /// An unsigned integer exceeded the i64 range of the value model.
    IntegerOutOfRange { at: usize, raw: u64 },
    /// A negative integer exceeded the i64 range of the value model.
    IntegerNegativeOutOfRange { at: usize, raw: u64 },
    /// Structural nesting exceeded [`MAX_DEPTH`].
    DepthLimitExceeded { at: usize },
    /// A declared definite length exceeds the remaining input.
    LengthExceedsInput { at: usize, declared: u64 },
    /// Extra bytes followed the complete top-level item.
    TrailingBytes { at: usize, count: usize },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::EmptyInput => write!(f, "empty input: at least one byte is required"),
            DecodeError::UnexpectedEnd { at, needed } => write!(
                f,
                "truncated input at byte offset {at}: {needed} more byte(s) were declared but the input ends"
            ),
            DecodeError::NonMinimalInteger { at } => write!(
                f,
                "non-minimal integer encoding at byte offset {at}: integers and definite lengths must use the shortest form"
            ),
            DecodeError::IndefiniteLength { at } => write!(
                f,
                "indefinite length at byte offset {at}: only definite lengths are allowed"
            ),
            DecodeError::BreakCode { at } => write!(
                f,
                "unexpected break code 0xFF at byte offset {at}"
            ),
            DecodeError::ReservedAdditionalInfo { at, info } => write!(
                f,
                "reserved additional-info value {info} at byte offset {at}"
            ),
            DecodeError::TagForbidden { at, tag } => write!(
                f,
                "CBOR tag {tag} at byte offset {at}: tags (including bignums) are forbidden on the ShareNet wire"
            ),
            DecodeError::FloatForbidden { at, width_bytes } => write!(
                f,
                "float value (width {width_bytes} bytes) at byte offset {at}: all floats (f16/f32/f64, NaN, Inf) are forbidden"
            ),
            DecodeError::SimpleValueForbidden { at, value } => write!(
                f,
                "simple value {value} at byte offset {at}: only false, true and null are allowed"
            ),
            DecodeError::InvalidUtf8 { at } => write!(
                f,
                "invalid UTF-8 in text string starting at byte offset {at}"
            ),
            DecodeError::UnsortedMapKeys { at } => write!(
                f,
                "unsorted map keys at byte offset {at}: keys must be sorted by the bytewise lexicographic order of their canonical encodings"
            ),
            DecodeError::DuplicateMapKey { at } => write!(
                f,
                "duplicate map key at byte offset {at}: map keys must be unique"
            ),
            DecodeError::IntegerOutOfRange { at, raw } => write!(
                f,
                "unsigned integer {raw} at byte offset {at} exceeds the i64 range of the ShareNet value model"
            ),
            DecodeError::IntegerNegativeOutOfRange { at, raw } => write!(
                f,
                "negative integer encoding {raw} at byte offset {at} exceeds the i64 range of the ShareNet value model"
            ),
            DecodeError::DepthLimitExceeded { at } => write!(
                f,
                "nesting deeper than {MAX_DEPTH} at byte offset {at}"
            ),
            DecodeError::LengthExceedsInput { at, declared } => write!(
                f,
                "declared definite length {declared} at byte offset {at} exceeds the remaining input"
            ),
            DecodeError::TrailingBytes { at, count } => write!(
                f,
                "{count} trailing byte(s) after the complete top-level item at byte offset {at}: trailing bytes are forbidden"
            ),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encodes a value to canonical ShareNet CBOR bytes.
pub fn encode(value: &Value) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    encode_at(value, &mut out, 0)?;
    Ok(out)
}

/// Encodes a value into an existing buffer (canonical bytes).
pub fn encode_into(value: &Value, out: &mut Vec<u8>) -> Result<(), EncodeError> {
    encode_at(value, out, 0)
}

/// Decodes exactly one canonical value from `bytes`.
///
/// Fails (typed) on any profile violation, including trailing bytes and
/// truncated input.
pub fn decode(bytes: &[u8]) -> Result<Value, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError::EmptyInput);
    }
    let mut dec = Decoder { buf: bytes, pos: 0 };
    let value = dec.parse(0)?;
    if dec.pos != bytes.len() {
        return Err(DecodeError::TrailingBytes {
            at: dec.pos,
            count: bytes.len() - dec.pos,
        });
    }
    Ok(value)
}

fn encode_at(value: &Value, out: &mut Vec<u8>, depth: usize) -> Result<(), EncodeError> {
    if depth > MAX_DEPTH {
        return Err(EncodeError::DepthLimitExceeded);
    }
    match value {
        Value::Int(i) => {
            if *i >= 0 {
                encode_head(out, 0, *i as u64);
            } else {
                // -1 - i is at most i64::MAX (when i == i64::MIN), so this
                // cannot overflow.
                encode_head(out, 1, (-1 - *i) as u64);
            }
        }
        Value::Bytes(b) => {
            encode_head(out, 2, b.len() as u64);
            out.extend_from_slice(b);
        }
        Value::Text(s) => {
            encode_head(out, 3, s.len() as u64);
            out.extend_from_slice(s.as_bytes());
        }
        Value::Array(items) => {
            encode_head(out, 4, items.len() as u64);
            for item in items {
                encode_at(item, out, depth + 1)?;
            }
        }
        Value::Map(entries) => {
            // Encode every key once, sort entries by canonical key bytes,
            // reject duplicates, then emit. This guarantees the wire form is
            // canonical regardless of the in-memory entry order.
            let mut keyed: Vec<(Vec<u8>, usize)> = Vec::with_capacity(entries.len());
            for (idx, (k, _)) in entries.iter().enumerate() {
                let mut kb = Vec::new();
                encode_at(k, &mut kb, depth + 1)?;
                keyed.push((kb, idx));
            }
            keyed.sort_by(|a, b| a.0.cmp(&b.0));
            for pair in keyed.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(EncodeError::DuplicateMapKey);
                }
            }
            encode_head(out, 5, entries.len() as u64);
            for (kb, idx) in keyed {
                out.extend_from_slice(&kb);
                encode_at(&entries[idx].1, out, depth + 1)?;
            }
        }
        Value::Bool(false) => out.push(0xF4),
        Value::Bool(true) => out.push(0xF5),
        Value::Null => out.push(0xF6),
    }
    Ok(())
}

fn encode_head(out: &mut Vec<u8>, major: u8, arg: u64) {
    let mt = major << 5;
    if arg <= 23 {
        out.push(mt | arg as u8);
    } else if arg <= 0xFF {
        out.push(mt | 24);
        out.push(arg as u8);
    } else if arg <= 0xFFFF {
        out.push(mt | 25);
        out.extend_from_slice(&(arg as u16).to_be_bytes());
    } else if arg <= 0xFFFF_FFFF {
        out.push(mt | 26);
        out.extend_from_slice(&(arg as u32).to_be_bytes());
    } else {
        out.push(mt | 27);
        out.extend_from_slice(&arg.to_be_bytes());
    }
}

struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Parses one value, enforcing every canonicality rule.
    fn parse(&mut self, depth: usize) -> Result<Value, DecodeError> {
        if depth > MAX_DEPTH {
            return Err(DecodeError::DepthLimitExceeded { at: self.pos });
        }
        let at = self.pos;
        if self.pos >= self.buf.len() {
            return Err(DecodeError::UnexpectedEnd { at, needed: 1 });
        }
        let initial = self.buf[self.pos];
        self.pos += 1;
        let major = initial >> 5;
        let info = initial & 0x1F;
        match major {
            0 => {
                let v = self.read_arg(info, at)?;
                if v > i64::MAX as u64 {
                    return Err(DecodeError::IntegerOutOfRange { at, raw: v });
                }
                Ok(Value::Int(v as i64))
            }
            1 => {
                let v = self.read_arg(info, at)?;
                // Encodes -(v+1); must be >= i64::MIN, i.e. v <= i64::MAX.
                if v > i64::MAX as u64 {
                    return Err(DecodeError::IntegerNegativeOutOfRange { at, raw: v });
                }
                Ok(Value::Int(-1 - v as i64))
            }
            2 => {
                let len = self.read_definite_length(info, at)?;
                let end = self
                    .pos
                    .checked_add(len)
                    .ok_or(DecodeError::LengthExceedsInput { at, declared: u64::MAX })?;
                if end > self.buf.len() {
                    return Err(DecodeError::LengthExceedsInput { at, declared: len as u64 });
                }
                let b = self.buf[self.pos..end].to_vec();
                self.pos = end;
                Ok(Value::Bytes(b))
            }
            3 => {
                let len = self.read_definite_length(info, at)?;
                let end = self
                    .pos
                    .checked_add(len)
                    .ok_or(DecodeError::LengthExceedsInput { at, declared: u64::MAX })?;
                if end > self.buf.len() {
                    return Err(DecodeError::LengthExceedsInput { at, declared: len as u64 });
                }
                let s = std::str::from_utf8(&self.buf[self.pos..end])
                    .map_err(|_| DecodeError::InvalidUtf8 { at })?
                    .to_string();
                self.pos = end;
                Ok(Value::Text(s))
            }
            4 => {
                let count = self.read_count(info, at)?;
                let mut items = Vec::new();
                for _ in 0..count {
                    items.push(self.parse(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let count = self.read_count(info, at)?;
                let mut entries: Vec<(Value, Value)> = Vec::new();
                let mut prev_key: Option<Vec<u8>> = None;
                for _ in 0..count {
                    let key_at = self.pos;
                    let key = self.parse(depth + 1)?;
                    // Re-encoding a decoded key cannot fail: the decoder has
                    // already enforced depth <= MAX_DEPTH and no duplicate
                    // keys can exist inside a freshly decoded value.
                    let key_bytes =
                        encode(&key).expect("canonical re-encode of a decoded value");
                    if let Some(prev) = &prev_key {
                        if key_bytes == *prev {
                            return Err(DecodeError::DuplicateMapKey { at: key_at });
                        }
                        if key_bytes < *prev {
                            return Err(DecodeError::UnsortedMapKeys { at: key_at });
                        }
                    }
                    prev_key = Some(key_bytes);
                    let value = self.parse(depth + 1)?;
                    entries.push((key, value));
                }
                Ok(Value::Map(entries))
            }
            6 => {
                let tag = self.read_arg(info, at)?;
                Err(DecodeError::TagForbidden { at, tag })
            }
            _ => self.parse_simple(info, at),
        }
    }

    fn parse_simple(&mut self, info: u8, at: usize) -> Result<Value, DecodeError> {
        match info {
            20 => Ok(Value::Bool(false)),
            21 => Ok(Value::Bool(true)),
            22 => Ok(Value::Null),
            23 => Err(DecodeError::SimpleValueForbidden { at, value: 23 }), // undefined
            24 => {
                // Two-byte simple value: consume the extension byte so error
                // offsets stay meaningful, then reject.
                if self.pos >= self.buf.len() {
                    return Err(DecodeError::UnexpectedEnd { at, needed: 1 });
                }
                let ext = self.buf[self.pos];
                self.pos += 1;
                Err(DecodeError::SimpleValueForbidden { at, value: ext })
            }
            25..=27 => {
                let width = match info {
                    25 => 2usize,
                    26 => 4,
                    _ => 8,
                };
                if self.pos + width > self.buf.len() {
                    return Err(DecodeError::UnexpectedEnd {
                        at,
                        needed: width,
                    });
                }
                self.pos += width;
                Err(DecodeError::FloatForbidden { at, width_bytes: width })
            }
            28..=30 => Err(DecodeError::ReservedAdditionalInfo { at, info }),
            31 => Err(DecodeError::BreakCode { at }),
            _ => Err(DecodeError::SimpleValueForbidden { at, value: info }),
        }
    }

    /// Reads the argument for integer values / tag numbers.
    fn read_arg(&mut self, info: u8, at: usize) -> Result<u64, DecodeError> {
        match info {
            0..=23 => Ok(info as u64),
            24 => self.read_ext_arg(1, 23, at),
            25 => self.read_ext_arg(2, 0xFF, at),
            26 => self.read_ext_arg(4, 0xFFFF, at),
            27 => self.read_ext_arg(8, 0xFFFF_FFFF, at),
            31 => Err(DecodeError::IndefiniteLength { at }),
            28..=30 => Err(DecodeError::ReservedAdditionalInfo { at, info }),
            // `info` is 5 bits; 0..=31 fully covered above.
            _ => unreachable!(),
        }
    }

    /// Reads an extended argument of `len` bytes, enforcing that the value is
    /// strictly greater than `min_excl` (minimality).
    fn read_ext_arg(&mut self, len: usize, min_excl: u64, at: usize) -> Result<u64, DecodeError> {
        if self.pos + len > self.buf.len() {
            return Err(DecodeError::UnexpectedEnd { at, needed: len });
        }
        let mut v: u64 = 0;
        for _ in 0..len {
            v = (v << 8) | self.buf[self.pos] as u64;
            self.pos += 1;
        }
        if v <= min_excl {
            return Err(DecodeError::NonMinimalInteger { at });
        }
        Ok(v)
    }

    /// Reads a definite length for byte/text strings, rejecting indefinite
    /// and non-minimal forms.
    fn read_definite_length(&mut self, info: u8, at: usize) -> Result<usize, DecodeError> {
        let v = self.read_arg(info, at)?;
        if v > self.buf.len() as u64 {
            // Cannot fit in the input at all; report as exceeding input.
            return Err(DecodeError::LengthExceedsInput { at, declared: v });
        }
        Ok(v as usize)
    }

    /// Reads an array/map element count. Every element needs at least one
    /// byte, so a count larger than the remaining input is rejected up front
    /// (fail-closed against hostile over-allocation).
    fn read_count(&mut self, info: u8, at: usize) -> Result<usize, DecodeError> {
        let v = self.read_arg(info, at)?;
        let remaining = (self.buf.len() - self.pos) as u64;
        if v > remaining {
            return Err(DecodeError::LengthExceedsInput { at, declared: v });
        }
        Ok(v as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn encode_rfc8949_core_examples() {
        // Canonical encodings from RFC 8949 (sections 3.1 / 4.2.1).
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
            (Value::Int(-1), "20"),
            (Value::Int(-10), "29"),
            (Value::Int(-100), "3863"),
            (Value::Int(-1000), "3903e7"),
            (Value::Bool(false), "f4"),
            (Value::Bool(true), "f5"),
            (Value::Null, "f6"),
            (Value::Text("".into()), "60"),
            (Value::Text("a".into()), "6161"),
            (Value::Text("IETF".into()), "6449455446"),
            (Value::Text("\"\\".into()), "62225c"),
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
        ];
        for (value, expected) in cases {
            let encoded = encode(&value).unwrap();
            assert_eq!(hex(&encoded), expected, "encoding of {value:?}");
        }
    }

    #[test]
    fn encode_integer_boundaries() {
        let cases: Vec<(i64, &str)> = vec![
            (255, "18ff"),
            (256, "190100"),
            (65535, "19ffff"),
            (65536, "1a00010000"),
            (4294967295, "1affffffff"),
            (4294967296, "1b0000000100000000"),
            (i64::MAX, "1b7fffffffffffffff"),
            (-24, "37"),
            (-25, "3818"),
            (-256, "38ff"),
            (-257, "390100"),
            (-65536, "39ffff"),
            (-65537, "3a00010000"),
            (-4294967296, "3affffffff"),
            (-4294967297, "3b0000000100000000"),
            (i64::MIN, "3b7fffffffffffffff"),
        ];
        for (value, expected) in cases {
            assert_eq!(hex(&encode(&Value::Int(value)).unwrap()), expected);
            // Round-trip.
            assert_eq!(decode(&unhex(expected)).unwrap(), Value::Int(value));
        }
    }

    #[test]
    fn encode_sorts_map_keys_regardless_of_entry_order() {
        let unsorted = Value::Map(vec![
            (Value::Int(3), Value::Int(4)),
            (Value::Int(1), Value::Int(2)),
        ]);
        assert_eq!(hex(&encode(&unsorted).unwrap()), "a201020304");

        // Keys sort by their FULL canonical encodings (length prefix
        // included): enc("b")   = 61 62
        //                 enc("ab") = 62 61 62
        // Bytewise, 0x61 < 0x62, so "b" sorts BEFORE "ab".
        let m = Value::Map(vec![
            (Value::Text("b".into()), Value::Int(2)),
            (Value::Text("ab".into()), Value::Int(1)),
        ]);
        assert_eq!(hex(&encode(&m).unwrap()), "a261620262616201");
    }

    #[test]
    fn encode_rejects_duplicate_map_keys() {
        let m = Value::Map(vec![
            (Value::Int(1), Value::Int(2)),
            (Value::Int(1), Value::Int(3)),
        ]);
        assert_eq!(encode(&m), Err(EncodeError::DuplicateMapKey));
    }

    #[test]
    fn map_builder_sorts_and_dedups() {
        let v = MapBuilder::new()
            .insert_int(2, Value::Int(20))
            .insert_int(1, Value::Int(10))
            .build()
            .unwrap();
        assert_eq!(
            v,
            Value::Map(vec![(Value::Int(1), Value::Int(10)), (Value::Int(2), Value::Int(20))])
        );
        let err = MapBuilder::new()
            .insert_int(1, Value::Int(10))
            .insert_int(1, Value::Int(20))
            .build()
            .unwrap_err();
        assert_eq!(err, EncodeError::DuplicateMapKey);
    }

    #[test]
    fn roundtrip_and_byte_stability() {
        let values = vec![
            Value::Int(i64::MIN),
            Value::Int(i64::MAX),
            Value::Text("ShareNet 中文 🌍".into()),
            Value::Bytes((0u8..=255).collect()),
            Value::Array(vec![Value::Null, Value::Bool(true), Value::Bytes(vec![0xAA; 300])]),
            MapBuilder::new()
                .insert_int(1, Value::Int(1))
                .insert_int(2, Value::Bytes(vec![0x42; 32]))
                .insert_text("zzz", Value::Array(vec![Value::Int(-1)]))
                .build()
                .unwrap(),
        ];
        for v in values {
            let bytes = encode(&v).unwrap();
            let decoded = decode(&bytes).unwrap();
            assert_eq!(decoded, v, "round-trip of {v:?}");
            assert_eq!(encode(&decoded).unwrap(), bytes, "byte-stability");
        }
    }

    #[test]
    fn decode_rejects_empty_input() {
        assert_eq!(decode(&[]), Err(DecodeError::EmptyInput));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        assert_eq!(
            decode(&unhex("0000")),
            Err(DecodeError::TrailingBytes { at: 1, count: 1 })
        );
        assert_eq!(
            decode(&unhex("01ff")),
            Err(DecodeError::TrailingBytes { at: 1, count: 1 })
        );
    }

    #[test]
    fn decode_rejects_non_minimal_integers() {
        assert_eq!(
            decode(&unhex("1800")),
            Err(DecodeError::NonMinimalInteger { at: 0 })
        );
        assert_eq!(
            decode(&unhex("1817")),
            Err(DecodeError::NonMinimalInteger { at: 0 })
        );
        assert_eq!(
            decode(&unhex("190018")),
            Err(DecodeError::NonMinimalInteger { at: 0 })
        );
        // Non-minimal negative: -1 must be 0x20, not 0x38 0x00.
        assert_eq!(
            decode(&unhex("3800")),
            Err(DecodeError::NonMinimalInteger { at: 0 })
        );
        // 255 encoded in uint16 form (must be 0x18 0xff).
        assert_eq!(
            decode(&unhex("1900ff")),
            Err(DecodeError::NonMinimalInteger { at: 0 })
        );
        // Non-minimal byte-string length: 3 bytes must be 0x43, not 0x58 0x03.
        assert_eq!(
            decode(&unhex("5803414244")),
            Err(DecodeError::NonMinimalInteger { at: 0 })
        );
    }

    #[test]
    fn decode_rejects_indefinite_lengths() {
        assert_eq!(
            decode(&unhex("1f")),
            Err(DecodeError::IndefiniteLength { at: 0 })
        );
        // Indefinite byte string.
        assert_eq!(
            decode(&unhex("5fff")),
            Err(DecodeError::IndefiniteLength { at: 0 })
        );
        // Indefinite text string with break.
        assert_eq!(
            decode(&unhex("7f6161ff")),
            Err(DecodeError::IndefiniteLength { at: 0 })
        );
        // Indefinite array.
        assert_eq!(
            decode(&unhex("9f01ff")),
            Err(DecodeError::IndefiniteLength { at: 0 })
        );
        // Indefinite map.
        assert_eq!(
            decode(&unhex("bf0161afff")),
            Err(DecodeError::IndefiniteLength { at: 0 })
        );
        // Bare break code.
        assert_eq!(decode(&unhex("ff")), Err(DecodeError::BreakCode { at: 0 }));
    }

    #[test]
    fn decode_rejects_tags() {
        assert_eq!(
            decode(&unhex("c000")),
            Err(DecodeError::TagForbidden { at: 0, tag: 0 })
        );
        assert_eq!(
            decode(&unhex("c10a")),
            Err(DecodeError::TagForbidden { at: 0, tag: 1 })
        );
        assert_eq!(
            decode(&unhex("ca00")),
            Err(DecodeError::TagForbidden { at: 0, tag: 10 })
        );
        // Bignum tag 2.
        assert_eq!(
            decode(&unhex("c2420100")),
            Err(DecodeError::TagForbidden { at: 0, tag: 2 })
        );
    }

    #[test]
    fn decode_rejects_floats() {
        assert_eq!(
            decode(&unhex("f90000")),
            Err(DecodeError::FloatForbidden { at: 0, width_bytes: 2 })
        );
        assert_eq!(
            decode(&unhex("fa00000000")),
            Err(DecodeError::FloatForbidden { at: 0, width_bytes: 4 })
        );
        assert_eq!(
            decode(&unhex("fb0000000000000000")),
            Err(DecodeError::FloatForbidden { at: 0, width_bytes: 8 })
        );
        // f16 NaN.
        assert_eq!(
            decode(&unhex("f97e00")),
            Err(DecodeError::FloatForbidden { at: 0, width_bytes: 2 })
        );
        // f16 +Inf.
        assert_eq!(
            decode(&unhex("f97c00")),
            Err(DecodeError::FloatForbidden { at: 0, width_bytes: 2 })
        );
    }

    #[test]
    fn decode_rejects_undefined_and_other_simple_values() {
        assert_eq!(
            decode(&unhex("f7")),
            Err(DecodeError::SimpleValueForbidden { at: 0, value: 23 })
        );
        assert_eq!(
            decode(&unhex("e0")),
            Err(DecodeError::SimpleValueForbidden { at: 0, value: 0 })
        );
        assert_eq!(
            decode(&unhex("f3")),
            Err(DecodeError::SimpleValueForbidden { at: 0, value: 19 })
        );
        assert_eq!(
            decode(&unhex("f800")),
            Err(DecodeError::SimpleValueForbidden { at: 0, value: 0 })
        );
    }

    #[test]
    fn decode_rejects_invalid_utf8() {
        assert_eq!(
            decode(&unhex("62c328")),
            Err(DecodeError::InvalidUtf8 { at: 0 })
        );
        // Overlong encoding 0xC0 0x80.
        assert_eq!(
            decode(&unhex("62c080")),
            Err(DecodeError::InvalidUtf8 { at: 0 })
        );
    }

    #[test]
    fn decode_rejects_unsorted_and_duplicate_map_keys() {
        // {3: 4, 1: 2} — keys out of order; the violation is reported at
        // the offset of the offending (out-of-order) key.
        assert_eq!(
            decode(&unhex("a203040102")),
            Err(DecodeError::UnsortedMapKeys { at: 3 })
        );
        // {1: 2, 1: 3} — duplicate key, reported at the duplicate key.
        assert_eq!(
            decode(&unhex("a201020103")),
            Err(DecodeError::DuplicateMapKey { at: 3 })
        );
    }

    #[test]
    fn decode_rejects_out_of_range_integers() {
        assert_eq!(
            decode(&unhex("1bffffffffffffffff")),
            Err(DecodeError::IntegerOutOfRange {
                at: 0,
                raw: u64::MAX
            })
        );
        assert_eq!(
            decode(&unhex("3bffffffffffffffff")),
            Err(DecodeError::IntegerNegativeOutOfRange {
                at: 0,
                raw: u64::MAX
            })
        );
    }

    #[test]
    fn decode_rejects_truncated_inputs() {
        // Argument byte missing.
        assert_eq!(
            decode(&unhex("18")),
            Err(DecodeError::UnexpectedEnd { at: 0, needed: 1 })
        );
        // Byte string longer than input.
        assert_eq!(
            decode(&unhex("440102")),
            Err(DecodeError::LengthExceedsInput { at: 0, declared: 4 })
        );
        // Array claiming one element with nothing behind it: the count
        // itself exceeds the remaining input.
        assert_eq!(
            decode(&unhex("81")),
            Err(DecodeError::LengthExceedsInput { at: 0, declared: 1 })
        );
        // Map key parsed, value missing.
        assert_eq!(
            decode(&unhex("a101")),
            Err(DecodeError::UnexpectedEnd { at: 2, needed: 1 })
        );
        // Float with missing payload.
        assert_eq!(
            decode(&unhex("f9")),
            Err(DecodeError::UnexpectedEnd { at: 0, needed: 2 })
        );
    }

    #[test]
    fn decode_rejects_reserved_additional_info() {
        assert_eq!(
            decode(&unhex("1c")),
            Err(DecodeError::ReservedAdditionalInfo { at: 0, info: 28 })
        );
        assert_eq!(
            decode(&unhex("3d00")),
            Err(DecodeError::ReservedAdditionalInfo { at: 0, info: 29 })
        );
        assert_eq!(
            decode(&unhex("5e0000")),
            Err(DecodeError::ReservedAdditionalInfo { at: 0, info: 30 })
        );
    }

    #[test]
    fn decode_rejects_hostile_counts() {
        // Array claiming 2^32-1 elements with nothing behind it.
        assert_eq!(
            decode(&unhex("9affffffff")),
            Err(DecodeError::LengthExceedsInput { at: 0, declared: 4294967295 })
        );
    }

    #[test]
    fn depth_limit_is_enforced() {
        let mut bytes = vec![0x81u8; MAX_DEPTH + 1];
        bytes.push(0x01);
        assert_eq!(
            decode(&bytes),
            Err(DecodeError::DepthLimitExceeded { at: MAX_DEPTH + 1 })
        );
        // Exactly MAX_DEPTH nested arrays is fine.
        let mut ok = vec![0x81u8; MAX_DEPTH];
        ok.push(0x01);
        assert!(decode(&ok).is_ok());
    }

    #[test]
    fn accessors() {
        let v = MapBuilder::new()
            .insert_int(1, Value::Text("one".into()))
            .insert_text("k", Value::Int(9))
            .build()
            .unwrap();
        assert_eq!(v.get_by_int(1).unwrap().as_text(), Some("one"));
        assert_eq!(v.get_by_text("k").unwrap().as_int(), Some(9));
        assert!(v.get_by_int(7).is_none());
        assert!(Value::Int(1).get_by_int(1).is_none());
        assert!(Value::Null.is_null());
        assert_eq!(Value::Bytes(vec![1, 2]).as_bytes(), Some(&[1u8, 2][..]));
    }
}
