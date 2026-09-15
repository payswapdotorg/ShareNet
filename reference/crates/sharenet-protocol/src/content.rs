//! Content manifests — the addressing foundation (work item R6-001).
//!
//! Content is content-addressed (architecture §12): a large object is
//! chunked and represented by a manifest, and the manifest IS the named
//! object:
//!
//! ```text
//! content bytes
//!     ↓ chunked at chunk_size (the last chunk may be shorter)
//! chunks
//!     ↓ SHA-256 per chunk, in order
//! chunk_hashes
//!     + chunk_size + total_length + content_type + metadata + created_at
//!     ↓ canonical CBOR map (the registry schema)
//! manifest bytes
//!     ↓ SHA-256
//! content_id     (commitment-derived — L013: caller-selected content ids
//!                 are FORBIDDEN)
//! ```
//!
//! The [`ContentManifest`] wire object (registered in
//! `spec/protocol-registry.yaml` before this implementation, per the
//! frozen rule):
//!
//! ```text
//! {1: scheme_version (=1, uint),
//!  2: chunk_size (uint, 1..=2097152 — the fixed chunk byte length; the
//!      LAST chunk may be shorter),
//!  3: total_length (uint, >= 1),
//!  4: chunk_hashes (array of 32-byte bstr, ceil(total_length/chunk_size)
//!      entries EXACTLY),
//!  5: content_type (text, 1..=64 bytes, UTF-8),
//!  6: metadata (optional map text -> bounded text/int, at most 16
//!      entries, keys 1..=64 bytes — application metadata, NEVER
//!      interpreted by the protocol),
//!  7: created_at_unix (uint)}
//! ```
//!
//! # Why chunk-level SHA-256 (and why no Merkle root)
//!
//! The registry pins a FLAT ordered hash list, not a Merkle tree: the
//! manifest is small, verified as a whole by `content_id`, and every
//! chunk is verified independently against its slot — so there is no
//! partial-acceptance surface for a tree to prune. (The R3-004 route
//! commitment needed a Merkle root because acceptances are signed
//! separately and the commitment must bind them all without embedding
//! every acceptance; here the manifest embeds every hash directly.)
//! Resumable transfer (R6-002) checks a single chunk against a single
//! list slot — O(1) per chunk, no proof paths needed.
//!
//! # Reassembly is fail-closed and manifest-only
//!
//! [`ContentManifest::reassemble`] verifies EVERY chunk hash in order
//! plus the exact total byte count and returns the content only when the
//! whole stream matches. It trusts ONLY the manifest's committed hashes —
//! never out-of-band claims: a chunk that "looks right" (right length,
//! plausible bytes) still fails unless its SHA-256 matches its slot, and
//! a wrong/missing/duplicate chunk fails with the SLOT INDEX in the typed
//! error, so R6-002 resumable transfer can tell exactly which slots to
//! re-request. There is no partial acceptance: the result is either the
//! exact content or a typed error.
//!
//! # Metadata is application territory
//!
//! The optional metadata map is carried, bounded and byte-stable, but
//! NEVER interpreted by the protocol (the registry rule): it affects
//! `content_id` like every other field, and nothing in this module reads
//! meaning into it.
//!
//! # What this is NOT (honest scope)
//!
//! This module is only the addressing foundation. Chunk TRANSFER and
//! resume are R6-002; DTN storage/carry/forward, TTL, priority,
//! replication and custody evidence are R6-003 (BPv7 interop stays a
//! future adapter — architecture §12: borrow DTN principles, rebuild
//! nothing). End-to-end payload integrity is THIS layer's job per the
//! CircuitFrame integrity rule (hop-by-hop transport security carries
//! frames; the content layer proves the payload).

use core::fmt;
use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use crate::cbor::{decode, encode, Value};

/// Scheme version of the ContentManifest wire object (v1).
pub const CONTENT_SCHEME_VERSION: i64 = 1;
/// Maximum chunk byte length (2 MiB — aligned with the CircuitFrame
/// payload bound so a full chunk always fits one end-to-end frame).
pub const CONTENT_MAX_CHUNK_SIZE: u64 = 2_097_152;
/// Minimum chunk byte length (a chunk_size of 0 would make the manifest
/// geometry meaningless — refused).
pub const CONTENT_MIN_CHUNK_SIZE: u64 = 1;
/// Maximum byte length of the content_type text (1..=64, mirroring the
/// display-name bound).
pub const CONTENT_TYPE_MAX_BYTES: usize = 64;
/// Maximum number of entries in the optional metadata map.
pub const METADATA_MAX_ENTRIES: usize = 16;
/// Maximum byte length of one metadata key (1..=64 — the capability
/// limits bound, mirrored).
pub const METADATA_MAX_KEY_BYTES: usize = 64;
/// Maximum byte length of one metadata TEXT value (1..=256 — the
/// documented bound for the registry's "bounded text/int"; keys are the
/// tighter 64 because they index application lookups).
pub const METADATA_MAX_VALUE_TEXT_BYTES: usize = 256;
/// Byte length of one chunk hash (SHA-256).
pub const CHUNK_HASH_LEN: usize = 32;

// ---------------------------------------------------------------------------
// Metadata values (application territory — carried, never interpreted)
// ---------------------------------------------------------------------------

/// One optional metadata value: bounded text or integer (no floats — the
/// canonical CBOR profile forbids them on the wire anyway).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MetadataValue {
    Text(String),
    Int(i64),
}

impl MetadataValue {
    /// The canonical wire form (text stays text, int stays int).
    pub fn to_wire(&self) -> Value {
        match self {
            MetadataValue::Text(t) => Value::Text(t.clone()),
            MetadataValue::Int(i) => Value::Int(*i),
        }
    }
}

impl fmt::Display for MetadataValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MetadataValue::Text(t) => write!(f, "{t:?}"),
            MetadataValue::Int(i) => write!(f, "{i}"),
        }
    }
}

// ---------------------------------------------------------------------------
// The manifest
// ---------------------------------------------------------------------------

/// A content manifest: the content-addressed description of one chunked
/// object. Invariants (the registry admission rule) are enforced at
/// construction AND re-enforced at parse — byte-stability requires
/// exactly one accepted form per logical manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentManifest {
    chunk_size: u64,
    total_length: u64,
    chunk_hashes: Vec<[u8; CHUNK_HASH_LEN]>,
    content_type: String,
    metadata: Option<BTreeMap<String, MetadataValue>>,
    created_at_unix: u64,
}

impl ContentManifest {
    /// Build a manifest from its parts, enforcing every parse-time
    /// invariant up front (the same set [`Self::from_wire`] re-enforces).
    pub fn new(
        chunk_size: u64,
        total_length: u64,
        chunk_hashes: Vec<[u8; CHUNK_HASH_LEN]>,
        content_type: impl Into<String>,
        metadata: Option<BTreeMap<String, MetadataValue>>,
        created_at_unix: u64,
    ) -> Result<Self, ContentError> {
        let content_type = content_type.into();
        check_geometry(chunk_size, total_length, chunk_hashes.len())?;
        check_content_type(&content_type)?;
        if let Some(map) = &metadata {
            check_metadata(map)?;
        }
        if created_at_unix > i64::MAX as u64 {
            return Err(ContentError::TimestampOutOfRange);
        }
        Ok(ContentManifest {
            chunk_size,
            total_length,
            chunk_hashes,
            content_type,
            metadata,
            created_at_unix,
        })
    }

    /// The chunk discipline: split `content` into `chunk_size`-byte
    /// chunks (the last may be shorter) and build the manifest from the
    /// SHA-256 hashes of the ACTUAL chunks.
    ///
    /// The manifest describes what is — never what a caller claims: the
    /// total length and every hash are measured from the bytes handed
    /// in. Empty content is refused (`total_length >= 1` is a registry
    /// invariant; there is no such thing as an empty named object).
    pub fn chunk(
        content: &[u8],
        chunk_size: u64,
        content_type: impl Into<String>,
        metadata: Option<BTreeMap<String, MetadataValue>>,
        created_at_unix: u64,
    ) -> Result<(Self, Vec<Vec<u8>>), ContentError> {
        if content.is_empty() {
            return Err(ContentError::ContentEmpty);
        }
        if !(CONTENT_MIN_CHUNK_SIZE..=CONTENT_MAX_CHUNK_SIZE).contains(&chunk_size) {
            return Err(ContentError::ChunkSizeOutOfRange { found: chunk_size });
        }
        let content_type = content_type.into();
        check_content_type(&content_type)?;
        if let Some(map) = &metadata {
            check_metadata(map)?;
        }
        if created_at_unix > i64::MAX as u64 {
            return Err(ContentError::TimestampOutOfRange);
        }
        let chunks: Vec<Vec<u8>> = content
            .chunks(usize::try_from(chunk_size).expect("chunk_size <= 2 MiB fits usize"))
            .map(|c| c.to_vec())
            .collect();
        let total_length = u64::try_from(content.len())
            .map_err(|_| ContentError::TotalLengthOutOfRange)?;
        let chunk_hashes: Vec<[u8; CHUNK_HASH_LEN]> =
            chunks.iter().map(|c| chunk_hash(c)).collect();
        check_geometry(chunk_size, total_length, chunk_hashes.len())?;
        let manifest = ContentManifest {
            chunk_size,
            total_length,
            chunk_hashes,
            content_type,
            metadata,
            created_at_unix,
        };
        Ok((manifest, chunks))
    }

    /// Reassemble the content from a chunk stream, trusting ONLY the
    /// manifest's committed hashes — never claimed lengths, never
    /// caller assertions.
    ///
    /// Verifies, in order: every provided chunk's length against the
    /// slot's expected length (exactly `chunk_size` for every slot but
    /// the last; the last is `total_length - (n-1)*chunk_size`), then
    /// every chunk's SHA-256 against its manifest slot, then the exact
    /// chunk count (a short stream names the first slot that never
    /// arrived; a long stream names the first extra slot). The exact
    /// total byte count is pinned by the per-slot length checks, so the
    /// result is either the exact content or a typed error — there is
    /// no partial acceptance.
    pub fn reassemble(&self, chunks: &[impl AsRef<[u8]>]) -> Result<Vec<u8>, ContentError> {
        let n = self.chunk_hashes.len();
        let provided = chunks.len();
        let mut content = Vec::new();
        let mut verified: u64 = 0;
        for (slot, chunk) in chunks.iter().enumerate().take(provided.min(n)) {
            let data = chunk.as_ref();
            let found = data.len() as u64; // usize <= 64 bits on every supported target
            let expected = self.expected_chunk_len(slot).expect("slot < chunk_count");
            if found != expected {
                return Err(ContentError::ChunkLengthWrong { slot, found, expected });
            }
            if chunk_hash(data) != self.chunk_hashes[slot] {
                return Err(ContentError::ChunkHashMismatch { slot });
            }
            content.extend_from_slice(data);
            verified += expected;
        }
        if provided < n {
            // Every provided slot verified; the stream is a verified
            // PREFIX — the first slot that never arrived is exactly
            // `provided` (the fact R6-002 resume re-requests from).
            return Err(ContentError::MissingChunk { slot: provided });
        }
        if provided > n {
            // Every manifest slot verified; the first slot beyond the
            // manifest is the stream's length-1 extra — a duplicate or
            // injected chunk.
            return Err(ContentError::ExtraChunk { slot: n });
        }
        // The per-slot length checks pin the total by construction;
        // the explicit check states the exact-total law in code.
        debug_assert_eq!(verified, self.total_length);
        if verified != self.total_length {
            return Err(ContentError::ChunkLengthWrong {
                slot: n.saturating_sub(1),
                found: verified,
                expected: self.total_length,
            });
        }
        Ok(content)
    }

    /// The expected byte length of chunk `slot` (`None` past the last
    /// slot): `chunk_size` for every slot but the last; the remainder
    /// for the last (which may equal `chunk_size` on an exact boundary).
    pub fn expected_chunk_len(&self, slot: usize) -> Option<u64> {
        if slot >= self.chunk_hashes.len() {
            return None;
        }
        if slot + 1 == self.chunk_hashes.len() {
            Some(self.total_length - (self.chunk_hashes.len() as u64 - 1) * self.chunk_size)
        } else {
            Some(self.chunk_size)
        }
    }

    /// The commitment-derived content id: SHA-256 over the exact
    /// canonical manifest bytes (L013 — the manifest IS the named
    /// object; two byte-identical manifests are the same content by
    /// construction).
    pub fn content_id(&self) -> [u8; CHUNK_HASH_LEN] {
        chunk_hash(&self.to_wire_bytes())
    }

    /// The canonical CBOR wire form (the registry schema).
    pub fn to_wire(&self) -> Value {
        let mut entries: Vec<(Value, Value)> = vec![
            (Value::Int(1), Value::Int(CONTENT_SCHEME_VERSION)),
            (Value::Int(2), Value::Int(self.chunk_size as i64)),
            (Value::Int(3), Value::Int(self.total_length as i64)),
            (
                Value::Int(4),
                Value::Array(
                    self.chunk_hashes
                        .iter()
                        .map(|h| Value::Bytes(h.to_vec()))
                        .collect(),
                ),
            ),
            (Value::Int(5), Value::Text(self.content_type.clone())),
        ];
        if let Some(map) = &self.metadata {
            // BTreeMap iteration is bytewise-ascending key order, which
            // is exactly the canonical CBOR map-key order for text keys.
            entries.push((
                Value::Int(6),
                Value::Map(
                    map.iter()
                        .map(|(k, v)| (Value::Text(k.clone()), v.to_wire()))
                        .collect(),
                ),
            ));
        }
        entries.push((Value::Int(7), Value::Int(self.created_at_unix as i64)));
        Value::Map(entries)
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire_bytes(bytes: &[u8]) -> Result<Self, ContentError> {
        let v = decode(bytes).map_err(ContentError::Cbor)?;
        Self::from_wire(&v)
    }

    /// Strict parse with the full parse-time invariant set (mirrors
    /// [`Self::new`]; anything else is refused — no lenient forms).
    pub fn from_wire(v: &Value) -> Result<Self, ContentError> {
        let Value::Map(entries) = v else {
            return Err(ContentError::NotAMap);
        };
        let mut chunk_size: Option<u64> = None;
        let mut total_length: Option<u64> = None;
        let mut chunk_hashes: Option<Vec<[u8; CHUNK_HASH_LEN]>> = None;
        let mut content_type: Option<String> = None;
        let mut metadata: Option<BTreeMap<String, MetadataValue>> = None;
        let mut created_at: Option<u64> = None;
        let mut seen_scheme = false;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(ContentError::KeyNotAnInteger);
            };
            match *key {
                1 => {
                    if seen_scheme {
                        return Err(ContentError::DuplicateField { key: 1 });
                    }
                    let Value::Int(s) = val else {
                        return Err(ContentError::FieldNotExpectedType { key: 1 });
                    };
                    if *s != CONTENT_SCHEME_VERSION {
                        return Err(ContentError::SchemeVersionUnsupported { found: *s });
                    }
                    seen_scheme = true;
                }
                2 => {
                    if chunk_size.is_some() {
                        return Err(ContentError::DuplicateField { key: 2 });
                    }
                    let Value::Int(cs) = val else {
                        return Err(ContentError::FieldNotExpectedType { key: 2 });
                    };
                    if *cs < 0 {
                        return Err(ContentError::ChunkSizeOutOfRange {
                            found: cs.unsigned_abs(),
                        });
                    }
                    chunk_size = Some(*cs as u64);
                }
                3 => {
                    if total_length.is_some() {
                        return Err(ContentError::DuplicateField { key: 3 });
                    }
                    let Value::Int(tl) = val else {
                        return Err(ContentError::FieldNotExpectedType { key: 3 });
                    };
                    if *tl < 0 {
                        return Err(ContentError::TotalLengthBelowMinimum);
                    }
                    total_length = Some(*tl as u64);
                }
                4 => {
                    if chunk_hashes.is_some() {
                        return Err(ContentError::DuplicateField { key: 4 });
                    }
                    let Value::Array(items) = val else {
                        return Err(ContentError::FieldNotExpectedType { key: 4 });
                    };
                    let mut hashes = Vec::with_capacity(items.len());
                    for (slot, item) in items.iter().enumerate() {
                        let Value::Bytes(b) = item else {
                            return Err(ContentError::FieldNotExpectedType { key: 4 });
                        };
                        if b.len() != CHUNK_HASH_LEN {
                            return Err(ContentError::ChunkHashWrongLength {
                                slot,
                                len: b.len(),
                            });
                        }
                        hashes.push(b.as_slice().try_into().expect("checked"));
                    }
                    chunk_hashes = Some(hashes);
                }
                5 => {
                    if content_type.is_some() {
                        return Err(ContentError::DuplicateField { key: 5 });
                    }
                    let Value::Text(t) = val else {
                        return Err(ContentError::FieldNotExpectedType { key: 5 });
                    };
                    check_content_type(t)?;
                    content_type = Some(t.clone());
                }
                6 => {
                    if metadata.is_some() {
                        return Err(ContentError::DuplicateField { key: 6 });
                    }
                    let Value::Map(map) = val else {
                        return Err(ContentError::FieldNotExpectedType { key: 6 });
                    };
                    if map.len() > METADATA_MAX_ENTRIES {
                        return Err(ContentError::MetadataTooManyEntries {
                            count: map.len(),
                            max: METADATA_MAX_ENTRIES,
                        });
                    }
                    let mut out = BTreeMap::new();
                    for (mk, mv) in map {
                        let Value::Text(k) = mk else {
                            return Err(ContentError::MetadataEntryMalformed);
                        };
                        if k.is_empty() || k.len() > METADATA_MAX_KEY_BYTES {
                            return Err(ContentError::MetadataKeyInvalid {
                                bytes: k.len(),
                                max: METADATA_MAX_KEY_BYTES,
                            });
                        }
                        let value = match mv {
                            Value::Text(t) => {
                                if t.is_empty() || t.len() > METADATA_MAX_VALUE_TEXT_BYTES {
                                    return Err(ContentError::MetadataValueInvalid);
                                }
                                MetadataValue::Text(t.clone())
                            }
                            Value::Int(i) => MetadataValue::Int(*i),
                            _ => return Err(ContentError::MetadataEntryMalformed),
                        };
                        out.insert(k.clone(), value);
                    }
                    metadata = Some(out);
                }
                7 => {
                    if created_at.is_some() {
                        return Err(ContentError::DuplicateField { key: 7 });
                    }
                    let Value::Int(t) = val else {
                        return Err(ContentError::FieldNotExpectedType { key: 7 });
                    };
                    if *t < 0 {
                        return Err(ContentError::TimestampNegative {
                            field: "created_at",
                        });
                    }
                    created_at = Some(*t as u64);
                }
                other => return Err(ContentError::UnknownField { key: other }),
            }
        }
        let chunk_size = chunk_size.ok_or(ContentError::MissingField { key: 2 })?;
        let total_length = total_length.ok_or(ContentError::MissingField { key: 3 })?;
        let chunk_hashes = chunk_hashes.ok_or(ContentError::MissingField { key: 4 })?;
        let content_type = content_type.ok_or(ContentError::MissingField { key: 5 })?;
        let created_at = created_at.ok_or(ContentError::MissingField { key: 7 })?;
        if !seen_scheme {
            return Err(ContentError::MissingField { key: 1 });
        }
        // parse-time enforcement of the same invariants as construction
        check_geometry(chunk_size, total_length, chunk_hashes.len())?;
        if created_at > i64::MAX as u64 {
            return Err(ContentError::TimestampOutOfRange);
        }
        Ok(ContentManifest {
            chunk_size,
            total_length,
            chunk_hashes,
            content_type,
            metadata,
            created_at_unix: created_at,
        })
    }

    /// The fixed chunk byte length (the last chunk may be shorter).
    pub fn chunk_size(&self) -> u64 {
        self.chunk_size
    }

    /// The exact total byte count of the content.
    pub fn total_length(&self) -> u64 {
        self.total_length
    }

    /// The ordered chunk hashes (slot i is chunk i).
    pub fn chunk_hashes(&self) -> &[[u8; CHUNK_HASH_LEN]] {
        &self.chunk_hashes
    }

    /// The content type text (application-defined, bounded).
    pub fn content_type(&self) -> &str {
        &self.content_type
    }

    /// The optional application metadata, if present (never interpreted).
    pub fn metadata(&self) -> Option<&BTreeMap<String, MetadataValue>> {
        self.metadata.as_ref()
    }

    /// When the manifest was created (unix seconds, publisher-assigned).
    pub fn created_at_unix(&self) -> u64 {
        self.created_at_unix
    }

    /// The number of chunks (== chunk_hashes.len(), == ceil(total/chunk)).
    pub fn chunk_count(&self) -> usize {
        self.chunk_hashes.len()
    }
}

/// SHA-256 of one chunk (the slot commitment). Public because R6-002
/// resumable transfer checks individual arriving chunks against manifest
/// slots with exactly this function.
pub fn chunk_hash(data: &[u8]) -> [u8; CHUNK_HASH_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    let out = h.finalize();
    let mut hash = [0u8; CHUNK_HASH_LEN];
    hash.copy_from_slice(&out);
    hash
}

/// The geometry invariants: chunk_size bounds, total_length minimum and
/// range, and the EXACT count law `chunk_hashes.len() ==
/// ceil(total_length / chunk_size)`.
fn check_geometry(
    chunk_size: u64,
    total_length: u64,
    hash_count: usize,
) -> Result<(), ContentError> {
    if !(CONTENT_MIN_CHUNK_SIZE..=CONTENT_MAX_CHUNK_SIZE).contains(&chunk_size) {
        return Err(ContentError::ChunkSizeOutOfRange { found: chunk_size });
    }
    if total_length < 1 {
        return Err(ContentError::TotalLengthBelowMinimum);
    }
    if total_length > i64::MAX as u64 {
        return Err(ContentError::TotalLengthOutOfRange);
    }
    let expected = total_length.div_ceil(chunk_size);
    let found = hash_count as u64;
    if found != expected {
        return Err(ContentError::ChunkHashCountMismatch { expected, found });
    }
    Ok(())
}

fn check_content_type(content_type: &str) -> Result<(), ContentError> {
    let bytes = content_type.len();
    if bytes == 0 || bytes > CONTENT_TYPE_MAX_BYTES {
        return Err(ContentError::ContentTypeInvalid { bytes });
    }
    Ok(())
}

fn check_metadata(map: &BTreeMap<String, MetadataValue>) -> Result<(), ContentError> {
    if map.len() > METADATA_MAX_ENTRIES {
        return Err(ContentError::MetadataTooManyEntries {
            count: map.len(),
            max: METADATA_MAX_ENTRIES,
        });
    }
    for (key, value) in map {
        if key.is_empty() || key.len() > METADATA_MAX_KEY_BYTES {
            return Err(ContentError::MetadataKeyInvalid {
                bytes: key.len(),
                max: METADATA_MAX_KEY_BYTES,
            });
        }
        if let MetadataValue::Text(t) = value {
            if t.is_empty() || t.len() > METADATA_MAX_VALUE_TEXT_BYTES {
                return Err(ContentError::MetadataValueInvalid);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Typed errors
// ---------------------------------------------------------------------------

/// Typed failures of the content manifest wire object, its parse-time
/// invariants and its reassembly discipline. Stable machine names
/// (`name()`) are the conformance vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContentError {
    NotAMap,
    KeyNotAnInteger,
    FieldNotExpectedType { key: i64 },
    DuplicateField { key: i64 },
    UnknownField { key: i64 },
    MissingField { key: i64 },
    SchemeVersionUnsupported { found: i64 },
    Cbor(crate::cbor::DecodeError),
    ChunkSizeOutOfRange { found: u64 },
    TotalLengthBelowMinimum,
    TotalLengthOutOfRange,
    ChunkHashCountMismatch { expected: u64, found: u64 },
    ChunkHashWrongLength { slot: usize, len: usize },
    ContentTypeInvalid { bytes: usize },
    MetadataEntryMalformed,
    MetadataTooManyEntries { count: usize, max: usize },
    MetadataKeyInvalid { bytes: usize, max: usize },
    MetadataValueInvalid,
    TimestampNegative { field: &'static str },
    TimestampOutOfRange,
    ContentEmpty,
    ChunkLengthWrong { slot: usize, found: u64, expected: u64 },
    ChunkHashMismatch { slot: usize },
    MissingChunk { slot: usize },
    ExtraChunk { slot: usize },
}

impl ContentError {
    /// Stable machine name (vectors + harness).
    pub fn name(&self) -> String {
        match self {
            ContentError::NotAMap => "not_a_map",
            ContentError::KeyNotAnInteger => "key_not_an_integer",
            ContentError::FieldNotExpectedType { .. } => "field_not_expected_type",
            ContentError::DuplicateField { .. } => "duplicate_field",
            ContentError::UnknownField { .. } => "unknown_field",
            ContentError::MissingField { .. } => "missing_field",
            ContentError::SchemeVersionUnsupported { .. } => "scheme_version_unsupported",
            ContentError::Cbor(e) => return format!("cbor:{}", e.name()),
            ContentError::ChunkSizeOutOfRange { .. } => "chunk_size_out_of_range",
            ContentError::TotalLengthBelowMinimum => "total_length_below_minimum",
            ContentError::TotalLengthOutOfRange => "total_length_out_of_range",
            ContentError::ChunkHashCountMismatch { .. } => "chunk_hash_count_mismatch",
            ContentError::ChunkHashWrongLength { .. } => "chunk_hash_wrong_length",
            ContentError::ContentTypeInvalid { .. } => "content_type_invalid",
            ContentError::MetadataEntryMalformed => "metadata_entry_malformed",
            ContentError::MetadataTooManyEntries { .. } => "metadata_too_many_entries",
            ContentError::MetadataKeyInvalid { .. } => "metadata_key_invalid",
            ContentError::MetadataValueInvalid => "metadata_value_invalid",
            ContentError::TimestampNegative { .. } => "timestamp_negative",
            ContentError::TimestampOutOfRange => "timestamp_out_of_range",
            ContentError::ContentEmpty => "content_empty",
            ContentError::ChunkLengthWrong { .. } => "chunk_length_wrong",
            ContentError::ChunkHashMismatch { .. } => "chunk_hash_mismatch",
            ContentError::MissingChunk { .. } => "missing_chunk",
            ContentError::ExtraChunk { .. } => "extra_chunk",
        }
        .to_string()
    }
}

impl fmt::Display for ContentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ContentError::NotAMap => write!(f, "manifest must be a CBOR map"),
            ContentError::KeyNotAnInteger => write!(f, "map keys must be integers"),
            ContentError::FieldNotExpectedType { key } => {
                write!(f, "field {key} has the wrong CBOR type")
            }
            ContentError::DuplicateField { key } => write!(f, "duplicate field {key}"),
            ContentError::UnknownField { key } => write!(f, "unknown field {key}"),
            ContentError::MissingField { key } => write!(f, "missing required field {key}"),
            ContentError::SchemeVersionUnsupported { found } => {
                write!(f, "scheme_version {found} unsupported")
            }
            ContentError::Cbor(e) => write!(f, "CBOR profile violation: {e}"),
            ContentError::ChunkSizeOutOfRange { found } => write!(
                f,
                "chunk_size must be {CONTENT_MIN_CHUNK_SIZE}..={CONTENT_MAX_CHUNK_SIZE}, found {found}"
            ),
            ContentError::TotalLengthBelowMinimum => {
                write!(f, "total_length must be at least 1")
            }
            ContentError::TotalLengthOutOfRange => {
                write!(f, "total_length exceeds the canonical integer range")
            }
            ContentError::ChunkHashCountMismatch { expected, found } => write!(
                f,
                "chunk_hashes must hold exactly ceil(total_length/chunk_size) = {expected} entries, found {found}"
            ),
            ContentError::ChunkHashWrongLength { slot, len } => {
                write!(f, "chunk hash {slot} must be {CHUNK_HASH_LEN} bytes, found {len}")
            }
            ContentError::ContentTypeInvalid { bytes } => write!(
                f,
                "content_type must be 1..={CONTENT_TYPE_MAX_BYTES} bytes, found {bytes}"
            ),
            ContentError::MetadataEntryMalformed => {
                write!(f, "metadata entries must be text -> text|int")
            }
            ContentError::MetadataTooManyEntries { count, max } => {
                write!(f, "metadata may have at most {max} entries, found {count}")
            }
            ContentError::MetadataKeyInvalid { bytes, max } => {
                write!(f, "metadata key must be 1..={max} bytes, found {bytes}")
            }
            ContentError::MetadataValueInvalid => write!(
                f,
                "metadata text values must be 1..={METADATA_MAX_VALUE_TEXT_BYTES} bytes"
            ),
            ContentError::TimestampNegative { field } => {
                write!(f, "{field} must be non-negative")
            }
            ContentError::TimestampOutOfRange => {
                write!(f, "timestamps exceed the canonical integer range")
            }
            ContentError::ContentEmpty => {
                write!(f, "content must be non-empty (total_length >= 1)")
            }
            ContentError::ChunkLengthWrong { slot, found, expected } => write!(
                f,
                "chunk {slot} must be {expected} bytes, found {found}"
            ),
            ContentError::ChunkHashMismatch { slot } => write!(
                f,
                "chunk {slot} does not match its manifest slot hash"
            ),
            ContentError::MissingChunk { slot } => {
                write!(f, "chunk {slot} never arrived (stream is short)")
            }
            ContentError::ExtraChunk { slot } => write!(
                f,
                "chunk {slot} is beyond the manifest (duplicate or injected)"
            ),
        }
    }
}

impl std::error::Error for ContentError {}

// ---------------------------------------------------------------------------
// Tests (unit level; the adversarial suite is tests/content_adversarial.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(pairs: &[(&str, MetadataValue)]) -> BTreeMap<String, MetadataValue> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect()
    }

    #[test]
    fn chunk_builds_manifest_from_actual_chunks() {
        let content = b"ShareNet content addressing vector zero";
        let (m, chunks) = ContentManifest::chunk(
            content,
            8,
            "application/octet-stream",
            None,
            1_700_000_000,
        )
        .expect("chunks");
        assert_eq!(m.total_length(), content.len() as u64);
        assert_eq!(m.chunk_count(), (content.len() + 7) / 8);
        assert_eq!(chunks.len(), m.chunk_count());
        for (slot, c) in chunks.iter().enumerate() {
            let expected_len = m.expected_chunk_len(slot).unwrap();
            assert_eq!(c.len() as u64, expected_len);
            assert_eq!(chunk_hash(c), m.chunk_hashes()[slot]);
        }
        // every slot but the last is exactly chunk_size; the last is the remainder
        for slot in 0..m.chunk_count() - 1 {
            assert_eq!(m.expected_chunk_len(slot), Some(8));
        }
        let last = m.expected_chunk_len(m.chunk_count() - 1).unwrap();
        assert!(last >= 1 && last <= 8);
        assert_eq!(
            (m.chunk_count() as u64 - 1) * 8 + last,
            content.len() as u64
        );
    }

    #[test]
    fn single_chunk_shorter_than_chunk_size() {
        let (m, chunks) =
            ContentManifest::chunk(b"ShareNet", 64, "text/plain", None, 1).expect("chunks");
        assert_eq!(m.chunk_count(), 1);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], b"ShareNet");
        assert_eq!(m.expected_chunk_len(0), Some(8));
        assert_eq!(m.expected_chunk_len(1), None);
    }

    #[test]
    fn exact_chunk_boundary() {
        let content = b"0123456789abcdef0123456789abcdef";
        let (m, chunks) =
            ContentManifest::chunk(content, 16, "application/octet-stream", None, 2)
                .expect("chunks");
        assert_eq!(m.chunk_count(), 2);
        assert_eq!(m.expected_chunk_len(0), Some(16));
        assert_eq!(m.expected_chunk_len(1), Some(16)); // exact boundary: last is full
        assert_eq!(chunks[1].len(), 16);
        let re = m.reassemble(&chunks).expect("reassembles");
        assert_eq!(re, content);
    }

    #[test]
    fn metadata_carries_text_and_int() {
        let (m, chunks) = ContentManifest::chunk(
            b"dtn custody payload bytes",
            5,
            "image/png",
            Some(meta(&[
                ("title", MetadataValue::Text("mission photo".into())),
                ("priority", MetadataValue::Int(2)),
                ("ttl_secs", MetadataValue::Int(3600)),
            ])),
            1_700_000_003,
        )
        .expect("chunks");
        let parsed =
            ContentManifest::from_wire_bytes(&m.to_wire_bytes()).expect("round trips");
        assert_eq!(parsed, m);
        assert_eq!(
            parsed.metadata().unwrap().get("title"),
            Some(&MetadataValue::Text("mission photo".into()))
        );
        let re = m.reassemble(&chunks).expect("reassembles");
        assert_eq!(re, b"dtn custody payload bytes");
    }

    #[test]
    fn reassemble_verifies_every_hash_in_order() {
        let content = b"0123456789abcdefghij";
        let (m, chunks) =
            ContentManifest::chunk(content, 4, "application/octet-stream", None, 7)
                .expect("chunks");
        assert_eq!(m.chunk_count(), 5);
        // valid stream
        assert_eq!(m.reassemble(&chunks).unwrap(), content);
        // swapped order fails at the FIRST mismatching slot
        let mut swapped = chunks.clone();
        swapped.swap(0, 1);
        assert_eq!(
            m.reassemble(&swapped),
            Err(ContentError::ChunkHashMismatch { slot: 0 })
        );
        // corrupted byte fails at its slot
        let mut corrupted = chunks.clone();
        corrupted[2][0] ^= 0x01;
        assert_eq!(
            m.reassemble(&corrupted),
            Err(ContentError::ChunkHashMismatch { slot: 2 })
        );
        // missing last chunk: everything verified, slot named
        let mut short = chunks.clone();
        short.pop();
        assert_eq!(
            m.reassemble(&short),
            Err(ContentError::MissingChunk { slot: 4 })
        );
        // extra chunk appended
        let mut extra = chunks.clone();
        extra.push(chunks[0].clone());
        assert_eq!(
            m.reassemble(&extra),
            Err(ContentError::ExtraChunk { slot: 5 })
        );
        // short last chunk
        let mut shrunk = chunks.clone();
        let last = shrunk.len() - 1;
        shrunk[last].pop();
        assert_eq!(
            m.reassemble(&shrunk),
            Err(ContentError::ChunkLengthWrong {
                slot: last,
                found: 3,
                expected: 4
            })
        );
    }

    #[test]
    fn content_id_is_commitment_derived_and_deterministic() {
        let content = b"same bytes twice";
        let (m1, _) =
            ContentManifest::chunk(content, 4, "application/octet-stream", None, 42)
                .expect("chunks");
        let (m2, _) =
            ContentManifest::chunk(content, 4, "application/octet-stream", None, 42)
                .expect("chunks");
        assert_eq!(m1.content_id(), m2.content_id());
        // ANY field change = a different id
        let (other_size, _) =
            ContentManifest::chunk(content, 5, "application/octet-stream", None, 42)
                .expect("chunks");
        assert_ne!(m1.content_id(), other_size.content_id());
        let (other_time, _) =
            ContentManifest::chunk(content, 4, "application/octet-stream", None, 43)
                .expect("chunks");
        assert_ne!(m1.content_id(), other_time.content_id());
        let (other_type, _) =
            ContentManifest::chunk(content, 4, "text/plain", None, 42).expect("chunks");
        assert_ne!(m1.content_id(), other_type.content_id());
        let (other_meta, _) = ContentManifest::chunk(
            content,
            4,
            "application/octet-stream",
            Some(meta(&[("k", MetadataValue::Int(1))])),
            42,
        )
        .expect("chunks");
        assert_ne!(m1.content_id(), other_meta.content_id());
        // one changed content byte = new hashes = new id
        let mut changed = content.to_vec();
        changed[0] ^= 0x01;
        let (other_bytes, _) =
            ContentManifest::chunk(&changed, 4, "application/octet-stream", None, 42)
                .expect("chunks");
        assert_ne!(m1.content_id(), other_bytes.content_id());
        // the id is exactly SHA-256 of the canonical bytes (recomputed)
        assert_eq!(m1.content_id(), chunk_hash(&m1.to_wire_bytes()));
    }

    #[test]
    fn parse_enforces_the_geometry_exactness() {
        let content = b"0123456789abcdef";
        let (m, _) =
            ContentManifest::chunk(content, 8, "application/octet-stream", None, 9)
                .expect("chunks");
        let good = m.to_wire_bytes();
        let parsed = ContentManifest::from_wire_bytes(&good).expect("parses");
        assert_eq!(parsed, m);

        // count mismatch: one hash dropped
        let Value::Map(entries) = decode(&good).unwrap() else { unreachable!() };
        let stripped: Vec<(Value, Value)> = entries
            .iter()
            .map(|(k, v)| {
                if let (Value::Int(4), Value::Array(items)) = (k, v) {
                    let mut items = items.clone();
                    items.pop();
                    (k.clone(), Value::Array(items))
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect();
        let bad = encode(&Value::Map(stripped)).unwrap();
        assert_eq!(
            ContentManifest::from_wire_bytes(&bad).unwrap_err(),
            ContentError::ChunkHashCountMismatch {
                expected: 2,
                found: 1
            }
        );

        // claimed-length lie: total inflated so ceil changes
        let inflated: Vec<(Value, Value)> = entries
            .iter()
            .map(|(k, v)| {
                if let (Value::Int(3), _) = (k, v) {
                    (k.clone(), Value::Int(23))
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect();
        let bad = encode(&Value::Map(inflated)).unwrap();
        assert_eq!(
            ContentManifest::from_wire_bytes(&bad).unwrap_err(),
            ContentError::ChunkHashCountMismatch {
                expected: 3,
                found: 2
            }
        );
    }

    #[test]
    fn parse_enforces_bounds() {
        let content = b"0123456789";
        let (m, _) =
            ContentManifest::chunk(content, 4, "application/octet-stream", None, 5)
                .expect("chunks");
        let good = m.to_wire_bytes();
        let Value::Map(entries) = decode(&good).unwrap() else { unreachable!() };
        let rebuild = |patch: &dyn Fn(&mut Vec<(Value, Value)>)| {
            let mut e = entries.clone();
            patch(&mut e);
            encode(&Value::Map(e)).unwrap()
        };

        // chunk_size 0 and above the cap
        for bad_size in [0i64, 2_097_153] {
            let bytes = rebuild(&|e| {
                for (k, v) in e.iter_mut() {
                    if let (Value::Int(2), slot) = (k, v) {
                        *slot = Value::Int(bad_size);
                    }
                }
            });
            assert_eq!(
                ContentManifest::from_wire_bytes(&bytes).unwrap_err(),
                ContentError::ChunkSizeOutOfRange {
                    found: bad_size as u64
                }
            );
        }
        // total_length 0 (and negative on the wire)
        for bad_total in [0i64, -1] {
            let bytes = rebuild(&|e| {
                for (k, v) in e.iter_mut() {
                    if let (Value::Int(3), slot) = (k, v) {
                        *slot = Value::Int(bad_total);
                    }
                }
            });
            assert_eq!(
                ContentManifest::from_wire_bytes(&bytes).unwrap_err(),
                ContentError::TotalLengthBelowMinimum
            );
        }
        // content_type bounds
        for bad_type in [String::new(), "x".repeat(65)] {
            let bytes = rebuild(&|e| {
                for (k, v) in e.iter_mut() {
                    if let (Value::Int(5), slot) = (k, v) {
                        *slot = Value::Text(bad_type.clone());
                    }
                }
            });
            assert_eq!(
                ContentManifest::from_wire_bytes(&bytes).unwrap_err(),
                ContentError::ContentTypeInvalid {
                    bytes: bad_type.len()
                }
            );
        }
    }

    #[test]
    fn empty_content_refused() {
        assert_eq!(
            ContentManifest::chunk(b"", 8, "application/octet-stream", None, 1).unwrap_err(),
            ContentError::ContentEmpty
        );
    }
}
