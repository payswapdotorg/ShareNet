//! R6-001 adversarial tests: the ContentManifest wire object and its chunk
//! discipline under tampering, geometry lies, claimed-length confusion,
//! duplicate/missing/reordered chunks, hostile metadata and non-canonical
//! encodings.
//!
//! Every refusal path is exercised against manifests built by the REAL
//! protocol builder from REAL content (then attacked) — not mocked
//! failures. The central property under attack: reassembly trusts ONLY
//! the manifest's committed hashes — never claimed lengths, never
//! caller assertions — and `content_id` is the commitment over every
//! field, so any change to anything is a different named object.

mod common;

use std::collections::BTreeMap;

use sharenet_protocol::cbor::{decode, encode, Value};
use sharenet_protocol::content::{
    chunk_hash, ContentError, ContentManifest, MetadataValue, CONTENT_MAX_CHUNK_SIZE,
    CONTENT_TYPE_MAX_BYTES, METADATA_MAX_ENTRIES, METADATA_MAX_KEY_BYTES,
    METADATA_MAX_VALUE_TEXT_BYTES,
};

/// Deterministic multi-chunk test content (7 bytes x 2 + remainder).
const CONTENT: &[u8] = b"0123456789abcdefg";

fn build() -> (ContentManifest, Vec<Vec<u8>>) {
    ContentManifest::chunk(CONTENT, 7, "application/octet-stream", None, 1_700_000_000)
        .expect("test manifest builds")
}

/// Patch one field of a parsed manifest map and re-encode: the semantic
/// tamper family (valid canonical CBOR, one changed field).
fn patched(manifest: &ContentManifest, key: i64, value: Value) -> Vec<u8> {
    let mut v = decode(&manifest.to_wire_bytes()).expect("manifest parses");
    let Value::Map(entries) = &mut v else { unreachable!("manifest is a map") };
    for (k, val) in entries.iter_mut() {
        if kn_for(k) == key {
            *val = value.clone();
        }
    }
    encode(&v).expect("in-profile")
}

fn metadata(pairs: &[(&str, MetadataValue)]) -> Option<BTreeMap<String, MetadataValue>> {
    if pairs.is_empty() {
        return None;
    }
    Some(pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect())
}

// ---------------------------------------------------------------------------
// content_id: the commitment over EVERY field
// ---------------------------------------------------------------------------

#[test]
fn any_field_tamper_is_a_different_named_object() {
    let (m, _) = build();
    let original_id = m.content_id();

    // chunk_size 7 -> 6 (count stays 3: ceil(17/6) = 3): valid CBOR,
    // valid geometry, DIFFERENT content_id.
    let tampered =
        ContentManifest::from_wire_bytes(&patched(&m, 2, Value::Int(6))).expect("parses");
    assert_ne!(tampered.content_id(), original_id);

    // total_length 17 -> 18 (ceil(18/7) = 3): same shape, different id.
    let tampered =
        ContentManifest::from_wire_bytes(&patched(&m, 3, Value::Int(18))).expect("parses");
    assert_ne!(tampered.content_id(), original_id);

    // one chunk hash byte flipped: still 32 bytes, still 3 hashes, so the
    // manifest still parses — but it names different content now.
    let mut v = decode(&m.to_wire_bytes()).expect("parses");
    if let Value::Map(entries) = &mut v {
        for (k, val) in entries.iter_mut() {
            if kn_for(k) == 4 {
                if let Value::Array(items) = val {
                    if let Value::Bytes(b) = &mut items[0] {
                        b[0] ^= 0x01;
                    }
                }
            }
        }
    }
    let tampered = ContentManifest::from_wire_bytes(&encode(&v).unwrap()).expect("parses");
    assert_ne!(tampered.content_id(), original_id);

    // content_type, created_at
    let tampered = ContentManifest::from_wire_bytes(&patched(&m, 5, Value::Text("text/plain".into())))
        .expect("parses");
    assert_ne!(tampered.content_id(), original_id);
    let tampered =
        ContentManifest::from_wire_bytes(&patched(&m, 7, Value::Int(1_700_000_001))).expect("parses");
    assert_ne!(tampered.content_id(), original_id);

    // metadata added: different id
    let (with_meta, _) = ContentManifest::chunk(
        CONTENT,
        7,
        "application/octet-stream",
        metadata(&[("k", MetadataValue::Int(1))]),
        1_700_000_000,
    )
    .expect("builds");
    assert_ne!(with_meta.content_id(), original_id);
    // ...and metadata VALUE changes are different objects too
    let (other_value, _) = ContentManifest::chunk(
        CONTENT,
        7,
        "application/octet-stream",
        metadata(&[("k", MetadataValue::Int(2))]),
        1_700_000_000,
    )
    .expect("builds");
    assert_ne!(other_value.content_id(), with_meta.content_id());
}

/// Helper for the raw-map match above (keeps the borrow checker happy).
fn kn_for(k: &Value) -> i64 {
    if let Value::Int(kn) = k {
        *kn
    } else {
        -1
    }
}

#[test]
fn content_id_is_exactly_sha256_of_the_canonical_bytes() {
    let (m, _) = build();
    assert_eq!(m.content_id(), chunk_hash(&m.to_wire_bytes()));
    // same content + same params built twice = byte-identical manifest
    let (m2, _) = build();
    assert_eq!(m.to_wire_bytes(), m2.to_wire_bytes());
    assert_eq!(m.content_id(), m2.content_id());
    // same content, different chunk_size = different manifest bytes, different id
    let (other, _) =
        ContentManifest::chunk(CONTENT, 5, "application/octet-stream", None, 1_700_000_000)
            .expect("builds");
    assert_ne!(m.to_wire_bytes(), other.to_wire_bytes());
    assert_ne!(m.content_id(), other.content_id());
}

#[test]
fn metadata_insertion_order_never_changes_the_wire_bytes() {
    let a = metadata(&[
        ("alpha", MetadataValue::Text("one".into())),
        ("beta", MetadataValue::Int(2)),
        ("gamma", MetadataValue::Int(3)),
    ])
    .unwrap();
    let mut b = BTreeMap::new(); // deliberately different insertion order
    b.insert("gamma".to_string(), MetadataValue::Int(3));
    b.insert("alpha".to_string(), MetadataValue::Text("one".into()));
    b.insert("beta".to_string(), MetadataValue::Int(2));
    let (ma, _) = ContentManifest::chunk(
        CONTENT,
        7,
        "application/octet-stream",
        Some(a),
        5,
    )
    .expect("builds");
    let (mb, _) = ContentManifest::chunk(
        CONTENT,
        7,
        "application/octet-stream",
        Some(b),
        5,
    )
    .expect("builds");
    assert_eq!(ma.to_wire_bytes(), mb.to_wire_bytes());
    assert_eq!(ma.content_id(), mb.content_id());
}

// ---------------------------------------------------------------------------
// Reassembly: manifest-only trust, no partial acceptance
// ---------------------------------------------------------------------------

#[test]
fn reassemble_returns_exactly_the_original_content() {
    let (m, chunks) = build();
    let content = m.reassemble(&chunks).expect("reassembles");
    assert_eq!(content, CONTENT);
    assert_eq!(content.len() as u64, m.total_length());
    // the manifest parsed FROM THE WIRE reassembles identically
    let parsed = ContentManifest::from_wire_bytes(&m.to_wire_bytes()).expect("parses");
    assert_eq!(parsed.reassemble(&chunks).expect("reassembles"), CONTENT);
}

#[test]
fn every_chunk_bit_flip_fails_at_its_own_slot() {
    let (m, chunks) = build();
    assert_eq!(m.chunk_count(), 3);
    for slot in 0..chunks.len() {
        for byte in 0..chunks[slot].len() {
            let mut attacked = chunks.clone();
            attacked[slot][byte] ^= 0x80;
            assert_eq!(
                m.reassemble(&attacked),
                Err(ContentError::ChunkHashMismatch { slot }),
                "flip at slot {slot} byte {byte} must name slot {slot}"
            );
        }
    }
}

#[test]
fn reordered_stream_fails_at_the_first_mismatching_slot() {
    let (m, chunks) = build();
    // swap slots 0 and 1 (both full-length): the length law passes, the
    // hash law fails at slot 0 — the classic wrong-order signature
    let mut swapped = chunks.clone();
    swapped.swap(0, 1);
    assert_eq!(
        m.reassemble(&swapped),
        Err(ContentError::ChunkHashMismatch { slot: 0 })
    );
    // reordering WITH the short last chunk trips the length law first at
    // the slot holding the short bytes (fail-fast: never hash structurally
    // wrong input)
    let mut swapped = chunks.clone();
    swapped.swap(1, 2);
    assert_eq!(
        m.reassemble(&swapped),
        Err(ContentError::ChunkLengthWrong {
            slot: 1,
            found: 3,
            expected: 7
        })
    );
    let mut swapped = chunks.clone();
    swapped.swap(0, 2);
    assert_eq!(
        m.reassemble(&swapped),
        Err(ContentError::ChunkLengthWrong {
            slot: 0,
            found: 3,
            expected: 7
        })
    );
}

#[test]
fn missing_tail_names_the_first_absent_slot() {
    let (m, chunks) = build();
    for drop_from in 0..chunks.len() {
        let short = &chunks[..drop_from];
        assert_eq!(
            m.reassemble(short),
            Err(ContentError::MissingChunk { slot: drop_from }),
            "a stream of {drop_from} verified chunks must name slot {drop_from}"
        );
    }
    // the empty stream names slot 0
    assert_eq!(m.reassemble(&[] as &[Vec<u8>]), Err(ContentError::MissingChunk { slot: 0 }));
}

#[test]
fn missing_middle_chunk_fails_the_law_at_its_slot() {
    let (m, chunks) = build();
    // dropping chunk 1 leaves [c0, c2]: slot 1 holds the SHORT last
    // chunk — the length law fires first (a positional stream cannot
    // "skip"; only verified-prefix truncation is a missing_chunk)
    let holed: Vec<Vec<u8>> = vec![chunks[0].clone(), chunks[2].clone()];
    assert_eq!(
        m.reassemble(&holed),
        Err(ContentError::ChunkLengthWrong {
            slot: 1,
            found: 3,
            expected: 7
        })
    );
    // on a uniform-length manifest, the same hole is caught by the
    // hash law at the hole's slot
    let uniform = b"0123456789abcdefghijklmno"; // 24 bytes / 8 = 3 x 8
    let (um, uchunks) =
        ContentManifest::chunk(uniform, 8, "a/b", None, 1).expect("builds");
    let holed: Vec<Vec<u8>> = vec![uchunks[0].clone(), uchunks[2].clone()];
    assert_eq!(
        um.reassemble(&holed),
        Err(ContentError::ChunkHashMismatch { slot: 1 })
    );
}

#[test]
fn duplicate_chunk_fails_wherever_it_lands() {
    let (m, chunks) = build();
    // in-place duplicate: slot 1 delivers chunk 0's bytes again
    let mut in_place = chunks.clone();
    in_place[1] = chunks[0].clone();
    assert_eq!(
        m.reassemble(&in_place),
        Err(ContentError::ChunkHashMismatch { slot: 1 })
    );
    // appended duplicate: every manifest slot verifies, the extra fails
    let mut appended = chunks.clone();
    appended.push(chunks[2].clone());
    assert_eq!(
        m.reassemble(&appended),
        Err(ContentError::ExtraChunk { slot: 3 })
    );
    // appending a NOVEL chunk (not a copy) fails the same way: extra
    let mut novel = chunks.clone();
    novel.push(b"XXXXXXX".to_vec());
    assert_eq!(
        m.reassemble(&novel),
        Err(ContentError::ExtraChunk { slot: 3 })
    );
}

#[test]
fn short_and_long_chunks_fail_the_length_law_at_their_slot() {
    let (m, chunks) = build();
    // non-last chunk one byte short
    let mut attacked = chunks.clone();
    attacked[0].pop();
    assert_eq!(
        m.reassemble(&attacked),
        Err(ContentError::ChunkLengthWrong {
            slot: 0,
            found: 6,
            expected: 7
        })
    );
    // non-last chunk one byte long
    let mut attacked = chunks.clone();
    attacked[0].push(b'x');
    assert_eq!(
        m.reassemble(&attacked),
        Err(ContentError::ChunkLengthWrong {
            slot: 0,
            found: 8,
            expected: 7
        })
    );
    // last chunk (the short remainder) short and long
    let mut attacked = chunks.clone();
    attacked[2].pop();
    assert_eq!(
        m.reassemble(&attacked),
        Err(ContentError::ChunkLengthWrong {
            slot: 2,
            found: 2,
            expected: 3
        })
    );
    let mut attacked = chunks.clone();
    attacked[2].push(b'x');
    assert_eq!(
        m.reassemble(&attacked),
        Err(ContentError::ChunkLengthWrong {
            slot: 2,
            found: 4,
            expected: 3
        })
    );
}

#[test]
fn claimed_total_length_never_smuggles_content_through() {
    // A forged manifest: the REAL chunk hashes, but a LIED total_length
    // chosen so the geometry count still matches (ceil stays 3) — the
    // parse succeeds, so only reassembly can catch the lie.
    let (m, chunks) = build();
    assert_eq!((m.total_length(), m.chunk_size(), m.chunk_count()), (17, 7, 3));

    // Lie total DOWN (17 -> 15): ceil(15/7) = 3 — count matches, parses.
    let forged = ContentManifest::from_wire_bytes(&patched(&m, 3, Value::Int(15))).expect("parses");
    // the original chunks are now the wrong lengths for the lie
    assert_eq!(
        forged.reassemble(&chunks),
        Err(ContentError::ChunkLengthWrong {
            slot: 2,
            found: 3,
            expected: 1
        })
    );
    // and chunks CUT to the lied lengths are the wrong BYTES (hash law)
    let mut cut = chunks.clone();
    cut[2].truncate(1);
    assert_eq!(
        forged.reassemble(&cut),
        Err(ContentError::ChunkHashMismatch { slot: 2 })
    );

    // Lie total UP (17 -> 21): ceil(21/7) = 3 — count matches, parses.
    let forged = ContentManifest::from_wire_bytes(&patched(&m, 3, Value::Int(21))).expect("parses");
    assert_eq!(
        forged.reassemble(&chunks),
        Err(ContentError::ChunkLengthWrong {
            slot: 2,
            found: 3,
            expected: 7
        })
    );
    // padding the last chunk to the lied length cannot forge the hash
    let mut padded = chunks.clone();
    padded[2].extend_from_slice(b"abcd");
    assert_eq!(
        forged.reassemble(&padded),
        Err(ContentError::ChunkHashMismatch { slot: 2 })
    );
}

#[test]
fn same_length_wrong_bytes_never_pass() {
    // the manifest-only trust law: right-looking lengths, wrong content
    let (m, _) = build();
    let mut lookalike: Vec<Vec<u8>> = (0..m.chunk_count())
        .map(|slot| {
            let len = m.expected_chunk_len(slot).unwrap() as usize;
            vec![b'A'; len]
        })
        .collect();
    lookalike[0][0] = b'0'; // even the exact first byte right
    assert_eq!(
        m.reassemble(&lookalike),
        Err(ContentError::ChunkHashMismatch { slot: 0 })
    );
}

#[test]
fn failing_reassembly_exposes_nothing_but_the_typed_error() {
    // no partial acceptance: a mid-stream failure (slot 1 of 3) names
    // slot 1 and returns no content bytes at all
    let (m, mut chunks) = build();
    chunks[1][0] ^= 0x01;
    let err = m.reassemble(&chunks).unwrap_err();
    assert_eq!(err, ContentError::ChunkHashMismatch { slot: 1 });
    assert_eq!(err.name(), "chunk_hash_mismatch");
    // the slot-carrying errors all carry the slot
    assert_eq!(
        ContentError::MissingChunk { slot: 2 }.name(),
        "missing_chunk"
    );
    assert_eq!(ContentError::ExtraChunk { slot: 3 }.name(), "extra_chunk");
    assert_eq!(
        ContentError::ChunkLengthWrong {
            slot: 0,
            found: 1,
            expected: 2
        }
        .name(),
        "chunk_length_wrong"
    );
}

// ---------------------------------------------------------------------------
// Geometry and bounds (parse-time invariants)
// ---------------------------------------------------------------------------

#[test]
fn chunk_size_boundaries() {
    let (min, _) = ContentManifest::chunk(b"ab", CONTENT_MAX_CHUNK_SIZE, "a/b", None, 1)
        .expect("2 MiB chunk_size is the cap");
    assert_eq!(min.chunk_count(), 1);
    assert_eq!(
        ContentManifest::chunk(b"ab", 0, "a/b", None, 1).unwrap_err(),
        ContentError::ChunkSizeOutOfRange { found: 0 }
    );
    assert_eq!(
        ContentManifest::chunk(b"ab", CONTENT_MAX_CHUNK_SIZE + 1, "a/b", None, 1).unwrap_err(),
        ContentError::ChunkSizeOutOfRange {
            found: CONTENT_MAX_CHUNK_SIZE + 1
        }
    );
    // one byte of content in a maximum-size chunk: the extreme small end
    let (one, chunks) = ContentManifest::chunk(b"x", CONTENT_MAX_CHUNK_SIZE, "a/b", None, 1)
        .expect("builds");
    assert_eq!((one.chunk_count(), one.total_length()), (1, 1));
    assert_eq!(one.reassemble(&chunks).unwrap(), b"x");
}

#[test]
fn geometry_lies_rejected_at_parse() {
    let (m, _) = build();
    // one hash dropped
    let mut v = decode(&m.to_wire_bytes()).unwrap();
    if let Value::Map(entries) = &mut v {
        for (k, val) in entries.iter_mut() {
            if kn_for(k) == 4 {
                if let Value::Array(items) = val {
                    items.pop();
                }
            }
        }
    }
    assert_eq!(
        ContentManifest::from_wire_bytes(&encode(&v).unwrap()).unwrap_err(),
        ContentError::ChunkHashCountMismatch {
            expected: 3,
            found: 2
        }
    );
    // one hash appended
    let mut v = decode(&m.to_wire_bytes()).unwrap();
    if let Value::Map(entries) = &mut v {
        for (k, val) in entries.iter_mut() {
            if kn_for(k) == 4 {
                if let Value::Array(items) = val {
                    items.push(Value::Bytes(vec![0u8; 32]));
                }
            }
        }
    }
    assert_eq!(
        ContentManifest::from_wire_bytes(&encode(&v).unwrap()).unwrap_err(),
        ContentError::ChunkHashCountMismatch {
            expected: 3,
            found: 4
        }
    );
    // empty hash list: count exactness forbids it (ceil >= 1 always)
    let mut v = decode(&m.to_wire_bytes()).unwrap();
    if let Value::Map(entries) = &mut v {
        for (k, val) in entries.iter_mut() {
            if kn_for(k) == 4 {
                *val = Value::Array(vec![]);
            }
        }
    }
    assert_eq!(
        ContentManifest::from_wire_bytes(&encode(&v).unwrap()).unwrap_err(),
        ContentError::ChunkHashCountMismatch {
            expected: 3,
            found: 0
        }
    );
    // total inflated past the hashes (ceil moves): count mismatch
    assert_eq!(
        ContentManifest::from_wire_bytes(&patched(&m, 3, Value::Int(22))).unwrap_err(),
        ContentError::ChunkHashCountMismatch {
            expected: 4,
            found: 3
        }
    );
    // total zero / negative
    assert_eq!(
        ContentManifest::from_wire_bytes(&patched(&m, 3, Value::Int(0))).unwrap_err(),
        ContentError::TotalLengthBelowMinimum
    );
    assert_eq!(
        ContentManifest::from_wire_bytes(&patched(&m, 3, Value::Int(-3))).unwrap_err(),
        ContentError::TotalLengthBelowMinimum
    );
    // beyond the canonical integer range (via the builder API: the wire
    // cannot carry it)
    assert_eq!(
        ContentManifest::new(
            7,
            i64::MAX as u64 + 1,
            vec![[0u8; 32]; 3],
            "a/b",
            None,
            1
        )
        .unwrap_err(),
        ContentError::TotalLengthOutOfRange
    );
}

#[test]
fn chunk_hash_wrong_length_names_the_slot() {
    let (m, _) = build();
    let mut v = decode(&m.to_wire_bytes()).unwrap();
    if let Value::Map(entries) = &mut v {
        for (k, val) in entries.iter_mut() {
            if kn_for(k) == 4 {
                if let Value::Array(items) = val {
                    items[1] = Value::Bytes(vec![0u8; 31]);
                }
            }
        }
    }
    assert_eq!(
        ContentManifest::from_wire_bytes(&encode(&v).unwrap()).unwrap_err(),
        ContentError::ChunkHashWrongLength { slot: 1, len: 31 }
    );
    // a non-bytes element is a type error for the field
    let mut v = decode(&m.to_wire_bytes()).unwrap();
    if let Value::Map(entries) = &mut v {
        for (k, val) in entries.iter_mut() {
            if kn_for(k) == 4 {
                if let Value::Array(items) = val {
                    items[2] = Value::Text("not a hash".into());
                }
            }
        }
    }
    assert_eq!(
        ContentManifest::from_wire_bytes(&encode(&v).unwrap()).unwrap_err(),
        ContentError::FieldNotExpectedType { key: 4 }
    );
}

#[test]
fn content_type_bounds() {
    let (m, _) = build();
    assert_eq!(
        ContentManifest::from_wire_bytes(&patched(&m, 5, Value::Text(String::new())))
            .unwrap_err(),
        ContentError::ContentTypeInvalid { bytes: 0 }
    );
    let long = "x".repeat(CONTENT_TYPE_MAX_BYTES + 1);
    assert_eq!(
        ContentManifest::from_wire_bytes(&patched(&m, 5, Value::Text(long.clone())))
            .unwrap_err(),
        ContentError::ContentTypeInvalid {
            bytes: CONTENT_TYPE_MAX_BYTES + 1
        }
    );
    // the cap itself is fine
    let at_cap = "y".repeat(CONTENT_TYPE_MAX_BYTES);
    let (capped, chunks) = ContentManifest::chunk(b"z", 4, &at_cap, None, 1).expect("builds");
    assert_eq!(capped.reassemble(&chunks).unwrap(), b"z");
}

#[test]
fn metadata_bounds_adversarial() {
    let (m, chunks) = build();
    // 16 entries at the cap
    let mut full = BTreeMap::new();
    for i in 0..METADATA_MAX_ENTRIES {
        full.insert(format!("k{i:02}"), MetadataValue::Int(i as i64));
    }
    let (capped, cc) = ContentManifest::chunk(CONTENT, 7, "a/b", Some(full), 1).expect("16 ok");
    assert_eq!(capped.reassemble(&cc).unwrap(), CONTENT);
    // 17 refused
    let mut over = BTreeMap::new();
    for i in 0..METADATA_MAX_ENTRIES + 1 {
        over.insert(format!("k{i:02}"), MetadataValue::Int(i as i64));
    }
    assert_eq!(
        ContentManifest::chunk(CONTENT, 7, "a/b", Some(over), 1).unwrap_err(),
        ContentError::MetadataTooManyEntries {
            count: METADATA_MAX_ENTRIES + 1,
            max: METADATA_MAX_ENTRIES
        }
    );
    // key at cap ok / over refused
    let mut key_cap = BTreeMap::new();
    key_cap.insert("k".repeat(METADATA_MAX_KEY_BYTES), MetadataValue::Int(1));
    assert!(ContentManifest::chunk(CONTENT, 7, "a/b", Some(key_cap), 1).is_ok());
    let mut key_over = BTreeMap::new();
    key_over.insert(
        "k".repeat(METADATA_MAX_KEY_BYTES + 1),
        MetadataValue::Int(1),
    );
    assert_eq!(
        ContentManifest::chunk(CONTENT, 7, "a/b", Some(key_over), 1).unwrap_err(),
        ContentError::MetadataKeyInvalid {
            bytes: METADATA_MAX_KEY_BYTES + 1,
            max: METADATA_MAX_KEY_BYTES
        }
    );
    // empty key refused
    let mut key_empty = BTreeMap::new();
    key_empty.insert(String::new(), MetadataValue::Int(1));
    assert_eq!(
        ContentManifest::chunk(CONTENT, 7, "a/b", Some(key_empty), 1).unwrap_err(),
        ContentError::MetadataKeyInvalid {
            bytes: 0,
            max: METADATA_MAX_KEY_BYTES
        }
    );
    // text value at cap ok / over refused (via the wire: bools are not
    // text/int; oversized text is caught at parse)
    let mut val_cap = BTreeMap::new();
    val_cap.insert(
        "k".to_string(),
        MetadataValue::Text("v".repeat(METADATA_MAX_VALUE_TEXT_BYTES)),
    );
    assert!(ContentManifest::chunk(CONTENT, 7, "a/b", Some(val_cap), 1).is_ok());
    let over_text = "v".repeat(METADATA_MAX_VALUE_TEXT_BYTES + 1);
    // craft the wire directly: metadata map with an oversized text value
    let oversized = Value::Map(vec![
        (Value::Text("k".into()), Value::Text(over_text.clone())),
    ]);
    let mut v = decode(&m.to_wire_bytes()).unwrap();
    if let Value::Map(entries) = &mut v {
        entries.push((Value::Int(6), oversized));
    }
    assert_eq!(
        ContentManifest::from_wire_bytes(&encode(&v).unwrap()).unwrap_err(),
        ContentError::MetadataValueInvalid
    );
    // bool value: not text/int
    let bool_val = Value::Map(vec![(Value::Text("k".into()), Value::Bool(true))]);
    let mut v = decode(&m.to_wire_bytes()).unwrap();
    if let Value::Map(entries) = &mut v {
        entries.push((Value::Int(6), bool_val));
    }
    assert_eq!(
        ContentManifest::from_wire_bytes(&encode(&v).unwrap()).unwrap_err(),
        ContentError::MetadataEntryMalformed
    );
    // bytes value: not text/int
    let bytes_val = Value::Map(vec![(Value::Text("k".into()), Value::Bytes(vec![1, 2]))]);
    let mut v = decode(&m.to_wire_bytes()).unwrap();
    if let Value::Map(entries) = &mut v {
        entries.push((Value::Int(6), bytes_val));
    }
    assert_eq!(
        ContentManifest::from_wire_bytes(&encode(&v).unwrap()).unwrap_err(),
        ContentError::MetadataEntryMalformed
    );
    // 17 entries through the wire
    let seventeen: Vec<(Value, Value)> = (0..17)
        .map(|i| (Value::Text(format!("k{i:02}")), Value::Int(i as i64)))
        .collect();
    let mut v = decode(&m.to_wire_bytes()).unwrap();
    if let Value::Map(entries) = &mut v {
        entries.push((Value::Int(6), Value::Map(seventeen)));
    }
    assert_eq!(
        ContentManifest::from_wire_bytes(&encode(&v).unwrap()).unwrap_err(),
        ContentError::MetadataTooManyEntries {
            count: 17,
            max: METADATA_MAX_ENTRIES
        }
    );
    // 16 entries through the wire: fine, reassembles
    let sixteen: Vec<(Value, Value)> = (0..16)
        .map(|i| (Value::Text(format!("k{i:02}")), Value::Int(i as i64)))
        .collect();
    let mut v = decode(&m.to_wire_bytes()).unwrap();
    if let Value::Map(entries) = &mut v {
        entries.push((Value::Int(6), Value::Map(sixteen)));
    }
    let parsed = ContentManifest::from_wire_bytes(&encode(&v).unwrap()).expect("parses");
    assert_eq!(parsed.metadata().map(|m| m.len()), Some(16));
    assert_eq!(parsed.reassemble(&chunks).unwrap(), CONTENT);
}

// ---------------------------------------------------------------------------
// Strict parsing: non-canonical and malformed wire forms
// ---------------------------------------------------------------------------

#[test]
fn non_canonical_and_malformed_manifests_refused() {
    let (m, _) = build();
    let good = m.to_wire_bytes();

    // not a map
    assert_eq!(
        ContentManifest::from_wire_bytes(&encode(&Value::Array(vec![])).unwrap()).unwrap_err(),
        ContentError::NotAMap
    );
    // scheme_version 2
    assert_eq!(
        ContentManifest::from_wire_bytes(&patched(&m, 1, Value::Int(2))).unwrap_err(),
        ContentError::SchemeVersionUnsupported { found: 2 }
    );
    // unknown field 8
    let mut v = decode(&good).unwrap();
    if let Value::Map(entries) = &mut v {
        entries.push((Value::Int(8), Value::Null));
    }
    assert_eq!(
        ContentManifest::from_wire_bytes(&encode(&v).unwrap()).unwrap_err(),
        ContentError::UnknownField { key: 8 }
    );
    // missing field 5
    let mut v = decode(&good).unwrap();
    if let Value::Map(entries) = &mut v {
        entries.retain(|(k, _)| kn_for(k) != 5);
    }
    assert_eq!(
        ContentManifest::from_wire_bytes(&encode(&v).unwrap()).unwrap_err(),
        ContentError::MissingField { key: 5 }
    );
    // wrong types
    assert_eq!(
        ContentManifest::from_wire_bytes(&patched(&m, 2, Value::Text("7".into()))).unwrap_err(),
        ContentError::FieldNotExpectedType { key: 2 }
    );
    assert_eq!(
        ContentManifest::from_wire_bytes(&patched(&m, 4, Value::Bytes(vec![0; 32]))).unwrap_err(),
        ContentError::FieldNotExpectedType { key: 4 }
    );
    // negative created_at
    assert_eq!(
        ContentManifest::from_wire_bytes(&patched(&m, 7, Value::Int(-1))).unwrap_err(),
        ContentError::TimestampNegative { field: "created_at" }
    );
    // created_at beyond the canonical integer range (via the builder)
    assert_eq!(
        ContentManifest::new(7, 17, vec![[0u8; 32]; 3], "a/b", None, i64::MAX as u64 + 1)
            .unwrap_err(),
        ContentError::TimestampOutOfRange
    );

    // non-minimal integer for field 1 (0x18 0x01): profile violation
    let mut nonminimal = Vec::with_capacity(good.len() + 1);
    nonminimal.extend_from_slice(&good[..2]);
    nonminimal.extend_from_slice(&[0x18, 0x01]);
    nonminimal.extend_from_slice(&good[3..]);
    assert_eq!(
        ContentManifest::from_wire_bytes(&nonminimal).unwrap_err().name(),
        "cbor:NonMinimalInteger"
    );
    // trailing bytes after a complete manifest
    let mut trailing = good.clone();
    trailing.push(0x00);
    assert_eq!(
        ContentManifest::from_wire_bytes(&trailing).unwrap_err().name(),
        "cbor:TrailingBytes"
    );
    // truncation
    assert_eq!(
        ContentManifest::from_wire_bytes(&good[..good.len() - 1])
            .unwrap_err()
            .name(),
        "cbor:Truncated"
    );
    // empty input
    assert_eq!(
        ContentManifest::from_wire_bytes(&[]).unwrap_err().name(),
        "cbor:EmptyInput"
    );
    // craft duplicate-key bytes by splicing a second field 2 after the first
    let mut dup = Vec::with_capacity(good.len() + 2);
    dup.extend_from_slice(&good[..3]); // 0xa6, 0x01, 0x01
    dup.extend_from_slice(&good[3..5]); // field 2 tag + value (0x02, 0x07)
    dup.extend_from_slice(&[0x02, 0x08]); // a DUPLICATE field 2
    dup.extend_from_slice(&good[5..]);
    // fix the map length: 6 -> 7 entries
    dup[0] = 0xa7;
    assert_eq!(
        ContentManifest::from_wire_bytes(&dup).unwrap_err().name(),
        "cbor:DuplicateMapKey"
    );
}

#[test]
fn empty_content_is_never_a_named_object() {
    assert_eq!(
        ContentManifest::chunk(b"", 7, "a/b", None, 1).unwrap_err(),
        ContentError::ContentEmpty
    );
    // and one byte is
    let (m, chunks) = ContentManifest::chunk(b"x", 7, "a/b", None, 1).expect("builds");
    assert_eq!((m.total_length(), m.chunk_count()), (1, 1));
    assert_eq!(m.reassemble(&chunks).unwrap(), b"x");
}
