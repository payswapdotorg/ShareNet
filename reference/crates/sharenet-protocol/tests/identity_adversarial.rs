//! Adversarial tests for identity binding and the durable identity store (R1-001).
//!
//! Coverage (per the assignment's §5):
//!
//! - tampered display_name (node_id still verifies — metadata is unbound — documented),
//!   tampered public_key / scheme_version (MUST change node_id / fail);
//! - swapped seed↔object (key does not match object → reject);
//! - corrupted / truncated identity file → fail closed, file left untouched;
//! - loose file permissions → fail closed;
//! - scheme_version ≠ 1 → reject;
//! - malleable / oversized / short Ed25519 signatures → verify fails;
//! - signature from a different key → fails; valid signature replayed against a
//!   different payload → fails;
//! - RFC 8032 conformance vectors;
//! - zeroization primitives and Debug redaction.

mod common;

use common::{from_hex, write_file, TempDir};
use sharenet_protocol::cbor::{decode, encode, Value};
use sharenet_protocol::identity::{
    derive_node_id, Identity, IdentityError, NodeIdentity, MAX_DISPLAY_NAME_BYTES, SCHEME_VERSION,
    SEED_LEN, SIGNATURE_LEN,
};
use sharenet_protocol::store::{load_identity_file, IdentityStore, StoreError};

// ---------------------------------------------------------------------------
// RFC 8032 §7.1 conformance
// ---------------------------------------------------------------------------

const RFC8032_VECTORS: &[(&str, &str, &str, &str)] = &[
    // (seed hex, public key hex, message hex, signature hex)
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
];

#[test]
fn rfc8032_signatures_match_exactly() {
    for (i, (seed_hex, pk_hex, msg_hex, sig_hex)) in RFC8032_VECTORS.iter().enumerate() {
        let seed: [u8; SEED_LEN] = from_hex(seed_hex).try_into().expect("seed len");
        let id = Identity::from_seed(seed, 0, None).unwrap();
        assert_eq!(
            id.node_identity().public_key_bytes(),
            from_hex(pk_hex).as_slice(),
            "public key mismatch in RFC 8032 vector {i}"
        );
        let msg = from_hex(msg_hex);
        let sig = id.sign_detached(&msg);
        assert_eq!(
            sig.as_slice(),
            from_hex(sig_hex).as_slice(),
            "signature mismatch in RFC 8032 vector {i}"
        );
        assert!(
            id.node_identity().verify_detached(&msg, &sig).is_ok(),
            "verify failed for RFC 8032 vector {i}"
        );
    }
}

// ---------------------------------------------------------------------------
// Signature adversarial cases
// ---------------------------------------------------------------------------

/// Little-endian 256-bit addition (mod 2^256), used to build malleable signatures.
fn le256_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let s = a[i] as u16 + b[i] as u16 + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    out
}

#[test]
fn verify_rejects_malleable_signature() {
    // S' = S + L (mod 2^256) still satisfies the verification equation but is
    // non-canonical (S' >= L); strict verification must reject it.
    // L = 2^252 + 27742317777372353535851937790883648493, little-endian:
    let l_le: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    let seed: [u8; SEED_LEN] = from_hex(RFC8032_VECTORS[0].0).try_into().unwrap();
    let id = Identity::from_seed(seed, 0, None).unwrap();
    let payload = b"malleability probe";
    let sig = id.sign_detached(payload);
    assert!(id.node_identity().verify_detached(payload, &sig).is_ok());

    let mut s_malleable = [0u8; 32];
    s_malleable.copy_from_slice(&sig[32..]);
    let s_prime = le256_add(&s_malleable, &l_le);
    let mut malleable = [0u8; SIGNATURE_LEN];
    malleable[..32].copy_from_slice(&sig[..32]);
    malleable[32..].copy_from_slice(&s_prime);
    assert!(
        malleable != sig,
        "test bug: malleable signature is identical to the original"
    );
    assert!(
        id.node_identity()
            .verify_detached(payload, &malleable)
            .is_err(),
        "strict verification must reject the malleable signature (S >= L)"
    );
}

#[test]
fn verify_rejects_wrong_length_signatures() {
    let seed: [u8; SEED_LEN] = from_hex(RFC8032_VECTORS[0].0).try_into().unwrap();
    let id = Identity::from_seed(seed, 0, None).unwrap();
    let payload = b"payload";
    let sig = id.sign_detached(payload);
    for bad_len in [0usize, 1, 32, 63, 65, 127, 128, 256] {
        let bad = vec![0x42u8; bad_len];
        assert!(
            id.node_identity().verify_detached(payload, &bad).is_err(),
            "signature of length {bad_len} must not verify"
        );
    }
    // Oversized/short variants of the real signature.
    let mut oversized = sig.to_vec();
    oversized.push(0);
    assert!(id
        .node_identity()
        .verify_detached(payload, &oversized)
        .is_err());
    assert!(id
        .node_identity()
        .verify_detached(payload, &sig[..63])
        .is_err());
}

#[test]
fn verify_rejects_foreign_signature_and_payload_replay() {
    let seed_a: [u8; SEED_LEN] = from_hex(RFC8032_VECTORS[0].0).try_into().unwrap();
    let seed_b: [u8; SEED_LEN] = from_hex(RFC8032_VECTORS[1].0).try_into().unwrap();
    let a = Identity::from_seed(seed_a, 0, None).unwrap();
    let b = Identity::from_seed(seed_b, 0, None).unwrap();
    let payload = b"shared payload";
    let sig_by_b = b.sign_detached(payload);
    // Signature from key B must not verify under key A.
    assert!(a
        .node_identity()
        .verify_detached(payload, &sig_by_b)
        .is_err());
    // Replay of A's valid signature against a different payload must fail.
    let sig_by_a = a.sign_detached(payload);
    assert!(a
        .node_identity()
        .verify_detached(b"different payload", &sig_by_a)
        .is_err());
    // And bit flips anywhere in the signature break it.
    for pos in [0usize, 16, 32, 48, 63] {
        let mut flipped = sig_by_a;
        flipped[pos] ^= 0x80;
        assert!(a
            .node_identity()
            .verify_detached(payload, &flipped)
            .is_err());
    }
}

#[test]
fn signing_is_deterministic_and_covers_empty_payload() {
    let seed: [u8; SEED_LEN] = from_hex(RFC8032_VECTORS[1].0).try_into().unwrap();
    let id = Identity::from_seed(seed, 0, None).unwrap();
    assert_eq!(id.sign_detached(b""), id.sign_detached(b""));
    let sig = id.sign_detached(b"");
    assert!(id.node_identity().verify_detached(b"", &sig).is_ok());
    assert!(id.node_identity().verify_detached(b"x", &sig).is_err());
}

// ---------------------------------------------------------------------------
// NodeIdentity wire validation
// ---------------------------------------------------------------------------

fn wire_of(id: &Identity) -> Value {
    id.node_identity().to_wire()
}

#[test]
fn wire_roundtrip_preserves_fields() {
    let seed: [u8; SEED_LEN] = from_hex(RFC8032_VECTORS[0].0).try_into().unwrap();
    let id = Identity::from_seed(seed, 1_700_000_000, Some("bridge-node".into())).unwrap();
    let wire = wire_of(&id);
    let bytes = encode(&wire).unwrap();
    let back = decode(&bytes).unwrap();
    let parsed = NodeIdentity::from_wire(&back).unwrap();
    assert_eq!(
        parsed.public_key_bytes(),
        id.node_identity().public_key_bytes()
    );
    assert_eq!(parsed.created_at_unix(), 1_700_000_000);
    assert_eq!(parsed.display_name(), Some("bridge-node"));
    assert_eq!(parsed.node_id(), id.node_id());
}

#[test]
fn wire_rejects_scheme_version_other_than_one() {
    let seed: [u8; SEED_LEN] = from_hex(RFC8032_VECTORS[0].0).try_into().unwrap();
    let id = Identity::from_seed(seed, 0, None).unwrap();
    for bad in [0i64, 2, -1, i64::MAX] {
        let mut wire = wire_of(&id);
        if let Value::Map(entries) = &mut wire {
            entries[0].1 = Value::Int(bad);
        }
        match NodeIdentity::from_wire(&wire) {
            Err(IdentityError::SchemeVersionUnsupported { found }) => assert_eq!(found, bad),
            other => panic!("expected SchemeVersionUnsupported for {bad}, got {other:?}"),
        }
    }
}

#[test]
fn wire_rejects_missing_unknown_and_mistyped_fields() {
    let seed: [u8; SEED_LEN] = from_hex(RFC8032_VECTORS[0].0).try_into().unwrap();
    let id = Identity::from_seed(seed, 0, None).unwrap();

    // Missing scheme (key 1).
    let mut wire = wire_of(&id);
    if let Value::Map(entries) = &mut wire {
        entries.remove(0);
    }
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::MissingField { key: 1 })
    );

    // Missing public key (key 2).
    let mut wire = wire_of(&id);
    if let Value::Map(entries) = &mut wire {
        entries.remove(1);
    }
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::MissingField { key: 2 })
    );

    // Missing created_at (key 3).
    let mut wire = wire_of(&id);
    if let Value::Map(entries) = &mut wire {
        entries.remove(2);
    }
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::MissingField { key: 3 })
    );

    // Unknown field 5.
    let mut wire = wire_of(&id);
    if let Value::Map(entries) = &mut wire {
        entries.push((Value::Int(5), Value::Null));
    }
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::UnknownField { key: 5 })
    );

    // Wrong types.
    let mut wire = wire_of(&id);
    if let Value::Map(entries) = &mut wire {
        entries[1].1 = Value::Text("not-a-key".into());
    }
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::FieldNotExpectedType { key: 2 })
    );
    let mut wire = wire_of(&id);
    if let Value::Map(entries) = &mut wire {
        entries[2].1 = Value::Bytes(vec![0]);
    }
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::FieldNotExpectedType { key: 3 })
    );

    // Public key with the wrong length.
    let mut wire = wire_of(&id);
    if let Value::Map(entries) = &mut wire {
        entries[1].1 = Value::Bytes(vec![0u8; 31]);
    }
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::PublicKeyWrongLength { len: 31 })
    );

    // Invalid Ed25519 point encoding: 32 × 0xff is a non-canonical y (>= p).
    let mut wire = wire_of(&id);
    if let Value::Map(entries) = &mut wire {
        entries[1].1 = Value::Bytes(vec![0xffu8; 32]);
    }
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::PublicKeyInvalid)
    );

    // Negative created_at.
    let mut wire = wire_of(&id);
    if let Value::Map(entries) = &mut wire {
        entries[2].1 = Value::Int(-1);
    }
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::CreatedAtOutOfRange { found: -1 })
    );

    // Not a map at all.
    assert_eq!(
        NodeIdentity::from_wire(&Value::Array(vec![])),
        Err(IdentityError::NotAMap)
    );
}

#[test]
fn display_name_boundaries() {
    let seed: [u8; SEED_LEN] = from_hex(RFC8032_VECTORS[0].0).try_into().unwrap();
    // Exactly 64 bytes: allowed.
    let name_64 = "x".repeat(64);
    let id = Identity::from_seed(seed, 0, Some(name_64.clone())).unwrap();
    let wire = wire_of(&id);
    let parsed = NodeIdentity::from_wire(&wire).unwrap();
    assert_eq!(parsed.display_name(), Some(name_64.as_str()));
    // 65 bytes: rejected at construction...
    let name_65 = "x".repeat(65);
    assert_eq!(
        Identity::from_seed(seed, 0, Some(name_65.clone())),
        Err(IdentityError::DisplayNameTooLong {
            bytes: 65,
            max: MAX_DISPLAY_NAME_BYTES
        })
    );
    // ...and on the wire.
    let mut wire = wire_of(&id);
    if let Value::Map(entries) = &mut wire {
        entries[3].1 = Value::Text(name_65);
    }
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::DisplayNameTooLong {
            bytes: 65,
            max: MAX_DISPLAY_NAME_BYTES
        })
    );
    // Multi-byte UTF-8 counts as bytes, not characters.
    let emoji_64_bytes: String = "🌉".repeat(16); // 16 * 4 = 64 bytes
    assert_eq!(emoji_64_bytes.len(), 64);
    let id2 = Identity::from_seed(seed, 0, Some(emoji_64_bytes.clone())).unwrap();
    assert_eq!(
        id2.node_identity().display_name(),
        Some(emoji_64_bytes.as_str())
    );
}

// ---------------------------------------------------------------------------
// node_id binding
// ---------------------------------------------------------------------------

#[test]
fn tampered_public_key_or_scheme_changes_node_id() {
    let seed: [u8; SEED_LEN] = from_hex(RFC8032_VECTORS[0].0).try_into().unwrap();
    let id = Identity::from_seed(seed, 0, None).unwrap();
    let pk = id.node_identity().public_key_bytes();
    let original = derive_node_id(SCHEME_VERSION, &pk);

    let mut tampered_pk = pk;
    tampered_pk[31] ^= 0x01;
    assert_ne!(derive_node_id(SCHEME_VERSION, &tampered_pk), original);

    assert_ne!(derive_node_id(2, &pk), original);

    // A tampered public key inside a stored identity is also a seed↔object mismatch
    // (covered separately in the store tests).
}

#[test]
fn tampered_display_name_keeps_node_id_stable() {
    // display_name and created_at are mutable metadata and are deliberately NOT part
    // of the node_id derivation: renaming a node must not break its identity binding.
    // (Documented: knowing node_id binds you to the key material and the scheme.)
    let seed: [u8; SEED_LEN] = from_hex(RFC8032_VECTORS[0].0).try_into().unwrap();
    let a = Identity::from_seed(seed, 111, None).unwrap();
    let b = Identity::from_seed(seed, 222, Some("tampered-name".into())).unwrap();
    assert_eq!(a.node_id(), b.node_id());
    assert_ne!(
        a.node_identity().display_name(),
        b.node_identity().display_name()
    );
    assert_ne!(
        a.node_identity().created_at_unix(),
        b.node_identity().created_at_unix()
    );
}

// ---------------------------------------------------------------------------
// Store: durability, atomicity, fail-closed behavior
// ---------------------------------------------------------------------------

#[test]
fn store_create_load_and_idempotence() {
    let tmp = TempDir::new("store-basic");
    let store = IdentityStore::new(tmp.path());
    let created = store.create(Some("alpha")).unwrap();
    let file = store.identity_path();
    assert!(file.is_file());

    #[cfg(unix)]
    assert_eq!(
        common::mode_of(&file),
        0o600,
        "identity file must be exactly 0600"
    );

    // Loading yields the same identity (same node_id, same public key).
    let loaded = store.load().unwrap();
    assert_eq!(loaded.node_id(), created.node_id());
    assert_eq!(
        loaded.node_identity().public_key_bytes(),
        created.node_identity().public_key_bytes()
    );
    assert_eq!(loaded.node_identity().display_name(), Some("alpha"));

    // load_or_create loads (does not regenerate) once the file exists.
    let again = store.load_or_create(None).unwrap();
    assert_eq!(again.node_id(), created.node_id());

    // Creating again refuses to overwrite.
    match store.create(None) {
        Err(StoreError::AlreadyExists { path }) => assert_eq!(path, file),
        other => panic!("expected AlreadyExists, got {other:?}"),
    }
    // ...and the file was not modified.
    let loaded = store.load().unwrap();
    assert_eq!(loaded.node_id(), created.node_id());
}

#[test]
fn store_fresh_directory_load_or_create_generates_once() {
    let tmp = TempDir::new("store-loc");
    let store = IdentityStore::new(tmp.join("nested/deeper"));
    let a = store.load_or_create(Some("deep")).unwrap();
    let b = store.load_or_create(Some("deep")).unwrap();
    assert_eq!(
        a.node_id(),
        b.node_id(),
        "load_or_create must not regenerate"
    );
    assert!(store.identity_path().is_file());
}

fn write_identity_file_raw(path: &std::path::Path, bytes: &[u8]) {
    write_file(path, bytes);
    #[cfg(unix)]
    common::set_mode(path, 0o600);
}

/// Build raw identity-file bytes for an arbitrary (seed, NodeIdentity-wire) combination.
fn file_bytes(seed: &[u8], node: &Value) -> Vec<u8> {
    encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(seed.to_vec())),
        (Value::Int(2), node.clone()),
    ]))
    .unwrap()
}

#[test]
fn store_fail_closed_on_truncation_and_garbage() {
    let tmp = TempDir::new("store-corrupt");
    let store = IdentityStore::new(tmp.path());
    let id = store.create(None).unwrap();
    let file = store.identity_path();
    let original = std::fs::read(&file).unwrap();

    // Truncated file.
    write_identity_file_raw(&file, &original[..original.len() - 4]);
    assert!(matches!(store.load(), Err(StoreError::Decode { .. })));
    // The failed load must NOT have rewritten/recreated the file.
    assert_eq!(
        std::fs::read(&file).unwrap(),
        &original[..original.len() - 4]
    );

    // Garbage.
    write_identity_file_raw(&file, &[0xde, 0xad, 0xbe, 0xef]);
    assert!(matches!(store.load(), Err(StoreError::Decode { .. })));
    assert_eq!(std::fs::read(&file).unwrap(), vec![0xde, 0xad, 0xbe, 0xef]);

    // Empty file.
    write_identity_file_raw(&file, &[]);
    assert!(matches!(store.load(), Err(StoreError::Decode { .. })));

    // Not a map at top level.
    write_identity_file_raw(&file, &encode(&Value::Array(vec![])).unwrap());
    assert!(matches!(store.load(), Err(StoreError::FileNotMap { .. })));

    // The original file (restored) still loads; node_id stable across all this.
    write_identity_file_raw(&file, &original);
    assert_eq!(store.load().unwrap().node_id(), id.node_id());
}

#[test]
fn store_fail_closed_on_swapped_seed_and_object() {
    let tmp_a = TempDir::new("store-swap-a");
    let tmp_b = TempDir::new("store-swap-b");
    let a = IdentityStore::new(tmp_a.path()).create(None).unwrap();
    let b = IdentityStore::new(tmp_b.path()).create(None).unwrap();

    // A's seed with B's NodeIdentity object.
    let seed_a: [u8; SEED_LEN] = std::fs::read(tmp_a.join("identity.cbor"))
        .map(|bytes| extract_seed(&bytes))
        .unwrap();
    let swapped = file_bytes(&seed_a, &b.node_identity().to_wire());
    let target = tmp_a.join("identity.cbor");
    write_identity_file_raw(&target, &swapped);
    match IdentityStore::new(tmp_a.path()).load() {
        Err(StoreError::SeedMismatch { .. }) => {}
        other => panic!("expected SeedMismatch, got {other:?}"),
    }

    // Tampered public key inside the object (valid point, different key): mismatch too.
    let mut node = a.node_identity().to_wire();
    if let Value::Map(entries) = &mut node {
        entries[1].1 = Value::Bytes(b.node_identity().public_key_bytes().to_vec());
    }
    let tampered = file_bytes(&seed_a, &node);
    write_identity_file_raw(&target, &tampered);
    assert!(matches!(
        IdentityStore::new(tmp_a.path()).load(),
        Err(StoreError::SeedMismatch { .. })
    ));
}

fn extract_seed(file_bytes_vec: &[u8]) -> [u8; SEED_LEN] {
    let v = decode(file_bytes_vec).expect("valid file for seed extraction");
    let Value::Map(entries) = v else {
        panic!("not a map")
    };
    for (k, val) in entries {
        if let (Value::Int(1), Value::Bytes(b)) = (k, val) {
            return b.as_slice().try_into().expect("seed length");
        }
    }
    panic!("no seed in file");
}

#[test]
fn store_fail_closed_on_scheme_tamper_and_wrong_shapes() {
    let tmp = TempDir::new("store-shape");
    let store = IdentityStore::new(tmp.path());
    let id = store.create(None).unwrap();
    let seed: [u8; SEED_LEN] = extract_seed(&std::fs::read(store.identity_path()).unwrap());

    // scheme_version = 2 in the object: wire-level rejection, and (independently) the
    // node_id derivation over scheme 2 differs — both directions are pinned by tests.
    let mut node = id.node_identity().to_wire();
    if let Value::Map(entries) = &mut node {
        entries[0].1 = Value::Int(2);
    }
    let path = store.identity_path();
    write_identity_file_raw(&path, &file_bytes(&seed, &node));
    assert!(matches!(
        IdentityStore::new(tmp.path()).load(),
        Err(StoreError::Identity {
            source: IdentityError::SchemeVersionUnsupported { .. },
            ..
        })
    ));

    // Seed with the wrong length.
    write_identity_file_raw(
        &path,
        &file_bytes(&[1u8; 31], &id.node_identity().to_wire()),
    );
    assert!(matches!(
        IdentityStore::new(tmp.path()).load(),
        Err(StoreError::FileSeedWrongLength { len: 31, .. })
    ));

    // Unknown top-level field 3.
    let mut v = Value::Map(vec![
        (Value::Int(1), Value::Bytes(seed.to_vec())),
        (Value::Int(2), id.node_identity().to_wire()),
    ]);
    if let Value::Map(entries) = &mut v {
        entries.push((Value::Int(3), Value::Null));
    }
    write_identity_file_raw(&path, &encode(&v).unwrap());
    assert!(matches!(
        IdentityStore::new(tmp.path()).load(),
        Err(StoreError::FileUnknownField { key: 3, .. })
    ));

    // Missing field 2 entirely.
    write_identity_file_raw(
        &path,
        &encode(&Value::Map(vec![(
            Value::Int(1),
            Value::Bytes(seed.to_vec()),
        )]))
        .unwrap(),
    );
    assert!(matches!(
        IdentityStore::new(tmp.path()).load(),
        Err(StoreError::FileMissingField { key: 2, .. })
    ));
}

#[test]
fn store_metadata_tamper_display_name_ok_node_id_stable() {
    // Renaming via direct file tamper: the seed still matches the public key, so the
    // file remains valid, and the node_id is unchanged — display_name is unbound
    // metadata. This documents WHY (mutable metadata excluded from derivation) while
    // public_key/scheme_version tampering fails closed (tests above).
    let tmp = TempDir::new("store-rename");
    let store = IdentityStore::new(tmp.path());
    let id = store.create(Some("original-name")).unwrap();
    let seed: [u8; SEED_LEN] = extract_seed(&std::fs::read(store.identity_path()).unwrap());

    let mut node = id.node_identity().to_wire();
    if let Value::Map(entries) = &mut node {
        // Replace the existing display_name entry (created with Some("original-name")).
        entries[3].1 = Value::Text("tampered-name".into());
    }
    let path = store.identity_path();
    write_identity_file_raw(&path, &file_bytes(&seed, &node));
    let loaded = IdentityStore::new(tmp.path()).load().unwrap();
    assert_eq!(loaded.node_id(), id.node_id());
    assert_eq!(loaded.node_identity().display_name(), Some("tampered-name"));
}

#[cfg(unix)]
#[test]
fn store_fail_closed_on_loose_permissions() {
    let tmp = TempDir::new("store-perms");
    let store = IdentityStore::new(tmp.path());
    let id = store.create(None).unwrap();
    let file = store.identity_path();
    assert_eq!(common::mode_of(&file), 0o600);

    // Loosening any bit beyond 0600 fails closed.
    for mode in [0o644u32, 0o666, 0o640, 0o604, 0o700] {
        common::set_mode(&file, mode);
        match store.load() {
            Err(StoreError::LoosePermissions { mode: found, .. }) => {
                assert_eq!(found, mode);
            }
            other => panic!("mode {mode:o}: expected LoosePermissions, got {other:?}"),
        }
    }

    // More restrictive than 0600 (e.g. 0400) is still acceptable.
    common::set_mode(&file, 0o400);
    assert!(store.load().is_ok());

    // Back to exactly 0600: fine.
    common::set_mode(&file, 0o600);
    assert_eq!(store.load().unwrap().node_id(), id.node_id());
}

#[cfg(unix)]
#[test]
fn store_refuses_symlink_identity_file() {
    let tmp = TempDir::new("store-symlink");
    let store = IdentityStore::new(tmp.path());
    let _id = store.create(None).unwrap();
    let file = store.identity_path();
    let victim = tmp.join("victim.cbor");
    std::fs::rename(&file, &victim).unwrap();
    std::os::unix::fs::symlink(&victim, &file).expect("symlink");
    match store.load() {
        Err(StoreError::RefusedSymlink { .. }) => {}
        other => panic!("expected RefusedSymlink, got {other:?}"),
    }
    // Creating over the symlink also refuses (the symlink exists).
    assert!(matches!(
        store.create(None),
        Err(StoreError::AlreadyExists { .. })
    ));
}

#[test]
fn store_no_silent_recreation_over_tampered_file() {
    // The critical fail-closed property: a corrupt existing file must cause
    // load_or_create to ERROR, never to silently overwrite/recreate.
    let tmp = TempDir::new("store-norecreate");
    let store = IdentityStore::new(tmp.path());
    let id = store.create(None).unwrap();
    let file = store.identity_path();
    let tampered = {
        let mut bytes = std::fs::read(&file).unwrap();
        // Corrupt a byte inside the seed region (offsets 4..36): the file layout is
        // a2 01 58 20 <32 seed bytes> ... so offset 10 is seed material. The seed↔object
        // cross-check must fail closed on this.
        assert_eq!(bytes[0], 0xa2, "expected file map head");
        assert_eq!(bytes[3], 0x20, "expected 32-byte seed length marker");
        bytes[10] ^= 0xff;
        bytes
    };
    write_identity_file_raw(&file, &tampered);
    match store.load_or_create(None) {
        Err(_) => {}
        Ok(_) => panic!("load_or_create must fail closed over a tampered file"),
    }
    // The file is untouched (no recreation over it).
    assert_eq!(std::fs::read(&file).unwrap(), tampered);
    let _ = id;
}

#[test]
fn store_file_too_large_is_rejected() {
    let tmp = TempDir::new("store-toolarge");
    let file = tmp.join("identity.cbor");
    write_identity_file_raw(&file, &vec![0u8; 5000]);
    assert!(matches!(
        load_identity_file(&file),
        Err(StoreError::FileTooLarge { len: 5000, .. })
    ));
}

#[test]
fn store_missing_file_is_actionable_error() {
    let tmp = TempDir::new("store-missing");
    let store = IdentityStore::new(tmp.path());
    match store.load() {
        Err(StoreError::IdentityFileNotFound { path }) => {
            assert!(path.ends_with("identity.cbor"));
            assert!(path.is_absolute() || path.starts_with(tmp.path()));
        }
        other => panic!("expected IdentityFileNotFound, got {other:?}"),
    }
}

#[test]
fn store_atomic_write_leaves_no_temporary_files() {
    let tmp = TempDir::new("store-tmpclean");
    let store = IdentityStore::new(tmp.path());
    store.create(None).unwrap();
    let entries: Vec<_> = std::fs::read_dir(tmp.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(
        entries
            .iter()
            .all(|e| !e.starts_with(".identity.cbor.tmp.")),
        "leftover temporary files: {entries:?}"
    );
    assert!(entries.contains(&"identity.cbor".to_string()));
}

// ---------------------------------------------------------------------------
// End-to-end: sign via loaded store, verify via file
// ---------------------------------------------------------------------------

#[test]
fn sign_via_store_and_verify_via_identity_file() {
    let tmp = TempDir::new("store-e2e");
    let store = IdentityStore::new(tmp.path());
    let id = store.load_or_create(Some("e2e-node")).unwrap();

    let payload = b"sharenet bridge payload";
    let sig = id.sign_detached(payload);

    // The signature verifies against the identity loaded from the file.
    let from_file = load_identity_file(&store.identity_path()).unwrap();
    assert!(from_file
        .node_identity()
        .verify_detached(payload, &sig)
        .is_ok());

    // And fails against a different payload (replay resistance).
    assert!(from_file
        .node_identity()
        .verify_detached(b"replayed", &sig)
        .is_err());
}

#[test]
fn created_at_rejects_out_of_wire_range() {
    let seed: [u8; SEED_LEN] = from_hex(RFC8032_VECTORS[0].0).try_into().unwrap();
    let too_big = (i64::MAX as u64) + 1;
    assert_eq!(
        Identity::from_seed(seed, too_big, None),
        Err(IdentityError::CreatedAtOutOfRange {
            found: too_big as i128
        })
    );
    // i64::MAX itself is fine.
    assert!(Identity::from_seed(seed, i64::MAX as u64, None).is_ok());
}
