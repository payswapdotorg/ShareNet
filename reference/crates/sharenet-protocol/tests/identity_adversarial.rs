//! Adversarial + conformance tests for node identity (R1-001):
//!
//! - RFC 8032 Ed25519 test vectors (seed → public key, deterministic
//!   signatures, strict verification);
//! - malleability (S + L, high-bit S) must be rejected;
//! - wrong-key / wrong-payload / malformed-length signatures;
//! - identity-file tamper matrix (fail-closed semantics);
//! - zeroization wiring and Debug redaction;
//! - golden identity vectors in `tests/vectors/identity_vectors.json`
//!   (sync-checked, regenerable via `cargo test -- --ignored regenerate_identity_vectors`).

#![forbid(unsafe_code)]

use serde_json::json;
use sharenet_protocol::cbor::{self, MapBuilder, Value};
use sharenet_protocol::hex;
use sharenet_protocol::identity::{
    verify_detached, IdentityError, NodeIdentity, NodeSigningKey, SEED_LEN,
};
use sharenet_protocol::store::{IdentityStore, StoreError, IDENTITY_FILE_NAME};
use std::sync::atomic::{AtomicBool, Ordering};

fn seed_from_hex(s: &str) -> [u8; SEED_LEN] {
    let bytes = hex::decode(s).expect("valid hex");
    let mut seed = [0u8; SEED_LEN];
    seed.copy_from_slice(&bytes);
    seed
}

// ---------------------------------------------------------------------------
// RFC 8032 conformance (Ed25519 test vectors, §7.1)
// ---------------------------------------------------------------------------

struct Rfc8032 {
    seed: &'static str,
    public_key: &'static str,
    message_hex: &'static str,
    signature: &'static str,
}

fn rfc8032_vectors() -> Vec<Rfc8032> {
    vec![
        Rfc8032 {
            seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            message_hex: "",
            signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        },
        Rfc8032 {
            seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            public_key: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            message_hex: "72",
            signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        },
        Rfc8032 {
            seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            public_key: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            message_hex: "af82",
            signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        },
    ]
}

#[test]
fn rfc8032_seed_public_key_and_signatures_match() {
    for (i, v) in rfc8032_vectors().iter().enumerate() {
        let sk = NodeSigningKey::from_seed(&seed_from_hex(v.seed));
        assert_eq!(
            hex::encode(&sk.public_key()),
            v.public_key,
            "RFC 8032 test {} public key",
            i + 1
        );
        let message = hex::decode(v.message_hex).unwrap();
        let signature = sk.sign(&message);
        assert_eq!(
            hex::encode(&signature),
            v.signature,
            "RFC 8032 test {} signature (deterministic signing)",
            i + 1
        );
        let pk = seed_from_hex(v.public_key);
        assert!(
            verify_detached(&pk, &message, &signature).is_ok(),
            "RFC 8032 test {} verification",
            i + 1
        );
    }
}

// ---------------------------------------------------------------------------
// Signature malleability and forgery resistance
// ---------------------------------------------------------------------------

/// Ed25519 group order L, little-endian bytes:
/// L = 2^252 + 27742317777372353535851937790883648493.
const L_LE: [u8; 32] = [
    0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE,
    0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x10,
];

#[test]
fn malleable_signature_s_plus_order_is_rejected() {
    // Classic Ed25519 malleability: (R, S) with S' = S + L verifies under
    // lenient implementations (because (S+L)·B == S·B) but S' >= L is a
    // non-canonical scalar. Strict verification MUST reject it.
    let sk = NodeSigningKey::from_seed(&seed_from_hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    let payload = b"sharenut malleability probe payload";
    let sig = sk.sign(payload);

    let mut malleated = sig;
    let mut carry: u16 = 0;
    for i in 0..32 {
        let sum = malleated[32 + i] as u16 + L_LE[i] as u16 + carry;
        malleated[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "S < L guarantees S + L < 2^256");

    assert_eq!(
        verify_detached(&sk.public_key(), payload, &malleated),
        Err(IdentityError::SignatureVerificationFailed),
        "strict verification must reject the malleable signature"
    );
    // Sanity: the original signature still verifies.
    assert!(verify_detached(&sk.public_key(), payload, &sig).is_ok());
}

#[test]
fn signature_with_high_bits_set_in_s_is_rejected() {
    let sk = NodeSigningKey::from_seed(&seed_from_hex(
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    ));
    let payload = b"payload";
    let mut sig = sk.sign(payload);
    sig[63] |= 0xE0; // s >= 2^253: never a canonical scalar
    assert!(verify_detached(&sk.public_key(), payload, &sig).is_err());
}

#[test]
fn signature_from_a_different_key_is_rejected() {
    let signer = NodeSigningKey::from_seed(&seed_from_hex(
        "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    ));
    let other = NodeSigningKey::from_seed(&seed_from_hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    let payload = b"cross-key test";
    let sig = signer.sign(payload);
    assert_eq!(
        verify_detached(&other.public_key(), payload, &sig),
        Err(IdentityError::SignatureVerificationFailed)
    );
    assert!(verify_detached(&signer.public_key(), payload, &sig).is_ok());
}

#[test]
fn valid_signature_replayed_against_different_payload_is_rejected() {
    let sk = NodeSigningKey::from_seed(&seed_from_hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    let payload_a = b"payload A";
    let payload_b = b"payload B";
    let sig = sk.sign(payload_a);
    assert_eq!(
        verify_detached(&sk.public_key(), payload_b, &sig),
        Err(IdentityError::SignatureVerificationFailed)
    );
}

#[test]
fn malformed_signature_lengths_are_rejected() {
    let sk = NodeSigningKey::from_seed(&seed_from_hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    let payload = b"length probe";
    let sig = sk.sign(payload);
    for wrong in [
        Vec::new(),
        sig[..63].to_vec(),
        sig[..1].to_vec(),
        [sig.as_slice(), &[0u8]].concat(), // 65 bytes
    ] {
        assert_eq!(
            verify_detached(&sk.public_key(), payload, &wrong),
            Err(IdentityError::SignatureMalformed { len: wrong.len() }),
            "length {}",
            wrong.len()
        );
    }
}

#[test]
fn corrupted_public_key_bytes_are_rejected_by_verifier() {
    // [2, 0, ...] does not decompress to a curve point at all.
    let mut non_point = [0u8; 32];
    non_point[0] = 2;
    assert_eq!(
        verify_detached(&non_point, b"x", &[0u8; 64]),
        Err(IdentityError::InvalidPublicKey)
    );

    // All-zeros decompresses to a small-order point; strict verification
    // rejects it during the verification checks (still fail-closed).
    let zero_pk = [0u8; 32];
    assert!(verify_detached(&zero_pk, b"x", &[0u8; 64]).is_err());
}

// ---------------------------------------------------------------------------
// node_id derivation semantics
// ---------------------------------------------------------------------------

#[test]
fn node_id_binds_key_and_scheme_but_not_metadata() {
    let pk = seed_from_hex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let with_metadata = NodeIdentity::new(pk, 1_700_000_000, Some("gateway-1")).unwrap();
    let other_metadata = NodeIdentity::new(pk, 1, None).unwrap();
    assert_eq!(
        with_metadata.node_id_hex(),
        other_metadata.node_id_hex(),
        "display_name/created_at are NOT part of the node_id derivation"
    );

    // Any change to scheme or public key changes node_id.
    let mut tampered_pk = pk;
    tampered_pk[0] ^= 1;
    let tampered = NodeIdentity::new(tampered_pk, 1_700_000_000, Some("gateway-1")).unwrap();
    assert_ne!(with_metadata.node_id_hex(), tampered.node_id_hex());

    // Scheme tampering is not representable through the constructor (it is
    // fixed to 1); through the wire it is rejected (see wire tests below).
}

#[test]
fn node_id_independent_hand_computation() {
    // Independent check: node_id == SHA-256(A2 01 01 02 58 20 || public_key)
    // computed directly with SHA-256, not through to_wire().
    let pk = seed_from_hex("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
    let mut material = Vec::new();
    material.extend_from_slice(&[0xA2, 0x01, 0x01, 0x02, 0x58, 0x20]);
    material.extend_from_slice(&pk);
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&material);
    let id = NodeIdentity::new(pk, 0, None).unwrap();
    assert_eq!(hex::encode(&digest), id.node_id_hex());
}

// ---------------------------------------------------------------------------
// Strict wire parsing
// ---------------------------------------------------------------------------

fn make_wire(
    scheme: i64,
    pk: &[u8],
    created: i64,
    name: Option<&str>,
) -> Value {
    let mut builder = MapBuilder::new()
        .insert_int(1, Value::Int(scheme))
        .insert_int(2, Value::Bytes(pk.to_vec()))
        .insert_int(3, Value::Int(created));
    if let Some(n) = name {
        builder = builder.insert_int(4, Value::Text(n.to_string()));
    }
    builder.build().unwrap()
}

#[test]
fn wire_scheme_version_mismatch_is_rejected() {
    let pk = [7u8; 32];
    for bad in [0i64, 2, -1, i64::MAX] {
        let wire = make_wire(bad, &pk, 100, None);
        assert_eq!(
            NodeIdentity::from_wire(&wire),
            Err(IdentityError::UnsupportedSchemeVersion { found: bad }),
            "scheme {bad}"
        );
    }
}

#[test]
fn wire_unknown_keys_missing_keys_and_wrong_types_are_rejected() {
    let pk = [7u8; 32];

    // Unknown key 5.
    let wire = MapBuilder::new()
        .insert_int(1, Value::Int(1))
        .insert_int(2, Value::Bytes(pk.to_vec()))
        .insert_int(3, Value::Int(1))
        .insert_int(5, Value::Null)
        .build()
        .unwrap();
    assert_eq!(NodeIdentity::from_wire(&wire), Err(IdentityError::UnknownWireKey));

    // Missing key 2.
    let wire = MapBuilder::new()
        .insert_int(1, Value::Int(1))
        .insert_int(3, Value::Int(1))
        .build()
        .unwrap();
    assert_eq!(NodeIdentity::from_wire(&wire), Err(IdentityError::MissingKey(2)));

    // Public key of wrong length.
    let wire = make_wire(1, &[7u8; 31], 1, None);
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::InvalidPublicKeyLength { found: 31 })
    );

    // Wrong types.
    let wire = MapBuilder::new()
        .insert_int(1, Value::Text("one".into()))
        .insert_int(2, Value::Bytes(pk.to_vec()))
        .insert_int(3, Value::Int(1))
        .build()
        .unwrap();
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::WrongType { key: 1, expected: "integer" })
    );

    // Not a map at all.
    assert_eq!(NodeIdentity::from_wire(&Value::Int(1)), Err(IdentityError::NotAMap));

    // Display name too long (65 bytes).
    let wire = make_wire(1, &pk, 1, Some(&"x".repeat(65)));
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::DisplayNameTooLong { bytes: 65, max: 64 })
    );

    // Negative timestamp.
    let wire = make_wire(1, &pk, -1, None);
    assert_eq!(
        NodeIdentity::from_wire(&wire),
        Err(IdentityError::TimestampOutOfRange { found: -1 })
    );
}

#[test]
fn tampered_public_key_in_object_changes_node_id_and_fails_file_load() {
    // (a) At the object level, node_id is a pure function of (scheme, pk):
    //     tampering pk changes node_id.
    let pk = [9u8; 32];
    let original = NodeIdentity::new(pk, 5, None).unwrap();
    let mut tampered_pk = pk;
    tampered_pk[31] ^= 0x40;
    let tampered = NodeIdentity::new(tampered_pk, 5, None).unwrap();
    assert_ne!(original.node_id_hex(), tampered.node_id_hex());

    // (b) At the file level, an object whose public key does not match the
    //     seed fails closed (see also store unit tests).
    let dir = tempfile::tempdir().unwrap();
    IdentityStore::load_or_create(dir.path(), None).unwrap();
    let path = dir.path().join(IDENTITY_FILE_NAME);
    let raw = std::fs::read(&path).unwrap();
    let v = cbor::decode(&raw).unwrap();
    let mut file_entries = v.as_map().unwrap().to_vec();
    for (k, val) in file_entries.iter_mut() {
        if k.as_int() == Some(2) {
            let mut object_entries = val.as_map().unwrap().to_vec();
            for (ok, oval) in object_entries.iter_mut() {
                if ok.as_int() == Some(2) {
                    let mut pk_bytes = oval.as_bytes().unwrap().to_vec();
                    pk_bytes[0] ^= 0x01;
                    *oval = Value::Bytes(pk_bytes);
                }
            }
            *val = cbor::canonicalize_map(object_entries).unwrap();
        }
    }
    let rebuilt = cbor::canonicalize_map(file_entries).unwrap();
    std::fs::write(&path, cbor::encode(&rebuilt).unwrap()).unwrap();
    match IdentityStore::load(dir.path()) {
        Err(StoreError::PublicKeyMismatch { .. }) => {}
        other => panic!("expected PublicKeyMismatch, got {other:?}"),
    }
}

#[test]
fn tampered_display_name_is_unbound_metadata() {
    // display_name tampering does NOT invalidate the file and does NOT
    // change node_id: the name is deliberately outside the node_id
    // derivation (documented, intended semantics — mutable metadata).
    let dir = tempfile::tempdir().unwrap();
    let (created, _) = IdentityStore::load_or_create(dir.path(), Some("original")).unwrap();
    let node_id = created.node_id_hex();
    let path = dir.path().join(IDENTITY_FILE_NAME);
    let raw = std::fs::read(&path).unwrap();

    let v = cbor::decode(&raw).unwrap();
    let mut file_entries = v.as_map().unwrap().to_vec();
    for (k, val) in file_entries.iter_mut() {
        if k.as_int() == Some(2) {
            let mut object_entries = val.as_map().unwrap().to_vec();
            for (ok, oval) in object_entries.iter_mut() {
                if ok.as_int() == Some(4) {
                    *oval = Value::Text("tampered-but-valid".into());
                }
            }
            *val = cbor::canonicalize_map(object_entries).unwrap();
        }
    }
    let rebuilt = cbor::canonicalize_map(file_entries).unwrap();
    std::fs::write(&path, cbor::encode(&rebuilt).unwrap()).unwrap();

    let (loaded, was_created) = IdentityStore::load_or_create(dir.path(), None).unwrap();
    assert!(!was_created, "an existing valid file must be loaded, not recreated");
    assert_eq!(loaded.node_id_hex(), node_id, "node_id must be unaffected by name edits");
    assert_eq!(loaded.identity().display_name(), Some("tampered-but-valid"));
}

#[test]
fn swapped_seed_and_object_fails_closed() {
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let _ = IdentityStore::load_or_create(dir_a.path(), None).unwrap();
    let _ = IdentityStore::load_or_create(dir_b.path(), None).unwrap();

    let read = |dir: &tempfile::TempDir| -> Value {
        let raw = std::fs::read(dir.path().join(IDENTITY_FILE_NAME)).unwrap();
        cbor::decode(&raw).unwrap()
    };
    let a = read(&dir_a);
    let b = read(&dir_b);
    let swapped = MapBuilder::new()
        .insert(Value::Int(1), a.get_by_int(1).unwrap().clone()) // seed of A
        .insert(Value::Int(2), b.get_by_int(2).unwrap().clone()) // object of B
        .build()
        .unwrap();
    std::fs::write(
        dir_a.path().join(IDENTITY_FILE_NAME),
        cbor::encode(&swapped).unwrap(),
    )
    .unwrap();
    match IdentityStore::load(dir_a.path()) {
        Err(StoreError::PublicKeyMismatch { .. }) => {}
        other => panic!("expected PublicKeyMismatch, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Zeroization and secret handling
// ---------------------------------------------------------------------------

#[test]
fn zeroizing_wrapper_calls_zeroize_on_drop() {
    // Probe type that records zeroize() calls; proves the Zeroizing<D>
    // mechanism used for seed buffers really wipes on drop.
    use zeroize::Zeroize;

    struct ProbeData {
        flag: std::sync::Arc<AtomicBool>,
        bytes: [u8; 32],
    }
    impl Zeroize for ProbeData {
        fn zeroize(&mut self) {
            self.bytes = [0u8; 32];
            self.flag.store(true, Ordering::SeqCst);
        }
    }

    let flag = std::sync::Arc::new(AtomicBool::new(false));
    {
        let _z = zeroize::Zeroizing::new(ProbeData {
            flag: flag.clone(),
            bytes: [0x41; 32],
        });
        assert!(!flag.load(Ordering::SeqCst), "zeroize must not run before drop");
    }
    assert!(flag.load(Ordering::SeqCst), "Zeroizing must zeroize on drop");

    // The same mechanism is what ed25519-dalek's SigningKey uses for its
    // seed via the `zeroize` feature (verified in the vendored source:
    // `impl Drop for SigningKey { fn drop(&mut self) { self.secret_key.zeroize() } }`).
    // Reading the actual wiped memory of a third-party type is not possible
    // from safe code, so that part is a wiring assertion (feature enabled,
    // wrapper documented) rather than a memory observation — an honestly
    // documented limit.
}

#[test]
fn debug_output_never_leaks_seed_material() {
    let seed_hex = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7";
    let seed = seed_from_hex(seed_hex);
    let sk = NodeSigningKey::from_seed(&seed);

    let key_debug = format!("{sk:?}");
    assert!(!key_debug.contains(seed_hex), "NodeSigningKey Debug leaks the seed");
    assert!(key_debug.contains("<redacted>"));

    // LoadedIdentity path: create a store file from this seed.
    let dir = tempfile::tempdir().unwrap();
    let identity = sk.node_identity(Some("leak-probe"), 1).unwrap();
    let file_value = MapBuilder::new()
        .insert_int(1, Value::Bytes(seed.to_vec()))
        .insert_int(2, identity.to_wire())
        .build()
        .unwrap();
    std::fs::create_dir_all(dir.path()).unwrap();
    std::fs::write(dir.path().join(IDENTITY_FILE_NAME), cbor::encode(&file_value).unwrap())
        .unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        dir.path().join(IDENTITY_FILE_NAME),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();

    let loaded = IdentityStore::load(dir.path()).unwrap();
    let loaded_debug = format!("{loaded:?}");
    assert!(
        !loaded_debug.contains(seed_hex),
        "LoadedIdentity Debug leaks the seed"
    );
    assert!(loaded_debug.contains("<redacted>"));
}

#[test]
fn no_public_api_returns_seed_bytes() {
    // Compile-time API surface check: NodeSigningKey and LoadedIdentity have
    // no public method returning secret bytes (only sign/public_key/etc.).
    // This is enforced by review; here we at least assert the store loads
    // and can sign without any seed accessor existing.
    let dir = tempfile::tempdir().unwrap();
    let (loaded, _) = IdentityStore::load_or_create(dir.path(), None).unwrap();
    let sig = loaded.sign(b"probe");
    assert_eq!(sig.len(), 64);
    // Public data accessors exist and are safe to print.
    let _ = loaded.identity().public_key_hex();
    let _ = loaded.node_id_hex();
}

// ---------------------------------------------------------------------------
// Golden identity vectors (tests/vectors/identity_vectors.json)
// ---------------------------------------------------------------------------

struct IdentityCase {
    name: &'static str,
    seed_hex: &'static str,
    created_at_unix: u64,
    display_name: Option<String>,
}

struct SignatureCase {
    name: &'static str,
    seed_hex: &'static str,
    payload_hex: String,
    signature_hex: String,
    expected: &'static str, // "valid" | "invalid"
    note: &'static str,
}

fn identity_cases() -> Vec<IdentityCase> {
    vec![
        IdentityCase {
            name: "rfc8032-test1-no-name",
            seed_hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            created_at_unix: 1700000000,
            display_name: None,
        },
        IdentityCase {
            name: "rfc8032-test1-with-name",
            seed_hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            created_at_unix: 1700000001,
            display_name: Some("gateway-alpha".into()),
        },
        IdentityCase {
            name: "rfc8032-test2-epoch-zero",
            seed_hex: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            created_at_unix: 0,
            display_name: None,
        },
        IdentityCase {
            name: "rfc8032-test3-name-at-limit",
            seed_hex: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            created_at_unix: 4294967296,
            display_name: Some("x".repeat(64)), // exactly the 64-byte limit
        },
    ]
}

fn signature_cases() -> Vec<SignatureCase> {
    let v = rfc8032_vectors();
    let mut cases = vec![
        SignatureCase {
            name: "rfc8032-test1-empty-payload",
            seed_hex: v[0].seed,
            payload_hex: "".into(),
            signature_hex: v[0].signature.into(),
            expected: "valid",
            note: "RFC 8032 §7.1 test 1 (deterministic signature)",
        },
        SignatureCase {
            name: "rfc8032-test2",
            seed_hex: v[1].seed,
            payload_hex: v[1].message_hex.into(),
            signature_hex: v[1].signature.into(),
            expected: "valid",
            note: "RFC 8032 §7.1 test 2",
        },
        SignatureCase {
            name: "rfc8032-test3",
            seed_hex: v[2].seed,
            payload_hex: v[2].message_hex.into(),
            signature_hex: v[2].signature.into(),
            expected: "valid",
            note: "RFC 8032 §7.1 test 3",
        },
    ];
    // Deterministic implementation-generated cases.
    let sk = NodeSigningKey::from_seed(&seed_from_hex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    let payload = b"ShareNet: bridge payload, canonical CBOR v1";
    cases.push(SignatureCase {
        name: "custom-payload",
        seed_hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        payload_hex: hex::encode(payload),
        signature_hex: hex::encode(&sk.sign(payload)),
        expected: "valid",
        note: "implementation-generated golden",
    });
    // Malleable: S + L over the same payload.
    let mut mal = sk.sign(payload);
    let mut carry: u16 = 0;
    for i in 0..32 {
        let sum = mal[32 + i] as u16 + L_LE[i] as u16 + carry;
        mal[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    cases.push(SignatureCase {
        name: "malleable-s-plus-order",
        seed_hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        payload_hex: hex::encode(payload),
        signature_hex: hex::encode(&mal),
        expected: "invalid",
        note: "S' = S + L verifies under lenient verifiers; strict must reject",
    });
    // Valid signature replayed against a different payload.
    let other_payload = b"different payload";
    cases.push(SignatureCase {
        name: "replay-against-different-payload",
        seed_hex: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        payload_hex: hex::encode(other_payload),
        signature_hex: hex::encode(&sk.sign(payload)),
        expected: "invalid",
        note: "signature of payload A replayed against payload B",
    });
    cases
}

fn identity_vectors_document() -> serde_json::Value {
    let identity_json: Vec<_> = identity_cases()
        .into_iter()
        .map(|c| {
            let sk = NodeSigningKey::from_seed(&seed_from_hex(c.seed_hex));
            let identity = sk
                .node_identity(c.display_name.as_deref(), c.created_at_unix)
                .unwrap();
            json!({
                "name": c.name,
                "seed_hex": c.seed_hex,
                "created_at_unix": c.created_at_unix,
                "display_name": c.display_name,
                "public_key_hex": identity.public_key_hex(),
                "node_id_hex": identity.node_id_hex(),
                "wire_hex": hex::encode(&identity.to_wire_bytes()),
            })
        })
        .collect();

    let signature_json: Vec<_> = signature_cases()
        .into_iter()
        .map(|c| {
            let sk = NodeSigningKey::from_seed(&seed_from_hex(c.seed_hex));
            json!({
                "name": c.name,
                "seed_hex": c.seed_hex,
                "public_key_hex": hex::encode(&sk.public_key()),
                "payload_hex": c.payload_hex,
                "signature_hex": c.signature_hex,
                "expected": c.expected,
                "note": c.note,
            })
        })
        .collect();

    json!({
        "profile": "sharenet-identity-v1",
        "description": "Golden vectors for ShareNet NodeIdentity (scheme v1). \
node_id = SHA-256(canonical CBOR of {1: scheme_version, 2: public_key}). \
Identity cases cover seed -> public key (Ed25519), node_id derivation and the \
canonical wire bytes. Signature cases are Ed25519 detached signatures \
(deterministic RFC 8032); 'expected' tells whether strict verification must \
accept ('valid') or reject ('invalid') them.",
        "scheme": {
            "scheme_version": 1,
            "algorithm": "Ed25519 (RFC 8032), strict verification",
            "wire": "NodeIdentity = {1: scheme_version(uint), 2: public_key(32-byte bstr), 3: created_at_unix(uint), 4: display_name(optional text, <= 64 bytes)}",
            "node_id_derivation": "SHA-256(canonical_cbor({1: scheme_version, 2: public_key}))",
            "identity_file": "{1: seed(32-byte bstr), 2: NodeIdentity map}; permissions 0600; atomic write (tmp+fsync+rename+dir fsync); fail-closed load"
        },
        "identity_cases": identity_json,
        "signature_cases": signature_json,
    })
}

fn vectors_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("vectors")
        .join("identity_vectors.json")
}

#[test]
fn identity_vectors_file_is_in_sync() {
    let rendered =
        format!("{}\n", serde_json::to_string_pretty(&identity_vectors_document()).unwrap());
    let on_disk = std::fs::read_to_string(vectors_path())
        .expect("vectors file must exist; run `cargo test -- --ignored regenerate_identity_vectors`");
    assert_eq!(
        on_disk, rendered,
        "identity_vectors.json is out of sync with the Rust case tables; \
         regenerate with: cargo test --test identity_adversarial -- --ignored regenerate_identity_vectors"
    );
}

#[test]
#[ignore = "run explicitly to regenerate the committed vectors file"]
fn regenerate_identity_vectors() {
    let rendered =
        format!("{}\n", serde_json::to_string_pretty(&identity_vectors_document()).unwrap());
    std::fs::write(vectors_path(), rendered).expect("write vectors file");
}

#[test]
fn golden_identity_vectors_verify() {
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(vectors_path()).unwrap()).unwrap();
    assert_eq!(doc["profile"], "sharenet-identity-v1");

    for case in doc["identity_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let sk = NodeSigningKey::from_seed(&seed_from_hex(case["seed_hex"].as_str().unwrap()));
        // Public key derivation matches the golden.
        assert_eq!(
            hex::encode(&sk.public_key()),
            case["public_key_hex"].as_str().unwrap(),
            "public key of {name}"
        );
        let identity = sk
            .node_identity(
                case["display_name"].as_str(),
                case["created_at_unix"].as_u64().unwrap(),
            )
            .unwrap();
        // node_id derivation matches the golden (cross-language check).
        assert_eq!(
            identity.node_id_hex(),
            case["node_id_hex"].as_str().unwrap(),
            "node_id of {name}"
        );
        // Wire bytes match the golden, byte for byte.
        assert_eq!(
            hex::encode(&identity.to_wire_bytes()),
            case["wire_hex"].as_str().unwrap(),
            "wire bytes of {name}"
        );
        // Wire bytes parse back.
        let wire = cbor::decode(&hex::decode(case["wire_hex"].as_str().unwrap()).unwrap())
            .unwrap_or_else(|e| panic!("wire of {name}: {e}"));
        assert_eq!(NodeIdentity::from_wire(&wire).unwrap(), identity);
    }

    for case in doc["signature_cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let sk = NodeSigningKey::from_seed(&seed_from_hex(case["seed_hex"].as_str().unwrap()));
        let payload = hex::decode(case["payload_hex"].as_str().unwrap()).unwrap();
        let signature = hex::decode(case["signature_hex"].as_str().unwrap()).unwrap();
        let result = verify_detached(&sk.public_key(), &payload, &signature);
        match case["expected"].as_str().unwrap() {
            "valid" => assert!(result.is_ok(), "signature case {name} must verify: {result:?}"),
            "invalid" => assert!(result.is_err(), "signature case {name} must be rejected"),
            other => panic!("unknown expected value {other}"),
        }
    }
}
