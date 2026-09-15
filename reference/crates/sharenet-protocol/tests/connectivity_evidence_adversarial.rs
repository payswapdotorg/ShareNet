//! R5-004 adversarial tests: the SignedConnectivityObservation wire object
//! under tampering, foreign signers, replays, cross-contract confusion,
//! envelope swaps, hostile execution maps and non-canonical encodings.
//!
//! Every refusal path is exercised against genuinely-signed observations
//! (built with the real protocol builder, signed with real Ed25519 keys,
//! then attacked) — not mocked failures.

mod common;

use std::collections::BTreeMap;

use sharenet_protocol::cbor::{decode, encode, Value};
use sharenet_protocol::connectivity_evidence::{
    AdmissionOutcome, ConnectivityEvidenceError, ConnectivityObservationStatement, EvidenceKind,
    ObservationAdmission, SignedConnectivityObservation, EXECUTION_MAX_ENTRIES,
    EXECUTION_MAX_KEY_BYTES,
};
use sharenet_protocol::identity::Identity;

/// Deterministic test identities (TEST-ONLY seeds; never production).
fn identity(seed_byte: u8) -> Identity {
    Identity::from_seed([seed_byte; 32], 1_700_000_000, None).expect("test identity")
}

fn contract(tag: u8) -> [u8; 32] {
    [tag; 32]
}

fn execution(pairs: &[(&str, i64)]) -> Option<BTreeMap<String, i64>> {
    if pairs.is_empty() {
        return None;
    }
    Some(pairs.iter().map(|(k, v)| (k.to_string(), *v)).collect())
}

fn signed_obs(
    provider: &Identity,
    tag: u8,
    kind: EvidenceKind,
    observed_at: u64,
    sequence: u64,
    exec: Option<BTreeMap<String, i64>>,
) -> SignedConnectivityObservation {
    ConnectivityObservationStatement::new(provider, contract(tag), kind, observed_at, sequence, exec)
        .expect("builds")
        .sign(provider)
        .expect("signs")
}

/// A base observation whose field values we mutate one at a time — the
/// semantic tamper family: each mutation rebuilds VALID canonical CBOR with
/// a changed field, keeping the ORIGINAL signature, exactly like an
/// on-path attacker who rewrites the observation bytes.
fn mutated(
    base: &SignedConnectivityObservation,
    provider: &Identity,
    field: u8,
) -> SignedConnectivityObservation {
    let mut v = decode(base.observation_bytes()).expect("base parses");
    let Value::Map(entries) = &mut v else { unreachable!("base is a map") };
    for (k, val) in entries.iter_mut() {
        let Value::Int(key) = *k else { continue };
        if key as u8 == field {
            match field {
                1 => {
                    // scheme_version: 1 -> 2
                    *val = Value::Int(2);
                }
                2 => {
                    // provider identity: swap the embedded public key byte
                    let Value::Map(identity_entries) = val else { unreachable!() };
                    for (ik, iv) in identity_entries.iter_mut() {
                        if let (Value::Int(2), Value::Bytes(pk)) = (ik, iv) {
                            pk[0] ^= 0x01;
                        }
                    }
                }
                3 => {
                    // contract_ref: flip the first ref byte
                    let Value::Bytes(b) = val else { unreachable!() };
                    b[0] ^= 0x01;
                }
                4 => {
                    // kind: degraded -> terminated
                    *val = Value::Text("terminated".to_string());
                }
                5 => {
                    // observed_at: 1000 -> 1001
                    let Value::Int(t) = val else { unreachable!() };
                    *t += 1;
                }
                6 => {
                    // sequence: bump by one (still in-range, still signed
                    // by nobody)
                    let Value::Int(s) = val else { unreachable!() };
                    *s += 1;
                }
                7 => {
                    // execution: change a counter value
                    let Value::Map(m) = val else { unreachable!() };
                    for (_mk, mv) in m.iter_mut() {
                        if let Value::Int(c) = mv {
                            *c += 1;
                        }
                    }
                }
                _ => unreachable!("known field"),
            }
        }
    }
    let _ = provider;
    SignedConnectivityObservation::from_parts(
        encode(&v).expect("in-profile"),
        *base.signature(),
    )
}

#[test]
fn every_field_tamper_fails_verification() {
    let provider = identity(0xA1);
    let base = signed_obs(
        &provider,
        0x01,
        EvidenceKind::ExecutionStateChanged,
        1_000,
        7,
        execution(&[("uplink_bytes", 2048), ("active_sessions", 1)]),
    );
    assert!(base.verify().is_ok(), "the base observation must verify");
    for field in 1..=7 {
        let tampered = mutated(&base, &provider, field);
        let err = tampered
            .verify()
            .expect_err("a field tamper must never verify");
        // A rewritten field either breaks the CBOR/parse (scheme_version,
        // provider identity, contract_ref length...) or keeps valid CBOR
        // while invalidating the signature — both are typed failures.
        let name = err.name();
        assert!(
            matches!(
                name.as_str(),
                "signature_invalid"
                    | "scheme_version_unsupported"
                    | "identity:identity_scheme_unsupported"
                    | "identity:identity_public_key_wrong_length"
                    | "identity:identity_point_not_canonical"
                    | "kind_unknown"
                    | "cbor:*"
            ) || name.starts_with("identity:")
            || name.starts_with("cbor:"),
            "field {field}: unexpected error {name}"
        );
    }
}

#[test]
fn signature_byte_flips_fail_verification() {
    let provider = identity(0xA2);
    let signed = signed_obs(&provider, 0x02, EvidenceKind::Degraded, 1_000, 1, None);
    for pos in [0usize, 31, 32, 63] {
        let mut sig = *signed.signature();
        sig[pos] ^= 0x80;
        let bad = SignedConnectivityObservation::from_parts(
            signed.observation_bytes().to_vec(),
            sig,
        );
        assert_eq!(
            bad.verify().unwrap_err(),
            ConnectivityEvidenceError::SignatureInvalid,
            "signature byte {pos} flipped must fail closed"
        );
    }
}

#[test]
fn raw_observation_byte_flips_fail_closed() {
    let provider = identity(0xA3);
    let signed = signed_obs(&provider, 0x03, EvidenceKind::Degraded, 1_000, 1, None);
    // flip one byte at a spread of offsets: every mutation of the signed
    // bytes must either fail the strict parse or fail the signature
    let bytes = signed.observation_bytes();
    for pos in [0, 1, 5, 9, 17, bytes.len() / 2, bytes.len() - 2, bytes.len() - 1] {
        let mut tampered = bytes.to_vec();
        tampered[pos] ^= 0x01;
        let bad = SignedConnectivityObservation::from_parts(tampered, *signed.signature());
        assert!(bad.verify().is_err(), "byte {pos} flipped must fail closed");
    }
}

#[test]
fn foreign_key_signature_is_rejected() {
    let provider = identity(0xA4);
    let attacker = identity(0xA5);
    let signed = signed_obs(&provider, 0x04, EvidenceKind::AssuranceAvailable, 1_000, 1, None);
    // The attacker re-signs the provider's observation bytes with their own
    // key: the embedded identity still names the provider, so strict
    // verification against the EMBEDDED key must fail.
    let forged = SignedConnectivityObservation::from_parts(
        signed.observation_bytes().to_vec(),
        attacker.sign_detached(signed.observation_bytes()),
    );
    assert_eq!(
        forged.verify().unwrap_err(),
        ConnectivityEvidenceError::SignatureInvalid
    );
}

#[test]
fn replayed_observation_is_ignored_not_reapplied() {
    let mut admission = ObservationAdmission::new(600);
    admission.register_contract(contract(0x05));
    let provider = identity(0xA6);
    let first = signed_obs(&provider, 0x05, EvidenceKind::ContractActivated, 1_000, 1, None);
    let replay = signed_obs(&provider, 0x05, EvidenceKind::ContractActivated, 1_000, 1, None);
    assert_eq!(
        admission.receive(&first, 1_030).unwrap(),
        AdmissionOutcome::Admitted
    );
    // An exact redelivery and a re-signed-but-equal-sequence observation are
    // both ignored (no state moves).
    assert_eq!(
        admission.receive(&first, 1_030).unwrap(),
        AdmissionOutcome::SequenceStale { sequence: 1 }
    );
    assert_eq!(
        admission.receive(&replay, 1_030).unwrap(),
        AdmissionOutcome::SequenceStale { sequence: 1 }
    );
    assert_eq!(
        admission.highest_sequence(&provider.node_id(), &contract(0x05)),
        Some(1),
        "a replay never advances the sequence gate"
    );
}

#[test]
fn sequence_regression_is_ignored_after_gap() {
    let mut admission = ObservationAdmission::new(600);
    admission.register_contract(contract(0x06));
    let provider = identity(0xA7);
    let s1 = signed_obs(&provider, 0x06, EvidenceKind::ContractActivated, 1_000, 1, None);
    let s5 = signed_obs(&provider, 0x06, EvidenceKind::Degraded, 1_040, 5, None);
    let s3 = signed_obs(&provider, 0x06, EvidenceKind::FailoverReplan, 1_020, 3, None);
    assert_eq!(admission.receive(&s1, 1_050).unwrap(), AdmissionOutcome::Admitted);
    // a gap is allowed: 5 > 1 admits
    assert_eq!(admission.receive(&s5, 1_050).unwrap(), AdmissionOutcome::Admitted);
    // a later-arriving 3 < 5 is a reordered redelivery: ignored
    assert_eq!(
        admission.receive(&s3, 1_050).unwrap(),
        AdmissionOutcome::SequenceStale { sequence: 3 }
    );
}

#[test]
fn cross_contract_sequence_confusion_stays_isolated() {
    let mut admission = ObservationAdmission::new(600);
    admission.register_contract(contract(0x07));
    admission.register_contract(contract(0x08));
    let provider = identity(0xA8);
    // sequence 4 accepted for contract 7...
    assert_eq!(
        admission
            .receive(
                &signed_obs(&provider, 0x07, EvidenceKind::Degraded, 1_000, 4, None),
                1_030
            )
            .unwrap(),
        AdmissionOutcome::Admitted
    );
    // ...must NOT block sequence 1..4 for contract 8 (independent
    // namespace), and must not be replays of it either:
    for seq in [1u64, 2, 4] {
        assert_eq!(
            admission
                .receive(
                    &signed_obs(&provider, 0x08, EvidenceKind::Degraded, 1_000, seq, None),
                    1_030
                )
                .unwrap(),
            AdmissionOutcome::Admitted,
            "sequence {seq} for a different contract is its own namespace"
        );
    }
    // and back on contract 7, sequence 4 is stale
    assert_eq!(
        admission
            .receive(
                &signed_obs(&provider, 0x07, EvidenceKind::Degraded, 1_000, 4, None),
                1_030
            )
            .unwrap(),
        AdmissionOutcome::SequenceStale { sequence: 4 }
    );
}

#[test]
fn envelope_confusion_is_rejected() {
    let provider_a = identity(0xA9);
    let provider_b = identity(0xAA);
    let obs_a = signed_obs(&provider_a, 0x09, EvidenceKind::Degraded, 1_000, 1, None);
    let obs_b = signed_obs(&provider_b, 0x0A, EvidenceKind::Degraded, 1_000, 1, None);
    // observation bytes of A + signature of B (the swap attack)
    let swapped = SignedConnectivityObservation::from_parts(
        obs_a.observation_bytes().to_vec(),
        *obs_b.signature(),
    );
    assert_eq!(
        swapped.verify().unwrap_err(),
        ConnectivityEvidenceError::SignatureInvalid,
        "an observation bytes/signature swap across envelopes must fail"
    );
    // ...and the mirror
    let mirror = SignedConnectivityObservation::from_parts(
        obs_b.observation_bytes().to_vec(),
        *obs_a.signature(),
    );
    assert_eq!(mirror.verify().unwrap_err(), ConnectivityEvidenceError::SignatureInvalid);

    // Envelope field confusion: {1: signature, 2: observation} (the fields
    // swapped inside the envelope) — the 64-byte signature lands in field 1
    // (which takes any bstr) and the observation map bytes land in field 2
    // (which requires exactly 64) — the envelope parse fails typed.
    let swapped_env = encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(obs_a.signature().to_vec())),
        (Value::Int(2), Value::Bytes(obs_a.observation_bytes().to_vec())),
    ]))
    .expect("encodes");
    assert!(matches!(
        SignedConnectivityObservation::from_envelope_bytes(&swapped_env).unwrap_err(),
        ConnectivityEvidenceError::SignatureWrongLength { .. },
    ));

    // An observation envelope carrying a TopologyEvidence-shaped inner
    // bytes (wrong object entirely) fails the strict parse typed.
    let topo_bytes = {
        let mut topo = vec![(Value::Int(1), Value::Int(1))];
        topo.push((Value::Int(2), provider_a.node_identity().to_wire()));
        topo.push((Value::Int(3), Value::Bytes([0xEE; 32].to_vec())));
        topo.push((Value::Int(4), Value::Text("link".to_string())));
        topo.push((Value::Int(5), Value::Int(1_000)));
        topo.push((Value::Int(6), Value::Int(1_300)));
        encode(&Value::Map(topo)).expect("encodes")
    };
    let wrong_object = SignedConnectivityObservation::from_parts(
        topo_bytes.clone(),
        provider_a.sign_detached(&topo_bytes),
    );
    assert!(wrong_object.observation().is_err(),
        "a correctly-signed foreign object is not a connectivity observation");
}

#[test]
fn oversized_and_wrong_typed_execution_maps_are_refused() {
    let provider = identity(0xAB);
    // 17 entries (one over the bound)
    let mut too_many = BTreeMap::new();
    for i in 0..=(EXECUTION_MAX_ENTRIES as i64) {
        too_many.insert(format!("counter_{i:02}"), i);
    }
    assert!(matches!(
        ConnectivityObservationStatement::new(
            &provider,
            contract(0x0B),
            EvidenceKind::ExecutionStateChanged,
            1_000,
            1,
            Some(too_many)
        ),
        Err(ConnectivityEvidenceError::ExecutionTooManyEntries { count, max })
            if count == EXECUTION_MAX_ENTRIES + 1 && max == EXECUTION_MAX_ENTRIES
    ));
    // key of 65 bytes (one over the bound)
    let long_key: BTreeMap<String, i64> =
        [("x".repeat(EXECUTION_MAX_KEY_BYTES + 1), 1)].into_iter().collect();
    assert!(matches!(
        ConnectivityObservationStatement::new(
            &provider,
            contract(0x0B),
            EvidenceKind::ExecutionStateChanged,
            1_000,
            1,
            Some(long_key)
        ),
        Err(ConnectivityEvidenceError::ExecutionKeyInvalid { bytes, max })
            if bytes == EXECUTION_MAX_KEY_BYTES + 1 && max == EXECUTION_MAX_KEY_BYTES
    ));

    // Wrong-typed entries on the WIRE (the builder cannot express these):
    // text value, integer key, negative key bytes.
    let wire_wrong_value = {
        let mut entries = base_wire_entries(&provider);
        entries.push((
            Value::Int(7),
            Value::Map(vec![(Value::Text("k".into()), Value::Text("not-an-int".into()))]),
        ));
        encode(&Value::Map(entries)).expect("encodes")
    };
    assert!(matches!(
        ConnectivityObservationStatement::from_wire_bytes(&wire_wrong_value).unwrap_err(),
        ConnectivityEvidenceError::ExecutionEntryMalformed
    ));
    let wire_int_key = {
        let mut entries = base_wire_entries(&provider);
        entries.push((
            Value::Int(7),
            Value::Map(vec![(Value::Int(1), Value::Int(1))]),
        ));
        encode(&Value::Map(entries)).expect("encodes")
    };
    assert!(matches!(
        ConnectivityObservationStatement::from_wire_bytes(&wire_int_key).unwrap_err(),
        ConnectivityEvidenceError::ExecutionEntryMalformed
    ));
    // an empty-text key
    let wire_empty_key = {
        let mut entries = base_wire_entries(&provider);
        entries.push((Value::Int(7), Value::Map(vec![(Value::Text(String::new()), Value::Int(1))])));
        encode(&Value::Map(entries)).expect("encodes")
    };
    assert!(matches!(
        ConnectivityObservationStatement::from_wire_bytes(&wire_empty_key).unwrap_err(),
        ConnectivityEvidenceError::ExecutionKeyInvalid { bytes: 0, .. }
    ));
    // the execution field as an ARRAY of pairs instead of a map
    let wire_array = {
        let mut entries = base_wire_entries(&provider);
        entries.push((
            Value::Int(7),
            Value::Array(vec![Value::Text("k".into()), Value::Int(1)]),
        ));
        encode(&Value::Map(entries)).expect("encodes")
    };
    assert!(matches!(
        ConnectivityObservationStatement::from_wire_bytes(&wire_array).unwrap_err(),
        ConnectivityEvidenceError::FieldNotExpectedType { key: 7 }
    ));
}

/// The six fixed fields of a valid observation (everything except the
/// optional execution map) — adversarial wire builders start from these.
fn base_wire_entries(provider: &Identity) -> Vec<(Value, Value)> {
    vec![
        (Value::Int(1), Value::Int(1)),
        (Value::Int(2), provider.node_identity().to_wire()),
        (Value::Int(3), Value::Bytes(contract(0x0C).to_vec())),
        (Value::Int(4), Value::Text("degraded".into())),
        (Value::Int(5), Value::Int(1_000)),
        (Value::Int(6), Value::Int(1)),
    ]
}

#[test]
fn non_canonical_encodings_are_rejected() {
    let provider = identity(0xAC);
    let valid = signed_obs(&provider, 0x0C, EvidenceKind::Degraded, 1_000, 1, None);
    let bytes = valid.observation_bytes();

    // 1. trailing bytes after the complete map
    let mut trailing = bytes.to_vec();
    trailing.push(0x00);
    assert!(ConnectivityObservationStatement::from_wire_bytes(&trailing).is_err());

    // 2. truncation
    let truncated = &bytes[..bytes.len() - 1];
    assert!(ConnectivityObservationStatement::from_wire_bytes(truncated).is_err());

    // 3. non-minimal integer: re-encode the whole map with observed_at as a
    //    4-byte-int (0x1a) instead of the minimal 2-byte form. The map is
    //    semantically identical but NOT canonical — must be refused.
    let mut v = decode(&bytes).expect("parses");
    if let Value::Map(entries) = &mut v {
        for (k, val) in entries.iter_mut() {
            if let (Value::Int(5), Value::Int(t)) = (k, val) {
                *t = 1_000; // same value; the non-minimal form comes from hand-encoding below
            }
        }
    }
    // hand-build the non-minimal encoding of the same map
    let mut raw: Vec<u8> = Vec::new();
    raw.push(0xa6); // map(6)
    raw.extend_from_slice(&[0x01, 0x01]); // 1: 1
    raw.extend_from_slice(&[0x02]); // 2: NodeIdentity map — encode via the value encoder
    let identity_bytes = encode(&provider.node_identity().to_wire()).expect("encodes");
    // strip the map header? No: the encoder emits the full item; embed as-is.
    raw.extend_from_slice(&identity_bytes);
    raw.extend_from_slice(&[0x03]);
    raw.extend_from_slice(&[0x58, 0x20]); // bytes(32)
    raw.extend_from_slice(&contract(0x0C));
    raw.extend_from_slice(&[0x04]);
    raw.extend_from_slice(&encode(&Value::Text("degraded".into())).expect("encodes"));
    raw.extend_from_slice(&[0x05, 0x1a, 0x00, 0x00, 0x03, 0xe8]); // 5: 1000 NON-minimal
    raw.extend_from_slice(&[0x06, 0x01]); // 6: 1
    assert!(
        ConnectivityObservationStatement::from_wire_bytes(&raw).is_err(),
        "a non-minimal integer encoding must be refused (the profile's strictness law)"
    );

    // 4. unsorted map keys: field order 6 before 5
    let mut unsorted = base_wire_entries(&provider);
    unsorted.swap(4, 5);
    // re-sort check: the encoder refuses unsorted maps — assert that
    // instead, then confirm a hand-rolled unsorted byte stream is refused
    // by the decoder (the strict profile).
    assert!(encode(&Value::Map(unsorted.clone())).is_err()
        || ConnectivityObservationStatement::from_wire_bytes(
            &encode(&Value::Map(sorted(unsorted))).expect("encodes")
        )
        .is_ok());
    // hand-rolled unsorted: map(6) with keys in the wrong order
    let mut unsorted_raw: Vec<u8> = Vec::new();
    unsorted_raw.push(0xa6);
    let sorted_entries = sorted(base_wire_entries(&provider));
    // emit fields 1,2,3,4,6,5 (6 before 5 — unsorted for integer keys 5 < 6)
    for idx in [0usize, 1, 2, 3, 5, 4] {
        let (k, val) = &sorted_entries[idx];
        unsorted_raw.extend_from_slice(&encode(k).expect("encodes"));
        unsorted_raw.extend_from_slice(&encode(val).expect("encodes"));
    }
    assert!(
        ConnectivityObservationStatement::from_wire_bytes(&unsorted_raw).is_err(),
        "unsorted map keys must be refused"
    );

    // 5. duplicate map keys: map(7) with two field-6 entries
    let mut dup: Vec<u8> = Vec::new();
    dup.push(0xa7); // map(7)
    let sorted_entries = sorted(base_wire_entries(&provider));
    for (k, val) in &sorted_entries {
        dup.extend_from_slice(&encode(k).expect("encodes"));
        dup.extend_from_slice(&encode(val).expect("encodes"));
    }
    // append a duplicate sequence field (key 6, value 2)
    dup.extend_from_slice(&[0x06, 0x02]);
    assert!(
        ConnectivityObservationStatement::from_wire_bytes(&dup).is_err(),
        "duplicate map keys must be refused"
    );

    // 6. the observation is not a map at all
    let not_a_map = encode(&Value::Array(vec![Value::Int(1)])).expect("encodes");
    assert!(matches!(
        ConnectivityObservationStatement::from_wire_bytes(&not_a_map).unwrap_err(),
        ConnectivityEvidenceError::NotAMap
    ));

    // 7. sequence 0 on the wire (below the reserved minimum)
    let mut entries = base_wire_entries(&provider);
    for (k, val) in entries.iter_mut() {
        if let (Value::Int(6), Value::Int(s)) = (k, val) {
            *s = 0;
        }
    }
    let wire = encode(&Value::Map(sorted(entries))).expect("encodes");
    assert!(matches!(
        ConnectivityObservationStatement::from_wire_bytes(&wire).unwrap_err(),
        ConnectivityEvidenceError::SequenceBelowMinimum { found: 0 }
    ));

    // 8. negative observed_at
    let mut entries = base_wire_entries(&provider);
    for (k, val) in entries.iter_mut() {
        if let (Value::Int(5), Value::Int(t)) = (k, val) {
            *t = -1;
        }
    }
    let wire = encode(&Value::Map(sorted(entries))).expect("encodes");
    assert!(matches!(
        ConnectivityObservationStatement::from_wire_bytes(&wire).unwrap_err(),
        ConnectivityEvidenceError::TimestampNegative { field: "observed_at" }
    ));
}

/// Sort entries by canonical key order (integer keys ascending — the
/// encoder's contract), so hand-built wire maps are canonically ordered
/// whenever the test wants the OTHER dimension to be the violation.
fn sorted(mut entries: Vec<(Value, Value)>) -> Vec<(Value, Value)> {
    entries.sort_by_key(|(k, _)| match k {
        Value::Int(i) => *i,
        _ => unreachable!("integer keys only"),
    });
    entries
}

#[test]
fn envelope_strictness() {
    let provider = identity(0xAD);
    let signed = signed_obs(&provider, 0x0D, EvidenceKind::Degraded, 1_000, 1, None);

    // 63-byte signature
    let short_sig = encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(signed.observation_bytes().to_vec())),
        (Value::Int(2), Value::Bytes(signed.signature()[..63].to_vec())),
    ]))
    .expect("encodes");
    assert!(matches!(
        SignedConnectivityObservation::from_envelope_bytes(&short_sig).unwrap_err(),
        ConnectivityEvidenceError::SignatureWrongLength { len: 63 }
    ));

    // extra field 3 (wrong entry count dominates: exactly 2 required)
    let extra = encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(signed.observation_bytes().to_vec())),
        (Value::Int(2), Value::Bytes(signed.signature().to_vec())),
        (Value::Int(3), Value::Int(1)),
    ]))
    .expect("encodes");
    assert!(matches!(
        SignedConnectivityObservation::from_envelope_bytes(&extra).unwrap_err(),
        ConnectivityEvidenceError::EnvelopeWrongEntryCount { count: 3 }
    ));

    // only one entry
    let one = encode(&Value::Map(vec![(
        Value::Int(1),
        Value::Bytes(signed.observation_bytes().to_vec()),
    )]))
    .expect("encodes");
    assert!(matches!(
        SignedConnectivityObservation::from_envelope_bytes(&one).unwrap_err(),
        ConnectivityEvidenceError::EnvelopeWrongEntryCount { count: 1 }
    ));

    // text instead of bytes in field 2
    let text_sig = encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(signed.observation_bytes().to_vec())),
        (Value::Int(2), Value::Text("deadbeef".into())),
    ]))
    .expect("encodes");
    assert!(matches!(
        SignedConnectivityObservation::from_envelope_bytes(&text_sig).unwrap_err(),
        ConnectivityEvidenceError::FieldNotExpectedType { key: 2 }
    ));

    // the envelope's field 1 carrying an UNSIGNED random map (wrong object)
    let garbage = encode(&Value::Map(vec![
        (Value::Int(9), Value::Int(9)),
        (Value::Int(2), provider.node_identity().to_wire()),
    ]))
    .expect("encodes");
    let wrong = encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(garbage.clone())),
        (Value::Int(2), Value::Bytes(provider.sign_detached(&garbage).to_vec())),
    ]))
    .expect("encodes");
    let parsed = SignedConnectivityObservation::from_envelope_bytes(&wrong).expect("envelope ok");
    assert!(parsed.observation().is_err(), "unknown field 9 is refused");
    assert!(parsed.verify().is_err());
}

#[test]
fn admission_rejects_unsigned_and_unknown_contract_paths() {
    let mut admission = ObservationAdmission::new(600);
    let provider = identity(0xAE);
    let signed = signed_obs(&provider, 0x0E, EvidenceKind::Degraded, 1_000, 1, None);
    // contract never registered
    assert!(matches!(
        admission.receive(&signed, 1_030),
        Err(ConnectivityEvidenceError::ContractUnknown { .. })
    ));
    // register and admit, then check the freshness edge exactly
    admission.register_contract(contract(0x0E));
    assert_eq!(
        admission.receive(&signed, 1_000).unwrap(),
        AdmissionOutcome::Admitted,
        "now == observed_at is inside the window (bound exclusive)"
    );
    let next = signed_obs(&provider, 0x0E, EvidenceKind::Terminated, 1_600, 2, None);
    assert!(matches!(
        admission.receive(&next, 1_599),
        Err(ConnectivityEvidenceError::NotYetValid { .. })
    ));
    assert!(matches!(
        admission.receive(&next, 2_200),
        Err(ConnectivityEvidenceError::Expired { .. })
    ));
    // a tampered observation never reaches the sequence state
    let mut bad_bytes = next.observation_bytes().to_vec();
    let last = bad_bytes.len() - 1;
    bad_bytes[last] ^= 0x01;
    let tampered =
        SignedConnectivityObservation::from_parts(bad_bytes.to_vec(), *next.signature());
    assert!(admission.receive(&tampered, 1_700).is_err());
    assert_eq!(
        admission.highest_sequence(&provider.node_id(), &contract(0x0E)),
        Some(1),
        "failed admissions never advance the sequence gate"
    );
}
