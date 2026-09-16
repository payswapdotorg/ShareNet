//! R8-001 adversarial tests: the ContributionReceipt wire object and its
//! ledger under foreign-key signatures, self-receipts, future-dated
//! claims, kind lies, envelope confusion, sequence replay/regression,
//! byte-count fabrications and snapshot tampering.
//!
//! Every refusal path is exercised against receipts built by the REAL
//! protocol builder from REAL identities and REAL content (then attacked)
//! — not mocked failures. The central properties under attack:
//!
//! - the receipt is the issuer's AUTHENTICATED bilateral claim — only
//!   the recipient's key can produce one that verifies, and a node can
//!   never acknowledge itself (the self-receipt exclusion);
//! - `receipt_id` = SHA-256(canonical bytes), so any change to anything
//!   is either a typed refusal or a different named object (L013);
//! - the ledger is replay-safe: identical re-deliveries are idempotent,
//!   repeated/regressed sequences are refused typed, and the sequence
//!   namespace is exactly the (issuer, contributor) pair.

mod common;

use sharenet_protocol::cbor::{decode, encode, Value};
use sharenet_protocol::content::ContentManifest;
use sharenet_protocol::contribution::{
    ContributionKind, ContributionReceipt, ReceiptAdmitOutcome, ReceiptLedger,
    SignedContributionReceipt, DELIVERED_BYTES_MAX,
};
use sharenet_protocol::identity::Identity;
use sharenet_protocol::revocation::{CircuitRevocation, RevocationReason, SignedCircuitRevocation};

/// Deterministic test content: 17 bytes, chunked at 7 (7 + 7 + 3).
const CONTENT: &[u8] = b"0123456789abcdefg";
const NOW: u64 = 1_700_000_000;

struct World {
    issuer: Identity,
    contributor: Identity,
    foreign: Identity,
    content_id: [u8; 32],
}

fn world() -> World {
    World {
        issuer: Identity::from_seed([0x11; 32], NOW, None).expect("issuer"),
        contributor: Identity::from_seed([0x22; 32], NOW, None).expect("contributor"),
        foreign: Identity::from_seed([0xEE; 32], NOW, None).expect("foreign"),
        content_id: ContentManifest::chunk(CONTENT, 7, "application/octet-stream", None, NOW)
            .expect("manifest")
            .0
            .content_id(),
    }
}

/// Build the base (valid, signed) receipt for the world.
fn base_receipt(w: &World) -> SignedContributionReceipt {
    ContributionReceipt::new(
        &w.issuer,
        *w.contributor.node_id().as_bytes(),
        w.content_id,
        ContributionKind::Carried,
        17,
        1,
        NOW + 10,
    )
    .expect("base receipt builds")
    .sign(&w.issuer)
    .expect("issuer signs")
}

/// Patch one field of a parsed receipt map and re-encode: the semantic
/// tamper family (valid canonical CBOR, one changed field).
fn patched(signed: &SignedContributionReceipt, key: i64, value: Value) -> Vec<u8> {
    let mut v = decode(signed.receipt_bytes()).expect("receipt parses");
    let Value::Map(entries) = &mut v else {
        unreachable!("receipt is a map")
    };
    for (k, val) in entries.iter_mut() {
        if let Value::Int(n) = k {
            if *n == key {
                *val = value;
                return encode(&v).expect("in-profile");
            }
        }
    }
    panic!("field {key} not found in the receipt map");
}

/// Patch + re-sign with a chosen key: makes the INVARIANT the failure
/// (not the signature), mirroring the conformance reject discipline.
fn patched_signed(
    signed: &SignedContributionReceipt,
    key: i64,
    value: Value,
    signer: &Identity,
) -> Vec<u8> {
    let bytes = patched(signed, key, value);
    let signature = signer.sign_detached(&bytes);
    encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(bytes)),
        (Value::Int(2), Value::Bytes(signature.to_vec())),
    ]))
    .expect("in-profile")
}

/// Patch without re-signing: any field tamper must break the signature.
fn patched_stale(signed: &SignedContributionReceipt, key: i64, value: Value) -> Vec<u8> {
    encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(patched(signed, key, value))),
        (Value::Int(2), Value::Bytes(signed.signature().to_vec())),
    ]))
    .expect("in-profile")
}

fn reject_name(bytes: &[u8]) -> String {
    SignedContributionReceipt::from_envelope_bytes(bytes)
        .expect_err("must be refused")
        .name()
        .to_string()
}

#[test]
fn foreign_keys_never_verify_as_the_issuer() {
    let w = world();
    let base = base_receipt(&w);
    let bytes = base.receipt_bytes().to_vec();
    // the contributor signs the issuer's exact receipt bytes
    let contributor_sig = w.contributor.sign_detached(&bytes);
    let env = encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(bytes.clone())),
        (Value::Int(2), Value::Bytes(contributor_sig.to_vec())),
    ]))
    .expect("in-profile");
    assert_eq!(reject_name(&env), "signature_invalid");
    // a wholly foreign key signs them too
    let foreign_sig = w.foreign.sign_detached(&bytes);
    let env = encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(bytes)),
        (Value::Int(2), Value::Bytes(foreign_sig.to_vec())),
    ]))
    .expect("in-profile");
    assert_eq!(reject_name(&env), "signature_invalid");
    // and the builder itself refuses to sign with the wrong live identity
    let unsigned = ContributionReceipt::new(
        &w.issuer,
        *w.contributor.node_id().as_bytes(),
        w.content_id,
        ContributionKind::Carried,
        17,
        1,
        NOW + 10,
    )
    .expect("build");
    assert_eq!(
        unsigned.sign(&w.contributor).unwrap_err().name(),
        "signer_mismatch"
    );
    assert_eq!(
        unsigned.sign(&w.foreign).unwrap_err().name(),
        "signer_mismatch"
    );
}

#[test]
fn self_receipt_is_refused_at_construction_and_parse() {
    let w = world();
    // construction: the issuer names itself as the contributor
    let err = ContributionReceipt::new(
        &w.issuer,
        *w.issuer.node_id().as_bytes(),
        w.content_id,
        ContributionKind::Carried,
        17,
        1,
        NOW + 10,
    )
    .unwrap_err();
    assert_eq!(err.name(), "self_receipt");
    // parse: a properly SIGNED self-receipt (field 3 mutated to the
    // issuer's own node id, then re-signed by the issuer) still fails
    let base = base_receipt(&w);
    let env = patched_signed(
        &base,
        3,
        Value::Bytes(w.issuer.node_id().as_bytes().to_vec()),
        &w.issuer,
    );
    assert_eq!(reject_name(&env), "self_receipt");
    // and it never reaches the ledger
    let ledger = ReceiptLedger::new();
    assert!(ledger.admit_envelope(NOW + 10, &env).is_err());
    assert_eq!(ledger.receipt_count(), 0);
}

#[test]
fn future_dated_receipts_are_refused_and_record_nothing() {
    let w = world();
    // a receipt dated far ahead, correctly signed by the issuer
    let future = ContributionReceipt::new(
        &w.issuer,
        *w.contributor.node_id().as_bytes(),
        w.content_id,
        ContributionKind::Carried,
        17,
        1,
        NOW + 10_000,
    )
    .expect("build")
    .sign(&w.issuer)
    .expect("sign");
    let ledger = ReceiptLedger::new();
    // parse + signature pass; the verifying clock refuses
    assert_eq!(
        ledger.admit(NOW + 10, &future).unwrap_err().name(),
        "issued_at_in_future"
    );
    assert_eq!(ledger.receipt_count(), 0);
    // nothing was recorded: the refusal is repeatable at the same clock
    assert_eq!(
        ledger.admit(NOW + 10, &future).unwrap_err().name(),
        "issued_at_in_future"
    );
    // the future gate fires BEFORE idempotency: even a receipt already
    // recorded refuses at a clock that went backwards (the caller's
    // clock discipline, fail-closed rather than silently re-accepting)
    let valid = base_receipt(&w);
    assert_eq!(
        ledger.admit(NOW + 10, &valid).unwrap(),
        ReceiptAdmitOutcome::Admitted
    );
    let clock_ahead = ContributionReceipt::new(
        &w.issuer,
        *w.contributor.node_id().as_bytes(),
        w.content_id,
        ContributionKind::Carried,
        17,
        2,
        NOW + 20,
    )
    .expect("build");
    let signed = clock_ahead.sign(&w.issuer).expect("sign");
    assert_eq!(
        ledger.admit(NOW + 15, &signed).unwrap_err().name(),
        "issued_at_in_future"
    );
    assert_eq!(ledger.receipt_count(), 1);
}

#[test]
fn kind_lies_are_refused_typed() {
    let w = world();
    let base = base_receipt(&w);
    // an invented kind name
    let env = patched_signed(&base, 5, Value::Text("relayed".into()), &w.issuer);
    assert_eq!(reject_name(&env), "kind_unknown");
    // a near-miss of the frozen set
    let env = patched_signed(&base, 5, Value::Text("carry".into()), &w.issuer);
    assert_eq!(reject_name(&env), "kind_unknown");
    // the kind as an integer code
    let env = patched_signed(&base, 5, Value::Int(1), &w.issuer);
    assert_eq!(reject_name(&env), "field_not_expected_type");
    // case games
    let env = patched_signed(&base, 5, Value::Text("Carried".into()), &w.issuer);
    assert_eq!(reject_name(&env), "kind_unknown");
}

#[test]
fn delivered_bytes_bounds_are_enforced_at_parse() {
    let w = world();
    let base = base_receipt(&w);
    // zero bytes (an empty acknowledgement is not evidence)
    let env = patched_signed(&base, 6, Value::Int(0), &w.issuer);
    assert_eq!(reject_name(&env), "delivered_bytes_out_of_range");
    // one past the 2^40 bound
    let env = patched_signed(
        &base,
        6,
        Value::Int(DELIVERED_BYTES_MAX as i64 + 1),
        &w.issuer,
    );
    assert_eq!(reject_name(&env), "delivered_bytes_out_of_range");
    // negative fabrication
    let env = patched_signed(&base, 6, Value::Int(-4096), &w.issuer);
    assert_eq!(reject_name(&env), "delivered_bytes_out_of_range");
    // the exact bound itself is legal
    let env = patched_signed(&base, 6, Value::Int(DELIVERED_BYTES_MAX as i64), &w.issuer);
    assert!(SignedContributionReceipt::from_envelope_bytes(&env).is_ok());
}

#[test]
fn sequence_number_fabrications_are_refused_at_parse() {
    let w = world();
    let base = base_receipt(&w);
    // sequence zero
    let env = patched_signed(&base, 7, Value::Int(0), &w.issuer);
    assert_eq!(reject_name(&env), "receipt_seq_invalid");
    // negative
    let env = patched_signed(&base, 7, Value::Int(-1), &w.issuer);
    assert_eq!(reject_name(&env), "receipt_seq_invalid");
    // issued_at negative / out of range
    let env = patched_signed(&base, 8, Value::Int(-1), &w.issuer);
    assert_eq!(reject_name(&env), "timestamp_out_of_range");
}

#[test]
fn structural_lies_are_refused_typed() {
    let w = world();
    let base = base_receipt(&w);
    // contributor node id of the wrong length
    let env = patched_signed(&base, 3, Value::Bytes(vec![0u8; 31]), &w.issuer);
    assert_eq!(reject_name(&env), "contributor_id_wrong_length");
    // content id of the wrong length
    let env = patched_signed(&base, 4, Value::Bytes(vec![0u8; 33]), &w.issuer);
    assert_eq!(reject_name(&env), "content_id_wrong_length");
    // scheme version bump
    let env = patched_signed(&base, 1, Value::Int(2), &w.issuer);
    assert_eq!(reject_name(&env), "scheme_version_unsupported");
    // unknown field smuggled in
    let mut v = decode(base.receipt_bytes()).expect("parses");
    if let Value::Map(ref mut entries) = v {
        entries.push((Value::Int(9), Value::Int(1)));
    }
    let bytes = encode(&v).expect("in-profile");
    let sig = w.issuer.sign_detached(&bytes);
    let env = encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(bytes)),
        (Value::Int(2), Value::Bytes(sig.to_vec())),
    ]))
    .expect("in-profile");
    assert_eq!(reject_name(&env), "unknown_field");
    // duplicate field: the canonical profile itself forbids duplicate
    // map keys, so the bytes must be hand-spliced (the encoder refuses
    // to build them — correct) and the refusal fires at the strictest
    // layer, the canonical CBOR decode inside the receipt parse
    let mut v = decode(base.receipt_bytes()).expect("parses");
    let dup_bytes = {
        let Value::Map(entries) = &mut v else {
            unreachable!("receipt is a map")
        };
        // single-entry-map trick: encode each pair as its own one-entry
        // map and strip the header byte to recover the raw entry bytes
        let raw: Vec<Vec<u8>> = entries
            .iter()
            .map(|(k, val)| {
                let one = encode(&Value::Map(vec![(k.clone(), val.clone())])).expect("in-profile");
                one[1..].to_vec()
            })
            .collect();
        // 9 entries with key 5 duplicated at its sorted position
        let mut out = vec![0xA0 | 9];
        for (i, (k, _)) in entries.iter().enumerate() {
            out.extend_from_slice(&raw[i]);
            if let Value::Int(5) = k {
                out.extend_from_slice(&raw[i]);
            }
        }
        out
    };
    let sig = w.issuer.sign_detached(&dup_bytes);
    let env = encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(dup_bytes)),
        (Value::Int(2), Value::Bytes(sig.to_vec())),
    ]))
    .expect("in-profile");
    let err = SignedContributionReceipt::from_envelope_bytes(&env)
        .expect_err("duplicate-key bytes must be refused");
    assert_eq!(err.name(), "cbor");
    assert!(
        err.to_string().contains("duplicate"),
        "the refusal is the duplicate-key law, got {err}"
    );
    // missing field (drop the sequence)
    let mut v = decode(base.receipt_bytes()).expect("parses");
    if let Value::Map(ref mut entries) = v {
        entries.retain(|(k, _)| !matches!(k, Value::Int(7)));
    }
    let bytes = encode(&v).expect("in-profile");
    let sig = w.issuer.sign_detached(&bytes);
    let env = encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(bytes)),
        (Value::Int(2), Value::Bytes(sig.to_vec())),
    ]))
    .expect("in-profile");
    assert_eq!(reject_name(&env), "missing_field");
}

#[test]
fn any_field_tamper_is_refused_or_a_different_named_object() {
    let w = world();
    let base = base_receipt(&w);
    // without re-signing, every field tamper is refused — but the strict
    // parse runs FIRST (the house law: parse, then identity, then
    // signature), so a tamper that leaves the canonical profile refuses
    // with its own typed structural error before the signature is even
    // consulted; every in-profile tamper breaks the signature instead.
    let expected = |key: i64| -> &str {
        match key {
            // scheme_version 2 leaves the supported set at parse time
            1 => "scheme_version_unsupported",
            // an empty issuer map fails the NodeIdentity strict parse
            2 => "identity_error",
            // in-variant values parse; the stale signature then refuses
            _ => "signature_invalid",
        }
    };
    for key in 1..=8 {
        let value = match key {
            1 => Value::Int(2),
            2 => Value::Map(vec![]),
            3 => Value::Bytes(vec![0x33; 32]),
            4 => Value::Bytes(vec![0x44; 32]),
            5 => Value::Text("delivered".into()),
            6 => Value::Int(9),
            7 => Value::Int(2),
            _ => Value::Int(NOW as i64 + 11),
        };
        let env = patched_stale(&base, key, value);
        assert_eq!(reject_name(&env), expected(key), "field {key} tamper");
    }
    // with the issuer's re-signature: in-variant changes are DIFFERENT
    // named objects (distinct receipt_id), out-of-variant ones refuse
    let in_variant: Vec<(i64, Value)> = vec![
        (3, Value::Bytes([0x55; 32].to_vec())),
        (4, Value::Bytes([0x66; 32].to_vec())),
        (5, Value::Text("delivered".into())),
        (6, Value::Int(9)),
        (7, Value::Int(4)),
        (8, Value::Int(NOW as i64 + 99)),
    ];
    for (key, value) in in_variant {
        let env = patched_signed(&base, key, value, &w.issuer);
        let parsed = SignedContributionReceipt::from_envelope_bytes(&env)
            .unwrap_or_else(|e| panic!("field {key} in-variant tamper must parse: {e}"));
        assert_ne!(
            parsed.receipt_id(),
            base.receipt_id(),
            "field {key} change must be a different named object"
        );
    }
}

#[test]
fn envelope_confusion_is_refused_both_ways() {
    let w = world();
    let base = base_receipt(&w);
    // a properly signed CircuitRevocation envelope fed to the
    // contribution path: the envelope parses, the inner object does not
    // (the revoker identity map lands in the content_id slot)
    let revocation = CircuitRevocation::new(
        &w.issuer,
        [0x77; 32],
        RevocationReason::Policy,
        None,
        NOW + 10,
    )
    .expect("revocation")
    .sign(&w.issuer)
    .expect("sign");
    let env = revocation.to_envelope_bytes();
    // the first slot where the two wire objects diverge is field 2
    // (a receipt's issuer map vs a revocation's circuit_id bstr): the
    // NodeIdentity strict parse refuses the non-map through the same
    // identity-layer path the revocation parser uses for its revoker
    // slot — typed and fail-closed either way
    assert_eq!(
        SignedContributionReceipt::from_envelope_bytes(&env)
            .expect_err("foreign object must not parse as a receipt")
            .name(),
        "identity_error"
    );
    // and the reverse: the receipt envelope fed to the revocation path
    // (its evidence map slot receives the kind text)
    match SignedCircuitRevocation::from_envelope_bytes(&base.to_envelope_bytes()) {
        Err(e) => {
            let name = e.name();
            assert!(
                ["field_not_expected_type", "reason_unknown"].contains(&name),
                "receipt fed to revocation refused with a typed error, got {name}"
            );
        }
        Ok(_) => panic!("a receipt must not parse as a revocation"),
    }
}

#[test]
fn malformed_envelopes_are_refused_typed() {
    let w = world();
    let base = base_receipt(&w);
    let wire = base.receipt_bytes().to_vec();
    let good_sig = base.signature().to_vec();
    // signature of 63 bytes
    let env = encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(wire.clone())),
        (Value::Int(2), Value::Bytes(good_sig[..63].to_vec())),
    ]))
    .expect("in-profile");
    assert_eq!(reject_name(&env), "signature_wrong_length");
    // envelope with only the payload entry
    let env = encode(&Value::Map(vec![(
        Value::Int(1),
        Value::Bytes(wire.clone()),
    )]))
    .expect("in-profile");
    assert_eq!(reject_name(&env), "envelope_wrong_entry_count");
    // three entries
    let env = encode(&Value::Map(vec![
        (Value::Int(1), Value::Bytes(wire.clone())),
        (Value::Int(2), Value::Bytes(good_sig.clone())),
        (Value::Int(3), Value::Int(1)),
    ]))
    .expect("in-profile");
    assert_eq!(reject_name(&env), "envelope_wrong_entry_count");
    // payload field not bytes
    let env = encode(&Value::Map(vec![
        (Value::Int(1), Value::Int(5)),
        (Value::Int(2), Value::Bytes(good_sig.clone())),
    ]))
    .expect("in-profile");
    assert_eq!(reject_name(&env), "field_not_expected_type");
    // not a map
    let env = encode(&Value::Array(vec![Value::Int(1)])).expect("in-profile");
    assert_eq!(reject_name(&env), "not_a_map");
    // a flipped signature bit on an otherwise valid envelope
    let mut tampered = base.to_envelope_bytes();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    assert_eq!(reject_name(&tampered), "signature_invalid");
}

#[test]
fn sequence_replay_and_regression_refused_idempotency_exact() {
    let w = world();
    let ledger = ReceiptLedger::new();
    let mk = |delivered: u64, seq: u64| {
        ContributionReceipt::new(
            &w.issuer,
            *w.contributor.node_id().as_bytes(),
            w.content_id,
            ContributionKind::Carried,
            delivered,
            seq,
            NOW + 10,
        )
        .expect("build")
        .sign(&w.issuer)
        .expect("sign")
    };
    let first = mk(17, 1);
    assert_eq!(
        ledger.admit(NOW + 10, &first).unwrap(),
        ReceiptAdmitOutcome::Admitted
    );
    // the exact same envelope re-delivered: idempotent, state unchanged
    assert_eq!(
        ledger.admit(NOW + 11, &first).unwrap(),
        ReceiptAdmitOutcome::Duplicate
    );
    assert_eq!(ledger.receipt_count(), 1);
    // a replayed sequence with different bytes: refused typed
    assert_eq!(
        ledger.admit(NOW + 12, &mk(9, 1)).unwrap_err().name(),
        "sequence_regressed"
    );
    // advance, then regress below the high-water mark
    assert_eq!(
        ledger.admit(NOW + 12, &mk(17, 2)).unwrap(),
        ReceiptAdmitOutcome::Admitted
    );
    assert_eq!(
        ledger.admit(NOW + 13, &mk(17, 5)).unwrap(),
        ReceiptAdmitOutcome::Admitted
    );
    assert_eq!(
        ledger.admit(NOW + 14, &mk(9, 4)).unwrap_err().name(),
        "sequence_regressed"
    );
    assert_eq!(
        ledger.admit(NOW + 14, &mk(9, 5)).unwrap_err().name(),
        "sequence_regressed"
    );
    // refusals never move the high-water mark
    assert_eq!(ledger.receipt_count(), 3);
    assert_eq!(
        ledger.last_seq(&w.issuer.node_id(), w.contributor.node_id().as_bytes()),
        Some(5)
    );
    // the next strictly-greater sequence still admits
    assert_eq!(
        ledger.admit(NOW + 15, &mk(9, 6)).unwrap(),
        ReceiptAdmitOutcome::Admitted
    );
}

#[test]
fn sequence_namespaces_are_independent_per_pair() {
    let w = world();
    let other_contributor = Identity::from_seed([0x33; 32], NOW, None).expect("contributor");
    let other_issuer = Identity::from_seed([0x44; 32], NOW, None).expect("issuer");
    let ledger = ReceiptLedger::new();
    let mk = |issuer: &Identity, contributor: &Identity, seq: u64| {
        ContributionReceipt::new(
            issuer,
            *contributor.node_id().as_bytes(),
            w.content_id,
            ContributionKind::Carried,
            17,
            seq,
            NOW + 10,
        )
        .expect("build")
        .sign(issuer)
        .expect("sign")
    };
    // the same sequence numbers flow freely across distinct pairs
    for seq in [1u64, 2, 3] {
        assert_eq!(
            ledger
                .admit(NOW + 10, &mk(&w.issuer, &w.contributor, seq))
                .unwrap(),
            ReceiptAdmitOutcome::Admitted
        );
        assert_eq!(
            ledger
                .admit(NOW + 10, &mk(&w.issuer, &other_contributor, seq))
                .unwrap(),
            ReceiptAdmitOutcome::Admitted
        );
        assert_eq!(
            ledger
                .admit(NOW + 10, &mk(&other_issuer, &w.contributor, seq))
                .unwrap(),
            ReceiptAdmitOutcome::Admitted
        );
    }
    assert_eq!(ledger.receipt_count(), 9);
    // but the same pair cannot repeat one: a REPEATED sequence on a
    // different named object (different acknowledged bytes) refuses
    // typed — the identical re-delivery is the idempotent Duplicate
    // covered by sequence_replay_and_regression_refused_idempotency_exact
    let regressed = ContributionReceipt::new(
        &w.issuer,
        *w.contributor.node_id().as_bytes(),
        w.content_id,
        ContributionKind::Carried,
        9,
        2,
        NOW + 10,
    )
    .expect("build")
    .sign(&w.issuer)
    .expect("sign");
    assert_eq!(
        ledger.admit(NOW + 10, &regressed).unwrap_err().name(),
        "sequence_regressed"
    );
    // and the other namespaces keep admitting at their own pace
    assert_eq!(
        ledger
            .admit(NOW + 10, &mk(&w.issuer, &other_contributor, 4))
            .unwrap(),
        ReceiptAdmitOutcome::Admitted
    );
}

#[test]
fn snapshot_tampering_fails_closed() {
    let w = world();
    let ledger = ReceiptLedger::new();
    for seq in [1u64, 2] {
        let signed = ContributionReceipt::new(
            &w.issuer,
            *w.contributor.node_id().as_bytes(),
            w.content_id,
            ContributionKind::Carried,
            17,
            seq,
            NOW + 10,
        )
        .expect("build")
        .sign(&w.issuer)
        .expect("sign");
        ledger.admit(NOW + 10, &signed).expect("admit");
    }
    let snapshot = ledger.to_snapshot_bytes();
    // any flipped byte anywhere in the snapshot fails the restore
    for at in [0usize, snapshot.len() / 2, snapshot.len() - 1] {
        let mut tampered = snapshot.clone();
        tampered[at] ^= 0x01;
        assert!(
            ReceiptLedger::from_snapshot_bytes(&tampered).is_err(),
            "tampered snapshot byte {at} must fail closed"
        );
    }
    // a rewritten receipt inside an otherwise well-formed envelope fails
    // the signature re-verification
    let mut v = decode(&snapshot).expect("snapshot parses");
    if let Value::Map(ref mut entries) = v {
        for (k, val) in entries.iter_mut() {
            if let Value::Int(2) = k {
                if let Value::Array(items) = val {
                    // flip a byte inside the first record's envelope
                    if let Value::Bytes(env) = &mut items[0] {
                        let at = env.len() / 2;
                        env[at] ^= 0x01;
                    }
                }
            }
        }
    }
    let rewritten = encode(&v).expect("in-profile");
    assert!(ReceiptLedger::from_snapshot_bytes(&rewritten).is_err());
    // the honest snapshot still restores and keeps the sequence law
    let restored = ReceiptLedger::from_snapshot_bytes(&snapshot).expect("restore");
    assert_eq!(restored.receipt_count(), 2);
    let replay = ContributionReceipt::new(
        &w.issuer,
        *w.contributor.node_id().as_bytes(),
        w.content_id,
        ContributionKind::Carried,
        9, // distinct bytes, repeated sequence
        2,
        NOW + 10,
    )
    .expect("build")
    .sign(&w.issuer)
    .expect("sign");
    assert_eq!(
        restored.admit(NOW + 10, &replay).unwrap_err().name(),
        "sequence_regressed"
    );
}

#[test]
fn snapshot_order_and_duplicates_are_refused() {
    let w = world();
    let other_issuer = Identity::from_seed([0x44; 32], NOW, None).expect("issuer");
    let envelope_for = |issuer: &Identity, seq: u64| {
        ContributionReceipt::new(
            issuer,
            *w.contributor.node_id().as_bytes(),
            w.content_id,
            ContributionKind::Carried,
            17,
            seq,
            NOW + 10,
        )
        .expect("build")
        .sign(issuer)
        .expect("sign")
        .to_envelope_bytes()
    };
    let build_snapshot = |envelopes: Vec<Value>| -> Vec<u8> {
        encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Array(envelopes)),
        ]))
        .expect("in-profile")
    };
    // canonical: issuer 0x11 seq 1, then issuer 0x44 seq 1 (pair order)
    let a1 = Value::Bytes(envelope_for(&w.issuer, 1));
    let b1 = Value::Bytes(envelope_for(&other_issuer, 1));
    let a2 = Value::Bytes(envelope_for(&w.issuer, 2));
    // reordered: out of canonical (issuer, contributor, seq) order
    let reordered = build_snapshot(vec![b1.clone(), a2.clone(), a1.clone()]);
    assert_eq!(
        ReceiptLedger::from_snapshot_bytes(&reordered)
            .expect_err("reordered snapshot refused")
            .name(),
        "snapshot_order_invalid"
    );
    // a duplicated record (the same receipt_id twice)
    let duplicated = build_snapshot(vec![a1.clone(), a1.clone()]);
    assert_eq!(
        ReceiptLedger::from_snapshot_bytes(&duplicated)
            .expect_err("duplicated snapshot refused")
            .name(),
        "snapshot_duplicate_record"
    );
    // the canonical order restores cleanly
    let canonical = build_snapshot(vec![a1.clone(), a2, b1]);
    let restored = ReceiptLedger::from_snapshot_bytes(&canonical).expect("restore");
    assert_eq!(restored.receipt_count(), 3);
}

#[test]
fn receipt_id_is_content_derived_not_caller_chosen() {
    let w = world();
    // two independent builds of the same logical receipt: identical
    // bytes, identical receipt_id (no nonce, no clock, no escape hatch)
    let one = base_receipt(&w);
    let two = ContributionReceipt::new(
        &w.issuer,
        *w.contributor.node_id().as_bytes(),
        w.content_id,
        ContributionKind::Carried,
        17,
        1,
        NOW + 10,
    )
    .expect("build")
    .sign(&w.issuer)
    .expect("sign");
    assert_eq!(one.receipt_bytes(), two.receipt_bytes());
    assert_eq!(one.receipt_id(), two.receipt_id());
    // the id is exactly SHA-256 of the canonical bytes (recomputed)
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(one.receipt_bytes());
    let expect: [u8; 32] = hasher.finalize().into();
    assert_eq!(one.receipt_id(), expect);
    // and it is NOT any of the receipt's inputs (no shortcut identity)
    assert_ne!(&one.receipt_id(), one.receipt().content_id());
    assert_ne!(one.receipt_id(), *one.receipt().contributor_node_id());
}
