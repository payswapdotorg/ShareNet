//! R7-001 adversarial verification: every revocation admission rule must
//! fail closed under attack — per-field tampering, foreign signers,
//! forged path membership, future timestamps, evidence-map violations,
//! envelope confusion, and L015 resurrection attempts (setup/ack/frame
//! replays on a durably revoked circuit id, including after a full
//! runtime-state loss modeled through the ledger snapshot seam).

use sharenet_protocol::cbor::{self, Value};
use sharenet_protocol::circuit::{
    derive_circuit_id, CircuitDestroy, CircuitError, CircuitFrame, CircuitRegistry, CircuitSetup,
    CircuitSetupAck,
};
use sharenet_protocol::identity::Identity;
use sharenet_protocol::revocation::{
    CircuitRevocation, EvidenceValue, RevocationLedger, RevocationReason,
    SignedCircuitRevocation, EVIDENCE_FAILURE_KIND, EVIDENCE_MAX_FIELDS,
};
use sharenet_protocol::route::{
    derive_proposal_id, RouteAcceptance, RouteCommitment, RouteProposal, SignedEnvelope,
};
use std::collections::BTreeMap;

/// Three members (proposer + two hops) with a verified commitment, plus
/// a valid outsider identity and an established circuit per nonce.
struct World {
    proposer: Identity,
    hop1: Identity,
    hop2: Identity,
    outsider: Identity,
    commitment: RouteCommitment,
}

fn world(now: u64) -> World {
    let proposer = Identity::from_seed([0xA1; 32], now, None).unwrap();
    let hop1 = Identity::from_seed([0xB2; 32], now, None).unwrap();
    let hop2 = Identity::from_seed([0xC3; 32], now, None).unwrap();
    let outsider = Identity::from_seed([0xD4; 32], now, None).unwrap();
    let mut path: Vec<[u8; 32]> = [
        *proposer.node_id().as_bytes(),
        *hop1.node_id().as_bytes(),
        *hop2.node_id().as_bytes(),
    ]
    .to_vec();
    path.sort();
    let proposal = RouteProposal::new(&proposer, path, "live", now, 600, [0x42; 32]).unwrap();
    let proposal_env = proposal.sign(&proposer).unwrap();
    let proposal_id = derive_proposal_id(proposal_env.bytes());
    let mut members: Vec<&Identity> = vec![&proposer, &hop1, &hop2];
    members.sort_by_key(|m| *m.node_id().as_bytes());
    let acceptance_envs: Vec<_> = members
        .iter()
        .enumerate()
        .map(|(i, m)| {
            let a = RouteAcceptance::new(m, proposal_id, i as u64, now, 600).unwrap();
            a.sign(m).unwrap()
        })
        .collect();
    let commitment = RouteCommitment::build(now, proposal_env, acceptance_envs).unwrap();
    World {
        proposer,
        hop1,
        hop2,
        outsider,
        commitment,
    }
}

/// A fully established circuit (setup admitted, all positions acked) —
/// plus the setup envelope for replay attacks.
fn established(
    now: u64,
    nonce: [u8; 32],
) -> (World, CircuitRegistry, [u8; 32], SignedEnvelope) {
    let w = world(now);
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, nonce, now, 600).unwrap();
    let setup_env = setup.sign(&w.proposer).unwrap();
    let circuit_id = derive_circuit_id(w.commitment.route_id(), &nonce);
    let mut registry = CircuitRegistry::new();
    registry.admit_setup(now, &setup_env).unwrap();
    let path = w.commitment.verify(now).unwrap().proposal.path().to_vec();
    for (pos, want) in path.iter().enumerate() {
        let member = [&w.proposer, &w.hop1, &w.hop2]
            .into_iter()
            .find(|m| m.node_id().as_bytes() == want)
            .unwrap();
        let ack = CircuitSetupAck::new(circuit_id, &setup_env, member, pos as u64, now, 500)
            .unwrap();
        let env = ack.sign(member).unwrap();
        registry.admit_ack(now, &env).unwrap();
    }
    (w, registry, circuit_id, setup_env)
}

fn evidence(kind: &str) -> BTreeMap<String, EvidenceValue> {
    BTreeMap::from([
        (
            EVIDENCE_FAILURE_KIND.to_string(),
            EvidenceValue::Text(kind.to_string()),
        ),
        ("missed_acks".to_string(), EvidenceValue::Int(3)),
    ])
}

/// A valid signed revocation by hop1 for the circuit.
fn valid_revocation(
    w: &World,
    circuit_id: [u8; 32],
    reason: RevocationReason,
    ev: Option<BTreeMap<String, EvidenceValue>>,
    revoked_at: u64,
) -> SignedCircuitRevocation {
    let r = CircuitRevocation::new(&w.hop1, circuit_id, reason, ev, revoked_at).unwrap();
    r.sign(&w.hop1).unwrap()
}

/// Replace one wire field of a signed revocation and re-sign it with
/// the given key (so the failure is the INVARIANT, not the signature).
fn rebuild_with<F>(base: &SignedCircuitRevocation, signer: &Identity, mutate: F) -> Vec<u8>
where
    F: FnOnce(&mut Value),
{
    let mut wire = cbor::decode(base.revocation_bytes()).unwrap();
    mutate(&mut wire);
    let bytes = cbor::encode(&wire).unwrap();
    SignedEnvelope::new(bytes.clone(), signer.sign_detached(&bytes)).to_envelope_bytes()
}

#[test]
fn tampered_revocation_bytes_rejected() {
    let now = 1_700_000_000u64;
    let (w, registry, circuit_id, _setup_env) = established(now, [0x61; 32]);
    let signed = valid_revocation(
        &w,
        circuit_id,
        RevocationReason::LinkFailure,
        Some(evidence("link_failure")),
        now + 10,
    );
    let mut tampered = signed.to_envelope_bytes();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01; // flip one signature bit
    let ledger = RevocationLedger::new();
    assert_eq!(
        ledger
            .admit_envelope(now + 10, &tampered, &registry)
            .unwrap_err()
            .name(),
        "signature_invalid"
    );
}

#[test]
fn foreign_key_signature_rejected() {
    let now = 1_700_000_000u64;
    let (w, registry, circuit_id, _setup_env) = established(now, [0x62; 32]);
    // The wire names hop1 as the revoker, but the outsider signs it:
    // the embedded identity's key must verify the signature.
    let r = CircuitRevocation::new(
        &w.hop1,
        circuit_id,
        RevocationReason::LinkFailure,
        Some(evidence("link_failure")),
        now + 10,
    )
    .unwrap();
    let bytes = r.to_wire_bytes();
    let env =
        SignedEnvelope::new(bytes.clone(), w.outsider.sign_detached(&bytes)).to_envelope_bytes();
    let ledger = RevocationLedger::new();
    assert_eq!(
        ledger
            .admit_envelope(now + 10, &env, &registry)
            .unwrap_err()
            .name(),
        "signature_invalid"
    );
}

#[test]
fn non_path_member_revoker_refused() {
    let now = 1_700_000_000u64;
    let (w, registry, circuit_id, _setup_env) = established(now, [0x63; 32]);
    // A perfectly valid signature by an identity that is NOT in the
    // committed path: the registry record decides, never the caller.
    let r = CircuitRevocation::new(
        &w.outsider,
        circuit_id,
        RevocationReason::Policy,
        None,
        now + 10,
    )
    .unwrap();
    let signed = r.sign(&w.outsider).unwrap();
    let ledger = RevocationLedger::new();
    assert_eq!(
        ledger
            .admit(now + 10, &signed, &registry)
            .unwrap_err()
            .name(),
        "revoker_not_on_path"
    );
    assert!(!ledger.is_revoked(&circuit_id));
    // A revocation for a circuit the registry has never admitted is
    // refused outright: the committed path cannot be verified.
    let unknown = CircuitRevocation::new(
        &w.hop1,
        [0x99; 32],
        RevocationReason::Policy,
        None,
        now + 10,
    )
    .unwrap();
    let ledger2 = RevocationLedger::new();
    assert_eq!(
        ledger2
            .admit(now + 10, &unknown.sign(&w.hop1).unwrap(), &registry)
            .unwrap_err()
            .name(),
        "circuit_unknown"
    );
}

#[test]
fn future_revoked_at_refused() {
    let now = 1_700_000_000u64;
    let (w, registry, circuit_id, _setup_env) = established(now, [0x64; 32]);
    let signed = valid_revocation(
        &w,
        circuit_id,
        RevocationReason::LinkFailure,
        Some(evidence("link_failure")),
        now + 10,
    );
    let ledger = RevocationLedger::new();
    assert_eq!(
        ledger
            .admit(now + 9, &signed, &registry)
            .unwrap_err()
            .name(),
        "revoked_at_in_future"
    );
    assert!(!ledger.is_revoked(&circuit_id));
    // the exact second is fine (revoked_at == now)
    ledger.admit(now + 10, &signed, &registry).unwrap();
    assert!(ledger.is_revoked(&circuit_id));
}

#[test]
fn unknown_reason_rejected() {
    let now = 1_700_000_000u64;
    let (w, registry, circuit_id, _setup_env) = established(now, [0x65; 32]);
    let signed = valid_revocation(
        &w,
        circuit_id,
        RevocationReason::LinkFailure,
        Some(evidence("link_failure")),
        now + 10,
    );
    let bytes = rebuild_with(&signed, &w.hop1, |wire| {
        if let Value::Map(ref mut entries) = wire {
            for (k, v) in entries.iter_mut() {
                if let Value::Int(4) = k {
                    *v = Value::Text("because".into());
                }
            }
        }
    });
    let ledger = RevocationLedger::new();
    assert_eq!(
        ledger
            .admit_envelope(now + 10, &bytes, &registry)
            .unwrap_err()
            .name(),
        "reason_unknown"
    );
}

#[test]
fn evidence_map_violations_rejected() {
    let now = 1_700_000_000u64;
    let (w, registry, circuit_id, _setup_env) = established(now, [0x66; 32]);
    let signed = valid_revocation(
        &w,
        circuit_id,
        RevocationReason::LinkFailure,
        Some(evidence("link_failure")),
        now + 10,
    );
    let ledger = RevocationLedger::new();

    // too many fields beyond failure_kind (9 extra > 8)
    let mut entries: Vec<(Value, Value)> = (0..EVIDENCE_MAX_FIELDS + 2)
        .map(|i| (Value::Text(format!("f{i}")), Value::Int(i as i64)))
        .collect();
    entries.push((Value::Text("failure_kind".into()), Value::Text("x".into())));
    entries.sort_by(|a, b| match (&a.0, &b.0) {
        (Value::Text(x), Value::Text(y)) => x.cmp(y),
        _ => unreachable!("text keys"),
    });
    let ordered = Value::Map(entries);
    let bytes = rebuild_with(&signed, &w.hop1, |wire| {
        if let Value::Map(ref mut entries) = wire {
            for (k, v) in entries.iter_mut() {
                if let Value::Int(5) = k {
                    *v = ordered.clone();
                }
            }
        }
    });
    assert_eq!(
        ledger
            .admit_envelope(now + 10, &bytes, &registry)
            .unwrap_err()
            .name(),
        "evidence_too_many_fields"
    );

    // evidence without failure_kind
    let no_kind = Value::Map(vec![(Value::Text("missed_acks".into()), Value::Int(1))]);
    let bytes = rebuild_with(&signed, &w.hop1, |wire| {
        if let Value::Map(ref mut entries) = wire {
            for (k, v) in entries.iter_mut() {
                if let Value::Int(5) = k {
                    *v = no_kind.clone();
                }
            }
        }
    });
    assert_eq!(
        ledger
            .admit_envelope(now + 10, &bytes, &registry)
            .unwrap_err()
            .name(),
        "failure_kind_missing"
    );

    // failure_kind not text
    let bad_kind =
        Value::Map(vec![(Value::Text("failure_kind".into()), Value::Int(7))]);
    let bytes = rebuild_with(&signed, &w.hop1, |wire| {
        if let Value::Map(ref mut entries) = wire {
            for (k, v) in entries.iter_mut() {
                if let Value::Int(5) = k {
                    *v = bad_kind.clone();
                }
            }
        }
    });
    assert_eq!(
        ledger
            .admit_envelope(now + 10, &bytes, &registry)
            .unwrap_err()
            .name(),
        "failure_kind_not_text"
    );

    // non-int/text entry value (bytes)
    let bad_value = Value::Map(vec![
        (Value::Text("failure_kind".into()), Value::Text("x".into())),
        (Value::Text("blob".into()), Value::Bytes(vec![0u8; 4])),
    ]);
    let bytes = rebuild_with(&signed, &w.hop1, |wire| {
        if let Value::Map(ref mut entries) = wire {
            for (k, v) in entries.iter_mut() {
                if let Value::Int(5) = k {
                    *v = bad_value.clone();
                }
            }
        }
    });
    assert_eq!(
        ledger
            .admit_envelope(now + 10, &bytes, &registry)
            .unwrap_err()
            .name(),
        "evidence_entry_malformed"
    );

    // evidence field not a map at all
    let bytes = rebuild_with(&signed, &w.hop1, |wire| {
        if let Value::Map(ref mut entries) = wire {
            for (k, v) in entries.iter_mut() {
                if let Value::Int(5) = k {
                    *v = Value::Int(3);
                }
            }
        }
    });
    assert_eq!(
        ledger
            .admit_envelope(now + 10, &bytes, &registry)
            .unwrap_err()
            .name(),
        "field_not_expected_type"
    );
    // nothing was recorded by any of the refused admissions
    assert!(!ledger.is_revoked(&circuit_id));
}

#[test]
fn per_field_wire_tampering_rejected() {
    let now = 1_700_000_000u64;
    let (w, _registry, circuit_id, _setup_env) = established(now, [0x67; 32]);
    let signed = valid_revocation(
        &w,
        circuit_id,
        RevocationReason::LinkFailure,
        Some(evidence("link_failure")),
        now + 10,
    );
    // scheme version 2
    let bytes = rebuild_with(&signed, &w.hop1, |wire| {
        if let Value::Map(ref mut entries) = wire {
            for (k, v) in entries.iter_mut() {
                if let Value::Int(1) = k {
                    *v = Value::Int(2);
                }
            }
        }
    });
    assert_eq!(
        SignedCircuitRevocation::from_envelope_bytes(&bytes)
            .unwrap_err()
            .name(),
        "scheme_version_unsupported"
    );
    // circuit_id of 31 bytes
    let bytes = rebuild_with(&signed, &w.hop1, |wire| {
        if let Value::Map(ref mut entries) = wire {
            for (k, v) in entries.iter_mut() {
                if let Value::Int(2) = k {
                    *v = Value::Bytes(vec![0u8; 31]);
                }
            }
        }
    });
    assert_eq!(
        SignedCircuitRevocation::from_envelope_bytes(&bytes)
            .unwrap_err()
            .name(),
        "circuit_id_wrong_length"
    );
    // missing revoked_at (field 6)
    let bytes = rebuild_with(&signed, &w.hop1, |wire| {
        if let Value::Map(ref mut entries) = wire {
            entries.retain(|(k, _)| !matches!(k, Value::Int(6)));
        }
    });
    assert_eq!(
        SignedCircuitRevocation::from_envelope_bytes(&bytes)
            .unwrap_err()
            .name(),
        "missing_field"
    );
    // unknown field 7
    let bytes = rebuild_with(&signed, &w.hop1, |wire| {
        if let Value::Map(ref mut entries) = wire {
            entries.push((Value::Int(7), Value::Int(1)));
        }
    });
    assert_eq!(
        SignedCircuitRevocation::from_envelope_bytes(&bytes)
            .unwrap_err()
            .name(),
        "unknown_field"
    );
    // negative revoked_at
    let bytes = rebuild_with(&signed, &w.hop1, |wire| {
        if let Value::Map(ref mut entries) = wire {
            for (k, v) in entries.iter_mut() {
                if let Value::Int(6) = k {
                    *v = Value::Int(-1);
                }
            }
        }
    });
    assert_eq!(
        SignedCircuitRevocation::from_envelope_bytes(&bytes)
            .unwrap_err()
            .name(),
        "timestamp_out_of_range"
    );
    // swapped identity (field 3): a DIFFERENT valid identity whose key
    // did not sign these bytes -> signature invalid
    let bytes = rebuild_with(&signed, &w.hop1, |wire| {
        if let Value::Map(ref mut entries) = wire {
            for (k, v) in entries.iter_mut() {
                if let Value::Int(3) = k {
                    *v = w.outsider.node_identity().to_wire();
                }
            }
        }
    });
    assert_eq!(
        SignedCircuitRevocation::from_envelope_bytes(&bytes)
            .unwrap_err()
            .name(),
        "signature_invalid"
    );
}

#[test]
fn envelope_confusion_rejected() {
    let now = 1_700_000_000u64;
    let (w, mut registry, circuit_id, _setup_env) = established(now, [0x68; 32]);
    // A CircuitDestroy envelope (same carrying-envelope shape) fed to
    // the revocation path: the destroy wire (field 5 = integer
    // destroyed_at, no field 6) does not parse as a revocation.
    let destroy = CircuitDestroy::new(circuit_id, &w.hop1, "link_failure", now + 10).unwrap();
    let destroy_env = destroy.sign(&w.hop1).unwrap();
    let ledger = RevocationLedger::new();
    assert_eq!(
        ledger
            .admit_envelope(now + 10, &destroy_env.to_envelope_bytes(), &registry)
            .unwrap_err()
            .name(),
        "field_not_expected_type"
    );
    // A revocation envelope fed to the circuit-destroy admission path
    // fails closed as well (destroy's own strict parse).
    let signed = valid_revocation(
        &w,
        circuit_id,
        RevocationReason::LinkFailure,
        Some(evidence("link_failure")),
        now + 10,
    );
    let env = SignedEnvelope::from_envelope_bytes(&signed.to_envelope_bytes()).unwrap();
    let result = registry.admit_destroy(&env);
    assert!(matches!(
        result,
        Err(CircuitError::Cbor(_)) | Err(CircuitError::FieldNotExpectedType { .. })
    ));
}

#[test]
fn revoked_circuit_admission_refused_setup_ack_frame() {
    let now = 1_700_000_000u64;
    let (w, mut registry, circuit_id, setup_env) = established(now, [0x69; 32]);
    let ledger = RevocationLedger::new();
    registry.install_revocation_ledger(&ledger);
    // Admit through the shared ledger view AFTER installation: the
    // registry's gate sees it immediately.
    let signed = valid_revocation(
        &w,
        circuit_id,
        RevocationReason::LinkFailure,
        Some(evidence("link_failure")),
        now + 10,
    );
    ledger.admit(now + 10, &signed, &registry).unwrap();
    assert!(ledger.is_revoked(&circuit_id));

    // Setup replay of the SAME setup envelope: refused (L015).
    assert_eq!(
        registry.admit_setup(now, &setup_env),
        Err(CircuitError::CircuitRevoked)
    );
    // Acks: refused.
    let ack = CircuitSetupAck::new(circuit_id, &setup_env, &w.hop1, 1, now, 500).unwrap();
    let ack_env = ack.sign(&w.hop1).unwrap();
    assert_eq!(
        registry.admit_ack(now, &ack_env),
        Err(CircuitError::CircuitRevoked)
    );
    // Frames: refused.
    let frame = CircuitFrame::new(circuit_id, 1, 0, b"payload".to_vec()).unwrap();
    assert_eq!(registry.admit_frame(&frame), Err(CircuitError::CircuitRevoked));
    // Even a destroy is refused: the durable revocation is the terminal
    // authority over the already-terminal circuit.
    let destroy = CircuitDestroy::new(circuit_id, &w.hop1, "link_failure", now + 11).unwrap();
    let destroy_env = destroy.sign(&w.hop1).unwrap();
    assert_eq!(
        registry.admit_destroy(&destroy_env),
        Err(CircuitError::CircuitRevoked)
    );
}

#[test]
fn revoked_setup_replay_refused_after_runtime_state_loss() {
    // THE L015 restart story: the whole runtime registry (circuits,
    // nonces, destroy flags) is lost; ONLY the durable revocation
    // survives (modeled through the snapshot seam). A setup replay for
    // the revoked circuit id must be refused.
    let now = 1_700_000_000u64;
    let (w, registry, circuit_id, setup_env) = established(now, [0x6A; 32]);
    let ledger = RevocationLedger::new();
    let signed = valid_revocation(
        &w,
        circuit_id,
        RevocationReason::EvidenceTimeout,
        Some(BTreeMap::from([
            (
                EVIDENCE_FAILURE_KIND.to_string(),
                EvidenceValue::Text("evidence_timeout".into()),
            ),
            (
                "stale_since_unix".to_string(),
                EvidenceValue::Int((now + 5) as i64),
            ),
        ])),
        now + 10,
    );
    ledger.admit(now + 10, &signed, &registry).unwrap();
    // "crash": only the snapshot survives
    let snapshot = ledger.to_snapshot_bytes();
    let restored = RevocationLedger::from_snapshot_bytes(&snapshot).unwrap();
    assert!(restored.is_revoked(&circuit_id));
    // "restart": a completely fresh runtime registry with the restored
    // durable ledger installed.
    let mut fresh = CircuitRegistry::new();
    fresh.install_revocation_ledger(&restored);
    // The setup replay now derives the SAME circuit id (identical route
    // + nonce) — and the durable revocation refuses it even though the
    // runtime nonce set is empty.
    assert_eq!(
        fresh.admit_setup(now, &setup_env),
        Err(CircuitError::CircuitRevoked)
    );
    // and the runtime destroy state was never there to save us: a
    // frame on the revoked circuit is refused, not "unknown".
    let frame = CircuitFrame::new(circuit_id, 1, 0, b"x".to_vec()).unwrap();
    assert_eq!(fresh.admit_frame(&frame), Err(CircuitError::CircuitRevoked));
}

#[test]
fn revoked_circuit_replacement_is_fresh() {
    // L014 + L015 together: the revoked circuit stays dead, and the
    // replacement MUST be a genuinely fresh circuit (new nonce ->
    // new circuit id) which is NOT blocked by the old revocation.
    let now = 1_700_000_000u64;
    let (w, mut registry, circuit_id, _setup_env) = established(now, [0x6B; 32]);
    let ledger = RevocationLedger::new();
    registry.install_revocation_ledger(&ledger);
    let signed = valid_revocation(
        &w,
        circuit_id,
        RevocationReason::LinkFailure,
        Some(evidence("link_failure")),
        now + 10,
    );
    ledger.admit(now + 10, &signed, &registry).unwrap();

    // The replacement: fresh setup nonce over the same route.
    let setup_b = CircuitSetup::new(&w.commitment, &w.proposer, [0x6C; 32], now, 600).unwrap();
    let env_b = setup_b.sign(&w.proposer).unwrap();
    let id_b = registry.admit_setup(now, &env_b).unwrap();
    assert_ne!(id_b, circuit_id);
    assert!(!ledger.is_revoked(&id_b));
    // and the replacement can be acked + framed normally
    let path = w.commitment.verify(now).unwrap().proposal.path().to_vec();
    for (pos, want) in path.iter().enumerate() {
        let member = [&w.proposer, &w.hop1, &w.hop2]
            .into_iter()
            .find(|m| m.node_id().as_bytes() == want)
            .unwrap();
        let ack = CircuitSetupAck::new(id_b, &env_b, member, pos as u64, now, 500).unwrap();
        let env = ack.sign(member).unwrap();
        registry.admit_ack(now, &env).unwrap();
    }
    let frame = CircuitFrame::new(id_b, 1, 0, b"replacement".to_vec()).unwrap();
    registry.admit_frame(&frame).unwrap();
    // while the old circuit stays dead
    let old = CircuitFrame::new(circuit_id, 1, 0, b"x".to_vec()).unwrap();
    assert_eq!(registry.admit_frame(&old), Err(CircuitError::CircuitRevoked));
}

#[test]
fn tampered_snapshot_fails_closed() {
    let now = 1_700_000_000u64;
    let (w, registry, circuit_id, _setup_env) = established(now, [0x6D; 32]);
    let ledger = RevocationLedger::new();
    let signed = valid_revocation(
        &w,
        circuit_id,
        RevocationReason::Operator,
        Some(BTreeMap::from([(
            EVIDENCE_FAILURE_KIND.to_string(),
            EvidenceValue::Text("operator_command".into()),
        )])),
        now + 10,
    );
    ledger.admit(now + 10, &signed, &registry).unwrap();
    let snapshot = ledger.to_snapshot_bytes();
    // every single-byte mutation of a valid snapshot must fail closed
    for i in 0..snapshot.len() {
        let mut tampered = snapshot.clone();
        tampered[i] ^= 0x01;
        assert!(
            RevocationLedger::from_snapshot_bytes(&tampered).is_err(),
            "snapshot mutation at byte {i} was accepted"
        );
    }
    // truncations too
    for i in 0..snapshot.len() {
        let truncated = &snapshot[..i];
        assert!(
            RevocationLedger::from_snapshot_bytes(truncated).is_err(),
            "snapshot truncated to {i} bytes was accepted"
        );
    }
}

#[test]
fn ledger_idempotence_and_second_revoker() {
    let now = 1_700_000_000u64;
    let (w, registry, circuit_id, _setup_env) = established(now, [0x6E; 32]);
    let ledger = RevocationLedger::new();
    let signed = valid_revocation(
        &w,
        circuit_id,
        RevocationReason::LinkFailure,
        Some(evidence("link_failure")),
        now + 10,
    );
    // byte-identical replay: idempotent
    assert!(ledger.admit(now + 10, &signed, &registry).unwrap().as_str() == "first");
    assert!(ledger.admit(now + 11, &signed, &registry).unwrap().as_str() == "duplicate");
    // a same-revoker revocation with a DIFFERENT reason is still a
    // duplicate per (circuit, revoker): the first recorded wins
    let other = CircuitRevocation::new(&w.hop1, circuit_id, RevocationReason::Policy, None, now + 12)
        .unwrap();
    assert_eq!(
        ledger.admit(now + 12, &other.sign(&w.hop1).unwrap(), &registry),
        Ok(sharenet_protocol::revocation::RevocationAdmitOutcome::Duplicate)
    );
    // a second revoker (the proposer) is recorded, never un-revokes
    let second = CircuitRevocation::new(&w.proposer, circuit_id, RevocationReason::Policy, None, now + 13)
        .unwrap();
    assert!(ledger.admit(now + 13, &second.sign(&w.proposer).unwrap(), &registry).unwrap().as_str() == "additional");
    assert_eq!(ledger.revoker_count(&circuit_id), 2);
    assert!(ledger.is_revoked(&circuit_id));
    // determinism: equal logical state -> equal snapshot bytes
    let s1 = ledger.to_snapshot_bytes();
    let restored = RevocationLedger::from_snapshot_bytes(&s1).unwrap();
    assert_eq!(restored.to_snapshot_bytes(), s1);
    assert_eq!(restored.revoker_count(&circuit_id), 2);
}

#[test]
fn revoked_pending_circuit_blocks_acks() {
    // A circuit revoked BEFORE full position coverage: the gate
    // refuses the remaining acks — a revoked circuit can never become
    // established (documented R7-001 reading: the committed path exists
    // from setup admission onward).
    let now = 1_700_000_000u64;
    let w = world(now);
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, [0x6F; 32], now, 600).unwrap();
    let setup_env = setup.sign(&w.proposer).unwrap();
    let circuit_id = derive_circuit_id(w.commitment.route_id(), &[0x6F; 32]);
    let mut registry = CircuitRegistry::new();
    registry.admit_setup(now, &setup_env).unwrap();
    let ledger = RevocationLedger::new();
    registry.install_revocation_ledger(&ledger);
    let signed = valid_revocation(
        &w,
        circuit_id,
        RevocationReason::LinkFailure,
        Some(evidence("link_failure")),
        now + 1,
    );
    ledger.admit(now + 1, &signed, &registry).unwrap();
    let path = w.commitment.verify(now).unwrap().proposal.path().to_vec();
    let member = [&w.proposer, &w.hop1, &w.hop2]
        .into_iter()
        .find(|m| m.node_id().as_bytes() == &path[0])
        .unwrap();
    let ack = CircuitSetupAck::new(circuit_id, &setup_env, member, 0, now, 500).unwrap();
    let env = ack.sign(member).unwrap();
    assert_eq!(
        registry.admit_ack(now, &env),
        Err(CircuitError::CircuitRevoked)
    );
}
