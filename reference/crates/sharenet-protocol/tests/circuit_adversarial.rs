//! R4-002 adversarial verification: every circuit admission rule must
//! fail closed under attack — tampering, replays, position forgery,
//! cross-circuit confusion, terminal-destroy enforcement.

use sharenet_protocol::circuit::{
    derive_circuit_id, CircuitDestroy, CircuitError, CircuitFrame, CircuitRegistry, CircuitSetup,
    CircuitSetupAck, CIRCUIT_MAX_PAYLOAD,
};
use sharenet_protocol::identity::Identity;
use sharenet_protocol::route::{
    derive_proposal_id, RouteAcceptance, RouteCommitment, RouteProposal, SignedEnvelope,
};
use sharenet_protocol::{cbor::Value, cbor};

/// Three members: the proposer plus two hops, with a verified commitment.
struct World {
    proposer: Identity,
    hop1: Identity,
    hop2: Identity,
    commitment: RouteCommitment,
    outsider: Identity,
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
    let proposal = RouteProposal::new(&proposer, path.clone(), "live", now, 600, [0x42; 32])
        .unwrap();
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
        commitment,
        outsider,
    }
}

/// Path of the verified commitment (ascending).
fn path_of(w: &World, now: u64) -> Vec<[u8; 32]> {
    w.commitment.verify(now).unwrap().proposal.path().to_vec()
}

fn member_at<'a>(w: &'a World, position: usize, now: u64) -> &'a Identity {
    let path = path_of(w, now);
    let want = path[position];
    for m in [&w.proposer, &w.hop1, &w.hop2] {
        if m.node_id().as_bytes() == &want {
            return m;
        }
    }
    unreachable!("member at position");
}

/// A fully established circuit (setup admitted, all positions acked).
fn established(now: u64, nonce: [u8; 32]) -> (World, CircuitRegistry, [u8; 32], SignedEnvelope) {
    let w = world(now);
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, nonce, now, 600).unwrap();
    let setup_env = setup.sign(&w.proposer).unwrap();
    let circuit_id = derive_circuit_id(w.commitment.route_id(), &nonce);
    let mut registry = CircuitRegistry::new();
    registry.admit_setup(now, &setup_env).unwrap();
    let path = path_of(&w, now);
    for pos in 0..path.len() {
        let member = member_at(&w, pos, now);
        let ack = CircuitSetupAck::new(circuit_id, &setup_env, member, pos as u64, now, 500)
            .unwrap();
        let env = ack.sign(member).unwrap();
        registry.admit_ack(now, &env).unwrap();
    }
    (w, registry, circuit_id, setup_env)
}

#[test]
fn tampered_setup_signature_rejected() {
    let now = 1_700_000_000u64;
    let w = world(now);
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, [0x51; 32], now, 600).unwrap();
    let env = setup.sign(&w.proposer).unwrap();
    let mut tampered = env.to_envelope_bytes();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01; // flip one signature bit
    let tampered_env = SignedEnvelope::from_envelope_bytes(&tampered).unwrap();
    let mut registry = CircuitRegistry::new();
    assert_eq!(
        registry.admit_setup(now, &tampered_env),
        Err(CircuitError::SetupSignatureInvalid)
    );
}

#[test]
fn setup_with_tampered_commitment_rejected() {
    let now = 1_700_000_000u64;
    let w = world(now);
    // Corrupt the embedded commitment bytes, then sign the setup with
    // the (still legitimate) initiator: the R3-004 verification inside
    // admission must refuse the corrupted commitment.
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, [0x52; 32], now, 600).unwrap();
    let mut wire = setup.to_wire();
    if let Value::Map(ref mut entries) = wire {
        for (k, v) in entries.iter_mut() {
            if let Value::Int(2) = k {
                if let Value::Bytes(b) = v {
                    b[10] ^= 0xFF;
                }
            }
        }
    }
    let bytes = cbor::encode(&wire).unwrap();
    let env = SignedEnvelope::new(bytes.clone(), w.proposer.sign_detached(&bytes));
    let mut registry = CircuitRegistry::new();
    // The failure is the wrapped route error (commitment verification).
    assert!(matches!(
        registry.admit_setup(now, &env),
        Err(CircuitError::RouteError(_))
    ));
}

#[test]
fn setup_nonce_single_use_enforced() {
    let now = 1_700_000_000u64;
    let w = world(now);
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, [0x53; 32], now, 600).unwrap();
    let env = setup.sign(&w.proposer).unwrap();
    let mut registry = CircuitRegistry::new();
    registry.admit_setup(now, &env).unwrap();
    // Byte-identical replay: the nonce is consumed.
    assert_eq!(
        registry.admit_setup(now, &env),
        Err(CircuitError::SetupNonceReused)
    );
    // The same envelope re-admitted later (still fresh, nonce consumed).
    assert_eq!(
        registry.admit_setup(now + 100, &env),
        Err(CircuitError::SetupNonceReused)
    );
    // Even re-signed fresh bytes with the SAME nonce are refused.
    let setup2 = CircuitSetup::new(&w.commitment, &w.proposer, [0x53; 32], now + 10, 600)
        .unwrap();
    let env2 = setup2.sign(&w.proposer).unwrap();
    assert_eq!(
        registry.admit_setup(now + 20, &env2),
        Err(CircuitError::SetupNonceReused)
    );
}

#[test]
fn setup_freshness_enforced() {
    let now = 1_700_000_000u64;
    let w = world(now);
    // A setup window SHORTER than the commitment's windows: the setup's
    // own freshness is then the failing check at the edges.
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, [0x54; 32], now, 100).unwrap();
    let env = setup.sign(&w.proposer).unwrap();
    let mut registry = CircuitRegistry::new();
    // Before issuance the embedded commitment's proposal is also not yet
    // valid — either way admission fails closed (the route check runs
    // first in the admission pipeline).
    assert!(registry.admit_setup(now - 1, &env).is_err());
    // The setup expires at now+100 while the commitment is fresh until
    // now+600: the setup's own freshness is the failing check.
    assert_eq!(
        registry.admit_setup(now + 100, &env),
        Err(CircuitError::SetupExpired)
    );
    // The acceptance freshness inside the commitment also gates admission.
    assert!(registry.admit_setup(now + 5000, &env).is_err());
    registry.admit_setup(now, &env).unwrap();
}

#[test]
fn ack_position_forgery_rejected() {
    let now = 1_700_000_000u64;
    let w = world(now);
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, [0x55; 32], now, 600).unwrap();
    let setup_env = setup.sign(&w.proposer).unwrap();
    let circuit_id = derive_circuit_id(w.commitment.route_id(), &[0x55; 32]);
    let mut registry = CircuitRegistry::new();
    registry.admit_setup(now, &setup_env).unwrap();

    // A member acks a position that is NOT theirs.
    let path = path_of(&w, now);
    let wrong = CircuitSetupAck::new(circuit_id, &setup_env, &w.hop1, 2, now, 500).unwrap();
    let env = wrong.sign(&w.hop1).unwrap();
    assert_eq!(
        registry.admit_ack(now, &env),
        Err(CircuitError::AckIdentityMismatch { position: 2 })
    );

    // An OUTSIDER acks any position: identity mismatch (and it is not
    // on the path at all).
    let forged = CircuitSetupAck::new(circuit_id, &setup_env, &w.outsider, 0, now, 500).unwrap();
    let env = forged.sign(&w.outsider).unwrap();
    assert_eq!(
        registry.admit_ack(now, &env),
        Err(CircuitError::AckIdentityMismatch { position: 0 })
    );

    // A position beyond the path.
    let beyond = CircuitSetupAck::new(
        circuit_id,
        &setup_env,
        &w.hop1,
        path.len() as u64,
        now,
        500,
    )
    .unwrap();
    let env = beyond.sign(&w.hop1).unwrap();
    assert!(matches!(
        registry.admit_ack(now, &env),
        Err(CircuitError::PositionOutOfRange { .. })
    ));
}

#[test]
fn ack_digest_and_double_take_rejected() {
    let now = 1_700_000_000u64;
    let w = world(now);
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, [0x56; 32], now, 600).unwrap();
    let setup_env = setup.sign(&w.proposer).unwrap();
    let circuit_id = derive_circuit_id(w.commitment.route_id(), &[0x56; 32]);
    let mut registry = CircuitRegistry::new();
    registry.admit_setup(now, &setup_env).unwrap();
    let member = member_at(&w, 0, now);

    // First ack succeeds.
    let ack = CircuitSetupAck::new(circuit_id, &setup_env, member, 0, now, 500).unwrap();
    let env = ack.sign(member).unwrap();
    registry.admit_ack(now, &env).unwrap();

    // Same position acked again (even byte-identical): refused.
    assert_eq!(
        registry.admit_ack(now, &env),
        Err(CircuitError::AckPositionAlreadyTaken { position: 0 })
    );

    // An ack bound to a DIFFERENT setup's digest is refused.
    let other_setup =
        CircuitSetup::new(&w.commitment, &w.proposer, [0x57; 32], now, 600).unwrap();
    let other_env = other_setup.sign(&w.proposer).unwrap();
    let confused = CircuitSetupAck::new(circuit_id, &other_env, member, 1, now, 500).unwrap();
    let env2 = confused.sign(member).unwrap();
    assert_eq!(
        registry.admit_ack(now, &env2),
        Err(CircuitError::SetupDigestMismatch)
    );

    // An ack for an unknown circuit.
    let unknown = CircuitSetupAck::new([0xEE; 32], &setup_env, member, 1, now, 500).unwrap();
    let env3 = unknown.sign(member).unwrap();
    assert_eq!(
        registry.admit_ack(now, &env3),
        Err(CircuitError::CircuitUnknown)
    );
}

#[test]
fn ack_outliving_setup_rejected() {
    let now = 1_700_000_000u64;
    let w = world(now);
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, [0x58; 32], now, 600).unwrap();
    let setup_env = setup.sign(&w.proposer).unwrap();
    let circuit_id = derive_circuit_id(w.commitment.route_id(), &[0x58; 32]);
    let mut registry = CircuitRegistry::new();
    registry.admit_setup(now, &setup_env).unwrap();
    let member = member_at(&w, 0, now);
    // accepted_at == setup expiry: cannot outlive the setup.
    let late = CircuitSetupAck::new(
        circuit_id,
        &setup_env,
        member,
        0,
        now + 600,
        500,
    )
    .unwrap();
    let env = late.sign(member).unwrap();
    assert_eq!(
        registry.admit_ack(now, &env),
        Err(CircuitError::AckOutlivesSetup)
    );
    // Expired ack.
    let expired = CircuitSetupAck::new(circuit_id, &setup_env, member, 0, now - 600, 100).unwrap();
    let env2 = expired.sign(member).unwrap();
    assert_eq!(
        registry.admit_ack(now, &env2),
        Err(CircuitError::AckExpired)
    );
}

#[test]
fn frame_replay_and_cross_circuit_confusion() {
    let now = 1_700_000_000u64;
    let (w, mut registry, circuit_id, _setup_env) =
        established(now, [0x59; 32]);
    // Another established circuit with a different nonce.
    let (w2, registry2, circuit_id2, _setup2) = established(now, [0x5A; 32]);
    let _ = (w2, registry2);

    let f0 = CircuitFrame::new(circuit_id, 1, 0, b"data-0".to_vec()).unwrap();
    registry.admit_frame(&f0).unwrap();
    // Replay.
    assert_eq!(
        registry.admit_frame(&f0),
        Err(CircuitError::FrameSeqOutOfOrder {
            direction: 1,
            expected: 1,
            found: 0
        })
    );
    // Gap.
    let f2 = CircuitFrame::new(circuit_id, 1, 2, b"data-2".to_vec()).unwrap();
    assert_eq!(
        registry.admit_frame(&f2),
        Err(CircuitError::FrameSeqOutOfOrder {
            direction: 1,
            expected: 1,
            found: 2
        })
    );
    // Cross-circuit confusion: A's frame against B's id is unknown.
    let confused = CircuitFrame::new(circuit_id2, 1, 1, b"borrowed".to_vec()).unwrap();
    assert_eq!(
        registry.admit_frame(&confused),
        Err(CircuitError::CircuitUnknown)
    );
    // Unknown circuit entirely.
    let unknown = CircuitFrame::new([0xEE; 32], 1, 0, b"x".to_vec()).unwrap();
    assert_eq!(
        registry.admit_frame(&unknown),
        Err(CircuitError::CircuitUnknown)
    );
    let _ = w;
}

#[test]
fn frames_before_establishment_rejected() {
    let now = 1_700_000_000u64;
    let w = world(now);
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, [0x5B; 32], now, 600).unwrap();
    let setup_env = setup.sign(&w.proposer).unwrap();
    let circuit_id = derive_circuit_id(w.commitment.route_id(), &[0x5B; 32]);
    let mut registry = CircuitRegistry::new();
    registry.admit_setup(now, &setup_env).unwrap();
    let early = CircuitFrame::new(circuit_id, 1, 0, b"early".to_vec()).unwrap();
    assert!(matches!(
        registry.admit_frame(&early),
        Err(CircuitError::CircuitNotEstablished { .. })
    ));
}

#[test]
fn destroy_is_terminal_and_membership_gated() {
    let now = 1_700_000_000u64;
    let (w, mut registry, circuit_id, _setup_env) = established(now, [0x5C; 32]);

    // An outsider cannot destroy.
    let by_outsider = CircuitDestroy::new(circuit_id, &w.outsider, "policy", now + 10).unwrap();
    let env = by_outsider.sign(&w.outsider).unwrap();
    assert_eq!(
        registry.admit_destroy(&env),
        Err(CircuitError::DestroySenderNotOnPath)
    );

    // A member destroys; the circuit is terminal forever.
    let destroy = CircuitDestroy::new(circuit_id, &w.hop2, "link_failure", now + 20).unwrap();
    let env = destroy.sign(&w.hop2).unwrap();
    registry.admit_destroy(&env).unwrap();

    // Frames after destroy.
    let late = CircuitFrame::new(circuit_id, 1, 0, b"late".to_vec()).unwrap();
    assert_eq!(
        registry.admit_frame(&late),
        Err(CircuitError::CircuitDestroyed)
    );

    // Acks after destroy.
    let setup_env2 = {
        let setup = CircuitSetup::new(&w.commitment, &w.proposer, [0x5D; 32], now, 600).unwrap();
        setup.sign(&w.proposer).unwrap()
    };
    let ack = CircuitSetupAck::new(circuit_id, &setup_env2, &w.hop1, 1, now, 500).unwrap();
    let env2 = ack.sign(&w.hop1).unwrap();
    assert_eq!(
        registry.admit_ack(now, &env2),
        Err(CircuitError::CircuitDestroyed)
    );

    // Idempotent duplicate destroy.
    registry.admit_destroy(&env).unwrap();

    // A replacement circuit needs a FRESH nonce (old nonce consumed).
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, [0x5C; 32], now, 600).unwrap();
    let env3 = setup.sign(&w.proposer).unwrap();
    assert_eq!(
        registry.admit_setup(now, &env3),
        Err(CircuitError::SetupNonceReused)
    );
}

#[test]
fn frame_bounds_enforced() {
    let now = 1_700_000_000u64;
    let (_w, _registry, circuit_id, _setup_env) = established(now, [0x5E; 32]);
    assert_eq!(
        CircuitFrame::new(circuit_id, 3, 0, b"x".to_vec()),
        Err(CircuitError::DirectionUnknown { found: 3 })
    );
    assert_eq!(
        CircuitFrame::new(circuit_id, 0, 0, b"x".to_vec()),
        Err(CircuitError::DirectionUnknown { found: 0 })
    );
    assert_eq!(
        CircuitFrame::new(circuit_id, 1, 0, Vec::new()),
        Err(CircuitError::PayloadEmpty)
    );
    assert_eq!(
        CircuitFrame::new(circuit_id, 1, 0, vec![0u8; CIRCUIT_MAX_PAYLOAD + 1]),
        Err(CircuitError::PayloadTooLarge {
            len: CIRCUIT_MAX_PAYLOAD + 1,
            max: CIRCUIT_MAX_PAYLOAD
        })
    );
}

#[test]
fn strict_wire_parsing_rejects() {
    let now = 1_700_000_000u64;
    let w = world(now);
    let setup = CircuitSetup::new(&w.commitment, &w.proposer, [0x5F; 32], now, 600).unwrap();
    let bytes = setup.to_wire_bytes();
    let parsed = CircuitSetup::from_wire_bytes(&bytes).unwrap();
    assert_eq!(parsed, setup);

    // Truncated bytes.
    assert!(CircuitSetup::from_wire_bytes(&bytes[..bytes.len() - 4]).is_err());
    // Trailing garbage.
    let mut trailing = bytes.clone();
    trailing.extend_from_slice(&[0x00]);
    assert!(CircuitSetup::from_wire_bytes(&trailing).is_err());
    // Not a map.
    assert!(CircuitSetup::from_wire_bytes(&[0x01]).is_err());

    // Hand-built wires with every strict violation.
    let hand = |entries: Vec<(Value, Value)>| cbor::encode(&Value::Map(entries)).unwrap();
    let commit = Value::Bytes(w.commitment.to_wire_bytes());
    let id = w.proposer.node_identity().to_wire();
    let good = vec![
        (Value::Int(1), Value::Int(1)),
        (Value::Int(2), commit.clone()),
        (Value::Int(3), Value::Bytes(vec![0x5F; 32])),
        (Value::Int(4), id.clone()),
        (Value::Int(5), Value::Int(now as i64)),
        (Value::Int(6), Value::Int((now + 600) as i64)),
    ];
    // Unknown field.
    let mut bad = good.clone();
    bad.push((Value::Int(99), Value::Null));
    assert_eq!(
        CircuitSetup::from_wire_bytes(&hand(bad)),
        Err(CircuitError::UnknownField { key: 99 })
    );
    // Duplicate fields are UNREPRESENTABLE through the canonical
    // encoder (it rejects duplicate map keys at encode time), so the
    // parser's DuplicateField defense is depth-in-depth for bytes that
    // bypass this encoder — nothing to hand-build here.
    // Missing field.
    let missing: Vec<_> = good.iter().filter(|(k, _)| k != &Value::Int(4)).cloned().collect();
    assert_eq!(
        CircuitSetup::from_wire_bytes(&hand(missing)),
        Err(CircuitError::MissingField { key: 4 })
    );
    // Wrong type.
    let mut wrong_type = good.clone();
    wrong_type[2].1 = Value::Text("not-bytes".into());
    assert_eq!(
        CircuitSetup::from_wire_bytes(&hand(wrong_type)),
        Err(CircuitError::FieldNotExpectedType { key: 3 })
    );
    // Wrong scheme version.
    let mut bad_scheme = good.clone();
    bad_scheme[0].1 = Value::Int(2);
    assert_eq!(
        CircuitSetup::from_wire_bytes(&hand(bad_scheme)),
        Err(CircuitError::SchemeVersionUnsupported { found: 2 })
    );
    // Window exceeded.
    let mut bad_window = good.clone();
    bad_window[5].1 = Value::Int((now + 3601) as i64);
    assert_eq!(
        CircuitSetup::from_wire_bytes(&hand(bad_window)),
        Err(CircuitError::SetupWindowExceeded)
    );
    // Bad destroy reason.
    let destroy_wire = hand(vec![
        (Value::Int(1), Value::Int(1)),
        (Value::Int(2), Value::Bytes(vec![0u8; 32])),
        (Value::Int(3), id.clone()),
        (Value::Int(4), Value::Text("no-reason".into())),
        (Value::Int(5), Value::Int(now as i64)),
    ]);
    assert_eq!(
        CircuitDestroy::from_wire_bytes(&destroy_wire),
        Err(CircuitError::ReasonUnknown {
            found: "no-reason".into()
        })
    );
}
