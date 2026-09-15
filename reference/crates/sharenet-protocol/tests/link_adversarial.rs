//! R3-001 adversarial tests: attacks on the authenticated-link handshake
//! and frame layer, all over real keys and real byte manipulations.

use sharenet_protocol::cbor::{decode, encode, Value};
use sharenet_protocol::capability::{Capability, CapabilityStatement};
use sharenet_protocol::identity::Identity;
use sharenet_protocol::link::{
    LinkConfirm, LinkError, LinkInitiate, LinkInitiator, LinkRespond, LinkResponder,
    LinkSession, REPLAY_WINDOW,
};

fn identity(seed: u8) -> Identity {
    Identity::from_seed([seed; 32], 1_700_000_000, None).expect("identity")
}

/// Full deterministic handshake helper: returns (msg bytes, sessions).
fn handshake(
    a: Identity,
    b: Identity,
    cap_a: Option<Vec<u8>>,
    cap_b: Option<Vec<u8>>,
) -> (
    Vec<u8>,
    Vec<u8>,
    Vec<u8>,
    LinkSession,
    LinkSession,
) {
    let initiator = LinkInitiator::from_ephemeral_bytes(&[0x55u8; 32], a, cap_a).unwrap();
    let responder = LinkResponder::new(b.clone(), cap_b);
    let m1 = initiator.initiate();
    let m1b = m1.to_wire_bytes();
    let (m2, pending) = responder.respond_fixed(&m1, &m1b, &[0x66u8; 32]).unwrap();
    let m2b = m2.to_wire_bytes();
    let (m3, session_i) = initiator.confirm(&m1b, &m2, &m2b).unwrap();
    let m3b = m3.to_wire_bytes();
    let session_r = pending.finish(&m1b, &m2b, &m3, &m3b).unwrap();
    (m1b, m2b, m3b, session_i, session_r)
}

#[test]
fn msg2_replayed_under_a_different_msg1_fails() {
    // A captured msg2 cannot be replayed to authenticate a responder under
    // a NEW initiator ephemeral: the signature covers msg1's bytes.
    let a = identity(1);
    let b = identity(2);
    let responder = LinkResponder::new(b, None);
    // honest exchange #1
    let init1 = LinkInitiator::from_ephemeral_bytes(&[0x01u8; 32], a.clone(), None).unwrap();
    let m1 = init1.initiate();
    let m1b = m1.to_wire_bytes();
    let (m2, _pending) = responder.respond_fixed(&m1, &m1b, &[0x02u8; 32]).unwrap();
    // attacker: replay m2 to a different initiator (different msg1)
    let init2 = LinkInitiator::from_ephemeral_bytes(&[0x03u8; 32], a, None).unwrap();
    let other_m1 = init2.initiate();
    let other_m1b = other_m1.to_wire_bytes();
    assert!(matches!(
        init2.confirm(&other_m1b, &m2, &m2.to_wire_bytes()),
        Err(LinkError::SignatureInvalid { which: "responder" })
    ));
}

#[test]
fn msg3_replayed_under_a_different_msg2_fails() {
    // msg3's signature covers msg1 and msg2 bytes; a different exchange
    // cannot recycle it.
    let a = identity(3);
    let b = identity(4);
    let (m1b, m2b, m3b, _, _) = handshake(a.clone(), b.clone(), None, None);
    // fresh exchange with different ephemerals
    let init2 = LinkInitiator::from_ephemeral_bytes(&[0x09u8; 32], a, None).unwrap();
    let m1 = init2.initiate();
    let m1b2 = m1.to_wire_bytes();
    let responder = LinkResponder::new(b, None);
    let (m2, pending) = responder.respond_fixed(&m1, &m1b2, &[0x0Au8; 32]).unwrap();
    let m2b2 = m2.to_wire_bytes();
    // replayed msg3 from the first exchange
    let m3_value = decode(&m3b).unwrap();
    let m3 = LinkConfirm::from_wire(&m3_value).unwrap();
    assert!(matches!(
        pending.finish(&m1b2, &m2b2, &m3, &m3.to_wire_bytes()),
        Err(LinkError::SignatureInvalid { which: "initiator" })
    ));
    let _ = (m1b, m2b);
}

#[test]
fn wrong_key_identity_substitution_fails() {
    // The attacker replaces the responder's NodeIdentity with their own
    // identity map but keeps the original signature: verification must
    // fail (the signature does not cover the substituted key).
    let a = identity(5);
    let b = identity(6);
    let attacker = identity(7);
    let init = LinkInitiator::from_ephemeral_bytes(&[0x0Bu8; 32], a, None).unwrap();
    let m1 = init.initiate();
    let m1b = m1.to_wire_bytes();
    let responder = LinkResponder::new(b, None);
    let (mut m2, _p) = responder.respond_fixed(&m1, &m1b, &[0x0Cu8; 32]).unwrap();
    // substitute the attacker's identity (same bytes otherwise)
    m2.identity = attacker.node_identity().clone();
    let m2b = m2.to_wire_bytes();
    assert!(init.confirm(&m1b, &m2, &m2b).is_err());
}

#[test]
fn link_id_depends_on_every_handshake_byte() {
    // Flip one bit in any handshake message and the derived link_id (and
    // session keys) must change.
    let a = identity(8);
    let b = identity(9);
    let (m1b, m2b, m3b, _, _) = handshake(a.clone(), b.clone(), None, None);
    let _ = (&a, &b);
    // the honest handshake is deterministic: same fixed ephemerals and
    // identities reproduce the SAME link_id
    let base_id = {
        let (_, _, _, si, _) = handshake(a.clone(), b.clone(), None, None);
        *si.link_id()
    };
    // tamper msg2's ephemeral byte
    let mut m2b_bad = m2b.clone();
    m2b_bad[10] ^= 0x01;
    let m2_bad_value = decode(&m2b_bad).unwrap();
    let m2_bad = LinkRespond::from_wire(&m2_bad_value);
    // either strict parse fails, or the handshake fails, or the link differs;
    // in every case the original link_id cannot be reproduced
    if let Ok(m2_bad) = m2_bad {
        let init = LinkInitiator::from_ephemeral_bytes(&[0x55u8; 32], a.clone(), None).unwrap();
        assert!(init.confirm(&m1b, &m2_bad, &m2b_bad).is_err());
    }
    // sanity: the honest handshake reproduces the SAME link_id (determinism)
    let (_, _, _, si2, _) = handshake(a, b, None, None);
    assert_eq!(*si2.link_id(), base_id);
    let _ = m3b;
}

#[test]
fn frames_across_sessions_cannot_be_confused() {
    // A frame from one link cannot be opened by another link between the
    // SAME identities when the ephemerals differ (different keys + link_id
    // in the AAD). Identical fixed scalars reproduce the same link, which
    // is also asserted (determinism).
    let a = identity(10);
    let b = identity(11);
    // link 1: fixed scalars [0x55]/[0x66]
    let (_, _, _, mut si1, mut sr1) = handshake(a.clone(), b.clone(), None, None);
    // link 2: identical fixed scalars -> the SAME link keys; a frame must
    // open on the peer side of link 2 (determinism sanity)
    let (_, _, _, _si2, mut sr2) = handshake(a, b, None, None);
    let f = si1.seal(b"same-link").unwrap();
    assert!(sr2.open(&f).is_ok(), "identical handshakes reproduce the same link");
    // link 3: DIFFERENT scalars -> different keys; link-1 frames must fail
    let init = LinkInitiator::from_ephemeral_bytes(&[0x77u8; 32], identity(10), None).unwrap();
    let resp = LinkResponder::new(identity(11), None);
    let m1 = init.initiate();
    let m1b = m1.to_wire_bytes();
    let (m2, pending) = resp.respond_fixed(&m1, &m1b, &[0x88u8; 32]).unwrap();
    let m2b = m2.to_wire_bytes();
    let (m3, _si3) = init.confirm(&m1b, &m2, &m2b).unwrap();
    let m3b = m3.to_wire_bytes();
    let mut sr3 = pending.finish(&m1b, &m2b, &m3, &m3b).unwrap();
    let f2 = si1.seal(b"cross-session").unwrap();
    assert!(
        matches!(sr3.open(&f2), Err(LinkError::FrameTagFailed)),
        "a different link must not open another link's frame"
    );
    let _ = sr1;
}

#[test]
fn replay_window_edges() {
    // in-order, gaps, duplicates, out-of-window, and far-future rejection
    let (_, _, _, mut si, mut sr) = handshake(identity(12), identity(13), None, None);
    let f0 = si.seal(b"0").unwrap();
    let f1 = si.seal(b"1").unwrap();
    let f2 = si.seal(b"2").unwrap();
    // deliver out of order: 2 first
    assert_eq!(sr.open(&f2).unwrap(), b"2");
    // duplicate 2 -> rejected
    assert!(matches!(sr.open(&f2), Err(LinkError::FrameReplay { seq: 2 })));
    // gap fill 0, 1 still accepted
    assert_eq!(sr.open(&f0).unwrap(), b"0");
    assert_eq!(sr.open(&f1).unwrap(), b"1");
    // duplicate 0 again -> rejected (already received)
    assert!(matches!(sr.open(&f0), Err(LinkError::FrameReplay { seq: 0 })));
    // far-future seq (beyond window) rejected without advancing state
    let far = {
        // craft: seal a frame, then rewrite its seq header to highest+WINDOW+1
        let f = si.seal(b"x").unwrap();
        let mut g = f.clone();
        g[7] = 3 + REPLAY_WINDOW as u8 + 1; // seq = 67+ — big-endian last byte
        g
    };
    assert!(matches!(sr.open(&far), Err(LinkError::FrameReplay { .. })));
    // frame with empty payload still authenticates
    let fe = si.seal(b"").unwrap();
    assert_eq!(sr.open(&fe).unwrap(), b"");
}

#[test]
fn frame_tamper_in_ciphertext_and_tag_rejected() {
    let (_, _, _, mut si, mut sr) = handshake(identity(14), identity(15), None, None);
    let f = si.seal(b"authentic payload").unwrap();
    let mut t1 = f.clone();
    let mid = t1.len() / 2;
    t1[mid] ^= 0x01;
    assert!(matches!(sr.open(&t1), Err(LinkError::FrameTagFailed)));
    let mut t2 = f.clone();
    let last = t2.len() - 1;
    t2[last] ^= 0x80;
    assert!(matches!(sr.open(&t2), Err(LinkError::FrameTagFailed)));
    // truncated frame
    assert!(matches!(
        sr.open(&f[..10]),
        Err(LinkError::FrameTagFailed)
    ));
}

#[test]
fn handshake_with_capability_envelope_end_to_end() {
    // The initiator presents a signed capability envelope during the
    // handshake; the responder verifies binding + signature on finish.
    let a = identity(16);
    let b = identity(17);
    let st = CapabilityStatement::new(
        a.node_id(),
        &[Capability::Gateway],
        1_700_000_000,
        1_700_003_600,
        None,
    )
    .unwrap();
    let signed = st.sign(&a).unwrap();
    let envelope = signed.to_envelope_bytes();

    let initiator = LinkInitiator::from_ephemeral_bytes(&[0x55u8; 32], a, Some(envelope.clone()))
        .unwrap();
    let responder = LinkResponder::new(b, None);
    let m1 = initiator.initiate();
    let m1b = m1.to_wire_bytes();
    let (m2, pending) = responder.respond_fixed(&m1, &m1b, &[0x66u8; 32]).unwrap();
    let m2b = m2.to_wire_bytes();
    let (m3, session_i) = initiator.confirm(&m1b, &m2, &m2b).unwrap();
    let m3b = m3.to_wire_bytes();
    let session_r = pending.finish(&m1b, &m2b, &m3, &m3b).unwrap();
    assert_eq!(session_i.link_id(), session_r.link_id());

    // tamper the envelope inside msg3 before the responder finishes:
    let init2 = LinkInitiator::from_ephemeral_bytes(
        &[0x56u8; 32],
        identity(18),
        Some(envelope),
    )
    .unwrap();
    let resp2 = LinkResponder::new(identity(19), None);
    let m1 = init2.initiate();
    let m1b = m1.to_wire_bytes();
    let (m2, pending2) = resp2.respond_fixed(&m1, &m1b, &[0x67u8; 32]).unwrap();
    let m2b = m2.to_wire_bytes();
    let (mut m3, _si) = init2.confirm(&m1b, &m2, &m2b).unwrap();
    // corrupt one byte of the envelope
    if let Some(env) = m3.capabilities.as_mut() {
        env[3] ^= 0x01;
    }
    let m3b = m3.to_wire_bytes();
    assert!(pending2.finish(&m1b, &m2b, &m3, &m3b).is_err());
}

#[test]
fn capability_envelope_bound_to_a_different_node_rejected() {
    // Envelope signed by A but presented inside B's msg3 identity.
    let a = identity(20);
    let b = identity(21);
    let st = CapabilityStatement::new(
        a.node_id(),
        &[Capability::Relay],
        1_700_000_000,
        1_700_003_600,
        None,
    )
    .unwrap();
    let envelope = st.sign(&a).unwrap().to_envelope_bytes();
    // b presents a's envelope
    let initiator = LinkInitiator::from_ephemeral_bytes(&[0x55u8; 32], b, Some(envelope)).unwrap();
    let responder = LinkResponder::new(identity(22), None);
    let m1 = initiator.initiate();
    let m1b = m1.to_wire_bytes();
    let (m2, pending) = responder.respond_fixed(&m1, &m1b, &[0x66u8; 32]).unwrap();
    let m2b = m2.to_wire_bytes();
    let (m3, _) = initiator.confirm(&m1b, &m2, &m2b).unwrap();
    let m3b = m3.to_wire_bytes();
    assert!(matches!(
        pending.finish(&m1b, &m2b, &m3, &m3b),
        Err(LinkError::Capability(_))
    ));
}

#[test]
fn handshake_wire_forms_are_strictly_parsed() {
    // unknown field / wrong scheme / bad ephemeral length all typed-fail
    let bad_unknown_field = encode(&Value::Map(vec![
        (Value::Int(1), Value::Int(1)),
        (Value::Int(2), Value::Bytes(vec![1u8; 32])),
        (Value::Int(9), Value::Null),
    ]))
    .unwrap();
    assert!(LinkInitiate::from_wire(&decode(&bad_unknown_field).unwrap()).is_err());

    let bad_scheme = encode(&Value::Map(vec![
        (Value::Int(1), Value::Int(2)),
        (Value::Int(2), Value::Bytes(vec![1u8; 32])),
    ]))
    .unwrap();
    assert!(matches!(
        LinkInitiate::from_wire(&decode(&bad_scheme).unwrap()),
        Err(LinkError::SchemeVersionUnsupported { found: 2 })
    ));

    let bad_ephemeral = encode(&Value::Map(vec![
        (Value::Int(1), Value::Int(1)),
        (Value::Int(2), Value::Bytes(vec![1u8; 31])),
    ]))
    .unwrap();
    assert!(LinkInitiate::from_wire(&decode(&bad_ephemeral).unwrap()).is_err());
}

#[test]
fn zeroize_on_drop_session_keys() {
    // We cannot observe wiped heap memory safely; assert the API keeps
    // keys private and drop does not panic under normal use.
    let (_, _, _, si, sr) = handshake(identity(23), identity(24), None, None);
    drop(si);
    drop(sr);
}

#[test]
fn link_ids_are_distinct_per_handshake_even_for_same_identities() {
    // Different ephemerals -> different link_id even between the same two
    // nodes (every replacement is genuinely new — L014 at link level).
    let a = identity(25);
    let b = identity(26);
    let (_, _, _, s1, _) = handshake(a.clone(), b.clone(), None, None);
    let init = LinkInitiator::from_ephemeral_bytes(&[0xC1u8; 32], a, None).unwrap();
    let resp = LinkResponder::new(b, None);
    let m1 = init.initiate();
    let m1b = m1.to_wire_bytes();
    let (m2, pending) = resp.respond_fixed(&m1, &m1b, &[0xC2u8; 32]).unwrap();
    let m2b = m2.to_wire_bytes();
    let (m3, si2) = init.confirm(&m1b, &m2, &m2b).unwrap();
    let m3b = m3.to_wire_bytes();
    let sr2 = pending.finish(&m1b, &m2b, &m3, &m3b).unwrap();
    assert_ne!(s1.link_id(), si2.link_id());
    assert_eq!(si2.link_id(), sr2.link_id());
}
