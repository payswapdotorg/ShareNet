//! R6-004 "adversarial" verification: the receiving edge refuses
//! hostile, stale, lying and replayed offers — fail-closed, typed, and
//! with nothing stored on the back of any refusal. What is proven, per
//! the work item's verify level:
//!
//! - **expired-offered** — a bundle already dead at the offer clock is
//!   refused typed, whatever its priority;
//! - **expired-during-negotiation** — the clock advancing between the
//!   decision and the application (and between chunks) re-evaluates the
//!   TTL: no stale verdict ever licenses admission;
//! - **already-held / already-complete** — re-offers are typed
//!   duplicates carrying the FIRST admission's metadata (never a TTL
//!   extension, never a priority upgrade, never a second record);
//! - **slot-conflict / wrong-hash / wrong-length** — the integrity law
//!   wins over dedup: a held slot re-delivered with different bytes is
//!   an integrity refusal, never a duplicate; an unverifiable chunk is
//!   never stored;
//! - **lie-count** — claimed ids, claimed classes and claimed
//!   replication state never take effect (the id is re-derived, the
//!   class is frozen, replays move no counter);
//! - **priority-inversion attempts** — TTL gates BEFORE priority: an
//!   expired `live` offer never outranks a fresh `dtn` one at the
//!   receiving edge;
//! - **capacity** — the carry order decides which accepted offer fits
//!   the last bundle slot;
//! - **replayed offers** — idempotent, exactly, from the store's own
//!   state.

mod common;

use common::{fixture, offer, peer, policy, seed_bundle, NOW};
use sharenet_dtn::{DtnStoreImage, ServicePriority, MAX_BUNDLES};
use sharenet_propagation::{
    ChunkOffer, ChunkRefusal, ChunkVerdict, ManifestRefusal, ManifestVerdict, PropagationPolicy,
    PropagationParams,
};
use sharenet_protocol::ContentManifest;

/// An offer of a bundle already dead at the decision clock is refused
/// typed — and nothing is stored.
#[test]
fn expired_offer_is_refused_whatever_the_priority() {
    let (manifest, _) = fixture(2, 0x10);
    let bytes = manifest.to_wire_bytes();
    let store = DtnStoreImage::new();
    let peer = peer();
    let policy = policy();
    // Exactly at the bound: expired (now >= expires is the law).
    let at_bound = ManifestVerdict::Refused(ManifestRefusal::OfferExpired {
        now_unix: NOW,
        expires_at_unix: NOW,
    });
    assert_eq!(
        policy.decide_manifest(&offer(&bytes, &peer, NOW), &store, NOW),
        at_bound
    );
    // A `live` priority does not rescue it (TTL gates BEFORE priority).
    let live = sharenet_propagation::ManifestOffer {
        priority_name: "live",
        ..offer(&bytes, &peer, NOW)
    };
    assert_eq!(
        policy.decide_manifest(&live, &store, NOW),
        at_bound,
        "no priority rescues an expired offer"
    );
    assert_eq!(store.bundle_count(), 0, "nothing stored on refusal");
    assert_eq!(store.evidence_count(), 0);
}

/// The clock advancing between the decision and the application
/// re-evaluates the TTL — a verdict a moment ago never licenses
/// admission now (the decision is re-run at the apply clock).
#[test]
fn expiry_during_negotiation_refuses_admission() {
    let (manifest, chunks) = fixture(2, 0x21);
    let bytes = manifest.to_wire_bytes();
    let mut store = DtnStoreImage::new();
    let peer = peer();
    let policy = policy();
    // Decided fresh at NOW (expires NOW + 100) ...
    assert!(
        policy
            .decide_manifest(&offer(&bytes, &peer, NOW + 100), &store, NOW)
            .is_accept()
    );
    // ... but applied a moment later, past the bound: refused, nothing
    // admitted (take_custody re-decides at ITS clock).
    let verdict = policy
        .take_custody(&mut store, &offer(&bytes, &peer, NOW + 100), NOW + 100)
        .expect("apply path");
    assert_eq!(
        verdict,
        ManifestVerdict::Refused(ManifestRefusal::OfferExpired {
            now_unix: NOW + 100,
            expires_at_unix: NOW + 100,
        })
    );
    assert_eq!(store.bundle_count(), 0);
    // And mid-stream: the manifest is admitted, a chunk lands at +99,
    // and the NEXT chunk (past the bound) is refused — expired bundles
    // take no new chunks (the R6-003 law at the receiving edge).
    let id = manifest.content_id();
    assert!(
        policy
            .take_custody(&mut store, &offer(&bytes, &peer, NOW + 100), NOW)
            .expect("apply path")
            .is_accept()
    );
    assert!(
        policy
            .receive_chunk(&mut store, &ChunkOffer::new(id, 0, &chunks[0]), NOW + 99)
            .expect("apply path")
            .is_accept()
    );
    assert_eq!(
        policy.decide_chunk(&ChunkOffer::new(id, 1, &chunks[1]), &store, NOW + 100),
        ChunkVerdict::Refused(ChunkRefusal::BundleExpired {
            now_unix: NOW + 100,
            expires_at_unix: NOW + 100,
        })
    );
    // The refused chunk was never stored.
    assert!(!store.holds_slot(&id, 1).expect("held bundle"));
}

/// A re-offer of held content carries the FIRST admission's metadata —
/// a longer claimed TTL, a higher claimed class and a bigger claimed
/// target all change nothing.
#[test]
fn reoffer_never_extends_ttl_or_upgrades_priority() {
    let (manifest, _) = fixture(3, 0x30);
    let bytes = manifest.to_wire_bytes();
    let mut store = DtnStoreImage::new();
    let peer = peer();
    let policy = policy();
    let id = manifest.content_id();
    assert!(
        policy
            .take_custody(&mut store, &offer(&bytes, &peer, NOW + 1_000), NOW)
            .expect("apply path")
            .is_accept()
    );
    // The lying re-offer: live class, double the TTL, a huge target.
    let lying = sharenet_propagation::ManifestOffer {
        priority_name: "live",
        expires_at_unix: NOW + 1_000_000,
        replication_target: 999,
        ..offer(&bytes, &peer, NOW + 1_000)
    };
    let verdict = policy.decide_manifest(&lying, &store, NOW);
    assert_eq!(verdict.name(), "already_held");
    let ManifestVerdict::AlreadyHeld(held) = verdict else {
        unreachable!("checked name");
    };
    assert_eq!(held.content_id(), &id);
    // The FIRST admission's metadata, not the re-offer's claims.
    assert_eq!(held.summary().priority(), ServicePriority::Dtn);
    assert_eq!(held.summary().expires_at_unix(), NOW + 1_000);
    assert_eq!(held.summary().replication_target(), 2);
    // The store agrees (the policy only reported its state).
    let summary = store.summary(&id).expect("held").clone();
    assert_eq!(summary.priority(), ServicePriority::Dtn);
    assert_eq!(summary.expires_at_unix(), NOW + 1_000);
    assert_eq!(summary.replication_target(), 2);
}

/// A complete bundle's re-offer is `already_complete`; a delivered
/// bundle's re-offer is the same duplicate with its terminal status.
#[test]
fn complete_and_delivered_reoffers_are_duplicates() {
    let (manifest, chunks) = fixture(2, 0x40);
    let bytes = manifest.to_wire_bytes();
    let mut store = DtnStoreImage::new();
    let peer = peer();
    let policy = policy();
    let id = manifest.content_id();
    seed_bundle(&mut store, &manifest, &chunks, NOW + 1_000);
    let verdict = policy.decide_manifest(&offer(&bytes, &peer, NOW + 1_000), &store, NOW);
    assert_eq!(verdict.name(), "already_complete");
    let ManifestVerdict::AlreadyComplete(held) = verdict else {
        unreachable!("checked name");
    };
    assert_eq!(held.status().as_str(), "live");
    assert!(held.summary().complete());
    // Terminal delivery changes the status, never the duplicate shape.
    store
        .mark_delivered(&id, NOW + 5, &peer)
        .expect("mark delivered");
    let delivered = policy.decide_manifest(&offer(&bytes, &peer, NOW + 1_000), &store, NOW);
    assert_eq!(delivered.name(), "already_complete");
    let ManifestVerdict::AlreadyComplete(held) = delivered else {
        unreachable!("checked name");
    };
    assert_eq!(held.status().as_str(), "delivered");
}

/// The replication-policy decision, applied adversarially: an
/// at-target held bundle is still a DUPLICATE (not a refusal) and its
/// missing chunks still complete — replication gates FORWARDING, not
/// receiving.
#[test]
fn at_target_held_bundle_still_duplicates_and_completes() {
    let (manifest, chunks) = fixture(3, 0x50);
    let bytes = manifest.to_wire_bytes();
    let mut store = DtnStoreImage::new();
    let peer = peer();
    let policy = policy();
    let id = manifest.content_id();
    // Held with 2 of 3 chunks and a replication target of 2, both
    // already spent (at target: ReplicationExhausted).
    seed_bundle(&mut store, &manifest, &chunks[..2], NOW + 1_000);
    store
        .note_forwarded(&id, NOW + 1, &peer)
        .expect("forward 1");
    store.note_forwarded(&id, NOW + 2, &peer).expect("forward 2");
    // The re-offer is a duplicate carrying the exhausted status.
    let verdict = policy.decide_manifest(&offer(&bytes, &peer, NOW + 1_000), &store, NOW);
    assert_eq!(verdict.name(), "already_held");
    let ManifestVerdict::AlreadyHeld(held) = verdict else {
        unreachable!("checked name");
    };
    assert_eq!(held.status().as_str(), "replication_exhausted");
    // The missing chunk still completes the held custody.
    assert!(
        policy
            .receive_chunk(&mut store, &ChunkOffer::new(id, 2, &chunks[2]), NOW)
            .expect("apply path")
            .is_accept()
    );
    assert!(store.summary(&id).expect("held").complete());
}

/// A held slot re-delivered with DIFFERENT bytes is an integrity
/// refusal — the duplicate verdict certifies verified byte-identity,
/// never a claim.
#[test]
fn slot_conflict_is_an_integrity_refusal() {
    let (manifest, chunks) = fixture(3, 0x60);
    let mut store = DtnStoreImage::new();
    let policy = policy();
    let id = manifest.content_id();
    seed_bundle(&mut store, &manifest, &chunks, NOW + 1_000);
    // Same length, different bytes: the hash law refuses.
    let mut forged = chunks[1].clone();
    forged[0] ^= 0xff;
    assert_eq!(
        policy.decide_chunk(&ChunkOffer::new(id, 1, &forged), &store, NOW),
        ChunkVerdict::Refused(ChunkRefusal::ChunkHashMismatch { slot: 1 })
    );
    // A DIFFERENT slot's valid bytes offered into slot 1: same law
    // (the slot commitment is per-slot — cross-slot confusion refused).
    assert_eq!(
        policy.decide_chunk(&ChunkOffer::new(id, 1, &chunks[2]), &store, NOW),
        ChunkVerdict::Refused(ChunkRefusal::ChunkHashMismatch { slot: 1 })
    );
    // Wrong length: the length law refuses BEFORE any hashing.
    assert_eq!(
        policy.decide_chunk(&ChunkOffer::new(id, 1, b"x"), &store, NOW),
        ChunkVerdict::Refused(ChunkRefusal::ChunkLengthWrong {
            slot: 1,
            found: 1,
            expected: 8,
        })
    );
    // The honest bytes are still a duplicate afterwards.
    assert_eq!(
        policy.decide_chunk(&ChunkOffer::new(id, 1, &chunks[1]), &store, NOW),
        ChunkVerdict::Duplicate { slot: 1 }
    );
}

/// Wrong-hash and wrong-length chunks for a FRESH slot are refused and
/// never stored (integrity before storage, always).
#[test]
fn wrong_hash_and_length_chunks_are_never_stored() {
    let (manifest, chunks) = fixture(2, 0x70);
    let mut store = DtnStoreImage::new();
    let policy = policy();
    let id = manifest.content_id();
    seed_bundle(&mut store, &manifest, &[], NOW + 1_000);
    let mut wrong_hash = chunks[0].clone();
    wrong_hash[7] ^= 0x01;
    assert_eq!(
        policy.decide_chunk(&ChunkOffer::new(id, 0, &wrong_hash), &store, NOW),
        ChunkVerdict::Refused(ChunkRefusal::ChunkHashMismatch { slot: 0 })
    );
    assert_eq!(
        policy.decide_chunk(&ChunkOffer::new(id, 0, b"much-too-long"), &store, NOW),
        ChunkVerdict::Refused(ChunkRefusal::ChunkLengthWrong {
            slot: 0,
            found: 13,
            expected: 8,
        })
    );
    assert!(!store.holds_slot(&id, 0).expect("held bundle"));
}

/// Lie-count: replays and claims move no counter. Five re-offers of the
/// manifest (with bigger claimed targets each time) leave the
/// replication count at 0 and the evidence log at exactly one
/// `received` record.
#[test]
fn replays_and_claims_move_no_counter() {
    let (manifest, chunks) = fixture(2, 0x80);
    let bytes = manifest.to_wire_bytes();
    let mut store = DtnStoreImage::new();
    let peer = peer();
    let policy = policy();
    let id = manifest.content_id();
    assert!(
        policy
            .take_custody(&mut store, &offer(&bytes, &peer, NOW + 1_000), NOW)
            .expect("apply path")
            .is_accept()
    );
    for i in 1..=5u32 {
        let replay = sharenet_propagation::ManifestOffer {
            replication_target: 100 + i,
            ..offer(&bytes, &peer, NOW + 1_000)
        };
        let verdict = policy
            .take_custody(&mut store, &replay, NOW)
            .expect("apply path");
        assert_eq!(verdict.name(), "already_held");
        let chunk = policy
            .receive_chunk(&mut store, &ChunkOffer::new(id, 1, &chunks[1]), NOW)
            .expect("apply path");
        // The first receipt completes the slot; every replay after it
        // is a verified duplicate.
        let expected = if i == 1 { "accept" } else { "duplicate" };
        assert_eq!(chunk.name(), expected);
    }
    let summary = store.summary(&id).expect("held");
    assert_eq!(summary.replication_count(), 0, "no claim moves the count");
    assert_eq!(summary.replication_target(), 2);
    assert_eq!(store.evidence_count(), 1, "one custody event, once");
    assert_eq!(store.evidence()[0].kind().as_str(), "received");
}

/// The priority-inversion attempt: an EXPIRED `live` offer must not
/// outrank a fresh `dtn` one — TTL gates BEFORE priority, so the
/// expired offer never even reaches the ingest order while the fresh
/// one is accepted.
#[test]
fn expired_live_never_outranks_fresh_dtn() {
    let (live_manifest, _) = fixture(2, 0x91);
    let (dtn_manifest, _) = fixture(2, 0x92);
    let live_bytes = live_manifest.to_wire_bytes();
    let dtn_bytes = dtn_manifest.to_wire_bytes();
    let store = DtnStoreImage::new();
    let peer = peer();
    let policy = policy();
    // The expired live offer: refused (never admitted, never ranked).
    let expired_live = sharenet_propagation::ManifestOffer {
        priority_name: "live",
        ..offer(&live_bytes, &peer, NOW)
    };
    assert_eq!(
        policy.decide_manifest(&expired_live, &store, NOW),
        ManifestVerdict::Refused(ManifestRefusal::OfferExpired {
            now_unix: NOW,
            expires_at_unix: NOW,
        })
    );
    // The fresh dtn offer: accepted.
    let fresh_dtn = offer(&dtn_bytes, &peer, NOW + 10_000);
    let ManifestVerdict::Accept(dtn_anchor) =
        policy.decide_manifest(&fresh_dtn, &store, NOW)
    else {
        panic!("fresh dtn offer must be accepted");
    };
    // The ingest order therefore contains ONLY the fresh dtn anchor:
    // the expired live one is not there to outrank anything.
    let mut anchors = vec![dtn_anchor.clone()];
    policy.order_for_ingest(&mut anchors);
    assert_eq!(anchors.len(), 1);
    assert_eq!(anchors[0].priority(), ServicePriority::Dtn);
    // And among FRESH offers the live class does come first — the
    // order law is priority-gated only for offers that passed TTL.
    let live_fresh = sharenet_propagation::ManifestOffer {
        priority_name: "live",
        ..offer(&live_bytes, &peer, NOW + 20_000)
    };
    let ManifestVerdict::Accept(live_anchor) =
        policy.decide_manifest(&live_fresh, &store, NOW) else {
        panic!("fresh live offer must be accepted");
    };
    let mut both = vec![dtn_anchor, live_anchor];
    policy.order_for_ingest(&mut both);
    assert_eq!(both[0].priority(), ServicePriority::Live);
    assert_eq!(both[1].priority(), ServicePriority::Dtn);
}

/// Capacity: with one bundle slot left, the carry order decides which
/// accepted offer fits — the higher-precedence one is admitted and the
/// other is then refused `store_full`.
#[test]
fn capacity_ingests_in_carry_order() {
    let mut store = DtnStoreImage::new();
    // Fill to one below the cap with distinct bundles.
    for i in 0..(MAX_BUNDLES - 1) {
        let content = format!("filler-{i}");
        let (manifest, _) =
            ContentManifest::chunk(content.as_bytes(), 8, "app/test", None, NOW)
                .expect("valid content");
        store
            .admit_manifest(&manifest, ServicePriority::Dtn, NOW, NOW + 10_000, 1)
            .expect("room left");
    }
    assert_eq!(store.bundle_count(), MAX_BUNDLES - 1);
    let (urgent, _) = fixture(2, 0xa1); // dtn, expires sooner
    let (lax, _) = fixture(2, 0xa2); // live, expires later
    let urgent_bytes = urgent.to_wire_bytes();
    let lax_bytes = lax.to_wire_bytes();
    let peer = peer();
    let policy = policy();
    let ManifestVerdict::Accept(urgent_anchor) = policy.decide_manifest(
        &offer(&urgent_bytes, &peer, NOW + 5_000),
        &store,
        NOW,
    ) else {
        panic!("urgent must be acceptable");
    };
    let lax_offer = sharenet_propagation::ManifestOffer {
        priority_name: "live",
        ..offer(&lax_bytes, &peer, NOW + 50_000)
    };
    let ManifestVerdict::Accept(lax_anchor) =
        policy.decide_manifest(&lax_offer, &store, NOW) else {
        panic!("lax must be acceptable");
    };
    // Carry order: live class first (rank beats expiry urgency).
    let mut batch = vec![urgent_anchor, lax_anchor];
    policy.order_for_ingest(&mut batch);
    assert_eq!(batch[0].priority(), ServicePriority::Live);
    // Ingest in order: the live one takes the last slot ...
    let first = lax_offer;
    assert!(
        policy
            .take_custody(&mut store, &first, NOW)
            .expect("apply path")
            .is_accept()
    );
    // ... and the dtn one is now refused typed (evict first).
    assert_eq!(
        policy.decide_manifest(&offer(&urgent_bytes, &peer, NOW + 5_000), &store, NOW),
        ManifestVerdict::Refused(ManifestRefusal::StoreFull {
            held: MAX_BUNDLES,
            cap: MAX_BUNDLES,
        })
    );
}

/// Replayed offers dedup exactly, independently and content-addressed:
/// two interleaved bundles each dedup against their own record.
#[test]
fn replayed_offers_dedup_exactly() {
    let (a, a_chunks) = fixture(2, 0xb1);
    let (b, b_chunks) = fixture(2, 0xb2);
    let a_bytes = a.to_wire_bytes();
    let b_bytes = b.to_wire_bytes();
    let mut store = DtnStoreImage::new();
    let peer = peer();
    let policy = policy();
    let a_id = a.content_id();
    let b_id = b.content_id();
    // First round: both accepted, one chunk each.
    for (bytes, id, chunk) in [
        (&a_bytes, a_id, &a_chunks[0]),
        (&b_bytes, b_id, &b_chunks[0]),
    ] {
        assert!(
            policy
                .take_custody(&mut store, &offer(bytes, &peer, NOW + 1_000), NOW)
                .expect("apply path")
                .is_accept()
        );
        assert!(
            policy
                .receive_chunk(&mut store, &ChunkOffer::new(id, 0, chunk), NOW)
                .expect("apply path")
                .is_accept()
        );
    }
    // Replay round (interleaved): all duplicates, exactly.
    for (bytes, id, chunk) in [
        (&a_bytes, a_id, &a_chunks[0]),
        (&b_bytes, b_id, &b_chunks[0]),
        (&a_bytes, a_id, &a_chunks[0]),
        (&b_bytes, b_id, &b_chunks[0]),
    ] {
        assert_eq!(
            policy
                .take_custody(&mut store, &offer(bytes, &peer, NOW + 1_000), NOW)
                .expect("apply path")
                .name(),
            "already_held"
        );
        assert_eq!(
            policy
                .receive_chunk(&mut store, &ChunkOffer::new(id, 0, chunk), NOW)
                .expect("apply path"),
            ChunkVerdict::Duplicate { slot: 0 }
        );
    }
    // Exactly two bundles, two custody events — replay moved nothing.
    assert_eq!(store.bundle_count(), 2);
    assert_eq!(store.evidence_count(), 2);
    assert!(store.holds_slot(&a_id, 0).expect("held"));
    assert!(!store.holds_slot(&a_id, 1).expect("held"));
}

/// An expired HELD bundle's re-offer is still a duplicate (the record
/// is the truth) — and after eviction the same content is FRESH custody
/// again, with the NEW offer's TTL (a legitimate new custody term).
#[test]
fn expired_held_reoffer_duplicates_until_evicted() {
    let (manifest, _) = fixture(1, 0xc1);
    let bytes = manifest.to_wire_bytes();
    let mut store = DtnStoreImage::new();
    let peer = peer();
    let policy = policy();
    let id = manifest.content_id();
    // Admitted with a 100s TTL.
    assert!(
        policy
            .take_custody(&mut store, &offer(&bytes, &peer, NOW + 100), NOW)
            .expect("apply path")
            .is_accept()
    );
    // Long past its bound: the re-offer is a duplicate whose anchor
    // reports the EXPIRED status (the first admission's own bound).
    let verdict =
        policy.decide_manifest(&offer(&bytes, &peer, NOW + 100), &store, NOW + 500);
    assert_eq!(verdict.name(), "already_held");
    let ManifestVerdict::AlreadyHeld(held) = verdict else {
        unreachable!("checked name");
    };
    assert_eq!(held.status().as_str(), "expired");
    assert_eq!(held.summary().expires_at_unix(), NOW + 100);
    // Evict, flush the decision away (the image IS the state), and the
    // same content is fresh custody with the new offer's TTL.
    let evicted = store.evict_expired(NOW + 500);
    assert_eq!(evicted, vec![id]);
    let fresh = policy
        .take_custody(&mut store, &offer(&bytes, &peer, NOW + 9_000), NOW + 500)
        .expect("apply path");
    assert_eq!(fresh.name(), "accept");
    let ManifestVerdict::Accept(anchor) = fresh else {
        unreachable!("checked name");
    };
    assert_eq!(anchor.expires_at_unix(), NOW + 9_000);
    // The custody evidence outlived the eviction (the R8 seam).
    assert_eq!(store.evidence_count(), 2);
    assert_eq!(store.evidence()[1].kind().as_str(), "received");
}

/// Chunks for unknown content are refused even while the store holds
/// OTHER bundles — nothing is ever stored orphaned.
#[test]
fn unknown_content_chunk_is_refused_among_held_bundles() {
    let (held, chunks) = fixture(2, 0xd1);
    let mut store = DtnStoreImage::new();
    let policy = policy();
    seed_bundle(&mut store, &held, &chunks, NOW + 1_000);
    let stranger = [0x5a; 32];
    assert_eq!(
        policy.decide_chunk(&ChunkOffer::new(stranger, 0, &chunks[0]), &store, NOW),
        ChunkVerdict::Refused(ChunkRefusal::UnknownContent {
            content_id: stranger,
        })
    );
    assert_eq!(store.bundle_count(), 1, "no orphan record appeared");
}

/// A manifest too large for the store's registry is refused at the
/// edge, before the store's own `ManifestTooLarge` would fire on the
/// receiving path.
#[test]
fn oversized_manifest_is_refused_at_the_edge() {
    // ~130k single-byte chunks -> ~4.4 MiB of canonical CBOR, past the
    // 4 MiB registry cap.
    let hashes = vec![[0u8; 32]; 130_000];
    let manifest =
        ContentManifest::new(1, 130_000, hashes, "app/test", None, NOW).expect("geometry");
    let bytes = manifest.to_wire_bytes();
    assert!(bytes.len() as u64 > sharenet_dtn::MAX_REGISTRY_BYTES);
    let store = DtnStoreImage::new();
    let peer = peer();
    let policy = policy();
    assert_eq!(
        policy.decide_manifest(&offer(&bytes, &peer, NOW + 1_000), &store, NOW),
        ManifestVerdict::Refused(ManifestRefusal::ManifestTooLarge {
            bytes: bytes.len(),
            max: sharenet_dtn::MAX_REGISTRY_BYTES,
        })
    );
}

/// Determinism: the same (offer, store, clock) triple always yields the
/// identical verdict, anchors included (architecture §2).
#[test]
fn verdicts_are_deterministic() {
    let (manifest, chunks) = fixture(2, 0xe1);
    let bytes = manifest.to_wire_bytes();
    let mut store = DtnStoreImage::new();
    let peer = peer();
    let policy = policy();
    seed_bundle(&mut store, &manifest, &chunks[..1], NOW + 1_000);
    let id = manifest.content_id();
    // Manifest: three identical decisions.
    for _ in 0..3 {
        let verdict = policy.decide_manifest(&offer(&bytes, &peer, NOW + 1_000), &store, NOW);
        assert_eq!(verdict.name(), "already_held");
        assert_eq!(
            verdict,
            policy.decide_manifest(&offer(&bytes, &peer, NOW + 1_000), &store, NOW)
        );
    }
    // Chunk: identical down to the anchor.
    let a = policy.decide_chunk(&ChunkOffer::new(id, 1, &chunks[1]), &store, NOW);
    let b = policy.decide_chunk(&ChunkOffer::new(id, 1, &chunks[1]), &store, NOW);
    assert_eq!(a, b);
    assert!(a.is_accept());
    // And a different clock is a different decision (the clock is an
    // input, never a hidden state).
    let expired = policy.decide_manifest(&offer(&bytes, &peer, NOW + 1_000), &store, NOW + 2_000);
    let ManifestVerdict::AlreadyHeld(held) = expired else {
        unreachable!("duplicate regardless of clock");
    };
    assert_eq!(held.status().as_str(), "expired");
}

/// The minimum-remaining-life floor is exact at the boundary for ANY
/// configured value (not just the default).
#[test]
fn floor_is_exact_for_any_configuration() {
    let (manifest, _) = fixture(1, 0xf1);
    let bytes = manifest.to_wire_bytes();
    let store = DtnStoreImage::new();
    let peer = peer();
    for floor in [0u64, 1, 600, 10_000] {
        let policy = PropagationPolicy::new(PropagationParams::new(floor));
        // At the floor exactly (never zero-remaining — that is the
        // hard expiry gate's own territory, not the floor's).
        let verdict = policy.decide_manifest(
            &offer(&bytes, &peer, NOW + floor.max(1)),
            &store,
            NOW,
        );
        assert!(
            verdict.is_accept(),
            "at the floor ({floor}) must be accepted"
        );
        let below = policy.decide_manifest(
            &offer(&bytes, &peer, NOW + floor.saturating_sub(1)),
            &store,
            NOW,
        );
        if floor <= 1 {
            // No floor (or one of exactly one second): the "one
            // below" offer is already past the hard expiry gate
            // (zero remaining life is expiry, not a floor miss).
            assert_eq!(below.name(), "refused");
            assert_eq!(below.refusal().unwrap().name(), "offer_expired");
        } else {
            assert_eq!(
                below,
                ManifestVerdict::Refused(ManifestRefusal::RemainingLifeBelowMinimum {
                    remaining_secs: floor - 1,
                    minimum_secs: floor,
                }),
                "one below the floor ({floor}) must be refused"
            );
        }
    }
}
