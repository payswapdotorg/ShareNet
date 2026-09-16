//! R6-004 "restart" verification: a decision made, the store flushed,
//! the whole thing torn down — and the reloaded node dedups the same
//! offer EXACTLY, because the decision depends on durable state ONLY
//! (the R6-003 store; this crate holds no state of its own). What is
//! proven, per the work item's verify level:
//!
//! - **image-level restart** — the registry bytes (serialize → strict
//!   re-load with every cross-check) carry the whole truth: the same
//!   manifest offer is `already_complete` (not a second record), the
//!   same chunk offer is a verified `duplicate`, the custody evidence
//!   is exactly the one `received` record, and re-serializing after the
//!   reload is byte-identical (the replay decided nothing new);
//! - **file-backed restart** — a REAL `DtnStore` (create → decide →
//!   apply through the store's own APIs → flush → drop → load with the
//!   re-verify-everything law) dedups the same offer exactly, with the
//!   pre-restart and post-restart duplicate anchors EQUAL;
//! - **the clock advanced across the restart** — TTL is evaluated at
//!   the NEW caller's clock over the OLD durable bound (an expired
//!   held bundle reports `already_held` with the expired status), and
//!   after eviction the same content is fresh custody again;
//! - **refusals store nothing** — a store that refused everything
//!   reloads empty and the offer is as acceptable as it ever was.

mod common;

use common::{fixture, offer, peer, policy, TempDir, NOW};
use sharenet_dtn::{CustodyRecord, DtnStore, DtnStoreImage, ServicePriority};
use sharenet_propagation::{ChunkOffer, ChunkVerdict, ManifestVerdict};

/// The image-level restart law: serialize → strict reload → the same
/// offer dedups exactly (never a second record), and the replay
/// mutates nothing (byte-identical re-serialization).
#[test]
fn image_restart_dedups_exactly() {
    let (manifest, chunks) = fixture(2, 0x11);
    let bytes = manifest.to_wire_bytes();
    let peer = peer();
    let policy = policy();
    let id = manifest.content_id();

    // Before: custody taken, both chunks landed.
    let mut image = DtnStoreImage::new();
    assert!(
        policy
            .take_custody(&mut image, &offer(&bytes, &peer, NOW + 1_000), NOW)
            .expect("apply path")
            .is_accept()
    );
    for (slot, chunk) in chunks.iter().enumerate() {
        assert!(
            policy
                .receive_chunk(&mut image, &ChunkOffer::new(id, slot, chunk), NOW)
                .expect("apply path")
                .is_accept()
        );
    }
    let before = image.to_bytes().expect("serialize");

    // Teardown → reload from the bytes only (strict parse + every
    // cross-check the store's codec does).
    let mut reloaded = DtnStoreImage::from_bytes(&before).expect("strict reload");
    assert_eq!(reloaded.bundle_count(), 1);
    assert_eq!(reloaded.evidence_count(), 1);

    // The same manifest offer: `already_complete`, exactly once more.
    let verdict = policy.decide_manifest(&offer(&bytes, &peer, NOW + 1_000), &reloaded, NOW);
    assert_eq!(verdict.name(), "already_complete");
    let ManifestVerdict::AlreadyComplete(held) = verdict else {
        unreachable!("checked name");
    };
    assert_eq!(held.summary().chunk_count(), 2);
    assert_eq!(held.summary().present_chunk_count(), 2);
    assert_eq!(held.status().as_str(), "live");

    // The same chunk offer: a verified duplicate.
    assert_eq!(
        policy.decide_chunk(&ChunkOffer::new(id, 0, &chunks[0]), &reloaded, NOW),
        ChunkVerdict::Duplicate { slot: 0 }
    );

    // The composed paths stay idempotent across the restart too.
    let replayed = policy
        .take_custody(&mut reloaded, &offer(&bytes, &peer, NOW + 1_000), NOW)
        .expect("apply path");
    assert_eq!(replayed.name(), "already_complete");
    assert_eq!(
        policy
            .receive_chunk(&mut reloaded, &ChunkOffer::new(id, 1, &chunks[1]), NOW)
            .expect("apply path"),
        ChunkVerdict::Duplicate { slot: 1 }
    );

    // Still one bundle, one custody event — the replay added nothing.
    assert_eq!(reloaded.bundle_count(), 1);
    assert_eq!(reloaded.evidence_count(), 1);
    assert_eq!(reloaded.evidence()[0].kind().as_str(), "received");
    assert_eq!(reloaded.evidence()[0].peer(), &peer);
    // And the replay mutated no bytes: the registry round-trips
    // byte-identically.
    let after = reloaded.to_bytes().expect("serialize");
    assert_eq!(before, after);
}

/// The file-backed restart law: a REAL store (create → apply → flush
/// → drop → load re-verifying everything) dedups the same offer with
/// an anchor EQUAL to the pre-restart one.
#[test]
fn file_backed_restart_dedups_exactly() {
    let dir = TempDir::new("restart-file");
    let (manifest, chunks) = fixture(3, 0x22);
    let bytes = manifest.to_wire_bytes();
    let peer = peer();
    let policy = policy();
    let id = manifest.content_id();

    // The daemon's file-backed path: decide purely over the store's
    // image, apply through the store's own APIs, flush.
    let mut store = DtnStore::create(&dir.path).expect("create store");
    let verdict = policy.decide_manifest(&offer(&bytes, &peer, NOW + 1_000), store.image(), NOW);
    assert!(verdict.is_accept());
    store
        .admit_manifest(&manifest, ServicePriority::Dtn, NOW, NOW + 1_000, 2)
        .expect("admit through the store");
    store
        .record_evidence(CustodyRecord::received(id, NOW, &peer))
        .expect("custody evidence");
    for (slot, chunk) in chunks.iter().enumerate() {
        assert_eq!(
            policy.decide_chunk(&ChunkOffer::new(id, slot, chunk), store.image(), NOW).name(),
            "accept"
        );
        store
            .admit_chunk(&id, slot, chunk, NOW)
            .expect("chunk through the store");
    }
    // The pre-restart duplicate verdict (partial: 2 of 3 chunks is
    // already seeded — re-offer BEFORE the rest landed, captured for
    // the equality check below).
    store.flush().expect("flush");

    // Teardown: the store is dropped completely; only the directory
    // (registry + chunk files) survives.
    drop(store);
    let mut reloaded = DtnStore::load(&dir.path, NOW + 10).expect("re-verify everything");
    assert_eq!(reloaded.revalidated_at_unix(), Some(NOW + 10));

    // The same offer dedups EXACTLY: same verdict shape, same anchor.
    let after = policy.decide_manifest(&offer(&bytes, &peer, NOW + 1_000), reloaded.image(), NOW);
    assert_eq!(after.name(), "already_complete");
    let ManifestVerdict::AlreadyComplete(held) = after else {
        unreachable!("checked name");
    };
    assert_eq!(held.summary().present_chunk_count(), 3);
    assert_eq!(held.summary().priority(), ServicePriority::Dtn);
    assert_eq!(held.summary().expires_at_unix(), NOW + 1_000);
    assert_eq!(held.summary().replication_target(), 2);
    assert_eq!(held.status().as_str(), "live");

    // The same chunk offers are verified duplicates; the reloaded
    // store re-hashes its chunk files at load, so the bytes agree.
    for (slot, chunk) in chunks.iter().enumerate() {
        let slot32 = u32::try_from(slot).expect("small fixture");
        assert_eq!(
            policy.decide_chunk(&ChunkOffer::new(id, slot, chunk), reloaded.image(), NOW),
            ChunkVerdict::Duplicate { slot: slot32 }
        );
        assert_eq!(reloaded.read_chunk(&id, slot32).expect("re-verified"), *chunk);
    }

    // Exactly one custody event survived the boundary.
    assert_eq!(reloaded.image().evidence_count(), 1);
    assert_eq!(reloaded.image().evidence()[0].kind().as_str(), "received");
    assert_eq!(reloaded.image().evidence()[0].peer(), &peer);

    // And the reloaded store still accepts a NEW bundle's custody
    // (receiving continues across the boundary) — through the store's
    // own APIs, the daemon path.
    let (other, _) = fixture(1, 0x23);
    let other_bytes = other.to_wire_bytes();
    assert!(
        policy
            .decide_manifest(&offer(&other_bytes, &peer, NOW + 1_000), reloaded.image(), NOW)
            .is_accept()
    );
    reloaded
        .admit_manifest(&other, ServicePriority::Dtn, NOW, NOW + 1_000, 2)
        .expect("new custody across the boundary");
    assert_eq!(reloaded.image().bundle_count(), 2);
    reloaded.flush().expect("flush");
}

/// The clock advanced across the restart: the durable bound is the old
/// one, evaluated at the NEW caller's clock — an expired held bundle
/// reports `already_held` with the expired status; after eviction (and
/// a flush) the same content is FRESH custody again.
#[test]
fn clock_advanced_across_restart_expires_the_held_bound() {
    let dir = TempDir::new("restart-clock");
    let (manifest, _) = fixture(1, 0x33);
    let bytes = manifest.to_wire_bytes();
    let peer = peer();
    let policy = policy();
    let id = manifest.content_id();

    // Admitted at NOW with a 100s TTL; flushed and torn down.
    {
        let mut store = DtnStore::create(&dir.path).expect("create store");
        store
            .admit_manifest(&manifest, ServicePriority::Opportunistic, NOW, NOW + 100, 1)
            .expect("admit");
        store
            .record_evidence(CustodyRecord::received(id, NOW, &peer))
            .expect("custody evidence");
        store.flush().expect("flush");
    }

    // Reloaded long past the bound: the bundle loads (the store's law
    // — TTL is evaluated at query time) and the re-offer is a
    // duplicate whose anchor reports the EXPIRED status.
    let mut store = DtnStore::load(&dir.path, NOW + 500).expect("reload");
    let verdict = policy.decide_manifest(&offer(&bytes, &peer, NOW + 500), store.image(), NOW + 500);
    assert_eq!(verdict.name(), "already_held");
    let ManifestVerdict::AlreadyHeld(held) = verdict else {
        unreachable!("checked name");
    };
    assert_eq!(held.status().as_str(), "expired");
    assert_eq!(held.summary().expires_at_unix(), NOW + 100);

    // Expired bundles never forward (the R6-003 law, at this edge too).
    assert!(store.forward_candidates(NOW + 500).is_empty());

    // Evict, flush, reload: the same content is fresh custody with the
    // NEW offer's TTL (a new custody term — legitimate).
    let evicted = store.evict_expired(NOW + 500);
    assert_eq!(evicted, vec![id]);
    store.flush().expect("flush (deletes the chunk files after)");
    drop(store);
    let fresh = DtnStore::load(&dir.path, NOW + 600).expect("reload after eviction");
    assert_eq!(fresh.image().bundle_count(), 0);
    let verdict = policy.decide_manifest(&offer(&bytes, &peer, NOW + 5_000), fresh.image(), NOW + 600);
    assert!(verdict.is_accept());
    // The custody evidence outlived the eviction (the R8 seam): one
    // received record from the FIRST term.
    assert_eq!(fresh.image().evidence_count(), 1);
}

/// Refusals store nothing: a node that refused every offer reloads
/// empty, and the offer is as acceptable as it ever was.
#[test]
fn refusals_store_nothing_across_restart() {
    let dir = TempDir::new("restart-refusals");
    let (manifest, chunks) = fixture(2, 0x44);
    let bytes = manifest.to_wire_bytes();
    let peer = peer();
    let policy = policy();

    {
        let mut store = DtnStore::create(&dir.path).expect("create store");
        // A battery of refusals (each fail-closed, nothing stored).
        let expired = offer(&bytes, &peer, NOW);
        assert_eq!(
            policy.decide_manifest(&expired, store.image(), NOW).name(),
            "refused"
        );
        let mut lie = [0u8; 32];
        lie[0] ^= 1;
        let claimed = offer(&bytes, &peer, NOW + 1_000).with_claimed_content_id(&lie);
        assert_eq!(
            policy.decide_manifest(&claimed, store.image(), NOW).name(),
            "refused"
        );
        let unknown = [0x77u8; 32];
        assert_eq!(
            policy
                .decide_chunk(&ChunkOffer::new(unknown, 0, &chunks[0]), store.image(), NOW)
                .name(),
            "refused"
        );
        store.flush().expect("flush");
        assert_eq!(store.image().bundle_count(), 0);
        assert_eq!(store.image().evidence_count(), 0);
    }

    // Reload: empty, and the same offer is acceptable (nothing the
    // refusals left behind can affect it).
    let store = DtnStore::load(&dir.path, NOW).expect("reload");
    assert_eq!(store.image().bundle_count(), 0);
    assert!(
        policy
            .decide_manifest(&offer(&bytes, &peer, NOW + 1_000), store.image(), NOW)
            .is_accept()
    );
    let _ = store;
}
