//! The receiving-side propagation policy (R6-004) — the pure decision
//! engine.
//!
//! `spec/architecture.md` §12: *"Propagation uses: deduplication;
//! integrity verification; TTL; priority; replication policy; ...
//! The design should borrow Delay-Tolerant Networking principles..."*.
//! R6-003 built the LOCAL half (the custody store); THIS crate is the
//! RECEIVING half: the rules for what THIS node accepts when ANOTHER
//! node propagates content to it — an offer of a manifest + chunks, or
//! a forward from a carrying peer. The R5-005 style, applied to the
//! content plane: typed offer evidence IN ([`ManifestOffer`] /
//! [`ChunkOffer`]), a pure decision over the node's own durable state
//! (the R6-003 [`sharenet_dtn::DtnStoreImage`]) and the caller's clock, typed verdict
//! OUT ([`ManifestVerdict`] / [`ChunkVerdict`]) — no I/O, no wall clock,
//! no propagation-local state.
//!
//! # The rule families (§12, one function family each)
//!
//! ## Deduplication
//!
//! Content is content-addressed, so dedup IS the identity question:
//! the content id is re-derived from the offered manifest bytes (L013)
//! and compared against the store's present set. Already held and
//! incomplete → [`ManifestVerdict::AlreadyHeld`] (missing slots may
//! still arrive); already held and complete →
//! [`ManifestVerdict::AlreadyComplete`]. Both are VERDICTS, not errors:
//! re-delivery is idempotent, never a second record, and the anchor
//! reports the FIRST admission's metadata — re-delivery never extends a
//! TTL or upgrades a priority (the R6-003 law, applied at the edge). At
//! slot level, a chunk whose slot is already present is a VERIFIED
//! [`ChunkVerdict::Duplicate`] — the manifest commits one hash per
//! slot, so a verified re-delivery is byte-identical by construction.
//! A slot re-delivered with DIFFERENT bytes is an integrity refusal,
//! never a duplicate: the duplicate verdict certifies verified
//! byte-identity, nothing less.
//!
//! ## Integrity verification
//!
//! The manifest is the only authority (R6-001): offered bytes are
//! strict-parsed with the protocol core's own invariants, the content
//! id is RE-DERIVED (a carrying frame's claimed id must agree or the
//! offer is refused typed — claims never get stored), and chunks
//! verify through the STORE's own path (`DtnStoreImage::verify_chunk`:
//! length law before hash law, the R6-001 discipline). This crate never
//! re-implements a hashing policy — it applies the store's, and where
//! it needs durable side effects it composes the store's APIs
//! ([`PropagationPolicy::take_custody`] = `admit_manifest` +
//! `record_evidence(Received)`; [`PropagationPolicy::receive_chunk`] =
//! `admit_chunk`), never a second store.
//!
//! ## TTL
//!
//! Every time parameter is caller-supplied — this crate has NO wall
//! clock (the law of the connectivity boundary, the admission policy
//! and the store, applied here). A bundle is expired at
//! `now >= expires_at_unix` (the exclusive-bound convention): expired
//! offers are refused typed, and offers whose REMAINING life is below
//! the policy's configured minimum are refused typed too
//! ([`PropagationParams::min_remaining_ttl_secs`] — nearly-dead
//! bundles are eviction load, not carry capacity; a floor of 0 disables
//! it, leaving the hard expiry gate). The floor gates NEW custody
//! only: chunks COMPLETING an already-held bundle pass with the hard
//! expiry gate alone (the bytes are already this node's custody; the
//! store's own law for held bundles is exactly that).
//!
//! ## Priority
//!
//! The frozen service classes — `live` / `opportunistic` / `dtn`
//! (ADR-003) — reused as [`sharenet_dtn::ServicePriority`]: the wire's
//! priority name parses ONLY through the frozen vocabulary (an
//! unknown class is a typed refusal — no second vocabulary, no
//! future-class smuggling). **TTL gates BEFORE priority**: an expired
//! `live` offer is refused while a fresh `dtn` offer is accepted — no
//! priority rescues a TTL failure, so no inversion is possible at the
//! receiving edge. Among offers that passed the gates,
//! [`PropagationPolicy::order_for_ingest`] fixes the ingestion order —
//! (priority rank, expiry urgency soonest-first, content id bytes) —
//! the SAME order law the store uses for carry-forward, so the
//! receiving edge and the sending edge agree on precedence.
//!
//! ## Replication policy
//!
//! What the local store's replication state means for receiving,
//! decided honestly from §12 and the store's semantics:
//!
//! 1. An offered replication target must be at least
//!    [`sharenet_dtn::REPLICATION_TARGET_MIN`] (1): a bundle that may
//!    never be handed onward has no business entering a carry-forward
//!    store (the R6-003 admission law, applied at the edge).
//! 2. This node's replication COUNT is this node's own fact: it starts
//!    at 0 at admission. The offer evidence deliberately has NO
//!    claimed-count field — a peer's claim about its own (or the
//!    network's) replication is unverifiable here and would be a
//!    caller-controlled boolean over a security-relevant decision, so
//!    the rules never even look at one.
//! 3. Replication gates FORWARDING, not RECEIVING: an already-held
//!    bundle at or past its replication target is still a DUPLICATE
//!    verdict (the bytes are here; dedup wins), and its missing chunks
//!    still complete (a coherent cache until TTL eviction is better
//!    storage hygiene than a permanently partial one). What an
//!    at-target held bundle never does again is FORWARD — that is the
//!    store's law, unchanged.
//!
//! # Fail-closed and deterministic
//!
//! Every ambiguity, tamper, lie, expiry or capacity pressure is a typed
//! refusal, and nothing is stored on the back of one. The verdict is a
//! pure function of (offer evidence, store state, caller clock) with a
//! fixed evaluation order (see [`crate::verdict`]'s module docs) — the same
//! inputs always yield the same verdict (architecture §2), which is
//! what makes the restart law true: a decision depends on durable state
//! ONLY, so after flush/teardown/reload the same offer dedups exactly.

use sharenet_dtn::{
    CustodyRecord, DtnError, DtnStoreImage, ServicePriority, MAX_BUNDLES, MAX_REGISTRY_BYTES,
    REPLICATION_TARGET_MIN,
};
use sharenet_protocol::ContentManifest;

use crate::evidence::{ChunkOffer, ManifestOffer};
use crate::verdict::{
    AcceptAnchor, ChunkAnchor, ChunkRefusal, ChunkVerdict, HeldAnchor, ManifestRefusal,
    ManifestVerdict,
};

/// The default minimum remaining TTL an offered bundle must have to be
/// accepted as NEW custody (60s: a bundle with under a minute of life
/// is eviction load, not carry capacity).
pub const DEFAULT_MIN_REMAINING_TTL_SECS: u64 = 60;

/// The receiving-side propagation policy's tunable parameters
/// (immutable; clone per configuration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropagationParams {
    min_remaining_ttl_secs: u64,
}

impl PropagationParams {
    /// Parameters requiring at least `min_remaining_ttl_secs` of
    /// remaining life (`0` disables the floor, leaving only the hard
    /// expiry gate).
    pub fn new(min_remaining_ttl_secs: u64) -> Self {
        PropagationParams {
            min_remaining_ttl_secs,
        }
    }

    /// The configured minimum remaining life for new custody.
    pub fn min_remaining_ttl_secs(&self) -> u64 {
        self.min_remaining_ttl_secs
    }
}

impl Default for PropagationParams {
    fn default() -> Self {
        PropagationParams {
            min_remaining_ttl_secs: DEFAULT_MIN_REMAINING_TTL_SECS,
        }
    }
}

/// The receiving-side propagation policy: an immutable parameter set
/// plus the pure decision functions over the node's own store state.
///
/// Deterministic for a fixed (offer, store, clock) triple
/// (architecture §2): no wall clock, no I/O, no hidden state — this
/// type is a namespace for the rules, not a mutable engine.
#[derive(Debug, Clone, Default)]
pub struct PropagationPolicy {
    params: PropagationParams,
}

impl PropagationPolicy {
    /// A policy with the given parameters.
    pub fn new(params: PropagationParams) -> Self {
        PropagationPolicy { params }
    }

    /// The policy's parameters.
    pub fn params(&self) -> &PropagationParams {
        &self.params
    }

    // -----------------------------------------------------------------------
    // The manifest rules (dedup / integrity / TTL / priority / replication)
    // -----------------------------------------------------------------------

    /// Decide a manifest offer against the store at the caller's clock.
    ///
    /// Evaluation order (fixed; one typed outcome — see [`crate::verdict`]'s
    /// module docs): strict parse → id-claim agreement → frozen-class
    /// priority → registry-size fit → dedup against the held set → TTL
    /// hard gate → minimum remaining life → replication target →
    /// bundle capacity. TTL gates BEFORE priority: no priority rescues
    /// an expired offer. Dedup gates BEFORE the offer's TTL claims: a
    /// held bundle answers with its own first-admission record.
    pub fn decide_manifest(
        &self,
        offer: &ManifestOffer<'_>,
        store: &DtnStoreImage,
        now_unix: u64,
    ) -> ManifestVerdict {
        // 1. The manifest must strict-parse with the R6-001
        //    invariants (the protocol core's own check — never a
        //    second opinion).
        let manifest = match ContentManifest::from_wire_bytes(offer.manifest_bytes) {
            Ok(manifest) => manifest,
            Err(cause) => {
                return ManifestVerdict::Refused(ManifestRefusal::ManifestMalformed { cause })
            }
        };
        // 2. The content id is RE-DERIVED (L013); a claim must agree.
        let derived = manifest.content_id();
        if let Some(claimed) = offer.claimed_content_id {
            if *claimed != derived {
                return ManifestVerdict::Refused(ManifestRefusal::ContentIdClaimDisagrees {
                    claimed: *claimed,
                    derived,
                });
            }
        }
        // 3. The priority parses ONLY through the frozen classes.
        let priority = match ServicePriority::from_name(offer.priority_name) {
            Some(priority) => priority,
            None => {
                return ManifestVerdict::Refused(ManifestRefusal::PriorityNotAFrozenClass {
                    found: offer.priority_name.to_owned(),
                })
            }
        };
        // 4. The manifest must fit the store's registry cap (refused
        //    here, before the store's own ManifestTooLarge would fire).
        if offer.manifest_bytes.len() as u64 > MAX_REGISTRY_BYTES {
            return ManifestVerdict::Refused(ManifestRefusal::ManifestTooLarge {
                bytes: offer.manifest_bytes.len(),
                max: MAX_REGISTRY_BYTES,
            });
        }
        // 5. Dedup against the store's present set: held content
        //    answers with the FIRST admission's own record.
        if store.holds_bundle(&derived) {
            let summary = store
                .summary(&derived)
                .expect("holds_bundle just confirmed the record");
            let status = store
                .bundle_status(&derived, now_unix)
                .expect("holds_bundle just confirmed the record");
            let held = HeldAnchor::new(summary, status);
            return if held.summary().complete() {
                ManifestVerdict::AlreadyComplete(held)
            } else {
                ManifestVerdict::AlreadyHeld(held)
            };
        }
        // 6. TTL hard gate — BEFORE priority (no inversion: no
        //    priority rescues an expired offer).
        if now_unix >= offer.expires_at_unix {
            return ManifestVerdict::Refused(ManifestRefusal::OfferExpired {
                now_unix,
                expires_at_unix: offer.expires_at_unix,
            });
        }
        let remaining_secs = offer.expires_at_unix - now_unix;
        // 7. The minimum-remaining-life floor for NEW custody.
        if remaining_secs < self.params.min_remaining_ttl_secs {
            return ManifestVerdict::Refused(ManifestRefusal::RemainingLifeBelowMinimum {
                remaining_secs,
                minimum_secs: self.params.min_remaining_ttl_secs,
            });
        }
        // 8. The replication-target law (the store's minimum, applied
        //    at the edge).
        if offer.replication_target < REPLICATION_TARGET_MIN {
            return ManifestVerdict::Refused(ManifestRefusal::ReplicationTargetBelowMinimum {
                target: offer.replication_target,
            });
        }
        // 9. Capacity: new custody needs a bundle slot (evict first).
        if store.bundle_count() >= MAX_BUNDLES {
            return ManifestVerdict::Refused(ManifestRefusal::StoreFull {
                held: store.bundle_count(),
                cap: MAX_BUNDLES,
            });
        }
        ManifestVerdict::Accept(AcceptAnchor::new(
            derived,
            priority,
            offer.expires_at_unix,
            remaining_secs,
            offer.replication_target,
            manifest.chunk_count() as u32,
        ))
    }

    // -----------------------------------------------------------------------
    // The chunk rules (integrity / TTL / slot-level dedup)
    // -----------------------------------------------------------------------

    /// Decide a chunk offer against the store at the caller's clock —
    /// verification through the STORE's own path (length law before
    /// hash law, the R6-001 discipline; this crate never re-implements
    /// the hashing policy).
    ///
    /// The chain mirrors `DtnStoreImage::verify_chunk` exactly: unknown
    /// content (the manifest must be accepted first — nothing is ever
    /// stored orphaned) → held-bundle expiry (expired bundles take no
    /// new chunks) → slot range → length law → hash law. A slot
    /// already present reports `Duplicate` only AFTER its bytes
    /// verified — byte-identity is certified, not assumed.
    pub fn decide_chunk(
        &self,
        offer: &ChunkOffer<'_>,
        store: &DtnStoreImage,
        now_unix: u64,
    ) -> ChunkVerdict {
        match store.verify_chunk(&offer.content_id, offer.slot, offer.bytes, now_unix) {
            Ok(true) => {
                // The slot verified and is new. Re-read the held
                // manifest for the slot's committed expected length
                // (the anchor's evidence; the manifest re-parses
                // because nothing is trusted across call boundaries).
                let manifest = match store.manifest(&offer.content_id) {
                    Ok(manifest) => manifest,
                    Err(err) => return ChunkVerdict::Refused(map_chunk_refusal(err)),
                };
                let expected_len = manifest
                    .expected_chunk_len(offer.slot)
                    .expect("slot < chunk_count (verified above)");
                let slot = u32::try_from(offer.slot)
                    .expect("slot < chunk_count <= u32::MAX (verified above)");
                ChunkVerdict::Accept(ChunkAnchor::new(offer.content_id, slot, expected_len))
            }
            Ok(false) => ChunkVerdict::Duplicate {
                slot: u32::try_from(offer.slot)
                    .expect("slot < chunk_count <= u32::MAX (verified above)"),
            },
            Err(err) => ChunkVerdict::Refused(map_chunk_refusal(err)),
        }
    }

    // -----------------------------------------------------------------------
    // The receiving order (priority, applied at the edge)
    // -----------------------------------------------------------------------

    /// Order a batch of ACCEPTED manifest anchors for ingestion: by
    /// (priority rank, expiry urgency — soonest first — content id
    /// bytes). This is the SAME order law the store uses for
    /// carry-forward (`DtnStoreImage::forward_candidates`), applied at
    /// the receiving edge, so the two edges agree on precedence and a
    /// store under capacity pressure ingests the most valuable custody
    /// first. Only offers that passed the gates reach here — TTL
    /// already gated BEFORE priority, so ordering can never invert it.
    pub fn order_for_ingest(&self, anchors: &mut [AcceptAnchor]) {
        anchors.sort_by(|a, b| {
            let ka = (a.priority(), a.expires_at_unix(), *a.content_id());
            let kb = (b.priority(), b.expires_at_unix(), *b.content_id());
            ka.cmp(&kb)
        });
    }

    // -----------------------------------------------------------------------
    // The composed apply paths (durable side effects through the store)
    // -----------------------------------------------------------------------

    /// Decide a manifest offer and, when the verdict is `Accept`, TAKE
    /// CUSTODY through the store's own APIs (composed, not duplicated):
    /// `admit_manifest` + a `Received` custody record for the offering
    /// peer. The decision is re-evaluated AT THIS CALL'S CLOCK — a
    /// verdict a moment ago never licenses admission now (the clock is
    /// caller-supplied, so "advancing" it is calling with a bigger
    /// `now_unix`).
    ///
    /// `AlreadyHeld` / `AlreadyComplete` / `Refused` record NOTHING: a
    /// duplicate takes no new custody and a refusal is fail-closed, so
    /// neither appends evidence (the Received record is the fact of
    /// custody TAKEN, first admission only — the bounded log records
    /// custody events, not offer traffic).
    pub fn take_custody(
        &self,
        store: &mut DtnStoreImage,
        offer: &ManifestOffer<'_>,
        now_unix: u64,
    ) -> Result<ManifestVerdict, DtnError> {
        let verdict = self.decide_manifest(offer, store, now_unix);
        if let ManifestVerdict::Accept(anchor) = &verdict {
            // Re-derive the manifest for the store call — parsed
            // evidence is never carried across the decision boundary
            // (verify-don't-trust, even on ourselves). Strict parse
            // succeeded inside the decision, so this cannot disagree
            // in practice; fail-closed if it somehow does.
            let manifest = ContentManifest::from_wire_bytes(offer.manifest_bytes)
                .map_err(|cause| DtnError::ManifestMalformed { cause })?;
            debug_assert_eq!(manifest.content_id(), *anchor.content_id());
            store.admit_manifest(
                &manifest,
                anchor.priority(),
                now_unix,
                offer.expires_at_unix,
                offer.replication_target,
            )?;
            store.record_evidence(CustodyRecord::received(
                *anchor.content_id(),
                now_unix,
                offer.peer,
            ))?;
        }
        Ok(verdict)
    }

    /// Decide a chunk offer and, when the verdict is `Accept`, store it
    /// through the store's own admission path (`admit_chunk`: verify,
    /// mark present — the wasm-host seam shape; on the file-backed
    /// `DtnStore` the caller drives `DtnStore::admit_chunk` after
    /// `decide_chunk`, which writes the chunk file before marking).
    ///
    /// `Duplicate` and `Refused` store NOTHING (idempotent /
    /// fail-closed). No custody evidence is recorded per chunk: the
    /// `Received` record is bundle-level (first admission) — per-chunk
    /// records would spend the bounded evidence log on stream traffic
    /// (a 100-chunk bundle is one custody event, not a hundred).
    pub fn receive_chunk(
        &self,
        store: &mut DtnStoreImage,
        offer: &ChunkOffer<'_>,
        now_unix: u64,
    ) -> Result<ChunkVerdict, DtnError> {
        let verdict = self.decide_chunk(offer, store, now_unix);
        if verdict.is_accept() {
            store.admit_chunk(&offer.content_id, offer.slot, offer.bytes, now_unix)?;
        }
        Ok(verdict)
    }
}

/// Map the store's typed verification failure to the receiving-edge
/// refusal vocabulary (same chain, same order — the names align with
/// the store's own `DtnError::name()` where they mirror).
fn map_chunk_refusal(err: DtnError) -> ChunkRefusal {
    match err {
        DtnError::UnknownContent { content_id } => ChunkRefusal::UnknownContent { content_id },
        DtnError::BundleExpired {
            expires_at_unix,
            now_unix,
        } => ChunkRefusal::BundleExpired {
            now_unix,
            expires_at_unix,
        },
        DtnError::SlotOutOfRange { slot, chunk_count } => {
            ChunkRefusal::SlotOutOfRange { slot, chunk_count }
        }
        DtnError::ChunkLengthWrong {
            slot,
            found,
            expected,
        } => ChunkRefusal::ChunkLengthWrong {
            slot,
            found,
            expected,
        },
        DtnError::ChunkHashMismatch { slot } => ChunkRefusal::ChunkHashMismatch { slot },
        DtnError::ManifestMalformed { cause } => ChunkRefusal::ManifestMalformed { cause },
        // verify_chunk models exactly the six cases above; anything
        // else is a store disagreement this edge fails CLOSED on
        // (nothing stored). The store error's machine name rides along.
        other => ChunkRefusal::StoreStateUnexpected { name: other.name() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sharenet_dtn::{ChunkAdmit, ManifestAdmit, PeerRef, CONTENT_ID_LEN};
    use sharenet_protocol::{chunk_hash, ContentManifest};

    /// A manifest with `n` chunks of 4 bytes (built from real content —
    /// real hashes, real geometry), returned as (manifest, chunks).
    fn fixture(n: usize) -> (ContentManifest, Vec<Vec<u8>>) {
        let content: Vec<u8> = (0..(n * 4)).map(|i| (i % 251) as u8).collect();
        ContentManifest::chunk(&content, 4, "app/test", None, 1_000).expect("valid content")
    }

    /// The offer of `fixture(n)`'s manifest, with 10_000s of TTL from
    /// `now` and a sane target.
    fn offer<'a>(manifest_bytes: &'a [u8], peer: &'a PeerRef) -> ManifestOffer<'a> {
        ManifestOffer::new(manifest_bytes, "dtn", 11_000, 2, peer)
    }

    fn peer() -> PeerRef {
        PeerRef::new(&[0xaa, 0xbb]).expect("valid peer")
    }

    /// The happy path: a well-formed, fresh, sane offer of unknown
    /// content is accepted with the exact admission plan.
    #[test]
    fn fresh_offer_is_accepted_with_the_plan() {
        let (manifest, _) = fixture(3);
        let store = DtnStoreImage::new();
        let peer = peer();
        let now = 1_000u64;
        let policy = PropagationPolicy::default();
        let verdict = policy.decide_manifest(&offer(&manifest.to_wire_bytes(), &peer), &store, now);
        assert!(verdict.is_accept());
        assert_eq!(verdict.name(), "accept");
        let ManifestVerdict::Accept(anchor) = verdict else {
            unreachable!("checked is_accept");
        };
        assert_eq!(anchor.content_id(), &manifest.content_id());
        assert_eq!(anchor.priority(), ServicePriority::Dtn);
        assert_eq!(anchor.expires_at_unix(), 11_000);
        assert_eq!(anchor.remaining_secs(), 10_000);
        assert_eq!(anchor.replication_target(), 2);
        assert_eq!(anchor.chunk_count(), 3);
    }

    /// The default floor is 60s; exactly 60s remaining is ACCEPTED and
    /// 59s is refused — the floor is inclusive (>= minimum).
    #[test]
    fn minimum_remaining_life_is_inclusive() {
        let (manifest, _) = fixture(1);
        let bytes = manifest.to_wire_bytes();
        let store = DtnStoreImage::new();
        let peer = peer();
        let policy = PropagationPolicy::default();
        let now = 1_000u64;
        // remaining == 60 exactly: accepted.
        let exact = ManifestOffer::new(&bytes, "dtn", now + 60, 1, &peer);
        assert!(policy.decide_manifest(&exact, &store, now).is_accept());
        // remaining == 59: refused with the exact numbers.
        let short = ManifestOffer::new(&bytes, "dtn", now + 59, 1, &peer);
        assert_eq!(
            policy.decide_manifest(&short, &store, now),
            ManifestVerdict::Refused(ManifestRefusal::RemainingLifeBelowMinimum {
                remaining_secs: 59,
                minimum_secs: 60,
            })
        );
        // A floor of 0 disables it: the hard expiry gate remains.
        let disabled = PropagationPolicy::new(PropagationParams::new(0));
        assert!(disabled.decide_manifest(&short, &store, now).is_accept());
    }

    /// Malformed manifest bytes are refused with the protocol core's
    /// own typed cause — and nothing is stored.
    #[test]
    fn malformed_manifest_is_refused() {
        let store = DtnStoreImage::new();
        let peer = peer();
        let policy = PropagationPolicy::default();
        let verdict = policy.decide_manifest(
            &ManifestOffer::new(b"not-cbor-at-all", "dtn", 11_000, 1, &peer),
            &store,
            1_000,
        );
        assert!(matches!(
            verdict,
            ManifestVerdict::Refused(ManifestRefusal::ManifestMalformed { .. })
        ));
        assert_eq!(verdict.name(), "refused");
        assert_eq!(
            verdict.refusal().unwrap().name(),
            "manifest_malformed"
        );
        assert_eq!(store.bundle_count(), 0, "nothing stored on refusal");
    }

    /// A claimed content id that disagrees with the derived one is a
    /// typed lie-refusal; an AGREEING claim is fine.
    #[test]
    fn content_id_claims_are_compared_not_trusted() {
        let (manifest, _) = fixture(2);
        let bytes = manifest.to_wire_bytes();
        let store = DtnStoreImage::new();
        let peer = peer();
        let policy = PropagationPolicy::default();
        let now = 1_000u64;
        // A lie: the derived id with one byte flipped.
        let mut lie = manifest.content_id();
        lie[0] ^= 0xff;
        let lying = offer(&bytes, &peer).with_claimed_content_id(&lie);
        assert_eq!(
            policy.decide_manifest(&lying, &store, now),
            ManifestVerdict::Refused(ManifestRefusal::ContentIdClaimDisagrees {
                claimed: lie,
                derived: manifest.content_id(),
            })
        );
        // The truth: accepted.
        let derived = manifest.content_id();
        let honest = offer(&bytes, &peer).with_claimed_content_id(&derived);
        assert!(policy.decide_manifest(&honest, &store, now).is_accept());
    }

    /// Priority names parse ONLY through the frozen classes.
    #[test]
    fn priority_must_be_a_frozen_class() {
        let (manifest, _) = fixture(1);
        let bytes = manifest.to_wire_bytes();
        let store = DtnStoreImage::new();
        let peer = peer();
        let policy = PropagationPolicy::default();
        let now = 1_000u64;
        for name in ["live", "opportunistic", "dtn"] {
            let good = ManifestOffer::new(&bytes, name, 11_000, 1, &peer);
            let verdict = policy.decide_manifest(&good, &store, now);
            let ManifestVerdict::Accept(anchor) = verdict else {
                panic!("frozen class {name} must parse");
            };
            assert_eq!(anchor.priority().as_str(), name);
        }
        for lie in ["bulk", "LIVE", "", "interactive"] {
            let bad = ManifestOffer::new(&bytes, lie, 11_000, 1, &peer);
            assert_eq!(
                policy.decide_manifest(&bad, &store, now),
                ManifestVerdict::Refused(ManifestRefusal::PriorityNotAFrozenClass {
                    found: lie.to_owned(),
                }),
                "unknown class {lie:?} must be refused"
            );
        }
    }

    /// Replication target below the store's minimum is refused.
    #[test]
    fn replication_target_below_minimum_is_refused() {
        let (manifest, _) = fixture(1);
        let store = DtnStoreImage::new();
        let peer = peer();
        let policy = PropagationPolicy::default();
        assert_eq!(
            policy.decide_manifest(
                &ManifestOffer::new(&manifest.to_wire_bytes(), "dtn", 11_000, 0, &peer),
                &store,
                1_000
            ),
            ManifestVerdict::Refused(ManifestRefusal::ReplicationTargetBelowMinimum { target: 0 })
        );
    }

    /// The store-full refusal fires exactly at the cap.
    #[test]
    fn full_store_refuses_new_custody() {
        let mut store = DtnStoreImage::new();
        // Fill to the cap with DISTINCT manifests (vary created_at so
        // the derived ids differ).
        for i in 0..MAX_BUNDLES {
            let content = format!("bundle-{i}");
            let (manifest, _) =
                ContentManifest::chunk(content.as_bytes(), 4, "app/test", None, 1 + i as u64)
                    .expect("valid content");
            store
                .admit_manifest(&manifest, ServicePriority::Dtn, 1_000, 11_000, 1)
                .expect("room left");
        }
        assert_eq!(store.bundle_count(), MAX_BUNDLES);
        let (offer_manifest, _) = fixture(1);
        let peer = peer();
        let policy = PropagationPolicy::default();
        assert_eq!(
            policy.decide_manifest(&offer(&offer_manifest.to_wire_bytes(), &peer), &store, 1_000),
            ManifestVerdict::Refused(ManifestRefusal::StoreFull {
                held: MAX_BUNDLES,
                cap: MAX_BUNDLES,
            })
        );
        // Dedup still works at capacity (a held bundle is no new
        // custody): a re-offer of a HELD manifest is a duplicate.
        let held = store.summaries()[0].clone();
        let held_bytes = store
            .manifest_bytes(held.content_id())
            .expect("held")
            .to_vec();
        assert_eq!(
            policy
                .decide_manifest(&offer(&held_bytes, &peer), &store, 1_000)
                .name(),
            "already_held"
        );
    }

    /// The chunk rules: accept → duplicate, through the store's own
    /// verification path.
    #[test]
    fn chunk_rules_accept_then_verified_duplicate() {
        let (manifest, chunks) = fixture(3);
        let mut store = DtnStoreImage::new();
        let policy = PropagationPolicy::default();
        let now = 1_000u64;
        let id = manifest.content_id();
        store
            .admit_manifest(&manifest, ServicePriority::Dtn, now, 11_000, 2)
            .expect("admit");
        // Slot 1: accepted with the committed expected length.
        let verdict = policy.decide_chunk(&ChunkOffer::new(id, 1, &chunks[1]), &store, now);
        assert_eq!(verdict.name(), "accept");
        let ChunkVerdict::Accept(anchor) = verdict else {
            unreachable!("checked name");
        };
        assert_eq!(anchor.slot(), 1);
        assert_eq!(anchor.expected_len(), 4);
        assert_eq!(anchor.content_id(), &id);
        // Store it, then re-offer the same bytes: verified duplicate.
        store
            .admit_chunk(&id, 1, &chunks[1], now)
            .expect("verified");
        assert_eq!(
            policy.decide_chunk(&ChunkOffer::new(id, 1, &chunks[1]), &store, now),
            ChunkVerdict::Duplicate { slot: 1 }
        );
        // The OTHER slots are still acceptable (slot-level dedup).
        assert_eq!(
            policy
                .decide_chunk(&ChunkOffer::new(id, 2, &chunks[2]), &store, now)
                .name(),
            "accept"
        );
    }

    /// A re-delivered slot with DIFFERENT bytes is an integrity
    /// refusal, never a duplicate (byte-identity is certified, not
    /// assumed).
    #[test]
    fn conflicting_slot_redelivery_is_an_integrity_refusal() {
        let (manifest, chunks) = fixture(2);
        let mut store = DtnStoreImage::new();
        let policy = PropagationPolicy::default();
        let now = 1_000u64;
        let id = manifest.content_id();
        store
            .admit_manifest(&manifest, ServicePriority::Dtn, now, 11_000, 2)
            .expect("admit");
        store
            .admit_chunk(&id, 0, &chunks[0], now)
            .expect("verified");
        // Same length, wrong bytes: the hash law refuses.
        let mut forged = chunks[0].clone();
        forged[0] ^= 0xff;
        assert_eq!(
            policy.decide_chunk(&ChunkOffer::new(id, 0, &forged), &store, now),
            ChunkVerdict::Refused(ChunkRefusal::ChunkHashMismatch { slot: 0 })
        );
        // Wrong length: the length law refuses BEFORE any hashing.
        assert_eq!(
            policy.decide_chunk(&ChunkOffer::new(id, 0, b"toolong"), &store, now),
            ChunkVerdict::Refused(ChunkRefusal::ChunkLengthWrong {
                slot: 0,
                found: 7,
                expected: 4,
            })
        );
    }

    /// Chunks for unknown content are refused — nothing orphaned.
    #[test]
    fn unknown_content_chunk_is_refused() {
        let store = DtnStoreImage::new();
        let policy = PropagationPolicy::default();
        let id = [0x11u8; CONTENT_ID_LEN];
        assert_eq!(
            policy.decide_chunk(&ChunkOffer::new(id, 0, b"data"), &store, 1_000),
            ChunkVerdict::Refused(ChunkRefusal::UnknownContent { content_id: id })
        );
    }

    /// Expired held bundles take no new chunks (the R6-003 law at the
    /// receiving edge).
    #[test]
    fn expired_bundle_takes_no_new_chunks() {
        let (manifest, chunks) = fixture(2);
        let mut store = DtnStoreImage::new();
        let policy = PropagationPolicy::default();
        let id = manifest.content_id();
        // Admitted at 1_000 with expiry 2_000; at 2_000 it is expired.
        store
            .admit_manifest(&manifest, ServicePriority::Dtn, 1_000, 2_000, 2)
            .expect("admit");
        assert_eq!(
            policy.decide_chunk(&ChunkOffer::new(id, 0, &chunks[0]), &store, 2_000),
            ChunkVerdict::Refused(ChunkRefusal::BundleExpired {
                now_unix: 2_000,
                expires_at_unix: 2_000,
            })
        );
    }

    /// Slot out of range is refused typed.
    #[test]
    fn slot_out_of_range_is_refused() {
        let (manifest, chunks) = fixture(2);
        let mut store = DtnStoreImage::new();
        let policy = PropagationPolicy::default();
        let id = manifest.content_id();
        store
            .admit_manifest(&manifest, ServicePriority::Dtn, 1_000, 11_000, 2)
            .expect("admit");
        assert_eq!(
            policy.decide_chunk(&ChunkOffer::new(id, 2, &chunks[0]), &store, 1_000),
            ChunkVerdict::Refused(ChunkRefusal::SlotOutOfRange {
                slot: 2,
                chunk_count: 2,
            })
        );
    }

    /// The composed manifest path: accept → bundle held + exactly one
    /// Received record from the offering peer; duplicates record
    /// nothing.
    #[test]
    fn take_custody_admits_and_records_once() {
        let (manifest, _) = fixture(2);
        let bytes = manifest.to_wire_bytes();
        let mut store = DtnStoreImage::new();
        let peer = peer();
        let policy = PropagationPolicy::default();
        let verdict = policy
            .take_custody(&mut store, &offer(&bytes, &peer), 1_000)
            .expect("apply");
        assert!(verdict.is_accept());
        assert!(store.holds_bundle(&manifest.content_id()));
        assert_eq!(store.evidence_count(), 1);
        assert_eq!(store.evidence()[0].kind().as_str(), "received");
        assert_eq!(store.evidence()[0].peer(), &peer);
        assert_eq!(store.evidence()[0].content_id(), &manifest.content_id());
        // Replay: already held, and NO new evidence.
        let replay = policy
            .take_custody(&mut store, &offer(&bytes, &peer), 1_050)
            .expect("apply");
        assert_eq!(replay.name(), "already_held");
        assert_eq!(store.evidence_count(), 1, "duplicates record nothing");
    }

    /// The composed chunk path stores only accepted chunks.
    #[test]
    fn receive_chunk_stores_only_accepted() {
        let (manifest, chunks) = fixture(2);
        let mut store = DtnStoreImage::new();
        let peer = peer();
        let policy = PropagationPolicy::default();
        let id = manifest.content_id();
        policy
            .take_custody(&mut store, &offer(&manifest.to_wire_bytes(), &peer), 1_000)
            .expect("admit");
        // No per-chunk custody records (bundle-level only).
        let v = policy
            .receive_chunk(&mut store, &ChunkOffer::new(id, 0, &chunks[0]), 1_000)
            .expect("apply");
        assert!(v.is_accept());
        assert!(store.holds_slot(&id, 0).expect("held"));
        assert_eq!(store.evidence_count(), 1, "chunks record no evidence");
        // Replay: duplicate, nothing new.
        let d = policy
            .receive_chunk(&mut store, &ChunkOffer::new(id, 0, &chunks[0]), 1_000)
            .expect("apply");
        assert_eq!(d, ChunkVerdict::Duplicate { slot: 0 });
        // A forged chunk: refused, nothing stored.
        let mut forged = chunks[1].clone();
        forged[2] ^= 0x01;
        let r = policy
            .receive_chunk(&mut store, &ChunkOffer::new(id, 1, &forged), 1_000)
            .expect("apply");
        assert_eq!(r.name(), "refused");
        assert!(!store.holds_slot(&id, 1).expect("held bundle"));
    }

    /// The ingestion order is the carry order: priority rank first,
    /// then expiry urgency (soonest first), then content id bytes.
    #[test]
    fn ingestion_order_is_the_carry_order() {
        let policy = PropagationPolicy::default();
        let mut anchors = vec![
            AcceptAnchor::new([3u8; 32], ServicePriority::Dtn, 9_000, 1, 1, 1),
            AcceptAnchor::new([2u8; 32], ServicePriority::Live, 8_000, 1, 1, 1),
            AcceptAnchor::new([1u8; 32], ServicePriority::Opportunistic, 7_000, 1, 1, 1),
            AcceptAnchor::new([9u8; 32], ServicePriority::Dtn, 5_000, 1, 1, 1),
            AcceptAnchor::new([4u8; 32], ServicePriority::Dtn, 5_000, 1, 1, 1),
        ];
        policy.order_for_ingest(&mut anchors);
        let order: Vec<([u8; 32], ServicePriority, u64)> = anchors
            .iter()
            .map(|a| (*a.content_id(), a.priority(), a.expires_at_unix()))
            .collect();
        assert_eq!(
            order,
            vec![
                ([2u8; 32], ServicePriority::Live, 8_000),
                ([1u8; 32], ServicePriority::Opportunistic, 7_000),
                ([4u8; 32], ServicePriority::Dtn, 5_000),
                ([9u8; 32], ServicePriority::Dtn, 5_000),
                ([3u8; 32], ServicePriority::Dtn, 9_000),
            ]
        );
    }

    /// The store's own admission APIs stay usable directly (the policy
    /// composes them, it does not replace them): the outcomes this
    /// policy's verdicts predict match the store's.
    #[test]
    fn store_apis_agree_with_the_verdicts() {
        let (manifest, chunks) = fixture(1);
        let mut store = DtnStoreImage::new();
        let peer = peer();
        let policy = PropagationPolicy::default();
        let id = manifest.content_id();
        // Manifest: policy Accept ↔ store Admitted.
        assert_eq!(
            policy.take_custody(&mut store, &offer(&manifest.to_wire_bytes(), &peer), 1_000)
                .expect("apply")
                .name(),
            "accept"
        );
        assert_eq!(
            store
                .admit_manifest(&manifest, ServicePriority::Live, 1_000, 99_999, 9)
                .expect("held"),
            ManifestAdmit::AlreadyPresent,
            "first admission's metadata wins (never a live upgrade)"
        );
        // Chunk: policy Accept ↔ store Admitted; policy Duplicate ↔
        // store Duplicate.
        assert_eq!(
            policy
                .receive_chunk(&mut store, &ChunkOffer::new(id, 0, &chunks[0]), 1_000)
                .expect("apply"),
            ChunkVerdict::Accept(ChunkAnchor::new(id, 0, 4))
        );
        assert_eq!(
            store.admit_chunk(&id, 0, &chunks[0], 1_000).expect("verified"),
            ChunkAdmit::Duplicate
        );
        // And the completed bundle reports complete.
        assert!(store.summary(&id).expect("held").complete());
    }

    /// Sanity: the fixture's chunk hashes really are the protocol
    /// core's (the anchor's expected_len mirrors the manifest law).
    #[test]
    fn fixture_hashes_come_from_the_protocol_core() {
        let (manifest, chunks) = fixture(2);
        for (slot, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk_hash(chunk), manifest.chunk_hashes()[slot]);
            assert_eq!(manifest.expected_chunk_len(slot), Some(4));
        }
    }
}
