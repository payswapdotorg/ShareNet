//! The offer evidence — what the receiving edge is asked to decide on.
//!
//! Another node propagates content to THIS node in one of two shapes,
//! both modeled here as typed borrowed evidence (the R5-005 style: typed
//! evidence IN, pure decision OUT — no callbacks, no I/O, no clock):
//!
//! - a **manifest offer** ([`ManifestOffer`]): the canonical manifest
//!   bytes plus the carry metadata the carrying frame attaches (the
//!   service-class name, the TTL bound, the replication target) and the
//!   offering peer. This is exactly what an R6-002 `OFFER` message (plus
//!   its session's carry metadata) or a custody-forward frame delivers;
//!   the types here are carriage-neutral so the same rules apply over a
//!   future BPv7 adapter unchanged.
//! - a **chunk offer** ([`ChunkOffer`]): one chunk slot's bytes under a
//!   content id THIS node has already taken custody of (the manifest was
//!   accepted first — chunks for unknown content are refused typed, so
//!   nothing is ever stored orphaned).
//!
//! # Verify-don't-trust, applied to evidence shape
//!
//! Nothing in this module validates anything — that is the point: the
//! evidence is the OFFER'S OWN CLAIMS, and every claim is re-derived by
//! the policy before it can matter:
//!
//! - `manifest_bytes` are strict-parsed with the R6-001 invariants and
//!   the content id is RE-DERIVED from them (L013); `claimed_content_id`
//!   is only ever COMPARED against the derived id, never believed.
//! - `priority_name` is parsed only through the frozen service-class
//!   vocabulary (`ServicePriority::from_name`) — an unknown class name
//!   is a typed refusal, not a parse into some local vocabulary.
//! - `expires_at_unix` and `replication_target` are evaluated as the
//!   admission bounds they are, against the caller's clock and the
//!   store's own minimum — never recorded unexamined.
//!
//! A peer's claimed replication COUNT is deliberately absent from the
//! evidence: this node's replication count is this node's own fact (it
//! starts at 0 at admission), and a claim about it is unverifiable at
//! this layer — trusting one would be a caller-controlled boolean over
//! a security-relevant decision (see the replication-policy docs in
//! [`crate::policy`]).

use sharenet_dtn::{PeerRef, CONTENT_ID_LEN};

/// An offer of a manifest (plus carry metadata) from another node —
/// the receiving-side unit of decision for NEW custody.
///
/// All fields are the offer's own claims; the policy re-derives or
/// evaluates every one of them (see the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManifestOffer<'a> {
    /// The offered manifest's canonical CBOR bytes (the R6-002 `OFFER`
    /// payload shape). Strict-parsed by the policy; never trusted.
    pub manifest_bytes: &'a [u8],
    /// What the carrying frame CLAIMS the content id is, if it claims
    /// one at all (e.g. an R6-002 `COMPLETE`-style id assertion riding
    /// with the offer). `None` is the honest common case: the id is
    /// derived from the bytes. A claim that disagrees with the derived
    /// id is a typed refusal — the lie never gets stored.
    pub claimed_content_id: Option<&'a [u8; CONTENT_ID_LEN]>,
    /// The offered carry priority, as the wire's frozen class NAME
    /// (`live` / `opportunistic` / `dtn`). Parsed only through
    /// [`sharenet_dtn::ServicePriority::from_name`] — there is no
    /// second vocabulary.
    pub priority_name: &'a str,
    /// The offered TTL bound: the bundle is expired at
    /// `now >= expires_at_unix` (the R6-003 exclusive-bound
    /// convention). Evaluated against the CALLER's clock.
    pub expires_at_unix: u64,
    /// The offered replication target (how many onward hand-offs this
    /// bundle wants before it stops being a carry-forward candidate).
    /// Must be at least [`sharenet_dtn::REPLICATION_TARGET_MIN`].
    pub replication_target: u32,
    /// The offering peer (opaque, bounded — recorded in the Received
    /// custody evidence when custody is taken).
    pub peer: &'a PeerRef,
}

impl<'a> ManifestOffer<'a> {
    /// An offer with no content-id claim (the common case: the id is
    /// derived, not asserted).
    pub fn new(
        manifest_bytes: &'a [u8],
        priority_name: &'a str,
        expires_at_unix: u64,
        replication_target: u32,
        peer: &'a PeerRef,
    ) -> Self {
        ManifestOffer {
            manifest_bytes,
            claimed_content_id: None,
            priority_name,
            expires_at_unix,
            replication_target,
            peer,
        }
    }

    /// Attach a content-id CLAIM to the offer (the carrying frame
    /// asserted an id alongside the manifest bytes). The policy compares
    /// it to the derived id and refuses the offer typed on disagreement.
    pub fn with_claimed_content_id(mut self, claimed: &'a [u8; CONTENT_ID_LEN]) -> Self {
        self.claimed_content_id = Some(claimed);
        self
    }
}

/// An offer of one chunk slot's bytes under content this node already
/// holds — the receiving-side unit of decision for COMPLETING custody
/// (the R6-002 `CHUNK` message shape).
///
/// `content_id` is the RECEIVER'S OWN derived id from the session state
/// (the manifest was accepted first; the policy refuses chunks for
/// unknown content typed — nothing is ever stored orphaned). The bytes
/// are verified against the HELD manifest's slot commitment through the
/// store's own verification path ([`sharenet_dtn::DtnStoreImage::verify_chunk`]
/// — length law before hash law, never re-implemented here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkOffer<'a> {
    /// The content id this chunk belongs to (the receiver's derived id
    /// for an accepted manifest, not a peer claim).
    pub content_id: [u8; CONTENT_ID_LEN],
    /// The chunk's slot index under the held manifest.
    pub slot: usize,
    /// The offered chunk bytes (verified against the held manifest's
    /// slot commitment; an unverifiable chunk is NEVER accepted).
    pub bytes: &'a [u8],
}

impl<'a> ChunkOffer<'a> {
    /// A chunk offer for `slot` under `content_id`.
    pub fn new(content_id: [u8; CONTENT_ID_LEN], slot: usize, bytes: &'a [u8]) -> Self {
        ChunkOffer {
            content_id,
            slot,
            bytes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The evidence carries the offer's claims verbatim — no field is
    /// validated at construction (that is the policy's job, on purpose:
    /// the R5-005 evidence-in style).
    #[test]
    fn manifest_offer_carries_claims_verbatim() {
        let peer = PeerRef::new(&[1, 2, 3]).expect("valid peer");
        let offer = ManifestOffer::new(b"some-bytes", "dtn", 5_000, 2, &peer);
        assert_eq!(offer.manifest_bytes, b"some-bytes");
        assert_eq!(offer.claimed_content_id, None);
        assert_eq!(offer.priority_name, "dtn");
        assert_eq!(offer.expires_at_unix, 5_000);
        assert_eq!(offer.replication_target, 2);
        assert_eq!(offer.peer, &peer);
        let id = [9u8; CONTENT_ID_LEN];
        let claimed = offer.with_claimed_content_id(&id);
        assert_eq!(claimed.claimed_content_id, Some(&id));
        // The builder is consuming; the original is untouched (Copy).
        assert_eq!(offer.claimed_content_id, None);
    }

    /// A chunk offer is pure data: id, slot, borrowed bytes.
    #[test]
    fn chunk_offer_is_pure_data() {
        let offer = ChunkOffer::new([7u8; CONTENT_ID_LEN], 3, b"chunk");
        assert_eq!(offer.content_id, [7u8; CONTENT_ID_LEN]);
        assert_eq!(offer.slot, 3);
        assert_eq!(offer.bytes, b"chunk");
        assert_eq!(offer.clone(), offer);
    }
}
