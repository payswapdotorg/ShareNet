//! The store's read views: what a held bundle looks like, what the
//! carry-forward list says, and the outcomes of admission.

use crate::priority::ServicePriority;

/// The outcome of manifest admission (idempotent by design: re-delivery of
/// a held bundle is `AlreadyPresent`, never an error, never a second
/// record).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestAdmit {
    /// The bundle entered the store (first custody of this content id).
    Admitted,
    /// The store already holds this content id — idempotent re-delivery.
    /// First-admission metadata (priority/TTL/replication target) wins;
    /// re-delivery never extends a TTL or upgrades a priority.
    AlreadyPresent,
}

/// The outcome of chunk admission. In both cases the offered chunk WAS
/// verified against the manifest slot (length law, then hash law) before
/// any decision — an unverifiable chunk is a typed error, never an
/// outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChunkAdmit {
    /// The chunk verified and was newly stored under its slot.
    Admitted,
    /// The chunk verified but its slot was already held — byte-identical
    /// by construction (the manifest commits one hash per slot), so this
    /// is idempotent re-delivery: no new storage, no new file.
    Duplicate,
}

/// The TTL/terminal status of a held bundle at a caller-supplied clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleStatus {
    /// Held, unexpired, undelivered, with replication remaining: a
    /// carry-forward candidate.
    Live,
    /// Held, but `now >= expires_at_unix`: it never forwards again and is
    /// an `evict_expired` candidate (the data stays until evicted).
    Expired {
        /// The expiry bound that has passed.
        expires_at_unix: u64,
    },
    /// Terminally delivered: it never forwards again (a Delivered custody
    /// record exists); the data stays as a readable cache until TTL
    /// eviction.
    Delivered,
    /// Live and undelivered, but the replication target is exhausted
    /// (`replication_count >= replication_target`): not in the
    /// carry-forward list; still held.
    ReplicationExhausted,
}

impl BundleStatus {
    /// Stable machine name (probe + tests).
    pub fn as_str(&self) -> &'static str {
        match self {
            BundleStatus::Live => "live",
            BundleStatus::Expired { .. } => "expired",
            BundleStatus::Delivered => "delivered",
            BundleStatus::ReplicationExhausted => "replication_exhausted",
        }
    }
}

impl std::fmt::Display for BundleStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The store's view of one held bundle (the read view of a custody
/// record). All facts are persisted-state facts; TTL/terminal evaluation
/// happens against a caller clock (`DtnStoreImage::bundle_status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleSummary {
    content_id: [u8; crate::CONTENT_ID_LEN],
    priority: ServicePriority,
    admitted_at_unix: u64,
    expires_at_unix: u64,
    replication_count: u32,
    replication_target: u32,
    delivered: bool,
    chunk_count: u32,
    present_chunk_count: u32,
}

impl BundleSummary {
    pub(crate) fn new(
        content_id: [u8; crate::CONTENT_ID_LEN],
        priority: ServicePriority,
        admitted_at_unix: u64,
        expires_at_unix: u64,
        replication_count: u32,
        replication_target: u32,
        delivered: bool,
        chunk_count: u32,
        present_chunk_count: u32,
    ) -> Self {
        BundleSummary {
            content_id,
            priority,
            admitted_at_unix,
            expires_at_unix,
            replication_count,
            replication_target,
            delivered,
            chunk_count,
            present_chunk_count,
        }
    }

    /// The commitment-derived content id (L013 — SHA-256 of the manifest's
    /// canonical bytes).
    pub fn content_id(&self) -> &[u8; crate::CONTENT_ID_LEN] {
        &self.content_id
    }

    /// The carry priority (the frozen service class set).
    pub fn priority(&self) -> ServicePriority {
        self.priority
    }

    /// When the bundle entered this store (the admission caller clock).
    pub fn admitted_at_unix(&self) -> u64 {
        self.admitted_at_unix
    }

    /// The TTL bound: the bundle is expired at `now >= expires_at_unix`
    /// (valid strictly before it — the same exclusive-bound convention as
    /// the R5-003 freshness law).
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    /// How many times this bundle has been handed onward
    /// (`note_forwarded`).
    pub fn replication_count(&self) -> u32 {
        self.replication_count
    }

    /// The replication target supplied at admission.
    pub fn replication_target(&self) -> u32 {
        self.replication_target
    }

    /// The manifest's chunk count (how many slots a complete bundle has).
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// How many chunk slots this store holds (partial bundles hold
    /// subsets — R6-002 resume re-requests the rest).
    pub fn present_chunk_count(&self) -> u32 {
        self.present_chunk_count
    }

    /// Whether every manifest slot is held.
    pub fn complete(&self) -> bool {
        self.present_chunk_count == self.chunk_count
    }

    /// Whether terminal custody was marked (a Delivered evidence record
    /// exists — the bit is cross-checked against the log at every load).
    pub fn delivered(&self) -> bool {
        self.delivered
    }
}

/// One entry of the carry-forward list: a bundle that MAY be handed onward
/// at the evaluated clock. The list is ordered (priority rank, then expiry
/// urgency — soonest first — then content id bytes) and every entry has
/// `replication_remaining >= 1`, is unexpired and undelivered at the clock
/// the list was computed at.
///
/// What the entry does NOT decide: WHERE the bundle goes. Gateway
/// selection is gated by the R5-005 admission decision (the caller
/// composes this list with `GatewayAdmissionPolicy` — only `Eligible`
/// gateways receive bundles); the opportunistic forwarding policy that
/// makes that composition at contact time is R6-005.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardCandidate {
    summary: BundleSummary,
}

impl ForwardCandidate {
    pub(crate) fn new(summary: BundleSummary) -> Self {
        ForwardCandidate { summary }
    }

    /// The underlying bundle facts.
    pub fn summary(&self) -> &BundleSummary {
        &self.summary
    }

    /// The content id (the forwarder's handle for
    /// `DtnStore::manifest`/`read_chunk`).
    pub fn content_id(&self) -> &[u8; crate::CONTENT_ID_LEN] {
        self.summary.content_id()
    }

    /// The carry priority.
    pub fn priority(&self) -> ServicePriority {
        self.summary.priority()
    }

    /// The expiry bound (urgency signal: soonest first in the list).
    pub fn expires_at_unix(&self) -> u64 {
        self.summary.expires_at_unix()
    }

    /// The replication count so far.
    pub fn replication_count(&self) -> u32 {
        self.summary.replication_count()
    }

    /// The replication target.
    pub fn replication_target(&self) -> u32 {
        self.summary.replication_target()
    }

    /// `target - count` (saturating; always `>= 1` inside a list).
    pub fn replication_remaining(&self) -> u32 {
        self.summary
            .replication_target()
            .saturating_sub(self.summary.replication_count())
    }

    /// The manifest's chunk count.
    pub fn chunk_count(&self) -> u32 {
        self.summary.chunk_count()
    }

    /// How many chunk slots this store holds (a partial bundle forwards
    /// its manifest first; R6-002's resumable transfer completes the
    /// rest).
    pub fn present_chunk_count(&self) -> u32 {
        self.summary.present_chunk_count()
    }

    /// Whether every manifest slot is held.
    pub fn complete(&self) -> bool {
        self.summary.complete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> BundleSummary {
        BundleSummary::new(
            [7u8; 32],
            ServicePriority::Dtn,
            1_000,
            2_000,
            1,
            3,
            false,
            4,
            2,
        )
    }

    #[test]
    fn summary_getters_report_the_record() {
        let s = summary();
        assert_eq!(s.content_id(), &[7u8; 32]);
        assert_eq!(s.priority(), ServicePriority::Dtn);
        assert_eq!(s.admitted_at_unix(), 1_000);
        assert_eq!(s.expires_at_unix(), 2_000);
        assert_eq!(s.replication_count(), 1);
        assert_eq!(s.replication_target(), 3);
        assert_eq!(s.chunk_count(), 4);
        assert_eq!(s.present_chunk_count(), 2);
        assert!(!s.complete());
        assert!(!s.delivered());
    }

    #[test]
    fn candidate_replication_math_saturates() {
        let mut s = summary();
        assert_eq!(
            ForwardCandidate::new(s.clone()).replication_remaining(),
            2
        );
        s = BundleSummary::new([7u8; 32], ServicePriority::Dtn, 1_000, 2_000, 9, 3, false, 4, 4);
        // Saturating: a count grown past the target reports 0 remaining,
        // never underflow.
        assert_eq!(ForwardCandidate::new(s).replication_remaining(), 0);
    }

    #[test]
    fn statuses_have_stable_names() {
        assert_eq!(BundleStatus::Live.as_str(), "live");
        assert_eq!(
            BundleStatus::Expired { expires_at_unix: 5 }.as_str(),
            "expired"
        );
        assert_eq!(BundleStatus::Delivered.as_str(), "delivered");
        assert_eq!(
            BundleStatus::ReplicationExhausted.as_str(),
            "replication_exhausted"
        );
    }
}
