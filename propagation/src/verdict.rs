//! The typed verdicts — the policy's output.
//!
//! Every rule family answers in a typed verdict with a stable machine
//! name (`name()` — the discipline of the codebase): there is no boolean,
//! no stringly-typed outcome and no partial state anywhere. A verdict is
//! one of exactly three shapes:
//!
//! - **Accept** — the offer is admissible; the anchor carries exactly
//!   what was decided (the derived content id, the parsed priority, the
//!   remaining life at the decision clock, ...), which is also the
//!   admission plan the composed apply path hands to the store.
//! - **Duplicate** — the content is already this node's (`AlreadyHeld`
//!   for a partial bundle, `AlreadyComplete` for a whole one; a chunk
//!   verdict's `Duplicate` means the slot verified byte-identical). A
//!   duplicate is a VERDICT, not an error: re-delivery is idempotent,
//!   never a second record, and the anchor reports the FIRST
//!   admission's metadata (re-delivery never extends a TTL or upgrades
//!   a priority — the R6-003 law, applied at the receiving edge).
//! - **Refused** — a typed refusal with the machine name of the rule
//!   that refused it. Fail-closed: any ambiguity, tamper, expiry,
//!   lie or capacity pressure lands here; nothing is stored.
//!
//! ## Refusal evaluation order (deterministic)
//!
//! The manifest rules form a chain (later checks depend on earlier
//! ones), so exactly ONE refusal is reported, in this fixed order:
//!
//! 1. evidence shape: manifest malformed → content-id claim disagrees →
//!    priority not a frozen class → manifest too large for the store;
//! 2. dedup: already held (`AlreadyComplete` if whole, else
//!    `AlreadyHeld` — duplicates, not refusals);
//! 3. TTL: expired at the offer clock → remaining life below the
//!    policy's minimum;
//! 4. replication target below the store's minimum;
//! 5. capacity: the store's bundle cap is reached.
//!
//! The chunk rules are the store's own verification chain in the
//! store's own order: unknown content → expired bundle → slot out of
//! range → length law → hash law (length BEFORE hash — the R6-001
//! discipline, never re-implemented here, applied through
//! [`sharenet_dtn::DtnStoreImage::verify_chunk`]).

use sharenet_dtn::{BundleStatus, BundleSummary, ServicePriority, CONTENT_ID_LEN};
use sharenet_protocol::ContentError;

/// What a manifest offer's acceptance rests on — and the exact
/// admission plan for the store (the derived id, the parsed priority,
/// the offered TTL bound and replication target; the chunk count the
/// manifest commits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptAnchor {
    content_id: [u8; CONTENT_ID_LEN],
    priority: ServicePriority,
    expires_at_unix: u64,
    remaining_secs: u64,
    replication_target: u32,
    chunk_count: u32,
}

impl AcceptAnchor {
    /// Assemble an acceptance anchor (the policy's constructor).
    pub(crate) fn new(
        content_id: [u8; CONTENT_ID_LEN],
        priority: ServicePriority,
        expires_at_unix: u64,
        remaining_secs: u64,
        replication_target: u32,
        chunk_count: u32,
    ) -> Self {
        AcceptAnchor {
            content_id,
            priority,
            expires_at_unix,
            remaining_secs,
            replication_target,
            chunk_count,
        }
    }

    /// The commitment-derived content id of the accepted manifest
    /// (re-derived by the policy — never the offer's claim).
    pub fn content_id(&self) -> &[u8; CONTENT_ID_LEN] {
        &self.content_id
    }

    /// The parsed carry priority (one of the frozen service classes).
    pub fn priority(&self) -> ServicePriority {
        self.priority
    }

    /// The accepted TTL bound (expired at `now >= expires_at_unix`).
    pub fn expires_at_unix(&self) -> u64 {
        self.expires_at_unix
    }

    /// The remaining life at the decision clock
    /// (`expires_at_unix - now`, `>= 1` by the hard gate).
    pub fn remaining_secs(&self) -> u64 {
        self.remaining_secs
    }

    /// The accepted replication target (`>= 1` by the store's minimum).
    pub fn replication_target(&self) -> u32 {
        self.replication_target
    }

    /// The manifest's chunk count (how many slots complete custody).
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }
}

/// What a duplicate manifest offer found in the store: the FIRST
/// admission's own record (summary) plus its typed TTL/terminal status
/// evaluated at the decision clock — the caller sees the truth of what
/// is held, not the re-offer's claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldAnchor {
    summary: BundleSummary,
    status: BundleStatus,
}

impl HeldAnchor {
    /// Assemble a held anchor (the policy's constructor).
    pub(crate) fn new(summary: BundleSummary, status: BundleStatus) -> Self {
        HeldAnchor { summary, status }
    }

    /// The held bundle's record (first-admission metadata; present
    /// chunk count; completeness; replication state).
    pub fn summary(&self) -> &BundleSummary {
        &self.summary
    }

    /// The held bundle's typed status at the decision clock
    /// (`live` / `expired` / `delivered` / `replication_exhausted`).
    pub fn status(&self) -> BundleStatus {
        self.status
    }

    /// The held content id.
    pub fn content_id(&self) -> &[u8; CONTENT_ID_LEN] {
        self.summary.content_id()
    }
}

/// The verdict on a manifest offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestVerdict {
    /// New custody is admissible: the manifest strict-parsed, its id
    /// re-derived (and any claim agreeing), its priority a frozen class,
    /// its remaining life above the floor, its target sane, the store
    /// below its bundle cap. The anchor is the admission plan.
    Accept(AcceptAnchor),
    /// The content id is already held but INCOMPLETE: the offer changes
    /// nothing (first admission wins) and missing slots may still arrive
    /// as chunk offers. Idempotent — never a second record.
    AlreadyHeld(HeldAnchor),
    /// The content id is already held and EVERY manifest slot is
    /// present: the offer is fully redundant. The held data stays as a
    /// readable cache until TTL eviction.
    AlreadyComplete(HeldAnchor),
    /// Typed refusal (fail-closed; one reason, see the module docs'
    /// fixed order).
    Refused(ManifestRefusal),
}

impl ManifestVerdict {
    /// Stable machine name: `accept` / `already_held` /
    /// `already_complete` / `refused`.
    pub fn name(&self) -> &'static str {
        match self {
            ManifestVerdict::Accept(_) => "accept",
            ManifestVerdict::AlreadyHeld(_) => "already_held",
            ManifestVerdict::AlreadyComplete(_) => "already_complete",
            ManifestVerdict::Refused(_) => "refused",
        }
    }

    /// Whether this verdict admits NEW custody (a derived accessor, not
    /// a trust input).
    pub fn is_accept(&self) -> bool {
        matches!(self, ManifestVerdict::Accept(_))
    }

    /// Whether this verdict is a duplicate (already held in either
    /// completeness shape).
    pub fn is_duplicate(&self) -> bool {
        matches!(
            self,
            ManifestVerdict::AlreadyHeld(_) | ManifestVerdict::AlreadyComplete(_)
        )
    }

    /// The typed refusal (only meaningful on `Refused`).
    pub fn refusal(&self) -> Option<&ManifestRefusal> {
        match self {
            ManifestVerdict::Refused(reason) => Some(reason),
            _ => None,
        }
    }
}

/// The verdict on a chunk offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkVerdict {
    /// The chunk verified against the held manifest's slot commitment
    /// (length law, then hash law — through the store's own path) and
    /// the slot is NEW: admissible for storage.
    Accept(ChunkAnchor),
    /// The chunk verified byte-identical to what the slot already
    /// holds (the manifest commits one hash per slot, so a verified
    /// re-delivery is byte-identical BY CONSTRUCTION). Idempotent —
    /// never a second file.
    Duplicate {
        /// The already-held slot.
        slot: u32,
    },
    /// Typed refusal (fail-closed; nothing is stored).
    Refused(ChunkRefusal),
}

impl ChunkVerdict {
    /// Stable machine name: `accept` / `duplicate` / `refused`.
    pub fn name(&self) -> &'static str {
        match self {
            ChunkVerdict::Accept(_) => "accept",
            ChunkVerdict::Duplicate { .. } => "duplicate",
            ChunkVerdict::Refused(_) => "refused",
        }
    }

    /// Whether this verdict admits a NEW chunk slot.
    pub fn is_accept(&self) -> bool {
        matches!(self, ChunkVerdict::Accept(_))
    }

    /// The typed refusal (only meaningful on `Refused`).
    pub fn refusal(&self) -> Option<&ChunkRefusal> {
        match self {
            ChunkVerdict::Refused(reason) => Some(reason),
            _ => None,
        }
    }
}

/// What a chunk acceptance rests on: the content id, the slot and the
/// held manifest's committed expected length (the law the bytes
/// satisfied).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkAnchor {
    content_id: [u8; CONTENT_ID_LEN],
    slot: u32,
    expected_len: u64,
}

impl ChunkAnchor {
    /// Assemble a chunk acceptance anchor (the policy's constructor).
    pub(crate) fn new(content_id: [u8; CONTENT_ID_LEN], slot: u32, expected_len: u64) -> Self {
        ChunkAnchor {
            content_id,
            slot,
            expected_len,
        }
    }

    /// The held content id the chunk belongs to.
    pub fn content_id(&self) -> &[u8; CONTENT_ID_LEN] {
        &self.content_id
    }

    /// The accepted slot index.
    pub fn slot(&self) -> u32 {
        self.slot
    }

    /// The manifest's committed expected length for the slot (what the
    /// offered bytes matched exactly).
    pub fn expected_len(&self) -> u64 {
        self.expected_len
    }
}

/// A typed refusal of a manifest offer. One reason per decision, in
/// the fixed order the module docs state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestRefusal {
    /// The manifest bytes failed the R6-001 strict parse (the typed
    /// cause from the protocol core — never a second opinion).
    ManifestMalformed {
        /// The protocol core's own typed parse failure.
        cause: ContentError,
    },
    /// The carrying frame CLAIMED a content id that disagrees with the
    /// id derived from the offered manifest bytes (L013) — a lie, typed
    /// and refused. Nothing is stored.
    ContentIdClaimDisagrees {
        /// The claim the offer made.
        claimed: [u8; CONTENT_ID_LEN],
        /// The id the manifest bytes actually derive.
        derived: [u8; CONTENT_ID_LEN],
    },
    /// The offered priority name is not one of the frozen service
    /// classes (`live` / `opportunistic` / `dtn`) — no second
    /// vocabulary, no future-class smuggling.
    PriorityNotAFrozenClass {
        /// The unknown name the offer carried.
        found: String,
    },
    /// The offered manifest's canonical bytes cannot fit the store's
    /// registry cap — refusing before admission, so the store's own
    /// `ManifestTooLarge` never has to fire on the receiving path.
    ManifestTooLarge {
        /// The offered byte length.
        bytes: usize,
        /// The store's registry cap ([`sharenet_dtn::MAX_REGISTRY_BYTES`]).
        max: u64,
    },
    /// The bundle is expired at the decision clock
    /// (`now >= expires_at_unix`): refused — an expired bundle never
    /// enters custody, whatever its priority.
    OfferExpired {
        /// The decision clock.
        now_unix: u64,
        /// The expiry bound that has passed.
        expires_at_unix: u64,
    },
    /// The bundle's remaining life is below the policy's minimum
    /// (nearly-dead bundles are eviction load, not carry capacity).
    RemainingLifeBelowMinimum {
        /// `expires_at_unix - now_unix` at the decision clock.
        remaining_secs: u64,
        /// The policy's configured minimum
        /// ([`crate::PropagationParams::min_remaining_ttl_secs`]).
        minimum_secs: u64,
    },
    /// The offered replication target is below the store's minimum: a
    /// bundle that may never be handed onward has no business entering
    /// a carry-forward store (the R6-003 law, applied at the edge).
    ReplicationTargetBelowMinimum {
        /// The offered target.
        target: u32,
    },
    /// The store's bundle cap is reached ([`sharenet_dtn::MAX_BUNDLES`])
    /// — capacity pressure refuses new custody; evict first.
    StoreFull {
        /// Bundles currently held.
        held: usize,
        /// The store's cap.
        cap: usize,
    },
}

impl ManifestRefusal {
    /// Stable machine name.
    pub fn name(&self) -> &'static str {
        match self {
            ManifestRefusal::ManifestMalformed { .. } => "manifest_malformed",
            ManifestRefusal::ContentIdClaimDisagrees { .. } => "content_id_claim_disagrees",
            ManifestRefusal::PriorityNotAFrozenClass { .. } => "priority_not_a_frozen_class",
            ManifestRefusal::ManifestTooLarge { .. } => "manifest_too_large",
            ManifestRefusal::OfferExpired { .. } => "offer_expired",
            ManifestRefusal::RemainingLifeBelowMinimum { .. } => {
                "remaining_life_below_minimum"
            }
            ManifestRefusal::ReplicationTargetBelowMinimum { .. } => {
                "replication_target_below_minimum"
            }
            ManifestRefusal::StoreFull { .. } => "store_full",
        }
    }
}

/// A typed refusal of a chunk offer. The chain mirrors the store's own
/// verification order exactly (unknown content → expired → slot range
/// → length law → hash law).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkRefusal {
    /// No manifest is held under this content id: chunks for unknown
    /// content are refused — nothing is ever stored orphaned (the
    /// manifest must be accepted first).
    UnknownContent {
        /// The content id the chunk claimed.
        content_id: [u8; CONTENT_ID_LEN],
    },
    /// The held bundle is expired at the decision clock: expired
    /// bundles take no new chunks (the R6-003 law, applied at the
    /// receiving edge).
    BundleExpired {
        /// The decision clock.
        now_unix: u64,
        /// The held bundle's expiry bound that has passed.
        expires_at_unix: u64,
    },
    /// The slot index is beyond the held manifest's chunk count.
    SlotOutOfRange {
        /// The offered slot.
        slot: usize,
        /// The manifest's chunk count.
        chunk_count: usize,
    },
    /// The offered bytes' length disagrees with the manifest slot's
    /// committed expected length (the length law, checked BEFORE any
    /// hashing — the R6-001 discipline).
    ChunkLengthWrong {
        /// The offered slot.
        slot: usize,
        /// The offered byte length.
        found: u64,
        /// The manifest's committed expected length.
        expected: u64,
    },
    /// The offered bytes' SHA-256 disagrees with the manifest slot's
    /// committed hash (the hash law — after the length law).
    ChunkHashMismatch {
        /// The offered slot.
        slot: usize,
    },
    /// The held bundle's stored manifest bytes failed re-parse during
    /// verification (store state inconsistency; fail-closed — the
    /// store itself would refuse the same way).
    ManifestMalformed {
        /// The protocol core's own typed parse failure.
        cause: ContentError,
    },
    /// The store refused the chunk in a way the receiving-edge rules
    /// do not model (a store-state disagreement the rules fail CLOSED
    /// on — nothing is stored). Carries the store error's stable
    /// machine name. `DtnStoreImage::verify_chunk` models exactly the
    /// six cases above, so this arm is future-proofing the fail-closed
    /// discipline, not an expected outcome.
    StoreStateUnexpected {
        /// The store error's machine name (diagnostic).
        name: &'static str,
    },
}

impl ChunkRefusal {
    /// Stable machine name.
    pub fn name(&self) -> &'static str {
        match self {
            ChunkRefusal::UnknownContent { .. } => "unknown_content",
            ChunkRefusal::BundleExpired { .. } => "bundle_expired",
            ChunkRefusal::SlotOutOfRange { .. } => "slot_out_of_range",
            ChunkRefusal::ChunkLengthWrong { .. } => "chunk_length_wrong",
            ChunkRefusal::ChunkHashMismatch { .. } => "chunk_hash_mismatch",
            ChunkRefusal::ManifestMalformed { .. } => "manifest_malformed",
            ChunkRefusal::StoreStateUnexpected { .. } => "store_state_unexpected",
        }
    }
}

impl std::fmt::Display for ManifestVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManifestVerdict::Accept(a) => write!(
                f,
                "accept {} ({}, expires {}, {}s remaining, target {}, {} chunks)",
                hex(a.content_id()),
                a.priority(),
                a.expires_at_unix(),
                a.remaining_secs(),
                a.replication_target(),
                a.chunk_count(),
            ),
            ManifestVerdict::AlreadyHeld(h) => write!(
                f,
                "already held {} ({}/{} chunks, {})",
                hex(h.content_id()),
                h.summary().present_chunk_count(),
                h.summary().chunk_count(),
                h.status(),
            ),
            ManifestVerdict::AlreadyComplete(h) => write!(
                f,
                "already complete {} ({}/{} chunks, {})",
                hex(h.content_id()),
                h.summary().present_chunk_count(),
                h.summary().chunk_count(),
                h.status(),
            ),
            ManifestVerdict::Refused(reason) => write!(f, "refused: {}", reason.name()),
        }
    }
}

impl std::fmt::Display for ChunkVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChunkVerdict::Accept(a) => write!(
                f,
                "accept chunk {} slot {} ({} bytes verified)",
                hex(a.content_id()),
                a.slot(),
                a.expected_len(),
            ),
            ChunkVerdict::Duplicate { slot } => {
                write!(f, "duplicate chunk slot {slot} (verified identical)")
            }
            ChunkVerdict::Refused(reason) => write!(f, "refused: {}", reason.name()),
        }
    }
}

impl std::fmt::Display for ManifestRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

impl std::fmt::Display for ChunkRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Lowercase hex (diagnostics only; the ids themselves are compared as
/// bytes everywhere).
fn hex(id: &[u8; CONTENT_ID_LEN]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn anchor() -> AcceptAnchor {
        AcceptAnchor::new(
            [7u8; CONTENT_ID_LEN],
            ServicePriority::Dtn,
            2_000,
            500,
            3,
            4,
        )
    }

    /// Every verdict shape has a stable machine name — the names the
    /// probe output, the tests and any caller parse.
    #[test]
    fn verdict_names_are_stable() {
        assert_eq!(ManifestVerdict::Accept(anchor()).name(), "accept");
        assert_eq!(
            ManifestVerdict::Refused(ManifestRefusal::OfferExpired {
                now_unix: 9,
                expires_at_unix: 8
            })
            .name(),
            "refused"
        );
        assert_eq!(ChunkVerdict::Duplicate { slot: 1 }.name(), "duplicate");
    }

    /// Every refusal has a stable machine name — one per rule, none
    /// reused.
    #[test]
    fn refusal_names_are_stable_and_distinct() {
        let id = [1u8; CONTENT_ID_LEN];
        let names = [
            ManifestRefusal::OfferExpired {
                now_unix: 0,
                expires_at_unix: 0,
            }
            .name(),
            ManifestRefusal::RemainingLifeBelowMinimum {
                remaining_secs: 0,
                minimum_secs: 1,
            }
            .name(),
            ManifestRefusal::ReplicationTargetBelowMinimum { target: 0 }.name(),
            ManifestRefusal::StoreFull { held: 1, cap: 1 }.name(),
            ManifestRefusal::PriorityNotAFrozenClass {
                found: "bulk".into(),
            }
            .name(),
            ManifestRefusal::ManifestTooLarge { bytes: 9, max: 1 }.name(),
            ManifestRefusal::ContentIdClaimDisagrees {
                claimed: id,
                derived: id,
            }
            .name(),
            ManifestRefusal::ManifestMalformed {
                cause: ContentError::ContentEmpty,
            }
            .name(),
        ];
        let expected = [
            "offer_expired",
            "remaining_life_below_minimum",
            "replication_target_below_minimum",
            "store_full",
            "priority_not_a_frozen_class",
            "manifest_too_large",
            "content_id_claim_disagrees",
            "manifest_malformed",
        ];
        assert_eq!(names, expected);
        // Distinct: no name collides (a rule is identifiable from its name).
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }

    /// Chunk refusal names cover the whole verification chain.
    #[test]
    fn chunk_refusal_names_are_stable_and_distinct() {
        let id = [1u8; CONTENT_ID_LEN];
        let names = [
            ChunkRefusal::UnknownContent { content_id: id }.name(),
            ChunkRefusal::BundleExpired {
                now_unix: 2,
                expires_at_unix: 1,
            }
            .name(),
            ChunkRefusal::SlotOutOfRange {
                slot: 9,
                chunk_count: 1,
            }
            .name(),
            ChunkRefusal::ChunkLengthWrong {
                slot: 0,
                found: 1,
                expected: 2,
            }
            .name(),
            ChunkRefusal::ChunkHashMismatch { slot: 0 }.name(),
            ChunkRefusal::ManifestMalformed {
                cause: ContentError::ContentEmpty,
            }
            .name(),
            ChunkRefusal::StoreStateUnexpected {
                name: "unmodeled",
            }
            .name(),
        ];
        assert_eq!(
            names,
            [
                "unknown_content",
                "bundle_expired",
                "slot_out_of_range",
                "chunk_length_wrong",
                "chunk_hash_mismatch",
                "manifest_malformed",
                "store_state_unexpected",
            ]
        );
        let mut sorted = names.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len());
    }

    /// The accept anchor reports the admission plan it was built from.
    #[test]
    fn accept_anchor_reports_the_plan() {
        let a = anchor();
        assert_eq!(a.content_id(), &[7u8; CONTENT_ID_LEN]);
        assert_eq!(a.priority(), ServicePriority::Dtn);
        assert_eq!(a.expires_at_unix(), 2_000);
        assert_eq!(a.remaining_secs(), 500);
        assert_eq!(a.replication_target(), 3);
        assert_eq!(a.chunk_count(), 4);
    }

    /// The derived accessors never lie about the shape they inspect.
    #[test]
    fn verdict_accessors_are_shape_honest() {
        let v = ManifestVerdict::Accept(anchor());
        assert!(v.is_accept());
        assert!(!v.is_duplicate());
        assert_eq!(v.refusal(), None);
        let refused = ManifestVerdict::Refused(ManifestRefusal::StoreFull { held: 1, cap: 1 });
        assert!(!refused.is_accept());
        assert!(!refused.is_duplicate());
        assert!(refused.refusal().is_some());
        let c = ChunkVerdict::Accept(ChunkAnchor::new([2u8; CONTENT_ID_LEN], 5, 64));
        assert!(c.is_accept());
        assert_eq!(c.refusal(), None);
        assert_eq!(ChunkVerdict::Duplicate { slot: 5 }.name(), "duplicate");
    }

    /// Displays are human diagnostics over the machine names.
    #[test]
    fn displays_render_without_panicking() {
        let v = ManifestVerdict::Accept(anchor());
        assert!(format!("{v}").starts_with("accept "));
        let d = ChunkVerdict::Duplicate { slot: 4 };
        assert_eq!(format!("{d}"), "duplicate chunk slot 4 (verified identical)");
        let r = ManifestRefusal::OfferExpired {
            now_unix: 2,
            expires_at_unix: 1,
        };
        assert_eq!(format!("{r}"), "offer_expired");
    }
}
