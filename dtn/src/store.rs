//! The DTN custody store — work item R6-003.
//!
//! This is ShareNet's local **store-carry-forward** layer (architecture
//! §12): the node-local custody store over R6-001 content manifests, the
//! durable persistence of carried bundles, the custody evidence log, and
//! the expiry-aware priority-ordered carry-forward list. It borrows
//! Delay-Tolerant Networking principles (custody, TTL, replication
//! counting) without rebuilding DTN concepts — BPv7 interoperability is a
//! future adapter, not this crate (the same law architecture §12 states).
//!
//! # The storage unit
//!
//! A bundle is a [`ContentManifest`] (R6-001) plus the chunk slots this
//! node holds under it. The manifest IS the named object — its
//! commitment-derived `content_id` (SHA-256 of its canonical CBOR bytes,
//! L013) is the bundle's identity everywhere in this store, and the
//! manifest's per-slot hashes are the ONLY integrity authority:
//!
//! - **Dedup** is by `(content_id, slot)`: re-delivering a held manifest
//!   is `AlreadyPresent`, re-delivering a held chunk is `Duplicate` —
//!   idempotent, never a second record, never a second file.
//! - **Integrity** is the manifest's chunk hash. A chunk is stored ONLY
//!   after its length matches its slot's expected length AND its SHA-256
//!   matches the manifest's committed hash (the R6-001 length-before-hash
//!   discipline: structurally wrong input is never hashed). An
//!   unverifiable chunk NEVER enters the store.
//! - **TTL** is a per-bundle `expires_at_unix` supplied at admission and
//!   evaluated ONLY against caller-supplied clocks — this crate has no
//!   wall clock, by the same law as the connectivity boundary and the
//!   admission policy. A bundle is expired at `now >= expires_at_unix`;
//!   expired bundles never forward and never take new chunks.
//! - **Priority** is the frozen service class set (`live` /
//!   `opportunistic` / `dtn`, ADR-003) — the typed
//!   [`crate::ServicePriority`], pinned to `sharenet_protocol::
//!   SERVICE_CLASSES` by test.
//! - **Replication** is counted per bundle (`note_forwarded`): the
//!   carry-forward list only offers bundles with replication remaining
//!   (`target - count >= 1`); the store itself applies no forwarding
//!   policy — R6-005 owns the contact-time decisions.
//!
//! # Restart semantics (the "restart" verify level)
//!
//! Following the R5-003 durable-store discipline exactly:
//!
//! 1. **Re-derive, never trust a summary.** On load, every stored manifest
//!    is strict-re-parsed, its content id is RE-DERIVED and cross-checked
//!    against the stored id ([`DtnError::ContentIdDisagrees`]), the
//!    persisted chunk-count summary is cross-checked against the
//!    re-parsed manifest ([`DtnError::ChunkCountDisagrees`]), and the
//!    persisted per-bundle delivered flag is cross-checked against the
//!    Delivered records re-derived from the evidence log
//!    ([`DtnError::DeliveredDisagrees`]). Any disagreement refuses the
//!    WHOLE store — no partial state.
//! 2. **Every stored chunk is re-hashed on load.** Trust nothing from
//!    disk: each chunk file is read, length-checked against its slot's
//!    expected length and SHA-256-checked against its manifest hash. A
//!    tampered, truncated or missing chunk file is a typed error and
//!    NOTHING loads. [`DtnStore::read_chunk`] re-verifies the same law on
//!    every read.
//! 3. **State survives restart.** The registry persists the manifest
//!    bytes, TTL/priority metadata, replication counts and the custody
//!    evidence log, so a reloaded store continues custody exactly where
//!    it stopped: dedup preserved (re-delivery is still `Duplicate`), the
//!    forward list identical, TTL math evaluated against the new
//!    caller's clock.
//! 4. **Corrupted registry fails closed.** Strict parsing (magic,
//!    version, flags, counts, lengths, CRC-32) plus the semantic
//!    cross-checks; every single-byte mutation of a valid registry is
//!    caught (proven by test), and so is every truncation.
//!
//! # Store layout and the crash discipline
//!
//! ```text
//! <dir>/registry.bin                       the registry image (this format)
//! <dir>/chunks/<hex-id>/<slot>.bin          one file per held chunk slot
//! <dir>/chunks/<hex-id>/<slot>.bin.tmp      scratch of an in-flight write
//! ```
//!
//! The registry is the authority for what the store holds; chunk files
//! carry only bytes (their integrity is the manifest's hash law, checked
//! at load and at read). All writes are atomic: temp file + `sync_all` +
//! rename. The fail-safe ORDER is fixed:
//!
//! - **Admit a chunk**: write (and fsync, and rename) the chunk file
//!   FIRST, then mark the slot present in the registry image; the registry
//!   is persisted only at [`DtnStore::flush`]. A crash between the two
//!   leaves an ORPHAN chunk file — never referenced by the registry,
//!   never read, harmless scratch (the same law as R5-003's stale `.tmp`).
//!   The dangerous direction (registry referencing a chunk that was
//!   never written) cannot happen.
//! - **Evict a bundle**: remove the registry record first, [`Self::flush`]
//!   (the replacement registry is durably in place), and only THEN delete
//!   the chunk files. A crash mid-eviction again leaves orphans, never
//!   dangling references.
//! - **Load**: reads ONLY the files the registry indexes. Unreferenced
//!   files in the chunks tree are ignored (scratch); referenced files are
//!   re-verified byte-for-byte.
//!
//! # Registry format (v1 — node-local durable state, NOT a wire object)
//!
//! Hand-rolled strict binary, little-endian, fixed-width (no serde, no
//! second CBOR profile — the manifest bytes inside are already canonical
//! CBOR from the protocol core). This file never crosses the network, so
//! the protocol registry does not govern it.
//!
//! ```text
//! offset  size  field
//! 0       4     magic = b"SNDS" (ShareNet DTN Store)
//! 4       2     format_version = 1 (REGISTRY_FORMAT_VERSION)
//! 6       2     flags = 0 (reserved; any nonzero is refused)
//! 8       4     bundle_count (u32)
//! 12      4     evidence_count (u32)
//! 16      4     body_len (u32) — byte length of the record section
//! 20      body_len  records
//! 20+body_len  4   crc32 (u32) — CRC-32/IEEE of bytes [0 .. 20+body_len)
//!
//! bundle records, sorted by strictly ascending content id:
//! 0       32    content_id (re-derived from the manifest bytes on load)
//! 32      1     priority tag (0=live 1=opportunistic 2=dtn)
//! 33      8     admitted_at_unix (u64)
//! 41      8     expires_at_unix (u64; must be > admitted_at_unix)
//! 49      4     replication_count (u32)
//! 53      4     replication_target (u32; must be >= 1)
//! 57      1     delivered flag (0/1; cross-checked against the log)
//! 58      4     chunk_count (u32; cross-checked against the manifest)
//! 62      8     manifest_len (u64)
//! 70      manifest_len  canonical manifest CBOR bytes
//!         4     present_slot_count (u32)
//!         present_slot_count × 4  slot numbers (u32), strictly
//!                                increasing, each < chunk_count
//!
//! evidence records, in append order:
//! 0       1     kind tag (0=received 1=forwarded 2=delivered)
//! 1       32    content_id
//! 33      8     at_unix (u64)
//! 41      1     peer_len (u8, 1..=64)
//! 42      peer_len  opaque peer ref bytes (never parsed)
//! ```
//!
//! # Platform independence (the wasm host seam)
//!
//! The pure model + registry codec ([`DtnStoreImage`]) compiles
//! everywhere including `wasm32-unknown-unknown`; only the file-backed
//! [`DtnStore`] is native (`#[cfg(not(target_family = "wasm"))]`). On a
//! wasm host the codec hands the registry bytes to the HOST's storage API
//! and the host persists chunk bytes itself, marking slots present
//! through the same [`DtnStoreImage`] methods after verifying them (the
//! module docs of each method state the law it enforces).
//!
//! The store is single-writer by design (`&mut self`, no interior
//! mutability, no file locking) — wrap it in the caller's mutex for
//! shared access, exactly like R5-003.

use std::collections::{BTreeMap, BTreeSet};

use sharenet_protocol::{chunk_hash, ContentManifest};

use crate::bundle::{
    BundleStatus, BundleSummary, ChunkAdmit, ForwardCandidate, ManifestAdmit,
};
use crate::error::DtnError;
#[cfg(not(target_family = "wasm"))]
use crate::error::StoreIoOp;
use crate::evidence::{CustodyKind, CustodyRecord, PeerRef, PEER_REF_MAX_BYTES};
use crate::priority::{priority_from_tag, ServicePriority};

#[cfg(not(target_family = "wasm"))]
use std::fs::{self, File};
#[cfg(not(target_family = "wasm"))]
use std::io::Write as _;
#[cfg(not(target_family = "wasm"))]
use std::path::{Path, PathBuf};

/// File magic: **SN**etnet **D**T**N** **S**tore.
pub const REGISTRY_MAGIC: [u8; 4] = *b"SNDS";
/// The registry format version this code writes and accepts (nothing else).
pub const REGISTRY_FORMAT_VERSION: u16 = 1;
/// Hard cap on the registry image size (read AND write side) — bounded
/// memory, fail-closed against hostile files.
pub const MAX_REGISTRY_BYTES: u64 = 4 * 1024 * 1024;
/// Hard cap on held bundles (fail-closed admission; evict first).
pub const MAX_BUNDLES: usize = 4096;
/// Hard cap on custody evidence records (append-only log; the archive is
/// R8-001's signed-receipt layer).
pub const MAX_EVIDENCE_RECORDS: usize = 16384;
/// The minimum replication target (a bundle that may never be handed
/// onward has no business entering a carry-forward store).
pub const REPLICATION_TARGET_MIN: u32 = 1;
/// Content id length (SHA-256, from the protocol core's manifest law).
pub const CONTENT_ID_LEN: usize = 32;

/// The registry file inside the store directory.
pub const REGISTRY_FILE_NAME: &str = "registry.bin";
/// The chunk tree inside the store directory.
pub const CHUNKS_DIR_NAME: &str = "chunks";

const HEADER_LEN: usize = 20;
const CRC_LEN: usize = 4;
/// content_id(32) + priority(1) + admitted(8) + expires(8) + count(4)
/// + target(4) + delivered(1) + chunk_count(4) + manifest_len(8)
const BUNDLE_FIXED_LEN: usize = 70;
const SLOT_BYTES: usize = 4;
/// kind(1) + content_id(32) + at(8) + peer_len(1)
const EVIDENCE_FIXED_LEN: usize = 42;
/// Cap on `Vec::with_capacity` for attacker-supplied counts (the body
/// bounds checks make larger counts fail anyway; this bounds allocation).
const MAX_SLOT_PREALLOC: usize = 131_072;

/// CRC-32/IEEE (the zlib polynomial `0xEDB88320`), bitwise — the registry
/// corruption detector. Private: format machinery, not a public service.
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in bytes {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// The bundle record (internal)
// ---------------------------------------------------------------------------

/// One held bundle: the persisted custody record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BundleRecord {
    priority: ServicePriority,
    admitted_at_unix: u64,
    expires_at_unix: u64,
    replication_count: u32,
    replication_target: u32,
    delivered: bool,
    /// Canonical manifest bytes (strict-re-parsed + content-id re-derived
    /// on every load — never trusted).
    manifest_bytes: Vec<u8>,
    /// Held chunk slots, strictly increasing.
    present_slots: Vec<u32>,
}

impl BundleRecord {
    fn parse_manifest(&self) -> Result<ContentManifest, DtnError> {
        ContentManifest::from_wire_bytes(&self.manifest_bytes)
            .map_err(|cause| DtnError::ManifestMalformed { cause })
    }
}

// ---------------------------------------------------------------------------
// The pure store image (model + registry codec)
// ---------------------------------------------------------------------------

/// The pure DTN store image: held bundles (manifest bytes + TTL/priority
/// metadata + present slots) and the custody evidence log, plus the
/// strict registry codec. This is what lives in `registry.bin` (and what
/// a wasm host persists through its own storage seam).
///
/// Chunk BYTES never live here — the image marks which slots are held
/// after they have been verified against the manifest; the bytes live in
/// the file-backed [`DtnStore`] (native) or the host's storage (wasm).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DtnStoreImage {
    bundles: BTreeMap<[u8; CONTENT_ID_LEN], BundleRecord>,
    evidence: Vec<CustodyRecord>,
}

impl DtnStoreImage {
    /// An empty store image.
    pub fn new() -> Self {
        Self::default()
    }

    /// How many bundles are held.
    pub fn bundle_count(&self) -> usize {
        self.bundles.len()
    }

    /// How many custody records are logged.
    pub fn evidence_count(&self) -> usize {
        self.evidence.len()
    }

    // -- bundle admission ---------------------------------------------------

    /// Admit a manifest into custody with its carry metadata. The content
    /// id is DERIVED from the manifest (L013 — never caller-supplied).
    ///
    /// Laws enforced (fail-closed, typed):
    /// - `expires_at_unix` must be strictly after `now_unix` (a bundle born
    ///   expired would never forward);
    /// - `replication_target` must be at least 1;
    /// - the manifest's canonical bytes must fit the registry cap;
    /// - idempotence: a content id already held is `AlreadyPresent` — the
    ///   FIRST admission's metadata (priority/TTL/target) wins, and
    ///   re-delivery never extends a TTL or upgrades a priority.
    pub fn admit_manifest(
        &mut self,
        manifest: &ContentManifest,
        priority: ServicePriority,
        now_unix: u64,
        expires_at_unix: u64,
        replication_target: u32,
    ) -> Result<ManifestAdmit, DtnError> {
        let content_id = manifest.content_id();
        if self.bundles.contains_key(&content_id) {
            return Ok(ManifestAdmit::AlreadyPresent);
        }
        if expires_at_unix <= now_unix {
            return Err(DtnError::ExpiryNotAfterNow {
                expires_at_unix,
                now_unix,
            });
        }
        if replication_target < REPLICATION_TARGET_MIN {
            return Err(DtnError::ReplicationTargetBelowMinimum {
                target: replication_target,
            });
        }
        let manifest_bytes = manifest.to_wire_bytes();
        if manifest_bytes.len() as u64 > MAX_REGISTRY_BYTES {
            return Err(DtnError::ManifestTooLarge {
                bytes: manifest_bytes.len(),
                max: MAX_REGISTRY_BYTES,
            });
        }
        if manifest.chunk_count() > u32::MAX as usize {
            return Err(DtnError::CountBeyondCap {
                what: "manifest chunk",
                found: manifest.chunk_count() as u64,
                max: u32::MAX as u64,
            });
        }
        if self.bundles.len() >= MAX_BUNDLES {
            return Err(DtnError::BundlesFull {
                count: self.bundles.len(),
                max: MAX_BUNDLES,
            });
        }
        self.bundles.insert(
            content_id,
            BundleRecord {
                priority,
                admitted_at_unix: now_unix,
                expires_at_unix,
                replication_count: 0,
                replication_target,
                delivered: false,
                manifest_bytes,
                present_slots: Vec::new(),
            },
        );
        Ok(ManifestAdmit::Admitted)
    }

    /// Verify an offered chunk against its manifest slot WITHOUT mutating
    /// anything: the file-backed store writes the chunk file first, then
    /// calls [`Self::mark_present`].
    ///
    /// Returns `true` when the slot is NEW (store it), `false` when it is
    /// already held (idempotent re-delivery — the bytes verified against
    /// the same slot commitment, so they are byte-identical by
    /// construction). Both paths have already enforced the integrity law:
    /// the length law runs BEFORE the hash law (never hash structurally
    /// wrong input), and a chunk that fails either is a typed error — an
    /// unverifiable chunk is NEVER stored.
    ///
    /// Expired bundles take no new chunks (`BundleExpired`).
    pub fn verify_chunk(
        &self,
        content_id: &[u8; CONTENT_ID_LEN],
        slot: usize,
        chunk: &[u8],
        now_unix: u64,
    ) -> Result<bool, DtnError> {
        let record = self
            .bundles
            .get(content_id)
            .ok_or(DtnError::UnknownContent { content_id: *content_id })?;
        if now_unix >= record.expires_at_unix {
            return Err(DtnError::BundleExpired {
                expires_at_unix: record.expires_at_unix,
                now_unix,
            });
        }
        let manifest = record.parse_manifest()?;
        let chunk_count = manifest.chunk_hashes().len();
        if slot >= chunk_count {
            return Err(DtnError::SlotOutOfRange { slot, chunk_count });
        }
        let expected = manifest
            .expected_chunk_len(slot)
            .expect("slot < chunk_count");
        let found = chunk.len() as u64;
        if found != expected {
            return Err(DtnError::ChunkLengthWrong { slot, found, expected });
        }
        if chunk_hash(chunk) != manifest.chunk_hashes()[slot] {
            return Err(DtnError::ChunkHashMismatch { slot });
        }
        let slot32 = u32::try_from(slot).expect("slot < chunk_count <= u32::MAX");
        Ok(record.present_slots.binary_search(&slot32).is_err())
    }

    /// Mark a verified chunk slot as held (strictly-increasing insert).
    /// Only call this AFTER the bytes are durably stored (the file-backed
    /// store writes the file first; a wasm host stores first, then marks).
    pub fn mark_present(&mut self, content_id: &[u8; CONTENT_ID_LEN], slot: usize) {
        let Some(record) = self.bundles.get_mut(content_id) else {
            return; // the caller verified against this bundle; nothing to do
        };
        let slot32 = u32::try_from(slot).expect("slot < chunk_count <= u32::MAX");
        if let Err(pos) = record.present_slots.binary_search(&slot32) {
            record.present_slots.insert(pos, slot32);
        }
    }

    /// The pure chunk-admission path (verify + mark), for hosts that store
    /// the bytes themselves (the wasm seam) and for image-level tests.
    pub fn admit_chunk(
        &mut self,
        content_id: &[u8; CONTENT_ID_LEN],
        slot: usize,
        chunk: &[u8],
        now_unix: u64,
    ) -> Result<ChunkAdmit, DtnError> {
        if self.verify_chunk(content_id, slot, chunk, now_unix)? {
            self.mark_present(content_id, slot);
            Ok(ChunkAdmit::Admitted)
        } else {
            Ok(ChunkAdmit::Duplicate)
        }
    }

    // -- queries -------------------------------------------------------------

    /// Whether a bundle is held under this content id.
    pub fn holds_bundle(&self, content_id: &[u8; CONTENT_ID_LEN]) -> bool {
        self.bundles.contains_key(content_id)
    }

    /// Whether a specific chunk slot of a held bundle is present
    /// (`UnknownContent` if the bundle is not held).
    pub fn holds_slot(
        &self,
        content_id: &[u8; CONTENT_ID_LEN],
        slot: u32,
    ) -> Result<bool, DtnError> {
        let record = self
            .bundles
            .get(content_id)
            .ok_or(DtnError::UnknownContent { content_id: *content_id })?;
        Ok(record.present_slots.binary_search(&slot).is_ok())
    }

    /// The held manifest (strict re-parse of the stored canonical bytes).
    pub fn manifest(
        &self,
        content_id: &[u8; CONTENT_ID_LEN],
    ) -> Result<ContentManifest, DtnError> {
        let record = self
            .bundles
            .get(content_id)
            .ok_or(DtnError::UnknownContent { content_id: *content_id })?;
        record.parse_manifest()
    }

    /// The held manifest's canonical bytes.
    pub fn manifest_bytes(
        &self,
        content_id: &[u8; CONTENT_ID_LEN],
    ) -> Result<&[u8], DtnError> {
        let record = self
            .bundles
            .get(content_id)
            .ok_or(DtnError::UnknownContent { content_id: *content_id })?;
        Ok(&record.manifest_bytes)
    }

    /// The read view of one held bundle (`None` when not held).
    pub fn summary(&self, content_id: &[u8; CONTENT_ID_LEN]) -> Option<BundleSummary> {
        let record = self.bundles.get(content_id)?;
        Some(BundleSummary::new(
            *content_id,
            record.priority,
            record.admitted_at_unix,
            record.expires_at_unix,
            record.replication_count,
            record.replication_target,
            record.delivered,
            record.manifest_chunk_count(),
            record.present_slots.len() as u32,
        ))
    }

    /// The read views of every held bundle, sorted by content id bytes.
    pub fn summaries(&self) -> Vec<BundleSummary> {
        self.bundles
            .iter()
            .map(|(id, record)| {
                BundleSummary::new(
                    *id,
                    record.priority,
                    record.admitted_at_unix,
                    record.expires_at_unix,
                    record.replication_count,
                    record.replication_target,
                    record.delivered,
                    record.manifest_chunk_count(),
                    record.present_slots.len() as u32,
                )
            })
            .collect()
    }

    /// The typed TTL/terminal status of a held bundle at a caller clock.
    pub fn bundle_status(
        &self,
        content_id: &[u8; CONTENT_ID_LEN],
        now_unix: u64,
    ) -> Result<BundleStatus, DtnError> {
        let record = self
            .bundles
            .get(content_id)
            .ok_or(DtnError::UnknownContent { content_id: *content_id })?;
        if record.delivered {
            return Ok(BundleStatus::Delivered);
        }
        if now_unix >= record.expires_at_unix {
            return Ok(BundleStatus::Expired {
                expires_at_unix: record.expires_at_unix,
            });
        }
        if record.replication_count >= record.replication_target {
            return Ok(BundleStatus::ReplicationExhausted);
        }
        Ok(BundleStatus::Live)
    }

    /// The held chunk slots of a bundle, ascending (`UnknownContent` when
    /// not held) — the R6-002 resume seam (what this node can already
    /// serve).
    pub fn present_slots(
        &self,
        content_id: &[u8; CONTENT_ID_LEN],
    ) -> Result<&[u32], DtnError> {
        let record = self
            .bundles
            .get(content_id)
            .ok_or(DtnError::UnknownContent { content_id: *content_id })?;
        Ok(&record.present_slots)
    }

    // -- carry-forward ------------------------------------------------------

    /// What to forward next at `now_unix`: every held bundle that is
    /// unexpired, undelivered and has replication remaining, ordered by
    /// (priority rank, expiry urgency — soonest first, content id bytes).
    ///
    /// The order is a pure function of the store state + clock
    /// (architecture §2 determinism): no hash-iteration dependence. What
    /// this list does NOT decide is WHERE a bundle goes — composing it
    /// with the R5-005 gateway admission decision (only `Eligible`
    /// gateways receive bundles) is the R6-005 opportunistic forwarder's
    /// job; this store is its storage layer.
    pub fn forward_candidates(&self, now_unix: u64) -> Vec<ForwardCandidate> {
        let mut candidates: Vec<ForwardCandidate> = self
            .bundles
            .iter()
            .filter(|(_, record)| {
                now_unix < record.expires_at_unix
                    && !record.delivered
                    && record.replication_count < record.replication_target
            })
            .map(|(id, record)| {
                ForwardCandidate::new(BundleSummary::new(
                    *id,
                    record.priority,
                    record.admitted_at_unix,
                    record.expires_at_unix,
                    record.replication_count,
                    record.replication_target,
                    record.delivered,
                    record.manifest_chunk_count(),
                    record.present_slots.len() as u32,
                ))
            })
            .collect();
        candidates.sort_by(|a, b| {
            let ka = (
                a.summary().priority(),
                a.summary().expires_at_unix(),
                *a.summary().content_id(),
            );
            let kb = (
                b.summary().priority(),
                b.summary().expires_at_unix(),
                *b.summary().content_id(),
            );
            ka.cmp(&kb)
        });
        candidates
    }

    // -- custody ------------------------------------------------------------

    /// Record that a HELD bundle was handed onward to `peer` at `at_unix`:
    /// appends the `Forwarded` custody record AND increments the
    /// replication count (its evidence twin). The count may grow past the
    /// target (the forwarder's policy decided it was worth it);
    /// `replication_remaining` saturates at zero.
    pub fn note_forwarded(
        &mut self,
        content_id: &[u8; CONTENT_ID_LEN],
        at_unix: u64,
        peer: &PeerRef,
    ) -> Result<(), DtnError> {
        let record = self
            .bundles
            .get_mut(content_id)
            .ok_or(DtnError::UnknownContent { content_id: *content_id })?;
        record.replication_count = record.replication_count.saturating_add(1);
        self.append_evidence(CustodyRecord::forwarded(*content_id, at_unix, peer))
    }

    /// Record terminal delivery of a bundle via `peer`: appends the
    /// `Delivered` custody record and, if the bundle is still held, sets
    /// its delivered flag (it never forwards again; the data stays as a
    /// readable cache until TTL eviction). Recording delivery of a bundle
    /// no longer held is allowed — custody evidence outlives the data
    /// (that is the R8 seam).
    pub fn mark_delivered(
        &mut self,
        content_id: &[u8; CONTENT_ID_LEN],
        at_unix: u64,
        peer: &PeerRef,
    ) -> Result<(), DtnError> {
        if let Some(record) = self.bundles.get_mut(content_id) {
            record.delivered = true;
        }
        self.append_evidence(CustodyRecord::delivered(*content_id, at_unix, peer))
    }

    /// Append a custody record verbatim (any kind, any content id — the
    /// log is append-only and unsigned; authentication and replay
    /// protection are R8-001's layer). Bounded by
    /// [`MAX_EVIDENCE_RECORDS`], fail-closed.
    pub fn record_evidence(&mut self, record: CustodyRecord) -> Result<(), DtnError> {
        self.append_evidence(record)
    }

    fn append_evidence(&mut self, record: CustodyRecord) -> Result<(), DtnError> {
        if self.evidence.len() >= MAX_EVIDENCE_RECORDS {
            return Err(DtnError::EvidenceLogFull {
                count: self.evidence.len(),
                max: MAX_EVIDENCE_RECORDS,
            });
        }
        self.evidence.push(record);
        Ok(())
    }

    /// The full custody evidence log, in append order.
    pub fn evidence(&self) -> &[CustodyRecord] {
        &self.evidence
    }

    /// The custody records for one content id, in append order.
    pub fn evidence_for(
        &self,
        content_id: &[u8; CONTENT_ID_LEN],
    ) -> Vec<&CustodyRecord> {
        self.evidence
            .iter()
            .filter(|r| r.content_id() == content_id)
            .collect()
    }

    // -- eviction -----------------------------------------------------------

    /// The bundles expired at `now_unix` (`now >= expires_at`), with their
    /// held slots — the file layer's deletion worklist.
    #[cfg(not(target_family = "wasm"))]
    pub(crate) fn expired_slots(
        &self,
        now_unix: u64,
    ) -> Vec<([u8; CONTENT_ID_LEN], Vec<u32>)> {
        self.bundles
            .iter()
            .filter(|(_, record)| now_unix >= record.expires_at_unix)
            .map(|(id, record)| (*id, record.present_slots.clone()))
            .collect()
    }

    /// Remove every bundle expired at `now_unix` (`now >= expires_at`),
    /// returning the evicted content ids. Custody evidence is NEVER
    /// evicted (delivery facts outlive the data — the R8 seam). Expired
    /// bundles never forward, so this changes no forward decision; it
    /// frees storage.
    pub fn evict_expired(&mut self, now_unix: u64) -> Vec<[u8; CONTENT_ID_LEN]> {
        let expired: Vec<[u8; CONTENT_ID_LEN]> = self
            .bundles
            .iter()
            .filter(|(_, record)| now_unix >= record.expires_at_unix)
            .map(|(id, _)| *id)
            .collect();
        for id in &expired {
            self.bundles.remove(id);
        }
        expired
    }

    // -- registry codec -----------------------------------------------------

    /// Serialize the image to the strict registry format. Deterministic:
    /// bundle records by ascending content id, evidence in append order,
    /// fixed-width little-endian fields.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DtnError> {
        let mut body: Vec<u8> = Vec::new();
        for (id, record) in &self.bundles {
            body.extend_from_slice(id);
            body.push(record.priority.tag());
            body.extend_from_slice(&record.admitted_at_unix.to_le_bytes());
            body.extend_from_slice(&record.expires_at_unix.to_le_bytes());
            body.extend_from_slice(&record.replication_count.to_le_bytes());
            body.extend_from_slice(&record.replication_target.to_le_bytes());
            body.push(u8::from(record.delivered));
            body.extend_from_slice(&record.manifest_chunk_count().to_le_bytes());
            body.extend_from_slice(&(record.manifest_bytes.len() as u64).to_le_bytes());
            body.extend_from_slice(&record.manifest_bytes);
            body.extend_from_slice(&(record.present_slots.len() as u32).to_le_bytes());
            for slot in &record.present_slots {
                body.extend_from_slice(&slot.to_le_bytes());
            }
        }
        for record in &self.evidence {
            body.push(record.kind().tag());
            body.extend_from_slice(record.content_id());
            body.extend_from_slice(&record.at_unix().to_le_bytes());
            let peer = record.peer().as_bytes();
            body.push(
                u8::try_from(peer.len()).expect("peer bounded at construction"),
            );
            body.extend_from_slice(peer);
        }
        let total = HEADER_LEN + body.len() + CRC_LEN;
        if total as u64 > MAX_REGISTRY_BYTES {
            return Err(DtnError::RegistryTooLarge {
                size: total as u64,
                max: MAX_REGISTRY_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&REGISTRY_MAGIC);
        out.extend_from_slice(&REGISTRY_FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags (reserved)
        out.extend_from_slice(&(self.bundles.len() as u32).to_le_bytes());
        out.extend_from_slice(&(self.evidence.len() as u32).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.extend_from_slice(&body);
        let crc = crc32(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        Ok(out)
    }

    /// Strict parse with the full re-derivation cross-check set (see the
    /// module docs). Any violation refuses the WHOLE image — no partial
    /// state is ever returned.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DtnError> {
        let len = bytes.len();
        if len as u64 > MAX_REGISTRY_BYTES {
            return Err(DtnError::RegistryTooLarge {
                size: len as u64,
                max: MAX_REGISTRY_BYTES,
            });
        }
        if len < HEADER_LEN + CRC_LEN {
            return Err(DtnError::LengthMismatch {
                expected: HEADER_LEN + CRC_LEN,
                actual: len,
            });
        }
        if bytes[0..4] != REGISTRY_MAGIC[..] {
            return Err(DtnError::BadMagic);
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().expect("4..6"));
        if version != REGISTRY_FORMAT_VERSION {
            return Err(DtnError::VersionUnsupported { found: version });
        }
        let flags = u16::from_le_bytes(bytes[6..8].try_into().expect("6..8"));
        if flags != 0 {
            return Err(DtnError::FlagsUnsupported { found: flags });
        }
        let bundle_count = u32::from_le_bytes(bytes[8..12].try_into().expect("8..12")) as u64;
        let evidence_count =
            u32::from_le_bytes(bytes[12..16].try_into().expect("12..16")) as u64;
        let body_len = u32::from_le_bytes(bytes[16..20].try_into().expect("16..20")) as u64;
        let expected_total = HEADER_LEN as u64 + body_len + CRC_LEN as u64;
        if expected_total != len as u64 {
            return Err(DtnError::LengthMismatch {
                expected: expected_total as usize,
                actual: len,
            });
        }
        let stored_crc = u32::from_le_bytes(
            bytes[len - CRC_LEN..].try_into().expect("crc trailer"),
        );
        let computed_crc = crc32(&bytes[..len - CRC_LEN]);
        if stored_crc != computed_crc {
            return Err(DtnError::ChecksumMismatch {
                found: stored_crc,
                expected: computed_crc,
            });
        }
        if bundle_count > MAX_BUNDLES as u64 {
            return Err(DtnError::CountBeyondCap {
                what: "bundle",
                found: bundle_count,
                max: MAX_BUNDLES as u64,
            });
        }
        if evidence_count > MAX_EVIDENCE_RECORDS as u64 {
            return Err(DtnError::CountBeyondCap {
                what: "evidence",
                found: evidence_count,
                max: MAX_EVIDENCE_RECORDS as u64,
            });
        }

        let body = &bytes[HEADER_LEN..HEADER_LEN + body_len as usize];
        let mut pos: usize = 0;
        let mut bundles: BTreeMap<[u8; CONTENT_ID_LEN], BundleRecord> = BTreeMap::new();
        let mut last_id: Option<[u8; CONTENT_ID_LEN]> = None;

        // -- bundle records --------------------------------------------------
        for _ in 0..bundle_count {
            if pos + BUNDLE_FIXED_LEN > body.len() {
                return Err(DtnError::LengthMismatch {
                    expected: pos + BUNDLE_FIXED_LEN,
                    actual: body.len(),
                });
            }
            let mut content_id = [0u8; CONTENT_ID_LEN];
            content_id.copy_from_slice(&body[pos..pos + CONTENT_ID_LEN]);
            pos += CONTENT_ID_LEN;
            let priority = priority_from_tag(body[pos])?;
            pos += 1;
            let admitted_at_unix = u64::from_le_bytes(
                body[pos..pos + 8].try_into().expect("8"),
            );
            pos += 8;
            let expires_at_unix = u64::from_le_bytes(
                body[pos..pos + 8].try_into().expect("8"),
            );
            pos += 8;
            if expires_at_unix <= admitted_at_unix {
                return Err(DtnError::ExpiryNotAfterAdmission {
                    expires_at_unix,
                    admitted_at_unix,
                });
            }
            let replication_count = u32::from_le_bytes(
                body[pos..pos + 4].try_into().expect("4"),
            );
            pos += 4;
            let replication_target = u32::from_le_bytes(
                body[pos..pos + 4].try_into().expect("4"),
            );
            pos += 4;
            if replication_target < REPLICATION_TARGET_MIN {
                return Err(DtnError::ReplicationTargetZeroOnDisk);
            }
            let delivered_byte = body[pos];
            pos += 1;
            if delivered_byte > 1 {
                return Err(DtnError::DeliveredTagInvalid {
                    found: delivered_byte,
                });
            }
            let delivered = delivered_byte == 1;
            let chunk_count = u32::from_le_bytes(
                body[pos..pos + 4].try_into().expect("4"),
            );
            pos += 4;
            let manifest_len = u64::from_le_bytes(
                body[pos..pos + 8].try_into().expect("8"),
            );
            pos += 8;
            let manifest_len = usize::try_from(manifest_len).map_err(|_| {
                DtnError::LengthMismatch {
                    expected: usize::MAX,
                    actual: body.len(),
                }
            })?;
            if pos + manifest_len > body.len() {
                return Err(DtnError::LengthMismatch {
                    expected: pos + manifest_len,
                    actual: body.len(),
                });
            }
            let manifest_bytes = body[pos..pos + manifest_len].to_vec();
            pos += manifest_len;
            // Trust nothing: strict re-parse + content-id re-derivation.
            let manifest = ContentManifest::from_wire_bytes(&manifest_bytes)
                .map_err(|cause| DtnError::ManifestMalformed { cause })?;
            let derived_id = manifest.content_id();
            if derived_id != content_id {
                return Err(DtnError::ContentIdDisagrees {
                    stored: content_id,
                    derived: derived_id,
                });
            }
            if manifest.chunk_count() as u64 != chunk_count as u64 {
                return Err(DtnError::ChunkCountDisagrees {
                    stored: chunk_count,
                    derived: manifest.chunk_count() as u32,
                });
            }
            if pos + 4 > body.len() {
                return Err(DtnError::LengthMismatch {
                    expected: pos + 4,
                    actual: body.len(),
                });
            }
            let slot_count = u32::from_le_bytes(
                body[pos..pos + 4].try_into().expect("4"),
            );
            pos += 4;
            let slot_count64 = slot_count as u64;
            if slot_count64 > MAX_SLOT_PREALLOC as u64 {
                return Err(DtnError::CountBeyondCap {
                    what: "slot",
                    found: slot_count64,
                    max: MAX_SLOT_PREALLOC as u64,
                });
            }
            let slots_bytes = slot_count64 as usize * SLOT_BYTES;
            if pos + slots_bytes > body.len() {
                return Err(DtnError::LengthMismatch {
                    expected: pos + slots_bytes,
                    actual: body.len(),
                });
            }
            let mut present_slots = Vec::with_capacity(slot_count64 as usize);
            let mut previous_slot: Option<u32> = None;
            for _ in 0..slot_count {
                let slot = u32::from_le_bytes(
                    body[pos..pos + SLOT_BYTES].try_into().expect("4"),
                );
                pos += SLOT_BYTES;
                if let Some(prev) = previous_slot {
                    if slot <= prev {
                        return Err(DtnError::SlotListNotIncreasing {
                            previous: prev,
                            next: slot,
                        });
                    }
                }
                if slot >= chunk_count {
                    return Err(DtnError::SlotBeyondManifest { slot, chunk_count });
                }
                previous_slot = Some(slot);
                present_slots.push(slot);
            }
            if let Some(prev) = last_id {
                if content_id == prev {
                    return Err(DtnError::DuplicateRecord { content_id });
                }
                if content_id < prev {
                    return Err(DtnError::RecordsNotAscending);
                }
            }
            last_id = Some(content_id);
            bundles.insert(
                content_id,
                BundleRecord {
                    priority,
                    admitted_at_unix,
                    expires_at_unix,
                    replication_count,
                    replication_target,
                    delivered,
                    manifest_bytes,
                    present_slots,
                },
            );
        }

        // -- evidence records ------------------------------------------------
        let mut evidence: Vec<CustodyRecord> = Vec::new();
        for _ in 0..evidence_count {
            if pos + EVIDENCE_FIXED_LEN > body.len() {
                return Err(DtnError::LengthMismatch {
                    expected: pos + EVIDENCE_FIXED_LEN,
                    actual: body.len(),
                });
            }
            let kind = CustodyKind::from_tag(body[pos])
                .ok_or(DtnError::EvidenceKindTagInvalid { found: body[pos] })?;
            pos += 1;
            let mut content_id = [0u8; CONTENT_ID_LEN];
            content_id.copy_from_slice(&body[pos..pos + CONTENT_ID_LEN]);
            pos += CONTENT_ID_LEN;
            let at_unix =
                u64::from_le_bytes(body[pos..pos + 8].try_into().expect("8"));
            pos += 8;
            let peer_len = body[pos] as usize;
            pos += 1;
            if peer_len == 0 || peer_len > PEER_REF_MAX_BYTES {
                return Err(DtnError::PeerRefInvalid { bytes: peer_len });
            }
            if pos + peer_len > body.len() {
                return Err(DtnError::LengthMismatch {
                    expected: pos + peer_len,
                    actual: body.len(),
                });
            }
            let peer = PeerRef::new(&body[pos..pos + peer_len])?;
            pos += peer_len;
            evidence.push(CustodyRecord::new(kind, content_id, at_unix, &peer));
        }

        if pos != body.len() {
            return Err(DtnError::TrailingBytes {
                extra: body.len() - pos,
            });
        }

        // -- the delivered-summary cross-check -------------------------------
        // The persisted delivered flag is never trusted blindly: a held
        // bundle is delivered iff its evidence log contains a Delivered
        // record (re-derived here from the log itself).
        let delivered_ids: BTreeSet<[u8; CONTENT_ID_LEN]> = evidence
            .iter()
            .filter(|r| r.kind() == CustodyKind::Delivered)
            .map(|r| *r.content_id())
            .collect();
        for (id, record) in &bundles {
            let derived = delivered_ids.contains(id);
            if record.delivered != derived {
                return Err(DtnError::DeliveredDisagrees {
                    content_id: *id,
                    persisted: record.delivered,
                    derived,
                });
            }
        }

        Ok(DtnStoreImage { bundles, evidence })
    }
}

impl BundleRecord {
    /// The re-derived chunk count summary (the persisted summary is
    /// cross-checked against this at load).
    fn manifest_chunk_count(&self) -> u32 {
        // The manifest was verified at admission and re-verified at load;
        // between loads this is derived from the stored bytes without
        // trusting the persisted summary.
        ContentManifest::from_wire_bytes(&self.manifest_bytes)
            .map(|m| m.chunk_count() as u32)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// The file-backed store (native only)
// ---------------------------------------------------------------------------

/// The file-backed DTN custody store: `registry.bin` + the chunk tree
/// under `chunks/`, following the R5-003 durable-store discipline (see the
/// module docs for the crash discipline and the format).
///
/// Single-writer by design; `flush` is the durability point for the
/// registry, chunk files are durable from their admission (each has its
/// own temp + fsync + rename), and evicted bundles' chunk files are
/// deleted only after the replacement registry is durably in place.
#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
pub struct DtnStore {
    dir: PathBuf,
    image: DtnStoreImage,
    /// Chunk files of evicted bundles, deleted by the NEXT flush (after
    /// the replacement registry is in place — the fail-safe order).
    pending_chunk_deletions: Vec<([u8; CONTENT_ID_LEN], u32)>,
    revalidated_at_unix: Option<u64>,
}

#[cfg(not(target_family = "wasm"))]
impl DtnStore {
    /// Create a NEW empty store at `dir` (the registry is flushed
    /// immediately). Refuses to clobber an existing registry — a store is
    /// either created once or loaded, never silently replaced.
    pub fn create(dir: &Path) -> Result<Self, DtnError> {
        let registry = Self::registry_path(dir);
        if registry.exists() {
            return Err(DtnError::StoreAlreadyExists);
        }
        fs::create_dir_all(Self::chunks_root(dir))
            .map_err(|e| DtnError::io(StoreIoOp::CreateStoreDir, e))?;
        let mut store = DtnStore {
            dir: dir.to_path_buf(),
            image: DtnStoreImage::new(),
            pending_chunk_deletions: Vec::new(),
            revalidated_at_unix: None,
        };
        store.flush()?;
        Ok(store)
    }

    /// Load the store from disk and RE-VALIDATE EVERYTHING (the restart
    /// law): the registry is strict-parsed with every cross-check
    /// (re-derived content ids, chunk-count summaries, delivered flags vs
    /// the evidence log, CRC, lengths), then every held chunk file is
    /// read back, length-checked against its manifest slot and
    /// RE-HASHED against the manifest commitment. A tampered, truncated
    /// or missing chunk file — or any registry corruption — is a typed
    /// error and NOTHING loads. Unreferenced files in the chunk tree are
    /// ignored (crash scratch; the registry is the authority).
    ///
    /// `now_unix` is the caller's clock at reload (this crate has no wall
    /// clock); it is recorded and surfaced through
    /// [`Self::revalidated_at_unix`]. TTL is evaluated at query time, so
    /// bundles that expired while the node was offline load normally and
    /// are excluded from [`Self::forward_candidates`] and removed by
    /// [`Self::evict_expired`].
    pub fn load(dir: &Path, now_unix: u64) -> Result<Self, DtnError> {
        let bytes = fs::read(Self::registry_path(dir))
            .map_err(|e| DtnError::io(StoreIoOp::ReadRegistry, e))?;
        let image = DtnStoreImage::from_bytes(&bytes)?;
        // Re-hash every stored chunk — trust nothing from disk.
        let summaries = image.summaries();
        for summary in &summaries {
            let id = summary.content_id();
            let manifest = image.manifest(id)?;
            for &slot in image.present_slots(id)? {
                let data = fs::read(Self::chunk_file(dir, id, slot))
                    .map_err(|e| DtnError::io(StoreIoOp::ReadChunk, e))?;
                let expected = manifest
                    .expected_chunk_len(slot as usize)
                    .expect("slot < chunk_count (validated at load)");
                if data.len() as u64 != expected {
                    return Err(DtnError::ChunkLengthWrong {
                        slot: slot as usize,
                        found: data.len() as u64,
                        expected,
                    });
                }
                if chunk_hash(&data) != manifest.chunk_hashes()[slot as usize] {
                    return Err(DtnError::ChunkHashMismatch {
                        slot: slot as usize,
                    });
                }
            }
        }
        Ok(DtnStore {
            dir: dir.to_path_buf(),
            image,
            pending_chunk_deletions: Vec::new(),
            revalidated_at_unix: Some(now_unix),
        })
    }

    /// The store directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The caller clock this store was re-validated against at load time
    /// (`None` for a freshly created store).
    pub fn revalidated_at_unix(&self) -> Option<u64> {
        self.revalidated_at_unix
    }

    /// The pure image this store persists (the wasm-host seam shape).
    pub fn image(&self) -> &DtnStoreImage {
        &self.image
    }

    /// Consume into the pure image (the wasm-host seam shape).
    pub fn into_image(self) -> DtnStoreImage {
        self.image
    }

    /// Admit a manifest into custody (see
    /// [`DtnStoreImage::admit_manifest`] for the laws). In-memory until
    /// [`Self::flush`].
    pub fn admit_manifest(
        &mut self,
        manifest: &ContentManifest,
        priority: ServicePriority,
        now_unix: u64,
        expires_at_unix: u64,
        replication_target: u32,
    ) -> Result<ManifestAdmit, DtnError> {
        self.image
            .admit_manifest(manifest, priority, now_unix, expires_at_unix, replication_target)
    }

    /// Admit one chunk under a held manifest: verify against the manifest
    /// slot (length law, then hash law — never store an unverifiable
    /// chunk), write the chunk file ATOMICALLY (temp + fsync + rename),
    /// then mark the slot present. The chunk file is durable from this
    /// call; the registry records it at the next [`Self::flush`].
    ///
    /// Dedup: a re-delivered (verified) chunk for a held slot is
    /// `Duplicate` — no new storage, no new file.
    pub fn admit_chunk(
        &mut self,
        content_id: &[u8; CONTENT_ID_LEN],
        slot: usize,
        chunk: &[u8],
        now_unix: u64,
    ) -> Result<ChunkAdmit, DtnError> {
        if !self.image.verify_chunk(content_id, slot, chunk, now_unix)? {
            return Ok(ChunkAdmit::Duplicate);
        }
        self.write_chunk_file(content_id, slot, chunk)?;
        self.image.mark_present(content_id, slot);
        Ok(ChunkAdmit::Admitted)
    }

    /// Read a held chunk back, RE-VERIFYING it against the manifest
    /// commitment (length + SHA-256) — the trust-nothing law applies on
    /// every read, not just at load.
    pub fn read_chunk(
        &self,
        content_id: &[u8; CONTENT_ID_LEN],
        slot: u32,
    ) -> Result<Vec<u8>, DtnError> {
        if !self.image.holds_slot(content_id, slot)? {
            return Err(DtnError::SlotNotHeld {
                content_id: *content_id,
                slot,
            });
        }
        let manifest = self.image.manifest(content_id)?;
        let data = fs::read(Self::chunk_file(&self.dir, content_id, slot))
            .map_err(|e| DtnError::io(StoreIoOp::ReadChunk, e))?;
        let expected = manifest
            .expected_chunk_len(slot as usize)
            .expect("slot < chunk_count (validated at admission)");
        if data.len() as u64 != expected {
            return Err(DtnError::ChunkLengthWrong {
                slot: slot as usize,
                found: data.len() as u64,
                expected,
            });
        }
        if chunk_hash(&data) != manifest.chunk_hashes()[slot as usize] {
            return Err(DtnError::ChunkHashMismatch {
                slot: slot as usize,
            });
        }
        Ok(data)
    }

    /// Record a forward (evidence + replication count). In-memory until
    /// [`Self::flush`].
    pub fn note_forwarded(
        &mut self,
        content_id: &[u8; CONTENT_ID_LEN],
        at_unix: u64,
        peer: &PeerRef,
    ) -> Result<(), DtnError> {
        self.image.note_forwarded(content_id, at_unix, peer)
    }

    /// Record terminal delivery (evidence + the never-forwards-again
    /// flag). In-memory until [`Self::flush`].
    pub fn mark_delivered(
        &mut self,
        content_id: &[u8; CONTENT_ID_LEN],
        at_unix: u64,
        peer: &PeerRef,
    ) -> Result<(), DtnError> {
        self.image.mark_delivered(content_id, at_unix, peer)
    }

    /// Append a custody record verbatim (the R8 seam's raw log). In-memory
    /// until [`Self::flush`].
    pub fn record_evidence(&mut self, record: CustodyRecord) -> Result<(), DtnError> {
        self.image.record_evidence(record)
    }

    /// The carry-forward list at a caller clock (see
    /// [`DtnStoreImage::forward_candidates`]).
    pub fn forward_candidates(&self, now_unix: u64) -> Vec<ForwardCandidate> {
        self.image.forward_candidates(now_unix)
    }

    /// Remove every bundle expired at `now_unix` (`now >= expires_at`),
    /// returning the evicted content ids. Custody evidence is never
    /// evicted. The bundle records are removed immediately (in-memory);
    /// the chunk files are deleted by the NEXT [`Self::flush`], AFTER the
    /// replacement registry is durably in place (the fail-safe order: a
    /// crash leaves orphans, never dangling references).
    pub fn evict_expired(&mut self, now_unix: u64) -> Vec<[u8; CONTENT_ID_LEN]> {
        let worklist = self.image.expired_slots(now_unix);
        for (id, slots) in &worklist {
            for slot in slots {
                self.pending_chunk_deletions.push((*id, *slot));
            }
        }
        self.image.evict_expired(now_unix)
    }

    /// Durably persist the registry: serialize in memory, write
    /// `registry.bin.tmp`, `sync_all`, rename over `registry.bin`, then
    /// delete evicted bundles' chunk files. Atomic — a crash leaves the
    /// previous complete registry, never a partial store.
    pub fn flush(&mut self) -> Result<(), DtnError> {
        let bytes = self.image.to_bytes()?;
        let tmp = {
            let mut os = Self::registry_path(&self.dir).into_os_string();
            os.push(".tmp");
            PathBuf::from(os)
        };
        let mut file =
            File::create(&tmp).map_err(|e| DtnError::io(StoreIoOp::WriteTemp, e))?;
        file.write_all(&bytes)
            .map_err(|e| DtnError::io(StoreIoOp::WriteTemp, e))?;
        file.sync_all()
            .map_err(|e| DtnError::io(StoreIoOp::SyncTemp, e))?;
        drop(file);
        fs::rename(&tmp, Self::registry_path(&self.dir))
            .map_err(|e| DtnError::io(StoreIoOp::RenameIntoPlace, e))?;
        // Only now (the replacement registry is in place) delete the
        // evicted bundles' chunk files. A crash mid-loop leaves orphans
        // that loads ignore; the queued work stays queued on failure.
        while let Some((id, slot)) = self.pending_chunk_deletions.pop() {
            match fs::remove_file(Self::chunk_file(&self.dir, &id, slot)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    self.pending_chunk_deletions.push((id, slot));
                    return Err(DtnError::io(StoreIoOp::RemoveChunkFile, e));
                }
            }
        }
        Ok(())
    }

    // -- path helpers --------------------------------------------------------

    fn registry_path(dir: &Path) -> PathBuf {
        dir.join(REGISTRY_FILE_NAME)
    }

    fn chunks_root(dir: &Path) -> PathBuf {
        dir.join(CHUNKS_DIR_NAME)
    }

    fn chunk_file(dir: &Path, id: &[u8; CONTENT_ID_LEN], slot: u32) -> PathBuf {
        Self::chunks_root(dir)
            .join(crate::hex::encode(id))
            .join(format!("{slot}.bin"))
    }

    fn write_chunk_file(
        &self,
        content_id: &[u8; CONTENT_ID_LEN],
        slot: usize,
        chunk: &[u8],
    ) -> Result<(), DtnError> {
        let bundle_dir = Self::chunks_root(&self.dir).join(crate::hex::encode(content_id));
        if !bundle_dir.is_dir() {
            fs::create_dir_all(&bundle_dir)
                .map_err(|e| DtnError::io(StoreIoOp::CreateChunkDir, e))?;
        }
        let slot32 = u32::try_from(slot).expect("slot < chunk_count <= u32::MAX");
        let final_path = bundle_dir.join(format!("{slot32}.bin"));
        let tmp_path = bundle_dir.join(format!("{slot32}.bin.tmp"));
        let mut file =
            File::create(&tmp_path).map_err(|e| DtnError::io(StoreIoOp::WriteTemp, e))?;
        file.write_all(chunk)
            .map_err(|e| DtnError::io(StoreIoOp::WriteTemp, e))?;
        file.sync_all()
            .map_err(|e| DtnError::io(StoreIoOp::SyncTemp, e))?;
        drop(file);
        fs::rename(&tmp_path, &final_path)
            .map_err(|e| DtnError::io(StoreIoOp::RenameIntoPlace, e))?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests — the pure image's laws
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::{BundleStatus, ChunkAdmit, ManifestAdmit};
    use crate::evidence::{CustodyKind, PeerRef};
    use crate::priority::ServicePriority;
    use sharenet_protocol::MetadataValue;
    use std::collections::BTreeMap;

    /// Deterministic test content: `len` patterned bytes.
    fn content(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_add(i as u8).wrapping_mul(31))
            .collect()
    }

    /// A manifest + its chunks (chunk_size 12, so multi-chunk with a short
    /// last chunk for most lengths).
    fn manifest(seed: u8, len: usize) -> (ContentManifest, Vec<Vec<u8>>) {
        ContentManifest::chunk(&content(seed, len), 12, "text/plain", None, 1_700_000_000)
            .expect("valid content")
    }

    fn peer(tag: u8) -> PeerRef {
        PeerRef::new(&[tag; 4]).expect("bounded")
    }

    const NOW: u64 = 1_700_000_500;
    const EXPIRY: u64 = NOW + 3_600;

    fn admit(
        image: &mut DtnStoreImage,
        seed: u8,
        len: usize,
        priority: ServicePriority,
        expiry: u64,
    ) -> [u8; CONTENT_ID_LEN] {
        let (m, _) = manifest(seed, len);
        let id = m.content_id();
        assert_eq!(
            image.admit_manifest(&m, priority, NOW, expiry, 3),
            Ok(ManifestAdmit::Admitted)
        );
        id
    }

    // -- manifest admission ---------------------------------------------------

    #[test]
    fn manifest_admission_is_idempotent_first_metadata_wins() {
        let mut image = DtnStoreImage::new();
        let (m, _) = manifest(1, 40);
        let id = m.content_id();
        assert_eq!(
            image.admit_manifest(&m, ServicePriority::Dtn, NOW, EXPIRY, 1),
            Ok(ManifestAdmit::Admitted)
        );
        // Re-delivery with DIFFERENT metadata: AlreadyPresent, first wins.
        assert_eq!(
            image.admit_manifest(&m, ServicePriority::Live, NOW, EXPIRY + 99_999, 7),
            Ok(ManifestAdmit::AlreadyPresent)
        );
        let s = image.summary(&id).expect("held");
        assert_eq!(s.priority(), ServicePriority::Dtn);
        assert_eq!(s.expires_at_unix(), EXPIRY);
        assert_eq!(s.replication_target(), 1);
        assert_eq!(image.bundle_count(), 1, "no second record");
    }

    #[test]
    fn born_expired_manifest_is_refused_typed() {
        let mut image = DtnStoreImage::new();
        let (m, _) = manifest(1, 40);
        assert_eq!(
            image.admit_manifest(&m, ServicePriority::Dtn, NOW, NOW, 1),
            Err(DtnError::ExpiryNotAfterNow {
                expires_at_unix: NOW,
                now_unix: NOW,
            })
        );
        assert_eq!(
            image.admit_manifest(&m, ServicePriority::Dtn, NOW, NOW - 1, 1),
            Err(DtnError::ExpiryNotAfterNow {
                expires_at_unix: NOW - 1,
                now_unix: NOW,
            })
        );
        assert_eq!(image.bundle_count(), 0, "nothing stored");
    }

    #[test]
    fn admission_validates_target_and_bounds() {
        let mut image = DtnStoreImage::new();
        let (m, _) = manifest(1, 40);
        assert_eq!(
            image.admit_manifest(&m, ServicePriority::Dtn, NOW, EXPIRY, 0),
            Err(DtnError::ReplicationTargetBelowMinimum { target: 0 })
        );
        assert!(image.admit_manifest(&m, ServicePriority::Dtn, NOW, EXPIRY, 1).is_ok());
    }

    // -- chunk admission: integrity + dedup -----------------------------------

    #[test]
    fn chunk_admission_verifies_then_dedups() {
        let mut image = DtnStoreImage::new();
        let (m, chunks) = manifest(7, 40); // 40 bytes / 12 = 4 chunks
        let id = m.content_id();
        image
            .admit_manifest(&m, ServicePriority::Opportunistic, NOW, EXPIRY, 3)
            .unwrap();
        assert_eq!(m.chunk_count(), 4);
        // Fresh: not held, status live, zero present.
        assert_eq!(image.summary(&id).unwrap().present_chunk_count(), 0);
        // Admit each chunk: Admitted, then re-delivery: Duplicate.
        for (slot, chunk) in chunks.iter().enumerate() {
            assert_eq!(
                image.admit_chunk(&id, slot, chunk, NOW),
                Ok(ChunkAdmit::Admitted)
            );
            assert_eq!(
                image.admit_chunk(&id, slot, chunk, NOW),
                Ok(ChunkAdmit::Duplicate)
            );
        }
        let s = image.summary(&id).unwrap();
        assert_eq!(s.present_chunk_count(), 4);
        assert!(s.complete());
        assert_eq!(image.present_slots(&id).unwrap(), [0, 1, 2, 3]);
    }

    #[test]
    fn unverifiable_chunks_are_never_stored() {
        let mut image = DtnStoreImage::new();
        let (m, chunks) = manifest(7, 40);
        let id = m.content_id();
        image
            .admit_manifest(&m, ServicePriority::Dtn, NOW, EXPIRY, 3)
            .unwrap();
        // Unknown content id.
        assert_eq!(
            image.admit_chunk(&[9u8; 32], 0, &chunks[0], NOW),
            Err(DtnError::UnknownContent { content_id: [9u8; 32] })
        );
        // Slot past the manifest.
        assert_eq!(
            image.admit_chunk(&id, 4, &chunks[3], NOW),
            Err(DtnError::SlotOutOfRange { slot: 4, chunk_count: 4 })
        );
        // Wrong length (short and long) — the length law first.
        let short = &chunks[0][..5];
        assert_eq!(
            image.admit_chunk(&id, 0, short, NOW),
            Err(DtnError::ChunkLengthWrong {
                slot: 0,
                found: 5,
                expected: 12,
            })
        );
        let mut long = chunks[0].clone();
        long.push(0xaa);
        assert_eq!(
            image.admit_chunk(&id, 0, &long, NOW),
            Err(DtnError::ChunkLengthWrong {
                slot: 0,
                found: 13,
                expected: 12,
            })
        );
        // Right length, wrong bytes — the hash law.
        let mut wrong = chunks[0].clone();
        wrong[0] ^= 0xff;
        assert_eq!(
            image.admit_chunk(&id, 0, &wrong, NOW),
            Err(DtnError::ChunkHashMismatch { slot: 0 })
        );
        // Nothing was stored by any failed path.
        assert_eq!(image.summary(&id).unwrap().present_chunk_count(), 0);
        // A DIFFERENT (verified) chunk for a HELD slot is still refused:
        // the manifest commits one hash per slot, so other bytes can only
        // fail it.
        assert_eq!(
            image.admit_chunk(&id, 0, &chunks[1], NOW),
            Err(DtnError::ChunkHashMismatch { slot: 0 })
        );
        // Expired bundles take no new chunks.
        assert_eq!(
            image.admit_chunk(&id, 0, &chunks[0], EXPIRY),
            Err(DtnError::BundleExpired {
                expires_at_unix: EXPIRY,
                now_unix: EXPIRY,
            })
        );
    }

    // -- TTL + status ---------------------------------------------------------

    #[test]
    fn ttl_math_is_exclusive_bound_against_the_caller_clock() {
        let mut image = DtnStoreImage::new();
        let id = admit(&mut image, 3, 40, ServicePriority::Dtn, EXPIRY);
        // Valid strictly BEFORE the bound; expired AT it.
        assert_eq!(image.bundle_status(&id, EXPIRY - 1), Ok(BundleStatus::Live));
        assert_eq!(
            image.bundle_status(&id, EXPIRY),
            Ok(BundleStatus::Expired { expires_at_unix: EXPIRY })
        );
        assert_eq!(
            image.bundle_status(&id, EXPIRY + 1),
            Ok(BundleStatus::Expired { expires_at_unix: EXPIRY })
        );
        // The clock is a parameter, not state: the same query at the same
        // clock always decides the same way.
        assert_eq!(image.bundle_status(&id, EXPIRY - 1), Ok(BundleStatus::Live));
    }

    #[test]
    fn expired_bundles_never_forward_or_take_chunks_even_at_dominant_priority() {
        // The adversarial TTL case: a TOP-priority bundle past its expiry
        // must be invisible to carry-forward (and refuse new chunks),
        // while an unexpired LOWEST-priority bundle still carries. Expiry
        // gates BEFORE priority — no inversion is possible.
        let mut image = DtnStoreImage::new();
        let live_short = admit(&mut image, 6, 40, ServicePriority::Live, NOW + 100);
        let dtn_long = admit(&mut image, 7, 40, ServicePriority::Dtn, NOW + 3_600);
        let (_, chunks6) = manifest(6, 40);

        // Before expiry: the live bundle dominates the carry order.
        let list = image.forward_candidates(NOW + 99);
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].content_id(), &live_short);
        // Chunks are admissible before expiry.
        assert!(image.verify_chunk(&live_short, 0, &chunks6[0], NOW + 99).unwrap());

        // AT the bound: the expired bundle is ABSENT despite the dominant
        // priority and its untouched replication budget.
        let list = image.forward_candidates(NOW + 100);
        assert_eq!(list.len(), 1, "expired never forwards");
        assert_eq!(list[0].content_id(), &dtn_long);

        // And it takes no new chunks: typed refusal, no partial storage.
        let err = image
            .verify_chunk(&live_short, 1, &chunks6[1], NOW + 100)
            .unwrap_err();
        assert!(matches!(err, DtnError::BundleExpired { .. }));
        assert_eq!(err.name(), "bundle_expired");
        // Nothing was stored by the refused admission.
        assert!(image.present_slots(&live_short).unwrap().is_empty());

        // The unexpired lowest-priority bundle still carries.
        assert!(
            image
                .forward_candidates(NOW + 101)
                .iter()
                .any(|c| c.content_id() == &dtn_long)
        );
    }

    // -- carry-forward ordering ----------------------------------------------

    #[test]
    fn forward_candidates_order_priority_then_expiry_then_id() {
        let mut image = DtnStoreImage::new();
        // Same priority, different expiries: soonest first.
        let dtn_far = admit(&mut image, 1, 40, ServicePriority::Dtn, NOW + 10_000);
        let dtn_soon = admit(&mut image, 2, 40, ServicePriority::Dtn, NOW + 100);
        // Higher classes sort before dtn regardless of expiry.
        let opp = admit(&mut image, 3, 40, ServicePriority::Opportunistic, NOW + 50_000);
        let live = admit(&mut image, 4, 40, ServicePriority::Live, NOW + 90_000);
        // Same priority AND expiry: content id bytes break the tie.
        let tie = admit(&mut image, 5, 40, ServicePriority::Dtn, NOW + 100);
        let list = image.forward_candidates(NOW);
        let ids: Vec<_> = list.iter().map(|c| *c.content_id()).collect();
        // Expected: live, opportunistic, then the dtn class by expiry then id.
        let mut dtn_tail = vec![dtn_soon, tie, dtn_far];
        dtn_tail.sort_by(|a, b| {
            let ea = image.summary(a).unwrap().expires_at_unix();
            let eb = image.summary(b).unwrap().expires_at_unix();
            ea.cmp(&eb).then(a.cmp(b))
        });
        let expected = [vec![live, opp], dtn_tail].concat();
        assert_eq!(ids, expected);
        // Pure function of state + clock: identical on re-query.
        assert_eq!(image.forward_candidates(NOW), list);
    }

    // -- replication + custody --------------------------------------------------

    #[test]
    fn note_forwarded_counts_and_evidences() {
        let mut image = DtnStoreImage::new();
        let id = admit(&mut image, 3, 40, ServicePriority::Dtn, EXPIRY);
        image.note_forwarded(&id, NOW + 5, &peer(0x11)).unwrap();
        image.note_forwarded(&id, NOW + 6, &peer(0x22)).unwrap();
        let s = image.summary(&id).unwrap();
        assert_eq!(s.replication_count(), 2);
        let ev = image.evidence_for(&id);
        assert_eq!(ev.len(), 2);
        assert_eq!(ev[0].kind(), CustodyKind::Forwarded);
        assert_eq!(ev[0].peer().as_bytes(), &[0x11; 4]);
        assert_eq!(ev[1].peer().as_bytes(), &[0x22; 4]);
        // Unknown bundle: typed refusal.
        assert_eq!(
            image.note_forwarded(&[9u8; 32], NOW, &peer(1)),
            Err(DtnError::UnknownContent { content_id: [9u8; 32] })
        );
    }

    #[test]
    fn replication_target_exhaustion_removes_from_forward_list() {
        let mut image = DtnStoreImage::new();
        let id = admit(&mut image, 3, 40, ServicePriority::Dtn, EXPIRY); // target 3
        assert_eq!(image.forward_candidates(NOW).len(), 1);
        for i in 0..3 {
            image.note_forwarded(&id, NOW + i, &peer(i as u8 + 1)).unwrap();
        }
        assert_eq!(
            image.bundle_status(&id, NOW),
            Ok(BundleStatus::ReplicationExhausted)
        );
        assert!(image.forward_candidates(NOW).is_empty(), "target reached");
        // The bundle is still HELD (queryable, readable) and the count may
        // keep growing past the target (saturating remaining).
        image.note_forwarded(&id, NOW + 9, &peer(9)).unwrap();
        assert_eq!(image.summary(&id).unwrap().replication_count(), 4);
        assert!(image.holds_bundle(&id));
    }

    #[test]
    fn delivered_is_terminal_and_survives_as_evidence_only() {
        let mut image = DtnStoreImage::new();
        let id = admit(&mut image, 3, 40, ServicePriority::Dtn, EXPIRY);
        image.mark_delivered(&id, NOW + 7, &peer(0x33)).unwrap();
        assert_eq!(image.bundle_status(&id, NOW + 10), Ok(BundleStatus::Delivered));
        assert!(
            !image
                .forward_candidates(NOW + 10)
                .iter()
                .any(|c| *c.content_id() == id),
            "delivered bundles never forward"
        );
        // Delivery evidence for an EVICTED (unknown) id is allowed — the
        // fact outlives the data (the R8 seam).
        image.mark_delivered(&[9u8; 32], NOW + 8, &peer(0x44)).unwrap();
        assert_eq!(image.evidence_count(), 2);
    }

    #[test]
    fn evidence_log_is_append_only_and_capped() {
        let mut image = DtnStoreImage::new();
        // Replays are NOT deduplicated here — this log is the raw local
        // fact layer; R8-001 owns authentication and replay protection.
        let record = CustodyRecord::received([1u8; 32], NOW, &peer(1));
        image.record_evidence(record.clone()).unwrap();
        image.record_evidence(record.clone()).unwrap();
        assert_eq!(image.evidence_count(), 2);
        for i in 2..MAX_EVIDENCE_RECORDS as u64 {
            image
                .record_evidence(CustodyRecord::received([1u8; 32], NOW + i, &peer(1)))
                .unwrap();
        }
        assert_eq!(image.evidence_count(), MAX_EVIDENCE_RECORDS);
        assert_eq!(
            image.record_evidence(record),
            Err(DtnError::EvidenceLogFull {
                count: MAX_EVIDENCE_RECORDS,
                max: MAX_EVIDENCE_RECORDS,
            })
        );
    }

    // -- eviction ---------------------------------------------------------------

    #[test]
    fn eviction_removes_only_expired_and_never_evidence() {
        let mut image = DtnStoreImage::new();
        let live = admit(&mut image, 1, 40, ServicePriority::Dtn, NOW + 1_000);
        let expired = admit(&mut image, 2, 40, ServicePriority::Dtn, NOW + 10);
        let delivered = admit(&mut image, 3, 40, ServicePriority::Dtn, NOW + 1_000);
        image.mark_delivered(&delivered, NOW + 5, &peer(0x55)).unwrap();
        image
            .record_evidence(CustodyRecord::received(expired, NOW, &peer(0x66)))
            .unwrap();
        // At NOW: nothing expired yet.
        assert!(image.evict_expired(NOW).is_empty());
        // At NOW+10: the expired bundle goes (delivered-but-unexpired stays).
        assert_eq!(image.evict_expired(NOW + 10), vec![expired]);
        assert!(image.holds_bundle(&live));
        assert!(image.holds_bundle(&delivered));
        assert!(!image.holds_bundle(&expired));
        assert_eq!(image.evidence_count(), 2, "custody evidence is never evicted");
        // At NOW+1000: everything expires (incl. the delivered one).
        assert_eq!(image.evict_expired(NOW + 1_000).len(), 2);
        assert_eq!(image.bundle_count(), 0);
        assert_eq!(image.evidence_count(), 2);
    }

    // -- registry codec ----------------------------------------------------------

    #[test]
    fn empty_image_round_trips_deterministically() {
        let image = DtnStoreImage::new();
        let a = image.to_bytes().unwrap();
        let b = image.to_bytes().unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), HEADER_LEN + CRC_LEN);
        let reloaded = DtnStoreImage::from_bytes(&a).unwrap();
        assert_eq!(reloaded, image);
        assert_eq!(reloaded.to_bytes().unwrap(), a, "canonical form");
    }

    #[test]
    fn full_image_round_trips_with_every_cross_check_satisfied() {
        let mut image = DtnStoreImage::new();
        let (m, chunks) = manifest(7, 40);
        let id_partial = m.content_id();
        image
            .admit_manifest(&m, ServicePriority::Opportunistic, NOW, EXPIRY, 2)
            .unwrap();
        for (slot, chunk) in chunks.iter().enumerate().take(2) {
            image.admit_chunk(&id_partial, slot, chunk, NOW).unwrap();
        }
        let (m2, chunks2) = manifest(9, 25);
        let id_full = m2.content_id();
        image
            .admit_manifest(&m2, ServicePriority::Dtn, NOW, EXPIRY + 5_000, 5)
            .unwrap();
        for (slot, chunk) in chunks2.iter().enumerate() {
            image.admit_chunk(&id_full, slot, chunk, NOW).unwrap();
        }
        image.note_forwarded(&id_partial, NOW + 1, &peer(0x77)).unwrap();
        image.mark_delivered(&id_full, NOW + 2, &peer(0x88)).unwrap();
        image
            .record_evidence(CustodyRecord::received(id_partial, NOW, &peer(0x99)))
            .unwrap();

        let bytes = image.to_bytes().unwrap();
        let reloaded = DtnStoreImage::from_bytes(&bytes).unwrap();
        assert_eq!(reloaded, image);
        assert_eq!(reloaded.to_bytes().unwrap(), bytes, "canonical form");
        // The state that matters survives:
        assert_eq!(reloaded.summaries(), image.summaries());
        assert_eq!(reloaded.evidence(), image.evidence());
        let s = reloaded.summary(&id_partial).unwrap();
        assert_eq!(s.present_chunk_count(), 2, "partial bundle stays partial");
        assert!(!s.complete());
        assert_eq!(reloaded.summary(&id_full).unwrap().replication_count(), 0);
        assert!(reloaded.summary(&id_full).unwrap().delivered());
        assert_eq!(
            reloaded.present_slots(&id_partial).unwrap(),
            [0, 1],
            "slot list survived"
        );
        // Determinism: rebuilding the same logical state yields the same
        // bytes — bundle insertion order must not matter (records sort by
        // content id); the evidence log's append order IS part of the
        // state (a chronological log), so it is replayed in the same
        // order.
        let mut image2 = DtnStoreImage::new();
        image2
            .admit_manifest(&m2, ServicePriority::Dtn, NOW, EXPIRY + 5_000, 5)
            .unwrap();
        for (slot, chunk) in chunks2.iter().enumerate() {
            image2.admit_chunk(&id_full, slot, chunk, NOW).unwrap();
        }
        image2
            .admit_manifest(&m, ServicePriority::Opportunistic, NOW, EXPIRY, 2)
            .unwrap();
        for (slot, chunk) in chunks.iter().enumerate().take(2) {
            image2.admit_chunk(&id_partial, slot, chunk, NOW).unwrap();
        }
        image2.note_forwarded(&id_partial, NOW + 1, &peer(0x77)).unwrap();
        image2.mark_delivered(&id_full, NOW + 2, &peer(0x88)).unwrap();
        image2
            .record_evidence(CustodyRecord::received(id_partial, NOW, &peer(0x99)))
            .unwrap();
        assert_eq!(image2.to_bytes().unwrap(), bytes, "order-independent canonical form");
    }

    #[test]
    fn decode_refuses_header_lies() {
        let image = DtnStoreImage::new();
        let mut bytes = image.to_bytes().unwrap();
        // Bad magic.
        bytes[0] = b'X';
        assert_eq!(DtnStoreImage::from_bytes(&bytes), Err(DtnError::BadMagic));
        let mut bytes = image.to_bytes().unwrap();
        // Version 2.
        bytes[4] = 2;
        assert_eq!(
            DtnStoreImage::from_bytes(&bytes),
            Err(DtnError::VersionUnsupported { found: 2 })
        );
        let mut bytes = image.to_bytes().unwrap();
        // Flags nonzero.
        bytes[6] = 1;
        assert_eq!(
            DtnStoreImage::from_bytes(&bytes),
            Err(DtnError::FlagsUnsupported { found: 1 })
        );
        // Truncations (every length below the minimum).
        let bytes = image.to_bytes().unwrap();
        for cut in 0..bytes.len() {
            assert!(
                DtnStoreImage::from_bytes(&bytes[..cut]).is_err(),
                "truncation at {cut} must fail closed"
            );
        }
        // Trailing bytes on the FILE (structure no longer accounts for
        // the file length).
        let mut bytes = image.to_bytes().unwrap();
        bytes.push(0);
        assert_eq!(
            DtnStoreImage::from_bytes(&bytes),
            Err(DtnError::LengthMismatch {
                expected: HEADER_LEN + CRC_LEN,
                actual: HEADER_LEN + CRC_LEN + 1,
            })
        );
        // (TrailingBytes is the in-BODY variant — a declared count smaller
        // than the records present — proven by the adversarial suite with
        // a repatched CRC.)
    }

    // -- misc ---------------------------------------------------------------------

    #[test]
    fn summary_reflects_metadata() {
        let mut image = DtnStoreImage::new();
        let id = admit(&mut image, 4, 24, ServicePriority::Live, EXPIRY); // 2 chunks
        let s = image.summary(&id).unwrap();
        assert_eq!(s.admitted_at_unix(), NOW);
        assert_eq!(s.chunk_count(), 2);
        assert_eq!(s.present_chunk_count(), 0);
        assert!(!s.complete());
        assert_eq!(
            image.summary(&[9u8; 32]),
            None,
            "unknown bundle has no summary"
        );
        // Metadata maps ride along inside the manifest bytes.
        let mut meta = BTreeMap::new();
        meta.insert("k".to_string(), MetadataValue::Text("v".to_string()));
        let (m, _) =
            ContentManifest::chunk(&content(1, 30), 10, "text/plain", Some(meta), NOW).unwrap();
        let mid = m.content_id();
        image.admit_manifest(&m, ServicePriority::Dtn, NOW, EXPIRY, 1).unwrap();
        let reloaded = image.manifest(&mid).unwrap();
        assert_eq!(reloaded.to_wire_bytes(), m.to_wire_bytes());
        assert_eq!(
            reloaded.metadata().and_then(|mm| mm.get("k")).cloned(),
            Some(MetadataValue::Text("v".to_string()))
        );
    }
}

// ---------------------------------------------------------------------------
// Tests — the FILE-BACKED store's restart laws (native only)
// ---------------------------------------------------------------------------

#[cfg(all(test, not(target_family = "wasm")))]
mod file_tests {
    use super::*;
    use crate::bundle::{ChunkAdmit, ManifestAdmit};
    use crate::evidence::{CustodyKind, CustodyRecord, PeerRef};
    use crate::priority::ServicePriority;

    const NOW: u64 = 1_700_000_500;
    const EXPIRY: u64 = NOW + 3_600;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sharenet-dtn-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn content(seed: u8, len: usize) -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_add(i as u8).wrapping_mul(31))
            .collect()
    }

    fn manifest(seed: u8, len: usize) -> (ContentManifest, Vec<Vec<u8>>) {
        ContentManifest::chunk(&content(seed, len), 12, "text/plain", None, 1_700_000_000)
            .expect("valid content")
    }

    fn peer(tag: u8) -> PeerRef {
        PeerRef::new(&[tag; 4]).expect("bounded")
    }

    fn chunk_file(dir: &Path, id: &[u8; CONTENT_ID_LEN], slot: u32) -> PathBuf {
        dir.join(CHUNKS_DIR_NAME)
            .join(crate::hex::encode(id))
            .join(format!("{slot}.bin"))
    }

    #[test]
    fn restart_preserves_state_and_custody_continues() {
        let dir = temp_dir("restart");
        let (manifest, chunks) = manifest(5, 45);
        let id = manifest.content_id();
        // 45 bytes / 12 = 4 chunks, last one 5 bytes.
        assert_eq!(chunks.len(), 4);

        // Process 1: admit partial + one forward + a received record.
        {
            let mut store = DtnStore::create(&dir).expect("create");
            assert_eq!(
                store.admit_manifest(&manifest, ServicePriority::Dtn, NOW, EXPIRY, 2),
                Ok(ManifestAdmit::Admitted)
            );
            assert_eq!(
                store.admit_chunk(&id, 0, &chunks[0], NOW),
                Ok(ChunkAdmit::Admitted)
            );
            assert_eq!(
                store.admit_chunk(&id, 1, &chunks[1], NOW),
                Ok(ChunkAdmit::Admitted)
            );
            store
                .record_evidence(CustodyRecord::received(id, NOW, &peer(0x05)))
                .unwrap();
            store.note_forwarded(&id, NOW + 5, &peer(0x11)).unwrap();
            store.flush().unwrap();
        } // teardown: the process ends; only bytes remain.

        // Process 2: reload — everything survived, re-verified.
        let mut store = DtnStore::load(&dir, NOW + 10).expect("load");
        assert_eq!(store.revalidated_at_unix(), Some(NOW + 10));
        assert_eq!(store.image().present_slots(&id).unwrap(), &[0u32, 1][..]);
        assert_eq!(store.read_chunk(&id, 0).unwrap(), chunks[0]);
        assert_eq!(store.read_chunk(&id, 1).unwrap(), chunks[1]);
        assert_eq!(store.image().summary(&id).unwrap().replication_count(), 1);

        // Custody CONTINUES: dedup is intact, the bundle completes.
        assert_eq!(
            store.admit_chunk(&id, 1, &chunks[1], NOW + 11),
            Ok(ChunkAdmit::Duplicate)
        );
        store.admit_chunk(&id, 2, &chunks[2], NOW + 12).unwrap();
        store.admit_chunk(&id, 3, &chunks[3], NOW + 13).unwrap();
        store.note_forwarded(&id, NOW + 14, &peer(0x22)).unwrap();
        store.flush().unwrap();

        // Process 3: the second restart sees the completed bundle.
        let store = DtnStore::load(&dir, NOW + 20).expect("reload");
        assert_eq!(
            store.image().present_slots(&id).unwrap(),
            &[0u32, 1, 2, 3][..]
        );
        assert_eq!(store.image().summary(&id).unwrap().replication_count(), 2);
        let kinds: Vec<CustodyKind> =
            store.image().evidence().iter().map(|r| r.kind()).collect();
        assert_eq!(
            kinds,
            [CustodyKind::Received, CustodyKind::Forwarded, CustodyKind::Forwarded]
        );
        // Replication target 2 exhausted: not a forward candidate again.
        assert!(
            store
                .forward_candidates(NOW + 21)
                .iter()
                .all(|c| c.content_id() != &id)
        );
        // read_chunk still re-verifies on every read (byte-exact).
        assert_eq!(store.read_chunk(&id, 3).unwrap(), chunks[3]);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn restart_refuses_tampered_and_truncated_chunk_files() {
        let dir = temp_dir("tamper");
        let (manifest, chunks) = manifest(9, 40);
        let id = manifest.content_id();
        {
            let mut store = DtnStore::create(&dir).expect("create");
            store
                .admit_manifest(&manifest, ServicePriority::Dtn, NOW, EXPIRY, 1)
                .unwrap();
            store.admit_chunk(&id, 0, &chunks[0], NOW).unwrap();
            store.flush().unwrap();
        }
        let path = chunk_file(&dir, &id, 0);

        // Byte flip: the re-hash on load refuses the whole store.
        let mut tampered = chunks[0].clone();
        tampered[0] ^= 0xFF;
        std::fs::write(&path, &tampered).unwrap();
        let err = DtnStore::load(&dir, NOW).unwrap_err();
        assert!(matches!(err, DtnError::ChunkHashMismatch { slot: 0 }));
        assert_eq!(err.name(), "chunk_hash_mismatch");

        // Truncation: the length law refuses it.
        std::fs::write(&path, &chunks[0][..4]).unwrap();
        let err = DtnStore::load(&dir, NOW).unwrap_err();
        assert!(matches!(err, DtnError::ChunkLengthWrong { slot: 0, .. }));

        // Restore: loads clean again (the honest state is recoverable).
        std::fs::write(&path, &chunks[0]).unwrap();
        DtnStore::load(&dir, NOW).expect("restored store loads");

        // Registry corruption: nothing loads, typed.
        let registry = dir.join(REGISTRY_FILE_NAME);
        let mut bytes = std::fs::read(&registry).unwrap();
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xFF;
        std::fs::write(&registry, &bytes).unwrap();
        assert!(DtnStore::load(&dir, NOW).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn create_never_clobbers_and_missing_registry_is_typed() {
        let dir = temp_dir("clobber");
        DtnStore::create(&dir).expect("create");
        let err = DtnStore::create(&dir).unwrap_err();
        assert!(matches!(err, DtnError::StoreAlreadyExists));
        assert_eq!(err.name(), "store_already_exists");

        let missing = temp_dir("missing");
        assert!(DtnStore::load(&missing, NOW).is_err());

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&missing).ok();
    }

    #[test]
    fn eviction_deletes_chunk_files_at_flush_and_evidence_survives() {
        let dir = temp_dir("evict");
        let (ma, ca) = manifest(1, 40);
        let (mb, cb) = manifest(2, 40);
        let ida = ma.content_id();
        let idb = mb.content_id();
        {
            let mut store = DtnStore::create(&dir).expect("create");
            store
                .admit_manifest(&ma, ServicePriority::Live, NOW, NOW + 100, 1)
                .unwrap();
            store
                .admit_manifest(&mb, ServicePriority::Dtn, NOW, EXPIRY, 1)
                .unwrap();
            for (slot, chunk) in ca.iter().enumerate() {
                store.admit_chunk(&ida, slot, chunk, NOW).unwrap();
            }
            for (slot, chunk) in cb.iter().enumerate() {
                store.admit_chunk(&idb, slot, chunk, NOW).unwrap();
            }
            store
                .record_evidence(CustodyRecord::received(ida, NOW, &peer(0x01)))
                .unwrap();
            store.flush().unwrap();
        }

        // A later process evicts the expired bundle.
        {
            let mut store = DtnStore::load(&dir, NOW + 100).expect("load");
            assert_eq!(store.evict_expired(NOW + 100), vec![ida]);
            // Records are gone in memory; the chunk files are STILL on
            // disk — deletion happens only at flush, after the
            // replacement registry is durable.
            assert!(chunk_file(&dir, &ida, 0).is_file());
            assert!(!store.image().holds_bundle(&ida));
            store.flush().unwrap();
        }

        // After the flush: A's files are gone, B is intact, evidence
        // (the R8 seam) survived the eviction.
        assert!(!chunk_file(&dir, &ida, 0).exists());
        let store = DtnStore::load(&dir, NOW + 200).expect("reload");
        assert!(!store.image().holds_bundle(&ida));
        assert!(store.image().holds_bundle(&idb));
        assert_eq!(store.image().present_slots(&idb).unwrap().len(), cb.len());
        assert!(
            store
                .image()
                .evidence()
                .iter()
                .any(|r| r.content_id() == &ida && r.kind() == CustodyKind::Received)
        );

        std::fs::remove_dir_all(&dir).ok();
    }
}
