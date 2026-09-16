//! ShareNet DTN store-carry-forward — work item R6-003.
//!
//! `spec/architecture.md` §12: *"Propagation uses: deduplication; integrity
//! verification; TTL; priority; replication policy; custody/delivery
//! evidence; opportunistic forwarding; partial transfer/resume. The design
//! should borrow Delay-Tolerant Networking principles and remain
//! interoperable with BPv7 in a later adapter instead of rebuilding DTN
//! concepts from scratch."*
//!
//! This crate is the LOCAL layer of that list: the node's custody store.
//! It holds carried bundles (R6-001 [`ContentManifest`]s + verified
//! chunks) durably, records their custody facts, and answers the two
//! carry-forward questions — *what do I forward next?* and *what do I
//! evict?* — deterministically, from caller-supplied clocks. It borrows
//! DTN principles (custody, TTL, replication counting, expiry-aware
//! carry) without rebuilding DTN concepts; a BPv7 adapter would sit ON
//! this store later, not replace it.
//!
//! # The laws
//!
//! 1. **Integrity is the manifest's hash law.** A chunk is stored ONLY if
//!    its length matches its manifest slot's expected length and its
//!    SHA-256 matches the manifest's committed hash (R6-001's
//!    length-before-hash discipline). An unverifiable chunk NEVER enters
//!    the store — typed refusal, no partial storage.
//! 2. **Dedup by `(content_id, slot)`.** Content is content-addressed and
//!    the content id is commitment-derived (L013 — SHA-256 of the
//!    manifest's canonical bytes, re-derived here, never
//!    caller-supplied). Re-delivery of a held manifest is `AlreadyPresent`
//!    and of a held chunk is `Duplicate`: idempotent, never a second
//!    record, never a second file.
//! 3. **TTL is per-bundle and caller-clocked.** Every time parameter —
//!    admission, queries, custody events — is supplied by the caller;
//!    this crate has NO wall clock (the law of the connectivity boundary
//!    and the admission policy, applied here). A bundle is expired at
//!    `now >= expires_at_unix`; expired bundles never forward, never take
//!    new chunks, and are the eviction candidates.
//! 4. **Priority is the frozen service class set.** `live` /
//!    `opportunistic` / `dtn` (ADR-003), as the typed
//!    [`ServicePriority`], pinned by test to the protocol core's frozen
//!    `SERVICE_CLASSES` — no second vocabulary.
//! 5. **Trust nothing from disk.** Loads strict-parse the registry
//!    (magic/version/flags/lengths/CRC-32), re-derive every content id
//!    from its own stored manifest bytes, cross-check the persisted
//!    chunk-count and delivered summaries, and RE-HASH every stored chunk
//!    file against its manifest commitment. Any tamper is a typed error
//!    and NOTHING loads. [`DtnStore::read_chunk`] re-verifies on every
//!    read.
//! 6. **Atomic flush, fail-closed load.** The registry is written
//!    temp + fsync + rename; chunk files each get their own atomic write;
//!    evicted bundles' chunk files are deleted only after the replacement
//!    registry is durably in place (a crash leaves ignored orphans, never
//!    dangling references).
//! 7. **Custody evidence is unsigned local fact.** [`CustodyRecord`]s
//!    (`received` / `forwarded` / `delivered`, when, to-whom as an OPAQUE
//!    bounded [`PeerRef`]) are the R8 contribution-evidence seam — R8-001
//!    owns signatures, receipts and anti-gaming. This log never signs and
//!    never deduplicates (append-only, capped, honest).
//! 8. **Determinism.** The store's outputs (forward lists, summaries,
//!    registry bytes) are pure functions of its state + the caller's
//!    clock: ordered maps, fixed sort keys, no hash-iteration dependence
//!    (architecture §2).
//!
//! # What this crate deliberately does NOT do
//!
//! - **No forwarding policy.** [`DtnStore::forward_candidates`] says WHAT
//!   may move; WHERE it goes (and whether now is a good moment) is the
//!   R6-005 opportunistic forwarder's decision, composed with the R5-005
//!   gateway admission policy — only an `Eligible` gateway receives
//!   bundles. The store is that composition's storage layer (the
//!   dependency-graph edge R6-003 → R5-005: admission-gated handoff is
//!   the consumption seam this crate's API shape serves).
//! - **No cross-node rules.** R6-004 owns the receiving-side
//!   dedup/integrity/TTL admission rules; this crate is the local half.
//! - **No chunk transfer protocol.** R6-002 owns the resumable transfer;
//!   [`DtnStore::present_slots`] is its seam (what this node can serve),
//!   and partial bundles forward (their manifests first).
//! - **No wire objects.** Everything here is node-local durable state;
//!   the protocol registry governs nothing in this crate (the same
//!   reading as R5-003's store).
//! - **No second source of truth** for content: the manifest IS the
//!   named object (R6-001); this store only ever derives its ids.
//!
//! # Layout
//!
//! - [`priority`]: [`ServicePriority`] — the frozen classes, typed.
//! - [`evidence`]: [`CustodyKind`], [`PeerRef`], [`CustodyRecord`] — the
//!   R8 seam.
//! - [`bundle`]: [`BundleSummary`], [`ForwardCandidate`], [`BundleStatus`]
//!   and the admission outcomes — the read views.
//! - [`store`]: [`DtnStoreImage`] (pure model + strict registry codec,
//!   wasm-portable) and [`DtnStore`] (the file-backed store, native) —
//!   the R5-003 durable-store discipline applied to DTN custody.
//! - [`hex`]: lowercase hex for ids/peers (probe + diagnostics).
//!
//! # Dependencies and platform independence
//!
//! Exactly one: `sharenet-protocol` (R6-001 — the manifest, its
//! commitment-derived ids, its per-slot hashes and expected-length law).
//! No async runtime, no serde, no wall clock, no I/O beyond the store's
//! own directory. `#![forbid(unsafe_code)]`. The lib compiles for
//! `wasm32-unknown-unknown` (the L007 discipline): the pure
//! [`DtnStoreImage`] + codec are the wasm host's persistence seam; only
//! the file-backed [`DtnStore`] is native.
//!
//! # Expected production callers
//!
//! - Today: the `dtn_probe` test-scaffolding binary (real processes
//!   admitting, carrying, forwarding and evicting across process
//!   boundaries — the multiprocess verify level).
//! - Next: the ShareNet daemon holds one `DtnStore` per node; its
//!   opportunistic forwarder (R6-005) polls `forward_candidates` at
//!   contact time, hands bundles to admitted gateways, and records
//!   custody through `note_forwarded`/`mark_delivered`; the R6-002
//!   transfer drives `admit_chunk` from the wire; R8-001's receipt layer
//!   reads the custody log.

#![forbid(unsafe_code)]

pub mod bundle;
pub mod error;
pub mod evidence;
pub mod hex;
pub mod priority;
pub mod store;

pub use bundle::{
    BundleStatus, BundleSummary, ChunkAdmit, ForwardCandidate, ManifestAdmit,
};
pub use error::{DtnError, StoreIoOp};
pub use evidence::{CustodyKind, CustodyRecord, PeerRef, PEER_REF_MAX_BYTES};
pub use priority::ServicePriority;
#[cfg(not(target_family = "wasm"))]
pub use store::DtnStore;
pub use store::{
    DtnStoreImage, CHUNKS_DIR_NAME, CONTENT_ID_LEN, MAX_BUNDLES,
    MAX_EVIDENCE_RECORDS, MAX_REGISTRY_BYTES, REGISTRY_FILE_NAME,
    REGISTRY_FORMAT_VERSION, REGISTRY_MAGIC, REPLICATION_TARGET_MIN,
};
