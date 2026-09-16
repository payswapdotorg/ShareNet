//! Typed failures of the DTN custody store. Every variant is fail-closed:
//! nothing is stored, served or loaded on the back of an error, and no
//! partial state survives (a failed load leaves the store untouched).

use std::fmt;

/// Which file operation an [`DtnError::Io`] failed at (stable machine names
/// via `as_str`; the OS error is diagnostic detail only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreIoOp {
    /// Creating the store directory tree (`DtnStore::create`).
    CreateStoreDir,
    /// Creating a bundle's chunk directory before the first chunk write.
    CreateChunkDir,
    /// Reading the registry file (`DtnStore::load`).
    ReadRegistry,
    /// Reading a chunk file (`DtnStore::load` re-validation, `read_chunk`).
    ReadChunk,
    /// Writing a flush temp file (registry or chunk).
    WriteTemp,
    /// fsync-ing a flush temp file (registry or chunk).
    SyncTemp,
    /// Renaming a temp file over its final path (registry or chunk).
    RenameIntoPlace,
    /// Deleting an evicted bundle's chunk file (after the replacement
    /// registry is durably in place).
    RemoveChunkFile,
}

impl StoreIoOp {
    /// Stable machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            StoreIoOp::CreateStoreDir => "create_store_dir",
            StoreIoOp::CreateChunkDir => "create_chunk_dir",
            StoreIoOp::ReadRegistry => "read_registry",
            StoreIoOp::ReadChunk => "read_chunk",
            StoreIoOp::WriteTemp => "write_temp",
            StoreIoOp::SyncTemp => "sync_temp",
            StoreIoOp::RenameIntoPlace => "rename_into_place",
            StoreIoOp::RemoveChunkFile => "remove_chunk_file",
        }
    }
}

impl fmt::Display for StoreIoOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed failures of the DTN store: admission laws, custody laws, and the
/// fail-closed registry/chunk file discipline. Stable machine names
/// (`name()`) are the test and probe vocabulary.
#[derive(Debug)]
pub enum DtnError {
    /// Filesystem I/O failed. `source` is diagnostic only (excluded from
    /// `PartialEq`). A missing registry on `load` is `Io { op: ReadRegistry }`
    /// — callers distinguish first boot (create) from a broken path.
    Io {
        /// The operation that failed.
        op: StoreIoOp,
        /// The underlying OS error (diagnostic).
        source: std::io::Error,
    },
    // ------------------------------------------------------------------
    // Admission laws (bundle + chunk)
    // ------------------------------------------------------------------
    /// The store does not hold any bundle under this content id (chunk
    /// admission, custody mutation or a query against an unknown bundle).
    UnknownContent {
        /// The content id that was asked for.
        content_id: [u8; crate::CONTENT_ID_LEN],
    },
    /// A chunk slot beyond the manifest's last slot was offered (or named
    /// on disk). There is no such thing as storing past the commitment.
    SlotOutOfRange {
        /// The slot that was offered.
        slot: usize,
        /// The manifest's chunk count.
        chunk_count: usize,
    },
    /// A chunk whose byte length is not its manifest slot's expected
    /// length (`chunk_size`, or the remainder for the last slot). The
    /// length law runs BEFORE the hash law — structurally wrong input is
    /// never hashed (the R6-001 discipline).
    ChunkLengthWrong {
        /// The slot that was offered.
        slot: usize,
        /// The byte length that was found.
        found: u64,
        /// The manifest's expected byte length.
        expected: u64,
    },
    /// A chunk whose SHA-256 is not its manifest slot's committed hash.
    /// NEVER stored — an unverifiable chunk never enters the store.
    ChunkHashMismatch {
        /// The slot that failed the commitment.
        slot: usize,
    },
    /// The bundle is expired at the caller's clock (`now_unix >=
    /// expires_at_unix`): expired bundles never take new chunks (and never
    /// forward). Evict or re-admit after eviction instead.
    BundleExpired {
        /// The expiry bound that has passed.
        expires_at_unix: u64,
        /// The caller clock at which it had passed.
        now_unix: u64,
    },
    /// `expires_at_unix <= now_unix` at manifest admission — a bundle born
    /// expired would never forward; that is a caller bug, refused typed.
    ExpiryNotAfterNow {
        /// The expiry that was supplied.
        expires_at_unix: u64,
        /// The caller clock it failed against.
        now_unix: u64,
    },
    /// The replication target must be at least 1 (a bundle that may never
    /// be handed onward has no business entering a carry-forward store).
    ReplicationTargetBelowMinimum {
        /// The target that was supplied.
        target: u32,
    },
    /// The store already holds `MAX_BUNDLES` bundles — fail-closed, the
    /// caller evicts (TTL) before admitting more.
    BundlesFull {
        /// The count the store already holds.
        count: usize,
        /// The hard cap (`MAX_BUNDLES`).
        max: usize,
    },
    /// The custody evidence log already holds `MAX_EVIDENCE_RECORDS`
    /// records — fail-closed (evidence is append-only here; the archive is
    /// R8-001's receipt layer).
    EvidenceLogFull {
        /// The count the log already holds.
        count: usize,
        /// The hard cap (`MAX_EVIDENCE_RECORDS`).
        max: usize,
    },
    /// The manifest's canonical bytes cannot fit in the registry image
    /// (`MAX_REGISTRY_BYTES` bounds the whole image).
    ManifestTooLarge {
        /// The manifest byte length that was found.
        bytes: usize,
        /// The registry image cap.
        max: u64,
    },
    // ------------------------------------------------------------------
    // Registry image format (fail-closed load)
    // ------------------------------------------------------------------
    /// The file does not start with the store magic.
    BadMagic,
    /// The file is not a registry version this code accepts.
    VersionUnsupported {
        /// The version that was found.
        found: u16,
    },
    /// The reserved header flags are nonzero.
    FlagsUnsupported {
        /// The flags that were found.
        found: u16,
    },
    /// The registry image exceeds the size cap (bounded memory; hostile
    /// files refused before allocation).
    RegistryTooLarge {
        /// The size that was found.
        size: u64,
        /// The allowed maximum (`MAX_REGISTRY_BYTES`).
        max: u64,
    },
    /// The image is shorter than the structure it declares (truncated /
    /// partial write).
    LengthMismatch {
        /// The length the structure declared.
        expected: usize,
        /// The length that was found.
        actual: usize,
    },
    /// The image is longer than the structure it declares.
    TrailingBytes {
        /// The number of unaccounted-for trailing bytes.
        extra: usize,
    },
    /// The CRC-32 over the registry image does not match the stored value.
    ChecksumMismatch {
        /// The checksum stored in the file.
        found: u32,
        /// The checksum computed over the bytes.
        expected: u32,
    },
    /// `DtnStore::create` refuses to clobber an existing registry file (no
    /// silent data loss); `load` it instead.
    StoreAlreadyExists,
    /// A declared count is beyond its hard cap (bundle / evidence / slot
    /// counts are capped before any allocation).
    CountBeyondCap {
        /// What was being counted.
        what: &'static str,
        /// The count that was found.
        found: u64,
        /// The cap.
        max: u64,
    },
    // ------------------------------------------------------------------
    // Registry re-derivation cross-checks (trust nothing from disk)
    // ------------------------------------------------------------------
    /// A bundle record's stored content id disagrees with the content id
    /// re-derived from its own stored manifest bytes (SHA-256 over the
    /// canonical form — L013). The whole store is refused.
    ContentIdDisagrees {
        /// The id the record claimed.
        stored: [u8; crate::CONTENT_ID_LEN],
        /// The id the manifest bytes actually derive.
        derived: [u8; crate::CONTENT_ID_LEN],
    },
    /// A stored manifest failed strict re-parse (the R6-001 invariant set).
    ManifestMalformed {
        /// The typed cause from the protocol core.
        cause: sharenet_protocol::ContentError,
    },
    /// The persisted chunk-count summary disagrees with the re-parsed
    /// manifest's chunk count.
    ChunkCountDisagrees {
        /// The count the record claimed.
        stored: u32,
        /// The count the manifest derives.
        derived: u32,
    },
    /// `expires_at_unix <= admitted_at_unix` on disk — a bundle that was
    /// born expired cannot have been admitted through the API; the file
    /// lies.
    ExpiryNotAfterAdmission {
        /// The expiry the record claimed.
        expires_at_unix: u64,
        /// The admission time the record claimed.
        admitted_at_unix: u64,
    },
    /// A replication target of 0 on disk (the admission invariant, broken).
    ReplicationTargetZeroOnDisk,
    /// The priority tag is outside the frozen service classes.
    PriorityTagInvalid {
        /// The tag that was found.
        found: u8,
    },
    /// The delivered flag byte is outside {0, 1}.
    DeliveredTagInvalid {
        /// The byte that was found.
        found: u8,
    },
    /// Bundle records are not sorted by strictly ascending content id.
    RecordsNotAscending,
    /// Two bundle records carry the same content id.
    DuplicateRecord {
        /// The duplicated content id.
        content_id: [u8; crate::CONTENT_ID_LEN],
    },
    /// The persisted slot list is not strictly increasing.
    SlotListNotIncreasing {
        /// The earlier slot.
        previous: u32,
        /// The slot that did not strictly exceed it.
        next: u32,
    },
    /// A persisted slot is beyond the manifest's last slot.
    SlotBeyondManifest {
        /// The slot the record claimed.
        slot: u32,
        /// The manifest's chunk count.
        chunk_count: u32,
    },
    /// An evidence kind tag is outside the three custody kinds.
    EvidenceKindTagInvalid {
        /// The tag that was found.
        found: u8,
    },
    /// An evidence peer ref is outside 1..=64 bytes.
    PeerRefInvalid {
        /// The byte length that was found.
        bytes: usize,
    },
    /// The persisted delivered flag disagrees with the Delivered evidence
    /// re-derived from the evidence log (a delivered bundle MUST have a
    /// Delivered record; a Delivered record for a HELD bundle MUST have its
    /// flag set). The persisted summary is never trusted blindly.
    DeliveredDisagrees {
        /// The bundle whose delivered flag lies.
        content_id: [u8; crate::CONTENT_ID_LEN],
        /// What the record claimed.
        persisted: bool,
        /// What the evidence log derives.
        derived: bool,
    },
    /// The caller asked to read a chunk slot the store does not hold
    /// (partial bundles hold subsets — check `BundleSummary::present_chunks`).
    SlotNotHeld {
        /// The bundle.
        content_id: [u8; crate::CONTENT_ID_LEN],
        /// The slot that was asked for.
        slot: u32,
    },
}

impl DtnError {
    /// Stable machine name (the typed-error discipline of the codebase).
    pub fn name(&self) -> &'static str {
        match self {
            DtnError::Io { .. } => "dtn_store_io",
            DtnError::UnknownContent { .. } => "unknown_content",
            DtnError::SlotOutOfRange { .. } => "slot_out_of_range",
            DtnError::ChunkLengthWrong { .. } => "chunk_length_wrong",
            DtnError::ChunkHashMismatch { .. } => "chunk_hash_mismatch",
            DtnError::BundleExpired { .. } => "bundle_expired",
            DtnError::ExpiryNotAfterNow { .. } => "expiry_not_after_now",
            DtnError::ReplicationTargetBelowMinimum { .. } => {
                "replication_target_below_minimum"
            }
            DtnError::BundlesFull { .. } => "bundles_full",
            DtnError::EvidenceLogFull { .. } => "evidence_log_full",
            DtnError::ManifestTooLarge { .. } => "manifest_too_large",
            DtnError::BadMagic => "bad_magic",
            DtnError::VersionUnsupported { .. } => "version_unsupported",
            DtnError::FlagsUnsupported { .. } => "flags_unsupported",
            DtnError::RegistryTooLarge { .. } => "registry_too_large",
            DtnError::LengthMismatch { .. } => "length_mismatch",
            DtnError::TrailingBytes { .. } => "trailing_bytes",
            DtnError::ChecksumMismatch { .. } => "checksum_mismatch",
            DtnError::StoreAlreadyExists => "store_already_exists",
            DtnError::CountBeyondCap { .. } => "count_beyond_cap",
            DtnError::ContentIdDisagrees { .. } => "content_id_disagrees",
            DtnError::ManifestMalformed { .. } => "manifest_malformed",
            DtnError::ChunkCountDisagrees { .. } => "chunk_count_disagrees",
            DtnError::ExpiryNotAfterAdmission { .. } => "expiry_not_after_admission",
            DtnError::ReplicationTargetZeroOnDisk => {
                "replication_target_zero_on_disk"
            }
            DtnError::PriorityTagInvalid { .. } => "priority_tag_invalid",
            DtnError::DeliveredTagInvalid { .. } => "delivered_tag_invalid",
            DtnError::RecordsNotAscending => "records_not_ascending",
            DtnError::DuplicateRecord { .. } => "duplicate_record",
            DtnError::SlotListNotIncreasing { .. } => "slot_list_not_increasing",
            DtnError::SlotBeyondManifest { .. } => "slot_beyond_manifest",
            DtnError::EvidenceKindTagInvalid { .. } => {
                "evidence_kind_tag_invalid"
            }
            DtnError::PeerRefInvalid { .. } => "peer_ref_invalid",
            DtnError::DeliveredDisagrees { .. } => "delivered_disagrees",
            DtnError::SlotNotHeld { .. } => "slot_not_held",
        }
    }

    #[cfg(not(target_family = "wasm"))]
    pub(crate) fn io(op: StoreIoOp, source: std::io::Error) -> Self {
        DtnError::Io { op, source }
    }
}

impl fmt::Display for DtnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DtnError::Io { op, source } => {
                write!(f, "store I/O failed at {op}: {source}")
            }
            DtnError::UnknownContent { content_id } => write!(
                f,
                "no bundle held under content id {}",
                crate::hex::encode(content_id)
            ),
            DtnError::SlotOutOfRange { slot, chunk_count } => write!(
                f,
                "chunk slot {slot} is beyond the manifest's last slot (chunk count {chunk_count})"
            ),
            DtnError::ChunkLengthWrong { slot, found, expected } => write!(
                f,
                "chunk slot {slot} must be {expected} bytes, found {found}"
            ),
            DtnError::ChunkHashMismatch { slot } => write!(
                f,
                "chunk slot {slot} does not hash to its manifest commitment (unverifiable chunks are never stored)"
            ),
            DtnError::BundleExpired { expires_at_unix, now_unix } => write!(
                f,
                "bundle expired at {expires_at_unix} before the caller clock {now_unix} (expired bundles take no new chunks and never forward)"
            ),
            DtnError::ExpiryNotAfterNow { expires_at_unix, now_unix } => write!(
                f,
                "expires_at_unix {expires_at_unix} is not after the caller clock {now_unix} (a bundle born expired would never forward)"
            ),
            DtnError::ReplicationTargetBelowMinimum { target } => write!(
                f,
                "replication target {target} must be at least 1"
            ),
            DtnError::BundlesFull { count, max } => write!(
                f,
                "store already holds {count} bundles (max {max}); evict before admitting more"
            ),
            DtnError::EvidenceLogFull { count, max } => write!(
                f,
                "custody evidence log already holds {count} records (max {max}); the archive is R8-001's layer"
            ),
            DtnError::ManifestTooLarge { bytes, max } => write!(
                f,
                "manifest is {bytes} bytes; the registry image is capped at {max}"
            ),
            DtnError::BadMagic => {
                write!(f, "not a ShareNet DTN registry (bad magic)")
            }
            DtnError::VersionUnsupported { found } => write!(
                f,
                "registry format version {found} is not supported (expected {})",
                crate::REGISTRY_FORMAT_VERSION
            ),
            DtnError::FlagsUnsupported { found } => write!(
                f,
                "registry header flags {found} are not supported (expected 0)"
            ),
            DtnError::RegistryTooLarge { size, max } => write!(
                f,
                "registry image is {size} bytes, max is {max}"
            ),
            DtnError::LengthMismatch { expected, actual } => write!(
                f,
                "registry is truncated: structure declares {expected} bytes, found {actual}"
            ),
            DtnError::TrailingBytes { extra } => write!(
                f,
                "registry has {extra} trailing bytes beyond its declared structure"
            ),
            DtnError::ChecksumMismatch { found, expected } => write!(
                f,
                "registry checksum mismatch: file says {found:#010x}, bytes compute {expected:#010x} (corrupted or tampered)"
            ),
            DtnError::StoreAlreadyExists => write!(
                f,
                "store directory already holds a registry: create refuses to clobber it (load it instead)"
            ),
            DtnError::CountBeyondCap { what, found, max } => write!(
                f,
                "{what} count {found} is beyond the cap {max}"
            ),
            DtnError::ContentIdDisagrees { stored, derived } => write!(
                f,
                "stored content id {} disagrees with the id re-derived from its own manifest bytes {} — refusing the whole store",
                crate::hex::encode(stored),
                crate::hex::encode(derived)
            ),
            DtnError::ManifestMalformed { cause } => {
                write!(f, "stored manifest failed strict re-parse: {cause}")
            }
            DtnError::ChunkCountDisagrees { stored, derived } => write!(
                f,
                "persisted chunk count {stored} disagrees with the re-parsed manifest ({derived})"
            ),
            DtnError::ExpiryNotAfterAdmission { expires_at_unix, admitted_at_unix } => write!(
                f,
                "on-disk bundle claims expiry {expires_at_unix} not after admission {admitted_at_unix} (born expired — impossible through the API)"
            ),
            DtnError::ReplicationTargetZeroOnDisk => write!(
                f,
                "on-disk bundle carries a replication target of 0 (the admission invariant, broken)"
            ),
            DtnError::PriorityTagInvalid { found } => write!(
                f,
                "priority tag {found} is outside the frozen service classes"
            ),
            DtnError::DeliveredTagInvalid { found } => write!(
                f,
                "delivered flag byte {found} is outside {{0, 1}}"
            ),
            DtnError::RecordsNotAscending => write!(
                f,
                "bundle records are not sorted by strictly ascending content id"
            ),
            DtnError::DuplicateRecord { content_id } => write!(
                f,
                "content id {} appears twice in the registry",
                crate::hex::encode(content_id)
            ),
            DtnError::SlotListNotIncreasing { previous, next } => write!(
                f,
                "slot list is not strictly increasing ({next} after {previous})"
            ),
            DtnError::SlotBeyondManifest { slot, chunk_count } => write!(
                f,
                "slot {slot} is beyond the manifest's chunk count {chunk_count}"
            ),
            DtnError::EvidenceKindTagInvalid { found } => write!(
                f,
                "evidence kind tag {found} is outside the three custody kinds"
            ),
            DtnError::PeerRefInvalid { bytes } => write!(
                f,
                "evidence peer ref must be 1..={} bytes, found {bytes}",
                crate::PEER_REF_MAX_BYTES
            ),
            DtnError::DeliveredDisagrees { content_id, persisted, derived } => write!(
                f,
                "bundle {} persisted delivered={persisted} but the evidence log derives delivered={derived} — refusing the whole store",
                crate::hex::encode(content_id)
            ),
            DtnError::SlotNotHeld { content_id, slot } => write!(
                f,
                "bundle {} does not hold chunk slot {slot} (partial bundles hold subsets)",
                crate::hex::encode(content_id)
            ),
        }
    }
}

impl std::error::Error for DtnError {}

/// `PartialEq` ignoring the diagnostic `source` of `Io` (the OS errno is
/// not identity); every other variant compares all fields.
impl PartialEq for DtnError {
    fn eq(&self, other: &Self) -> bool {
        use std::mem::discriminant;
        if discriminant(self) != discriminant(other) {
            return false;
        }
        match (self, other) {
            (DtnError::Io { op: a, .. }, DtnError::Io { op: b, .. }) => a == b,
            (
                DtnError::UnknownContent { content_id: a },
                DtnError::UnknownContent { content_id: b },
            ) => a == b,
            (
                DtnError::SlotOutOfRange { slot: a, chunk_count: b },
                DtnError::SlotOutOfRange { slot: c, chunk_count: d },
            ) => a == c && b == d,
            (
                DtnError::ChunkLengthWrong { slot: a, found: b, expected: c },
                DtnError::ChunkLengthWrong { slot: d, found: e, expected: g },
            ) => a == d && b == e && c == g,
            (DtnError::ChunkHashMismatch { slot: a }, DtnError::ChunkHashMismatch { slot: b }) => {
                a == b
            }
            (
                DtnError::BundleExpired { expires_at_unix: a, now_unix: b },
                DtnError::BundleExpired { expires_at_unix: c, now_unix: d },
            ) => a == c && b == d,
            (
                DtnError::ExpiryNotAfterNow { expires_at_unix: a, now_unix: b },
                DtnError::ExpiryNotAfterNow { expires_at_unix: c, now_unix: d },
            ) => a == c && b == d,
            (
                DtnError::ReplicationTargetBelowMinimum { target: a },
                DtnError::ReplicationTargetBelowMinimum { target: b },
            ) => a == b,
            (
                DtnError::BundlesFull { count: a, max: b },
                DtnError::BundlesFull { count: c, max: d },
            ) => a == c && b == d,
            (
                DtnError::EvidenceLogFull { count: a, max: b },
                DtnError::EvidenceLogFull { count: c, max: d },
            ) => a == c && b == d,
            (
                DtnError::ManifestTooLarge { bytes: a, max: b },
                DtnError::ManifestTooLarge { bytes: c, max: d },
            ) => a == c && b == d,
            (DtnError::VersionUnsupported { found: a }, DtnError::VersionUnsupported { found: b }) => {
                a == b
            }
            (DtnError::FlagsUnsupported { found: a }, DtnError::FlagsUnsupported { found: b }) => {
                a == b
            }
            (
                DtnError::RegistryTooLarge { size: a, max: b },
                DtnError::RegistryTooLarge { size: c, max: d },
            ) => a == c && b == d,
            (
                DtnError::LengthMismatch { expected: a, actual: b },
                DtnError::LengthMismatch { expected: c, actual: d },
            ) => a == c && b == d,
            (DtnError::TrailingBytes { extra: a }, DtnError::TrailingBytes { extra: b }) => a == b,
            (
                DtnError::ChecksumMismatch { found: a, expected: b },
                DtnError::ChecksumMismatch { found: c, expected: d },
            ) => a == c && b == d,
            (
                DtnError::CountBeyondCap { what: a, found: b, max: c },
                DtnError::CountBeyondCap { what: d, found: e, max: g },
            ) => a == d && b == e && c == g,
            (
                DtnError::ContentIdDisagrees { stored: a, derived: b },
                DtnError::ContentIdDisagrees { stored: c, derived: d },
            ) => a == c && b == d,
            (
                DtnError::ManifestMalformed { cause: a },
                DtnError::ManifestMalformed { cause: b },
            ) => a == b,
            (
                DtnError::ChunkCountDisagrees { stored: a, derived: b },
                DtnError::ChunkCountDisagrees { stored: c, derived: d },
            ) => a == c && b == d,
            (
                DtnError::ExpiryNotAfterAdmission { expires_at_unix: a, admitted_at_unix: b },
                DtnError::ExpiryNotAfterAdmission { expires_at_unix: c, admitted_at_unix: d },
            ) => a == c && b == d,
            (
                DtnError::PriorityTagInvalid { found: a },
                DtnError::PriorityTagInvalid { found: b },
            ) => a == b,
            (
                DtnError::DeliveredTagInvalid { found: a },
                DtnError::DeliveredTagInvalid { found: b },
            ) => a == b,
            (
                DtnError::DuplicateRecord { content_id: a },
                DtnError::DuplicateRecord { content_id: b },
            ) => a == b,
            (
                DtnError::SlotListNotIncreasing { previous: a, next: b },
                DtnError::SlotListNotIncreasing { previous: c, next: d },
            ) => a == c && b == d,
            (
                DtnError::SlotBeyondManifest { slot: a, chunk_count: b },
                DtnError::SlotBeyondManifest { slot: c, chunk_count: d },
            ) => a == c && b == d,
            (DtnError::EvidenceKindTagInvalid { found: a }, DtnError::EvidenceKindTagInvalid { found: b }) => {
                a == b
            }
            (DtnError::PeerRefInvalid { bytes: a }, DtnError::PeerRefInvalid { bytes: b }) => {
                a == b
            }
            (
                DtnError::DeliveredDisagrees { content_id: a, persisted: b, derived: c },
                DtnError::DeliveredDisagrees { content_id: d, persisted: e, derived: g },
            ) => a == d && b == e && c == g,
            (
                DtnError::SlotNotHeld { content_id: a, slot: b },
                DtnError::SlotNotHeld { content_id: c, slot: d },
            ) => a == c && b == d,
            _ => true, // same discriminant, nothing field-wise to compare
        }
    }
}

impl Eq for DtnError {}
