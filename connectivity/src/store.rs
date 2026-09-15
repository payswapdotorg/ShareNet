//! The durable local health projection — work item R5-003.
//!
//! `spec/integrations/adcos.md` says ShareNet stores, per contract: the
//! `ConnectivityContractRef`, optional lease/reference data, signed
//! observations and a **local health projection**. This module IS that last
//! item, durably: a versioned, strict, fail-closed binary store holding, per
//! [`ConnectivityContractRef`]:
//!
//! - the accepted [`ConnectivityObservation`] log — deduplicated by the
//!   per-provider sequence (only a strictly greater sequence is accepted,
//!   exactly the [`crate::ObservationCache`] policy), in acceptance order;
//! - the derived [`ContractState`] projection — R5-001's event-mapping state
//!   machine ([`ContractState::from_observation_kind`]) folded over the log;
//! - freshness metadata — the `observed_at_unix` of the last accepted
//!   observation plus the store's freshness window (the provider's bound),
//!   persisted in the header.
//!
//! ADCOS stays the contract authority: this store is a *projection of
//! accepted evidence*, never a second `ConnectivityContract` truth, and it
//! mutates nothing but its own file (the observation read-only law).
//!
//! # Restart semantics (the R5-003 "restart" verify level)
//!
//! 1. **Re-derive, never trust a summary.** [`DurableProjection::from_bytes`]
//!    re-derives every contract state by folding the event mapping over the
//!    persisted observation log and cross-checks the persisted summary against
//!    it; a disagreement is [`StoreError::SummaryDisagrees`] — the whole
//!    store is refused (fail-closed, no partial state). The state a reloaded
//!    store serves is always the re-derived one.
//! 2. **Freshness re-validation against the CURRENT time.**
//!    [`DurableProjectionStore::load`] takes the caller's `now_unix` (this
//!    crate has no wall clock by law) and records it;
//!    [`DurableProjectionStore::freshness_at_reload`] and
//!    [`ContractHealth::freshness`] surface the typed
//!    [`ProjectionFreshness`] — a stale store reads
//!    [`ProjectionFreshness::Stale`], never fresh data.
//! 3. **State survives restart.** The observation *log* (not just a summary)
//!    is persisted, so a reloaded store continues the sequence exactly where
//!    it stopped: a redelivered sequence is
//!    [`crate::AcceptOutcome::IgnoredReplay`], the next strictly greater one
//!    is accepted — no sequence regression, terminate idempotence preserved.
//! 4. **Corrupted/partial files fail closed.** Strict parsing (exact magic,
//!    version, flags, lengths, CRC-32) plus the semantic cross-checks; any
//!    violation is a typed [`StoreError`] and NOTHING is loaded.
//!
//! # The no-fabrication law
//!
//! adcos.md failure semantics: *"do not fabricate a contract state; cache
//! the last accepted observation with freshness metadata."* A reload
//! therefore serves the LAST ACCEPTED observation with its ORIGINAL
//! freshness metadata (bound = its original `observed_at_unix + window`,
//! never re-anchored to the reload time); when that bound has passed, the
//! projection is typed [`ProjectionFreshness::Stale`] — stale evidence,
//! honestly labeled, never presented as current.
//!
//! # File format (v1, private local durable state — NOT a protocol object)
//!
//! Hand-rolled strict binary, little-endian, fixed-width (zero dependencies;
//! the same discipline as the R5-002 client's hand-rolled codecs). This file
//! never crosses the network, so the protocol registry does not govern it;
//! it is node-local durable state, and the refs inside stay opaque (they are
//! reconstructed through the kind-validated
//! [`crate::refs::ConnectivityContractRef::from_parts`] seam, never parsed).
//!
//! ```text
//! offset  size  field
//! 0       4     magic = b"SNCP" (ShareNet Connectivity Contract Projection)
//! 4       2     format_version = 1 (STORE_FORMAT_VERSION)
//! 6       2     flags = 0 (reserved; any nonzero is refused)
//! 8       8     freshness_window_secs — the provider's freshness bound
//! 16      4     contract_count (u32)
//! 20      4     body_len (u32) — byte length of the record section
//! 24      body_len  contract records, sorted by contract id bytes
//! 24+body_len  4   crc32 (u32) — CRC-32/IEEE of bytes [0 .. 24+body_len]
//!
//! record (54 fixed bytes + 17 per observation):
//! 0       32    contract id (opaque bytes; never parsed)
//! 32      1     ref-kind tag (2 = contract; anything else is refused)
//! 33      1     state tag (0=projected 1=active 2=degraded 3=terminated)
//! 34      8     last_accepted_observed_at (0 iff the log is empty)
//! 42      8     highest_sequence (0 iff the log is empty)
//! 50      4     observation_count (u32)
//! 54      …     observations × N: [1B kind tag][8B observed_at][8B sequence]
//! ```
//!
//! Every single-byte mutation of a valid file is caught (magic, version,
//! flags, length arithmetic, or CRC-32 — proven by
//! `every_bit_flip_fails_closed`), and every truncation too
//! (`every_truncation_fails_closed`).
//!
//! # Atomic flush
//!
//! [`DurableProjectionStore::flush`] serializes in memory, writes
//! `<path>.tmp`, `sync_all`s it, then `rename`s it over the store path — the
//! classic atomic-replace pattern: a crash mid-flush leaves either the old
//! complete file or the new complete file, never a partial store. A stale
//! `<path>.tmp` from a crashed flush is scratch and is never read.
//!
//! # Platform independence (the wasm host seam)
//!
//! The pure model ([`DurableProjection`], [`ContractHealth`],
//! [`ProjectionFreshness`]) plus the codec ([`DurableProjection::to_bytes`]
//! / [`DurableProjection::from_bytes`]) compile everywhere, including
//! `wasm32-unknown-unknown`. Only the file-backed
//! [`DurableProjectionStore`] is native (`#[cfg(not(target_family =
//! "wasm"))]`): on a wasm host the same codec hands the bytes to the HOST's
//! storage API — the host seam. The store is single-writer by design
//! (`&mut self`, no interior mutability, no file locking); wrap it in the
//! caller's mutex if a process needs shared mutation.

use std::collections::BTreeMap;
use std::fmt;

use crate::observation::{AcceptOutcome, CachedObservation, ConnectivityObservation, ObservationKind};
use crate::projection::ContractState;
use crate::refs::{ConnectivityContractRef, RefKind, REF_ID_LEN};

#[cfg(not(target_family = "wasm"))]
use std::fs::{self, File};
#[cfg(not(target_family = "wasm"))]
use std::io::Write as _;
#[cfg(not(target_family = "wasm"))]
use std::path::{Path, PathBuf};

/// File magic: **SN**etnet **C**ontract **P**rojection.
pub const STORE_MAGIC: [u8; 4] = *b"SNCP";
/// The store format version this code writes and accepts (nothing else).
pub const STORE_FORMAT_VERSION: u16 = 1;
/// Hard cap on the store file size (read AND write side) — bounded memory,
/// fail-closed against hostile files.
pub const MAX_STORE_FILE_BYTES: u64 = 4 * 1024 * 1024;

const HEADER_LEN: usize = 24;
const CRC_LEN: usize = 4;
const RECORD_FIXED_LEN: usize = 32 + 1 + 1 + 8 + 8 + 4;
const OBSERVATION_LEN: usize = 1 + 8 + 8;
/// Cap on `Vec::with_capacity` for an attacker-supplied count (the body
/// bounds check makes larger counts fail anyway; this only bounds allocation).
const MAX_RECORD_PREALLOC: usize = 1024;

// ---------------------------------------------------------------------------
// Persistence tags (private to the format)
// ---------------------------------------------------------------------------

fn ref_kind_tag(kind: RefKind) -> u8 {
    match kind {
        RefKind::Intent => 0,
        RefKind::Offer => 1,
        RefKind::Contract => 2,
    }
}

fn ref_kind_from_tag(tag: u8) -> Option<RefKind> {
    match tag {
        0 => Some(RefKind::Intent),
        1 => Some(RefKind::Offer),
        2 => Some(RefKind::Contract),
        _ => None,
    }
}

fn observation_kind_tag(kind: ObservationKind) -> u8 {
    match kind {
        ObservationKind::ContractActivated => 0,
        ObservationKind::ExecutionStateChanged => 1,
        ObservationKind::Degraded => 2,
        ObservationKind::AssuranceAvailable => 3,
        ObservationKind::FailoverReplan => 4,
        ObservationKind::Terminated => 5,
    }
}

fn observation_kind_from_tag(tag: u8) -> Option<ObservationKind> {
    match tag {
        0 => Some(ObservationKind::ContractActivated),
        1 => Some(ObservationKind::ExecutionStateChanged),
        2 => Some(ObservationKind::Degraded),
        3 => Some(ObservationKind::AssuranceAvailable),
        4 => Some(ObservationKind::FailoverReplan),
        5 => Some(ObservationKind::Terminated),
        _ => None,
    }
}

fn contract_state_tag(state: ContractState) -> u8 {
    match state {
        ContractState::Projected => 0,
        ContractState::Active => 1,
        ContractState::Degraded => 2,
        ContractState::Terminated => 3,
    }
}

fn contract_state_from_tag(tag: u8) -> Option<ContractState> {
    match tag {
        0 => Some(ContractState::Projected),
        1 => Some(ContractState::Active),
        2 => Some(ContractState::Degraded),
        3 => Some(ContractState::Terminated),
        _ => None,
    }
}

/// CRC-32/IEEE (the zlib polynomial `0xEDB88320`), bitwise — the corruption
/// detector of the store format. Private: it is format machinery, not a
/// public hashing service.
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
// Typed errors
// ---------------------------------------------------------------------------

/// Which file operation an [`StoreError::Io`] failed at (stable machine
/// names via `as_str`; the OS error is diagnostic detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreIoOp {
    /// Reading the store file (`load`).
    ReadStore,
    /// Writing the flush temp file.
    WriteTemp,
    /// fsync-ing the flush temp file.
    SyncTemp,
    /// Renaming the temp file over the store path.
    RenameIntoPlace,
}

impl StoreIoOp {
    /// Stable machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            StoreIoOp::ReadStore => "read_store",
            StoreIoOp::WriteTemp => "write_temp",
            StoreIoOp::SyncTemp => "sync_temp",
            StoreIoOp::RenameIntoPlace => "rename_into_place",
        }
    }
}

impl fmt::Display for StoreIoOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Typed failures of the durable local health projection store. Every
/// variant is fail-closed: no partial state is ever served.
#[derive(Debug)]
pub enum StoreError {
    /// Filesystem I/O failed. `source` is diagnostic only (excluded from
    /// `PartialEq`). A missing file on `load` is `Io { op: ReadStore }` —
    /// callers distinguish first boot from corruption by checking the path
    /// or the io error kind.
    Io {
        /// The operation that failed.
        op: StoreIoOp,
        /// The underlying OS error (diagnostic).
        source: std::io::Error,
    },
    /// The file does not start with the store magic.
    BadMagic,
    /// The file is not a store version this code accepts.
    VersionUnsupported {
        /// The version that was found.
        found: u16,
    },
    /// The reserved header flags are nonzero.
    FlagsUnsupported {
        /// The flags that were found.
        found: u16,
    },
    /// The store (or its in-memory image) exceeds the size cap.
    StoreTooLarge {
        /// The size that was found.
        size: u64,
        /// The allowed maximum (`MAX_STORE_FILE_BYTES`).
        max: u64,
    },
    /// The file is shorter than the structure it declares (truncated /
    /// partial write).
    LengthMismatch {
        /// The length the structure declared.
        expected: usize,
        /// The length that was found.
        actual: usize,
    },
    /// The file is longer than the structure it declares.
    TrailingBytes {
        /// The number of unaccounted-for trailing bytes.
        extra: usize,
    },
    /// The CRC-32 over the store image does not match the stored value.
    ChecksumMismatch {
        /// The checksum stored in the file.
        found: u32,
        /// The checksum computed over the bytes.
        expected: u32,
    },
    /// A record's ref-kind tag is not a known kind.
    RefKindTagInvalid {
        /// The tag that was found.
        found: u8,
    },
    /// A record is not a contract record (the kind-validated `from_parts`
    /// seam refused the reconstruction — an offer/intent id cannot be
    /// resurrected as a contract record).
    RecordKindNotContract {
        /// The kind the record carried.
        found: RefKind,
    },
    /// An observation kind tag is outside 0..=5 (the six adcos.md events).
    ObservationKindTagInvalid {
        /// The tag that was found.
        found: u8,
    },
    /// A contract-state tag is outside 0..=3.
    StateTagInvalid {
        /// The tag that was found.
        found: u8,
    },
    /// A persisted observation sequence does not strictly increase within
    /// its contract log (the dedup invariant was violated on disk).
    SequenceNotIncreasing {
        /// The contract whose log is broken.
        contract: ConnectivityContractRef,
        /// The earlier sequence.
        previous: u64,
        /// The sequence that did not strictly exceed it.
        next: u64,
    },
    /// The persisted derived-state summary disagrees with re-derivation from
    /// the observation log — the summary is never trusted blindly; the whole
    /// store is refused.
    SummaryDisagrees {
        /// The contract whose summary lies.
        contract: ConnectivityContractRef,
        /// The state the file claimed.
        persisted: ContractState,
        /// The state the observation log re-derives.
        derived: ContractState,
    },
    /// The persisted last-accepted metadata disagrees with the log tail.
    MetadataDisagrees {
        /// The contract whose metadata lies.
        contract: ConnectivityContractRef,
        /// The `observed_at_unix` the file claimed.
        stored_observed_at: u64,
        /// The sequence the file claimed.
        stored_sequence: u64,
        /// The `observed_at_unix` the log tail actually has.
        log_observed_at: u64,
        /// The sequence the log tail actually has.
        log_sequence: u64,
    },
    /// Two records carry the same contract id.
    DuplicateRecord {
        /// The duplicated contract.
        contract: ConnectivityContractRef,
    },
    /// `create` refuses to clobber an existing store file (no silent data
    /// loss); `load` the existing file instead.
    StoreAlreadyExists,
}

impl StoreError {
    /// Stable machine name (the typed-error discipline of the crate).
    pub fn name(&self) -> &'static str {
        match self {
            StoreError::Io { .. } => "store_io",
            StoreError::BadMagic => "store_bad_magic",
            StoreError::VersionUnsupported { .. } => "store_version_unsupported",
            StoreError::FlagsUnsupported { .. } => "store_flags_unsupported",
            StoreError::StoreTooLarge { .. } => "store_too_large",
            StoreError::LengthMismatch { .. } => "store_length_mismatch",
            StoreError::TrailingBytes { .. } => "store_trailing_bytes",
            StoreError::ChecksumMismatch { .. } => "store_checksum_mismatch",
            StoreError::RefKindTagInvalid { .. } => "store_ref_kind_tag_invalid",
            StoreError::RecordKindNotContract { .. } => "store_record_kind_not_contract",
            StoreError::ObservationKindTagInvalid { .. } => "store_observation_kind_tag_invalid",
            StoreError::StateTagInvalid { .. } => "store_state_tag_invalid",
            StoreError::SequenceNotIncreasing { .. } => "store_sequence_not_increasing",
            StoreError::SummaryDisagrees { .. } => "store_summary_disagrees",
            StoreError::MetadataDisagrees { .. } => "store_metadata_disagrees",
            StoreError::DuplicateRecord { .. } => "store_duplicate_record",
            StoreError::StoreAlreadyExists => "store_already_exists",
        }
    }

    #[cfg(not(target_family = "wasm"))]
    fn io(op: StoreIoOp, source: std::io::Error) -> Self {
        StoreError::Io { op, source }
    }
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::Io { op, source } => {
                write!(f, "store I/O failed at {op}: {source}")
            }
            StoreError::BadMagic => {
                write!(f, "not a ShareNet contract projection store (bad magic)")
            }
            StoreError::VersionUnsupported { found } => {
                write!(f, "store format version {found} is not supported (expected {STORE_FORMAT_VERSION})")
            }
            StoreError::FlagsUnsupported { found } => {
                write!(f, "store header flags {found} are not supported (expected 0)")
            }
            StoreError::StoreTooLarge { size, max } => {
                write!(f, "store is {size} bytes, max is {max}")
            }
            StoreError::LengthMismatch { expected, actual } => {
                write!(f, "store is truncated: structure declares {expected} bytes, found {actual}")
            }
            StoreError::TrailingBytes { extra } => {
                write!(f, "store has {extra} trailing bytes beyond its declared structure")
            }
            StoreError::ChecksumMismatch { found, expected } => {
                write!(f, "store checksum mismatch: file says {found:#010x}, bytes compute {expected:#010x} (corrupted or tampered)")
            }
            StoreError::RefKindTagInvalid { found } => {
                write!(f, "record ref-kind tag {found} is not a known kind")
            }
            StoreError::RecordKindNotContract { found } => {
                write!(f, "record is a {found} record, not a contract record (an id of one kind cannot be re-typed)")
            }
            StoreError::ObservationKindTagInvalid { found } => {
                write!(f, "observation kind tag {found} is outside the six adcos.md events")
            }
            StoreError::StateTagInvalid { found } => {
                write!(f, "contract state tag {found} is not a known state")
            }
            StoreError::SequenceNotIncreasing {
                contract,
                previous,
                next,
            } => write!(
                f,
                "contract {} observation log sequence {next} does not strictly increase past {previous}",
                contract.to_hex()
            ),
            StoreError::SummaryDisagrees {
                contract,
                persisted,
                derived,
            } => write!(
                f,
                "contract {} persisted state summary {} disagrees with re-derivation from its observation log ({}) — refusing the whole store",
                contract.to_hex(),
                persisted.as_str(),
                derived.as_str()
            ),
            StoreError::MetadataDisagrees {
                contract,
                stored_observed_at,
                stored_sequence,
                log_observed_at,
                log_sequence,
            } => write!(
                f,
                "contract {} last-accepted metadata (at {stored_observed_at}, seq {stored_sequence}) disagrees with its log tail (at {log_observed_at}, seq {log_sequence})",
                contract.to_hex()
            ),
            StoreError::DuplicateRecord { contract } => {
                write!(f, "contract {} appears twice in the store", contract.to_hex())
            }
            StoreError::StoreAlreadyExists => {
                write!(f, "store file already exists: create refuses to clobber it (load it instead)")
            }
        }
    }
}

impl std::error::Error for StoreError {}

/// `PartialEq` ignoring the diagnostic `source` of `Io` (the OS errno is
/// not identity); every other variant compares all fields.
impl PartialEq for StoreError {
    fn eq(&self, other: &Self) -> bool {
        use std::mem::discriminant;
        if discriminant(self) != discriminant(other) {
            return false;
        }
        match (self, other) {
            (StoreError::Io { op: a, .. }, StoreError::Io { op: b, .. }) => a == b,
            (
                StoreError::VersionUnsupported { found: a },
                StoreError::VersionUnsupported { found: b },
            ) => a == b,
            (
                StoreError::FlagsUnsupported { found: a },
                StoreError::FlagsUnsupported { found: b },
            ) => a == b,
            (
                StoreError::StoreTooLarge { size: a, max: b },
                StoreError::StoreTooLarge { size: c, max: d },
            ) => a == c && b == d,
            (
                StoreError::LengthMismatch { expected: a, actual: b },
                StoreError::LengthMismatch { expected: c, actual: d },
            ) => a == c && b == d,
            (StoreError::TrailingBytes { extra: a }, StoreError::TrailingBytes { extra: b }) => {
                a == b
            }
            (
                StoreError::ChecksumMismatch { found: a, expected: b },
                StoreError::ChecksumMismatch { found: c, expected: d },
            ) => a == c && b == d,
            (
                StoreError::RefKindTagInvalid { found: a },
                StoreError::RefKindTagInvalid { found: b },
            ) => a == b,
            (
                StoreError::RecordKindNotContract { found: a },
                StoreError::RecordKindNotContract { found: b },
            ) => a == b,
            (
                StoreError::ObservationKindTagInvalid { found: a },
                StoreError::ObservationKindTagInvalid { found: b },
            ) => a == b,
            (
                StoreError::StateTagInvalid { found: a },
                StoreError::StateTagInvalid { found: b },
            ) => a == b,
            (
                StoreError::SequenceNotIncreasing {
                    contract: a,
                    previous: b,
                    next: c,
                },
                StoreError::SequenceNotIncreasing {
                    contract: d,
                    previous: e,
                    next: g,
                },
            ) => a == d && b == e && c == g,
            (
                StoreError::SummaryDisagrees {
                    contract: a,
                    persisted: b,
                    derived: c,
                },
                StoreError::SummaryDisagrees {
                    contract: d,
                    persisted: e,
                    derived: g,
                },
            ) => a == d && b == e && c == g,
            (
                StoreError::MetadataDisagrees {
                    contract: a,
                    stored_observed_at: b,
                    stored_sequence: c,
                    log_observed_at: d,
                    log_sequence: e,
                },
                StoreError::MetadataDisagrees {
                    contract: g,
                    stored_observed_at: h,
                    stored_sequence: i,
                    log_observed_at: j,
                    log_sequence: k,
                },
            ) => a == g && b == h && c == i && d == j && e == k,
            (StoreError::DuplicateRecord { contract: a }, StoreError::DuplicateRecord { contract: b }) => {
                a == b
            }
            _ => true, // same discriminant, no fields to compare
        }
    }
}

impl Eq for StoreError {}

// ---------------------------------------------------------------------------
// The health view
// ---------------------------------------------------------------------------

/// The typed freshness of a projected contract — the reload-time
/// re-validation surface. Stale is a *needs-refresh* verdict, never fresh
/// data: the health below it remains the LAST ACCEPTED observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectionFreshness {
    /// No observation has ever been accepted for the contract (nothing to
    /// be fresh about — the projection is `Projected`).
    NoObservation,
    /// The last accepted observation is fresh strictly before
    /// `fresh_until_unix` at the evaluation time.
    Fresh {
        /// The exclusive freshness bound (the ORIGINAL
        /// `observed_at_unix + window`, never re-anchored).
        fresh_until_unix: u64,
    },
    /// The freshness bound has passed: the data below is the last accepted
    /// observation (stale now, never fabricated); a provider refresh is
    /// needed.
    Stale {
        /// The exclusive freshness bound that has passed.
        fresh_until_unix: u64,
        /// When the provider observed the last accepted observation — the
        /// no-fabrication evidence (the original `observed_at_unix`).
        last_observed_at_unix: u64,
    },
}

/// The durable local health projection for one contract — the store's read
/// view. The `state` is ALWAYS re-derived from the accepted observation log
/// (never a blindly trusted persisted summary); the `last_accepted` carries
/// the ORIGINAL freshness metadata (the no-fabrication law).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContractHealth {
    contract: ConnectivityContractRef,
    state: ContractState,
    observations: Vec<ConnectivityObservation>,
    last_accepted: Option<CachedObservation>,
}

impl ContractHealth {
    /// The contract this health projects.
    pub fn contract(&self) -> &ConnectivityContractRef {
        &self.contract
    }

    /// The projected lifecycle state (re-derived from the observation log).
    pub fn state(&self) -> ContractState {
        self.state
    }

    /// The accepted observation log, in acceptance order (deduplicated by
    /// strictly-increasing per-provider sequence).
    pub fn observations(&self) -> &[ConnectivityObservation] {
        &self.observations
    }

    /// The last accepted observation with its ORIGINAL freshness metadata,
    /// if any was ever accepted.
    pub fn last_accepted(&self) -> Option<&CachedObservation> {
        self.last_accepted.as_ref()
    }

    /// The highest accepted per-provider sequence (`None` when the log is
    /// empty) — the restart anchor: strictly greater sequences continue the
    /// stream, lower-or-equal ones are replays.
    pub fn highest_sequence(&self) -> Option<u64> {
        self.observations.last().map(|o| o.sequence())
    }

    /// The typed freshness at `now_unix` (fresh strictly before the bound —
    /// the bound is exclusive, mirroring `ObservationCache::is_fresh`).
    pub fn freshness(&self, now_unix: u64) -> ProjectionFreshness {
        match &self.last_accepted {
            None => ProjectionFreshness::NoObservation,
            Some(cached) => {
                let bound = cached.fresh_until_unix();
                if now_unix < bound {
                    ProjectionFreshness::Fresh { fresh_until_unix: bound }
                } else {
                    ProjectionFreshness::Stale {
                        fresh_until_unix: bound,
                        last_observed_at_unix: cached.observation().observed_at_unix(),
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The pure durable projection (model + codec)
// ---------------------------------------------------------------------------

/// One contract's persisted record.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ContractRecord {
    contract: ConnectivityContractRef,
    /// The accepted observation log — strictly increasing sequences.
    log: Vec<ConnectivityObservation>,
    /// The event-mapping fold over the log (the persisted summary,
    /// cross-checked against re-derivation on load).
    derived_state: ContractState,
}

/// The durable local health projection: the pure model + the strict binary
/// codec. This is what lives on disk (and what a wasm host persists through
/// its own storage seam — see the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableProjection {
    freshness_window_secs: u64,
    contracts: BTreeMap<[u8; REF_ID_LEN], ContractRecord>,
}

impl DurableProjection {
    /// An empty projection treating accepted observations as fresh for
    /// `freshness_window_secs` after their `observed_at_unix` (the
    /// provider's bound — persisted in the header, preserved across
    /// reloads so freshness metadata is never re-anchored).
    pub fn new(freshness_window_secs: u64) -> Self {
        Self {
            freshness_window_secs,
            contracts: BTreeMap::new(),
        }
    }

    /// The persisted freshness window (seconds).
    pub fn freshness_window_secs(&self) -> u64 {
        self.freshness_window_secs
    }

    /// Register a contract the caller holds a reference to, with no
    /// observations yet — the honest `(accepted offer, nothing observed)`
    /// `Projected` state of the event mapping. Idempotent: registering a
    /// known contract changes nothing (its log is never touched).
    pub fn register(&mut self, contract: &ConnectivityContractRef) {
        self.contracts.entry(*contract.id()).or_insert_with(|| ContractRecord {
            contract: *contract,
            log: Vec::new(),
            derived_state: ContractState::Projected,
        });
    }

    /// Accept an observation if its sequence is strictly greater than the
    /// log tail for its contract; ignore replays — EXACTLY the
    /// [`crate::ObservationCache`] dedup policy, applied to the durable log
    /// (auto-registers an unseen contract). Accepting folds the adcos.md
    /// event mapping into the derived state.
    pub fn accept(&mut self, observation: &ConnectivityObservation) -> AcceptOutcome {
        let record = self
            .contracts
            .entry(*observation.contract().id())
            .or_insert_with(|| ContractRecord {
                contract: *observation.contract(),
                log: Vec::new(),
                derived_state: ContractState::Projected,
            });
        match record.log.last() {
            Some(last) if last.sequence() >= observation.sequence() => {
                AcceptOutcome::IgnoredReplay {
                    sequence: observation.sequence(),
                }
            }
            _ => {
                if let Some(next) = ContractState::from_observation_kind(observation.kind()) {
                    record.derived_state = next;
                }
                record.log.push(observation.clone());
                AcceptOutcome::Accepted
            }
        }
    }

    /// The contracts this projection tracks, sorted by id bytes (canonical
    /// order — the same order the codec writes).
    pub fn contracts(&self) -> Vec<ConnectivityContractRef> {
        self.contracts.values().map(|r| r.contract).collect()
    }

    /// The durable local health projection for one contract, if tracked.
    pub fn health(&self, contract: &ConnectivityContractRef) -> Option<ContractHealth> {
        let record = self.contracts.get(contract.id())?;
        let last_accepted = record.log.last().map(|obs| {
            // The ORIGINAL freshness bound: observed_at + the persisted
            // window, computed the moment it is read — never re-anchored.
            let fresh_until = obs
                .observed_at_unix()
                .saturating_add(self.freshness_window_secs);
            CachedObservation::new(obs.clone(), fresh_until)
        });
        Some(ContractHealth {
            contract: record.contract,
            state: record.derived_state,
            observations: record.log.clone(),
            last_accepted,
        })
    }

    // -- encoding -----------------------------------------------------------

    /// Serialize to the canonical v1 image (sorted records, fixed-width
    /// little-endian, CRC-32 trailer). Fails only on the size cap — an
    /// image beyond `MAX_STORE_FILE_BYTES` is refused instead of written.
    pub fn to_bytes(&self) -> Result<Vec<u8>, StoreError> {
        let count = self.contracts.len();
        let count_u32 = u32::try_from(count).map_err(|_| StoreError::StoreTooLarge {
            size: count as u64,
            max: u32::MAX as u64,
        })?;
        // Exact-ish preallocation from the format's fixed sizes (saturating,
        // capped by the store cap — never an overflow panic).
        let capacity = self
            .contracts
            .values()
            .map(|r| RECORD_FIXED_LEN + r.log.len().saturating_mul(OBSERVATION_LEN))
            .fold(0usize, |acc, n| acc.saturating_add(n))
            .min(MAX_STORE_FILE_BYTES as usize);
        let mut body = Vec::with_capacity(capacity);
        for record in self.contracts.values() {
            body.extend_from_slice(record.contract.id());
            body.push(ref_kind_tag(record.contract.kind()));
            body.push(contract_state_tag(record.derived_state));
            let (last_at, last_seq) = record
                .log
                .last()
                .map(|o| (o.observed_at_unix(), o.sequence()))
                .unwrap_or((0, 0));
            body.extend_from_slice(&last_at.to_le_bytes());
            body.extend_from_slice(&last_seq.to_le_bytes());
            let obs_count = u32::try_from(record.log.len()).map_err(|_| StoreError::StoreTooLarge {
                size: record.log.len() as u64,
                max: u32::MAX as u64,
            })?;
            body.extend_from_slice(&obs_count.to_le_bytes());
            for observation in &record.log {
                body.push(observation_kind_tag(observation.kind()));
                body.extend_from_slice(&observation.observed_at_unix().to_le_bytes());
                body.extend_from_slice(&observation.sequence().to_le_bytes());
            }
        }
        let body_len = u32::try_from(body.len()).map_err(|_| StoreError::StoreTooLarge {
            size: body.len() as u64,
            max: u32::MAX as u64,
        })?;
        let total = HEADER_LEN + body.len() + CRC_LEN;
        if total as u64 > MAX_STORE_FILE_BYTES {
            return Err(StoreError::StoreTooLarge {
                size: total as u64,
                max: MAX_STORE_FILE_BYTES,
            });
        }
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(&STORE_MAGIC);
        out.extend_from_slice(&STORE_FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&self.freshness_window_secs.to_le_bytes());
        out.extend_from_slice(&count_u32.to_le_bytes());
        out.extend_from_slice(&body_len.to_le_bytes());
        out.extend_from_slice(&body);
        let crc = crc32(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        Ok(out)
    }

    /// Strictly parse + validate a v1 image: structural checks (magic,
    /// version, flags, lengths, CRC-32), the dedup invariant, the persisted
    /// summary cross-checked against re-derivation from the log, and the
    /// last-accepted metadata cross-checked against the log tail. ANY
    /// violation fails closed with a typed error — no partial state.
    ///
    /// The reloaded `derived_state` is the RE-DERIVED one (the summary only
    /// cross-checks), which is why re-derivation provably equals the live
    /// projection for the same observation stream.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let actual = bytes.len() as u64;
        if actual > MAX_STORE_FILE_BYTES {
            return Err(StoreError::StoreTooLarge { size: actual, max: MAX_STORE_FILE_BYTES });
        }
        if bytes.len() < HEADER_LEN + CRC_LEN {
            return Err(StoreError::LengthMismatch {
                expected: HEADER_LEN + CRC_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0..4] != STORE_MAGIC {
            return Err(StoreError::BadMagic);
        }
        let version = u16::from_le_bytes(bytes[4..6].try_into().expect("slice is 2 bytes"));
        if version != STORE_FORMAT_VERSION {
            return Err(StoreError::VersionUnsupported { found: version });
        }
        let flags = u16::from_le_bytes(bytes[6..8].try_into().expect("slice is 2 bytes"));
        if flags != 0 {
            return Err(StoreError::FlagsUnsupported { found: flags });
        }
        let window = u64::from_le_bytes(bytes[8..16].try_into().expect("slice is 8 bytes"));
        let declared_count =
            u32::from_le_bytes(bytes[16..20].try_into().expect("slice is 4 bytes"));
        let body_len =
            u32::from_le_bytes(bytes[20..24].try_into().expect("slice is 4 bytes")) as u64;
        let expected_total = (HEADER_LEN as u64) + body_len + (CRC_LEN as u64);
        if actual < expected_total {
            return Err(StoreError::LengthMismatch {
                expected: expected_total as usize,
                actual: bytes.len(),
            });
        }
        if actual > expected_total {
            return Err(StoreError::TrailingBytes {
                extra: (actual - expected_total) as usize,
            });
        }
        let body_end = HEADER_LEN + body_len as usize;
        let stored_crc =
            u32::from_le_bytes(bytes[body_end..body_end + 4].try_into().expect("slice is 4 bytes"));
        let computed_crc = crc32(&bytes[..body_end]);
        if stored_crc != computed_crc {
            return Err(StoreError::ChecksumMismatch {
                found: stored_crc,
                expected: computed_crc,
            });
        }

        let mut cursor = Cursor::new(&bytes[HEADER_LEN..body_end]);
        let mut contracts: BTreeMap<[u8; REF_ID_LEN], ContractRecord> = BTreeMap::new();
        for _ in 0..declared_count {
            let record = parse_record(&mut cursor)?;
            if contracts.contains_key(record.contract.id()) {
                return Err(StoreError::DuplicateRecord {
                    contract: record.contract,
                });
            }
            contracts.insert(*record.contract.id(), record);
        }
        if cursor.remaining() != 0 {
            return Err(StoreError::TrailingBytes { extra: cursor.remaining() });
        }

        Ok(Self {
            freshness_window_secs: window,
            contracts,
        })
    }
}

/// Strict bounds-checked little-endian reader over the record section.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], StoreError> {
        if self.remaining() < n {
            return Err(StoreError::LengthMismatch {
                expected: self.data.len() + (n - self.remaining()),
                actual: self.data.len(),
            });
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, StoreError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, StoreError> {
        let slice = self.take(4)?;
        Ok(u32::from_le_bytes(slice.try_into().expect("slice is 4 bytes")))
    }

    fn u64(&mut self) -> Result<u64, StoreError> {
        let slice = self.take(8)?;
        Ok(u64::from_le_bytes(slice.try_into().expect("slice is 8 bytes")))
    }
}

/// Parse one contract record: structure, tags, the dedup invariant, the
/// re-derivation cross-check, and the metadata cross-check.
fn parse_record(cursor: &mut Cursor<'_>) -> Result<ContractRecord, StoreError> {
    let id: [u8; REF_ID_LEN] = cursor
        .take(REF_ID_LEN)?
        .try_into()
        .expect("slice is 32 bytes");
    let kind_tag = cursor.u8()?;
    let Some(kind) = ref_kind_from_tag(kind_tag) else {
        return Err(StoreError::RefKindTagInvalid { found: kind_tag });
    };
    // The kind-validated reconstruction seam (refs.rs): an offer/intent id
    // can never be resurrected as a contract record.
    let contract = ConnectivityContractRef::from_parts(kind, id)
        .map_err(|_| StoreError::RecordKindNotContract { found: kind })?;
    let state_tag = cursor.u8()?;
    let Some(persisted) = contract_state_from_tag(state_tag) else {
        return Err(StoreError::StateTagInvalid { found: state_tag });
    };
    let stored_observed_at = cursor.u64()?;
    let stored_sequence = cursor.u64()?;
    let count = cursor.u32()? as usize;

    let mut log = Vec::with_capacity(count.min(MAX_RECORD_PREALLOC));
    let mut previous: Option<u64> = None;
    let mut derived = ContractState::Projected;
    for _ in 0..count {
        let kind_tag = cursor.u8()?;
        let Some(kind) = observation_kind_from_tag(kind_tag) else {
            return Err(StoreError::ObservationKindTagInvalid { found: kind_tag });
        };
        let observed_at = cursor.u64()?;
        let sequence = cursor.u64()?;
        if let Some(prev) = previous {
            if sequence <= prev {
                return Err(StoreError::SequenceNotIncreasing {
                    contract,
                    previous: prev,
                    next: sequence,
                });
            }
        }
        previous = Some(sequence);
        // THE re-derivation: fold the event mapping over the log.
        if let Some(next) = ContractState::from_observation_kind(kind) {
            derived = next;
        }
        log.push(ConnectivityObservation::new(kind, observed_at, contract, sequence));
    }

    // The persisted summary is never trusted blindly: it must equal the
    // re-derivation from the log, or the whole store is refused.
    if persisted != derived {
        return Err(StoreError::SummaryDisagrees {
            contract,
            persisted,
            derived,
        });
    }
    let (log_observed_at, log_sequence) = log
        .last()
        .map(|o| (o.observed_at_unix(), o.sequence()))
        .unwrap_or((0, 0));
    if stored_observed_at != log_observed_at || stored_sequence != log_sequence {
        return Err(StoreError::MetadataDisagrees {
            contract,
            stored_observed_at,
            stored_sequence,
            log_observed_at,
            log_sequence,
        });
    }
    Ok(ContractRecord {
        contract,
        log,
        derived_state: derived,
    })
}

// ---------------------------------------------------------------------------
// The file-backed store (native only; the wasm host persists via the codec)
// ---------------------------------------------------------------------------

/// The durable local health projection, file-backed — the R5-003 store.
///
/// Single-writer by design: `&mut self` for mutation, no interior
/// mutability, no file locking (wrap in the caller's mutex for shared
/// access). `flush` is the durability point: mutations live in memory until
/// the caller flushes (atomic temp-file + rename — see the module docs).
#[cfg(not(target_family = "wasm"))]
#[derive(Debug)]
pub struct DurableProjectionStore {
    path: PathBuf,
    projection: DurableProjection,
    revalidated_at_unix: Option<u64>,
}

#[cfg(not(target_family = "wasm"))]
impl DurableProjectionStore {
    /// Create a NEW empty store file at `path` (durably: the empty image is
    /// flushed immediately). Refuses to clobber an existing file — a store
    /// is either created once or loaded, never silently replaced.
    pub fn create(path: &Path, freshness_window_secs: u64) -> Result<Self, StoreError> {
        if path.exists() {
            return Err(StoreError::StoreAlreadyExists);
        }
        let store = Self {
            path: path.to_path_buf(),
            projection: DurableProjection::new(freshness_window_secs),
            revalidated_at_unix: None,
        };
        store.flush()?;
        Ok(store)
    }

    /// Load the store from disk, re-deriving the projection from the
    /// persisted observation log and re-validating freshness against the
    /// CURRENT time — `now_unix` is supplied by the caller (this crate has
    /// no wall clock by law). A stale store is surfaced typed through
    /// [`Self::freshness_at_reload`]; a corrupted, truncated or tampered
    /// file fails closed with a typed [`StoreError`] and NOTHING is loaded.
    pub fn load(path: &Path, now_unix: u64) -> Result<Self, StoreError> {
        let bytes = fs::read(path).map_err(|e| StoreError::io(StoreIoOp::ReadStore, e))?;
        let projection = DurableProjection::from_bytes(&bytes)?;
        Ok(Self {
            path: path.to_path_buf(),
            projection,
            revalidated_at_unix: Some(now_unix),
        })
    }

    /// The store file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The pure projection this store persists (the wasm-host seam shape).
    pub fn projection(&self) -> &DurableProjection {
        &self.projection
    }

    /// The `now_unix` this store was re-validated against at load time
    /// (`None` for a freshly created store — nothing was reload-validated).
    pub fn revalidated_at_unix(&self) -> Option<u64> {
        self.revalidated_at_unix
    }

    /// Register a held contract reference (no observations yet). Idempotent.
    pub fn register(&mut self, contract: &ConnectivityContractRef) {
        self.projection.register(contract);
    }

    /// Accept an observation (the [`crate::ObservationCache`] dedup policy —
    /// strictly greater per-contract sequence; replays ignored). In-memory
    /// until [`Self::flush`].
    pub fn accept(&mut self, observation: &ConnectivityObservation) -> AcceptOutcome {
        self.projection.accept(observation)
    }

    /// The tracked contracts, sorted by id bytes.
    pub fn contracts(&self) -> Vec<ConnectivityContractRef> {
        self.projection.contracts()
    }

    /// The durable local health projection for one contract, if tracked.
    /// The state is the re-derived one; the freshness metadata is the
    /// ORIGINAL (never re-anchored).
    pub fn health(&self, contract: &ConnectivityContractRef) -> Option<ContractHealth> {
        self.projection.health(contract)
    }

    /// The typed freshness of the CURRENT last-accepted observation,
    /// evaluated at the store's reload timestamp — the reload-time
    /// re-validation. `None` when the store was created (not loaded) or the
    /// contract is unknown; [`Self::health`] + [`ContractHealth::freshness`]
    /// evaluate at any time.
    pub fn freshness_at_reload(
        &self,
        contract: &ConnectivityContractRef,
    ) -> Option<ProjectionFreshness> {
        let now = self.revalidated_at_unix?;
        self.projection.health(contract).map(|h| h.freshness(now))
    }

    /// Durably persist the current projection: serialize in memory, write
    /// `<path>.tmp`, `sync_all`, `rename` over the store path. Atomic — a
    /// crash leaves the previous complete file, never a partial store.
    pub fn flush(&self) -> Result<(), StoreError> {
        let bytes = self.projection.to_bytes()?;
        let tmp = self.temp_path();
        let mut file = File::create(&tmp).map_err(|e| StoreError::io(StoreIoOp::WriteTemp, e))?;
        file.write_all(&bytes)
            .map_err(|e| StoreError::io(StoreIoOp::WriteTemp, e))?;
        file.sync_all()
            .map_err(|e| StoreError::io(StoreIoOp::SyncTemp, e))?;
        drop(file);
        fs::rename(&tmp, &self.path)
            .map_err(|e| StoreError::io(StoreIoOp::RenameIntoPlace, e))?;
        Ok(())
    }

    fn temp_path(&self) -> PathBuf {
        let mut os = self.path.clone().into_os_string();
        os.push(".tmp");
        PathBuf::from(os)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observation::AcceptOutcome;
    use crate::port::ConnectivityPort;
    use crate::refs::REF_ID_LEN;

    fn contract(tag: u8) -> ConnectivityContractRef {
        ConnectivityContractRef::from_id([tag; REF_ID_LEN])
    }

    fn obs(kind: ObservationKind, at: u64, tag: u8, sequence: u64) -> ConnectivityObservation {
        ConnectivityObservation::new(kind, at, contract(tag), sequence)
    }

    /// Patch the CRC trailer to match the (mutated) bytes — the corruption
    /// tests that target SEMANTIC checks must defeat the checksum, exactly
    /// like a sophisticated tamperer would.
    fn repatch_crc(bytes: &mut [u8]) {
        let n = bytes.len();
        let crc = crc32(&bytes[..n - 4]);
        bytes[n - 4..].copy_from_slice(&crc.to_le_bytes());
    }

    // -- pure: round trips, determinism ------------------------------------

    #[test]
    fn round_trip_empty_store_is_deterministic() {
        let projection = DurableProjection::new(600);
        let a = projection.to_bytes().unwrap();
        let b = projection.to_bytes().unwrap();
        assert_eq!(a, b, "encoding is canonical/deterministic");
        assert_eq!(a.len(), HEADER_LEN + CRC_LEN, "empty body");
        let reloaded = DurableProjection::from_bytes(&a).unwrap();
        assert_eq!(reloaded, projection);
        assert_eq!(reloaded.freshness_window_secs(), 600);
        assert!(reloaded.contracts().is_empty());
        // Encode(decode(encode)) is stable (canonical form).
        let c = reloaded.to_bytes().unwrap();
        assert_eq!(a, c);
    }

    #[test]
    fn round_trip_full_projection_multi_contract() {
        let mut projection = DurableProjection::new(600);
        projection.register(&contract(1)); // held, never observed
        projection.register(&contract(2));
        assert_eq!(
            projection.accept(&obs(ObservationKind::ContractActivated, 1_000, 2, 1)),
            AcceptOutcome::Accepted
        );
        // A sequence gap (other contracts consumed 2..=5) is normal, not
        // corruption: per-provider sequences are global.
        assert_eq!(
            projection.accept(&obs(ObservationKind::Degraded, 1_010, 2, 7)),
            AcceptOutcome::Accepted
        );
        assert_eq!(
            projection.accept(&obs(ObservationKind::AssuranceAvailable, 1_020, 2, 9)),
            AcceptOutcome::Accepted
        );
        assert_eq!(
            projection.accept(&obs(ObservationKind::Terminated, 1_030, 2, 10)),
            AcceptOutcome::Accepted
        );
        assert_eq!(
            projection.accept(&obs(ObservationKind::ContractActivated, 1_005, 1, 2)),
            AcceptOutcome::Accepted
        );

        let bytes = projection.to_bytes().unwrap();
        let reloaded = DurableProjection::from_bytes(&bytes).unwrap();
        assert_eq!(reloaded, projection, "full structural round trip");
        assert_eq!(reloaded.freshness_window_secs(), 600);

        // The health view round-trips exactly, including freshness at
        // several evaluation times.
        for tag in [1u8, 2u8] {
            let before = projection.health(&contract(tag)).unwrap();
            let after = reloaded.health(&contract(tag)).unwrap();
            assert_eq!(before, after);
            for now in [0u64, 1_000, 1_600, 1_601, 10_000] {
                assert_eq!(before.freshness(now), after.freshness(now));
            }
        }
        assert_eq!(reloaded.health(&contract(2)).unwrap().state(), ContractState::Terminated);
        assert_eq!(reloaded.health(&contract(1)).unwrap().state(), ContractState::Active);
    }

    #[test]
    fn rederivation_equals_live_projection_for_same_stream() {
        // Drive the R5-001 fake through a full lifecycle (its virtual clock
        // and sequences are deterministic), feed a live projection, then
        // verify the reloaded projection is EXACTLY the live one.
        use crate::memory::InMemoryConnectivityPort;
        use crate::requirement::{ConnectivityRequirement, ServiceClass};

        let provider = InMemoryConnectivityPort::new();
        let intent = provider
            .create_intent(ConnectivityRequirement::new(ServiceClass::Live))
            .unwrap();
        let offers = provider.discover_offers(&intent).unwrap();
        let a = provider.accept_offer(&intent, &offers[0]).unwrap();
        let b = provider.accept_offer(&intent, &offers[1]).unwrap();

        provider.emit_observation(&a, ObservationKind::ContractActivated).unwrap();
        provider.set_execution(&a, "active", 1_000, 20).unwrap();
        provider.emit_observation(&a, ObservationKind::Degraded).unwrap();
        provider.emit_observation(&b, ObservationKind::ContractActivated).unwrap();
        provider.emit_observation(&a, ObservationKind::FailoverReplan).unwrap();
        provider.terminate(&a).unwrap();
        // Provider redeliveries must dedup identically live and reloaded.
        let stream_a = provider.get_assurance(&a).unwrap();
        let replayed = provider.replay_observation(&a, stream_a[0].sequence()).unwrap().unwrap();

        let mut live = DurableProjection::new(600);
        for observation in provider.get_assurance(&a).unwrap() {
            live.accept(&observation);
        }
        for observation in provider.get_assurance(&b).unwrap() {
            live.accept(&observation);
        }
        assert!(live.accept(&replayed) == AcceptOutcome::IgnoredReplay { sequence: replayed.sequence() });

        let bytes = live.to_bytes().unwrap();
        let reloaded = DurableProjection::from_bytes(&bytes).unwrap();
        assert_eq!(reloaded, live, "re-derivation == live projection");
        for c in live.contracts() {
            assert_eq!(reloaded.health(&c).unwrap(), live.health(&c).unwrap());
        }
        // Terminal state survived and the reloaded log is identical.
        let health = reloaded.health(&a).unwrap();
        assert_eq!(health.state(), ContractState::Terminated);
        assert_eq!(health.observations(), live.health(&a).unwrap().observations());
    }

    // -- pure: fail-closed corruption --------------------------------------

    #[test]
    fn every_truncation_fails_closed() {
        let mut projection = DurableProjection::new(600);
        projection.accept(&obs(ObservationKind::ContractActivated, 1_000, 3, 1));
        projection.accept(&obs(ObservationKind::Degraded, 1_010, 3, 4));
        let bytes = projection.to_bytes().unwrap();
        for cut in 0..bytes.len() {
            let truncated = &bytes[..cut];
            assert!(
                DurableProjection::from_bytes(truncated).is_err(),
                "truncation at {cut} bytes must fail closed"
            );
        }
        // Spot-check the typed reasons.
        assert_eq!(
            DurableProjection::from_bytes(&[]),
            Err(StoreError::LengthMismatch { expected: HEADER_LEN + CRC_LEN, actual: 0 })
        );
        // Cutting into the CRC trailer still under-runs the declared body.
        let cut = bytes.len() - 2;
        match DurableProjection::from_bytes(&bytes[..cut]).unwrap_err() {
            StoreError::LengthMismatch { .. } => {}
            other => panic!("wrong error for CRC truncation: {other:?}"),
        }
    }

    #[test]
    fn every_bit_flip_fails_closed() {
        // Every single-byte mutation of a valid image is caught by the
        // magic, version, flags, length arithmetic, or the CRC-32 — no
        // silent corruption survives.
        let mut projection = DurableProjection::new(600);
        projection.accept(&obs(ObservationKind::ContractActivated, 1_000, 5, 1));
        projection.accept(&obs(ObservationKind::ExecutionStateChanged, 1_010, 5, 2));
        projection.accept(&obs(ObservationKind::Terminated, 1_020, 5, 3));
        let bytes = projection.to_bytes().unwrap();
        for i in 0..bytes.len() {
            for mask in [0xFFu8, 0x01, 0x80] {
                let mut mutated = bytes.clone();
                mutated[i] ^= mask;
                assert!(
                    DurableProjection::from_bytes(&mutated).is_err(),
                    "mutation at byte {i} (^{mask:#x}) must fail closed"
                );
            }
        }
    }

    #[test]
    fn header_fields_fail_typed() {
        let mut projection = DurableProjection::new(600);
        projection.accept(&obs(ObservationKind::ContractActivated, 1_000, 9, 1));
        let bytes = projection.to_bytes().unwrap();

        let mut bad_magic = bytes.clone();
        bad_magic[0] = b'X';
        assert_eq!(DurableProjection::from_bytes(&bad_magic), Err(StoreError::BadMagic));

        let mut bad_version = bytes.clone();
        bad_version[4] = 2;
        assert_eq!(
            DurableProjection::from_bytes(&bad_version),
            Err(StoreError::VersionUnsupported { found: 2 })
        );

        let mut bad_flags = bytes.clone();
        bad_flags[6] = 1;
        assert_eq!(
            DurableProjection::from_bytes(&bad_flags),
            Err(StoreError::FlagsUnsupported { found: 1 })
        );

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            DurableProjection::from_bytes(&trailing),
            Err(StoreError::TrailingBytes { extra: 1 })
        );
    }

    #[test]
    fn lying_summary_fails_closed() {
        // A tamperer rewrites the persisted state summary AND fixes the
        // checksum — the re-derivation cross-check still refuses it.
        let mut projection = DurableProjection::new(600);
        projection.accept(&obs(ObservationKind::ContractActivated, 1_000, 4, 1));
        let mut bytes = projection.to_bytes().unwrap();
        let state_tag_offset = HEADER_LEN + REF_ID_LEN + 1; // after id + ref-kind tag
        assert_eq!(bytes[state_tag_offset], 1, "active");
        bytes[state_tag_offset] = 3; // claim terminated
        repatch_crc(&mut bytes);
        assert_eq!(
            DurableProjection::from_bytes(&bytes),
            Err(StoreError::SummaryDisagrees {
                contract: contract(4),
                persisted: ContractState::Terminated,
                derived: ContractState::Active,
            })
        );
    }

    #[test]
    fn non_increasing_sequence_fails_closed() {
        let mut projection = DurableProjection::new(600);
        projection.accept(&obs(ObservationKind::ContractActivated, 1_000, 6, 1));
        projection.accept(&obs(ObservationKind::Degraded, 1_010, 6, 3));
        let mut bytes = projection.to_bytes().unwrap();
        // Second observation's sequence (last 8 bytes of its entry).
        let offset = HEADER_LEN + RECORD_FIXED_LEN + OBSERVATION_LEN + 9;
        bytes[offset..offset + 8].copy_from_slice(&1u64.to_le_bytes()); // 1 <= 3
        repatch_crc(&mut bytes);
        assert_eq!(
            DurableProjection::from_bytes(&bytes),
            Err(StoreError::SequenceNotIncreasing {
                contract: contract(6),
                previous: 1,
                next: 1,
            })
        );
    }

    #[test]
    fn lying_metadata_fails_closed() {
        let mut projection = DurableProjection::new(600);
        projection.accept(&obs(ObservationKind::ContractActivated, 1_000, 7, 1));
        let mut bytes = projection.to_bytes().unwrap();
        let last_at_offset = HEADER_LEN + REF_ID_LEN + 2; // after id + ref-kind + state tags
        bytes[last_at_offset..last_at_offset + 8].copy_from_slice(&9_999u64.to_le_bytes());
        repatch_crc(&mut bytes);
        assert_eq!(
            DurableProjection::from_bytes(&bytes),
            Err(StoreError::MetadataDisagrees {
                contract: contract(7),
                stored_observed_at: 9_999,
                stored_sequence: 1,
                log_observed_at: 1_000,
                log_sequence: 1,
            })
        );
    }

    #[test]
    fn invalid_tags_fail_closed() {
        let mut projection = DurableProjection::new(600);
        projection.accept(&obs(ObservationKind::ContractActivated, 1_000, 8, 1));
        let mut bytes = projection.to_bytes().unwrap();

        // Observation kind tag beyond the six adcos.md events.
        let kind_offset = HEADER_LEN + RECORD_FIXED_LEN;
        bytes[kind_offset] = 6;
        repatch_crc(&mut bytes);
        assert_eq!(
            DurableProjection::from_bytes(&bytes),
            Err(StoreError::ObservationKindTagInvalid { found: 6 })
        );

        // Contract state tag beyond the four states.
        let mut bytes = projection.to_bytes().unwrap();
        let state_offset = HEADER_LEN + REF_ID_LEN + 1;
        bytes[state_offset] = 4;
        repatch_crc(&mut bytes);
        assert_eq!(
            DurableProjection::from_bytes(&bytes),
            Err(StoreError::StateTagInvalid { found: 4 })
        );

        // A record claiming to be an OFFER record: the from_parts seam
        // refuses to re-type an offer id as a contract record.
        let mut bytes = projection.to_bytes().unwrap();
        let kind_tag_offset = HEADER_LEN + REF_ID_LEN;
        bytes[kind_tag_offset] = 1; // offer
        repatch_crc(&mut bytes);
        assert_eq!(
            DurableProjection::from_bytes(&bytes),
            Err(StoreError::RecordKindNotContract { found: RefKind::Offer })
        );

        // A ref-kind tag that is not any kind at all.
        let mut bytes = projection.to_bytes().unwrap();
        bytes[kind_tag_offset] = 7;
        repatch_crc(&mut bytes);
        assert_eq!(
            DurableProjection::from_bytes(&bytes),
            Err(StoreError::RefKindTagInvalid { found: 7 })
        );
    }

    #[test]
    fn duplicate_record_fails_closed() {
        let mut projection = DurableProjection::new(600);
        projection.accept(&obs(ObservationKind::ContractActivated, 1_000, 2, 1));
        let bytes = projection.to_bytes().unwrap();
        // Hand-build: header declaring 2 records, body = the SAME record
        // twice (checksum recomputed) — the duplicate must be refused.
        let body_len = u32::from_le_bytes(bytes[20..24].try_into().unwrap()) as usize;
        let record = bytes[HEADER_LEN..HEADER_LEN + body_len].to_vec();
        let mut forged = Vec::with_capacity(bytes.len() + record.len());
        forged.extend_from_slice(&STORE_MAGIC);
        forged.extend_from_slice(&STORE_FORMAT_VERSION.to_le_bytes());
        forged.extend_from_slice(&0u16.to_le_bytes());
        forged.extend_from_slice(&600u64.to_le_bytes());
        forged.extend_from_slice(&2u32.to_le_bytes()); // two records
        forged.extend_from_slice(&((body_len * 2) as u32).to_le_bytes());
        forged.extend_from_slice(&record);
        forged.extend_from_slice(&record);
        let crc = crc32(&forged);
        forged.extend_from_slice(&crc.to_le_bytes());
        assert_eq!(
            DurableProjection::from_bytes(&forged),
            Err(StoreError::DuplicateRecord { contract: contract(2) })
        );
    }

    #[test]
    fn oversized_file_fails_closed() {
        let huge = vec![0u8; MAX_STORE_FILE_BYTES as usize + 1];
        assert_eq!(
            DurableProjection::from_bytes(&huge),
            Err(StoreError::StoreTooLarge {
                size: MAX_STORE_FILE_BYTES + 1,
                max: MAX_STORE_FILE_BYTES,
            })
        );
    }

    // -- pure: semantics ----------------------------------------------------

    #[test]
    fn sequence_gaps_do_not_fabricate() {
        let mut projection = DurableProjection::new(600);
        assert_eq!(
            projection.accept(&obs(ObservationKind::ContractActivated, 1_000, 1, 1)),
            AcceptOutcome::Accepted
        );
        assert_eq!(
            projection.accept(&obs(ObservationKind::Degraded, 1_010, 1, 2)),
            AcceptOutcome::Accepted
        );
        // Gap: sequences 3..=6 were consumed elsewhere (per-provider global
        // counter). Accepting 7 is normal; the gap fabricates NOTHING.
        assert_eq!(
            projection.accept(&obs(ObservationKind::Terminated, 1_020, 1, 7)),
            AcceptOutcome::Accepted
        );
        let health = projection.health(&contract(1)).unwrap();
        assert_eq!(
            health.observations().iter().map(|o| o.sequence()).collect::<Vec<_>>(),
            vec![1, 2, 7],
            "the gap is honest: no invented observations"
        );
        assert_eq!(health.state(), ContractState::Terminated, "derived only from what was accepted");
        // A late delivery INSIDE the gap is a replay by per-provider
        // monotonicity — ignored, never fabricated in.
        assert_eq!(
            projection.accept(&obs(ObservationKind::AssuranceAvailable, 1_015, 1, 5)),
            AcceptOutcome::IgnoredReplay { sequence: 5 }
        );
        // The stream continues after the gap.
        assert_eq!(
            projection.accept(&obs(ObservationKind::FailoverReplan, 1_030, 1, 8)),
            AcceptOutcome::Accepted
        );
        assert_eq!(projection.health(&contract(1)).unwrap().highest_sequence(), Some(8));
    }

    #[test]
    fn freshness_math_is_exclusive_and_saturating() {
        let mut projection = DurableProjection::new(600);
        // No observation YET (a registered, held contract): no freshness
        // claim, not "fresh".
        projection.register(&contract(1));
        let none = projection.health(&contract(1)).unwrap();
        assert_eq!(none.freshness(0), ProjectionFreshness::NoObservation);
        assert_eq!(none.highest_sequence(), None);
        // An unknown contract has no health at all (never fabricated).
        assert!(projection.health(&contract(9)).is_none());

        projection.accept(&obs(ObservationKind::ContractActivated, 1_000, 1, 1));
        let health = projection.health(&contract(1)).unwrap();
        assert_eq!(health.last_accepted().unwrap().fresh_until_unix(), 1_600);
        assert_eq!(health.freshness(1_599), ProjectionFreshness::Fresh { fresh_until_unix: 1_600 });
        assert_eq!(
            health.freshness(1_600),
            ProjectionFreshness::Stale { fresh_until_unix: 1_600, last_observed_at_unix: 1_000 },
            "the bound is exclusive"
        );
        assert_eq!(health.freshness(u64::MAX), ProjectionFreshness::Stale {
            fresh_until_unix: 1_600,
            last_observed_at_unix: 1_000,
        });

        // Saturating window math at the edge of the u64 range: no panic.
        let mut edge = DurableProjection::new(u64::MAX);
        edge.accept(&obs(ObservationKind::ContractActivated, u64::MAX - 1, 2, 1));
        let edge_health = edge.health(&contract(2)).unwrap();
        assert_eq!(edge_health.last_accepted().unwrap().fresh_until_unix(), u64::MAX);
        assert_eq!(
            edge_health.freshness(u64::MAX - 1),
            ProjectionFreshness::Fresh { fresh_until_unix: u64::MAX }
        );
        assert_eq!(edge_health.freshness(u64::MAX), ProjectionFreshness::Stale {
            fresh_until_unix: u64::MAX,
            last_observed_at_unix: u64::MAX - 1,
        });

        // A zero window: accept-then-immediately-stale.
        let mut zero = DurableProjection::new(0);
        zero.accept(&obs(ObservationKind::ContractActivated, 1_000, 3, 1));
        assert_eq!(
            zero.health(&contract(3)).unwrap().freshness(1_000),
            ProjectionFreshness::Stale { fresh_until_unix: 1_000, last_observed_at_unix: 1_000 }
        );
    }

    #[test]
    fn reload_keeps_original_freshness_metadata_never_fabricates() {
        // The adcos.md no-fabrication law, as code: a reload long after an
        // outage serves the LAST ACCEPTED observation with its ORIGINAL
        // freshness metadata — typed Stale, never re-anchored, never
        // refreshed, never a fabricated current state.
        let mut projection = DurableProjection::new(600);
        projection.accept(&obs(ObservationKind::ContractActivated, 1_000, 1, 1));
        let bytes = projection.to_bytes().unwrap();

        let reloaded = DurableProjection::from_bytes(&bytes).unwrap();
        let health = reloaded.health(&contract(1)).unwrap();
        let last = health.last_accepted().unwrap();
        assert_eq!(last.observation().observed_at_unix(), 1_000, "original observed_at");
        assert_eq!(last.observation().kind(), ObservationKind::ContractActivated);
        assert_eq!(last.fresh_until_unix(), 1_600, "original bound (1_000 + window 600)");
        // Reload "now" far past the bound: stale typed, ORIGINAL metadata.
        assert_eq!(
            health.freshness(1_000_000),
            ProjectionFreshness::Stale { fresh_until_unix: 1_600, last_observed_at_unix: 1_000 }
        );
        // And still fresh just before the bound.
        assert_eq!(
            health.freshness(1_599),
            ProjectionFreshness::Fresh { fresh_until_unix: 1_600 }
        );
        // The state is still the accepted evidence (Active), never
        // fabricated into something newer.
        assert_eq!(health.state(), ContractState::Active);
    }

    #[test]
    fn dedup_matches_observation_cache_policy() {
        // The store's accept() must agree with the R5-001 ObservationCache
        // on every delivery of the same stream (the same dedup law, durable).
        let stream = [
            obs(ObservationKind::ContractActivated, 1_000, 1, 1),
            obs(ObservationKind::ContractActivated, 1_000, 1, 1), // exact duplicate
            obs(ObservationKind::Degraded, 1_010, 1, 4),
            obs(ObservationKind::Degraded, 1_005, 1, 2), // reordered replay
            obs(ObservationKind::Terminated, 1_020, 1, 6),
            obs(ObservationKind::ContractActivated, 1_000, 2, 3), // other contract
        ];
        let mut projection = DurableProjection::new(600);
        let mut cache = crate::observation::ObservationCache::new(600);
        for observation in &stream {
            assert_eq!(
                projection.accept(observation),
                cache.accept(observation),
                "store and cache agree on {observation:?}"
            );
        }
        let cached = cache.last_accepted(&contract(1)).unwrap();
        let stored_health = projection.health(&contract(1)).unwrap();
        let stored = stored_health.last_accepted().unwrap();
        assert_eq!(stored.observation(), cached.observation());
        assert_eq!(stored.fresh_until_unix(), cached.fresh_until_unix());
        // And after a round trip the reloaded store keeps agreeing.
        let mut reloaded = DurableProjection::from_bytes(&projection.to_bytes().unwrap()).unwrap();
        for observation in &stream {
            assert_eq!(reloaded.accept(observation), AcceptOutcome::IgnoredReplay {
                sequence: observation.sequence()
            });
        }
    }

    #[test]
    fn register_is_idempotent_and_projects() {
        let mut projection = DurableProjection::new(600);
        projection.register(&contract(1));
        projection.register(&contract(1)); // idempotent
        let health = projection.health(&contract(1)).unwrap();
        assert_eq!(health.state(), ContractState::Projected);
        assert!(health.observations().is_empty());
        assert_eq!(health.freshness(0), ProjectionFreshness::NoObservation);
        // Registering a contract WITH observations never disturbs its log.
        projection.accept(&obs(ObservationKind::ContractActivated, 1_000, 2, 1));
        projection.register(&contract(2));
        assert_eq!(projection.health(&contract(2)).unwrap().observations().len(), 1);
        // Round-trips.
        let reloaded = DurableProjection::from_bytes(&projection.to_bytes().unwrap()).unwrap();
        assert_eq!(reloaded, projection);
        assert_eq!(reloaded.health(&contract(1)).unwrap().state(), ContractState::Projected);
    }
}

/// File-backed restart tests (native only — the wasm host persists through
/// the codec seam instead).
#[cfg(all(test, not(target_family = "wasm")))]
mod file_tests {
    use super::*;
    use crate::observation::AcceptOutcome;
    use crate::port::ConnectivityPort;
    use crate::requirement::{ConnectivityRequirement, ServiceClass};

    fn contract(tag: u8) -> ConnectivityContractRef {
        ConnectivityContractRef::from_id([tag; REF_ID_LEN])
    }

    fn obs(kind: ObservationKind, at: u64, tag: u8, sequence: u64) -> ConnectivityObservation {
        ConnectivityObservation::new(kind, at, contract(tag), sequence)
    }

    /// A unique temp store path (per test tag + process), with best-effort
    /// cleanup on drop — including any leftover flush temp file.
    struct TempStore {
        path: std::path::PathBuf,
    }

    impl TempStore {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("sharenet-r5003-{}", std::process::id()));
            std::fs::create_dir_all(&dir).expect("temp dir");
            Self {
                path: dir.join(format!("{tag}.store")),
            }
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
            let _ = std::fs::remove_file({
                let mut os = self.path.clone().into_os_string();
                os.push(".tmp");
                std::path::PathBuf::from(os)
            });
            let _ = std::fs::remove_dir(self.path.parent().expect("parent"));
        }
    }

    #[test]
    fn file_restart_round_trip_with_state_intact() {
        let temp = TempStore::new("restart-round-trip");
        let mut store = DurableProjectionStore::create(&temp.path, 600).unwrap();
        store.register(&contract(1));
        store.accept(&obs(ObservationKind::ContractActivated, 1_000, 2, 1));
        store.accept(&obs(ObservationKind::Degraded, 1_010, 2, 5));
        store.flush().unwrap();
        let snapshot: Vec<_> = store
            .contracts()
            .iter()
            .map(|c| store.health(c).unwrap())
            .collect();
        drop(store); // FULL teardown — only the file remains.

        // Restart: reload at a time where the data is still fresh.
        let reloaded = DurableProjectionStore::load(&temp.path, 1_200).unwrap();
        assert_eq!(reloaded.revalidated_at_unix(), Some(1_200));
        assert_eq!(reloaded.contracts().len(), 2);
        for health in &snapshot {
            let after = reloaded.health(health.contract()).unwrap();
            assert_eq!(after, *health, "state restored intact");
        }
        // The reload-time re-validation is typed fresh here...
        assert_eq!(
            reloaded.freshness_at_reload(&contract(2)),
            Some(ProjectionFreshness::Fresh { fresh_until_unix: 1_610 })
        );
        // ...and typed stale when the restart happens past the bound.
        let stale_view = DurableProjectionStore::load(&temp.path, 1_610).unwrap();
        assert_eq!(
            stale_view.freshness_at_reload(&contract(2)),
            Some(ProjectionFreshness::Stale {
                fresh_until_unix: 1_610,
                last_observed_at_unix: 1_010,
            })
        );
        // A registered-never-observed contract reloads as NoObservation.
        assert_eq!(
            stale_view.freshness_at_reload(&contract(1)),
            Some(ProjectionFreshness::NoObservation)
        );
        // The projection accessor exposes the pure seam.
        assert_eq!(stale_view.projection().freshness_window_secs(), 600);
    }

    #[test]
    fn torn_and_partial_writes_never_reach_the_store() {
        let temp = TempStore::new("torn-writes");
        let mut store = DurableProjectionStore::create(&temp.path, 600).unwrap();
        store.accept(&obs(ObservationKind::ContractActivated, 1_000, 1, 1));
        store.flush().unwrap();
        let good = std::fs::read(&temp.path).unwrap();
        drop(store);

        // A torn write (a non-atomic writer truncated the store in place):
        // loading must fail typed, never serve partial state.
        for cut in [0, 1, 10, 27, good.len() - 1] {
            std::fs::write(&temp.path, &good[..cut]).unwrap();
            assert!(
                DurableProjectionStore::load(&temp.path, 0).is_err(),
                "torn write (cut {cut}) must fail closed"
            );
        }
        // Trailing garbage glued to a valid image: refused.
        let mut trailing = good.clone();
        trailing.push(0xEE);
        std::fs::write(&temp.path, &trailing).unwrap();
        assert_eq!(
            DurableProjectionStore::load(&temp.path, 0).unwrap_err(),
            StoreError::TrailingBytes { extra: 1 }
        );

        // A stray flush temp file is scratch: never read, never fatal.
        std::fs::write(
            {
                let mut os = temp.path.clone().into_os_string();
                os.push(".tmp");
                std::path::PathBuf::from(os)
            },
            b"garbage from a crashed flush",
        )
        .unwrap();
        std::fs::write(&temp.path, &good).unwrap();
        let reloaded = DurableProjectionStore::load(&temp.path, 1_000).unwrap();
        assert_eq!(reloaded.health(&contract(1)).unwrap().state(), ContractState::Active);

        // The next flush atomically replaces the store and consumes the
        // temp file (rename): no partial image is ever the store.
        let mut store = reloaded;
        store.accept(&obs(ObservationKind::Terminated, 1_020, 1, 2));
        store.flush().unwrap();
        let tmp_path = {
            let mut os = temp.path.clone().into_os_string();
            os.push(".tmp");
            std::path::PathBuf::from(os)
        };
        assert!(!tmp_path.exists(), "flush consumed the temp file via rename");
        let again = DurableProjectionStore::load(&temp.path, 1_000).unwrap();
        assert_eq!(again.health(&contract(1)).unwrap().state(), ContractState::Terminated);
    }

    #[test]
    fn create_refuses_to_clobber_existing_store() {
        let temp = TempStore::new("clobber");
        let mut store = DurableProjectionStore::create(&temp.path, 600).unwrap();
        store.accept(&obs(ObservationKind::ContractActivated, 1_000, 1, 1));
        store.flush().unwrap();
        drop(store);

        assert_eq!(
            DurableProjectionStore::create(&temp.path, 600).unwrap_err(),
            StoreError::StoreAlreadyExists
        );
        // The existing file is intact — load still works.
        let reloaded = DurableProjectionStore::load(&temp.path, 0).unwrap();
        assert_eq!(reloaded.contracts().len(), 1);

        // A fresh create on a NEW path works and writes the empty image.
        let temp2 = TempStore::new("clobber-2");
        let store = DurableProjectionStore::create(&temp2.path, 0).unwrap();
        assert!(store.contracts().is_empty());
        let reloaded = DurableProjectionStore::load(&temp2.path, 0).unwrap();
        assert!(reloaded.contracts().is_empty());
    }

    #[test]
    fn terminal_state_and_dedup_survive_restart() {
        // The fake drives a real event stream; terminate idempotence is
        // proven at the projection level across a restart.
        let provider = crate::memory::InMemoryConnectivityPort::new();
        let intent = provider
            .create_intent(ConnectivityRequirement::new(ServiceClass::Dtn))
            .unwrap();
        let offers = provider.discover_offers(&intent).unwrap();
        let c = provider.accept_offer(&intent, &offers[0]).unwrap();

        let temp = TempStore::new("terminal-restart");
        let mut store = DurableProjectionStore::create(&temp.path, 600).unwrap();
        provider
            .emit_observation(&c, ObservationKind::ContractActivated)
            .unwrap();
        for observation in provider.get_assurance(&c).unwrap() {
            store.accept(&observation);
        }
        store.flush().unwrap();
        drop(store);

        // Restart mid-life: the reloaded store continues the sequence with
        // no regression (redeliveries ignored, next sequence accepted).
        let mut store = DurableProjectionStore::load(&temp.path, 0).unwrap();
        let pre = store.health(&c).unwrap();
        let highest = pre.highest_sequence().unwrap();
        for observation in provider.get_assurance(&c).unwrap() {
            assert_eq!(
                store.accept(&observation),
                AcceptOutcome::IgnoredReplay { sequence: observation.sequence() },
                "redelivery after restart must not regress"
            );
        }
        provider.terminate(&c).unwrap();
        for observation in provider.get_assurance(&c).unwrap() {
            store.accept(&observation);
        }
        let post = store.health(&c).unwrap();
        assert_eq!(post.state(), ContractState::Terminated);
        assert!(post.highest_sequence().unwrap() > highest);
        store.flush().unwrap();
        drop(store);

        // Restart again: terminal state intact, and replaying the full log
        // (including the terminated observation) changes nothing — the
        // terminate idempotence preserved across restarts.
        let mut store = DurableProjectionStore::load(&temp.path, 0).unwrap();
        for observation in provider.get_assurance(&c).unwrap() {
            assert_eq!(
                store.accept(&observation),
                AcceptOutcome::IgnoredReplay { sequence: observation.sequence() }
            );
        }
        assert_eq!(store.health(&c).unwrap().state(), ContractState::Terminated);
    }
}
