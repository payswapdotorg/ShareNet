//! The durable circuit-revocation ledger file — work item R7-002, the
//! durability layer the R7-001 snapshot seam deferred.
//!
//! R7-001 ([`sharenet_protocol::revocation::RevocationLedger`]) models
//! durability as a serialized canonical snapshot and honestly documents
//! the gap: *"full durable files (atomic append-only storage, retention,
//! crash recovery) are R7-002 scope; the seam is the honest in-memory
//! boundary between the two. A snapshot attack that DELETES whole
//! records cannot be caught by per-record signatures — R7-002 must use
//! append-only durable storage to close that hole."*
//!
//! This module IS that durable storage:
//!
//! - **Append-only**: revocations are never rewritten or removed. Each
//!   admitted revocation is appended as one framed record and `fsync`ed
//!   before the call returns (durable-first: the in-memory authority is
//!   only updated after the record reached the disk).
//! - **Chain-verified**: every record stores
//!   `prev_chain = SHA-256("sharenet-revocation-chain-v1" || chain after
//!   the previous record || previous payload)`. Deleting, reordering or
//!   replaying records breaks the chain at the first surviving link and
//!   the file fails closed — the whole-record-deletion hole is closed
//!   for every position except the TAIL (see the honest limits).
//! - **Fail-closed load**: magic/version/flags checks, per-record CRC-32,
//!   per-record envelope signature re-verification, chain walk, and the
//!   final state is rebuilt by round-tripping the surviving records
//!   through the R7-001 snapshot seam
//!   ([`RevocationLedger::from_snapshot_bytes`]) — the R7-001 checks
//!   (canonical order, per-(circuit, revoker) uniqueness, signature
//!   re-verification) run on the durable bytes too.
//! - **Crash-safe**: a torn FINAL record (a crash mid-append; length
//!   short of EOF, or a CRC/envelope failure of the record whose extent
//!   exactly reaches EOF) is the append log's expected crash residue:
//!   it is discarded from the loaded view and surfaced in the
//!   [`LedgerLoadReport`]. Loads never WRITE (a concurrent reader can
//!   never fight a writer); the on-disk repair (truncate to the last
//!   good record) runs under the store's own mutex at the NEXT append,
//!   so no record can ever extend past the residue. Any failure NOT at
//!   the tail is corruption and fails closed.
//!
//! [`is_revoked`] on this type is the L015 authority, now backed by the
//! file: load it, hand [`Self::ledger`] to
//! [`sharenet_protocol::circuit::CircuitRegistry::install_revocation_ledger`],
//! and revoked circuit ids stay revoked across restarts.
//!
//! # File format (v1, node-local durable state — not a wire object)
//!
//! ```text
//! header (8 bytes, immutable):
//!   [0..4]   magic = b"SNRL" (ShareNet Revocation Ledger)
//!   [4..6]   format_version = 1 (u16 LE)
//!   [6..8]   flags = 0 (u16 LE; nonzero refused)
//!
//! records (append-only, admission order):
//!   [0..4]   payload_len (u32 LE)
//!   [4..8]   payload_crc32 (u32 LE; CRC-32/IEEE of the payload)
//!   [8..40]  prev_chain (32 bytes; all-zero genesis for the first record)
//!   [40..]   payload — the SignedCircuitRevocation carrying-envelope bytes
//! ```
//!
//! The chain value after record *i* is
//! `SHA-256("sharenet-revocation-chain-v1" || prev_chain_i || payload_i)`
//! and is stored as record *i+1*'s `prev_chain` (not stored anywhere for
//! the last record — the file's length is its extent).
//!
//! # Honest limits (documented, by design)
//!
//! - **Tail truncation / rollback**: an attacker with write access to the
//!   file can drop the last record (or corrupt the final record into a
//!   torn-tail repair) and the load cannot distinguish that from crash
//!   residue — the resulting ledger is a consistent prefix. Full rollback
//!   resistance needs external anchoring (e.g. periodic exchange of
//!   revocation digests with peers, a second device, or the R7-006
//!   multi-node recovery layer) and is out of R7-002 scope. The chain
//!   closes deletion/reorder/replay for every NON-tail position.
//! - **Recomputation**: the chain is unkeyed; an attacker who recomputes
//!   chains can rewrite any local file — the per-record Ed25519
//!   signatures are what authenticate records, and they cannot be forged
//!   (the rollback limit above still applies).
//! - **Single writer**: one process owns the file (the append path and
//!   the in-memory ledger are serialized under the store's mutex);
//!   cross-process coordination is the caller's (the R5-003 discipline).
//! - **Whole-ledger re-verification at load** is O(records) signature
//!   verifications — bounded by the file cap.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use sharenet_protocol::cbor::{encode, Value};
use sharenet_protocol::circuit::CircuitRegistry;
use sharenet_protocol::revocation::{
    RevocationAdmitOutcome, RevocationError, RevocationLedger, REVOCATION_SNAPSHOT_VERSION,
    SignedCircuitRevocation,
};

use crate::error::{RecoveryError, RecoveryIoOp};
use crate::sha256::chain_next;

/// File magic: **SN**etnet **R**evocation **L**edger.
pub const LEDGER_MAGIC: [u8; 4] = *b"SNRL";
/// The ledger-log format version this code writes and accepts.
pub const LEDGER_FORMAT_VERSION: u16 = 1;
/// Hard cap on the ledger file (read and write side) — bounded durable
/// state, fail-closed against hostile files.
pub const MAX_LEDGER_FILE_BYTES: u64 = 4 * 1024 * 1024;
/// The fixed per-record framing prefix: payload_len + payload_crc32 +
/// prev_chain.
const RECORD_PREFIX_LEN: usize = 4 + 4 + 32;
/// The immutable file header length.
const HEADER_LEN: usize = 8;

/// The all-zero genesis chain value (the first record's `prev_chain`).
pub const GENESIS_CHAIN: [u8; 32] = [0u8; 32];

// ---------------------------------------------------------------------------
// CRC-32/IEEE (the same corruption detector as the R5-003 store format)
// ---------------------------------------------------------------------------

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
// Load report
// ---------------------------------------------------------------------------

/// What [`DurableRevocationLedger::load`] found and (honestly) did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LedgerLoadReport {
    /// The number of torn-tail bytes found and discarded from the loaded
    /// view (a crash mid-append). Zero for a clean file. The on-disk
    /// truncation (the only repair the durable layer ever does) runs at
    /// the NEXT append — loads never write.
    pub truncated_tail_bytes: u64,
    /// The number of verified records loaded.
    pub records_loaded: usize,
}

// ---------------------------------------------------------------------------
// Inner state
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct LedgerInner {
    /// The in-memory R7-001 authority — built ONLY from verified file
    /// bytes (load) or through the durable-first admit path.
    ledger: RevocationLedger,
    /// The admitted records in file order (the durable log's mirror).
    records: Vec<SignedCircuitRevocation>,
    /// The chain value after the last appended record (genesis = zeros).
    chain_tail: [u8; 32],
    /// A torn tail found at load, not yet repaired on disk: loads never
    /// write (a concurrent reader must never fight a writer), so the
    /// truncation runs under this store's mutex at the NEXT append.
    pending_repair_to: Option<u64>,
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

/// The file-backed circuit-revocation ledger — the durable L015 authority.
///
/// Clones of the inner [`RevocationLedger`] (via [`Self::ledger`]) share
/// the same authoritative view for the lifetime of this store: the inner
/// ledger object is created once (at load/create) and only ever MUTATED
/// through [`Self::admit`], never replaced.
#[derive(Debug)]
pub struct DurableRevocationLedger {
    path: PathBuf,
    inner: Mutex<LedgerInner>,
}

impl DurableRevocationLedger {
    /// Create a fresh (empty) ledger file. Refuses to clobber an
    /// existing file — `load` it instead (no silent data loss).
    pub fn create(path: &Path) -> Result<Self, RecoveryError> {
        if path.exists() {
            return Err(RecoveryError::StoreAlreadyExists { path: path.to_path_buf() });
        }
        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(&LEDGER_MAGIC);
        header.extend_from_slice(&LEDGER_FORMAT_VERSION.to_le_bytes());
        header.extend_from_slice(&0u16.to_le_bytes());
        atomic_create(&path, &header)?;
        Ok(Self {
            path: path.to_path_buf(),
            inner: Mutex::new(LedgerInner {
                ledger: RevocationLedger::new(),
                records: Vec::new(),
                chain_tail: GENESIS_CHAIN,
                pending_repair_to: None,
            }),
        })
    }

    /// Load the ledger from disk — the full fail-closed verification
    /// chain (header, framing, CRC, envelope signatures, chain, R7-001
    /// seam round-trip), with torn-tail repair for crash residue.
    pub fn load(path: &Path) -> Result<(Self, LedgerLoadReport), RecoveryError> {
        let mut bytes = Vec::new();
        File::open(path)
            .and_then(|mut f| f.read_to_end(&mut bytes))
            .map_err(|e| RecoveryError::io(RecoveryIoOp::ReadStore, e))?;
        if bytes.len() as u64 > MAX_LEDGER_FILE_BYTES {
            return Err(RecoveryError::StoreTooLarge {
                which: "ledger",
                size: bytes.len() as u64,
                max: MAX_LEDGER_FILE_BYTES,
            });
        }
        if bytes.len() < HEADER_LEN {
            return Err(RecoveryError::LengthMismatch {
                which: "ledger",
                expected: HEADER_LEN,
                actual: bytes.len(),
            });
        }
        if bytes[0..4] != LEDGER_MAGIC {
            return Err(RecoveryError::BadMagic {
                which: "ledger",
                found: bytes[0..4].try_into().expect("4 bytes"),
            });
        }
        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        if version != LEDGER_FORMAT_VERSION {
            return Err(RecoveryError::VersionUnsupported { which: "ledger", found: version });
        }
        let flags = u16::from_le_bytes([bytes[6], bytes[7]]);
        if flags != 0 {
            return Err(RecoveryError::FlagsUnsupported { which: "ledger", found: flags });
        }

        // Walk the records. `good_len` = end of the last verified record.
        let mut records: Vec<SignedCircuitRevocation> = Vec::new();
        let mut chain = GENESIS_CHAIN;
        let mut offset = HEADER_LEN;
        let mut torn_at: Option<usize> = None;
        let mut record_index = 0usize;
        while offset < bytes.len() {
            let remaining = bytes.len() - offset;
            if remaining < RECORD_PREFIX_LEN {
                // A partial framing prefix at EOF — crash residue.
                torn_at = Some(offset);
                break;
            }
            let payload_len =
                u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("4")) as usize;
            let stored_crc =
                u32::from_le_bytes(bytes[offset + 4..offset + 8].try_into().expect("4"));
            let prev_chain: [u8; 32] =
                bytes[offset + 8..offset + RECORD_PREFIX_LEN].try_into().expect("32");
            let extent = RECORD_PREFIX_LEN.checked_add(payload_len);
            let extent = match extent {
                Some(e) if e <= remaining => e,
                _ => {
                    // Declared extent runs past EOF — crash residue.
                    torn_at = Some(offset);
                    break;
                }
            };
            let payload = &bytes[offset + RECORD_PREFIX_LEN..offset + extent];
            let final_record = offset + extent == bytes.len();
            if crc32(payload) != stored_crc {
                if final_record {
                    // The torn write's classic form: file size includes
                    // unwritten (zero) blocks. Only the FINAL record gets
                    // the benefit of the doubt.
                    torn_at = Some(offset);
                    break;
                }
                return Err(RecoveryError::ChecksumMismatch {
                    which: "ledger",
                    record: record_index,
                });
            }
            let signed = match SignedCircuitRevocation::from_envelope_bytes(payload) {
                Ok(s) => s,
                Err(source) => {
                    if final_record {
                        torn_at = Some(offset);
                        break;
                    }
                    return Err(RecoveryError::LedgerEnvelopeInvalid { record: record_index, source });
                }
            };
            // Chain link: this record's prev_chain must commit to the
            // state after the previous record — ALWAYS enforced, tail
            // included (a torn write cannot corrupt an EARLIER record's
            // bytes, so a broken chain is tampering, never crash residue).
            if prev_chain != chain {
                return Err(RecoveryError::ChainBroken { record: record_index });
            }
            chain = chain_next(&prev_chain, payload);
            records.push(signed);
            offset += extent;
            record_index += 1;
        }

        // Torn tail: recorded (NOT repaired — loads never write, so a
        // concurrent reader can never fight a writer). The repair runs
        // under the store's own mutex at the NEXT append, before any new
        // record can extend past the residue; read-only loads are
        // idempotent against the still-present residue.
        let mut truncated_tail_bytes = 0u64;
        let mut pending_repair_to: Option<u64> = None;
        if let Some(good_len) = torn_at {
            truncated_tail_bytes = (bytes.len() - good_len) as u64;
            pending_repair_to = Some(good_len as u64);
        }

        // The seam round-trip: rebuild the R7-001 ledger through its own
        // snapshot form (order + duplicates + signatures re-verified by
        // the R7-001 code itself — the durable bytes do not get a private
        // path into the authority).
        let ledger = rebuild_through_seam(&records)?;
        let store = Self {
            path: path.to_path_buf(),
            inner: Mutex::new(LedgerInner {
                ledger,
                records,
                chain_tail: chain,
                pending_repair_to,
            }),
        };
        Ok((
            store,
            LedgerLoadReport { truncated_tail_bytes, records_loaded: record_index },
        ))
    }

    /// Load if the file exists, create if it does not.
    pub fn open_or_create(path: &Path) -> Result<(Self, LedgerLoadReport), RecoveryError> {
        if path.exists() {
            Self::load(path)
        } else {
            Ok((Self::create(path)?, LedgerLoadReport::default()))
        }
    }

    /// Admit a verified revocation envelope, durably (durable-first:
    /// the record is appended and fsynced BEFORE the in-memory authority
    /// records it — a revocation is only ever authoritative once it is
    /// on disk).
    ///
    /// The full R7-001 admission chain runs first against a scratch
    /// ledger (parse + signature at [`SignedCircuitRevocation`]
    /// construction, committed-path membership against `registry`,
    /// `revoked_at` not in the future) — a failure admits nothing and
    /// writes nothing.
    pub fn admit_envelope(
        &self,
        now_unix: u64,
        envelope_bytes: &[u8],
        registry: &CircuitRegistry,
    ) -> Result<RevocationAdmitOutcome, RecoveryError> {
        let signed = SignedCircuitRevocation::from_envelope_bytes(envelope_bytes)
            .map_err(|source| RecoveryError::AdmitEnvelopeInvalid { source })?;
        self.admit(now_unix, &signed, registry)
    }

    /// Admit an already-verified signed revocation (see
    /// [`Self::admit_envelope`] for the discipline).
    pub fn admit(
        &self,
        now_unix: u64,
        signed: &SignedCircuitRevocation,
        registry: &CircuitRegistry,
    ) -> Result<RevocationAdmitOutcome, RecoveryError> {
        let mut inner = lock(&self.inner);
        let circuit_id = *signed.revocation().circuit_id();
        let revoker = *signed.revocation().revoker_node_id().as_bytes();

        // Per-(circuit, revoker) idempotence against the DURABLE record
        // set (the mirror of the in-memory authority): the first recorded
        // revocation wins; duplicates change nothing and write nothing.
        if inner.records.iter().any(|r| {
            *r.revocation().circuit_id() == circuit_id
                && *r.revocation().revoker_node_id().as_bytes() == revoker
        }) {
            return Ok(RevocationAdmitOutcome::Duplicate);
        }

        // The R7-001 verification chain against a scratch ledger —
        // nothing live is touched before durability.
        let scratch = RevocationLedger::new();
        scratch
            .admit(now_unix, signed, registry)
            .map_err(|source| RecoveryError::RevocationAdmissionRefused { source })?;

        // The outcome relative to the current state (the scratch admit
        // above ran on an empty ledger, so it cannot tell us this).
        let outcome = if inner.ledger.is_revoked(&circuit_id) {
            RevocationAdmitOutcome::Additional
        } else {
            RevocationAdmitOutcome::First
        };

        // Durable-first: (repair any load-time torn tail so the new
        // record cannot extend past the residue), append + fsync the
        // framed record, then admit into the live in-memory authority.
        let payload = signed.to_envelope_bytes();
        let new_size = file_size(&self.path)? + (RECORD_PREFIX_LEN + payload.len()) as u64;
        if new_size > MAX_LEDGER_FILE_BYTES {
            return Err(RecoveryError::StoreTooLarge {
                which: "ledger",
                size: new_size,
                max: MAX_LEDGER_FILE_BYTES,
            });
        }
        if let Some(good_len) = inner.pending_repair_to.take() {
            repair_truncate(&self.path, good_len)?;
        }
        append_record(&self.path, &inner.chain_tail, &payload)?;
        inner.chain_tail = chain_next(&inner.chain_tail, &payload);
        let live = inner
            .ledger
            .admit(now_unix, signed, registry)
            .map_err(|source| RecoveryError::RevocationAdmissionRefused { source })?;
        if live != outcome {
            return Err(RecoveryError::InternalInconsistent {
                what: "live ledger admission disagreed with the durable record set",
            });
        }
        inner.records.push(signed.clone());
        Ok(outcome)
    }

    /// The authoritative revoked answer (L015): once true for a circuit
    /// id, true forever. Backed by the durable file (loaded verified, or
    /// admitted durable-first).
    pub fn is_revoked(&self, circuit_id: &[u8; 32]) -> bool {
        lock(&self.inner).ledger.is_revoked(circuit_id)
    }

    /// How many distinct path members have recorded revocations for a
    /// circuit (0 = not revoked).
    pub fn revoker_count(&self, circuit_id: &[u8; 32]) -> usize {
        lock(&self.inner).ledger.revoker_count(circuit_id)
    }

    /// The `revoked_at_unix` of the circuit's FIRST recorded revocation
    /// (the §11 freshness anchor the attempt log uses), or `None` when
    /// the circuit is not revoked.
    pub fn revoked_at(&self, circuit_id: &[u8; 32]) -> Option<u64> {
        let inner = lock(&self.inner);
        inner
            .records
            .iter()
            .find(|r| r.revocation().circuit_id() == circuit_id)
            .map(|r| r.revocation().revoked_at_unix())
    }

    /// The number of distinct revoked circuits in the ledger.
    pub fn revoked_circuit_count(&self) -> usize {
        lock(&self.inner).ledger.revoked_circuit_count()
    }

    /// The number of durable records in the file (the append count).
    pub fn record_count(&self) -> usize {
        lock(&self.inner).records.len()
    }

    /// A clone of the inner R7-001 ledger — shares the authoritative view
    /// (install it into a `CircuitRegistry` with
    /// `install_revocation_ledger`; the inner ledger object is never
    /// replaced, only mutated through [`Self::admit`]).
    pub fn ledger(&self) -> RevocationLedger {
        lock(&self.inner).ledger.clone()
    }

    /// The R7-001 snapshot form of the current state (the persistence
    /// seam's serialization — deterministic for equal logical state).
    pub fn to_snapshot_bytes(&self) -> Vec<u8> {
        lock(&self.inner).ledger.to_snapshot_bytes()
    }

    /// The store file path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn lock(inner: &Mutex<LedgerInner>) -> std::sync::MutexGuard<'_, LedgerInner> {
    inner.lock().expect("durable revocation ledger poisoned (a panic occurred mid-mutation)")
}

/// Rebuild the R7-001 ledger by round-tripping the surviving records
/// through the R7-001 snapshot seam (its own order/duplicate/signature
/// checks run on the durable bytes).
fn rebuild_through_seam(records: &[SignedCircuitRevocation]) -> Result<RevocationLedger, RecoveryError> {
    let mut keyed: Vec<&SignedCircuitRevocation> = records.iter().collect();
    keyed.sort_by_key(|r| {
        (
            *r.revocation().circuit_id(),
            *r.revocation().revoker_node_id().as_bytes(),
        )
    });
    let envelopes: Vec<Value> =
        keyed.iter().map(|r| Value::Bytes(r.to_envelope_bytes())).collect();
    let snapshot = encode(&Value::Map(vec![
        (Value::Int(1), Value::Int(REVOCATION_SNAPSHOT_VERSION)),
        (Value::Int(2), Value::Array(envelopes)),
    ]))
    .map_err(|e| RecoveryError::SnapshotInvalid {
        source: RevocationError::Cbor(e.to_string()),
    })?;
    RevocationLedger::from_snapshot_bytes(&snapshot)
        .map_err(|source| RecoveryError::SnapshotInvalid { source })
}

/// Write a fresh file (create) atomically: temp + fsync + rename.
fn atomic_create(path: &Path, bytes: &[u8]) -> Result<(), RecoveryError> {
    let tmp = temp_path(path);
    let mut file =
        File::create(&tmp).map_err(|e| RecoveryError::io(RecoveryIoOp::CreateStore, e))?;
    file.write_all(bytes).map_err(|e| RecoveryError::io(RecoveryIoOp::CreateStore, e))?;
    file.sync_all().map_err(|e| RecoveryError::io(RecoveryIoOp::SyncTemp, e))?;
    drop(file);
    fs::rename(&tmp, path).map_err(|e| RecoveryError::io(RecoveryIoOp::RenameIntoPlace, e))?;
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(".tmp");
    PathBuf::from(os)
}

fn file_size(path: &Path) -> Result<u64, RecoveryError> {
    Ok(fs::metadata(path)
        .map_err(|e| RecoveryError::io(RecoveryIoOp::ReadStore, e))?
        .len())
}

/// Append one framed record at EOF + fsync (the durability unit).
fn append_record(path: &Path, prev_chain: &[u8; 32], payload: &[u8]) -> Result<(), RecoveryError> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .map_err(|e| RecoveryError::io(RecoveryIoOp::AppendLedger, e))?;
    let mut frame = Vec::with_capacity(RECORD_PREFIX_LEN + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&crc32(payload).to_le_bytes());
    frame.extend_from_slice(prev_chain);
    frame.extend_from_slice(payload);
    // One write of the whole frame, under the store mutex — a concurrent
    // reader can observe at most a partial FINAL record (the torn tail
    // the load path repairs), never a partial middle one.
    file.write_all(&frame)
        .and_then(|_| file.sync_all())
        .map_err(|e| RecoveryError::io(RecoveryIoOp::AppendLedger, e))?;
    Ok(())
}

/// Truncate the file to `good_len` and fsync (the torn-tail repair).
fn repair_truncate(path: &Path, good_len: u64) -> Result<(), RecoveryError> {
    let mut file = OpenOptions::new()
        .write(true)
        .open(path)
        .map_err(|e| RecoveryError::io(RecoveryIoOp::RepairTruncate, e))?;
    file.set_len(good_len)
        .and_then(|_| {
            file.seek(SeekFrom::Start(good_len))?;
            file.sync_all()
        })
        .map_err(|e| RecoveryError::io(RecoveryIoOp::RepairTruncate, e))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Unit tests (the R7-002 "unit" verify level for the ledger file)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit as tk;

    /// `create` then `load` of a fresh empty file: a clean report, zero
    /// records, nobody revoked — and `create` never clobbers.
    #[test]
    fn create_load_empty_and_no_clobber() {
        let dir = tk::TempDir::new("ledger-empty");
        let path = dir.ledger_path();
        let store = DurableRevocationLedger::create(&path).expect("create");
        assert!(!store.is_revoked(&[0xAA; 32]));
        assert_eq!(store.record_count(), 0);
        assert_eq!(store.revoked_circuit_count(), 0);
        drop(store);

        let (reloaded, report) = DurableRevocationLedger::load(&path).expect("load");
        assert_eq!(
            report,
            LedgerLoadReport { truncated_tail_bytes: 0, records_loaded: 0 }
        );
        assert_eq!(reloaded.record_count(), 0);

        // create refuses to clobber the existing file (no silent loss).
        let err = DurableRevocationLedger::create(&path).unwrap_err();
        assert!(matches!(err, RecoveryError::StoreAlreadyExists { .. }));
        assert_eq!(err.name(), "store_already_exists");

        // open_or_create loads the existing file (and reports it).
        let (_, report) = DurableRevocationLedger::open_or_create(&path).expect("open");
        assert_eq!(report.records_loaded, 0);
    }

    /// The admission outcomes: First → is_revoked forever; a second
    /// revoker is Additional; the same revoker again is a Duplicate that
    /// writes nothing; the per-circuit views stay consistent.
    #[test]
    fn admit_first_additional_duplicate() {
        let dir = tk::TempDir::new("ledger-admit");
        let (store, w, registry, revoked, _live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        assert_eq!(store.record_count(), 1);
        assert!(store.is_revoked(&revoked));
        assert_eq!(store.revoker_count(&revoked), 1);
        assert_eq!(store.revoked_at(&revoked), Some(tk::NOW));

        // A different path member: Additional (recorded, never un-revokes).
        assert_eq!(
            store
                .admit(tk::NOW, &tk::policy_revocation(&w, revoked, tk::NOW), &registry)
                .unwrap(),
            RevocationAdmitOutcome::Additional
        );
        assert_eq!(store.record_count(), 2);
        assert_eq!(store.revoker_count(&revoked), 2);

        // The same (circuit, revoker) pair again: Duplicate, NOTHING written.
        assert_eq!(
            store
                .admit(tk::NOW, &tk::policy_revocation(&w, revoked, tk::NOW), &registry)
                .unwrap(),
            RevocationAdmitOutcome::Duplicate
        );
        assert_eq!(store.record_count(), 2);

        // A circuit that was never revoked stays unrevoked.
        assert!(!store.is_revoked(&_live));
        assert_eq!(store.revoked_at(&_live), None);
    }

    /// A refused admission (future revoked_at / off-path revoker / unknown
    /// circuit / garbage envelope) writes NOTHING — the file bytes are
    /// unchanged and the authority is untouched.
    #[test]
    fn refused_admission_writes_nothing() {
        let dir = tk::TempDir::new("ledger-refuse");
        let (store, w, registry, revoked, live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        let before = std::fs::read(dir.ledger_path()).expect("read");

        // revoked_at in the future: the R7-001 chain refuses.
        let err = store
            .admit(tk::NOW, &tk::policy_revocation(&w, revoked, tk::NOW + 1), &registry)
            .unwrap_err();
        assert_eq!(err.name(), "revocation_admission_refused");

        // The revoker is not on the committed path.
        let err =
            store.admit(tk::NOW, &tk::off_path_revocation(tk::NOW, revoked), &registry).unwrap_err();
        assert_eq!(err.name(), "revocation_admission_refused");

        // The circuit is unknown to the registry.
        let err = store
            .admit(tk::NOW, &tk::policy_revocation(&w, [0x99; 32], tk::NOW), &registry)
            .unwrap_err();
        assert_eq!(err.name(), "revocation_admission_refused");

        // A garbage envelope.
        let err = store.admit_envelope(tk::NOW, b"not-an-envelope", &registry).unwrap_err();
        assert_eq!(err.name(), "admit_envelope_invalid");

        assert_eq!(std::fs::read(dir.ledger_path()).expect("read"), before);
        assert_eq!(store.record_count(), 1);
        assert_eq!(store.revoker_count(&revoked), 1);
        let _ = live;
    }

    /// Full restart round-trip: three revocations over two circuits, then
    /// teardown → `load` — every answer, count and the R7-001 snapshot
    /// bytes are identical (the durable file is the authority).
    #[test]
    fn restart_round_trip_preserves_authority() {
        let dir = tk::TempDir::new("ledger-restart");
        let (store, w, mut registry, c1, _live) = tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        let c2 = tk::admit_circuit(&w, &mut registry, tk::NOW, [0x73; 32]);
        store
            .admit(tk::NOW + 10, &tk::policy_revocation(&w, c1, tk::NOW + 5), &registry)
            .unwrap();
        store
            .admit(tk::NOW + 20, &tk::link_failure_revocation(&w, c2, tk::NOW + 10), &registry)
            .unwrap();
        assert_eq!(store.record_count(), 3);
        let snapshot = store.to_snapshot_bytes();
        drop(store);

        let (reloaded, report) = DurableRevocationLedger::load(&dir.ledger_path()).expect("load");
        assert_eq!(report, LedgerLoadReport { truncated_tail_bytes: 0, records_loaded: 3 });
        // L015: both circuits stay revoked; nothing un-revokes.
        assert!(reloaded.is_revoked(&c1));
        assert!(reloaded.is_revoked(&c2));
        assert_eq!(reloaded.revoked_circuit_count(), 2);
        assert_eq!(reloaded.revoker_count(&c1), 2);
        assert_eq!(reloaded.revoker_count(&c2), 1);
        // The §11 freshness anchor is the FIRST recorded revocation.
        assert_eq!(reloaded.revoked_at(&c1), Some(tk::NOW));
        assert_eq!(reloaded.revoked_at(&c2), Some(tk::NOW + 10));
        // The seam serialization is identical for equal logical state.
        assert_eq!(reloaded.to_snapshot_bytes(), snapshot);
    }

    /// The R7-001 seam: the durable ledger's snapshot restores into a
    /// plain `RevocationLedger` and the two views agree; installed into a
    /// `CircuitRegistry` it gates setup admission for the revoked id (the
    /// L015 end-to-end posture).
    #[test]
    fn seam_snapshot_round_trips_into_r7001_ledger() {
        let dir = tk::TempDir::new("ledger-seam");
        let (store, w, registry, revoked, _live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        store
            .admit(tk::NOW, &tk::policy_revocation(&w, revoked, tk::NOW), &registry)
            .unwrap();
        drop(store);

        let (reloaded, _) = DurableRevocationLedger::load(&dir.ledger_path()).expect("load");
        let restored = RevocationLedger::from_snapshot_bytes(&reloaded.to_snapshot_bytes())
            .expect("seam restore");
        assert!(restored.is_revoked(&revoked));
        assert_eq!(restored.revoker_count(&revoked), 2);
        assert_eq!(restored.revoked_circuit_count(), 1);

        // The L015 gate through a fresh registry: the revoked circuit id
        // is refused even though this registry has no runtime state.
        let mut gated = CircuitRegistry::new();
        gated.install_revocation_ledger(&restored);
        let env = tk::setup_envelope_for(&w, tk::NOW, [0x71; 32]);
        let err = gated.admit_setup(tk::NOW, &env).unwrap_err();
        assert_eq!(err.name(), "circuit_revoked");
    }

    /// The header regions: a wrong magic, an unsupported version, nonzero
    /// flags and a too-short file all fail closed (typed, nothing loads).
    #[test]
    fn header_corruption_fails_closed() {
        let dir = tk::TempDir::new("ledger-header");
        let (store, _w, _registry, _revoked, _live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        drop(store);
        let good = std::fs::read(dir.ledger_path()).expect("read");

        let mut bad = good.clone();
        bad[0] = b'X';
        std::fs::write(dir.path.join("a"), &bad).unwrap();
        let err = DurableRevocationLedger::load(&dir.path.join("a")).unwrap_err();
        assert!(matches!(err, RecoveryError::BadMagic { which: "ledger", .. }));
        assert_eq!(err.name(), "store_bad_magic");

        let mut bad = good.clone();
        bad[4] = 2;
        std::fs::write(dir.path.join("b"), &bad).unwrap();
        let err = DurableRevocationLedger::load(&dir.path.join("b")).unwrap_err();
        assert!(matches!(err, RecoveryError::VersionUnsupported { which: "ledger", found: 2 }));
        assert_eq!(err.name(), "store_version_unsupported");

        let mut bad = good.clone();
        bad[6] = 1;
        std::fs::write(dir.path.join("c"), &bad).unwrap();
        let err = DurableRevocationLedger::load(&dir.path.join("c")).unwrap_err();
        assert!(matches!(err, RecoveryError::FlagsUnsupported { which: "ledger", found: 1 }));
        assert_eq!(err.name(), "store_flags_unsupported");

        // Every truncation of the immutable header.
        for cut in 0..HEADER_LEN {
            std::fs::write(dir.path.join("d"), &good[..cut]).unwrap();
            let err = DurableRevocationLedger::load(&dir.path.join("d")).unwrap_err();
            assert!(
                matches!(err, RecoveryError::LengthMismatch { which: "ledger", expected: HEADER_LEN, .. }),
                "cut {cut}: {err}"
            );
            assert_eq!(err.name(), "store_length_mismatch");
        }
    }

    /// The record regions: a payload byte flip fails typed on a NON-final
    /// record; on the FINAL record the same flip is the torn-tail crash
    /// residue (discarded from the view, reported — never resurrected).
    #[test]
    fn crc_corruption_typed_by_position() {
        let dir = tk::TempDir::new("ledger-crc");
        let (store, w, registry, revoked, _live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        store
            .admit(tk::NOW, &tk::policy_revocation(&w, revoked, tk::NOW), &registry)
            .unwrap();
        drop(store);
        let good = std::fs::read(dir.ledger_path()).expect("read");
        let frames = tk::ledger_frame_offsets(&good);
        assert_eq!(frames.len(), 2);

        // Flip a payload byte of record 0 (non-final): fail closed.
        let mut bad = good.clone();
        bad[frames[0] + RECORD_PREFIX_LEN + 5] ^= 0x01;
        std::fs::write(dir.path.join("a"), &bad).unwrap();
        let err = DurableRevocationLedger::load(&dir.path.join("a")).unwrap_err();
        assert!(matches!(err, RecoveryError::ChecksumMismatch { which: "ledger", record: 0 }));
        assert_eq!(err.name(), "store_checksum_mismatch");

        // The same flip on the final record: torn tail — the verified
        // prefix survives, the residue is reported.
        let mut bad = good.clone();
        bad[frames[1] + RECORD_PREFIX_LEN + 5] ^= 0x01;
        std::fs::write(dir.path.join("b"), &bad).unwrap();
        let (reloaded, report) = DurableRevocationLedger::load(&dir.path.join("b")).expect("load");
        assert_eq!(report.records_loaded, 1);
        assert!(report.truncated_tail_bytes > 0);
        assert!(reloaded.is_revoked(&revoked));
        assert_eq!(reloaded.revoker_count(&revoked), 1);

        // A flip inside the length field of the final record that makes
        // its declared extent run PAST EOF (the torn write's other
        // classic form).
        let mut bad = good.clone();
        bad[frames[1] + 3] = 0x7F; // a huge payload_len
        std::fs::write(dir.path.join("c"), &bad).unwrap();
        let (reloaded, report) = DurableRevocationLedger::load(&dir.path.join("c")).expect("load");
        assert_eq!(report.records_loaded, 1);
        assert!(report.truncated_tail_bytes > 0);
        assert!(reloaded.is_revoked(&revoked));
    }

    /// An envelope corrupted in a CRC-CONSISTENT way (the signature
    /// re-verification is what catches it): typed on a non-final record,
    /// torn-tail on the final one.
    #[test]
    fn envelope_corruption_typed_by_position() {
        let dir = tk::TempDir::new("ledger-env");
        let (store, w, registry, revoked, _live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        store
            .admit(tk::NOW, &tk::policy_revocation(&w, revoked, tk::NOW), &registry)
            .unwrap();
        drop(store);
        let good = std::fs::read(dir.ledger_path()).expect("read");
        let frames = tk::ledger_frame_offsets(&good);

        // Flip a payload byte AND fix the CRC: record 0 is non-final, so
        // the signature re-verification refuses it typed.
        let mut bad = good.clone();
        let at = frames[0] + RECORD_PREFIX_LEN + 5;
        bad[at] ^= 0x01;
        let payload_len = u32::from_le_bytes(bad[frames[0]..frames[0] + 4].try_into().unwrap())
            as usize;
        let crc = tk::crc32(&bad[frames[0] + RECORD_PREFIX_LEN
            ..frames[0] + RECORD_PREFIX_LEN + payload_len]);
        bad[frames[0] + 4..frames[0] + 8].copy_from_slice(&crc.to_le_bytes());
        std::fs::write(dir.path.join("a"), &bad).unwrap();
        let err = DurableRevocationLedger::load(&dir.path.join("a")).unwrap_err();
        assert!(matches!(err, RecoveryError::LedgerEnvelopeInvalid { record: 0, .. }));
        assert_eq!(err.name(), "ledger_envelope_invalid");

        // Same on the final record: torn tail (the expected crash residue).
        let mut bad = good.clone();
        let at = frames[1] + RECORD_PREFIX_LEN + 5;
        bad[at] ^= 0x01;
        let payload_len = u32::from_le_bytes(bad[frames[1]..frames[1] + 4].try_into().unwrap())
            as usize;
        let crc = tk::crc32(&bad[frames[1] + RECORD_PREFIX_LEN
            ..frames[1] + RECORD_PREFIX_LEN + payload_len]);
        bad[frames[1] + 4..frames[1] + 8].copy_from_slice(&crc.to_le_bytes());
        std::fs::write(dir.path.join("b"), &bad).unwrap();
        let (_, report) = DurableRevocationLedger::load(&dir.path.join("b")).expect("load");
        assert_eq!(report.records_loaded, 1);
        assert!(report.truncated_tail_bytes > 0);
    }

    /// The chain region: a broken `prev_chain`, a reordered pair, a
    /// deleted middle record and a replayed frame are ALL `ChainBroken`
    /// (fail closed); a replay with a RECOMPUTED chain is still refused
    /// by the R7-001 seam (duplicate record).
    #[test]
    fn chain_tampering_fails_closed() {
        let dir = tk::TempDir::new("ledger-chain");
        let (store, w, registry, revoked, _live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        store
            .admit(tk::NOW, &tk::policy_revocation(&w, revoked, tk::NOW), &registry)
            .unwrap();
        drop(store);
        let good = std::fs::read(dir.ledger_path()).expect("read");
        let frames = tk::ledger_frame_offsets(&good);
        let len0 = RECORD_PREFIX_LEN
            + u32::from_le_bytes(good[frames[0]..frames[0] + 4].try_into().unwrap()) as usize;
        let len1 = RECORD_PREFIX_LEN
            + u32::from_le_bytes(good[frames[1]..frames[1] + 4].try_into().unwrap()) as usize;

        // A flipped prev_chain byte of record 1 (not covered by any CRC).
        let mut bad = good.clone();
        bad[frames[1] + 10] ^= 0x01;
        std::fs::write(dir.path.join("a"), &bad).unwrap();
        let err = DurableRevocationLedger::load(&dir.path.join("a")).unwrap_err();
        assert!(matches!(err, RecoveryError::ChainBroken { record: 1 }));
        assert_eq!(err.name(), "ledger_chain_broken");

        // Reordered frames: record 1 first (its prev_chain is not genesis).
        let mut bad = good[..HEADER_LEN].to_vec();
        bad.extend_from_slice(&good[frames[1]..frames[1] + len1]);
        bad.extend_from_slice(&good[frames[0]..frames[0] + len0]);
        std::fs::write(dir.path.join("b"), &bad).unwrap();
        let err = DurableRevocationLedger::load(&dir.path.join("b")).unwrap_err();
        assert!(matches!(err, RecoveryError::ChainBroken { record: 0 }));

        // Record 0 deleted: record 1's prev_chain is not genesis.
        let mut bad = good[..HEADER_LEN].to_vec();
        bad.extend_from_slice(&good[frames[1]..frames[1] + len1]);
        std::fs::write(dir.path.join("c"), &bad).unwrap();
        let err = DurableRevocationLedger::load(&dir.path.join("c")).unwrap_err();
        assert!(matches!(err, RecoveryError::ChainBroken { record: 0 }));

        // A replay of record 0 appended verbatim at the tail.
        let mut bad = good.clone();
        bad.extend_from_slice(&good[frames[0]..frames[0] + len0]);
        std::fs::write(dir.path.join("d"), &bad).unwrap();
        let err = DurableRevocationLedger::load(&dir.path.join("d")).unwrap_err();
        assert!(matches!(err, RecoveryError::ChainBroken { record: 2 }));

        // A replay of record 0 with an HONESTLY RECOMPUTED chain (an
        // attacker who fixes the chaining): the R7-001 seam refuses the
        // duplicate (circuit, revoker) record.
        let payload0 = &good[frames[0] + RECORD_PREFIX_LEN..frames[0] + len0];
        let chain_after_rec1 = crate::sha256::chain_next(
            &good[frames[1] + 8..frames[1] + RECORD_PREFIX_LEN]
                .try_into()
                .expect("32"),
            &good[frames[1] + RECORD_PREFIX_LEN..frames[1] + len1],
        );
        let mut tail = Vec::with_capacity(RECORD_PREFIX_LEN + payload0.len());
        tail.extend_from_slice(&(payload0.len() as u32).to_le_bytes());
        tail.extend_from_slice(&tk::crc32(payload0).to_le_bytes());
        tail.extend_from_slice(&chain_after_rec1);
        tail.extend_from_slice(payload0);
        let mut bad = good.clone();
        bad.extend_from_slice(&tail);
        std::fs::write(dir.path.join("e"), &bad).unwrap();
        let err = DurableRevocationLedger::load(&dir.path.join("e")).unwrap_err();
        assert_eq!(err.name(), "ledger_snapshot_invalid");
    }

    /// A torn tail: a partial frame appended after valid records loads
    /// with the residue reported, loads never write (the repair is
    /// deferred), and the NEXT append repairs the file and extends it
    /// cleanly past the residue.
    #[test]
    fn torn_tail_repaired_only_at_next_append() {
        let dir = tk::TempDir::new("ledger-torn");
        let (store, w, registry, revoked, live) = tk::revoked_ledger(&dir.ledger_path(), tk::NOW);
        drop(store);
        let clean_len = std::fs::metadata(dir.ledger_path()).unwrap().len();

        // Simulate the crash mid-append: half a frame prefix.
        let mut torn = std::fs::read(dir.ledger_path()).unwrap();
        torn.extend_from_slice(&[0x40, 0x00, 0x00]); // a partial length prefix
        std::fs::write(dir.ledger_path(), &torn).unwrap();
        let torn_len = torn.len() as u64;
        assert!(torn_len > clean_len);

        // Load: the verified prefix survives, the residue is reported.
        let (reloaded, report) = DurableRevocationLedger::load(&dir.ledger_path()).expect("load");
        assert_eq!(report.records_loaded, 1);
        assert_eq!(report.truncated_tail_bytes, torn_len - clean_len);
        assert!(reloaded.is_revoked(&revoked));

        // Loads never write: a second load sees the same residue.
        let (_, report2) = DurableRevocationLedger::load(&dir.ledger_path()).expect("load");
        assert_eq!(report2, report);
        assert_eq!(std::fs::metadata(dir.ledger_path()).unwrap().len(), torn_len);

        // The next append repairs the tail first, then extends.
        reloaded
            .admit(tk::NOW, &tk::policy_revocation(&w, revoked, tk::NOW), &registry)
            .unwrap();
        let size = std::fs::metadata(dir.ledger_path()).unwrap().len();
        assert!(size > clean_len, "the repair removed the residue, not the records");
        let (repaired, report) = DurableRevocationLedger::load(&dir.ledger_path()).expect("load");
        assert_eq!(report.truncated_tail_bytes, 0);
        assert_eq!(report.records_loaded, 2);
        assert_eq!(repaired.revoker_count(&revoked), 2);
        assert!(!repaired.is_revoked(&live));
    }

    /// The hard file cap: an oversized file is refused before anything
    /// parses (read side), and an admit that would push the file past the
    /// cap is refused typed with nothing written (write side).
    #[test]
    fn file_cap_enforced_both_sides() {
        let dir = tk::TempDir::new("ledger-cap");
        let (store, w, registry, revoked, _live) =
            tk::revoked_ledger(&dir.ledger_path(), tk::NOW);

        // Read side: a file past the cap refuses before parsing.
        let mut huge = store.to_snapshot_bytes(); // arbitrary filler
        huge.resize(MAX_LEDGER_FILE_BYTES as usize + 1, 0u8);
        std::fs::write(dir.path.join("huge"), &huge).unwrap();
        let err = DurableRevocationLedger::load(&dir.path.join("huge")).unwrap_err();
        assert!(matches!(err, RecoveryError::StoreTooLarge { which: "ledger", .. }));
        assert_eq!(err.name(), "store_too_large");

        // Write side: inflate the file past the cap, then admit — the
        // projected size refuses the append, nothing is written.
        let mut inflated = std::fs::read(dir.ledger_path()).unwrap();
        inflated.resize(MAX_LEDGER_FILE_BYTES as usize, 0u8);
        std::fs::write(dir.ledger_path(), &inflated).unwrap();
        let err = store
            .admit(tk::NOW, &tk::policy_revocation(&w, revoked, tk::NOW), &registry)
            .unwrap_err();
        assert!(matches!(err, RecoveryError::StoreTooLarge { which: "ledger", .. }));
        assert_eq!(std::fs::read(dir.ledger_path()).unwrap(), inflated);
        assert_eq!(store.record_count(), 1);
    }

    /// A missing file is a typed I/O error (read op context), never a
    /// silent empty store.
    #[test]
    fn missing_file_is_typed_io() {
        let dir = tk::TempDir::new("ledger-missing");
        let err = DurableRevocationLedger::load(&dir.ledger_path()).unwrap_err();
        assert!(matches!(err, RecoveryError::Io { .. }));
        assert_eq!(err.name(), "recovery_io");
        assert_eq!(err.op(), Some(RecoveryIoOp::ReadStore));
    }
}
