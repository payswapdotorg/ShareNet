//! The durable receiver bank: file-backed state for resumable transfer.
//!
//! The receiver's persistent state is exactly what an interrupted
//! transfer needs to resume in a NEW process (the work item's restart
//! evidence):
//!
//! ```text
//! <state-dir>/manifest.cbor    the manifest wire bytes (the authority
//!                               record — the object this state belongs to)
//! <state-dir>/bitmap.bin       the serialized slot bitmap (ADVISORY; see
//!                               the reload law below)
//! <state-dir>/chunks/chunk-<slot>.bin   one file per banked VERIFIED chunk
//! ```
//!
//! # The reload law (verified chunks are the only authority)
//!
//! On [`ReceiverStore::open_or_create`], every chunk file on disk is
//! RE-VERIFIED against the manifest (`expected_chunk_len` +
//! `chunk_hash` — the R6-001 seams) and the bitmap is RE-DERIVED from
//! the verified set:
//!
//! - a chunk file that no longer verifies (disk corruption) is evicted
//!   and re-requested — corruption is CONTAINED per slot (the content
//!   plane's natural advantage over whole-store refusal; the contrast
//!   with R5-003's whole-store `SummaryDisagrees` is deliberate: there,
//!   one record poisons a projection; here, one bad chunk is one
//!   re-fetch);
//! - the persisted `bitmap.bin` is advisory bookkeeping only — a
//!   tampered bitmap can neither fabricate content (no chunk file, no
//!   bit) nor hide verified content (the file re-verifies and sets its
//!   bit back). Disagreements are counted in the reload report, never
//!   trusted;
//! - `manifest.cbor` is the one authority record: unreadable/unparsable
//!   → the whole store is refused typed (without the manifest nothing
//!   can be verified; the honest recovery is a fresh state dir and a
//!   re-offer).
//!
//! Writes are atomic (temp + fsync + rename, the R5-003 discipline):
//! a crash mid-`accept` leaves either a stray `.tmp` (cleaned on next
//! reload) or a fully-written chunk file whose bit gets set by the
//! re-derivation — never a torn chunk.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use sharenet_protocol::content::{chunk_hash, ContentManifest};

use crate::bank::ChunkBank;
use crate::bitmap::SlotBitmap;
use crate::error::TransferError;

const MANIFEST_FILE: &str = "manifest.cbor";
const BITMAP_FILE: &str = "bitmap.bin";
const CHUNKS_DIR: &str = "chunks";
const TMP_EXT: &str = "tmp";

/// What a reload observed (evidence lines + the tests' exact-resume
/// assertions).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReloadReport {
    /// Chunk files found on disk.
    pub seen: usize,
    /// Chunk files that re-verified and were banked.
    pub accepted: usize,
    /// Chunk files evicted (failed re-verification — disk corruption,
    /// contained per slot).
    pub evicted: usize,
    /// Stray `.tmp` scratch files removed.
    pub tmp_removed: usize,
    /// A `bitmap.bin` existed but was unparsable/corrupt (advisory
    /// record — the derived bitmap wins regardless).
    pub bitmap_corrupt: bool,
    /// Bits where the persisted (advisory) bitmap disagreed with the
    /// re-derived, verified bitmap.
    pub bitmap_disagreements: usize,
    /// Whether the store already existed (a resume) or was created
    /// fresh by this call.
    pub resumed: bool,
}

/// The file-backed durable [`ChunkBank`] (cfg'd non-wasm — the same host
/// seam as `connectivity`'s durable store; an embedder on a no-fs host
/// brings its own bank).
#[derive(Debug)]
pub struct ReceiverStore {
    dir: PathBuf,
    manifest: ContentManifest,
    bitmap: SlotBitmap,
    chunks: Vec<Option<Vec<u8>>>,
    report: ReloadReport,
}

impl ReceiverStore {
    /// Open the store at `dir`, binding it to `manifest` (the OFFER's
    /// manifest, already verified by the session):
    ///
    /// - fresh dir → the manifest record is written and the store starts
    ///   empty;
    /// - existing store for the SAME content id → resume: every chunk
    ///   file is re-verified, the bitmap re-derived, corruption evicted;
    /// - existing store for a DIFFERENT content id → typed refusal (a
    ///   state dir belongs to exactly one object).
    pub fn open_or_create(
        dir: impl AsRef<Path>,
        manifest: &ContentManifest,
    ) -> Result<Self, TransferError> {
        let dir = dir.as_ref();
        let count = manifest.chunk_count();
        if count == 0 || count > u32::MAX as usize {
            return Err(TransferError::SlotIndexOverflow { count });
        }
        let manifest_path = dir.join(MANIFEST_FILE);
        let mut report = ReloadReport::default();

        let (bound_manifest, resumed) = match fs::read(&manifest_path) {
            Ok(bytes) => {
                let stored = ContentManifest::from_wire_bytes(&bytes).map_err(|e| {
                    TransferError::StoreCorrupt {
                        detail: format!("manifest record: {e}"),
                    }
                })?;
                if stored.content_id() != manifest.content_id() {
                    return Err(TransferError::ContentIdMismatch {
                        expected: stored.content_id(),
                        found: manifest.content_id(),
                    });
                }
                (stored, true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Fresh store: the manifest record is written FIRST (the
                // authority precedes any chunk it can authorize).
                fs::create_dir_all(dir).map_err(|e| store_io("create state dir", e))?;
                fs::create_dir_all(dir.join(CHUNKS_DIR))
                    .map_err(|e| store_io("create chunks dir", e))?;
                atomic_write(&manifest_path, &manifest.to_wire_bytes())?;
                (manifest.clone(), false)
            }
            Err(e) => return Err(store_io("read manifest record", e)),
        };

        let mut bitmap = SlotBitmap::new(count)?;
        let mut chunks: Vec<Option<Vec<u8>>> = Vec::new();
        chunks
            .try_reserve_exact(count)
            .map_err(|_| TransferError::BitmapAllocationFailed { words: count })?;
        chunks.resize(count, None);

        // Re-derive the truth from the verified chunk files — ALWAYS,
        // fresh or resumed: any chunk file that verifies against the
        // manifest is by definition the right bytes (manifest-only
        // trust), and anything else is evicted.
        let chunks_dir = dir.join(CHUNKS_DIR);
        fs::create_dir_all(&chunks_dir).map_err(|e| store_io("scan chunks", e))?;
        {
            let entries = fs::read_dir(&chunks_dir).map_err(|e| store_io("scan chunks", e))?;
            let mut names: Vec<String> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            for name in &names {
                if let Some(slot) = parse_chunk_file_name(name) {
                    report.seen += 1;
                    let bytes = fs::read(chunks_dir.join(name))
                        .map_err(|e| store_io("read chunk file", e))?;
                    if (slot as usize) < count
                        && verify_against_manifest(&bound_manifest, slot, &bytes)
                    {
                        chunks[slot as usize] = Some(bytes);
                        bitmap.set(slot)?;
                        report.accepted += 1;
                    } else {
                        // Out-of-range name or failed verification:
                        // contained per-slot eviction (re-fetch).
                        fs::remove_file(chunks_dir.join(name))
                            .map_err(|e| store_io("evict chunk", e))?;
                        report.evicted += 1;
                    }
                } else if name.ends_with(TMP_EXT) {
                    let _ = fs::remove_file(chunks_dir.join(name));
                    report.tmp_removed += 1;
                }
            }
        }

        // The advisory persisted bitmap: never authority, only evidence.
        let bitmap_path = dir.join(BITMAP_FILE);
        if resumed {
            match fs::read(&bitmap_path) {
                Ok(bytes) => match SlotBitmap::from_bytes(&bytes) {
                    Ok(persisted) if persisted.slots() == count => {
                        for slot in 0..count as u32 {
                            if persisted.is_set(slot) != bitmap.is_set(slot) {
                                report.bitmap_disagreements += 1;
                            }
                        }
                    }
                    Ok(_) => report.bitmap_disagreements += 1,
                    Err(_) => report.bitmap_corrupt = true,
                },
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => report.bitmap_corrupt = true,
            }
        }
        report.resumed = resumed;

        Ok(ReceiverStore {
            dir: dir.to_path_buf(),
            manifest: bound_manifest,
            bitmap,
            chunks,
            report,
        })
    }

    /// What the reload observed (evidence).
    pub fn reload_report(&self) -> &ReloadReport {
        &self.report
    }

    /// The state directory (the binary's --state-dir).
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Flush the (advisory) bitmap record durably.
    pub fn flush_bitmap(&self) -> Result<(), TransferError> {
        atomic_write(&self.dir.join(BITMAP_FILE), &self.bitmap.to_bytes())
    }

    /// The number of chunk files currently on disk (test evidence).
    pub fn chunk_files_on_disk(&self) -> usize {
        self.chunks.iter().filter(|c| c.is_some()).count()
    }

    /// The derived bitmap (test/evidence seam).
    pub fn bitmap(&self) -> &SlotBitmap {
        &self.bitmap
    }
}

impl ChunkBank for ReceiverStore {
    fn manifest(&self) -> &ContentManifest {
        &self.manifest
    }

    fn slot_present(&self, slot: u32) -> bool {
        self.chunks.get(slot as usize).map(|c| c.is_some()).unwrap_or(false)
    }

    fn accept(&mut self, slot: u32, data: Vec<u8>) -> Result<(), TransferError> {
        let slot_usize = slot as usize;
        if slot_usize >= self.chunks.len() {
            return Err(TransferError::RequestSlotOutOfRange {
                slot,
                count: self.chunks.len(),
            });
        }
        // The PRE-VERIFIED law: only the session calls this, after
        // length + hash verification. The store's job is durability,
        // not trust.
        atomic_write(
            &self
                .dir
                .join(CHUNKS_DIR)
                .join(format!("chunk-{slot}.bin")),
            &data,
        )?;
        self.chunks[slot_usize] = Some(data);
        self.bitmap.set(slot)?;
        self.flush_bitmap()?;
        Ok(())
    }

    fn missing_slots(&self) -> Vec<u32> {
        self.bitmap.missing_slots()
    }

    fn is_complete(&self) -> bool {
        self.bitmap.is_full()
    }

    fn ordered_chunks(&self) -> Vec<Vec<u8>> {
        self.chunks
            .iter()
            .map(|c| c.clone().unwrap_or_default())
            .collect()
    }

    fn banked_count(&self) -> usize {
        self.bitmap.count_ones()
    }
}

/// Length-then-hash verification of one stored chunk (the R6-001 law,
/// reused verbatim by the reload path).
fn verify_against_manifest(
    manifest: &ContentManifest,
    slot: u32,
    data: &[u8],
) -> bool {
    let slot_usize = slot as usize;
    if slot_usize >= manifest.chunk_count() {
        return false;
    }
    match manifest.expected_chunk_len(slot_usize) {
        Some(expected) if expected == data.len() as u64 => {}
        _ => return false,
    }
    chunk_hash(data) == manifest.chunk_hashes()[slot_usize]
}

/// `chunk-<u32>.bin` → slot.
fn parse_chunk_file_name(name: &str) -> Option<u32> {
    let stem = name.strip_suffix(".bin")?;
    let digits = stem.strip_prefix("chunk-")?;
    digits.parse::<u32>().ok()
}

fn store_io(context: &'static str, e: std::io::Error) -> TransferError {
    TransferError::StoreIo {
        context,
        source: e.to_string(),
    }
}

/// Atomic durable write: temp file + fsync + rename (the R5-003
/// discipline; the known limit — no parent-dir fsync after rename — is
/// inherited honestly and documented in the README).
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), TransferError> {
    let tmp = path.with_extension(TMP_EXT);
    let mut file = fs::File::create(&tmp).map_err(|e| store_io("create temp", e))?;
    file.write_all(bytes).map_err(|e| store_io("write temp", e))?;
    file.sync_all().map_err(|e| store_io("sync temp", e))?;
    drop(file);
    fs::rename(&tmp, path).map_err(|e| store_io("rename into place", e))?;
    Ok(())
}

/// Build a manifest from raw bytes (the binary's offer path; strict
/// parse with full R6-001 invariants).
pub fn manifest_from_bytes(bytes: &[u8]) -> Result<ContentManifest, TransferError> {
    ContentManifest::from_wire_bytes(bytes)
        .map_err(|cause| TransferError::ManifestInvalid { cause })
}

/// Convenience: chunk `content` for a sender (the binary's send path).
pub fn chunk_content(
    content: &[u8],
    chunk_size: u64,
    content_type: &str,
    created_at_unix: u64,
) -> Result<(ContentManifest, Vec<Vec<u8>>), TransferError> {
    ContentManifest::chunk(
        content,
        chunk_size,
        content_type,
        None::<BTreeMap<String, sharenet_protocol::MetadataValue>>,
        created_at_unix,
    )
    .map_err(|cause| TransferError::ManifestInvalid { cause })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sharenet-transfer-{}-{}-{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn build(n_chunks: usize, chunk_size: u64) -> (ContentManifest, Vec<Vec<u8>>, Vec<u8>) {
        let total = n_chunks as u64 * chunk_size - 3; // short last chunk
        let content: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
        let (manifest, chunks) = ContentManifest::chunk(
            &content,
            chunk_size,
            "application/test",
            None,
            1_700_000_000,
        )
        .expect("manifest");
        (manifest, chunks, content)
    }

    #[test]
    fn fresh_store_writes_manifest_first() {
        let dir = temp_dir("fresh");
        let (manifest, _, _) = build(4, 8);
        let store = ReceiverStore::open_or_create(&dir, &manifest).expect("store");
        assert!(!store.reload_report().resumed);
        assert!(dir.join(MANIFEST_FILE).is_file());
        assert!(dir.join(CHUNKS_DIR).is_dir());
        assert!(!dir.join(BITMAP_FILE).exists(), "no bitmap before any chunk");
        assert_eq!(store.missing_slots(), vec![0, 1, 2, 3]);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn accept_persists_chunk_and_bitmap() {
        let dir = temp_dir("accept");
        let (manifest, chunks, _) = build(5, 8);
        let mut store = ReceiverStore::open_or_create(&dir, &manifest).expect("store");
        store.accept(1, chunks[1].clone()).expect("accept");
        assert!(dir.join(CHUNKS_DIR).join("chunk-1.bin").is_file());
        assert!(dir.join(BITMAP_FILE).is_file());
        assert!(store.slot_present(1));
        assert!(!store.slot_present(0));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_resumes_exact_verified_state() {
        let dir = temp_dir("reload");
        let (manifest, chunks, content) = build(8, 8);
        {
            let mut store = ReceiverStore::open_or_create(&dir, &manifest).expect("store");
            for slot in [0u32, 2, 4, 6] {
                store.accept(slot, chunks[slot as usize].clone()).expect("accept");
            }
        }
        // A NEW process would construct the store from disk right here.
        let store = ReceiverStore::open_or_create(&dir, &manifest).expect("reload");
        let report = store.reload_report();
        assert!(report.resumed);
        assert_eq!(report.seen, 4);
        assert_eq!(report.accepted, 4);
        assert_eq!(report.evicted, 0);
        assert_eq!(report.bitmap_disagreements, 0);
        assert_eq!(store.missing_slots(), vec![1, 3, 5, 7]);
        // The persisted chunks are byte-exact.
        assert_eq!(store.ordered_chunks()[2], chunks[2]);
        assert_eq!(content.len(), 61);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_evicts_disk_corrupted_chunk_per_slot() {
        let dir = temp_dir("evict");
        let (manifest, chunks, _) = build(6, 8);
        {
            let mut store = ReceiverStore::open_or_create(&dir, &manifest).expect("store");
            for slot in 0..6u32 {
                store.accept(slot, chunks[slot as usize].clone()).expect("accept");
            }
        }
        // Corrupt one persisted chunk on disk (an attacker or bit rot).
        let victim = dir.join(CHUNKS_DIR).join("chunk-3.bin");
        let mut bytes = fs::read(&victim).expect("read");
        bytes[0] ^= 0xFF;
        fs::write(&victim, &bytes).expect("write");
        let store = ReceiverStore::open_or_create(&dir, &manifest).expect("reload");
        let report = store.reload_report();
        assert_eq!(report.evicted, 1);
        assert!(!store.slot_present(3), "corrupt chunk evicted");
        assert_eq!(store.missing_slots(), vec![3]);
        assert!(!victim.exists(), "evicted file removed");
        assert!(store.slot_present(2));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_ignores_tampered_advisory_bitmap() {
        let dir = temp_dir("bitmap-tamper");
        let (manifest, chunks, _) = build(6, 8);
        {
            let mut store = ReceiverStore::open_or_create(&dir, &manifest).expect("store");
            for slot in 0..3u32 {
                store.accept(slot, chunks[slot as usize].clone()).expect("accept");
            }
        }
        // Claim-everything tamper: rebuild the bitmap record with all
        // bits set (a recomputing adversary).
        let mut bm = SlotBitmap::new(6).expect("bitmap");
        for slot in 0..6u32 {
            bm.set(slot).expect("set");
        }
        fs::write(dir.join(BITMAP_FILE), bm.to_bytes()).expect("write");
        let store = ReceiverStore::open_or_create(&dir, &manifest).expect("reload");
        let report = store.reload_report();
        assert!(report.bitmap_disagreements >= 3, "tamper observed: {report:?}");
        // The DERIVED truth: only 3 verified chunks, regardless.
        assert_eq!(store.banked_count(), 3);
        assert_eq!(store.missing_slots(), vec![3, 4, 5]);
        assert!(!store.is_complete(), "a claimed bitmap fabricates nothing");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_with_corrupt_bitmap_record_still_derives_truth() {
        let dir = temp_dir("bitmap-corrupt");
        let (manifest, chunks, _) = build(4, 8);
        {
            let mut store = ReceiverStore::open_or_create(&dir, &manifest).expect("store");
            store.accept(0, chunks[0].clone()).expect("accept");
            store.accept(1, chunks[1].clone()).expect("accept");
        }
        fs::write(dir.join(BITMAP_FILE), b"garbage-not-a-bitmap").expect("write");
        let store = ReceiverStore::open_or_create(&dir, &manifest).expect("reload");
        assert!(store.reload_report().bitmap_corrupt);
        assert_eq!(store.banked_count(), 2);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reload_removes_stray_tmp_scratch() {
        let dir = temp_dir("tmp");
        let (manifest, chunks, _) = build(4, 8);
        {
            let mut store = ReceiverStore::open_or_create(&dir, &manifest).expect("store");
            store.accept(0, chunks[0].clone()).expect("accept");
        }
        let stray = dir.join(CHUNKS_DIR).join("chunk-2.bin.tmp");
        fs::write(&stray, b"torn write").expect("write");
        let store = ReceiverStore::open_or_create(&dir, &manifest).expect("reload");
        assert_eq!(store.reload_report().tmp_removed, 1);
        assert!(!stray.exists());
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupted_manifest_record_refuses_whole_store() {
        let dir = temp_dir("manifest-corrupt");
        let (manifest, chunks, _) = build(4, 8);
        {
            let mut store = ReceiverStore::open_or_create(&dir, &manifest).expect("store");
            store.accept(0, chunks[0].clone()).expect("accept");
        }
        fs::write(dir.join(MANIFEST_FILE), b"\xa5truncated").expect("write");
        let err = ReceiverStore::open_or_create(&dir, &manifest).unwrap_err();
        assert_eq!(err.name(), "store_corrupt");
        assert!(err.to_string().contains("manifest record"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn different_manifest_same_state_dir_refused() {
        let dir = temp_dir("mismatch");
        let (manifest_a, chunks_a, _) = build(4, 8);
        let (manifest_b, _, _) = build(5, 8);
        {
            let mut store = ReceiverStore::open_or_create(&dir, &manifest_a).expect("store");
            store.accept(0, chunks_a[0].clone()).expect("accept");
        }
        let err = ReceiverStore::open_or_create(&dir, &manifest_b).unwrap_err();
        assert_eq!(err.name(), "content_id_mismatch");
        // State untouched: the chunk is still there for the RIGHT object.
        let store = ReceiverStore::open_or_create(&dir, &manifest_a).expect("reopen");
        assert!(store.slot_present(0));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn reassembled_content_after_full_reload_is_byte_exact() {
        let dir = temp_dir("full");
        let (manifest, chunks, content) = build(9, 16);
        {
            let mut store = ReceiverStore::open_or_create(&dir, &manifest).expect("store");
            for (slot, chunk) in chunks.iter().enumerate() {
                store.accept(slot as u32, chunk.clone()).expect("accept");
            }
        }
        let store = ReceiverStore::open_or_create(&dir, &manifest).expect("reload");
        assert!(store.is_complete());
        let got = store.manifest().reassemble(&store.ordered_chunks()).expect("reassemble");
        assert_eq!(got, content);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn manifest_record_bytes_round_trip_exactly() {
        let dir = temp_dir("wirebytes");
        let (manifest, _, _) = build(3, 8);
        {
            let _ = ReceiverStore::open_or_create(&dir, &manifest).expect("store");
        }
        let stored = fs::read(dir.join(MANIFEST_FILE)).expect("read");
        assert_eq!(stored, manifest.to_wire_bytes(), "byte-stable authority record");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn helpers_reject_bad_input_typed() {
        assert!(manifest_from_bytes(b"").is_err());
        assert_eq!(
            manifest_from_bytes(b"").unwrap_err().name(),
            "manifest_invalid"
        );
        // Empty content refused at chunk time.
        assert!(chunk_content(b"", 8, "t", 1).is_err());
    }

    #[test]
    fn out_of_range_accept_is_typed() {
        let dir = temp_dir("range");
        let (manifest, _, _) = build(2, 8);
        let mut store = ReceiverStore::open_or_create(&dir, &manifest).expect("store");
        let err = store.accept(2, vec![0u8]).unwrap_err();
        assert_eq!(err.name(), "request_slot_out_of_range");
        fs::remove_dir_all(&dir).ok();
    }
}
