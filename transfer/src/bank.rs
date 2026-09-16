//! The receiver's chunk bank: where VERIFIED chunks live.
//!
//! The session owns verification (manifest-only trust); the bank owns
//! storage. The [`ChunkBank`] trait is the seam between them — and the
//! documented growth path for the content plane:
//!
//! - [`MemoryBank`] — in-memory (unit tests, embedded receivers).
//! - `store::ReceiverStore` — the file-backed durable bank (multiprocess
//!   restart evidence; cfg'd non-wasm like `connectivity`'s store).
//! - R6-003's DTN store implements the same trait on top of its
//!   content-addressed store (dedup/TTL/replication are that layer's
//!   laws, not this protocol's).
//!
//! The trait's one hard law: [`ChunkBank::accept`] is called ONLY with
//! chunks the session has ALREADY verified against the manifest slot
//! (`expected_chunk_len` + `chunk_hash` — the R6-001 seams). The bank
//! never re-derives trust; it also never fabricates it.

use sharenet_protocol::ContentManifest;

use crate::error::TransferError;

/// Where a receiver banks its verified chunks.
pub trait ChunkBank {
    /// The manifest this bank is bound to (the trust authority — the
    /// bank was constructed from it and its content id is the binding).
    fn manifest(&self) -> &ContentManifest;

    /// Whether slot `slot` is already banked.
    fn slot_present(&self, slot: u32) -> bool;

    /// Bank a PRE-VERIFIED chunk (the session's law: only chunks whose
    /// length and SHA-256 match the manifest slot reach this call).
    fn accept(&mut self, slot: u32, data: Vec<u8>) -> Result<(), TransferError>;

    /// The not-yet-banked slots, ascending (exactly what a REQUEST
    /// carries; exactly the `MissingChunk { slot }` semantics of a
    /// verified prefix).
    fn missing_slots(&self) -> Vec<u32>;

    /// Full coverage (completion precondition #1; #2 is `reassemble`).
    fn is_complete(&self) -> bool;

    /// The banked chunks in slot order (input to
    /// `ContentManifest::reassemble` — the derived completion proof).
    fn ordered_chunks(&self) -> Vec<Vec<u8>>;

    /// How many chunks are banked (evidence lines).
    fn banked_count(&self) -> usize {
        self.manifest().chunk_count() - self.missing_slots().len()
    }
}

/// The in-memory bank: a slot-indexed `Option` row.
///
/// Not durable — the durable bank is `store::ReceiverStore`. Useful for
/// unit tests, embedded receivers, and as the reference semantics of the
/// trait.
#[derive(Debug, Clone)]
pub struct MemoryBank {
    manifest: ContentManifest,
    chunks: Vec<Option<Vec<u8>>>,
}

impl MemoryBank {
    /// A fresh empty bank for `manifest`.
    pub fn new(manifest: ContentManifest) -> Result<Self, TransferError> {
        if manifest.chunk_count() == 0 || manifest.chunk_count() > u32::MAX as usize {
            return Err(TransferError::SlotIndexOverflow {
                count: manifest.chunk_count(),
            });
        }
        let mut chunks = Vec::new();
        chunks
            .try_reserve_exact(manifest.chunk_count())
            .map_err(|_| TransferError::BitmapAllocationFailed {
                words: manifest.chunk_count(),
            })?;
        chunks.resize(manifest.chunk_count(), None);
        Ok(MemoryBank { manifest, chunks })
    }
}

impl ChunkBank for MemoryBank {
    fn manifest(&self) -> &ContentManifest {
        &self.manifest
    }

    fn slot_present(&self, slot: u32) -> bool {
        self.chunks
            .get(slot as usize)
            .map(|c| c.is_some())
            .unwrap_or(false)
    }

    fn accept(&mut self, slot: u32, data: Vec<u8>) -> Result<(), TransferError> {
        let idx = slot as usize;
        if idx >= self.chunks.len() {
            return Err(TransferError::RequestSlotOutOfRange {
                slot,
                count: self.chunks.len(),
            });
        }
        self.chunks[idx] = Some(data);
        Ok(())
    }

    fn missing_slots(&self) -> Vec<u32> {
        (0..self.chunks.len() as u32)
            .filter(|&slot| self.chunks[slot as usize].is_none())
            .collect()
    }

    fn is_complete(&self) -> bool {
        self.chunks.iter().all(|c| c.is_some())
    }

    fn ordered_chunks(&self) -> Vec<Vec<u8>> {
        // Only meaningful when complete; incomplete rows surface as
        // empty vectors and reassemble's exact-count law catches them.
        self.chunks
            .iter()
            .map(|c| c.clone().unwrap_or_default())
            .collect()
    }

    fn banked_count(&self) -> usize {
        self.chunks.iter().filter(|c| c.is_some()).count()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn test_manifest(n_chunks: usize, chunk_size: u64) -> (ContentManifest, Vec<Vec<u8>>) {
        let content: Vec<u8> = (0..(n_chunks as u64 * chunk_size - 3).max(1))
            .map(|i| (i % 251) as u8)
            .collect();
        ContentManifest::chunk(
            &content,
            chunk_size,
            "application/test",
            None::<BTreeMap<String, sharenet_protocol::MetadataValue>>,
            1_700_000_000,
        )
        .expect("manifest")
    }

    #[test]
    fn memory_bank_coverage_math() {
        let (manifest, chunks) = test_manifest(6, 8);
        let mut bank = MemoryBank::new(manifest.clone()).expect("bank");
        assert_eq!(bank.missing_slots(), vec![0, 1, 2, 3, 4, 5]);
        assert!(!bank.is_complete());
        assert_eq!(bank.banked_count(), 0);
        bank.accept(2, chunks[2].clone()).expect("accept");
        bank.accept(5, chunks[5].clone()).expect("accept");
        assert_eq!(bank.missing_slots(), vec![0, 1, 3, 4]);
        assert_eq!(bank.banked_count(), 2);
        assert!(bank.slot_present(2));
        assert!(!bank.slot_present(0));
        assert!(!bank.slot_present(99));
        assert!(!bank.is_complete());
        for (slot, chunk) in chunks.iter().enumerate() {
            if slot != 2 && slot != 5 {
                bank.accept(slot as u32, chunk.clone()).expect("accept");
            }
        }
        assert!(bank.is_complete());
        assert_eq!(bank.ordered_chunks(), chunks);
        assert_eq!(bank.manifest().content_id(), manifest.content_id());
    }

    #[test]
    fn ordered_chunks_of_incomplete_bank_fails_reassemble_length_law() {
        // The trait returns empty rows for missing slots — the R6-001
        // per-slot LENGTH law catches them at their slot, never the
        // bank fabricating content (an empty row at a non-last slot
        // cannot be the short last chunk, so it is structurally wrong).
        let (manifest, chunks) = test_manifest(4, 8);
        let mut bank = MemoryBank::new(manifest).expect("bank");
        bank.accept(0, chunks[0].clone()).expect("accept");
        bank.accept(1, chunks[1].clone()).expect("accept");
        let err = bank
            .manifest()
            .reassemble(&bank.ordered_chunks())
            .unwrap_err();
        assert!(matches!(
            err,
            sharenet_protocol::ContentError::ChunkLengthWrong { slot: 2, .. }
        ));
    }

    #[test]
    fn out_of_range_accept_is_typed() {
        let (manifest, _) = test_manifest(3, 8);
        let mut bank = MemoryBank::new(manifest).expect("bank");
        let err = bank.accept(3, vec![0u8]).unwrap_err();
        assert_eq!(err.name(), "request_slot_out_of_range");
    }
}
