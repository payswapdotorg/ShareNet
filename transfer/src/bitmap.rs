//! The receiver's slot bitmap: one bit per manifest slot.
//!
//! This is the "which chunks do I already hold" index that makes
//! transfer resumable — the receiver's REQUEST is exactly its complement
//! (`missing_slots()`), completion is exactly `is_full()`, and the
//! serialized form is what the receiver persists next to its chunk
//! files. The on-disk form carries a SHA-256 trailer (via the protocol
//! core's `chunk_hash` — no second hash vocabulary), and on RELOAD the
//! persisted bitmap is never authority: verified chunk files are (the
//! store re-derives; a tampered bitmap can neither fabricate nor hide
//! verified content).

use sharenet_protocol::content::chunk_hash;

use crate::error::TransferError;

/// Bitmap file magic ("ShareNet Transfer Receiver Bitmap", v1).
const BITMAP_MAGIC: &[u8; 7] = b"SNTRB1\0";
/// Serialization version of the bitmap record.
const BITMAP_VERSION: u8 = 1;

/// One bit per manifest slot: the receiver's coverage index.
///
/// Invariants: `slots >= 1` (a manifest always has at least one chunk),
/// `slots <= u32::MAX` (the wire's slot index space — the session
/// enforces this from the manifest before building a bitmap), and
/// `words == ceil(slots/64)` with all tail padding bits zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotBitmap {
    slots: usize,
    words: Vec<u64>,
}

impl SlotBitmap {
    /// A fresh all-zero bitmap over `slots` bits.
    ///
    /// The allocation is graceful (`try_reserve`), so an absurd slot
    /// count fails typed instead of aborting the process.
    pub fn new(slots: usize) -> Result<Self, TransferError> {
        if slots == 0 {
            return Err(TransferError::BitmapEmpty);
        }
        let words = slots.div_ceil(64);
        let mut vec = Vec::new();
        vec.try_reserve_exact(words)
            .map_err(|_| TransferError::BitmapAllocationFailed { words })?;
        vec.resize(words, 0u64);
        Ok(SlotBitmap { slots, words: vec })
    }

    /// Total slots (the manifest's chunk count).
    pub fn slots(&self) -> usize {
        self.slots
    }

    /// Set bit `slot`. Out-of-range slots are a typed error (the wire
    /// handed us garbage — the session range-checks first, this is the
    /// second lock on the same door).
    pub fn set(&mut self, slot: u32) -> Result<(), TransferError> {
        let slot = slot as usize;
        if slot >= self.slots {
            return Err(TransferError::RequestSlotOutOfRange {
                slot: slot as u32,
                count: self.slots,
            });
        }
        self.words[slot / 64] |= 1u64 << (slot % 64);
        Ok(())
    }

    /// Clear bit `slot` (store eviction of a chunk that no longer
    /// verifies on reload).
    pub fn clear(&mut self, slot: u32) -> Result<(), TransferError> {
        let slot = slot as usize;
        if slot >= self.slots {
            return Err(TransferError::RequestSlotOutOfRange {
                slot: slot as u32,
                count: self.slots,
            });
        }
        self.words[slot / 64] &= !(1u64 << (slot % 64));
        Ok(())
    }

    /// Read bit `slot` (`false` past the end — a read is benign).
    pub fn is_set(&self, slot: u32) -> bool {
        let slot = slot as usize;
        if slot >= self.slots {
            return false;
        }
        (self.words[slot / 64] >> (slot % 64)) & 1 == 1
    }

    /// Number of set bits.
    pub fn count_ones(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Full coverage (the completion precondition — the first half of
    /// the derived completion proof).
    pub fn is_full(&self) -> bool {
        self.count_ones() == self.slots
    }

    /// The complement, ascending: exactly what a REQUEST carries, and
    /// exactly what `ContentError::MissingChunk { slot }` semantics
    /// name for a verified prefix (the R6-001 seam this builds on).
    pub fn missing_slots(&self) -> Vec<u32> {
        (0..self.slots as u32)
            .filter(|&slot| !self.is_set(slot))
            .collect()
    }

    /// Serialize: magic + version + slot count + word count + words +
    /// SHA-256 trailer over all preceding bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BITMAP_MAGIC.len() + 13 + self.words.len() * 8 + 32);
        out.extend_from_slice(BITMAP_MAGIC);
        out.push(BITMAP_VERSION);
        out.extend_from_slice(&(self.slots as u64).to_be_bytes());
        out.extend_from_slice(&(self.words.len() as u32).to_be_bytes());
        for word in &self.words {
            out.extend_from_slice(&word.to_be_bytes());
        }
        let trailer = chunk_hash(&out);
        out.extend_from_slice(&trailer);
        out
    }

    /// Strict parse of [`Self::to_bytes`] output: wrong magic, wrong
    /// version, count/geometry disagreement, trailing bytes or a bad
    /// trailer are all typed refusals.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TransferError> {
        let min_len = BITMAP_MAGIC.len() + 1 + 8 + 4 + 32;
        if bytes.len() < min_len {
            return Err(TransferError::MessageMalformed {
                kind: "slot_bitmap",
                reason: "shorter than the fixed header + trailer",
            });
        }
        let (body, trailer) = bytes.split_at(bytes.len() - 32);
        if chunk_hash(body) != trailer {
            return Err(TransferError::MessageMalformed {
                kind: "slot_bitmap",
                reason: "SHA-256 trailer mismatch",
            });
        }
        if &body[..BITMAP_MAGIC.len()] != BITMAP_MAGIC {
            return Err(TransferError::MessageMalformed {
                kind: "slot_bitmap",
                reason: "bad magic",
            });
        }
        let mut at = BITMAP_MAGIC.len();
        if body[at] != BITMAP_VERSION {
            return Err(TransferError::MessageMalformed {
                kind: "slot_bitmap",
                reason: "unsupported version",
            });
        }
        at += 1;
        let slots = u64::from_be_bytes(
            body[at..at + 8]
                .try_into()
                .expect("slice of len 8 checked above"),
        );
        at += 8;
        let word_count = u32::from_be_bytes(
            body[at..at + 4]
                .try_into()
                .expect("slice of len 4 checked above"),
        );
        at += 4;
        if slots == 0 || slots > u32::MAX as u64 {
            return Err(TransferError::MessageMalformed {
                kind: "slot_bitmap",
                reason: "slot count outside the 1..=u32::MAX space",
            });
        }
        let expected_words = (slots as usize).div_ceil(64);
        if word_count as usize != expected_words {
            return Err(TransferError::MessageMalformed {
                kind: "slot_bitmap",
                reason: "word count disagrees with slot count",
            });
        }
        if body.len() != at + expected_words * 8 {
            return Err(TransferError::MessageMalformed {
                kind: "slot_bitmap",
                reason: "payload length disagrees with word count",
            });
        }
        let mut words = Vec::with_capacity(expected_words);
        for i in 0..expected_words {
            let b: [u8; 8] = body[at + i * 8..at + i * 8 + 8]
                .try_into()
                .expect("checked geometry");
            words.push(u64::from_be_bytes(b));
        }
        // Mask off the padding bits beyond `slots` (strictness: they must
        // be zero in OUR output; a foreign writer with stray bits is
        // normalized here and the store's advisory compare surfaces it).
        let tail = slots as usize % 64;
        if tail != 0 {
            let mask = (1u64 << tail) - 1;
            let last = words.len() - 1;
            words[last] &= mask;
        }
        Ok(SlotBitmap {
            slots: slots as usize,
            words,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_bitmap_is_all_missing() {
        let bm = SlotBitmap::new(7).expect("bitmap");
        assert_eq!(bm.slots(), 7);
        assert_eq!(bm.count_ones(), 0);
        assert!(!bm.is_full());
        assert_eq!(bm.missing_slots(), vec![0, 1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn zero_slots_refused() {
        let err = SlotBitmap::new(0).unwrap_err();
        assert_eq!(err, TransferError::BitmapEmpty);
        assert_eq!(err.name(), "bitmap_empty");
    }

    #[test]
    fn set_is_set_clear_across_word_boundaries() {
        let mut bm = SlotBitmap::new(130).expect("bitmap"); // 3 words, tail 2
        for slot in [0u32, 1, 31, 32, 63, 64, 65, 127, 128, 129] {
            bm.set(slot).expect("in range");
        }
        assert_eq!(bm.count_ones(), 10);
        assert!(!bm.is_full());
        for slot in [0u32, 1, 31, 32, 63, 64, 65, 127, 128, 129] {
            assert!(bm.is_set(slot), "slot {slot} set");
        }
        assert!(!bm.is_set(2));
        assert!(!bm.is_set(62));
        assert!(!bm.is_set(126));
        // Reads past the end are false, writes past the end are typed.
        assert!(!bm.is_set(130));
        assert_eq!(bm.set(130).unwrap_err().name(), "request_slot_out_of_range");
        // Clear works and does not disturb neighbors.
        bm.clear(64).expect("clear");
        assert!(!bm.is_set(64));
        assert!(bm.is_set(63));
        assert!(bm.is_set(65));
        assert_eq!(bm.count_ones(), 9);
    }

    #[test]
    fn completion_is_exact_full_coverage() {
        let mut bm = SlotBitmap::new(64).expect("bitmap"); // exactly one word
        for slot in 0..63u32 {
            bm.set(slot).expect("set");
            assert!(!bm.is_full(), "full only at the last slot");
        }
        bm.set(63).expect("last");
        assert!(bm.is_full());
        assert_eq!(bm.missing_slots(), Vec::<u32>::new());
        bm.clear(31).expect("one hole");
        assert!(!bm.is_full());
        assert_eq!(bm.missing_slots(), vec![31]);
    }

    #[test]
    fn missing_slots_are_ascending_complement() {
        let mut bm = SlotBitmap::new(10).expect("bitmap");
        for slot in [1u32, 3, 7, 9] {
            bm.set(slot).expect("set");
        }
        assert_eq!(bm.missing_slots(), vec![0, 2, 4, 5, 6, 8]);
    }

    #[test]
    fn serialization_round_trip() {
        let mut bm = SlotBitmap::new(200).expect("bitmap");
        for slot in (0..200u32).step_by(3) {
            bm.set(slot).expect("set");
        }
        let bytes = bm.to_bytes();
        let back = SlotBitmap::from_bytes(&bytes).expect("parse");
        assert_eq!(back, bm);
        assert_eq!(back.missing_slots().len(), 133); // 200 - ceil(200/3) set = 200 - 67
    }

    #[test]
    fn serialization_exact_shape_is_pinned() {
        let mut bm = SlotBitmap::new(1).expect("bitmap");
        bm.set(0).expect("set");
        let bytes = bm.to_bytes();
        assert_eq!(&bytes[..7], b"SNTRB1\0");
        assert_eq!(bytes[7], 1);
        assert_eq!(&bytes[8..16], &1u64.to_be_bytes());
        assert_eq!(&bytes[16..20], &1u32.to_be_bytes());
        assert_eq!(&bytes[20..28], &1u64.to_be_bytes());
        assert_eq!(bytes.len(), 28 + 32);
        assert_eq!(bytes[28..].len(), 32);
    }

    #[test]
    fn tampered_serialization_refused_everywhere() {
        let mut bm = SlotBitmap::new(70).expect("bitmap");
        for slot in [0u32, 5, 69] {
            bm.set(slot).expect("set");
        }
        let bytes = bm.to_bytes();
        // Every single-byte mutation must fail (trailer is the last line
        // of defense; header/geometry checks fire earlier).
        for i in 0..bytes.len() {
            let mut tampered = bytes.clone();
            tampered[i] ^= 0xFF;
            assert!(
                SlotBitmap::from_bytes(&tampered).is_err(),
                "mutation at byte {i} must be refused"
            );
        }
        // Truncation refused at every length.
        for end in 0..bytes.len() {
            assert!(SlotBitmap::from_bytes(&bytes[..end]).is_err());
        }
    }

    #[test]
    fn geometry_lies_refused() {
        let mut bm = SlotBitmap::new(65).expect("bitmap");
        bm.set(64).expect("set");
        let mut bytes = bm.to_bytes();
        // Lie the slot count up (word count now disagrees).
        bytes[8..16].copy_from_slice(&66u64.to_be_bytes());
        assert!(SlotBitmap::from_bytes(&bytes).is_err());
        // Lie the word count (65 slots truly need 2 words; claim 3).
        let mut bytes = bm.to_bytes();
        bytes[16..20].copy_from_slice(&3u32.to_be_bytes());
        assert!(SlotBitmap::from_bytes(&bytes).is_err());
        // Wrong magic / version.
        let mut bytes = bm.to_bytes();
        bytes[0] = b'X';
        assert!(SlotBitmap::from_bytes(&bytes).is_err());
        let mut bytes = bm.to_bytes();
        bytes[7] = 2;
        assert!(SlotBitmap::from_bytes(&bytes).is_err());
        // Slot count zero.
        let mut bytes = bm.to_bytes();
        bytes[8..16].copy_from_slice(&0u64.to_be_bytes());
        assert!(SlotBitmap::from_bytes(&bytes).is_err());
        // Beyond u32 space.
        let mut bytes = bm.to_bytes();
        bytes[8..16].copy_from_slice(&(u32::MAX as u64 + 2).to_be_bytes());
        assert!(SlotBitmap::from_bytes(&bytes).is_err());
    }

    #[test]
    fn stray_tail_bits_are_normalized() {
        // A foreign writer that sets padding bits beyond `slots`: parse
        // normalizes (the bit math is defined over `slots` only).
        let mut bm = SlotBitmap::new(65).expect("bitmap");
        bm.set(0).expect("set");
        let mut bytes = bm.to_bytes();
        // Word 1 covers slots 64..=127; slot 65.. are padding. Flip a
        // padding bit AND fix the trailer (a real adversary recomputes).
        bytes[20 + 8] ^= 0b100; // word[1] bit 2 -> padding slot 66
        let trailer = chunk_hash(&bytes[..bytes.len() - 32]);
        let tail_start = bytes.len() - 32;
        bytes[tail_start..].copy_from_slice(&trailer);
        let parsed = SlotBitmap::from_bytes(&bytes).expect("normalized");
        assert!(!parsed.is_set(66), "padding bit is not a slot");
        assert_eq!(parsed.count_ones(), 1);
    }

    #[test]
    fn large_but_sane_allocations_succeed() {
        // 2^24 slots = 2 MiB of words: fine.
        let mut bm = SlotBitmap::new(1 << 24).expect("alloc");
        bm.set((1 << 24) - 1).expect("last slot");
        assert_eq!(bm.count_ones(), 1);
        assert!(!bm.is_full());
        assert_eq!(bm.missing_slots().len(), (1 << 24) - 1);
    }
}
