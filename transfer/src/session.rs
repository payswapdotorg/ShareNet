//! The session state machines: the sender and the receiver.
//!
//! A transfer is receiver-driven and consists of one OFFER, then rounds
//! of (REQUEST → CHUNK… → COMPLETE), then — and only then — the
//! receiver's DERIVED completion:
//!
//! ```text
//! sender                                   receiver
//!   │ OFFER(manifest)                        │
//!   │ ────────────────────────────────────► │ parse + invariants (R6-001)
//!   │                                       │ bind the bank (content id)
//!   │                    REQUEST(missing)   │ ← bitmap complement
//!   │ ◄──────────────────────────────────── │
//!   │ CHUNK(slot, bytes) ─────────────────► │ verify slot: length law,
//!   │ CHUNK(slot, bytes) ─────────────────► │   then hash law (R6-001);
//!   │ ...                                   │   bank ONLY verified chunks
//!   │ COMPLETE(content_id) ───────────────► │ round terminator (a HINT:
//!   │                                       │   premature → re-request)
//!   │                                       │ (bitmap full?)
//!   │                                       │ reassemble() — the proof
//!   │            DELIVERED(content_id)      │
//!   │ ◄──────────────────────────────────── │
//! ```
//!
//! # The laws, as code
//!
//! - **Manifest-only trust.** The manifest from the OFFER is the only
//!   authority. Claimed sizes, counts, batch claims and completion
//!   assertions are never believed: every chunk is verified with
//!   `expected_chunk_len` + `chunk_hash` against its manifest slot
//!   (the R6-001 seams built for exactly this).
//! - **Per-chunk containment.** A bad chunk (wrong slot, wrong length,
//!   wrong hash, duplicate) is RECORDED and re-requested — the transfer
//!   continues. Only carriage failures, protocol violations, manifest
//!   binding failures and the stall bound abort the session.
//! - **Completion is derived, never asserted.** The sender's COMPLETE is
//!   a hint the receiver verifies against its own state; completion =
//!   full bitmap coverage + successful `reassemble()`. The receiver's
//!   DELIVERED is the ack of that derived fact (and is itself verified
//!   by the sender against its manifest — a forged ack is typed-rejected
//!   and the sender does NOT record a delivery).
//! - **Resume from any partial state.** The bank persists per verified
//!   chunk; a resumed receiver's first REQUEST is exactly its missing
//!   slots — nothing already verified is re-fetched (proven by the
//!   resume tests).
//! - **The receiver never accepts unsolicited authority.** An
//!   unrequested-but-verified chunk IS accepted (manifest-only trust:
//!   the bytes are right — the opportunistic-delivery seam R6-005
//!   builds on); an unverified anything never is.

use std::collections::HashSet;

use sharenet_protocol::content::{chunk_hash, ContentManifest};
use sharenet_protocol::ContentError;

use crate::bank::ChunkBank;
use crate::error::TransferError;
use crate::frame::TransferStream;
use crate::message::Message;

/// Default bound on consecutive no-progress rounds before the receiver
/// gives up typed (a lying manifest / a sender that never delivers
/// anything verifiable would otherwise loop forever).
pub const DEFAULT_MAX_STALL_ROUNDS: u32 = 4;

/// The receiver's session policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverPolicy {
    /// Consecutive rounds with zero newly-verified chunks that abort the
    /// session with `stalled`.
    pub max_stall_rounds: u32,
}

impl Default for ReceiverPolicy {
    fn default() -> Self {
        ReceiverPolicy {
            max_stall_rounds: DEFAULT_MAX_STALL_ROUNDS,
        }
    }
}

/// One contained chunk rejection (evidence — never fatal).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkRejection {
    pub slot: u32,
    pub cause: ChunkRejectionCause,
}

/// Why one chunk was rejected (the length-before-hash discipline of
/// R6-001: never hash structurally wrong input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkRejectionCause {
    /// The slot index is outside the manifest (wrong-slot delivery).
    SlotOutOfRange { slot: u32, count: usize },
    /// The chunk's length is not its manifest slot's expected length.
    LengthWrong { slot: u32, found: u64, expected: u64 },
    /// The chunk's SHA-256 does not match its manifest slot.
    HashMismatch { slot: u32 },
}

impl ChunkRejectionCause {
    /// Stable machine name (aligned with the R6-001 vocabulary).
    pub fn name(&self) -> &'static str {
        match self {
            ChunkRejectionCause::SlotOutOfRange { .. } => "slot_out_of_range",
            ChunkRejectionCause::LengthWrong { .. } => "chunk_length_wrong",
            ChunkRejectionCause::HashMismatch { .. } => "chunk_hash_mismatch",
        }
    }
}

/// The receiver's evidence + result of a completed transfer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverOutcome {
    /// The reassembled, fully verified content (the derived proof's
    /// product).
    pub content: Vec<u8>,
    /// The object this was (manifest-derived).
    pub content_id: [u8; 32],
    /// REQUEST rounds used.
    pub rounds: u32,
    /// Chunks banked this session (a resumed session may bank few).
    pub accepted: u32,
    /// Contained rejections, in arrival order.
    pub rejections: Vec<ChunkRejection>,
    /// Redelivered already-banked slots (injection/redelivery — no state
    /// change).
    pub duplicates: Vec<u32>,
    /// COMPLETE claims that arrived while slots were still outstanding
    /// (premature completion hints — ignored as authority, recorded as
    /// evidence).
    pub premature_completions: u32,
    /// COMPLETE claims bound to a different content id (misrouted or
    /// forged — recorded; still only a hint).
    pub complete_id_mismatches: u32,
}

/// The sender's result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderOutcome {
    /// The delivered object (the receiver's verified ack named it).
    pub content_id: [u8; 32],
}

// ---------------------------------------------------------------------------
// Sender
// ---------------------------------------------------------------------------

/// Sender-side TEST AFFORDANCES (documented, default-off; the same
/// discipline as the transport binaries' `--drop-every`): they let the
/// adversarial multiprocess suite drive a LYING sender through the real
/// protocol code path — one source of truth, no test-side reimplementation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SenderFaults {
    /// First delivery of slot N: flip one byte (corrupted chunk).
    pub corrupt_slot_once: Option<u32>,
    /// First delivery of slot N: also send one extra identical copy
    /// (duplicate injection).
    pub duplicate_slot: Option<u32>,
    /// First time slot A is due: deliver chunk B's bytes labeled as A
    /// (wrong-slot delivery).
    pub wrong_slot_once: Option<(u32, u32)>,
    /// First round slot N is requested: skip its delivery entirely (the
    /// sender still terminates the round with COMPLETE — the receiver
    /// sees a premature completion).
    pub withhold_slot_once: Option<u32>,
    /// Mutate every delivered chunk's bytes in place, same length (the
    /// lying-manifest scenario: manifest of A, bytes of B).
    pub lie_chunk_bytes: bool,
    /// Abort after N chunk deliveries (interrupted transfer; surfaces as
    /// `Interrupted` on the sender and `Closed` on the receiver).
    pub stop_after_chunks: Option<u32>,
}

#[derive(Default, Debug)]
struct FaultState {
    corrupt_done: bool,
    duplicate_done: bool,
    wrong_done: bool,
    withhold_done: bool,
}

/// The sender side: holds the manifest and its self-verified chunk
/// source, answers REQUEST rounds, terminates batches with COMPLETE,
/// and accepts exactly one correctly-bound DELIVERED.
#[derive(Debug)]
pub struct TransferSender {
    manifest: ContentManifest,
    chunks: Vec<Vec<u8>>,
    faults: SenderFaults,
    state: FaultState,
}

impl TransferSender {
    /// Build the sender from a manifest and its chunk list.
    ///
    /// FAIL-CLOSED BEFORE THE WIRE: every chunk is verified against its
    /// manifest slot (length law, then hash law) at construction — a
    /// sender never sends an unverifiable chunk. The chunk count must
    /// match the manifest exactly and fit the u32 slot index space.
    pub fn new(
        manifest: ContentManifest,
        chunks: Vec<Vec<u8>>,
    ) -> Result<Self, TransferError> {
        if manifest.chunk_count() == 0 || manifest.chunk_count() > u32::MAX as usize {
            return Err(TransferError::SlotIndexOverflow {
                count: manifest.chunk_count(),
            });
        }
        if chunks.len() != manifest.chunk_count() {
            return Err(TransferError::ChunkSourceCountMismatch {
                expected: manifest.chunk_count(),
                found: chunks.len(),
            });
        }
        for (slot, chunk) in chunks.iter().enumerate() {
            let expected = manifest
                .expected_chunk_len(slot)
                .expect("slot < chunk_count checked above");
            if chunk.len() as u64 != expected {
                return Err(TransferError::ChunkSourceCorrupt {
                    slot: slot as u32,
                    cause: ContentError::ChunkLengthWrong {
                        slot,
                        found: chunk.len() as u64,
                        expected,
                    },
                });
            }
            if chunk_hash(chunk) != manifest.chunk_hashes()[slot] {
                return Err(TransferError::ChunkSourceCorrupt {
                    slot: slot as u32,
                    cause: ContentError::ChunkHashMismatch { slot },
                });
            }
        }
        Ok(TransferSender {
            manifest,
            chunks,
            faults: SenderFaults::default(),
            state: FaultState::default(),
        })
    }

    /// Attach TEST AFFORDANCES (default: none).
    pub fn with_faults(mut self, faults: SenderFaults) -> Self {
        self.faults = faults;
        self
    }

    pub fn manifest(&self) -> &ContentManifest {
        &self.manifest
    }

    /// Run the sender session to DELIVERED (or a typed failure).
    pub fn run<S: TransferStream>(&mut self, stream: &mut S) -> Result<SenderOutcome, TransferError> {
        stream.send_frame(&Message::Offer(self.manifest.to_wire_bytes()).encode())?;
        let mut delivered: u32 = 0;
        loop {
            let frame = stream.recv_frame()?;
            match Message::decode(&frame)? {
                Message::Request(slots) => {
                    if slots.is_empty() {
                        return Err(TransferError::EmptyRequest);
                    }
                    for &slot in &slots {
                        let slot_usize = slot as usize;
                        if slot_usize >= self.chunks.len() {
                            return Err(TransferError::RequestSlotOutOfRange {
                                slot,
                                count: self.chunks.len(),
                            });
                        }
                        if self.withhold(slot) {
                            continue;
                        }
                        self.send_one_chunk(stream, slot)?;
                        delivered += 1;
                        if let Some(limit) = self.faults.stop_after_chunks {
                            if delivered >= limit {
                                return Err(TransferError::Interrupted { sent: delivered });
                            }
                        }
                    }
                    // The batch terminator + completion hint (the
                    // receiver verifies it against its own state).
                    stream.send_frame(
                        &Message::Complete {
                            content_id: self.manifest.content_id(),
                        }
                        .encode(),
                    )?;
                }
                Message::Delivered { content_id } => {
                    if content_id != self.manifest.content_id() {
                        return Err(TransferError::DeliveredIdMismatch {
                            expected: self.manifest.content_id(),
                            found: content_id,
                        });
                    }
                    return Ok(SenderOutcome {
                        content_id,
                    });
                }
                other => {
                    return Err(TransferError::UnexpectedMessage {
                        expected: "request | delivered",
                        found: other.kind(),
                    })
                }
            }
        }
    }

    /// The `withhold_slot_once` fault: skip the slot's first due
    /// delivery.
    fn withhold(&mut self, slot: u32) -> bool {
        if self.faults.withhold_slot_once == Some(slot) && !self.state.withhold_done {
            self.state.withhold_done = true;
            return true;
        }
        false
    }

    /// Deliver one chunk for `slot` (applying the delivery-time faults —
    /// the source itself stays verified and intact).
    fn send_one_chunk<S: TransferStream>(
        &mut self,
        stream: &mut S,
        slot: u32,
    ) -> Result<(), TransferError> {
        let mut bytes = self.chunks[slot as usize].clone();
        // lie_chunk_bytes: mutate in place (same length → the hash law
        // catches it, never the length law).
        if self.faults.lie_chunk_bytes {
            bytes[0] ^= 0xFF;
        }
        // wrong_slot_once: deliver chunk B's bytes labeled as slot A.
        if let Some((a, b)) = self.faults.wrong_slot_once {
            if a == slot && !self.state.wrong_done {
                self.state.wrong_done = true;
                bytes = self.chunks[b as usize].clone();
            }
        }
        // corrupt_slot_once: flip one byte of the first delivery.
        if self.faults.corrupt_slot_once == Some(slot) && !self.state.corrupt_done {
            self.state.corrupt_done = true;
            let last = bytes.len() - 1;
            bytes[last] ^= 0xFF;
        }
        stream.send_frame(
            &Message::Chunk {
                slot,
                data: bytes,
            }
            .encode(),
        )?;
        // duplicate_slot: an extra identical copy right after.
        if self.faults.duplicate_slot == Some(slot) && !self.state.duplicate_done {
            self.state.duplicate_done = true;
            stream.send_frame(
                &Message::Chunk {
                    slot,
                    data: self.chunks[slot as usize].clone(),
                }
                .encode(),
            )?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Receiver
// ---------------------------------------------------------------------------

/// Receiver-side TEST AFFORDANCES (default-off; used by the adversarial
/// suite to forge the completion ack).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiverFaults {
    /// Send DELIVERED with this (wrong) content id instead of the true
    /// one — the sender must reject it typed.
    pub ack_id_override: Option<[u8; 32]>,
}

/// Receive + strictly parse the sender's OFFER. Returns the manifest
/// (the object on offer — `content_id`-committed) or a typed refusal.
///
/// The session split is deliberate: the CALLER owns bank construction
/// (fresh `MemoryBank`/store vs. a resumed store opened against the
/// offered manifest — content-id-bound), then hands both to
/// [`drive_receiver`].
pub fn receive_offer<S: TransferStream>(
    stream: &mut S,
) -> Result<ContentManifest, TransferError> {
    let frame = stream.recv_frame()?;
    match Message::decode(&frame)? {
        Message::Offer(bytes) => {
            let manifest = ContentManifest::from_wire_bytes(&bytes)
                .map_err(|cause| TransferError::ManifestInvalid { cause })?;
            if manifest.chunk_count() > u32::MAX as usize {
                return Err(TransferError::SlotIndexOverflow {
                    count: manifest.chunk_count(),
                });
            }
            Ok(manifest)
        }
        other => Err(TransferError::UnexpectedMessage {
            expected: "offer",
            found: other.kind(),
        }),
    }
}

/// Drive the receiver rounds to the DERIVED completion: full coverage +
/// successful reassemble, then DELIVERED (the ack of that fact).
///
/// `manifest` is the offered object (from [`receive_offer`]); `bank`
/// must be bound to the same content id (asserted here — a bank from a
/// different object is a caller bug the protocol refuses to paper
/// over).
pub fn drive_receiver<S: TransferStream, B: ChunkBank>(
    stream: &mut S,
    manifest: &ContentManifest,
    bank: &mut B,
    policy: &ReceiverPolicy,
    faults: &ReceiverFaults,
) -> Result<ReceiverOutcome, TransferError> {
    if bank.manifest().content_id() != manifest.content_id() {
        return Err(TransferError::ContentIdMismatch {
            expected: bank.manifest().content_id(),
            found: manifest.content_id(),
        });
    }
    let mut outcome = ReceiverOutcome {
        content: Vec::new(),
        content_id: manifest.content_id(),
        rounds: 0,
        accepted: 0,
        rejections: Vec::new(),
        duplicates: Vec::new(),
        premature_completions: 0,
        complete_id_mismatches: 0,
    };
    let mut stall: u32 = 0;
    loop {
        if bank.is_complete() {
            // The derived completion proof: full coverage AND a
            // successful reassemble of the exact content.
            let content = bank
                .manifest()
                .reassemble(&bank.ordered_chunks())
                .map_err(|cause| TransferError::ReassemblyFailed { cause })?;
            let ack_id = faults.ack_id_override.unwrap_or(manifest.content_id());
            stream.send_frame(&Message::Delivered { content_id: ack_id }.encode())?;
            outcome.content = content;
            return Ok(outcome);
        }
        let missing = bank.missing_slots();
        let requested: HashSet<u32> = missing.iter().copied().collect();
        let banked_before = bank.banked_count();
        stream.send_frame(&Message::Request(missing).encode())?;
        outcome.rounds += 1;
        // Slots this round has seen a delivery for (accepted, rejected
        // or duplicate): COMPLETE while a requested slot was never
        // delivered AT ALL is the premature-completion forgery signal.
        let mut discharged: HashSet<u32> = HashSet::new();
        // One round: read chunks until the sender's COMPLETE terminator
        // (or a fatal error).
        loop {
            let frame = stream.recv_frame()?;
            match Message::decode(&frame)? {
                Message::Chunk { slot, data } => {
                    discharged.insert(slot);
                    match verify_chunk(manifest, slot, &data) {
                        Ok(()) => {
                            if bank.slot_present(slot) {
                                outcome.duplicates.push(slot);
                            } else {
                                bank.accept(slot, data)?;
                                outcome.accepted += 1;
                            }
                        }
                        Err(cause) => outcome.rejections.push(ChunkRejection { slot, cause }),
                    }
                }
                Message::Complete { content_id } => {
                    if content_id != manifest.content_id() {
                        outcome.complete_id_mismatches += 1;
                    }
                    if requested.iter().any(|slot| !discharged.contains(slot)) {
                        outcome.premature_completions += 1;
                    }
                    break;
                }
                other => {
                    return Err(TransferError::UnexpectedMessage {
                        expected: "chunk | complete",
                        found: other.kind(),
                    })
                }
            }
        }
        // The stall bound: rounds with zero newly-verified chunks.
        if bank.banked_count() == banked_before {
            stall += 1;
            if stall >= policy.max_stall_rounds {
                return Err(TransferError::Stalled {
                    rounds: stall,
                    missing: bank.missing_slots().len(),
                });
            }
        } else {
            stall = 0;
        }
    }
}

/// The per-chunk admission law (length before hash — the R6-001
/// discipline): `Ok(())` only for a chunk that matches its manifest
/// slot EXACTLY.
fn verify_chunk(
    manifest: &ContentManifest,
    slot: u32,
    data: &[u8],
) -> Result<(), ChunkRejectionCause> {
    let slot_usize = slot as usize;
    if slot_usize >= manifest.chunk_count() {
        return Err(ChunkRejectionCause::SlotOutOfRange {
            slot,
            count: manifest.chunk_count(),
        });
    }
    let expected = manifest
        .expected_chunk_len(slot_usize)
        .expect("slot < chunk_count checked above");
    if data.len() as u64 != expected {
        return Err(ChunkRejectionCause::LengthWrong {
            slot,
            found: data.len() as u64,
            expected,
        });
    }
    if chunk_hash(data) != manifest.chunk_hashes()[slot_usize] {
        return Err(ChunkRejectionCause::HashMismatch { slot });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bank::MemoryBank;
    use crate::frame::{DuplexPair, TappingStream};

    /// Deterministic multi-chunk content: 10 chunks of 8 bytes, last one
    /// 5 (77 bytes total).
    fn build10() -> (ContentManifest, Vec<Vec<u8>>, Vec<u8>) {
        let content: Vec<u8> = (0..77u32).map(|i| (i % 251) as u8).collect();
        let (manifest, chunks) =
            ContentManifest::chunk(&content, 8, "application/test", None, 1_700_000_000)
                .expect("manifest");
        (manifest, chunks, content)
    }

    /// Run a full transfer over an in-memory duplex pair (one scoped
    /// thread per role). Returns (sender result, receiver result).
    fn run_transfer(
        mut sender: TransferSender,
        bank: &mut MemoryBank,
        policy: &ReceiverPolicy,
        rfaults: &ReceiverFaults,
    ) -> (Result<SenderOutcome, TransferError>, Result<ReceiverOutcome, TransferError>) {
        let pair = DuplexPair::new();
        let (mut s_end, mut r_end) = (pair.a, pair.b);
        std::thread::scope(|scope| {
            let sh = scope.spawn(move || sender.run(&mut s_end));
            let rh = scope.spawn(move || {
                let manifest = receive_offer(&mut r_end)?;
                drive_receiver(&mut r_end, &manifest, bank, policy, rfaults)
            });
            (
                sh.join().expect("sender thread"),
                rh.join().expect("receiver thread"),
            )
        })
    }

    /// Like [`run_transfer`], but also returns every frame the RECEIVER
    /// sent (the REQUEST evidence for exact-resume assertions).
    fn run_transfer_tapped(
        mut sender: TransferSender,
        bank: &mut MemoryBank,
        policy: &ReceiverPolicy,
    ) -> (
        Result<SenderOutcome, TransferError>,
        Result<ReceiverOutcome, TransferError>,
        Vec<Message>,
    ) {
        let pair = DuplexPair::new();
        let (mut s_end, r_end) = (pair.a, pair.b);
        let (mut tapped, log) = TappingStream::new(r_end);
        let out = std::thread::scope(|scope| {
            let sh = scope.spawn(move || sender.run(&mut s_end));
            let rh = scope.spawn(move || {
                let manifest = receive_offer(&mut tapped)?;
                drive_receiver(&mut tapped, &manifest, bank, policy, &ReceiverFaults::default())
            });
            (
                sh.join().expect("sender thread"),
                rh.join().expect("receiver thread"),
            )
        });
        let frames: Vec<Message> = log
            .try_iter()
            .map(|f| Message::decode(&f).expect("receiver sent a valid frame"))
            .collect();
        (out.0, out.1, frames)
    }

    #[test]
    fn happy_path_full_transfer_byte_exact() {
        let (manifest, chunks, content) = build10();
        let sender = TransferSender::new(manifest, chunks).expect("sender");
        let mut bank = MemoryBank::new(build10().0).expect("bank");
        let (sres, rres) = run_transfer(
            sender,
            &mut bank,
            &ReceiverPolicy::default(),
            &ReceiverFaults::default(),
        );
        let s = sres.expect("sender delivered");
        let r = rres.expect("receiver delivered");
        assert_eq!(s.content_id, r.content_id);
        assert_eq!(r.content, content);
        assert_eq!(r.rounds, 1, "one round when nothing is rejected");
        assert_eq!(r.accepted, 10);
        assert!(r.rejections.is_empty());
        assert!(r.duplicates.is_empty());
        assert_eq!(r.premature_completions, 0);
        assert_eq!(r.complete_id_mismatches, 0);
    }

    #[test]
    fn exact_resume_only_missing_slots_requested() {
        let (manifest, chunks, content) = build10();
        // Session 1: interrupted after 4 chunks.
        let sender = TransferSender::new(manifest.clone(), chunks.clone())
            .expect("sender")
            .with_faults(SenderFaults {
                stop_after_chunks: Some(4),
                ..Default::default()
            });
        let mut bank = MemoryBank::new(manifest.clone()).expect("bank");
        let (sres, rres) = run_transfer(
            sender,
            &mut bank,
            &ReceiverPolicy::default(),
            &ReceiverFaults::default(),
        );
        assert!(matches!(sres, Err(TransferError::Interrupted { sent: 4 })));
        assert!(matches!(rres, Err(TransferError::Closed)));
        assert_eq!(bank.banked_count(), 4);
        assert_eq!(bank.missing_slots(), vec![4, 5, 6, 7, 8, 9]);

        // Session 2: a NEW receiver holding the same partial state —
        // its ONLY request must name EXACTLY the complement.
        let sender2 = TransferSender::new(manifest, chunks).expect("sender");
        let policy = ReceiverPolicy::default();
        let (sres, rres, sent_frames) = run_transfer_tapped(sender2, &mut bank, &policy);
        sres.expect("sender2 delivered");
        let r = rres.expect("receiver completes");
        assert_eq!(r.content, content);
        assert_eq!(r.accepted, 6, "only the missing slots were fetched");
        let requests: Vec<&Vec<u32>> = sent_frames
            .iter()
            .filter_map(|m| match m {
                Message::Request(slots) => Some(slots),
                _ => None,
            })
            .collect();
        assert_eq!(requests.len(), 1, "one round after clean partial state");
        assert_eq!(requests[0], &vec![4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn corrupted_chunk_rejected_then_refetched_transfer_completes() {
        let (manifest, chunks, content) = build10();
        let sender = TransferSender::new(manifest.clone(), chunks)
            .expect("sender")
            .with_faults(SenderFaults {
                corrupt_slot_once: Some(3),
                ..Default::default()
            });
        let mut bank = MemoryBank::new(manifest).expect("bank");
        let (_s, r) = run_transfer(
            sender,
            &mut bank,
            &ReceiverPolicy::default(),
            &ReceiverFaults::default(),
        );
        let r = r.expect("transfer continues to completion");
        assert_eq!(r.content, content);
        assert_eq!(r.rounds, 2, "a second round refetched the bad slot");
        assert_eq!(r.rejections.len(), 1);
        assert_eq!(r.rejections[0].slot, 3);
        assert_eq!(r.rejections[0].cause.name(), "chunk_hash_mismatch");
        assert_eq!(r.accepted, 10);
        // The sender DID answer slot 3 (badly): its COMPLETE was not a
        // premature-completion forgery.
        assert_eq!(r.premature_completions, 0);
    }

    #[test]
    fn duplicate_injection_is_idempotent_no_double_store() {
        let (manifest, chunks, content) = build10();
        let sender = TransferSender::new(manifest.clone(), chunks)
            .expect("sender")
            .with_faults(SenderFaults {
                duplicate_slot: Some(2),
                ..Default::default()
            });
        let mut bank = MemoryBank::new(manifest).expect("bank");
        let (_s, r) = run_transfer(
            sender,
            &mut bank,
            &ReceiverPolicy::default(),
            &ReceiverFaults::default(),
        );
        let r = r.expect("delivered");
        assert_eq!(r.content, content);
        assert_eq!(r.duplicates, vec![2]);
        assert_eq!(bank.banked_count(), 10, "the duplicate stored nothing");
        assert_eq!(r.accepted, 10);
    }

    #[test]
    fn wrong_slot_delivery_rejected_then_refetched() {
        let (manifest, chunks, content) = build10();
        let sender = TransferSender::new(manifest.clone(), chunks)
            .expect("sender")
            .with_faults(SenderFaults {
                wrong_slot_once: Some((7, 0)), // slot 7 labeled, chunk 0's bytes
                ..Default::default()
            });
        let mut bank = MemoryBank::new(manifest).expect("bank");
        let (_s, r) = run_transfer(
            sender,
            &mut bank,
            &ReceiverPolicy::default(),
            &ReceiverFaults::default(),
        );
        let r = r.expect("delivered");
        assert_eq!(r.content, content);
        let rej = &r.rejections[0];
        assert_eq!(rej.slot, 7);
        assert_eq!(rej.cause.name(), "chunk_hash_mismatch");
        assert!(bank.slot_present(7), "refetched good slot 7");
    }

    #[test]
    fn short_chunk_rejected_by_length_law_before_hash_law() {
        // The verdict-level law: structurally wrong input is never
        // hashed (the R6-001 discipline carried into admission).
        let (manifest, _, _) = build10();
        let cause = verify_chunk(&manifest, 0, &[]).unwrap_err();
        assert!(matches!(
            cause,
            ChunkRejectionCause::LengthWrong { slot: 0, found: 0, expected: 8 }
        ));
        let cause = verify_chunk(&manifest, 9, &[0u8; 6]).unwrap_err();
        assert!(matches!(cause, ChunkRejectionCause::LengthWrong { slot: 9, .. }));
        let cause = verify_chunk(&manifest, 10, &[0u8; 8]).unwrap_err();
        assert!(matches!(cause, ChunkRejectionCause::SlotOutOfRange { slot: 10, count: 10 }));
        let cause = verify_chunk(&manifest, u32::MAX, &[0u8; 8]).unwrap_err();
        assert!(matches!(cause, ChunkRejectionCause::SlotOutOfRange { .. }));
        // A good chunk passes both laws.
        let good: Vec<u8> = (32..40).map(|i| i as u8).collect();
        assert!(verify_chunk(&manifest, 4, &good).is_ok());
        // Same length, wrong bytes: the hash law.
        let mut bad = good.clone();
        bad[7] ^= 0xFF;
        assert!(matches!(
            verify_chunk(&manifest, 4, &bad).unwrap_err(),
            ChunkRejectionCause::HashMismatch { slot: 4 }
        ));
    }

    #[test]
    fn lying_manifest_stalls_fail_closed_after_policy_rounds() {
        let (manifest, chunks, _) = build10();
        let sender = TransferSender::new(manifest.clone(), chunks)
            .expect("sender")
            .with_faults(SenderFaults {
                lie_chunk_bytes: true,
                ..Default::default()
            });
        let mut bank = MemoryBank::new(manifest).expect("bank");
        let policy = ReceiverPolicy {
            max_stall_rounds: 2,
        };
        let (sres, rres) = run_transfer(sender, &mut bank, &policy, &ReceiverFaults::default());
        let err = rres.unwrap_err();
        assert_eq!(err.name(), "stalled");
        assert!(matches!(err, TransferError::Stalled { rounds: 2, missing: 10 }));
        assert_eq!(bank.banked_count(), 0, "nothing unverifiable was banked");
        assert!(sres.is_err(), "the sender also fails (receiver gave up)");
    }

    #[test]
    fn withheld_slot_premature_complete_is_ignored_and_transfer_continues() {
        let (manifest, chunks, content) = build10();
        let sender = TransferSender::new(manifest.clone(), chunks)
            .expect("sender")
            .with_faults(SenderFaults {
                withhold_slot_once: Some(5),
                ..Default::default()
            });
        let mut bank = MemoryBank::new(manifest).expect("bank");
        let (_s, r) = run_transfer(
            sender,
            &mut bank,
            &ReceiverPolicy::default(),
            &ReceiverFaults::default(),
        );
        let r = r.expect("the forged hint never produced completion");
        assert_eq!(r.content, content);
        assert_eq!(r.premature_completions, 1);
        assert_eq!(r.rounds, 2);
        assert_eq!(r.accepted, 10);
    }

    #[test]
    fn forged_complete_before_any_chunk_is_contained() {
        // A forger fires COMPLETE immediately after the OFFER, then
        // (as an honest sender would after re-request) delivers the
        // real chunks. The forged hint must be recorded and ignored —
        // completion is only ever derived.
        let (manifest, chunks, content) = build10();
        let pair = DuplexPair::new();
        let (mut s_end, mut r_end) = (pair.a, pair.b);
        let res = std::thread::scope(|scope| {
            let sh = scope.spawn(move || -> Result<SenderOutcome, TransferError> {
                s_end.send_frame(&Message::Offer(manifest.to_wire_bytes()).encode())?;
                // The forgery: completion claimed before any chunk.
                s_end.send_frame(
                    &Message::Complete {
                        content_id: manifest.content_id(),
                    }
                    .encode(),
                )?;
                // Then behave honestly for every request round.
                //
                // The forged COMPLETE consumes the receiver's first
                // round, so the receiver re-requests — and its SECOND
                // request races the receiver's own completion: the
                // receiver banks the first response's chunks, derives
                // completion, sends DELIVERED and returns (dropping its
                // end) while this sender may still be responding to that
                // second request. A `Closed` there is the BENIGN
                // early-shutdown (the peer completed and hung up), not a
                // transfer loss — the receiver's outcome is asserted
                // independently below (byte-exact content, the recorded
                // forgery, all 10 chunks), so mapping it to an early
                // success keeps the oracle exactly as strong.
                let mut responded_rounds: u32 = 0;
                loop {
                    match Message::decode(&s_end.recv_frame()?)? {
                        Message::Request(slots) => {
                            for slot in slots {
                                let send = s_end.send_frame(
                                    &Message::Chunk {
                                        slot,
                                        data: chunks[slot as usize].clone(),
                                    }
                                    .encode(),
                                );
                                if matches!(send, Err(TransferError::Closed))
                                    && responded_rounds >= 1
                                {
                                    return Ok(SenderOutcome {
                                        content_id: manifest.content_id(),
                                    });
                                }
                                send?;
                            }
                            let send = s_end.send_frame(
                                &Message::Complete {
                                    content_id: manifest.content_id(),
                                }
                                .encode(),
                            );
                            if matches!(send, Err(TransferError::Closed))
                                && responded_rounds >= 1
                            {
                                return Ok(SenderOutcome {
                                    content_id: manifest.content_id(),
                                });
                            }
                            send?;
                            responded_rounds += 1;
                        }
                        Message::Delivered { .. } => {
                            return Ok(SenderOutcome {
                                content_id: manifest.content_id(),
                            })
                        }
                        other => {
                            return Err(TransferError::UnexpectedMessage {
                                expected: "request | delivered",
                                found: other.kind(),
                            })
                        }
                    }
                }
            });
            let rh = scope.spawn(move || {
                let m = receive_offer(&mut r_end)?;
                let mut bank = MemoryBank::new(m.clone()).expect("bank");
                drive_receiver(
                    &mut r_end,
                    &m,
                    &mut bank,
                    &ReceiverPolicy::default(),
                    &ReceiverFaults::default(),
                )
            });
            (
                sh.join().expect("s thread"),
                rh.join().expect("r thread"),
            )
        });
        res.0.expect("sender delivered");
        let r = res.1.expect("receiver completed despite the forgery");
        assert_eq!(r.content, content);
        assert_eq!(r.premature_completions, 1, "the early COMPLETE is recorded");
        assert_eq!(r.accepted, 10);
    }

    #[test]
    fn forged_delivered_ack_rejected_by_sender() {
        let (manifest, chunks, _) = build10();
        let sender = TransferSender::new(manifest, chunks).expect("sender");
        let mut bank = MemoryBank::new(build10().0).expect("bank");
        let wrong_id = [0xEE; 32];
        let faults = ReceiverFaults {
            ack_id_override: Some(wrong_id),
        };
        let (sres, rres) = run_transfer(
            sender,
            &mut bank,
            &ReceiverPolicy::default(),
            &faults,
        );
        // The receiver legitimately completed (the forge is in the ack).
        rres.expect("receiver completed");
        let err = sres.unwrap_err();
        assert_eq!(err.name(), "delivered_id_mismatch");
        assert!(
            matches!(err, TransferError::DeliveredIdMismatch { found, .. } if found == wrong_id),
            "got {err:?}"
        );
    }

    #[test]
    fn sender_source_corruption_fails_before_the_wire() {
        let (manifest, mut chunks, _) = build10();
        chunks[4][0] ^= 0xFF; // the sender's own content is corrupt
        let err = TransferSender::new(manifest, chunks).unwrap_err();
        assert_eq!(err.name(), "chunk_source_corrupt");
        assert!(matches!(err, TransferError::ChunkSourceCorrupt { slot: 4, .. }));
    }

    #[test]
    fn sender_count_mismatch_fails_before_the_wire() {
        let (manifest, mut chunks, _) = build10();
        chunks.pop();
        let err = TransferSender::new(manifest, chunks).unwrap_err();
        assert_eq!(err.name(), "chunk_source_count_mismatch");
    }

    #[test]
    fn receiver_refuses_offer_for_a_different_object() {
        // The bank is bound to object A; the offer names object B.
        let (manifest_a, _, _) = build10();
        let content_b: Vec<u8> = (0..50u32).map(|i| (i % 247) as u8).collect();
        let (manifest_b, _) =
            ContentManifest::chunk(&content_b, 8, "application/test", None, 1_700_000_000)
                .expect("manifest");
        let pair = DuplexPair::new();
        let (mut s_end, mut r_end) = (pair.a, pair.b);
        // Feed the receiver's inbox with B's offer (no live sender
        // needed: the binding check fires before any round).
        s_end
            .send_frame(&Message::Offer(manifest_b.to_wire_bytes()).encode())
            .expect("offer B");
        let mut bank = MemoryBank::new(manifest_a).expect("bank for A");
        let manifest = receive_offer(&mut r_end).expect("offer B parses");
        let err = drive_receiver(
            &mut r_end,
            &manifest,
            &mut bank,
            &ReceiverPolicy::default(),
            &ReceiverFaults::default(),
        )
        .unwrap_err();
        assert_eq!(err.name(), "content_id_mismatch");
    }

    #[test]
    fn empty_request_is_a_protocol_violation_for_the_sender() {
        let (manifest, chunks, _) = build10();
        let mut sender = TransferSender::new(manifest, chunks).expect("sender");
        let pair = DuplexPair::new();
        let (mut s_end, mut r_end) = (pair.a, pair.b);
        // A "receiver" that requests nothing.
        r_end
            .send_frame(&Message::Request(vec![]).encode())
            .expect("empty request");
        let err = sender.run(&mut s_end).unwrap_err();
        assert_eq!(err.name(), "empty_request");
    }

    #[test]
    fn out_of_range_request_slot_fails_closed_on_the_sender() {
        let (manifest, chunks, _) = build10();
        let mut sender = TransferSender::new(manifest, chunks).expect("sender");
        let pair = DuplexPair::new();
        let (mut s_end, mut r_end) = (pair.a, pair.b);
        r_end
            .send_frame(&Message::Request(vec![10, 11]).encode())
            .expect("request");
        let err = sender.run(&mut s_end).unwrap_err();
        assert_eq!(err.name(), "request_slot_out_of_range");
    }

    #[test]
    fn unexpected_messages_are_typed_violations() {
        // RECEIVER sees a DELIVERED (only the sender accepts those).
        let pair = DuplexPair::new();
        let (mut s_end, mut r_end) = (pair.a, pair.b);
        s_end
            .send_frame(&Message::Delivered { content_id: [0; 32] }.encode())
            .expect("bogus");
        let err = receive_offer(&mut r_end).unwrap_err();
        assert_eq!(err.name(), "unexpected_message");

        // SENDER sees an OFFER (only the receiver accepts those).
        let (manifest, chunks, _) = build10();
        let mut sender = TransferSender::new(manifest, chunks).expect("sender");
        let pair2 = DuplexPair::new();
        let (mut s2, mut r2) = (pair2.a, pair2.b);
        r2.send_frame(&Message::Offer(vec![1, 2, 3]).encode())
            .expect("bogus offer");
        let err = sender.run(&mut s2).unwrap_err();
        assert_eq!(err.name(), "unexpected_message");
    }

    #[test]
    fn garbage_type_byte_is_a_typed_violation() {
        let pair = DuplexPair::new();
        let (mut s_end, mut r_end) = (pair.a, pair.b);
        s_end.send_frame(&[0x99, 0x00]).expect("garbage frame");
        let err = receive_offer(&mut r_end).unwrap_err();
        assert_eq!(err.name(), "unknown_message_type");
    }

    #[test]
    fn unparsable_offer_manifest_refused_typed() {
        let pair = DuplexPair::new();
        let (mut s_end, mut r_end) = (pair.a, pair.b);
        s_end
            .send_frame(&Message::Offer(b"\xa5truncated".to_vec()).encode())
            .expect("offer with a garbage manifest");
        let err = receive_offer(&mut r_end).unwrap_err();
        assert_eq!(err.name(), "manifest_invalid");
    }

    #[test]
    fn multiple_faults_compose() {
        // corrupt slot 1, duplicate slot 2, wrong-slot 7=0, withhold 5:
        // every contained rejection refetched, transfer still completes.
        let (manifest, chunks, content) = build10();
        let sender = TransferSender::new(manifest.clone(), chunks)
            .expect("sender")
            .with_faults(SenderFaults {
                corrupt_slot_once: Some(1),
                duplicate_slot: Some(2),
                wrong_slot_once: Some((7, 0)),
                withhold_slot_once: Some(5),
                ..Default::default()
            });
        let mut bank = MemoryBank::new(manifest).expect("bank");
        let (_s, r) = run_transfer(
            sender,
            &mut bank,
            &ReceiverPolicy::default(),
            &ReceiverFaults::default(),
        );
        let r = r.expect("delivered despite everything");
        assert_eq!(r.content, content);
        assert_eq!(r.duplicates, vec![2]);
        let rejected: Vec<u32> = r.rejections.iter().map(|x| x.slot).collect();
        assert!(rejected.contains(&1) && rejected.contains(&7), "{rejected:?}");
        assert_eq!(
            r.premature_completions, 1,
            "the withheld slot made round 1 premature"
        );
        assert!(r.rounds >= 2);
        assert_eq!(bank.banked_count(), 10);
    }

    #[test]
    fn stall_counter_resets_on_progress() {
        // Rounds that make progress never accumulate a stall — the
        // bound counts CONSECUTIVE no-progress rounds only.
        let (manifest, chunks, content) = build10();
        let sender = TransferSender::new(manifest.clone(), chunks)
            .expect("sender")
            .with_faults(SenderFaults {
                corrupt_slot_once: Some(3),
                ..Default::default()
            });
        let mut bank = MemoryBank::new(manifest).expect("bank");
        let policy = ReceiverPolicy {
            max_stall_rounds: 2,
        };
        let (_s, r) = run_transfer(sender, &mut bank, &policy, &ReceiverFaults::default());
        let r = r.expect("progress resets the stall counter");
        assert_eq!(r.content, content);
        assert_eq!(r.rounds, 2);
    }

    #[test]
    fn single_chunk_content_transfers() {
        let content = b"one chunk only".to_vec();
        let (manifest, chunks) =
            ContentManifest::chunk(&content, 1024, "application/test", None, 1_700_000_000)
                .expect("manifest");
        let sender = TransferSender::new(manifest.clone(), chunks).expect("sender");
        let mut bank = MemoryBank::new(manifest).expect("bank");
        let (_s, r) = run_transfer(
            sender,
            &mut bank,
            &ReceiverPolicy::default(),
            &ReceiverFaults::default(),
        );
        assert_eq!(r.expect("delivered").content, content);
    }

    #[test]
    fn exact_boundary_content_transfers() {
        // 32 bytes at chunk_size 16: no short last chunk.
        let content: Vec<u8> = (0..32u8).collect();
        let (manifest, chunks) =
            ContentManifest::chunk(&content, 16, "application/test", None, 1_700_000_000)
                .expect("manifest");
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[1].len(), 16);
        let sender = TransferSender::new(manifest.clone(), chunks).expect("sender");
        let mut bank = MemoryBank::new(manifest).expect("bank");
        let (_s, r) = run_transfer(
            sender,
            &mut bank,
            &ReceiverPolicy::default(),
            &ReceiverFaults::default(),
        );
        assert_eq!(r.expect("delivered").content, content);
    }

    #[test]
    fn default_policy_bounds() {
        assert_eq!(ReceiverPolicy::default().max_stall_rounds, DEFAULT_MAX_STALL_ROUNDS);
        assert_eq!(DEFAULT_MAX_STALL_ROUNDS, 4);
        assert_eq!(SenderFaults::default(), SenderFaults::default());
        assert_eq!(ReceiverFaults::default(), ReceiverFaults::default());
    }
}
