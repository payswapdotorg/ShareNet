//! # sharenet-transfer — R6-002: resumable content transfer
//!
//! The receiver-driven chunk-transfer session protocol that moves a
//! chunked, content-addressed object (an R6-001 `ContentManifest`) from
//! a sender to a receiver over ANY established byte-stream/tunnel, and
//! can resume from ANY partial state.
//!
//! This is a DOCUMENTED RUNTIME CONTROL PROTOCOL (the same class as the
//! Linux gateway's tunnel control protocol, R4-003 — NOT a registry
//! wire object): it rides INSIDE a carrying layer and its only trust
//! authority is the registered, `content_id`-committed `ContentManifest`
//! carried in the OFFER.
//!
//! ## The protocol
//!
//! ```text
//! sender                                   receiver
//!   │ OFFER(manifest bytes)                  │
//!   │ ────────────────────────────────────► │ strict parse (R6-001 invariants)
//!   │                                       │ bind the bank: same content id,
//!   │                                       │   or refuse typed
//!   │                 REQUEST(missing slots) │ ← the bank's slot bitmap complement
//!   │ ◄──────────────────────────────────── │
//!   │ CHUNK(slot, bytes) ─────────────────► │ per-slot verification (length law,
//!   │ CHUNK(slot, bytes) ─────────────────► │   then hash law); bank ONLY verified
//!   │ ...                                   │   chunks; bad chunks are CONTAINED
//!   │ COMPLETE(content_id) ───────────────► │ round terminator — a HINT, never
//!   │                                       │   authority (premature → re-request)
//!   │                                       │ bitmap full? → reassemble() — the
//!   │                                       │   DERIVED completion proof
//!   │               DELIVERED(content_id)   │
//!   │ ◄──────────────────────────────────── │
//! ```
//!
//! | byte | message | direction | payload |
//! |---|---|---|---|
//! | 0x01 | OFFER | S→R | manifest canonical CBOR bytes |
//! | 0x02 | REQUEST | R→S | u32 n + n × u32 slot |
//! | 0x03 | CHUNK | S→R | u32 slot + chunk bytes |
//! | 0x04 | COMPLETE | S→R | content_id (32 bytes) |
//! | 0x05 | DELIVERED | R→S | content_id (32 bytes) |
//!
//! ## The laws
//!
//! 1. **Manifest-only trust.** The manifest is the only authority:
//!    never claimed sizes, never claimed counts, never completion
//!    assertions. Every chunk is verified with the R6-001 seams
//!    (`expected_chunk_len`, then `chunk_hash` — length before hash, so
//!    structurally wrong input is never hashed).
//! 2. **Per-slot hash verification.** A chunk enters the bank ONLY
//!    after matching its manifest slot exactly.
//! 3. **Completion is derived, never asserted.** Completion = full
//!    bitmap coverage + successful `reassemble()`. The sender's
//!    COMPLETE is a hint the receiver verifies; the receiver's
//!    DELIVERED is the ack of a derived fact — and the sender verifies
//!    THAT against its own manifest (a forged ack is rejected typed, no
//!    delivery recorded).
//! 4. **Fail-closed, contained per chunk.** Carriage failures,
//!    protocol violations, manifest binding mismatches, a corrupt
//!    sender source and the stall bound abort typed. A single bad
//!    chunk is recorded and re-requested — the transfer continues.
//! 5. **Resume from any partial state.** The bank persists per
//!    verified chunk; on reload every chunk file is re-verified
//!    against the manifest and the bitmap re-derived (a tampered
//!    bitmap fabricates nothing; disk corruption is evicted per slot
//!    and re-fetched).
//! 6. **Transport-agnostic.** The protocol runs over anything
//!    implementing [`TransferStream`] (TCP here; the QUIC
//!    `TunnelStream` and DTN pipes at integration — see the README).
//!
//! ## What this is NOT (honest scope)
//!
//! No dedup-by-hash store, TTL, replication or custody evidence — that
//! is R6-003's DTN layer (which implements [`ChunkBank`] on top of its
//! content store). No signed delivery receipts — DELIVERED is an ack of
//! a derived fact, not future contribution evidence (R8-001 signs
//! receipts). No windowing/flow control (the whole missing set is
//! requested per round — R6-005's opportunistic forwarding composes on
//! top). The receiver's DELIVERED does not attest WHO received the
//! content — sender/receiver authentication belongs to the carrying
//! layer (a node-pinned R4-001 tunnel in production; a bare TCP run is
//! unauthenticated carriage, though content integrity still holds).

#![forbid(unsafe_code)]

pub mod bank;
pub mod bitmap;
pub mod error;
pub mod frame;
pub mod message;
pub mod session;
#[cfg(not(target_family = "wasm"))]
pub mod store;

pub use bank::{ChunkBank, MemoryBank};
pub use bitmap::SlotBitmap;
pub use error::{hex, unhex_32, TransferError, CONTENT_ID_LEN};
pub use frame::{
    DuplexEnd, DuplexPair, LengthPrefixed, TappingStream, TransferStream, TRANSFER_MAX_FRAME,
};
pub use message::{Message, MSG_CHUNK, MSG_COMPLETE, MSG_DELIVERED, MSG_OFFER, MSG_REQUEST};
pub use session::{
    drive_receiver, receive_offer, ChunkRejection, ChunkRejectionCause, ReceiverFaults,
    ReceiverOutcome, ReceiverPolicy, SenderFaults, SenderOutcome, TransferSender,
    DEFAULT_MAX_STALL_ROUNDS,
};
#[cfg(not(target_family = "wasm"))]
pub use store::{manifest_from_bytes, chunk_content, ReceiverStore, ReloadReport};

#[cfg(test)]
mod lib_tests {
    // A cross-module sanity test: the crate's own README protocol table
    // pinned as constants.
    use crate::*;

    #[test]
    fn crate_surface_is_wired() {
        let policy = ReceiverPolicy::default();
        assert_eq!(policy.max_stall_rounds, 4);
        assert_eq!(TRANSFER_MAX_FRAME, 2_097_152 + 64);
        assert_eq!(MSG_OFFER, 0x01);
        assert_eq!(MSG_REQUEST, 0x02);
        assert_eq!(MSG_CHUNK, 0x03);
        assert_eq!(MSG_COMPLETE, 0x04);
        assert_eq!(MSG_DELIVERED, 0x05);
        assert_eq!(CONTENT_ID_LEN, 32);
        assert_eq!(hex(&[0xbe, 0xef]), "beef");
        assert!(unhex_32("00").is_none());
        let bm = SlotBitmap::new(64).expect("bitmap");
        assert_eq!(bm.slots(), 64);
    }
}
