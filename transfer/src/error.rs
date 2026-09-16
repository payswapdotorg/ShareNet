//! Typed failures of the resumable transfer protocol, with stable machine
//! names (the house `name()` vocabulary — the test binaries and the
//! multiprocess evidence lines speak exactly these strings).

use sharenet_protocol::ContentError;

/// Byte length of a content id (SHA-256, same as a chunk hash).
pub const CONTENT_ID_LEN: usize = 32;

/// Typed failures of the resumable transfer session protocol.
///
/// Two classes, deliberately separated:
///
/// - **fatal** (`Err`): carriage failures, wire-syntax violations,
///   protocol violations, manifest binding mismatches, a corrupt sender
///   source, and the stall bound. These abort the session fail-closed.
/// - **contained** (recorded in [`crate::ChunkRejection`], never fatal): a
///   single bad chunk is rejected and re-requested — "the receiver
///   rejects, the transfer continues" is a law, not a bug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransferError {
    // ---- carriage (the carrying stream) ----
    /// Underlying I/O failure of the carrying stream.
    Io { context: &'static str, source: String },
    /// The peer closed the carrying stream (clean EOF mid-session —
    /// an interrupted transfer; receiver state persists).
    Closed,
    /// A frame length prefix exceeded the frame cap (the R4-001/R4-003
    /// adversarial 0xFFFFFFFF precedent).
    FrameTooLarge { found: usize, max: usize },
    // ---- wire syntax ----
    /// Unknown message type byte on the wire.
    UnknownMessageType { found: u8 },
    /// A structurally invalid message (bad payload length, trailing
    /// bytes, count disagreement).
    MessageMalformed { kind: &'static str, reason: &'static str },
    // ---- protocol violations ----
    /// A message arrived that the state machine never accepts in that
    /// state.
    UnexpectedMessage { expected: &'static str, found: &'static str },
    /// The receiver sent an empty REQUEST (a complete receiver
    /// finalizes, it never requests nothing).
    EmptyRequest,
    /// The receiver requested a slot outside the manifest.
    RequestSlotOutOfRange { slot: u32, count: usize },
    /// The receiver's DELIVERED ack names a different object than the
    /// one this sender served (forged completion proof).
    DeliveredIdMismatch { expected: [u8; CONTENT_ID_LEN], found: [u8; CONTENT_ID_LEN] },
    // ---- manifest binding ----
    /// The OFFER did not carry a valid ContentManifest (R6-001 strict
    /// parse + invariants).
    ManifestInvalid { cause: ContentError },
    /// The offered object is not the one this receiver state belongs to
    /// (a state dir is bound to exactly one content id).
    ContentIdMismatch { expected: [u8; CONTENT_ID_LEN], found: [u8; CONTENT_ID_LEN] },
    /// The manifest has more chunk slots than the u32 slot indices on
    /// the wire can name.
    SlotIndexOverflow { count: usize },
    // ---- sender source ----
    /// The sender's own chunks disagree with its manifest (fail-closed
    /// BEFORE the wire: a sender never sends an unverifiable chunk).
    ChunkSourceCorrupt { slot: u32, cause: ContentError },
    /// The sender's chunk list length disagrees with the manifest.
    ChunkSourceCountMismatch { expected: usize, found: usize },
    // ---- completion ----
    /// Consecutive rounds made no accepted progress (a lying manifest /
    /// a sender that never delivers anything verifiable). Fail-closed
    /// after the policy bound instead of looping forever.
    Stalled { rounds: u32, missing: usize },
    /// The final reassembly failed although every present chunk was
    /// verified at admission (disk tampering between admission and
    /// reassembly — impossible without local state corruption).
    ReassemblyFailed { cause: ContentError },
    // ---- receiver store (durable state) ----
    /// I/O failure of the file-backed receiver store.
    StoreIo { context: &'static str, source: String },
    /// The persisted state is unusable (e.g. an unreadable manifest
    /// record — the authority file; without it nothing can be verified).
    StoreCorrupt { detail: String },
    /// The slot bitmap could not be allocated.
    BitmapAllocationFailed { words: usize },
    /// A zero-slot bitmap was requested (a manifest always has at least
    /// one chunk).
    BitmapEmpty,
    // ---- test affordance (documented, not a production path) ----
    /// The sender's `stop_after_chunks` fault fired: the transfer was
    /// interrupted on purpose after `sent` chunk deliveries (the
    /// interrupted-resume evidence driver).
    Interrupted { sent: u32 },
}

impl TransferError {
    /// Stable machine name (test assertions + the binary's ERROR lines).
    pub fn name(&self) -> String {
        match self {
            TransferError::Io { .. } => "io",
            TransferError::Closed => "closed",
            TransferError::FrameTooLarge { .. } => "frame_too_large",
            TransferError::UnknownMessageType { .. } => "unknown_message_type",
            TransferError::MessageMalformed { .. } => "message_malformed",
            TransferError::UnexpectedMessage { .. } => "unexpected_message",
            TransferError::EmptyRequest => "empty_request",
            TransferError::RequestSlotOutOfRange { .. } => "request_slot_out_of_range",
            TransferError::DeliveredIdMismatch { .. } => "delivered_id_mismatch",
            TransferError::ManifestInvalid { .. } => "manifest_invalid",
            TransferError::ContentIdMismatch { .. } => "content_id_mismatch",
            TransferError::SlotIndexOverflow { .. } => "slot_index_overflow",
            TransferError::ChunkSourceCorrupt { .. } => "chunk_source_corrupt",
            TransferError::ChunkSourceCountMismatch { .. } => "chunk_source_count_mismatch",
            TransferError::Stalled { .. } => "stalled",
            TransferError::ReassemblyFailed { .. } => "reassembly_failed",
            TransferError::StoreIo { .. } => "store_io",
            TransferError::StoreCorrupt { .. } => "store_corrupt",
            TransferError::BitmapAllocationFailed { .. } => "bitmap_allocation_failed",
            TransferError::BitmapEmpty => "bitmap_empty",
            TransferError::Interrupted { .. } => "interrupted",
        }
        .to_string()
    }
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use TransferError::*;
        match self {
            Io { context, source } => write!(f, "{context}: {source}"),
            Closed => write!(f, "carrying stream closed mid-session (interrupted transfer)"),
            FrameTooLarge { found, max } => {
                write!(f, "frame of {found} bytes exceeds the {max} byte frame cap")
            }
            UnknownMessageType { found } => {
                write!(f, "unknown message type byte 0x{found:02x}")
            }
            MessageMalformed { kind, reason } => {
                write!(f, "malformed {kind} message: {reason}")
            }
            UnexpectedMessage { expected, found } => {
                write!(f, "unexpected message: expected {expected}, found {found}")
            }
            EmptyRequest => write!(f, "receiver sent an empty REQUEST (protocol violation)"),
            RequestSlotOutOfRange { slot, count } => {
                write!(f, "receiver requested slot {slot} of a {count}-slot manifest")
            }
            DeliveredIdMismatch { expected, found } => write!(
                f,
                "DELIVERED ack names {} but this sender served {}",
                hex(found),
                hex(expected)
            ),
            ManifestInvalid { cause } => write!(f, "OFFER manifest invalid: {cause}"),
            ContentIdMismatch { expected, found } => write!(
                f,
                "offered content {} but this receiver state belongs to {}",
                hex(found),
                hex(expected)
            ),
            SlotIndexOverflow { count } => write!(
                f,
                "manifest has {count} chunks, beyond the u32 slot index space"
            ),
            ChunkSourceCorrupt { slot, cause } => {
                write!(f, "sender chunk {slot} disagrees with its manifest: {cause}")
            }
            ChunkSourceCountMismatch { expected, found } => write!(
                f,
                "sender holds {found} chunks for a {expected}-slot manifest"
            ),
            Stalled { rounds, missing } => write!(
                f,
                "no verified progress for {rounds} consecutive rounds ({missing} slots still missing)"
            ),
            ReassemblyFailed { cause } => write!(f, "final reassembly failed: {cause}"),
            StoreIo { context, source } => write!(f, "receiver store {context}: {source}"),
            StoreCorrupt { detail } => write!(f, "receiver store corrupt: {detail}"),
            BitmapAllocationFailed { words } => {
                write!(f, "slot bitmap of {words} words could not be allocated")
            }
            BitmapEmpty => write!(f, "a slot bitmap needs at least one slot"),
            Interrupted { sent } => {
                write!(f, "transfer interrupted by fault after {sent} chunk deliveries")
            }
        }
    }
}

impl std::error::Error for TransferError {}

/// Lowercase hex (evidence lines + error text).
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Parse 64 hex chars into 32 bytes (binary flags).
pub fn unhex_32(s: &str) -> Option<[u8; CONTENT_ID_LEN]> {
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; CONTENT_ID_LEN];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn machine_names_are_stable_and_snake_case() {
        let cases: Vec<(TransferError, &str)> = vec![
            (TransferError::Closed, "closed"),
            (
                TransferError::FrameTooLarge { found: 5, max: 1 },
                "frame_too_large",
            ),
            (
                TransferError::UnknownMessageType { found: 0xff },
                "unknown_message_type",
            ),
            (
                TransferError::MessageMalformed {
                    kind: "request",
                    reason: "trailing",
                },
                "message_malformed",
            ),
            (
                TransferError::UnexpectedMessage {
                    expected: "offer",
                    found: "chunk",
                },
                "unexpected_message",
            ),
            (TransferError::EmptyRequest, "empty_request"),
            (
                TransferError::RequestSlotOutOfRange { slot: 9, count: 3 },
                "request_slot_out_of_range",
            ),
            (TransferError::ManifestInvalid {
                cause: ContentError::NotAMap,
            }, "manifest_invalid"),
            (TransferError::Stalled { rounds: 3, missing: 2 }, "stalled"),
            (TransferError::Interrupted { sent: 7 }, "interrupted"),
        ];
        for (err, name) in cases {
            assert_eq!(err.name(), name);
        }
    }

    #[test]
    fn hex_round_trip() {
        let bytes = [0u8, 1, 2, 0xab, 0xff];
        assert_eq!(hex(&bytes), "000102abff");
        assert_eq!(unhex_32(&"0".repeat(64)), Some([0u8; 32]));
        assert_eq!(unhex_32("zz"), None);
        assert_eq!(unhex_32(&"0".repeat(63)), None);
        assert_eq!(unhex_32(&"0".repeat(65)), None);
        let all_f = "f".repeat(64);
        assert_eq!(unhex_32(&all_f), Some([0xff; 32]));
    }
}
