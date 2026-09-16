//! The transfer session's runtime control protocol — the message set.
//!
//! Like the Linux gateway's tunnel control protocol (R4-003), this is a
//! DOCUMENTED RUNTIME CONTROL PROTOCOL, not a registry wire object: it
//! rides INSIDE an established carrying stream ([`crate::TransferStream`]
//! — TCP here, a QUIC `TunnelStream` or DTN pipe at integration) and its
//! only trust authority is the R6-001 `ContentManifest` carried in the
//! OFFER (the registry's wire object, `content_id`-committed).
//!
//! Every frame is `[type byte][payload]`, all multi-byte integers
//! big-endian:
//!
//! | byte | message | direction | payload | meaning |
//! |---|---|---|---|---|
//! | 0x01 | OFFER | S→R | manifest canonical CBOR bytes | the manifest advertisement: the object on offer, committed by `content_id` |
//! | 0x02 | REQUEST | R→S | u32 n + n × u32 slot | the receiver's missing slots (its bitmap complement); n ≥ 1 |
//! | 0x03 | CHUNK | S→R | u32 slot + chunk bytes | one chunk, accepted only after per-slot verification against the manifest |
//! | 0x04 | COMPLETE | S→R | content_id (32 bytes) | the sender's batch terminator and completion HINT — never evidence; the receiver verifies |
//! | 0x05 | DELIVERED | R→S | content_id (32 bytes) | the receiver's ack of a DERIVED fact (full coverage + successful reassemble); not future custody evidence |
//!
//! A transfer is: OFFER → rounds of (REQUEST → CHUNK… → COMPLETE) → the
//! receiver derives completion locally → DELIVERED. Decode is strict
//! SYNTAX only (exact payload shapes, no trailing bytes); SEMANTICS
//! (slot ranges, lengths, hashes, completion) belong to the session.

use crate::error::TransferError;
use crate::frame::TRANSFER_MAX_FRAME;

/// OFFER: the manifest advertisement (S→R).
pub const MSG_OFFER: u8 = 0x01;
/// REQUEST: the receiver's missing-slot list (R→S).
pub const MSG_REQUEST: u8 = 0x02;
/// CHUNK: one chunk delivery (S→R).
pub const MSG_CHUNK: u8 = 0x03;
/// COMPLETE: the sender's batch terminator / completion hint (S→R).
pub const MSG_COMPLETE: u8 = 0x04;
/// DELIVERED: the receiver's derived-proof ack (R→S).
pub const MSG_DELIVERED: u8 = 0x05;

/// One control-protocol message (the decoded form of one frame).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// The manifest advertisement: the exact canonical CBOR bytes of a
    /// `ContentManifest` (re-parsed strictly by the receiver — R6-001's
    /// invariants, plus the u32 slot-space bound).
    Offer(Vec<u8>),
    /// Request exactly these slots (ascending, the bitmap complement).
    Request(Vec<u32>),
    /// A chunk delivery for `slot` (accepted only after verification).
    Chunk { slot: u32, data: Vec<u8> },
    /// The sender's batch terminator + completion hint, bound to the
    /// offered object.
    Complete { content_id: [u8; 32] },
    /// The receiver's proof-of-delivery ack (sent only after the local
    /// derivation of completion).
    Delivered { content_id: [u8; 32] },
}

impl Message {
    /// Stable human/machine name (evidence lines, errors).
    pub fn kind(&self) -> &'static str {
        match self {
            Message::Offer(_) => "offer",
            Message::Request(_) => "request",
            Message::Chunk { .. } => "chunk",
            Message::Complete { .. } => "complete",
            Message::Delivered { .. } => "delivered",
        }
    }

    /// Encode into one frame (type byte + payload).
    pub fn encode(&self) -> Vec<u8> {
        let mut frame = Vec::with_capacity(64);
        match self {
            Message::Offer(bytes) => {
                frame.push(MSG_OFFER);
                frame.extend_from_slice(bytes);
            }
            Message::Request(slots) => {
                frame.push(MSG_REQUEST);
                frame.extend_from_slice(&(slots.len() as u32).to_be_bytes());
                for slot in slots {
                    frame.extend_from_slice(&slot.to_be_bytes());
                }
            }
            Message::Chunk { slot, data } => {
                frame.push(MSG_CHUNK);
                frame.extend_from_slice(&slot.to_be_bytes());
                frame.extend_from_slice(data);
            }
            Message::Complete { content_id } | Message::Delivered { content_id } => {
                frame.push(match self {
                    Message::Complete { .. } => MSG_COMPLETE,
                    _ => MSG_DELIVERED,
                });
                frame.extend_from_slice(content_id);
            }
        }
        frame
    }

    /// Strict decode of one frame: unknown types, wrong payload shapes
    /// and trailing bytes are refused typed (semantics live in the
    /// session — decode accepts structurally valid slot indices and
    /// chunk lengths it cannot judge).
    pub fn decode(frame: &[u8]) -> Result<Self, TransferError> {
        let Some((&kind, payload)) = frame.split_first() else {
            return Err(TransferError::MessageMalformed {
                kind: "frame",
                reason: "empty frame",
            });
        };
        match kind {
            MSG_OFFER => {
                if payload.is_empty() {
                    return Err(TransferError::MessageMalformed {
                        kind: "offer",
                        reason: "empty manifest payload",
                    });
                }
                Ok(Message::Offer(payload.to_vec()))
            }
            MSG_REQUEST => {
                if payload.len() < 4 {
                    return Err(TransferError::MessageMalformed {
                        kind: "request",
                        reason: "missing slot count",
                    });
                }
                let count =
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as usize;
                let rest = &payload[4..];
                if rest.len() != count * 4 {
                    return Err(TransferError::MessageMalformed {
                        kind: "request",
                        reason: "slot count disagrees with payload length",
                    });
                }
                let mut slots = Vec::with_capacity(count);
                for i in 0..count {
                    let b = &rest[i * 4..i * 4 + 4];
                    slots.push(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
                }
                Ok(Message::Request(slots))
            }
            MSG_CHUNK => {
                if payload.len() < 5 {
                    return Err(TransferError::MessageMalformed {
                        kind: "chunk",
                        reason: "missing slot index or chunk bytes",
                    });
                }
                let slot = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                Ok(Message::Chunk {
                    slot,
                    data: payload[4..].to_vec(),
                })
            }
            MSG_COMPLETE | MSG_DELIVERED => {
                let name = if kind == MSG_COMPLETE {
                    "complete"
                } else {
                    "delivered"
                };
                if payload.len() != 32 {
                    return Err(TransferError::MessageMalformed {
                        kind: name,
                        reason: "content id must be exactly 32 bytes",
                    });
                }
                let mut content_id = [0u8; 32];
                content_id.copy_from_slice(payload);
                if kind == MSG_COMPLETE {
                    Ok(Message::Complete { content_id })
                } else {
                    Ok(Message::Delivered { content_id })
                }
            }
            found => Err(TransferError::UnknownMessageType { found }),
        }
    }

    /// True if this message may lawfully carry a full-size chunk (the
    /// sender's send-side frame sanity check).
    pub fn encoded_len(&self) -> usize {
        self.encode().len()
    }

    /// The frame-cap law for this message (send side).
    pub fn fits_frame_cap(&self) -> bool {
        self.encoded_len() <= TRANSFER_MAX_FRAME
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_every_message_kind() {
        let cases = vec![
            Message::Offer(vec![0xA5, 0x01, 0x02]),
            Message::Request(vec![]),
            Message::Request(vec![0, 1, u32::MAX, 7]),
            Message::Chunk {
                slot: 42,
                data: b"chunk bytes".to_vec(),
            },
            Message::Chunk {
                slot: 0,
                data: vec![1u8; 4096],
            },
            Message::Complete { content_id: [0xAB; 32] },
            Message::Delivered { content_id: [0x01; 32] },
        ];
        for msg in cases {
            let frame = msg.encode();
            assert!(msg.fits_frame_cap());
            let back = Message::decode(&frame).expect("decode");
            assert_eq!(back, msg, "round trip of {:?}", msg.kind());
        }
    }

    #[test]
    fn empty_frame_refused() {
        let err = Message::decode(&[]).unwrap_err();
        assert!(matches!(err, TransferError::MessageMalformed { .. }));
        assert_eq!(err.name(), "message_malformed");
    }

    #[test]
    fn unknown_type_byte_refused() {
        for bad in [0x00u8, 0x06, 0x7F, 0xFF] {
            let err = Message::decode(&[bad, 0x00]).unwrap_err();
            assert!(matches!(err, TransferError::UnknownMessageType { found } if found == bad));
            assert_eq!(err.name(), "unknown_message_type");
        }
    }

    #[test]
    fn request_count_lies_refused() {
        // Count says 3, payload holds 2 slots.
        let mut frame = vec![MSG_REQUEST];
        frame.extend_from_slice(&3u32.to_be_bytes());
        frame.extend_from_slice(&1u32.to_be_bytes());
        frame.extend_from_slice(&2u32.to_be_bytes());
        let err = Message::decode(&frame).unwrap_err();
        assert!(matches!(err, TransferError::MessageMalformed { kind: "request", .. }));

        // Truncated before the count.
        let err = Message::decode(&[MSG_REQUEST, 0, 0]).unwrap_err();
        assert!(matches!(err, TransferError::MessageMalformed { kind: "request", .. }));

        // Payload not slot-aligned.
        let err = Message::decode(&[MSG_REQUEST, 0, 0, 0, 1, 0xAA]).unwrap_err();
        assert!(matches!(err, TransferError::MessageMalformed { kind: "request", .. }));
    }

    #[test]
    fn chunk_needs_five_payload_bytes() {
        let err = Message::decode(&[MSG_CHUNK, 0, 0, 0, 1]).unwrap_err();
        assert!(matches!(err, TransferError::MessageMalformed { kind: "chunk", .. }));
        assert!(Message::decode(&[MSG_CHUNK, 0, 0, 0, 1, 0xFF]).is_ok());
    }

    #[test]
    fn offer_empty_payload_refused() {
        let err = Message::decode(&[MSG_OFFER]).unwrap_err();
        assert!(matches!(err, TransferError::MessageMalformed { kind: "offer", .. }));
    }

    #[test]
    fn content_id_messages_need_exactly_32_bytes() {
        for kind in [MSG_COMPLETE, MSG_DELIVERED] {
            let short = {
                let mut f = vec![kind];
                f.extend_from_slice(&[0u8; 31]);
                f
            };
            let err = Message::decode(&short).unwrap_err();
            assert!(matches!(err, TransferError::MessageMalformed { .. }));
            let long = {
                let mut f = vec![kind];
                f.extend_from_slice(&[0u8; 33]);
                f
            };
            assert!(Message::decode(&long).is_err());
            let exact = {
                let mut f = vec![kind];
                f.extend_from_slice(&[0u8; 32]);
                f
            };
            assert!(Message::decode(&exact).is_ok());
        }
    }

    #[test]
    fn wire_shapes_are_pinned() {
        // Golden shapes: the protocol table as bytes.
        assert_eq!(
            Message::Request(vec![1, 2]).encode(),
            vec![MSG_REQUEST, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 2]
        );
        assert_eq!(
            Message::Chunk {
                slot: 7,
                data: vec![0xEE]
            }
            .encode(),
            vec![MSG_CHUNK, 0, 0, 0, 7, 0xEE]
        );
        assert_eq!(
            Message::Complete { content_id: [0x09; 32] }.encode(),
            {
                let mut f = vec![MSG_COMPLETE];
                f.extend_from_slice(&[0x09; 32]);
                f
            }
        );
        assert_eq!(
            Message::Delivered { content_id: [0x0D; 32] }.encode(),
            {
                let mut f = vec![MSG_DELIVERED];
                f.extend_from_slice(&[0x0D; 32]);
                f
            }
        );
        assert_eq!(MSG_OFFER, 0x01);
        assert_eq!(MSG_REQUEST, 0x02);
        assert_eq!(MSG_CHUNK, 0x03);
        assert_eq!(MSG_COMPLETE, 0x04);
        assert_eq!(MSG_DELIVERED, 0x05);
    }

    #[test]
    fn kind_names_are_stable() {
        assert_eq!(Message::Offer(vec![1]).kind(), "offer");
        assert_eq!(Message::Request(vec![]).kind(), "request");
        assert_eq!(Message::Chunk { slot: 0, data: vec![] }.kind(), "chunk");
        assert_eq!(Message::Complete { content_id: [0; 32] }.kind(), "complete");
        assert_eq!(Message::Delivered { content_id: [0; 32] }.kind(), "delivered");
    }
}
