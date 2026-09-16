//! Custody evidence — the R8 contribution-evidence seam.
//!
//! A DTN node that carries bundles for the network is doing verified useful
//! work (architecture §13: "successful DTN custody/delivery" is a primary
//! contribution class), and the store records the LOCAL FACTS of that work:
//! which bundle was received (custody taken), forwarded (custody handed
//! onward, replication counted), or delivered (terminal custody), when, and
//! to/from whom.
//!
//! # What these records are NOT
//!
//! They are **unsigned local facts**. R8-001 owns signatures, receipts and
//! the anti-gaming layer ("Evidence requires authenticated participants and
//! durable replay-safe receipts") — nothing here signs, nothing here
//! authenticates a peer, and nothing here deduplicates a replayed record:
//! the log is append-only and bounded. A `PeerRef` is an OPAQUE byte ref
//! (typically a 32-byte node id, but the store never parses it — the same
//! opacity law as the ADCOS refs). The honest composition: this log is the
//! input R8-001's signed-receipt layer reads; the store never pretends a
//! record proves more than "this node's store recorded this custody event
//! at this caller-supplied time".

use crate::error::DtnError;
use crate::hex;

/// The hard cap on a peer ref (bounded format; `to-whom` stays opaque).
pub const PEER_REF_MAX_BYTES: usize = 64;

/// What happened to a bundle's custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CustodyKind {
    /// Custody taken: this store received the bundle (or a chunk of it)
    /// from the peer.
    Received,
    /// Custody handed onward: this store forwarded the bundle to the peer
    /// (the event `note_forwarded` records — the replication counter's
    /// evidence twin).
    Forwarded,
    /// Terminal custody: the bundle was delivered to its destination via
    /// the peer. The terminal kind — a held bundle with a Delivered record
    /// never forwards again.
    Delivered,
}

impl CustodyKind {
    /// Stable machine name (probe + tests + the R8 seam vocabulary).
    pub fn as_str(&self) -> &'static str {
        match self {
            CustodyKind::Received => "received",
            CustodyKind::Forwarded => "forwarded",
            CustodyKind::Delivered => "delivered",
        }
    }

    /// Parse from the machine name (probe + tests).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "received" => Some(CustodyKind::Received),
            "forwarded" => Some(CustodyKind::Forwarded),
            "delivered" => Some(CustodyKind::Delivered),
            _ => None,
        }
    }

    pub(crate) fn tag(self) -> u8 {
        match self {
            CustodyKind::Received => 0,
            CustodyKind::Forwarded => 1,
            CustodyKind::Delivered => 2,
        }
    }

    pub(crate) fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            0 => Some(CustodyKind::Received),
            1 => Some(CustodyKind::Forwarded),
            2 => Some(CustodyKind::Delivered),
            _ => None,
        }
    }
}

impl std::fmt::Display for CustodyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `to-whom`/`from-whom` of a custody record: an opaque bounded byte
/// ref (never parsed, never interpreted — echoed and persisted only).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerRef(Vec<u8>);

impl PeerRef {
    /// A peer ref of 1..=64 opaque bytes (fail-closed bounds).
    pub fn new(bytes: &[u8]) -> Result<Self, DtnError> {
        if bytes.is_empty() || bytes.len() > PEER_REF_MAX_BYTES {
            return Err(DtnError::PeerRefInvalid { bytes: bytes.len() });
        }
        Ok(PeerRef(bytes.to_vec()))
    }

    /// The opaque bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Lowercase hex (probe + diagnostics).
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

/// One typed custody fact: `kind` happened to `content_id` at `at_unix`
/// with `peer` as the counterparty (opaque).
///
/// `at_unix` is caller-supplied (no wall clock in this crate, by law).
/// Records are append-only; the same event recorded twice is two records
/// (deduplication/authentication is R8-001's layer, not this log's).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustodyRecord {
    kind: CustodyKind,
    content_id: [u8; crate::CONTENT_ID_LEN],
    at_unix: u64,
    peer: PeerRef,
}

impl CustodyRecord {
    /// Build a custody record (validates the peer bounds).
    pub fn new(
        kind: CustodyKind,
        content_id: [u8; crate::CONTENT_ID_LEN],
        at_unix: u64,
        peer: &PeerRef,
    ) -> Self {
        CustodyRecord {
            kind,
            content_id,
            at_unix,
            peer: peer.clone(),
        }
    }

    /// Custody taken from `peer`.
    pub fn received(
        content_id: [u8; crate::CONTENT_ID_LEN],
        at_unix: u64,
        peer: &PeerRef,
    ) -> Self {
        Self::new(CustodyKind::Received, content_id, at_unix, peer)
    }

    /// Custody handed onward to `peer`.
    pub fn forwarded(
        content_id: [u8; crate::CONTENT_ID_LEN],
        at_unix: u64,
        peer: &PeerRef,
    ) -> Self {
        Self::new(CustodyKind::Forwarded, content_id, at_unix, peer)
    }

    /// Terminal custody via `peer`.
    pub fn delivered(
        content_id: [u8; crate::CONTENT_ID_LEN],
        at_unix: u64,
        peer: &PeerRef,
    ) -> Self {
        Self::new(CustodyKind::Delivered, content_id, at_unix, peer)
    }

    /// What happened.
    pub fn kind(&self) -> CustodyKind {
        self.kind
    }

    /// The bundle the record is about.
    pub fn content_id(&self) -> &[u8; crate::CONTENT_ID_LEN] {
        &self.content_id
    }

    /// When (caller-supplied clock).
    pub fn at_unix(&self) -> u64 {
        self.at_unix
    }

    /// The counterparty (opaque).
    pub fn peer(&self) -> &PeerRef {
        &self.peer
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_ref_bounds_are_fail_closed() {
        assert!(PeerRef::new(&[7u8; 1]).is_ok());
        assert!(PeerRef::new(&[7u8; 64]).is_ok());
        assert_eq!(
            PeerRef::new(&[]),
            Err(DtnError::PeerRefInvalid { bytes: 0 })
        );
        assert_eq!(
            PeerRef::new(&[7u8; 65]),
            Err(DtnError::PeerRefInvalid { bytes: 65 })
        );
        let p = PeerRef::new(&[0xab, 0xcd]).unwrap();
        assert_eq!(p.as_bytes(), &[0xab, 0xcd]);
        assert_eq!(p.to_hex(), "abcd");
    }

    #[test]
    fn custody_kinds_round_trip_names_and_tags() {
        for k in [CustodyKind::Received, CustodyKind::Forwarded, CustodyKind::Delivered] {
            assert_eq!(CustodyKind::from_name(k.as_str()), Some(k));
            assert_eq!(CustodyKind::from_tag(k.tag()), Some(k));
        }
        assert_eq!(CustodyKind::from_name("vanished"), None);
        assert_eq!(CustodyKind::from_tag(3), None);
        assert_eq!(CustodyKind::from_tag(255), None);
    }

    #[test]
    fn record_constructors_are_the_typed_kinds() {
        let id = [9u8; 32];
        let peer = PeerRef::new(&[1, 2, 3]).unwrap();
        let r = CustodyRecord::received(id, 100, &peer);
        assert_eq!(r.kind(), CustodyKind::Received);
        assert_eq!(r.content_id(), &id);
        assert_eq!(r.at_unix(), 100);
        assert_eq!(r.peer(), &peer);
        assert_eq!(
            CustodyRecord::forwarded(id, 101, &peer).kind(),
            CustodyKind::Forwarded
        );
        assert_eq!(
            CustodyRecord::delivered(id, 102, &peer).kind(),
            CustodyKind::Delivered
        );
        // Plain data: clone-equal, no hidden state.
        assert_eq!(r.clone(), r);
    }
}
