//! Shared helpers for the R8-002 adversarial suite.

use sharenet_protocol::contribution::ContributionKind;
use sharenet_protocol::contribution::ContributionReceipt;
use sharenet_protocol::identity::Identity;

pub const NOW: u64 = 1_700_000_000;

/// A deterministic identity from a seed byte pattern.
pub fn id(seed: u8) -> Identity {
    Identity::from_seed([seed; 32], NOW, None).expect("identity")
}

/// The zero-pattern identity (0x00 seed).
pub fn id0() -> Identity {
    Identity::from_seed([0x00; 32], NOW, None).expect("identity")
}

/// A well-formed receipt (the receipt-layer laws respected: seq >= 1,
/// bytes >= 1, issued_at is the issuer's claim).
pub fn receipt(
    issuer: &Identity,
    contributor: &[u8; 32],
    kind: ContributionKind,
    bytes: u64,
    seq: u64,
    issued_at: u64,
) -> ContributionReceipt {
    ContributionReceipt::new(issuer, *contributor, [0x5C; 32], kind, bytes, seq, issued_at)
        .expect("receipt builds")
}
