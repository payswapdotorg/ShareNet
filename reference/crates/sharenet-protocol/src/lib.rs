//! ShareNet protocol core — Wave 1 foundation, part 1 (work item R1-002).
//!
//! This crate is the protocol core's implementation home. Per `AGENTS.md` and
//! architecture lock L007 it is platform-independent Rust with no database and no
//! OS integration; it compiles for `wasm32-unknown-unknown`
//! (`cargo check --target wasm32-unknown-unknown`) to prove that independence.
//!
//! # Modules
//!
//! - [`cbor`]: ShareNet Canonical CBOR Profile v1 (R1-002). This is the ONE wire
//!   serialization path for the protocol: every future normative wire object in
//!   `spec/protocol-registry.yaml` (NodeIdentity, Advertisement, LinkAuthentication,
//!   RouteProposal, RouteAcceptance, RouteCommitment, Circuit*, Contribution*) MUST
//!   serialize through `cbor::encode` and parse through `cbor::decode`, so the whole
//!   network shares one canonical byte image per object.
//!
//! Identity binding and the durable identity store (R1-001) follow in the next
//! commit of this branch.

#![forbid(unsafe_code)]

pub mod cbor;

pub use cbor::{decode, encode, DecodeError, EncodeError, Value};

#[cfg(test)]
pub(crate) mod testutil {
    /// Lowercase hex decoding for tests and vectors.
    pub fn from_hex(s: &str) -> Vec<u8> {
        let s = s.trim();
        assert!(s.len() % 2 == 0, "odd-length hex string");
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let nib = |c: u8| -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("invalid hex digit"),
            }
        };
        for pair in bytes.chunks(2) {
            out.push((nib(pair[0]) << 4) | nib(pair[1]));
        }
        out
    }
}
