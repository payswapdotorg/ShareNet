//! ShareNet protocol core — Rust implementation of the Wave 1 foundations
//! (work items R1-001 identity binding and R1-002 canonical CBOR wire).
//!
//! This crate is the protocol core's implementation home. Per `AGENTS.md` and
//! architecture lock L007 it is platform-independent Rust with no database and no
//! OS integration beyond the file I/O of the durable identity store; it compiles
//! for `wasm32-unknown-unknown` (`cargo check --target wasm32-unknown-unknown`)
//! to prove that independence.
//!
//! # Modules
//!
//! - [`cbor`]: ShareNet Canonical CBOR Profile v1 (R1-002). This is the ONE wire
//!   serialization path for the protocol: every future normative wire object in
//!   `spec/protocol-registry.yaml` (Advertisement, LinkAuthentication, RouteProposal,
//!   RouteAcceptance, RouteCommitment, Circuit*, Contribution*) MUST serialize through
//!   `cbor::encode` and parse through `cbor::decode`, so the whole network shares one
//!   canonical byte image per object.
//! - [`identity`]: the self-certifying node identity (R1-001): Ed25519 keys, the
//!   NodeIdentity wire object, the derived `node_id`, and strict detached signatures.
//! - [`store`]: the durable, atomic, fail-closed identity file store.
//!
//! # Expected production callers
//!
//! - Today: the `sharenet-id` binary (create/show/verify/sign/verify-signature) — a real
//!   process performing real file I/O through the [`store::IdentityStore`] API.
//! - Next: the future ShareNet daemon, which will create/load the node identity at
//!   startup by calling `IdentityStore::load_or_create` — the same API — and every wire
//!   object it sends or receives will be serialized through this CBOR profile.
//! - The cross-language conformance harness (R1-003) consumes the JSON vectors under
//!   `tests/vectors/`.

#![forbid(unsafe_code)]

pub mod advertisement;
pub mod cbor;
pub mod capability;
pub mod circuit;
pub mod identity;
pub mod link;
pub mod route;
pub mod store;
pub mod topology;

pub use advertisement::{
    Advertisement, AdvertisementError, DiscoveryCache, DiscoveryOutcome, SignedAdvertisement,
    TransportDescriptor, AD_MAX_ENDPOINT_BYTES, AD_MAX_TRANSPORTS, AD_MAX_WINDOW,
    AD_TRANSPORT_KINDS, AD_SCHEME_VERSION,
};
pub use cbor::{decode, encode, DecodeError, EncodeError, Value};
pub use capability::{
    admit, Admitted, AdmissionError, Capability, CapabilityError, CapabilityStatement,
    SignedCapabilityStatement, CAP_SCHEME_VERSION, MAX_LIMITS_ENTRIES, MAX_LIMIT_KEY_BYTES,
};
pub use circuit::{
    derive_circuit_id, setup_digest, AckOutcome, CircuitDestroy, CircuitError, CircuitFrame,
    CircuitRegistry, CircuitSetup, CircuitSetupAck, CIRCUIT_MAX_PAYLOAD, CIRCUIT_MAX_PATH,
    CIRCUIT_MAX_WINDOW, CIRCUIT_SCHEME_VERSION, DESTROY_REASONS, DIRECTION_EXIT_TO_INITIATOR,
    DIRECTION_INITIATOR_TO_EXIT,
};
pub use route::{
    derive_proposal_id, derive_route_id, merkle_root, RouteAcceptance, RouteCommitment,
    RouteError, RouteProposal, SignedEnvelope, VerifiedRoute, ROUTE_MAX_PATH, ROUTE_MAX_WINDOW,
    ROUTE_SCHEME_VERSION, SERVICE_CLASSES,
};
pub use topology::{
    BilateralLink, LinkQualitySnapshot, Observation, ReceiveOutcome, SignedTopologyEvidence,
    TopologyError, TopologyEvidence, TopologyStore, EVIDENCE_MAX_WINDOW,
    EVIDENCE_SCHEME_VERSION, LOSS_RATIO_PPM_MAX,
};
pub use link::{
    LinkConfirm, LinkError, LinkInitiate, LinkInitiator, LinkRespond, LinkResponder,
    LinkResponderPending, LinkSession, LinkTransport, EPHEMERAL_LEN, LINK_ID_LEN,
    LINK_SCHEME_VERSION, NONCE_LEN, REPLAY_WINDOW, SESSION_KEY_LEN,
};
pub use identity::{
    derive_node_id, Identity, IdentityError, NodeId, NodeIdentity, VerifyError,
    MAX_DISPLAY_NAME_BYTES, NODE_ID_LEN, PUBLIC_KEY_LEN, SCHEME_VERSION, SEED_LEN, SIGNATURE_LEN,
};
pub use store::{load_identity_file, IdentityStore, StoreError, IDENTITY_FILE_NAME};

#[cfg(test)]
pub(crate) mod testutil {
    /// Lowercase hex decoding for tests and vectors.
    pub fn from_hex(s: &str) -> Vec<u8> {
        let s = s.trim();
        assert!(s.len().is_multiple_of(2), "odd-length hex string");
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
