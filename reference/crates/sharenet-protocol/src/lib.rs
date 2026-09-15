//! # sharenet-protocol
//!
//! ShareNet's platform-independent protocol core (Rust; architecture lock
//! L007). This crate owns the canonical wire encoding and the cryptographic
//! node identity for Wave 1 (work items R1-002 and R1-001).
//!
//! ## Who calls this crate (production callers)
//!
//! - **Every future ShareNet wire object** — `Advertisement`,
//!   `LinkAuthentication`, `RouteProposal`, `RouteAcceptance`,
//!   `RouteCommitment`, `CircuitSetup`, `ContributionReceipt`, ... as
//!   registered in `spec/protocol-registry.yaml` — serializes through the
//!   canonical CBOR profile in [`cbor`]. There is no second encoder; this
//!   module is the single wire authority.
//! - **Node startup**: the `sharenet-id` binary (and, later, the ShareNet
//!   daemon at node startup) creates/loads the node identity through
//!   [`store::IdentityStore::load_or_create`] — the exact same library API.
//! - Detached signing/verification of arbitrary payloads flows through
//!   [`identity::verify_detached`] and
//!   [`store::LoadedIdentity::sign`].
//!
//! ## Modules
//!
//! - [`cbor`]: ShareNet Canonical CBOR Profile v1 (strict encoder/decoder,
//!   byte-stable, typed rejection of every out-of-profile input).
//! - [`identity`]: `NodeIdentity` wire object, derived `node_id`
//!   (SHA-256 over canonical CBOR of scheme+public key), Ed25519
//!   sign/verify with strict verification and zeroized secret keys.
//! - [`store`]: durable identity file store — atomic writes, 0600
//!   permissions, fail-closed loads.
//! - [`hex`]: minimal hex helpers.
//!
//! ## Platform independence
//!
//! No platform, OS, database or network dependencies. The only I/O is plain
//! `std::fs` in [`store`]. The crate compiles for `wasm32-unknown-unknown`
//! (checked as the L007 architecture proof) — on targets without a real
//! filesystem the store simply cannot be used, while `cbor`/`identity`
//! remain fully functional.
//!
//! ## Security posture (summary)
//!
//! - `node_id` is always **derived**, never caller-chosen.
//! - Identity loads **fail closed** on corruption, tampering, seed/object
//!   mismatch, or insecure permissions.
//! - Secret key material lives only in zeroize-on-drop types; `Debug`
//!   output is redacted; no public API returns the seed.
//! - Signature verification is strict (malleable/non-canonical signatures
//!   are rejected).

#![forbid(unsafe_code)]

pub mod cbor;
pub mod hex;
pub mod identity;
pub mod store;
