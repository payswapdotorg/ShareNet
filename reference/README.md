# ShareNet reference/ — protocol core home

This directory is the ShareNet protocol core (`AGENTS.md`: protocol authority, platform- and
database-independent Rust). Wave 1 foundation: `crates/sharenet-protocol` implements work items
R1-002 (canonical CBOR wire profile v1 — the single serialization path every future ShareNet wire
object must use) and R1-001 (Ed25519 node-identity binding with derived `node_id`, durable
fail-closed identity store, and the `sharenet-id` CLI runtime). Build with `cargo test
--workspace` inside this directory; see `crates/sharenet-protocol/README.md` for the wire
profile, API, persistence and security guarantees.
