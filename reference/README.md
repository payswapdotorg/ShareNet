# ShareNet `reference/` — Protocol Core

This directory is ShareNet's protocol authority: the platform- and
database-independent Rust core that owns identity, canonical wire formats and
all normative protocol semantics (architecture lock L007). Wave 1 provides
the canonical CBOR wire foundation (R1-002) and the cryptographic node
identity binding with its durable store and `sharenet-id` CLI (R1-001); every
future wire object registered in `spec/protocol-registry.yaml` serializes
through this core. See `crates/sharenet-protocol/README.md` for the API,
wire profile, persistence and security guarantees.
