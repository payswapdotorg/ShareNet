"""ShareNet conformance package — Python leg of the R1-003 harness.

Independent reimplementation of the ShareNet Canonical CBOR Profile v1
(R1-002), node identity binding (R1-001) and signed capability statements
(R1-004), pinned against the committed vectors in
``reference/crates/sharenet-protocol/tests/vectors/``.

The three language legs (Rust, TypeScript, Python) must emit byte-identical
conformance lines; ``run_harness.sh`` diffs them.
"""
