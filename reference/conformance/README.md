# ShareNet Cross-Language Conformance Suite (R1-003)

This directory pins the ShareNet wire formats across three independent
implementations (architecture lock L022: every normative wire object appears
in the protocol registry and the cross-language conformance suite).

## What it proves

For every committed vector in
[`../crates/sharenet-protocol/tests/vectors/`](../crates/sharenet-protocol/tests/vectors/):

- **Canonical CBOR profile v1** (R1-002): 45 roundtrip cases decode to the
  recorded value and re-encode to the exact bytes; 57 reject cases fail with
  the exact same typed error name in all three languages.
- **NodeIdentity** (R1-001): public keys derive identically from seeds;
  `node_id = SHA-256(canonical_cbor({1: scheme_version, 2: public_key}))`
  matches byte-for-byte; the NodeIdentity wire map encodes identically;
  signatures verify and re-sign deterministically to the same bytes.
- **CapabilityStatement** (R1-004): statements rebuild to the exact wire
  bytes; Ed25519 signatures reproduce byte-exactly; admission outcomes
  (parse + binding + signature + time window + capability lookup) agree on
  every case; malformed statements fail with identical typed errors.
- **SignedConnectivityObservation** (R5-004): observation statements
  rebuild to the exact wire bytes (all six adcos.md event kinds, the
  optional execution counter map, cross-contract and cross-provider
  sequence namespaces); Ed25519 provider signatures and the canonical
  carrying envelope reproduce byte-exactly; the admission outcomes
  (signature, known-contract rule, monotonic sequence gate, freshness
  edges; tampered and foreign signatures) agree on every receive case,
  checked against the vector's pinned `expect` in all three legs.
- **ContentManifest** (R6-001): manifests rebuild to the exact wire
  bytes from the content inputs (multi-chunk, single-chunk,
  exact-boundary, metadata-carrying) with matching content_id =
  SHA-256(canonical bytes) and chunk-hash lists; the reassembly
  discipline agrees on every outcome (valid, swap, corrupt, drop,
  extra, short, duplicate — each slot-indexed) in all three legs,
  checked against the vector's pinned `expect`.
- **ContributionReceipt** (R8-001): receipts rebuild to the exact wire
  bytes (both frozen kinds — carried/delivered — cross-contributor and
  cross-issuer sequence namespaces, future-dating); the issuer's Ed25519
  signature, the canonical carrying envelope and the commitment-derived
  receipt_id = SHA-256(receipt bytes) reproduce byte-exactly; the ledger
  admission outcomes (signature, future clock, receipt_id idempotency,
  the per-(issuer, contributor) monotonic sequence law; tampered and
  foreign signatures) agree on every admit case through ONE shared
  ledger replayed in vector order, checked against the pinned `expect`
  in all three legs.

The strict statement/envelope PARSE rejections are enforced by the Rust
leg (the protocol core — the authority); the TypeScript and Python legs
pin the encoder and the admission taxonomy for those cases (the same
scope split as the earlier object families).

## Legs

| Leg | Runtime | Entry point |
|---|---|---|
| Rust | cargo (the protocol core itself) | `crates/sharenet-conformance` |
| TypeScript | bun (node:crypto Ed25519) | `typescript/runner.ts` |
| Python | python3 ≥ 3.10 (stdlib only; pure-Python RFC 8032) | `python/sharenet_conformance/runner.py` |

Each leg re-derives every value from the vector INPUTS (seeds, fields) —
never copies the expected outputs — and prints canonical lines:

```
CBOR_RT  <idx> <re-encoded hex>
CBOR_REJ <idx> <DecodeError name>
IDENT    <idx> pk=<hex> id=<hex> wire=<hex> sig=ok
CAP      <idx> pk=<hex> id=<hex> wire=<hex> sig=<signature hex>
ADMIT    <idx> now=<unix> require=<csv> <"ok" | AdmissionError name>
CAP_REJ  <idx> <CapabilityError name>
CONN_OBS       <idx> wire=<hex> sig=<hex> env=<hex>
CONN_OBS_RECV  <idx> now=<unix> <"admitted" | "sequence_stale" | error name>
CONN_OBS_REJ   <idx> <ConnectivityEvidenceError name>
CONN_OBS_ENV_REJ <idx> <ConnectivityEvidenceError name>
CONTENT        <idx> wire=<hex> id=<hex> chunks=<csv of chunk hash hex>
CONTENT_REASM  <idx> <"ok" | "<error name> slot=<n>">
CONTENT_REJ    <idx> <ContentError name>
CONTRIB         <idx> wire=<hex> sig=<hex> env=<hex> id=<hex>
CONTRIB_ADMIT   <idx> now=<unix> <"admitted" | "duplicate" | error name>
CONTRIB_REJ     <idx> <ReceiptError name>
CONTRIB_ENV_REJ <idx> <ReceiptError name>
```

(The full line vocabulary spans every registered wire-object family with
committed vectors — CBOR, identity, capability, link, advertisement,
topology, route, circuit, connectivity evidence, content, contribution —
see the runner sources for the exact formats.)

## Running

```sh
reference/conformance/run_harness.sh
```

PASS means all three outputs are byte-identical and every in-language check
succeeded.

## Scope notes (honest limitations)

- The TypeScript and Python legs are CONFORMANCE implementations, not the
  cryptographic authority. The Rust protocol core (`reference/crates/
  sharenet-protocol`) remains the single source of truth for production
  signing and strict verification (including rejection of malleable
  signature forms, which node:crypto/OpenSSL and this pure-Python verifier
  do not enforce to the same strictness).
- The Python Ed25519 implementation is deliberately not constant-time and
  must not be used for production key operations. (R5-004 note: its
  `verify` is total — an off-curve signature point decodes to `False`,
  not an exception; found by the tampered-signature vectors.)
- The vector files are generated by the Rust core
  (`cargo test -p sharenet-protocol --test test_vectors -- --ignored`) and
  committed; regeneration is a conscious, reviewed act. EXCEPTION: the
  R5-004 connectivity evidence vectors are generated by
  `gen_connectivity_vectors.py` (the Python conformance modules — the
  same three legs then re-derive them, so the pinning is identical).
  If any leg drifts, the harness fails and the drift must be resolved
  (implementation bug or conscious profile change + vector regeneration)
  before merging.
