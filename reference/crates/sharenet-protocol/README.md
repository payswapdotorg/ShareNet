# sharenet-protocol

ShareNet protocol core (Rust, platform-independent — architecture lock L007).
Wave 1 scope: **R1-002 Canonical CBOR wire foundation** and **R1-001
Identity binding**.

- Every future ShareNet wire object (`Advertisement`, `LinkAuthentication`,
  `RouteProposal`, `RouteAcceptance`, `RouteCommitment`, `Circuit*`,
  `ContributionReceipt`, ... — see `spec/protocol-registry.yaml`) serializes
  through this crate's CBOR profile. There is no second encoder.
- Node identities are created/loaded at node startup through
  `IdentityStore::load_or_create` — the same library API the `sharenet-id`
  binary exercises today and the future ShareNet daemon will call.

## Layout

```text
src/cbor.rs             Canonical CBOR profile v1 (strict encoder/decoder)
src/identity.rs         NodeIdentity, node_id derivation, Ed25519 sign/verify
src/store.rs            Durable identity file store (atomic, 0600, fail-closed)
src/bin/sharenet-id.rs  Production CLI (create/show/verify/sign/verify-signature)
src/hex.rs              Minimal hex helpers
tests/cbor_conformance.rs  RFC 8949 vectors, golden vectors, property tests
tests/cbor_reject.rs       Adversarial rejection suite (typed errors)
tests/identity_adversarial.rs  RFC 8032 vectors, malleability, tamper matrix,
                               zeroization, golden identity vectors
tests/cli_runtime.rs     End-to-end CLI tests (real process, real files)
tests/vectors/*.json     Machine-readable golden vectors for the future
                         cross-language conformance harness (R1-003)
```

## ShareNet Canonical CBOR Profile v1

Value model: `Int (i64 range) | Bytes | Text | Array | Map (keys unique,
canonically sorted) | Bool | Null`.

Wire rules (RFC 8949 core deterministic encoding + ShareNet profile):

- integers: minimal-length encoding only;
- byte strings / text strings / arrays / maps: definite lengths only;
- map keys: unique, sorted by the **bytewise lexicographic order of their
  full canonical encodings** (the length prefix is part of the key encoding:
  text `"b"` (`61 62`) sorts before `"ab"` (`62 61 62`), and integer `0`
  (`00`) sorts before `-1` (`20`));
- text: must be valid UTF-8;
- allowed simple values: `false`, `true`, `null` only;
- forbidden on the wire (decoder rejects with a typed error; the encoder
  cannot produce them): tags (incl. bignums), **all** floats (f16/f32/f64,
  NaN, ±Inf), indefinite lengths, `undefined`, other simple values, trailing
  bytes after a complete top-level item.

Strictness law (tested): for in-profile bytes `B`:
`encode(decode(B)) == B` (byte-stability) and `decode(encode(x)) == x`.

Implementation protections (documented deviations-by-addition, fail-closed):
structural depth limit `cbor::MAX_DEPTH = 256`; declared definite lengths that
exceed the remaining input are rejected before allocation.

### API sketch

```rust
use sharenet_protocol::cbor::{self, MapBuilder, Value};

let value = MapBuilder::new()
    .insert_int(1, Value::Int(1))
    .insert_int(2, Value::Bytes(public_key.to_vec()))
    .build()?;                      // sorted unique keys, typed error on dups
let bytes = cbor::encode(&value)?;  // canonical bytes
let back = cbor::decode(&bytes)?;   // strict: any violation is a typed error
```

`Value::get_by_int(k)` / `get_by_text(k)` give typed lookups for wire objects
with compact integer keys (NodeIdentity uses keys 1..=4).

## Node identity (R1-001)

Wire object (strict v1; unknown keys rejected):

```text
NodeIdentity = {1: scheme_version (uint, =1),
                2: public_key (32-byte bstr),
                3: created_at_unix (uint),
                4: display_name (optional text, <= 64 bytes)}
```

- Algorithm: Ed25519 (RFC 8032) via `ed25519-dalek` (zeroize feature on).
  Verification is **strict**: malleable signatures (e.g. `S' = S + L`) and
  non-canonical scalars are rejected (`verify_strict`).
- `node_id` is **derived, never caller-chosen**:
  `node_id = SHA-256(canonical_cbor({1: scheme_version, 2: public_key}))`
  (32 bytes, lowercase hex for display).
- `display_name` / `created_at_unix` are mutable metadata and are NOT part of
  the derivation — the identity is self-certifying, and editing the name does
  not change the `node_id`.
- Detached signatures over arbitrary payloads: `NodeSigningKey::sign` /
  `LoadedIdentity::sign`, `identity::verify_detached` (raw bytes in/out).
- Secret material: the seed lives only in zeroize-on-drop types; `Debug`
  impls are redacted; no public API returns seed bytes (only the store
  materializes the seed, and only to persist it with 0600).

## Durable identity store

File: `<dir>/node.sharenet-identity` (matches the repo `.gitignore` pattern
`*.sharenet-identity`), strict canonical CBOR:

```text
{1: seed (32-byte bstr), 2: node_identity (NodeIdentity map)}
```

Guarantees:

- **Atomic durable write**: unique temp file created with mode 0600 →
  `fsync(file)` → `rename` → `fsync(parent dir)`. A crash never leaves a
  half-written file under the final name; no temp files remain.
- **Permissions**: exactly `0600` on unix (enforced at creation and after
  write, umask-independent).
- **Fail-closed load**: strict canonical decode, exact structural shape,
  scheme check, 32-byte seed/public key, and a cryptographic cross-check
  (seed-derived public key must equal the recorded public key). Any
  corruption, tampering, seed/object mismatch, or non-0600 permissions is a
  hard error. The store NEVER silently recreates or overwrites; a missing
  file is the only trigger for creation.
- What tampering is/isn't detected: seed or public-key edits fail closed
  (cross-check); scheme/structure edits fail closed; `display_name` /
  `created_at` edits are deliberately undetectable (unbound metadata) and
  leave `node_id` unchanged; replacing the whole file (seed+object
  consistently) is not detectable from the file alone — inherent to local
  storage.

### API

```rust
use sharenet_protocol::store::IdentityStore;

// Daemon startup path:
let (identity, created_new) = IdentityStore::load_or_create(&dir, Some("name"))?;
let node_id = identity.node_id_hex();
let sig = identity.sign(b"payload");
IdentityStore::verify_file(&path)?;   // full re-validation, public data only
```

The directory is injectable (tests use tempdirs).

## `sharenet-id` CLI (production runtime path)

```text
sharenet-id create --dir <DIR> [--name <NAME>]
sharenet-id show --dir <DIR>                     # never prints the seed
sharenet-id verify --dir <DIR>
sharenet-id sign --dir <DIR> --payload <FILE> [--out <FILE>]   # default: <PAYLOAD>.sig
sharenet-id verify-signature --identity-file <FILE> --payload <FILE> --signature <FILE>
```

Exit codes: 0 success, 1 failure (actionable message on stderr), 2 usage
error. Example:

```console
$ sharenet-id create --dir /tmp/nodeA --name nodeA
status: created
node_id: cd17d28a348ee16dc2f64c7f6ed5a951cf52068b68ec1ea57daa86d7f1dbcc78
...
$ sharenet-id sign --dir /tmp/nodeA --payload msg.bin
node_id: cd17d2...
signature_file: msg.bin.sig
$ sharenet-id verify-signature --identity-file /tmp/nodeA/node.sharenet-identity \
      --payload msg.bin --signature msg.bin.sig
signature valid
```

## Vectors (for the R1-003 cross-language harness)

`tests/vectors/cbor_vectors.json` and `tests/vectors/identity_vectors.json`
are machine-readable golden vectors:

- CBOR values are encoded as tagged JSON:
  `{"t":"int","v":1}`, `{"t":"bytes","v":"<hex>"}`, `{"t":"text","v":"..."}`,
  `{"t":"array","v":[...]}`, `{"t":"map","v":[[key,value],...]}`,
  `{"t":"bool","v":true}`, `{"t":"null"}`.
- `encode_cases` test both directions plus byte-stability; `reject_cases`
  carry the expected typed error variant name.
- Identity vectors cover seed → public key, `node_id` derivation, canonical
  wire bytes, and Ed25519 signature acceptance/rejection (including the
  malleable `S + L` case). RFC 8032 §7.1 vectors are included, so other
  language implementations can be validated against the standard directly.
- The files are kept in sync with the Rust case tables by
  `*_vectors_file_is_in_sync` tests; regenerate after changing the tables:

  ```console
  cargo test --test cbor_conformance -- --ignored regenerate_cbor_vectors
  cargo test --test identity_adversarial -- --ignored regenerate_identity_vectors
  ```

## Building and verification

```console
cargo test --workspace                       # unit + adversarial + conformance
cargo run --bin share-id ...                 # (use: cargo run --bin sharenet-id -- ...)
cargo check --target wasm32-unknown-unknown  # L007 platform-independence proof
```

Note on wasm32: `NodeSigningKey::generate()` and the store's creation path
require an OS entropy source and are compiled only for
`not(wasm32-unknown-unknown)` (getrandom cannot compile there). The CBOR and
identity modules — the wire/protocol surface — compile everywhere; on bare
wasm, construct keys with `NodeSigningKey::from_seed` from host-provided
entropy.

Dependencies (runtime): `ed25519-dalek` (+`curve25519-dalek`, `sha2`,
`zeroize`, `rand` on non-bare-wasm). No async runtime, no platform SDKs, no
database, no network stack. `#![forbid(unsafe_code)]` throughout.

## Honest limits

- Zeroization of the third-party `SigningKey`'s internal buffer cannot be
  observed from safe code; the `zeroize` feature (which implements
  `Drop → secret_key.zeroize()`) is enabled and the crate-side wiring
  (`Zeroizing` seed buffers, scrubbed decoded values, redacted `Debug`) is
  tested with a zeroize-aware probe.
- No file locking: concurrent `load_or_create` in one directory may both
  create; last atomic rename wins (one daemon per identity directory is the
  v1 assumption).
- Symlinked identity files are followed; the target's permissions are
  checked.
- The store requires exactly `0600` (more restrictive modes such as `0400`
  are also rejected, with an actionable `chmod 600` message).
