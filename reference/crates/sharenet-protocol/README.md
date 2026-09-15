# sharenet-protocol — ShareNet protocol core (Wave 1: R1-001 + R1-002)

ShareNet's mission is **resilient Internet bridging**: people who have Internet access
bridge it to people who do not. This crate is the protocol core's implementation home
(`AGENTS.md`: protocol authority, platform- and database-independent). It provides the
two Wave 1 foundations:

- **R1-002 — ShareNet Canonical CBOR Profile v1**: the ONE wire serialization path.
  Every future normative wire object in `spec/protocol-registry.yaml` (Advertisement,
  LinkAuthentication, RouteProposal, RouteAcceptance, RouteCommitment, Circuit*,
  Contribution*) MUST serialize through `cbor::encode` and parse through `cbor::decode`.
- **R1-001 — Identity binding**: the self-certifying Ed25519 node identity, the derived
  `node_id`, strict detached signatures, and the durable fail-closed identity store with
  the `sharenet-id` CLI as its real runtime path.

Platform independence is proven by `cargo check --target wasm32-unknown-unknown`
(architecture lock L007). No databases, no platform SDKs, no `unsafe` (the crate is
`#![forbid(unsafe_code)]`).

## Canonical CBOR Profile v1 (normative)

**Value model** (the only things that exist on the wire): `Int` (i64 range), `Bytes`,
`Text` (UTF-8), `Array`, `Map` (unique keys, canonically sorted), `Bool`, `Null`.

**Encoding rules** (RFC 8949 core deterministic encoding, restricted):

- integers (including lengths): minimal-length encoding only;
- strings/arrays/maps: definite lengths only;
- map keys: sorted by **bytewise lexicographic order of their canonical encodings**,
  duplicates forbidden. (Bytewise comparison of the full key encodings is the ShareNet
  rule. It coincides with RFC 8949 §4.2.1's "shorter key first, then bytewise" whenever
  key encodings have equal length; the rules differ only for mixed-length key pairs
  such as `24` vs `-1`. All ShareNet objects use small unsigned integer keys where both
  rules agree. The choice is pinned by the exported vectors.)
- text must be valid UTF-8;
- allowed simple values: `false`/`true`/`null` only, in their single-byte forms.

**Forbidden on the wire** (encoder errors, decoder rejects with a typed error naming the
violation): tags of any kind (incl. bignums); all floats (f16/f32/f64, NaN, Inf);
indefinite lengths; `undefined` and any other simple value; trailing bytes after a
complete top-level item; non-minimal integers; unsorted or duplicate map keys; invalid
UTF-8; truncated input; empty input; integers outside the i64 range; nesting deeper than
`MAX_DEPTH` (128).

**Strictness law** (tested as both vectors and properties): for every in-profile byte
string `B`: `encode(decode(B)) == B`; and for every encodable value `x`:
`decode(encode(x)) == x`. Decoding arbitrary random bytes never panics; anything it
accepts re-encodes to exactly itself.

## API

```rust
use sharenet_protocol::{cbor::{decode, encode, Value}, identity::Identity,
                        store::IdentityStore};

// Wire objects:
let v = Value::Map(vec![
    (Value::Int(1), Value::Int(1)),          // field 1: scheme_version = 1
    (Value::Int(2), Value::Bytes(pub_key)),  // field 2: public_key
]);
let wire: Vec<u8> = encode(&v)?;              // canonical bytes (maps are sorted)
let back: Value = decode(&wire)?;             // strict; typed errors on violation

// Node identity (created/loaded at node startup):
let store = IdentityStore::new("/var/lib/sharenet");
let id = store.load_or_create(Some("human-readable-name"))?;  // generate-once semantics
println!("node_id: {}", id.node_id());       // derived, never caller-chosen
let sig = id.sign_detached(payload);          // detached Ed25519 (RFC 8032)
id.node_identity().verify_detached(payload, &sig)?;  // strict: rejects malleable sigs
```

### NodeIdentity wire object

```text
{1: scheme_version (uint, =1),
 2: public_key (32-byte bstr, canonical Ed25519 point encoding),
 3: created_at_unix (uint),
 4: display_name (optional text, ≤ 64 UTF-8 bytes)}
```

`node_id = SHA-256(canonical_cbor({1: scheme_version, 2: public_key}))` (32 bytes, hex
for display). The identity is self-certifying: knowing `node_id` binds you to the exact
key material and scheme. `display_name` and `created_at_unix` are mutable metadata,
deliberately NOT part of the derivation (renaming does not break the binding); tampering
with `public_key` or `scheme_version` changes `node_id` and — on the stored file — fails
closed (the seed must derive the exact public-key bytes).

Public-key encodings are validated for RFC 8032 canonical form (y < p) in addition to
decompression, so one node has exactly one possible key byte image (and one `node_id`).

## Durable identity store — persistence guarantees

The identity file (`<dir>/identity.cbor`) is strict-canonical CBOR:
`{1: seed (32-byte bstr), 2: NodeIdentity map}``.

- **Atomic writes**: tmp file (same directory, `create_new`, 0600 from creation) →
  `write` + `fsync` → pin permissions to exactly 0600 (umask cannot add bits, only
  remove; the pin restores anything removed) → install **without clobbering**
  (`hard_link` + `unlink`, which fails atomically if the destination exists; an
  exists-check + `rename` fallback covers filesystems without hard links, with a
  documented TOCTOU window in that fallback only) → parent-directory `fsync`.
- **Fail-closed loads**: symlink at the path → refused; not a regular file → refused;
  any permission bit beyond 0600 (unix) → refused; larger than 4 KiB → refused;
  non-canonical CBOR, wrong shape, wrong scheme version, seed↔object mismatch → refused.
  **The store never silently overwrites, recreates, or partially accepts.**
- `IdentityStore::load_or_create(dir)` generates exactly once; a concurrent creator
  that wins the race is loaded rather than clobbered.
- The identity directory is created 0700 (unix) when the store has to make it; an
  existing directory's permissions are not enforced.

## sharenet-id CLI (the production runtime path)

```text
sharenet-id create --dir <DIR> [--name <NAME>]        # generate + write; refuses existing
sharenet-id show --dir <DIR>                          # node_id, pk, created_at, name; never the seed
sharenet-id verify --dir <DIR>                         # strict re-validation (fail-closed)
sharenet-id sign --dir <DIR> --payload <FILE> [--out <FILE>]   # detached signature
sharenet-id verify-signature --identity-file <FILE> --payload <FILE> --signature <FILE>
```

Exit codes: `0` success, `1` operational failure, `2` usage error. All failures print an
actionable message to stderr. The future ShareNet daemon calls
`IdentityStore::load_or_create` (the same API) at node startup.

## Test vectors (for the R1-003 cross-language harness)

`tests/vectors/cbor_vectors.json` — 45 roundtrip cases (decode → value, value →
canonical bytes) and 57 reject cases (input → exact typed error name).
`tests/vectors/identity_vectors.json` — 5 cases: fixed seeds (three RFC 8032 §7.1
seeds), the exact `node_id` SHA-256 preimage, the NodeIdentity wire bytes, the identity
file bytes, and deterministic detached signatures.

- Validate the committed vectors: `cargo test --test test_vectors`
- Regenerate after intentional changes: `cargo test --test test_vectors -- --ignored`

## Verification commands

```bash
cargo test --workspace                        # 65 tests: unit + adversarial + conformance
cargo check --target wasm32-unknown-unknown    # platform independence (L007)
cargo clippy --workspace --all-targets         # clean
cargo fmt --all --check                        # clean
```

## Security notes, threat model and honest limits

- **Strict verification**: signatures are verified with `verify_strict` (rejects
  malleable signatures with a non-canonical `S`); wrong-length signatures are rejected
  before verification; deterministic RFC 8032 signing (no RNG on the signing path).
- **Zeroization**: the seed copy in `Identity` lives in `Zeroizing<[u8; 32]>`; the
  `SigningKey` zeroizes on drop via the `ed25519-dalek` `zeroize` feature; seed transit
  buffers in the store are zeroized and the encoded file bytes (which contain the seed)
  are wrapped in a zeroize-on-drop buffer. Tests observe the zeroize primitives on live
  buffers and assert the wiring by construction. **Limit:** observing memory after
  deallocation would require `unsafe`, which this crate forbids — post-drop zeroization
  is therefore trusted to the `zeroize` crate's guarantees rather than directly
  observed. `Debug` for `Identity` redacts the seed.
- **No public API hands out the raw secret bytes**; only the same-crate store can
  request the seed (to write the 0600 file).
- **Entropy**: unix hosts read 32 bytes from `/dev/urandom`; other platforms fail closed
  with an actionable error (callers provide a seed via `Identity::from_seed`).
- **Permissions** are enforced on unix only (the profile's rule is explicitly unix); on
  platforms without POSIX modes the checks are skipped and documented.
- **TOCTOU**: the load path stat → read window is not protected against a concurrent
  replacement of the file by an attacker with write access to the directory; the write
  path does not clobber, and symlinked identity files are refused. Host directory
  integrity is assumed.
- The identity file is the durable secret store by design (0600); its contents are not
  zeroized on disk (deleting the file is the operator's revocation).
- Hand-rolled CBOR encoder/decoder over an explicit value model: no codec dependency to
  audit, fully deterministic, `#![forbid(unsafe_code)]`.

## Scope

Wave 1 only: `NodeIdentity` (the registry's foundation wire object), the CBOR profile,
the identity store and CLI. Advertisement, LinkAuthentication, Route*, Circuit*,
Contribution*, capabilities/admission, transports, ADCOS integration, and the
cross-language harness are deliberately **not** here (R1-003/R1-004 and later waves).
