# sharenet-dtn — R6-003 (DTN store-carry-forward)

The node's LOCAL custody store: the layer of `spec/architecture.md` §12
that holds carried bundles (R6-001 `ContentManifest`s + verified chunks)
durably, records their custody facts, and answers the two carry-forward
questions — *what do I forward next?* and *what do I evict?* —
deterministically, from caller-supplied clocks. It borrows DTN principles
(custody, TTL, replication counting, expiry-aware carry) without
rebuilding DTN concepts; a BPv7 adapter would sit ON this store later,
not replace it.

Exactly one dependency: `sharenet-protocol` (R6-001). No async runtime,
no serde, no wall clock, no I/O beyond the store's own directory.
`#![forbid(unsafe_code)]`. The lib compiles for `wasm32-unknown-unknown`
(the L007 discipline): the pure `DtnStoreImage` + registry codec are the
wasm host's persistence seam; only the file-backed `DtnStore` is native.

## The laws

1. **Integrity is the manifest's hash law.** A chunk is stored ONLY if
   its length matches its manifest slot's expected length and its
   SHA-256 matches the manifest's committed hash (R6-001's
   length-before-hash discipline). An unverifiable chunk NEVER enters the
   store — typed refusal, no partial storage.
2. **Dedup by `(content_id, slot)`.** The content id is
   commitment-derived (L013 — re-derived here, never caller-supplied).
   Re-delivery of a held manifest is `AlreadyPresent`; of a held chunk is
   `Duplicate`: idempotent, never a second record, never a second file.
3. **TTL is per-bundle and caller-clocked.** Every time parameter is
   supplied by the caller; this crate has NO wall clock. A bundle is
   expired at `now >= expires_at_unix`; expired bundles NEVER forward
   (TTL gates BEFORE priority — no inversion is possible), never take
   new chunks, and are the eviction candidates.
4. **Priority is the frozen service class set.** `live` /
   `opportunistic` / `dtn` (ADR-003), as the typed `ServicePriority`,
   pinned by test to the protocol core's frozen `SERVICE_CLASSES` — no
   second vocabulary.
5. **Trust nothing from disk.** Loads strict-parse the registry
   (magic/version/flags/lengths/CRC-32), re-derive every content id from
   its own stored manifest bytes, cross-check the persisted chunk-count
   and delivered summaries, and RE-HASH every stored chunk file against
   its manifest commitment. Any tamper is a typed error and NOTHING
   loads. `DtnStore::read_chunk` re-verifies on every read.
6. **Atomic flush, fail-closed load.** The registry is written temp +
   fsync + rename; chunk files each get their own atomic write; evicted
   bundles' chunk files are deleted only after the replacement registry
   is durably in place (a crash leaves ignored orphans, never dangling
   references).
7. **Custody evidence is unsigned local fact.** `CustodyRecord`s
   (`received` / `forwarded` / `delivered`, when, to-whom as an OPAQUE
   bounded `PeerRef`) are the R8 contribution-evidence seam — R8-001
   owns signatures, receipts and anti-gaming. This log never signs and
   never deduplicates (append-only, capped, honest). Evidence survives
   eviction (delivery facts outlive the data).
8. **Determinism.** Forward lists, summaries and registry bytes are
   pure functions of state + the caller's clock: ordered maps, fixed
   sort keys, no hash-iteration dependence (architecture §2).

## What it provides

| Piece | Where | What |
|---|---|---|
| `ServicePriority` | `src/priority.rs` | The frozen classes, typed; the carry order (`live` > `opportunistic` > `dtn`). |
| `CustodyKind` / `PeerRef` / `CustodyRecord` | `src/evidence.rs` | The R8 seam: append-only custody facts with opaque bounded peers. |
| `BundleSummary` / `ForwardCandidate` / `BundleStatus` | `src/bundle.rs` | Read views: what is held, what may move (with replication math), the typed live/expired/delivered/replication-exhausted verdicts. |
| `DtnStoreImage` | `src/store.rs` | The pure model + strict registry codec (wasm-portable): `admit_manifest` / `verify_chunk` / `mark_present` / `admit_chunk` / `forward_candidates` / `note_forwarded` / `mark_delivered` / `record_evidence` / `evict_expired` / `to_bytes` / `from_bytes` with every cross-check. |
| `DtnStore` | `src/store.rs` | The file-backed store (native): `create` (never clobbers) / `load` (re-verify EVERYTHING — the restart law) / `admit_*` (chunk files atomic per write) / `read_chunk` (re-verified every read) / `evict_expired` (deletion only at flush, after the replacement registry is durable) / `flush`. Single-writer by design. |
| `dtn_probe` | `src/bin/dtn_probe.rs` | TEST SCAFFOLDING for the multiprocess verify level: a real separate process (seed / fill-chunks / forward-list / forward-one / deliver / evict / evidence / status / read-chunk) with machine-parsable output lines. |

## Restart + multiprocess evidence (verify levels)

- **In-lib** (`src/store.rs` `file_tests`): teardown→reload preserves
  bundles, present slots, replication counts and evidence; custody
  CONTINUES across the boundary (dedup intact, partial bundle
  completes, second reload sees the result); tampered / truncated chunk
  files refuse the whole load typed; registry corruption refuses;
  `create` never clobbers; eviction deletes chunk files only at flush
  and evidence survives.
- **Integration** (`tests/multiprocess_carry.rs`): nine REAL probe
  processes continue one bundle's custody — seed partial (2/4 chunks) →
  complete from disk → forward-list → two forwards → replication
  exhausted (never a candidate again) → evidence log intact →
  byte-exact re-verified read → typed status; plus the adversarial TTL
  leg: a dominant-priority bundle that NEVER forwards at/after its
  bound, evicts from a later process, refuses status typed (exit 3),
  and whose evidence SURVIVES the eviction.

```sh
cargo test                                     # 32 unit + 2 multiprocess
cargo check --target wasm32-unknown-unknown --lib   # the L007 discipline
```

## Deliberately NOT done here (honest scope)

- **No forwarding policy.** `forward_candidates` says WHAT may move;
  WHERE (and whether now is a good moment) is the R6-005 opportunistic
  forwarder composed with the R5-005 gateway admission policy.
- **No cross-node rules.** R6-004 owns receiving-side
  dedup/integrity/TTL admission; this crate is the local half.
- **No chunk transfer protocol.** R6-002 owns resumable transfer;
  `present_slots` is its seam (what this node can serve).
- **No wire objects.** Everything here is node-local durable state; the
  protocol registry governs nothing in this crate (the same reading as
  R5-003's store).
- **No second source of truth** for content: the manifest IS the named
  object; this store only ever derives its ids.
