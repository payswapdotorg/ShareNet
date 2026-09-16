# sharenet-propagation — R6-004 (receiving-side cross-node propagation rules)

The RECEIVING half of `spec/architecture.md` §12's propagation list:
what THIS node accepts when ANOTHER node propagates content to it — an
offer of a manifest + chunks, or a forward from a carrying peer. R6-003
built the local half (the custody store) and named this crate's
position explicitly; this crate is the pure decision engine OVER that
store, in the R5-005 style: typed offer evidence in, a pure decision
over the node's own durable state and the caller's clock, typed verdict
out — no I/O, no wall clock, no propagation-local state.

Exactly two dependencies, both ShareNet: `sharenet-protocol` (R6-001 —
the manifest, its strict parse, its commitment-derived ids) and
`sharenet-dtn` (R6-003 — the store state, the frozen priority, the read
views, the custody evidence seam, the caps). No async runtime, no
serde, no I/O anywhere in the lib.
`#![forbid(unsafe_code)]`. The whole crate compiles for
`wasm32-unknown-unknown` (the L007 discipline) — on a wasm host the
same rules decide over the host's own `DtnStoreImage`.

## The laws

1. **The store is the only state.** Every verdict is derived from the
   node's own durable store state; this crate holds no state of its
   own, so a decision made before a restart holds identically after it
   (the restart verify level).
2. **Dedup is the identity question.** The content id is RE-DERIVED
   from the offered bytes (L013 — a carrying frame's claimed id must
   agree or the offer is refused typed); already-held content answers
   `already_held` (partial) / `already_complete` (whole) with the FIRST
   admission's own record, and a verified slot re-delivery is a
   `duplicate`. Re-delivery never creates a second record, never
   extends a TTL, never upgrades a priority.
3. **Integrity is the manifest's hash law.** Manifests strict-parse
   through the R6-001 seams; chunks verify through the STORE's own path
   (`DtnStoreImage::verify_chunk`: length law before hash law). A held
   slot re-delivered with different bytes is an integrity refusal,
   never a duplicate — the duplicate verdict certifies verified
   byte-identity. Nothing unverifiable is ever stored.
4. **TTL is caller-clocked and gates BEFORE priority.** Expired offers
   are refused typed; offers below the policy's minimum remaining life
   (default 60s, configurable, 0 disables the floor) are refused typed;
   expired held bundles take no new chunks. No priority rescues a TTL
   failure — an expired `live` offer never outranks a fresh `dtn` one,
   at the decision or in the ingest order.
5. **Priority is the frozen service class set.** The wire's class name
   parses only through `ServicePriority::from_name` — an unknown class
   is a typed refusal (no second vocabulary, no future-class
   smuggling); accepted offers ingest in carry order (priority rank,
   expiry urgency soonest-first, content id bytes) — the same order law
   the store uses for `forward_candidates`.
6. **Replication policy is local.** A target below the store's minimum
   (1) is refused; this node's replication count is its own fact
   (starts at 0 — the offer evidence has NO claimed-count field, so a
   peer's count claims cannot take effect at this layer); replication
   gates FORWARDING, not receiving — an at-target held bundle is still a
   duplicate verdict (not a refusal) and still completes its chunks.
7. **Fail-closed, deterministic, typed.** Every tamper, lie, expiry,
   ambiguity or capacity pressure is a typed refusal with a stable
   machine name (`name()`), and nothing is stored on the back of one.
   The evaluation order is fixed (evidence shape → dedup → TTL →
   target → capacity); the same (offer, store, clock) always yields the
   same verdict (architecture §2).

## What it provides

| Piece | Where | What |
|---|---|---|
| `ManifestOffer` / `ChunkOffer` | `src/evidence.rs` | The typed offer evidence: manifest bytes + carry metadata (class name, TTL bound, target, peer) and chunk slot/bytes — the offer's own claims, re-derived by the policy before they matter. |
| `ManifestVerdict` / `ChunkVerdict` | `src/verdict.rs` | The typed outcomes: `accept` (with the admission-plan anchor), `already_held` / `already_complete` / `duplicate` (with the held record + its live/expired/delivered/replication-exhausted status), `refused` (one typed reason, stable machine names). |
| `PropagationPolicy` / `PropagationParams` | `src/policy.rs` | The pure decisions `decide_manifest` / `decide_chunk` (over `&DtnStoreImage` + caller clock), the composed apply paths `take_custody` (admit + one `received` custody record) / `receive_chunk`, and `order_for_ingest` (the carry order for a batch of accepts). |
| `DEFAULT_MIN_REMAINING_TTL_SECS` | `src/policy.rs` | 60 — the floor below which new custody is refused (0 disables; the hard expiry gate always remains). |

## Verification evidence (the work item's levels)

- **unit** (in-module `#[cfg(test)]`, 26 tests): every rule family's
  happy path + typed refusals with `matches!` + `name()` assertions —
  the admission plan, the inclusive floor boundary, malformed /
  lie-claim / unknown-class / low-target / oversize / store-full
  refusals, the chunk chain (accept → verified duplicate, integrity
  refusals, unknown content, expiry, slot range), the composed apply
  paths (custody recorded exactly once; chunks record no evidence), the
  ingest order, and the verdict/refusal name vocabularies pinned
  distinct.
- **adversarial** (`tests/adversarial.rs`, 16 tests): expired-offered
  (no priority rescue), expired-during-negotiation (the clock advances
  between decision and application, and between chunks), already-held
  with the first admission's metadata (TTL-extension / priority-upgrade
  / target-inflation lies all refused by dedup), already-complete and
  delivered re-offers, the at-target replication decision (duplicate +
  still completes), slot-conflict (different bytes under a held slot is
  an integrity refusal), wrong-hash / wrong-length never stored,
  lie-count (replays and claims move no counter), priority-inversion
  attempts (the expired `live` offer never outranks the fresh `dtn`
  one), capacity ingest order, interleaved replays deduping exactly,
  expired-held re-offer → evict → fresh accept, unknown-content chunks
  refused among held bundles, oversized manifests, determinism, and
  floor exactness for any configuration.
- **restart** (`tests/restart.rs`, 4 tests): image-level (serialize →
  strict reload → same offer `already_complete`, chunk `duplicate`,
  one custody record, byte-identical re-serialization after the
  replay), file-backed (a real `DtnStore`: create → decide → apply
  through the store's own APIs → flush → drop → load re-verifying
  everything → the same offer dedups with an equal anchor, chunks
  re-verified on read, receiving continues), the clock advanced across
  the boundary (the durable bound evaluated at the new clock; evict →
  flush → reload → fresh custody), and refusals storing nothing.

```sh
cargo test                                     # 26 unit + 16 adversarial + 4 restart
cargo check --target wasm32-unknown-unknown --lib   # the L007 discipline
```

## Design decisions (spec ambiguity, resolved honestly)

- **Already-at-target bundles ARE still acceptable custody.** §12 lists
  "replication policy" without semantics; the R6-003 store's semantics
  decide it: the replication count is THIS node's own forward count,
  so it gates FORWARDING (`forward_candidates` excludes exhausted
  bundles), not the receiving of content this node already holds. A
  re-offer of an at-target held bundle is therefore a duplicate (the
  bytes are here), and its missing chunks still complete — a coherent
  cache until TTL eviction. A peer's claimed replication state (its own
  count, or a network-wide one) is unverifiable at this layer, so the
  offer evidence has no such field at all — nothing can be adopted.
- **The TTL floor gates new custody only.** Completing an already-held
  bundle needs only the hard expiry gate (the store's own law for held
  bundles): the bytes are already this node's custody, and a coherent
  cache is better storage hygiene than a permanently partial one.
- **Custody evidence is bundle-level.** `take_custody` records exactly
  one `received` record per bundle (first admission); duplicates and
  refusals record nothing, and chunks record nothing. Per-chunk records
  would spend the store's bounded evidence log (16_384) on stream
  traffic — a 100-chunk bundle is one custody event, not a hundred.
- **Capacity prefers carry order.** When the store's bundle cap is
  reached, `decide_manifest` refuses `store_full`; among offers that
  passed the gates, `order_for_ingest` fixes which to admit first —
  (priority rank, expiry urgency, content id), the store's own forward
  order, so both edges agree on precedence.
- **One fail-closed catch-all.** `ChunkRefusal::store_state_unexpected`
  maps any store disagreement the receiving rules do not model —
  `verify_chunk` models exactly its six cases today, so this arm is the
  future-proofing of the fail-closed discipline, not an expected
  outcome.

## Deliberately NOT done here (honest scope)

- **No forwarding policy.** WHERE accepted content goes next (and
  whether now is a good moment) is R6-005's opportunistic forwarder,
  composed with the R5-005 gateway admission policy — this crate is the
  RECEIVING edge of that composition.
- **No carriage — and no `sharenet-transfer` dependency.** R6-002 is a
  work-item dependency (the offer evidence mirrors exactly what an
  R6-002 session delivers on the wire: `OFFER` manifest bytes, `CHUNK`
  slot/bytes, plus the carrying frame's metadata), but the rules are
  carriage-NEUTRAL: the same decisions apply over a future BPv7 adapter
  or node-local IPC, so depending on the transfer crate would couple
  the rules to one carriage for zero rule-value. The daemon wires the
  two: session → `decide_*` → store.
- **No second store.** The R6-003 store owns all durable state (and
  its `DtnStore`/`DtnStoreImage` APIs are the only mutation paths the
  composed apply paths call); this crate never persists anything of
  its own.
- **No signed receipts.** The one custody record an acceptance appends
  is the R6-003 unsigned local-fact log (the R8-001 seam); signatures,
  receipts and anti-gaming stay R8-001's layer.
- **No wire objects.** Verdicts and offers are node-local API types;
  the protocol registry governs nothing in this crate (the same
  reading as R5-003's store and R5-005's policy).
- **No future-creation policy.** A manifest whose `created_at_unix` is
  ahead of the decision clock is NOT refused here: DTN nodes are
  offline for long stretches and their clocks skew legitimately, and no
  spec text pins a bound — a skew-tolerance policy (if ever wanted)
  belongs to the daemon's receive configuration, not the frozen rule
  families.
