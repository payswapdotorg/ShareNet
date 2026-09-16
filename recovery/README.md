# sharenet-recovery — R7-002 (durable recovery attempts)

The durable-file layer of ShareNet's failure handling
(`spec/architecture.md` §11), completing what R7-001's snapshot seam
deferred. Two laws anchor the crate:

- **L015** — *"Revocation is durable and authoritative; recovery cannot
  resurrect a revoked circuit."* The durable ledger file
  (`ledger::DurableRevocationLedger`) is the L015 authority backed by an
  append-only, chain-verified log whose records are the R7-001 signed
  revocation envelopes themselves (re-verified — signature, committed-path
  membership, not-future — at every load, round-tripped through the
  R7-001 snapshot seam).
- **L021 / §11** — *"Recovery state is durable and bounded."* The attempt
  log (`attempt::RecoveryAttemptLog`) records every recovery attempt
  (revoked circuit, per-circuit monotonic seq, started_at, fresh route
  commitment ref or typed failure reason, pending/succeeded/abandoned)
  durably and bounded: at most `MAX_ATTEMPT_RECORDS_PER_CIRCUIT`
  retained attempts per circuit (oldest abandoned compacted) and a hard
  file cap.

And one ordering rule enforced at every admission: **no attempt may
resurrect the revoked circuit** — an attempt referencing a circuit the
durable ledger does not show as revoked is refused typed
(`circuit_not_revoked`); recovery only ever *follows* durable
invalidation. Success is terminal per circuit; a new failure of the
fresh circuit is a new revocation and a new recovery (L014: fresh
session identity).

Dependencies: `sharenet-protocol` + std only. No wall clock (every time
parameter is caller-supplied), no async runtime, no serde.
`#![forbid(unsafe_code)]`. Native by design (durable files); there is no
wasm story to claim here — the durable layer is the host's.

## What it provides

| Piece | Where | What |
|---|---|---|
| `DurableRevocationLedger` | `src/ledger.rs` | The L015 authority as an append-only file: `open_or_create` (never clobbers) / `admit_envelope` (the full R7-001 chain first; durable-first: appended + fsynced before authoritative) / `load` (strict parse, every cross-check, torn tails reported-and-truncated — the only repair, at the next append) / `ledger()` (the R7-001 view, installable into `CircuitRegistry`). SHA-256 chained records, CRC-32 guarded, byte-cap enforced both sides. |
| `RecoveryAttemptLog` | `src/attempt.rs` | §11's bounded attempt state: `begin_attempt` (single-flight, §11-ordered — only a durably revoked circuit; per-circuit monotonic seq from the persisted high-water) / `finish_attempt_with_route` (the commitment is verified in full when in hand: R3-004 chain + §11 freshness — `proposed_at` must not predate the revocation anchor) / `finish_attempt_with_failure` (typed reasons) / restart-safe reload with the same fail-closed discipline. |
| `FreshRouteEvidence` | `src/attempt.rs` | What a succeeded attempt brings back: a verified `RouteCommitment` (RECOMMENDED — identity derived from verified bytes, L013) or a bare route ref (recorded, trust left to the caller's carrying layer). |
| `RecoveryDriver` | `src/driver.rs` | The composition: owns both stores, exposes the §11 lifecycle as far as R7-002 reaches — `attempt_next → SelectFreshGateway` (the R7-003 seam) → `attempt_succeeded` / `attempt_failed`; hands the R7-001 ledger view out for the `CircuitRegistry` L015 gate. |
| `RecoveryError` | `src/error.rs` | Typed errors with stable machine names (`circuit_not_revoked`, `recovery_already_complete`, `attempt_already_pending`, `no_pending_attempt`, `route_not_fresh`, corruption families…). |

## Documented policies

- **Durable-first writes.** A record is appended + fsynced before it
  becomes authoritative (the R5-003 discipline; temp + rename not needed
  for append-only logs — the torn-tail law below covers the crash
  window instead).
- **Trust nothing from disk.** Both loads strict-parse (magic/version,
  lengths, CRC-32 per record, the SHA-256 chain for the ledger), and the
  ledger re-runs the R7-001 admission verification on every envelope.
  Corruption is a typed refusal naming the region; a torn TAIL is the
  one tolerated residue — kept as a verified prefix, reported, and
  repaired only by the next append.
- **§11 ordering.** Recovery strictly follows durable invalidation; a
  pending attempt blocks new ones (single flight); success is terminal;
  the per-circuit numbering never regresses across restarts (persisted
  high-water).
- **Bounded.** Retained attempts per circuit and total file bytes are
  hard-capped; compaction removes the oldest ABANDONED attempts only.

## Verification evidence (R7-002: unit, restart, concurrency)

- **unit (32)** — `src/ledger.rs` (12): create/load/no-clobber, admit
  outcomes (first/additional/duplicate), refused admission writes
  NOTHING, restart round-trip, the R7-001 seam snapshot round-trip,
  header/CRC/envelope corruption typed BY POSITION, chain tampering,
  torn-tail repair discipline, file caps, missing file typed.
  `src/attempt.rs` (14): deterministic round-trips of every record
  state, header/structure/record corruption fail-closed,
  sequence/bound violations, the CRC trailer, unrevoked-circuit refusal,
  lifecycle refusals + monotonic numbering, typed finish paths, fresh
  route evidence verification (incl. the §11 `route_not_fresh` anchor
  law), the bounded compaction law, file caps, frozen vocabularies, seq
  overflow. `src/driver.rs` (3): the composed lifecycle end-to-end, the
  L015 gate through a fresh registry, refusals leaving durable state
  untouched. `src/sha256.rs` (3): the chain construction against
  standard vectors.
- **restart (`tests/restart.rs`, 4)** — L015 END-TO-END (a revoked
  circuit stays revoked across a full teardown; the reloaded view gates
  a fresh `CircuitRegistry` while live siblings admit; recovery itself
  continues), attempt numbering + pending survival + the §11 freshness
  anchor across the boundary, bounded compaction + high-water across
  reload, and torn-tail crash residue with repair-at-next-append.
- **concurrency (`tests/concurrency.rs`, 5)** — single flight under
  racing begins (`attempt_already_pending`), exactly-once finish under
  racing finishes (the reloaded disk carries the winner's outcome),
  idempotent racing admits (one record per (circuit, revoker); the
  reloaded chain verifies), concurrent loads racing real appends
  (complete image, torn TAIL reported, or typed refusal — never
  garbage; bounded so a writer failure fails the test instead of
  hanging), and four full lifecycles interleaved over one shared driver.

```sh
cargo test          # 32 unit + 5 concurrency + 4 restart — all green
```

## Deliberately NOT done here (honest scope)

Gateway selection, route construction, circuit setup and verification
are R7-003/R7-004 scope (the `SelectFreshGateway` seam is the typed
hand-off); retry/backoff policy is R7-005; concurrent-recovery
COORDINATION across processes is R7-006 (in-process single flight is
enforced here). No second source of truth for circuit terminal state
(AGENTS.md): the R7-001 ledger view IS the authority this layer
persists.
