# sharenet-recovery — R7-002 (durable recovery attempts) + R7-003 (alternate route/gateway recovery) + R7-004 (replacement circuit) + R7-005 (retry/backoff)

The durable-file layer of ShareNet's failure handling
(`spec/architecture.md` §11), completing what R7-001's snapshot seam
deferred — now carrying the recovery pipeline through fresh-gateway
selection and fresh-route establishment (R7-003). Two laws anchor the
crate:

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

Dependencies: `sharenet-protocol` + `sharenet-admission` (the R5-005
gateway admission policy, composed — never rewritten) +
`sharenet-connectivity` (the R5-003/R5-004 evidence types the admission
factors borrow) + std. No wall clock (every time parameter is
caller-supplied), no async runtime, no serde. `#![forbid(unsafe_code)]`.
Native by design (durable files); there is no wasm story to claim here
— the durable layer is the host's.

## What it provides

| Piece | Where | What |
|---|---|---|
| `DurableRevocationLedger` | `src/ledger.rs` | The L015 authority as an append-only file: `open_or_create` (never clobbers) / `admit_envelope` (the full R7-001 chain first; durable-first: appended + fsynced before authoritative) / `load` (strict parse, every cross-check, torn tails reported-and-truncated — the only repair, at the next append) / `ledger()` (the R7-001 view, installable into `CircuitRegistry`). SHA-256 chained records, CRC-32 guarded, byte-cap enforced both sides. |
| `RecoveryAttemptLog` | `src/attempt.rs` | §11's bounded attempt state: `begin_attempt` (single-flight, §11-ordered — only a durably revoked circuit; per-circuit monotonic seq from the persisted high-water) / `finish_attempt_with_route` (the commitment is verified in full when in hand: R3-004 chain + §11 freshness — `proposed_at` must not predate the revocation anchor) / `finish_attempt_with_failure` (typed reasons) / restart-safe reload with the same fail-closed discipline. |
| `FreshRouteEvidence` | `src/attempt.rs` | What a succeeded attempt brings back: a verified `RouteCommitment` (RECOMMENDED — identity derived from verified bytes, L013) or a bare route ref (recorded, trust left to the caller's carrying layer). |
| `RecoveryDriver` | `src/driver.rs` | The composition: owns both stores, exposes the §11 lifecycle — `attempt_next → SelectFreshGateway` → `select_gateway` (R7-003: the R5-005 policy composed in, deterministic tie-break) → `establish_fresh_route` (R7-003: R3-004 proposal → acceptance → commitment, admission-freshness-checked at construction time) → `attempt_succeeded` / `attempt_failed`; hands the R7-001 ledger view out for the `CircuitRegistry` L015 gate. |
| `GatewayCandidate` / `GatewaySelection` / `select_eligible_gateway` | `src/gateway.rs` | **R7-003's selection stage.** A candidate is exactly the R5-005 evidence shape (borrowed, the admission crate's own types — the stages cannot drift); the REAL policy runs per candidate (every signature verified at selection time — no caller-supplied "eligible" booleans, ever); only `Eligible` selects; ties break deterministically by ascending gateway node-id bytes (input order never matters); ambiguous sets (duplicate ids) and no-eligible-candidate sets (empty included) are typed refusals (`duplicate_gateway_candidate`, `no_eligible_gateway` — the machine name R7-005's retry policy will consume). Pure: the same `(policy, candidates, now)` always yields the same selection. |
| `RecoveryDriver` (R7-004 stage) | `src/driver.rs` | `record_zeroization` (the §11 step between durable invalidation and the new session — a typed, durable, single-shot FACT; in-process key destruction belongs to the runtime layers, this records and orders the fact) and `establish_replacement_circuit`: the signed R4-002 material (setup envelope + per-position acks) over the recorded fresh route, admitted through a registry gated by the driver's own L015 ledger view — zeroization-gated, record-bound (`replacement_route_mismatch`), L014-fresh (`replacement_circuit_id_not_fresh`), single-flight (`replacement_already_established`). |
| `BackoffPolicy` / `BackoffSchedule` / `RetryDecision` | `src/backoff.rs` + `src/driver.rs` | **R7-005's retry/backoff policy.** Pure, validated-at-construction schedules (fixed / linear / exponential-capped; saturating math, exact bounds pinned by test) + an optional attempt budget; the gate `when_may_retry(circuit, now, policy)` reads the durable §11 state and returns the typed verdict (`RetryNow` / `NotYet { retry_at_unix }` — the daemon's timer input / `Terminal { NotRevoked | AttemptPending | AlreadySucceeded | Exhausted }`); `attempt_next_when_permitted` composes the gate with `attempt_next` (typed `retry_not_yet` / `retry_exhausted`). No wall clock, no timers, no jitter (a daemon wanting jitter adds it outside the frozen, reproducible decision). |
| `recovery_probe` | `src/bin/recovery_probe.rs` | TEST SCAFFOLDING for the multiprocess verify level: a real separate process driving setup → zeroize → attempt → select → establish → establish-replacement → state across process boundaries, with machine-parsable output lines and typed exit codes. |
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

## Verification evidence (R7-002: unit, restart, concurrency; R7-003: adversarial, multiprocess)

- **unit (38)** — `src/ledger.rs` (12): create/load/no-clobber, admit
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
  overflow. `src/driver.rs` (5): the composed lifecycle end-to-end, the
  L015 gate through a fresh registry, refusals leaving durable state
  untouched, plus the R7-003 stage bindings (selection bound to the
  open attempt, construction-time admission freshness).
  `src/gateway.rs` (4): the selection laws (eligibility gating,
  deterministic tie-break, typed refusals, re-query purity).
  `src/sha256.rs` (3): the chain construction against standard vectors.
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

- **adversarial (`tests/adversarial.rs`, 7)** — ineligible-only
  candidate sets never select (typed `no_eligible_gateway`, even when
  it is the ONLY candidate), pre-revocation routes refused END-TO-END
  (a commitment predating the revocation anchor fails
  `attempt_succeeded`), lying candidates never selected (evidence that
  does not verify under the real policy), selection determinism +
  re-query purity (input permutations never matter), empty candidate
  sets typed, duplicate candidate ids typed, and the selected gateway
  is provably on the committed path.
- **adversarial, R7-004 (`tests/adversarial.rs`, 6 more)** — the §11
  zeroization ordering typed at every edge (before revocation refused,
  unknown circuits refused, pre-revocation clocks refused,
  single-shot), the replacement zeroization gate (`zeroization_missing`
  cured exactly by recording the fact in order), a replacement over the
  REVOKED circuit's own route refused (`replacement_route_mismatch`),
  forged material refused typed (malformed content →
  `replacement_setup_invalid`; flipped signature bytes → the R4-002
  admission gate) with NOTHING recorded, double replacement as the typed
  single flight (registry-level idempotence AND the durable
  `replacement_already_established` through a fresh registry), and the
  zeroization + replacement facts surviving a full crash → reload.
- **restart + concurrency, R7-005** — the backoff decision is a pure
  function of the durable history: the same (state, policy, clock)
  decides the same across a full teardown; a circuit whose window
  elapsed while the node was OFFLINE is immediately retryable on
  reload (offline time counts — no catch-up sleeps); under concurrency
  the gate is consistent across racing threads and the composed open
  is single-flight (exactly one racer opens; the rest typed
  `attempt_already_pending`; one pending record on disk).
- **multiprocess (`tests/multiprocess.rs`, 3)** — through the REAL
  `recovery_probe` binary: a gateway recovery flowing across three
  process roles (revocation+attempt → selection+establishment →
  reloaded terminal state), the typed no-eligible-gateway refusal
  crossing a process boundary, and the R7-004 replacement flow across
  four process roles (revocation+zeroization → selection+route →
  replacement → reload showing every durable fact + the cross-boundary
  single-flight refusal).

```sh
cargo test          # 56 unit + 6 concurrency + 5 restart + 13 adversarial + 3 multiprocess — all green
```

## Deliberately NOT done here (honest scope)

Concurrent-recovery COORDINATION across processes is R7-006
(in-process single flight is enforced here; the R7-005 gate itself is a
pure query — the daemon's timers and wakeups are its own wiring, and
the policy never sleeps). The
zeroization FACT is durable and ordered; destroying live session key
material in the runtime layers (tunnels, session state) is not this
crate's to claim — the record is the §11 ordering evidence, honestly
bounded. No second source of truth for circuit terminal state
(AGENTS.md): the R7-001 ledger view IS the authority this layer
persists. Selection is a hard-constraint filter + deterministic
tie-break, NOT a quality ranking — the optimizer layers of R3-004
routing may compose on top.
