# sharenet-economics — R8-002 (useful-work valuation)

ShareNet's versioned, explicit economic formula: how VERIFIED
contribution evidence becomes valued contribution points.
**`spec/architecture.md` §13**: *"Civic Points are earned only from
verified useful work... The economic formula is versioned and
explicit."* This crate is that formula — nothing else.

## Position (the honest boundary)

- **Input contract**: R8-001 [`ContributionReceipt`]s already admitted
  by the `sharenet_protocol::contribution::ReceiptLedger` (signature,
  parse, self-receipt exclusion, per-pair monotonic sequence and
  issued_at bounds were enforced THERE). This crate never re-verifies
  signatures and never trusts caller-supplied identity: the issuer,
  contributor, kind, byte count and receipt_id are re-derived from the
  receipt's own parsed fields (no caller-controlled booleans — the
  architecture law).
- **NOT here**: durable storage (R8-003, the Civic Point ledger — this
  engine is in-memory policy), perk consumption (R8-004), anomaly
  DETECTION / Sybil identification / audit trails (R8-005 — here the
  caps merely BOUND the abuse), and any monetary interpretation (§13:
  monetary rewards are a separate settlement program; points are not
  intrinsically redeemable).

## The formula (v1, pinned by `VALUATION_FORMULA_VERSION = 1`)

```text
billable(receipt)  = min(receipt.delivered_bytes, PER_RECEIPT_BYTE_CAP)
intrinsic(receipt) = kind_weight_bp(receipt.kind) * billable(receipt) / 10_000
award(receipt)     = min(intrinsic,
                        pair_cap_remaining(issuer, contributor, window),
                        contributor_cap_remaining(contributor, window))
window(receipt)    = receipt.issued_at_unix / window_secs
```

- **Kind weights** (the §14 "contribution-quality weighting"):
  `carried` = 10_000 bp (1.0×), `delivered` = 15_000 bp (1.5×) —
  terminal delivery outweighs intermediate custody. Integer math
  throughout, truncating division, deterministic.
- **Per-receipt byte cap** (default 1 MiB): one receipt's byte claim
  can bill no further than this — the schema-level bound on fabricated
  bytes (the receipt layer's optional manifest-binding check remains
  the stronger form when the manifest is in hand).
- **Per-window caps** (the §14 "per-counterparty and per-time-window
  caps"): the `(issuer, contributor)` pair is capped per window AND
  the contributor is capped ACROSS ALL ISSUERS per window (the Sybil
  bound: any number of colluding issuers cannot amplify one
  contributor past the contributor cap; a circular acknowledging pair
  cannot pass the pair cap in either direction).
- **Capped ≠ refused**: a capped receipt is still valid evidence; the
  verdict reports the intrinsic value, the awarded points and the
  binding cap. Nothing is deleted or refused at this layer (the
  receipt laws below stay intact).
- **Idempotent + future-closed** (defense in depth): a re-delivered
  receipt_id is a `Duplicate` (zero points); a receipt dated after the
  caller's clock refuses typed (the ledger already refuses those at
  admit time).

## The Civic Point ledger (R8-003)

`src/ledger.rs` is the DURABLE form: `CivicPointLedger` composes the
engine — `award(receipt, now)` prices through the SAME law and appends a
`LedgerEntry` (the registered CivicPointLedgerEntry durable-state
record: contributor + issuer, awarded + intrinsic points, the formula
version, the receipt_id evidence link, the window, the append clock)
when the award is non-zero. Exactly-once per receipt_id; duplicates and
refusals record nothing; zero-point capped receipts record nothing
(they remain valid evidence, un-priced again). Balances only ever
increase in v1 — spending/perk consumption is R8-004's and no code path
here decrements.

Durability: the snapshot round-trips
(`{1: version, 2: policy, 3: [entries]}`, fail-closed reload) AND the
`FileCivicPointLedger` appends length-prefixed canonical records with
flush + fsync per entry (the appliance-journal convention). The RESTART
LAW: the reload restores the ENGINE state too (valued ids, per-pair and
per-contributor window totals) — a restart must NOT reset the window
caps (the farming-by-restart vector is closed by construction; found by
the restart suite, fixed by design).

## Layout

```
economics/
  src/lib.rs        the formula, the policy (validated bounds), the
                    engine (window/pair/contributor accounting) + unit tests
  src/ledger.rs    the Civic Point ledger (R8-003): entries, the pure
                    ledger, the file-backed durable form, the engine
                    restore (the restart law)
  src/sim.rs        the simulation verify level: seeded deterministic
                    adversarial simulation (honest baseline, an 8-issuer
                    sybil ring, a circular pair, a window straddler)
                    asserting the cap invariant EVERY step
  src/bin/economics_sim.rs   the driver: seed → report line,
                    byte-identical run to run, exits 1 on any cap violation
  tests/adversarial.rs      cap evasion, window games, byte inflation,
                            replay revaluation, clock games, exact bounds
  tests/ledger_restart.rs    snapshot + file-backed reload exactness,
                            fail-closed tamper, caps-survive-restart
  tests/ledger_concurrency.rs racing threads: exactly-once per receipt,
                            exact totals, durable file racing
```

## Verification

```bash
cargo test                                # 28 tests: unit + sim + adversarial
cargo run --bin economics_sim 42          # the deterministic report line
cargo check --target wasm32-unknown-unknown   # platform independence
```

Sample report (seed 42, the sim.rs scenario):

```text
seed=42 windows=24 steps=1555 valued=1555 capped=1243 honest=1930
sybil=50000 potential=160000 circular=40000 straddler=20000 violations=0
```

Read: the 8-issuer ring's uncapped potential is 160k points/window;
the contributor cap holds its actual award at 50k. The circular pair
farms exactly two directional pair caps (40k). The straddler gets one
pair cap (20k) — boundary timing accrues each window's own cap, never
double. The honest baseline (modest flow) is never capped. Zero cap
violations in every seeded run (asserted, not just observed).

## Honest limits (what the simulation is NOT)

- A directional POLICY simulation over synthetic receipts — not field
  evidence, not a market survey, not anomaly detection (R8-005 owns
  detection; here the ring's capped points are still PAID — bounded,
  not punished).
- The caps bound the abuse; they do not catch it. A determined Sybil
  ring earns up to the contributor cap in every window until R8-005's
  analysis layer identifies it.
- The engine is order-sensitive by design (caps are consumed in
  valuation order); the daemon values receipts in ledger order, which
  is deterministic per node. Cross-node aggregation is R8-003's ledger
  concern.
