# sharenet-admission — R5-005 (gateway admission/backhaul policy)

The typed, pure, deterministic **two-factor gateway admission decision** of
`spec/integrations/adcos.md` ("Gateway admission"):

> "A gateway becomes ShareNet-eligible only when BOTH exist:
> 1. authenticated ShareNet node/link evidence;
> 2. acceptable ADCOS-backed external connectivity evidence."

and ADR-005 ("Two-Factor Gateway Admission"): *neither is sufficient alone*.
This crate is that rule as code — a policy engine that composes the evidence
domains ShareNet already owns and decides `Eligible` or `Ineligible`
(fail-closed, never a default-allow), with typed machine-named reasons and
no caller-controlled trust booleans anywhere in the API.

## The decision

```rust
let decision = GatewayAdmissionPolicy::new(AdmissionParams::new(
    freshness_window_secs, loss_ppm_floor, latency_bound_ms,
)?).decide(GatewayAdmissionRequest {
    gateway_node_id,        // the node under review — evidence must bind to it
    now_unix,               // the caller's clock (this crate has no wall clock)
    sharenet_link: Some(&signed_topology_evidence),   // factor 1 (R3-003)
    adcos_backhaul: Some(AdcosBackhaulEvidence {      // factor 2 (R5-003 + R5-004)
        health: store.health(&contract),              // the durable projection
        signed_observations: &verified_set,            // the verified-path residue
    }),
});
```

`Eligible` carries the evidence anchors (link id, observer, effective loss
ppm, p95 RTT, freshness bounds; contract, state, provider, sequence) and
`valid_until_unix` — the earlier of the two factors' freshness bounds, the
decision's own horizon. `Ineligible` carries the ordered typed reasons.

## What the policy verifies (and derives — never trusts)

**Factor 1 — the ShareNet side.** The exact `TopologyStore::receive`
verification steps, minus collection: strict parse → Ed25519 against the
embedded observer identity → link kind (advertisement evidence is not link
evidence) → subject binding (evidence about a different node never
transfers) → temporal window (not from the future; fresh strictly before
the earlier of the observer's `expires_at_unix` and the policy's
`observed_at + freshness_window_secs`). A caller that already collected
the evidence through a real `TopologyStore` passes the SAME signed record —
verification is idempotent and never trusted.

**Factor 2 — the ADCOS side.** The R5-003 projection is consumed through
its typed surface (`ContractHealth` + `ProjectionFreshness`), and the
R5-004 trust boundary ("UNSIGNED observations never enter durable ShareNet
state") is **derived** at decision time rather than trusted:

1. every supplied signed observation is parsed and Ed25519-verified — one
   broken signature poisons the set (fail-closed);
2. the verified evidence for THIS contract must be claim-consistent per
   `(provider, sequence)` — identical redeliveries are fine (expected
   provider behavior), two DIFFERENT claims at one sequence are a signed
   contradiction;
3. every entry of the projection's accepted log must be covered by a
   verified observation (same kind, `observed_at`, sequence, contract) —
   a store fed off the verified path cannot admit;
4. the verified evidence must not be AHEAD of the projection — the
   snapshot must be self-consistent (feed the store, then decide);
5. the projected state must be `Active`, and the store's typed freshness
   at the decision clock must be `Fresh`.

## The freshness authorities (one per side, no second source of truth)

| Evidence | Freshness authority |
|---|---|
| ShareNet link evidence | the observer's signed window (`expires_at_unix`) **and** the admission policy's `freshness_window_secs` (the accepting node's bound on evidence age) — effective bound = the **earlier** |
| ADCOS projection | the R5-003 store's typed `ProjectionFreshness` — the provider's window, persisted at store creation, never re-anchored (the no-fabrication law) |

The policy's `freshness_window_secs` therefore applies to the ShareNet-side
evidence age; the ADCOS side's freshness is exactly what the store reports.

## The quality floor (integer math, no floats)

- **Loss**: the effective loss ratio is the WORSE of the snapshot's signed
  `loss_ratio_ppm` and the ratio derived from its signed counters
  `lost * 1_000_000 / (delivered + lost)` (exact integer arithmetic, u128
  intermediates). An observer understating its own counters is evaluated on
  the counters — an internally inconsistent snapshot never admits. A link
  passes when `effective_ppm <= loss_ppm_floor`: the exact floor passes,
  one ppm above fails.
- **Latency**: the evidence's `p95_rtt_micros` (the tail that breaks
  interactive service) against `latency_bound_ms * 1000` (saturating) —
  compared in exact microseconds: the exact bound passes, one microsecond
  above fails.

## The reasons (typed, machine-named, ordered)

Evaluation order is fixed (ShareNet chain → ADCOS set → quality floor →
latency bound), so the same snapshot always produces the same decision.

| Variant | Machine name | Fires when |
|---|---|---|
| `ShareNetEvidenceMissing` | `sharenet_evidence_missing` | no link evidence supplied |
| `ShareNetEvidenceUnverified { cause }` | `sharenet_evidence_unverified` | parse or signature failure (typed cause carried) |
| `ShareNetEvidenceNotALink` | `sharenet_evidence_not_a_link` | advertisement-kind evidence |
| `ShareNetEvidenceWrongSubject { .. }` | `sharenet_evidence_wrong_subject` | evidence about a different node (binding) |
| `ShareNetEvidenceNotYetValid { .. }` | `sharenet_evidence_not_yet_valid` | `now < observed_at` (clock-skew/replay probe) |
| `ShareNetEvidenceStale { .. }` | `sharenet_evidence_stale` | past the effective bound (both bounds reported) |
| `AdcosEvidenceMissing` | `adcos_evidence_missing` | no bundle, untracked contract, or never-observed contract |
| `AdcosEvidenceUnverified { cause }` | `adcos_evidence_unverified` | a signed observation failed parse/signature |
| `AdcosEvidenceSequenceCollision { .. }` | `adcos_evidence_sequence_collision` | two different claims at one (provider, sequence) |
| `AdcosProjectionLogUnverified { sequence }` | `adcos_projection_log_unverified` | a log entry not covered by verified evidence (the off-the-record bypass) |
| `AdcosProjectionLagsEvidence { .. }` | `adcos_projection_lags_evidence` | verified evidence ahead of the projection |
| `AdcosContractNotActive { state }` | `adcos_contract_not_active` | projected/degraded/terminated backhaul |
| `ProjectionStale { .. }` | `projection_stale` | the store's typed freshness is `Stale` (original metadata) |
| `QualityBelowFloor { loss_ppm, floor_ppm }` | `quality_below_floor` | effective loss above the floor |
| `LatencyAboveBound { p95_rtt_micros, bound_micros }` | `latency_above_bound` | p95 above the bound (exact µs) |

## Determinism (architecture §2)

> "The routing objective is deterministic for a fixed evidence snapshot.
> Hard constraints may not be overridden by an optimizer."

`decide` is a pure function of `(AdmissionParams, GatewayAdmissionRequest)`:
no wall clock (the caller supplies `now_unix`), no I/O, no hash maps (so no
iteration-order leakage), reasons pushed in a fixed order. The same
snapshot decides identically — proven by test, including around an
interleaved different decision (the policy is stateless).

## The honest boundary

- **An `Eligible` decision is the typed INPUT to gateway selection.** It
  grants NO packet-delivery attestation and NO provider-fulfillment
  attestation (adcos.md: "ADCOS does not attest ShareNet packet delivery.
  ShareNet does not attest provider fulfillment."). It says exactly: this
  gateway's two-factor evidence is present, verified, fresh and within the
  floor at `now_unix` — nothing more.
- **One-directional link evidence.** The ShareNet-side input is ONE
  verified link evidence about the gateway. R3-003's bilateral anti-gaming
  rule (fresh evidence from BOTH endpoints) is the routing layer's concern;
  gateway selection composes it on top if it wants it.
- **No provider pinning.** Signatures verify against each observation's
  embedded provider identity, but the policy does not pin WHICH provider
  may observe a given contract (the contract→provider binding is not on
  any ShareNet wire — refs are opaque by law). A daemon wanting a pin
  pre-filters the signed set it passes in; the store's own feed path (the
  R5-002 adapter) is the primary control.
- **No registry entry.** The decision is a local typed policy output —
  never serialized, never signed, no wire object introduced.

## Layout, build, tests

```
src/params.rs     AdmissionParams (+ typed validation)
src/evidence.rs   GatewayAdmissionRequest, AdcosBackhaulEvidence
src/decision.rs   GatewayAdmission, AdmissionReason, the anchors
src/policy.rs     GatewayAdmissionPolicy (the engine + the ppm math)
tests/common/mod.rs              real-stack scaffolding (identities,
                                 evidence builders, the verified-path
                                 daemon wiring, temp stores)
tests/gateway_admission.rs       the integration composition (6 tests)
tests/gateway_admission_adversarial.rs  the attack surface (11 tests)
```

```bash
cd admission
cargo test                                   # 8 unit + 6 integration + 11 adversarial = 25
cargo check --target wasm32-unknown-unknown --lib   # platform independence (L007)
```

Dependencies: exactly two, both ShareNet — `sharenet-protocol`
(authenticated evidence + verification) and `sharenet-connectivity` (the
typed ADCOS projection). The `connectivity/` boundary itself stays
zero-dependency (ADR-001); this crate lives OUTSIDE it, in the same
composition position as `connectivity-client/`. No serde, no async
runtime, no I/O, no wall clock; `#![forbid(unsafe_code)]`.

## Known limits (honest)

- **The decision is only as good as the snapshot.** Between `now_unix` and
  the consumer's use of the decision, evidence can expire (hence
  `valid_until_unix`) and reality can change (hence R7-001 failure
  detection on the live path).
- **The policy re-verifies signatures but does not re-run the R5-004
  admission history** (per-(provider, contract) sequence monotonicity at
  ACCEPT time). Its durable residue — the store's dedup'd,
  strictly-increasing log — plus the coverage/lags/collision checks are
  what the decision derives from.
- **Provider-identity pinning and provider-contract ownership** are out of
  scope (see the honest boundary above); the caller can layer the former
  by pre-filtering the signed set.
- **Latency is p95 RTT only** — one measure, clearly documented (the tail
  that breaks interactive service). Richer SLO shapes are a selection-layer
  concern.
