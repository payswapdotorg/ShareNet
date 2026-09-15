# sharenet-connectivity — R5-001 (ConnectivityPort) + R5-003 (durable local health projection)

ShareNet's ADCOS boundary. **This crate IS the `connectivity/` layer** named by
`spec/architecture.md` §6 and mandated by `AGENTS.md`: "`connectivity/` is the
boundary to ADCOS." It contains the technology-neutral seam through which
ShareNet acquires external connectivity outcomes — per ADR-001, *"ShareNet
consumes technology-neutral connectivity outcomes through
`ConnectivityPort`"* — and per `spec/integrations/adcos.md`: *"ShareNet MUST
NOT recreate ADCOS contract semantics."*

No protocol semantics, no transport adapters, no provider-native anything
(architecture lock L006: "Provider-native APIs/SDK types cannot cross
`ConnectivityPort`"). No dependency at all: std only, so the crate is
independently freezable from the circuit implementation (exactly what
`tools/architecture_check.py` enforces for R5-001's dependency set) and
compiles for `wasm32-unknown-unknown` (the L007 discipline of the protocol
core, applied to the boundary).

## What it provides

| Piece | Where | What |
|---|---|---|
| `ConnectivityPort` trait | `src/port.rs` | The EXACT `spec/integrations/adcos.md` interface, Rust-ified with owned types, `&self` and a typed `PortError`: `create_intent` / `discover_offers` / `accept_offer` / `get_contract` / `get_assurance` / `get_execution` / `terminate`. Implementable by an in-memory fake and by a future real ADCOS developer-API client ("the actual wire client speaks the ADCOS developer API; the domain does not import ADCOS server internals"). |
| `ConnectivityIntentRef` / `ConnectivityOfferRef` / `ConnectivityContractRef` | `src/refs.rs` | Opaque capability references: 32-byte provider-assigned ids + a typed `RefKind` tag. **NOT wire objects** — no canonical CBOR, no signatures, no derivation (boundary layer, deliberately); `from_parts` validates the kind tag so a raw offer id can never be re-typed as a contract id. |
| `ConnectivityRequirement` | `src/requirement.rs` | The intent input: versioned struct (v1) with the frozen ADR-003 service class set `{live, opportunistic, dtn}` and optional plain-`u64` max-cost / max-latency hints + bounded region hint text. |
| `ConnectivityContractProjection` | `src/projection.rs` | Read-only local projection of an ADCOS contract: state enum `Projected`/`Active`/`Degraded`/`Terminated` per the adcos.md event mapping, validity window (`valid_from_unix < valid_until_unix` **enforced at construction**), the opaque ref, freshness timestamp. NEVER a competing contract authority. |
| `ConnectivityExecutionProjection` | `src/projection.rs` | Read-only execution state: provider-reported throughput/latency as plain `u64` counters (bits/s, ms), bounded state text, freshness timestamp. |
| `ConnectivityObservation` + `ObservationKind` | `src/observation.rs` | Read-only provider events — EXACTLY the six adcos.md kinds (`contract_activated`, `execution_state_changed`, `degraded`, `assurance_available`, `failover_replan`, `terminated`) — with `observed_at_unix`, the contract ref, and a monotonic per-provider sequence number for replay ordering. |
| `ObservationCache` (+ `CachedObservation`, `AcceptOutcome`) | `src/observation.rs` | The **caching policy type** for ADCOS-unavailable periods: caches the last accepted observation per contract with freshness metadata, dedupes replayed/duplicate observations by sequence (only strictly-greater accepted), never fabricates contract state, never touches anything but its own storage. |
| `PortError` | `src/error.rs` | Typed errors with stable machine names (`name()`), following the protocol core's typed-error style. Includes the adcos.md failure semantics: `ProviderUnavailable { last_observation_fresh_until_unix }` and `AcquisitionUnauthorized`. |
| `InMemoryConnectivityPort` | `src/memory.rs` | **TEST VEHICLE** (clearly marked, like `MemoryTunPair` in `transport/linux`): deterministic fake provider — fixed virtual clock, counter-derived unique ids, stable per-intent offer sets, adcos.md event-mapping state transitions, monotonic per-provider sequences, injectable `FailureMode`s (`ProviderUnavailable` / `AcquisitionUnauthorized`), provider-redelivery affordance (`replay_observation`). No I/O, no network, no security properties. |
| `DurableProjection` + `ContractHealth` + `ProjectionFreshness` | `src/store.rs` | **R5-003 — the durable local health projection.** The pure model + strict binary codec (zero deps, hand-rolled): per contract, the accepted observation log (dedup'd by the per-provider sequence — the exact `ObservationCache` policy), the re-derived `ContractState` projection, and the ORIGINAL freshness metadata of the last accepted observation. `ProjectionFreshness` is the typed `NoObservation`/`Fresh`/`Stale` verdict — a stale reload is needs-refresh evidence, never fresh data (the no-fabrication law). |
| `DurableProjectionStore` | `src/store.rs` | The file-backed store (native only, `#[cfg(not(target_family = "wasm"))]`): `create` (never clobbers) / `load(path, now_unix)` (re-derives from the log, re-validates freshness against the caller's now, fails closed on ANY corruption) / `accept` / `flush` (atomic: temp file + fsync + rename). Single-writer by design. On wasm the pure codec is the HOST persistence seam. |

## Documented policies

- **Observations are READ-ONLY data.** *"An observation is not permitted to
  mutate ShareNet's authoritative circuit, route, identity or content state
  without independent ShareNet protocol verification"* (adcos.md). Enforced
  at the design level: no API anywhere accepts an observation as input to a
  mutating operation; the port exposes only queries plus the intent
  lifecycle; `ConnectivityObservation` and both projections are plain data
  with private fields and getters (inspect/clone only — no tamper-and-write-
  back). Proven by `projections_and_observations_are_read_only_data`.
- **No second source of truth for ADCOS `ConnectivityContract`** (AGENTS.md,
  architecture lock L002/L005). ShareNet holds only the opaque
  `ConnectivityContractRef` plus a local read-only projection; the contract
  stays ADCOS's canonical durable object. `ContractState::from_observation_kind`
  is the one place the adcos.md event mapping lives in code.
- **Failure semantics (adcos.md "Failure semantics"), as typed errors + a
  caching policy type.** When ADCOS is unavailable: `ProviderUnavailable`
  fails every trait method (queries included — no fabricated state) and
  carries the provider-side freshness bound of the last accepted
  observation; callers cache that observation with freshness metadata
  (`ObservationCache`), do NOT destroy local P2P state because of the
  outage, and continue local/DTN operation. When acquisition authorization
  cannot be established: `AcquisitionUnauthorized` blocks only
  `create_intent` / `discover_offers` / `accept_offer` — queries and
  `terminate` stay available.
- **`terminate` is idempotent** (trait contract): a second terminate is
  `Ok(())` with no new effects; further acquisition on the terminated
  contract refuses (`ContractTerminated`) while queries keep reporting the
  terminal state.
- **Refs are opaque.** Compared and echoed, never parsed. The fake's ids are
  structured (domain byte + counter, unique by construction) purely for
  debuggability; a real provider's ids are arbitrary bytes — treat both as
  opaque.
- **Dependency law.** No dependencies at all (std only): no protocol-core
  import, no async runtime, no wall clock (timestamps are caller/provider
  supplied; the fake uses a deterministic virtual clock). This keeps the
  boundary independently freezable and platform-independent — proven by
  `cargo check --target wasm32-unknown-unknown`.
- **Version discipline.** `ConnectivityRequirement` carries a version field
  validated at the port seam, so future extensions add optional fields or a
  new version — never silently reinterpret old ones.

## Seams and production callers

- The `ConnectivityPort` trait is THE seam (`spec/architecture.md` §6: the
  only ShareNet-to-ADCOS boundary). The future **R5-002 ADCOS client**
  implements it against the real ADCOS developer API and is expected to run
  the same conformance core (`tests/port_conformance.rs::conformance_core`)
  against its provider-backed instance; `InMemoryConnectivityPort` is the
  deterministic vehicle it is developed and tested against first.
- **R5-003 (contract projection)** IS this crate's `store` module — the
  durable local health projection. **R5-005 (gateway admission/backhaul
  policy)** will consume `health()`/`freshness()` together with ShareNet's
  own authenticated link/topology evidence — per adcos.md, gateway
  eligibility needs BOTH.
- Honest status: the `ConnectivityPort` trait's production caller is R5-002
  (`connectivity-client/`, delivered); the store's first production caller
  is the daemon that wires `AdcosClient::get_assurance` observations into it
  (verified end-to-end against the real client + real test server in
  `connectivity-client/tests/durable_restart.rs`); R5-004 (signed
  observations) will harden acceptance, R5-005 consumes the health.

## Persistence

**The durable local health projection** (R5-003, `src/store.rs`) — the one
piece of durable ShareNet state this crate owns, per
`spec/integrations/adcos.md`: "ShareNet stores: ConnectivityContractRef,
optional lease/reference data, signed observations, local health
projection."

- **Format**: a private, versioned, strict binary image (`SNCP` magic,
version 1, little-endian fixed-width, CRC-32/IEEE trailer, records sorted
by contract id) — hand-rolled because the crate is zero-dependency. It is
node-LOCAL durable state, NOT a protocol wire object, so the protocol
registry does not govern it; refs inside stay opaque and are reconstructed
through the kind-validated `from_parts` seam (never parsed).
- **Restart semantics**: reload re-derives every `ContractState` by folding
  the event mapping over the persisted log and cross-checks the persisted
  summary (a disagreement refuses the WHOLE store — fail-closed); freshness
  is re-validated against the caller-supplied current time and surfaces as
  the typed `ProjectionFreshness::Stale`, never as fresh data; the LAST
  ACCEPTED observation is served with its ORIGINAL freshness metadata
  (never re-anchored — the no-fabrication law); every truncation,
  single-bit flip, trailing byte, lying summary, non-monotonic sequence and
  metadata lie is a typed `StoreError` (stable machine names), and NO
  partial state is ever loaded.
- **Atomicity**: `flush` writes `<path>.tmp`, fsyncs, then renames over
  the store path — a crash leaves the old complete file, never a partial
  store; `create` refuses to clobber an existing store.
- **Platform split**: the codec + model compile on
  `wasm32-unknown-unknown`; the file-backed store is native-only — the wasm
  host persists via the same `to_bytes`/`from_bytes` seam.

## Build and test

```bash
cd connectivity
cargo test                                  # 38 unit + 12 conformance tests (50 total)
cargo check --target wasm32-unknown-unknown  # platform-independence proof (L007 discipline)
```

- `tests/port_conformance.rs` runs the trait conformance suite over the
  fake: full lifecycle (create → discover → accept → contract → observations
  in order → terminate), event-mapping state machine, determinism across
  instances, sequence monotonicity (per provider, global counter), dedup of
  replayed observations by sequence, provider-unavailable freshness
  semantics (error bound == caller cache bound), acquisition-unauthorized
  blocking scope, terminate idempotence + refusal of further acquisition,
  unknown/mismatched ref rejection, read-only-law proof.
- Inline unit tests in each module pin the type invariants (validity
  windows, ref kinds, requirement bounds, adcos.md-kind mapping, cache
  freshness semantics, fake-id uniqueness) and — in `store.rs` — the
  durable-projection invariants: canonical round trips, re-derivation ==
  live projection for the same stream, every-truncation and every-bit-flip
  fail-closed proofs, lying summary/metadata/sequence/tag/duplicate
  refusals, sequence gaps never fabricating, freshness math (exclusive
  bound, saturating window), original-metadata preservation, dedup parity
  with `ObservationCache`, atomic-flush torn-write behavior, `create`
  never clobbering, and terminal state + dedup surviving restart.
- Cross-PROCESS restart verification (the R5-003 "restart" verify level
  against the REAL ADCOS wire client + real test server) lives in
  `connectivity-client/tests/durable_restart.rs`, driven by the
  `projection_store_probe` scaffolding binary.

## Known limits (honest)

- **No real ADCOS wire client** — that is R5-002 (delivered in
  `connectivity-client/`); this crate is the boundary definition plus the
  deterministic test vehicle plus the durable projection store.
- **No provider federation** — provider-side concerns (offer ranking,
  federation, eligibility policy) stay ADCOS-side by design.
- **Observations are provider-asserted data** — no signature/authenticity
  verification exists yet (R5-004 "Signed observations"); the store only
  orders, bounds and persists them.
- The fake's single-use offers, permissive event-mapping transitions,
  fixed clock step and offer-set policies are the FAKE's documented
  policies, not claims about real ADCOS semantics — mapping real semantics
  is R5-002's job.
- `ConnectivityLeaseRef` and `ConnectivityHealth` (named in architecture §6)
  are future scope; `RefKind` is the extension point.
- **Store durability limits (honest)**: single-writer, no file locking
  (wrap in the caller's mutex); `flush` does not fsync the parent
  directory (a power loss could theoretically lose the rename — the file
  itself is fsynced); the whole image is rewritten per flush (no append
  log, no compaction/GC of old terminated contracts); the store is capped
  at `MAX_STORE_FILE_BYTES` (4 MiB); a missing file on `load` is a typed
  I/O error, not an empty store (first boot uses `create`).
