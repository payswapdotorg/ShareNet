# sharenet-connectivity-client — R5-002/R5-004 (ADCOS client)

ShareNet's ADCOS wire client: the boundary adapter that implements the
[`sharenet-connectivity`] crate's `ConnectivityPort` trait against the
ADCOS developer API. Per `spec/integrations/adcos.md` ("Only the ADCOS
adapter may know the ADCOS developer API transport format"), this crate
— its `wire.rs`, `http.rs` and `transport.rs` — is the ONLY place in
ShareNet that knows what an ADCOS request or response looks like.

Since **R5-004** it is also the TRUST BOUNDARY for observations: every
assurance element must carry a `SignedConnectivityObservation`
(`reference/crates/sharenet-protocol`, the protocol registry entry) and
the client verifies it — signature, known contract, sequence gate,
freshness — before ANYTHING reaches the connectivity layer (see
[The observation trust boundary](#the-observation-trust-boundary-r5-004)).

## What it provides

| Piece | Where | What |
|---|---|---|
| `AdcosClient` | `src/client.rs` | The `ConnectivityPort` implementation: every trait call maps onto the endpoint table below, with typed error mapping, an `ObservationCache` (the parent's caller-side caching policy) for the adcos.md failure semantics, and a richer INHERENT method surface (`AdcosError`) alongside the trait surface (`PortError`) for diagnosis. R5-004: holds the protocol-core `ObservationAdmission` state (known contracts + per-(provider node_id, contract_ref) highest verified sequence) and `get_assurance`/`get_assurance_at` verify every observation before it is returned, cached or persisted. |
| HTTP/1.1 subset | `src/http.rs` | A minimal, strict request/response codec: request line + headers + Content-Length bodies, `Connection: close` (one request per connection — no keep-alive, no chunked). Hand-computed byte vectors in the unit tests. |
| Transport | `src/transport.rs` | std-TCP exchange with connect/read timeouts and a deliberate retry policy: transport failures (connect) retry; a request whose bytes were SENT is never blindly retried (a dropped POST may have been applied server-side — the safe choice); status errors surface to the caller instead of being retried semantically. |
| Wire shapes | `src/wire.rs` | The endpoint table + DTOs + the error envelope: `{"error":{"code":"<PortError machine name>", ...typed fields}}` — the parent crate's stable machine names ARE the wire error vocabulary. Code↔status pairing is enforced (a mismatch is typed `CodeStatusMismatch`). R5-004: the assurance DTO carries `signed_envelope` (hex of the signed carrying envelope) and `verify_observation_dtos` is the verification pipeline. |
| `adcos_test_server` | `src/bin/…` | **TEST SCAFFOLDING**: a real HTTP server speaking exactly this wire shape, backed by a deterministic in-memory store, with injectable fault modes (`503:N`, `drop:N`, `garbage:N`, `tamper_sig:N`, `tamper_dto:N`, `unsigned:N`). It is a SIGNING provider: a real ShareNet `Identity` (deterministic seed, `--provider-seed` to override) signs every observation it emits. |
| `projection_store_probe` | `src/bin/…` | **TEST SCAFFOLDING** (R5-003): a real separate process that loads the parent crate's durable projection store from disk (`inspect`), reports the re-derived state + typed freshness, and continues the projection (`accept` + atomic flush) — the process-boundary half of the restart verification. Machine-parsable stdout lines; typed `ERROR <machine_name>` + exit 3 on any store failure. |

## Endpoint table (the adapter's documented mapping)

| Trait method | HTTP | Path | Success body |
|---|---|---|---|
| `create_intent` | POST | `/intents` | `{"intent_ref":WireRef}` |
| `discover_offers` | GET | `/intents/{id}/offers` | `[WireRef]` |
| `accept_offer` | POST | `/intents/{id}/offers/{offer}/accept` | `{"contract_ref":WireRef}` |
| `get_contract` | GET | `/contracts/{id}` | projection fields |
| `get_assurance` | GET | `/contracts/{id}/assurance` | `[observation fields + signed_envelope]` |
| `get_execution` | GET | `/contracts/{id}/execution` | execution fields |
| `terminate` | POST | `/contracts/{id}/terminate` | `{}` |

`{id}` segments are 64 lowercase hex chars; a `WireRef` is
`{"kind":"intent|offer|contract","id":"<hex>"}` (wrong-kind refs are
typed `RefKindMismatch`, never silently re-typed).

## Boundary laws enforced

- **Never fabricate contract state during an outage**: transport,
  protocol and malformed failures all degrade to
  `PortError::ProviderUnavailable` carrying the cached-observation
  freshness bound (`ObservationCache`, the parent's policy type).
- **New acquisition blocked when unauthorized**: `AcquisitionUnauthorized`
  passes through typed.
- **Observations stay read-only**: no API mutates authoritative
  ShareNet state; the projections enforce their invariants at
  construction (an inverted validity window from the provider is a
  typed `ValidityWindowInvalid`, never a fabricated projection).
- **Only verified observations cross the boundary (R5-004)**: see below.
- **Dependencies**: `sharenet-connectivity` (the domain, zero-dependency —
  ADR-001 intact) + `sharenet-protocol` (the verification core — the
  ADAPTER may know it; the domain may not) + serde for the JSON. The
  pure-data modules compile for `wasm32-unknown-unknown` (the TCP
  transport is unix-side runtime state).

## The observation trust boundary (R5-004)

The protocol registry's `SignedConnectivityObservation` admission rule
says: *"UNSIGNED observations never enter durable ShareNet state — the
R5-003 store's trust boundary is exactly this object's verification."*
This client IS that verification:

1. **Envelope decode** — the assurance element's `signed_envelope` must
   be lowercase hex of the canonical CBOR carrying envelope
   `{1: observation, 2: signature}`; anything else is typed
   (`UnsignedObservation`, `SignedEnvelopeNotHex`, envelope parse
   errors carried as `AdcosError::Evidence(..)`).
2. **Strict statement parse** — the signed bytes parse under the full
   parse-time invariant set (frozen six kinds, sequence ≥ 1, execution
   map bounds, provider `NodeIdentity` with R1-001 node_id derivation).
3. **Wrapper agreement** — the JSON fields must agree with the SIGNED
   statement field-for-field (kind, observed_at, contract, sequence).
   The signed bytes are the truth; a rewritten wrapper is a typed
   `ObservationDisagreement`.
4. **Protocol-core admission** — Ed25519 signature against the EMBEDDED
   provider identity (self-certifying), the known-contract rule
   (an observation for an unknown contract is never a trust grant —
   contracts register on `accept_offer` or via
   `register_known_contract`, the reload seam), the per-(provider
   node_id, contract_ref) strictly-greater sequence gate, and the
   accepting node's freshness window (system clock via
   `get_assurance`, deterministic clock via `get_assurance_at`).

Verified redeliveries (sequence already seen) are still returned —
they are verified observations; dedup is the CONSUMER's policy (the
R5-003 store's `accept`, the client cache). Through the trait,
verification failures degrade to `ProviderUnavailable` (an answer that
failed verification is not a trustworthy answer); the inherent surface
keeps the typed `evidence_invalid(<machine name>)` detail.

**Honest limits**: the signature binds the observation to the provider
identity EMBEDDED in it — it does not attest ShareNet packet delivery
and does not attest provider fulfillment (adcos.md), and binding a
contract to an EXPECTED provider identity set (pinning) is daemon
policy above this crate: today the known-contract rule is the gate.
The acceptance window lives in the client's in-memory admission state
(rebuilt on restart via `register_known_contract`); the DURABLE
sequence/freshness gate is the R5-003 store's own cross-checks.

## Persistence

**None of its own** — and that is the division of labor: the client is
runtime state; the ADCOS server holds the contract truth (ADR-001).
The DURABLE local health projection is the parent crate's `store` module
(R5-003, `sharenet_connectivity::DurableProjectionStore`); this crate's
integration suite is the first place where the real client, the real test
server and that store are wired together across process restarts.

## Build and test

```bash
cd connectivity-client
cargo test    # 37 unit (codec bytes, wire shapes, error tables, verification) + 13 integration
cargo check --target wasm32-unknown-unknown
```

The integration tests run the REAL `AdcosClient` against the REAL
(signing) `adcos_test_server` process over real loopback TCP: full
lifecycle, the 503-with-cached-freshness semantics, dropped connections
(typed failure, never fabrication), garbage bodies (typed malformed on
the inherent surface), parallel clients, unknown-ref typing, and the
terminate idempotence. `tests/durable_restart.rs` (R5-003) adds the
restart battery: the real client feeds observations into the parent
crate's durable store, the ShareNet side is fully torn down and reloaded
from disk — once through the `projection_store_probe` CHILD PROCESS, once
in-process — proving state restored, staleness typed (`Fresh`/`Stale`,
original freshness metadata never re-anchored), no sequence regression
across the restart, and terminate idempotence preserved.
`tests/signed_observations.rs` (R5-004) adds the trust-boundary battery:
verified observations reach the durable store and survive the restart
(the persisted log contains ONLY verified observations, re-derived in a
child process); tampered-signature, unsigned and rewritten-wrapper
observations are typed refusals that NEVER enter the store (and the
cache); the mid-stream tamperer recovers; the freshness edges and the
known-contract rule are exercised over the real wire.

## Known limits (honest)

- The wire shape is THIS repo's documented mapping of the ADCOS
  developer API; a real ADCOS deployment may differ — the adapter is
  the only place that would change (ADR-001's whole point).
- No TLS yet (future hardening; the sandbox evidence is loopback).
- No webhook/event push — polling only, as designed for R5-002.
- No DNS: the endpoint is a socket address (documented).
- One request per connection (Connection: close) — keep-alive is a
  future optimization, not a correctness need.
- The durable-restart tests model the provider as SURVIVING the ShareNet
  restart (its state is its own concern — one server stays up across the
  epochs; the killed-provider case is covered by the 503/dead-address
  outage phase plus a reload that needs no provider at all). A real
  ADCOS provider restart is out of sandbox scope.
