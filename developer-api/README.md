# sharenet-developer-api — C2-005 (Developer API app registry, auth, scopes and webhook model)

The MODEL layer of ShareNet's hosted Developer API (productization work
item C2-005, wave P1): the application registry, developer public-key
credentials, the scope taxonomy and decision API, the webhook
registration/delivery model with signed events, and the quota/rate-limit
policy model — implementing the normative developer contract
(`spec/developer-integration.yaml`).

## Position (the honest boundary)

**Owns** exactly the hosted-API list from
`docs/tech-lead/SHARENET-CONSOLE-IMPLEMENTATION-HANDOFF.md`: application
registration, environments, credentials, scopes, webhook registration
and signed events, quotas, and evidence-reference-shaped data.
Successors C2-006..C2-010 (Embedded SDK contract, enrollment/binding,
session API and signed-event delivery, capability intersection,
server-side participation) build on these types.

**Never owns** (architecture locks L028-L031): node private keys,
route/circuit authority, raw packet forwarding, ADCOS
ConnectivityContract authority, durable local node state. The manifest
has **zero `sharenet-*` dependencies** — no protocol-core coupling by
construction; the model operates on application-scoped data only. A
hosted API call alone never turns a browser or phone into a ShareNet
data-plane node. Deployment/serving of the hosted service is C3-005:
this crate is pure model — no I/O, no wall clock (time is a parameter),
no transport, no randomness source.

## Modules

| Module | What it is |
|---|---|
| `ids` | Registry-issued stable ids + the deterministic seed/counter id mint (SHA-256 → lower-base32). Callers never choose ids. |
| `app` | The application registry — the ROOT TRUTH of existence; environments (`dev`/`staging`/`prod`, one per kind per app); revocation is terminal, authoritative everywhere. |
| `credential` | Public-key credential model (Ed25519 public keys only — private material NEVER enters the registry), lifecycle (issue/rotate/revoke with an EXPLICIT bounded rotation overlap), single-use challenge authentication. |
| `scopes` | The 17-scope taxonomy derived one-to-one from `spec/developer-integration.yaml`'s verbs, profile gating (consumer/participant/service_backend), per-environment assignments, credential subsets (least privilege), and the TOTAL `decide_scope` API (every combination yields Allowed or a typed denial). |
| `webhook` | Registration (URL + event types + secret; https-only in prod), typed delivery records (pending/delivered/failed/expired with bounded backoff), and SIGNED events — see the signature scheme below. |
| `quota` | Fixed-window rate-limit policy model: counters, policy overrides, over/under decisions. Enforcement callers arrive in later items. |
| `lib` | The `DeveloperApi` facade composing the stores behind the cross-cutting laws: fail-closed revocation, app isolation, least privilege, exact rotation windows, and the JSON snapshot round-trip. |

## The webhook signature scheme (`sharenet-webhook-hmacsha256-v1`)

- **Algorithm**: HMAC-SHA-256 keyed with the webhook's REGISTERED secret
  (the symmetric secret the developer supplies at registration — the
  GitHub/Stripe pattern `spec/developer-integration.yaml` names via
  `signed_webhooks` + the registration contract's "secret"). Ed25519 is
  deliberately reserved for developer *authentication* (asymmetric: the
  registry holds only the public half). Same RustCrypto palette as the
  rest of the repository; no new primitives.
- **Canonicalization**: a fixed-order `\n`-joined envelope —
  `sharenet.webhook.v1`, webhook_id, event_id, event_type, occurred_at
  (decimal unix seconds), nonce (32 lowercase hex chars), then the
  payload as canonical JSON (sorted object keys, no whitespace,
  integers only — floats do not exist in the payload model, strict
  escaping). Deterministic by construction; the same event always signs
  and verifies byte-identically.
- **Timestamp + nonce**: `occurred_at` must be within ±300s (default) of
  the verifier's clock; the 16-byte nonce is unique per emitted event;
  the `ReplayGuard` records every successfully verified
  `(webhook_id, event_id)` and rejects any second presentation
  (`EventReplayed`). Verification order is fail-closed: registration
  (app-scoped — cross-app webhook ids are unknown, no oracle) →
  registration active → app active → environment active → scheme EXACT
  match → event type subscribed → timestamp window → replay guard →
  HMAC. Replay protection survives the snapshot round-trip.

## Verification (the plan's level: unit, adversarial, integration, architecture)

- **Unit** (`src/**/tests`): registry/credential/scope/webhook/quota
  logic, id minting, canonical JSON, URL policy, delivery state machine.
- **Adversarial** (`tests/adversarial.rs`) — the contract's six
  mandatory cases as real tests:
  1. forged signatures rejected (tampered payload / wrong key / bad
     scheme / burned brute-force challenges);
  2. replayed signed events rejected (guard + window, including across
     a snapshot restore);
  3. scope escalation denied at every rung (credential subset,
     assignment, profile — typed reasons, never silent upgrade);
  4. revoked credentials rejected EVERYWHERE (authentication, challenge
     issuance, scope decisions, snapshot-restored state — with a valid
     signature in hand; registry truth, not caller claims); revoked
     apps cascade to all environments/credentials/emission paths;
  5. app isolation (lists, lookups, decisions, emissions, deliveries and
     verification never cross the app boundary);
  6. rotation exactness (zero-grace kills the old key at the instant;
     bounded grace is an exact window; explicit revoke beats grace;
     re-rotating a rotating credential is refused).
- **Integration** (`tests/integration.rs`): the end-to-end registry →
  credential → authentication → signed webhook event → verification →
  delivery-outcome cycle in one process, plus the persistence
  round-trip (byte-stable snapshot, behavior continuation, fail-closed
  restore of corrupt snapshots).
- **Architecture**: the crate adds no `sharenet-*` dependency, violates
  no boundary law, and the repository governance check
  (`tools/architecture_check.py`) stays green.

## Determinism

Everything is deterministic: ids/nonces are minted from
`SHA-256(deployment_seed || kind_tag || counter)`, time is always a
parameter, and the snapshot JSON is byte-stable across round trips.
Tests use fixed seeds — `cargo test` is reproducible.
