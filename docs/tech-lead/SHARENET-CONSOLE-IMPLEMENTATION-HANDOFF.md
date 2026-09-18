# ShareNet Console + Productization — Tech Lead Handoff

## Repository truth

The frozen R0-R10 protocol/runtime program is executed. This post-closure productization plan is currently staged on branch `architect/console-free-tier-productization-final`, based directly on the latest main closure `609c97147f62974ebcc73da182b29c1530c5aac1`. The PR must be merged or its exact reviewed HEAD must be adopted before implementation begins; do not silently substitute another branch.

The repository does not yet contain a first-class end-user console. The current user-facing surfaces are operator-oriented CLI/probe binaries: identity, discovery, Linux gateway/participant/appliance, DTN, recovery and economics simulations.

This is therefore a post-closure productization program. It must not reopen the frozen protocol architecture.

Authoritative plan: spec/product-console-plan.yaml.

## Design direction

The requested design is explicitly inspired by https://sharenet-conformance.vercel.app.

Use the Conformance interaction pattern: dark/high-signal operations-console visual language, persistent left navigation, compact health/status cards, search and filters, dense evidence tables, expandable detail rows, and progressive disclosure from human summary to exact protocol evidence.

The goal is ShareNet made understandable, not a protocol debugger.

Primary navigation:
Overview -> Connect -> Network -> Transfers -> Contribution -> Activity -> Diagnostics

Secondary:
Devices, Connectivity, Developer, Settings.

Users should discover outcomes rather than R1-R10 concepts. NodeId, routeId, CircuitId, signed observations, custody evidence and commitment roots remain drill-down evidence.

## User-journey simulation findings

Because no console exists in the repository, the following is a product/navigation simulation against the implemented backend capability set.

### J1: First run with no Internet

Desired path:
Overview -> No Internet -> Find nearby connection -> verified gateway -> Connect -> Active Circuit.

Existing capability coverage:
identity, advertisement/discovery, authenticated links, topology evidence, route commitment, circuit establishment, gateway admission and real Internet bridge.

Missing:
a single discovery/connect workflow, progress state, normalized gateway cards and a node-agent API.

### J2: Share my Internet

Desired:
Overview -> Share connectivity -> prerequisites/admission -> active contribution -> Civic Points.

Existing:
gateway forwarding, topology evidence, ADCOS connectivity evidence, admission, contribution receipts and valuation.

Missing:
safe user-facing enable/disable workflow and a contribution read model.

### J3: Connection degradation and recovery

Desired:
Healthy -> Degraded -> Link Down -> Recovering -> Recovered.

Existing:
failure detector, revocation, durable recovery attempts, alternate gateway selection, replacement circuit, retry/backoff and concurrent recovery.

Missing:
human-readable recovery timeline and realtime event projection.

### J4: Send content when live Internet is unavailable

Desired:
Transfers -> Live / Opportunistic / Store & Carry -> queue -> custody/forwarding -> delivered/expired.

Existing:
content addressing, resumable transfer, DTN store-carry-forward, integrity/dedup/TTL and opportunistic forwarding.

Missing:
content command surface, queue management and user-visible custody state.

### J5: Earn and use Civic Points

Desired:
Contribution -> Evidence -> Valuation -> Balance -> Perks -> Spend.

Existing:
signed contribution evidence, valuation, ledger, exactly-once perk consumption and anti-gaming.

Missing:
balance/history/evidence/perk UX and commands.

### J6: Understand the network

Desired:
Network -> nodes -> links -> quality -> gateways -> routes -> recovery -> connectivity evidence.

Missing:
a normalized network read model that joins already-implemented subsystems.

### J7: Platform readiness

The UI must show Android/iOS capability and hardware/environment gaps honestly. Device-gated work must never appear falsely green.

### J8: ADCOS/cloud outage

The console must distinguish local node truth from unavailable remote control-plane data. Local P2P, DTN and already-authorized operations must remain usable.

## Architecture boundary

Implement:

Console -> Console API -> Node Agent -> existing ShareNet runtime/protocol seams

Do not allow the console to talk directly to reference/, raw runtime files or provider-native ADCOS APIs.

The console is never authoritative for protocol identity, routes, circuits, recovery state or ConnectivityContract.

## Three workers

### Worker 1 — Experience / Console

Own console/, navigation, all user-facing pages, accessibility and browser E2E against the frozen API contract.

Never owns protocol semantics, cryptographic authority, ADCOS authority or node persistence.

### Worker 2 — Node Agent / Control Surface

Own node-agent/, normalized read model, typed idempotent commands, realtime events, Linux packaging and supervision.

Reuse existing production runtime paths; do not create a second routing, recovery, DTN, economics or gateway implementation.

### Worker 3 — Integration / Demo / Deployment

Own deterministic demo fixture, browser journey harness, free-tier deployment, smoke tests, demo seed, observability and operator runbooks.

Do not move protocol authority into hosted infrastructure.

## Execution waves

The authoritative machine-readable schedule is `spec/product-console-plan.yaml`. It is deliberately stricter than the earlier six-wave sketch: every predecessor is completed in an earlier wave and no wave contains more than three items.

| Wave | Concurrent assignments |
|---|---|
| P1 | C1-001, C2-001, C2-005 |
| P2 | C1-002, C2-002, C2-003 |
| P3 | C1-003, C1-004, C2-006 |
| P4 | C2-004, C3-001, C3-002 |
| P5 | C2-007, C1-006 |
| P6 | C2-009, C1-005, C2-008 |
| P7 | C3-003, C2-010 |
| P8 | C3-004 |
| P9 | C3-005 |
| P10 | C3-006 |

The Tech Lead must never schedule a work item before every declared predecessor is complete. Empty worker slots are acceptable; dependency independence outranks artificial utilization. Select only READY work from `spec/product-console-plan.yaml`.

## Closure predicate

A productization item is complete only when:
- the user can reach it in the console;
- a production caller exists;
- it exercises the real node-agent/runtime path;
- failures are visible and typed;
- local/offline behavior survives control-plane loss;
- browser E2E covers the journey;
- fresh pushed-HEAD audit passes.

## New architectural requirement: platform adapters

The platform layer is now explicitly adapter-driven.

The product contract is:

`Host App -> ShareNet Embedded SDK -> Platform Adapter -> Node Agent/Runtime -> existing ShareNet protocol`

The hosted console is itself a web experience/control adapter. It is not the data-plane runtime.

### Web

Use the web adapter for:

- consumer console;
- developer portal;
- host-app web integration;
- foreground content/application sessions;
- status, diagnostics and evidence.

Do NOT advertise web as a standalone offline mesh node. A cached/PWA shell can open without Internet, but without a locally reachable native ShareNet runtime it cannot obtain Wi-Fi/BLE/Wi-Fi Aware/TUN capabilities or provide reliable background relay.

### Native

Android, iOS, Linux, macOS and Windows implementations are platform adapters around the same Embedded SDK contract. Their advertised capabilities must be runtime-derived and intersected with:

`developer scopes ∩ user consent ∩ platform capability ∩ runtime policy`

The adapter must fail closed on unsupported capabilities.

## New architectural requirement: embedded third-party participation

Third-party applications are now a first-class ShareNet integration surface.

The user does **not** need a separate ShareNet app when the host application embeds the SDK.

There are two distinct developer surfaces:

### Hosted Developer API

Owns:
- app registration;
- environments;
- credentials;
- scopes;
- user authorization/session exchange;
- device enrollment;
- host-app/node binding;
- webhook registration and signed events;
- application-level session APIs;
- quotas/rate limits;
- evidence references.

It does NOT own:
- node private keys;
- route/circuit authority;
- raw packet forwarding;
- ConnectivityContract authority;
- durable node state.

### Embedded SDK

Owns local:
- node lifecycle;
- identity enrollment;
- capability negotiation;
- connectivity requests;
- transfer requests;
- contribution participation;
- status/events;
- local/offline behavior.

## Developer/frontend journey requirements

The implementation must cover all of these as complete end-to-end journeys:

### DEV-001 — Developer integration

Developer Portal -> Create app -> Choose scopes -> Create environment -> credentials -> SDK quickstart -> webhook verification -> first test session.

### DEV-002 — User opts in inside an existing app

Host App -> “Use ShareNet” -> explain participation -> user consent -> capability preview -> device enrollment -> active.

There must be no ShareNet-app installation requirement.

### DEV-003 — Host app requests resilient connectivity

Host App -> ShareNetConnectControl -> capability check -> discovery -> gateway selection -> live circuit -> Connected.

The host app sees human-level state, not route/circuit construction internals.

### DEV-004 — Host app survives loss of normal Internet

Native Host App -> local runtime -> existing peer/gateway/DTN capabilities -> delivery/recovery.

The cloud Developer API is optional once local authorization/runtime state exists.

### DEV-005 — User contributes from the host app

Host App -> ParticipationConsent -> platform capability check -> sharing enabled -> verified useful work -> contribution receipt -> Civic Points.

No self-reporting.

### DEV-006 — Host app observes recovery

Host App -> Degraded -> Recovering -> Gateway changed -> Recovered.

Events are emitted by the node runtime, not synthesized by UI.

### DEV-007 — Developer observes its users

Developer Portal -> sessions -> status -> signed event/webhook -> evidence reference.

The developer gets application-scoped observability, not private node secrets.

### DEV-008 — User revokes participation

Host App -> disable/revoke -> session/device grant revoked -> runtime stops the relevant participation -> state becomes disabled.

### DEV-009 — Web offline limitation

Cached Web UI -> local-node discovery only if a native runtime is reachable -> otherwise explain that native adapter participation is required.

### DEV-010 — Backend/service participation

Developer backend -> Developer API -> provision/authorize server runtime -> service session -> application-level events.

A cloud API call alone is never treated as a substitute for a ShareNet-compatible data-plane runtime.

## Reference implementation source

The older design repository was explicitly audited:

https://github.com/pectoraux/ShareNet

Useful patterns to preserve conceptually:
- the `src/lib/sharenet/*` UI adapter boundary;
- Conformance-style network/path/evidence UX;
- `android/sharenet-sdk` as the intent for a single public application entry point.

Do not copy its explicit prototype limitations into the new implementation. Its current UI uses a mock adapter, and its Android SDK factory contains stub/in-memory production wiring. Those are design-history inputs only, not implementation truth.

## Worker ownership

### W1 — Console + host-app UX

Owns:
- console;
- developer portal UI;
- embedded host-app UI components;
- consent/capability screens;
- connection/recovery/transfer/contribution UI;
- accessibility;
- browser E2E.

### W2 — Runtime + Developer API + SDK contract

Owns:
- node-agent;
- normalized read model;
- command API;
- realtime events;
- developer application registry/auth/scopes;
- user/device enrollment;
- host-app/node binding;
- revocation;
- webhooks;
- common Embedded SDK contract;
- capability intersection enforcement;
- server-side developer participation surface.

### W3 — Platform adapters + integration + deployment

Owns:
- web adapter restrictions;
- native adapter conformity harness;
- Android/iOS/desktop adapter integration against the common SDK;
- deterministic fixtures;
- cross-platform E2E;
- Vercel/Neon/free-tier deployment;
- SDK quickstarts;
- production demo.

No worker may change frozen protocol semantics to make an adapter easier to implement.

## CI takeover gate

The repository's ShareNet Architecture Governance workflow is a mandatory takeover gate. The Tech Lead must not merge implementation work while this gate is failing. Every meaningful productization increment must leave the pushed HEAD passing the repository checker and its fresh integration/audit requirements.
