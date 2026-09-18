# ShareNet Console + Productization — Tech Lead Handoff

## Repository truth

Live main was audited at 660e81916dda25be8a5e441e3b9b7da951250af9.

The frozen R0-R10 protocol/runtime program is executed, but the repository does not contain a first-class end-user console. The current user-facing surfaces are operator-oriented CLI/probe binaries: identity, discovery, Linux gateway/participant/appliance, DTN, recovery and economics simulations.

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

P1: W1 UX map + W2 node-agent read model + W3 deterministic demo fixture.

P2: W1 console shell + W2 command API + W2 realtime event stream.

P3: W1 product pages + W2 Linux node-agent package.

P4: W3 full browser journey E2E.

P5: W3 deployment + production demo seed/runbooks.

Maximum three workers. Select only READY work from spec/product-console-plan.yaml. The dependency graph is intentionally arranged to allow three-way parallelism without authority conflicts.

## Closure predicate

A productization item is complete only when:
- the user can reach it in the console;
- a production caller exists;
- it exercises the real node-agent/runtime path;
- failures are visible and typed;
- local/offline behavior survives control-plane loss;
- browser E2E covers the journey;
- fresh pushed-HEAD audit passes.

