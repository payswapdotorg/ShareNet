# ShareNet Dependency Graph — Three-Worker Orchestration

## Authority

The atomic registry is `spec/work-items.yaml`. This document explains how the Tech Lead may schedule those items across at most three direct workers.

## Worker contracts

### Worker 1 — Protocol / Security
Owns:
- identity
- canonical wire formats
- capabilities and admission
- authenticated links
- topology evidence
- route commitments
- circuit/recovery state machines
- contribution proof and Civic Points protocol logic
- protocol conformance

Never owns:
- Android/Linux device adapters
- ADCOS provider APIs
- provider-native network mechanisms

### Worker 2 — Runtime / Network / Platforms
Owns:
- Android nearby transports
- Android VpnService
- Linux transport/TUN
- QUIC/TLS runtime
- ICE/TURN/MASQUE adapters
- gateway forwarding
- iOS/network platform adapters
- real-device and real-network validation

Never owns:
- route identity
- cryptographic authority
- Civic Point valuation semantics
- ADCOS contract authority

### Worker 3 — Connectivity / Content / Service Operations
Owns:
- ConnectivityPort
- ADCOS developer API integration
- contract projection and observations
- gateway/backhaul admission integration
- content addressing/transfer
- DTN queues
- service-priority consumption
- final simulation and operational evidence

Never owns:
- provider-native APIs inside protocol-core
- ShareNet cryptographic authority
- canonical Civic Point issuance rules

## Scheduling rule

At any time:

```text
READY items
   ↓
filter by predecessors COMPLETE
   ↓
filter by architecture authority conflicts
   ↓
choose at most 3
   ↓
execute independently
   ↓
worker verification
   ↓
Tech Lead integration
   ↓
fresh audit
   ↓
mark COMPLETE
```

The Tech Lead must prefer three-way parallelism only when the dependency graph proves independence. Artificially filling all three slots is forbidden.

## Critical dependency spine

```text
R1 + R2
  ↓
R3 authenticated topology/routing
  ↓
R4 real circuit/IP bridge
  ↓
R7 recovery
  ↓
R8 measured contribution/Civic Points
  ↓
R10 production verification
```

R5 (ADCOS) is a control-plane branch that can begin with the typed connectivity seam before the full bridge is finished, but gateway admission must consume the real ShareNet route/circuit and ADCOS evidence.

R6 (DTN/content) depends on real circuit/data-plane primitives, but its content-domain work may proceed in parallel with late R4 work once the required transport contract is frozen.

R9 is expansion, not a prerequisite to the Android/Linux mission gate.

## High-value parallel waves

| Wave | Worker 1 | Worker 2 | Worker 3 |
|---|---|---|---|
| 1 | R1-001, R1-002 | R2-001, R2-003 | idle until a non-conflicting task is READY |
| 2 | R1-003, R1-004 | R2-004 | idle |
| 6 | R3-004 | R4-001 | idle |
| 8 | — | R4-003, R4-004 | R5-001 |
| 9 | — | R4-006 / R4-007 | R5-002 |
| 11 | R7-001 | — | R5-005 / R6-001 |
| 12 | R7-002 | — | R6-002 / R6-003 |
| 17 | R8-001 | R9-001 | — |
| 18 | R8-002 | R9-003 | — |
| 20 | R8-003 | R9-002 | R8-004 |
| 22 | — | R10-001, R10-002 | — |
| 23 | R10-004 | R10-003 | — |

The exact machine-readable schedule is authoritative in `spec/roadmap.yaml` and `spec/work-items.yaml`.

## Integration gates

Every worker must provide:

1. files changed;
2. tests added/updated;
3. production caller(s);
4. runtime path;
5. persistence implications;
6. verification level;
7. known remaining gaps.

The Tech Lead integrates only after reviewing those seven items.

## Hard stop conditions

Stop the current work item and ask the Architect to resolve the authority if:

- a worker must alter a frozen primitive;
- two modules become competing sources of truth;
- a security property depends on caller-controlled metadata;
- the work requires a provider-native API in protocol-core;
- a test passes only through mocks while production wiring is missing;
- the implementation requires changing a predecessor's contract unexpectedly.

## Definition of implementation complete

A work item is complete only when:

    definition
      + implementation
      + production caller
      + real runtime path
      + required persistence
      + adversarial tests
      + required verification level
      + fresh audit of pushed HEAD

are all satisfied.
