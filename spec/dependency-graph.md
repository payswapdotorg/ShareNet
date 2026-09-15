# ShareNet Dependency Graph and 3-Worker Execution Model

## Worker rule

Maximum 3 direct workers.

Each work item must have one clear owner, explicit prerequisites, and a verification gate.

## Parallel lanes

### Worker 1 — Protocol Core

R1-001 → R1-004 → R3-001 → R3-004 → R4-002 → R7 → R8

Owns:
- identity
- wire formats
- route commitments
- protocol state machines
- conformance
- recovery/economics core

### Worker 2 — Runtime / Transport

R2-001/R2-002/R2-003 → R4-001/R4-003/R4-004/R4-005/R4-006 → R10

Owns:
- Android/Linux transport
- QUIC
- TUN/VpnService
- NAT traversal
- real-network verification

### Worker 3 — Connectivity / Control Plane

R5-001 → R5-005 → gateway admission → R6 → R9

Owns:
- ADCOS adapter
- contract projection
- observations
- gateway control plane
- DTN/content runtime
- later platform adapters

## Cross-worker dependencies

```text
R1
├── Worker 1 ──> R3
└── Worker 2 ──> R2

R2 + R3
    └──> R4

R4 + ADCOS boundary
    └──> R5

R4
    ├──> R6
    └──> R7

R6 + R7
    └──> R8

R4 + R5 + R7
    └──> R9

R4 + R5 + R6 + R7 + R8 + R9
    └──> R10
```

## Hard ordering rules

1. Do not implement Civic Points before measured service exists.
2. Do not call live Internet bridging complete before an Android/Linux real-device test.
3. Do not call ADCOS integration complete until ShareNet can continue local/offline operation while ADCOS is unavailable.
4. Do not call recovery complete before a real replacement route and circuit have been established.
5. Do not add a transport-specific feature to protocol-core.
6. Do not add provider-native ADCOS semantics to ShareNet.

## Verification gates

Every gate requires:

    unit
    architecture
    conformance
    integration

Higher gates additionally require:

    multiprocess
    restart
    real-device
    endurance
    adversarial

The final production gate requires real connectivity evidence, not only simulation.
