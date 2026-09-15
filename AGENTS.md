# ShareNet — Agent Governance

## Mission

ShareNet exists to let people who have Internet connectivity reliably bridge that connectivity to people who do not, using nearby devices, gateways, relays, and opportunistic store-carry-forward when live connectivity is unavailable.

The second mission is to make contribution measurable and valuable through Civic Points, which may provide non-monetary perks such as priority access and, through explicitly separate settlement programs, monetary benefits.

## Authority

The repository is the source of truth. Never trust implementation reports, commit messages, or claimed test counts without checking the actual code.

Before architecture claims or implementation:
1. inspect `origin/main`;
2. inspect specs/ADRs/registry;
3. search callers;
4. inspect tests and production wiring;
5. distinguish implementation from integration and verification.

Execution scheduling authority is `spec/work-items.yaml` + `spec/roadmap.yaml`, with the detailed orchestration rules in `docs/tech-lead/SHARENET-ORCHESTRATOR-HANDOFF.md`.

## Architecture law

Security-critical facts must be derived from authenticated protocol state, cryptographic evidence, and durable state. Never accept caller-controlled security booleans when the fact can be derived.

## Mandatory boundaries

- `reference/` is protocol authority and must remain platform/database independent.
- `connectivity/` is the boundary to ADCOS.
- `transport/` contains ShareNet transport adapters; ADCOS provider-native technology never enters this layer.
- ADCOS owns connectivity acquisition/contracts/assurance. ShareNet owns identity, routing, circuits, P2P distribution, publisher trust, contribution attribution, and Civic Points.
- ShareNet must continue local/offline operation when ADCOS is unreachable.
- No second source of truth for ADCOS `ConnectivityContract`.
- No second source of truth for ShareNet circuit terminal state.

## Worker model

Maximum three direct workers. Never force parallelism where dependencies or authority conflicts exist. Work items are atomic and dependency-declared. Every worker assignment must specify scope, predecessors, production caller, verification level, adversarial tests, and closure predicate.

## Implementation discipline

Use TDD for protocol behavior. Every substantial change requires:
architecture/spec check → implementation → adversarial tests → integration tests → fresh audit.

Never mark a capability complete because a helper or unit test exists. Completion requires a production caller and the required verification level.
