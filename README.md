# ShareNet

**Internet bridging infrastructure for people without reliable Internet access.**

ShareNet turns nearby Internet-connected people and gateway devices into a resilient, authenticated connectivity fabric. It supports:

1. **Live bridging** — interactive Internet access through a connected gateway.
2. **Opportunistic bridging** — requests and data continue through moving peers when live paths are unavailable.
3. **Store-carry-forward** — content is securely carried until a useful connectivity opportunity appears.
4. **Measured contribution** — relay/gateway work is evidenced and converted into Civic Points.
5. **Connectivity orchestration** — ADCOS acquires and continuously assures external gateway connectivity without becoming part of ShareNet's data plane.

## Core architectural rule

ADCOS supplies **connectivity outcomes**. ShareNet supplies **connectivity protocol, routing, P2P transport, content distribution, publisher trust, contribution accounting, and application semantics**.

`ShareNet -> ConnectivityPort -> ADCOS -> ConnectivityContract -> provider execution`

never:

`ShareNet -> provider-native SDK`

## Current status

This repository is an architecture-first restart of the legacy `pectoraux/sharenet-2.0` implementation. Legacy code is reference material only; it is not authoritative.

See:
- `spec/architecture.md`
- `spec/architecture-lock.md`
- `spec/research.md`
- `spec/roadmap.yaml`
- `spec/dependency-graph.md`
- `docs/tech-lead/SHARENET-TECH-LEAD-HANDOFF.md`
- `simulation/results.md`
