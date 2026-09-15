# ShareNet Tech Lead / Orchestrator Handoff

## Mission

Build a resilient Internet bridge that lets people with usable Internet access extend connectivity to people without reliable Internet access, while enabling verifiable contribution accounting and Civic Points that can unlock priority, access and—through a later settlement layer—monetary benefits.

Primary mission proof:

```text
connected Android/Linux node
        ↓
nearby node with no Internet
        ↓
authenticated ShareNet bridge
        ↓
real HTTPS
        ↓
induced link/gateway failure
        ↓
automatic replacement
        ↓
HTTPS continues
```

## Authorities

In order:

1. spec/architecture.md
2. spec/architecture-lock.md
3. spec/adrs/*
4. spec/protocol-registry.yaml
5. spec/work-items.yaml
6. spec/roadmap.yaml
7. spec/dependency-graph.md
8. this handoff

Legacy `pectoraux/sharenet-2.0` is reference material, not authority. ADCOS Architecture 1.1 is authority for acquired external connectivity and is consumed only through ShareNet's `ConnectivityPort`.

## Roles

Architect:
- frozen architecture;
- scope/change control;
- acceptance;
- contradiction resolution;
- closure.

Tech Lead:
- worker selection;
- dependency-aware scheduling;
- integration;
- verification orchestration;
- evidence collection;
- program status.

Worker:
- implementation inside one authorized work item.

## Three-worker rule

Maximum three direct workers. Do not manufacture parallelism. Never assign two workers to the same normative interface, state machine, or security authority simultaneously.

## Scheduling loop

1. Fresh-audit `origin/main`.
2. Read roadmap and work-item registry.
3. Compute READY items from predecessor completion.
4. Remove items with authority/file conflicts.
5. Pick up to three independent items.
6. Give each worker an explicit assignment contract.
7. Review evidence when each worker finishes.
8. Integrate only after targeted verification.
9. Run aggregate verification.
10. Push.
11. Fresh-audit pushed HEAD.
12. Recompute the next READY wave.

Do not use worker count as the optimization target; minimize integration risk.

## Assignment contract

Every worker receives:

```text
WORK ITEM
OWNER
PREDECESSORS
OBJECTIVE
IN SCOPE
OUT OF SCOPE
AUTHORITY
PRODUCTION CALLER
VERIFICATION LEVEL
ADVERSARIAL CASES
DONE WHEN
```

## Mandatory worker loop

```text
fresh audit
  ↓
read relevant architecture locks / ADRs
  ↓
inspect current callers/runtime path
  ↓
implement smallest conforming change
  ↓
add adversarial tests
  ↓
wire real production caller
  ↓
run required verification
  ↓
commit
  ↓
fresh audit pushed HEAD
```

## Completion rule

Never close an item because a class, helper, mock, or passing unit test exists.

Completion requires:

```text
definition
+
implementation
+
production caller
+
actual runtime path
+
persistence where required
+
adversarial evidence
+
required verification level
+
fresh pushed-HEAD audit
```

## Verification levels

```text
DESIGNED
IMPLEMENTED
LOCALLY_VERIFIED
MULTIPROCESS_VERIFIED
REAL_NETWORK_VERIFIED
PLATFORM_VERIFIED
NORTH_STAR_VERIFIED
```

Never promote based only on lower-level tests.

## Critical dependency spine

```text
R1 + R2
  ↓
R3 authenticated topology/routing
  ↓
R4 real Internet bridge
  ↓
R7 automatic recovery
  ↓
R8 measured contribution/Civic Points
  ↓
R10 production verification
```

R5 ADCOS can progress once the typed boundary is frozen; gateway admission waits for actual ShareNet runtime evidence. R6 can begin once the data-plane contract is stable. R9 is expansion and must not delay the Android/Linux mission gate.

## Architectural boundaries

ShareNet owns:
- identity;
- authenticated links;
- topology;
- route/circuit state;
- content/P2P semantics;
- publisher trust;
- contribution evidence;
- Civic Point policy.

ADCOS owns:
- connectivity intent;
- offer/eligibility;
- ConnectivityContract;
- provider execution;
- connectivity assurance;
- connectivity settlement references.

ShareNet stores a contract reference and operational projection, never a competing contract authority.

Provider-native ADCOS semantics never enter protocol-core.

## Offline-first invariant

ADCOS outage must not disable local content, local P2P, already-authorized DTN custody, catalog validation, or already-authorized offline operations.

## Security review checklist

For every security-sensitive change ask:

1. What is authoritative?
2. Who can create it?
3. Is identity cryptographically bound?
4. Can a caller fabricate it?
5. Does it survive restart if required?
6. Is replay prevented?
7. Is failure fail-closed?
8. Is evidence portable across processes?
9. Is there a second source of truth?

Never accept caller-controlled security facts if derivation from protocol state is possible.

## Change-control rule

When a contradiction appears:

```text
STOP → identify conflicting artifacts → determine authority → update ADR/spec/registry → implement
```

Never silently modify frozen protocol semantics.

## Mission gates

### R4
Real Android/Linux Internet bridge using real DNS + HTTPS, with failure and reconnect evidence.

### R5
Real ShareNet connectivity requirement → ADCOS intent → ConnectivityContract → execution → assurance observation → gateway availability, plus proof that ShareNet remains useful while ADCOS is unavailable.

### R7
Real failure → durable revocation → authenticated replacement route → new circuit → old circuit permanently dead → traffic restored.

### R8
Civic Points derived only from verified useful-work evidence. Initial perks are priority/access; monetary settlement is a separate future boundary.

### R10
Two-process Linux, real Android, restart, failure injection, endurance, four-week simulation, competitor comparison, durable evidence.

## Worker status

```text
HEAD
WORK ITEM
FILES CHANGED
PRODUCTION CALLERS
RUNTIME PATH
PERSISTENCE IMPACT
TESTS
VERIFICATION LEVEL
OPEN RISKS
NEXT DEPENDENCY
```

## Tech Lead checkpoint

```text
HEAD:
ACTIVE WORKERS:
COMPLETED ITEMS:
BLOCKED ITEMS:
INTEGRATION CONFLICTS:
VERIFICATION:
PRODUCTION CALLERS PROVEN:
PERSISTENCE PROVEN:
REAL-NETWORK EVIDENCE:
ARCHITECT DECISIONS NEEDED:
NEXT READY WAVE:
```

## First execution

```text
Worker 1: R1-001 + R1-002
Worker 2: R2-001 + R2-003
Worker 3: idle until a non-conflicting READY item exists
```

After Wave 1:

```text
Worker 1: R1-003 + R1-004
Worker 2: R2-004
Worker 3: first newly READY non-conflicting control-plane item
```

The machine-readable schedule is `spec/roadmap.yaml` + `spec/work-items.yaml`.

## Final operating rule

Optimize for minimal scope, correct dependency ordering, independent workers, real integration, strong evidence, and zero architectural drift. A slower provable implementation is preferable to a faster implementation that only passes mocks.
