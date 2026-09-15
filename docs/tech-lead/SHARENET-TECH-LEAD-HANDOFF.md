# ShareNet Tech Lead Handoff

## Mission

Build a resilient Internet bridge that lets connected people/gateways serve nearby people without reliable Internet and rewards measured useful contribution.

## Architect authority

The architect owns:
- architecture interpretation;
- scope;
- acceptance;
- change control;
- closure decisions.

The Tech Lead owns:
- worker decomposition;
- implementation sequencing;
- integration;
- test orchestration;
- evidence collection.

## Worker constraints

At most three direct workers.

Use independent tasks with minimal dependencies.

## Mandatory implementation loop

For every item:

1. fresh repository audit;
2. read the relevant architecture lock/ADR;
3. implement only the authorized scope;
4. add adversarial tests;
5. integrate real callers;
6. run verification;
7. commit;
8. fresh audit pushed HEAD.

## No false closure

Never close a work item because:
- a class exists;
- a test helper exists;
- a unit test passes;
- a mock transport passes;
- a report says implemented.

Closure requires:
- production caller;
- actual runtime path;
- required persistence;
- required verification level.

## First execution

R1 + R2 may start in parallel.

R3 follows the protocol-core identity/link boundaries.

R4 is the first critical mission gate because it proves actual Internet bridging.

R5 then turns gateway acquisition into an externalized ADCOS control-plane concern.

R6/R7 improve resilience.

R8 comes only after measured service exists.

## Mission KPI evidence

Every integration test should record:
- connection success;
- time to bridge;
- throughput;
- failure/reconnect time;
- gateway diversity;
- percentage of offline requests served;
- contributor bytes/service time;
- Civic Points issued from actual evidence.
