# ADR-003 — LIVE, OPPORTUNISTIC and DTN Service Classes

## Decision

ShareNet exposes three explicit service classes:

LIVE:
continuous path required.

OPPORTUNISTIC:
service may suspend and resume across connectivity opportunities.

DTN:
data is queued, carried and delivered asynchronously with a deadline/TTL.

## Rationale

A mesh cannot guarantee live Internet access in sparse or highly mobile environments. Pretending otherwise creates false reliability claims.

DTN is therefore a first-class mission feature rather than an emergency afterthought.

## Consequence

Reliability metrics must distinguish live availability from eventual delivery.
