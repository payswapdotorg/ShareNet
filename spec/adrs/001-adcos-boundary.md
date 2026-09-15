# ADR-001 — ADCOS Boundary

## Decision

ADCOS is ShareNet's external connectivity acquisition/control exchange.

ShareNet consumes technology-neutral connectivity outcomes through `ConnectivityPort`.

ADCOS is not part of:
- protocol core;
- local P2P transport;
- circuit crypto;
- content distribution;
- contribution attribution.

## Rationale

ADCOS Architecture 1.1 explicitly makes `ConnectivityContract` the canonical connectivity object and keeps provider mechanisms behind provider adapters.

This lets ShareNet focus on the mission-critical bridge while inheriting a mature connectivity exchange/failover layer.

## Consequence

Gateway backhaul can be replaced or replanned without modifying ShareNet's wire protocol.
