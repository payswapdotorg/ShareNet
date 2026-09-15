# ADR-005 — Two-Factor Gateway Admission

## Decision

A gateway needs:

1. ShareNet protocol eligibility;
2. acceptable external connectivity evidence.

Neither is sufficient alone.

## Consequence

ADCOS contract existence cannot cause a node to become a trusted ShareNet gateway. ShareNet still verifies the node, local link and forwarding behavior.
