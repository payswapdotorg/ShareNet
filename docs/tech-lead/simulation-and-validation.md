# ShareNet Validation Strategy

Simulation is useful for architecture exploration, not closure.

## Required validation ladder

1. deterministic protocol vectors;
2. unit tests;
3. architecture/import tests;
4. two-process loopback;
5. Linux real-network bridge;
6. Android real-device bridge;
7. Android gateway + Linux gateway failover;
8. 24-hour restart/endurance;
9. controlled Internet impairment;
10. multi-week field pilot.

## Production success metrics

### Connectivity
- bridge success rate;
- p50/p95 connection establishment;
- recovery time after gateway loss;
- percentage of users with no direct Internet served;
- throughput and latency.

### Reliability
- hourly live availability;
- successful reconnect rate;
- session recovery rate;
- DTN eventual-delivery probability by deadline.

### Economics
- contribution bytes;
- contribution service-time;
- verified receipt rate;
- point issuance;
- reward redemption;
- contribution concentration / fairness.

### Safety
- fabricated receipt rejection;
- replay rejection;
- sybil/anomaly detection;
- unauthorized gateway rejection;
- stale ADCOS observation rejection.

Simulation must never replace these measurements.
