# ShareNet Simulation Results — 28-Day Monte Carlo

## Important interpretation

These numbers are **simulation outputs**, not observed field statistics.

The model intentionally tests whether the architecture behaves plausibly under different population density, Internet availability, gateway participation and mobility assumptions.

## Baseline live-bridge reliability

| Segment | ShareNet | Community mesh | Direct hotspot | Satellite hotspot | Tailscale/ZeroTier* |
|---|---:|---:|---:|---:|---:|
| Enterprise | 99.45% | 99.07% | 84.69% | 40.92% | 0% |
| Medium | 61.02% | 57.04% | 35.67% | 12.02% | 0% |
| SME | 28.79% | 27.52% | 18.77% | 5.35% | 0% |
| Individual | 15.69% | 15.05% | 10.52% | 2.73% | 0% |

*The overlay class does not create Internet connectivity for a user who has no underlying connection, so it is intentionally weak in this mission-specific metric.

## Key finding

ShareNet is strongest when there are enough participating gateways.

The architecture improves over one-hop hotspot sharing because it can:
- use multiple potential gateways;
- traverse multiple peers;
- adapt to failures;
- use ADCOS to improve external gateway continuity;
- use incentives to increase gateway participation.

But the simulation shows a hard truth:

> sparse communities with too few Internet-bearing gateways do not become reliable merely because a mesh protocol exists.

Gateway seeding is therefore part of the product architecture.

## Dedicated gateway sensitivity

For individual/community scenarios, adding dedicated gateways materially changes live reliability:

| Dedicated gateways | Mean live reliability |
|---:|---:|
| 1 | 23.7% |
| 2 | 41.1% |
| 3 | 53.6% |
| 4 | 63.3% |

This makes community gateway programs, sponsored gateway devices and Civic-Point incentives first-class deployment mechanisms.

## Synthetic adoption model

Estimated willingness to make ShareNet the ONLY connectivity bridge:

| Segment | ShareNet-only |
|---|---:|
| Enterprise | 2.1% |
| Medium | 16.2% |
| SME | 33.2% |
| Individual/community | 61.0% |

Estimated willingness to add ShareNet alongside existing connectivity:

| Segment | Add ShareNet |
|---|---:|
| Enterprise | 13.0% |
| Medium | 49.4% |
| SME | 69.7% |
| Individual/community | 87.5% |

Using a synthetic population mix of 20% enterprise / 30% medium / 30% SME / 20% individual:

- **ShareNet-only:** ~27.4%
- **Add ShareNet alongside existing connectivity:** ~55.8%

## Product implication

ShareNet should NOT initially position itself as:

> "replace every Internet provider."

The stronger proposition is:

> "make Internet access resilient and shareable when ordinary connectivity fails or does not reach everyone."

That positioning is consistent with the network physics and the simulation.

## Reliability targets

These are engineering targets, not measured results:

- dense enterprise/community deployment: >=99.5% live-bridge availability;
- medium deployment with gateway redundancy: >=97%;
- SME deployment with 2–3 gateways: >=90% target after deployment tuning;
- sparse individual community: prioritize eventual DTN delivery, with live-bridge reliability improving as gateway density increases.

The final SLOs must be replaced by real-device evidence after R4/R10.
