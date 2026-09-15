# ShareNet Agent Simulation

This is a directional agent-based Monte Carlo simulation, not a market survey and not proof of field performance.

## World

Agents are grouped into:
- Enterprise
- Medium organization
- SME
- Individual/community

Each run spans 28 days.

Variables include:
- direct Internet availability;
- gateway participation;
- user mobility;
- local-link availability;
- ADCOS gateway backhaul availability;
- peer/gateway density;
- ShareNet adaptive gateway participation;
- competitor-specific constraints.

## Competitor classes

- Direct hotspot/tethering
- pre-deployed community mesh
- satellite hotspot
- Tailscale/ZeroTier-style Internet overlay
- Briar-style offline messaging

Only the first four are compared for live Internet bridging. Briar is included to show a different capability class.

## Outputs

- fraction of offline demand served;
- 10th/90th percentile run range;
- estimated willingness to adopt ShareNet as the only bridge;
- estimated willingness to add ShareNet alongside existing connectivity.

The willingness model is synthetic utility modeling, not survey-derived.
