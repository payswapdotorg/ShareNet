# ShareNet User-Journey Simulation

Repository: payswapdotorg/ShareNet
HEAD: 660e81916dda25be8a5e441e3b9b7da951250af9

This is a product/navigation simulation against the implemented runtime. It is not a browser test because the repository currently has no first-class ShareNet console.

## Capability coverage

J1 No Internet -> nearby gateway -> connect:
identity, discovery, authenticated links, topology, route commitment, circuit admission, gateway admission and real Internet bridge are implemented. Missing: one user flow and node-agent projection.

J2 Share Internet:
gateway forwarding, topology/ADCOS evidence, admission, contribution receipts and valuation are implemented. Missing: user onboarding, lifecycle command and contribution dashboard.

J3 Degraded -> recovery:
failure detection, revocation, durable attempts, gateway selection, replacement circuit, backoff and concurrent recovery are implemented. Missing: realtime user-facing timeline.

J4 Content while offline:
content addressing, resumable transfer, DTN store/carry/forward, dedup/integrity/TTL and opportunistic forwarding are implemented. Missing: content queue/command UX.

J5 Civic Points:
receipts, valuation, ledger, perk consumption and anti-gaming are implemented. Missing: user balance, evidence and perk UX.

J6 Network understanding:
authenticated topology, telemetry, gateway admission and ADCOS projection are implemented. Missing: one normalized network read model.

J7 Platform readiness:
Android Nearby, Wi-Fi Aware, VpnService/JNI, iOS participant and appliance work exist with honest environment gaps. Missing: one truthful readiness surface.

J8 Control-plane outage:
architecture requires local operation to continue when ADCOS/control-plane data is unavailable. Missing: UI distinction between local truth and stale/unavailable remote information.

## Navigation conclusion

The major user capabilities exist in the runtime, but they are not discoverable as user workflows.

The missing product seam is:

Existing ShareNet runtime
 -> node-agent/read model
 -> Console API
 -> Conformance-inspired console
 -> browser-tested user journeys

The console home should answer:
1. Am I online?
2. How am I connected?
3. Is the connection healthy?
4. What is ShareNet doing for me?
5. What can I do now?

Protocol details are one level deeper, available through expandable evidence panels and export/copy actions.
