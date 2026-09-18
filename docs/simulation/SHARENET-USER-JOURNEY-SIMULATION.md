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

## Second-order simulation: embedded third-party applications

The previous journey simulation covered a first-party ShareNet console. The architecture now adds a second major product surface: third-party host applications.

### DEV-001 — Developer integrates ShareNet

Developer opens web portal -> creates application -> selects scopes -> receives credentials -> installs Embedded SDK -> registers webhook -> runs a test session.

Expected backend:
app registry, environment isolation, scoped credentials, webhook verification, usage tracking, audit trail.

Expected frontend:
scope picker, platform-specific quickstart, install instructions, status/evidence, test-session result.

### DEV-002 — User joins without installing ShareNet

User opens a host application -> chooses “Use ShareNet” -> sees what the host app wants to enable -> approves -> the app enrolls this device -> ShareNet status becomes available inside the host app.

Important invariant:
there is no separate ShareNet app installation step. The host app is the product entry point.

### DEV-003 — Host app requests a connection

Host app calls the SDK -> adapter checks capabilities -> node runtime discovers/chooses a gateway -> route/circuit becomes active -> host app receives CONNECTED.

User-visible output:
Connected / degraded / recovering / offline. Protocol details remain behind a details/evidence action.

### DEV-004 — User has no normal Internet

Native host app loads local SDK/runtime state -> uses already-authorized local mesh/DTN capability -> queued or live request progresses.

Cloud Developer API may be unreachable. Local operation must continue where the frozen architecture allows it.

### DEV-005 — User contributes

Host app asks permission to participate -> adapter computes effective capability set -> user sees exactly what the platform can do -> participation starts -> useful-work evidence arrives -> points update.

Unsupported capabilities must be disabled with an explanation, not shown as selectable and later silently ignored.

### DEV-006 — Web host app with no Internet

Web app/PWA starts from cache -> checks for a locally reachable native ShareNet runtime -> if none exists, shows a clear Native ShareNet Required state.

The web app must not imply that a cached browser can independently discover nearby radios or become an Internet gateway.

### DEV-007 — Developer backend participates

Developer backend uses a server SDK/runtime -> Developer API provisions identity/scopes -> backend opens application-level ShareNet sessions.

The Developer API does not itself become the packet plane.

### DEV-008 — Revoke

User disables participation -> host app calls revoke -> server-side grant/session is revoked -> native runtime disables participation -> UI shows disabled.

### Design learning

The Conformance-inspired first-party console and the embedded SDK experience should feel like the same product:

- same state vocabulary;
- same evidence hierarchy;
- same capability terminology;
- same recovery language;
- same truthful platform restrictions.

The first-party console is the full observability/control surface. Embedded host apps receive compact task-specific components backed by the same adapter contract.

## Updated productization verdict

ShareNet now has two equally important user-facing surfaces:

1. **Direct ShareNet experience** — web/desktop/mobile console or native app.
2. **ShareNet-powered experience** — a third-party app that embeds the SDK.

The second surface was not represented in the previous plan and is now a first-class backend + frontend architecture and E2E requirement.
