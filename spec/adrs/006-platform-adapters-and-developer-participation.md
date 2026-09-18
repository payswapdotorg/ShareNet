# ADR-006 — Platform Adapters and Embedded Developer Participation

## Status

Accepted as a post-closure productization architecture extension.

## Context

The frozen ShareNet protocol/runtime implementation is broad, but user interaction must exist across web, desktop and mobile. ShareNet must also be embeddable into third-party applications so their users can participate without installing a separate ShareNet application.

The older `pectoraux/sharenet` repository provides useful design evidence: its UI is built behind a `src/lib/sharenet` adapter boundary, and it exposes an Android `sharenet-sdk` public entry point. However, that repository's adapter is explicitly a mock and its Android SDK factory contains stub/in-memory implementations, so neither is production authority.

Reference implementation/design source used for this decision:
https://github.com/pectoraux/ShareNet
UI inspiration:
https://sharenet-conformance.vercel.app

## Decisions

### 1. All platform experiences are adapters

The common ShareNet contract is platform-independent.

Web, Android, iOS, Linux, macOS and Windows implement adapters around the common contract. Protocol semantics remain in `reference/`; OS APIs remain in platform adapters.

### 2. The web app is primarily a control/presentation adapter

A browser cannot be treated as equivalent to a native ShareNet node. A cached/PWA shell may launch without Internet, but it cannot itself obtain Wi-Fi/BLE radio access, create a system TUN interface, or reliably run a background relay.

Therefore:

- Web = console/developer portal + embedded foreground app integration.
- Native adapter = required for true offline/no-Internet device participation.
- A web app may communicate with an already reachable local ShareNet runtime.
- The UI must explicitly explain when native participation is required.

### 3. Third-party applications use two surfaces

**Developer API:** hosted control-plane API for app registration, user authorization, device enrollment, capabilities, session orchestration, webhooks, quotas and evidence references.

**Embedded SDK:** local runtime interface used by the host application. It selects the concrete platform adapter and reaches the ShareNet node runtime.

A hosted API call alone cannot turn an arbitrary user's device into a ShareNet node.

### 4. Host-app participation is first-class

Users can participate through an application they already use:

`Host App -> ShareNet SDK -> Platform Adapter -> Node Runtime -> ShareNet Protocol`

There is no requirement to install the standalone ShareNet app.

### 5. Capability intersection is mandatory

The requested capability set is intersected with:

`Developer scopes ∩ User consent ∩ Platform capabilities ∩ Runtime policy`

The result is the only capability set that may be advertised or activated. Unsupported requests fail typed and visibly.

### 6. Data-plane authority stays local

The hosted Developer API never becomes the packet-forwarding/data-plane authority. Node identity, route, circuit, replay and durable local state remain under the existing ShareNet runtime.

## Consequences

Positive:
- third-party applications can adopt ShareNet without forcing a separate app install;
- web/desktop/mobile UX can share a common product language;
- platform limitations are surfaced honestly;
- existing frozen runtime remains the single implementation authority.

Costs:
- a stable SDK contract is required;
- developer API, enrollment and revocation become new production infrastructure;
- each platform needs a real adapter and capability matrix;
- browser limitations prevent the web adapter from replacing native offline networking.

## Forbidden shortcuts

- browser JavaScript must not claim TUN/radio access it does not possess;
- hosted API must not forward raw ShareNet packets;
- host apps must not import protocol internals;
- developer webhooks must not expose private node seeds or unrestricted network evidence;
- a capability must not be shown as available merely because the developer requested it.
