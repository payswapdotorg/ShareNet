# ShareNet Free-Tier Deployment Plan

## Current deployment audit

As of 2026-09-18, the connected Vercel account does not contain a project named ShareNet, sharenet, or sharenet-console. The ShareNet repository also has no web application or Vercel deployment configuration.

So ShareNet is not currently deployed as a user-facing application through the connected Vercel account.

## Target topology

Vercel console
  -> stateless Console API
  -> Neon Postgres for console metadata
  -> authenticated Linux node-agent
  -> existing ShareNet runtime
  -> ADCOS via ConnectivityPort

Optional Cloudflare Worker:
  edge API/rate limiting/SSE fan-out only.

The ShareNet data plane must remain on persistent Linux/Android/appliance runtimes. Never place TUN, gateway, circuit or DTN authority inside serverless functions.

## Free-tier stack

### Vercel

Current Hobby pricing is $0/month and includes automatic CI/CD and web delivery. Vercel documents Hobby as intended for personal/non-commercial use, so it is appropriate for the public prototype/demo, not as the permanent commercial production plan. See Vercel pricing: https://vercel.com/pricing.

Use:
- Next.js console
- Git-linked preview deployments
- main -> production
- Vercel-provided domain first
- zero protocol secrets in browser code

### Neon

Neon's current Free plan includes free Postgres with scale-to-zero, 50 CU-hours/month per project, 0.5 GB/project and a limited free egress allowance; verify exact limits during provisioning because provider quotas can change.

Use Neon only for console users/sessions, device display metadata, UI preferences, audit indexes, demo fixtures and deployment summaries.

Do not move protocol truth from node-local durable state into Neon.

### Cloudflare Workers

Workers Free currently allows 100,000 requests/day and 10 ms CPU per invocation. Use it only for lightweight edge/API duties where useful.

Do not put long-running ShareNet gateway state into Workers.

### Persistent Linux compute

Use a free/Always-Free VM tier for development and the public demonstration.

Oracle Cloud currently documents Always Free compute including up to two AMD E2.1.Micro instances and free Ampere A1 allocation equivalent to 2 OCPUs and 12 GB memory for eligible Always Free tenancies, subject to home-region capacity.

Google Cloud currently lists one free e2-micro Compute Engine instance/month for eligible customers.

Prefer Oracle A1 for the main development topology; keep Google e2-micro as fallback.

## Proposed demo topology

VM-1: gateway appliance
VM-2: participant/test node
VM-3: optional second gateway for recovery demonstration

The console connects to the participant/node-agent over an authenticated control API. Gateway QUIC/data-plane ports remain separate from the control API.

## Deployment waves

D1:
- create Vercel console project
- connect GitHub previews
- create Neon database
- establish preview/production environment separation

D2:
- provision Always-Free Linux VM
- install pinned ShareNet runtime
- run GatewayAppliance under systemd
- install node-agent
- expose only authenticated control API
- firewall data-plane and control-plane ports separately

D3:
- connect console to live node
- demonstrate discovery, gateway selection, live bridge, contribution, failure and automatic recovery, DTN queue and Civic Points

D4:
- add second gateway
- demonstrate recovery across nodes
- disable Console API/Neon and verify local ShareNet operation
- simulate ADCOS unavailability and expose stale/unavailable assurance honestly

## Security

Browser never receives:
- node private seeds
- provider credentials
- raw gateway command sockets
- provider-native ADCOS secrets

Use explicit device enrollment and short-lived scoped node-agent credentials.

Commands should include:
discover, connect, disconnect, share, queue-transfer, cancel-transfer, consume-perk and export-evidence.

## Free-tier guardrails

- Vercel Hobby is for non-commercial use; upgrade before commercial launch.
- Neon usage must stay within the current free allowance; avoid over-fetching and unnecessary egress.
- Cloudflare Worker usage must stay within the current free request/CPU limits.
- VM automation must detect free-tier capacity loss and fail closed rather than silently creating paid resources.
- Configure billing alerts wherever a payment method is required.
- Keep the node-agent/provider interface provider-independent.

## Deployment done means

- live console URL
- live node-agent
- real gateway
- real participant
- browser-tested live bridge
- browser-tested failure/recovery
- DTN journey
- contribution/perk journey
- evidence export
- ADCOS outage behavior
- provider quota assumptions recorded
- rollback runbook

## Embedded SDK / Developer API deployment

The hosted deployment must now expose two product planes:

1. consumer/developer web console;
2. Developer API for embedded applications and server-side integrations.

The Developer API remains a control-plane service. Actual user-device participation runs inside the host app's Embedded SDK and platform adapter.

### Hosted components

- Vercel: consumer console + developer portal.
- Stateless Console/Developer API layer: application registry, OAuth/session exchange, device enrollment, scopes, webhooks, session metadata.
- Neon: application metadata, developer accounts, scoped installations, webhook configs, UI/demo metadata. Never protocol truth.
- Cloudflare Workers: optional rate limiting/edge facade/signature verification.
- Persistent Linux VM(s): ShareNet node-agent, gateway appliance and server-side SDK/runtime when backend participation is needed.

### Native SDK distribution

- Android: AAR.
- iOS: Swift Package / native framework.
- Desktop: Rust-native runtime with language bindings appropriate to host applications.
- Web: TypeScript package for control/foreground integration only; no claim of native radio/TUN/offline mesh capabilities.

### Deployment-specific E2E

Every deployment smoke environment should exercise at least:

- browser consumer console -> live node;
- developer portal -> app registration;
- host-app fixture -> authorization -> enrollment;
- host-app fixture -> connection session;
- webhook -> signed event receipt;
- revoke -> host app disabled;
- native/desktop fixture -> local operation when hosted API is unavailable;
- web fixture -> explicit native-adapter-required state when offline with no local runtime.
