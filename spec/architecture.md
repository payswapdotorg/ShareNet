# ShareNet Architecture — Mission-First 1.0

## 1. Mission

ShareNet's primary job is not messaging, file sharing, or generic mesh networking.

It is:

> enable people who have Internet access to reliably bridge that access to people who do not.

The system must therefore work across three service classes:

### LIVE
Interactive IP connectivity for browsing, messaging, APIs, voice/video and other ordinary Internet applications.

### OPPORTUNISTIC
A live request or object that may pause, resume and reroute as gateways/peers appear.

### DTN
Store-carry-forward delivery with explicit TTL, integrity, deduplication and delivery receipts.

Civic Points are the incentive layer that encourages the network to supply useful gateways, relay capacity and mobility.

## 2. Reliability model

ShareNet must optimize for **service success**, not merely packet-path existence.

For every service request, the control plane tracks:

- route availability;
- gateway backhaul availability;
- per-hop health;
- battery/power eligibility;
- radio availability;
- quota/cost constraints;
- observed throughput;
- packet loss and RTT;
- contribution history;
- replay/freshness evidence.

The routing objective is deterministic for a fixed evidence snapshot.

Hard constraints may not be overridden by an optimizer.

## 3. Three planes

```text
                         SHARENET
                             |
              +--------------+--------------+
              |                             |
         CONTROL PLANE                 DATA PLANE
              |                             |
     identity / discovery          local transport
     topology / routing            authenticated links
     service negotiation           QUIC tunnel
     gateway selection             packet forwarding
     recovery                      content transfer
              |
              +------ ConnectivityPort ------+
                                             |
                                            ADCOS
                                             |
                                    ConnectivityContract
                                             |
                                      provider execution
```

## 4. Ownership boundaries

### ShareNet owns

- node identity;
- authenticated link identity;
- topology evidence;
- route proposal/acceptance/commitment;
- circuit and session semantics;
- P2P local transport;
- end-to-end tunnel semantics;
- content identity/addressing;
- content propagation;
- publisher trust;
- delivery evidence;
- contribution accounting;
- Civic Points policy.

### ADCOS owns

- connectivity intent normalization;
- provider offer exchange;
- eligibility and policy for acquired connectivity;
- `ConnectivityContract`;
- provider federation;
- execution plan;
- provider execution;
- connectivity assurance;
- connectivity usage and connectivity settlement references;
- developer connectivity API.

ADCOS explicitly treats `ConnectivityContract` as the canonical durable connectivity object. ShareNet MUST hold only a contract reference and local operational projection, never a competing contract authority.

## 5. Gateway model

A gateway is a ShareNet node or gateway appliance that can provide a usable path to the Internet.

Gateway eligibility has two independent dimensions:

1. **ShareNet eligibility** — authenticated identity, measured local link capacity, relay health, policy and capacity.
2. **External connectivity** — ADCOS contract/lease plus fresh connectivity observations.

A gateway is not trusted merely because ADCOS says a contract exists. ShareNet still authenticates the node and verifies that the node is actually reachable and providing the promised service.

## 6. Connectivity boundary

The only ShareNet-to-ADCOS boundary is:

```text
ConnectivityIntent
ConnectivityOfferRef
ConnectivityContractRef
ConnectivityLeaseRef
ConnectivityObservation
ConnectivityHealth
```

The adapter is:

```text
connectivity/
    ConnectivityPort
    AdcosConnectivityProvider
    ContractProjection
    ObservationMapper
    WebhookVerifier
```

No provider-native types enter ShareNet protocol core.

## 7. Local transport strategy

### Android first

Use a transport ladder:

1. Google Nearby Connections for discovery and high-level P2P.
2. Wi-Fi Aware for direct high-throughput IP links where supported.
3. Wi-Fi Direct / local-only hotspot where appropriate.
4. BLE only for discovery/control/low-rate signaling.
5. IP/UDP transport when the platform exposes a routable local path.

### Apple

Use Network.framework with peer-to-peer Wi-Fi and Wi-Fi Aware where available. Multipeer Connectivity is legacy/deprecated and is not the forward architecture.

### Linux / gateway devices

Use native IP, Wi-Fi, Ethernet, TUN and QUIC. Linux is the preferred first real-network gateway platform because it allows deterministic control of routing and TUN interfaces.

## 8. Tunnel stack

Do not invent a new transport when a standard exists.

Recommended stack:

```text
IP application packet
    ↓
OS TUN / Packet Tunnel
    ↓
ShareNet tunnel session
    ↓
QUIC + TLS 1.3
    ↓
optional relays forwarding opaque QUIC packets
    ↓
gateway
    ↓
NAT / normal Internet routing
```

QUIC is the preferred Internet-facing transport. It provides secure multiplexed streams, congestion control and connection-level recovery.

Use ICE/STUN/TURN concepts for NAT traversal and relay fallback rather than inventing a proprietary NAT traversal mechanism.

Use MASQUE `CONNECT-IP`/`CONNECT-UDP` where it reduces bespoke gateway tunneling code and is compatible with the deployment.

## 9. Relay privacy

Relays should forward opaque end-to-end tunnel traffic whenever possible.

A relay needs enough information to forward a packet to the next hop, but it must not become an application-data authority.

This is stronger than the legacy architecture's custom per-frame cryptography when standard QUIC/TLS can supply equivalent transport security.

Custom packet cryptography is permitted only when a demonstrated protocol requirement cannot be met with a standard.

## 10. Route commitment

A route is derived from:

```text
RouteProposal
    +
authenticated RouteAcceptances
    ↓
Merkle commitment
    ↓
commitmentRoot
    ↓
routeId
```

No caller-selected authoritative route ID.

Every replacement route is genuinely new.

## 11. Recovery

Failure handling:

```text
link failure
    ↓
durable circuit invalidation
    ↓
zeroization
    ↓
recovery attempt
    ↓
fresh gateway selection
    ↓
fresh route commitment
    ↓
fresh circuit session
    ↓
verification
```

A failed circuit is never resurrected.

Recovery state is durable and bounded.

## 12. DTN/content architecture

Content is content-addressed.

Large objects are chunked and represented by a manifest/root.

Propagation uses:

- deduplication;
- integrity verification;
- TTL;
- priority;
- replication policy;
- custody/delivery evidence;
- opportunistic forwarding;
- partial transfer/resume.

The design should borrow Delay-Tolerant Networking principles and remain interoperable with BPv7 in a later adapter instead of rebuilding DTN concepts from scratch.

## 13. Civic Points

Civic Points are earned only from verified useful work.

Primary contribution classes:

- gateway Internet service;
- relay bytes delivered;
- relay availability;
- successful DTN custody/delivery;
- infrastructure service uptime;
- validated community gateway operation.

A contribution is not valid merely because a node reports it.

Evidence requires authenticated participants and durable replay-safe receipts.

The economic formula is versioned and explicit.

Civic Points may provide:

- priority in ShareNet resource scheduling;
- preferential access to shared gateways;
- fee reductions;
- sponsored connectivity;
- community rewards.

Monetary rewards are a separate settlement program. The protocol does not make Civic Points intrinsically redeemable for money.

## 14. Anti-gaming

The economics subsystem MUST prevent:

- self-relay loops;
- duplicate receipts;
- replayed deliveries;
- fabricated bytes;
- circular traffic created solely to farm points;
- Sybil multiplication of contribution.

At minimum enforce:

- bilateral/recipient acknowledgement;
- content/packet identity;
- monotonic receipt sequence;
- per-counterparty and per-time-window caps;
- anomaly detection;
- durable idempotency;
- exclusion of known self-generated traffic;
- contribution-quality weighting.

## 15. Offline-first rule

ADCOS outage does not disable:

- local content;
- local P2P transfer;
- existing valid sessions until their local/contract conditions expire;
- DTN capture and later forwarding;
- contribution evidence capture.

ADCOS absence primarily affects acquisition of NEW external connectivity.

## 16. Platform strategy

### Phase 1

Android + Linux gateways.

### Phase 2

iOS participation and Packet Tunnel Provider where platform entitlements permit.

### Phase 3

Dedicated gateway appliances/community routers.

### Phase 4

advanced external access technologies through ADCOS.

This is deliberate: the hardest mission requirement is not cryptography; it is OS-level ability to forward real Internet packets through a nearby peer.

## 17. North-star product

The user should experience:

```text
Internet available nearby?
    → connect automatically.

Primary gateway fails?
    → route moves to another gateway.

No live gateway?
    → request is queued/carries until one appears.

You help others?
    → your contribution is measured.

You contribute consistently?
    → priority/perks improve.

ADCOS fails?
    → ShareNet keeps local and already-authorized operation alive.
```

## 18. Sources informing this architecture

- ADCOS Architecture 1.1 and application model.
- IETF RFC 8445 ICE.
- IETF RFC 8656 TURN.
- IETF RFC 9001 QUIC/TLS.
- IETF RFC 9171 BPv7.
- IETF RFC 9484 MASQUE CONNECT-IP.
- Google Nearby Connections.
- Android Wi-Fi Aware.
- Android VpnService.
- Apple Network.framework / Wi-Fi Aware.
- Briar's offline store-and-forward architecture.
- Internet Society community-centered connectivity work.
