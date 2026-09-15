# ADR-002 — Standards-First Transport Stack

## Decision

Prefer:
- Nearby Connections / Wi-Fi Aware / Network.framework for local proximity;
- QUIC + TLS 1.3 for Internet-facing transport;
- ICE/STUN/TURN for NAT traversal;
- MASQUE CONNECT-IP/CONNECT-UDP where appropriate;
- TUN/VpnService/Packet Tunnel Provider for transparent device traffic;
- BPv7-compatible DTN principles for delayed delivery.

## Rejected

A bespoke Internet transport and bespoke NAT traversal protocol.

## Consequence

ShareNet protocol complexity is concentrated in:
- identity;
- route authority;
- relay semantics;
- contribution evidence;
- recovery.

It does not duplicate mature transport primitives without need.
