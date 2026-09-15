# ShareNet State-of-the-Art Review — September 2026

## Mission finding

The mission is best served by combining four mature ideas instead of inventing a new everything-protocol:

1. platform-native nearby connectivity;
2. standards-based NAT traversal and secure transport;
3. delay-tolerant/store-carry-forward delivery;
4. a connectivity exchange for gateway backhaul.

## Evidence

### Community connectivity

Internet Society continues to promote community-centered connectivity because many rural/underserved deployments are constrained by affordability, economics and local context rather than radio technology alone.

This validates ShareNet's gateway/incentive model, but also shows that technology alone is not enough: the deployment model matters.

### Offline P2P

Briar demonstrates that secure local communication can survive Internet loss by using Bluetooth/Wi-Fi and store-carry-forward. ShareNet extends this concept from messages into a connectivity bridge, so it must add authenticated gateways, routing, packet forwarding and contribution accounting.

### Nearby transport

Google Nearby Connections provides offline peer discovery and encrypted exchange over Bluetooth/BLE/Wi-Fi and offers Cluster, Star and Point-to-Point strategies.

Android Wi-Fi Aware provides direct high-throughput P2P networking without infrastructure.

Apple's current direction is Network.framework plus peer-to-peer Wi-Fi/Wi-Fi Aware. Multipeer Connectivity is deprecated and should not be the new architecture.

### Internet tunneling

QUIC/TLS 1.3 is preferred for Internet-facing tunnel transport.

ICE and TURN are mature standards for NAT traversal and relaying.

MASQUE CONNECT-IP and CONNECT-UDP provide standards-based IP/UDP proxying over HTTP/2/HTTP/3 and are strong candidates for restrictive networks.

Android `VpnService` provides the OS-level TUN boundary needed for general device Internet access.

### Delay-tolerant networking

BPv7 is the standard store-carry-forward foundation for stressed networks. ShareNet should adopt its design principles and provide an adapter/interoperability path rather than inventing incompatible DTN semantics.

### Existing overlay competitors

Tailscale and ZeroTier demonstrate a strong pattern:

    direct path → peer relay → central relay

and prove that transparent fallback between direct and relay connections materially improves connectivity reliability.

ShareNet's differentiation is that its relay graph can include ordinary nearby users/devices and that those contributions can be rewarded, while ADCOS manages external gateway connectivity.

## Architectural conclusion

Do NOT build:

- a custom radio stack;
- custom NAT traversal;
- custom WAN transport;
- an ADCOS clone;
- a centralized relay-only architecture;
- a messaging-only mesh.

Build a protocol that composes:

    Nearby / Wi-Fi Aware / Network.framework
        +
    QUIC / TLS 1.3
        +
    ICE / TURN / MASQUE
        +
    DTN/store-carry-forward
        +
    ADCOS connectivity contracts
        +
    verifiable contribution accounting

## Platform risk

The hardest technical constraint is OS-level forwarding, not cryptography.

Therefore real-network verification must start on:

    Android client ↔ Android peer ↔ Linux gateway

before claiming that ShareNet can provide transparent Internet access.

iOS should initially be treated as a participant/content/relay platform and promoted to full packet gateway only when Packet Tunnel Provider and peer-to-peer constraints are verified on real devices.

## Source set

- https://www.internetsociety.org/action-plan/connecting-the-unconnected/
- https://briarproject.org/how-it-works/
- https://developers.google.com/nearby/connections/overview
- https://developer.android.com/develop/connectivity/wifi/wifi-aware
- https://developer.android.com/reference/android/net/VpnService
- https://developer.apple.com/documentation/technotes/tn3213-moving-from-multipeer-connectivity-to-network-framework
- https://developer.apple.com/documentation/WiFiAware
- https://www.rfc-editor.org/rfc/rfc8445.html
- https://www.rfc-editor.org/rfc/rfc8656.html
- https://www.rfc-editor.org/rfc/rfc9001.html
- https://www.rfc-editor.org/rfc/rfc9171.html
- https://www.rfc-editor.org/rfc/rfc9484.html
- https://tailscale.com/docs/reference/device-connectivity
- https://tailscale.com/docs/features/peer-relay
- https://docs.zerotier.com/relay/
