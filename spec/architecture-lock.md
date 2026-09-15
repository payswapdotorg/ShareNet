# ShareNet Architecture Lock

The following are normative locks for the first implementation.

| ID | LOCK |
|---|---|
| L001 | ShareNet mission is resilient Internet bridging, not generic mesh/chat. |
| L002 | ADCOS is the connectivity exchange/control authority; ShareNet never becomes a second connectivity-contract authority. |
| L003 | ADCOS is outside ShareNet `reference/` and outside local data-plane `transport/`. |
| L004 | ShareNet remains functional for local/offline workloads if ADCOS is unreachable. |
| L005 | `ConnectivityContract` is an opaque external authority represented inside ShareNet by a reference/projection. |
| L006 | Provider-native APIs/SDK types cannot cross `ConnectivityPort`. |
| L007 | Protocol core is Rust and platform-independent. |
| L008 | Android/Linux are the first real-network verification targets. |
| L009 | Nearby Connections/Wi-Fi Aware/Network.framework are platform adapters, not protocol semantics. |
| L010 | QUIC/TLS 1.3 is the preferred Internet-facing transport. |
| L011 | ICE/STUN/TURN/MASQUE should be reused before custom NAT/proxy protocols are invented. |
| L012 | Relays forward opaque end-to-end tunnel traffic whenever possible. |
| L013 | Route identity is commitment-derived; caller-selected route IDs are forbidden. |
| L014 | Circuit replacement always creates fresh session identity and replay namespace. |
| L015 | Revocation is durable and authoritative; recovery cannot resurrect a revoked circuit. |
| L016 | LIVE, OPPORTUNISTIC and DTN are separate service classes with explicit semantics. |
| L017 | Content is chunked, content-addressed, integrity protected and resumable. |
| L018 | Civic Points require verifiable useful-work evidence; self-report is insufficient. |
| L019 | Civic Points can confer protocol/service perks; cash redemption is a separate settlement program. |
| L020 | No reward farming through replay, duplicate, circular or self-generated traffic. |
| L021 | Recovery state, economic state and contract projections are durable where required. |
| L022 | Every normative wire object appears in the protocol registry and cross-language conformance suite. |
| L023 | Tests are not completion evidence without production callers and required verification level. |
| L024 | Legacy `pectoraux/sharenet-2.0` is reference material, not an authority. |
| L025 | Every substantial implementation increment must be freshly audited against the repository. |
