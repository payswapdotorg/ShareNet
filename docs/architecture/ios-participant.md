# iOS Network.framework participant — architecture record (R9-001)

Work item: **R9-001 "iOS Network.framework participant"** (wave 17, gate R9,
owner W2; deps R4-001 ✓, R3-001 ✓). Verify levels: `architecture` (this
document + the code's seam discipline) and `ios` (compile/run on Apple
platforms — **honestly not executable in this Linux sandbox**; see
"Recorded gaps").

Implementation: `transport/ios/` (Swift package `ShareNetParticipant`).

## What the frozen architecture demands, and where it landed

| Frozen requirement (source) | Where it lives in `transport/ios/` |
|---|---|
| §3 control plane: discovery of nearby participants | `Participant/BonjourBrowser` over `NWBrowser` (Bonjour) — emits the contract's `discovered` events; no identity/capability semantics |
| §3 data plane: authenticated links between peers | `NWConnection` carrying the R3-001 handshake bytes + sealed frames; ALL cryptography/replay behind the `LinkSession`/engine seams |
| §6 connectivity boundary: ADCOS never enters transport | nothing in this package knows about ADCOS; the QUIC tunnel (R4-001) rides above via `TransportFrame`s |
| §8 tunnel stack | not re-implemented — frames are opaque to the adapter (channel id + payload) |
| §16 Phase 2: "iOS participation and Packet Tunnel Provider where platform entitlements permit" | participation = this wave; Packet Tunnel Provider evaluation = R9-002 (needs a real device + entitlements) |
| L009 (adapters, not protocol semantics) | `Contract/` imports only `Foundation`; `Network.framework` is imported by exactly the `Participant/` adapter layer; the engine seams carry all protocol semantics |
| L014 (a failed link is never reused) | `AuthenticatedLink` terminal-failure rule + the handshake driver's fresh-engine-per-attempt factory |

## Seam map (no second vocabulary)

The Swift types are mirrors of the established cross-platform vocabulary —
no second source of truth:

- `TransportEvent` / `TransportFrame` / `TransportError` /
  `EndpointID` / `ParticipantTransport` ↔ the Android `contract` module's
  `TransportEvent` / `TransportFrame` / `TransportError` /
  `NearbyTransport` (same machine names, same semantics, same
  accept/reject/send surface and the same "stop dispatches no per-endpoint
  Disconnected" rule).
- `ConnectionTracker` ↔ the Android `ConnectionTracker` (the same
  REQUESTED→ACCEPTED→CONNECTED ladder, typed illegal-state refusals,
  insertion-order determinism).
- `FrameCodec` ↔ the shared 4-byte big-endian length-prefix framing used
  by the Android `vpn` module's pipe and the conformance-pinned transport
  convention.
- `LinkHandshakeDriver` ↔ the flow of `reference/crates/sharenet-protocol/
  src/link.rs` (msg1 → msg2 → msg3, one overall deadline, terminal on
  failure) — the driver moves bytes; the engine seams (Rust core over FFI
  in production, scripted fakes in tests) own the cryptographic content.

## Honest scope and recorded gaps

1. **Not compiled, not executed here.** The authoring environment is a
   Linux sandbox with no Swift toolchain. `swift test` requires macOS 13+ /
   Xcode 15+. The 32 written XCTest functions have NO claimed results. The
   "ios" verification level of R9-001 is OPEN until a Mac runner executes
   the suite (tracked as the integration gap, same category as the Android
   JNI bridge being R10-002's).
2. **No production engine.** The engine seams have no FFI implementation
   this wave; until the Rust-core FFI bridge exists, the package is
   participant scaffolding + the adapter layer, not a runnable node. (The
   Android wave recorded the identical deferral for its JNI bridge.)
3. **Packet Tunnel Provider** (NEPacketTunnelProvider) is R9-002's
   evaluation and is deliberately absent.
4. The `LinkWire` constants in `Link/LinkHandshake.swift` are interface
   documentation only — never enforced twice (the core owns every law);
   this is stated in the source.

## Governance

`python3 tools/architecture_check.py` passes with this tree unchanged in
its required-authority set (no registry changes: no new wire objects —
Bonjour service types are platform discovery vocabulary, explicitly not
protocol-registry objects).
