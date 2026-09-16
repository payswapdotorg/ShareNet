# sharenet-transport-ios — R9-001 (iOS Network.framework participant)

iOS participant transport adapter for ShareNet. **Platform adapter, not
protocol semantics** (`spec/architecture-lock.md` L009, the Android
`transport/android` precedent): Apple Network.framework is a standard
platform primitive that ShareNet adapts behind a clean seam. No identity,
routing, circuit, content, contribution, or cryptographic logic lives here
(protocol core = Worker 1, `reference/`).

`spec/architecture.md` §16 Phase 2: *"iOS participation and Packet Tunnel
Provider where platform entitlements permit."* This wave delivers the
**participation** half; the Packet Tunnel Provider evaluation is R9-002.

## Architecture mapping

| Frozen seam (`spec/architecture.md`) | Network.framework surface |
|---|---|
| §3 control plane: identity/discovery | `NWBrowser` Bonjour browsing + `NWListener` advertising (the Android `nearby` role) |
| §3 data plane: authenticated links | `NWConnection` carrying the R3-001 handshake messages + sealed frames |
| §8 tunnel stack: the QUIC/TLS tunnel (R4-001) | rides ABOVE this transport (frames in, frames out); the tunnel's protocol logic is not re-implemented here |
| §16 Phase 2: Packet Tunnel Provider | R9-002 scope — deliberately absent |

## Module layout

```
transport/ios/
  Package.swift            ← Swift 5.9, iOS 15 / macOS 13 (see below)
  Sources/ShareNetParticipant/
    Contract/  ← THE SEAM (pure Foundation, ZERO Network.framework types)
      ParticipantTransport — the transport interface (Android NearbyTransport's
                              Swift analog; inbound accept/reject + send)
      TransportListener    — events + frames (delivered on the adapter's queue)
      TransportEvent       — discovered | connectionRequested | connected |
                              disconnected(reason)  (the Android vocabulary)
      TransportFrame       — channel id + opaque payload bytes
      TransportError      — typed, no Network.framework types leak here
      EndpointID          — opaque endpoint identity
      FrameCodec          — the 4-byte big-endian length-prefixed frame codec
                            (the cross-transport convention)
      SendWindow          — bounded in-flight send window (backpressure:
                            refuse + retry, never buffer without bound)
      ConnectionTracker   — pure-Swift state machine
                            (Idle→Advertising/Discovering; per-endpoint
                            REQUESTED→ACCEPTED→CONNECTED) with typed errors
    Link/      ← the R3-001 adapter-side handshake + frame path
      LinkHandshake        — engine seams + wire-shape documentation
                            (LinkInitiatorEngine / LinkResponderEngine /
                            LinkSession — the protocol core's presence here)
      LinkHandshakeDriver  — the msg1→msg2→msg3 sequencer (initiate /
                            respond; one overall deadline; terminal on
                            failure; FRESH engine per attempt, L014)
      LinkEnvelope         — u64be channelID || payload framing
      AuthenticatedLink    — envelope → session.seal → transport; transport →
                            session.open → envelope → sink (malformed
                            envelopes dropped+counted; session failures
                            TERMINAL, the Android nearby rule)
      FrameByteTransport   — send/receive of sealed byte frames (the seam the
                            NW adapter implements)
    Participant/ ← the ADAPTER (imports Network)
      NWParticipantTransport — the ParticipantTransport over NWBrowser +
                            NWListener/NWConnection; engine factories
                            injected (fresh engine per attempt)
      NWLinkTransport      — one NWConnection as a FrameByteTransport
                            (waitUntilReady, receive loop, send)
      BonjourBrowser       — NWBrowser wrapper (browse + endpoint mapping)
      BonjourAdvertiser    — NWListener wrapper (advertise + inbound accept)
      ParticipantConfiguration — bounds, Bonjour service identity, timeouts
  Tests/ShareNetParticipantTests/
      TestSupport            — scripted fakes of the engine seams
      ConnectionTrackerTests — the state-machine ladder + typed refusals
      FrameCodecTests       — the length-prefix codec edges
      SendWindowTests       — the backpressure window law
```

## Seams (what future work plugs into)

1. **`Contract`**: the transport seam. Any later iOS transport (or a macOS
   test harness) implements the same protocols; the module imports only
   `Foundation`, so seam isolation is enforced by the build, not by
   convention (the Android `contract` module's rule).
2. **Engine seams (`Link/LinkHandshake.swift`)**: `LinkInitiatorEngine`,
   `LinkResponderEngine`, `LinkSession` — the R3-001 protocol core's
   presence on this platform. **Production: the Rust `sharenet-protocol`
   core over Swift FFI** (the Android wave left the same JNI bridge to
   R10-002). Tests: scripted fakes. No cryptographic content is created,
   inspected, or verified in Swift — ever.
3. **`NWParticipantTransport`**: the only layer that imports
   `Network.framework`. Everything below it speaks contract vocabulary.

## Failure semantics (the frozen rules, mirrored)

- A failed handshake or session failure is **terminal for the link (L014)**:
  the driver tears the connection down; a retry is a FRESH handshake with
  fresh ephemerals (a fresh engine from the factory — never a reused one).
- A malformed channel envelope (above the crypto) is **dropped and
  counted**, never terminal — the link survives bad framing.
- `SendWindow` full → typed `sendWindowExhausted`: the caller retries;
  the adapter never buffers without bound.
- All typed errors (`TransportError`) carry machine-readable cases; no
  `Network.framework` error type crosses a seam boundary.

## Sandbox honesty (recorded gaps)

This package was authored in a Linux sandbox with **no Swift toolchain**
(`which swift` fails there). Therefore:

- **NOT compiled, NOT executed** in this environment. Building and running
  requires macOS 13+ with Xcode 15+ (or a Swift 5.9+ toolchain):
  `cd transport/ios && swift test`.
- The 32 XCTest functions (`ConnectionTracker` 14, `FrameCodec` 10,
  `SendWindow` 8) are written to run there — their results are **not
  claimed here**. No test output has been fabricated.
- The "ios" verification level of R9-001 (compile + run on iOS) is
  **honestly OUT OF SCOPE in this sandbox** and remains open until a Mac
  runner exists. The "architecture" verification level IS delivered: the
  seam/isolation mapping above + `docs/architecture/ios-participant.md`.
- macOS 13 is declared as a second platform so `swift test` can execute the
  pure-logic suite on a Mac (Network.framework exists on both); iOS 15 is
  the product floor.
- The engine seams have NO production implementation in this wave (the
  Rust-core FFI bridge is the same deferred integration the Android wave
  recorded for R10-002). Until then the package is participant scaffolding
  + the adapter layer, not a runnable node.

## Production caller

The future ShareNet iOS app (the `ShareNetParticipant` library is embedded
via SPM):

```swift
let configuration = try ParticipantConfiguration(serviceType: "_sharenet._tcp")
let transport = NWParticipantTransport(
    configuration: configuration,
    initiatorEngineFactory: { CoreFFIInitiatorEngine(nodeIdentity: id) },
    responderEngineFactory: { CoreFFIResponderEngine(nodeIdentity: id) }
)
transport.addListener(self)          // events + frames
try transport.startAdvertising(name: "iphone-42")
try transport.startDiscovery()
```

`Packet Tunnel Provider` (NEPacketTunnelProvider) is R9-002's evaluation —
deliberately not started here.
