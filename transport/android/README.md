# sharenet-transport-android — R2-001 + R2-004 (quality seam)

Android Nearby Connections transport adapter for ShareNet. **Platform adapter,
not protocol semantics** (`spec/architecture-lock.md` L009, `spec/adrs/002`):
Google Nearby Connections is a standard platform primitive that ShareNet
adapts behind a clean seam. No identity, routing, circuit, content,
contribution, or cryptographic logic lives here (protocol core = Worker 1,
`reference/`).

## Module layout

```
transport/android/
  settings.gradle.kts / build.gradle.kts / gradle.properties / gradlew
  contract/   ← THE SEAM (kotlin("jvm"), ZERO Android/GMS dependencies)
    TransportEvent   — Discovered | ConnectionRequested | Connected | Disconnected(reason)
    TransportFrame   — opaque payload bytes + channel id
    TransportError   — PermissionsDenied | PlayServicesUnavailable | IllegalState |
                       ConnectionRejected | IoFailure  (NO GMS types leak here)
    NearbyTransport  — the interface every future transport implements
    ConnectionTracker— pure-Kotlin state machine (Idle→Advertising/Discovering;
                       per-endpoint REQUESTED→ACCEPTED→CONNECTED) with typed errors
  nearby/     ← the ADAPTER (com.android.library, compileSdk 35 / minSdk 26)
    NearbyApi            — facade over GMS (no GMS types in its API)
    GmsNearbyApi         — THE ONLY FILE WITH GMS TYPES (play-services-nearby 19.5.0)
    NearbyConnectionsAdapter — implements NearbyTransport over NearbyApi
    PayloadPolicy        — BYTES/STREAM routing + 8-byte channel envelope
    ShareNetTransportService — Android Service skeleton (production caller)
    FakeNearbyApi        — scripted fake of the GMS boundary (TEST SOURCES ONLY)
```

## Seams (what future work plugs into)

1. **`contract` module**: the transport seam. Wi-Fi Aware (R2-002) and any
   later transport implement the same contract types; the module compiles on
   plain JVM with an empty dependency list so seam isolation is enforced by
   the build, not by convention.
2. **`NearbyApi` facade**: the seam INSIDE the adapter. GMS types appear in
   exactly one file (`GmsNearbyApi.kt`); everything else speaks
   contract vocabulary. Verified by grep in CI-style checks
   (see "Architecture compliance" below).
3. **Quality seam (R2-004)**: `QualitySample` / `QualityReporter` /
   `QualityRecorder` in the `contract` module (pure Kotlin, zero Android
   deps). The Nearby adapter reports honest connect/disconnect timing
   through it; every future transport reports the same way.

## Quality reporting (R2-004 — honest surface)

The adapter's constructor takes a `QualityReporter` (default
`QualityReporter.NOOP`; `ShareNetTransportService` wires a real
`QualityRecorder`). It reports ONLY what the platform actually provides:

- `QualitySampleKind.CONNECT_SETUP` — initiation → platform confirmation
  (setup latency, `System.nanoTime` delta);
- `QualitySampleKind.DISCONNECT` — connected → endpoint gone (connection
  lifetime).

There is deliberately **NO RTT sample**: Google Nearby Connections exposes
no raw RTT, and fabricating one is forbidden. When a future app layer pings
over `TransportFrame`s, real RTT samples can be added (the Linux side
already measures RTT actively via the `sharenet-transport-telemetry`
prober). `stop()` clears timing state without emitting samples (it
dispatches no per-endpoint Disconnected events either). A throwing
reporter is counted (`adapter.qualityReportFailures`) and swallowed — a
hostile sink never breaks the transport.

`QualityRecorder` (pure JVM, unit-tested): bounded ring buffer
(**drop-oldest**, default capacity 256), **window-scoped duplicate
suppression** on `(channelId, seq)`, per-kind **EWMA** (α = 0.2, same
constant as the Rust `DEFAULT_EWMA_ALPHA`). Persistence: **none** —
in-memory streaming state (durable evidence capture is R8-001's concern).

## Production caller

`ShareNetTransportService` (declared in the nearby module manifest) — the
skeleton the future ShareNet Android app embeds:

```kotlin
Intent(context, ShareNetTransportService::class.java).apply {
    action = ShareNetTransportService.ACTION_START_ADVERTISING
    putExtra(ShareNetTransportService.EXTRA_ENDPOINT_NAME, "gateway-42")
}
context.startService(intent)
```

It wires Service lifecycle → adapter lifecycle on a dedicated background
thread (GMS calls block — never the main thread), translates typed
`TransportError`s into logs instead of crashes, and declares the full
permission set for current targetSdk levels (BLUETOOTH* ≤30,
BLUETOOTH_SCAN/ADVERTISE/CONNECT 31+, NEARBY_WIFI_DEVICES 33+ with
neverForLocation, legacy ACCESS_FINE_LOCATION ≤32).

## Payload policy (documented)

- **BYTES route**: payload ≤ 32 KiB (`PayloadPolicy.MAX_BYTES_PAYLOAD_BYTES`).
  Google documents no hard BYTES limit but recommends "small" payloads; 32 KiB
  is our conservative cap.
- **STREAM route**: payload > 32 KiB → routed onto a STREAM payload (never
  rejected — the tunnel layer R4-001 needs the bulk path anyway). Received
  streams are reassembled per payload id and delivered as one frame.
- **Envelope** (adapter-level framing, NOT protocol semantics): Nearby
  payloads carry no channel metadata, so every wire payload is
  `u64be channelId || payload`. Malformed envelopes are dropped and counted
  (`adapter.malformedFramesDropped`).

## Strategy tradeoffs (injectable, default P2P_CLUSTER)

| Strategy | Shape | Best for | Cost |
|---|---|---|---|
| `P2P_CLUSTER` (default) | full mesh of nearby devices | ShareNet relay/gateway clusters where several nodes stay mutually reachable | more radio chatter |
| `P2P_POINT_TO_POINT` | exactly two devices | single gateway↔client bridge, highest dedicated-link throughput | no third peer |
| `P2P_STAR` | hub-and-spoke | one gateway hub serving client spokes | hub is a local single point of failure |

## Persistence

**None.** Transient session state only: the tracker's in-memory state and
receive-side stream buffers. Nothing is written to durable storage.

## Build & test (real SDK build)

```bash
cd transport/android
export ANDROID_HOME=/path/to/sdk          # platforms;android-35, build-tools;35.0.0
./gradlew :nearby:assembleDebug :nearby:testDebugUnitTest :contract:test
```

- `:nearby:assembleDebug` builds `nearby/build/outputs/aar/nearby-debug.aar`
  against the real Android SDK + play-services-nearby 19.5.0.
- `:nearby:testDebugUnitTest` (31 tests) runs the ADAPTER LOGIC on the JVM
  against `FakeNearbyApi` — the scripted fake of the **external** GMS
  boundary (the only legitimate fake: Play services exists only on devices).
  Covered adversarial cases: play-services unavailable → typed
  `PlayServicesUnavailable` + rollback; permission denial → `PermissionsDenied`;
  double `startAdvertising` → `IllegalState`; connection request during/after
  `stop()` → dropped, no panic; disconnect mid-STREAM → cleanup + no partial
  frame; transfer failure mid-STREAM → buffer dropped, endpoint stays
  connected; oversized BYTES → STREAM routing; endpoint lost →
  `Disconnected`; rapid advertise/stop cycles → convergence; malformed
  envelope → dropped+counted; re-entrant listener (calls `stop()` from inside
  an event) → no deadlock.
- `:contract:test` (23 tests) covers the tracker state machine including a
  seeded fuzz-lite run (random op sequences converge to legal states) and
  contract-type semantics.

## Known limits (honest)

- **No on-device verification in this wave**: real GMS Nearby behavior
  (advertising, discovery, payloads over BT/Wi-Fi) requires physical devices
  with Play services — that is R4-004 (Android VpnService wave, verify level
  `real-device`). This wave verifies: unit + architecture + android build.
- `ShareNetTransportService` is a skeleton: foreground-service promotion,
  notifications, and UI wiring belong to the embedding app / later waves.
- Outbound connection initiation (`requestConnection`) is deliberately NOT in
  the contract yet — the authenticated-links layer (R3-001) decides when and
  how to initiate. This foundation handles inbound requests (accept/reject).
- The `ConnectionRequested.authenticationToken` is transport-level pairing
  evidence only — never ShareNet authentication.

## Architecture compliance (how to re-verify)

```bash
# GMS types confined to GmsNearbyApi.kt (doc-comment mentions excluded):
grep -rl "com.google.android.gms" --include="*.kt" . | grep -v build | grep -v GmsNearbyApi.kt
# contract module has ZERO Android dependencies:
grep -rl "import android\." contract/src/   # → no results
```
