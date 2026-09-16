# sharenet-transport-android-vpn — R4-004

Android `VpnService` data plane for ShareNet: the module that brings device
traffic into the tunnel. **Platform adapter, not protocol semantics**
(`spec/architecture-lock.md` L009, `spec/adrs/002`): no identity, routing,
circuit, content, or cryptographic logic lives here (protocol core = Worker 1,
`reference/`). This module speaks raw IP packets and hands them to a
`TunnelBackhaul` seam — whose production implementation arrived with R10-002:
[`JniTunnelBackhaul`](#the-jni-bridge-r10-002) over the Rust
`sharenet-android-bridge` cdylib.

## Module layout

```
transport/android/vpn/
  build.gradle.kts      ← com.android.library, compileSdk 35 / minSdk 26,
                          EMPTY production dependencies (raw IP packets, not
                          TransportFrames — nothing from :contract needed)
  src/main/kotlin/org/sharenet/transport/vpn/
    NetTypes.kt          — strict IpAddress/Cidr parsing (pure Kotlin, zero
                           deps; NO java.net.InetAddress — it accepts forms we
                           must reject and may attempt resolution)
    VpnConfig.kt         — strict total validation + PURE toBuilderParams()
    IpPacketFilter.kt    — pure-Kotlin IP sanity filter (the TUN→tunnel gate)
    PacketIo.kt          — THE fd I/O SEAM (packet-atomic blocking reads)
    PacketLoop.kt        — the production loop shape (JVM-testable)
    TunnelBackhaul.kt    — THE TUNNEL SEAM (the contract)
    BridgeNative.kt      — THE JNI SURFACE (R10-002): external funs +
                           injectable BridgeNativeLibrary
    JniTunnelBackhaul.kt — THE PRODUCTION BACKHAUL (R10-002): the seam
                           over libsharenet_bridge.so
    VpnError.kt          — typed errors (InvalidConfig(field,reason) /
                           PacketTooLarge / BackhaulFailure / IoFailure /
                           VpnNotPrepared)
    FdPacketIo.kt        — ANDROID BOUNDARY: ParcelFileDescriptor adapter
    ShareNetVpnService.kt— ANDROID BOUNDARY: the VpnService (Builder mapping,
                           loop thread, lifecycle; established interface)
  src/test/kotlin/.../   — PacketPipe (pipe-backed fd fake with 4-byte length
                           framing), FakeTunnelBackhaul (echo/scripted),
                           TestPackets (hand-built v4/v6 bytes)
```

## The pure/Android split (the whole point)

EVERYTHING testable on the JVM is extracted and unit-tested:
`VpnConfig`/`toBuilderParams`, `NetTypes`, `IpPacketFilter`, and the
`PacketLoop` (driven end-to-end over the pipe-backed `PacketIO` with an echo
backhaul). The remaining Android glue (`ShareNetVpnService`,
`FdPacketIo`) is mechanical wiring — a 1:1 Builder mapping, the fd handoff,
thread + lifecycle plumbing — and is NOT unit-testable without a device
(android.jar methods fail under the JVM unit-test runner by design).
On-device verification is R10-002 scope.

## Seams (what future work plugs into)

1. **`PacketIO`** — the fd I/O boundary. Tests drive `PacketPipe` (test
   sources); production uses `FdPacketIo`. One `readPacket` = one COMPLETE
   packet; reads block; EOF (null) = device side closed.
2. **`TunnelBackhaul`** — where an outbound packet crosses from Kotlin/JVM
   into the ShareNet tunnel. The production implementation IS R10-002's
   `JniTunnelBackhaul`: the Rust `sharenet-android-bridge` session (pinned
   QUIC tunnel + R4-002 circuit admission + the R4-003 data plane — the
   exact session the R10-001 two-process loopback proved). JVM tests use
   `FakeTunnelBackhaul` and the fake `BridgeNativeLibrary` (the external
   functions need the NDK-built .so); the android-bridge crate's host tests
   drive the REAL stack (gateway, tunnel, circuit — see its
   tests/bridge_session.rs).
3. **`configureBackhaul`** — the wiring point: the embedding app installs
   `JniTunnelBackhaul(LoadedBridgeNative, seed, gatewayAddr,
   gatewayNodeHex)` (or any other `TunnelBackhaul`) — with NO factory
   installed the service refuses to start a loop (typed log, no crash).

## Config validation (strict, total, typed)

`VpnConfig.validate()` throws `VpnError.InvalidConfig(field, reason)` on the
FIRST invalid field; no silent defaults for invalid input. The only defaults
are the documented ones: MTU 1280, no tunnel DNS, no app filter
(BLOCKLIST-empty = all apps routed). Strictness highlights:

- IPv4 literals: exactly 4 decimal octets 0..255, **no leading zeros**
  (kills the "010.0.0.1" octal ambiguity); IPv6: `::`-compressed or full
  8-group hex, at most one `::`, **no embedded IPv4 tails** (the platform
  accepts `::ffff:1.2.3.4`; we reject — spell the pure-hex form).
- Routes REQUIRE `ip/prefix` and REJECT host bits below the prefix (a dirty
  route is a config typo). Interface addresses accept bare IPs (→ /32, /128
  host routes) or CIDR.
- Duplicate detection is by PARSED value within each list (differently
  spelled literals of the same address are caught).
- Package names must be ≥2 dot-separated segments, each
  letter-started + letters/digits/underscore; an empty ALLOWLIST is rejected
  (it would route nothing).
- MTU bounded [68, 65535] (RFC 791 minimum / IPv4 total-length field).

## Packet filter policy (documented)

- **IPv4 — deep, strict**: version nibble == 4; IHL ≥ 5; total-length field
  must EQUAL the actual byte count (truncated, padded, and oversized all
  rejected — typed `TotalLengthMismatch`); protocol must be ICMP/TCP/UDP
  (others dropped, typed `ProtocolBlocked`). Check order is fixed and
  test-asserted: empty → too large → version → family-specific.
- **IPv6 — pass-through, shallow**: version nibble, complete 40-byte base
  header, payload-length consistency (40 + payload == size; zero payload
  with more bytes = claimed jumbogram → typed rejection). NO deep
  inspection: extension headers make the next-header chain
  position-dependent — protocol policy and flow keys are IPv4-only
  (documented seam; full IPv6 flow awareness is future tunnel-layer work).
- Absolute per-packet bound: 40 + 65,535 bytes (`TooLarge`).
- Best-effort `FlowKey` (src/dst/proto/ports) for logging/dedup seams,
  IPv4 only, null on anything not a valid IPv4 datagram.

## Packet loop semantics (fixed, test-asserted ORDER)

Per iteration: (1) stop flag checked FIRST; (2) read next complete packet —
EOF is a clean return, `PacketTooLarge` is counted and the loop CONTINUES
(one oversized packet must not kill the VPN), `IOException` is a typed
terminal; (3) stop flag re-checked after the read (a packet read after a
stop request is DROPPED, not forwarded); (4) filter decides — rejects are
counted, the loop survives bad input; (5) accepted packets go to the
backhaul — a throwing backhaul is a typed terminal `BackhaulFailure`
(fail closed: a half-dead VPN silently swallowing traffic is worse than a
visible dead one); (6) every response is defensively re-filtered before
being written back (a corrupted response must not inject a malformed packet
into the device).

Honest limit (pinned by a test): a loop BLOCKED inside a read cannot observe
`stop()` — the fd close is the unblock signal. The standard teardown is
`stop()` then close the fd, which `ShareNetVpnService.stopLoop()` performs
in that order.

## Production caller

`ShareNetVpnService` (manifest-declared, `BIND_VPN_SERVICE`-guarded,
exported for the system): the skeleton the future ShareNet Android app
embeds — consent (`VpnService.prepare`) belongs to the app; the service
refuses to establish without it (`VpnNotPrepared`).

```kotlin
// 1. consent, 2. skeleton wiring (JNI backhaul arrives in R10-002):
ShareNetVpnService.configureBackhaul { jniBackhaul() }
// 3. start:
context.startService(Intent(context, ShareNetVpnService::class.java).apply {
    action = ShareNetVpnService.ACTION_START
    putExtra(ShareNetVpnService.EXTRA_SESSION_NAME, "sharenet-bridge")
    putStringArrayListExtra(ShareNetVpnService.EXTRA_ADDRESSES, arrayListOf("10.111.111.2/32", "fd00::2/128"))
    putStringArrayListExtra(ShareNetVpnService.EXTRA_ROUTES, arrayListOf("0.0.0.0/0", "::/0"))
})
```

`Builder.setBlocking(true)` matches `PacketIO`'s blocking contract.
Reconfigure = stop + start (restart, not mutation). Not sticky: a restart
without an intent has no backhaul or config to resume.

## Persistence

**None.** The service keeps only the live loop, thread, and descriptor.

## Build & test (real SDK build)

```bash
cd transport/android
export ANDROID_HOME=/path/to/sdk          # platforms;android-35, build-tools;35.0.0
./gradlew :vpn:testDebugUnitTest :vpn:assembleDebug
```

- `:vpn:assembleDebug` builds `vpn/build/outputs/aar/vpn-debug.aar` against
  the real Android SDK.
- `:vpn:testDebugUnitTest` (67 tests) runs the LOGIC on the JVM: config
  validation (every malformed shape typed-rejected), the filter battery
  (hand-built IPv4/IPv6 bytes), and the production loop end-to-end over the
  pipe fake — in-order echo, malformed packets dropped while the loop
  survives, oversized consumed-and-continue, garbage backhaul responses
  re-filtered and never written, backhaul/IO failure typed terminal,
  stop-flag races (stop before run; concurrent stop; stop during blocked
  read drops the packet; re-entrant stop from inside the backhaul
  completes the current packet first), EOF clean stop.

## The JNI bridge (R10-002)

The seam's production implementation: **`transport/android-bridge`** (Rust,
`sharenet-android-bridge`) + **`JniTunnelBackhaul`** (this module).

- **Rust side**: a `GatewayClient` participant session — pinned QUIC
  tunnel (R4-001) + R4-002 circuit admission + the R4-003 data plane,
  exactly the session the R10-001 two-process loopback proved — behind
  a frozen JNI surface (`BridgeNative.nativeVersion/nativeOpen/
  nativeForward/nativeDestroy`; `BRIDGE_API_VERSION = 1`). Errors map
  to a typed `IllegalStateException`; the session fails CLOSED.
- **Kotlin side**: `JniTunnelBackhaul` implements `TunnelBackhaul` over
  the injectable `BridgeNativeLibrary` (production: `LoadedBridgeNative`
  — `System.loadLibrary("sharenet_bridge")`).
- **Verified here**: the Rust core against a REAL in-process
  `GatewayServer` with a loopback uplink echo (the crate's host tests,
  incl. wrong-pin fail-closed and destroy-then-forward fail-closed);
  the host cdylib builds with all four symbols exported (nm-verified);
  the JVM side: `JniTunnelBackhaul` construction/argument laws, forward/
  close semantics, the FULL `PacketLoop` over the bridge seam, and the
  dead-bridge fail-closed path (the fake library stands in for the .so
  only — the seam discipline).
- **The on-device runbook** (the `real-device` verify leg — no NDK or
  physical device exists in the build sandbox, honestly):
  1. Install the NDK + `cargo install cargo-ndk`.
  2. `cd transport/android-bridge && cargo ndk -t arm64-v8a -t armeabi-v7a \
     -t x86_64 -o ../android/vpn/src/main/jniLibs build --release`
  3. Build + install the embedding app
     (`./gradlew :vpn:assembleDebug` verified here; the app wires
     `ShareNetVpnService.configureBackhaul {
         JniTunnelBackhaul(LoadedBridgeNative, seed, gatewayAddr, gatewayNodeHex)
     }` with the gateway address + node id its discovery produced).
  4. Start the service (ACTION_START with the session extras); grant
     the system VPN consent; verify real traffic crossing the TUN
     through the ShareNet circuit (the R4-007 mission-gate shape now
     on a phone).

## Known limits (honest)

- **No on-device run in this sandbox**: the JNI bridge is implemented
  and host-verified (real gateway stack + symbol surface), the JVM
  side is unit-verified, but the physical-device leg (NDK cross-build,
  install, VPN consent, real radio traffic) is the operator runbook
  above — no NDK/device exists in this build sandbox. This wave
  verifies: unit + android build + host bridge tests.
- **IPv6 is pass-through-only** in the filter (see policy above).
- **IPv6 is pass-through-only** in the filter (see policy above).
- On a real fd, a packet larger than the MTU buffer is truncated by the
  kernel read; the tail is lost and the short remainder fails the filter's
  total-length check downstream — a typed drop, not a corruption (the
  `PacketTooLarge` path is what the pipe fake exercises deterministically).
