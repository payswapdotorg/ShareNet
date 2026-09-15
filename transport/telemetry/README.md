# sharenet-transport-telemetry — R2-004

ShareNet transport quality telemetry: the **measurement layer** over the
Wave 1 transports — active RTT probes, throughput sampling, loss estimation,
and a typed **LinkQuality** evidence stream. These are the raw measurements
the architecture's reliability model consumes (`spec/architecture.md` §2:
"route availability, per-hop health, observed throughput, packet loss and
RTT").

**Measurement only.** No routing decisions, no policy, no gateway admission
— those are R3-* and R5-005 scope. Per `spec/architecture-lock.md` **L009**
this crate holds no ShareNet protocol semantics (no identity, no link
authentication, no routing state, no cryptographic authority), and the
telemetry types are **transport-internal, NOT registered wire objects**
(they do not appear in `spec/protocol-registry.yaml` and must never claim
wire authority).

## Layout

| Piece | Where | What |
|---|---|---|
| `LinkQualitySample` | `src/sample.rs` | The raw evidence unit: `{channel_id, seq, sent_at_unix_nanos, rtt_micros, payload_bytes, lost}` — plain data with constructors/accessors. `channel_id` is the adapter-level envelope channel id from Wave 1 (`u64`; `0` on a channel-less raw UDP transport). |
| `LinkQualityStream` | `src/sample.rs` | Bounded, thread-safe evidence window (`Mutex<VecDeque>`; **drop-oldest** overflow policy — routing wants current conditions; lock poisoning recovered, documented). |
| `summarize` / `LinkQualitySummary` | `src/stats.rs` | Pure, **deterministic** window statistics: EWMA RTT (α=0.2 default), MAD jitter, p50/p95 order statistics with linear interpolation, loss ratio, throughput estimate. |
| `Prober` / `FrameTransport` | `src/probe.rs` | The active prober: stop-and-wait ping/pong with 64-bit correlation ids, per-attempt timeouts, optional retries, fixed-cadence pacing; generic over the transport seam. |
| `TelemetryError` | `src/error.rs` | Typed errors — no raw OS errors leak. |
| `telemetry_echo_child` | `src/bin/…` | Tiny in-crate echo responder for the two-process integration tests (TEST SCAFFOLDING, clearly marked; std-only, speaks the documented Wave 1 frame format). |

## Documented policies (the short version — details in module docs)

- **Empty window** → typed error `EmptyWindow` (never a plausible zero
  summary). A window where every probe was lost IS valid evidence:
  `loss_ratio = 1.0`, RTT fields `0` (check `delivered > 0`).
- **Out-of-order input**: `summarize` sorts stably by `seq` first —
  summaries are identical regardless of insertion order.
- **Duplicate seqs**: deduped; if both a lost and a delivered variant share
  a seq, the **delivered** one wins (a pong did come back).
- **Clock skew**: a DELIVERED sample with `rtt_micros == 0` (pong at or
  before ping) is rejected with the typed error `ClockSkew { seq }` — never
  silently clamped. Negative RTT is unrepresentable: RTT is measured from a
  single local monotonic clock, so cross-host skew cannot enter.
- **EWMA**: `ewma_i = α·x_i + (1−α)·ewma_(i−1)` over delivered samples in
  **seq order**; the final value is a convex combination of the RTTs, so a
  single outlier shifts it by at most `α·(outlier − current)` (20% of the
  gap at the default α) and decays geometrically. Tested exactly.
- **Lost samples** count in `loss_ratio` and are excluded from all RTT
  statistics; their payload bytes are excluded from throughput.
- **Throughput** is the observed delivered-payload rate of the probe
  traffic over the window (`8·bytes/time`), honestly NOT a link-capacity
  measurement (capacity needs bulk transfer — future tunnel-layer work).
- **Prober robustness**: stop-and-wait (one outstanding correlation id);
  late/duplicate pongs counted (`late_pongs`) and ignored; foreign frames
  and malformed/oversized datagrams counted and ignored (no panic, no
  abort); K consecutive losses just record K lost samples; retries re-send
  the SAME correlation id (default `retries = 0`: a re-sent probe measures
  retransmission behavior, not clean loss); a dead send path aborts with a
  typed error (nothing left to measure).

## Dependency direction (why the prober is generic)

The prober drives the Wave 1 transports through the small `FrameTransport`
seam defined HERE, and the concrete implementation for
`sharenet_transport_linux::UdpTransport` lives in the **linux crate**
(`telemetry_bridge` module), because cargo forbids the package cycle that a
concrete-type prober here would require — the linux binary (the production
`probe-rtt` caller) must depend on this crate. This crate dev-depends on
the linux crate so its TESTS run the prober over the REAL `UdpTransport`
(real sockets, real syscalls) — the same dev-cycle shape as
serde/serde_json.

## Probe frame (transport-internal, NOT a registered wire object)

```text
probe payload :=
  0..2   magic        [0x53, 0x4E]  ("SN")
  2      kind         u8  (1 = ping, 2 = pong)
  3..11  correlation  u64be
  11..19 seq          u64be
  19..   zero padding to the configured payload size
```

It rides as the payload of the underlying transport's own framing (Wave 1
length-prefixed UDP frames on Linux; the `u64be channelId` envelope on
Android) — the prober reuses the transport's frame codec, it does not add a
second framing layer. A pong is any frame from the measured peer with our
magic and the outstanding correlation id (kind `PING` reflected — the
reference responder is the generic `sharenet_transport_linux echo` — or
`PONG` from a dedicated responder).

## Production callers

1. **`sharenet_transport_linux probe-rtt`** (today): the real binary
   subcommand — `probe-rtt --peer ADDR [--count N] [--interval-ms M]`
   against a peer running `echo`; prints a final `LinkQualitySummary`,
   exits 0 on any completed run (measured loss is evidence, not failure).
2. **The crate API** (named future consumers):
   - **R3-003 authenticated topology evidence** consumes `LinkQualityStream`
     / `LinkQualitySample` via this crate's API (`Prober::stream()` hands
     out a live shared handle; `summarize()` derives deterministic
     summaries).
   - **R5-005 gateway admission/backhaul policy** consumes
     `LinkQualitySummary` values as its measurement input.
   - **R4-001/R4-003** (QUIC tunnel, gateway forwarding) construct probers
     through `sharenet_transport_linux::telemetry_bridge::udp_prober`.
3. **Android seam**: the pure-Kotlin mirror
   (`org.sharenet.transport.contract.QualitySample/QualityReporter/QualityRecorder`)
   lets the app layer report platform-event timing uniformly; the Nearby
   adapter emits honest connect/disconnect timing through it (see
   `transport/android/README.md`).

## Persistence

**None.** Telemetry is in-memory, process-local streaming state by design.
Durable evidence capture is **R8-001**'s concern (contribution evidence),
explicitly not the measurement layer's.

## Build and test

```bash
cd transport/telemetry
cargo test                    # unit + adversarial + two-process integration
cd ../linux
cargo test                    # includes the probe-rtt/echo binary-path tests
cargo run --bin sharenet_transport_linux -- probe-rtt --peer 127.0.0.1:<echo-port> --count 200
```

- `tests/telemetry_unit.rs`: the prober over REAL in-process loopback
  `UdpTransport`s — adversarial: consecutive losses continue, duplicate/late
  pongs, retries, malformed/oversized/foreign input, wrong-address pongs,
  reuse rejection, config validation.
- `tests/telemetry_integration.rs`: the **two-process REAL measurement** —
  spawns `telemetry_echo_child` (real second process), runs 200 probes over
  loopback (≥95% delivered, sane RTT bounds, p95 ≥ p50), then a
  `--drop-every 3` phase asserting measured loss ≈ 1/3 ± 0.1, both phases
  cross-validated against the child's own counters.
- `transport/linux/tests/probe_rtt.rs`: the fully-production path — the
  real `probe-rtt` binary against the real `echo` binary (both children are
  the production binaries).

## Known limits (honest)

- The `Prober` is synchronous (std only), like the Wave 1 transport; an
  async wrapper is R4-001 scope.
- Throughput is probe-traffic goodput, not capacity (documented above).
- The in-crate echo child duplicates the 4-byte Wave 1 length-prefix (frozen
  public documentation) so it can stay std-only; the prober side and the
  linux binary path always ride the real codec.
- No physical-network RTT distribution has been measured yet — real-network
  validation is R4-003/R10-001 scope.
