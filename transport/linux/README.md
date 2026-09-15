# sharenet-transport-linux — R2-003 + R2-004 (telemetry bridge)

ShareNet Linux transport/TUN foundation. **Platform adapter layer** per
`spec/architecture-lock.md` L009 and `spec/adrs/002-standard-transport-stack.md`:
TUN and raw IP are standard platform primitives that ShareNet *adapts*, never
replaces. This crate contains **no protocol semantics** (no identity, links,
routing, circuits, content, contribution, or cryptography — those live in the
protocol core owned by Worker 1). Since R2-004 it also hosts the **telemetry
bridge**: the concrete `FrameTransport` implementation that lets the
`sharenet-transport-telemetry` prober drive this crate's `UdpTransport`.

## What it provides

| Piece | Where | What |
|---|---|---|
| `TunDevice` trait | `src/tun.rs` | Sync seam for raw IP packet I/O: `read_packet` / `write_packet` / `set_nonblocking` / `poll_read_ready` / `close`, with typed errors (`AlreadyInUse`, `Permission`, `Unsupported`, `InvalidName`, `WouldBlock`, `PacketTooLarge`, `Closed`, `Io`). |
| `SystemTunDevice` | `src/tun.rs` | The real thing: opens `/dev/net/tun`, `ioctl(TUNSETIFF)` with `IFF_TUN \| IFF_NO_PI` via raw `libc` (no helper crates), queries MTU via `SIOCGIFMTU`. |
| `MemoryTunPair` | `src/tun.rs` | **TEST VEHICLE** (clearly marked in code): in-memory duplex pair; never touches `/dev/net/tun`. |
| `probe_tun()` | `src/probe.rs` | Honest runtime capability probe: `Available \| Absent(reason) \| Forbidden`. Opens the device and runs `TUNSETIFF` with a kernel-assigned name, then closes (ephemeral, side-effect free). |
| `UdpTransport` | `src/udp.rs` | Raw local UDP with length-framed datagrams (`u32be len \|\| payload`), one frame per datagram, non-blocking + `WouldBlock` typed, read timeout, `poll`-based readiness, `MSG_TRUNC` truncation detection via `recvmsg(2)`. |
| `telemetry_bridge` | `src/telemetry_bridge.rs` | **R2-004**: implements `sharenet_transport_telemetry::probe::FrameTransport` for `UdpTransport` (sends/receives go through the REAL frame codec; `EAGAIN`→`TransportWouldBlock`, `Closed`→`TransportClosed`), plus `udp_prober(peer, config)` — the one-call prober constructor. |
| binary | `src/bin/…` | `probe` (exit 0 available / 2 not), `echo --bind ADDR [--max-frames N] [--drop-every N]` (UDP frame echo server; `--drop-every` is the honest R2-004 test affordance for induced loss), and `probe-rtt --peer ADDR [--count N] [--interval-ms M]` (R2-004 active RTT/loss measurement printing a `LinkQualitySummary`; exit 0 on any completed run — measured loss is evidence, not failure). |

## Documented policies

- **Oversized TUN packet → reject** (`PacketTooLarge`), never split.
  Segmentation above the TUN seam belongs to the future tunnel (R4-001).
- **Zero-length TUN packet → reject** (`Unsupported`).
- **Interface names**: 1–15 bytes of `[A-Za-z0-9._-]` (stricter than the
  kernel on purpose — avoids `eth0:1` alias ambiguity).
- **UDP frame limit**: payload ≤ 65 500 bytes (`MAX_FRAME_PAYLOAD`), one frame
  per datagram; trailing bytes after a complete frame are `FrameMalformed`.
- **Truncation**: datagram > receive buffer → `DatagramTruncated` (detected
  via `MSG_TRUNC`, not silently clipped); header claims more than the
  datagram holds → `FrameTruncated`.
- **`WouldBlock`** covers both non-blocking no-data and Linux `SO_RCVTIMEO`
  expiry (kernel reports both as `EAGAIN`).
- **`echo --drop-every N`** (R2-004): every Nth *well-formed received* frame
  is silently dropped instead of echoed (N ≥ 1; N=1 drops everything);
  dropped frames are counted separately and never toward `--max-frames` —
  deterministic induced loss for the telemetry tests.
- **Dependency direction (R2-004)**: this crate depends on
  `sharenet-transport-telemetry` (path `../telemetry`) so the binary can run
  the prober; the telemetry crate in turn only *dev*-depends on this crate
  for its real-socket tests (the serde/serde_json dev-cycle shape). The
  `FrameTransport` impl lives HERE because cargo forbids the reverse
  regular dependency (orphan rule: this crate owns `UdpTransport`).

## Seams and production callers

- The `TunDevice` / `UdpTransport` public APIs are the seams. The future
  **R4-001 QUIC/TLS tunnel** and **R4-003 Linux gateway forwarding** (and the
  future `sharenetd` daemon) construct transports through this crate's API —
  they own everything above the seam.
- The `telemetry_bridge` is the **R2-004 seam**: `udp_prober(peer, config)` is
  how the future **R3-003 topology evidence** layer and **R5-005 admission
  policy** construct active measurement over this transport (see
  `../telemetry/README.md`).
- The `sharenet_transport_linux` binary is a production caller *today*:
  `probe` is the honest capability report every Linux gateway host should run
  before R4-003 data-path bring-up; `echo` is a real UDP frame echo server;
  `probe-rtt` (R2-004) is the real RTT/loss measurement CLI.

## Persistence

**None.** Stateless foundation: sockets and TUN fds are process-local kernel
objects; nothing is written to durable storage. The R2-004 telemetry state
the bridge feeds is likewise in-memory (see `../telemetry/README.md`).

## Build and test

```bash
cd transport/linux
cargo test                                   # unit + adversarial + gated + two-process + probe-rtt
cargo run --bin sharenet_transport_linux -- probe
cargo run --bin sharenet_transport_linux -- echo --bind 127.0.0.1:9000
cargo run --bin sharenet_transport_linux -- probe-rtt --peer 127.0.0.1:9000 --count 200
```

- `tests/udp_multiprocess.rs` spawns the echo binary as a **real second
  process** and exchanges frames over **real loopback UDP sockets** — this is
  the multiprocess/runtime evidence.
- `tests/probe_rtt.rs` (R2-004) runs the REAL `probe-rtt` binary against the
  REAL `echo` binary (two child processes): reliable phase (50 probes, sane
  bounds) and induced-loss phase (`echo --drop-every 3` → measured loss
  within ±0.1 of 1/3).
- `tests/tun_gated.rs` runs live `SystemTunDevice` tests only when
  `probe_tun() == Available`. On hosts without `/dev/net/tun` (common in
  sandboxes) the tests **SKIP with a printed reason** — that is correct
  probe behavior, not a failure. Live TUN data-path verification is R4-003.

## Known limits (honest)

- No async runtime wrappers (R4-001 scope).
- No packet interpretation whatsoever — including no fragmentation/reassembly.
- `SystemTunDevice` live data path (packets actually traversing the interface)
  requires a host with TUN + `CAP_NET_ADMIN`; validated at R4-003 on real
  gateway hosts, not in this foundation.
- `probe-rtt` measures over loopback in CI-like environments; real-network
  RTT distributions are R4-003/R10-001 scope.
