# sharenet-transport-linux — R2-003

ShareNet Linux transport/TUN foundation. **Platform adapter layer** per
`spec/architecture-lock.md` L009 and `spec/adrs/002-standard-transport-stack.md`:
TUN and raw IP are standard platform primitives that ShareNet *adapts*, never
replaces. This crate contains **no protocol semantics** (no identity, links,
routing, circuits, content, contribution, or cryptography — those live in the
protocol core owned by Worker 1).

## What it provides

| Piece | Where | What |
|---|---|---|
| `TunDevice` trait | `src/tun.rs` | Sync seam for raw IP packet I/O: `read_packet` / `write_packet` / `set_nonblocking` / `poll_read_ready` / `close`, with typed errors (`AlreadyInUse`, `Permission`, `Unsupported`, `InvalidName`, `WouldBlock`, `PacketTooLarge`, `Closed`, `Io`). |
| `SystemTunDevice` | `src/tun.rs` | The real thing: opens `/dev/net/tun`, `ioctl(TUNSETIFF)` with `IFF_TUN \| IFF_NO_PI` via raw `libc` (no helper crates), queries MTU via `SIOCGIFMTU`. |
| `MemoryTunPair` | `src/tun.rs` | **TEST VEHICLE** (clearly marked in code): in-memory duplex pair; never touches `/dev/net/tun`. |
| `probe_tun()` | `src/probe.rs` | Honest runtime capability probe: `Available \| Absent(reason) \| Forbidden`. Opens the device and runs `TUNSETIFF` with a kernel-assigned name, then closes (ephemeral, side-effect free). |
| `UdpTransport` | `src/udp.rs` | Raw local UDP with length-framed datagrams (`u32be len \|\| payload`), one frame per datagram, non-blocking + `WouldBlock` typed, read timeout, `poll`-based readiness, `MSG_TRUNC` truncation detection via `recvmsg(2)`. |
| binary | `src/bin/…` | `probe` (exit 0 available / 2 not) and `echo --bind ADDR [--max-frames N]` (UDP frame echo server — the runtime path used by the two-process test). |

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

## Seams and production callers

- The `TunDevice` / `UdpTransport` public APIs are the seams. The future
  **R4-001 QUIC/TLS tunnel** and **R4-003 Linux gateway forwarding** (and the
  future `sharenetd` daemon) construct transports through this crate's API —
  they own everything above the seam.
- The `sharenet_transport_linux` binary is a production caller *today*:
  `probe` is the honest capability report every Linux gateway host should run
  before R4-003 data-path bring-up; `echo` is a real UDP frame echo server.

## Persistence

**None.** Stateless foundation: sockets and TUN fds are process-local kernel
objects; nothing is written to durable storage.

## Build and test

```bash
cd transport/linux
cargo test                                   # unit + adversarial + gated + two-process
cargo run --bin sharenet_transport_linux -- probe
cargo run --bin sharenet_transport_linux -- echo --bind 127.0.0.1:9000
```

- `tests/udp_multiprocess.rs` spawns the echo binary as a **real second
  process** and exchanges frames over **real loopback UDP sockets** — this is
  the multiprocess/runtime evidence.
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
