# sharenet-transport-quic — R4-001 (QUIC/TLS tunnel)

ShareNet Internet-facing QUIC tunnel transport. **Platform adapter layer**
per `spec/architecture-lock.md` L009/L010 and
`spec/adrs/002-standard-transport-stack.md`: QUIC + TLS 1.3 via the
standard Rust stack (quinn + rustls) — no bespoke transport (L010),
no new cryptographic primitives (ADR-002: the TLS layer supplies
transport security, the identity layer supplies node authentication).
This crate contains **no protocol semantics** (no links, routing,
circuits, content — those live in the protocol core).

## What it provides

| Piece | Where | What |
|---|---|---|
| `TunnelServer` | `src/lib.rs` | Binds a QUIC endpoint presenting a node identity certificate; optionally pins the set of admitted client node ids at the TLS handshake (`expected_clients`). |
| `TunnelClient` | `src/lib.rs` | Connects to a server endpoint **pinning the server's node id** (a wrong pin never completes a usable tunnel) while presenting its own node identity certificate. |
| `TunnelStream` | `src/lib.rs` | Length-framed bidirectional session over one QUIC stream: `send_frame`/`recv_frame` (u32 BE prefix, `MAX_FRAME` = 2 MiB enforced on BOTH sides), `finish()` graceful close, `remote_addr()`. |
| `sharenet_quic_peer` | `src/bin/…` | **TEST SCAFFOLDING** (clearly marked): a real second process echoing frames, with `--evil oversize` emitting a bogus `0xFFFFFFFF` length prefix for the adversarial receive-limit test. |

## Identity binding (the R4-001 rule)

Each endpoint presents a **self-signed Ed25519 certificate whose private
key IS the node identity key** (R1-001; the seed is PKCS#8-wrapped into
the TLS key — rcgen, no second key). The pinned node identity is derived
from the certificate's public key by the exact R1-001 rule
(`SHA-256(canonical_cbor({1: scheme_version, 2: public_key}))`), verified
by a unit test against the protocol core's own derivation. TLS possession
proof + node pin = node authentication without a CA:

- clients MUST pin the server's node id (the advertisement's announcer);
- servers MAY pin client node ids (unpinned clients are refused);
- an **unpinned server entry is an unauthenticated transport** —
  ShareNet-level authentication (R3-001 links, R4-002 circuits) rides
  INSIDE the tunnel and must not be assumed by the tunnel alone.

Wire details are frozen in `spec/protocol-registry.yaml`
(`QuicTunnelTransport`): ALPN `sharenet-tunnel-v1`, Ed25519-only
certificate signature schemes, TLS 1.2 refused.

## Documented policies

- **Oversized frame → reject** (`FrameTooLarge`), enforced before the
  socket write (send) and on the length prefix (receive) — a receiver
  never buffers a claimed 4 GiB frame.
- **Close semantics (standard QUIC)**: `finish()` closes the sending half
  gracefully, but dropping the last handle to the connection aborts it —
  in-flight frames may be lost. Callers needing delivery keep the stream
  alive until the peer consumed the data (the tests' `done`-frame
  protocol exists for exactly this).
- **Runtime lifecycle**: each endpoint owns a tokio runtime in an `Arc`
  shared with every `TunnelStream` it produced — a stream keeps the
  driver alive, so in-flight frames still transmit after the endpoint
  owner is dropped; teardown happens when the last owner/stream goes
  away.
- **Stream signaling**: `open_bi` alone sends nothing on the wire; the
  client's first frame (or FIN) materializes the stream at the server —
  documented in both `connect` and `accept`.

## Seams and production callers

- The `TunnelServer`/`TunnelClient`/`TunnelStream` APIs are the seams.
  The future **R4-002 circuit binding** rides authenticated sessions over
  these tunnels; **R4-005 ICE/TURN** wraps the same endpoints for NAT
  traversal; the future `sharenetd` daemon and gateways construct
  tunnels through this crate's API.
- The tunnel carries **opaque frames** — relays forward opaque tunnel
  traffic (L012); end-to-end circuit objects are R4-002 scope.

## Persistence

**None.** Tunnels are runtime state (durable circuit state is
R4-002/R7 scope) — documented in the crate and the registry.

## Build and test

```bash
cd transport/quic
cargo test        # unit (incl. R1-001 derivation equality) + in-process mutual pinning + two-process tunnel tests
```

- `tests/quic_multiprocess.rs` spawns the peer binary as a **real second
  process** over **real loopback QUIC/TLS 1.3**: pinned tunnel echo, a
  wrong node pin rejected, and the adversarial oversized-frame-header
  rejection (`FrameTooLarge` without buffering).

## Known limits (honest)

- Relays/ICE/STUN/TURN traversal are R4-005 scope (L011); this crate
  binds direct endpoints only.
- Gateway data-plane forwarding (TUN ↔ tunnel) is R4-003; this crate
  stops at the framed session seam.
- No physical-network (non-loopback) run in evidence — R4-007/R10 scope;
  loopback exercises the full QUIC/TLS handshake, pinning and framing
  paths deterministically.
