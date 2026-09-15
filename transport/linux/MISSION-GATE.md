# MISSION GATE — R4-007 (real Internet bridge) — evidence report

The mission gate is the work item that bridges ShareNet's authenticated
overlay to the real Internet. This report records exactly what was
verified, on what evidence, and what remains for operator hardware.
It follows the repo's evidence law: nothing is claimed that a test or a
probe did not observe.

## What the mission gate IS

A participant's application datagram crosses the full ShareNet stack to
a REAL external destination and the response returns:

```text
participant
  → node-pinned QUIC tunnel (R4-001)
  → route commitment + circuit admission (R3-004 + R4-002, R4-003)
  → gateway uplink (the Internet side)
  → REAL external server
  ← response flows back as direction-2 frames
```

## Verified in this environment (2026-09-15)

### 1. Full control-plane + data-plane composition (loopback)

`transport/linux/tests/mission_gate.rs::mission_gate_full_stack` —
identity (R1-001) → signed capability statement (R1-004) →
advertisement discovery with capability admission (R3-002) →
authenticated link handshake with sealed frames to the ADVERTISED
endpoint (R3-001) → route commitment + circuit admission inside the
pinned QUIC tunnel (R3-004 + R4-002 + R4-003) → the data plane: 5
packets cross to the uplink and responses return. The participant
learns the gateway's node id and BOTH transport endpoints from the
SIGNED advertisement — nothing is hardcoded.

Plus `mission_gate_refuses_tampered_capability_on_ramp`: a tampered
capability envelope in the advertisement is refused at discovery — the
mission on-ramp never admits an unauthorized gateway.

### 2. REAL-Internet crossing (the actual mission gate)

`transport/linux/tests/mission_gate.rs::mission_gate_real_internet_crossing`
— the gateway's uplink points at a REAL public resolver
(8.8.8.8:53; 9.9.9.9, 1.1.1.1, 8.8.4.4 as fallbacks), the
participant's packet is a well-formed DNS query for `example.com.`, and
a REAL DNS response (transaction id echo + QR bit + question echo;
61 bytes observed) returns through the ENTIRE stack to the participant.
The response's txid proves it is OUR query's answer, not a reflected or
fabricated datagram.

This is a genuine `real-network` verification: real sockets, real
external server, real response — carried by the full ShareNet
control-plane chain.

### 3. The gateway fix this required

The R4-003 gateway bound its uplink socket to `127.0.0.1:0` — a
loopback-bound socket cannot route to the real Internet (`send_to`
fails with EINVAL). R4-007 changed it to a wildcard bind
(`0.0.0.0:0`): the uplink is the INTERNET side. All existing gateway
tests still pass (61/61 in the linux crate).

### 4. The environment's real network policy (probe-uplink evidence)

`sharenet_transport_linux probe-uplink --dest ADDR` (new subcommand)
sends a DNS-shaped probe to a real destination and records the typed
outcome:

| Destination | Outcome |
|---|---|
| 8.8.8.8:53 (Google)   | reachable — 101-byte DNS response |
| 8.8.4.4:53 (Google)   | reachable |
| 9.9.9.9:53 (Quad9)    | reachable |
| 1.1.1.1:53 (Cloudflare) | reachable |
| 208.67.222.222:53 (OpenDNS) | reachable |
| 74.82.42.42:53 (HE)   | reachable |
| 8.8.8.8:443           | no response (port blocked) |
| 8.8.8.8:19302 (STUN)  | no response (port blocked) |
| raw TCP to arbitrary IPs | blocked (timeout) |
| HTTPS to allowlisted domains | allowed |

So this host sits behind an allowlist firewall that permits UDP/53 to
public resolvers and blocks other UDP ports and raw TCP. The DNS-based
real-network crossing above is therefore the STRONGEST real-Internet
verification achievable from inside this environment. Exit codes are
typed: 0 = egress confirmed, 3 = no response within the window (host
network restriction — evidence, not a bug), 2 = usage.

The real-network test applies the tun_gated discipline: if no resolver
answers (an even more restrictive network), it prints
`REAL_INTERNET_UNAVAILABLE` and skips honestly — the loopback
full-stack composition runs unconditionally.

## NOT verified here — operator-side steps (honest gaps)

1. **Android device leg (R4-004 + this item's real-device level)**: the
   `:vpn` module builds against the real SDK (AAR produced; 67/67 unit
   tests) but no physical Android device exists here. The live path —
   `VpnService.establish()` with real consent, the TUN fd feeding
   `PacketLoop` through `TunnelBackhaul` — requires:
   - the R10-002 JNI bridge (Kotlin `TunnelBackhaul` → the Rust
     `GatewayClient` tunnel session), which is exactly the seam
     R4-004 froze for it;
   - an Android device with the embedding app; consent flow per the
     R4-004 README.
2. **Non-DNS destinations**: this environment blocks non-53 UDP; the
   uplink's real-destination breadth (HTTP over the bridge, arbitrary
   services) must be run from an open-UDP network. The mission test's
   uplink address is a constructor argument — point it anywhere.
3. **Real NAT shapes** (the R4-006 fallback under a real restrictive
   NAT): srflx/relayed candidate gathering against real STUN/TURN
   servers, and the client-side local-relay fallback, need real NAT
   topology (R4-005/R4-006 documented this as R4-007/R10 evidence).
4. **Endurance** (24h, restarts) is R10-003's verify level.

## How to run the mission gate on operator hardware

```bash
cd transport/linux
cargo test --test mission_gate            # loopback composition (always)
cargo test --test mission_gate -- --nocapture   # shows the real-resolver leg

# the standalone egress probe:
cargo run --bin sharenet_transport_linux -- probe-uplink --dest 8.8.8.8:53
```

On a host with open UDP egress, the real-internet leg exercises against
whichever resolver answers first; on a fully restrictive host it skips
with the typed reason (never a false pass — the DNS-reply shape is
asserted only when a response actually arrives).
