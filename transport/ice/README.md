# sharenet-transport-ice — R4-005 (ICE/TURN)

ShareNet NAT-traversal / relay transport. **Platform adapter layer**
per `spec/architecture-lock.md` L009/L011/L012 and
`spec/adrs/002-standard-transport-stack.md`: standard STUN/TURN/ICE
concepts are reused (L011 — "ICE/STUN/TURN/MASQUE should be reused
before custom NAT/proxy protocols are invented"), the relay forwards
opaque end-to-end tunnel traffic (L012), and this crate contains **no
protocol semantics** (no identity, links, routing, circuits, content —
node authentication happens in the QUIC/TLS layer it hands addresses
to; ShareNet-level authentication rides inside the tunnel).

## What it provides

| Piece | Where | What |
|---|---|---|
| STUN codec (RFC 5389 subset) | `src/stun.rs` | Strict 20-byte-header codec: magic cookie `0x2112A442`, 96-bit transaction ids, method/class bit encoding (§6), attribute TLVs with 4-byte alignment, XOR-MAPPED-ADDRESS (§15.2), SOFTWARE. Rejects: bad cookie, unknown comprehension-required attributes, malformed TLV lengths, trailing garbage, unaligned message lengths, duplicate attributes. |
| STUN client | `src/stun.rs` | `binding_request` over any `DatagramPipe` (real UDP): random transaction id, response matched by EXACT transaction id (mismatched responses discarded — verified adversarially), 3-attempt retry with timeout, fail-closed on any malformed response. `connectivity_check` = the RFC 8445 §7-subset check (returns the address the target observed). |
| Candidate model (RFC 8445) | `src/candidate.rs` | `CandidateType::{Host, ServerReflexive, Relayed}` with the standard priority formula `(2^24)*type_pref + (2^8)*local_pref + (256 - component)` and type+base-derived foundations; `gather` (host always; srflx via STUN; relayed via allocation), `pair_candidates` ordered by pair priority (controlling-agent rule). No agent nomination state machine — that is future R4-006/R4-007 scope (documented). |
| TURN-style relay (RFC 8656 concepts) | `src/relay.rs` | `RelayServer`: per-5-tuple allocations (RFC 8656 437 allocation-mismatch on a conflicting new nonce; identical-nonce retransmission returns the byte-identical response), a relayed UDP address per allocation forwarding OPAQUE datagrams (never parsed — L012), permission-lite activation (relayed socket silent until the client has sent first — documented simplification). `RelayClient`: allocate/send/recv with typed errors; `RelayServerAdapter` pumps a real QUIC endpoint's datagrams through an allocation. Control framing: 12-byte `magic "SN" + msg_type + allocation_id + len` — TEST/LOCAL scope (no TURN auth; production TURN is R4-006 scope). |
| QUIC bridge | `src/bridge.rs` | `tunnel_connect(candidate, seed, expected_node_id)`: a gathered candidate is the ADDRESS source for a node-pinned `sharenet_transport_quic` tunnel (R4-001) — authentication is entirely the tunnel layer's; relays carry the QUIC datagrams opaque (L012). |
| binaries | `src/bin/…` | **TEST SCAFFOLDING**: `stun_server` (Binding Request → XOR-MAPPED-ADDRESS + SOFTWARE, `--evil` modes wrong-txid/bad-cookie/trailing-garbage/unknown-required), `turn_relay` (allocations + opaque forwarding), `turn_client` (echo peer behind the relay; `--mode quic` hosts a node-pinned TunnelServer reachable through its relayed address). |

## Documented policies

- **Strict STUN parsing everywhere** (client and scaffolding server):
  any response that fails the strict parse fails the whole operation
  closed — no fallback to looser interpretations.
- **Datagram limit**: `MAX_RELAY_DATAGRAM` = 2 MiB (mirrors the QUIC
  tunnel frame bound), enforced library-side before any send and
  defense-in-depth relay-side; oversize → typed error, never split.
- **Adversarial input never kills the relay**: unparseable datagrams
  are silently dropped (never replied to — a garbage source could be
  spoofed); semantically invalid control frames get `RELAY-ERROR`
  replies with typed codes (1 malformed, 2 unknown allocation, 3 not
  owner, 437 allocation mismatch, …).
- **Entropy**: transaction ids and allocation nonces come from
  `/dev/urandom` (exact reads); non-unix hosts fail closed — the same
  policy as the protocol core (no weak fallback, ever).
- **srflx on loopback is the identity mapping** (the observed address
  is the local address) — real NAT shapes are R4-007/R10 evidence.

## Seams and production callers

- `gather`/`pair_candidates`/`connectivity_check`/`tunnel_connect`
  are the seams: **R4-006 restrictive-network fallback** and
  **R4-007 mission-gate real-Internet bridge** (and the future
  `sharenetd` daemon) construct candidate-driven, node-pinned tunnels
  through this crate's API.
- The relay treats payloads as opaque bytes end-to-end (L012) —
  circuit/content objects ride inside the tunnel, never in the relay.

## Persistence

**None.** Candidates, allocations and relay state are runtime state
(durable circuit state is R4-002/R7 scope).

## Build and test

```bash
cd transport/ice
cargo test    # 33 unit (codec vectors hand-computed, strict rejects, formulas)
              # + 11 multiprocess/adversarial: REAL stun_server / turn_relay /
              # turn_client processes over real loopback UDP
```

Multiprocess coverage: STUN binding + gather + connectivity check vs
the real server; wrong-transaction-id responses ignored while the
matching one is accepted; fail-closed on evil responses (bad cookie /
trailing garbage / unknown required attribute, exact typed errors);
opaque echo through the relay between two processes; all three
candidate types gathered from real processes with RFC 8445 priority
ordering; a full node-pinned QUIC/TLS 1.3 tunnel riding the relay
transparently; a wrong node pin failing closed while the relay
survives; duplicate-allocation rules (identical nonce → same
response, new nonce → 437); malformed relayed datagrams forwarded
opaquely; the relay surviving adversarial control frames.

## Known limits (honest)

- No real external STUN/TURN server in evidence — the sandbox runs
  local real ones (the standard pattern of this repo's two-process
  evidence); real-network NAT shapes are R4-007/R10 scope.
- No TURN authentication (long-term credentials etc.) — production
  TURN relays are R4-006 scope; this crate's control framing is
  TEST/LOCAL scope by design.
- No full ICE agent (nomination, consent freshness, role conflicts) —
  RFC 8445 candidate/pairing/check primitives only; the agent is
  future scope above this crate.
- Relay permission model simplified (client-sends-first activation
  instead of RFC 8656 permissions/CHANNEL-BINDINGS).
- `stun_server` silently drops non-Binding-Request datagrams instead
  of RFC 5389 §7.4 error responses (scaffolding simplification).
