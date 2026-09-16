# Wave 20 platform items — R9-002 + R9-004 architecture records

## R9-002 — iOS Packet Tunnel Provider evaluation

**Verify level `platform` — honestly OUT OF SCOPE in this sandbox**
(the same gap R9-001 recorded: no Swift toolchain; requires macOS 13+ /
Xcode 15+ and a real iOS device with the tunnel entitlement).

What this evaluation delivers NOW (the criteria the Mac runner will
execute against):

1. **Entitlement reality**: `NEPacketTunnelProvider` requires the
   `com.apple.developer.networking.networkextension` entitlement +
   a paid Apple Developer Program membership + a manually-approved
   entitlement request for packet-tunnel providers. The evaluation
   MUST record whether the team's entitlement was granted — this is
   Apple's gate, not ShareNet's.
2. **The seam is ready**: `transport/ios/` (R9-001) already separates
   the Contract/ seam from the adapter. A future
   `PacketTunnelAdapter` would implement the same
   `ParticipantTransport` frame discipline over the packet flow, with
   the tun-style seam R2-003 established (`TunDevice`'s Linux shape is
   the reference: read_packet/write_packet, `PacketTooLarge` reject,
   never split — segmentation belongs above the seam).
3. **The JNI/FFI prerequisite**: the tunnel's protocol logic rides the
   Rust core over FFI — the same deferred bridge R9-001 recorded
   (R10-002 scope for Android; the iOS bridge is the same class of
   work).
4. **The decision the evaluation makes**: whether iOS participation
   runs as a full tunnel (packet-level, entitlement-gated) or stays at
   the frame-participant level (`transport/ios/` as-is) — architecture
   §16's own wording ("where platform entitlements permit") makes this
   a PER-DEPLOYMENT decision, not a protocol one.

## R9-004 — Additional access adapters

**Verify levels `architecture` (delivered here) + `integration`
(satisfied by the existing, exercised boundary).**

Architecture §16 Phase 4: *"advanced external access technologies
through ADCOS."* The boundary analysis (AGENTS.md, architecture §6):

- Additional access technologies (satellite backhaul, cellular
  bonding, community ISP uplinks, future LEO services) are ADCOS
  PROVIDER-side technologies. They NEVER enter `transport/` (the
  ShareNet-side adapter layer) — they arrive as ADCOS
  `ConnectivityContract` offers observed through the R5-002 port and
  the R5-004 signed-observation trust boundary, which the R5-003
  durable projection and the R5-005 admission policy already consume.
- The ShareNet-side integration surface for EVERY access technology
  is therefore the SAME three seams: the `ConnectivityPort` (the
  boundary trait), `SignedConnectivityObservation` (the verified
  provider claim) and the admission/backhaul policy (the two-factor
  eligibility decision). These are implemented, adversarially tested
  and conformance-pinned — including over the REAL developer API by
  `connectivity-client` (R5-002's HTTP evidence chain, 50 tests).
- **No new ShareNet-side code is required for a new access
  technology**; that is the architecture working as designed (the
  boundary absorbs provider diversity). The integration evidence for
  THIS item is the existing end-to-end chain: developer API → adapter
  → port → verified observations → R5-003 store → R5-005 admission →
  R7-003 gateway selection → R7-004 replacement circuits.
- Honest gap: exercising a SPECIFIC new access technology (e.g. a real
  satellite provider's ADCOS integration) needs that provider's
  developer credentials and live egress — outside this sandbox, and
  driven by the ADCOS project's rollout, not by ShareNet's roadmap.
