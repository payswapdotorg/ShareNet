package org.sharenet.transport.vpn

/**
 * THE SEAM of the Android VPN data plane (R4-004): where an outbound IP
 * packet crosses from the Kotlin/JVM world into the ShareNet tunnel.
 *
 * The production implementation is FUTURE SCOPE (R10-002, "Android
 * real-device bridge"): a JNI bridge to the Rust `sharenet-transport-quic`
 * `TunnelStream` (frame-oriented `send_frame`/`recv_frame`) plus the
 * protocol-core circuit registry, which requires the NDK — deliberately
 * absent from this wave's build. Until then:
 *  * tests use `FakeTunnelBackhaul` (echo) in src/test;
 *  * the on-device service accepts any implementation injected by the
 *    embedding app.
 *
 * Contract:
 *  * [forward] is called by the packet loop on the loop thread, once per
 *    ACCEPTED outbound packet (see [IpPacketFilter]).
 *  * It returns the RESPONSE packets for this packet (0..n) in write
 *    order; the loop writes them back to the TUN device unchanged.
 *    Batching multiple reads into one circuit frame is the
 *    implementation's business — from the loop's perspective it is
 *    request -> responses.
 *  * It may block (the real tunnel performs network I/O).
 *  * It must be safe to call from one thread only (the loop thread).
 *  * Throwing is a TUNNEL FAILURE: the loop stops and records a typed
 *    [VpnError.BackhaulFailure] (fail closed — a half-dead VPN that
 *    silently swallows traffic is worse than a visible dead one).
 */
interface TunnelBackhaul {

    /**
     * Forward one complete, filter-accepted IP packet into the tunnel and
     * return the packets to write back to the device.
     *
     * @param packet a COMPLETE IP packet (never partial — TUN reads are
     *        packet-atomic and the loop drops non-IP/malformed packets
     *        before calling this).
     * @return response packets in write order (may be empty).
     * @throws Throwable on tunnel failure (typed by the loop as
     *         [VpnError.BackhaulFailure]).
     */
    fun forward(packet: ByteArray): List<ByteArray>
}
