package org.sharenet.transport.vpn

/**
 * SCRIPTED FAKE of the tunnel seam (test sources ONLY — R4-004).
 *
 * Stands in for the future JNI backhaul (R10-002: bridge to the Rust
 * `sharenet-transport-quic` TunnelStream). Default behavior: ECHO —
 * every forwarded packet comes straight back, which exercises the loop's
 * read->forward->write path end-to-end.
 *
 * Scripting knobs:
 *  * [echo] — return the packet (default) or nothing;
 *  * [failure] — throw from forward (terminal BackhaulFailure path);
 *  * [script] — full control over responses (also used for re-entrant
 *    `stop()` tests: the script can call `loop.stop()`).
 *
 * Records every forwarded packet for order/content assertions.
 */
class FakeTunnelBackhaul : TunnelBackhaul {

    var echo = true

    var failure: RuntimeException? = null

    var script: ((packet: ByteArray) -> List<ByteArray>)? = null

    val forwarded = mutableListOf<ByteArray>()

    var forwardCalls = 0
        private set

    override fun forward(packet: ByteArray): List<ByteArray> {
        forwardCalls++
        forwarded.add(packet.copyOf())
        script?.let { return it(packet) }
        failure?.let { throw it }
        return if (echo) listOf(packet.copyOf()) else emptyList()
    }
}
