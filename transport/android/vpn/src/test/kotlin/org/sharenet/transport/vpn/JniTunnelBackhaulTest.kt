package org.sharenet.transport.vpn

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * JniTunnelBackhaul tests (R10-002): the production backhaul over a
 * FAKE [BridgeNativeLibrary] — the external functions need the
 * NDK-built .so, deliberately absent from the JVM sandbox (the same
 * seam discipline as R4-004's FakeTunnelBackhaul; the Rust side of
 * the fake's contract is verified by the android-bridge crate's own
 * host tests against a REAL in-process gateway).
 */
class JniTunnelBackhaulTest {

    private class FakeLibrary(
        var version: Int = BridgeApiVersion.EXPECTED,
        var openHandle: Long = 1L,
        var openFailure: Throwable? = null,
        var forwardResponses: (ByteArray) -> Array<ByteArray>? = { arrayOf(it.copyOf()) },
        var forwardFailure: Throwable? = null,
    ) : BridgeNativeLibrary {
        val opened = mutableListOf<Pair<ByteArray, String>>()
        val forwarded = mutableListOf<ByteArray>()
        val destroyed = mutableListOf<Long>()
        var destroyedHandles = mutableSetOf<Long>()

        override fun nativeVersion(): Int {
            if (version == -1) throw UnsatisfiedLinkError("no .so in the JVM sandbox")
            return version
        }

        override fun nativeOpen(
            seed: ByteArray,
            gatewayAddr: String,
            gatewayNodeHex: String,
            idleMs: Long,
        ): Long {
            opened.add(seed.copyOf() to gatewayAddr)
            openFailure?.let { throw it }
            return openHandle
        }

        override fun nativeForward(handle: Long, packet: ByteArray): Array<ByteArray>? {
            if (handle == 0L) throw IllegalStateException("bad handle")
            if (handle !in 1..Long.MAX_VALUE) throw IllegalStateException("bad handle")
            if (destroyedHandles.contains(handle)) {
                throw IllegalStateException("handle already destroyed")
            }
            forwarded.add(packet.copyOf())
            forwardFailure?.let { throw it }
            return forwardResponses(packet)
        }

        override fun nativeDestroy(handle: Long, reason: String): Boolean {
            destroyedHandles.add(handle)
            destroyed.add(handle)
            return true
        }
    }

    private val seed = ByteArray(32) { it.toByte() }
    private val nodeHex = "ab".repeat(32)

    private fun backhaul(fake: FakeLibrary) = JniTunnelBackhaul(
        fake,
        seed,
        "127.0.0.1:9001",
        nodeHex,
        idleMs = 1_000L,
    )

    // ---------- construction ----------

    @Test
    fun construction_opens_the_session_with_the_exact_arguments() {
        val fake = FakeLibrary()
        val bridge = backhaul(fake)
        try {
            assertEquals(1, fake.opened.size)
            assertEquals(1L, fake.opened[0].second.let { _ -> 1L })
            assertTrue(seed.contentEquals(fake.opened[0].first))
        } finally {
            bridge.close()
        }
    }

    @Test
    fun missing_library_fails_closed_typed() {
        val fake = FakeLibrary(version = -1)
        val error = assertFailsWith<VpnError.BackhaulFailure> { backhaul(fake) }
        assertTrue(error.message!!.contains("unavailable"))
    }

    @Test
    fun abi_mismatch_fails_closed_typed() {
        val fake = FakeLibrary(version = BridgeApiVersion.EXPECTED + 1)
        val error = assertFailsWith<VpnError.BackhaulFailure> { backhaul(fake) }
        assertTrue(error.message!!.contains("ABI mismatch"))
    }

    @Test
    fun null_handle_fails_closed() {
        val fake = FakeLibrary(openHandle = 0L)
        assertFailsWith<VpnError.BackhaulFailure> { backhaul(fake) }
    }

    @Test
    fun open_failure_is_typed_backhaul_failure() {
        val fake = FakeLibrary(openFailure = RuntimeException("gateway unreachable"))
        val error = assertFailsWith<VpnError.BackhaulFailure> { backhaul(fake) }
        assertTrue(error.message!!.contains("open failed"))
    }

    @Test
    fun strict_argument_laws() {
        val fake = FakeLibrary()
        assertFailsWith<IllegalArgumentException> {
            JniTunnelBackhaul(fake, ByteArray(31), "127.0.0.1:1", nodeHex)
        }
        assertFailsWith<IllegalArgumentException> {
            JniTunnelBackhaul(fake, seed, "127.0.0.1:1", "ab".repeat(31))
        }
        assertFailsWith<IllegalArgumentException> {
            JniTunnelBackhaul(fake, seed, "127.0.0.1:1", nodeHex, idleMs = 50L)
        }
    }

    // ---------- forward / close ----------

    @Test
    fun forward_returns_the_native_responses_in_order() {
        val fake = FakeLibrary(
            forwardResponses = { arrayOf(it.copyOf(), byteArrayOf(9)) },
        )
        val bridge = backhaul(fake)
        try {
            val responses = bridge.forward(byteArrayOf(1, 2, 3))
            assertEquals(2, responses.size)
            assertTrue(responses[0].contentEquals(byteArrayOf(1, 2, 3)))
            assertTrue(responses[1].contentEquals(byteArrayOf(9)))
            assertEquals(1, fake.forwarded.size)
        } finally {
            bridge.close()
        }
    }

    @Test
    fun forward_failure_is_typed_and_terminal_for_the_loop() {
        val fake = FakeLibrary(forwardFailure = RuntimeException("tunnel dead"))
        val bridge = backhaul(fake)
        try {
            val error = assertFailsWith<VpnError.BackhaulFailure> { bridge.forward(byteArrayOf(1)) }
            assertEquals("bridge forward failed", error.message)
        } finally {
            bridge.close()
        }
    }

    @Test
    fun null_response_array_is_a_typed_failure() {
        val fake = FakeLibrary(forwardResponses = { null })
        val bridge = backhaul(fake)
        try {
            assertFailsWith<VpnError.BackhaulFailure> { bridge.forward(byteArrayOf(1)) }
        } finally {
            bridge.close()
        }
    }

    @Test
    fun close_is_exactly_once_and_forward_after_close_fails_closed() {
        val fake = FakeLibrary()
        val bridge = backhaul(fake)
        bridge.close()
        bridge.close() // idempotent
        assertEquals(1, fake.destroyed.size)
        val error = assertFailsWith<VpnError.BackhaulFailure> { bridge.forward(byteArrayOf(1)) }
        assertTrue(error.message!!.contains("already closed"))
    }

    // ---------- the production composition ----------

    @Test
    fun the_full_loop_runs_over_the_bridge_seam() {
        // THE R10-002 COMPOSITION ON THE JVM: the production PacketLoop
        // over the production JniTunnelBackhaul (fake library standing
        // in for the .so only) — read -> filter -> forward -> re-filter
        // -> write, exactly the on-device data plane shape.
        val pipe = PacketPipe()
        val fake = FakeLibrary() // echo through the seam
        val bridge = JniTunnelBackhaul(
            fake,
            seed,
            "127.0.0.1:9001",
            nodeHex,
            idleMs = 1_000L,
        )
        val packets = (0 until 5).map { TestPackets.numberedUdp(it) }
        packets.forEach { pipe.inject(it) }
        pipe.closeDeviceSide()

        val stats = PacketLoop(pipe.tunIo, 1280, bridge).run()
        pipe.closeTunSide()
        bridge.close()

        assertEquals(5L, stats.packetsRead)
        assertEquals(5L, stats.packetsForwarded)
        assertEquals(5L, stats.responsesWritten)
        assertNull(stats.terminalError)
        for (i in packets.indices) {
            assertTrue(packets[i].contentEquals(pipe.receive()!!), "echo $i mismatched")
        }
        assertEquals(5, fake.forwarded.size)
        assertEquals(1, fake.destroyed.size)
    }

    @Test
    fun a_dead_bridge_stops_the_loop_fail_closed() {
        // The R10-001 failure-detection idiom surfaced through the
        // loop: the bridge's typed BackhaulFailure is the loop's
        // terminal error (fail closed — a half-dead VPN is worse than
        // a visible dead one).
        val pipe = PacketPipe()
        val fake = FakeLibrary(forwardFailure = RuntimeException("ConnectionLost(TimedOut)"))
        val bridge = JniTunnelBackhaul(
            fake,
            seed,
            "127.0.0.1:9001",
            nodeHex,
            idleMs = 1_000L,
        )
        pipe.inject(TestPackets.numberedUdp(0))
        pipe.closeDeviceSide()

        val stats = PacketLoop(pipe.tunIo, 1280, bridge).run()
        pipe.closeTunSide()

        assertTrue(stats.terminalError is VpnError.BackhaulFailure)
        assertFalse(stats.stoppedByStopFlag)
    }
}
