package org.sharenet.transport.vpn

import java.util.concurrent.CountDownLatch
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * PacketLoop tests (R4-004): the production loop shape, driven
 * end-to-end on the JVM over the pipe-backed [PacketIO] fake with an
 * echo [FakeTunnelBackhaul] — no android.jar involved.
 */
class PacketLoopTest {

    private val mtu = 1280

    private fun loop(io: PacketIO, backhaul: TunnelBackhaul) = PacketLoop(io, mtu, backhaul)

    // ---------- data path ----------

    @Test
    fun n_packets_echo_back_in_order() {
        val pipe = PacketPipe()
        val backhaul = FakeTunnelBackhaul() // echo
        val packets = (0 until 5).map { TestPackets.numberedUdp(it) }
        packets.forEach { pipe.inject(it) }
        pipe.closeDeviceSide() // after draining: EOF terminates the loop

        val stats = loop(pipe.tunIo, backhaul).run()
        pipe.closeTunSide() // loop exited: no more responses can ever arrive

        assertEquals(5L, stats.packetsRead)
        assertEquals(5L, stats.packetsForwarded)
        assertEquals(5L, stats.responsesReceived)
        assertEquals(5L, stats.responsesWritten)
        assertEquals(0L, stats.packetsDropped)
        assertEquals(0L, stats.oversizedRejected)
        assertNull(stats.terminalError)
        assertFalse(stats.stoppedByStopFlag)
        // Order preserved end-to-end.
        for (i in packets.indices) {
            assertTrue(packets[i].contentEquals(pipe.receive()!!), "echo $i mismatched")
        }
        assertEquals(5, backhaul.forwarded.size)
        for (i in packets.indices) {
            assertTrue(packets[i].contentEquals(backhaul.forwarded[i]), "forwarded $i mismatched")
        }
        assertNull(pipe.receive()) // nothing beyond the echoes
    }

    @Test
    fun malformed_packets_are_dropped_not_forwarded_and_loop_survives() {
        val pipe = PacketPipe()
        val backhaul = FakeTunnelBackhaul()
        pipe.inject(TestPackets.numberedUdp(0))
        pipe.inject(TestPackets.ipv4(versionNibble = 5)) // garbage: dropped
        pipe.inject(TestPackets.ipv4(protocol = 47)) // GRE: policy drop
        pipe.inject(TestPackets.numberedUdp(1))
        pipe.closeDeviceSide()

        val stats = loop(pipe.tunIo, backhaul).run()

        assertEquals(2L, stats.packetsForwarded)
        assertEquals(2L, stats.packetsDropped)
        assertEquals(2, backhaul.forwarded.size)
    }

    @Test
    fun oversized_packet_rejected_with_typed_error_and_loop_continues() {
        val pipe = PacketPipe()
        val backhaul = FakeTunnelBackhaul()
        pipe.inject(TestPackets.numberedUdp(0))
        val oversized = TestPackets.ipv4(payloadBytes = mtu) // mtu + 20 header > bound
        pipe.inject(oversized)
        pipe.inject(TestPackets.numberedUdp(1))
        pipe.closeDeviceSide()

        val stats = loop(pipe.tunIo, backhaul).run()

        assertEquals(1L, stats.oversizedRejected)
        assertEquals(2L, stats.packetsForwarded, "loop must survive the oversized packet")
        // The oversized packet is consumed and lost (like a truncated TUN read).
        assertEquals(2, backhaul.forwarded.size)
        assertFalse(backhaul.forwarded.any { it.size > mtu })
    }

    @Test
    fun oversized_error_is_typed() {
        val pipe = PacketPipe()
        try {
            pipe.inject(ByteArray(mtu + 1))
            pipe.tunIo.readPacket(mtu)
            throw AssertionError("expected PacketTooLarge")
        } catch (e: VpnError.PacketTooLarge) {
            assertEquals(mtu + 1, e.size)
            assertEquals(mtu, e.maxBytes)
        }
    }

    @Test
    fun garbage_backhaul_responses_are_rejected_not_written() {
        val pipe = PacketPipe()
        val backhaul = FakeTunnelBackhaul().apply {
            script = { packet -> listOf(packet.copyOf(), ByteArray(7) { 0x55 }) } // echo + garbage
        }
        pipe.inject(TestPackets.numberedUdp(0))
        pipe.closeDeviceSide()

        val stats = loop(pipe.tunIo, backhaul).run()
        pipe.closeTunSide() // loop exited: drain-then-EOF for receive()

        assertEquals(1L, stats.packetsForwarded)
        assertEquals(2L, stats.responsesReceived)
        assertEquals(1L, stats.responsesWritten) // only the echo
        assertEquals(1L, stats.responsesRejected) // the garbage
        assertTrue(TestPackets.numberedUdp(0).contentEquals(pipe.receive()!!))
        assertNull(pipe.receive())
    }

    @Test
    fun backhaul_failure_is_terminal_and_typed() {
        val pipe = PacketPipe()
        val backhaul = FakeTunnelBackhaul().apply {
            failure = IllegalStateException("jni bridge died")
        }
        pipe.inject(TestPackets.numberedUdp(0))
        pipe.closeDeviceSide()

        val stats = loop(pipe.tunIo, backhaul).run()

        val terminal = stats.terminalError
        assertIs<VpnError.BackhaulFailure>(terminal)
        assertEquals(0L, stats.packetsForwarded) // failed before counting
        assertEquals(0L, stats.responsesWritten)
    }

    @Test
    fun io_failure_is_terminal_and_typed() {
        val pipe = object : PacketIO {
            override fun readPacket(maxBytes: Int): ByteArray = throw java.io.IOException("fd gone")

            override fun writePacket(packet: ByteArray) = throw java.io.IOException("fd gone")

            override fun close() = Unit
        }
        val stats = loop(pipe, FakeTunnelBackhaul()).run()
        assertIs<VpnError.IoFailure>(stats.terminalError)
    }

    @Test
    fun invalid_mtu_is_rejected_typed_in_constructor() {
        for (bad in listOf(67, 65_536, 0, -1)) {
            val error = kotlin.test.assertFailsWith<VpnError.InvalidConfig> {
                PacketLoop(PacketPipe().tunIo, bad, FakeTunnelBackhaul())
            }
            assertEquals("mtu", error.field)
        }
    }

    // ---------- stop flag / lifecycle ----------

    @Test
    fun stop_before_run_exits_immediately_without_reading() {
        val pipe = PacketPipe()
        val backhaul = FakeTunnelBackhaul()
        val packetLoop = loop(pipe.tunIo, backhaul)
        packetLoop.stop()
        pipe.inject(TestPackets.numberedUdp(0)) // must never be read

        val stats = packetLoop.run()

        assertTrue(packetLoop.isStopped)
        assertTrue(stats.stoppedByStopFlag)
        assertEquals(0L, stats.packetsRead)
        assertEquals(0, backhaul.forwardCalls)
    }

    @Test
    fun concurrent_stop_calls_are_safe_and_idempotent() {
        val packetLoop = loop(PacketPipe().tunIo, FakeTunnelBackhaul())
        val threads = (1..8).map {
            thread {
                repeat(100) { packetLoop.stop() }
            }
        }
        threads.forEach { it.join(5_000) }
        threads.forEach { assertFalse(it.isAlive, "stop() contention must not hang or throw") }
        assertTrue(packetLoop.isStopped)
    }

    @Test
    fun stop_during_blocked_read_drops_the_packet_instead_of_forwarding() {
        val pipe = PacketPipe()
        val backhaul = FakeTunnelBackhaul()
        val packetLoop = loop(pipe.tunIo, backhaul)
        val finished = CountDownLatch(1)
        val loopThread = thread(start = false) {
            packetLoop.run()
            finished.countDown()
        }
        loopThread.start()

        // The loop is (or is about to be) blocked on the empty pipe.
        packetLoop.stop()
        pipe.inject(TestPackets.numberedUdp(0)) // arrives AFTER the stop request
        pipe.closeDeviceSide()

        assertTrue(finished.await(5, java.util.concurrent.TimeUnit.SECONDS), "loop must terminate")
        loopThread.join(5_000)
        val stats = packetLoop.stats
        assertTrue(stats.stoppedByStopFlag)
        assertEquals(0L, stats.packetsForwarded, "nothing may be forwarded after stop()")
        assertTrue(stats.packetsRead <= 1L, "at most the single post-stop packet was read")
        assertEquals(0, backhaul.forwardCalls)
    }

    @Test
    fun reentrant_stop_from_backhaul_completes_current_packet_then_stops() {
        val pipe = PacketPipe()
        val backhaul = FakeTunnelBackhaul()
        val packetLoop = loop(pipe.tunIo, backhaul)
        backhaul.script = { packet ->
            if (backhaul.forwardCalls == 3) packetLoop.stop() // re-entrant stop
            listOf(packet.copyOf())
        }
        repeat(10) { pipe.inject(TestPackets.numberedUdp(it)) }
        pipe.closeDeviceSide()

        val stats = packetLoop.run()

        assertEquals(3L, stats.packetsForwarded, "current packet completes, then the loop stops")
        assertEquals(3L, stats.responsesWritten)
        assertTrue(stats.stoppedByStopFlag)
        assertEquals(3, backhaul.forwarded.size)
    }

    @Test
    fun eof_terminates_cleanly_without_terminal_error() {
        val pipe = PacketPipe()
        val backhaul = FakeTunnelBackhaul().apply { echo = false } // no responses at all
        pipe.inject(TestPackets.numberedUdp(0))
        pipe.inject(TestPackets.numberedUdp(1))
        pipe.closeDeviceSide()

        val stats = loop(pipe.tunIo, backhaul).run()

        assertEquals(2L, stats.packetsForwarded)
        assertEquals(0L, stats.responsesReceived)
        assertNull(stats.terminalError)
        assertFalse(stats.stoppedByStopFlag)
    }

    @Test
    fun no_traffic_ever_means_blocked_forever_until_close() {
        // Documents (and pins) the honest limit: a blocked read does not
        // observe stop() — the fd close is the unblock signal. Here the
        // close arrives and the loop exits even though it processed
        // nothing.
        val pipe = PacketPipe()
        val stats = loop(pipe.tunIo, FakeTunnelBackhaul()).let { packetLoop ->
            val done = CountDownLatch(1)
            val t = thread { packetLoop.run(); done.countDown() }
            pipe.closeDeviceSide()
            assertTrue(done.await(5, java.util.concurrent.TimeUnit.SECONDS))
            t.join(1_000)
            packetLoop.stats
        }
        assertEquals(0L, stats.packetsRead)
        assertNull(stats.terminalError)
    }
}
