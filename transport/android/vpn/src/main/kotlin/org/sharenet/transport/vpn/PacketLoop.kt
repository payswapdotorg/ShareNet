package org.sharenet.transport.vpn

import java.io.IOException

/**
 * Live counters for a packet loop run. Written by the loop thread;
 * reads from other threads see the latest completed updates (fields
 * are volatile — the loop writes one field at a time, so a cross-thread
 * read is an honest snapshot, not an atomic multi-field one).
 */
class PacketLoopStats {
    /** Complete packets read from the TUN device (post-stop reads included). */
    @Volatile var packetsRead: Long = 0L
        private set

    /** Packets handed to the [TunnelBackhaul] (filter-accepted). */
    @Volatile var packetsForwarded: Long = 0L
        private set

    /** Outbound packets dropped by [IpPacketFilter] (bad version/length/protocol). */
    @Volatile var packetsDropped: Long = 0L
        private set

    /** Packets the backhaul produced in response to forwarded packets. */
    @Volatile var responsesReceived: Long = 0L
        private set

    /** Response packets actually written to the TUN device. */
    @Volatile var responsesWritten: Long = 0L
        private set

    /** Response packets rejected by [IpPacketFilter] (defensive re-check). */
    @Volatile var responsesRejected: Long = 0L
        private set

    /** Packets rejected by the MTU bound (see [VpnError.PacketTooLarge]). */
    @Volatile var oversizedRejected: Long = 0L
        private set

    /** Typed error that ended the loop early, if any (IO/backhaul failure). */
    @Volatile var terminalError: VpnError? = null
        private set

    /** True when the run ended because [PacketLoop.stop] was requested. */
    @Volatile var stoppedByStopFlag: Boolean = false
        private set

    internal fun markRead() { packetsRead++ }

    internal fun markForwarded() { packetsForwarded++ }

    internal fun markDropped() { packetsDropped++ }

    internal fun markResponse() { responsesReceived++ }

    internal fun markWritten() { responsesWritten++ }

    internal fun markResponseRejected() { responsesRejected++ }

    internal fun markOversized() { oversizedRejected++ }

    internal fun markTerminal(error: VpnError) { terminalError = error }

    internal fun markStoppedByFlag() { stoppedByStopFlag = true }

    override fun toString(): String =
        "PacketLoopStats(read=$packetsRead, fwd=$packetsForwarded, dropped=$packetsDropped, " +
            "resp=$responsesReceived, written=$responsesWritten, rejected=$responsesRejected, " +
            "oversized=$oversizedRejected, terminal=${terminalError?.javaClass?.simpleName}, " +
            "byStopFlag=$stoppedByStopFlag)"
}

/**
 * The production packet loop (R4-004), in JVM-testable shape.
 *
 * Per iteration (documented ORDER):
 *  1. stop flag checked FIRST — stopping is observed before any I/O;
 *  2. read the next complete packet (at most [mtu] bytes) from [io];
 *     * EOF -> clean return (the device side closed the fd);
 *     * [VpnError.PacketTooLarge] -> counted, packet dropped, loop
 *       CONTINUES (one oversized packet must not kill the VPN);
 *     * [IOException] -> typed [VpnError.IoFailure], loop STOPS;
 *  3. the stop flag is re-checked after the read (a blocked read does
 *     not notice stop() — the caller unblocks it by closing the fd);
 *     a packet read after a stop is DROPPED, not forwarded;
 *  4. [IpPacketFilter] decides: rejected packets are counted and
 *     dropped (the loop survives bad input);
 *  5. accepted packets go to [backhaul]; a throwing backhaul is a
 *     terminal [VpnError.BackhaulFailure] — fail closed;
 *  6. every response is defensively re-filtered (the tunnel is OUR
 *     code, but a corrupted response must not inject a malformed
 *     packet into the device) and written back in order.
 *
 * This class is pure JVM (no android.* imports) — the unit tests run it
 * end-to-end over a pipe-backed [PacketIO] with an echo backhaul.
 */
class PacketLoop(
    private val io: PacketIO,
    private val mtu: Int,
    private val backhaul: TunnelBackhaul,
) {
    private val stopped = java.util.concurrent.atomic.AtomicBoolean(false)

    /** The loop's live counters (same instance [run] returns). */
    val stats = PacketLoopStats()

    init {
        if (mtu !in VpnConfig.MIN_MTU..VpnConfig.MAX_MTU) {
            throw VpnError.InvalidConfig("mtu", "mtu $mtu outside [${VpnConfig.MIN_MTU}, ${VpnConfig.MAX_MTU}]")
        }
    }

    /** True once [stop] has been requested (from any thread). */
    val isStopped: Boolean get() = stopped.get()

    /**
     * Request a graceful stop. Safe from any thread, idempotent, never
     * throws. NOTE: a loop BLOCKED inside a read cannot observe this
     * until the fd delivers or closes — the standard teardown is
     * `stop()` then close the fd (which the pipe tests model as EOF and
     * `ShareNetVpnService` performs via the descriptor owner).
     */
    fun stop() {
        stopped.set(true)
    }

    /**
     * Run the loop (blocking, on the CALLING thread). Returns when the
     * stop flag is observed, the descriptor hits EOF, or a terminal
     * error occurs — it never throws; failures land in
     * [PacketLoopStats.terminalError] as typed [VpnError]s.
     */
    fun run(): PacketLoopStats {
        while (true) {
            if (stopped.get()) {
                stats.markStoppedByFlag()
                return stats
            }
            val packet = try {
                io.readPacket(mtu) ?: return stats // EOF: clean stop
            } catch (tooLarge: VpnError.PacketTooLarge) {
                stats.markOversized()
                continue
            } catch (io: IOException) {
                stats.markTerminal(VpnError.IoFailure(io))
                return stats
            } catch (interrupted: InterruptedException) {
                // Defensive: a loop thread should not be interrupted, but
                // treat it as a stop request, not a crash.
                stats.markStoppedByFlag()
                return stats
            }
            stats.markRead()
            if (stopped.get()) {
                // stop() raced the blocked read: drop the packet, do not
                // forward anything the caller asked us to stop.
                continue
            }
            when (val verdict = IpPacketFilter.inspect(packet)) {
                is PacketVerdict.Accept -> {
                    val responses = try {
                        backhaul.forward(verdict.packet)
                    } catch (failure: Throwable) {
                        stats.markTerminal(VpnError.BackhaulFailure(failure))
                        return stats
                    }
                    stats.markForwarded()
                    for (response in responses) {
                        stats.markResponse()
                        when (val responseVerdict = IpPacketFilter.inspect(response)) {
                            is PacketVerdict.Accept -> {
                                try {
                                    io.writePacket(responseVerdict.packet)
                                } catch (io: IOException) {
                                    stats.markTerminal(VpnError.IoFailure(io))
                                    return stats
                                }
                                stats.markWritten()
                            }
                            is PacketVerdict.Reject -> stats.markResponseRejected()
                        }
                    }
                }
                is PacketVerdict.Reject -> stats.markDropped()
            }
        }
    }
}
