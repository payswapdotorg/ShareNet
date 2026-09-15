package org.sharenet.transport.vpn

import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.io.PipedInputStream
import java.io.PipedOutputStream

/**
 * Pipe-backed JVM fake of the TUN descriptor (test sources ONLY — the
 * same seam trick the nearby module uses for GMS: the fd I/O boundary
 * is [PacketIO], so tests never need a real `ParcelFileDescriptor`).
 *
 * Two `java.io` pipes model the two directions of the TUN fd:
 *
 *                     device side        tun side (loop)
 *   outbound packets  [inject] ───────▶  [readPacket]
 *   responses         [receive] ◀─────── [writePacket]
 *
 * Because byte pipes do not preserve packet boundaries, the fake adds a
 * 4-byte big-endian length prefix per packet on BOTH directions — the
 * framing lives entirely inside this helper; the production
 * [FdPacketIo] needs none of it (a real TUN read is packet-atomic).
 *
 * Semantics deliberately mirroring the real descriptor:
 *  * [closeDeviceSide] is the fd close: buffered packets stay readable,
 *    then the loop sees EOF (readPacket -> null) — the clean-stop path;
 *  * a packet larger than the read bound is CONSUMED (skipped) and
 *    raises [VpnError.PacketTooLarge], like a truncated TUN read.
 */
class PacketPipe(pipeCapacityBytes: Int = 512 * 1024) {

    private val lock = Any()

    // device -> tun direction
    private val deviceToTunOut = PipedOutputStream()
    private val deviceToTunIn = PipedInputStream(deviceToTunOut, pipeCapacityBytes)
    private val deviceToTunWriter = DataOutputStream(deviceToTunOut)
    private val deviceToTunReader = DataInputStream(deviceToTunIn)

    // tun -> device direction
    private val tunToDeviceOut = PipedOutputStream()
    private val tunToDeviceIn = PipedInputStream(tunToDeviceOut, pipeCapacityBytes)
    private val tunToDeviceWriter = DataOutputStream(tunToDeviceOut)
    private val deviceReader = DataInputStream(tunToDeviceIn)

    private var deviceSideClosed = false

    /** The loop's view of the TUN descriptor. */
    val tunIo: PacketIO = object : PacketIO {

        override fun readPacket(maxBytes: Int): ByteArray? {
            val length = try {
                deviceToTunReader.readInt()
            } catch (eof: EOFException) {
                return null // device side closed: clean EOF
            }
            if (length < 0) throw IOException("malformed test frame length $length")
            if (length > maxBytes) {
                consume(length) // truncated real-TUN read loses the tail
                throw VpnError.PacketTooLarge(length, maxBytes)
            }
            val packet = ByteArray(length)
            try {
                deviceToTunReader.readFully(packet)
            } catch (eof: EOFException) {
                throw IOException("test pipe truncated mid-packet", eof)
            }
            return packet
        }

        override fun writePacket(packet: ByteArray) {
            synchronized(lock) {
                tunToDeviceWriter.writeInt(packet.size)
                tunToDeviceWriter.write(packet)
                tunToDeviceWriter.flush()
            }
        }

        override fun close() {
            // The loop never closes its IO (ownership stays with whoever
            // created the fd); nothing to do for the loop's view here.
        }
    }

    /** Test -> device: enqueue one outbound packet for the loop. */
    fun inject(packet: ByteArray) {
        check(!deviceSideClosed) { "test bug: inject after closeDeviceSide" }
        synchronized(lock) {
            deviceToTunWriter.writeInt(packet.size)
            deviceToTunWriter.write(packet)
            deviceToTunWriter.flush()
        }
    }

    /**
     * Test <- device: read one response packet (blocking). null at EOF.
     *
     * (java.io pipes flag a dead writer thread as IOException("Write end
     * dead") only once the buffer is DRAINED, so a loop-thread shutdown
     * after writing responses still lets the test read them all — after
     * that, treat the broken pipe as EOF.)
     */
    fun receive(): ByteArray? {
        val length = try {
            deviceReader.readInt()
        } catch (eof: EOFException) {
            return null
        } catch (deadWriter: IOException) {
            return null // write end dead after the buffer drained
        }
        val packet = ByteArray(length)
        deviceReader.readFully(packet)
        return packet
    }

    /** Close the device side: buffered packets drain, then the loop sees EOF. */
    fun closeDeviceSide() {
        deviceSideClosed = true
        deviceToTunWriter.close()
    }

    /**
     * Close the LOOP side of the response direction (the loop's end of the
     * fd). Call this once the loop has exited (`run()` returned) and no
     * more responses can ever be written: buffered responses stay
     * readable, then [receive] sees EOF — the same drain-then-EOF a real
     * descriptor gives its reader when the writer end goes away.
     *
     * Without it, a test that drained responses with [receive] on the SAME
     * thread that ran the loop would wait forever: the pipe's write end
     * belongs to that (alive, idle) thread, so an empty read just blocks.
     */
    fun closeTunSide() {
        tunToDeviceWriter.close()
    }

    private fun consume(length: Int) {
        val sink = ByteArray(minOf(length, 8192))
        var remaining = length
        while (remaining > 0) {
            val chunk = minOf(remaining, sink.size)
            deviceToTunReader.readFully(sink, 0, chunk)
            remaining -= chunk
        }
    }
}
