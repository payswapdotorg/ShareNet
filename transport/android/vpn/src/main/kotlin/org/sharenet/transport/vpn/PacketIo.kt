package org.sharenet.transport.vpn

import java.io.IOException

/**
 * The TUN descriptor I/O seam (R4-004) — same seam trick as the nearby
 * module's `NearbyApi`: `java.io` pipes are the only fd-like primitive
 * on the JVM, so the fd I/O is abstracted behind this packet-oriented
 * interface and unit tests drive a pipe-backed fake
 * (`PacketPipe`, test sources). The production adapter is
 * [FdPacketIo] (a thin `ParcelFileDescriptor` wrapper, unit-verified
 * for wiring only — see the module README).
 *
 * TUN semantics this interface promises:
 *  * one [readPacket] = one COMPLETE packet (a TUN read never merges two
 *    packets; a packet larger than the buffer is truncated by the
 *    kernel and the tail is lost);
 *  * [readPacket] blocks until a packet arrives or the descriptor closes.
 */
interface PacketIO {

    /**
     * Read the next COMPLETE packet, at most [maxBytes] bytes.
     *
     * @return the packet, or null when the descriptor reached EOF (the
     *         device side closed — the loop's clean-stop signal).
     * @throws IOException on descriptor failure (the loop records a
     *         typed [VpnError.IoFailure] and stops).
     * @throws VpnError.PacketTooLarge when the next packet is longer
     *         than [maxBytes] — the packet is dropped by the
     *         implementation (consumed/lost, like a truncated TUN read)
     *         and the stream stays usable for the NEXT packet.
     */
    @Throws(IOException::class)
    fun readPacket(maxBytes: Int): ByteArray?

    /**
     * Write one COMPLETE packet to the device. Partial writes are not
     * part of the contract — implementations must deliver all of it.
     *
     * @throws IOException on descriptor failure.
     */
    @Throws(IOException::class)
    fun writePacket(packet: ByteArray)

    /**
     * Close the descriptor. OWNERSHIP NOTE: the packet loop never calls
     * this — the fd belongs to the caller that handed it in
     * (`ShareNetVpnService` closes its fd after stopping the loop; a
     * blocked read is unblocked by that close, not by the stop flag).
     */
    fun close()
}
