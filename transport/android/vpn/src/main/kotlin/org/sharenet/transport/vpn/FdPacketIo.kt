package org.sharenet.transport.vpn

import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException

/**
 * Production [PacketIO] over a real TUN descriptor (R4-004).
 *
 * This is the ANDROID BOUNDARY of the I/O seam (the only file besides
 * `ShareNetVpnService.kt` with `android.*` imports). It is a thin,
 * mechanical adapter — unit-verified for WIRING only (it compiles into
 * the AAR and maps TUN's packet-atomic blocking reads onto [readPacket]);
 * its runtime behavior needs a real `/dev/tun` fd, i.e. a device, which
 * this wave does not have (R10-002 scope).
 *
 * Mapping notes (documented, honest):
 *  * The service establishes the interface with
 *    `Builder.setBlocking(true)`, so [FileInputStream.read] blocks until
 *    a whole packet is available and returns its exact length.
 *  * A packet LARGER than [readPacket]'s buffer is truncated by the
 *    kernel read: the tail is lost and the short remainder fails
 *    [IpPacketFilter]'s total-length check downstream — typed drop,
 *    not a corruption. (The interface's VpnError.PacketTooLarge path
 *    is what the pipe-backed test fake exercises deterministically; on
 *    a real fd truncation is only detectable via the filter.)
 */
class FdPacketIo(fd: ParcelFileDescriptor) : PacketIO {

    private val input = FileInputStream(fd.fileDescriptor)
    private val output = FileOutputStream(fd.fileDescriptor)

    override fun readPacket(maxBytes: Int): ByteArray? {
        if (maxBytes <= 0) throw IllegalArgumentException("maxBytes must be positive")
        val buffer = ByteArray(maxBytes)
        val read = input.read(buffer)
        if (read < 0) return null // EOF: the device side closed the fd
        return buffer.copyOf(read)
    }

    override fun writePacket(packet: ByteArray) {
        output.write(packet)
        output.flush()
    }

    override fun close() {
        // Closing the stream pair releases the underlying fd (single
        // close: ShareNetVpnService routes ALL closes through this
        // method and never calls ParcelFileDescriptor.close() itself —
        // a double close could hit a recycled fd number). Best-effort
        // by contract: never throws.
        try {
            input.close()
        } catch (_: IOException) {
        }
        try {
            output.close()
        } catch (_: IOException) {
        }
    }
}
