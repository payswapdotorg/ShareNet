package org.sharenet.transport.vpn

/**
 * Hand-built IP packet constructors for the filter/loop tests — no
 * real network stack involved, every field under the test's control.
 */
object TestPackets {

    /**
     * Minimal IPv4 packet. Defaults: version 4, IHL 5, UDP, declared
     * total length == actual size, addresses 10.0.0.2 -> 10.0.0.1.
     */
    fun ipv4(
        payloadBytes: Int = 4,
        protocol: Int = 17, // UDP
        versionNibble: Int = 4,
        ihlNibble: Int = 5,
        totalLengthOverride: Int? = null,
        src: ByteArray = byteArrayOf(10, 0, 0, 2),
        dst: ByteArray = byteArrayOf(10, 0, 0, 1),
    ): ByteArray {
        val ihlBytes = ihlNibble * 4
        require(ihlBytes >= 0)
        val size = ihlBytes + payloadBytes
        val packet = ByteArray(size)
        packet[0] = (((versionNibble and 0xF) shl 4) or (ihlNibble and 0xF)).toByte()
        val total = totalLengthOverride ?: size
        packet[2] = (total ushr 8).toByte()
        packet[3] = (total and 0xFF).toByte()
        packet[8] = 64.toByte() // TTL
        packet[9] = protocol.toByte()
        if (size >= 20) { // sub-minimum headers stay truncated (test shapes)
            System.arraycopy(src, 0, packet, 12, 4)
            System.arraycopy(dst, 0, packet, 16, 4)
        }
        for (i in 0 until payloadBytes) {
            packet[ihlBytes + i] = ((i * 7 + 1) and 0xFF).toByte()
        }
        return packet
    }

    /** Valid IPv4/TCP packet with ports 1234 -> 443 (IHL 5, 20-byte TCP header). */
    fun tcpIpv4(segmentBytes: Int = 0): ByteArray {
        val packet = ipv4(payloadBytes = 20 + segmentBytes, protocol = 6)
        packet[20] = (1234 ushr 8).toByte() // src port
        packet[21] = (1234 and 0xFF).toByte()
        packet[22] = (443 ushr 8).toByte() // dst port
        packet[23] = (443 and 0xFF).toByte()
        return packet
    }

    /** Valid IPv4/UDP packet with ports 5353 -> 5353. */
    fun udpIpv4(payloadBytes: Int = 8): ByteArray {
        val packet = ipv4(payloadBytes = 8 + payloadBytes, protocol = 17)
        packet[20] = (5353 ushr 8).toByte()
        packet[21] = (5353 and 0xFF).toByte()
        packet[22] = (5353 ushr 8).toByte()
        packet[23] = (5353 and 0xFF).toByte()
        return packet
    }

    /** Minimal IPv6 packet (40-byte base header + payload). */
    fun ipv6(
        payloadBytes: Int = 8,
        versionNibble: Int = 6,
        payloadLengthOverride: Int? = null,
        nextHeader: Int = 17, // UDP
    ): ByteArray {
        val size = 40 + payloadBytes
        val packet = ByteArray(size)
        packet[0] = (((versionNibble and 0xF) shl 4) or 0).toByte()
        val payloadLength = payloadLengthOverride ?: payloadBytes
        packet[4] = (payloadLength ushr 8).toByte()
        packet[5] = (payloadLength and 0xFF).toByte()
        packet[6] = nextHeader.toByte() // byte 6: next header
        packet[7] = 64.toByte() // byte 7: hop limit
        for (i in 0 until payloadBytes) {
            packet[40 + i] = ((i * 3 + 1) and 0xFF).toByte()
        }
        return packet
    }

    /** Distinct, valid UDP packets (loop order tests): payload varies with [i]. */
    fun numberedUdp(i: Int): ByteArray = udpIpv4(payloadBytes = 16).also {
        it[28] = i.toByte() // inside the UDP payload
    }
}
