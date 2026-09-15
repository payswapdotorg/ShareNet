package org.sharenet.transport.vpn

/**
 * IP version + transport protocol vocabulary for the packet filter.
 * Numbers are the IANA assigned values found in the IP header fields.
 */
enum class IpProtocol(val number: Int) {
    ICMP(1),
    TCP(6),
    UDP(17),
}

/**
 * Typed verdict for one inspected packet.
 *
 * [Reject.reason] is a typed reason (never a bare boolean/string) so
 * logging/dedup seams can distinguish failure classes.
 */
sealed class PacketVerdict {
    /** A complete, structurally sound packet — forward it. */
    data class Accept(val packet: ByteArray) : PacketVerdict()

    /** Dropped; [reason] says exactly why. */
    data class Reject(val reason: RejectReason) : PacketVerdict()
}

/** Typed drop reasons, with the offending values where meaningful. */
sealed class RejectReason {
    /** Zero bytes arrived. */
    object EmptyPacket : RejectReason()

    /** Fewer bytes than the base header needs (20 v4 / 40 v6). */
    data class ShortHeader(val have: Int, val need: Int) : RejectReason()

    /** Version nibble is neither 4 nor 6. */
    data class VersionMismatch(val version: Int) : RejectReason()

    /** IPv4 IHL nibble below 5 (header shorter than the 20-byte minimum). */
    data class BadHeaderLength(val ihlBytes: Int) : RejectReason()

    /** IPv4 total-length field disagrees with the actual byte count. */
    data class TotalLengthMismatch(val declared: Int, val actual: Int) : RejectReason()

    /** IPv6 payload-length field disagrees with the bytes after the base header. */
    data class PayloadLengthMismatch(val declared: Int, val actual: Int) : RejectReason()

    /** IPv4 protocol outside the allow-list (see [IpPacketFilter.ALLOWED_PROTOCOLS]). */
    data class ProtocolBlocked(val protocol: Int) : RejectReason()

    /** IPv6 jumbogram (payload length 0 with a jumbo option): unsupported. */
    object JumbogramUnsupported : RejectReason()

    /** Larger than the absolute per-packet bound (see [IpPacketFilter.MAX_PACKET_BYTES]). */
    data class TooLarge(val size: Int, val maxBytes: Int) : RejectReason()
}

/** Best-effort flow identity (src/dst/proto/ports) for logging/dedup seams. */
data class FlowKey(
    val srcAddr: String,
    val dstAddr: String,
    val protocol: IpProtocol,
    val srcPort: Int,
    val dstPort: Int,
)

/**
 * Pure-Kotlin IP packet sanity filter (R4-004) — the gate between the
 * TUN device and the [TunnelBackhaul].
 *
 * IPv4 (deep inspection, strict):
 *  1. version nibble == 4;
 *  2. IHL >= 5 (header >= 20 bytes) and total length >= IHL*4;
 *  3. the total-length field must EQUAL the actual byte count —
 *     truncated, padded, and oversized packets are all rejected;
 *  4. protocol must be TCP/UDP/ICMP (others dropped, typed reason).
 *
 * IPv6 (pass-through, shallow):
 *  * version nibble == 6, base header complete (40 bytes), and the
 *    payload-length field consistent with the actual byte count
 *    (40 + payloadLength == size). NO deep inspection: extension
 *    headers make the next-header chain position-dependent, so
 *    protocol policy and flow-key extraction are IPv4-only (documented
 *    seam — full IPv6 flow awareness is future tunnel-layer work).
 *
 * Check order is fixed and test-asserted: empty -> too large -> version
 * -> family-specific checks. Everything here is JVM-pure and covered by
 * hand-built byte arrays in the unit tests.
 */
object IpPacketFilter {

    /** 40-byte IPv6 base header + the 16-bit payload-length maximum. */
    const val MAX_PACKET_BYTES: Int = 40 + 65_535

    /** IPv4 base header size. */
    const val IPV4_HEADER_BYTES: Int = 20

    /** IPv6 base header size. */
    const val IPV6_HEADER_BYTES: Int = 40

    /** The only IPv4 protocols this data plane forwards. */
    val ALLOWED_PROTOCOLS: Set<Int> = setOf(IpProtocol.ICMP.number, IpProtocol.TCP.number, IpProtocol.UDP.number)

    /**
     * Inspect one COMPLETE packet (TUN reads deliver whole packets).
     *
     * @throws VpnError never — rejection is a typed [PacketVerdict.Reject].
     */
    fun inspect(packet: ByteArray): PacketVerdict {
        if (packet.isEmpty()) return PacketVerdict.Reject(RejectReason.EmptyPacket)
        if (packet.size > MAX_PACKET_BYTES) {
            return PacketVerdict.Reject(RejectReason.TooLarge(packet.size, MAX_PACKET_BYTES))
        }
        val version = packet[0].toInt() ushr 4 and 0xF
        return when (version) {
            4 -> inspectIpv4(packet)
            6 -> inspectIpv6(packet)
            else -> PacketVerdict.Reject(RejectReason.VersionMismatch(version))
        }
    }

    /**
     * Best-effort flow key (IPv4 only; IPv6 is pass-through-only here).
     * Returns null when the packet is not a valid IPv4 datagram or the
     * transport header does not carry ports (TCP/UDP shorter than
     * 4 bytes past the IP header; ICMP gets ports 0/0).
     */
    fun flowKey(packet: ByteArray): FlowKey? {
        val verdict = inspect(packet)
        if (verdict !is PacketVerdict.Accept) return null
        val ihlBytes = (packet[0].toInt() and 0xF) * 4
        val protocolNumber = packet[9].toInt() and 0xFF
        val protocol = IpProtocol.entries.firstOrNull { it.number == protocolNumber } ?: return null
        val src = formatIpv4(packet, 12)
        val dst = formatIpv4(packet, 16)
        return when (protocol) {
            IpProtocol.ICMP -> FlowKey(src, dst, protocol, 0, 0)
            IpProtocol.TCP, IpProtocol.UDP -> {
                if (packet.size < ihlBytes + 4) return null // ports absent
                FlowKey(
                    src, dst, protocol,
                    u16(packet, ihlBytes),
                    u16(packet, ihlBytes + 2),
                )
            }
        }
    }

    private fun inspectIpv4(packet: ByteArray): PacketVerdict {
        if (packet.size < IPV4_HEADER_BYTES) {
            return PacketVerdict.Reject(RejectReason.ShortHeader(packet.size, IPV4_HEADER_BYTES))
        }
        val ihlBytes = (packet[0].toInt() and 0xF) * 4
        if (ihlBytes < IPV4_HEADER_BYTES) {
            return PacketVerdict.Reject(RejectReason.BadHeaderLength(ihlBytes))
        }
        val declared = u16(packet, 2)
        if (declared != packet.size || declared < ihlBytes) {
            return PacketVerdict.Reject(RejectReason.TotalLengthMismatch(declared, packet.size))
        }
        val protocol = packet[9].toInt() and 0xFF
        if (protocol !in ALLOWED_PROTOCOLS) {
            return PacketVerdict.Reject(RejectReason.ProtocolBlocked(protocol))
        }
        return PacketVerdict.Accept(packet)
    }

    private fun inspectIpv6(packet: ByteArray): PacketVerdict {
        if (packet.size < IPV6_HEADER_BYTES) {
            return PacketVerdict.Reject(RejectReason.ShortHeader(packet.size, IPV6_HEADER_BYTES))
        }
        val declared = u16(packet, 4)
        val actual = packet.size - IPV6_HEADER_BYTES
        if (declared == 0) {
            // Zero payload is legal (exactly the 40-byte base header);
            // payload 0 with MORE bytes claims a jumbogram we cannot verify.
            return if (actual == 0) {
                PacketVerdict.Accept(packet)
            } else {
                PacketVerdict.Reject(RejectReason.JumbogramUnsupported)
            }
        }
        if (declared != actual) {
            return PacketVerdict.Reject(RejectReason.PayloadLengthMismatch(declared, actual))
        }
        return PacketVerdict.Accept(packet)
    }

    private fun u16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xFF) shl 8) or (packet[offset + 1].toInt() and 0xFF)

    private fun formatIpv4(packet: ByteArray, offset: Int): String =
        "${packet[offset].toInt() and 0xFF}.${packet[offset + 1].toInt() and 0xFF}." +
            "${packet[offset + 2].toInt() and 0xFF}.${packet[offset + 3].toInt() and 0xFF}"
}
