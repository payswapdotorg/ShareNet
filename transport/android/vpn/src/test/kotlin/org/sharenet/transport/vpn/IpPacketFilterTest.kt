package org.sharenet.transport.vpn

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * IpPacketFilter tests (R4-004): hand-built IPv4/IPv6 byte arrays —
 * valid packets pass, every malformed/short/truncated/mismatched shape
 * is rejected with the TYPED reason, and the protocol policy (and its
 * IPv6 exemption) is enforced.
 */
class IpPacketFilterTest {

    private fun reject(packet: ByteArray): RejectReason {
        val verdict = IpPacketFilter.inspect(packet)
        return assertIs<PacketVerdict.Reject>(verdict).reason
    }

    private fun accept(packet: ByteArray): ByteArray {
        val verdict = IpPacketFilter.inspect(packet)
        return assertIs<PacketVerdict.Accept>(verdict).packet
    }

    // ---------- IPv4 happy paths ----------

    @Test
    fun valid_ipv4_udp_packet_passes() {
        val packet = TestPackets.udpIpv4()
        assertTrue(accept(packet).contentEquals(packet))
    }

    @Test
    fun valid_ipv4_tcp_and_icmp_packets_pass() {
        assertTrue(IpPacketFilter.inspect(TestPackets.tcpIpv4()) is PacketVerdict.Accept)
        assertTrue(IpPacketFilter.inspect(TestPackets.ipv4(protocol = 1)) is PacketVerdict.Accept)
    }

    @Test
    fun ipv4_with_options_ihl_gt_5_passes() {
        // IHL 6 = 24-byte header (4 option bytes); total length must match.
        val packet = TestPackets.ipv4(payloadBytes = 8, ihlNibble = 6)
        assertEquals(32, packet.size) // 24-byte header + 8 payload
        assertTrue(IpPacketFilter.inspect(packet) is PacketVerdict.Accept)
    }

    // ---------- IPv4 structure ----------

    @Test
    fun empty_packet_rejected() {
        assertEquals(RejectReason.EmptyPacket, reject(ByteArray(0)))
    }

    @Test
    fun version_mismatch_rejected() {
        val reason = reject(TestPackets.ipv4(versionNibble = 5))
        assertEquals(5, assertIs<RejectReason.VersionMismatch>(reason).version)
        assertEquals(0, assertIs<RejectReason.VersionMismatch>(reject(ByteArray(1))).version)
    }

    @Test
    fun short_ipv4_header_rejected() {
        val reason = reject(ByteArray(19) { 0x45 })
        val short = assertIs<RejectReason.ShortHeader>(reason)
        assertEquals(19, short.have)
        assertEquals(20, short.need)
    }

    @Test
    fun ihl_below_minimum_rejected() {
        // IHL nibble 4 => 16-byte header < the 20-byte minimum. The buffer
        // must be >= 20 bytes so the SHORT-header check does not fire first
        // (check order: buffer length, then IHL) — like a crafted packet
        // carrying 20+ bytes while declaring a short header.
        val reason = reject(TestPackets.ipv4(ihlNibble = 4, payloadBytes = 4))
        assertEquals(16, assertIs<RejectReason.BadHeaderLength>(reason).ihlBytes)
    }

    @Test
    fun truncated_total_length_rejected() {
        // Declares 64 bytes, actually 32.
        val reason = reject(TestPackets.ipv4(payloadBytes = 12, totalLengthOverride = 64))
        val mismatch = assertIs<RejectReason.TotalLengthMismatch>(reason)
        assertEquals(64, mismatch.declared)
        assertEquals(32, mismatch.actual)
    }

    @Test
    fun trailing_bytes_beyond_total_length_rejected() {
        // Declares 20, actually 24 (oversized/trailing garbage).
        val reason = reject(TestPackets.ipv4(payloadBytes = 4, totalLengthOverride = 20))
        val mismatch = assertIs<RejectReason.TotalLengthMismatch>(reason)
        assertEquals(20, mismatch.declared)
        assertEquals(24, mismatch.actual)
    }

    @Test
    fun total_length_below_header_length_rejected() {
        // IHL 6 (24-byte header) but total length says 22.
        val reason = reject(TestPackets.ipv4(payloadBytes = 4, ihlNibble = 6, totalLengthOverride = 22))
        assertIs<RejectReason.TotalLengthMismatch>(reason)
    }

    @Test
    fun absolute_size_bound_rejected() {
        val huge = ByteArray(IpPacketFilter.MAX_PACKET_BYTES + 1)
        huge[0] = 0x60
        val reason = reject(huge)
        val tooLarge = assertIs<RejectReason.TooLarge>(reason)
        assertEquals(IpPacketFilter.MAX_PACKET_BYTES + 1, tooLarge.size)
        assertEquals(IpPacketFilter.MAX_PACKET_BYTES, tooLarge.maxBytes)
    }

    // ---------- IPv4 protocol policy ----------

    @Test
    fun blocked_protocols_rejected_with_typed_reason() {
        for ((name, number) in listOf("GRE" to 47, "OSPF" to 89, "SCTP" to 132, "hopopt" to 0)) {
            val reason = reject(TestPackets.ipv4(protocol = number))
            val blocked = assertIs<RejectReason.ProtocolBlocked>(reason, "expected ProtocolBlocked for $name")
            assertEquals(number, blocked.protocol)
        }
    }

    @Test
    fun allowed_protocol_set_is_exactly_icmp_tcp_udp() {
        assertEquals(setOf(1, 6, 17), IpPacketFilter.ALLOWED_PROTOCOLS)
    }

    // ---------- IPv6 (pass-through, shallow) ----------

    @Test
    fun valid_ipv6_packet_passes() {
        assertTrue(IpPacketFilter.inspect(TestPackets.ipv6(payloadBytes = 16)) is PacketVerdict.Accept)
    }

    @Test
    fun ipv6_header_only_packet_with_zero_payload_length_passes() {
        assertTrue(IpPacketFilter.inspect(TestPackets.ipv6(payloadBytes = 0)) is PacketVerdict.Accept)
    }

    @Test
    fun short_ipv6_header_rejected() {
        val reason = reject(ByteArray(39) { 0x60 })
        val short = assertIs<RejectReason.ShortHeader>(reason)
        assertEquals(39, short.have)
        assertEquals(40, short.need)
    }

    @Test
    fun ipv6_payload_length_mismatch_rejected_both_directions() {
        // Declares 8, actually carries 12.
        val declaredShort = assertIs<RejectReason.PayloadLengthMismatch>(
            reject(TestPackets.ipv6(payloadBytes = 12, payloadLengthOverride = 8)),
        )
        assertEquals(8, declaredShort.declared)
        assertEquals(12, declaredShort.actual)

        // Declares 32, actually carries 8.
        val declaredLong = assertIs<RejectReason.PayloadLengthMismatch>(
            reject(TestPackets.ipv6(payloadBytes = 8, payloadLengthOverride = 32)),
        )
        assertEquals(32, declaredLong.declared)
        assertEquals(8, declaredLong.actual)
    }

    @Test
    fun ipv6_jumbogram_claim_rejected() {
        // Payload length 0 with extra bytes claims a jumbogram.
        assertEquals(RejectReason.JumbogramUnsupported, reject(TestPackets.ipv6(payloadBytes = 100, payloadLengthOverride = 0)))
    }

    @Test
    fun ipv6_is_pass_through_even_for_blocked_protocols() {
        // Deep inspection is IPv4-only: a v6 packet whose next header is
        // GRE (47) still passes (documented module limitation).
        assertTrue(IpPacketFilter.inspect(TestPackets.ipv6(payloadBytes = 8, nextHeader = 47)) is PacketVerdict.Accept)
    }

    // ---------- flow keys ----------

    @Test
    fun flow_key_extracts_tcp_addresses_and_ports() {
        val key = IpPacketFilter.flowKey(TestPackets.tcpIpv4())!!
        assertEquals("10.0.0.2", key.srcAddr)
        assertEquals("10.0.0.1", key.dstAddr)
        assertEquals(IpProtocol.TCP, key.protocol)
        assertEquals(1234, key.srcPort)
        assertEquals(443, key.dstPort)
    }

    @Test
    fun flow_key_extracts_udp_addresses_and_ports() {
        val key = IpPacketFilter.flowKey(TestPackets.udpIpv4())!!
        assertEquals(IpProtocol.UDP, key.protocol)
        assertEquals(5353, key.srcPort)
        assertEquals(5353, key.dstPort)
    }

    @Test
    fun flow_key_icmp_has_zero_ports() {
        val key = IpPacketFilter.flowKey(TestPackets.ipv4(protocol = 1, payloadBytes = 8))!!
        assertEquals(IpProtocol.ICMP, key.protocol)
        assertEquals(0, key.srcPort)
        assertEquals(0, key.dstPort)
    }

    @Test
    fun flow_key_with_options_uses_ports_after_the_real_header() {
        val packet = TestPackets.ipv4(payloadBytes = 24, protocol = 6, ihlNibble = 6)
        packet[24] = (5555 ushr 8).toByte()
        packet[25] = (5555 and 0xFF).toByte()
        packet[26] = (80 ushr 8).toByte()
        packet[27] = (80 and 0xFF).toByte()
        val key = IpPacketFilter.flowKey(packet)!!
        assertEquals(5555, key.srcPort)
        assertEquals(80, key.dstPort)
    }

    @Test
    fun flow_key_returns_null_for_ipv6_and_invalid_packets() {
        assertNull(IpPacketFilter.flowKey(TestPackets.ipv6(payloadBytes = 8))) // v6: pass-through only
        assertNull(IpPacketFilter.flowKey(TestPackets.ipv4(versionNibble = 5))) // not IPv4
        assertNull(IpPacketFilter.flowKey(TestPackets.ipv4(totalLengthOverride = 999))) // malformed
        assertNull(IpPacketFilter.flowKey(ByteArray(0)))
    }

    @Test
    fun flow_key_returns_null_when_transport_ports_absent() {
        // TCP declared exactly at the IP header: no 4 port bytes at all.
        val packet = TestPackets.ipv4(payloadBytes = 0, protocol = 6)
        assertEquals(20, packet.size)
        assertNull(IpPacketFilter.flowKey(packet))
    }
}
