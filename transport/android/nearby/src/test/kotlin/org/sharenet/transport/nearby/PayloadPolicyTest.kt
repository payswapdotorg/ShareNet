package org.sharenet.transport.nearby

import org.sharenet.transport.contract.TransportFrame
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Payload policy tests (R2-001): envelope, routing boundary, chunking. */
class PayloadPolicyTest {

    @Test
    fun envelope_roundtrip_preserves_channel_and_payload() {
        val payload = ByteArray(300) { (it % 7).toByte() }
        val wire = PayloadPolicy.encodeEnvelope(42, payload)
        assertEquals(8 + 300, wire.size)
        val frame = PayloadPolicy.decodeEnvelope(wire)!!
        assertEquals(TransportFrame(42, payload), frame)
    }

    @Test
    fun envelope_header_is_u64be() {
        val wire = PayloadPolicy.encodeEnvelope(0x0102030405060708L, ByteArray(0))
        val expected = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        assertTrue(wire.contentEquals(expected), "header was ${wire.joinToString()}")
    }

    @Test
    fun envelope_zero_channel_and_empty_payload_roundtrip() {
        val wire = PayloadPolicy.encodeEnvelope(0, ByteArray(0))
        assertEquals(8, wire.size)
        assertEquals(TransportFrame(0, ByteArray(0)), PayloadPolicy.decodeEnvelope(wire))
    }

    @Test
    fun malformed_envelopes_return_null() {
        assertNull(PayloadPolicy.decodeEnvelope(ByteArray(0)))
        assertNull(PayloadPolicy.decodeEnvelope(ByteArray(7)))
        // u64be with the high bit set decodes to a negative channelId: rejected.
        assertNull(PayloadPolicy.decodeEnvelope(byteArrayOf(-1, 0, 0, 0, 0, 0, 0, 0)))
    }

    @Test
    fun routing_boundary_is_exactly_max_bytes() {
        assertEquals(PayloadRoute.BYTES, PayloadPolicy.routeFor(0))
        assertEquals(PayloadRoute.BYTES, PayloadPolicy.routeFor(PayloadPolicy.MAX_BYTES_PAYLOAD_BYTES))
        assertEquals(
            PayloadRoute.STREAM,
            PayloadPolicy.routeFor(PayloadPolicy.MAX_BYTES_PAYLOAD_BYTES + 1),
        )
    }

    @Test
    fun stream_chunking_covers_all_bytes_in_order() {
        val wire = ByteArray(PayloadPolicy.MAX_BYTES_PAYLOAD_BYTES + 1234) { (it % 31).toByte() }
        val chunks = PayloadPolicy.chunkForStream(wire)
        assertTrue(chunks.all { it.size <= PayloadPolicy.STREAM_CHUNK_BYTES })
        assertEquals(wire.size, chunks.sumOf { it.size })
        val rejoined = ByteArray(wire.size)
        var offset = 0
        for (chunk in chunks) {
            System.arraycopy(chunk, 0, rejoined, offset, chunk.size)
            offset += chunk.size
        }
        assertTrue(wire.contentEquals(rejoined))
    }
}
