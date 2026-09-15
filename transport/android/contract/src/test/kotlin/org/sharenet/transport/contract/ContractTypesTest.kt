package org.sharenet.transport.contract

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Contract type sanity: frames compare by content; events are data classes. */
class ContractTypesTest {

    @Test
    fun frames_with_same_content_are_equal() {
        val a = TransportFrame(channelId = 7, payload = byteArrayOf(1, 2, 3))
        val b = TransportFrame(channelId = 7, payload = byteArrayOf(1, 2, 3))
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun frames_differ_on_channel_or_payload() {
        val base = TransportFrame(channelId = 7, payload = byteArrayOf(1, 2, 3))
        assertNotEquals(base, TransportFrame(channelId = 8, payload = byteArrayOf(1, 2, 3)))
        assertNotEquals(base, TransportFrame(channelId = 7, payload = byteArrayOf(1, 2, 4)))
    }

    @Test
    fun negative_channelId_is_rejected() {
        assertFailsWith<IllegalArgumentException> { TransportFrame(channelId = -1, payload = ByteArray(0)) }
    }

    @Test
    fun frame_toString_redacts_payload_bytes() {
        val frame = TransportFrame(channelId = 3, payload = byteArrayOf(9, 9, 9))
        val text = frame.toString()
        assertTrue(text.contains("channelId=3"))
        assertTrue(text.contains("payloadSize=3"))
        assertTrue(!text.contains("[9, 9, 9]"), "payload bytes must not appear in toString: $text")
    }

    @Test
    fun endpointId_is_opaque_value() {
        assertEquals(EndpointId("A1"), EndpointId("A1"))
        assertEquals("A1", EndpointId("A1").toString())
    }
}
