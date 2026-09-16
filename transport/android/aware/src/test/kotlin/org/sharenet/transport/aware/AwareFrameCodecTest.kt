package org.sharenet.transport.aware

import org.sharenet.transport.contract.TransportFrame
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * FrameCodec law tests (R2-002) — the frozen repo-wide 4-byte big-endian
 * length-prefix convention over the aware datapath stream, composed with the
 * R2-001 channel envelope:
 *
 * ```text
 * wire := u32be frameLength || u64be channelId || payload
 * ```
 *
 * Adversarial coverage (assignment):
 *  * short length-prefix (split across chunks / stream end mid-frame);
 *  * oversized claim → FrameTooLarge BEFORE buffering (never buffer without
 *    bound — the law), including the hostile 4 GiB-1 claim;
 *  * garbage bytes → MalformedFrameException (impossible prefix, negative
 *    channel envelope);
 *  * decoder state resets on failure (reusable after the caller drops the
 *    endpoint);
 *  * encoder enforces the SAME 2 MiB bound on send.
 */
class AwareFrameCodecTest {

    private fun wire(channelId: Long, payload: ByteArray): ByteArray =
        AwareFrameCodec.encode(channelId, payload)

    private fun u32be(value: Long): ByteArray = byteArrayOf(
        ((value ushr 24) and 0xFF).toByte(),
        ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(),
        (value and 0xFF).toByte(),
    )

    // ------------------------------------------------------------------
    // Encode/decode roundtrips
    // ------------------------------------------------------------------

    @Test
    fun roundtrip_single_frame() {
        val wire = wire(channelId = 7, payload = byteArrayOf(1, 2, 3, 4))
        // u32be(12) || u64be(7) || 4 payload bytes.
        assertEquals(
            u32be(12).toList() + byteArrayOf(0, 0, 0, 0, 0, 0, 0, 7).toList() + listOf(1, 2, 3, 4),
            wire.toList(),
            "the documented wire form",
        )
        val decoder = FrameDecoder()
        val frames = decoder.feed(wire)
        assertEquals(listOf(TransportFrame(7, byteArrayOf(1, 2, 3, 4))), frames)
        assertEquals(0, decoder.pendingBytes)
    }

    @Test
    fun empty_payload_frame_roundtrips() {
        val frames = FrameDecoder().feed(wire(channelId = 3, payload = ByteArray(0)))
        assertEquals(listOf(TransportFrame(3, ByteArray(0))), frames)
    }

    @Test
    fun max_boundary_frame_roundtrips() {
        // frameLength = 8 + payload == MAX_FRAME_BYTES exactly: legal.
        val payload = ByteArray(AwareFrameCodec.MAX_FRAME_BYTES - AwareFrameCodec.ENVELOPE_HEADER_BYTES) { (it % 251).toByte() }
        val frames = FrameDecoder().feed(wire(channelId = 1, payload = payload))
        assertEquals(listOf(TransportFrame(1, payload)), frames)
    }

    @Test
    fun chunked_delivery_one_byte_at_a_time() {
        val wire = wire(channelId = 9, payload = ByteArray(1024) { (it % 253).toByte() })
        val decoder = FrameDecoder()
        var frames = listOf<TransportFrame>()
        for (byte in wire) {
            frames += decoder.feed(byteArrayOf(byte))
        }
        assertEquals(listOf(TransportFrame(9, ByteArray(1024) { (it % 253).toByte() })), frames)
        assertEquals(0, decoder.pendingBytes)
    }

    @Test
    fun multiple_frames_in_one_chunk() {
        val wire = wire(1, byteArrayOf(0x0A)) + wire(2, byteArrayOf(0x0B, 0x0C)) + wire(3, ByteArray(0))
        val frames = FrameDecoder().feed(wire)
        assertEquals(
            listOf(
                TransportFrame(1, byteArrayOf(0x0A)),
                TransportFrame(2, byteArrayOf(0x0B, 0x0C)),
                TransportFrame(3, ByteArray(0)),
            ),
            frames,
        )
    }

    @Test
    fun frames_survive_every_possible_split_offset() {
        // Property-style: split the concatenated wire of two frames at EVERY
        // offset — reassembly must be exact, exactly once, every time.
        val wire = wire(4, byteArrayOf(1, 2, 3)) + wire(5, byteArrayOf(9, 8))
        val expected = listOf(TransportFrame(4, byteArrayOf(1, 2, 3)), TransportFrame(5, byteArrayOf(9, 8)))
        for (split in 0..wire.size) {
            val decoder = FrameDecoder()
            var frames = decoder.feed(wire.copyOfRange(0, split))
            frames += decoder.feed(wire.copyOfRange(split, wire.size))
            assertEquals(expected, frames, "split at offset $split")
        }
    }

    // ------------------------------------------------------------------
    // Short prefix / partial frames (stream ends mid-frame)
    // ------------------------------------------------------------------

    @Test
    fun short_length_prefix_split_across_chunks_stays_pending() {
        val wire = wire(channelId = 2, payload = byteArrayOf(1))
        val decoder = FrameDecoder()
        assertEquals(emptyList(), decoder.feed(wire.copyOfRange(0, 1)))
        assertEquals(emptyList(), decoder.feed(wire.copyOfRange(1, 3)))
        assertEquals(3, decoder.pendingBytes)
        // The remaining byte completes the prefix; the body is still partial.
        assertEquals(emptyList(), decoder.feed(wire.copyOfRange(3, 4)))
        assertEquals(emptyList(), decoder.feed(wire.copyOfRange(4, 8)))
        assertEquals(4, decoder.pendingBytes, "only the partial body is pending")
        assertEquals(listOf(TransportFrame(2, byteArrayOf(1))), decoder.feed(wire.copyOfRange(8, wire.size)))
    }

    @Test
    fun partial_prefix_then_claim_with_no_body_emits_no_frame() {
        val decoder = FrameDecoder()
        assertEquals(emptyList<TransportFrame>(), decoder.feed(byteArrayOf(0, 0, 0)))
        assertEquals(3, decoder.pendingBytes)
        // Completing the prefix claims a 16-byte body that never arrives: no
        // frame, no error (a stream END is not corruption — the caller
        // discards the partial with the endpoint).
        assertEquals(emptyList<TransportFrame>(), decoder.feed(byteArrayOf(16)))
        assertEquals(0, decoder.pendingBytes, "the parsed prefix is consumed; the body is empty")
    }

    @Test
    fun stream_end_mid_body_leaves_only_a_partial_frame() {
        val wire = wire(channelId = 6, payload = ByteArray(100) { 7 })
        val decoder = FrameDecoder()
        decoder.feed(wire.copyOfRange(0, wire.size - 10))
        assertEquals(emptyList<TransportFrame>(), decoder.feed(ByteArray(0)))
        assertEquals(98, decoder.pendingBytes, "the partial frame stays buffered")
        // The caller (adapter) discards it with the endpoint: no frame is
        // ever delivered from a partial tail.
    }

    // ------------------------------------------------------------------
    // Oversized claims — reject BEFORE buffering (the FrameCodec law)
    // ------------------------------------------------------------------

    @Test
    fun oversized_claim_is_rejected_before_buffering() {
        val decoder = FrameDecoder()
        // A prefix claiming 3 MiB (> the 2 MiB law) followed by nothing —
        // the rejection must happen at the PREFIX, before any body.
        val claim = u32be(3 * 1024 * 1024)
        val error = assertFailsWith<FrameTooLargeException> { decoder.feed(claim) }
        assertEquals(3 * 1024 * 1024L, error.claimedLength)
        assertEquals(AwareFrameCodec.MAX_FRAME_BYTES, error.maximum)
        assertTrue(
            decoder.pendingBytes < 100,
            "nothing was buffered beyond the prefix (law: never buffer without bound); pending=${decoder.pendingBytes}",
        )
    }

    @Test
    fun hostile_4gib_claim_is_reported_honestly_unsigned() {
        val decoder = FrameDecoder()
        // 0xFFFFFFFF = 4294967295: the maximum u32be claim. It must be
        // rejected with the HONEST unsigned value, not a sign-wrapped -1.
        val error = assertFailsWith<FrameTooLargeException> { decoder.feed(u32be(0xFFFFFFFFL)) }
        assertEquals(4_294_967_295L, error.claimedLength)
    }

    @Test
    fun oversized_claim_after_partial_data_is_also_rejected_at_prefix() {
        val decoder = FrameDecoder()
        // A complete frame first, then a hostile claim in the same stream.
        val good = wire(1, byteArrayOf(1))
        val claim = u32be(2 * 1024 * 1024 + 1)
        val error = assertFailsWith<FrameTooLargeException> {
            decoder.feed(good + claim)
        }
        assertEquals(2 * 1024 * 1024 + 1L, error.claimedLength)
        assertEquals(0, decoder.pendingBytes, "state reset: the good frame was already emitted")
    }

    @Test
    fun a_single_hostile_multi_megabyte_chunk_cannot_force_buffering() {
        // The bounded-feed law: even one giant chunk containing a hostile
        // claim in its middle is rejected at the prefix — the decoder never
        // copies more of the chunk than the frame under assembly needs.
        val decoder = FrameDecoder()
        val good = wire(1, byteArrayOf(5))
        val hostile = u32be(0xFFFF_FFF0)
        val filler = ByteArray(1024 * 1024) { 0x41 } // 1 MiB of garbage after the claim
        val error = assertFailsWith<FrameTooLargeException> {
            decoder.feed(good + hostile + filler)
        }
        assertEquals(0xFFFF_FFF0L, error.claimedLength)
        assertTrue(decoder.pendingBytes < 100, "bounded: pending=${decoder.pendingBytes}")
    }

    // ------------------------------------------------------------------
    // Garbage bytes — typed frame errors, stream desynchronization
    // ------------------------------------------------------------------

    @Test
    fun prefix_too_small_for_envelope_is_malformed() {
        val decoder = FrameDecoder()
        // A prefix of 7 cannot even carry the 8-byte channel envelope.
        val error = assertFailsWith<MalformedFrameException> { decoder.feed(u32be(7) + ByteArray(7)) }
        assertTrue(error.message!!.contains("cannot carry"))
        assertEquals(0, decoder.pendingBytes, "state reset")
    }

    @Test
    fun garbage_negative_channel_envelope_is_malformed() {
        val decoder = FrameDecoder()
        // frameLength = 8 (envelope only), channelId with the high bit set:
        // garbage that happens to parse as a legal length.
        val garbage = u32be(8) + byteArrayOf(0xFF.toByte()) + ByteArray(7)
        val error = assertFailsWith<MalformedFrameException> { decoder.feed(garbage) }
        assertTrue(error.message!!.contains("garbage"))
        assertEquals(0, decoder.pendingBytes, "state reset")
    }

    @Test
    fun decoder_is_reusable_after_a_corruption_reset() {
        val decoder = FrameDecoder()
        assertFailsWith<FrameTooLargeException> { decoder.feed(u32be(0x7FFF_FFFF)) }
        // After the caller dropped the endpoint, a FRESH stream's frames
        // decode cleanly (the reset law).
        val frames = decoder.feed(wire(11, byteArrayOf(1, 2)))
        assertEquals(listOf(TransportFrame(11, byteArrayOf(1, 2))), frames)
    }

    // ------------------------------------------------------------------
    // Send-side enforcement (the bound applies on BOTH sides)
    // ------------------------------------------------------------------

    @Test
    fun encoder_rejects_oversized_frames_with_typed_error() {
        val tooBig = ByteArray(AwareFrameCodec.MAX_FRAME_BYTES - AwareFrameCodec.ENVELOPE_HEADER_BYTES + 1)
        val error = assertFailsWith<FrameTooLargeException> {
            AwareFrameCodec.encode(channelId = 1, payload = tooBig)
        }
        assertEquals(AwareFrameCodec.MAX_FRAME_BYTES + 1L, error.claimedLength)
    }

    @Test
    fun encoder_accepts_exactly_the_bound() {
        val payload = ByteArray(AwareFrameCodec.MAX_FRAME_BYTES - AwareFrameCodec.ENVELOPE_HEADER_BYTES)
        val wire = AwareFrameCodec.encode(channelId = 0, payload = payload)
        assertEquals(AwareFrameCodec.LENGTH_PREFIX_BYTES + AwareFrameCodec.MAX_FRAME_BYTES, wire.size)
    }

    @Test
    fun frame_too_large_is_a_typed_runtime_error_not_a_transport_error() {
        // The codec is adapter-level: its typed errors are codec-local
        // exceptions the ADAPTER translates into contract TransportErrors
        // (the sealed contract hierarchy cannot be extended outside :contract).
        val error = assertFailsWith<RuntimeException> {
            AwareFrameCodec.encode(channelId = 1, payload = ByteArray(AwareFrameCodec.MAX_FRAME_BYTES))
        }
        assertIs<FrameTooLargeException>(error)
    }
}
