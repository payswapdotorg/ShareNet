package org.sharenet.transport.nearby

import org.sharenet.transport.contract.TransportFrame

/**
 * Payload routing + envelope policy for the Nearby adapter (R2-001).
 *
 * ## BYTES vs STREAM (documented policy)
 *
 * Google does not publish a hard byte limit for BYTES payloads but its
 * guidance is "small payloads" for BYTES and streams for bulk data. This
 * adapter therefore enforces a CONSERVATIVE, documented cap:
 *
 *  * payload ≤ [MAX_BYTES_PAYLOAD_BYTES] → sent as a BYTES payload
 *    (low latency, delivered atomically by the platform);
 *  * payload > [MAX_BYTES_PAYLOAD_BYTES] → sent as a STREAM payload
 *    (chunked bulk transfer). Oversized frames are NEVER silently rejected:
 *    they are always routed onto STREAM — chosen over a typed error because
 *    the tunnel layer (R4-001) needs a reliable bulk path anyway.
 *
 * ## Envelope (documented, adapter-level framing — NOT protocol semantics)
 *
 * Nearby payloads carry no channel metadata, but the contract's
 * [TransportFrame] has a channel id. The adapter therefore frames every
 * wire payload (both BYTES and reassembled STREAM bytes) as:
 *
 * ```text
 * wire := u64be channelId || payload
 * ```
 *
 * This is transport framing inside the adapter (like the length prefix of the
 * Linux UDP transport), not ShareNet protocol semantics: no identity,
 * routing, or cryptographic meaning is assigned here.
 */
object PayloadPolicy {

    /** Conservative cap for BYTES payloads (Google guidance: "small" BYTES). */
    const val MAX_BYTES_PAYLOAD_BYTES: Int = 32 * 1024

    /** Chunk size the fake/GMS layer uses to surface STREAM progress. */
    const val STREAM_CHUNK_BYTES: Int = 16 * 1024

    /** Envelope header size (u64be channelId). */
    const val ENVELOPE_HEADER_BYTES: Int = 8

    /** Where a frame of [payloadSize] bytes will be routed. */
    fun routeFor(payloadSize: Int): PayloadRoute =
        if (payloadSize <= MAX_BYTES_PAYLOAD_BYTES) PayloadRoute.BYTES else PayloadRoute.STREAM

    /** Encode a frame into its wire form: `u64be channelId || payload`. */
    fun encodeEnvelope(channelId: Long, payload: ByteArray): ByteArray {
        val wire = ByteArray(ENVELOPE_HEADER_BYTES + payload.size)
        var v = channelId
        for (i in 0 until ENVELOPE_HEADER_BYTES) {
            wire[i] = ((v ushr 56) and 0xFF).toByte()
            v = v shl 8
        }
        System.arraycopy(payload, 0, wire, ENVELOPE_HEADER_BYTES, payload.size)
        return wire
    }

    /**
     * Decode wire bytes back into a frame. Returns `null` for malformed input
     * (shorter than the 8-byte header) — the adapter drops such payloads and
     * counts them (surfaced via logs today, transport telemetry in R2-004).
     */
    fun decodeEnvelope(wire: ByteArray): TransportFrame? {
        if (wire.size < ENVELOPE_HEADER_BYTES) {
            return null
        }
        var channelId = 0L
        for (i in 0 until ENVELOPE_HEADER_BYTES) {
            channelId = (channelId shl 8) or (wire[i].toLong() and 0xFF)
        }
        if (channelId < 0) {
            return null
        }
        val payload = wire.copyOfRange(ENVELOPE_HEADER_BYTES, wire.size)
        return TransportFrame(channelId, payload)
    }

    /** Split [wire] into [STREAM_CHUNK_BYTES] chunks for stream simulation. */
    fun chunkForStream(wire: ByteArray): List<ByteArray> {
        if (wire.isEmpty()) return listOf(ByteArray(0))
        return wire.asList()
            .chunked(STREAM_CHUNK_BYTES)
            .map { it.toByteArray() }
    }
}

/** Which Nearby payload type a frame is routed onto. */
enum class PayloadRoute { BYTES, STREAM }
