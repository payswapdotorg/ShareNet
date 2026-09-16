package org.sharenet.transport.aware

import org.sharenet.transport.contract.TransportFrame
import java.io.ByteArrayOutputStream

/**
 * The 4-byte big-endian length-prefix frame convention over the aware
 * datapath stream (R2-002), composed with the R2-001 channel envelope:
 *
 * ```text
 * wire := u32be frameLength || u64be channelId || payload
 * frameLength = 8 + payload.size
 * ```
 *
 * This is the exact convention used across the ShareNet transport adapters:
 *  * the u32 BE prefix + [MAX_FRAME_BYTES] = 2 MiB bound enforced on BOTH
 *    send and receive is the frozen tunnel law (`spec/protocol-registry.yaml`
 *    L012-adjacent frame rule; the QUIC tunnel `TunnelStream`, the iOS
 *    `FrameCodec`, the Android VPN `PacketPipe` all use it);
 *  * the `u64be channelId || payload` envelope is the R2-001 adapter-level
 *    channel tagging (nearby `PayloadPolicy.encodeEnvelope`) — Wi-Fi Aware
 *    datapaths carry no channel metadata either.
 *
 * Adapter-level framing, NOT protocol semantics (lock L009): no identity,
 * routing, or cryptographic meaning is assigned here.
 *
 * ## FrameCodec law (never buffer without bound)
 *
 * A receiver rejects an oversized length prefix with [FrameTooLargeException]
 * BEFORE buffering the claimed payload — a claimed 4 GiB frame is rejected
 * at the 4-byte prefix, never buffered. The decoder's pending state is
 * therefore bounded by [MAX_FRAME_BYTES] + 4 at all times. A rejected or
 * garbage stream is unrecoverable (byte-stream desynchronization): the
 * decoder resets itself, throws, and the caller (the adapter) drops the
 * endpoint with a typed error.
 */
object AwareFrameCodec {

    /** The length prefix width in bytes (u32 big-endian). */
    const val LENGTH_PREFIX_BYTES: Int = 4

    /** The channel envelope width in bytes (u64 big-endian channelId). */
    const val ENVELOPE_HEADER_BYTES: Int = 8

    /**
     * The frame bound: 2 MiB, the same constant as the QUIC tunnel's
     * `MAX_FRAME` and the iOS `FrameCodec.defaultMaxFrameBytes`, enforced on
     * BOTH sides (send and receive).
     */
    const val MAX_FRAME_BYTES: Int = 2 * 1024 * 1024

    /**
     * Encode one frame into its length-prefixed wire form.
     *
     * @throws FrameTooLargeException when the framed body
     *   (channelId + payload) exceeds [maxFrameBytes].
     */
    fun encode(channelId: Long, payload: ByteArray, maxFrameBytes: Int = MAX_FRAME_BYTES): ByteArray {
        require(maxFrameBytes >= ENVELOPE_HEADER_BYTES) {
            "maxFrameBytes must be >= $ENVELOPE_HEADER_BYTES (got $maxFrameBytes)"
        }
        val frameLength = ENVELOPE_HEADER_BYTES + payload.size
        if (frameLength > maxFrameBytes) {
            throw FrameTooLargeException(frameLength.toLong(), maxFrameBytes)
        }
        val wire = ByteArray(LENGTH_PREFIX_BYTES + frameLength)
        // u32be frameLength
        wire[0] = ((frameLength ushr 24) and 0xFF).toByte()
        wire[1] = ((frameLength ushr 16) and 0xFF).toByte()
        wire[2] = ((frameLength ushr 8) and 0xFF).toByte()
        wire[3] = (frameLength and 0xFF).toByte()
        // u64be channelId
        var v = channelId
        for (i in 0 until ENVELOPE_HEADER_BYTES) {
            wire[LENGTH_PREFIX_BYTES + i] = ((v ushr 56) and 0xFF).toByte()
            v = v shl 8
        }
        System.arraycopy(payload, 0, wire, LENGTH_PREFIX_BYTES + ENVELOPE_HEADER_BYTES, payload.size)
        return wire
    }
}

/**
 * Incremental decoder for the length-prefixed framing: feed it raw stream
 * bytes in ANY chunking; it emits complete [TransportFrame]s as they
 * assemble. Pure logic — no I/O, no platform types — so it is unit-testable
 * on the host JVM.
 *
 * Fail-closed rules (FrameCodec law):
 *  * a length prefix claiming more than [maxFrameBytes] throws
 *    [FrameTooLargeException] BEFORE any body is buffered — pending state
 *    stays bounded by [maxFrameBytes] + 4 forever, even against hostile
 *    input;
 *  * a length prefix smaller than the channel envelope (cannot even carry a
 *    channelId) or a body whose channelId decodes negative (the high bit of
 *    the u64 is set) throws [MalformedFrameException];
 *  * on ANY of the above the decoder resets its state and the caller must
 *    drop the connection (the byte stream is desynchronized and cannot be
 *    resynced).
 *
 * A stream that simply ENDS mid-frame is NOT corruption: whatever is pending
 * is a partial frame the caller discards with the endpoint (the adapter
 * cleans up on disconnect — no partial frame is ever delivered).
 */
class FrameDecoder(private val maxFrameBytes: Int = AwareFrameCodec.MAX_FRAME_BYTES) {

    init {
        require(maxFrameBytes >= AwareFrameCodec.ENVELOPE_HEADER_BYTES) {
            "maxFrameBytes must be >= ${AwareFrameCodec.ENVELOPE_HEADER_BYTES} (got $maxFrameBytes)"
        }
    }

    /** Assembling prefix bytes (0..3). */
    private var prefix = ByteArray(0)

    /** The parsed prefix value once 4 bytes are buffered, else null. */
    private var prefixValue: Int? = null

    /** Assembling frame body (channelId + payload), bounded by [maxFrameBytes]. */
    private val body = ByteArrayOutputStream()

    /** Bytes currently buffered while a frame is still assembling. */
    val pendingBytes: Int
        get() = prefix.size + body.size()

    /**
     * Feed raw stream bytes; returns the complete frames that became
     * available (in order). Partial input stays buffered for the next feed.
     *
     * The implementation never copies more of [chunk] into its internal
     * state than the frame currently being assembled needs: even a single
     * hostile multi-megabyte chunk cannot make the decoder buffer without
     * bound.
     *
     * @throws FrameTooLargeException when a claimed length exceeds
     *   [maxFrameBytes] (state is reset; the caller drops the connection).
     * @throws MalformedFrameException on a structurally impossible frame
     *   (state is reset; the caller drops the connection).
     */
    fun feed(chunk: ByteArray): List<TransportFrame> {
        val frames = ArrayList<TransportFrame>(2)
        var offset = 0
        while (offset < chunk.size) {
            if (prefixValue == null) {
                // Top up the prefix.
                val need = AwareFrameCodec.LENGTH_PREFIX_BYTES - prefix.size
                val take = minOf(need, chunk.size - offset)
                if (take > 0) {
                    prefix = prefix + chunk.copyOfRange(offset, offset + take)
                    offset += take
                }
                if (prefix.size < AwareFrameCodec.LENGTH_PREFIX_BYTES) break // need more bytes
                prefixValue = parsePrefix(prefix)
                // The prefix is consumed once parsed: pending accounting
                // covers only the assembling body.
                prefix = ByteArray(0)
                checkPrefixSanity(prefixValue!!)
            } else {
                // Top up the body of the frame under assembly.
                val need = prefixValue!! - body.size()
                val take = minOf(need, chunk.size - offset)
                if (take > 0) {
                    body.write(chunk, offset, take)
                    offset += take
                }
                if (body.size() < prefixValue!!) break // need more bytes
                try {
                    frames.add(parseFrame(body.toByteArray()))
                } catch (e: MalformedFrameException) {
                    reset() // documented: the decoder resets on ANY failure
                    throw e
                }
                reset()
            }
        }
        return frames
    }

    /** Drop all partially-assembled state (a fresh stream's start). */
    fun reset() {
        prefix = ByteArray(0)
        prefixValue = null
        body.reset()
    }

    /** Parse the u32 big-endian prefix (exactly 4 bytes). */
    private fun parsePrefix(bytes: ByteArray): Int {
        val b0 = bytes[0].toLong() and 0xFF
        val b1 = bytes[1].toLong() and 0xFF
        val b2 = bytes[2].toLong() and 0xFF
        val b3 = bytes[3].toLong() and 0xFF
        // Parsed as unsigned into a Long first: a hostile prefix may claim up
        // to 4 GiB-1, which MUST be comparable against maxFrameBytes without
        // sign wraparound.
        val value = (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
        return value.toInt()
    }

    /**
     * Reject impossible prefixes BEFORE any body buffering (the FrameCodec
     * law). Resets state so the decoder is reusable after the caller drops
     * the endpoint.
     */
    private fun checkPrefixSanity(length: Int) {
        if (length > maxFrameBytes || length < 0) {
            // A u32be prefix can claim up to 4 GiB-1; claims >= 2^31 wrap
            // negative in the Int view. Both cases are the oversized claim.
            val claimed = if (length < 0) length.toLong() + (1L shl 32) else length.toLong()
            reset()
            throw FrameTooLargeException(claimed, maxFrameBytes)
        }
        if (length < AwareFrameCodec.ENVELOPE_HEADER_BYTES) {
            reset()
            throw MalformedFrameException(
                "frame length $length cannot carry the ${AwareFrameCodec.ENVELOPE_HEADER_BYTES}-byte channel envelope",
            )
        }
    }

    /** Parse one complete frame body into a [TransportFrame]. */
    private fun parseFrame(bodyBytes: ByteArray): TransportFrame {
        var channelId = 0L
        for (i in 0 until AwareFrameCodec.ENVELOPE_HEADER_BYTES) {
            channelId = (channelId shl 8) or (bodyBytes[i].toLong() and 0xFF)
        }
        if (channelId < 0) {
            throw MalformedFrameException(
                "channelId envelope decodes negative (high bit set): garbage stream",
            )
        }
        val payload = bodyBytes.copyOfRange(AwareFrameCodec.ENVELOPE_HEADER_BYTES, bodyBytes.size)
        return TransportFrame(channelId, payload)
    }
}

/**
 * A claimed frame length exceeds the bound. Thrown BEFORE any body is
 * buffered (FrameCodec law: a receiver never buffers a claimed 4 GiB frame).
 * The adapter translates this into a typed [org.sharenet.transport.contract.TransportError.IoFailure]
 * with this cause and drops the endpoint.
 */
class FrameTooLargeException(
    val claimedLength: Long,
    val maximum: Int,
) : RuntimeException("frame length $claimedLength exceeds the $maximum-byte bound")

/**
 * Structurally impossible framing (prefix too small for the envelope, or a
 * garbage channel envelope). The byte stream is desynchronized; the caller
 * must drop the connection.
 */
class MalformedFrameException(message: String) : RuntimeException(message)
