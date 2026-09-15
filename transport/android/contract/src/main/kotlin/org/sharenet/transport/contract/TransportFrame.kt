package org.sharenet.transport.contract

/**
 * One opaque payload plus a channel id. Both BYTES control frames and STREAM
 * bulk payloads of the underlying platform map onto this type.
 *
 * The payload is UNINTERPRETED at the transport layer — no protocol
 * semantics (identity/routing/crypto) live below this seam.
 *
 * Content equality by [channelId] and payload bytes (manual implementation
 * because Kotlin data classes compare arrays by identity).
 */
class TransportFrame(
    val channelId: Long,
    val payload: ByteArray,
) {
    init {
        require(channelId >= 0) { "channelId must be non-negative (got $channelId)" }
    }

    val payloadSize: Int get() = payload.size

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TransportFrame) return false
        return channelId == other.channelId && payload.contentEquals(other.payload)
    }

    override fun hashCode(): Int {
        var result = channelId.hashCode()
        result = 31 * result + payload.contentHashCode()
        return result
    }

    override fun toString(): String =
        "TransportFrame(channelId=$channelId, payloadSize=${payload.size})"
}
