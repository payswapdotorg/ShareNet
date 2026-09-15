package org.sharenet.transport.contract

/**
 * One honest, measurable link-quality observation (R2-004).
 *
 * Mirror of the Rust `LinkQualitySample` concept, adapted to what platform
 * adapters can REALLY measure: event timing deltas on a single local
 * monotonic clock. Each sample covers one [QualitySampleKind] event with
 * its measured [durationMicros].
 *
 * ## Honest limits (documented)
 *
 * Google Nearby Connections exposes NO raw RTT. This seam therefore carries
 * only timing deltas an adapter can truly observe:
 *  * [QualitySampleKind.CONNECT_SETUP] — platform connection initiation →
 *    platform confirmation (setup latency);
 *  * [QualitySampleKind.DISCONNECT] — connection established → gone
 *    (connection lifetime).
 *
 * There is deliberately NO RTT kind: fabricating one from platform
 * callbacks would be a fake measurement. When a future app layer pings over
 * [TransportFrame]s, real RTT samples can be added then (out of R2-004's
 * scope; the Linux side measures RTT actively via the
 * `sharenet-transport-telemetry` prober).
 *
 * ## Field semantics
 *
 *  * [channelId] — the adapter-level envelope channel id domain from Wave 1
 *    (`TransportFrame.channelId`). `0` = transport-level event (not tied to
 *    a specific frame channel) — the value used by the Nearby adapter.
 *  * [seq] — adapter-assigned monotonic sample sequence (1-based). Unique
 *    per adapter instance; consumers dedup on `(channelId, seq)`.
 *  * [durationMicros] — the measured event duration, truncated to
 *    microseconds from a `System.nanoTime()` delta. `0` is legitimate
 *    (a same-thread synchronous platform can complete in under a
 *    microsecond); unlike the Rust RTT sample there is no clock-skew
 *    rejection here because both timestamps come from one monotonic clock
 *    and zero-duration events are real observations, not skew evidence.
 *  * [atUnixMillis] — wall-clock event time for cross-referencing; never
 *    used in duration arithmetic.
 *
 * Transport-internal type: NOT a protocol wire object (lock L009 — adapters
 * and their telemetry, not protocol semantics).
 */
data class QualitySample(
    val channelId: Long,
    val seq: Long,
    val kind: QualitySampleKind,
    val durationMicros: Long,
    val atUnixMillis: Long,
) {
    init {
        require(channelId >= 0) { "channelId must be non-negative (got $channelId)" }
        require(seq >= 0) { "seq must be non-negative (got $seq)" }
        require(durationMicros >= 0) { "durationMicros must be non-negative (got $durationMicros)" }
        require(atUnixMillis >= 0) { "atUnixMillis must be non-negative (got $atUnixMillis)" }
    }
}

/** The kinds of quality events adapters can measure honestly. */
enum class QualitySampleKind {
    /** Connection setup: initiation → platform confirmation. */
    CONNECT_SETUP,

    /** Connection lifetime: platform confirmation → endpoint gone. */
    DISCONNECT,
}
