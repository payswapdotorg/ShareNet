package org.sharenet.transport.contract

import java.util.ArrayDeque

/**
 * Bounded, thread-safe [QualitySample] sink with per-kind EWMA statistics
 * (R2-004) — the pure-JVM counterpart of the Rust `LinkQualityStream` +
 * `LinkQualitySummary` pair, kept intentionally small (the heavy statistics
 * live in the `sharenet-transport-telemetry` crate; this recorder is the
 * app-side evidence buffer for platform-event samples).
 *
 * ## Policies (documented, mirroring the Rust stream)
 *
 *  * **Ring buffer, drop-oldest.** At most [capacity] samples are retained;
 *    overflow evicts the OLDEST (routing wants current conditions). Tested.
 *  * **Duplicate suppression, window-scoped.** A sample whose
 *    `(channelId, seq)` is currently in the ring is rejected
 *    ([record] returns `false`) and affects neither statistics nor count.
 *    Once evicted by overflow, the same key may be recorded again —
 *    well-behaved adapters use monotonic `seq`s, so this cannot arise from
 *    them; the policy keeps the dedup set bounded with the ring.
 *  * **EWMA per kind, arrival order.** `ewma_k = alpha * x_k + (1 - alpha) *
 *    ewma_(k-1)` over accepted samples in arrival order, default
 *    [DEFAULT_ALPHA] = 0.2 (same constant as the Rust
 *    `DEFAULT_EWMA_ALPHA`; a single outlier moves the estimate by at most
 *    `alpha` of the gap). Deterministic for a fixed arrival sequence.
 *
 * ## Persistence (documented)
 *
 * **None.** In-memory, process-local streaming state. Durable evidence
 * capture is R8-001's concern, not the measurement layer's.
 *
 * Pure JVM: zero Android/GMS dependencies (lock L009 seam).
 */
class QualityRecorder(
    private val capacity: Int = DEFAULT_CAPACITY,
    private val alpha: Double = DEFAULT_ALPHA,
) : QualityReporter {

    init {
        require(capacity > 0) { "capacity must be > 0 (got $capacity)" }
        require(alpha > 0.0 && alpha <= 1.0) { "alpha must be in (0.0, 1.0] (got $alpha)" }
    }

    private val lock = Any()

    /** Retained samples, oldest first (the ring). */
    private val ring = ArrayDeque<QualitySample>(capacity)

    /** Keys currently in the ring (window-scoped duplicate suppression). */
    private val keysInRing = HashSet<Pair<Long, Long>>()

    /** Running EWMA per kind (over accepted samples, arrival order). */
    private val ewmaByKind = HashMap<QualitySampleKind, Double>()

    /** Accepted-sample count per kind (over the recorder's whole life). */
    private val countByKind = HashMap<QualitySampleKind, Int>()

    /**
     * Record one sample. Returns `true` when accepted, `false` when
     * rejected as an in-window duplicate.
     *
     * @throws IllegalArgumentException when the sample fails its own
     *   validation (negative fields).
     */
    fun record(sample: QualitySample): Boolean {
        // Validate outside the lock: QualitySample's init block already ran
        // at construction; re-check defensively for Java callers.
        require(sample.channelId >= 0 && sample.seq >= 0 && sample.durationMicros >= 0) {
            "invalid sample: $sample"
        }
        synchronized(lock) {
            val key = sample.channelId to sample.seq
            if (!keysInRing.add(key)) {
                return false // in-window duplicate: ignored entirely
            }
            if (ring.size == capacity) {
                val evicted = ring.removeFirst()
                keysInRing.remove(evicted.channelId to evicted.seq)
            }
            ring.addLast(sample)
            val next = ewmaByKind[sample.kind]?.let { alpha * sample.durationMicros + (1 - alpha) * it }
                ?: sample.durationMicros.toDouble()
            ewmaByKind[sample.kind] = next
            countByKind[sample.kind] = (countByKind[sample.kind] ?: 0) + 1
            return true
        }
    }

    /** [QualityReporter] seam: record and ignore the duplicate verdict. */
    override fun report(sample: QualitySample) {
        record(sample)
    }

    /** Snapshot of the retained samples, oldest first (a defensive copy). */
    fun snapshot(): List<QualitySample> = synchronized(lock) { ring.toList() }

    /** Number of retained samples (never exceeds [capacity]). */
    fun size(): Int = synchronized(lock) { ring.size }

    /** Whether no samples are retained. */
    fun isEmpty(): Boolean = synchronized(lock) { ring.isEmpty() }

    /**
     * The running EWMA of durations for [kind], or `null` when no sample of
     * that kind was ever accepted.
     */
    fun ewmaDurationMicros(kind: QualitySampleKind): Double? =
        synchronized(lock) { ewmaByKind[kind] }

    /** How many samples of [kind] were accepted over the recorder's life. */
    fun count(kind: QualitySampleKind): Int = synchronized(lock) { countByKind[kind] ?: 0 }

    /** Drop all retained samples and per-kind statistics. */
    fun clear() = synchronized(lock) {
        ring.clear()
        keysInRing.clear()
        ewmaByKind.clear()
        countByKind.clear()
    }

    companion object {
        /** Default ring capacity. */
        const val DEFAULT_CAPACITY: Int = 256

        /** Default EWMA alpha (matches the Rust `DEFAULT_EWMA_ALPHA`). */
        const val DEFAULT_ALPHA: Double = 0.2
    }
}
