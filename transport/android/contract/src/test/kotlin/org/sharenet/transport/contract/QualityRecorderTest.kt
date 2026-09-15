package org.sharenet.transport.contract

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Quality seam tests (R2-004): sample validation, ring-buffer overflow
 * (drop-oldest), window-scoped duplicate suppression, per-kind EWMA.
 *
 * Adversarial coverage (assignment §5):
 *  * ring buffer overflow: capacity enforced, oldest evicted;
 *  * duplicate suppression (in-window rejected; evicted key re-recordable);
 *  * invalid samples / zero capacity rejected with typed-ish errors;
 *  * thread-safety smoke (concurrent reporters never corrupt the ring).
 */
class QualityRecorderTest {

    private fun setup(
        seq: Long,
        kind: QualitySampleKind = QualitySampleKind.CONNECT_SETUP,
        durationMicros: Long = 100,
        channelId: Long = 0,
    ) = QualitySample(
        channelId = channelId,
        seq = seq,
        kind = kind,
        durationMicros = durationMicros,
        atUnixMillis = 1_000,
    )

    @Test
    fun sample_validation_rejects_negative_fields() {
        assertFailsWith<IllegalArgumentException> {
            QualitySample(channelId = -1, seq = 1, kind = QualitySampleKind.CONNECT_SETUP, durationMicros = 1, atUnixMillis = 1)
        }
        assertFailsWith<IllegalArgumentException> {
            QualitySample(channelId = 0, seq = -1, kind = QualitySampleKind.CONNECT_SETUP, durationMicros = 1, atUnixMillis = 1)
        }
        assertFailsWith<IllegalArgumentException> {
            QualitySample(channelId = 0, seq = 1, kind = QualitySampleKind.CONNECT_SETUP, durationMicros = -1, atUnixMillis = 1)
        }
        assertFailsWith<IllegalArgumentException> {
            QualitySample(channelId = 0, seq = 1, kind = QualitySampleKind.CONNECT_SETUP, durationMicros = 1, atUnixMillis = -1)
        }
        // Zero duration is LEGAL (synchronous platform observation).
        QualitySample(0, 1, QualitySampleKind.CONNECT_SETUP, 0, 0)
    }

    @Test
    fun zero_capacity_and_bad_alpha_are_rejected() {
        assertFailsWith<IllegalArgumentException> { QualityRecorder(capacity = 0) }
        assertFailsWith<IllegalArgumentException> { QualityRecorder(alpha = 0.0) }
        assertFailsWith<IllegalArgumentException> { QualityRecorder(alpha = 1.5) }
        QualityRecorder(capacity = 1, alpha = 1.0) // alpha == 1.0 is legal (pure latest)
    }

    @Test
    fun record_and_snapshot_preserve_arrival_order() {
        val r = QualityRecorder(capacity = 8)
        assertTrue(r.isEmpty())
        assertTrue(r.record(setup(1)))
        assertTrue(r.record(setup(2)))
        assertTrue(r.record(setup(3)))
        assertEquals(listOf(1L, 2L, 3L), r.snapshot().map { it.seq })
        assertEquals(3, r.size())
    }

    @Test
    fun ring_overflow_enforces_capacity_and_drops_oldest() {
        val r = QualityRecorder(capacity = 3)
        for (seq in 1..10L) {
            assertTrue(r.record(setup(seq)))
            assertTrue(r.size() <= 3, "capacity must never be exceeded")
        }
        assertEquals(3, r.size())
        assertEquals(listOf(8L, 9L, 10L), r.snapshot().map { it.seq }, "drop-oldest must retain the NEWEST")
    }

    @Test
    fun in_window_duplicates_are_suppressed_entirely() {
        val r = QualityRecorder(capacity = 8)
        assertTrue(r.record(setup(1, durationMicros = 100)))
        assertFalse(r.record(setup(1, durationMicros = 999)), "in-window duplicate must be rejected")
        assertEquals(1, r.size())
        assertEquals(1, r.count(QualitySampleKind.CONNECT_SETUP))
        // The duplicate did NOT touch the EWMA.
        assertEquals(100.0, r.ewmaDurationMicros(QualitySampleKind.CONNECT_SETUP))
        // A different channelId with the same seq is NOT a duplicate.
        assertTrue(r.record(setup(1, channelId = 7)))
        assertEquals(2, r.size())
    }

    @Test
    fun evicted_key_may_be_recorded_again_window_scoped_policy() {
        val r = QualityRecorder(capacity = 2)
        assertTrue(r.record(setup(1)))
        assertTrue(r.record(setup(2)))
        assertTrue(r.record(setup(3))) // evicts seq=1
        // seq=1 is no longer in the window: re-recordable (documented policy).
        assertTrue(r.record(setup(1)))
        assertEquals(listOf(3L, 1L), r.snapshot().map { it.seq })
    }

    @Test
    fun ewma_is_per_kind_and_matches_the_documented_formula() {
        val r = QualityRecorder(alpha = 0.2)
        r.record(setup(1, QualitySampleKind.CONNECT_SETUP, durationMicros = 100))
        r.record(setup(2, QualitySampleKind.CONNECT_SETUP, durationMicros = 300))
        r.record(setup(3, QualitySampleKind.DISCONNECT, durationMicros = 5_000))
        // CONNECT_SETUP: 100 -> 0.2*300 + 0.8*100 = 140.
        assertEquals(140.0, r.ewmaDurationMicros(QualitySampleKind.CONNECT_SETUP))
        // DISCONNECT: only one sample -> its own value.
        assertEquals(5_000.0, r.ewmaDurationMicros(QualitySampleKind.DISCONNECT))
    }

    @Test
    fun unknown_kind_ewma_is_null() {
        val r = QualityRecorder()
        assertNull(r.ewmaDurationMicros(QualitySampleKind.DISCONNECT))
        assertEquals(0, r.count(QualitySampleKind.DISCONNECT))
    }

    @Test
    fun ewma_bounded_influence_of_a_single_outlier() {
        val r = QualityRecorder(alpha = 0.2)
        repeat(20) { i -> r.record(setup(i.toLong() + 1, durationMicros = 100)) }
        assertEquals(100.0, r.ewmaDurationMicros(QualitySampleKind.CONNECT_SETUP))
        r.record(setup(99, durationMicros = 60_000_000))
        val after = r.ewmaDurationMicros(QualitySampleKind.CONNECT_SETUP)!!
        // Exact bound for a last-position sample: alpha*outlier + (1-alpha)*prev.
        assertTrue(after <= 0.2 * 60_000_000 + 0.8 * 100 + 1e-9, "outlier influence must be bounded by alpha: got $after")
        assertTrue(after < 60_000_000.0, "outlier must not dominate")
    }

    @Test
    fun snapshot_is_a_defensive_copy() {
        val r = QualityRecorder()
        r.record(setup(1))
        val snap = r.snapshot()
        r.clear()
        assertEquals(1, snap.size, "the snapshot must be an independent copy")
        assertTrue(r.isEmpty(), "clearing the recorder must not reach into an old snapshot")
    }

    @Test
    fun clear_resets_everything() {
        val r = QualityRecorder()
        r.record(setup(1))
        r.record(setup(2))
        r.clear()
        assertTrue(r.isEmpty())
        assertNull(r.ewmaDurationMicros(QualitySampleKind.CONNECT_SETUP))
        assertEquals(0, r.count(QualitySampleKind.CONNECT_SETUP))
        // After clear the same key is recordable again (window empty).
        assertTrue(r.record(setup(1)))
    }

    @Test
    fun concurrent_reporters_never_corrupt_the_ring() {
        val r = QualityRecorder(capacity = 512)
        val threads = (1..4).map { t ->
            Thread {
                repeat(128) { i -> r.report(setup(seq = (t * 1_000 + i).toLong())) }
            }
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        assertEquals(512, r.size(), "capacity must hold exactly under concurrency")
        assertEquals(512, r.snapshot().map { it.seq }.toSet().size, "no sample may be duplicated or lost inside the window")
        assertEquals(512, r.count(QualitySampleKind.CONNECT_SETUP))
    }

    @Test
    fun construction_rejects_invalid_samples_and_recorder_stays_usable() {
        val r = QualityRecorder()
        assertFailsWith<IllegalArgumentException> {
            QualitySample(0, -5, QualitySampleKind.CONNECT_SETUP, 10, 10)
        }
        assertFailsWith<IllegalArgumentException> {
            QualitySample(-1, 5, QualitySampleKind.DISCONNECT, 10, 10)
        }
        // The recorder stays fully usable after hostile input attempts.
        assertTrue(r.record(setup(1)))
        assertEquals(1, r.size())
    }
}
