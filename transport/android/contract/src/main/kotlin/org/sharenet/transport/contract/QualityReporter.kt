package org.sharenet.transport.contract

/**
 * Sink for [QualitySample]s raised by a transport adapter (R2-004).
 *
 * Adapters report through this seam unconditionally; the embedding app
 * wires the real sink (e.g. a [QualityRecorder], or a bridge into the
 * future R3-003 topology evidence layer). The default wiring is
 * [NOOP] so an adapter never depends on an app-provided sink existing.
 *
 * Threading: implementations MUST be thread-safe — adapters call
 * [report] from whatever thread the platform uses (the main thread for
 * Google Nearby Connections). Implementations should return quickly;
 * heavy work must be queued by the app.
 */
interface QualityReporter {

    /** Record one quality observation. Must not throw on duplicate input. */
    fun report(sample: QualitySample)

    companion object {
        /**
         * Default no-op sink. Used when the embedding app supplies no
         * reporter; also the seam default in adapter constructors.
         */
        val NOOP: QualityReporter = object : QualityReporter {
            override fun report(sample: QualitySample) {
                // Deliberately nothing — the seam stays wired either way.
            }
        }
    }
}
