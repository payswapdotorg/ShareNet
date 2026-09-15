package org.sharenet.transport.nearby

import org.sharenet.transport.contract.EndpointId
import org.sharenet.transport.contract.QualityRecorder
import org.sharenet.transport.contract.QualityReporter
import org.sharenet.transport.contract.QualitySample
import org.sharenet.transport.contract.QualitySampleKind
import org.sharenet.transport.contract.TransportEvent
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * R2-004 quality emission tests: the adapter reports honest connect /
 * disconnect timing samples through the [QualityReporter] seam, wired here
 * to the REAL [QualityRecorder] sink (no fake sink — the production pair is
 * what gets validated).
 *
 * The scripted [FakeNearbyApi] stands in for Google Play services ONLY (the
 * external boundary). All timing deltas the assertions check are REAL
 * `System.nanoTime()` measurements around REAL `Thread.sleep` gaps.
 *
 * Honest limit (documented in the adapter): there is NO RTT sample —
 * Nearby Connections exposes no raw RTT and fabricating one is forbidden.
 * Real-device connect/disconnect latencies are R4-004 scope.
 */
class NearbyQualityTest {

    private class Harness {
        val api = FakeNearbyApi()
        val recorder = QualityRecorder()
        val adapter = NearbyConnectionsAdapter(api, NearbyStrategyKind.P2P_CLUSTER, recorder)

        init {
            // The tracker only accepts connection requests while an activity
            // (advertising/discovery) is active — same setup as production.
            adapter.startAdvertising("quality-test")
        }

        fun connect(endpoint: String, setupDelayMs: Long = 0) {
            api.remoteConnectionInitiated(endpoint, "name-$endpoint")
            if (setupDelayMs > 0) Thread.sleep(setupDelayMs)
            adapter.acceptConnection(EndpointId(endpoint))
            api.remoteConnectionAccepted(endpoint)
        }
    }

    @Test
    fun connect_setup_emitted_with_real_measured_duration() {
        val h = Harness()
        h.connect("E1", setupDelayMs = 15)

        val samples = h.recorder.snapshot()
        assertEquals(1, samples.size, "exactly one CONNECT_SETUP sample: {samples}")
        val s = samples.single()
        assertEquals(QualitySampleKind.CONNECT_SETUP, s.kind)
        assertEquals(0L, s.channelId, "transport-level event carries channelId 0")
        assertEquals(1L, s.seq, "seq is 1-based and monotonic")
        assertTrue(
            s.durationMicros >= 15_000,
            "setup duration must be a REAL measurement of the 15ms gap (got ${s.durationMicros}us)",
        )
        assertTrue(s.atUnixMillis > 0)
        assertEquals(0, h.adapter.qualityReportFailures, "the real recorder sink never throws")
    }

    @Test
    fun connect_setup_and_disconnect_both_emitted_with_lifetimes() {
        val h = Harness()
        h.connect("E1", setupDelayMs = 10)
        Thread.sleep(12) // the connection lives for at least 12ms
        h.api.remoteDisconnected("E1")

        val samples = h.recorder.snapshot()
        assertEquals(2, samples.size, "CONNECT_SETUP + DISCONNECT: {samples}")
        val setup = samples[0]
        val gone = samples[1]
        assertEquals(QualitySampleKind.CONNECT_SETUP, setup.kind)
        assertEquals(QualitySampleKind.DISCONNECT, gone.kind)
        assertTrue(gone.durationMicros >= 12_000, "lifetime must cover the real 12ms gap (got ${gone.durationMicros}us)")
        assertEquals(setup.seq + 1, gone.seq, "seq strictly monotonic across kinds")
        assertEquals(1, h.recorder.count(QualitySampleKind.CONNECT_SETUP))
        assertEquals(1, h.recorder.count(QualitySampleKind.DISCONNECT))
    }

    @Test
    fun endpoint_lost_while_connected_emits_disconnect_sample() {
        val h = Harness()
        h.connect("E1")
        Thread.sleep(8)
        h.api.remoteEndpointLost("E1")

        val kinds = h.recorder.snapshot().map { it.kind }
        assertTrue(QualitySampleKind.CONNECT_SETUP in kinds)
        assertTrue(QualitySampleKind.DISCONNECT in kinds, "endpoint lost of a CONNECTED endpoint must report its lifetime")
    }

    @Test
    fun rejected_pending_connection_emits_no_quality_sample() {
        val h = Harness()
        h.api.remoteConnectionInitiated("E1", "name")
        h.adapter.rejectConnection(EndpointId("E1"))
        h.api.remoteConnectionRejected("E1")

        assertEquals(0, h.recorder.size(), "a never-connected endpoint has no measurable timing")
    }

    @Test
    fun duplicate_confirmation_emits_no_second_sample() {
        val h = Harness()
        h.connect("E1")
        h.api.remoteConnectionAccepted("E1") // duplicate platform confirm: dropped

        assertEquals(1, h.recorder.count(QualitySampleKind.CONNECT_SETUP), "duplicate confirm must not double-report")
    }

    @Test
    fun stop_clears_timing_state_without_emitting_samples() {
        val h = Harness()
        h.connect("E1")
        h.adapter.stop()

        // Only the CONNECT_SETUP exists; stop() emits no DISCONNECT samples
        // (documented: it dispatches no per-endpoint Disconnected events).
        assertEquals(1, h.recorder.size())
        assertEquals(1, h.recorder.count(QualitySampleKind.CONNECT_SETUP))
        // Late platform events after stop() are dropped entirely.
        h.api.remoteDisconnected("E1")
        assertEquals(1, h.recorder.size(), "late disconnect after stop() must not report")
    }

    @Test
    fun throwing_reporter_never_breaks_the_transport() {
        val api = FakeNearbyApi()
        val hostile = object : QualityReporter {
            override fun report(sample: QualitySample) {
                throw IllegalStateException("hostile sink")
            }
        }
        val adapter = NearbyConnectionsAdapter(api, NearbyStrategyKind.P2P_CLUSTER, hostile)
        adapter.startAdvertising("hostile-sink-test")
        val events = mutableListOf<TransportEvent>()
        adapter.addListener(object : org.sharenet.transport.contract.TransportListener {
            override fun onTransportEvent(event: TransportEvent) {
                events.add(event)
            }

            override fun onFrame(endpointId: EndpointId, frame: org.sharenet.transport.contract.TransportFrame) {
                // no frames in this test
            }
        })

        api.remoteConnectionInitiated("E1", "name")
        adapter.acceptConnection(EndpointId("E1"))
        api.remoteConnectionAccepted("E1")

        // The Connected event STILL flowed despite the throwing sink.
        assertTrue(events.any { it is TransportEvent.Connected }, "events must survive a hostile reporter")
        assertEquals(1, adapter.qualityReportFailures, "the swallowed failure is counted")

        // And the adapter keeps working (disconnect path).
        api.remoteDisconnected("E1")
        assertTrue(events.any { it is TransportEvent.Disconnected })
        assertEquals(2, adapter.qualityReportFailures)
    }

    @Test
    fun multiple_endpoints_get_monotonic_unique_seqs() {
        val h = Harness()
        h.connect("E1")
        h.connect("E2")
        h.api.remoteDisconnected("E1")
        h.api.remoteDisconnected("E2")

        val seqs = h.recorder.snapshot().map { it.seq }
        assertEquals(seqs.size, seqs.toSet().size, "seqs unique")
        assertEquals(seqs.sorted(), seqs, "seqs strictly increasing in arrival order")
        assertEquals(4, h.recorder.snapshot().size, "2 setups + 2 lifetimes")
    }
}
