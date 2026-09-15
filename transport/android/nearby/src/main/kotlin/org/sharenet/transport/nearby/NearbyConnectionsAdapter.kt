package org.sharenet.transport.nearby

import org.sharenet.transport.contract.ConnectionTracker
import org.sharenet.transport.contract.DisconnectReason
import org.sharenet.transport.contract.EndpointId
import org.sharenet.transport.contract.NearbyTransport
import org.sharenet.transport.contract.QualityReporter
import org.sharenet.transport.contract.QualitySample
import org.sharenet.transport.contract.QualitySampleKind
import org.sharenet.transport.contract.TransportError
import org.sharenet.transport.contract.TransportEvent
import org.sharenet.transport.contract.TransportFrame
import org.sharenet.transport.contract.TransportListener
import java.io.ByteArrayOutputStream
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/**
 * The Nearby Connections adapter (R2-001 + R2-004 quality events) —
 * architecture lock L009: a platform ADAPTER, not protocol semantics. It
 * implements the [NearbyTransport] contract on top of the [NearbyApi]
 * facade and holds no ShareNet protocol logic whatsoever.
 *
 * Construction: inject any [NearbyApi]. Production wiring is
 * `GmsNearbyApi(Nearby.getConnectionsClient(context), serviceId)` (see
 * [ShareNetTransportService]); unit tests inject the scripted
 * `FakeNearbyApi` that fakes the EXTERNAL GMS boundary.
 *
 * ## Quality events (R2-004, honest surface)
 *
 * The adapter emits [QualitySample]s through the injected
 * [qualityReporter] (default [QualityReporter.NOOP]; the embedding app
 * wires the real sink, e.g. a `QualityRecorder`). It reports ONLY timing
 * deltas the platform actually provides:
 *  * [QualitySampleKind.CONNECT_SETUP] — `onConnectionInitiated` →
 *    `onConnectionAccepted` (setup latency, `System.nanoTime` delta);
 *  * [QualitySampleKind.DISCONNECT] — connected → endpoint gone
 *    (connection lifetime).
 *
 * There is deliberately NO RTT sample: Nearby Connections exposes no raw
 * RTT, and fabricating one is forbidden (assignment honesty rule). Local
 * `stop()` clears timing state WITHOUT emitting samples, mirroring the
 * event stream (stop() dispatches no per-endpoint Disconnected events
 * either). A reporter that throws must not break the transport: failures
 * are counted in [qualityReportFailures] and swallowed.
 *
 * Threading: contract methods may be called from any thread EXCEPT the
 * Android main thread (the production [GmsNearbyApi] blocks). Listener
 * callbacks arrive on the platform thread and are forwarded synchronously;
 * the adapter never invokes listeners while holding its lock, so listeners
 * may safely call back into the adapter. Quality samples are reported
 * BEFORE the corresponding [TransportEvent] is dispatched, without the
 * lock held.
 *
 * Robustness policy (adversarial §5): platform-originated events that would
 * be illegal for the [ConnectionTracker] (e.g. a connection request arriving
 * after stop()) are DROPPED, never propagated as crashes. Caller-originated
 * mistakes surface as typed [TransportError.IllegalState].
 *
 * Persistence: none — session state only (tracker + receive buffers +
 * quality timing state).
 */
class NearbyConnectionsAdapter(
    private val api: NearbyApi,
    private val strategy: NearbyStrategyKind = NearbyStrategyKind.P2P_CLUSTER,
    private val qualityReporter: QualityReporter = QualityReporter.NOOP,
) : NearbyTransport, NearbyApiListener {

    private val lock = Any()

    private val tracker = ConnectionTracker()

    private val listeners = CopyOnWriteArrayList<TransportListener>()

    /** Receive-side STREAM reassembly: endpoint → payloadId → accumulated bytes. */
    private val pendingStreams = HashMap<EndpointId, HashMap<Long, ByteArrayOutputStream>>()

    /** Quality timing state per endpoint (R2-004), guarded by [lock]. */
    private val qualityTimings = HashMap<EndpointId, EndpointTiming>()

    /** Monotonic quality-sample sequence (1-based, adapter instance scope). */
    private val qualitySeq = AtomicLong(0)

    /** Malformed wire payloads dropped (observability). */
    private val malformedDropped = AtomicLong(0)

    /** Times an app-provided quality reporter threw (transport stays alive). */
    private val qualityFailures = AtomicLong(0)

    /** Diagnostics counter for dropped malformed payloads. */
    val malformedFramesDropped: Long get() = malformedDropped.get()

    /** Diagnostics counter for swallowed quality-reporter failures. */
    val qualityReportFailures: Long get() = qualityFailures.get()

    /** Per-endpoint quality timing (guarded by [lock]). */
    private data class EndpointTiming(
        val initiatedAtNanos: Long,
        val connectedAtNanos: Long?,
    )

    // ------------------------------------------------------------------
    // NearbyTransport (the contract seam)
    // ------------------------------------------------------------------

    override fun addListener(listener: TransportListener) {
        listeners.addIfAbsent(listener)
    }

    override fun removeListener(listener: TransportListener) {
        listeners.remove(listener)
    }

    override fun startAdvertising(name: String) {
        tracker.startAdvertising()
        try {
            api.startAdvertising(name, strategy, this)
        } catch (e: TransportError) {
            // Roll the tracker back so a retry is legal.
            tracker.stopAdvertising()
            throw e
        }
    }

    override fun startDiscovery() {
        tracker.startDiscovery()
        try {
            api.startDiscovery(strategy, this)
        } catch (e: TransportError) {
            tracker.stopDiscovery()
            throw e
        }
    }

    override fun stop() {
        synchronized(lock) {
            tracker.stopAll()
            pendingStreams.clear()
            // Documented: no DISCONNECT samples on local stop() — it
            // dispatches no per-endpoint Disconnected events either.
            qualityTimings.clear()
        }
        // Best-effort at the facade level; never throws.
        api.stopAll()
    }

    override fun acceptConnection(endpointId: EndpointId) {
        tracker.acceptConnection(endpointId)
        try {
            api.acceptConnection(endpointId)
        } catch (e: TransportError) {
            // The platform refused: forget the pending request so state stays
            // consistent (a later request from the same endpoint re-registers).
            tracker.abandonConnection(endpointId)
            throw e
        }
    }

    override fun rejectConnection(endpointId: EndpointId) {
        tracker.rejectConnection(endpointId)
        try {
            api.rejectConnection(endpointId)
        } catch (e: TransportError) {
            tracker.abandonConnection(endpointId)
            throw e
        }
    }

    override fun send(endpointId: EndpointId, frame: TransportFrame) {
        tracker.assertCanSend(endpointId)
        val wire = PayloadPolicy.encodeEnvelope(frame.channelId, frame.payload)
        when (PayloadPolicy.routeFor(frame.payload.size)) {
            PayloadRoute.BYTES -> api.sendBytes(endpointId, wire)
            PayloadRoute.STREAM -> api.sendStream(endpointId, wire)
        }
    }

    // ------------------------------------------------------------------
    // NearbyApiListener (platform-originated events)
    // ------------------------------------------------------------------

    override fun onEndpointFound(endpointId: EndpointId, name: String) {
        if (!tracker.isActive) return // late event after stop(): drop, no panic
        dispatch(TransportEvent.Discovered(endpointId, name))
    }

    override fun onEndpointLost(endpointId: EndpointId) {
        forgetEndpoint(endpointId)
        // Documented: an endpoint lost during discovery is surfaced as a
        // Disconnected event (assignment §5 expects this mapping).
        dispatch(TransportEvent.Disconnected(endpointId, DisconnectReason.PEER))
    }

    override fun onConnectionInitiated(endpointId: EndpointId, name: String, authenticationToken: String?) {
        // Adversarial: request arriving during/after stop() is dropped.
        if (!tracker.isActive) return
        try {
            tracker.onConnectionRequested(endpointId)
        } catch (expected: TransportError.IllegalState) {
            // Duplicate/weird platform event: drop instead of crashing.
            return
        }
        synchronized(lock) {
            qualityTimings[endpointId] = EndpointTiming(initiatedAtNanos = System.nanoTime(), connectedAtNanos = null)
        }
        dispatch(TransportEvent.ConnectionRequested(endpointId, name, authenticationToken))
    }

    override fun onConnectionAccepted(endpointId: EndpointId) {
        try {
            tracker.onConnectionAccepted(endpointId)
        } catch (expected: TransportError.IllegalState) {
            return // duplicate confirmation: drop
        }
        // Quality (R2-004): setup latency = initiation → confirmation. Only
        // measurable when we observed the initiation; computed under the
        // lock, emitted outside it, before the Connected event.
        val setupMicros: Long? = synchronized(lock) {
            val timing = qualityTimings[endpointId]
            if (timing != null) {
                val now = System.nanoTime()
                qualityTimings[endpointId] = timing.copy(connectedAtNanos = now)
                (now - timing.initiatedAtNanos) / 1_000
            } else {
                null
            }
        }
        if (setupMicros != null) {
            reportQuality(QualitySampleKind.CONNECT_SETUP, setupMicros)
        }
        dispatch(TransportEvent.Connected(endpointId))
    }

    override fun onConnectionRejected(endpointId: EndpointId) {
        try {
            if (tracker.isEndpointPending(endpointId)) {
                tracker.onConnectionRejected(endpointId)
            }
        } catch (expected: TransportError.IllegalState) {
            // Unknown to the tracker already: still surface the event below.
        }
        // Pending (never connected): no lifetime to measure — drop the
        // timing state. Pathological rejection of a CONNECTED endpoint: the
        // lifetime WAS measurable, so emit it (honest over convenient).
        val lifetimeMicros: Long? = synchronized(lock) {
            val timing = qualityTimings.remove(endpointId)
            timing?.connectedAtNanos?.let { connected ->
                (System.nanoTime() - connected) / 1_000
            }
        }
        if (lifetimeMicros != null) {
            reportQuality(QualitySampleKind.DISCONNECT, lifetimeMicros)
        }
        dispatch(TransportEvent.Disconnected(endpointId, DisconnectReason.REJECTED))
    }

    override fun onDisconnected(endpointId: EndpointId) {
        // Cleanup first: mid-STREAM receive buffers must never leak a partial
        // frame after the endpoint is gone.
        forgetEndpoint(endpointId)
        dispatch(TransportEvent.Disconnected(endpointId, DisconnectReason.PEER))
    }

    override fun onBytesReceived(endpointId: EndpointId, bytes: ByteArray) {
        if (!tracker.isEndpointConnected(endpointId)) return // late delivery: drop
        val frame = PayloadPolicy.decodeEnvelope(bytes)
        if (frame == null) {
            malformedDropped.incrementAndGet()
            return
        }
        dispatchFrame(endpointId, frame)
    }

    override fun onStreamChunk(endpointId: EndpointId, payloadId: Long, chunk: ByteArray) {
        if (!tracker.isEndpointConnected(endpointId)) return
        synchronized(lock) {
            pendingStreams.getOrPut(endpointId) { HashMap() }
                .getOrPut(payloadId) { ByteArrayOutputStream() }
                .write(chunk)
        }
    }

    override fun onStreamCompleted(endpointId: EndpointId, payloadId: Long) {
        val wire: ByteArray? = synchronized(lock) {
            val map = pendingStreams[endpointId]
            val buffer = map?.remove(payloadId)
            if (map != null && map.isEmpty()) pendingStreams.remove(endpointId)
            buffer?.toByteArray()
        }
        if (wire == null) {
            // Completion for a stream we never saw (or that was cleaned up by
            // a disconnect/transfer failure): platform anomaly, counted.
            malformedDropped.incrementAndGet()
            return
        }
        if (!tracker.isEndpointConnected(endpointId)) return
        val frame = PayloadPolicy.decodeEnvelope(wire)
        if (frame == null) {
            malformedDropped.incrementAndGet()
            return
        }
        dispatchFrame(endpointId, frame)
    }

    override fun onTransferFailed(endpointId: EndpointId, payloadId: Long) {
        // Receive-side mid-STREAM failure: drop the partial buffer so a later
        // well-formed stream from the same endpoint starts clean.
        synchronized(lock) {
            pendingStreams[endpointId]?.remove(payloadId)
        }
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    /** Tracker + receive-buffer cleanup for a disappearing endpoint. */
    private fun forgetEndpoint(endpointId: EndpointId) {
        try {
            if (tracker.isEndpointPending(endpointId) || tracker.isEndpointConnected(endpointId)) {
                tracker.onDisconnected(endpointId)
            }
        } catch (expected: TransportError.IllegalState) {
            tracker.abandonConnection(endpointId)
        }
        // Quality (R2-004): a CONNECTED endpoint's lifetime is measurable —
        // emit DISCONNECT with the connection duration. Pending (never
        // connected) endpoints have no lifetime: state is just dropped.
        val lifetimeMicros: Long? = synchronized(lock) {
            val timing = qualityTimings.remove(endpointId)
            timing?.connectedAtNanos?.let { connected ->
                (System.nanoTime() - connected) / 1_000
            }
        }
        if (lifetimeMicros != null) {
            reportQuality(QualitySampleKind.DISCONNECT, lifetimeMicros)
        }
        synchronized(lock) {
            pendingStreams.remove(endpointId)
        }
    }

    /**
     * Report one quality sample. NEVER called with [lock] held; a throwing
     * app-provided reporter is counted and swallowed (the transport must
     * survive hostile sinks).
     */
    private fun reportQuality(kind: QualitySampleKind, durationMicros: Long) {
        val sample = QualitySample(
            channelId = 0, // transport-level event (not a frame channel)
            seq = qualitySeq.incrementAndGet(),
            kind = kind,
            durationMicros = durationMicros,
            atUnixMillis = System.currentTimeMillis(),
        )
        try {
            qualityReporter.report(sample)
        } catch (expected: Throwable) {
            qualityFailures.incrementAndGet()
        }
    }

    private fun dispatch(event: TransportEvent) {
        for (listener in listeners) {
            listener.onTransportEvent(event)
        }
    }

    private fun dispatchFrame(endpointId: EndpointId, frame: TransportFrame) {
        for (listener in listeners) {
            listener.onFrame(endpointId, frame)
        }
    }
}
