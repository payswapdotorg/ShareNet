package org.sharenet.transport.aware

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
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/**
 * The Wi-Fi Aware links adapter (R2-002) — architecture lock L009: a platform
 * ADAPTER, not protocol semantics. It implements the [NearbyTransport]
 * contract (the same seam R2-001's nearby adapter implements) on top of the
 * [AwareApi] facade and holds no ShareNet protocol logic whatsoever.
 *
 * Transport-ladder position (`spec/architecture.md` §7): rung 2 — Wi-Fi
 * Aware for direct high-throughput IP links where supported, above Nearby
 * Connections (rung 1) and below Wi-Fi Direct/hotspot (rung 3, out of scope).
 *
 * Construction: inject any [AwareApi]. Production wiring is
 * `AndroidAwareApi.fromContext(context)` (see [ShareNetAwareService]); unit
 * tests inject the scripted `FakeAwareApi` that fakes the EXTERNAL
 * `android.net.wifi.aware` boundary.
 *
 * ## Mapping (platform → contract)
 *
 *  * publish (advertising side) → [NearbyTransport.startAdvertising];
 *  * subscribe (discovery side) → [NearbyTransport.startDiscovery];
 *  * service discovered/lost → [TransportEvent.Disconnected]/[TransportEvent.Discovered]
 *    (an endpoint lost during discovery is surfaced as a Disconnected event,
 *    the R2-001 mapping);
 *  * facade connect signaling (connect request → accept/reject) →
 *    [TransportEvent.ConnectionRequested] → [NearbyTransport.acceptConnection]/
 *    [NearbyTransport.rejectConnection];
 *  * aware datapath established → [TransportEvent.Connected];
 *  * frame I/O → the frozen repo-wide framing over the datapath byte stream
 *    ([AwareFrameCodec]: `u32be frameLength || u64be channelId || payload`).
 *
 * The adapter deduplicates discovery bookkeeping in a LinkedHashMap
 * (insertion-order determinism — the ConnectionTracker law): a re-discovery
 * of a currently-visible endpoint dispatches NO second Discovered event, and
 * a session-loss teardown dispatches loss events in insertion order.
 *
 * ## Quality events (R2-004 seam, honest surface)
 *
 * The adapter emits [QualitySample]s through the injected [qualityReporter]
 * (default [QualityReporter.NOOP]; the embedding app wires the real sink,
 * e.g. a `QualityRecorder`). It reports ONLY timing deltas the platform
 * actually provides:
 *  * [QualitySampleKind.CONNECT_SETUP] — connect signaling observed →
 *    datapath established (setup latency, `System.nanoTime` delta);
 *  * [QualitySampleKind.DISCONNECT] — datapath established → endpoint gone
 *    (connection lifetime), including the error teardown paths (stream
 *    corruption, session loss).
 *
 * Honest limit: there is NO RTT sample. Wi-Fi Aware exposes RTT via NAN
 * ranging (`WifiAwareManager.startRanging`, API 33+), but the frozen
 * `QualitySampleKind` seam carries no RTT kind (R2-004 deliberately
 * documented "no fabricated RTT") and the contract module is out of this
 * work item's file authority — so ranging-based RTT is recorded as an open
 * seam extension, not reported mislabeled. Local `stop()` clears timing
 * state WITHOUT emitting samples, mirroring the event stream (stop()
 * dispatches no per-endpoint Disconnected events either). A reporter that
 * throws must not break the transport: failures are counted in
 * [qualityReportFailures] and swallowed.
 *
 * ## Robustness policy (adversarial)
 *
 * Platform-originated events that would be illegal for the
 * [ConnectionTracker] (e.g. a connection request arriving after stop()) are
 * DROPPED, never propagated as crashes. Caller-originated mistakes surface
 * as typed [TransportError.IllegalState]. A corrupted datapath stream (the
 * FrameCodec law) drops the endpoint with a [TransportEvent.Disconnected]
 * (reason [DisconnectReason.ERROR]) — a desynchronized byte stream cannot be
 * resynced.
 *
 * Threading: contract methods may be called from any thread EXCEPT the
 * Android main thread (the production [AndroidAwareApi] blocks). Listener
 * callbacks arrive on the platform thread and are forwarded synchronously;
 * the adapter never invokes listeners while holding its lock, so listeners
 * may safely call back into the adapter. Quality samples are reported BEFORE
 * the corresponding [TransportEvent] is dispatched, without the lock held.
 *
 * Persistence: none — session state only (tracker + discovery bookkeeping +
 * per-endpoint decode state + quality timing state).
 */
class AwareLinksAdapter(
    private val api: AwareApi,
    private val serviceName: String = DEFAULT_SERVICE_NAME,
    private val qualityReporter: QualityReporter = QualityReporter.NOOP,
) : NearbyTransport, AwareApiListener {

    companion object {
        /** The ShareNet Wi-Fi Aware NAN service scope (discovery filter). */
        const val DEFAULT_SERVICE_NAME: String = "org.sharenet.transport.aware"

        /**
         * Conservative cap for the advertised endpoint name carried in the
         * NAN service-specific info (the platform allows ~1300 bytes via
         * `Characteristic.getMaxServiceSpecificInfoLength()`; 128 is the
         * documented conservative bound, like the R2-001 32 KiB BYTES cap).
         */
        const val MAX_SERVICE_INFO_BYTES: Int = 128
    }

    private val lock = Any()

    private val tracker = ConnectionTracker()

    private val listeners = CopyOnWriteArrayList<TransportListener>()

    /**
     * Discovery bookkeeping: endpoint → advertised name, in INSERTION order
     * (LinkedHashMap — the ConnectionTracker law: deterministic teardown and
     * event order). An entry exists from Discovered until lost/rejected/
     * disconnected/stop.
     */
    private val discoveredEndpoints = LinkedHashMap<EndpointId, String>()

    /** Per-endpoint datapath stream decode state (the FrameCodec). */
    private val decoders = HashMap<EndpointId, FrameDecoder>()

    /** Quality timing state per endpoint (R2-004), guarded by [lock]. */
    private val qualityTimings = HashMap<EndpointId, EndpointTiming>()

    /** Monotonic quality-sample sequence (1-based, adapter instance scope). */
    private val qualitySeq = AtomicLong(0)

    /** Datapath streams dropped for corruption (FrameCodec law violations). */
    private val corruptionErrors = AtomicLong(0)

    /** Times an app-provided quality reporter threw (transport stays alive). */
    private val qualityFailures = AtomicLong(0)

    /** Diagnostics counter for corrupted datapath streams (typed frame errors). */
    val streamCorruptionErrors: Long get() = corruptionErrors.get()

    /** Diagnostics counter for swallowed quality-reporter failures. */
    val qualityReportFailures: Long get() = qualityFailures.get()

    /** Per-endpoint quality timing (guarded by [lock]). */
    private data class EndpointTiming(
        val initiatedAtNanos: Long,
        val connectedAtNanos: Long?,
    )

    /** Snapshot plan for the session-loss teardown (see [onSessionLost]). */
    private class LossPlan(
        val tracked: List<EndpointId>,
        val discoveredOnly: List<EndpointId>,
        val lifetimesMicros: List<Pair<EndpointId, Long>>,
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
        val serviceInfo = name.encodeToByteArray()
        if (serviceInfo.size > MAX_SERVICE_INFO_BYTES) {
            // Surface BEFORE touching any state: a caller mistake, typed.
            throw TransportError.IllegalState(
                "advertised name is ${serviceInfo.size} bytes; the aware service-info bound is $MAX_SERVICE_INFO_BYTES",
            )
        }
        tracker.startAdvertising()
        try {
            // Idempotent on the facade: the second start* shares the attach.
            api.attach(this)
            api.startPublish(serviceName, serviceInfo)
        } catch (e: TransportError) {
            // Roll the tracker back so a retry is legal.
            tracker.stopAdvertising()
            throw e
        }
    }

    override fun startDiscovery() {
        tracker.startDiscovery()
        try {
            api.attach(this)
            api.startSubscribe(serviceName)
        } catch (e: TransportError) {
            tracker.stopDiscovery()
            throw e
        }
    }

    override fun stop() {
        synchronized(lock) {
            tracker.stopAll()
            discoveredEndpoints.clear()
            decoders.clear()
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
            api.acceptDatapath(endpointId)
        } catch (e: TransportError) {
            // The platform refused/failed: forget the pending request so
            // state stays consistent (a later request re-registers).
            tracker.abandonConnection(endpointId)
            synchronized(lock) { qualityTimings.remove(endpointId) }
            throw e
        }
    }

    override fun rejectConnection(endpointId: EndpointId) {
        tracker.rejectConnection(endpointId)
        try {
            api.rejectDatapath(endpointId)
        } catch (e: TransportError) {
            tracker.abandonConnection(endpointId)
            throw e
        } finally {
            synchronized(lock) { qualityTimings.remove(endpointId) }
        }
    }

    override fun send(endpointId: EndpointId, frame: TransportFrame) {
        tracker.assertCanSend(endpointId)
        val wire = try {
            AwareFrameCodec.encode(frame.channelId, frame.payload)
        } catch (e: FrameTooLargeException) {
            // The frozen 2 MiB frame law, enforced on send (typed).
            throw TransportError.IoFailure(e, "frame of ${e.claimedLength} bytes exceeds the aware stream bound")
        }
        api.sendData(endpointId, wire)
    }

    // ------------------------------------------------------------------
    // AwareApiListener (platform-originated events)
    // ------------------------------------------------------------------

    override fun onSessionLost() {
        // The transport failed underneath EVERYTHING (attach torn down
        // mid-discovery): typed loss events for every tracked endpoint (in
        // tracker insertion order), the adapter returns to Idle, and a later
        // start* re-attaches fresh.
        val plan = synchronized(lock) {
            val tracked = tracker.activeEndpointIds()
            val discoveredOnly = discoveredEndpoints.keys.filter { it !in tracked }
            val lifetimes = tracked.mapNotNull { endpointId ->
                qualityTimings.remove(endpointId)?.connectedAtNanos?.let { connected ->
                    endpointId to ((System.nanoTime() - connected) / 1_000)
                }
            }
            tracker.stopAll()
            discoveredEndpoints.clear()
            decoders.clear()
            LossPlan(tracked, discoveredOnly, lifetimes)
        }
        // Quality BEFORE events, without the lock (the error-transition
        // teardown paths report honestly too).
        for ((_, lifetimeMicros) in plan.lifetimesMicros) {
            reportQuality(QualitySampleKind.DISCONNECT, lifetimeMicros)
        }
        // Tracked endpoints: the transport failed underneath → ERROR.
        for (endpointId in plan.tracked) {
            dispatch(TransportEvent.Disconnected(endpointId, DisconnectReason.ERROR))
        }
        // Merely-discovered peers: they are gone like an endpoint lost → PEER.
        for (endpointId in plan.discoveredOnly) {
            dispatch(TransportEvent.Disconnected(endpointId, DisconnectReason.PEER))
        }
    }

    override fun onServiceDiscovered(endpointId: EndpointId, name: String) {
        if (!tracker.isActive) return // late event after stop(): drop, no panic
        // Deduplicated discovery bookkeeping: a re-discovery of a
        // currently-visible endpoint dispatches NO second event (insertion
        // order preserved; name changes surface via lost+found cycles).
        val isNew = synchronized(lock) {
            if (discoveredEndpoints.containsKey(endpointId)) {
                false
            } else {
                discoveredEndpoints[endpointId] = name
                true
            }
        }
        if (isNew) {
            dispatch(TransportEvent.Discovered(endpointId, name))
        }
    }

    override fun onServiceLost(endpointId: EndpointId) {
        // Endpoint lost during discovery: surfaced as a Disconnected event
        // (the R2-001 mapping) for both merely-discovered and connected
        // endpoints. An unknown peer (platform anomaly) is dropped — the
        // aware bookkeeping is authoritative and deterministic.
        val known = forgetEndpoint(endpointId)
        if (known) {
            dispatch(TransportEvent.Disconnected(endpointId, DisconnectReason.PEER))
        }
    }

    override fun onConnectionRequested(endpointId: EndpointId, name: String) {
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
        // No authenticationToken: NAN has no GMS-style pairing token
        // (AwarePairingConfig bootstrap is API 34+ and out of this
        // foundation's scope — documented honestly).
        dispatch(TransportEvent.ConnectionRequested(endpointId, name, authenticationToken = null))
    }

    override fun onConnectionAccepted(endpointId: EndpointId) {
        try {
            tracker.onConnectionAccepted(endpointId)
        } catch (expected: TransportError.IllegalState) {
            return // duplicate confirmation: drop
        }
        // Quality (R2-004): setup latency = connect signaling → datapath
        // established. Computed under the lock, emitted outside it, BEFORE
        // the Connected event.
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
        synchronized(lock) {
            decoders.getOrPut(endpointId) { FrameDecoder() }
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
        synchronized(lock) {
            decoders.remove(endpointId)
            discoveredEndpoints.remove(endpointId)
        }
        if (lifetimeMicros != null) {
            reportQuality(QualitySampleKind.DISCONNECT, lifetimeMicros)
        }
        dispatch(TransportEvent.Disconnected(endpointId, DisconnectReason.REJECTED))
    }

    override fun onDisconnected(endpointId: EndpointId) {
        val known = forgetEndpoint(endpointId)
        if (known) {
            dispatch(TransportEvent.Disconnected(endpointId, DisconnectReason.PEER))
        }
    }

    override fun onStreamData(endpointId: EndpointId, chunk: ByteArray) {
        if (!tracker.isEndpointConnected(endpointId)) return // late data: drop
        val decoder = synchronized(lock) { decoders[endpointId] } ?: return
        val frames = try {
            decoder.feed(chunk)
        } catch (e: FrameTooLargeException) {
            handleStreamCorruption(endpointId, e)
            return
        } catch (e: MalformedFrameException) {
            handleStreamCorruption(endpointId, e)
            return
        }
        for (frame in frames) {
            dispatchFrame(endpointId, frame)
        }
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    /**
     * Tracker + bookkeeping + decode-state cleanup for a disappearing
     * endpoint. Returns whether the endpoint was known (dispatch decision).
     * Quality (R2-004): a CONNECTED endpoint's lifetime is measurable — the
     * DISCONNECT sample is reported by the caller-visible path via
     * [endpointLifetime].
     */
    private fun forgetEndpoint(endpointId: EndpointId): Boolean {
        val wasTracked: Boolean
        val wasDiscovered: Boolean
        synchronized(lock) {
            wasTracked = tracker.isEndpointPending(endpointId) || tracker.isEndpointConnected(endpointId)
            wasDiscovered = discoveredEndpoints.remove(endpointId) != null
            decoders.remove(endpointId)
        }
        if (wasTracked) {
            try {
                tracker.onDisconnected(endpointId)
            } catch (expected: TransportError.IllegalState) {
                tracker.abandonConnection(endpointId)
            }
        }
        val lifetimeMicros = endpointLifetime(endpointId)
        if (lifetimeMicros != null) {
            reportQuality(QualitySampleKind.DISCONNECT, lifetimeMicros)
        }
        return wasTracked || wasDiscovered
    }

    /**
     * Remove and return the measurable lifetime of a CONNECTED endpoint, or
     * null (pending endpoints have no lifetime). NEVER called with listeners
     * engaged; the caller reports the sample before dispatching events.
     */
    private fun endpointLifetime(endpointId: EndpointId): Long? =
        synchronized(lock) {
            qualityTimings.remove(endpointId)?.connectedAtNanos?.let { connected ->
                (System.nanoTime() - connected) / 1_000
            }
        }

    /**
     * A corrupted datapath stream (FrameCodec law): typed frame error
     * counted, endpoint torn down (Disconnected with reason ERROR — the
     * transport failed underneath), lifetime reported honestly.
     */
    private fun handleStreamCorruption(endpointId: EndpointId, cause: RuntimeException) {
        corruptionErrors.incrementAndGet()
        forgetEndpoint(endpointId)
        dispatch(TransportEvent.Disconnected(endpointId, DisconnectReason.ERROR))
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
