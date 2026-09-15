package org.sharenet.transport.contract

/**
 * Pure-Kotlin state machine tracking transport activity (R2-001).
 *
 * Ladder: Idle → Advertising/Discovering (independently switchable, matching
 * the real platform where both may run) → per-endpoint
 * `REQUESTED → ACCEPTED → CONNECTED`:
 *
 * ```text
 *                onConnectionRequested
 *   (gone) ─────────────────────────────► REQUESTED
 *      ▲                                      │
 *      │              rejectConnection        │ acceptConnection
 *      │◄─────────────────────────────────────┤
 *      │                                      ▼
 *      │  onConnectionRejected/         ACCEPTED
 *      │  onDisconnected                    │
 *      │                                    │ onConnectionAccepted
 *      │                                    ▼
 *      └──────────────────────────────── CONNECTED
 * ```
 *
 * The tracker enforces legal transitions with [TransportError.IllegalState]
 * and is deliberately STRICT: platform adapters tolerate weird native event
 * ordering at their own boundary (dropping what the tracker rejects) so that
 * this class can stay a precise, testable machine.
 *
 * Thread-safe (internal lock); no callbacks are invoked while the lock is
 * held, so listeners called by the adapter may safely call back in.
 */
class ConnectionTracker {

    private val lock = Any()

    private var advertising = false
    private var discovering = false

    private enum class EndpointState { REQUESTED, ACCEPTED, CONNECTED }

    private val endpoints = LinkedHashMap<EndpointId, EndpointState>()

    /** True while advertising is active. */
    val isAdvertising: Boolean
        get() = synchronized(lock) { advertising }

    /** True while discovery is active. */
    val isDiscovering: Boolean
        get() = synchronized(lock) { discovering }

    /** True while neither advertising nor discovering (ladder "Idle" state). */
    val isIdle: Boolean
        get() = synchronized(lock) { !advertising && !discovering }

    /** True while advertising or discovering. */
    val isActive: Boolean
        get() = synchronized(lock) { advertising || discovering }

    /** Snapshot of endpoint ids currently known (requested/accepted/connected). */
    fun activeEndpointIds(): List<EndpointId> = synchronized(lock) { endpoints.keys.toList() }

    /** True if [endpointId] has an ESTABLISHED (platform-confirmed) connection. */
    fun isEndpointConnected(endpointId: EndpointId): Boolean =
        synchronized(lock) { endpoints[endpointId] == EndpointState.CONNECTED }

    /** True if [endpointId] has a connection that is not yet confirmed. */
    fun isEndpointPending(endpointId: EndpointId): Boolean =
        synchronized(lock) { endpoints[endpointId].let { it == EndpointState.REQUESTED || it == EndpointState.ACCEPTED } }

    // ------------------------------------------------------------------
    // Activity transitions
    // ------------------------------------------------------------------

    /**
     * @throws TransportError.IllegalState if already advertising.
     */
    @Throws(TransportError.IllegalState::class)
    fun startAdvertising() {
        synchronized(lock) {
            if (advertising) {
                throw TransportError.IllegalState("already advertising")
            }
            advertising = true
        }
    }

    /**
     * @throws TransportError.IllegalState if not advertising.
     */
    @Throws(TransportError.IllegalState::class)
    fun stopAdvertising() {
        synchronized(lock) {
            if (!advertising) {
                throw TransportError.IllegalState("not advertising")
            }
            advertising = false
        }
    }

    /**
     * @throws TransportError.IllegalState if already discovering.
     */
    @Throws(TransportError.IllegalState::class)
    fun startDiscovery() {
        synchronized(lock) {
            if (discovering) {
                throw TransportError.IllegalState("already discovering")
            }
            discovering = true
        }
    }

    /**
     * @throws TransportError.IllegalState if not discovering.
     */
    @Throws(TransportError.IllegalState::class)
    fun stopDiscovery() {
        synchronized(lock) {
            if (!discovering) {
                throw TransportError.IllegalState("not discovering")
            }
            discovering = false
        }
    }

    /**
     * Tear everything down to Idle: advertising, discovery and ALL endpoints.
     * Idempotent — this is the one deliberately lenient operation (a stop
     * after a failed start must converge, see the rapid-cycle tests).
     */
    fun stopAll() {
        synchronized(lock) {
            advertising = false
            discovering = false
            endpoints.clear()
        }
    }

    // ------------------------------------------------------------------
    // Per-endpoint transitions
    // ------------------------------------------------------------------

    /**
     * A connection request arrived for [endpointId].
     *
     * @throws TransportError.IllegalState if [endpointId] is already known.
     */
    @Throws(TransportError.IllegalState::class)
    fun onConnectionRequested(endpointId: EndpointId) {
        synchronized(lock) {
            if (endpoints.containsKey(endpointId)) {
                throw TransportError.IllegalState(
                    "connection already pending or connected for endpoint ${endpointId.value}",
                )
            }
            endpoints[endpointId] = EndpointState.REQUESTED
        }
    }

    /**
     * Local decision: accept the pending request for [endpointId]. The
     * endpoint becomes ACCEPTED; it becomes CONNECTED only when the platform
     * confirms ([onConnectionAccepted]).
     *
     * @throws TransportError.IllegalState if there is no pending request, it
     * was already accepted, or it is already connected.
     */
    @Throws(TransportError.IllegalState::class)
    fun acceptConnection(endpointId: EndpointId) {
        synchronized(lock) {
            when (endpoints[endpointId]) {
                EndpointState.REQUESTED -> endpoints[endpointId] = EndpointState.ACCEPTED
                EndpointState.ACCEPTED -> throw TransportError.IllegalState(
                    "endpoint ${endpointId.value} is already accepted (awaiting platform confirmation)",
                )
                EndpointState.CONNECTED -> throw TransportError.IllegalState(
                    "endpoint ${endpointId.value} is already connected",
                )
                null -> throw TransportError.IllegalState(
                    "no pending connection request for endpoint ${endpointId.value}",
                )
            }
        }
    }

    /**
     * Local decision: reject the pending request for [endpointId].
     *
     * @throws TransportError.IllegalState if there is no pending request or
     * it was already accepted/connected.
     */
    @Throws(TransportError.IllegalState::class)
    fun rejectConnection(endpointId: EndpointId) {
        synchronized(lock) {
            when (endpoints[endpointId]) {
                EndpointState.REQUESTED -> endpoints.remove(endpointId)
                EndpointState.ACCEPTED -> throw TransportError.IllegalState(
                    "endpoint ${endpointId.value} was already accepted; rejecting is only legal before acceptance",
                )
                EndpointState.CONNECTED -> throw TransportError.IllegalState(
                    "endpoint ${endpointId.value} is already connected; rejecting is only legal before acceptance",
                )
                null -> throw TransportError.IllegalState(
                    "no pending connection request for endpoint ${endpointId.value}",
                )
            }
        }
    }

    /**
     * The platform confirmed the connection for [endpointId]: a locally
     * ACCEPTED request, or a REQUESTED one (platform confirm without a local
     * accept, e.g. the future outbound flow in R3-001).
     *
     * @throws TransportError.IllegalState if [endpointId] is unknown or
     * already connected (duplicate confirmation).
     */
    @Throws(TransportError.IllegalState::class)
    fun onConnectionAccepted(endpointId: EndpointId) {
        synchronized(lock) {
            when (endpoints[endpointId]) {
                EndpointState.REQUESTED, EndpointState.ACCEPTED ->
                    endpoints[endpointId] = EndpointState.CONNECTED
                EndpointState.CONNECTED -> throw TransportError.IllegalState(
                    "duplicate connection confirmation for endpoint ${endpointId.value}",
                )
                null -> throw TransportError.IllegalState(
                    "connection confirmed for unknown endpoint ${endpointId.value}",
                )
            }
        }
    }

    /**
     * The pending request for [endpointId] was rejected by the remote side
     * (or failed before confirmation). Removes the endpoint.
     *
     * @throws TransportError.IllegalState if [endpointId] is unknown.
     */
    @Throws(TransportError.IllegalState::class)
    fun onConnectionRejected(endpointId: EndpointId) {
        synchronized(lock) {
            if (!endpoints.containsKey(endpointId)) {
                throw TransportError.IllegalState(
                    "connection rejected for unknown endpoint ${endpointId.value}",
                )
            }
            endpoints.remove(endpointId)
        }
    }

    /**
     * The endpoint disconnected (or was lost). Removes it.
     *
     * @throws TransportError.IllegalState if [endpointId] is unknown.
     */
    @Throws(TransportError.IllegalState::class)
    fun onDisconnected(endpointId: EndpointId) {
        synchronized(lock) {
            if (!endpoints.containsKey(endpointId)) {
                throw TransportError.IllegalState(
                    "disconnect for unknown endpoint ${endpointId.value}",
                )
            }
            endpoints.remove(endpointId)
        }
    }

    /**
     * Drop the endpoint unconditionally if present (adapter rollback helper
     * after a platform failure; also tolerates unknown ids).
     */
    fun abandonConnection(endpointId: EndpointId) {
        synchronized(lock) { endpoints.remove(endpointId) }
    }

    /**
     * Enforce send legality.
     *
     * @throws TransportError.IllegalState if [endpointId] is not CONNECTED.
     */
    @Throws(TransportError.IllegalState::class)
    fun assertCanSend(endpointId: EndpointId) {
        synchronized(lock) {
            when (endpoints[endpointId]) {
                EndpointState.CONNECTED -> Unit
                EndpointState.ACCEPTED -> throw TransportError.IllegalState(
                    "endpoint ${endpointId.value} is accepted but not confirmed yet",
                )
                EndpointState.REQUESTED -> throw TransportError.IllegalState(
                    "endpoint ${endpointId.value} is not connected yet (request pending)",
                )
                null -> throw TransportError.IllegalState(
                    "endpoint ${endpointId.value} is not connected",
                )
            }
        }
    }

    /** Snapshot for diagnostics (invariant-checked by the fuzz tests). */
    fun snapshot(): TrackerSnapshot = synchronized(lock) {
        TrackerSnapshot(
            advertising = advertising,
            discovering = discovering,
            endpoints = endpoints.entries.associate { (id, state) ->
                id to (state == EndpointState.CONNECTED)
            },
        )
    }

    /** Read-only state snapshot: endpoint id → connected? */
    data class TrackerSnapshot(
        val advertising: Boolean,
        val discovering: Boolean,
        val endpoints: Map<EndpointId, Boolean>,
    )
}
