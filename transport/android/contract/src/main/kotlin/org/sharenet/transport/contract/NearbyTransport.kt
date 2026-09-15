package org.sharenet.transport.contract

/**
 * Receives transport events and frames. Implementations should return
 * quickly; heavy work must be queued by the app, not done inline.
 *
 * Threading: events are delivered on whatever thread the underlying platform
 * transport uses (the main thread for Google Nearby Connections). Adapters
 * guarantee they never call listeners while holding their internal locks.
 */
interface TransportListener {

    /** Lifecycle event (discovery / connection lifecycle). */
    fun onTransportEvent(event: TransportEvent)

    /** A complete frame arrived from [endpointId]. */
    fun onFrame(endpointId: EndpointId, frame: TransportFrame)
}

/**
 * The transport seam for the Nearby-class local transport (R2-001).
 *
 * Implemented by platform adapters (lock L009: adapters, not protocol
 * semantics). This foundation handles INBOUND connection requests
 * ([ConnectionRequested] → accept/reject); actively initiating outbound
 * connections is the authenticated-links layer's decision (R3-001) and is
 * deliberately not part of this contract yet.
 *
 * All methods may throw [TransportError]; all of them are safe to call from
 * any thread EXCEPT the main thread when the underlying adapter performs
 * blocking platform calls (see the adapter documentation).
 */
interface NearbyTransport {

    /** Register a listener (idempotent). */
    fun addListener(listener: TransportListener)

    /** Unregister a listener (idempotent). */
    fun removeListener(listener: TransportListener)

    /**
     * Start advertising this device as [name] so nearby peers can find us and
     * request connections.
     *
     * @throws TransportError.IllegalState if already advertising.
     * @throws TransportError.PlayServicesUnavailable if the platform backend is unusable.
     * @throws TransportError.PermissionsDenied if platform permissions are missing.
     */
    @Throws(TransportError::class)
    fun startAdvertising(name: String)

    /**
     * Start discovering nearby advertising peers.
     *
     * @throws TransportError.IllegalState if already discovering.
     */
    @Throws(TransportError::class)
    fun startDiscovery()

    /**
     * Stop everything (advertising, discovery, all connections) and release
     * platform resources. Idempotent; never throws.
     */
    fun stop()

    /**
     * Accept a pending connection request (from [TransportEvent.ConnectionRequested]).
     *
     * @throws TransportError.IllegalState if there is no pending request for [endpointId].
     * @throws TransportError.ConnectionRejected if the platform refuses the accept.
     */
    @Throws(TransportError::class)
    fun acceptConnection(endpointId: EndpointId)

    /**
     * Reject a pending connection request.
     *
     * @throws TransportError.IllegalState if there is no pending request for [endpointId].
     */
    @Throws(TransportError::class)
    fun rejectConnection(endpointId: EndpointId)

    /**
     * Send one frame to a connected endpoint.
     *
     * @throws TransportError.IllegalState if [endpointId] is not connected.
     * @throws TransportError.IoFailure if the platform transfer fails synchronously.
     */
    @Throws(TransportError::class)
    fun send(endpointId: EndpointId, frame: TransportFrame)
}
