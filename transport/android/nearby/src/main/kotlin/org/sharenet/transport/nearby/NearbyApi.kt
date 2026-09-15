package org.sharenet.transport.nearby

import org.sharenet.transport.contract.EndpointId
import org.sharenet.transport.contract.TransportError

/**
 * Facade over the Google Nearby Connections surface (R2-001).
 *
 * EVERY GMS type stays behind [GmsNearbyApi] — the single implementation of
 * this interface that touches `com.google.android.gms.nearby.*`. All other
 * code (the adapter, the service, tests) speaks ONLY this facade and the
 * [org.sharenet.transport.contract] types. This is the architecture-lock
 * L009 seam-inspection point: review = "no GMS imports outside GmsNearbyApi.kt".
 *
 * Contract notes:
 *  * Start/stop methods are synchronous. Implementations that wrap async
 *    platform APIs (GmsNearbyApi does) block the CALLING thread — callers
 *    must not invoke them on the Android main thread.
 *  * [NearbyApiListener] callbacks arrive on the platform's thread (the main
 *    thread for GMS; immediately and synchronously for the scripted fake).
 *  * stop* methods are best-effort and never throw.
 */
interface NearbyApi {

    /**
     * @throws TransportError.PlayServicesUnavailable if the backend is unusable.
     * @throws TransportError.PermissionsDenied if platform permissions are missing.
     */
    @Throws(TransportError::class)
    fun startAdvertising(name: String, strategy: NearbyStrategyKind, listener: NearbyApiListener)

    /** Best-effort; never throws. */
    fun stopAdvertising()

    /**
     * @throws TransportError.PlayServicesUnavailable if the backend is unusable.
     * @throws TransportError.PermissionsDenied if platform permissions are missing.
     */
    @Throws(TransportError::class)
    fun startDiscovery(strategy: NearbyStrategyKind, listener: NearbyApiListener)

    /** Best-effort; never throws. */
    fun stopDiscovery()

    /** Stop everything. Best-effort; never throws. */
    fun stopAll()

    /**
     * @throws TransportError.IllegalState if the endpoint is unknown to the platform.
     * @throws TransportError.ConnectionRejected if the platform refuses.
     */
    @Throws(TransportError::class)
    fun acceptConnection(endpointId: EndpointId)

    /**
     * @throws TransportError.IllegalState if the endpoint is unknown to the platform.
     */
    @Throws(TransportError::class)
    fun rejectConnection(endpointId: EndpointId)

    /**
     * Send [wire] as a BYTES payload (small frames only — see
     * [PayloadPolicy.MAX_BYTES_PAYLOAD_BYTES]).
     *
     * @throws TransportError.IoFailure if the platform send fails.
     */
    @Throws(TransportError::class)
    fun sendBytes(endpointId: EndpointId, wire: ByteArray)

    /**
     * Send [wire] as a STREAM payload (bulk frames). Fire-and-forget at the
     * facade level: synchronous failure raises
     * [TransportError.IoFailure]; in-flight failure is reported later via
     * [NearbyApiListener.onTransferFailed].
     *
     * @throws TransportError.IoFailure if the platform send fails immediately.
     */
    @Throws(TransportError::class)
    fun sendStream(endpointId: EndpointId, wire: ByteArray)
}

/**
 * Callbacks from the platform side, already translated into ShareNet
 * contract vocabulary. NO GMS types appear here — [GmsNearbyApi] performs the
 * translation.
 */
interface NearbyApiListener {

    /** A remote advertising endpoint became visible (discovery). */
    fun onEndpointFound(endpointId: EndpointId, name: String)

    /** A previously-found endpoint is no longer visible. */
    fun onEndpointLost(endpointId: EndpointId)

    /** A remote endpoint initiated a connection to us. */
    fun onConnectionInitiated(endpointId: EndpointId, name: String, authenticationToken: String?)

    /** The platform confirmed the connection (result SUCCESS). */
    fun onConnectionAccepted(endpointId: EndpointId)

    /** The pending connection was rejected by the remote side (or failed). */
    fun onConnectionRejected(endpointId: EndpointId)

    /** A connected endpoint disconnected. */
    fun onDisconnected(endpointId: EndpointId)

    /** A complete BYTES payload arrived. */
    fun onBytesReceived(endpointId: EndpointId, bytes: ByteArray)

    /** One chunk of a STREAM payload arrived (in order for that payload). */
    fun onStreamChunk(endpointId: EndpointId, payloadId: Long, chunk: ByteArray)

    /** A STREAM payload finished; all chunks have been delivered. */
    fun onStreamCompleted(endpointId: EndpointId, payloadId: Long)

    /** A payload transfer failed mid-flight (endpoint may or may not remain connected). */
    fun onTransferFailed(endpointId: EndpointId, payloadId: Long)
}

/**
 * Nearby Connections strategy selection (assignment §4.1: injectable, with a
 * documented tradeoff).
 *
 * Tradeoffs (see transport/android/README.md for the full table):
 *  * [P2P_CLUSTER] (default) — full mesh of nearby devices; best for
 *    ShareNet relay/gateway clusters where several nodes should stay
 *    mutually reachable.
 *  * [P2P_POINT_TO_POINT] — exactly two devices, highest throughput on a
 *    dedicated link; suits a single gateway↔client bridge.
 *  * [P2P_STAR] — hub-and-spoke; every node connects through one host. Good
 *    when one device is the gateway and others are clients, at the cost of
 *    the hub being a single point of failure for the local group.
 */
enum class NearbyStrategyKind {
    P2P_CLUSTER,
    P2P_POINT_TO_POINT,
    P2P_STAR,
}
