package org.sharenet.transport.aware

import org.sharenet.transport.contract.EndpointId
import org.sharenet.transport.contract.TransportError

/**
 * Facade over the Android Wi-Fi Aware surface (IEEE 802.11mc NAN — R2-002).
 *
 * EVERY `android.net.wifi.aware.*` type stays behind [AndroidAwareApi] — the
 * single implementation of this interface that touches the platform. All
 * other code (the adapter, the service, tests) speaks ONLY this facade and
 * the [org.sharenet.transport.contract] types. This is the architecture-lock
 * L009 seam-inspection point: review = "no android.net.wifi.aware imports
 * outside AndroidAwareApi.kt".
 *
 * The facade abstracts the platform's session/discovery/datapath shape:
 *
 * ```text
 * attach ──► WifiAwareSession ──► publish (advertising side)
 *                              └─► subscribe (discovery side)
 * discovered peer ──► connect signaling ──► aware datapath (NDP)
 *                                             └─► socket stream I/O
 * ```
 *
 * The connect signaling (the message exchange that carries a connection
 * request/accept/reject between ShareNet peers before the datapath is
 * created) is FACADE-INTERNAL: the real [AndroidAwareApi] implements it over
 * NAN follow-up messages, the scripted fake implements it in-memory. It is
 * transport-level connection plumbing — the same class of thing GMS does
 * natively for Nearby Connections — and NOT ShareNet protocol semantics
 * (lock L009: no identity/routing/crypto meaning is assigned here).
 *
 * Contract notes (mirroring the R2-001 [org.sharenet.transport.nearby.NearbyApi]
 * facade exactly):
 *  * Start methods are synchronous. Implementations that wrap async platform
 *    APIs (AndroidAwareApi does) block the CALLING thread — callers must not
 *    invoke them on the Android main thread.
 *  * [AwareApiListener] callbacks arrive on the platform's thread (the
 *    facade-constructed Handler for the real implementation; immediately and
 *    synchronously for the scripted fake).
 *  * The stop methods (and detach) are best-effort and never throw.
 *  * [attach] is idempotent: attaching an already-attached facade is a no-op
 *    success (the adapter attaches before publish AND before subscribe).
 */
interface AwareApi {

    /**
     * Attach a Wi-Fi Aware session (the lifecycle root above discovery).
     * Blocks until the platform confirms the session or fails.
     *
     * @throws TransportError.PlayServicesUnavailable if Wi-Fi Aware is
     *   unsupported/unavailable on this device (the NAN-off case — the
     *   platform-unavailable typed error).
     * @throws TransportError.PermissionsDenied if the platform permissions
     *   (location / nearby devices) are missing.
     */
    @Throws(TransportError::class)
    fun attach(listener: AwareApiListener)

    /** Detach the session. Best-effort; never throws. Idempotent. */
    fun detach()

    /**
     * Start publishing [serviceName] with [serviceInfo] as the
     * service-specific info peers see during discovery. Blocks until the
     * publish session is live or fails. Requires [attach].
     *
     * [serviceName] scopes discovery to ShareNet (the NAN service type);
     * [serviceInfo] carries the advertised endpoint name bytes.
     *
     * @throws TransportError.IllegalState if not attached.
     * @throws TransportError.PlayServicesUnavailable if the platform backend
     *   is unusable.
     * @throws TransportError.PermissionsDenied if platform permissions are
     *   missing.
     */
    @Throws(TransportError::class)
    fun startPublish(serviceName: String, serviceInfo: ByteArray)

    /**
     * Update the publish's service-specific info. LAST-WRITE-WINS: racing
     * updates converge on the most recent write, by design (the platform's
     * updatePublish race behavior, mirrored by the fake).
     *
     * @throws TransportError.IllegalState if no publish is active.
     */
    @Throws(TransportError::class)
    fun updatePublish(serviceInfo: ByteArray)

    /** Stop publishing. Best-effort; never throws. */
    fun stopPublish()

    /**
     * Start subscribing to [serviceName]. Blocks until the subscribe session
     * is live or fails. Requires [attach].
     *
     * @throws TransportError.IllegalState if not attached.
     * @throws TransportError.PlayServicesUnavailable if the platform backend
     *   is unusable.
     * @throws TransportError.PermissionsDenied if platform permissions are
     *   missing.
     */
    @Throws(TransportError::class)
    fun startSubscribe(serviceName: String)

    /** Stop subscribing. Best-effort; never throws. */
    fun stopSubscribe()

    /**
     * INITIATOR role: request a connection + aware datapath to a discovered
     * [endpointId]. Sends the connect signaling, then creates the network
     * specifier and waits for the datapath. Blocks until established or
     * refused. (The R2-002 adapter itself only ACCEPTS inbound requests —
     * outbound initiation is the authenticated-links layer's decision,
     * R3-001 — but the facade models the full platform surface.)
     *
     * @throws TransportError.IllegalState if [endpointId] is unknown.
     * @throws TransportError.ConnectionRejected if the peer refuses or the
     *   datapath fails (resources are released — no zombie request).
     * @throws TransportError.IoFailure on platform failure.
     */
    @Throws(TransportError::class)
    fun initiateDatapath(endpointId: EndpointId)

    /**
     * RESPONDER role: accept the pending connection request from
     * [endpointId] (delivered as [AwareApiListener.onConnectionRequested]).
     * Creates the responder-side network specifier and waits for the
     * datapath. Blocks until established or failed.
     *
     * @throws TransportError.IllegalState if there is no pending request.
     * @throws TransportError.ConnectionRejected if the initiator vanished or
     *   the datapath fails (resources are released — no zombie request).
     * @throws TransportError.IoFailure on platform failure.
     */
    @Throws(TransportError::class)
    fun acceptDatapath(endpointId: EndpointId)

    /**
     * RESPONDER role: reject the pending connection request from
     * [endpointId]. Sends the reject signaling and releases the pending
     * request's resources.
     *
     * @throws TransportError.IllegalState if there is no pending request.
     */
    @Throws(TransportError::class)
    fun rejectDatapath(endpointId: EndpointId)

    /**
     * Write [bytes] to [endpointId]'s established datapath stream
     * (fire-and-forget at the facade level; ordering is preserved).
     *
     * @throws TransportError.IllegalState if [endpointId] has no established
     *   datapath.
     * @throws TransportError.IoFailure if the stream write fails.
     */
    @Throws(TransportError::class)
    fun sendData(endpointId: EndpointId, bytes: ByteArray)

    /**
     * Stop everything: all datapath streams, pending requests, publish,
     * subscribe, and the attached session. Best-effort; never throws.
     * Idempotent.
     */
    fun stopAll()
}

/**
 * Callbacks from the platform side, already translated into ShareNet
 * contract vocabulary. NO `android.net.wifi.aware` types appear here —
 * [AndroidAwareApi] performs the translation.
 */
interface AwareApiListener {

    /**
     * The attached session was torn down by the platform (e.g. Wi-Fi aware
     * switched off mid-discovery). Every pending/connected endpoint and
     * discovery bookkeeping below must be considered GONE after this event.
     */
    fun onSessionLost()

    /** A publishing endpoint became visible to our active subscription. */
    fun onServiceDiscovered(endpointId: EndpointId, name: String)

    /** A previously-discovered endpoint is no longer visible. */
    fun onServiceLost(endpointId: EndpointId)

    /**
     * A remote endpoint initiated a connection to us (connect signaling
     * received). The app decides via [AwareApi.acceptDatapath] /
     * [AwareApi.rejectDatapath].
     */
    fun onConnectionRequested(endpointId: EndpointId, name: String)

    /** The aware datapath to [endpointId] is established; streams may flow. */
    fun onConnectionAccepted(endpointId: EndpointId)

    /**
     * The pending connection was refused or failed before the datapath was
     * established (remote reject, datapath creation failure).
     */
    fun onConnectionRejected(endpointId: EndpointId)

    /** A connected endpoint's datapath went down. */
    fun onDisconnected(endpointId: EndpointId)

    /**
     * Bytes arrived on [endpointId]'s datapath stream. Chunk boundaries are
     * ARBITRARY (a raw byte stream) — consumers must reassemble framed units
     * themselves (the adapter does, via [AwareFrameCodec]).
     */
    fun onStreamData(endpointId: EndpointId, chunk: ByteArray)
}
