package org.sharenet.transport.nearby

import org.sharenet.transport.contract.EndpointId
import org.sharenet.transport.contract.TransportError

/**
 * SCRIPTED FAKE of the EXTERNAL GMS boundary (test sources ONLY — R2-001).
 *
 * This is the one legitimate fake in the module: it stands in for Google
 * Play services, which only exists on real devices. It fakes the platform
 * side of [NearbyApi]; the adapter logic under test is fully real.
 *
 * Scripting knobs:
 *  * [playServicesUnavailable] — every start* call throws PlayServicesUnavailable.
 *  * [permissionsDenied] — every start* call throws PermissionsDenied.
 *  * [failStreamSends] — sendStream throws IoFailure (mid-STREAM failure).
 *
 * Test-driver methods (`remote*`) simulate the remote/platform side raising
 * events. All callbacks fire synchronously (deterministic tests).
 */
class FakeNearbyApi : NearbyApi {

    // ----- scripting -----
    var playServicesUnavailable = false
    var permissionsDenied = false
    var failStreamSends = false

    var listener: NearbyApiListener? = null
        private set

    // ----- recorded calls (assertions) -----
    val advertisingStarts = mutableListOf<String>()
    val discoveryStarts = mutableListOf<NearbyStrategyKind>()
    val accepted = mutableListOf<EndpointId>()
    val rejected = mutableListOf<EndpointId>()
    val bytesSent = mutableListOf<Pair<EndpointId, ByteArray>>()
    val streamsSent = mutableListOf<Pair<EndpointId, ByteArray>>()
    var stopAdvertisingCalls = 0
    var stopDiscoveryCalls = 0
    var stopAllCalls = 0
    var lastStrategy: NearbyStrategyKind? = null
        private set

    private var nextPayloadId = 1_000L

    override fun startAdvertising(name: String, strategy: NearbyStrategyKind, listener: NearbyApiListener) {
        guard()
        this.listener = listener
        lastStrategy = strategy
        advertisingStarts.add(name)
    }

    override fun stopAdvertising() {
        stopAdvertisingCalls++
    }

    override fun startDiscovery(strategy: NearbyStrategyKind, listener: NearbyApiListener) {
        guard()
        this.listener = listener
        lastStrategy = strategy
        discoveryStarts.add(strategy)
    }

    override fun stopDiscovery() {
        stopDiscoveryCalls++
    }

    override fun stopAll() {
        stopAllCalls++
    }

    override fun acceptConnection(endpointId: EndpointId) {
        accepted.add(endpointId)
    }

    override fun rejectConnection(endpointId: EndpointId) {
        rejected.add(endpointId)
    }

    override fun sendBytes(endpointId: EndpointId, wire: ByteArray) {
        bytesSent.add(endpointId to wire.copyOf())
    }

    override fun sendStream(endpointId: EndpointId, wire: ByteArray) {
        if (failStreamSends) {
            throw TransportError.IoFailure(
                java.io.IOException("scripted mid-STREAM failure"),
                "sendStream failed (scripted)",
            )
        }
        streamsSent.add(endpointId to wire.copyOf())
    }

    // ------------------------------------------------------------------
    // Test-driver: simulate the remote/platform side.
    // ------------------------------------------------------------------

    /** A remote endpoint becomes visible during discovery. */
    fun remoteEndpointFound(endpointId: String, name: String) {
        listener?.onEndpointFound(EndpointId(endpointId), name)
    }

    /** A discovered endpoint disappears (endpoint lost). */
    fun remoteEndpointLost(endpointId: String) {
        listener?.onEndpointLost(EndpointId(endpointId))
    }

    /** The remote side initiates a connection to us. */
    fun remoteConnectionInitiated(endpointId: String, name: String, token: String? = null) {
        listener?.onConnectionInitiated(EndpointId(endpointId), name, token)
    }

    /** The platform confirms the connection (after our accept). */
    fun remoteConnectionAccepted(endpointId: String) {
        listener?.onConnectionAccepted(EndpointId(endpointId))
    }

    /** The remote side rejects a pending connection. */
    fun remoteConnectionRejected(endpointId: String) {
        listener?.onConnectionRejected(EndpointId(endpointId))
    }

    /** A connected endpoint disconnects. */
    fun remoteDisconnected(endpointId: String) {
        listener?.onDisconnected(EndpointId(endpointId))
    }

    /** A complete BYTES payload arrives from a remote endpoint. */
    fun remoteBytes(endpointId: String, wire: ByteArray) {
        listener?.onBytesReceived(EndpointId(endpointId), wire.copyOf())
    }

    /** One STREAM chunk arrives. */
    fun remoteStreamChunk(endpointId: String, payloadId: Long, chunk: ByteArray) {
        listener?.onStreamChunk(EndpointId(endpointId), payloadId, chunk.copyOf())
    }

    /** A STREAM payload finished. */
    fun remoteStreamCompleted(endpointId: String, payloadId: Long) {
        listener?.onStreamCompleted(EndpointId(endpointId), payloadId)
    }

    /** A payload transfer failed mid-flight. */
    fun remoteTransferFailed(endpointId: String, payloadId: Long) {
        listener?.onTransferFailed(EndpointId(endpointId), payloadId)
    }

    /** Generate a payload id the tests can use for stream simulations. */
    fun newPayloadId(): Long = nextPayloadId++

    private fun guard() {
        if (playServicesUnavailable) {
            throw TransportError.PlayServicesUnavailable("scripted: no play services")
        }
        if (permissionsDenied) {
            throw TransportError.PermissionsDenied()
        }
    }
}
