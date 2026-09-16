package org.sharenet.transport.aware

import org.sharenet.transport.contract.EndpointId
import org.sharenet.transport.contract.TransportError
import java.io.IOException

/**
 * SCRIPTED FAKE of the EXTERNAL `android.net.wifi.aware` boundary (test
 * sources ONLY — R2-002).
 *
 * This is the one legitimate fake in the module: it stands in for the
 * Wi-Fi Aware platform stack (NAN attach/publish/subscribe/datapaths), which
 * only exists on real devices. It fakes the platform side of [AwareApi]
 * INCLUDING the facade-internal connect signaling (exactly like the R2-001
 * `FakeNearbyApi` fakes GMS + its connection handshake as one unit); the
 * adapter logic under test is fully real.
 *
 * Scripting knobs:
 *  * [awareUnavailable] — attach throws PlayServicesUnavailable (the NAN
 *    unsupported/off-on-this-device case).
 *  * [permissionsDenied] — attach throws PermissionsDenied.
 *  * [failDatapathRequests] — initiateDatapath/acceptDatapath throw
 *    ConnectionRejected AFTER recording the resource release (no zombie
 *    request — observable in [releasedDatapaths]).
 *  * [failSends] — sendData throws IoFailure.
 *
 * Determinism: the fake resolves platform outcomes SYNCHRONOUSLY (the real
 * implementation blocks until its async platform callbacks resolve — the
 * same instaneity FakeNearbyApi gives Tasks.await). All callbacks fire
 * synchronously on the calling thread.
 *
 * Last-write-wins: [updatePublish] mirrors the platform's update race
 * behavior — racing updates converge on the most recent write, and
 * [publishUpdates] records them in call order for assertions.
 */
class FakeAwareApi : AwareApi {

    // ----- scripting -----
    var awareUnavailable = false
    var permissionsDenied = false
    var failDatapathRequests = false
    var failSends = false

    var listener: AwareApiListener? = null
        private set

    // ----- recorded calls (assertions) -----
    var attachCalls = 0
        private set
    var detachCalls = 0
        private set
    var stopAllCalls = 0
        private set
    var stopPublishCalls = 0
        private set
    var stopSubscribeCalls = 0
        private set

    val publishStarts = mutableListOf<String>()
    val publishUpdates = mutableListOf<ByteArray>()
    val subscribeStarts = mutableListOf<String>()

    val initiatedDatapaths = mutableListOf<EndpointId>()
    val acceptedDatapaths = mutableListOf<EndpointId>()
    val rejectedDatapaths = mutableListOf<EndpointId>()
    val releasedDatapaths = mutableListOf<EndpointId>()
    val dataSent = mutableListOf<Pair<EndpointId, ByteArray>>()

    // ----- platform-side state (the world the fake models) -----
    var attached = false
        private set
    var publishActive = false
        private set
    var publishServiceName: String? = null
        private set
    var publishServiceInfo: ByteArray? = null
        private set
    var subscribeActive = false
        private set
    var subscribeServiceName: String? = null
        private set

    /** Endpoints with a pending inbound connection request. */
    val pendingRequests = mutableSetOf<EndpointId>()

    /** Endpoints with an established datapath. */
    val datapaths = mutableSetOf<EndpointId>()

    /** Currently-visible discovered peers (endpoint → advertised name). */
    val discoveredPeers = LinkedHashMap<EndpointId, String>()

    // ------------------------------------------------------------------
    // AwareApi implementation
    // ------------------------------------------------------------------

    override fun attach(listener: AwareApiListener) {
        guard()
        this.listener = listener
        if (!attached) {
            attached = true
            attachCalls++
        }
        // Idempotent: attaching an already-attached facade is a no-op
        // success (the second start* shares the attach).
    }

    override fun detach() {
        detachCalls++
        attached = false
    }

    override fun startPublish(serviceName: String, serviceInfo: ByteArray) {
        requireAttached()
        if (publishActive) {
            throw TransportError.IllegalState("already publishing")
        }
        publishActive = true
        publishServiceName = serviceName
        publishServiceInfo = serviceInfo.copyOf()
        publishStarts.add(serviceName)
    }

    override fun updatePublish(serviceInfo: ByteArray) {
        if (!publishActive) {
            throw TransportError.IllegalState("no active publish to update")
        }
        // LAST-WRITE-WINS by design: the platform's updatePublish race
        // behavior converges on the most recent write.
        publishServiceInfo = serviceInfo.copyOf()
        publishUpdates.add(serviceInfo.copyOf())
    }

    override fun stopPublish() {
        stopPublishCalls++
        publishActive = false
    }

    override fun startSubscribe(serviceName: String) {
        requireAttached()
        if (subscribeActive) {
            throw TransportError.IllegalState("already subscribing")
        }
        subscribeActive = true
        subscribeServiceName = serviceName
        subscribeStarts.add(serviceName)
    }

    override fun stopSubscribe() {
        stopSubscribeCalls++
        subscribeActive = false
    }

    override fun initiateDatapath(endpointId: EndpointId) {
        if (endpointId !in discoveredPeers) {
            throw TransportError.IllegalState(
                "endpoint ${endpointId.value} has not been discovered; nothing to initiate against",
            )
        }
        initiatedDatapaths.add(endpointId)
        if (failDatapathRequests) {
            // Typed refusal, resources released — no zombie request.
            releasedDatapaths.add(endpointId)
            throw TransportError.ConnectionRejected(
                endpointId,
                "scripted datapath refusal for ${endpointId.value}",
            )
        }
        // Synchronous platform resolution (see class doc): the blocking
        // contract resolves instaneously in the fake.
        establishDatapath(endpointId)
    }

    override fun acceptDatapath(endpointId: EndpointId) {
        if (endpointId !in pendingRequests) {
            throw TransportError.IllegalState(
                "no pending connection request for endpoint ${endpointId.value}",
            )
        }
        acceptedDatapaths.add(endpointId)
        if (failDatapathRequests) {
            pendingRequests.remove(endpointId)
            releasedDatapaths.add(endpointId)
            throw TransportError.ConnectionRejected(
                endpointId,
                "scripted datapath failure for ${endpointId.value}",
            )
        }
        // Synchronous platform resolution: the blocking call returns with
        // the datapath established (the initiator's request was already
        // pending — remoteConnectRequest — so the NDP forms now).
        pendingRequests.remove(endpointId)
        establishDatapath(endpointId)
    }

    override fun rejectDatapath(endpointId: EndpointId) {
        if (endpointId !in pendingRequests) {
            throw TransportError.IllegalState(
                "no pending connection request for endpoint ${endpointId.value}",
            )
        }
        pendingRequests.remove(endpointId)
        rejectedDatapaths.add(endpointId)
        // The reject signaling releases the pending request's resources.
        releasedDatapaths.add(endpointId)
    }

    override fun sendData(endpointId: EndpointId, bytes: ByteArray) {
        if (endpointId !in datapaths) {
            throw TransportError.IllegalState(
                "endpoint ${endpointId.value} has no established datapath",
            )
        }
        if (failSends) {
            throw TransportError.IoFailure(
                IOException("scripted stream write failure"),
                "sendData failed (scripted)",
            )
        }
        dataSent.add(endpointId to bytes.copyOf())
    }

    override fun stopAll() {
        stopAllCalls++
        // Teardown releases every established datapath's resources.
        releasedDatapaths.addAll(datapaths)
        releasedDatapaths.addAll(pendingRequests)
        datapaths.clear()
        pendingRequests.clear()
        discoveredPeers.clear()
        publishActive = false
        subscribeActive = false
        attached = false
    }

    // ------------------------------------------------------------------
    // Test-driver: simulate the remote/platform side.
    // ------------------------------------------------------------------

    /** A publishing endpoint becomes visible to our active subscription. */
    fun platformServiceDiscovered(peerId: String, name: String) {
        val endpointId = EndpointId(peerId)
        discoveredPeers[endpointId] = name
        listener?.onServiceDiscovered(endpointId, name)
    }

    /** A previously-discovered endpoint is no longer visible. */
    fun platformServiceLost(peerId: String) {
        val endpointId = EndpointId(peerId)
        discoveredPeers.remove(endpointId)
        listener?.onServiceLost(endpointId)
    }

    /**
     * A remote endpoint initiates a connection to us (its connect signaling
     * message arrives; the request is pending until we accept/reject).
     */
    fun remoteConnectRequest(peerId: String, name: String) {
        val endpointId = EndpointId(peerId)
        pendingRequests.add(endpointId)
        listener?.onConnectionRequested(endpointId, name)
    }

    /** The remote initiator vanished / its pending request failed. */
    fun platformRequestFailed(peerId: String) {
        val endpointId = EndpointId(peerId)
        pendingRequests.remove(endpointId)
        listener?.onConnectionRejected(endpointId)
    }

    /** One chunk of stream bytes arrives from a connected endpoint. */
    fun remoteStreamData(peerId: String, chunk: ByteArray) {
        val endpointId = EndpointId(peerId)
        if (endpointId in datapaths) {
            listener?.onStreamData(endpointId, chunk.copyOf())
        }
    }

    /** A connected endpoint's datapath went down. */
    fun remoteDisconnect(peerId: String) {
        val endpointId = EndpointId(peerId)
        if (endpointId in datapaths) {
            datapaths.remove(endpointId)
            listener?.onDisconnected(endpointId)
        }
    }

    /**
     * The attached session was torn down by the platform mid-discovery
     * (e.g. Wi-Fi Aware switched off): all session-scoped state is gone.
     */
    fun platformSessionLost() {
        attached = false
        publishActive = false
        subscribeActive = false
        releasedDatapaths.addAll(datapaths)
        releasedDatapaths.addAll(pendingRequests)
        datapaths.clear()
        pendingRequests.clear()
        discoveredPeers.clear()
        listener?.onSessionLost()
    }

    /** The platform re-delivers a connection confirmation (duplicate). */
    fun establishDuplicateConfirmation(peerId: String) {
        listener?.onConnectionAccepted(EndpointId(peerId))
    }

    /** Establish a datapath and notify (the platform's completion callback). */
    private fun establishDatapath(endpointId: EndpointId) {
        datapaths.add(endpointId)
        listener?.onConnectionAccepted(endpointId)
    }

    private fun guard() {
        if (awareUnavailable) {
            throw TransportError.PlayServicesUnavailable(
                "scripted: wi-fi aware unavailable (NAN off or unsupported on this device)",
            )
        }
        if (permissionsDenied) {
            throw TransportError.PermissionsDenied("scripted: required permissions were denied")
        }
    }

    private fun requireAttached() {
        if (!attached) {
            throw TransportError.IllegalState("not attached: attach a session first")
        }
    }
}
