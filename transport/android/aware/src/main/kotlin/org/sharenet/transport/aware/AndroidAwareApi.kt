package org.sharenet.transport.aware

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.LinkProperties
import android.net.wifi.aware.AwarePairingConfig
import android.net.wifi.aware.AttachCallback
import android.net.wifi.aware.DiscoverySession
import android.net.wifi.aware.DiscoverySessionCallback
import android.net.wifi.aware.PeerHandle
import android.net.wifi.aware.PublishConfig
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.SubscribeConfig
import android.net.wifi.aware.SubscribeDiscoverySession
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareNetworkSpecifier
import android.net.wifi.aware.WifiAwareSession
import android.os.Build
import android.os.Handler
import android.os.Looper
import org.sharenet.transport.contract.EndpointId
import org.sharenet.transport.contract.TransportError
import java.io.IOException
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * THE ONLY PLACE where `android.net.wifi.aware.*` types appear (R2-002,
 * architecture lock L009) — the Wi-Fi Aware sibling of the R2-001
 * [org.sharenet.transport.nearby.GmsNearbyApi].
 *
 * Thin, mechanical translation between the IEEE 802.11mc NAN platform API
 * and the [AwareApi] facade:
 *  * attach (WifiAwareManager.attach) → blocking session lifecycle;
 *  * publish/subscribe discovery (WifiAwareSession.publish/subscribe,
 *    DiscoverySessionCallback) → facade discovery + connect-signaling
 *    events in contract vocabulary;
 *  * aware datapaths (WifiAwareNetworkSpecifier.Builder + ConnectivityManager
 *    .requestNetwork, API 33+) → the blocking initiate/accept facade calls;
 *  * socket stream I/O over the aware Network → sendData/onStreamData;
 *  * every platform failure → a typed [TransportError].
 *
 * ## Facade-internal connect signaling (documented, NOT protocol semantics)
 *
 * NAN has no GMS-style connection handshake, so the facade drives one over
 * DiscoverySession.sendMessage follow-up messages (API 29+):
 *
 * ```text
 * CONNECT := 0x01 || endpointName (UTF-8)
 * ACCEPT  := 0x02 || u16be port || responder IPv6 (UTF-8 text form)
 * REJECT  := 0x00
 * ```
 *
 * Responder acceptDatapath: specifier(publishSession, peer) → requestNetwork
 * → onAvailable → ServerSocket bound to the LOCAL aware IPv6 (from
 * LinkProperties) → ACCEPT(port, address) to the initiator → accept on the
 * IO executor. Initiator initiateDatapath: CONNECT → ACCEPT →
 * specifier(subscribeSession, peer) → requestNetwork → onAvailable →
 * socketFactory socket → connect(peer IPv6, port). This is transport-level
 * connection plumbing — the same class of thing GMS does natively for
 * Nearby Connections — with no ShareNet protocol meaning (lock L009).
 *
 * ## Honest API-level matrix (compile-verified against SDK 35)
 *
 *  * attach/publish/subscribe + service-discovered events: API 26+;
 *    onServiceLost only ever fires on API 29+ (peers vanishing silently on
 *    26–28 is inherent to the platform there).
 *  * Connect signaling (DiscoverySession.sendMessage): API 29+.
 *  * Datapaths (WifiAwareNetworkSpecifier.Builder): API 33+ — devices below
 *    get a typed PlayServicesUnavailable ("platform-unavailable") error for
 *    connection flows; discovery still works.
 *  * NAN pairing bootstrap (AwarePairingConfig on publish/subscribe): API
 *    34+ — enabled opportunistically for the future secure-pairing layer;
 *    this foundation does not drive the pairing callbacks.
 *
 * On-device behavior is the operator-gated device leg (this sandbox has no
 * NAN radio): the class is compile-verified against the real SDK 35 and its
 * logic kept deliberately small so device bring-up has little surface to
 * trust — exactly the R2-001 discipline.
 *
 * Threading: callbacks arrive on the constructed [handler] (main looper by
 * default — the platform thread); blocking facade methods use latches with
 * timeouts and MUST be called off the Android main thread (the service
 * skeleton enforces this). State is guarded by [state]; listeners are never
 * invoked while [state] is held.
 */
class AndroidAwareApi(
    private val wifiAwareManager: WifiAwareManager?,
    private val connectivityManager: ConnectivityManager,
    private val handler: Handler = Handler(Looper.getMainLooper()),
) : AwareApi {

    companion object {
        /**
         * Production factory: the ONLY approved way to build this class.
         * Keeps every other file in the module free of
         * android.net.wifi.aware imports.
         */
        fun fromContext(
            context: Context,
            handler: Handler = Handler(Looper.getMainLooper()),
        ): AndroidAwareApi = AndroidAwareApi(
            context.getSystemService(WifiAwareManager::class.java),
            context.getSystemService(ConnectivityManager::class.java)
                ?: throw TransportError.PlayServicesUnavailable("ConnectivityManager unavailable"),
            handler,
        )

        private const val ATTACH_TIMEOUT_MS = 10_000L
        private const val SESSION_START_TIMEOUT_MS = 10_000L
        private const val DATAPATH_TIMEOUT_MS = 15_000L
        private const val SOCKET_CONNECT_TIMEOUT_MS = 10_000L

        /** Read granularity for the datapath stream reader (chunk size). */
        private const val STREAM_READ_BYTES = 16 * 1024

        /** Facade-internal signaling message discriminators (see class doc). */
        private const val MSG_REJECT: Byte = 0x00
        private const val MSG_CONNECT: Byte = 0x01
        private const val MSG_ACCEPT: Byte = 0x02
    }

    private val state = Any()

    private var listener: AwareApiListener? = null
    private var session: WifiAwareSession? = null
    private var attached = false

    private var publishSession: PublishDiscoverySession? = null
    private var publishServiceName: String? = null
    private var publishServiceInfo: ByteArray? = null

    private var subscribeSession: SubscribeDiscoverySession? = null
    private var subscribeServiceName: String? = null

    /** EndpointId → platform peer (insertion order = discovery order). */
    private val peers = LinkedHashMap<EndpointId, PeerHandle>()

    /** Reverse lookup (identity semantics: the platform reuses instances). */
    private val peersReverse = java.util.IdentityHashMap<PeerHandle, EndpointId>()

    /** Endpoint ids handed out (EndpointId is opaque at the contract level). */
    private val endpointSeq = AtomicLong(0)

    /** Pending inbound connection requests (responder side). */
    private val pendingRequests = LinkedHashMap<EndpointId, PeerHandle>()

    /** Established datapaths: endpoint → socket + platform plumbing. */
    private val established = LinkedHashMap<EndpointId, Datapath>()

    /** Pending initiator waits (endpoint → latch + ACCEPT payload). */
    private val pendingInitiations = HashMap<EndpointId, PendingInitiation>()

    /** The single IO executor for accept/read loops (daemon threads). */
    private val ioExecutor: ExecutorService = Executors.newCachedThreadPool { runnable ->
        Thread(runnable, "sharenet-aware-io").apply { isDaemon = true }
    }

    /** One established datapath's platform plumbing. */
    private class Datapath(
        val networkCallback: ConnectivityManager.NetworkCallback,
        var socket: Socket?,
        var serverSocket: ServerSocket?,
        val writeLock: Any,
    )

    /** An initiator waiting for the responder's ACCEPT/REJECT. */
    private class PendingInitiation(
        val latch: CountDownLatch,
        @Volatile var acceptPayload: ByteArray? = null,
        @Volatile var rejected: Boolean = false,
    )

    // ------------------------------------------------------------------
    // AwareApi implementation
    // ------------------------------------------------------------------

    override fun attach(listener: AwareApiListener) {
        synchronized(state) {
            if (attached) return // idempotent: the second start* shares it
            this.listener = listener
        }
        val manager = wifiAwareManager
            ?: throw TransportError.PlayServicesUnavailable(
                "wifi aware unsupported on this device (no WifiAwareManager)",
            )
        if (!manager.isAvailable) {
            throw TransportError.PlayServicesUnavailable(
                "wifi aware unavailable (radio off or unsupported)",
            )
        }
        val attachedLatch = CountDownLatch(1)
        val failure = java.util.concurrent.atomic.AtomicReference<TransportError?>()
        try {
            manager.attach(object : AttachCallback() {
                override fun onAttached(session: WifiAwareSession) {
                    synchronized(state) { this@AndroidAwareApi.session = session }
                    attachedLatch.countDown()
                }

                override fun onAttachFailed() {
                    failure.set(
                        TransportError.PlayServicesUnavailable("wifi aware attach failed (NAN off/unsupported)"),
                    )
                    attachedLatch.countDown()
                }

                override fun onAwareSessionTerminated() {
                    handleSessionLost()
                }
            }, handler)
        } catch (e: SecurityException) {
            throw TransportError.PermissionsDenied("attach blocked: ${e.message}")
        }
        awaitLatch(attachedLatch, "attach", ATTACH_TIMEOUT_MS)
        failure.get()?.let { throw it }
        synchronized(state) { attached = true }
    }

    override fun detach() {
        bestEffort {
            synchronized(state) {
                session?.close()
                session = null
                attached = false
                publishSession = null
                subscribeSession = null
            }
        }
    }

    override fun startPublish(serviceName: String, serviceInfo: ByteArray) {
        val currentSession = requireSession("startPublish")
        synchronized(state) {
            if (publishSession != null) {
                throw TransportError.IllegalState("already publishing")
            }
            publishServiceName = serviceName
            publishServiceInfo = serviceInfo.copyOf()
        }
        val started = CountDownLatch(1)
        val failure = java.util.concurrent.atomic.AtomicReference<TransportError?>()
        try {
            currentSession.publish(buildPublishConfig(serviceName, serviceInfo), object : DiscoverySessionCallback() {
                override fun onPublishStarted(session: PublishDiscoverySession) {
                    synchronized(state) { publishSession = session }
                    started.countDown()
                }

                override fun onSessionConfigFailed() {
                    failure.set(TransportError.IoFailure(RuntimeException("publish session config failed"), "startPublish failed"))
                    started.countDown()
                }

                override fun onSessionTerminated() {
                    handleSessionLost()
                }

                override fun onMessageReceived(peerHandle: PeerHandle, message: ByteArray) {
                    handleSignalingMessage(peerHandle, message)
                }
            }, handler)
        } catch (e: SecurityException) {
            throw TransportError.PermissionsDenied("publish blocked: ${e.message}")
        }
        awaitLatch(started, "startPublish", SESSION_START_TIMEOUT_MS)
        failure.get()?.let {
            synchronized(state) { publishServiceName = null; publishServiceInfo = null }
            throw it
        }
    }

    override fun updatePublish(serviceInfo: ByteArray) {
        val name: String?
        synchronized(state) {
            val current = publishSession ?: throw TransportError.IllegalState("no active publish to update")
            name = publishServiceName
            publishServiceInfo = serviceInfo.copyOf()
        }
        // Last-write-wins: the latest update call replaces the service info
        // for every subsequent discovery; racing updates converge on the
        // most recent write (the platform's updatePublish semantics).
        bestEffort {
            currentPublishSession()?.updatePublish(buildPublishConfig(name ?: "", serviceInfo))
        }
    }

    override fun stopPublish() {
        bestEffort {
            synchronized(state) {
                publishSession?.close()
                publishSession = null
                publishServiceName = null
                publishServiceInfo = null
            }
        }
    }

    override fun startSubscribe(serviceName: String) {
        val currentSession = requireSession("startSubscribe")
        synchronized(state) {
            if (subscribeSession != null) {
                throw TransportError.IllegalState("already subscribing")
            }
        }
        val started = CountDownLatch(1)
        val failure = java.util.concurrent.atomic.AtomicReference<TransportError?>()
        try {
            currentSession.subscribe(buildSubscribeConfig(serviceName), object : DiscoverySessionCallback() {
                override fun onSubscribeStarted(session: SubscribeDiscoverySession) {
                    synchronized(state) { subscribeSession = session }
                    started.countDown()
                }

                override fun onSessionConfigFailed() {
                    failure.set(TransportError.IoFailure(RuntimeException("subscribe session config failed"), "startSubscribe failed"))
                    started.countDown()
                }

                override fun onSessionTerminated() {
                    handleSessionLost()
                }

                override fun onServiceDiscovered(peerHandle: PeerHandle, serviceSpecificInfo: ByteArray?, matchFilter: MutableList<ByteArray>) {
                    val endpointId = internPeer(peerHandle)
                    // The advertised endpoint name rides the service-specific
                    // info (R2-002 convention): decode UTF-8 leniently.
                    val name = if (serviceSpecificInfo != null && serviceSpecificInfo.isNotEmpty()) {
                        serviceSpecificInfo.decodeToString()
                    } else {
                        "aware-${endpointId.value}"
                    }
                    listener?.onServiceDiscovered(endpointId, name)
                }

                override fun onServiceLost(peerHandle: PeerHandle, reason: Int) {
                    val endpointId = synchronized(state) { peersReverse[peerHandle] } ?: return
                    forgetPeer(endpointId)
                    listener?.onServiceLost(endpointId)
                }

                override fun onMessageReceived(peerHandle: PeerHandle, message: ByteArray) {
                    handleSignalingMessage(peerHandle, message)
                }
            }, handler)
        } catch (e: SecurityException) {
            throw TransportError.PermissionsDenied("subscribe blocked: ${e.message}")
        }
        awaitLatch(started, "startSubscribe", SESSION_START_TIMEOUT_MS)
        failure.get()?.let { throw it }
    }

    override fun stopSubscribe() {
        bestEffort {
            synchronized(state) {
                subscribeSession?.close()
                subscribeSession = null
                subscribeServiceName = null
            }
        }
    }

    override fun initiateDatapath(endpointId: EndpointId) {
        requireDatapathApis()
        val subscribe: SubscribeDiscoverySession
        val peer: PeerHandle
        synchronized(state) {
            subscribe = subscribeSession
                ?: throw TransportError.IllegalState("not discovering: no subscribe session to initiate from")
            peer = peers[endpointId]
                ?: throw TransportError.IllegalState("endpoint ${endpointId.value} has not been discovered")
            if (pendingInitiations.containsKey(endpointId)) {
                throw TransportError.IllegalState("initiation already pending for ${endpointId.value}")
            }
        }
        // 1. Send CONNECT (our advertised name rides the payload).
        val connectMessage = byteArrayOf(MSG_CONNECT) + "sharenet-node".encodeToByteArray()
        try {
            subscribe.sendMessage(peer, 0, connectMessage)
        } catch (e: SecurityException) {
            throw TransportError.PermissionsDenied("connect signaling blocked: ${e.message}")
        }
        // 2. Wait for ACCEPT/REJECT (handled in onMessageReceived).
        val initiation = PendingInitiation(CountDownLatch(1))
        synchronized(state) { pendingInitiations[endpointId] = initiation }
        awaitLatch(initiation.latch, "initiateDatapath (connect signaling)", DATAPATH_TIMEOUT_MS)
        synchronized(state) { pendingInitiations.remove(endpointId) }
        if (initiation.rejected) {
            throw TransportError.ConnectionRejected(endpointId, "connection rejected by endpoint ${endpointId.value}")
        }
        val accept = initiation.acceptPayload
            ?: throw TransportError.ConnectionRejected(endpointId, "no accept payload from endpoint ${endpointId.value}")
        // 3. Parse ACCEPT: u16be port || responder IPv6 text.
        if (accept.size < 3) {
            throw TransportError.ConnectionRejected(endpointId, "malformed accept payload from endpoint ${endpointId.value}")
        }
        val port = ((accept[1].toInt() and 0xFF) shl 8) or (accept[2].toInt() and 0xFF)
        val addressText = accept.copyOfRange(3, accept.size).decodeToString()
        val address = try {
            java.net.InetAddress.getByName(addressText)
        } catch (e: IOException) {
            throw TransportError.ConnectionRejected(endpointId, "invalid responder address from endpoint ${endpointId.value}")
        }
        // 4. Create the initiator-side network specifier + requestNetwork.
        val network = requestAwareNetwork(endpointId) {
            WifiAwareNetworkSpecifier.Builder(subscribe, peer).build()
        }
        // 5. Connect the stream socket through the aware network.
        val socket = try {
            val s = network.socketFactory.createSocket()
            s.connect(InetSocketAddress(address, port), SOCKET_CONNECT_TIMEOUT_MS.toInt())
            s
        } catch (e: IOException) {
            releaseNetwork(endpointId)
            throw TransportError.IoFailure(e, "initiateDatapath socket connect failed for ${endpointId.value}")
        }
        registerEstablished(endpointId, socket = socket, serverSocket = null)
        startReader(endpointId, socket)
        listener?.onConnectionAccepted(endpointId)
    }

    override fun acceptDatapath(endpointId: EndpointId) {
        requireDatapathApis()
        val publish: PublishDiscoverySession
        val peer: PeerHandle
        synchronized(state) {
            publish = publishSession
                ?: throw TransportError.IllegalState("not publishing: no publish session to accept on")
            peer = pendingRequests.remove(endpointId)
                ?: throw TransportError.IllegalState("no pending connection request for endpoint ${endpointId.value}")
        }
        // 1. Responder-side specifier for THIS peer's pending request.
        val network = requestAwareNetwork(endpointId) {
            WifiAwareNetworkSpecifier.Builder(publish, peer).build()
        }
        // 2. Server socket bound to the LOCAL aware IPv6 (from the
        //    network's link properties — no wildcard bind).
        val linkProperties = connectivityManager.getLinkProperties(network)
        val localAddress = linkProperties?.linkAddresses
            ?.mapNotNull { it.address as? Inet6Address }
            ?.firstOrNull()
        val serverSocket = try {
            if (localAddress != null) ServerSocket(0, 1, localAddress) else ServerSocket(0, 1)
        } catch (e: IOException) {
            releaseNetwork(endpointId)
            throw TransportError.IoFailure(e, "acceptDatapath server socket bind failed for ${endpointId.value}")
        }
        val port = serverSocket.localPort
        // 3. ACCEPT carries the port + our aware address to the initiator.
        val addressText = localAddress?.hostAddress ?: ""
        val acceptMessage = byteArrayOf(MSG_ACCEPT) + byteArrayOf(
            ((port ushr 8) and 0xFF).toByte(),
            (port and 0xFF).toByte(),
        ) + addressText.encodeToByteArray()
        try {
            publish.sendMessage(peer, 0, acceptMessage)
        } catch (e: SecurityException) {
            bestEffort { serverSocket.close() }
            releaseNetwork(endpointId)
            throw TransportError.PermissionsDenied("accept signaling blocked: ${e.message}")
        } catch (e: RuntimeException) {
            bestEffort { serverSocket.close() }
            releaseNetwork(endpointId)
            throw TransportError.IoFailure(e, "acceptDatapath signaling failed for ${endpointId.value}")
        }
        registerEstablished(endpointId, socket = null, serverSocket = serverSocket)
        // 4. The datapath is up (NDP established + listening): notify now;
        //    the TCP accept happens on the IO executor.
        ioExecutor.execute {
            try {
                val socket = serverSocket.accept()
                synchronized(state) { established[endpointId]?.let { it.socket = socket } }
                startReader(endpointId, socket)
            } catch (e: IOException) {
                // The initiator never connected: the datapath is gone.
                teardownEndpoint(endpointId)
                listener?.onDisconnected(endpointId)
            }
        }
        listener?.onConnectionAccepted(endpointId)
    }

    override fun rejectDatapath(endpointId: EndpointId) {
        val publish: PublishDiscoverySession?
        val peer: PeerHandle?
        synchronized(state) {
            peer = pendingRequests.remove(endpointId)
                ?: throw TransportError.IllegalState("no pending connection request for endpoint ${endpointId.value}")
            publish = publishSession
        }
        // Refuse the request and release its resources.
        if (publish != null) {
            bestEffort { publish.sendMessage(peer!!, 0, byteArrayOf(MSG_REJECT)) }
        }
        forgetPeer(endpointId)
    }

    override fun sendData(endpointId: EndpointId, bytes: ByteArray) {
        val socket = synchronized(state) {
            established[endpointId]?.socket
        } ?: throw TransportError.IllegalState("endpoint ${endpointId.value} has no established datapath")
        try {
            synchronized(established[endpointId]!!.writeLock) {
                socket.getOutputStream().write(bytes)
                socket.getOutputStream().flush()
            }
        } catch (e: IOException) {
            throw TransportError.IoFailure(e, "sendData failed for endpoint ${endpointId.value}")
        }
    }

    override fun stopAll() {
        // Best-effort full teardown; never throws.
        val endpoints: List<EndpointId>
        synchronized(state) {
            endpoints = established.keys.toList()
        }
        for (endpointId in endpoints) {
            teardownEndpoint(endpointId)
        }
        bestEffort {
            synchronized(state) {
                publishSession?.close()
                subscribeSession?.close()
                session?.close()
                publishSession = null
                subscribeSession = null
                session = null
                attached = false
                pendingRequests.clear()
                pendingInitiations.clear()
                peers.clear()
                peersReverse.clear()
                publishServiceName = null
                publishServiceInfo = null
                subscribeServiceName = null
            }
        }
    }

    // ------------------------------------------------------------------
    // Signaling (facade-internal connect handshake over follow-up messages)
    // ------------------------------------------------------------------

    /** Parse and route one CONNECT/ACCEPT/REJECT follow-up message. */
    private fun handleSignalingMessage(peerHandle: PeerHandle, message: ByteArray) {
        if (message.isEmpty()) return
        when (message[0]) {
            MSG_CONNECT -> {
                // Responder side: a remote endpoint wants to connect.
                val name = if (message.size > 1) message.copyOfRange(1, message.size).decodeToString() else "aware-peer"
                val endpointId = internPeer(peerHandle)
                synchronized(state) {
                    if (pendingRequests.containsKey(endpointId)) return // duplicate: drop
                    pendingRequests[endpointId] = peerHandle
                }
                listener?.onConnectionRequested(endpointId, name)
            }
            MSG_ACCEPT -> {
                // Initiator side: the responder accepted — wake the waiter.
                val endpointId = synchronized(state) { peersReverse[peerHandle] } ?: return
                val initiation = synchronized(state) { pendingInitiations[endpointId] } ?: return
                initiation.acceptPayload = message.copyOf()
                initiation.latch.countDown()
            }
            MSG_REJECT -> {
                val endpointId = synchronized(state) { peersReverse[peerHandle] } ?: return
                val initiation = synchronized(state) { pendingInitiations[endpointId] } ?: return
                initiation.rejected = true
                initiation.latch.countDown()
            }
            else -> Unit // unknown signaling byte: ignored (forward-compatible)
        }
    }

    // ------------------------------------------------------------------
    // Datapath plumbing (API 33+)
    // ------------------------------------------------------------------

    /** Typed platform-unavailable error for devices without the API level. */
    private fun requireDatapathApis() {
        if (Build.VERSION.SDK_INT < 33) {
            throw TransportError.PlayServicesUnavailable(
                "wifi aware datapaths require API 33+ (device runs API ${Build.VERSION.SDK_INT})",
            )
        }
    }

    /**
     * requestNetwork with an aware specifier; BLOCKS until onAvailable
     * (returns the Network) or fails typed. The callback stays registered
     * for the datapath's lifetime (released in [releaseNetwork]).
     */
    private fun requestAwareNetwork(
        endpointId: EndpointId,
        specifier: () -> WifiAwareNetworkSpecifier,
    ): Network {
        val available = CountDownLatch(1)
        val outcome = java.util.concurrent.atomic.AtomicReference<Any?>() // Network | TransportError
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                outcome.set(network)
                available.countDown()
            }

            override fun onUnavailable() {
                outcome.set(
                    TransportError.ConnectionRejected(
                        endpointId,
                        "aware datapath unavailable for endpoint ${endpointId.value}",
                    ),
                )
                available.countDown()
            }
        }
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI_AWARE)
            .setNetworkSpecifier(specifier())
            .build()
        try {
            connectivityManager.requestNetwork(request, callback, handler)
        } catch (e: SecurityException) {
            bestEffort { connectivityManager.unregisterNetworkCallback(callback) }
            throw TransportError.PermissionsDenied("datapath request blocked: ${e.message}")
        }
        // The callback doubles as the datapath's lifecycle owner: re-register
        // it into the established table once the network is up.
        awaitLatch(available, "requestNetwork (aware datapath)", DATAPATH_TIMEOUT_MS)
        val result = outcome.get()
        if (result is TransportError) {
            bestEffort { connectivityManager.unregisterNetworkCallback(callback) }
            throw result
        }
        val network = result as Network
        synchronized(state) {
            established[endpointId] = Datapath(networkCallback = callback, socket = null, serverSocket = null, writeLock = Any())
        }
        return network
    }

    /** Release one endpoint's network callback (resource release, no zombie). */
    private fun releaseNetwork(endpointId: EndpointId) {
        val datapath = synchronized(state) { established.remove(endpointId) } ?: return
        bestEffort { connectivityManager.unregisterNetworkCallback(datapath.networkCallback) }
        bestEffort { datapath.socket?.close() }
        bestEffort { datapath.serverSocket?.close() }
    }

    private fun registerEstablished(endpointId: EndpointId, socket: Socket?, serverSocket: ServerSocket?) {
        synchronized(state) {
            val existing = established[endpointId]
            if (existing != null) {
                existing.socket = socket
                existing.serverSocket = serverSocket
            } else {
                established[endpointId] = Datapath(
                    networkCallback = object : ConnectivityManager.NetworkCallback() {},
                    socket = socket,
                    serverSocket = serverSocket,
                    writeLock = Any(),
                )
            }
        }
    }

    /** Stream reader: raw chunks to [AwareApiListener.onStreamData]. */
    private fun startReader(endpointId: EndpointId, socket: Socket) {
        ioExecutor.execute {
            val buffer = ByteArray(STREAM_READ_BYTES)
            try {
                val input = socket.getInputStream()
                while (true) {
                    val n = input.read(buffer)
                    if (n < 0) break
                    val chunk = if (n == buffer.size) buffer.copyOf() else buffer.copyOf(n)
                    listener?.onStreamData(endpointId, chunk)
                }
            } catch (expected: IOException) {
                // Fall through to the teardown below.
            }
            // Stream end (peer closed or failed): the datapath is gone.
            teardownEndpoint(endpointId)
            listener?.onDisconnected(endpointId)
        }
    }

    /** Close and forget one endpoint's datapath resources. */
    private fun teardownEndpoint(endpointId: EndpointId) {
        val datapath: Datapath?
        synchronized(state) { datapath = established.remove(endpointId) }
        if (datapath == null) return
        bestEffort { connectivityManager.unregisterNetworkCallback(datapath.networkCallback) }
        bestEffort { datapath.socket?.close() }
        bestEffort { datapath.serverSocket?.close() }
    }

    // ------------------------------------------------------------------
    // Session/config construction
    // ------------------------------------------------------------------

    private fun requireSession(operation: String): WifiAwareSession {
        val current = synchronized(state) {
            if (!attached) null else session
        }
        return current ?: throw TransportError.IllegalState("not attached: attach a session first ($operation)")
    }

    private fun currentPublishSession(): PublishDiscoverySession? =
        synchronized(state) { publishSession }

    private fun buildPublishConfig(serviceName: String, serviceInfo: ByteArray): PublishConfig {
        val builder = PublishConfig.Builder()
            .setServiceName(serviceName)
            .setServiceSpecificInfo(serviceInfo.copyOf())
            .setPublishType(PublishConfig.PUBLISH_TYPE_UNSOLICITED)
            .setTerminateNotificationEnabled(true)
        if (Build.VERSION.SDK_INT >= 34) {
            // NAN pairing bootstrap (API 34+): enabled opportunistically for
            // the future secure-pairing layer; this foundation does not
            // drive the pairing callbacks yet.
            builder.setPairingConfig(
                AwarePairingConfig.Builder().setPairingSetupEnabled(true).build(),
            )
        }
        return builder.build()
    }

    private fun buildSubscribeConfig(serviceName: String): SubscribeConfig {
        val builder = SubscribeConfig.Builder()
            .setServiceName(serviceName)
            .setSubscribeType(SubscribeConfig.SUBSCRIBE_TYPE_PASSIVE)
            .setTerminateNotificationEnabled(true)
        if (Build.VERSION.SDK_INT >= 34) {
            builder.setPairingConfig(
                AwarePairingConfig.Builder().setPairingSetupEnabled(true).build(),
            )
        }
        return builder.build()
    }

    // ------------------------------------------------------------------
    // Peer bookkeeping + session loss
    // ------------------------------------------------------------------

    /** Map a platform peer to its stable opaque EndpointId. */
    private fun internPeer(peerHandle: PeerHandle): EndpointId {
        synchronized(state) {
            peersReverse[peerHandle]?.let { return it }
            val endpointId = EndpointId("aware-${endpointSeq.incrementAndGet()}")
            peers[endpointId] = peerHandle
            peersReverse[peerHandle] = endpointId
            return endpointId
        }
    }

    /** Drop all bookkeeping for a peer (it is gone). */
    private fun forgetPeer(endpointId: EndpointId) {
        synchronized(state) {
            peers.remove(endpointId)?.let { peersReverse.remove(it) }
            pendingRequests.remove(endpointId)
        }
        teardownEndpoint(endpointId)
    }

    /**
     * Conservative session-loss policy: ANY NAN session termination
     * (attach-level [AttachCallback.onAwareSessionTerminated] or a
     * publish/subscribe session termination) resets the whole facade to
     * detached and fires [AwareApiListener.onSessionLost] — never a zombie
     * half-session. The adapter's next start* re-attaches fresh.
     */
    private fun handleSessionLost() {
        synchronized(state) {
            session = null
            attached = false
            publishSession = null
            subscribeSession = null
            publishServiceName = null
            publishServiceInfo = null
            subscribeServiceName = null
            pendingRequests.clear()
            peers.clear()
            peersReverse.clear()
            val endpoints = established.keys.toList()
            // Wake any stranded initiator waiters.
            for (pending in pendingInitiations.values) {
                pending.rejected = true
                pending.latch.countDown()
            }
            pendingInitiations.clear()
            for (endpointId in endpoints) {
                established[endpointId]?.let { datapath ->
                    bestEffort { connectivityManager.unregisterNetworkCallback(datapath.networkCallback) }
                    bestEffort { datapath.socket?.close() }
                    bestEffort { datapath.serverSocket?.close() }
                }
            }
            established.clear()
        }
        listener?.onSessionLost()
    }

    // ------------------------------------------------------------------
    // Mechanical helpers
    // ------------------------------------------------------------------

    private fun awaitLatch(latch: CountDownLatch, operation: String, timeoutMs: Long) {
        try {
            if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                throw TransportError.IoFailure(
                    RuntimeException("$operation timed out"),
                    "$operation timed out after ${timeoutMs}ms",
                )
            }
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw TransportError.IoFailure(e, "$operation interrupted")
        }
    }

    /** Best-effort operations must never throw (the stop* law). */
    private inline fun bestEffort(task: () -> Unit) {
        try {
            task()
        } catch (expected: Exception) {
            // Deliberately swallowed.
        }
    }
}
