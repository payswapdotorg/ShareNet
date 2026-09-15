package org.sharenet.transport.nearby

import com.google.android.gms.common.api.ApiException
import com.google.android.gms.nearby.Nearby
import com.google.android.gms.nearby.connection.AdvertisingOptions
import com.google.android.gms.nearby.connection.ConnectionInfo
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback
import com.google.android.gms.nearby.connection.ConnectionResolution
import com.google.android.gms.nearby.connection.ConnectionsClient
import com.google.android.gms.nearby.connection.DiscoveredEndpointInfo
import com.google.android.gms.nearby.connection.DiscoveryOptions
import com.google.android.gms.nearby.connection.EndpointDiscoveryCallback
import com.google.android.gms.nearby.connection.Payload
import com.google.android.gms.nearby.connection.PayloadCallback
import com.google.android.gms.nearby.connection.PayloadTransferUpdate
import com.google.android.gms.nearby.connection.Strategy
import com.google.android.gms.tasks.RuntimeExecutionException
import com.google.android.gms.tasks.Task
import com.google.android.gms.tasks.Tasks
import org.sharenet.transport.contract.EndpointId
import org.sharenet.transport.contract.TransportError
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * THE ONLY PLACE where Google Play services (GMS) types appear (R2-001,
 * architecture lock L009).
 *
 * Thin, mechanical translation between the GMS Nearby Connections API and
 * the [NearbyApi] facade:
 *  * GMS callbacks → [NearbyApiListener] events in contract vocabulary;
 *  * GMS tasks → blocking calls (`Tasks.await`) — so callers MUST be off the
 *    main thread (the [ShareNetTransportService] skeleton enforces this);
 *  * GMS/`ApiException` failures → typed [TransportError]s.
 *
 * STREAM receives are drained on a single background executor and surfaced as
 * chunk events, so the adapter can reassemble them exactly like it does for
 * the scripted fake in tests.
 *
 * Real GMS behavior runs on devices (R4-004); in this foundation the class is
 * compile-verified against play-services-nearby 19.5.0 and its logic is kept
 * deliberately small so device bring-up has little surface to trust.
 */
class GmsNearbyApi(
    private val client: ConnectionsClient,
    private val serviceId: String,
) : NearbyApi {

    companion object {
        /**
         * Production factory: the ONLY approved way to build this class. Keeps
         * every other file in the module free of GMS imports.
         */
        fun fromContext(context: android.content.Context, serviceId: String): GmsNearbyApi =
            GmsNearbyApi(Nearby.getConnectionsClient(context), serviceId)
    }

    @Volatile
    private var listener: NearbyApiListener? = null

    private val streamExecutor: ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "sharenet-nearby-streams").apply { isDaemon = true }
    }

    // ------------------------------------------------------------------
    // NearbyApi implementation
    // ------------------------------------------------------------------

    override fun startAdvertising(name: String, strategy: NearbyStrategyKind, listener: NearbyApiListener) {
        this.listener = listener
        val callback = object : ConnectionLifecycleCallback() {
            override fun onConnectionInitiated(endpointId: String, info: ConnectionInfo) {
                listener.onConnectionInitiated(
                    EndpointId(endpointId),
                    info.endpointName,
                    info.authenticationToken,
                )
            }

            override fun onConnectionResult(endpointId: String, resolution: ConnectionResolution) {
                if (resolution.status.isSuccess) {
                    listener.onConnectionAccepted(EndpointId(endpointId))
                } else {
                    listener.onConnectionRejected(EndpointId(endpointId))
                }
            }

            override fun onDisconnected(endpointId: String) {
                listener.onDisconnected(EndpointId(endpointId))
            }
        }
        await("startAdvertising") {
            client.startAdvertising(
                name,
                serviceId,
                callback,
                AdvertisingOptions.Builder().setStrategy(toGmsStrategy(strategy)).build(),
            )
        }
    }

    override fun stopAdvertising() {
        bestEffort { client.stopAdvertising() }
    }

    override fun startDiscovery(strategy: NearbyStrategyKind, listener: NearbyApiListener) {
        this.listener = listener
        val callback = object : EndpointDiscoveryCallback() {
            override fun onEndpointFound(endpointId: String, info: DiscoveredEndpointInfo) {
                listener.onEndpointFound(EndpointId(endpointId), info.endpointName)
            }

            override fun onEndpointLost(endpointId: String) {
                listener.onEndpointLost(EndpointId(endpointId))
            }
        }
        await("startDiscovery") {
            client.startDiscovery(
                serviceId,
                callback,
                DiscoveryOptions.Builder().setStrategy(toGmsStrategy(strategy)).build(),
            )
        }
    }

    override fun stopDiscovery() {
        bestEffort { client.stopDiscovery() }
    }

    override fun stopAll() {
        bestEffort { client.stopAllEndpoints() }
    }

    override fun acceptConnection(endpointId: EndpointId) {
        await("acceptConnection") { client.acceptConnection(endpointId.value, payloadCallback) }
    }

    override fun rejectConnection(endpointId: EndpointId) {
        await("rejectConnection") { client.rejectConnection(endpointId.value) }
    }

    override fun sendBytes(endpointId: EndpointId, wire: ByteArray) {
        await("sendBytes") { client.sendPayload(endpointId.value, Payload.fromBytes(wire)) }
    }

    override fun sendStream(endpointId: EndpointId, wire: ByteArray) {
        await("sendStream") {
            client.sendPayload(endpointId.value, Payload.fromStream(ByteArrayInputStream(wire)))
        }
    }

    // ------------------------------------------------------------------
    // Payload plumbing
    // ------------------------------------------------------------------

    private val payloadCallback = object : PayloadCallback() {
        override fun onPayloadReceived(endpointId: String, payload: Payload) {
            val target = listener ?: return
            when (payload.type) {
                Payload.Type.BYTES -> {
                    val bytes = payload.asBytes() ?: return
                    target.onBytesReceived(EndpointId(endpointId), bytes)
                }
                Payload.Type.STREAM -> {
                    val stream: InputStream = payload.asStream()?.asInputStream() ?: return
                    val payloadId = payload.id
                    streamExecutor.execute {
                        drainStream(target, EndpointId(endpointId), payloadId, stream)
                    }
                }
                // FILE payloads are not used by this transport (documented).
                else -> Unit
            }
        }

        override fun onPayloadTransferUpdate(endpointId: String, update: PayloadTransferUpdate) {
            val target = listener ?: return
            if (update.status == PayloadTransferUpdate.Status.FAILURE) {
                target.onTransferFailed(EndpointId(endpointId), update.payloadId)
            }
        }
    }

    /** Read a received stream fully, forwarding chunks to the listener. */
    private fun drainStream(target: NearbyApiListener, endpointId: EndpointId, payloadId: Long, stream: InputStream) {
        val buffer = ByteArray(PayloadPolicy.STREAM_CHUNK_BYTES)
        try {
            while (true) {
                val n = stream.read(buffer)
                if (n < 0) break
                if (n == buffer.size) {
                    target.onStreamChunk(endpointId, payloadId, buffer.copyOf())
                } else {
                    target.onStreamChunk(endpointId, payloadId, buffer.copyOf(n))
                }
            }
            target.onStreamCompleted(endpointId, payloadId)
        } catch (e: IOException) {
            // Surface as transfer failure; the adapter cleans up partial state.
            target.onTransferFailed(endpointId, payloadId)
        } finally {
            try {
                stream.close()
            } catch (expected: IOException) {
                // Closing a finished transfer stream is best-effort.
            }
        }
    }

    // ------------------------------------------------------------------
    // Task / error translation (mechanical)
    // ------------------------------------------------------------------

    private inline fun await(operation: String, task: () -> Task<Void>) {
        try {
            Tasks.await(task())
        } catch (e: ApiException) {
            throw translate(operation, e)
        } catch (e: SecurityException) {
            throw TransportError.PermissionsDenied("$operation blocked: ${e.message}")
        } catch (e: RuntimeExecutionException) {
            val cause = e.cause
            if (cause is SecurityException) {
                throw TransportError.PermissionsDenied("$operation blocked: ${cause.message}")
            }
            throw TransportError.IoFailure(e, "$operation failed")
        } catch (e: IOException) {
            throw TransportError.IoFailure(e, "$operation failed")
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            throw TransportError.IoFailure(e, "$operation interrupted")
        }
    }

    /** Classify a GMS [ApiException] into a typed TransportError. */
    private fun translate(operation: String, e: ApiException): TransportError = when (e.statusCode) {
        // Google Play services is unusable on this device right now.
        com.google.android.gms.common.api.CommonStatusCodes.API_NOT_CONNECTED,
        com.google.android.gms.common.api.CommonStatusCodes.NETWORK_ERROR,
        com.google.android.gms.common.api.CommonStatusCodes.DEVELOPER_ERROR,
        -> TransportError.PlayServicesUnavailable("$operation: api error ${e.statusCode}: ${e.message}")

        else -> TransportError.IoFailure(e, "$operation failed with api error ${e.statusCode}")
    }

    /** Best-effort stops must never throw (assignment: stop is idempotent/safe). */
    private inline fun bestEffort(task: () -> Unit) {
        try {
            task()
        } catch (expected: Exception) {
            // Deliberately swallowed: stop paths are best-effort, and partial
            // platform state is cleaned by stopAllEndpoints semantics.
        }
    }

    private fun toGmsStrategy(strategy: NearbyStrategyKind): Strategy = when (strategy) {
        NearbyStrategyKind.P2P_CLUSTER -> Strategy.P2P_CLUSTER
        NearbyStrategyKind.P2P_POINT_TO_POINT -> Strategy.P2P_POINT_TO_POINT
        NearbyStrategyKind.P2P_STAR -> Strategy.P2P_STAR
    }
}
