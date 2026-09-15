package org.sharenet.transport.nearby

import android.app.Service
import android.content.Intent
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import org.sharenet.transport.contract.NearbyTransport
import org.sharenet.transport.contract.TransportError
import org.sharenet.transport.contract.TransportEvent
import org.sharenet.transport.contract.TransportFrame
import org.sharenet.transport.contract.TransportListener

/**
 * Production caller skeleton (R2-001): the Android Service the future
 * ShareNet app embeds to run the nearby transport.
 *
 * This is a SKELETON: it wires Service lifecycle (onCreate/onDestroy) to
 * adapter lifecycle (start/stop) and dispatches the ACTION_* intents to
 * adapter calls on a dedicated background thread (GmsNearbyApi blocks —
 * never on the main thread). App-level concerns (foreground-service
 * promotion, notifications, UI wiring, listener registration into the
 * protocol stack) belong to the embedding app and later waves (R4-004).
 *
 * Usage from the host app:
 * ```kotlin
 * val intent = Intent(context, ShareNetTransportService::class.java).apply {
 *     action = ShareNetTransportService.ACTION_START_ADVERTISING
 *     putExtra(ShareNetTransportService.EXTRA_ENDPOINT_NAME, "gateway-42")
 * }
 * context.startService(intent)
 * ```
 *
 * Persistence: none — the service keeps only transient session state in the
 * adapter.
 */
class ShareNetTransportService : Service() {

    companion object {
        private const val TAG = "ShareNetTransport"

        /** Nearby Connections service id — scoping discovery to ShareNet. */
        const val SERVICE_ID = "org.sharenet.transport"

        /** Start advertising with [EXTRA_ENDPOINT_NAME] (default "sharenet-node"). */
        const val ACTION_START_ADVERTISING =
            "org.sharenet.transport.nearby.action.START_ADVERTISING"

        /** Start discovering nearby ShareNet endpoints. */
        const val ACTION_START_DISCOVERY =
            "org.sharenet.transport.nearby.action.START_DISCOVERY"

        /** Stop everything (advertising, discovery, connections). */
        const val ACTION_STOP = "org.sharenet.transport.nearby.action.STOP"

        /** String extra for [ACTION_START_ADVERTISING]: advertised endpoint name. */
        const val EXTRA_ENDPOINT_NAME = "endpoint_name"

        private const val DEFAULT_ENDPOINT_NAME = "sharenet-node"
    }

    private lateinit var workerThread: HandlerThread
    private lateinit var worker: Handler

    /** The transport this service hosts; created in onCreate, stopped in onDestroy. */
    private var transport: NearbyTransport? = null

    override fun onCreate() {
        super.onCreate()
        workerThread = HandlerThread("ShareNetTransport").also { it.start() }
        worker = Handler(workerThread.looper)

        // Production wiring — the ONLY construction of GmsNearbyApi in the
        // app process (via its factory, so no GMS import appears here).
        // Everything below this line is contract vocabulary.
        val api = GmsNearbyApi.fromContext(this, SERVICE_ID)
        transport = NearbyConnectionsAdapter(api, NearbyStrategyKind.P2P_CLUSTER).also { adapter ->
            // Skeleton-level logging listener. The real app registers its
            // transport consumer here (the future link layer, R3-001).
            adapter.addListener(LoggingListener)
        }
        Log.i(TAG, "transport service created (serviceId=$SERVICE_ID)")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        val endpointName = intent?.getStringExtra(EXTRA_ENDPOINT_NAME) ?: DEFAULT_ENDPOINT_NAME
        worker.post {
            val adapter = transport ?: return@post
            try {
                when (action) {
                    ACTION_START_ADVERTISING -> adapter.startAdvertising(endpointName)
                    ACTION_START_DISCOVERY -> adapter.startDiscovery()
                    ACTION_STOP -> adapter.stop()
                    else -> Log.w(TAG, "ignoring unknown action $action")
                }
            } catch (e: TransportError) {
                // Typed transport errors are service-level events, not crashes
                // (e.g. play services unavailable on this device).
                Log.w(TAG, "transport action $action failed: $e")
            }
        }
        // Not sticky: transport is demand-driven; a restart without intents
        // would have nothing to resume (session state is transient by design).
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        // Ordered posts: stop the adapter first, then quit the worker.
        worker.post { transport?.stop() }
        worker.post { workerThread.quitSafely() }
        Log.i(TAG, "transport service destroyed")
        super.onDestroy()
    }

    override fun onBind(intent: Intent?) = null // started service; not bindable

    /** Skeleton listener: logs lifecycle events (real consumer arrives in R3-001). */
    private object LoggingListener : TransportListener {
        override fun onTransportEvent(event: TransportEvent) {
            Log.d(TAG, "event: $event")
        }

        override fun onFrame(endpointId: org.sharenet.transport.contract.EndpointId, frame: TransportFrame) {
            Log.d(TAG, "frame from ${endpointId.value}: $frame")
        }
    }
}
