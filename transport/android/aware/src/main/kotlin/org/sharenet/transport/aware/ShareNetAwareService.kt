package org.sharenet.transport.aware

import android.app.Service
import android.content.Intent
import android.os.Handler
import android.os.HandlerThread
import android.util.Log
import org.sharenet.transport.contract.NearbyTransport
import org.sharenet.transport.contract.QualityRecorder
import org.sharenet.transport.contract.TransportEvent
import org.sharenet.transport.contract.TransportFrame
import org.sharenet.transport.contract.TransportListener

/**
 * Production caller (R2-002): the Android Service the ShareNet app embeds to
 * run the Wi-Fi Aware transport — the same class of caller R2-001 proved for
 * Nearby Connections (`nearby/ShareNetTransportService`).
 *
 * The service owns the adapter lifecycle (Service create → attach aware
 * session → publish/subscribe → datapaths → teardown) and dispatches the
 * ACTION_* intents to adapter calls on a dedicated background thread via the
 * host-tested [AwareServiceController] ([AndroidAwareApi] blocks — never on
 * the main thread).
 *
 * This is a SKELETON in the R2-001 sense: foreground-service promotion,
 * notifications, UI wiring, and listener registration into the protocol
 * stack belong to the embedding app and later waves (R4-004). The runtime
 * path (create → attach → publish/subscribe → datapaths → teardown) is
 * host-verified through `FakeAwareApi`; on-device behavior against real NAN
 * radios is the operator-gated gap (mirroring the R10-002 device-leg
 * pattern).
 *
 * Usage from the host app:
 * ```kotlin
 * val intent = Intent(context, ShareNetAwareService::class.java).apply {
 *     action = ShareNetAwareService.ACTION_START_PUBLISH
 *     putExtra(ShareNetAwareService.EXTRA_ENDPOINT_NAME, "gateway-42")
 * }
 * context.startService(intent)
 * ```
 *
 * Persistence: none — the service keeps only transient session state in the
 * adapter.
 */
class ShareNetAwareService : Service() {

    companion object {
        private const val TAG = "ShareNetAware"

        /**
         * The NAN service name scoping discovery to ShareNet (also the
         * adapter's default — see [AwareLinksAdapter.DEFAULT_SERVICE_NAME]).
         */
        const val SERVICE_NAME: String = AwareLinksAdapter.DEFAULT_SERVICE_NAME

        /** Start publishing with [EXTRA_ENDPOINT_NAME] (default "sharenet-node"). */
        const val ACTION_START_PUBLISH =
            "org.sharenet.transport.aware.action.START_PUBLISH"

        /** Start subscribing to nearby ShareNet publishers. */
        const val ACTION_START_SUBSCRIBE =
            "org.sharenet.transport.aware.action.START_SUBSCRIBE"

        /** Stop everything (publish, subscribe, datapaths, session). */
        const val ACTION_STOP =
            "org.sharenet.transport.aware.action.STOP"

        /** String extra for [ACTION_START_PUBLISH]: advertised endpoint name. */
        const val EXTRA_ENDPOINT_NAME = "endpoint_name"

        private const val DEFAULT_ENDPOINT_NAME = "sharenet-node"
    }

    private lateinit var workerThread: HandlerThread
    private lateinit var worker: Handler

    /** The transport this service hosts; created in onCreate, stopped in onDestroy. */
    private var transport: NearbyTransport? = null

    /** Host-tested intent routing + typed-error containment (R2-002). */
    private var controller: AwareServiceController? = null

    /**
     * Quality evidence sink (R2-004): connect/disconnect timing samples the
     * adapter measures honestly. In-memory only (see QualityRecorder docs);
     * the embedding app reads it (e.g. for the future R3-003 topology
     * evidence layer) — this skeleton exposes it for the app to poll.
     */
    private lateinit var qualityRecorder: QualityRecorder

    override fun onCreate() {
        super.onCreate()
        workerThread = HandlerThread("ShareNetAware").also { it.start() }
        worker = Handler(workerThread.looper)

        // Production wiring — the ONLY construction of AndroidAwareApi in
        // the app process (via its factory, so no android.net.wifi.aware
        // import appears here). Everything below this line is contract
        // vocabulary.
        val api = AndroidAwareApi.fromContext(this)
        qualityRecorder = QualityRecorder()
        transport = AwareLinksAdapter(api, SERVICE_NAME, qualityRecorder).also { adapter ->
            // Skeleton-level logging listener. The real app registers its
            // transport consumer here (the future link layer, R3-001).
            adapter.addListener(LoggingListener)
        }
        controller = AwareServiceController(
            transport!!,
            log = { message -> Log.w(TAG, message) },
        )
        Log.i(TAG, "aware transport service created (serviceName=$SERVICE_NAME)")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        val endpointName = intent?.getStringExtra(EXTRA_ENDPOINT_NAME) ?: DEFAULT_ENDPOINT_NAME
        worker.post {
            controller?.handleAction(action, endpointName)
        }
        // Not sticky: transport is demand-driven; a restart without intents
        // would have nothing to resume (session state is transient by design).
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        // Ordered posts: stop the adapter first, then quit the worker.
        worker.post { controller?.destroy() }
        worker.post { workerThread.quitSafely() }
        Log.i(TAG, "aware transport service destroyed")
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
