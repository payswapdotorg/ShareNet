package org.sharenet.transport.aware

import org.sharenet.transport.contract.NearbyTransport
import org.sharenet.transport.contract.TransportError

/**
 * Host-testable service logic for [ShareNetAwareService] (R2-002).
 *
 * The R2-001 production caller (`nearby/ShareNetTransportService`) wires
 * Service lifecycle → adapter lifecycle inline; this class extracts exactly
 * that logic into a pure-Kotlin controller with NO Android imports, so the
 * intent routing, typed-error containment, and teardown semantics are
 * host-verifiable through the scripted `FakeAwareApi` (the service shell
 * itself is compile-verified by the real Android SDK build).
 *
 * Responsibilities (deliberately narrow, mirroring R2-001):
 *  * route ACTION_* intents to [NearbyTransport] calls;
 *  * contain typed [TransportError]s (log, never crash — e.g. Wi-Fi Aware
 *    unavailable on this device);
 *  * own the teardown-on-destroy ordering (stop the transport, once).
 *
 * App-level concerns (foreground-service promotion, notifications, UI
 * wiring, listener registration into the protocol stack) belong to the
 * embedding app and later waves.
 */
class AwareServiceController(
    private val transport: NearbyTransport,
    private val log: (String) -> Unit = {},
) {

    /** Whether [destroy] has run (idempotent teardown). */
    private var destroyed = false

    /**
     * Handle one service action. Returns `true` when the action was
     * recognized (and routed), `false` for unknown/null actions.
     *
     * Typed transport failures are CONTAINED: logged, never rethrown — the
     * service must survive a transport being unavailable (the NAN-off case).
     */
    fun handleAction(action: String?, endpointName: String): Boolean {
        if (destroyed) {
            log("ignoring action after destroy: $action")
            return false
        }
        return try {
            when (action) {
                ShareNetAwareService.ACTION_START_PUBLISH -> {
                    transport.startAdvertising(endpointName)
                    true
                }
                ShareNetAwareService.ACTION_START_SUBSCRIBE -> {
                    transport.startDiscovery()
                    true
                }
                ShareNetAwareService.ACTION_STOP -> {
                    transport.stop()
                    true
                }
                else -> {
                    log("ignoring unknown action $action")
                    false
                }
            }
        } catch (e: TransportError) {
            // Typed transport errors are service-level events, not crashes
            // (e.g. Wi-Fi Aware unsupported on this device).
            log("transport action $action failed: $e")
            true // the action was recognized even though the transport failed
        }
    }

    /**
     * Teardown: stop the transport. Idempotent and never-throwing (the
     * best-effort stop law, applied at the service boundary too).
     */
    fun destroy() {
        if (destroyed) return
        destroyed = true
        try {
            transport.stop()
        } catch (expected: Throwable) {
            // stop() is documented never-throw; this guard is belt-and-braces
            // for hostile transport implementations.
            log("transport stop failed: $expected")
        }
    }
}
