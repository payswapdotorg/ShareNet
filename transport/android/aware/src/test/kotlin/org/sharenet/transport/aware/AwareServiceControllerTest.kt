package org.sharenet.transport.aware

import org.sharenet.transport.contract.EndpointId
import org.sharenet.transport.contract.NearbyTransport
import org.sharenet.transport.contract.TransportError
import org.sharenet.transport.contract.TransportEvent
import org.sharenet.transport.contract.TransportFrame
import org.sharenet.transport.contract.TransportListener
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Service logic tests (R2-002) — the host-testable [AwareServiceController]
 * extracted from the Android Service shell ([ShareNetAwareService] is
 * compile-verified by the real SDK build; its runtime logic lives HERE and
 * is verified on the JVM through the scripted fake):
 *
 *  * ACTION_* intents route to the adapter (publish/subscribe/stop);
 *  * typed transport errors are CONTAINED (logged, never crash the service
 *    — e.g. Wi-Fi Aware unavailable on this device);
 *  * teardown-on-destroy runs exactly once, never throws, and ignores
 *    post-destroy actions.
 */
class AwareServiceControllerTest {

    private class RecordingTransport : NearbyTransport {
        val advertisingNames = mutableListOf<String>()
        var discoveryStarts = 0
        var stopCalls = 0
        var failAdvertising = false

        override fun addListener(listener: TransportListener) = Unit
        override fun removeListener(listener: TransportListener) = Unit

        override fun startAdvertising(name: String) {
            if (failAdvertising) throw TransportError.PlayServicesUnavailable("scripted: no nan")
            advertisingNames.add(name)
        }

        override fun startDiscovery() {
            discoveryStarts++
        }

        override fun stop() {
            stopCalls++
        }

        override fun acceptConnection(endpointId: EndpointId) = Unit
        override fun rejectConnection(endpointId: EndpointId) = Unit
        override fun send(endpointId: EndpointId, frame: TransportFrame) = Unit
    }

    private class RecordingTransportListener : TransportListener {
        val events = mutableListOf<TransportEvent>()
        val frames = mutableListOf<Pair<EndpointId, TransportFrame>>()

        override fun onTransportEvent(event: TransportEvent) {
            events.add(event)
        }

        override fun onFrame(endpointId: EndpointId, frame: TransportFrame) {
            frames.add(endpointId to frame)
        }
    }

    @Test
    fun publish_action_routes_to_start_advertising_with_the_extra_name() {
        val transport = RecordingTransport()
        val logs = mutableListOf<String>()
        val controller = AwareServiceController(transport, log = { logs.add(it) })

        val handled = controller.handleAction(ShareNetAwareService.ACTION_START_PUBLISH, "gateway-42")
        assertTrue(handled)
        assertEquals(listOf("gateway-42"), transport.advertisingNames)
        assertTrue(logs.isEmpty())
    }

    @Test
    fun subscribe_and_stop_actions_route_to_the_adapter() {
        val transport = RecordingTransport()
        val controller = AwareServiceController(transport)

        assertTrue(controller.handleAction(ShareNetAwareService.ACTION_START_SUBSCRIBE, "x"))
        assertEquals(1, transport.discoveryStarts)
        assertTrue(controller.handleAction(ShareNetAwareService.ACTION_STOP, "x"))
        assertEquals(1, transport.stopCalls)
    }

    @Test
    fun unknown_and_null_actions_are_ignored_without_touching_the_transport() {
        val transport = RecordingTransport()
        val logs = mutableListOf<String>()
        val controller = AwareServiceController(transport, log = { logs.add(it) })

        assertFalse(controller.handleAction(null, "x"))
        assertFalse(controller.handleAction("org.sharenet.some.other.action", "x"))
        assertTrue(transport.advertisingNames.isEmpty())
        assertEquals(0, transport.discoveryStarts)
        assertEquals(0, transport.stopCalls)
        assertEquals(2, logs.size, "both the null and the unknown action were logged, not crashed")
    }

    @Test
    fun typed_transport_errors_are_contained_not_crashed() {
        val transport = RecordingTransport()
        transport.failAdvertising = true
        val logs = mutableListOf<String>()
        val controller = AwareServiceController(transport, log = { logs.add(it) })

        // The NAN-off device case: the action is recognized, the typed error
        // is logged, and the service would keep living.
        val handled = controller.handleAction(ShareNetAwareService.ACTION_START_PUBLISH, "gateway-42")
        assertTrue(handled, "the action was recognized even though the transport failed")
        assertEquals(1, logs.size)
        assertTrue(logs[0].contains("PlayServicesUnavailable") || logs[0].contains("failed"))

        // Recovery works: the same action succeeds once the platform is back.
        transport.failAdvertising = false
        controller.handleAction(ShareNetAwareService.ACTION_START_PUBLISH, "gateway-42")
        assertEquals(listOf("gateway-42"), transport.advertisingNames)
    }

    @Test
    fun destroy_stops_the_transport_exactly_once() {
        val transport = RecordingTransport()
        val controller = AwareServiceController(transport)
        controller.destroy()
        controller.destroy() // idempotent
        assertEquals(1, transport.stopCalls)
    }

    @Test
    fun actions_after_destroy_are_ignored() {
        val transport = RecordingTransport()
        val logs = mutableListOf<String>()
        val controller = AwareServiceController(transport, log = { logs.add(it) })
        controller.destroy()

        assertFalse(controller.handleAction(ShareNetAwareService.ACTION_START_PUBLISH, "x"))
        assertTrue(transport.advertisingNames.isEmpty(), "no transport calls after destroy")
        assertTrue(logs.any { it.contains("after destroy") })
    }

    @Test
    fun destroy_contains_a_hostile_transport_stop() {
        val hostile = object : NearbyTransport {
            override fun addListener(listener: TransportListener) = Unit
            override fun removeListener(listener: TransportListener) = Unit
            override fun startAdvertising(name: String) = Unit
            override fun startDiscovery() = Unit
            override fun stop() = throw IllegalStateException("hostile stop")
            override fun acceptConnection(endpointId: EndpointId) = Unit
            override fun rejectConnection(endpointId: EndpointId) = Unit
            override fun send(endpointId: EndpointId, frame: TransportFrame) = Unit
        }
        val logs = mutableListOf<String>()
        val controller = AwareServiceController(hostile, log = { logs.add(it) })
        controller.destroy() // must not throw
        assertTrue(logs.any { it.contains("stop failed") })
    }

    @Test
    fun the_full_runtime_path_through_the_controller_and_fake() {
        // The service's runtime path (create → attach → publish/subscribe →
        // datapaths → teardown) exercised end to end through the REAL
        // adapter + controller with the scripted platform.
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingTransportListener()
        adapter.addListener(listener)
        val controller = AwareServiceController(adapter, log = {})
        val logs = mutableListOf<String>()

        // Service onStartCommand sequence.
        controller.handleAction(ShareNetAwareService.ACTION_START_PUBLISH, "gateway-42")
        controller.handleAction(ShareNetAwareService.ACTION_START_SUBSCRIBE, "gateway-42")

        // A peer appears, connects, exchanges one frame.
        fake.platformServiceDiscovered("P1", "node-P1")
        fake.remoteConnectRequest("P1", "node-P1")
        adapter.acceptConnection(EndpointId("P1"))
        adapter.send(EndpointId("P1"), TransportFrame(3, byteArrayOf(1, 2, 3)))
        fake.remoteStreamData("P1", AwareFrameCodec.encode(3, byteArrayOf(1, 2, 3)))

        assertEquals(
            listOf(
                TransportEvent.Discovered(EndpointId("P1"), "node-P1"),
                TransportEvent.ConnectionRequested(EndpointId("P1"), "node-P1", null),
                TransportEvent.Connected(EndpointId("P1")),
            ),
            listener.events,
        )
        assertEquals(1, listener.frames.size)
        assertEquals(1, fake.dataSent.size)

        // Service onDestroy.
        controller.destroy()
        assertEquals(1, fake.stopAllCalls)
        assertTrue(logs.isEmpty())
    }
}
