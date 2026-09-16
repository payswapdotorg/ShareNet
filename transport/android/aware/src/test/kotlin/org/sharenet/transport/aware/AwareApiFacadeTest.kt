package org.sharenet.transport.aware

import org.sharenet.transport.contract.EndpointId
import org.sharenet.transport.contract.TransportError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Facade contract tests (R2-002) — the [AwareApi] surface driven directly
 * through the scripted [FakeAwareApi]: the session lifecycle (attach/
 * detach/re-attach), publish/subscribe with last-write-wins updates, the
 * initiator datapath role (R3-001's future surface), typed refusals with
 * observable resource release, and the best-effort never-throw stop laws.
 *
 * The fake IS the platform boundary here: everything asserted is the facade
 * contract the adapter (and the future authenticated-links layer) relies on.
 */
class AwareApiFacadeTest {

    private class RecordingListener : AwareApiListener {
        val sessionLost = mutableListOf<Unit>()
        val discovered = mutableListOf<Pair<EndpointId, String>>()
        val lost = mutableListOf<EndpointId>()
        val requested = mutableListOf<Pair<EndpointId, String>>()
        val accepted = mutableListOf<EndpointId>()
        val rejected = mutableListOf<EndpointId>()
        val disconnected = mutableListOf<EndpointId>()
        val streamData = mutableListOf<Pair<EndpointId, ByteArray>>()

        override fun onSessionLost() {
            sessionLost.add(Unit)
        }

        override fun onServiceDiscovered(endpointId: EndpointId, name: String) {
            discovered.add(endpointId to name)
        }

        override fun onServiceLost(endpointId: EndpointId) {
            lost.add(endpointId)
        }

        override fun onConnectionRequested(endpointId: EndpointId, name: String) {
            requested.add(endpointId to name)
        }

        override fun onConnectionAccepted(endpointId: EndpointId) {
            accepted.add(endpointId)
        }

        override fun onConnectionRejected(endpointId: EndpointId) {
            rejected.add(endpointId)
        }

        override fun onDisconnected(endpointId: EndpointId) {
            disconnected.add(endpointId)
        }

        override fun onStreamData(endpointId: EndpointId, chunk: ByteArray) {
            streamData.add(endpointId to chunk.copyOf())
        }
    }

    // ------------------------------------------------------------------
    // Session lifecycle
    // ------------------------------------------------------------------

    @Test
    fun attach_is_idempotent_and_re_attachable() {
        val fake = FakeAwareApi()
        val listener = RecordingListener()
        fake.attach(listener)
        fake.attach(listener) // the second start* shares the attach
        assertTrue(fake.attached)
        assertEquals(1, fake.attachCalls)
        fake.detach()
        assertFalse(fake.attached)
        assertEquals(1, fake.detachCalls)
        fake.attach(listener)
        assertEquals(2, fake.attachCalls, "re-attach after detach works")
    }

    @Test
    fun aware_unaware_device_attach_fails_typed_with_no_zombie_session() {
        val fake = FakeAwareApi()
        fake.awareUnavailable = true
        assertFailsWith<TransportError.PlayServicesUnavailable> { fake.attach(RecordingListener()) }
        assertFalse(fake.attached, "no zombie session: the failed attach attached nothing")
        // Recoverable: the platform coming back makes attach legal again.
        fake.awareUnavailable = false
        fake.attach(RecordingListener())
        assertTrue(fake.attached)
    }

    @Test
    fun permission_denial_is_typed_at_attach() {
        val fake = FakeAwareApi()
        fake.permissionsDenied = true
        val error = assertFailsWith<TransportError.PermissionsDenied> { fake.attach(RecordingListener()) }
        assertTrue(error.message!!.contains("scripted"))
        assertFalse(fake.attached)
    }

    // ------------------------------------------------------------------
    // Publish / subscribe + last-write-wins updates
    // ------------------------------------------------------------------

    @Test
    fun publish_requires_attach_and_records_service_scope() {
        val fake = FakeAwareApi()
        assertFailsWith<TransportError.IllegalState> {
            fake.startPublish("org.sharenet.transport.aware", "gateway".encodeToByteArray())
        }
        fake.attach(RecordingListener())
        fake.startPublish("org.sharenet.transport.aware", "gateway".encodeToByteArray())
        assertTrue(fake.publishActive)
        assertEquals("org.sharenet.transport.aware", fake.publishServiceName)
        assertEquals("gateway", String(fake.publishServiceInfo!!))
    }

    @Test
    fun update_publish_is_last_write_wins_under_races() {
        val fake = FakeAwareApi()
        fake.attach(RecordingListener())
        fake.startPublish("svc", "A".encodeToByteArray())
        // Racing updates (no synchronization between them): the final state
        // converges on the LAST write — by design.
        fake.updatePublish("B".encodeToByteArray())
        fake.updatePublish("C".encodeToByteArray())
        assertEquals("C", String(fake.publishServiceInfo!!), "last write wins")
        assertEquals(2, fake.publishUpdates.size, "every update is recorded in call order")
        assertEquals("B", String(fake.publishUpdates[0]))
        assertEquals("C", String(fake.publishUpdates[1]))
    }

    @Test
    fun update_publish_without_active_publish_is_typed() {
        val fake = FakeAwareApi()
        fake.attach(RecordingListener())
        assertFailsWith<TransportError.IllegalState> { fake.updatePublish("x".encodeToByteArray()) }
    }

    @Test
    fun subscribe_requires_attach_and_records_service_scope() {
        val fake = FakeAwareApi()
        assertFailsWith<TransportError.IllegalState> { fake.startSubscribe("svc") }
        fake.attach(RecordingListener())
        fake.startSubscribe("svc")
        assertTrue(fake.subscribeActive)
        assertEquals("svc", fake.subscribeServiceName)
    }

    @Test
    fun stop_publish_and_stop_subscribe_never_throw_without_start() {
        val fake = FakeAwareApi()
        fake.stopPublish() // best-effort law
        fake.stopSubscribe()
        assertEquals(1, fake.stopPublishCalls)
        assertEquals(1, fake.stopSubscribeCalls)
    }

    // ------------------------------------------------------------------
    // Datapaths: initiator role (the R3-001 outbound surface)
    // ------------------------------------------------------------------

    @Test
    fun initiate_datapath_unknown_endpoint_is_typed() {
        val fake = FakeAwareApi()
        fake.attach(RecordingListener())
        assertFailsWith<TransportError.IllegalState> { fake.initiateDatapath(EndpointId("ghost")) }
        assertTrue(fake.initiatedDatapaths.isEmpty())
    }

    @Test
    fun initiate_datapath_to_discovered_endpoint_establishes_and_notifies() {
        val fake = FakeAwareApi()
        val listener = RecordingListener()
        fake.attach(listener)
        fake.startSubscribe("svc")
        fake.platformServiceDiscovered("P1", "node-1")
        fake.initiateDatapath(EndpointId("P1"))
        assertEquals(listOf(EndpointId("P1")), fake.initiatedDatapaths)
        assertTrue(EndpointId("P1") in fake.datapaths)
        assertEquals(listOf(EndpointId("P1")), listener.accepted, "the blocking call resolved with the datapath up")
        // The established stream carries data in both directions.
        fake.sendData(EndpointId("P1"), byteArrayOf(1, 2))
        assertEquals(1, fake.dataSent.size)
    }

    @Test
    fun refused_datapath_initiation_is_typed_and_releases_resources() {
        val fake = FakeAwareApi()
        fake.attach(RecordingListener())
        fake.startSubscribe("svc")
        fake.platformServiceDiscovered("P1", "node-1")
        fake.failDatapathRequests = true
        val error = assertFailsWith<TransportError.ConnectionRejected> {
            fake.initiateDatapath(EndpointId("P1"))
        }
        assertTrue(error.message!!.contains("P1"))
        // Resources released — no zombie request against the platform.
        assertTrue(EndpointId("P1") in fake.releasedDatapaths, "refused initiation released its resources")
        assertFalse(EndpointId("P1") in fake.datapaths)
    }

    // ------------------------------------------------------------------
    // Datapaths: responder role (the adapter's inbound path)
    // ------------------------------------------------------------------

    @Test
    fun accept_datapath_without_pending_request_is_typed() {
        val fake = FakeAwareApi()
        fake.attach(RecordingListener())
        assertFailsWith<TransportError.IllegalState> { fake.acceptDatapath(EndpointId("P1")) }
        assertTrue(fake.acceptedDatapaths.isEmpty())
    }

    @Test
    fun accept_datapath_establishes_and_releases_pending_request() {
        val fake = FakeAwareApi()
        val listener = RecordingListener()
        fake.attach(listener)
        fake.remoteConnectRequest("P1", "node-1")
        fake.acceptDatapath(EndpointId("P1"))
        assertEquals(listOf(EndpointId("P1")), fake.acceptedDatapaths)
        assertTrue(EndpointId("P1") in fake.datapaths)
        assertFalse(EndpointId("P1") in fake.pendingRequests, "the pending request was consumed")
        assertEquals(listOf(EndpointId("P1")), listener.accepted)
    }

    @Test
    fun failed_accept_datapath_is_typed_and_releases_resources() {
        val fake = FakeAwareApi()
        fake.attach(RecordingListener())
        fake.remoteConnectRequest("P1", "node-1")
        fake.failDatapathRequests = true
        assertFailsWith<TransportError.ConnectionRejected> { fake.acceptDatapath(EndpointId("P1")) }
        assertTrue(EndpointId("P1") in fake.releasedDatapaths)
        assertFalse(EndpointId("P1") in fake.pendingRequests, "no zombie pending request")
        assertFalse(EndpointId("P1") in fake.datapaths)
    }

    @Test
    fun reject_datapath_records_and_releases() {
        val fake = FakeAwareApi()
        fake.attach(RecordingListener())
        fake.remoteConnectRequest("P1", "node-1")
        fake.rejectDatapath(EndpointId("P1"))
        assertEquals(listOf(EndpointId("P1")), fake.rejectedDatapaths)
        assertTrue(EndpointId("P1") in fake.releasedDatapaths)
        assertFalse(EndpointId("P1") in fake.pendingRequests)
    }

    @Test
    fun reject_datapath_without_pending_request_is_typed() {
        val fake = FakeAwareApi()
        fake.attach(RecordingListener())
        assertFailsWith<TransportError.IllegalState> { fake.rejectDatapath(EndpointId("P1")) }
    }

    // ------------------------------------------------------------------
    // Stream I/O + stopAll
    // ------------------------------------------------------------------

    @Test
    fun send_data_without_datapath_is_typed_and_failures_are_typed() {
        val fake = FakeAwareApi()
        fake.attach(RecordingListener())
        assertFailsWith<TransportError.IllegalState> { fake.sendData(EndpointId("P1"), byteArrayOf(1)) }
        fake.remoteConnectRequest("P1", "n")
        fake.acceptDatapath(EndpointId("P1"))
        fake.failSends = true
        assertFailsWith<TransportError.IoFailure> { fake.sendData(EndpointId("P1"), byteArrayOf(1)) }
        fake.failSends = false
        fake.sendData(EndpointId("P1"), byteArrayOf(9))
        assertEquals(1, fake.dataSent.size)
    }

    @Test
    fun stop_all_is_best_effort_idempotent_and_releases_everything() {
        val fake = FakeAwareApi()
        val listener = RecordingListener()
        fake.attach(listener)
        fake.startPublish("svc", "A".encodeToByteArray())
        fake.startSubscribe("svc")
        fake.remoteConnectRequest("P1", "node-1")
        fake.acceptDatapath(EndpointId("P1"))
        fake.stopAll()
        fake.stopAll() // idempotent, never throws
        assertEquals(2, fake.stopAllCalls)
        assertFalse(fake.attached)
        assertFalse(fake.publishActive)
        assertFalse(fake.subscribeActive)
        assertTrue(fake.datapaths.isEmpty())
        assertTrue(EndpointId("P1") in fake.releasedDatapaths, "teardown released the established datapath")
        // A full re-start from nothing is legal afterwards.
        fake.attach(RecordingListener())
        fake.startPublish("svc", "B".encodeToByteArray())
        assertTrue(fake.publishActive)
    }

    @Test
    fun platform_session_lost_clears_platform_state_and_notifies() {
        val fake = FakeAwareApi()
        val listener = RecordingListener()
        fake.attach(listener)
        fake.startPublish("svc", "A".encodeToByteArray())
        fake.startSubscribe("svc")
        fake.platformServiceDiscovered("P1", "node-1")
        fake.remoteConnectRequest("P2", "node-2")
        fake.platformSessionLost()
        assertEquals(1, listener.sessionLost.size)
        assertFalse(fake.attached)
        assertFalse(fake.publishActive)
        assertFalse(fake.subscribeActive)
        assertTrue(fake.discoveredPeers.isEmpty())
        assertTrue(fake.pendingRequests.isEmpty())
        assertTrue(fake.datapaths.isEmpty())
    }
}
