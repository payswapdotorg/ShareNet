package org.sharenet.transport.aware

import org.sharenet.transport.contract.DisconnectReason
import org.sharenet.transport.contract.EndpointId
import org.sharenet.transport.contract.TransportError
import org.sharenet.transport.contract.TransportEvent
import org.sharenet.transport.contract.TransportFrame
import org.sharenet.transport.contract.TransportListener
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Adapter logic tests (R2-002) — run on the JVM against the scripted
 * [FakeAwareApi] at the android.net.wifi.aware boundary. The adapter,
 * tracker and codec code under test are production code; only the external
 * platform is faked.
 *
 * Adversarial coverage (assignment):
 *  * permissions denied → typed PermissionsDenied, recoverable retry;
 *  * NAN unsupported (attach fails) → typed PlayServicesUnavailable,
 *    clean degradation, no zombie session;
 *  * session lost mid-discovery → typed loss events for every tracked
 *    endpoint (insertion-order determinism), adapter back to idle,
 *    re-attach works;
 *  * publish/subscribe update races → last-write-wins service info, no
 *    missed/dupe endpoint events;
 *  * datapath initiation/accept refused → typed refusal, resources
 *    released;
 *  * stream corruption: short length-prefix, oversized claim, garbage
 *    bytes → typed frame errors, endpoint dropped, NEVER buffered without
 *    bound;
 *  * double-stop / stop-without-start → best-effort no-throw;
 *  * rapid publish/stop cycles converge (the R2-001 storm pattern);
 *  * re-entrant listener calls stop() from inside an event → no deadlock.
 */
class AwareLinksAdapterTest {

    private class RecordingListener : TransportListener {
        val events = mutableListOf<TransportEvent>()
        val frames = mutableListOf<Pair<EndpointId, TransportFrame>>()

        override fun onTransportEvent(event: TransportEvent) {
            events.add(event)
        }

        override fun onFrame(endpointId: EndpointId, frame: TransportFrame) {
            frames.add(endpointId to frame)
        }
    }

    private fun connectedEndpoint(
        fake: FakeAwareApi,
        adapter: AwareLinksAdapter,
        endpointId: String = "P1",
    ): EndpointId {
        // Standard bring-up: subscribe + incoming connection + accept
        // (the fake resolves the datapath synchronously).
        adapter.startDiscovery()
        fake.platformServiceDiscovered(endpointId, "node-$endpointId")
        fake.remoteConnectRequest(endpointId, "node-$endpointId")
        adapter.acceptConnection(EndpointId(endpointId))
        return EndpointId(endpointId)
    }

    private fun u32be(value: Long): ByteArray = byteArrayOf(
        ((value ushr 24) and 0xFF).toByte(),
        ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(),
        (value and 0xFF).toByte(),
    )

    // ------------------------------------------------------------------
    // Happy paths
    // ------------------------------------------------------------------

    @Test
    fun publish_discover_request_accept_delivers_contract_events() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)

        adapter.startAdvertising("gateway-42")
        adapter.startDiscovery()

        fake.platformServiceDiscovered("P1", "node-P1")
        fake.remoteConnectRequest("P1", "node-P1")
        adapter.acceptConnection(EndpointId("P1"))

        assertEquals(
            listOf(
                TransportEvent.Discovered(EndpointId("P1"), "node-P1"),
                TransportEvent.ConnectionRequested(EndpointId("P1"), "node-P1", null),
                TransportEvent.Connected(EndpointId("P1")),
            ),
            listener.events,
        )
        // The facade saw the real calls, with the documented service scope.
        assertEquals(listOf(AwareLinksAdapter.DEFAULT_SERVICE_NAME), fake.publishStarts)
        assertEquals(listOf(AwareLinksAdapter.DEFAULT_SERVICE_NAME), fake.subscribeStarts)
        assertEquals("gateway-42", String(fake.publishServiceInfo!!))
        assertEquals(listOf(EndpointId("P1")), fake.acceptedDatapaths)
    }

    @Test
    fun frame_roundtrips_over_the_datapath_stream() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        val frame = TransportFrame(channelId = 7, payload = byteArrayOf(1, 2, 3, 4))
        adapter.send(ep, frame)

        // The wire form is the frozen length-prefix + envelope convention.
        assertEquals(1, fake.dataSent.size)
        val (sentTo, wire) = fake.dataSent[0]
        assertEquals(ep, sentTo)
        assertEquals(
            AwareFrameCodec.encode(7, byteArrayOf(1, 2, 3, 4)).toList(),
            wire.toList(),
        )

        // The remote side sends the same wire form back → frame delivered.
        fake.remoteStreamData(ep.value, wire)
        assertEquals(1, listener.frames.size)
        assertEquals(ep to frame, listener.frames[0])
    }

    @Test
    fun chunked_stream_delivery_reassembles_frames_exactly_once() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        val wire = AwareFrameCodec.encode(5, ByteArray(64 * 1024) { 3 })
        // Arbitrary chunking (a raw byte stream has no message boundaries).
        for (chunk in wire.asList().chunked(1_000).map { it.toByteArray() }) {
            fake.remoteStreamData(ep.value, chunk)
        }
        assertEquals(1, listener.frames.size)
        assertEquals(ep to TransportFrame(5, ByteArray(64 * 1024) { 3 }), listener.frames[0])
    }

    @Test
    fun multiple_frames_in_one_stream_chunk_are_delivered_in_order() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        val wire = AwareFrameCodec.encode(1, byteArrayOf(0x0A)) +
            AwareFrameCodec.encode(2, byteArrayOf(0x0B, 0x0C))
        fake.remoteStreamData(ep.value, wire)
        assertEquals(
            listOf(
                ep to TransportFrame(1, byteArrayOf(0x0A)),
                ep to TransportFrame(2, byteArrayOf(0x0B, 0x0C)),
            ),
            listener.frames,
        )
    }

    @Test
    fun default_service_name_used_and_is_injectable() {
        val fake = FakeAwareApi()
        AwareLinksAdapter(fake).startAdvertising("x")
        assertEquals(AwareLinksAdapter.DEFAULT_SERVICE_NAME, fake.publishStarts.single())

        val fakeCustom = FakeAwareApi()
        AwareLinksAdapter(fakeCustom, serviceName = "org.sharenet.custom").startDiscovery()
        assertEquals(listOf("org.sharenet.custom"), fakeCustom.subscribeStarts)
    }

    @Test
    fun stop_tears_everything_down_and_is_idempotent() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val ep = connectedEndpoint(fake, adapter)

        adapter.stop()
        adapter.stop() // idempotent

        // stop() delegates to the platform on EVERY call (best-effort,
        // idempotent at the platform level too) — the tracker guards the
        // state, not the platform call count.
        assertEquals(2, fake.stopAllCalls)
        // Restart is legal after a stop.
        adapter.startAdvertising("again")
        assertEquals("again", String(fake.publishServiceInfo!!))
        assertEquals(1, fake.publishStarts.size)
    }

    @Test
    fun stop_without_start_is_best_effort_no_throw() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        adapter.stop() // never started: no throw
        adapter.stop()
        assertEquals(2, fake.stopAllCalls)
    }

    // ------------------------------------------------------------------
    // Adversarial cases (assignment)
    // ------------------------------------------------------------------

    @Test
    fun permission_denial_is_typed_and_retry_after_grant_works() {
        val fake = FakeAwareApi()
        fake.permissionsDenied = true
        val adapter = AwareLinksAdapter(fake)

        assertFailsWith<TransportError.PermissionsDenied> { adapter.startAdvertising("gateway-42") }
        assertFailsWith<TransportError.PermissionsDenied> { adapter.startDiscovery() }

        // Recoverable: granting the permission makes a retry legal (tracker
        // rolled back, nothing zombie).
        fake.permissionsDenied = false
        adapter.startAdvertising("gateway-42")
        assertEquals(1, fake.publishStarts.size)
        adapter.startDiscovery()
        assertEquals(1, fake.subscribeStarts.size)
    }

    @Test
    fun nan_unsupported_attach_failure_is_typed_and_degrades_cleanly() {
        val fake = FakeAwareApi()
        fake.awareUnavailable = true
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)

        val error = assertFailsWith<TransportError.PlayServicesUnavailable> {
            adapter.startAdvertising("gateway-42")
        }
        assertTrue(error.detail.contains("scripted"))

        // Clean degradation: no crash, no zombie session, no events.
        assertFalse(fake.attached, "no zombie aware session")
        assertTrue(fake.publishStarts.isEmpty(), "no zombie publish")
        assertEquals(0, listener.events.size)

        // The platform coming back makes everything retryable.
        fake.awareUnavailable = false
        adapter.startDiscovery()
        assertEquals(1, fake.subscribeStarts.size)
    }

    @Test
    fun double_startAdvertising_is_typed_illegal_state() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        adapter.startAdvertising("one")
        val e = assertFailsWith<TransportError.IllegalState> { adapter.startAdvertising("two") }
        assertTrue(e.message!!.contains("already advertising"))
        // The second call did NOT reach the platform.
        assertEquals(1, fake.publishStarts.size)
    }

    @Test
    fun connection_request_arriving_during_stop_is_dropped_without_panic() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)

        adapter.startDiscovery()
        adapter.stop()
        // The platform delivers a late connection request after stop().
        fake.remoteConnectRequest("P1", "node-P1")
        // No event, no crash, and the endpoint is NOT registered.
        assertEquals(0, listener.events.size)
        assertFailsWith<TransportError.IllegalState> { adapter.acceptConnection(EndpointId("P1")) }
    }

    @Test
    fun session_lost_mid_discovery_emits_loss_events_in_insertion_order_and_returns_to_idle() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)

        adapter.startDiscovery()
        // Three endpoints in insertion order: one merely discovered, one
        // pending, one connected.
        fake.platformServiceDiscovered("PA", "node-PA")
        fake.platformServiceDiscovered("PB", "node-PB")
        fake.remoteConnectRequest("PB", "node-PB")
        fake.remoteConnectRequest("PC", "node-PC")
        adapter.acceptConnection(EndpointId("PC"))

        fake.platformSessionLost()

        // Typed loss events for every tracked endpoint: PB (pending) and PC
        // (connected) get ERROR (the transport failed underneath), in
        // tracker insertion order; PA (merely discovered) gets PEER.
        val losses = listener.events.filterIsInstance<TransportEvent.Disconnected>()
        assertEquals(3, losses.size, "every tracked + discovered endpoint got a loss event")
        assertEquals(
            listOf(
                TransportEvent.Disconnected(EndpointId("PB"), DisconnectReason.ERROR),
                TransportEvent.Disconnected(EndpointId("PC"), DisconnectReason.ERROR),
                TransportEvent.Disconnected(EndpointId("PA"), DisconnectReason.PEER),
            ),
            losses,
            "insertion-order determinism (ConnectionTracker law)",
        )

        // The adapter is back to idle: a fresh start re-attaches.
        adapter.startDiscovery()
        assertEquals(2, fake.attachCalls, "the re-attach after session loss happened")
        assertEquals(2, fake.subscribeStarts.size)
        // And the re-attached session works end to end.
        fake.platformServiceDiscovered("PD", "node-PD")
        assertEquals(
            TransportEvent.Discovered(EndpointId("PD"), "node-PD"),
            listener.events.last(),
        )
    }

    @Test
    fun session_lost_with_connected_endpoint_is_typed_error_teardown() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        fake.platformSessionLost()

        assertEquals(
            TransportEvent.Disconnected(ep, DisconnectReason.ERROR),
            listener.events.last(),
        )
        // Sending on the torn-down endpoint is a typed IllegalState.
        assertFailsWith<TransportError.IllegalState> {
            adapter.send(ep, TransportFrame(channelId = 1, payload = byteArrayOf(1)))
        }
    }

    @Test
    fun publish_update_races_last_write_wins_and_discovery_never_dupes_or_misses() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)

        adapter.startAdvertising("gateway-42")
        adapter.startDiscovery()

        // Facade-level update races converge last-write-wins (the fake is
        // the platform): the advertised state is the most recent write.
        fake.updatePublish("gateway-43".encodeToByteArray())
        fake.updatePublish("gateway-44".encodeToByteArray())
        assertEquals("gateway-44", String(fake.publishServiceInfo!!))
        assertEquals(2, fake.publishUpdates.size)

        // Adapter-level discovery determinism: no missed/dupe events.
        fake.platformServiceDiscovered("P1", "node-P1")
        fake.platformServiceDiscovered("P1", "node-P1") // re-delivery while visible
        assertEquals(1, listener.events.count { it is TransportEvent.Discovered })
        fake.platformServiceLost("P1")
        fake.platformServiceDiscovered("P1", "node-P1") // a genuine lost+found cycle
        fake.platformServiceLost("P1")
        assertEquals(
            2,
            listener.events.count { it is TransportEvent.Discovered },
            "the lost+found cycle re-delivered exactly once more",
        )
        assertEquals(
            2,
            listener.events.count {
                it is TransportEvent.Disconnected && it.endpointId == EndpointId("P1")
            },
            "each lost dispatched exactly one loss event",
        )
    }

    @Test
    fun datapath_refusal_on_accept_is_typed_and_releases_resources() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)

        adapter.startDiscovery()
        fake.platformServiceDiscovered("P1", "node-P1")
        fake.remoteConnectRequest("P1", "node-P1")
        fake.failDatapathRequests = true

        val error = assertFailsWith<TransportError.ConnectionRejected> {
            adapter.acceptConnection(EndpointId("P1"))
        }
        assertEquals(EndpointId("P1"), error.endpointId)

        // Resources released at the platform: no zombie request/datapath.
        assertTrue(EndpointId("P1") in fake.releasedDatapaths)
        assertFalse(EndpointId("P1") in fake.datapaths)
        // The adapter rolled back: no Connected event, and a RETRY from the
        // same endpoint re-registers cleanly.
        assertEquals(0, listener.events.count { it is TransportEvent.Connected })
        fake.failDatapathRequests = false
        fake.remoteConnectRequest("P1", "node-P1")
        adapter.acceptConnection(EndpointId("P1"))
        assertEquals(1, listener.events.count { it is TransportEvent.Connected })
    }

    @Test
    fun stream_corruption_oversized_claim_drops_endpoint_with_typed_error() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        // A prefix claiming 3 MiB (> the frozen 2 MiB law) followed by a
        // plausible body: rejected BEFORE buffering, endpoint dropped.
        val hostile = u32be(3 * 1024 * 1024) + ByteArray(64)
        fake.remoteStreamData(ep.value, hostile)

        assertEquals(0, listener.frames.size, "no frame from a corrupted stream")
        assertEquals(
            TransportEvent.Disconnected(ep, DisconnectReason.ERROR),
            listener.events.last(),
        )
        assertEquals(1, adapter.streamCorruptionErrors, "the typed frame error is counted")
        // The endpoint is gone: sending is now a typed IllegalState.
        assertFailsWith<TransportError.IllegalState> {
            adapter.send(ep, TransportFrame(channelId = 1, payload = byteArrayOf(1)))
        }
    }

    @Test
    fun stream_corruption_garbage_channel_envelope_drops_endpoint() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        // frameLength=8 (envelope only) with the channelId high bit set:
        // garbage that parses as a legal length.
        fake.remoteStreamData(ep.value, u32be(8) + byteArrayOf(0xFF.toByte()) + ByteArray(7))
        assertEquals(0, listener.frames.size)
        assertEquals(TransportEvent.Disconnected(ep, DisconnectReason.ERROR), listener.events.last())
        assertEquals(1, adapter.streamCorruptionErrors)
    }

    @Test
    fun stream_end_mid_frame_after_disconnect_emits_no_partial_frame() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        // Half a frame arrives, then the endpoint's datapath goes down.
        val wire = AwareFrameCodec.encode(5, ByteArray(1024) { 3 })
        fake.remoteStreamData(ep.value, wire.copyOfRange(0, wire.size / 2))
        fake.remoteDisconnect(ep.value)

        // No partial frame, a Disconnected event instead.
        assertEquals(0, listener.frames.size)
        assertEquals(TransportEvent.Disconnected(ep, DisconnectReason.PEER), listener.events.last())

        // The endpoint reconnects and a FULL frame works: decode state was
        // cleaned, so stale partial bytes cannot corrupt the new stream.
        fake.remoteConnectRequest(ep.value, "node-${ep.value}")
        adapter.acceptConnection(ep)
        fake.remoteStreamData(ep.value, AwareFrameCodec.encode(6, ByteArray(512) { 9 }))
        assertEquals(1, listener.frames.size)
        assertEquals(ep to TransportFrame(6, ByteArray(512) { 9 }), listener.frames[0])
    }

    @Test
    fun stream_send_failure_is_typed_io_failure_and_endpoint_stays_usable() {
        val fake = FakeAwareApi()
        fake.failSends = true
        val adapter = AwareLinksAdapter(fake)
        val ep = connectedEndpoint(fake, adapter)

        assertFailsWith<TransportError.IoFailure> {
            adapter.send(ep, TransportFrame(channelId = 1, payload = byteArrayOf(1)))
        }
        // The write failed but the endpoint itself remains usable.
        fake.failSends = false
        adapter.send(ep, TransportFrame(channelId = 1, payload = byteArrayOf(5)))
        assertEquals(1, fake.dataSent.size)
    }

    @Test
    fun oversized_send_is_typed_io_failure_from_the_frame_law() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val ep = connectedEndpoint(fake, adapter)

        // A frame whose body exceeds the frozen 2 MiB bound: rejected on
        // SEND with the typed FrameTooLarge cause (the bound applies on
        // both sides).
        val tooBig = TransportFrame(
            channelId = 1,
            payload = ByteArray(AwareFrameCodec.MAX_FRAME_BYTES - AwareFrameCodec.ENVELOPE_HEADER_BYTES + 1),
        )
        val error = assertFailsWith<TransportError.IoFailure> { adapter.send(ep, tooBig) }
        assertIs<FrameTooLargeException>(error.cause)
        assertTrue(fake.dataSent.isEmpty(), "nothing reached the stream")
    }

    @Test
    fun advertised_name_over_the_service_info_bound_is_typed() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val tooLong = "x".repeat(AwareLinksAdapter.MAX_SERVICE_INFO_BYTES + 1)
        val e = assertFailsWith<TransportError.IllegalState> { adapter.startAdvertising(tooLong) }
        assertTrue(e.message!!.contains("service-info bound"))
        assertTrue(fake.publishStarts.isEmpty(), "the platform was never called")
    }

    @Test
    fun service_lost_surfaces_disconnected_event() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)

        adapter.startDiscovery()
        fake.platformServiceDiscovered("P1", "node-P1")
        fake.platformServiceLost("P1")
        assertEquals(
            listOf(
                TransportEvent.Discovered(EndpointId("P1"), "node-P1"),
                TransportEvent.Disconnected(EndpointId("P1"), DisconnectReason.PEER),
            ),
            listener.events,
        )
    }

    @Test
    fun service_lost_for_connected_endpoint_clears_state() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        fake.platformServiceLost(ep.value)
        assertEquals(TransportEvent.Disconnected(ep, DisconnectReason.PEER), listener.events.last())
        // Sending to the lost endpoint is now a typed IllegalState.
        assertFailsWith<TransportError.IllegalState> {
            adapter.send(ep, TransportFrame(channelId = 1, payload = byteArrayOf(1)))
        }
    }

    @Test
    fun remote_request_failure_surfaces_disconnected_with_rejected_reason() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        adapter.startDiscovery()
        fake.platformServiceDiscovered("P1", "node-P1")
        fake.remoteConnectRequest("P1", "node-P1")
        // The remote initiator vanished before we accepted.
        fake.platformRequestFailed("P1")
        assertEquals(
            TransportEvent.Disconnected(EndpointId("P1"), DisconnectReason.REJECTED),
            listener.events.last(),
        )
    }

    @Test
    fun local_rejection_tears_down_the_pending_request_cleanly() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        adapter.startDiscovery()
        fake.platformServiceDiscovered("P1", "node-P1")
        fake.remoteConnectRequest("P1", "node-P1")

        adapter.rejectConnection(EndpointId("P1"))

        // No Disconnected event for a LOCAL rejection (the R2-001 law: no
        // event when the local side acts) — but the platform saw the reject
        // and the pending request was released.
        assertEquals(0, listener.events.count { it is TransportEvent.Disconnected })
        assertEquals(listOf(EndpointId("P1")), fake.rejectedDatapaths)
        assertTrue(EndpointId("P1") in fake.releasedDatapaths)
        assertFalse(EndpointId("P1") in fake.pendingRequests)
        // And a later request from the same endpoint registers again.
        fake.remoteConnectRequest("P1", "node-P1")
        adapter.acceptConnection(EndpointId("P1"))
        assertEquals(1, listener.events.count { it is TransportEvent.Connected })
    }

    @Test
    fun rapid_publish_stop_cycles_converge() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        repeat(50) { i ->
            adapter.startAdvertising("node-$i")
            adapter.stop()
        }
        // After the storm: one final start works, the platform saw all 51.
        adapter.startAdvertising("final")
        assertEquals(51, fake.publishStarts.size)
        adapter.stop()
        // Interleaved variant: publish + subscribe churn together.
        repeat(50) {
            adapter.startDiscovery()
            adapter.startAdvertising("dual")
            adapter.stop()
        }
        adapter.startAdvertising("done")
        // 50 (loop) + 1 ("final") + 50 ("dual") + 1 ("done") = 102.
        assertEquals(102, fake.publishStarts.size)
        assertEquals(50, fake.subscribeStarts.size)
    }

    @Test
    fun send_to_unconnected_endpoint_is_typed_illegal_state() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        // Never connected.
        assertFailsWith<TransportError.IllegalState> {
            adapter.send(EndpointId("P42"), TransportFrame(channelId = 1, payload = byteArrayOf(1)))
        }
        // Pending but not accepted: also illegal.
        adapter.startDiscovery()
        fake.remoteConnectRequest("P1", "node-P1")
        assertFailsWith<TransportError.IllegalState> {
            adapter.send(EndpointId("P1"), TransportFrame(channelId = 1, payload = byteArrayOf(1)))
        }
    }

    @Test
    fun late_stream_data_after_disconnect_is_dropped() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)
        fake.remoteDisconnect(ep.value)
        // The platform delivers a late stream chunk for the dead endpoint.
        fake.remoteStreamData(ep.value, AwareFrameCodec.encode(1, byteArrayOf(1)))
        assertEquals(0, listener.frames.size)
    }

    @Test
    fun accept_without_pending_request_is_typed_illegal_state() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val e = assertFailsWith<TransportError.IllegalState> { adapter.acceptConnection(EndpointId("P1")) }
        assertTrue(e.message!!.contains("no pending connection request"))
        // And the platform was not called.
        assertTrue(fake.acceptedDatapaths.isEmpty())
    }

    @Test
    fun reject_after_acceptance_is_typed_illegal_state() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val ep = connectedEndpoint(fake, adapter)
        assertFailsWith<TransportError.IllegalState> { adapter.rejectConnection(ep) }
    }

    @Test
    fun duplicate_connection_request_is_dropped_not_crashed() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        adapter.startDiscovery()
        fake.remoteConnectRequest("P1", "node-P1")
        // The platform re-delivers the same request (e.g. retry).
        fake.remoteConnectRequest("P1", "node-P1")
        // Exactly ONE ConnectionRequested event surfaced.
        assertEquals(1, listener.events.count { it is TransportEvent.ConnectionRequested })
    }

    @Test
    fun unknown_service_lost_is_dropped_not_surfaced_as_a_phantom_event() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        adapter.startDiscovery()
        // A serviceLost for a peer we never saw: the aware bookkeeping is
        // authoritative — deterministic, no phantom events.
        fake.platformServiceLost("GHOST")
        assertEquals(0, listener.events.size)
    }

    @Test
    fun listener_registration_is_idempotent() {
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        adapter.addListener(listener)
        adapter.startDiscovery()
        fake.platformServiceDiscovered("P1", "x")
        assertEquals(1, listener.events.size)
        adapter.removeListener(listener)
        adapter.removeListener(listener)
        fake.platformServiceDiscovered("P2", "y")
        assertEquals(1, listener.events.size)
    }

    @Test
    fun events_and_frames_are_only_dispatched_outside_internal_locks() {
        // A listener that synchronously calls stop() from inside an event
        // must not deadlock — proves dispatch happens without the adapter
        // lock, INCLUDING during the synchronous accept flow.
        val fake = FakeAwareApi()
        val adapter = AwareLinksAdapter(fake)
        adapter.addListener(object : TransportListener {
            override fun onTransportEvent(event: TransportEvent) {
                if (event is TransportEvent.Connected) {
                    adapter.stop() // re-entrant call from a callback
                }
            }

            override fun onFrame(endpointId: EndpointId, frame: TransportFrame) = Unit
        })
        adapter.startDiscovery()
        fake.remoteConnectRequest("P1", "node-P1")
        adapter.acceptConnection(EndpointId("P1")) // the fake fires Connected inside this call
        assertEquals(1, fake.stopAllCalls)
    }
}
