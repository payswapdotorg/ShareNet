package org.sharenet.transport.nearby

import org.sharenet.transport.contract.DisconnectReason
import org.sharenet.transport.contract.EndpointId
import org.sharenet.transport.contract.TransportError
import org.sharenet.transport.contract.TransportEvent
import org.sharenet.transport.contract.TransportFrame
import org.sharenet.transport.contract.TransportListener
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Adapter logic tests (R2-001) — run on the JVM against the scripted
 * [FakeNearbyApi] at the GMS boundary. The adapter, tracker and policy code
 * under test are production code; only the external platform is faked.
 *
 * Adversarial coverage (assignment §5):
 *  * play services unavailable → typed PlayServicesUnavailable, no crash;
 *  * permission denial → typed PermissionsDenied;
 *  * double startAdvertising → typed IllegalState;
 *  * connection request during stop() → dropped event, no panic;
 *  * disconnect mid-STREAM → cleanup, no partial frame;
 *  * oversized BYTES payload → documented STREAM routing;
 *  * endpoint lost → Disconnected event;
 *  * rapid advertise/stop cycles → state converges;
 *  * malformed envelope → dropped and counted.
 */
class NearbyConnectionsAdapterTest {

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
        fake: FakeNearbyApi,
        adapter: NearbyConnectionsAdapter,
        endpointId: String = "EP1",
    ): EndpointId {
        // Standard bring-up: discovery + incoming connection + accept.
        adapter.startDiscovery()
        fake.remoteEndpointFound(endpointId, "phone-$endpointId")
        fake.remoteConnectionInitiated(endpointId, "phone-$endpointId", token = "tok-123")
        adapter.acceptConnection(EndpointId(endpointId))
        fake.remoteConnectionAccepted(endpointId)
        return EndpointId(endpointId)
    }

    // ------------------------------------------------------------------
    // Happy paths
    // ------------------------------------------------------------------

    @Test
    fun advertise_discover_request_accept_delivers_contract_events() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)

        adapter.startAdvertising("gateway-42")
        adapter.startDiscovery()

        fake.remoteEndpointFound("EP1", "phone-EP1")
        fake.remoteConnectionInitiated("EP1", "phone-EP1", "tok-123")
        adapter.acceptConnection(EndpointId("EP1"))
        fake.remoteConnectionAccepted("EP1")

        assertEquals(
            listOf(
                TransportEvent.Discovered(EndpointId("EP1"), "phone-EP1"),
                TransportEvent.ConnectionRequested(EndpointId("EP1"), "phone-EP1", "tok-123"),
                TransportEvent.Connected(EndpointId("EP1")),
            ),
            listener.events,
        )
        // The facade saw the real calls.
        assertEquals(listOf("gateway-42"), fake.advertisingStarts)
        assertEquals(1, fake.discoveryStarts.size)
        assertEquals(listOf(EndpointId("EP1")), fake.accepted)
    }

    @Test
    fun small_frame_roundtrips_over_bytes() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        val frame = TransportFrame(channelId = 7, payload = byteArrayOf(1, 2, 3, 4))
        adapter.send(ep, frame)

        // BYTES route used, with the documented envelope on the wire.
        assertEquals(1, fake.bytesSent.size)
        val (sentTo, wire) = fake.bytesSent[0]
        assertEquals(ep, sentTo)
        assertEquals(PayloadPolicy.encodeEnvelope(7, byteArrayOf(1, 2, 3, 4)).toList(), wire.toList())

        // Remote side sends the same envelope back → frame delivered.
        fake.remoteBytes(ep.value, wire)
        assertEquals(1, listener.frames.size)
        assertEquals(ep to frame, listener.frames[0])
    }

    @Test
    fun oversized_frame_routes_onto_stream_and_reassembles() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        // Payload over the BYTES cap → STREAM route (documented policy).
        val bigPayload = ByteArray(PayloadPolicy.MAX_BYTES_PAYLOAD_BYTES + 1) { (it % 251).toByte() }
        val frame = TransportFrame(channelId = 9, payload = bigPayload)
        adapter.send(ep, frame)
        assertEquals(0, fake.bytesSent.size, "oversized frame must NOT use BYTES")
        assertEquals(1, fake.streamsSent.size)
        val (_, wire) = fake.streamsSent[0]
        assertEquals(PayloadPolicy.encodeEnvelope(9, bigPayload).toList(), wire.toList())

        // Remote delivers the stream in chunks; the frame reassembles exactly once.
        val payloadId = fake.newPayloadId()
        for (chunk in PayloadPolicy.chunkForStream(wire)) {
            fake.remoteStreamChunk(ep.value, payloadId, chunk)
        }
        // No frame before completion.
        assertEquals(0, listener.frames.size)
        fake.remoteStreamCompleted(ep.value, payloadId)
        assertEquals(1, listener.frames.size)
        assertEquals(ep to frame, listener.frames[0])
    }

    @Test
    fun boundary_payload_exactly_at_bytes_cap_uses_bytes() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val ep = connectedEndpoint(fake, adapter)

        adapter.send(ep, TransportFrame(channelId = 1, payload = ByteArray(PayloadPolicy.MAX_BYTES_PAYLOAD_BYTES)))
        assertEquals(1, fake.bytesSent.size)
        assertEquals(0, fake.streamsSent.size)
    }

    @Test
    fun default_strategy_is_p2p_cluster_and_is_injectable() {
        val fake = FakeNearbyApi()
        NearbyConnectionsAdapter(fake).startAdvertising("x")
        assertEquals(NearbyStrategyKind.P2P_CLUSTER, fake.lastStrategy)

        val fakePointToPoint = FakeNearbyApi()
        NearbyConnectionsAdapter(fakePointToPoint, NearbyStrategyKind.P2P_POINT_TO_POINT).startAdvertising("x")
        assertEquals(NearbyStrategyKind.P2P_POINT_TO_POINT, fakePointToPoint.lastStrategy)
    }

    @Test
    fun stop_tears_everything_down_and_is_idempotent() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val ep = connectedEndpoint(fake, adapter)

        adapter.stop()
        adapter.stop() // idempotent

        // stop() delegates to the platform on EVERY call (best-effort,
        // idempotent at the platform level too) — the tracker guards the
        // state, not the platform call count.
        assertEquals(2, fake.stopAllCalls)
        // Restart is legal after a stop.
        adapter.startAdvertising("again")
        assertEquals(listOf("again"), fake.advertisingStarts)
    }

    // ------------------------------------------------------------------
    // Adversarial cases (assignment §5)
    // ------------------------------------------------------------------

    @Test
    fun play_services_unavailable_is_typed_and_recoverable() {
        val fake = FakeNearbyApi()
        fake.playServicesUnavailable = true
        val adapter = NearbyConnectionsAdapter(fake)

        val error = assertFailsWith<TransportError.PlayServicesUnavailable> {
            adapter.startAdvertising("gateway-42")
        }
        assertTrue(error.detail.contains("scripted"))

        // No crash — and the failure is recoverable: unblocking the platform
        // makes a retry legal (tracker rolled back).
        fake.playServicesUnavailable = false
        adapter.startAdvertising("gateway-42")
        assertEquals(listOf("gateway-42"), fake.advertisingStarts)

        // Discovery hits the same typed error while the script is active.
        fake.playServicesUnavailable = true
        assertFailsWith<TransportError.PlayServicesUnavailable> { adapter.startDiscovery() }
    }

    @Test
    fun permission_denial_is_typed() {
        val fake = FakeNearbyApi()
        fake.permissionsDenied = true
        val adapter = NearbyConnectionsAdapter(fake)

        assertFailsWith<TransportError.PermissionsDenied> { adapter.startAdvertising("x") }
        assertFailsWith<TransportError.PermissionsDenied> { adapter.startDiscovery() }
        // Again: tracker rolled back, retry works once permission is granted.
        fake.permissionsDenied = false
        adapter.startDiscovery()
        assertEquals(1, fake.discoveryStarts.size)
    }

    @Test
    fun double_startAdvertising_is_typed_illegal_state() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        adapter.startAdvertising("one")
        val e = assertFailsWith<TransportError.IllegalState> { adapter.startAdvertising("two") }
        assertTrue(e.message!!.contains("already advertising"))
        // The second call did NOT reach the platform.
        assertEquals(listOf("one"), fake.advertisingStarts)
    }

    @Test
    fun connection_request_arriving_during_stop_is_dropped_without_panic() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)

        adapter.startDiscovery()
        adapter.stop()
        // Platform delivers a late connection request after stop().
        fake.remoteConnectionInitiated("EP1", "phone-EP1", "tok")
        // No event, no crash, and the endpoint is NOT registered.
        assertEquals(0, listener.events.size)
        assertFailsWith<TransportError.IllegalState> { adapter.acceptConnection(EndpointId("EP1")) }
    }

    @Test
    fun disconnect_mid_stream_cleans_up_and_emits_no_partial_frame() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        // Half a stream arrives, then the endpoint disconnects.
        val wire = PayloadPolicy.encodeEnvelope(5, ByteArray(64 * 1024) { 3 })
        val payloadId = fake.newPayloadId()
        val chunks = PayloadPolicy.chunkForStream(wire)
        fake.remoteStreamChunk(ep.value, payloadId, chunks[0])
        fake.remoteDisconnected(ep.value)

        // No partial frame, a Disconnected event instead.
        assertEquals(0, listener.frames.size)
        assertEquals(TransportEvent.Disconnected(ep, DisconnectReason.PEER), listener.events.last())

        // The endpoint reconnects and a FULL stream works: buffers were
        // cleaned, so stale partial bytes cannot corrupt the new stream.
        fake.remoteConnectionInitiated("EP1", "phone-EP1", null)
        adapter.acceptConnection(ep)
        fake.remoteConnectionAccepted("EP1")
        val payloadId2 = fake.newPayloadId()
        val cleanWire = PayloadPolicy.encodeEnvelope(6, ByteArray(40 * 1024) { 9 })
        for (chunk in PayloadPolicy.chunkForStream(cleanWire)) {
            fake.remoteStreamChunk("EP1", payloadId2, chunk)
        }
        fake.remoteStreamCompleted("EP1", payloadId2)
        assertEquals(1, listener.frames.size)
        assertEquals(ep to TransportFrame(6, ByteArray(40 * 1024) { 9 }), listener.frames[0])
    }

    @Test
    fun transfer_failure_mid_stream_drops_partial_buffer() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        val payloadId = fake.newPayloadId()
        fake.remoteStreamChunk(ep.value, payloadId, ByteArray(1024) { 7 })
        // Platform reports the transfer failed mid-flight.
        fake.remoteTransferFailed(ep.value, payloadId)
        // Still connected, no frame, no crash.
        assertEquals(0, listener.frames.size)
        assertEquals(
            TransportEvent.Connected(ep),
            listener.events.last(),
            "transfer failure must NOT disconnect the endpoint",
        )
        // A subsequent well-formed stream still works (buffer replaced).
        val payloadId2 = fake.newPayloadId()
        val wire = PayloadPolicy.encodeEnvelope(2, byteArrayOf(1, 2, 3))
        fake.remoteStreamChunk(ep.value, payloadId2, wire)
        fake.remoteStreamCompleted(ep.value, payloadId2)
        assertEquals(1, listener.frames.size)
    }

    @Test
    fun stream_send_failure_is_typed_io_failure() {
        val fake = FakeNearbyApi()
        fake.failStreamSends = true
        val adapter = NearbyConnectionsAdapter(fake)
        val ep = connectedEndpoint(fake, adapter)

        val big = TransportFrame(channelId = 3, payload = ByteArray(PayloadPolicy.MAX_BYTES_PAYLOAD_BYTES + 10))
        assertFailsWith<TransportError.IoFailure> { adapter.send(ep, big) }
        // The transfer failed but the endpoint itself remains usable: small
        // frames still go out over BYTES afterwards.
        fake.failStreamSends = false
        adapter.send(ep, TransportFrame(channelId = 1, payload = byteArrayOf(5)))
        assertEquals(1, fake.bytesSent.size)
        assertEquals(0, fake.streamsSent.size)
    }

    @Test
    fun endpoint_lost_surfaces_disconnected_event() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)

        adapter.startDiscovery()
        fake.remoteEndpointFound("EP1", "phone-EP1")
        fake.remoteEndpointLost("EP1")
        assertEquals(
            listOf(
                TransportEvent.Discovered(EndpointId("EP1"), "phone-EP1"),
                TransportEvent.Disconnected(EndpointId("EP1"), DisconnectReason.PEER),
            ),
            listener.events,
        )
    }

    @Test
    fun endpoint_lost_for_connected_endpoint_clears_state() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        fake.remoteEndpointLost(ep.value)
        assertEquals(TransportEvent.Disconnected(ep, DisconnectReason.PEER), listener.events.last())
        // Sending to the lost endpoint is now a typed IllegalState.
        assertFailsWith<TransportError.IllegalState> {
            adapter.send(ep, TransportFrame(channelId = 1, payload = byteArrayOf(1)))
        }
    }

    @Test
    fun remote_rejection_surfaces_disconnected_with_rejected_reason() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        adapter.startDiscovery()
        fake.remoteEndpointFound("EP1", "phone-EP1")
        fake.remoteConnectionInitiated("EP1", "phone-EP1", null)
        fake.remoteConnectionRejected("EP1")

        assertEquals(
            TransportEvent.Disconnected(EndpointId("EP1"), DisconnectReason.REJECTED),
            listener.events.last(),
        )
    }

    @Test
    fun rapid_advertise_stop_cycles_converge() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        repeat(50) { i ->
            adapter.startAdvertising("node-$i")
            adapter.stop()
        }
        // After the storm: one final start works, platform saw all 51.
        adapter.startAdvertising("final")
        assertEquals(51, fake.advertisingStarts.size)
        adapter.stop()
        // Interleaved variant: advertising + discovery churn together.
        repeat(50) {
            adapter.startDiscovery()
            adapter.startAdvertising("dual")
            adapter.stop()
        }
        adapter.startAdvertising("done")
        // 50 (loop) + 1 ("final") + 50 ("dual") + 1 ("done") = 102.
        assertEquals(102, fake.advertisingStarts.size)
        assertEquals(50, fake.discoveryStarts.size)
    }

    @Test
    fun send_to_unconnected_endpoint_is_typed_illegal_state() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        // Never connected.
        assertFailsWith<TransportError.IllegalState> {
            adapter.send(EndpointId("EP42"), TransportFrame(channelId = 1, payload = byteArrayOf(1)))
        }
        // Pending but not accepted: also illegal.
        adapter.startDiscovery()
        fake.remoteConnectionInitiated("EP1", "phone-EP1", null)
        assertFailsWith<TransportError.IllegalState> {
            adapter.send(EndpointId("EP1"), TransportFrame(channelId = 1, payload = byteArrayOf(1)))
        }
    }

    @Test
    fun malformed_wire_envelope_is_dropped_and_counted() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)

        // Shorter than the 8-byte envelope header.
        fake.remoteBytes(ep.value, byteArrayOf(1, 2, 3))
        // Header decodes to a negative channelId: rejected by the contract.
        val negative = ByteArray(9)
        negative[0] = 0xFF.toByte()
        fake.remoteBytes(ep.value, negative)
        // Malformed completed stream: empty buffer.
        fake.remoteStreamCompleted(ep.value, fake.newPayloadId())

        assertEquals(0, listener.frames.size)
        assertEquals(3, adapter.malformedFramesDropped)
    }

    @Test
    fun late_payload_after_disconnect_is_dropped() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        val ep = connectedEndpoint(fake, adapter)
        fake.remoteDisconnected(ep.value)
        // Platform delivers a late BYTES payload for the dead endpoint.
        fake.remoteBytes(ep.value, PayloadPolicy.encodeEnvelope(1, byteArrayOf(1)))
        assertEquals(0, listener.frames.size)
    }

    @Test
    fun accept_without_pending_request_is_typed_illegal_state() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val e = assertFailsWith<TransportError.IllegalState> { adapter.acceptConnection(EndpointId("EP1")) }
        assertTrue(e.message!!.contains("no pending connection request"))
        // And the platform was not called.
        assertTrue(fake.accepted.isEmpty())
    }

    @Test
    fun reject_after_acceptance_is_typed_illegal_state() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val ep = connectedEndpoint(fake, adapter)
        assertFailsWith<TransportError.IllegalState> { adapter.rejectConnection(ep) }
    }

    @Test
    fun duplicate_connection_request_is_dropped_not_crashed() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        adapter.startDiscovery()
        fake.remoteConnectionInitiated("EP1", "phone-EP1", null)
        // Platform re-delivers the same initiation (e.g. retry).
        fake.remoteConnectionInitiated("EP1", "phone-EP1", null)
        // Exactly ONE ConnectionRequested event surfaced.
        assertEquals(
            1,
            listener.events.count { it is TransportEvent.ConnectionRequested },
        )
    }

    @Test
    fun listener_registration_is_idempotent() {
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        val listener = RecordingListener()
        adapter.addListener(listener)
        adapter.addListener(listener)
        adapter.startDiscovery()
        fake.remoteEndpointFound("EP1", "x")
        assertEquals(1, listener.events.size)
        adapter.removeListener(listener)
        adapter.removeListener(listener)
        fake.remoteEndpointFound("EP2", "y")
        assertEquals(1, listener.events.size)
    }

    @Test
    fun events_and_frames_are_only_dispatched_outside_internal_locks() {
        // A listener that synchronously calls stop() from inside an event must
        // not deadlock — proves dispatch happens without the adapter lock.
        val fake = FakeNearbyApi()
        val adapter = NearbyConnectionsAdapter(fake)
        adapter.addListener(object : TransportListener {
            override fun onTransportEvent(event: TransportEvent) {
                if (event is TransportEvent.Connected) {
                    adapter.stop() // re-entrant call from a callback
                }
            }

            override fun onFrame(endpointId: EndpointId, frame: TransportFrame) = Unit
        })
        adapter.startDiscovery()
        fake.remoteConnectionInitiated("EP1", "phone-EP1", null)
        adapter.acceptConnection(EndpointId("EP1"))
        fake.remoteConnectionAccepted("EP1") // triggers stop() inside the callback
        assertEquals(1, fake.stopAllCalls)
    }
}
