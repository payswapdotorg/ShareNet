package org.sharenet.transport.contract

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * ConnectionTracker state machine tests (R2-001): legal transitions succeed,
 * illegal transitions raise typed IllegalState, and random legal op
 * sequences always leave the tracker in a legal state (fuzz-lite).
 */
class ConnectionTrackerTest {

    private fun ep(id: String) = EndpointId(id)

    @Test
    fun starts_idle() {
        val tracker = ConnectionTracker()
        assertTrue(tracker.isIdle)
        assertFalse(tracker.isAdvertising)
        assertFalse(tracker.isDiscovering)
        assertTrue(tracker.activeEndpointIds().isEmpty())
    }

    @Test
    fun double_startAdvertising_is_illegal_state() {
        val tracker = ConnectionTracker()
        tracker.startAdvertising()
        val error = assertFailsWith<TransportError.IllegalState> { tracker.startAdvertising() }
        assertTrue(error.message!!.contains("already advertising"))
    }

    @Test
    fun stopAdvertising_without_start_is_illegal_state() {
        val tracker = ConnectionTracker()
        assertFailsWith<TransportError.IllegalState> { tracker.stopAdvertising() }
    }

    @Test
    fun double_startDiscovery_is_illegal_state() {
        val tracker = ConnectionTracker()
        tracker.startDiscovery()
        assertFailsWith<TransportError.IllegalState> { tracker.startDiscovery() }
    }

    @Test
    fun stopDiscovery_without_start_is_illegal_state() {
        val tracker = ConnectionTracker()
        assertFailsWith<TransportError.IllegalState> { tracker.stopDiscovery() }
    }

    @Test
    fun advertising_and_discovery_are_independent() {
        val tracker = ConnectionTracker()
        tracker.startDiscovery()
        tracker.startAdvertising()
        assertTrue(tracker.isAdvertising && tracker.isDiscovering)
        assertFalse(tracker.isIdle)
        tracker.stopDiscovery()
        assertTrue(tracker.isAdvertising && !tracker.isDiscovering)
        tracker.stopAdvertising()
        assertTrue(tracker.isIdle)
    }

    @Test
    fun accept_without_pending_request_is_illegal_state() {
        val tracker = ConnectionTracker()
        assertFailsWith<TransportError.IllegalState> { tracker.acceptConnection(ep("EP1")) }
    }

    @Test
    fun full_connection_lifecycle() {
        val tracker = ConnectionTracker()
        tracker.startAdvertising()
        tracker.onConnectionRequested(ep("EP1"))
        assertTrue(tracker.isEndpointPending(ep("EP1")))
        assertFalse(tracker.isEndpointConnected(ep("EP1")))

        // Local accept: ACCEPTED (awaiting platform confirmation), not yet
        // connected.
        tracker.acceptConnection(ep("EP1"))
        assertTrue(tracker.isEndpointPending(ep("EP1")))
        assertFalse(tracker.isEndpointConnected(ep("EP1")))

        // Platform confirmation: CONNECTED.
        tracker.onConnectionAccepted(ep("EP1"))
        assertTrue(tracker.isEndpointConnected(ep("EP1")))
        assertFalse(tracker.isEndpointPending(ep("EP1")))

        tracker.onDisconnected(ep("EP1"))
        assertFalse(tracker.isEndpointConnected(ep("EP1")))
        assertTrue(tracker.activeEndpointIds().isEmpty())
    }

    @Test
    fun double_accept_is_illegal_state() {
        val tracker = ConnectionTracker()
        tracker.onConnectionRequested(ep("EP1"))
        tracker.acceptConnection(ep("EP1"))
        assertFailsWith<TransportError.IllegalState> { tracker.acceptConnection(ep("EP1")) }
    }

    @Test
    fun confirmation_without_local_accept_is_legal() {
        // A REQUESTED endpoint can be confirmed directly (future outbound
        // flow / platform-side auto-confirm).
        val tracker = ConnectionTracker()
        tracker.onConnectionRequested(ep("EP1"))
        tracker.onConnectionAccepted(ep("EP1"))
        assertTrue(tracker.isEndpointConnected(ep("EP1")))
    }

    @Test
    fun send_requires_connected_endpoint() {
        val tracker = ConnectionTracker()
        tracker.startDiscovery()
        tracker.onConnectionRequested(ep("EP1"))
        // Pending but not accepted: illegal.
        assertFailsWith<TransportError.IllegalState> { tracker.assertCanSend(ep("EP1")) }
        // Unknown endpoint: illegal.
        assertFailsWith<TransportError.IllegalState> { tracker.assertCanSend(ep("EP9")) }
        // Accepted but not yet platform-confirmed: still illegal.
        tracker.acceptConnection(ep("EP1"))
        assertFailsWith<TransportError.IllegalState> { tracker.assertCanSend(ep("EP1")) }
        // Confirmed: legal.
        tracker.onConnectionAccepted(ep("EP1"))
        tracker.assertCanSend(ep("EP1"))
    }

    @Test
    fun reject_is_only_legal_while_pending() {
        val tracker = ConnectionTracker()
        tracker.onConnectionRequested(ep("EP1"))
        tracker.rejectConnection(ep("EP1"))
        assertTrue(tracker.activeEndpointIds().isEmpty())
        // After acceptance, reject must be refused.
        tracker.onConnectionRequested(ep("EP2"))
        tracker.acceptConnection(ep("EP2"))
        assertFailsWith<TransportError.IllegalState> { tracker.rejectConnection(ep("EP2")) }
    }

    @Test
    fun duplicate_connection_request_is_illegal_state() {
        val tracker = ConnectionTracker()
        tracker.onConnectionRequested(ep("EP1"))
        assertFailsWith<TransportError.IllegalState> { tracker.onConnectionRequested(ep("EP1")) }
    }

    @Test
    fun remote_rejection_removes_pending_endpoint() {
        val tracker = ConnectionTracker()
        tracker.onConnectionRequested(ep("EP1"))
        tracker.onConnectionRejected(ep("EP1"))
        assertTrue(tracker.activeEndpointIds().isEmpty())
        // A second rejection event for the same endpoint is now illegal.
        assertFailsWith<TransportError.IllegalState> { tracker.onConnectionRejected(ep("EP1")) }
    }

    @Test
    fun duplicate_confirmation_is_illegal_state() {
        val tracker = ConnectionTracker()
        tracker.onConnectionRequested(ep("EP1"))
        tracker.onConnectionAccepted(ep("EP1"))
        assertFailsWith<TransportError.IllegalState> { tracker.onConnectionAccepted(ep("EP1")) }
    }

    @Test
    fun stopAll_is_total_and_idempotent() {
        val tracker = ConnectionTracker()
        tracker.startAdvertising()
        tracker.startDiscovery()
        tracker.onConnectionRequested(ep("EP1"))
        tracker.acceptConnection(ep("EP1"))
        tracker.stopAll()
        assertTrue(tracker.isIdle)
        assertTrue(tracker.activeEndpointIds().isEmpty())
        // Second stop: fine.
        tracker.stopAll()
        // And everything can be restarted cleanly.
        tracker.startAdvertising()
        tracker.startDiscovery()
        assertTrue(tracker.isActive)
    }

    @Test
    fun abandonConnection_tolerates_unknown_and_connected() {
        val tracker = ConnectionTracker()
        tracker.abandonConnection(ep("nope")) // no throw
        tracker.onConnectionRequested(ep("EP1"))
        tracker.abandonConnection(ep("EP1"))
        assertTrue(tracker.activeEndpointIds().isEmpty())
    }

    /**
     * Fuzz-lite (assignment §5): random op sequences — mixing legal and
     * illegal calls — must never panic with an unexpected exception type,
     * never corrupt state, and always converge to a legal state via stopAll().
     */
    @Test
    fun random_operation_sequences_converge_to_legal_state() {
        val seeds = listOf(1L, 42L, 20260915L, 777L, 1234567L)
        for (seed in seeds) {
            val random = java.util.Random(seed)
            val tracker = ConnectionTracker()
            repeat(500) {
                val ep = ep("EP${random.nextInt(3)}")
                val op = random.nextInt(14)
                try {
                    when (op) {
                        0 -> tracker.startAdvertising()
                        1 -> tracker.stopAdvertising()
                        2 -> tracker.startDiscovery()
                        3 -> tracker.stopDiscovery()
                        4 -> tracker.stopAll()
                        5 -> tracker.onConnectionRequested(ep)
                        6 -> tracker.acceptConnection(ep)
                        7 -> tracker.rejectConnection(ep)
                        8 -> tracker.onConnectionAccepted(ep)
                        9 -> tracker.onConnectionRejected(ep)
                        10 -> tracker.onDisconnected(ep)
                        11 -> tracker.abandonConnection(ep)
                        12 -> tracker.assertCanSend(ep)
                        13 -> tracker.snapshot()
                        else -> error("unreachable")
                    }
                } catch (expected: TransportError.IllegalState) {
                    // The only legal failure mode of this machine.
                }
                // Structural invariant: every endpoint is pending-or-connected,
                // i.e. the snapshot's map only ever contains booleans (trivially
                // true) AND activeEndpointIds matches the snapshot keys.
                val snapshot = tracker.snapshot()
                assertEquals(snapshot.endpoints.keys.toSet(), tracker.activeEndpointIds().toSet())
            }
            // Convergence: stopAll always brings the machine back to Idle.
            tracker.stopAll()
            assertTrue(tracker.isIdle, "seed $seed: tracker must converge to idle after stopAll")
            assertTrue(tracker.activeEndpointIds().isEmpty())
        }
    }
}
