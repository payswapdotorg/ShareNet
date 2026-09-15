package org.sharenet.transport.contract

/**
 * Events surfaced by a transport to registered [TransportListener]s.
 *
 * Contract-level only: platform adapters (lock L009) translate their native
 * callbacks into these types; no GMS/Android types ever appear here.
 */
sealed class TransportEvent {

    /** A remote endpoint became visible during discovery. */
    data class Discovered(
        val endpointId: EndpointId,
        val name: String,
    ) : TransportEvent()

    /**
     * A remote endpoint wants to connect. The app decides via
     * [NearbyTransport.acceptConnection] / [NearbyTransport.rejectConnection].
     *
     * [authenticationToken] is the platform-supplied pairing token when the
     * transport provides one (Nearby does); it is *transport-level* evidence,
     * never ShareNet cryptographic authentication (that is R3-001).
     */
    data class ConnectionRequested(
        val endpointId: EndpointId,
        val name: String,
        val authenticationToken: String? = null,
    ) : TransportEvent()

    /** The connection to [endpointId] is established and payloads may flow. */
    data class Connected(
        val endpointId: EndpointId,
    ) : TransportEvent()

    /**
     * The endpoint is gone. This event is also used when a merely-discovered
     * endpoint disappears (endpoint lost) and when a pending connection
     * request is rejected by the remote side — [reason] distinguishes the
     * cases.
     */
    data class Disconnected(
        val endpointId: EndpointId,
        val reason: DisconnectReason,
    ) : TransportEvent()
}

/** Why an endpoint disappeared. */
enum class DisconnectReason {
    /** The remote endpoint went away or the platform lost it. */
    PEER,

    /** The transport failed underneath the connection (I/O or transfer error). */
    ERROR,

    /** A pending connection request was rejected by the remote endpoint. */
    REJECTED,

    /** Local stop() tore the connection down. */
    LOCAL,
}
