import Foundation

/// Events surfaced by a transport to registered `TransportListener`s.
///
/// Contract-level only: platform adapters (architecture lock L009 — adapters,
/// not protocol semantics) translate their native callbacks into these types;
/// no Network.framework / NWError types ever appear here.
///
/// Swift mirror of the Android `contract` module's `TransportEvent`, with one
/// recorded deviation: `connectionRequested` carries no name and no
/// transport-level pairing token, because `NWListener` hands an inbound TCP
/// connection over without either (the authenticated peer identity arrives
/// with the established R3-001 link, never from the platform).
public enum TransportEvent: Equatable, CustomStringConvertible, Sendable {

    /// A remote endpoint became visible during discovery.
    case discovered(EndpointID, name: String)

    /// A remote endpoint wants to connect. The app decides via
    /// `ParticipantTransport.acceptConnection(_:)` /
    /// `ParticipantTransport.rejectConnection(_:)`.
    case connectionRequested(EndpointID)

    /// The authenticated link to the endpoint is established and frames may
    /// flow (transport-ready AND the R3-001 handshake completed — the
    /// participant never reports a mere platform connection as connected).
    case connected(EndpointID)

    /// The endpoint is gone. Also used when a merely-discovered endpoint
    /// disappears (a lost browse result) — `reason` distinguishes the cases.
    case disconnected(EndpointID, reason: DisconnectReason)

    public var description: String {
        switch self {
        case .discovered(let endpoint, let name):
            return "discovered \(endpoint.value) (\"\(name)\")"
        case .connectionRequested(let endpoint):
            return "connection requested by \(endpoint.value)"
        case .connected(let endpoint):
            return "connected \(endpoint.value)"
        case .disconnected(let endpoint, let reason):
            return "disconnected \(endpoint.value) (\(reason))"
        }
    }
}

/// Why an endpoint disappeared. Swift mirror of the Android contract's
/// `DisconnectReason`.
public enum DisconnectReason: Equatable, CustomStringConvertible, Sendable {

    /// The remote endpoint went away or the platform lost it (including a
    /// lost Bonjour browse result for a not-yet-connected endpoint).
    case peer

    /// The transport failed underneath the connection (I/O, stream, or link
    /// authentication failure — any of which is terminal, per L014).
    case error

    /// A pending connection request was rejected by the remote endpoint.
    case rejected

    /// Local `stop()` tore the connection down.
    case local

    public var description: String {
        switch self {
        case .peer: return "peer"
        case .error: return "error"
        case .rejected: return "rejected"
        case .local: return "local"
        }
    }
}
