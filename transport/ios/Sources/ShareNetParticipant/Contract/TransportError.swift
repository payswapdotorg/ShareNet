import Foundation

/// Typed transport errors. NO platform (Network.framework / NWError) types
/// leak here — adapters classify their native errors into these cases at
/// their boundary (the same discipline as the Android `contract` module's
/// `TransportError`, which allows no GMS types).
public enum TransportError: Error, Equatable, CustomStringConvertible {

    /// The app has not granted the platform permissions the transport needs
    /// (iOS 14+: the Local Network privacy permission for Bonjour browsing
    /// and peer-to-peer connections; the embedding app must declare
    /// `NSLocalNetworkUsageDescription` and `NSBonjourServices`).
    case permissionsDenied(detail: String)

    /// Bonjour advertising/browsing is unusable on this platform right now
    /// (an `NWBrowser`/`NWListener` `.failed` state, e.g. mDNSResponder
    /// unavailable). The iOS analog of the Android contract's
    /// `PlayServicesUnavailable`.
    case bonjourUnavailable(String)

    /// The operation is not legal in the current transport state.
    case illegalState(String)

    /// The remote endpoint refused the connection.
    case connectionRejected(EndpointID)

    /// An I/O failure inside the transport (underlying `NWError`
    /// classification, stream errors, ...).
    case ioFailure(String)

    /// A frame (or its claimed length) exceeded the transport's frame bound.
    /// Enforced BEFORE the socket write (send) and on the length prefix
    /// (receive) — a receiver never buffers an oversized claimed frame.
    case frameTooLarge(length: Int, maximum: Int)

    /// The bounded send window is full — the caller MUST treat this as
    /// backpressure (slow down / retry), never as a reason to buffer without
    /// bound. There is deliberately no unbounded send path.
    case sendWindowExhausted(inFlightBytes: Int, maximumBytes: Int)

    /// The R3-001 authenticated-link handshake failed. `reason` carries the
    /// protocol core's machine name when available (e.g.
    /// `signature_invalid`, `scheme_version_unsupported`); the cryptography
    /// itself lives in the shared protocol implementation, never here.
    case handshakeFailed(reason: String)

    /// A deadline elapsed (connection readiness, handshake phase, ...).
    case timedOut(phase: String)

    /// The stream/connection reached EOF or was cancelled — terminal.
    case connectionClosed

    /// A payload could not be parsed at the transport boundary (e.g. a
    /// channel envelope shorter than its 8-byte channel id). Dropped and
    /// counted by the adapter, not propagated as a session failure.
    case malformedMessage(String)

    /// An established link session rejected a frame (authentication or
    /// replay failure surfaced by the protocol core). Any occurrence is
    /// TERMINAL for the session — a failed link is never silently recovered
    /// (L014: recovery means a fresh handshake and a fresh link id).
    case linkSessionFailed(reason: String)

    public var description: String {
        switch self {
        case .permissionsDenied(let detail):
            return "required platform permissions were denied or not granted: \(detail)"
        case .bonjourUnavailable(let detail):
            return "bonjour unavailable: \(detail)"
        case .illegalState(let detail):
            return "illegal transport state: \(detail)"
        case .connectionRejected(let endpoint):
            return "connection rejected by endpoint \(endpoint.value)"
        case .ioFailure(let detail):
            return "transport i/o failure: \(detail)"
        case .frameTooLarge(let length, let maximum):
            return "frame of \(length) bytes exceeds the maximum of \(maximum) bytes"
        case .sendWindowExhausted(let inFlight, let maximum):
            return "send window exhausted (\(inFlight)/\(maximum) bytes in flight); retry after in-flight sends complete"
        case .handshakeFailed(let reason):
            return "authenticated-link handshake failed: \(reason)"
        case .timedOut(let phase):
            return "timed out while \(phase)"
        case .connectionClosed:
            return "connection closed"
        case .malformedMessage(let detail):
            return "malformed transport message: \(detail)"
        case .linkSessionFailed(let reason):
            return "link session rejected a frame: \(reason)"
        }
    }
}
