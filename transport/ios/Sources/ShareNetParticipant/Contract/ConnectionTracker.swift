import Foundation

/// Pure-Swift state machine tracking transport activity (R9-001).
///
/// Ladder: Idle → Advertising/Discovering (independently switchable, matching
/// the real platform where both may run) → per-endpoint
/// `requested → accepted → connected`:
///
/// ```text
///                onConnectionRequested
///   (gone) ─────────────────────────────► REQUESTED
///      ▲                                      │
///      │              rejectConnection        │ acceptConnection
///      │◄─────────────────────────────────────┤
///      │                                      ▼
///      │  onConnectionRejected/         ACCEPTED
///      │  onDisconnected                    │
///      │                                    │ onConnectionAccepted
///      │                                    ▼
///      └──────────────────────────────── CONNECTED
/// ```
///
/// The tracker enforces legal transitions with `TransportError.illegalState`
/// and is deliberately STRICT: platform adapters tolerate weird native event
/// ordering at their own boundary (dropping what the tracker rejects) so that
/// this class can stay a precise, testable machine.
///
/// `onConnectionAccepted` also accepts a REQUESTED endpoint directly (the
/// outbound flow: the authenticated-links layer R3-001 initiates, the platform
/// confirms). On iOS the adapter sets `connected` only after the R3-001
/// handshake has completed, so `assertCanSend` implies "authenticated link
/// established", not merely "TCP established".
///
/// Thread-safe (internal lock); no callbacks are invoked while the lock is
/// held, so code called by the adapter may safely call back in.
///
/// Deterministic: endpoint order is insertion order (mirroring the Android
/// tracker's `LinkedHashMap`), so diagnostics and tests never depend on
/// dictionary hashing.
public final class ConnectionTracker {

    /// Read-only state snapshot: endpoint id → connected?
    public struct Snapshot: Equatable {
        public let advertising: Bool
        public let discovering: Bool
        public let endpoints: [EndpointID: Bool]
    }

    private enum EndpointState {
        case requested
        case accepted
        case connected
    }

    private let lock = NSLock()
    private var advertising = false
    private var discovering = false
    private var endpointStates: [EndpointID: EndpointState] = [:]
    private var endpointOrder: [EndpointID] = []

    /// True while advertising is active.
    public var isAdvertising: Bool {
        lock.lock(); defer { lock.unlock() }
        return advertising
    }

    /// True while discovery is active.
    public var isDiscovering: Bool {
        lock.lock(); defer { lock.unlock() }
        return discovering
    }

    /// True while neither advertising nor discovering (ladder "Idle" state).
    public var isIdle: Bool {
        lock.lock(); defer { lock.unlock() }
        return !advertising && !discovering
    }

    /// True while advertising or discovering.
    public var isActive: Bool {
        lock.lock(); defer { lock.unlock() }
        return advertising || discovering
    }

    /// Snapshot of endpoint ids currently known (requested/accepted/
    /// connected), in first-contact order.
    public func activeEndpointIds() -> [EndpointID] {
        lock.lock(); defer { lock.unlock() }
        return endpointOrder
    }

    /// True if `endpoint` has an ESTABLISHED (platform-confirmed and, for the
    /// participant adapter, handshake-completed) connection.
    public func isEndpointConnected(_ endpoint: EndpointID) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return endpointStates[endpoint] == .connected
    }

    /// True if `endpoint` has a connection that is not yet confirmed.
    public func isEndpointPending(_ endpoint: EndpointID) -> Bool {
        lock.lock(); defer { lock.unlock() }
        switch endpointStates[endpoint] {
        case .requested, .accepted: return true
        case .connected, nil: return false
        }
    }

    // MARK: Activity transitions

    /// - Throws: `TransportError.illegalState` if already advertising.
    public func startAdvertising() throws {
        lock.lock(); defer { lock.unlock() }
        if advertising {
            throw TransportError.illegalState("already advertising")
        }
        advertising = true
    }

    /// - Throws: `TransportError.illegalState` if not advertising.
    public func stopAdvertising() throws {
        lock.lock(); defer { lock.unlock() }
        if !advertising {
            throw TransportError.illegalState("not advertising")
        }
        advertising = false
    }

    /// - Throws: `TransportError.illegalState` if already discovering.
    public func startDiscovery() throws {
        lock.lock(); defer { lock.unlock() }
        if discovering {
            throw TransportError.illegalState("already discovering")
        }
        discovering = true
    }

    /// - Throws: `TransportError.illegalState` if not discovering.
    public func stopDiscovery() throws {
        lock.lock(); defer { lock.unlock() }
        if !discovering {
            throw TransportError.illegalState("not discovering")
        }
        discovering = false
    }

    /// Tear everything down to Idle: advertising, discovery and ALL endpoints.
    /// Idempotent — the one deliberately lenient operation (a stop after a
    /// failed start must converge; see the rapid-cycle tests).
    public func stopAll() {
        lock.lock(); defer { lock.unlock() }
        advertising = false
        discovering = false
        endpointStates.removeAll()
        endpointOrder.removeAll()
    }

    // MARK: Per-endpoint transitions

    /// A connection request arrived for `endpoint` (inbound from the
    /// platform, or an outbound request placed by the link layer).
    ///
    /// - Throws: `TransportError.illegalState` if `endpoint` is already known.
    public func onConnectionRequested(_ endpoint: EndpointID) throws {
        lock.lock(); defer { lock.unlock() }
        if endpointStates[endpoint] != nil {
            throw TransportError.illegalState(
                "connection already pending or connected for endpoint \(endpoint.value)"
            )
        }
        endpointStates[endpoint] = .requested
        endpointOrder.append(endpoint)
    }

    /// Local decision: accept the pending request for `endpoint`. The
    /// endpoint becomes ACCEPTED; it becomes CONNECTED only when the platform
    /// (and, for the participant, the R3-001 handshake) confirms
    /// (`onConnectionAccepted`).
    ///
    /// - Throws: `TransportError.illegalState` if there is no pending request,
    ///   it was already accepted, or it is already connected.
    public func acceptConnection(_ endpoint: EndpointID) throws {
        lock.lock(); defer { lock.unlock() }
        switch endpointStates[endpoint] {
        case .requested:
            endpointStates[endpoint] = .accepted
        case .accepted:
            throw TransportError.illegalState(
                "endpoint \(endpoint.value) is already accepted (awaiting platform confirmation)"
            )
        case .connected:
            throw TransportError.illegalState(
                "endpoint \(endpoint.value) is already connected"
            )
        case nil:
            throw TransportError.illegalState(
                "no pending connection request for endpoint \(endpoint.value)"
            )
        }
    }

    /// Local decision: reject the pending request for `endpoint`.
    ///
    /// - Throws: `TransportError.illegalState` if there is no pending request
    ///   or it was already accepted/connected.
    public func rejectConnection(_ endpoint: EndpointID) throws {
        lock.lock(); defer { lock.unlock() }
        switch endpointStates[endpoint] {
        case .requested:
            removeLocked(endpoint)
        case .accepted:
            throw TransportError.illegalState(
                "endpoint \(endpoint.value) was already accepted; rejecting is only legal before acceptance"
            )
        case .connected:
            throw TransportError.illegalState(
                "endpoint \(endpoint.value) is already connected; rejecting is only legal before acceptance"
            )
        case nil:
            throw TransportError.illegalState(
                "no pending connection request for endpoint \(endpoint.value)"
            )
        }
    }

    /// The platform confirmed the connection for `endpoint`: a locally
    /// ACCEPTED request, or a REQUESTED one (outbound flow: the link layer
    /// requested, the platform — and on iOS the R3-001 handshake — confirmed).
    ///
    /// - Throws: `TransportError.illegalState` if `endpoint` is unknown or
    ///   already connected (duplicate confirmation).
    public func onConnectionAccepted(_ endpoint: EndpointID) throws {
        lock.lock(); defer { lock.unlock() }
        switch endpointStates[endpoint] {
        case .requested, .accepted:
            endpointStates[endpoint] = .connected
        case .connected:
            throw TransportError.illegalState(
                "duplicate connection confirmation for endpoint \(endpoint.value)"
            )
        case nil:
            throw TransportError.illegalState(
                "connection confirmed for unknown endpoint \(endpoint.value)"
            )
        }
    }

    /// The pending request for `endpoint` was rejected by the remote side
    /// (or failed before confirmation). Removes the endpoint.
    ///
    /// - Throws: `TransportError.illegalState` if `endpoint` is unknown.
    public func onConnectionRejected(_ endpoint: EndpointID) throws {
        lock.lock(); defer { lock.unlock() }
        if endpointStates[endpoint] == nil {
            throw TransportError.illegalState(
                "connection rejected for unknown endpoint \(endpoint.value)"
            )
        }
        removeLocked(endpoint)
    }

    /// The endpoint disconnected (or was lost). Removes the endpoint.
    ///
    /// - Throws: `TransportError.illegalState` if `endpoint` is unknown.
    public func onDisconnected(_ endpoint: EndpointID) throws {
        lock.lock(); defer { lock.unlock() }
        if endpointStates[endpoint] == nil {
            throw TransportError.illegalState(
                "disconnect for unknown endpoint \(endpoint.value)"
            )
        }
        removeLocked(endpoint)
    }

    /// Drop the endpoint unconditionally if present (adapter rollback helper
    /// after a platform failure; also tolerates unknown ids).
    public func abandonConnection(_ endpoint: EndpointID) {
        lock.lock(); defer { lock.unlock() }
        removeLocked(endpoint)
    }

    /// Enforce send legality.
    ///
    /// - Throws: `TransportError.illegalState` if `endpoint` is not CONNECTED.
    public func assertCanSend(_ endpoint: EndpointID) throws {
        lock.lock(); defer { lock.unlock() }
        switch endpointStates[endpoint] {
        case .connected:
            break
        case .accepted:
            throw TransportError.illegalState(
                "endpoint \(endpoint.value) is accepted but not confirmed yet"
            )
        case .requested:
            throw TransportError.illegalState(
                "endpoint \(endpoint.value) is not connected yet (request pending)"
            )
        case nil:
            throw TransportError.illegalState(
                "endpoint \(endpoint.value) is not connected"
            )
        }
    }

    /// Snapshot for diagnostics (invariant-checked by the fuzz-lite test).
    public func snapshot() -> Snapshot {
        lock.lock(); defer { lock.unlock() }
        return Snapshot(
            advertising: advertising,
            discovering: discovering,
            endpoints: endpointOrder.reduce(into: [EndpointID: Bool]()) { result, endpoint in
                result[endpoint] = endpointStates[endpoint] == .connected
            }
        )
    }

    /// MUST be called with the lock held.
    private func removeLocked(_ endpoint: EndpointID) {
        endpointStates.removeValue(forKey: endpoint)
        if let index = endpointOrder.firstIndex(of: endpoint) {
            endpointOrder.remove(at: index)
        }
    }
}
