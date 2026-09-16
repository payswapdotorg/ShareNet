import Foundation

/// Receives transport events and frames. Implementations should return
/// quickly; heavy work must be queued by the app, not done inline.
///
/// Threading: events are delivered on the adapter's delivery queue (a serial
/// `DispatchQueue` owned by the transport). Adapters guarantee they never
/// call listeners while holding their internal locks, so listeners may call
/// back into the transport.
///
/// Swift mirror of the Android `contract` module's `TransportListener`.
public protocol TransportListener: AnyObject {

    /// A lifecycle event (discovery / connection lifecycle).
    func transport(_ transport: ParticipantTransport, didReceive event: TransportEvent)

    /// A complete frame arrived from `endpoint` over an established,
    /// authenticated link.
    func transport(_ transport: ParticipantTransport, didReceiveFrame frame: TransportFrame, from endpoint: EndpointID)
}

/// The transport seam for the ShareNet participant (R9-001).
///
/// Implemented by platform adapters (architecture lock L009: adapters, not
/// protocol semantics). This foundation handles INBOUND connection requests
/// (`connectionRequested` → accept/reject); actively initiating outbound
/// links is exposed by the concrete adapter (`NWParticipantTransport.connect`)
/// and is driven by the authenticated-links layer (R3-001) — the same
/// deliberate omission as the Android `NearbyTransport` contract.
///
/// The Swift analog of the Android `contract` module's `NearbyTransport`:
/// a platform-neutral interface whose logic is exercised in unit tests
/// against pure state machines and scripted fakes.
public protocol ParticipantTransport: AnyObject {

    /// Register a listener (idempotent, identity-based).
    func addListener(_ listener: TransportListener)

    /// Unregister a listener (idempotent).
    func removeListener(_ listener: TransportListener)

    /// Start advertising this device as `name` so nearby peers can find it
    /// and open connections to it.
    ///
    /// - Throws: `TransportError.illegalState` if already advertising;
    ///   `TransportError.bonjourUnavailable` if the platform listener fails.
    func startAdvertising(name: String) throws

    /// Start discovering nearby advertising peers.
    ///
    /// - Throws: `TransportError.illegalState` if already discovering.
    func startDiscovery() throws

    /// Stop everything (advertising, discovery, all links) and release
    /// platform resources. Idempotent; never throws; dispatches no
    /// per-endpoint `disconnected` events (the Android contract's stop
    /// semantics).
    func stop()

    /// Accept a pending connection request (from `.connectionRequested`).
    ///
    /// - Throws: `TransportError.illegalState` if there is no pending request
    ///   for `endpoint` or it was already accepted.
    func acceptConnection(_ endpoint: EndpointID) throws

    /// Reject a pending connection request.
    ///
    /// - Throws: `TransportError.illegalState` if there is no pending request
    ///   or it was already accepted.
    func rejectConnection(_ endpoint: EndpointID) throws

    /// Send one frame to an endpoint with an established authenticated link.
    ///
    /// - Throws: `TransportError.illegalState` if `endpoint` has no
    ///   established link; `TransportError.sendWindowExhausted` when the
    ///   bounded send window is full (backpressure — retry, never buffer
    ///   without bound); `TransportError.frameTooLarge` when the sealed frame
    ///   exceeds the frame bound.
    func send(_ frame: TransportFrame, to endpoint: EndpointID) throws
}
