import Foundation
import Network

/// The iOS ShareNet participant: `ParticipantTransport` over Apple
/// Network.framework (R9-001, spec/architecture.md §16 Phase 2 — "iOS
/// participation and Packet Tunnel Provider where platform entitlements
/// permit").
///
/// Architecture mapping (see transport/ios/README.md for the full table):
///
/// | Frozen seam (architecture.md) | Network.framework surface |
/// |---|---|
/// | §3 control plane: identity/discovery | `NWBrowser` Bonjour browsing + `NWListener` advertising |
/// | §3 data plane: authenticated links | `NWConnection` carrying the R3-001 handshake + sealed frames |
/// | §8 tunnel hand-off | the QUIC tunnel (R4-001) rides ABOVE this transport; the Packet Tunnel Provider is R9-002 |
///
/// This class is a PLATFORM ADAPTER (architecture lock L009): it owns OS
/// lifecycle, discovery, connection acceptance and teardown. All protocol
/// semantics — the R3-001 cryptography, replay window, circuit identity —
/// live behind the engine seams supplied at construction. The engines are
/// the protocol core's presence on this platform (production: the Rust
/// `sharenet-protocol` core over FFI; this wave ships no production engine —
/// see README "Recorded gaps").
///
/// Threading: events and frames are delivered to listeners on a serial
/// delivery queue; listener callbacks may call back into this transport
/// (internal locks are never held across callbacks). The blocking handshake
/// runs on a dedicated thread per attempt.
public final class NWParticipantTransport: ParticipantTransport {

    private struct LinkEntry {
        let link: AuthenticatedLink
        let transport: NWLinkTransport
    }

    /// Factory for per-attempt initiator-side protocol-core engines. Each
    /// handshake attempt gets a FRESH engine (fresh ephemerals — a failed
    /// handshake is never retried with the same engine, L014).
    public typealias InitiatorEngineFactory = () -> any LinkInitiatorEngine

    /// Factory for per-attempt responder-side protocol-core engines.
    public typealias ResponderEngineFactory = () -> any LinkResponderEngine

    public let configuration: ParticipantConfiguration

    private let initiatorEngineFactory: InitiatorEngineFactory
    private let responderEngineFactory: ResponderEngineFactory
    private let tracker = ConnectionTracker()
    private let queue: DispatchQueue
    private let nwQueue: DispatchQueue
    private let lock = NSLock()

    private var listeners: [any TransportListener] = []
    private var browser: BonjourBrowser?
    private var advertiser: BonjourAdvertiser?
    private var pendingInbound: [EndpointID: NWConnection] = [:]
    private var links: [EndpointID: LinkEntry] = [:]
    private var eventsContinuation: AsyncStream<TransportEvent>.Continuation?
    private var stopped = false

    /// Diagnostic sink for transport-internal failures that have no contract
    /// event (Bonjour stack failures — the same gap the Android contract
    /// fills with logs). Called on the delivery queue; never used for
    /// control flow.
    public var onTransportHealth: ((TransportError) -> Void)?

    /// - Parameters:
    ///   - configuration: bounds, Bonjour service identity, timeouts
    ///     (validated at ITS construction — a misconfigured bound fails
    ///     before the transport is built).
    ///   - initiatorEngineFactory: fresh initiator engines for outbound
    ///     link attempts.
    ///   - responderEngineFactory: fresh responder engines for inbound link
    ///     attempts.
    public init(
        configuration: ParticipantConfiguration,
        initiatorEngineFactory: @escaping InitiatorEngineFactory,
        responderEngineFactory: @escaping ResponderEngineFactory,
        deliveryQueue: DispatchQueue = DispatchQueue(label: "org.sharenet.transport.ios.events"),
        connectionQueue: DispatchQueue = DispatchQueue(label: "org.sharenet.transport.ios.connections")
    ) {
        self.configuration = configuration
        self.initiatorEngineFactory = initiatorEngineFactory
        self.responderEngineFactory = responderEngineFactory
        self.queue = deliveryQueue
        self.nwQueue = connectionQueue
    }

    deinit {
        stop()
    }

    // MARK: ParticipantTransport

    public func addListener(_ listener: TransportListener) {
        lock.lock(); defer { lock.unlock() }
        if !listeners.contains(where: { $0 === listener }) {
            listeners.append(listener)
        }
    }

    public func removeListener(_ listener: TransportListener) {
        lock.lock(); defer { lock.unlock() }
        listeners.removeAll { $0 === listener }
    }

    public func startAdvertising(name: String) throws {
        try tracker.startAdvertising()
        do {
            let advertiser = BonjourAdvertiser(
                configuration: BonjourAdvertiser.Configuration(
                    serviceType: configuration.serviceType,
                    serviceDomain: configuration.serviceDomain,
                    includePeerToPeer: configuration.includePeerToPeer
                ),
                queue: queue,
                onAccept: { [weak self] connection in
                    // newConnectionHandler arrives on the listener's queue,
                    // which is our delivery queue.
                    self?.handleInbound(connection)
                },
                onEvent: { [weak self] event in
                    self?.handleAdvertiserEvent(event)
                }
            )
            try advertiser.startAdvertising(name: name)
            lock.lock()
            self.advertiser = advertiser
            lock.unlock()
        } catch {
            // Platform failure: roll the tracker back (the Android adapter's
            // rollback discipline — never leave the tracker ahead of the
            // platform).
            try? tracker.stopAdvertising()
            throw error
        }
    }

    public func startDiscovery() throws {
        try tracker.startDiscovery()
        do {
            let browser = BonjourBrowser(
                configuration: BonjourBrowser.Configuration(
                    serviceType: configuration.serviceType,
                    serviceDomain: configuration.serviceDomain,
                    includePeerToPeer: configuration.includePeerToPeer
                ),
                queue: queue,
                onEvent: { [weak self] event in
                    self?.handleBrowserEvent(event)
                }
            )
            try browser.start()
            lock.lock()
            self.browser = browser
            lock.unlock()
        } catch {
            try? tracker.stopDiscovery()
            throw error
        }
    }

    public func stop() {
        lock.lock()
        if stopped {
            lock.unlock()
            return
        }
        stopped = true
        let browser = self.browser
        let advertiser = self.advertiser
        self.browser = nil
        self.advertiser = nil
        let pending = pendingInbound
        pendingInbound.removeAll()
        let entries = Array(links.values)
        links.removeAll()
        let continuation = eventsContinuation
        eventsContinuation = nil
        lock.unlock()

        // Mirrors the Android stop(): NO per-endpoint disconnected events —
        // stopping is the caller's own signal.
        browser?.cancel()
        advertiser?.stopAdvertising()
        for (_, connection) in pending {
            connection.cancel()
        }
        for entry in entries {
            entry.link.terminate()
            entry.transport.cancel()
        }
        tracker.stopAll()
        continuation?.finish()
    }

    public func acceptConnection(_ endpoint: EndpointID) throws {
        try tracker.acceptConnection(endpoint)
        lock.lock()
        let connection = pendingInbound.removeValue(forKey: endpoint)
        lock.unlock()
        guard let connection else {
            // The platform connection vanished between the request event and
            // the local accept (e.g. a stop raced) — roll the tracker back.
            tracker.abandonConnection(endpoint)
            throw TransportError.illegalState("no pending platform connection for endpoint \(endpoint.value)")
        }
        startLinkHandshake(endpoint: endpoint, connection: connection, role: .responder) { _ in }
    }

    public func rejectConnection(_ endpoint: EndpointID) throws {
        try tracker.rejectConnection(endpoint)
        lock.lock()
        let connection = pendingInbound.removeValue(forKey: endpoint)
        lock.unlock()
        connection?.cancel()
    }

    public func send(_ frame: TransportFrame, to endpoint: EndpointID) throws {
        try tracker.assertCanSend(endpoint)
        lock.lock()
        let entry = links[endpoint]
        lock.unlock()
        guard let entry else {
            throw TransportError.illegalState(
                "endpoint \(endpoint.value) has no established authenticated link"
            )
        }
        try entry.link.send(frame)
    }

    // MARK: Outbound links (Swift-concurrency convenience over the blocking driver)

    /// Open an outbound authenticated link to a discovered endpoint (the
    /// R3-001 layer decides when to initiate — this is deliberately NOT part
    /// of the `ParticipantTransport` contract, mirroring the Android seam).
    ///
    /// - Throws: `TransportError.illegalState` when the endpoint is not
    ///   discovered or already has a pending/established link; handshake and
    ///   transport errors from the attempt.
    @discardableResult
    public func connect(to endpoint: EndpointID) async throws -> AuthenticatedLink {
        try await withCheckedThrowingContinuation { continuation in
            startOutboundLink(to: endpoint) { result in
                continuation.resume(with: result)
            }
        }
    }

    private func startOutboundLink(
        to endpoint: EndpointID,
        completion: @escaping (Result<AuthenticatedLink, TransportError>) -> Void
    ) {
        lock.lock()
        let browser = self.browser
        lock.unlock()
        guard let nwEndpoint = browser?.endpoint(for: endpoint) else {
            queue.async {
                completion(.failure(TransportError.illegalState(
                    "endpoint \(endpoint.value) is not discovered"
                )))
            }
            return
        }
        do {
            try tracker.onConnectionRequested(endpoint)
        } catch {
            queue.async { completion(.failure(error)) }
            return
        }
        let connection = NWConnection(to: nwEndpoint, using: linkParameters())
        startLinkHandshake(endpoint: endpoint, connection: connection, role: .initiator, completion: completion)
    }

    // MARK: Event stream (Swift-concurrency convenience over the listener API)

    /// A single-consumer event stream mirroring the listener events (the
    /// listener API remains the multi-consumer contract). Creating a new
    /// stream finishes the previous one.
    public func makeEventStream() -> AsyncStream<TransportEvent> {
        AsyncStream { continuation in
            lock.lock()
            let previous = eventsContinuation
            eventsContinuation = continuation
            lock.unlock()
            previous?.finish()
        }
    }

    // MARK: Internals

    /// TCP parameters for the local link leg: the R3-001 authenticated link
    /// supplies authentication/confidentiality (the Wave-1 UDP transport's
    /// division); TLS 1.3 belongs to the Internet-facing tunnel (§8).
    private func linkParameters() -> NWParameters {
        let parameters = NWParameters.tcp
        parameters.includePeerToPeer = configuration.includePeerToPeer
        return parameters
    }

    /// Drive one link handshake on a dedicated thread (the blocking
    /// `FrameByteTransport` seam must not run on a dispatch queue that also
    /// delivers its frames).
    private func startLinkHandshake(
        endpoint: EndpointID,
        connection: NWConnection,
        role: LinkRole,
        completion: @escaping (Result<AuthenticatedLink, TransportError>) -> Void
    ) {
        let transport = NWLinkTransport(
            connection: connection,
            queue: nwQueue,
            maxFrameBytes: configuration.maxFrameBytes,
            sendWindow: SendWindow(limits: configuration.sendWindowLimits)
        )
        transport.start()

        let handshakeTimeout = configuration.handshakeTimeout
        let connectionTimeout = configuration.connectionTimeout

        let thread = Thread { [weak self] in
            guard let self else {
                // The participant went away before the attempt started: fail
                // closed and still resume the caller exactly once.
                transport.cancel()
                completion(.failure(TransportError.connectionClosed))
                return
            }
            let outcome: Result<EstablishedLink, TransportError>
            do {
                try transport.waitUntilReady(timeout: connectionTimeout)
                let options = try LinkHandshakeDriver.Options(timeout: handshakeTimeout)
                switch role {
                case .initiator:
                    let engine = self.initiatorEngineFactory()
                    outcome = .success(try LinkHandshakeDriver.initiate(over: transport, engine: engine, options: options))
                case .responder:
                    let engine = self.responderEngineFactory()
                    outcome = .success(try LinkHandshakeDriver.respond(over: transport, engine: engine, options: options))
                }
            } catch let error as TransportError {
                outcome = .failure(error)
            } catch {
                outcome = .failure(TransportError.handshakeFailed(reason: String(describing: error)))
            }
            self.queue.async {
                self.finishLinkHandshake(
                    endpoint: endpoint,
                    transport: transport,
                    result: outcome,
                    completion: completion
                )
            }
        }
        thread.name = "sharenet-link-handshake"
        thread.start()
    }

    /// Runs on the delivery queue.
    private func finishLinkHandshake(
        endpoint: EndpointID,
        transport: NWLinkTransport,
        result: Result<EstablishedLink, TransportError>,
        completion: (Result<AuthenticatedLink, TransportError>) -> Void
    ) {
        switch result {
        case .failure(let error):
            teardownFailedHandshake(endpoint: endpoint, transport: transport, error: error)
            completion(.failure(error))
        case .success(let established):
            do {
                // REQUESTED → CONNECTED (outbound) or ACCEPTED → CONNECTED
                // (inbound): only after the R3-001 handshake completed.
                try tracker.onConnectionAccepted(endpoint)
            } catch {
                // A stop()/disconnect raced the handshake — fail closed.
                transport.cancel()
                completion(.failure(error))
                return
            }
            let link = AuthenticatedLink(
                established: established,
                transport: transport,
                frameSink: { [weak self] frame in
                    self?.deliverFrame(frame, from: endpoint)
                },
                failureSink: { [weak self] failure in
                    guard let self else { return }
                    self.queue.async {
                        self.handleLinkFailure(endpoint, failure)
                    }
                }
            )
            lock.lock()
            links[endpoint] = LinkEntry(link: link, transport: transport)
            lock.unlock()

            transport.setReceiveHandler { [weak self] incoming in
                guard let self else { return }
                switch incoming {
                case .success(let frame):
                    if let entry = self.linkEntry(for: endpoint) {
                        entry.link.handleIncoming(frame)
                    }
                case .failure(let error):
                    self.queue.async {
                        self.handleLinkFailure(endpoint, error)
                    }
                }
            }

            emit(.connected(endpoint))
            completion(.success(link))
        }
    }

    /// Runs on the delivery queue.
    private func teardownFailedHandshake(
        endpoint: EndpointID,
        transport: NWLinkTransport,
        error: TransportError
    ) {
        transport.cancel()
        // The endpoint may already be gone (stop()/teardown raced) — the
        // tracker's strictness is enforced where it matters, tolerated here.
        try? tracker.onConnectionRejected(endpoint)
        let reason: DisconnectReason
        if case .connectionRejected = error {
            reason = .rejected
        } else {
            reason = .error
        }
        emit(.disconnected(endpoint, reason: reason))
    }

    /// Runs on the delivery queue. Terminal for the endpoint's link: a link
    /// is never resurrected on the same connection (L014).
    private func handleLinkFailure(_ endpoint: EndpointID, _ error: TransportError) {
        lock.lock()
        let entry = links.removeValue(forKey: endpoint)
        lock.unlock()
        guard let entry else { return }
        entry.link.terminate()
        entry.transport.cancel()
        try? tracker.onDisconnected(endpoint)
        let reason: DisconnectReason
        if case .connectionClosed = error {
            reason = .peer
        } else {
            reason = .error
        }
        emit(.disconnected(endpoint, reason: reason))
    }

    /// An inbound connection arrived (on the delivery queue via the
    /// listener).
    private func handleInbound(_ connection: NWConnection) {
        // Endpoint ids are transport-opaque: the listener hands no peer
        // identifier at accept time, so a locally minted id carries the
        // pending connection (the authenticated identity arrives with the
        // established R3-001 link).
        let endpoint = EndpointID("inbound-\(UUID().uuidString)")
        lock.lock()
        let stopped = self.stopped
        if !stopped {
            pendingInbound[endpoint] = connection
        }
        lock.unlock()
        guard !stopped else {
            connection.cancel()
            return
        }
        do {
            try tracker.onConnectionRequested(endpoint)
        } catch {
            lock.lock()
            pendingInbound.removeValue(forKey: endpoint)
            lock.unlock()
            connection.cancel()
            return
        }
        emit(.connectionRequested(endpoint))
    }

    /// Runs on the delivery queue.
    private func handleBrowserEvent(_ event: BonjourBrowser.Event) {
        switch event {
        case .ready:
            break
        case .discovered(let endpoint, let name):
            emit(.discovered(endpoint, name: name))
        case .lost(let endpoint):
            // Mirror of the Android contract: a merely-discovered endpoint
            // disappearing surfaces as Disconnected(.peer). An ESTABLISHED
            // link is NOT torn down — an expired Bonjour record does not
            // kill a TCP connection (documented deviation from GMS endpoint
            // semantics, recorded in the README).
            lock.lock()
            let hasLink = links[endpoint] != nil
            lock.unlock()
            if !hasLink {
                emit(.disconnected(endpoint, reason: .peer))
            }
        case .failed(let detail):
            // The browse stack died; browsing state rolls back and the
            // failure surfaces through the diagnostic health sink (no
            // contract event exists for transport-internal failures — the
            // same gap the Android contract fills with logs).
            lock.lock()
            browser = nil
            lock.unlock()
            try? tracker.stopDiscovery()
            onTransportHealth?(TransportError.bonjourUnavailable(detail))
        }
    }

    /// Runs on the delivery queue.
    private func handleAdvertiserEvent(_ event: BonjourAdvertiser.Event) {
        switch event {
        case .advertising:
            break
        case .registration:
            // Diagnostics only (e.g. mDNSResponder renamed us after a
            // collision).
            break
        case .failed(let detail):
            lock.lock()
            advertiser = nil
            lock.unlock()
            try? tracker.stopAdvertising()
            onTransportHealth?(TransportError.bonjourUnavailable(detail))
        }
    }

    // MARK: Delivery helpers

    private func linkEntry(for endpoint: EndpointID) -> LinkEntry? {
        lock.lock(); defer { lock.unlock() }
        return links[endpoint]
    }

    private func emit(_ event: TransportEvent) {
        lock.lock()
        let stopped = self.stopped
        let listeners = self.listeners
        if !stopped {
            eventsContinuation?.yield(event)
        }
        lock.unlock()
        guard !stopped else { return }
        queue.async {
            for listener in listeners {
                listener.transport(self, didReceive: event)
            }
        }
    }

    private func deliverFrame(_ frame: TransportFrame, from endpoint: EndpointID) {
        lock.lock()
        let stopped = self.stopped
        let listeners = self.listeners
        lock.unlock()
        guard !stopped else { return }
        queue.async {
            for listener in listeners {
                listener.transport(self, didReceiveFrame: frame, from: endpoint)
            }
        }
    }
}
