import Foundation
import Network

/// Advertising + inbound-accept plane: advertise the participant over
/// Bonjour with an `NWListener` — the iOS analog of the Android `nearby`
/// module's advertising role. Inbound TCP connections arrive through the
/// listener's `newConnectionHandler` and are handed to the owner, which
/// surfaces `connectionRequested` and runs the R3-001 responder handshake on
/// accept.
///
/// The listener binds plain TCP (`NWParameters.tcp`): the authenticated link
/// layer (R3-001) supplies authentication and confidentiality on the local
/// peer-to-peer leg — the same division as the Wave-1 UDP transport. TLS 1.3
/// belongs to the Internet-facing tunnel leg (§8), not the local link.
final class BonjourAdvertiser {

    enum Event {
        /// The listener is up and the service is advertised.
        case advertising
        /// The registered Bonjour endpoint (diagnostics; e.g. the resolved
        /// name when the requested name collided and mDNSResponder renamed).
        case registration(NWEndpoint)
        /// Advertising failed terminally (mapped to
        /// `TransportError.bonjourUnavailable` by the owner).
        case failed(String)
    }

    struct Configuration {
        let serviceType: String
        let serviceDomain: String?
        let includePeerToPeer: Bool
    }

    private let configuration: Configuration
    private let queue: DispatchQueue
    private let onAccept: (NWConnection) -> Void
    private let onEvent: (Event) -> Void
    private let lock = NSLock()
    private var listener: NWListener?
    private var advertising = false

    init(
        configuration: Configuration,
        queue: DispatchQueue,
        onAccept: @escaping (NWConnection) -> Void,
        onEvent: @escaping (Event) -> Void
    ) {
        self.configuration = configuration
        self.queue = queue
        self.onAccept = onAccept
        self.onEvent = onEvent
    }

    /// True while the advertisement is up.
    var isAdvertising: Bool {
        lock.lock(); defer { lock.unlock() }
        return advertising
    }

    /// Start advertising `name` and accepting inbound connections.
    ///
    /// - Throws: `TransportError.illegalState` if already advertising;
    ///   `TransportError.bonjourUnavailable` when the listener cannot be
    ///   created (e.g. no usable interfaces).
    func startAdvertising(name: String) throws {
        lock.lock()
        if advertising {
            lock.unlock()
            throw TransportError.illegalState("already advertising")
        }
        lock.unlock()

        let parameters = NWParameters.tcp
        parameters.includePeerToPeer = configuration.includePeerToPeer

        let listener: NWListener
        do {
            listener = try NWListener(using: parameters)
        } catch {
            throw TransportError.bonjourUnavailable(String(describing: error))
        }
        listener.service = NWListener.Service(
            name: name,
            type: configuration.serviceType,
            domain: configuration.serviceDomain
        )

        listener.newConnectionHandler = { [weak self] connection in
            self?.onAccept(connection)
        }

        listener.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.lock.lock()
                self.advertising = true
                self.lock.unlock()
                self.onEvent(.advertising)
            case .failed(let error):
                self.lock.lock()
                self.advertising = false
                self.lock.unlock()
                self.onEvent(.failed(String(describing: error)))
            default:
                // `.setup`/`.preparing` transitional; `.waiting` is
                // deliberately not surfaced (e.g. pending Local Network
                // permission); `.cancelled` follows stopAdvertising.
                break
            }
        }

        listener.serviceRegistrationUpdateHandler = { [weak self] endpoint in
            self?.onEvent(.registration(endpoint))
        }

        lock.lock()
        self.listener = listener
        lock.unlock()
        listener.start(queue: queue)
    }

    /// Stop advertising (idempotent, never throws). Established links are
    /// NOT touched — the owner owns them.
    func stopAdvertising() {
        lock.lock()
        let listener = self.listener
        self.listener = nil
        advertising = false
        lock.unlock()
        listener?.cancel()
    }
}
