// Platform guard: Network.framework exists only on Apple platforms, so this
// whole file (the Network adapter layer) compiles only where it exists. On
// macOS/iOS `canImport(Network)` is always true and the file compiles exactly
// as authored; on Linux it contributes nothing, keeping the pure-Foundation
// Contract/Link layers buildable and testable (`swift test`). Executing the
// Network layer itself still requires Apple hardware (the recorded R9-001
// honest gap).
#if canImport(Network)
import Foundation
import Network

/// Discovery plane: browse for ShareNet participants over Bonjour/mDNS with
/// `NWBrowser` — the iOS analog of the Android `nearby` module's discovery
/// role (architecture §3: discovery belongs to the control plane; §7 Apple:
/// Network.framework, not Multipeer Connectivity).
///
/// This class is the ONLY place that touches `NWBrowser` types; it maps
/// browse results into contract types (`EndpointID`, discovered/lost events)
/// and keeps the resolved `NWEndpoint` per endpoint id so the owner can
/// connect outbound. Platform failures are classified into
/// `TransportError.bonjourUnavailable`.
///
/// Threading: Bonjour callbacks arrive on the provided serial queue; events
/// are delivered on that queue. State is lock-protected.
final class BonjourBrowser {

    /// What the browse surface reports to the owner.
    enum Event {
        /// Browsing is up and results may start arriving.
        case ready
        /// A ShareNet service appeared (endpoint id = its advertised name).
        case discovered(EndpointID, name: String)
        /// A previously-seen service disappeared (the owner surfaces this as
        /// a `TransportEvent.disconnected(reason: .peer)` for not-yet-
        /// connected endpoints, mirroring the Android contract).
        case lost(EndpointID)
        /// Browsing failed terminally (mapped to
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
    private let onEvent: (Event) -> Void
    private let lock = NSLock()
    private var browser: NWBrowser?
    private var browsing = false
    private var endpoints: [EndpointID: NWEndpoint] = [:]

    init(configuration: Configuration, queue: DispatchQueue, onEvent: @escaping (Event) -> Void) {
        self.configuration = configuration
        self.queue = queue
        self.onEvent = onEvent
    }

    /// True while browsing is active.
    var isBrowsing: Bool {
        lock.lock(); defer { lock.unlock() }
        return browsing
    }

    /// The resolved endpoint for a discovered id (for outbound connects);
    /// `nil` when unknown or after browsing stopped.
    func endpoint(for id: EndpointID) -> NWEndpoint? {
        lock.lock(); defer { lock.unlock() }
        return endpoints[id]
    }

    /// Start browsing.
    ///
    /// - Throws: `TransportError.illegalState` if already browsing.
    func start() throws {
        lock.lock()
        if browsing {
            lock.unlock()
            throw TransportError.illegalState("already browsing")
        }
        lock.unlock()

        let parameters = NWParameters()
        parameters.includePeerToPeer = configuration.includePeerToPeer
        let browser = NWBrowser(
            for: .bonjour(type: configuration.serviceType, domain: configuration.serviceDomain),
            using: parameters
        )

        browser.browseResultsChangedHandler = { [weak self] _, changed in
            guard let self else { return }
            for change in changed {
                switch change {
                case .added(let result):
                    self.handleResult(result, added: true)
                case .removed(let result):
                    self.handleResult(result, added: false)
                default:
                    // `.identical` / `.changed` (metadata refresh): no
                    // discovery-lifecycle effect.
                    break
                }
            }
        }

        browser.stateUpdateHandler = { [weak self] state in
            guard let self else { return }
            switch state {
            case .ready:
                self.onEvent(.ready)
            case .failed(let error):
                self.onEvent(.failed(String(describing: error)))
            default:
                // `.setup`/`.preparing` are transitional; `.waiting` is the
                // Local-Network-permission-pending state on iOS 14+ — it is
                // deliberately NOT surfaced (the app observes via logs and
                // the Local Network prompt).
                break
            }
        }

        lock.lock()
        self.browser = browser
        browsing = true
        lock.unlock()
        browser.start(queue: queue)
    }

    /// Stop browsing (idempotent, never throws). Resolved endpoints are
    /// dropped.
    func cancel() {
        lock.lock()
        let browser = self.browser
        self.browser = nil
        browsing = false
        endpoints.removeAll()
        lock.unlock()
        browser?.cancel()
    }

    private func handleResult(_ result: NWBrowser.Result, added: Bool) {
        let name = Self.serviceName(of: result.endpoint)
        // A Bonjour service endpoint without a resolvable name cannot be
        // addressed; ignore it (defensive, counted nowhere — results like
        // these do not occur for `.bonjour` descriptors in practice).
        guard let name, !name.isEmpty else { return }
        let id = EndpointID(name)
        if added {
            lock.lock()
            endpoints[id] = result.endpoint
            lock.unlock()
            onEvent(.discovered(id, name: name))
        } else {
            lock.lock()
            endpoints.removeValue(forKey: id)
            lock.unlock()
            onEvent(.lost(id))
        }
    }

    /// The advertised service name of a Bonjour endpoint, when the endpoint
    /// is a service (`.service(name:type:domain:interface:)`).
    private static func serviceName(of endpoint: NWEndpoint) -> String? {
        if case let .service(name, _, _, _) = endpoint {
            return name
        }
        return nil
    }
}

#endif  // canImport(Network)
