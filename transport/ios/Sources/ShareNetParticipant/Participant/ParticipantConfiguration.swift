import Foundation

/// Configuration for the `NWParticipantTransport` adapter. Validated at
/// construction — a misconfigured bound fails with a typed
/// `TransportError.illegalState`, never a crash.
public struct ParticipantConfiguration {

    /// The Bonjour service type the participant advertises and browses.
    ///
    /// Platform-level discovery vocabulary (like the Android module's
    /// Nearby strategy), NOT a protocol-registry wire object: the registered
    /// ShareNet wire objects live in `spec/protocol-registry.yaml` and this
    /// adds none.
    ///
    /// `_sharenet._tcp` requires `_sharenet._tcp` to be listed in the
    /// embedding app's `NSBonjourServices` Info.plist array on iOS 14+.
    public static let defaultServiceType = "_sharenet._tcp"

    /// The service type (must look like `_name._tcp`/`_name._udp`).
    public let serviceType: String

    /// The Bonjour registration domain (`nil` → the platform's default
    /// domains, `.local` among them).
    public let serviceDomain: String?

    /// Include peer-to-peer (AWDL) interfaces in advertising, browsing and
    /// connections — the Network.framework equivalent of the architecture's
    /// "peer-to-peer Wi-Fi where available" (spec/architecture.md §7 Apple).
    public let includePeerToPeer: Bool

    /// The frame bound for the length-prefixed framing (both directions).
    /// Defaults to `FrameCodec.defaultMaxFrameBytes` (2 MiB — the QUIC
    /// tunnel's `MAX_FRAME` convention, enforced on BOTH sides).
    public let maxFrameBytes: Int

    /// The bounded send window per link.
    public let sendWindowLimits: SendWindow.Limits

    /// The overall R3-001 handshake deadline per link attempt.
    public let handshakeTimeout: TimeInterval

    /// How long an outbound `NWConnection` may take to become ready.
    public let connectionTimeout: TimeInterval

    /// - Throws: `TransportError.illegalState` on a non-positive service
    ///   type, non-positive bounds, or non-positive timeouts.
    public init(
        serviceType: String = ParticipantConfiguration.defaultServiceType,
        serviceDomain: String? = nil,
        includePeerToPeer: Bool = true,
        maxFrameBytes: Int = FrameCodec.defaultMaxFrameBytes,
        sendWindowLimits: SendWindow.Limits = .standard,
        handshakeTimeout: TimeInterval = 10.0,
        connectionTimeout: TimeInterval = 10.0
    ) throws {
        guard !serviceType.isEmpty else {
            throw TransportError.illegalState("serviceType must not be empty")
        }
        guard maxFrameBytes >= 0 else {
            throw TransportError.illegalState("maxFrameBytes must be non-negative (got \(maxFrameBytes))")
        }
        guard handshakeTimeout > 0 else {
            throw TransportError.illegalState("handshakeTimeout must be positive (got \(handshakeTimeout))")
        }
        guard connectionTimeout > 0 else {
            throw TransportError.illegalState("connectionTimeout must be positive (got \(connectionTimeout))")
        }
        self.serviceType = serviceType
        self.serviceDomain = serviceDomain
        self.includePeerToPeer = includePeerToPeer
        self.maxFrameBytes = maxFrameBytes
        self.sendWindowLimits = sendWindowLimits
        self.handshakeTimeout = handshakeTimeout
        self.connectionTimeout = connectionTimeout
    }
}
