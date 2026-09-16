import Foundation

/// Identifier of a remote endpoint as presented by the local transport.
///
/// Opaque at the contract level: transports are free to derive it from their
/// platform identifiers (a Bonjour service name for outbound links on iOS,
/// a locally minted pending-connection id for inbound links, Nearby endpoint
/// ids on Android). It carries NO ShareNet protocol identity — authenticated
/// link identity is protocol-core scope (R3-001), not transport scope.
///
/// Swift mirror of the Android `contract` module's `EndpointId`
/// (`transport/android/contract/.../EndpointId.kt`).
public struct EndpointID: Hashable, CustomStringConvertible, Sendable {

    /// The platform-derived opaque value (never empty in practice; the
    /// transport owns its own minting discipline).
    public let value: String

    public init(_ value: String) {
        self.value = value
    }

    public var description: String { value }
}
