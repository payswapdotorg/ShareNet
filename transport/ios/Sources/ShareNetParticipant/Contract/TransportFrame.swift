import Foundation

/// One opaque payload plus a channel id — the unit of exchange above the
/// transport seam. Both control frames and bulk payloads of the underlying
/// platform map onto this type.
///
/// The payload is UNINTERPRETED at the transport layer — no protocol
/// semantics (identity/routing/crypto) live below this seam. The channel id
/// multiplexes logical streams over one platform connection; the wire
/// representation (`u64be channelId || payload`, the adapter-level envelope
/// the Android `nearby` module established) is applied above the
/// authenticated-link layer, not here.
///
/// Swift mirror of the Android `contract` module's `TransportFrame`.
public struct TransportFrame: Equatable, CustomStringConvertible {

    /// The logical channel this payload belongs to (non-negative by type).
    public let channelID: UInt64

    /// The opaque payload bytes.
    public let payload: Data

    public init(channelID: UInt64, payload: Data) {
        self.channelID = channelID
        self.payload = payload
    }

    public var payloadSize: Int { payload.count }

    public var description: String {
        "TransportFrame(channelID: \(channelID), payloadSize: \(payload.count))"
    }
}
