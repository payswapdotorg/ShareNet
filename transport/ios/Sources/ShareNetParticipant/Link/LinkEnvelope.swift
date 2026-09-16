import Foundation

/// The adapter-level channel envelope: every plaintext payload above the
/// authenticated-link layer rides as
///
/// ```text
/// u64be channelID || payloadBytes
/// ```
///
/// This is the convention the Android `nearby` module established for
/// platforms whose wire payloads carry no channel metadata
/// (`PayloadPolicy.kt`: `u64be channelId || payload` — adapter-level framing,
/// NOT protocol semantics). The iOS participant applies the same envelope so
/// `TransportFrame` channels multiplex over one authenticated link, and the
/// sealed link payload stays channel-agnostic.
public enum LinkEnvelope {

    /// The channel id prefix width in bytes (u64 big-endian).
    public static let channelIDBytes = 8

    /// Wrap a channel id and payload into the envelope bytes (these are the
    /// bytes handed to `LinkSession.seal`).
    public static func encode(channelID: UInt64, payload: Data) -> Data {
        var envelope = Data(capacity: channelIDBytes + payload.count)
        envelope.append(UInt8((channelID >> 56) & 0xFF))
        envelope.append(UInt8((channelID >> 48) & 0xFF))
        envelope.append(UInt8((channelID >> 40) & 0xFF))
        envelope.append(UInt8((channelID >> 32) & 0xFF))
        envelope.append(UInt8((channelID >> 24) & 0xFF))
        envelope.append(UInt8((channelID >> 16) & 0xFF))
        envelope.append(UInt8((channelID >> 8) & 0xFF))
        envelope.append(UInt8(channelID & 0xFF))
        envelope.append(payload)
        return envelope
    }

    /// Parse envelope bytes into (channel id, payload).
    ///
    /// - Throws: `TransportError.malformedMessage` when the envelope is
    ///   shorter than the 8-byte channel id. The adapter DROPS AND COUNTS
    ///   malformed envelopes (the link stays up); it never tears a session
    ///   down for a bad envelope.
    public static func decode(_ envelope: Data) throws -> (channelID: UInt64, payload: Data) {
        guard envelope.count >= channelIDBytes else {
            throw TransportError.malformedMessage(
                "envelope of \(envelope.count) bytes is shorter than the \(channelIDBytes)-byte channel id"
            )
        }
        let start = envelope.startIndex
        var channelID: UInt64 = 0
        for offset in 0..<channelIDBytes {
            channelID = (channelID << 8) | UInt64(envelope[start + offset])
        }
        let payload = envelope.subdata(in: (start + channelIDBytes)..<envelope.endIndex)
        return (channelID, payload)
    }
}
