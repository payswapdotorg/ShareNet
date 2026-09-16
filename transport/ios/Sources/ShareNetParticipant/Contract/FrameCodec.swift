import Foundation

/// The 4-byte big-endian length-prefixed frame convention used across the
/// ShareNet transport adapters: every wire unit on a stream transport is
///
/// ```text
/// u32be payloadLength || payloadBytes
/// ```
///
/// This is the exact convention of the QUIC tunnel session
/// (`transport/quic` `TunnelStream`: u32 BE prefix, `MAX_FRAME` = 2 MiB
/// enforced on BOTH sides) and of the Android VPN test pipe
/// (`transport/android/vpn` `PacketPipe`). The iOS participant uses the same
/// convention over `NWConnection` so a link frame or handshake message rides
/// as one length-prefixed unit over the byte stream.
///
/// Oversized frames are rejected BEFORE any buffering (`frameTooLarge`):
/// a receiver never buffers a claimed 4 GiB frame, exactly like the tunnel's
/// adversarial receive-limit rule.
public enum FrameCodec {

    /// The length prefix width in bytes (u32 big-endian).
    public static let lengthPrefixBytes = 4

    /// The default frame bound: 2 MiB, the same constant as the QUIC tunnel's
    /// `MAX_FRAME` (`transport/quic/src/lib.rs`), enforced on both sides.
    public static let defaultMaxFrameBytes = 2 * 1024 * 1024

    /// Encode one payload into its length-prefixed wire form.
    ///
    /// - Throws: `TransportError.frameTooLarge` when `payload` exceeds
    ///   `maxFrameBytes`; `TransportError.illegalState` for a misconfigured
    ///   bound.
    public static func encode(
        _ payload: Data,
        maxFrameBytes: Int = FrameCodec.defaultMaxFrameBytes
    ) throws -> Data {
        guard maxFrameBytes >= 0 else {
            throw TransportError.illegalState("maxFrameBytes must be non-negative (got \(maxFrameBytes))")
        }
        guard payload.count <= maxFrameBytes else {
            throw TransportError.frameTooLarge(length: payload.count, maximum: maxFrameBytes)
        }
        var wire = Data(capacity: lengthPrefixBytes + payload.count)
        let count = payload.count
        wire.append(UInt8((count >> 24) & 0xFF))
        wire.append(UInt8((count >> 16) & 0xFF))
        wire.append(UInt8((count >> 8) & 0xFF))
        wire.append(UInt8(count & 0xFF))
        wire.append(payload)
        return wire
    }
}

/// Incremental decoder for the length-prefixed framing: feed it raw stream
/// bytes in any chunking; it emits complete frames as they assemble.
///
/// Pure logic — no I/O, no platform types — so it is unit-testable on any
/// host that can run Swift. Fail-closed rule: a length prefix that claims
/// more than `maxFrameBytes` is a protocol violation the caller cannot
/// recover from (the stream is desynchronized); the decoder resets its
/// buffer and throws `frameTooLarge`, and the caller must drop the
/// connection.
public final class FrameDecoder {

    /// The frame bound this decoder enforces on every claimed length.
    public let maxFrameBytes: Int

    private var buffer = Data()
    private var consumed = 0

    public init(maxFrameBytes: Int = FrameCodec.defaultMaxFrameBytes) {
        self.maxFrameBytes = maxFrameBytes
    }

    /// Bytes currently buffered while a frame is still assembling.
    public var pendingBytes: Int {
        buffer.count - consumed
    }

    /// Feed raw bytes; returns the complete frames that became available
    /// (in order). Partial input stays buffered for the next feed.
    ///
    /// - Throws: `TransportError.frameTooLarge` when a claimed length exceeds
    ///   `maxFrameBytes` (decoder state is reset; the caller drops the
    ///   connection); `TransportError.illegalState` for a misconfigured
    ///   bound.
    public func feed(_ bytes: Data) throws -> [Data] {
        guard maxFrameBytes >= 0 else {
            throw TransportError.illegalState("maxFrameBytes must be non-negative (got \(maxFrameBytes))")
        }
        compact()
        buffer.append(bytes)
        var frames: [Data] = []
        while pendingBytes >= FrameCodec.lengthPrefixBytes {
            let length = prefixLength()
            guard length <= maxFrameBytes else {
                buffer = Data()
                consumed = 0
                throw TransportError.frameTooLarge(length: length, maximum: maxFrameBytes)
            }
            let totalLength = FrameCodec.lengthPrefixBytes + length
            guard pendingBytes >= totalLength else {
                break
            }
            let start = buffer.startIndex + consumed
            frames.append(
                buffer.subdata(in: (start + FrameCodec.lengthPrefixBytes)..<(start + totalLength))
            )
            consumed += totalLength
        }
        compact()
        return frames
    }

    /// Reads the u32 big-endian prefix at the current head. MUST be called
    /// only when at least `FrameCodec.lengthPrefixBytes` bytes are pending.
    private func prefixLength() -> Int {
        let start = buffer.startIndex + consumed
        let b0 = UInt32(buffer[start])
        let b1 = UInt32(buffer[start + 1])
        let b2 = UInt32(buffer[start + 2])
        let b3 = UInt32(buffer[start + 3])
        return Int(b0 << 24 | b1 << 16 | b2 << 8 | b3)
    }

    /// Drops already-consumed head bytes so `buffer` stays proportional to
    /// the actually-pending tail.
    private func compact() {
        guard consumed > 0 else { return }
        buffer.removeFirst(consumed)
        consumed = 0
    }
}
