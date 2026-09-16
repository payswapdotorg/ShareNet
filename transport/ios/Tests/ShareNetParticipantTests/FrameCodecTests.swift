import XCTest
@testable import ShareNetParticipant

/// Frame I/O: the 4-byte big-endian length-prefixed frame convention
/// (`FrameCodec`/`FrameDecoder`) — the convention shared with the QUIC
/// tunnel session (u32 BE, 2 MiB enforced on BOTH sides) and the Android VPN
/// pipe.
final class FrameCodecTests: XCTestCase {

    func testEncodeProducesBigEndianLengthPrefix() throws {
        let payload = Data([0xAA, 0xBB, 0xCC])
        let wire = try FrameCodec.encode(payload)
        XCTAssertEqual(Array(wire.prefix(4)), [0x00, 0x00, 0x00, 0x03])
        XCTAssertEqual(Array(wire.dropFirst(4)), [0xAA, 0xBB, 0xCC])
    }

    func testEncodeRejectsOversizedPayload() {
        let oversized = Data(repeating: 0x01, count: 9)
        XCTAssertThrowsError(try FrameCodec.encode(oversized, maxFrameBytes: 8)) { error in
            XCTAssertEqual(
                error as? TransportError,
                .frameTooLarge(length: 9, maximum: 8)
            )
        }
    }

    func testRoundTripSingleFrame() throws {
        let payload = Data("sharenet-link-frame".utf8)
        let wire = try FrameCodec.encode(payload)
        let decoder = FrameDecoder()
        let frames = try decoder.feed(wire)
        XCTAssertEqual(frames, [payload])
        XCTAssertEqual(decoder.pendingBytes, 0)
    }

    func testDecoderAssemblesFramesFedByteByByte() throws {
        let payload = Data((0..<64).map { UInt8($0 % 251) })
        let wire = try FrameCodec.encode(payload)
        let decoder = FrameDecoder()
        var frames: [Data] = []
        for byte in wire {
            frames.append(contentsOf: try decoder.feed(Data([byte])))
        }
        XCTAssertEqual(frames, [payload])
        XCTAssertEqual(decoder.pendingBytes, 0)
    }

    func testDecoderHandlesMultipleFramesInOneFeed() throws {
        let first = Data([0x01, 0x02])
        let second = Data([0x03])
        let wire = try FrameCodec.encode(first) + FrameCodec.encode(second)
        let decoder = FrameDecoder()
        let frames = try decoder.feed(wire)
        XCTAssertEqual(frames, [first, second])
    }

    func testDecoderRejectsOversizedClaimWithoutBuffering() throws {
        // A hostile 0xFFFFFFFF length prefix must be refused before any
        // buffering (the tunnel's adversarial receive-limit rule).
        let hostile = Data([0xFF, 0xFF, 0xFF, 0xFF])
        let decoder = FrameDecoder(maxFrameBytes: 16)
        XCTAssertThrowsError(try decoder.feed(hostile)) { error in
            XCTAssertEqual(
                error as? TransportError,
                .frameTooLarge(length: 0xFFFFFFFF, maximum: 16)
            )
        }
        XCTAssertEqual(decoder.pendingBytes, 0)
    }

    func testDecoderAcceptsZeroLengthFrame() throws {
        let wire = try FrameCodec.encode(Data())
        let decoder = FrameDecoder()
        let frames = try decoder.feed(wire)
        XCTAssertEqual(frames.count, 1)
        XCTAssertEqual(frames[0].count, 0)
    }

    func testDecoderBoundaryAtExactLimit() throws {
        let atLimit = Data(repeating: 0x09, count: 16)
        let decoder = FrameDecoder(maxFrameBytes: 16)
        let frames = try decoder.feed(try FrameCodec.encode(atLimit, maxFrameBytes: 16))
        XCTAssertEqual(frames, [atLimit])

        XCTAssertThrowsError(try FrameCodec.encode(Data(repeating: 0x09, count: 17), maxFrameBytes: 16))
    }

    func testDecoderPendingBytesAccounting() throws {
        let decoder = FrameDecoder()
        // A 3-byte payload needs 4 + 3 = 7 wire bytes.
        let wire = try FrameCodec.encode(Data([1, 2, 3]))
        _ = try decoder.feed(wire.prefix(4))
        XCTAssertEqual(decoder.pendingBytes, 4, "partial prefix is pending")
        _ = try decoder.feed(wire.dropFirst(4))
        XCTAssertEqual(decoder.pendingBytes, 0)
    }

    func testDefaultMaxFrameMatchesTunnelConvention() {
        // 2 MiB — the same constant as transport/quic's MAX_FRAME.
        XCTAssertEqual(FrameCodec.defaultMaxFrameBytes, 2 * 1024 * 1024)
    }
}
