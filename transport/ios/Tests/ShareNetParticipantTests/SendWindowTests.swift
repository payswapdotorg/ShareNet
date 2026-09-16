import XCTest
@testable import ShareNetParticipant

/// Backpressure: the bounded send window (`SendWindow`) — typed refusal when
/// full, defensive over-release, aggregate accounting.
final class SendWindowTests: XCTestCase {

    func testAcquireReleaseAccounting() throws {
        let window = SendWindow(limits: try .init(maxInFlightBytes: 100, maxInFlightFrames: 10))
        try window.tryAcquire(frameBytes: 60)
        XCTAssertEqual(window.currentInFlightBytes, 60)
        XCTAssertEqual(window.currentInFlightFrames, 1)
        try window.tryAcquire(frameBytes: 40)
        XCTAssertEqual(window.currentInFlightBytes, 100)
        window.release(frameBytes: 60)
        XCTAssertEqual(window.currentInFlightBytes, 40)
        XCTAssertEqual(window.availableBytes, 60)
        window.release(frameBytes: 40)
        XCTAssertEqual(window.currentInFlightFrames, 0)
    }

    func testExhaustionThrowsTypedRefusal() throws {
        let window = SendWindow(limits: try .init(maxInFlightBytes: 100, maxInFlightFrames: 10))
        try window.tryAcquire(frameBytes: 100)
        XCTAssertThrowsError(try window.tryAcquire(frameBytes: 1)) { error in
            XCTAssertEqual(
                error as? TransportError,
                .sendWindowExhausted(inFlightBytes: 100, maximumBytes: 100)
            )
        }
        XCTAssertEqual(window.exhaustionCount, 1)
        // Capacity restored by release → the identical acquire succeeds.
        window.release(frameBytes: 100)
        XCTAssertNoThrow(try window.tryAcquire(frameBytes: 1))
        XCTAssertEqual(window.exhaustionCount, 1)
    }

    func testSingleFrameLargerThanWholeWindowIsRejected() throws {
        let window = SendWindow(limits: try .init(maxInFlightBytes: 100, maxInFlightFrames: 10))
        XCTAssertThrowsError(try window.tryAcquire(frameBytes: 101)) { error in
            XCTAssertEqual(error as? TransportError, .frameTooLarge(length: 101, maximum: 100))
        }
        // The refusal did not consume state.
        XCTAssertEqual(window.currentInFlightBytes, 0)
    }

    func testFrameCountCapIndependentlyBinds() throws {
        let window = SendWindow(limits: try .init(maxInFlightBytes: 10_000, maxInFlightFrames: 3))
        try window.tryAcquire(frameBytes: 1)
        try window.tryAcquire(frameBytes: 1)
        try window.tryAcquire(frameBytes: 1)
        // Bytes available, but no frame slots.
        XCTAssertThrowsError(try window.tryAcquire(frameBytes: 1)) { error in
            guard case .sendWindowExhausted = error else {
                return XCTFail("expected sendWindowExhausted, got \(error)")
            }
        }
        window.release(frameBytes: 1)
        XCTAssertNoThrow(try window.tryAcquire(frameBytes: 1))
    }

    func testOverReleaseClampsAndCountsNeverCrashes() throws {
        let window = SendWindow(limits: try .init(maxInFlightBytes: 100, maxInFlightFrames: 10))
        try window.tryAcquire(frameBytes: 50)
        window.release(frameBytes: 50)
        XCTAssertEqual(window.overReleaseCount, 0)
        // A duplicate release with nothing in flight: clamped, counted.
        window.release(frameBytes: 50)
        XCTAssertEqual(window.overReleaseCount, 1)
        XCTAssertEqual(window.currentInFlightBytes, 0)
        XCTAssertEqual(window.currentInFlightFrames, 0)
    }

    func testNegativeFrameBytesRefused() throws {
        let window = SendWindow(limits: try .init(maxInFlightBytes: 100, maxInFlightFrames: 10))
        XCTAssertThrowsError(try window.tryAcquire(frameBytes: -1)) { error in
            guard case .illegalState = error else {
                return XCTFail("expected illegalState, got \(error)")
            }
        }
    }

    func testLimitsValidationIsTyped() {
        XCTAssertThrowsError(try SendWindow.Limits(maxInFlightBytes: 0, maxInFlightFrames: 10)) { error in
            guard case .illegalState = error else {
                return XCTFail("expected illegalState, got \(error)")
            }
        }
        XCTAssertThrowsError(try SendWindow.Limits(maxInFlightBytes: 10, maxInFlightFrames: 0)) { error in
            guard case .illegalState = error else {
                return XCTFail("expected illegalState, got \(error)")
            }
        }
    }

    func testConcurrentAcquiresNeverExceedTheBound() throws {
        // Hammer the window from many threads WITHOUT releases: the total
        // admitted bytes must never exceed the bound, and every admission is
        // accounted. (Deterministic outcome; the interleaving is not.)
        let window = SendWindow(limits: try .init(maxInFlightBytes: 10_000, maxInFlightFrames: .max / 2))
        let admitted = LockedBox<Int>()
        admitted.set(0)
        let workerCount = 16
        let acquisitionsPerWorker = 500
        DispatchQueue.concurrentPerform(iterations: workerCount) { worker in
            for _ in 0..<acquisitionsPerWorker {
                let size = 1 + (worker % 7)
                do {
                    try window.tryAcquire(frameBytes: size)
                    admitted.update(default: 0) { total in total += size }
                } catch {
                    // Window full — the typed backpressure refusal.
                }
            }
        }
        let totalAdmitted = admitted.get() ?? 0
        XCTAssertLessThanOrEqual(totalAdmitted, 10_000)
        XCTAssertEqual(window.currentInFlightBytes, totalAdmitted)
    }
}
