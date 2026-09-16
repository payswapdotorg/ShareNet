import Foundation

/// Bounded outbound backpressure for a link's send path (pure logic).
///
/// `NWConnection.send` is asynchronous: without a bound, a producer faster
/// than the network buffers without limit. The send window caps BOTH the
/// bytes and the count of frames handed to the platform but not yet
/// processed by the send completion. When the window is full the send path
/// fails with a TYPED refusal — `TransportError.sendWindowExhausted` — the
/// ShareNet discipline of visible, bounded state: the caller backs off and
/// retries; nothing buffers without bound and nothing blocks a cooperative
/// thread.
///
/// `tryAcquire`/`release` are aggregate operations (an acquire pairs with
/// exactly one release of the same byte count); a defensive over-release
/// clamps at zero and is counted (`overReleaseCount`), it never crashes the
/// library path.
///
/// Thread-safe (internal lock). This window is the TRANSPORT-level
/// backpressure; the R3-001 replay window (sequence-number protection inside
/// `LinkSession`) is protocol-core semantics and deliberately NOT duplicated
/// here.
public final class SendWindow {

    /// Window bounds, validated at construction.
    public struct Limits {

        /// Maximum bytes handed to the platform with send completions
        /// outstanding.
        public let maxInFlightBytes: Int

        /// Maximum frames handed to the platform with send completions
        /// outstanding.
        public let maxInFlightFrames: Int

        /// The standard participant window: 256 KiB / 64 frames in flight.
        /// (`try!` is statically safe: the literals satisfy the invariants.)
        public static let standard = try! Limits(maxInFlightBytes: 256 * 1024, maxInFlightFrames: 64)

        /// - Throws: `TransportError.illegalState` when either bound is not
        ///   positive.
        public init(maxInFlightBytes: Int, maxInFlightFrames: Int) throws {
            guard maxInFlightBytes > 0 else {
                throw TransportError.illegalState("maxInFlightBytes must be positive (got \(maxInFlightBytes))")
            }
            guard maxInFlightFrames > 0 else {
                throw TransportError.illegalState("maxInFlightFrames must be positive (got \(maxInFlightFrames))")
            }
            self.maxInFlightBytes = maxInFlightBytes
            self.maxInFlightFrames = maxInFlightFrames
        }
    }

    private let lock = NSLock()
    private let limits: Limits
    private var inFlightBytes = 0
    private var inFlightFrames = 0
    private var exhaustionCount = 0
    private var overReleaseCount = 0

    public init(limits: Limits) {
        self.limits = limits
    }

    /// Bytes currently in flight (admitted, not yet released).
    public var currentInFlightBytes: Int {
        lock.lock(); defer { lock.unlock() }
        return inFlightBytes
    }

    /// Frames currently in flight (admitted, not yet released).
    public var currentInFlightFrames: Int {
        lock.lock(); defer { lock.unlock() }
        return inFlightFrames
    }

    /// How many times the window refused a send because it was full.
    public var exhaustionCount: Int {
        lock.lock(); defer { lock.unlock() }
        return exhaustionCount
    }

    /// How many releases arrived with nothing in flight (defensive
    /// diagnostics — should stay zero in a correct pairing).
    public var overReleaseCount: Int {
        lock.lock(); defer { lock.unlock() }
        return overReleaseCount
    }

    /// Bytes still admissible at this instant.
    public var availableBytes: Int {
        lock.lock(); defer { lock.unlock() }
        return limits.maxInFlightBytes - inFlightBytes
    }

    /// Frame slots still admissible at this instant.
    public var availableFrameSlots: Int {
        lock.lock(); defer { lock.unlock() }
        return limits.maxInFlightFrames - inFlightFrames
    }

    /// Reserve one frame of `frameBytes` payload.
    ///
    /// - Throws: `TransportError.frameTooLarge` when a single frame cannot
    ///   ever fit the window; `TransportError.sendWindowExhausted` when the
    ///   window is currently full (backpressure — retry after completions).
    public func tryAcquire(frameBytes: Int) throws {
        guard frameBytes >= 0 else {
            throw TransportError.illegalState("frameBytes must be non-negative (got \(frameBytes))")
        }
        lock.lock(); defer { lock.unlock() }
        guard frameBytes <= limits.maxInFlightBytes else {
            throw TransportError.frameTooLarge(length: frameBytes, maximum: limits.maxInFlightBytes)
        }
        guard inFlightBytes + frameBytes <= limits.maxInFlightBytes,
              inFlightFrames + 1 <= limits.maxInFlightFrames else {
            exhaustionCount += 1
            throw TransportError.sendWindowExhausted(
                inFlightBytes: inFlightBytes,
                maximumBytes: limits.maxInFlightBytes
            )
        }
        inFlightBytes += frameBytes
        inFlightFrames += 1
    }

    /// Return one frame's reservation to the window. MUST be called exactly
    /// once per successful `tryAcquire` (from the send completion). A release
    /// with nothing in flight clamps at zero and is counted, never crashes.
    public func release(frameBytes: Int) {
        lock.lock(); defer { lock.unlock() }
        if inFlightBytes == 0 || inFlightFrames == 0 {
            overReleaseCount += 1
        }
        inFlightBytes = max(0, inFlightBytes - frameBytes)
        inFlightFrames = max(0, inFlightFrames - 1)
    }
}
