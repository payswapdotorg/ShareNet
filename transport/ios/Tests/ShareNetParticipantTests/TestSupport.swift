import Foundation
@testable import ShareNetParticipant

// MARK: - In-memory FrameByteTransport pair
//
// The pipe-backed fake of the byte-frame transport boundary (the same seam
// trick as the Android modules' `PacketPipe`/`FakeNearbyApi`: the EXTERNAL
// boundary — here, the OS stream — is the only legitimate fake). Handshakes
// and frames cross between the two sides with real cross-thread blocking
// semantics, so the drivers under test exercise the same waiting paths the
// NWConnection adapter uses.

final class InMemoryFrameTransport: FrameByteTransport {

    private let lock = NSLock()
    private var incoming: [Data] = []
    private let signal = DispatchSemaphore(value: 0)
    private var cancelled = false
    private var handler: ((Result<Data, TransportError>) -> Void)?
    private var peer: InMemoryFrameTransport?
    private let sendWindow: SendWindow?

    /// - Parameter sendWindow: optional admission control so the typed
    ///   backpressure path is exercisable without the platform.
    init(sendWindow: SendWindow? = nil) {
        self.sendWindow = sendWindow
    }

    static func makePair(
        firstWindow: SendWindow? = nil,
        secondWindow: SendWindow? = nil
    ) -> (InMemoryFrameTransport, InMemoryFrameTransport) {
        let first = InMemoryFrameTransport(sendWindow: firstWindow)
        let second = InMemoryFrameTransport(sendWindow: secondWindow)
        first.peer = second
        second.peer = first
        return (first, second)
    }

    func send(_ frame: Data) throws {
        if let sendWindow {
            try sendWindow.tryAcquire(frameBytes: frame.count)
        }
        lock.lock()
        let cancelled = self.cancelled
        lock.unlock()
        if cancelled {
            if let sendWindow { sendWindow.release(frameBytes: frame.count) }
            throw TransportError.connectionClosed
        }
        guard let peer else {
            if let sendWindow { sendWindow.release(frameBytes: frame.count) }
            throw TransportError.connectionClosed
        }
        peer.deliver(frame)
        // The in-memory platform "processes" the send synchronously.
        if let sendWindow { sendWindow.release(frameBytes: frame.count) }
    }

    func receive(timeout: TimeInterval) throws -> Data? {
        lock.lock()
        if !incoming.isEmpty {
            let frame = incoming.removeFirst()
            lock.unlock()
            return frame
        }
        let cancelled = self.cancelled
        lock.unlock()
        if cancelled {
            throw TransportError.connectionClosed
        }

        let waitResult = signal.wait(timeout: .now() + timeout)
        if waitResult == .timedOut {
            return nil
        }

        lock.lock()
        defer { lock.unlock() }
        if !incoming.isEmpty {
            return incoming.removeFirst()
        }
        if cancelled {
            throw TransportError.connectionClosed
        }
        return nil
    }

    func setReceiveHandler(_ handler: ((Result<Data, TransportError>) -> Void)?) {
        lock.lock()
        self.handler = handler
        let buffered = incoming
        incoming = []
        lock.unlock()
        // Buffered frames flush in order, then live frames are delivered
        // synchronously on the sender's thread (mirroring the scripted-fake
        // discipline: immediately and synchronously).
        for frame in buffered {
            handler?(.success(frame))
        }
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let handler = self.handler
        lock.unlock()
        signal.signal()
        handler?(.failure(TransportError.connectionClosed))
    }

    /// Frames currently buffered (test assertions).
    var bufferedCount: Int {
        lock.lock(); defer { lock.unlock() }
        return incoming.count
    }

    private func deliver(_ frame: Data) {
        lock.lock()
        if let handler {
            lock.unlock()
            handler(.success(frame))
            return
        }
        incoming.append(frame)
        lock.unlock()
        signal.signal()
    }
}

// MARK: - Scripted handshake engines
//
// The handshake ENGINES are the protocol-core seam — the only legitimate
// fake. They emit fixed message bytes and record what the driver handed
// them, so the tests verify the TRANSPORT sequencing (ordering, deadlines,
// fail-closed), never cryptography (the real core is the Rust
// sharenet-protocol implementation).

final class ScriptedInitiatorEngine: LinkInitiatorEngine {

    private let lock = NSLock()
    private(set) var initiated = false
    private(set) var respondedTo: Data?
    let initiateMessage: Data
    let confirmMessage: Data
    let established: EstablishedLink
    var confirmHook: ((Data) throws -> Void)?

    init(initiateMessage: Data, confirmMessage: Data, established: EstablishedLink) {
        self.initiateMessage = initiateMessage
        self.confirmMessage = confirmMessage
        self.established = established
    }

    func initiate() throws -> Data {
        lock.lock(); defer { lock.unlock() }
        initiated = true
        return initiateMessage
    }

    func confirm(responding msg2: Data) throws -> (confirmation: Data, link: EstablishedLink) {
        lock.lock(); defer { lock.unlock() }
        respondedTo = msg2
        try confirmHook?(msg2)
        return (confirmMessage, established)
    }
}

final class ScriptedResponderEngine: LinkResponderEngine {

    private let lock = NSLock()
    private(set) var receivedInitiate: Data?
    private(set) var confirmReceived: Data?
    let respondMessage: Data
    let established: EstablishedLink
    var respondHook: ((Data) throws -> Void)?
    var finishHook: ((Data) throws -> Void)?

    init(respondMessage: Data, established: EstablishedLink) {
        self.respondMessage = respondMessage
        self.established = established
    }

    func respond(toInitiate msg1: Data) throws -> Data {
        lock.lock(); defer { lock.unlock() }
        receivedInitiate = msg1
        try respondHook?(msg1)
        return respondMessage
    }

    func finish(confirming msg3: Data) throws -> EstablishedLink {
        lock.lock(); defer { lock.unlock() }
        confirmReceived = msg3
        try finishHook?(msg3)
        return established
    }
}

// MARK: - Fake link session
//
// A byte-transparent stand-in for the protocol core's `LinkSession`:
// seal/open must be INVERTIBLE and content-checked so the transport path
// under test behaves like a real session (open refuses frames it did not
// seal). It deliberately does NOT implement the replay window — that is
// protocol-core scope, not the transport adapter's.

final class FakeLinkSession: LinkSession {

    enum SessionError: Error {
        case notOurFrame
        case tooShort
    }

    private let lock = NSLock()
    private let prefix: UInt8
    private(set) var sealedCount = 0
    private(set) var openedCount = 0
    var openHook: ((Data) throws -> Void)?
    var sealHook: ((Data) throws -> Void)?

    init(prefix: UInt8 = 0x5A) {
        self.prefix = prefix
    }

    func seal(_ payload: Data) throws -> Data {
        lock.lock()
        sealedCount += 1
        lock.unlock()
        try sealHook?(payload)
        var sealed = Data([prefix])
        sealed.append(payload)
        return sealed
    }

    func open(_ frame: Data) throws -> Data {
        lock.lock()
        openedCount += 1
        lock.unlock()
        try openHook?(frame)
        guard !frame.isEmpty else { throw SessionError.tooShort }
        guard frame[frame.startIndex] == prefix else { throw SessionError.notOurFrame }
        return frame.subdata(in: (frame.startIndex + 1)..<frame.endIndex)
    }
}

// MARK: - Cross-thread result box

final class LockedBox<T> {
    private let lock = NSLock()
    private var value: T?

    func set(_ newValue: T) {
        lock.lock()
        value = newValue
        lock.unlock()
    }

    func get() -> T? {
        lock.lock(); defer { lock.unlock() }
        return value
    }

    /// Atomic read-modify-write under the box's lock (uses `defaultValue`
    /// when the box is still empty — no force unwraps in test support).
    func update(default defaultValue: T, _ transform: (inout T) -> Void) {
        lock.lock()
        var working = value ?? defaultValue
        transform(&working)
        value = working
        lock.unlock()
    }
}

// MARK: - Seeded LCG (deterministic fuzz-lite, no GameplayKit dependency)

struct SeededRandom {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed == 0 ? 0x9E3779B97F4A7C15 : seed
    }

    mutating func next() -> UInt64 {
        // Numerical Recipes 64-bit LCG.
        state = state &* 6364136223846793005 &+ 1442695040888963407
        return state
    }

    mutating func nextIndex(upperBound: Int) -> Int {
        upperBound <= 0 ? 0 : Int(next() % UInt64(upperBound))
    }

    mutating func nextBool() -> Bool {
        next() & 1 == 0
    }
}
