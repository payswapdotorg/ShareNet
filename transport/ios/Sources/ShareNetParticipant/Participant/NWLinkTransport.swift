import Foundation
import Network

/// `FrameByteTransport` over one `NWConnection` — the authenticated-link
/// transport edge (R9-001). This is where Network.framework meets the
/// ShareNet seam: the connection's byte stream is delimited into frames
/// with the 4-byte big-endian length prefix (`FrameCodec`), sends are
/// admitted through a bounded `SendWindow`, and platform errors are
/// classified into typed `TransportError`s.
///
/// Lifecycle: `start()` wires the state handler and starts the connection on
/// `queue`. A dedicated (blocking) caller uses `waitUntilReady(timeout:)`
/// before driving the R3-001 handshake via `receive(timeout:)` /
/// `send(_:)`. After establishment the owner installs a receive handler
/// (`setReceiveHandler`) and frames arrive on `queue`.
///
/// The sealed link frames are OPAQUE here: authentication, decryption and
/// replay protection are protocol-core work behind the `LinkSession` seam —
/// this class never inspects a frame's contents, only its length prefix.
final class NWLinkTransport: FrameByteTransport {

    private enum State {
        case connecting
        case ready
        case closed
    }

    /// The read chunk handed to the platform per receive call.
    private static let readChunkBytes = 64 * 1024

    private let connection: NWConnection
    private let queue: DispatchQueue
    private let decoder: FrameDecoder
    private let sendWindow: SendWindow
    private let lock = NSLock()
    private var state: State = .connecting
    private var terminalError: TransportError?
    private var receiveHandler: ((Result<Data, TransportError>) -> Void)?
    private var frameQueue: [Data] = []
    private let frameSignal = DispatchSemaphore(value: 0)
    private let readySignal = DispatchSemaphore(value: 0)
    private var started = false

    init(
        connection: NWConnection,
        queue: DispatchQueue,
        maxFrameBytes: Int,
        sendWindow: SendWindow
    ) {
        self.connection = connection
        self.queue = queue
        self.decoder = FrameDecoder(maxFrameBytes: maxFrameBytes)
        self.sendWindow = sendWindow
    }

    /// Wire the state handler and start the connection (idempotent).
    func start() {
        lock.lock()
        if started {
            lock.unlock()
            return
        }
        started = true
        lock.unlock()

        connection.stateUpdateHandler = { [weak self] newState in
            guard let self else { return }
            switch newState {
            case .ready:
                self.lock.lock()
                let wasClosed = self.state == .closed
                if !wasClosed {
                    self.state = .ready
                }
                self.lock.unlock()
                if !wasClosed {
                    self.readySignal.signal()
                    self.readNext()
                }
            case .failed(let error):
                self.fail(with: Self.map(error))
            case .cancelled:
                self.markCancelled()
            default:
                // `.setup`/`.preparing`/`.waiting` are transitional.
                break
            }
        }
        connection.start(queue: queue)
    }

    /// Block the calling thread until the connection is ready (used by the
    /// handshake thread before driving the exchange).
    ///
    /// - Throws: `TransportError.connectionClosed` / the terminal error when
    ///   the connection died; `TransportError.timedOut` on deadline.
    func waitUntilReady(timeout: TimeInterval) throws {
        lock.lock()
        let currentState = state
        let error = terminalError
        lock.unlock()
        if currentState == .ready { return }
        if currentState == .closed { throw error ?? TransportError.connectionClosed }

        let result = readySignal.wait(timeout: .now() + timeout)
        lock.lock()
        let finalState = state
        let finalError = terminalError
        lock.unlock()
        if finalState == .ready { return }
        if result == .timedOut {
            throw TransportError.timedOut(phase: "awaiting connection readiness")
        }
        throw finalError ?? TransportError.connectionClosed
    }

    // MARK: FrameByteTransport

    /// Send one complete frame (length-prefixed on the wire). Admission is
    /// bounded by the send window: `sendWindowExhausted` means RETRY, and
    /// `release` happens on the platform's send completion.
    ///
    /// - Throws: `TransportError.illegalState` when not ready; typed
    ///   admission/encode errors; see `SendWindow.tryAcquire(frameBytes:)`.
    func send(_ frame: Data) throws {
        lock.lock()
        let currentState = state
        lock.unlock()
        guard currentState == .ready else {
            throw TransportError.illegalState(
                currentState == .closed
                    ? "connection is closed"
                    : "connection is not ready yet"
            )
        }
        let wire = try FrameCodec.encode(frame, maxFrameBytes: decoder.maxFrameBytes)
        try sendWindow.tryAcquire(frameBytes: frame.count)
        connection.send(
            content: wire,
            contentContext: nil,
            isComplete: false,
            completion: .contentProcessed { [weak self] error in
                guard let self else { return }
                self.sendWindow.release(frameBytes: frame.count)
                if let error {
                    self.fail(with: Self.map(error))
                }
            }
        )
    }

    /// Poll one complete frame (single consumer — the handshake driver's
    /// thread). Drains buffered frames first; returns `nil` on idle timeout;
    /// a closed stream drains its buffer and then throws the terminal error.
    func receive(timeout: TimeInterval) throws -> Data? {
        lock.lock()
        if !frameQueue.isEmpty {
            let frame = frameQueue.removeFirst()
            lock.unlock()
            return frame
        }
        let error = terminalError
        lock.unlock()
        if let error {
            throw error
        }

        let waitResult = frameSignal.wait(timeout: .now() + timeout)
        if waitResult == .timedOut {
            return nil
        }

        lock.lock()
        defer { lock.unlock() }
        if !frameQueue.isEmpty {
            return frameQueue.removeFirst()
        }
        if let error = terminalError {
            throw error
        }
        return nil
    }

    /// Established-phase delivery: frames (and terminal failures) are
    /// delivered to `handler` on `queue`. Buffered frames are flushed first,
    /// in order.
    func setReceiveHandler(_ handler: ((Result<Data, TransportError>) -> Void)?) {
        lock.lock()
        receiveHandler = handler
        let buffered = frameQueue
        frameQueue = []
        lock.unlock()
        for frame in buffered {
            dispatchToHandler(.success(frame))
        }
    }

    /// Stop the transport and release the connection (idempotent, never
    /// throws). In-flight sends may be lost.
    func cancel() {
        fail(with: TransportError.connectionClosed)
    }

    // MARK: Read pump (runs on `queue`)

    private func readNext() {
        connection.receive(
            minimumIncompleteLength: 1,
            maximumLength: Self.readChunkBytes
        ) { [weak self] data, _, isComplete, error in
            guard let self else { return }
            if let data, !data.isEmpty {
                do {
                    let frames = try self.decoder.feed(data)
                    for frame in frames {
                        self.enqueueFrame(frame)
                    }
                } catch let error as TransportError {
                    self.fail(with: error)
                    return
                } catch {
                    self.fail(with: .ioFailure(String(describing: error)))
                    return
                }
            }
            if let error {
                self.fail(with: Self.map(error))
                return
            }
            if isComplete {
                self.markEOF()
                return
            }
            self.readNext()
        }
    }

    /// A decoded frame arrived: queue it for a poller or hand it to the
    /// installed handler (on `queue`).
    private func enqueueFrame(_ frame: Data) {
        lock.lock()
        let handler = receiveHandler
        if handler == nil {
            frameQueue.append(frame)
        }
        lock.unlock()
        if let handler {
            queue.async { handler(.success(frame)) }
        } else {
            frameSignal.signal()
        }
    }

    /// The peer closed its sending half (isComplete). Buffered frames stay
    /// readable; afterwards `receive` throws `connectionClosed`. A partial
    /// frame still assembling at EOF is a truncation failure (terminal,
    /// fail closed).
    private func markEOF() {
        lock.lock()
        if decoder.pendingBytes > 0 {
            lock.unlock()
            fail(with: TransportError.ioFailure("stream truncated mid-frame"))
            return
        }
        guard state != .closed else {
            lock.unlock()
            return
        }
        state = .closed
        if terminalError == nil {
            terminalError = .connectionClosed
        }
        let handler = receiveHandler
        let error = terminalError ?? .connectionClosed
        lock.unlock()

        connection.cancel()
        if let handler {
            queue.async { handler(.failure(error)) }
        }
        frameSignal.signal()
        readySignal.signal()
    }

    /// Terminal failure: close, record the typed error, wake waiters.
    private func fail(with cause: TransportError) {
        lock.lock()
        if state == .closed {
            lock.unlock()
            return
        }
        state = .closed
        if terminalError == nil {
            terminalError = cause
        }
        let handler = receiveHandler
        let error = terminalError ?? cause
        lock.unlock()

        connection.cancel()
        if let handler {
            queue.async { handler(.failure(error)) }
        }
        frameSignal.signal()
        readySignal.signal()
    }

    /// The platform reported `.cancelled` (e.g. our own `cancel()`).
    private func markCancelled() {
        fail(with: TransportError.connectionClosed)
    }

    private func dispatchToHandler(_ result: Result<Data, TransportError>) {
        lock.lock()
        let handler = receiveHandler
        lock.unlock()
        guard let handler else { return }
        queue.async { handler(result) }
    }

    /// Classify a platform `NWError` into a typed transport error. No
    /// `NWError` ever crosses this boundary.
    private static func map(_ error: NWError) -> TransportError {
        switch error {
        case .posix(let code):
            return .ioFailure("posix \(code.rawValue)")
        case .tls(let code):
            return .ioFailure("tls \(code)")
        case .dns(let code):
            return .ioFailure("dns \(code)")
        default:
            return .ioFailure(String(describing: error))
        }
    }
}
