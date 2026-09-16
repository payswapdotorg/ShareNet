import Foundation

/// The transport-side view of one established authenticated link: it owns the
/// frame path (envelope → core seal → transport; transport → core open →
/// envelope → sink) and the fail-closed lifecycle, while ALL cryptography and
/// replay protection stay behind the `LinkSession` seam (protocol core).
///
/// Send path (one `TransportFrame`):
///
/// ```text
/// envelope = u64be channelID || payload     (LinkEnvelope)
/// sealed   = session.seal(envelope)         (protocol core)
/// transport.send(sealed)                    (length-prefixed on the wire)
/// ```
///
/// Receive path (the owner feeds sealed frames in via `handleIncoming`):
/// `session.open` → `LinkEnvelope.decode` → `frameSink`. A `session.open`
/// failure is TERMINAL (L014 — the link is dead; the owner tears it down via
/// `failureSink`); a malformed channel envelope is DROPPED AND COUNTED
/// (the Android `nearby` module's `malformedFramesDropped` rule — the link
/// survives bad framing above the crypto).
public final class AuthenticatedLink {

    /// Live counters (lock-protected snapshot).
    public struct Counters {
        /// Frames sealed and handed to the transport.
        public let framesSent: Int
        /// Frames opened and delivered to the sink.
        public let framesReceived: Int
        /// Frames whose decrypted payload was not a valid channel envelope
        /// (dropped, not terminal).
        public let malformedEnvelopesDropped: Int
    }

    /// The commitment-derived link identifier (32 bytes; carried, never
    /// derived here).
    public let linkID: Data

    /// The role this side drove in the R3-001 handshake.
    public let role: LinkRole

    /// Wall-clock establishment time (diagnostics only; not authenticated).
    public let establishedAt: Date

    private let transport: any FrameByteTransport
    private let session: any LinkSession
    private let frameSink: (TransportFrame) -> Void
    private let failureSink: (TransportError) -> Void
    private let lock = NSLock()
    private var framesSent = 0
    private var framesReceived = 0
    private var malformedEnvelopesDropped = 0
    private var terminated = false

    /// - Parameters:
    ///   - established: the handshake outcome (link id, role, core session).
    ///   - transport: the byte-frame transport the handshake rode on; after
    ///     construction the owner installs its receive handler and routes
    ///     frames into `handleIncoming`.
    ///   - frameSink: called per decoded `TransportFrame`. Called on the
    ///     thread/queue `handleIncoming` runs on — hop to the app's queue
    ///     there, never do heavy work inline. MUST NOT call back into this
    ///     link synchronously.
    ///   - failureSink: called once, terminally, when the link dies
    ///     (authentication/replay failure surfaced by the core, or a
    ///     transport error). The owner tears the transport down and updates
    ///     its registry/tracker. Same re-entrancy rule as `frameSink`.
    public init(
        established: EstablishedLink,
        transport: any FrameByteTransport,
        frameSink: @escaping (TransportFrame) -> Void,
        failureSink: @escaping (TransportError) -> Void
    ) {
        self.linkID = established.linkID
        self.role = established.role
        self.session = established.session
        self.transport = transport
        self.frameSink = frameSink
        self.failureSink = failureSink
        self.establishedAt = Date()
    }

    /// True once the link has failed terminally; sends refuse afterwards.
    public var isTerminated: Bool {
        lock.lock(); defer { lock.unlock() }
        return terminated
    }

    /// Counter snapshot for diagnostics.
    public func counters() -> Counters {
        lock.lock(); defer { lock.unlock() }
        return Counters(
            framesSent: framesSent,
            framesReceived: framesReceived,
            malformedEnvelopesDropped: malformedEnvelopesDropped
        )
    }

    /// Send one frame over the established link (envelope → seal → transport).
    ///
    /// - Throws: `TransportError.illegalState` when the link (or its
    ///   transport) is terminated/not ready; `TransportError.linkSessionFailed`
    ///   when the core refuses to seal; admission errors from the transport
    ///   (`sendWindowExhausted` — retry, `frameTooLarge`).
    public func send(_ frame: TransportFrame) throws {
        lock.lock(); defer { lock.unlock() }
        guard !terminated else {
            throw TransportError.illegalState("link is terminated; a failed link is never reused (L014)")
        }
        let envelope = LinkEnvelope.encode(channelID: frame.channelID, payload: frame.payload)
        let sealed: Data
        do {
            sealed = try session.seal(envelope)
        } catch let error as TransportError {
            throw error
        } catch {
            throw TransportError.linkSessionFailed(reason: String(describing: error))
        }
        do {
            try transport.send(sealed)
        } catch let error as TransportError {
            if case .connectionClosed = error {
                terminated = true
            }
            throw error
        }
        framesSent += 1
    }

    /// Handle one sealed frame from the transport's receive handler.
    /// Session failure is terminal (the link tears down via `failureSink`);
    /// a malformed envelope is dropped and counted. Idempotent no-op after
    /// termination.
    public func handleIncoming(_ sealedFrame: Data) {
        lock.lock(); defer { lock.unlock() }
        guard !terminated else { return }

        let payload: Data
        do {
            payload = try session.open(sealedFrame)
        } catch {
            terminateLocked(TransportError.linkSessionFailed(reason: String(describing: error)))
            return
        }

        let decoded: (channelID: UInt64, payload: Data)
        do {
            decoded = try LinkEnvelope.decode(payload)
        } catch {
            malformedEnvelopesDropped += 1
            return
        }
        framesReceived += 1
        frameSink(TransportFrame(channelID: decoded.channelID, payload: decoded.payload))
    }

    /// Mark the link terminally dead (owner-side teardown after a transport
    /// failure). Subsequent sends refuse; subsequent incoming frames drop.
    public func terminate() {
        lock.lock(); defer { lock.unlock() }
        terminateLocked(TransportError.connectionClosed)
    }

    /// MUST be called with the lock held.
    private func terminateLocked(_ cause: TransportError) {
        guard !terminated else { return }
        terminated = true
        failureSink(cause)
    }
}
