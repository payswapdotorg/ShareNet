import Foundation

/// Sequencer for the R3-001 authenticated-link handshake over a
/// `FrameByteTransport`. Mirrors the machine flow of
/// `reference/crates/sharenet-protocol/src/link.rs`:
///
/// ```text
/// initiator: initiate (msg1 out) → await msg2 → confirm (msg3 out) → established
/// responder: await msg1 → respond (msg2 out) → await msg3 → finish → established
/// ```
///
/// The driver is a TRANSPORT ADAPTER: it moves the bytes the engine seam
/// produces, enforces ordering, one overall deadline, and the
/// terminal-on-failure rule. It never inspects or creates cryptographic
/// content. Engine (protocol-core) failures are wrapped into
/// `TransportError.handshakeFailed(reason:)`, where `reason` carries the
/// core's machine name when the production FFI mapping provides it
/// (e.g. `signature_invalid`, `scheme_version_unsupported`).
///
/// Failure semantics (fail closed, per link.rs): any error during the
/// handshake is terminal for the connection; the caller tears the transport
/// down (`cancel()`). A failed handshake is retried only as a FRESH
/// handshake with fresh ephemerals (L014); the driver never re-uses an
/// engine across attempts.
public enum LinkHandshakeDriver {

    /// One overall handshake deadline (connection readiness is waited for
    /// separately by the adapter — see `NWLinkTransport.waitUntilReady`).
    public struct Options {

        /// The handshake timeout in seconds (deadline measured from driver
        /// start, covering the whole message exchange).
        public let timeout: TimeInterval

        /// - Throws: `TransportError.illegalState` when the timeout is not
        ///   positive.
        public init(timeout: TimeInterval) throws {
            guard timeout > 0 else {
                throw TransportError.illegalState("handshake timeout must be positive (got \(timeout))")
            }
            self.timeout = timeout
        }
    }

    /// Initiator side: send msg1, await msg2, send msg3, return the
    /// established link. Blocking — run it on a dedicated thread.
    ///
    /// - Throws: `TransportError.timedOut` when the overall deadline
    ///   elapses; `TransportError.handshakeFailed` when the engine refuses;
    ///   transport-typed errors as raised by `transport`.
    @discardableResult
    public static func initiate(
        over transport: any FrameByteTransport,
        engine: any LinkInitiatorEngine,
        options: Options,
        now: @escaping () -> Date = { Date() }
    ) throws -> EstablishedLink {
        let deadline = now().addingTimeInterval(options.timeout)
        do {
            let msg1 = try engine.initiate()
            try transport.send(msg1)
            while true {
                try throwIfPast(deadline: deadline, now: now, phase: "awaiting the responder's link respond message")
                guard let msg2 = try transport.receive(timeout: waitSlice(to: deadline, now: now)) else {
                    continue
                }
                let outcome = try engine.confirm(responding: msg2)
                try transport.send(outcome.confirmation)
                return outcome.link
            }
        } catch let error as TransportError {
            throw error
        } catch {
            throw TransportError.handshakeFailed(reason: String(describing: error))
        }
    }

    /// Responder side: await msg1, send msg2, await msg3, return the
    /// established link. Blocking — run it on a dedicated thread.
    ///
    /// - Throws: as `initiate(over:engine:options:now:)`.
    @discardableResult
    public static func respond(
        over transport: any FrameByteTransport,
        engine: any LinkResponderEngine,
        options: Options,
        now: @escaping () -> Date = { Date() }
    ) throws -> EstablishedLink {
        let deadline = now().addingTimeInterval(options.timeout)
        var responded = false
        do {
            while true {
                try throwIfPast(
                    deadline: deadline,
                    now: now,
                    phase: responded
                        ? "awaiting the initiator's link confirm message"
                        : "awaiting the initiator's link initiate message"
                )
                guard let message = try transport.receive(timeout: waitSlice(to: deadline, now: now)) else {
                    continue
                }
                if !responded {
                    let msg2 = try engine.respond(toInitiate: message)
                    try transport.send(msg2)
                    responded = true
                } else {
                    return try engine.finish(confirming: message)
                }
            }
        } catch let error as TransportError {
            throw error
        } catch {
            throw TransportError.handshakeFailed(reason: String(describing: error))
        }
    }

    /// The receive slice for the current loop step: the remaining time to the
    /// deadline, floored at 10 ms so a deadline-hugging receive waits instead
    /// of busy-spinning.
    private static func waitSlice(to deadline: Date, now: () -> Date) -> TimeInterval {
        let remaining = deadline.timeIntervalSince(now())
        return max(remaining, 0.01)
    }

    private static func throwIfPast(deadline: Date, now: () -> Date, phase: String) throws {
        if now() >= deadline {
            throw TransportError.timedOut(phase: phase)
        }
    }
}
