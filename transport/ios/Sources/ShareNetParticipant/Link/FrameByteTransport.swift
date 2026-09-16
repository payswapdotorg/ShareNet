import Foundation

/// The byte-frame transport seam a link rides on — the Swift mirror of the
/// protocol core's `LinkTransport` trait
/// (`reference/crates/sharenet-protocol/src/link.rs`:
/// `send(&mut self, frame: &[u8])` / `recv(&mut self) -> Option<Vec<u8>>`
/// where `None` means "timeout with nothing available").
///
/// One "frame" is one complete, un-delimited unit of bytes (a handshake
/// message or a sealed link frame). Stream-oriented implementations (the
/// `NWConnection` adapter) apply the 4-byte big-endian length-prefix
/// convention internally (`FrameCodec`); the seam itself never sees partial
/// frames.
///
/// Send admission: implementations that hand frames to an asynchronous
/// platform enforce a bounded send window and surface
/// `TransportError.sendWindowExhausted` (see `SendWindow`). Implementations
/// without platform buffering may be unbounded (test doubles).
///
/// Threading: `receive(timeout:)` may block the calling thread (it is called
/// from a dedicated handshake thread, never a dispatch queue that the
/// implementation itself needs for delivery). `setReceiveHandler` switches
/// the transport into established-phase delivery: frames arrive on the
/// implementation's queue and polling stops.
public protocol FrameByteTransport: AnyObject {

    /// Send one complete frame.
    ///
    /// - Throws: `TransportError.illegalState` when not ready; admission
    ///   errors (`sendWindowExhausted` / `frameTooLarge`) from windowed
    ///   implementations; `TransportError.connectionClosed` after cancel.
    func send(_ frame: Data) throws

    /// Receive one complete frame, waiting at most `timeout` seconds.
    /// Returns `nil` on idle timeout with nothing available (the link.rs
    /// `recv -> Ok(None)` convention). Drains buffered frames first, then
    /// reports a terminal error (`connectionClosed` / `ioFailure`).
    ///
    /// - Throws: typed `TransportError`s for transport failures; a return of
    ///   `nil` is NOT an error.
    func receive(timeout: TimeInterval) throws -> Data?

    /// Established-phase delivery: install the handler that receives frames
    /// as they arrive (on the implementation's queue) plus the terminal
    /// failure if the stream dies. Installing a handler replaces polling via
    /// `receive(timeout:)`; buffered frames are flushed to it in order.
    /// Passing `nil` uninstalls.
    func setReceiveHandler(_ handler: ((Result<Data, TransportError>) -> Void)?)

    /// Stop the transport and release platform resources. Idempotent; never
    /// throws. In-flight sends may be lost (the standard stream-teardown
    /// semantics documented for the QUIC tunnel: callers needing delivery
    /// keep the link alive until the peer consumed the data).
    func cancel()
}
