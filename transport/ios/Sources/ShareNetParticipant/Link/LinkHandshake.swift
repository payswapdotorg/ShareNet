import Foundation

/// Wire-shape constants of the R3-001 authenticated link, mirrored from
/// `reference/crates/sharenet-protocol/src/link.rs` for INTERFACE
/// DOCUMENTATION ONLY.
///
/// The Swift participant is a TRANSPORT ADAPTER (architecture lock L009): it
/// moves the bytes and enforces the OS-level lifecycle. It does NOT
/// re-implement the cryptography, the CBOR handshake encoding, the AEAD
/// framing, or the replay window — those live in the shared protocol
/// implementation behind the engine seams below (production: the Rust
/// `sharenet-protocol` core over Swift FFI; tests: scripted fakes). These
/// constants exist so the adapter-side code and its tests can document and
/// pin the interface contract; they are never enforced twice.
public enum LinkWire {

    /// The authenticated-link handshake scheme version (v1).
    public static let schemeVersion = 1

    /// link_id length in bytes (commitment-derived by the core:
    /// SHA-256("sharenet-link-id-v1" || msg1 || msg2 || msg3)).
    public static let linkIDLength = 32

    /// The R3-001 replay window size (sequence numbers behind the highest
    /// seen that reorder-tolerant acceptance covers). Enforced INSIDE the
    /// protocol core's session (`LinkSession.open`), never here.
    public static let replayWindow: UInt64 = 64

    /// The sealed-frame minimum the core accepts: 8-byte sequence prefix +
    /// 16-byte AEAD tag. Enforced by the core; surfaced here for
    /// documentation.
    public static let sealedFrameMinimumBytes = 8 + 16
}

/// Which side of the R3-001 handshake this link drove.
public enum LinkRole: Equatable, CustomStringConvertible, Sendable {
    /// Drove msg1 (`LinkInitiate`) → msg2 → msg3 (`LinkConfirm`).
    case initiator
    /// Awaited msg1, produced msg2, consumed msg3.
    case responder

    public var description: String {
        switch self {
        case .initiator: return "initiator"
        case .responder: return "responder"
        }
    }
}

/// The established-session surface the adapter carries frames through
/// (Swift mirror of link.rs's `LinkSession` seal/open — the CRYPTOGRAPHY AND
/// REPLAY WINDOW STAY IN THE PROTOCOL CORE).
///
/// `seal` wraps one payload into an outgoing link frame; `open`
/// authenticates and decrypts one incoming frame. The adapter treats sealed
/// frames as OPAQUE bytes. Any `open` failure is TERMINAL for the session
/// (L014: a failed link is never silently recovered — recovery is a fresh
/// handshake and a fresh link id, R7 scope).
public protocol LinkSession: AnyObject {

    /// Protect one payload into an outgoing link frame (opaque bytes out).
    ///
    /// - Throws: core-typed errors (the adapter surfaces them as
    ///   `TransportError.linkSessionFailed`).
    func seal(_ payload: Data) throws -> Data

    /// Authenticate + decrypt one incoming frame. Any failure is terminal.
    ///
    /// - Throws: core-typed errors (tamper, replay, desync).
    func open(_ frame: Data) throws -> Data
}

/// What a completed R3-001 handshake produced. The link identifier is
/// COMMITMENT-DERIVED by the protocol core (SHA-256 over the full handshake
/// transcript — caller-selected link ids are forbidden, mirroring the
/// route-identity law L013); the adapter validates the carried length but
/// never derives or trusts a caller-supplied value.
public struct EstablishedLink: CustomStringConvertible {

    /// Exactly `LinkWire.linkIDLength` (32) bytes, commitment-derived by the
    /// protocol core.
    public let linkID: Data

    /// The role this side drove in the handshake.
    public let role: LinkRole

    /// The core-owned session for frame protection.
    public let session: any LinkSession

    /// - Throws: `TransportError.handshakeFailed` when `linkID` is not
    ///   exactly 32 bytes (a protocol-core contract violation — fail closed).
    public init(linkID: Data, role: LinkRole, session: any LinkSession) throws {
        guard linkID.count == LinkWire.linkIDLength else {
            throw TransportError.handshakeFailed(
                reason: "link id must be \(LinkWire.linkIDLength) bytes (got \(linkID.count))"
            )
        }
        self.linkID = linkID
        self.role = role
        self.session = session
    }

    public var description: String {
        "EstablishedLink(role: \(role), linkID: \(linkID.map { String(format: "%02x", $0) }.joined()))"
    }
}

/// Initiator-side handshake engine — the seam to the shared protocol
/// implementation (Swift mirror of link.rs's `LinkInitiator`:
/// `initiate()` / `confirm()`).
///
/// The engine owns the X25519 ephemeral, the Ed25519 signatures, the
/// transcript hashing and the key derivation. The adapter only sequences the
/// message flow over the transport (see `LinkHandshakeDriver`).
public protocol LinkInitiatorEngine: AnyObject {

    /// Produce msg1 (`LinkInitiate`) bytes with a fresh ephemeral.
    func initiate() throws -> Data

    /// Consume msg2 (`LinkRespond`) bytes: verify the responder against its
    /// `NodeIdentity`, then produce msg3 (`LinkConfirm`) bytes and the
    /// established session.
    func confirm(responding msg2: Data) throws -> (confirmation: Data, link: EstablishedLink)
}

/// Responder-side handshake engine — the seam to the shared protocol
/// implementation (Swift mirror of link.rs's `LinkResponder.respond` +
/// `LinkResponderPending.finish`).
public protocol LinkResponderEngine: AnyObject {

    /// Consume msg1 bytes; produce the SIGNED msg2 (`LinkRespond`) bytes with
    /// a fresh ephemeral.
    func respond(toInitiate msg1: Data) throws -> Data

    /// Consume msg3 (`LinkConfirm`) bytes: verify the initiator and
    /// establish the session.
    func finish(confirming msg3: Data) throws -> EstablishedLink
}
