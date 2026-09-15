//! Typed errors of the ICE/TURN transport crate.
//!
//! Variant names are stable machine names (the crate is compiled with
//! them, the tests match on them) in the style of `transport/quic`'s
//! `TunnelError` and the protocol core's typed errors. `Display` strings
//! are for humans; programs must match variants, never strings.

use std::net::SocketAddr;

use crate::agent::PairAttempt;

/// Errors of the ICE/TURN transport layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IceError {
    // ------------------------------------------------------------------
    // Entropy / sockets
    // ------------------------------------------------------------------
    /// No OS entropy source is available on this platform (fail closed).
    EntropyUnavailable,
    /// Generic socket I/O failure.
    Io(String),
    /// A local bind failed.
    BindFailed(String),
    /// The caller's receive buffer is smaller than the received datagram.
    RecvBufferTooSmall { needed: usize, have: usize },
    /// The configured read timeout expired (a wait ended without data).
    TimedOut,

    // ------------------------------------------------------------------
    // STUN codec (RFC 5389 subset) — strict parse failures
    // ------------------------------------------------------------------
    /// Fewer than the 20-byte STUN header.
    StunTooShort { len: usize },
    /// The two leading type bits are nonzero — not a STUN message.
    StunNotStun { leading_bits: u8 },
    /// The magic cookie is not 0x2112A442.
    StunBadMagicCookie { found: u32 },
    /// Message length is not 4-aligned or does not exactly cover the buffer.
    StunBadMessageLength { claimed: usize, available: usize },
    /// The message uses a method this strict subset does not implement.
    StunUnsupportedMethod { method: u16 },
    /// An attribute TLV overruns the message length.
    StunAttributeTruncated { attr_type: u16, claimed: usize, available: usize },
    /// Unknown comprehension-required attribute (RFC 5389 §15 range rule).
    StunUnknownRequiredAttribute { attr_type: u16 },
    /// A known attribute appears more than once.
    StunDuplicateAttribute { attr_type: u16 },
    /// XOR-MAPPED-ADDRESS: the leading byte of the 16-bit field is nonzero.
    StunAddressReservedByteNonZero { found: u8 },
    /// XOR-MAPPED-ADDRESS: unsupported address family byte.
    StunAddressFamilyUnsupported { family: u8 },
    /// XOR-MAPPED-ADDRESS: value length is not 8 (IPv4) or 20 (IPv6).
    StunAddressValueMalformed { attr_type: u16, len: usize },
    /// XOR-MAPPED-ADDRESS decoded to port 0 (no socket can have it).
    StunAddressPortZero,
    /// SOFTWARE value exceeds the 128-byte cap.
    StunSoftwareTooLong { len: usize },
    /// SOFTWARE value is not valid UTF-8.
    StunSoftwareNotUtf8,

    // ------------------------------------------------------------------
    // STUN client
    // ------------------------------------------------------------------
    /// A response arrived with an unexpected message class.
    StunUnexpectedMessageClass { found: &'static str },
    /// A success response carried no XOR-MAPPED-ADDRESS.
    StunMissingXorMappedAddress,
    /// No response matching the pending transaction id arrived in time.
    StunTimeout { server: SocketAddr, attempts: u32 },

    // ------------------------------------------------------------------
    // TURN-style relay control protocol (TEST/LOCAL scope)
    // ------------------------------------------------------------------
    /// A control frame is structurally invalid.
    RelayControlMalformed { reason: &'static str },
    /// A control frame of an unexpected message type arrived mid-session.
    RelayControlUnexpected { msg_type: u16 },
    /// A datagram exceeds `MAX_RELAY_DATAGRAM` (never split).
    RelayDatagramTooLarge { len: usize, max: usize },
    /// The relay refused an ALLOCATE (e.g. 437 Allocation Mismatch).
    RelayAllocateFailed { code: u16, reason: String },
    /// The relay reported an error for a previously sent datagram.
    RelaySendFailed { code: u16, reason: String },
    /// No ALLOCATE-SUCCESS arrived in time.
    RelayTimeout { server: SocketAddr, attempts: u32 },
    /// A relay control address payload carries an unsupported family.
    RelayAddressFamilyUnsupported { family: u8 },
    /// The relay's control bind used a wildcard IP: relayed sockets
    /// would bind it too, yielding unusable addresses like 0.0.0.0:port.
    RelayBindUnspecified { addr: SocketAddr },

    // ------------------------------------------------------------------
    // Candidates
    // ------------------------------------------------------------------
    /// Component id outside 1..=256.
    CandidateComponentInvalid { component: u32 },
    /// Local preference above 2^24-1 (would overflow the priority formula).
    CandidateLocalPreferenceInvalid { local_preference: u32 },

    // ------------------------------------------------------------------
    // ICE agent nomination (R4-006)
    // ------------------------------------------------------------------
    /// The remote candidate list is empty: nothing to pair or check.
    AgentNoRemoteCandidates,
    /// Every candidate pair's connectivity check failed. The payload is
    /// the full attempt transcript — one typed failure per pair, in
    /// attempt order (fail-closed: no nomination is fabricated).
    AgentNoPath { attempts: Vec<PairAttempt> },

    // ------------------------------------------------------------------
    // TURN relay authentication (R4-006)
    // ------------------------------------------------------------------
    /// An authenticated relay demanded credentials the caller did not
    /// present (an uncredentialed ALLOCATE received an auth challenge).
    RelayAuthRequired,
    /// The relay refused the authenticated allocation: 401 (wrong
    /// credential / message-integrity mismatch) or 438 (stale or invalid
    /// nonce), per the RFC 5389-style code model.
    RelayAuthRejected { code: u16, reason: String },
    /// An authentication control payload is structurally invalid.
    RelayAuthMalformed { reason: &'static str },
    /// The relay/credential configuration itself is invalid (empty
    /// username, oversized realm, …).
    RelayAuthConfigInvalid { reason: &'static str },
}

impl std::fmt::Display for IceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IceError::EntropyUnavailable => {
                write!(f, "no entropy source available (failed closed)")
            }
            IceError::Io(e) => write!(f, "socket I/O failure: {e}"),
            IceError::BindFailed(e) => write!(f, "bind failed: {e}"),
            IceError::RecvBufferTooSmall { needed, have } => write!(
                f,
                "receive buffer of {have} bytes is smaller than the {needed}-byte datagram"
            ),
            IceError::TimedOut => write!(f, "read timeout expired"),
            IceError::StunTooShort { len } => {
                write!(f, "STUN message shorter than the 20-byte header: {len} bytes")
            }
            IceError::StunNotStun { leading_bits } => write!(
                f,
                "leading type bits are {leading_bits:#04x} — not a STUN message (RFC 5389 §6)"
            ),
            IceError::StunBadMagicCookie { found } => write!(
                f,
                "bad STUN magic cookie {found:#010x} (expected 0x2112a442)"
            ),
            IceError::StunBadMessageLength { claimed, available } => write!(
                f,
                "STUN message length {claimed} does not exactly cover the {available} available bytes (or is not 4-aligned)"
            ),
            IceError::StunUnsupportedMethod { method } => write!(
                f,
                "STUN method {method:#06x} is not implemented by this strict subset (only Binding)"
            ),
            IceError::StunAttributeTruncated { attr_type, claimed, available } => write!(
                f,
                "attribute {attr_type:#06x} claims {claimed} value bytes but only {available} remain in the message"
            ),
            IceError::StunUnknownRequiredAttribute { attr_type } => write!(
                f,
                "unknown comprehension-required attribute {attr_type:#06x} (RFC 5389 §15: 0x0000-0x7FFF must be understood)"
            ),
            IceError::StunDuplicateAttribute { attr_type } => write!(
                f,
                "attribute {attr_type:#06x} appears more than once"
            ),
            IceError::StunAddressReservedByteNonZero { found } => write!(
                f,
                "XOR-MAPPED-ADDRESS leading byte is {found:#04x} (must be zero)"
            ),
            IceError::StunAddressFamilyUnsupported { family } => write!(
                f,
                "address family byte {family:#04x} is not 0x01 (IPv4) or 0x02 (IPv6)"
            ),
            IceError::StunAddressValueMalformed { attr_type, len } => write!(
                f,
                "attribute {attr_type:#06x} address value has wrong length {len} (need 8 or 20)"
            ),
            IceError::StunAddressPortZero => {
                write!(f, "decoded address port is 0")
            }
            IceError::StunSoftwareTooLong { len } => write!(
                f,
                "SOFTWARE value of {len} bytes exceeds the 128-byte cap"
            ),
            IceError::StunSoftwareNotUtf8 => {
                write!(f, "SOFTWARE value is not valid UTF-8")
            }
            IceError::StunUnexpectedMessageClass { found } => write!(
                f,
                "STUN response has unexpected message class {found}"
            ),
            IceError::StunMissingXorMappedAddress => write!(
                f,
                "STUN success response carried no XOR-MAPPED-ADDRESS"
            ),
            IceError::StunTimeout { server, attempts } => write!(
                f,
                "no STUN response matching the pending transaction id from {server} after {attempts} attempts"
            ),
            IceError::RelayControlMalformed { reason } => {
                write!(f, "malformed relay control frame: {reason}")
            }
            IceError::RelayControlUnexpected { msg_type } => write!(
                f,
                "unexpected relay control message type {msg_type:#06x}"
            ),
            IceError::RelayDatagramTooLarge { len, max } => write!(
                f,
                "relayed datagram of {len} bytes exceeds the {max}-byte limit (never split)"
            ),
            IceError::RelayAllocateFailed { code, reason } => write!(
                f,
                "relay refused the allocation (code {code}): {reason}"
            ),
            IceError::RelaySendFailed { code, reason } => write!(
                f,
                "relay reported an error for a sent datagram (code {code}): {reason}"
            ),
            IceError::RelayTimeout { server, attempts } => write!(
                f,
                "no relay ALLOCATE-SUCCESS from {server} after {attempts} attempts"
            ),
            IceError::RelayAddressFamilyUnsupported { family } => write!(
                f,
                "relay address family byte {family:#04x} is not 0x01 (IPv4) or 0x02 (IPv6)"
            ),
            IceError::RelayBindUnspecified { addr } => write!(
                f,
                "relay control bind {addr} uses a wildcard IP: relayed sockets would inherit it and produce unusable relayed addresses (bind a concrete address)"
            ),
            IceError::CandidateComponentInvalid { component } => write!(
                f,
                "candidate component id {component} outside 1..=256"
            ),
            IceError::CandidateLocalPreferenceInvalid { local_preference } => write!(
                f,
                "candidate local preference {local_preference} exceeds 2^24-1"
            ),
            IceError::AgentNoRemoteCandidates => {
                write!(f, "the remote candidate list is empty: nothing to pair or check")
            }
            IceError::AgentNoPath { attempts } => write!(
                f,
                "no candidate pair passed its connectivity check ({} pairs tried, in order: {})",
                attempts.len(),
                attempts
                    .iter()
                    .map(|a| match &a.outcome {
                        Ok(observed) => format!(
                            "{}->{}: ok (observed {observed})",
                            a.pair.local.candidate_type().foundation_prefix(),
                            a.pair.remote.candidate_type().foundation_prefix()
                        ),
                        Err(e) => format!(
                            "{}->{}: {e}",
                            a.pair.local.candidate_type().foundation_prefix(),
                            a.pair.remote.candidate_type().foundation_prefix()
                        ),
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
            IceError::RelayAuthRequired => write!(
                f,
                "the relay requires allocation authentication (present a credential)"
            ),
            IceError::RelayAuthRejected { code, reason } => write!(
                f,
                "relay refused the authenticated allocation (code {code}): {reason}"
            ),
            IceError::RelayAuthMalformed { reason } => {
                write!(f, "malformed relay authentication payload: {reason}")
            }
            IceError::RelayAuthConfigInvalid { reason } => {
                write!(f, "invalid relay authentication configuration: {reason}")
            }
        }
    }
}

impl std::error::Error for IceError {}
