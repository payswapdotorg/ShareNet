//! RFC 5389 STUN subset — strict codec and UDP client (work item R4-005).
//!
//! Standards-first per architecture lock L011 (ICE/STUN/TURN are reused,
//! not reinvented): this is the standard STUN Binding exchange defined by
//! RFC 5389, restricted to the subset ShareNet's candidate gathering
//! needs, and parsed STRICTLY:
//!
//! - 20-byte header: message type (class/method bits per RFC 5389 §6,
//!   the two leading bits MUST be zero), message length (MUST be a
//!   multiple of 4 and MUST exactly cover the received datagram), magic
//!   cookie 0x2112A442, 96-bit transaction id;
//! - attributes are TLVs (type/length/value, value padded to a 4-byte
//!   multiple per RFC 5389 §15);
//! - comprehension-required attributes (types 0x0000-0x7FFF, RFC 5389
//!   §15) that this subset does not know are REJECTED
//!   (`StunUnknownRequiredAttribute`); unknown comprehension-optional
//!   attributes (0x8000-0xFFFF) are ignored, as the RFC allows;
//! - XOR-MAPPED-ADDRESS (RFC 5389 §15.2): family 0x01/0x02, port XOR
//!   the cookie's top 16 bits, IPv4 address XOR the cookie, IPv6
//!   address XOR cookie||transaction-id; the leading byte MUST be zero
//!   and the value length MUST be 8 (IPv4) or 20 (IPv6);
//! - SOFTWARE (RFC 5389 §15.10): UTF-8, at most 128 bytes.
//!
//! The client sends a Binding Request with a random 96-bit transaction
//! id, retransmits it (same transaction id — RFC 5389 unreliable-transport
//! semantics) up to `attempts` times with a per-attempt timeout, accepts
//! only a response whose transaction id matches EXACTLY, and fails closed
//! on any malformed datagram received from the queried server.
//!
//! No new protocol is invented here and no protocol semantics leak in:
//! the mapped address feeds the candidate model (`crate::candidate`),
//! which is the address source for pinned QUIC tunnels (`crate::bridge`).

use std::net::SocketAddr;
use std::time::Duration;

use crate::entropy;
use crate::error::IceError;

/// The RFC 5389 magic cookie.
pub const MAGIC_COOKIE: u32 = 0x2112A442;
/// STUN header size in bytes.
pub const HEADER_LEN: usize = 20;
/// The Binding method (the only method this strict subset implements).
pub const METHOD_BINDING: u16 = 0x001;
/// XOR-MAPPED-ADDRESS attribute type (RFC 5389 §15.2).
pub const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
/// SOFTWARE attribute type (RFC 5389 §15.10, comprehension-optional).
pub const ATTR_SOFTWARE: u16 = 0x8022;
/// SOFTWARE value cap in bytes (RFC 5389 §15.10: less than 128 characters).
pub const SOFTWARE_MAX_BYTES: usize = 128;

/// STUN message classes (RFC 5389 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl MessageClass {
    /// Stable class name for error reporting.
    pub fn name(self) -> &'static str {
        match self {
            MessageClass::Request => "request",
            MessageClass::Indication => "indication",
            MessageClass::SuccessResponse => "success response",
            MessageClass::ErrorResponse => "error response",
        }
    }
}

/// A 96-bit STUN transaction id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionId(pub [u8; 12]);

impl TransactionId {
    /// A cryptographically random transaction id (OS entropy, fail closed).
    pub fn random() -> Result<Self, IceError> {
        let mut id = [0u8; 12];
        entropy::random_bytes(&mut id)?;
        Ok(TransactionId(id))
    }

    pub fn as_bytes(&self) -> &[u8; 12] {
        &self.0
    }
}

/// A parsed/encodable STUN attribute of this subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribute {
    XorMappedAddress(SocketAddr),
    Software(String),
}

/// A STUN message: class, method (always Binding here), transaction id
/// and the attributes of this subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StunMessage {
    pub class: MessageClass,
    pub method: u16,
    pub transaction_id: TransactionId,
    pub attributes: Vec<Attribute>,
}

impl StunMessage {
    /// A Binding Request carrying an optional SOFTWARE attribute.
    pub fn binding_request(
        transaction_id: TransactionId,
        software: Option<&str>,
    ) -> Result<Self, IceError> {
        let mut attributes = Vec::new();
        if let Some(s) = software {
            check_software(s)?;
            attributes.push(Attribute::Software(s.to_string()));
        }
        Ok(StunMessage {
            class: MessageClass::Request,
            method: METHOD_BINDING,
            transaction_id,
            attributes,
        })
    }

    /// A Binding success response carrying XOR-MAPPED-ADDRESS and an
    /// optional SOFTWARE attribute.
    pub fn binding_success(
        transaction_id: TransactionId,
        mapped: SocketAddr,
        software: Option<&str>,
    ) -> Result<Self, IceError> {
        let mut attributes = vec![Attribute::XorMappedAddress(mapped)];
        if let Some(s) = software {
            check_software(s)?;
            attributes.push(Attribute::Software(s.to_string()));
        }
        Ok(StunMessage {
            class: MessageClass::SuccessResponse,
            method: METHOD_BINDING,
            transaction_id,
            attributes,
        })
    }

    /// The first XOR-MAPPED-ADDRESS, if present.
    pub fn xor_mapped_address(&self) -> Option<SocketAddr> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::XorMappedAddress(addr) => Some(*addr),
            _ => None,
        })
    }

    /// The first SOFTWARE value, if present.
    pub fn software(&self) -> Option<&str> {
        self.attributes.iter().find_map(|a| match a {
            Attribute::Software(s) => Some(s.as_str()),
            _ => None,
        })
    }

    /// Encode the message (header + padded attribute TLVs).
    pub fn encode(&self) -> Result<Vec<u8>, IceError> {
        let mut attrs = Vec::new();
        for attribute in &self.attributes {
            match attribute {
                Attribute::XorMappedAddress(addr) => {
                    let value = encode_xor_mapped_address_value(addr, &self.transaction_id);
                    push_tlv(&mut attrs, ATTR_XOR_MAPPED_ADDRESS, &value);
                }
                Attribute::Software(s) => {
                    check_software(s)?;
                    push_tlv(&mut attrs, ATTR_SOFTWARE, s.as_bytes());
                }
            }
        }
        let msg_len = attrs.len();
        if msg_len > u16::MAX as usize {
            return Err(IceError::StunBadMessageLength {
                claimed: msg_len,
                available: u16::MAX as usize,
            });
        }
        let mut out = Vec::with_capacity(HEADER_LEN + msg_len);
        out.extend_from_slice(&encode_type(self.method, self.class).to_be_bytes());
        out.extend_from_slice(&(msg_len as u16).to_be_bytes());
        out.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        out.extend_from_slice(&self.transaction_id.0);
        out.extend_from_slice(&attrs);
        Ok(out)
    }

    /// Strict parse (see the module docs for the full rejection list).
    pub fn parse(bytes: &[u8]) -> Result<Self, IceError> {
        if bytes.len() < HEADER_LEN {
            return Err(IceError::StunTooShort { len: bytes.len() });
        }
        let msg_type = u16::from_be_bytes([bytes[0], bytes[1]]);
        let (method, class) = decode_type(msg_type)?;
        if method != METHOD_BINDING {
            return Err(IceError::StunUnsupportedMethod { method });
        }
        let msg_len = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
        let available = bytes.len() - HEADER_LEN;
        if msg_len % 4 != 0 || msg_len != available {
            return Err(IceError::StunBadMessageLength {
                claimed: msg_len,
                available,
            });
        }
        let cookie = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if cookie != MAGIC_COOKIE {
            return Err(IceError::StunBadMagicCookie { found: cookie });
        }
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&bytes[8..20]);

        let mut attributes: Vec<Attribute> = Vec::new();
        let mut off = HEADER_LEN;
        let end = HEADER_LEN + msg_len;
        while off < end {
            if end - off < 4 {
                return Err(IceError::StunAttributeTruncated {
                    attr_type: 0,
                    claimed: 4,
                    available: end - off,
                });
            }
            let attr_type = u16::from_be_bytes([bytes[off], bytes[off + 1]]);
            let attr_len = u16::from_be_bytes([bytes[off + 2], bytes[off + 3]]) as usize;
            let padded = (attr_len + 3) & !3usize;
            if off + 4 + padded > end {
                return Err(IceError::StunAttributeTruncated {
                    attr_type,
                    claimed: attr_len,
                    available: end - off - 4,
                });
            }
            let value = &bytes[off + 4..off + 4 + attr_len];
            match attr_type {
                ATTR_XOR_MAPPED_ADDRESS => {
                    if attributes
                        .iter()
                        .any(|a| matches!(a, Attribute::XorMappedAddress(_)))
                    {
                        return Err(IceError::StunDuplicateAttribute { attr_type });
                    }
                    let addr = parse_xor_mapped_address_value(
                        value,
                        &TransactionId(transaction_id),
                    )?;
                    attributes.push(Attribute::XorMappedAddress(addr));
                }
                ATTR_SOFTWARE => {
                    if attributes.iter().any(|a| matches!(a, Attribute::Software(_))) {
                        return Err(IceError::StunDuplicateAttribute { attr_type });
                    }
                    if value.len() > SOFTWARE_MAX_BYTES {
                        return Err(IceError::StunSoftwareTooLong { len: value.len() });
                    }
                    let s = std::str::from_utf8(value)
                        .map_err(|_| IceError::StunSoftwareNotUtf8)?
                        .to_string();
                    attributes.push(Attribute::Software(s));
                }
                t if t < 0x8000 => {
                    // RFC 5389 §15: attributes 0x0000-0x7FFF are
                    // comprehension-required — a strict subset rejects
                    // the ones it does not know instead of guessing.
                    return Err(IceError::StunUnknownRequiredAttribute { attr_type: t });
                }
                _ => {
                    // Unknown comprehension-optional attribute
                    // (0x8000-0xFFFF): ignored per RFC 5389 §15.
                }
            }
            off += 4 + padded;
        }
        Ok(StunMessage {
            class,
            method,
            transaction_id: TransactionId(transaction_id),
            attributes,
        })
    }
}

/// Encode the 14-bit STUN message type from method + class (RFC 5389 §6:
/// class bits C1C0 live at positions 8 and 4, method bits spread around
/// them).
pub fn encode_type(method: u16, class: MessageClass) -> u16 {
    let class_bits = match class {
        MessageClass::Request => 0u16,
        MessageClass::Indication => 1,
        MessageClass::SuccessResponse => 2,
        MessageClass::ErrorResponse => 3,
    };
    (((method & 0x0F80) << 2) | ((method & 0x0070) << 1) | (method & 0x000F))
        | ((class_bits & 0x2) << 7)
        | ((class_bits & 0x1) << 4)
}

/// Decode a 14-bit STUN message type back into (method, class).
pub fn decode_type(msg_type: u16) -> Result<(u16, MessageClass), IceError> {
    let leading = ((msg_type >> 14) & 0x3) as u8;
    if leading != 0 {
        return Err(IceError::StunNotStun { leading_bits: leading });
    }
    let method = ((msg_type >> 2) & 0x0F80) | ((msg_type >> 1) & 0x0070) | (msg_type & 0x000F);
    let class = match ((msg_type >> 7) & 0x2) | ((msg_type >> 4) & 0x1) {
        0 => MessageClass::Request,
        1 => MessageClass::Indication,
        2 => MessageClass::SuccessResponse,
        _ => MessageClass::ErrorResponse,
    };
    Ok((method, class))
}

fn check_software(s: &str) -> Result<(), IceError> {
    if s.len() > SOFTWARE_MAX_BYTES {
        return Err(IceError::StunSoftwareTooLong { len: s.len() });
    }
    Ok(())
}

fn push_tlv(out: &mut Vec<u8>, attr_type: u16, value: &[u8]) {
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
    let pad = (4 - (value.len() % 4)) % 4;
    out.extend(std::iter::repeat(0u8).take(pad));
}

/// XOR mask for IPv6 XOR-MAPPED-ADDRESS: cookie || transaction id.
fn xor_mask_v6(transaction_id: &[u8; 12]) -> [u8; 16] {
    let mut mask = [0u8; 16];
    mask[0..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    mask[4..16].copy_from_slice(transaction_id);
    mask
}

/// Encode the XOR-MAPPED-ADDRESS attribute value (RFC 5389 §15.2).
fn encode_xor_mapped_address_value(addr: &SocketAddr, transaction_id: &TransactionId) -> Vec<u8> {
    let mut value = Vec::with_capacity(20);
    value.push(0); // the top 8 bits of the 16-bit field: zero (§15.2)
    let port = match addr {
        SocketAddr::V4(a) => {
            value.push(0x01);
            a.port()
        }
        SocketAddr::V6(a) => {
            value.push(0x02);
            a.port()
        }
    };
    value.extend_from_slice(&(port ^ (MAGIC_COOKIE >> 16) as u16).to_be_bytes());
    match addr {
        SocketAddr::V4(a) => {
            let cookie = MAGIC_COOKIE.to_be_bytes();
            for (i, b) in a.ip().octets().iter().enumerate() {
                value.push(b ^ cookie[i]);
            }
        }
        SocketAddr::V6(a) => {
            let mask = xor_mask_v6(&transaction_id.0);
            for (i, b) in a.ip().octets().iter().enumerate() {
                value.push(b ^ mask[i]);
            }
        }
    }
    value
}

/// Parse the XOR-MAPPED-ADDRESS attribute value (RFC 5389 §15.2), strictly.
fn parse_xor_mapped_address_value(
    value: &[u8],
    transaction_id: &TransactionId,
) -> Result<SocketAddr, IceError> {
    if value.len() < 4 {
        return Err(IceError::StunAddressValueMalformed {
            attr_type: ATTR_XOR_MAPPED_ADDRESS,
            len: value.len(),
        });
    }
    if value[0] != 0 {
        return Err(IceError::StunAddressReservedByteNonZero { found: value[0] });
    }
    let port =
        u16::from_be_bytes([value[2], value[3]]) ^ (MAGIC_COOKIE >> 16) as u16;
    if port == 0 {
        return Err(IceError::StunAddressPortZero);
    }
    match value[1] {
        0x01 => {
            if value.len() != 8 {
                return Err(IceError::StunAddressValueMalformed {
                    attr_type: ATTR_XOR_MAPPED_ADDRESS,
                    len: value.len(),
                });
            }
            let raw = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let ip = raw ^ MAGIC_COOKIE;
            Ok(SocketAddr::from((std::net::Ipv4Addr::from(ip), port)))
        }
        0x02 => {
            if value.len() != 20 {
                return Err(IceError::StunAddressValueMalformed {
                    attr_type: ATTR_XOR_MAPPED_ADDRESS,
                    len: value.len(),
                });
            }
            let mask = xor_mask_v6(&transaction_id.0);
            let mut octets = [0u8; 16];
            for i in 0..16 {
                octets[i] = value[4 + i] ^ mask[i];
            }
            Ok(SocketAddr::from((std::net::Ipv6Addr::from(octets), port)))
        }
        family => Err(IceError::StunAddressFamilyUnsupported { family }),
    }
}

// ---------------------------------------------------------------------------
// Client: a datagram pipe abstraction + the Binding request/response loop
// ---------------------------------------------------------------------------

/// A datagram transport the STUN client can run over: a plain UDP socket
/// or a TURN-style relay allocation (`crate::relay::RelayClient` — the
/// same Binding exchange works through the relay because the relay
/// forwards opaque datagrams, L012).
pub trait DatagramPipe {
    /// Send one datagram to `target`.
    fn pipe_send_to(&self, target: SocketAddr, data: &[u8]) -> Result<(), IceError>;
    /// Block until one datagram arrives (honoring the read timeout) and
    /// return its source and length. A timeout is reported as
    /// `IceError::TimedOut`.
    fn pipe_recv_from(&self, buf: &mut [u8]) -> Result<(SocketAddr, usize), IceError>;
    /// Set the read timeout (must be nonzero when `Some`).
    fn pipe_set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), IceError>;
    /// The local (base) address of this pipe.
    fn pipe_local_addr(&self) -> Result<SocketAddr, IceError>;
}

fn is_timeout_error(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

impl DatagramPipe for std::net::UdpSocket {
    fn pipe_send_to(&self, target: SocketAddr, data: &[u8]) -> Result<(), IceError> {
        self.send_to(data, target)
            .map(|_| ())
            .map_err(|e| IceError::Io(e.to_string()))
    }

    fn pipe_recv_from(&self, buf: &mut [u8]) -> Result<(SocketAddr, usize), IceError> {
        match self.recv_from(buf) {
            Ok((n, peer)) => Ok((peer, n)),
            Err(e) if is_timeout_error(&e) => Err(IceError::TimedOut),
            Err(e) => Err(IceError::Io(e.to_string())),
        }
    }

    fn pipe_set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), IceError> {
        self.set_read_timeout(timeout)
            .map_err(|e| IceError::Io(e.to_string()))
    }

    fn pipe_local_addr(&self) -> Result<SocketAddr, IceError> {
        self.local_addr().map_err(|e| IceError::Io(e.to_string()))
    }
}

/// Client behavior for the Binding exchange.
#[derive(Debug, Clone)]
pub struct StunConfig {
    /// SOFTWARE value placed in requests (<= 128 bytes).
    pub software: String,
    /// Total transmissions of the request (retransmissions carry the SAME
    /// transaction id, RFC 5389 §7.2.1 semantics).
    pub attempts: u32,
    /// Per-attempt wait for a matching response (must be nonzero).
    pub attempt_timeout: Duration,
}

impl Default for StunConfig {
    fn default() -> Self {
        StunConfig {
            software: "sharenet-transport-ice/0.1".to_string(),
            attempts: 3,
            attempt_timeout: Duration::from_millis(400),
        }
    }
}

/// The result of a successful Binding exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingOutcome {
    /// The server that answered.
    pub server: SocketAddr,
    /// The XOR-MAPPED-ADDRESS — the server-reflexive candidate address.
    pub mapped: SocketAddr,
    /// The transaction id of the accepted response.
    pub transaction_id: TransactionId,
    /// The server's SOFTWARE, when present.
    pub software: Option<String>,
}

/// Run one STUN Binding exchange over `pipe`:
///
/// 1. send a Binding Request with a fresh random transaction id (plus the
///    configured SOFTWARE attribute);
/// 2. wait up to `attempt_timeout` for a response FROM the server whose
///    transaction id matches EXACTLY — datagrams from other sources and
///    responses with a different transaction id are discarded (mismatch
///    refusal: they can never satisfy the pending request);
/// 3. a datagram from the server that fails the strict parse fails the
///    whole operation CLOSED (`IceError::Stun*`) — no fallback, no
///    acceptance of partially-valid responses;
/// 4. retransmit (same transaction id) up to `attempts` times; exhaustion
///    yields `IceError::StunTimeout`.
///
/// On success the XOR-MAPPED-ADDRESS is returned as `mapped` (the
/// server-reflexive candidate) together with the mapped server.
///
/// Note: the pipe's read timeout is left set to `attempt_timeout`;
/// callers that reuse the pipe re-set their own timeout.
pub fn binding_request<P: DatagramPipe>(
    pipe: &P,
    server: SocketAddr,
    config: &StunConfig,
) -> Result<BindingOutcome, IceError> {
    let attempts = config.attempts.max(1);
    let transaction_id = TransactionId::random()?;
    let request = StunMessage::binding_request(transaction_id, Some(&config.software))?.encode()?;
    pipe.pipe_set_read_timeout(Some(config.attempt_timeout))?;
    let mut buf = vec![0u8; 65_536];
    for _ in 0..attempts {
        pipe.pipe_send_to(server, &request)?;
        let deadline = std::time::Instant::now() + config.attempt_timeout;
        loop {
            if std::time::Instant::now() >= deadline {
                break; // attempt expired
            }
            match pipe.pipe_recv_from(&mut buf) {
                Ok((peer, n)) => {
                    if peer != server {
                        continue; // unrelated source: discard
                    }
                    // A datagram from the queried server: strict parse,
                    // fail closed on anything malformed.
                    let msg = StunMessage::parse(&buf[..n])?;
                    if msg.transaction_id != transaction_id {
                        continue; // mismatch refusal: discard, keep waiting
                    }
                    if msg.class != MessageClass::SuccessResponse {
                        return Err(IceError::StunUnexpectedMessageClass {
                            found: msg.class.name(),
                        });
                    }
                    let mapped = msg
                        .xor_mapped_address()
                        .ok_or(IceError::StunMissingXorMappedAddress)?;
                    let software = msg.software().map(str::to_string);
                    return Ok(BindingOutcome {
                        server,
                        mapped,
                        transaction_id,
                        software,
                    });
                }
                Err(IceError::TimedOut) => break, // attempt expired
                Err(IceError::Io(_)) => break, // transport error: retry the attempt
                Err(other) => return Err(other), // typed protocol error: fail closed
            }
        }
    }
    Err(IceError::StunTimeout { server, attempts })
}

/// An ICE connectivity check (RFC 8445 §7 subset): a STUN Binding
/// request/response over the candidate's base pipe toward `target`.
///
/// `target` must answer STUN (a STUN server or an ICE-lite peer — full
/// agent nomination is future R4-006/R4-007 scope and is NOT implemented
/// here). Returns the address `target` observed as this pipe's source.
pub fn connectivity_check<P: DatagramPipe>(
    pipe: &P,
    target: SocketAddr,
) -> Result<SocketAddr, IceError> {
    connectivity_check_with(pipe, target, &StunConfig::default())
}

/// A connectivity check with an explicit policy (the R4-006 ICE agent
/// walks many candidate pairs and needs a faster/tunable retry policy
/// than the default Binding exchange).
pub fn connectivity_check_with<P: DatagramPipe>(
    pipe: &P,
    target: SocketAddr,
    config: &StunConfig,
) -> Result<SocketAddr, IceError> {
    let outcome = binding_request(pipe, target, config)?;
    Ok(outcome.mapped)
}

// ---------------------------------------------------------------------------
// Unit tests: codec roundtrips, hand-computed byte vectors, strict rejects
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 5389 §15.2's own worked example transaction id.
    const TXID: TransactionId = TransactionId([
        0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae,
    ]);

    fn header(msg_type: u16, msg_len: u16, tx: TransactionId) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&msg_type.to_be_bytes());
        b.extend_from_slice(&msg_len.to_be_bytes());
        b.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        b.extend_from_slice(tx.as_bytes());
        b
    }

    fn tlv(attr_type: u16, value: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&attr_type.to_be_bytes());
        b.extend_from_slice(&(value.len() as u16).to_be_bytes());
        b.extend_from_slice(value);
        let pad = (4 - (value.len() % 4)) % 4;
        b.extend(std::iter::repeat(0u8).take(pad));
        b
    }

    #[test]
    fn message_type_constants() {
        assert_eq!(encode_type(METHOD_BINDING, MessageClass::Request), 0x0001);
        assert_eq!(encode_type(METHOD_BINDING, MessageClass::Indication), 0x0011);
        assert_eq!(
            encode_type(METHOD_BINDING, MessageClass::SuccessResponse),
            0x0101
        );
        assert_eq!(encode_type(METHOD_BINDING, MessageClass::ErrorResponse), 0x0111);
        for (msg_type, method, class) in [
            (0x0001u16, 0x001u16, MessageClass::Request),
            (0x0011, 0x001, MessageClass::Indication),
            (0x0101, 0x001, MessageClass::SuccessResponse),
            (0x0111, 0x001, MessageClass::ErrorResponse),
        ] {
            assert_eq!(decode_type(msg_type), Ok((method, class)));
        }
    }

    #[test]
    fn message_type_roundtrip_across_method_bits() {
        // 12-bit methods exercising every bit position of the RFC 5389 §6
        // spread (including the high method bits that live around the
        // class bits).
        for method in [0x001u16, 0x00F, 0x070, 0x080, 0x0F2, 0xABC, 0xFFF] {
            for class in [
                MessageClass::Request,
                MessageClass::Indication,
                MessageClass::SuccessResponse,
                MessageClass::ErrorResponse,
            ] {
                let encoded = encode_type(method, class);
                assert_eq!(
                    decode_type(encoded),
                    Ok((method, class)),
                    "roundtrip failed for method {method:#06x}"
                );
            }
        }
    }

    /// RFC 5389 §15.2's worked example, byte for byte: address
    /// 192.0.2.1:32853 with (IPv4) only the cookie in the XOR.
    #[test]
    fn xor_mapped_address_rfc5389_worked_example() {
        let value = [0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43];
        let addr = parse_xor_mapped_address_value(&value, &TXID).expect("parse");
        assert_eq!(addr, "192.0.2.1:32853".parse().expect("addr"));
        let encoded = encode_xor_mapped_address_value(&addr, &TXID);
        assert_eq!(encoded, value);
        // IPv4 XOR does not involve the transaction id: any id gives
        // the same bytes.
        let other = TransactionId([0xFF; 12]);
        assert_eq!(encode_xor_mapped_address_value(&addr, &other), value);
    }

    /// IPv6 hand-computed vector: 2001:db8::1 port 4660 with transaction
    /// id 00112233-44556677-8899aabb; the mask is cookie || txid.
    #[test]
    fn xor_mapped_address_ipv6_hand_computed() {
        let tx = TransactionId([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        ]);
        let value = [
            0x00, 0x02, 0x33, 0x26, // family, XOR'd port (0x1234 ^ 0x2112)
            0x01, 0x13, 0xa9, 0xfa, // 2001:0db8 ^ cookie 2112a442
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, // :: ^ txid[0..8]
            0x88, 0x99, 0xaa, 0xba, // 0001 ^ txid[8..12]
        ];
        let addr = parse_xor_mapped_address_value(&value, &tx).expect("parse");
        assert_eq!(addr, "[2001:db8::1]:4660".parse().expect("addr"));
        assert_eq!(encode_xor_mapped_address_value(&addr, &tx), value);
    }

    /// A complete Binding Request as literal bytes: header + SOFTWARE
    /// "AB" (padded to 4).
    #[test]
    fn binding_request_literal_bytes() {
        let literal: [u8; 28] = [
            0x00, 0x01, 0x00, 0x08, // type, length
            0x21, 0x12, 0xa4, 0x42, // magic cookie
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, // txid
            0x80, 0x22, 0x00, 0x02, 0x41, 0x42, 0x00, 0x00, // SOFTWARE "AB"
        ];
        let msg = StunMessage::binding_request(TXID, Some("AB")).expect("build");
        assert_eq!(msg.encode().expect("encode"), literal);
        let parsed = StunMessage::parse(&literal).expect("parse");
        assert_eq!(parsed, msg);
        assert_eq!(parsed.class, MessageClass::Request);
        assert_eq!(parsed.method, METHOD_BINDING);
        assert_eq!(parsed.transaction_id, TXID);
        assert_eq!(parsed.software(), Some("AB"));
    }

    /// A complete Binding success response as literal bytes:
    /// XOR-MAPPED-ADDRESS (the RFC worked example) + SOFTWARE "SN".
    #[test]
    fn binding_success_literal_bytes() {
        let literal: [u8; 40] = [
            0x01, 0x01, 0x00, 0x14, // type, length (20)
            0x21, 0x12, 0xa4, 0x42, // magic cookie
            0xb7, 0xe7, 0xa7, 0x01, 0xbc, 0x34, 0xd6, 0x86, 0xfa, 0x87, 0xdf, 0xae, // txid
            0x00, 0x20, 0x00, 0x08, 0x00, 0x01, 0xa1, 0x47, 0xe1, 0x12, 0xa6, 0x43, // XMA
            0x80, 0x22, 0x00, 0x02, 0x53, 0x4e, 0x00, 0x00, // SOFTWARE "SN"
        ];
        let msg =
            StunMessage::binding_success(TXID, "192.0.2.1:32853".parse().expect("addr"), Some("SN"))
                .expect("build");
        assert_eq!(msg.encode().expect("encode"), literal);
        let parsed = StunMessage::parse(&literal).expect("parse");
        assert_eq!(parsed, msg);
        assert_eq!(parsed.class, MessageClass::SuccessResponse);
        assert_eq!(parsed.xor_mapped_address(), Some("192.0.2.1:32853".parse().expect("addr")));
    }

    #[test]
    fn encode_parse_roundtrip_v4_v6() {
        for (addr, software) in [
            ("127.0.0.1:5300", Some("sharenet")),
            ("[2001:db8::1]:4660", None),
            ("[::1]:65535", Some("x".repeat(128).as_str())),
        ] {
            let addr: SocketAddr = addr.parse().expect("addr");
            let msg = StunMessage::binding_success(TXID, addr, software).expect("build");
            let bytes = msg.encode().expect("encode");
            assert_eq!(StunMessage::parse(&bytes).expect("parse"), msg);
        }
    }

    // ------------------------------------------------------------------
    // Strict rejects (each with the exact typed error)
    // ------------------------------------------------------------------

    #[test]
    fn rejects_short_message() {
        assert_eq!(
            StunMessage::parse(&[0u8; 19]),
            Err(IceError::StunTooShort { len: 19 })
        );
        assert_eq!(StunMessage::parse(&[]), Err(IceError::StunTooShort { len: 0 }));
    }

    #[test]
    fn rejects_non_stun_leading_bits() {
        let mut bytes = header(0xC001, 0, TXID);
        bytes.extend_from_slice(&tlv(ATTR_XOR_MAPPED_ADDRESS, &[0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43]));
        // fix the length field to cover the attribute
        bytes[2..4].copy_from_slice(&12u16.to_be_bytes());
        match StunMessage::parse(&bytes) {
            Err(IceError::StunNotStun { leading_bits }) => assert_eq!(leading_bits, 0b11),
            other => panic!("expected StunNotStun, got {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_magic_cookie() {
        let mut bytes = header(0x0101, 20, TXID);
        bytes.extend_from_slice(&tlv(ATTR_XOR_MAPPED_ADDRESS, &[0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43]));
        bytes.extend_from_slice(&tlv(ATTR_SOFTWARE, b"SN"));
        bytes[7] ^= 0x01; // corrupt the cookie
        match StunMessage::parse(&bytes) {
            Err(IceError::StunBadMagicCookie { found }) => {
                assert_eq!(found, MAGIC_COOKIE ^ 0x01);
            }
            other => panic!("expected StunBadMagicCookie, got {other:?}"),
        }
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut bytes = header(0x0101, 20, TXID);
        bytes.extend_from_slice(&tlv(ATTR_XOR_MAPPED_ADDRESS, &[0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43]));
        bytes.extend_from_slice(&tlv(ATTR_SOFTWARE, b"SN"));
        bytes.extend_from_slice(b"XY"); // NOT covered by the length
        match StunMessage::parse(&bytes) {
            Err(IceError::StunBadMessageLength { claimed, available }) => {
                assert_eq!((claimed, available), (20, 22));
            }
            other => panic!("expected StunBadMessageLength, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unaligned_message_length() {
        let mut bytes = header(0x0001, 7, TXID); // 7 is not a multiple of 4
        bytes.extend_from_slice(&[0u8; 7]);
        assert!(matches!(
            StunMessage::parse(&bytes),
            Err(IceError::StunBadMessageLength { claimed: 7, available: 7 })
        ));
    }

    #[test]
    fn rejects_unsupported_method() {
        let bytes = header(0x0002, 0, TXID); // method 0x002 (not Binding)
        match StunMessage::parse(&bytes) {
            Err(IceError::StunUnsupportedMethod { method }) => assert_eq!(method, 0x002),
            other => panic!("expected StunUnsupportedMethod, got {other:?}"),
        }
    }

    #[test]
    fn rejects_malformed_tlv_overrun() {
        let xma = tlv(ATTR_XOR_MAPPED_ADDRESS, &[0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43]);
        let mut bytes = header(0x0101, 0, TXID);
        bytes.extend_from_slice(&xma[..8]); // cut mid-attribute
        bytes[2..4].copy_from_slice(&8u16.to_be_bytes()); // length covers the cut
        match StunMessage::parse(&bytes) {
            Err(IceError::StunAttributeTruncated { attr_type, claimed, available }) => {
                assert_eq!((attr_type, claimed, available), (ATTR_XOR_MAPPED_ADDRESS, 8, 4));
            }
            other => panic!("expected StunAttributeTruncated, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_comprehension_required_attribute() {
        let mut bytes = header(0x0101, 8, TXID);
        bytes.extend_from_slice(&tlv(0x7FFF, &[0xDE, 0xAD, 0xBE, 0xEF]));
        match StunMessage::parse(&bytes) {
            Err(IceError::StunUnknownRequiredAttribute { attr_type }) => {
                assert_eq!(attr_type, 0x7FFF);
            }
            other => panic!("expected StunUnknownRequiredAttribute, got {other:?}"),
        }
        // low range is comprehension-required too (e.g. PRIORITY 0x0024)
        let mut bytes = header(0x0101, 8, TXID);
        bytes.extend_from_slice(&tlv(0x0024, &[0x00, 0x00, 0x00, 0x64]));
        assert!(matches!(
            StunMessage::parse(&bytes),
            Err(IceError::StunUnknownRequiredAttribute { attr_type: 0x0024 })
        ));
    }

    #[test]
    fn ignores_unknown_comprehension_optional_attribute() {
        let xma = tlv(ATTR_XOR_MAPPED_ADDRESS, &[0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43]);
        let unknown = tlv(0x8025, &[0xAA, 0xBB, 0xCC]); // 3 bytes -> 1 pad
        let mut bytes = header(0x0101, (xma.len() + unknown.len()) as u16, TXID);
        bytes.extend_from_slice(&xma);
        bytes.extend_from_slice(&unknown);
        let parsed = StunMessage::parse(&bytes).expect("optional attributes are ignored");
        assert_eq!(
            parsed.xor_mapped_address(),
            Some("192.0.2.1:32853".parse().expect("addr"))
        );
        assert_eq!(parsed.attributes.len(), 1);
    }

    #[test]
    fn rejects_duplicate_attributes() {
        let xma = tlv(ATTR_XOR_MAPPED_ADDRESS, &[0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43]);
        let mut bytes = header(0x0101, (xma.len() * 2) as u16, TXID);
        bytes.extend_from_slice(&xma);
        bytes.extend_from_slice(&xma);
        assert!(matches!(
            StunMessage::parse(&bytes),
            Err(IceError::StunDuplicateAttribute { attr_type: ATTR_XOR_MAPPED_ADDRESS })
        ));
        let sw = tlv(ATTR_SOFTWARE, b"SN");
        let mut bytes = header(0x0101, (sw.len() * 2) as u16, TXID);
        bytes.extend_from_slice(&sw);
        bytes.extend_from_slice(&sw);
        assert!(matches!(
            StunMessage::parse(&bytes),
            Err(IceError::StunDuplicateAttribute { attr_type: ATTR_SOFTWARE })
        ));
    }

    #[test]
    fn rejects_xor_mapped_address_malformed_values() {
        // reserved byte nonzero
        let mut value = [0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43];
        value[0] = 0x80;
        assert!(matches!(
            parse_xor_mapped_address_value(&value, &TXID),
            Err(IceError::StunAddressReservedByteNonZero { found: 0x80 })
        ));
        // unsupported family
        let value = [0x00, 0x03, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43];
        assert!(matches!(
            parse_xor_mapped_address_value(&value, &TXID),
            Err(IceError::StunAddressFamilyUnsupported { family: 0x03 })
        ));
        // IPv4 value of wrong length (7 instead of 8)
        let value = [0x00, 0x01, 0xA1, 0x47, 0xE1, 0x12, 0xA6];
        assert!(matches!(
            parse_xor_mapped_address_value(&value, &TXID),
            Err(IceError::StunAddressValueMalformed { len: 7, .. })
        ));
        // IPv6 value of wrong length (19 instead of 20)
        let value = [0x00, 0x02, 0x33, 0x26, 0x01, 0x13, 0xa9, 0xfa, 0x00, 0x11, 0x22, 0x33,
            0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa];
        assert!(matches!(
            parse_xor_mapped_address_value(&value, &TXID),
            Err(IceError::StunAddressValueMalformed { len: 19, .. })
        ));
        // port XORs to zero (raw XOR'd port bytes must equal 0x2112)
        let value = [0x00, 0x01, 0x21, 0x12, 0xE1, 0x12, 0xA6, 0x43];
        assert!(matches!(
            parse_xor_mapped_address_value(&value, &TXID),
            Err(IceError::StunAddressPortZero)
        ));
    }

    #[test]
    fn rejects_bad_software_values() {
        // over the 128-byte cap
        let sw = tlv(ATTR_SOFTWARE, &[b'x'; 129]);
        let mut bytes = header(0x0101, sw.len() as u16, TXID);
        bytes.extend_from_slice(&sw);
        assert!(matches!(
            StunMessage::parse(&bytes),
            Err(IceError::StunSoftwareTooLong { len: 129 })
        ));
        // not UTF-8
        let sw = tlv(ATTR_SOFTWARE, &[0xFF, 0xFE]);
        let mut bytes = header(0x0101, sw.len() as u16, TXID);
        bytes.extend_from_slice(&sw);
        assert!(matches!(
            StunMessage::parse(&bytes),
            Err(IceError::StunSoftwareNotUtf8)
        ));
        // the builder enforces the cap too
        assert!(matches!(
            StunMessage::binding_request(TXID, Some(&"y".repeat(129))),
            Err(IceError::StunSoftwareTooLong { len: 129 })
        ));
        // exactly 128 is fine
        assert!(StunMessage::binding_request(TXID, Some(&"y".repeat(128))).is_ok());
    }
}
