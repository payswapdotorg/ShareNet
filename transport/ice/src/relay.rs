//! TURN-style relay over UDP (RFC 8656 concepts, work item R4-005).
//!
//! Standards-first per architecture lock L011: this follows the TURN
//! allocation model rather than inventing a NAT traversal protocol, and
//! per L012 the relayed datagrams are OPAQUE bytes — the relay parses
//! only its tiny control framing, never the payloads (a QUIC tunnel's
//! packets cross it unmodified; see `crate::bridge` and the integration
//! test).
//!
//! # Model (RFC 8656 concepts, UDP only)
//!
//! - A client allocates from its 5-tuple (its control socket ↔ the relay
//!   control address): one allocation per client 5-tuple. A retransmitted
//!   ALLOCATE with the same nonce returns the same allocation; a NEW
//!   ALLOCATE (different nonce) from the same 5-tuple is refused with
//!   code 437 "Allocation Mismatch" (the RFC 8656 rule).
//! - The relay binds a fresh relayed socket per allocation; peers send
//!   plain UDP datagrams to the relayed address and receive from it.
//! - Traffic between the allocation's client and peers is encapsulated
//!   in the control framing below (the client's single socket cannot
//!   interleave raw peer datagrams with control frames).
//!
//! # Permission-lite (documented simplification)
//!
//! Real TURN installs per-peer permissions (CreatePermission, RFC 8656
//! §7.2). This relay is deliberately simpler: the relayed address
//! forwards peer→client datagrams only after the CLIENT has sent first
//! (any datagram — see [`RelayClient::activate`]); before that, peer
//! datagrams are silently dropped. After activation, forwarding is
//! allowed to/from ANY address. This is a TEST/LOCAL simplification, not
//! a security boundary; production permission enforcement is future
//! R4-006 scope.
//!
//! # TEST/LOCAL scope of the control protocol
//!
//! The framing is a minimal binary header (magic + type + allocation
//! id) — no TURN authentication (no long-term credentials, RFC 8656 §5),
//! no allocation lifetimes, no Refresh, no Delete, no channel binding.
//! It exists so real separate processes can exercise allocation and
//! opaque forwarding over real UDP; production TURN interop and auth
//! are future R4-006 scope. The wire format is documented here and
//! should be registered in `spec/protocol-registry.yaml` by the Tech
//! Lead at integration (workers do not edit `spec/`).
//!
//! # Control framing
//!
//! Every control datagram (both directions):
//!
//! ```text
//!  0      2      4                12
//! +------+------+-----------------+-----------------------------+
//! | 0x53 | 0x4E | msg-type (u16 BE) | allocation id (u64 BE)     |
//! +------+-------------------------+-----------------------------+
//! | payload (the UDP datagram boundary ends the frame)            |
//! +--------------------------------------------------------------+
//! ```
//!
//! Messages (client→relay): `ALLOCATE` (1; the allocation-id field
//! carries the client's random 8-byte nonce; payload empty),
//! `SEND` (3; payload = peer address prefix + opaque data).
//! Messages (relay→client): `ALLOCATE-SUCCESS` (2; payload = the relayed
//! address prefix), `DATA` (4; payload = peer address prefix + opaque
//! data), `RELAY-ERROR` (6; payload = error code u16 BE + UTF-8 reason).
//!
//! Address prefix: 1 byte family (0x01 IPv4 / 0x02 IPv6), 2 bytes port
//! (BE), then 4 or 16 address bytes.
//!
//! # Datagram size policy
//!
//! `MAX_RELAY_DATAGRAM` = 2 MiB (the crate's `MAX_FRAME`-style cap,
//! mirroring the QUIC tunnel and UDP transport siblings): datagrams
//! over the cap are rejected with `RelayDatagramTooLarge` and NEVER
//! split. Honest note: a single UDP datagram cannot exceed ~65 507
//! bytes anyway, so the relay-side rejection is defense in depth; the
//! library-side check is the reachable one.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::error::IceError;
use crate::stun::DatagramPipe;

/// Control-frame magic: ASCII "SN".
pub const RELAY_MAGIC: [u8; 2] = [0x53, 0x4E];
/// Control-frame header length: magic(2) + type(2) + allocation id(8).
pub const RELAY_HEADER_LEN: usize = 12;
/// Maximum relayed datagram (2 MiB — never split; see module docs).
pub const MAX_RELAY_DATAGRAM: usize = 2 * 1024 * 1024;

// Message types (client→relay).
/// ALLOCATE (allocation-id field carries the client nonce).
pub const MSG_ALLOCATE: u16 = 1;
/// A retransmitted ALLOCATE answer carrying the same allocation.
pub const MSG_ALLOCATE_SUCCESS: u16 = 2;
/// Client→peer datagram (payload = peer address prefix + data).
pub const MSG_SEND: u16 = 3;
/// Peer→client datagram (payload = peer address prefix + data).
pub const MSG_DATA: u16 = 4;
/// Relay error report (payload = error code u16 BE + UTF-8 reason).
pub const MSG_RELAY_ERROR: u16 = 6;

// Error codes (437 mirrors RFC 8656's Allocation Mismatch).
/// Structurally invalid control frame.
pub const ERR_MALFORMED: u16 = 1;
/// No allocation with that id (for this relay).
pub const ERR_UNKNOWN_ALLOCATION: u16 = 2;
/// Allocation belongs to a different client 5-tuple.
pub const ERR_NOT_OWNER: u16 = 3;
/// Datagrams over `MAX_RELAY_DATAGRAM` are never split.
pub const ERR_DATAGRAM_TOO_LARGE: u16 = 4;
/// The relay could not forward a datagram to its destination peer.
pub const ERR_FORWARD_FAILED: u16 = 5;
/// RFC 8656 437: the 5-tuple already has an allocation (new nonce).
pub const ERR_ALLOCATION_MISMATCH: u16 = 437;

/// Shared datagram-size limit (send and relay side).
pub fn check_datagram_limit(len: usize) -> Result<(), IceError> {
    if len > MAX_RELAY_DATAGRAM {
        Err(IceError::RelayDatagramTooLarge {
            len,
            max: MAX_RELAY_DATAGRAM,
        })
    } else {
        Ok(())
    }
}

/// One relay control frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFrame {
    pub msg_type: u16,
    pub allocation_id: u64,
    pub payload: Vec<u8>,
}

impl ControlFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RELAY_HEADER_LEN + self.payload.len());
        out.extend_from_slice(&RELAY_MAGIC);
        out.extend_from_slice(&self.msg_type.to_be_bytes());
        out.extend_from_slice(&self.allocation_id.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// Strict parse: the datagram must start with the magic and cover at
    /// least the 12-byte header (the datagram boundary ends the frame —
    /// there is no separate length field to lie about).
    pub fn parse(datagram: &[u8]) -> Result<Self, IceError> {
        if datagram.len() < RELAY_HEADER_LEN {
            return Err(IceError::RelayControlMalformed {
                reason: "frame shorter than the 12-byte header",
            });
        }
        if datagram[0..2] != RELAY_MAGIC {
            return Err(IceError::RelayControlMalformed { reason: "bad magic" });
        }
        let msg_type = u16::from_be_bytes([datagram[2], datagram[3]]);
        let allocation_id = u64::from_be_bytes([
            datagram[4], datagram[5], datagram[6], datagram[7], datagram[8], datagram[9],
            datagram[10], datagram[11],
        ]);
        Ok(ControlFrame {
            msg_type,
            allocation_id,
            payload: datagram[RELAY_HEADER_LEN..].to_vec(),
        })
    }
}

/// Encode an address prefix (family byte + port + address bytes).
pub fn encode_address(addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(3 + 16);
    match addr {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.port().to_be_bytes());
            out.extend_from_slice(&a.ip().octets());
        }
        SocketAddr::V6(a) => {
            out.push(0x02);
            out.extend_from_slice(&a.port().to_be_bytes());
            out.extend_from_slice(&a.ip().octets());
        }
    }
    out
}

/// Parse an address prefix at the start of `payload`; returns the
/// address and the number of bytes it consumed (the rest is data).
pub fn parse_address(payload: &[u8]) -> Result<(SocketAddr, usize), IceError> {
    if payload.len() < 3 {
        return Err(IceError::RelayControlMalformed {
            reason: "address prefix truncated (need family + port)",
        });
    }
    let port = u16::from_be_bytes([payload[1], payload[2]]);
    match payload[0] {
        0x01 => {
            if payload.len() < 7 {
                return Err(IceError::RelayControlMalformed {
                    reason: "IPv4 address prefix truncated",
                });
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&payload[3..7]);
            Ok((SocketAddr::from((std::net::Ipv4Addr::from(ip), port)), 7))
        }
        0x02 => {
            if payload.len() < 19 {
                return Err(IceError::RelayControlMalformed {
                    reason: "IPv6 address prefix truncated",
                });
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&payload[3..19]);
            Ok((SocketAddr::from((std::net::Ipv6Addr::from(ip), port)), 19))
        }
        family => Err(IceError::RelayAddressFamilyUnsupported { family }),
    }
}

fn parse_error_payload(payload: &[u8]) -> Result<(u16, String), IceError> {
    if payload.len() < 2 {
        return Err(IceError::RelayControlMalformed {
            reason: "error payload shorter than the 2-byte code",
        });
    }
    let code = u16::from_be_bytes([payload[0], payload[1]]);
    let reason = String::from_utf8_lossy(&payload[2..]).into_owned();
    Ok((code, reason))
}

// ---------------------------------------------------------------------------
// Relay client (the allocation owner)
// ---------------------------------------------------------------------------

/// The client side of one relay allocation.
#[derive(Debug)]
pub struct RelayClient {
    control: UdpSocket,
    relay_control_addr: SocketAddr,
    allocation_id: u64,
    nonce: u64,
    relayed_addr: SocketAddr,
}

impl RelayClient {
    /// Bind a control socket at `bind` and allocate on the relay at
    /// `relay`. The allocation request carries a fresh random nonce and
    /// is retransmitted (same nonce) up to 3 times.
    pub fn allocate(relay: SocketAddr, bind: SocketAddr) -> Result<Self, IceError> {
        let control = UdpSocket::bind(bind).map_err(|e| {
            IceError::BindFailed(format!("{bind}: {e}"))
        })?;
        Self::allocate_on(control, relay)
    }

    /// Allocate using an existing socket (the 5-tuple is the socket's;
    /// a second ALLOCATE on it is refused by the relay with 437 unless
    /// it is a retransmission with the same nonce).
    pub fn allocate_on(control: UdpSocket, relay: SocketAddr) -> Result<Self, IceError> {
        let nonce = crate::entropy::random_u64()?;
        control
            .set_read_timeout(Some(Duration::from_millis(400)))
            .map_err(|e| IceError::Io(e.to_string()))?;
        let request = ControlFrame {
            msg_type: MSG_ALLOCATE,
            allocation_id: nonce,
            payload: Vec::new(),
        }
        .encode();
        let mut buf = vec![0u8; 65_536];
        const ATTEMPTS: u32 = 3;
        let attempt_timeout = Duration::from_millis(400);
        for _ in 0..ATTEMPTS {
            control
                .send_to(&request, relay)
                .map_err(|e| IceError::Io(e.to_string()))?;
            let deadline = std::time::Instant::now() + attempt_timeout;
            loop {
                if std::time::Instant::now() >= deadline {
                    break;
                }
                match control.recv_from(&mut buf) {
                    Ok((n, peer)) => {
                        if peer != relay {
                            continue; // unrelated source
                        }
                        let frame = ControlFrame::parse(&buf[..n])?;
                        match frame.msg_type {
                            MSG_ALLOCATE_SUCCESS => {
                                let (relayed, consumed) = parse_address(&frame.payload)?;
                                if frame.payload.len() != consumed {
                                    return Err(IceError::RelayControlMalformed {
                                        reason: "allocate-success payload has trailing bytes",
                                    });
                                }
                                return Ok(RelayClient {
                                    control,
                                    relay_control_addr: relay,
                                    allocation_id: frame.allocation_id,
                                    nonce,
                                    relayed_addr: relayed,
                                });
                            }
                            MSG_RELAY_ERROR => {
                                let (code, reason) = parse_error_payload(&frame.payload)?;
                                return Err(IceError::RelayAllocateFailed { code, reason });
                            }
                            other => {
                                return Err(IceError::RelayControlUnexpected { msg_type: other })
                            }
                        }
                    }
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                        ) =>
                    {
                        break; // attempt expired
                    }
                    Err(_) => break, // transport error: retry the attempt
                }
            }
        }
        Err(IceError::RelayTimeout {
            server: relay,
            attempts: ATTEMPTS,
        })
    }

    /// The relayed address of this allocation.
    pub fn relayed_addr(&self) -> SocketAddr {
        self.relayed_addr
    }

    /// The server-assigned allocation id.
    pub fn allocation_id(&self) -> u64 {
        self.allocation_id
    }

    /// The client nonce (ALLOCATION retransmission correlation).
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// The control socket's local address (the candidate base).
    pub fn local_addr(&self) -> Result<SocketAddr, IceError> {
        self.control
            .local_addr()
            .map_err(|e| IceError::Io(e.to_string()))
    }

    /// Set the control socket's read timeout (used by `recv_from`).
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), IceError> {
        self.control
            .set_read_timeout(timeout)
            .map_err(|e| IceError::Io(e.to_string()))
    }

    /// Enable permission-lite forwarding: send one 1-byte datagram
    /// through the relay aimed at the relay's own control address, where
    /// the relay silently discards it. The datagram's only purpose is to
    /// make this client "send first", which switches the allocation's
    /// relayed address into forwarding mode (see the module docs).
    ///
    /// Callers that intend to RECEIVE through the relay must activate
    /// (datagrams from peers are dropped until the client has sent).
    pub fn activate(&self) -> Result<(), IceError> {
        self.send_to(self.relay_control_addr, &[0u8])
    }

    /// Send one opaque datagram to `peer` through the relayed address
    /// (TURN Send semantics: fire-and-forget; errors the relay detects
    /// later surface on the next `recv_from` as `RelaySendFailed`).
    ///
    /// Datagrams over `MAX_RELAY_DATAGRAM` are rejected locally with a
    /// typed error and never split.
    pub fn send_to(&self, peer: SocketAddr, data: &[u8]) -> Result<(), IceError> {
        check_datagram_limit(data.len())?;
        let mut payload = encode_address(peer);
        payload.extend_from_slice(data);
        let frame = ControlFrame {
            msg_type: MSG_SEND,
            allocation_id: self.allocation_id,
            payload,
        };
        self.control
            .send_to(&frame.encode(), self.relay_control_addr)
            .map_err(|e| IceError::Io(format!("relay send: {e}")))?;
        Ok(())
    }

    /// Block until one datagram arrives through the relayed address;
    /// returns the peer that sent it and its length. A read timeout is
    /// reported as `IceError::TimedOut`; a relay error report for a
    /// previously sent datagram is reported as `RelaySendFailed`.
    pub fn recv_from(&self, buf: &mut [u8]) -> Result<(SocketAddr, usize), IceError> {
        let mut frame_buf = vec![0u8; 65_536];
        loop {
            let (n, peer) = match self.control.recv_from(&mut frame_buf) {
                Ok(x) => x,
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    return Err(IceError::TimedOut)
                }
                Err(e) => return Err(IceError::Io(e.to_string())),
            };
            if peer != self.relay_control_addr {
                continue; // unrelated source: discard
            }
            let frame = ControlFrame::parse(&frame_buf[..n])?;
            match frame.msg_type {
                MSG_DATA => {
                    let (peer_addr, consumed) = parse_address(&frame.payload)?;
                    let data = &frame.payload[consumed..];
                    if data.len() > buf.len() {
                        return Err(IceError::RecvBufferTooSmall {
                            needed: data.len(),
                            have: buf.len(),
                        });
                    }
                    buf[..data.len()].copy_from_slice(data);
                    return Ok((peer_addr, data.len()));
                }
                MSG_RELAY_ERROR => {
                    let (code, reason) = parse_error_payload(&frame.payload)?;
                    return Err(IceError::RelaySendFailed { code, reason });
                }
                other => return Err(IceError::RelayControlUnexpected { msg_type: other }),
            }
        }
    }
}

impl DatagramPipe for RelayClient {
    fn pipe_send_to(&self, target: SocketAddr, data: &[u8]) -> Result<(), IceError> {
        self.send_to(target, data)
    }

    fn pipe_recv_from(&self, buf: &mut [u8]) -> Result<(SocketAddr, usize), IceError> {
        self.recv_from(buf)
    }

    fn pipe_set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), IceError> {
        self.set_read_timeout(timeout)
    }

    fn pipe_local_addr(&self) -> Result<SocketAddr, IceError> {
        self.local_addr()
    }
}

// ---------------------------------------------------------------------------
// Relay server
// ---------------------------------------------------------------------------

struct Allocation {
    id: u64,
    owner: SocketAddr,
    nonce: u64,
    relayed: Arc<UdpSocket>,
    relayed_addr: SocketAddr,
    /// Permission-lite state: peer→client forwarding is enabled only
    /// after the client's first SEND.
    active: AtomicBool,
}

/// The relay server: one control socket, one relayed socket (and one
/// forwarder thread) per allocation. Runs until the process is stopped.
pub struct RelayServer {
    control: Arc<UdpSocket>,
    allocations: Mutex<HashMap<u64, Arc<Allocation>>>,
    by_tuple: Mutex<HashMap<SocketAddr, u64>>,
    next_id: AtomicU64,
}

impl RelayServer {
    /// Bind the relay's control address. The address MUST have a concrete
    /// (non-wildcard) IP: relayed sockets inherit it, and a wildcard
    /// would produce unusable relayed addresses such as `0.0.0.0:port`
    /// (rejected with `RelayBindUnspecified`).
    pub fn bind(addr: SocketAddr) -> Result<Self, IceError> {
        if addr.ip().is_unspecified() {
            return Err(IceError::RelayBindUnspecified { addr });
        }
        let control = Arc::new(
            UdpSocket::bind(addr)
                .map_err(|e| IceError::BindFailed(format!("{addr}: {e}")))?,
        );
        Ok(RelayServer {
            control,
            allocations: Mutex::new(HashMap::new()),
            by_tuple: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        })
    }

    /// The relay's control address (what clients allocate on).
    pub fn control_addr(&self) -> Result<SocketAddr, IceError> {
        self.control
            .local_addr()
            .map_err(|e| IceError::Io(e.to_string()))
    }

    /// Serve allocations forever. Adversarial input NEVER kills the relay:
    /// unparseable datagrams are dropped, semantically invalid control
    /// frames get a RELAY-ERROR reply, and every failure is reported and
    /// carried on.
    pub fn run(&self) -> Result<(), IceError> {
        let mut buf = vec![0u8; 65_536];
        loop {
            let (n, from) = self
                .control
                .recv_from(&mut buf)
                .map_err(|e| IceError::Io(e.to_string()))?;
            if let Err(e) = self.handle_control(from, &buf[..n]) {
                eprintln!("relay: control handling from {from} failed: {e}");
            }
        }
    }

    fn handle_control(&self, from: SocketAddr, datagram: &[u8]) -> Result<(), IceError> {
        // Garbage / non-relay datagrams: silently dropped (never a
        // reply — a garbage source could be spoofed).
        let frame = match ControlFrame::parse(datagram) {
            Ok(f) => f,
            Err(_) => return Ok(()),
        };
        match frame.msg_type {
            MSG_ALLOCATE => self.handle_allocate(from, frame),
            MSG_SEND => self.handle_send(from, frame),
            // Server→client message types arriving from a client: misuse.
            MSG_ALLOCATE_SUCCESS | MSG_DATA | MSG_RELAY_ERROR => {
                self.reply_error(from, frame.allocation_id, ERR_MALFORMED, "unexpected message type")
            }
            _ => self.reply_error(from, frame.allocation_id, ERR_MALFORMED, "unknown message type"),
        }
    }

    fn handle_allocate(&self, from: SocketAddr, frame: ControlFrame) -> Result<(), IceError> {
        if !frame.payload.is_empty() {
            return self.reply_error(
                from,
                frame.allocation_id,
                ERR_MALFORMED,
                "allocate payload must be empty",
            );
        }
        let nonce = frame.allocation_id;

        // One allocation per client 5-tuple (RFC 8656 §5: the 5-tuple
        // identifies the allocation).
        let mut by_tuple = self.by_tuple.lock().expect("by_tuple lock");
        if let Some(id) = by_tuple.get(&from).copied() {
            let allocations = self.allocations.lock().expect("allocations lock");
            if let Some(existing) = allocations.get(&id) {
                if existing.nonce == nonce {
                    // Retransmission of the same ALLOCATE: the same
                    // response (RFC 8656 retransmission rule).
                    let success = ControlFrame {
                        msg_type: MSG_ALLOCATE_SUCCESS,
                        allocation_id: existing.id,
                        payload: encode_address(existing.relayed_addr),
                    };
                    return self.send_frame(&success.encode(), from);
                }
                // A genuinely new ALLOCATE on an allocated 5-tuple.
                return self.reply_error(
                    from,
                    nonce,
                    ERR_ALLOCATION_MISMATCH,
                    "allocation already exists for this 5-tuple (RFC 8656 437)",
                );
            }
        }

        // Fresh allocation.
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let host = self.control_addr()?.ip();
        let relayed = Arc::new(
            UdpSocket::bind(SocketAddr::new(host, 0))
                .map_err(|e| IceError::BindFailed(format!("relayed socket: {e}")))?,
        );
        let relayed_addr = relayed
            .local_addr()
            .map_err(|e| IceError::Io(e.to_string()))?;
        let allocation = Arc::new(Allocation {
            id,
            owner: from,
            nonce,
            relayed: relayed.clone(),
            relayed_addr,
            active: AtomicBool::new(false),
        });

        // The relayed-address forwarder: peer datagrams → the client,
        // as DATA frames over the control channel. Payloads stay opaque
        // (L012) — only the address prefix is added.
        {
            let control = self.control.clone();
            let allocation = allocation.clone();
            std::thread::Builder::new()
                .name(format!("relay-forward-{id}"))
                .spawn(move || {
                    let mut buf = [0u8; 65_536];
                    loop {
                        match allocation.relayed.recv_from(&mut buf) {
                            Ok((n, peer)) => {
                                if !allocation.active.load(Ordering::SeqCst) {
                                    // Permission-lite: silent until the
                                    // client has sent first.
                                    continue;
                                }
                                let mut payload = encode_address(peer);
                                payload.extend_from_slice(&buf[..n]);
                                let frame = ControlFrame {
                                    msg_type: MSG_DATA,
                                    allocation_id: allocation.id,
                                    payload,
                                };
                                if let Err(e) =
                                    control.send_to(&frame.encode(), allocation.owner)
                                {
                                    eprintln!(
                                        "relay: forwarding DATA to {} failed: {e}",
                                        allocation.owner
                                    );
                                }
                            }
                            Err(e) => {
                                eprintln!("relay: relayed socket error: {e}");
                            }
                        }
                    }
                })
                .map_err(|e| IceError::Io(format!("spawn forwarder: {e}")))?;
        }

        self.allocations
            .lock()
            .expect("allocations lock")
            .insert(id, allocation);
        by_tuple.insert(from, id);

        let success = ControlFrame {
            msg_type: MSG_ALLOCATE_SUCCESS,
            allocation_id: id,
            payload: encode_address(relayed_addr),
        };
        eprintln!(
            "relay: ALLOCATION {id} owner {from} relayed {relayed_addr} (nonce {nonce})"
        );
        self.send_frame(&success.encode(), from)
    }

    fn handle_send(&self, from: SocketAddr, frame: ControlFrame) -> Result<(), IceError> {
        let allocation = {
            let allocations = self.allocations.lock().expect("allocations lock");
            match allocations.get(&frame.allocation_id) {
                Some(a) => a.clone(),
                None => {
                    return self.reply_error(
                        from,
                        frame.allocation_id,
                        ERR_UNKNOWN_ALLOCATION,
                        "no allocation with that id",
                    )
                }
            }
        };
        if allocation.owner != from {
            return self.reply_error(
                from,
                frame.allocation_id,
                ERR_NOT_OWNER,
                "allocation belongs to another client 5-tuple",
            );
        }
        let (peer, consumed) = match parse_address(&frame.payload) {
            Ok(x) => x,
            Err(_) => {
                return self.reply_error(
                    from,
                    frame.allocation_id,
                    ERR_MALFORMED,
                    "send payload lacks a valid peer address prefix",
                )
            }
        };
        let data = &frame.payload[consumed..];
        if check_datagram_limit(data.len()).is_err() {
            // Unreachable over plain UDP (datagram bound ~65 507) —
            // defense in depth for the 2 MiB policy; never split.
            return self.reply_error(
                from,
                frame.allocation_id,
                ERR_DATAGRAM_TOO_LARGE,
                "datagram exceeds MAX_RELAY_DATAGRAM (never split)",
            );
        }
        // Permission-lite activation: the client has now sent.
        allocation.active.store(true, Ordering::SeqCst);
        if let Err(e) = allocation.relayed.send_to(data, peer) {
            // The forward itself failed (e.g. unreachable network):
            // surface it to the client as a RELAY-ERROR report, matching
            // `RelayClient::send_to`'s documented error surfacing.
            return self.reply_error(
                from,
                frame.allocation_id,
                ERR_FORWARD_FAILED,
                &format!("forward to {peer} failed: {e}"),
            );
        }
        Ok(())
    }

    fn reply_error(
        &self,
        to: SocketAddr,
        allocation_id: u64,
        code: u16,
        reason: &str,
    ) -> Result<(), IceError> {
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(reason.as_bytes());
        let frame = ControlFrame {
            msg_type: MSG_RELAY_ERROR,
            allocation_id,
            payload,
        };
        self.send_frame(&frame.encode(), to)
    }

    fn send_frame(&self, bytes: &[u8], to: SocketAddr) -> Result<(), IceError> {
        self.control
            .send_to(bytes, to)
            .map(|_| ())
            .map_err(|e| IceError::Io(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// Server-side pump: make a real UDP server reachable at the relayed address
// ---------------------------------------------------------------------------

/// Pumps opaque datagrams between an allocation's relayed address and a
/// real local UDP server, so a UDP server that cannot speak the relay
/// control protocol becomes reachable at the relayed address:
///
/// ```text
/// QUIC/UDP client → relayed addr R → (DATA) → pump → real server S
/// real server S   → pump → (SEND)  → relay   → R    → QUIC/UDP client
/// ```
///
/// The relayed datagrams are untouched (L012) — the QUIC tunnel test in
/// `tests/ice_multiprocess.rs` rides a full pinned QUIC/TLS 1.3 session
/// through this pump.
///
/// Single active peer session: datagrams from `target` are forwarded to
/// the most recent peer that sent through the relayed address (one
/// 4-tuple at a time — enough for tunnel bring-up; documented
/// TEST/LOCAL simplification). `stop()` unblocks both pump threads.
pub struct RelayServerAdapter {
    relayed_addr: SocketAddr,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl RelayServerAdapter {
    /// Start pumping between `client`'s allocation and the UDP server at
    /// `target`. Activates the allocation first (permission-lite warm-up)
    /// so peers' datagrams flow before the local side sends anything.
    pub fn start(client: RelayClient, target: SocketAddr) -> Result<Self, IceError> {
        client.activate()?;
        let relayed_addr = client.relayed_addr();
        client.set_read_timeout(Some(Duration::from_millis(100)))?;
        let local_bind: SocketAddr = if target.is_ipv4() {
            "127.0.0.1:0".parse().expect("static addr")
        } else {
            "[::1]:0".parse().expect("static addr")
        };
        let to_server = Arc::new(
            UdpSocket::bind(local_bind)
                .map_err(|e| IceError::BindFailed(format!("pump socket: {e}")))?,
        );
        to_server
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| IceError::Io(e.to_string()))?;

        let client = Arc::new(client);
        let stop = Arc::new(AtomicBool::new(false));
        let last_peer: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
        let mut threads = Vec::with_capacity(2);

        // relay → server (DATA frames in, raw datagrams out)
        {
            let client = client.clone();
            let to_server = to_server.clone();
            let stop = stop.clone();
            let last_peer = last_peer.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("relay-adapter-in".into())
                    .spawn(move || {
                        let mut buf = [0u8; 65_536];
                        while !stop.load(Ordering::SeqCst) {
                            match client.recv_from(&mut buf) {
                                Ok((peer, n)) => {
                                    *last_peer.lock().expect("last_peer lock") = Some(peer);
                                    if let Err(e) = to_server.send_to(&buf[..n], target) {
                                        eprintln!("relay adapter: forward to server failed: {e}");
                                    }
                                }
                                Err(IceError::TimedOut) => continue,
                                Err(e) => {
                                    eprintln!("relay adapter: control receive failed: {e}");
                                    return;
                                }
                            }
                        }
                    })
                    .expect("spawn relay-adapter-in"),
            );
        }

        // server → relay (raw datagrams in, SEND frames out)
        {
            let client = client.clone();
            let to_server = to_server.clone();
            let stop = stop.clone();
            threads.push(
                std::thread::Builder::new()
                    .name("relay-adapter-out".into())
                    .spawn(move || {
                        let mut buf = [0u8; 65_536];
                        while !stop.load(Ordering::SeqCst) {
                            match to_server.recv_from(&mut buf) {
                                Ok((n, from)) => {
                                    if from != target {
                                        continue; // only the pinned server
                                    }
                                    let peer_guard = last_peer.lock().expect("last_peer lock");
                                    if let Some(peer) = peer_guard.as_ref() {
                                        if let Err(e) = client.send_to(*peer, &buf[..n]) {
                                            eprintln!("relay adapter: send via relay failed: {e}");
                                        }
                                    }
                                }
                                Err(e)
                                    if matches!(
                                        e.kind(),
                                        std::io::ErrorKind::WouldBlock
                                            | std::io::ErrorKind::TimedOut
                                    ) =>
                                {
                                    continue
                                }
                                Err(e) => {
                                    eprintln!("relay adapter: server receive failed: {e}");
                                    return;
                                }
                            }
                        }
                    })
                    .expect("spawn relay-adapter-out"),
            );
        }

        Ok(RelayServerAdapter {
            relayed_addr,
            stop,
            threads,
        })
    }

    /// The relayed address this adapter serves.
    pub fn relayed_addr(&self) -> SocketAddr {
        self.relayed_addr
    }

    /// Stop both pump threads (waits at most one poll cycle each).
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests: control-frame codec, address prefixes, datagram limits
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn datagram_limit_enforced() {
        assert_eq!(check_datagram_limit(0), Ok(()));
        assert_eq!(check_datagram_limit(MAX_RELAY_DATAGRAM), Ok(()));
        assert_eq!(
            check_datagram_limit(MAX_RELAY_DATAGRAM + 1),
            Err(IceError::RelayDatagramTooLarge {
                len: MAX_RELAY_DATAGRAM + 1,
                max: MAX_RELAY_DATAGRAM,
            })
        );
    }

    #[test]
    fn control_frame_roundtrip() {
        for payload in [
            Vec::new(),
            vec![0x00, 0x01, 0xA1],
            b"opaque payload bytes \x00\xFF".to_vec(),
            vec![0xAB; 512],
        ] {
            let frame = ControlFrame {
                msg_type: MSG_SEND,
                allocation_id: 0x0102_0304_0506_0708,
                payload: payload.clone(),
            };
            let bytes = frame.encode();
            assert_eq!(bytes.len(), RELAY_HEADER_LEN + payload.len());
            assert_eq!(ControlFrame::parse(&bytes), Ok(frame));
        }
    }

    #[test]
    fn control_frame_strict_rejects() {
        // shorter than the 12-byte header
        assert!(matches!(
            ControlFrame::parse(&[0x53, 0x4E, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            Err(IceError::RelayControlMalformed { .. })
        ));
        assert!(matches!(
            ControlFrame::parse(&[]),
            Err(IceError::RelayControlMalformed { .. })
        ));
        // wrong magic
        let mut bytes = ControlFrame {
            msg_type: MSG_ALLOCATE,
            allocation_id: 1,
            payload: Vec::new(),
        }
        .encode();
        bytes[0] = 0x54;
        assert!(matches!(
            ControlFrame::parse(&bytes),
            Err(IceError::RelayControlMalformed { .. })
        ));
    }

    #[test]
    fn address_prefix_roundtrip_v4_v6() {
        for addr in ["127.0.0.1:5300", "192.0.2.33:49171", "[2001:db8::1]:4660", "[::1]:65535"] {
            let addr: SocketAddr = addr.parse().expect("addr");
            let encoded = encode_address(addr);
            assert_eq!(encoded.len(), if addr.is_ipv4() { 7 } else { 19 });
            let (parsed, consumed) = parse_address(&encoded).expect("parse");
            assert_eq!(parsed, addr);
            assert_eq!(consumed, encoded.len());
            // trailing bytes after the prefix are data, not part of it
            let mut with_data = encoded.clone();
            with_data.extend_from_slice(b"data");
            let (parsed, consumed) = parse_address(&with_data).expect("parse");
            assert_eq!(parsed, addr);
            assert_eq!(&with_data[consumed..], b"data");
        }
    }

    #[test]
    fn address_prefix_strict_rejects() {
        // unsupported family
        assert!(matches!(
            parse_address(&[0x03, 0x14, 0x51, 1, 2, 3, 4]),
            Err(IceError::RelayAddressFamilyUnsupported { family: 0x03 })
        ));
        // IPv4 truncated (6 bytes instead of 7)
        assert!(matches!(
            parse_address(&[0x01, 0x14, 0x51, 1, 2, 3]),
            Err(IceError::RelayControlMalformed { .. })
        ));
        // IPv6 truncated (18 bytes instead of 19)
        assert!(matches!(
            parse_address(&[0x02, 0x12, 0x34, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]),
            Err(IceError::RelayControlMalformed { .. })
        ));
        // not even family + port
        assert!(matches!(
            parse_address(&[0x01, 0x14]),
            Err(IceError::RelayControlMalformed { .. })
        ));
    }

    #[test]
    fn relay_server_bind_rejects_wildcard_control_address() {
        for addr in ["0.0.0.0:3478", "[::]:3478"] {
            let addr: SocketAddr = addr.parse().expect("addr");
            assert!(matches!(
                RelayServer::bind(addr),
                Err(IceError::RelayBindUnspecified { addr: rejected }) if rejected == addr
            ));
        }
    }
}
