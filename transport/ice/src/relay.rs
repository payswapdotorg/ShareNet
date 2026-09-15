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
//! scope (R4-007 and beyond).
//!
//! # Allocation authentication (R4-006, RFC 5389 §10.2 concepts)
//!
//! [`RelayServer::bind`] starts an UNAUTHENTICATED relay (the R4-005
//! TEST/LOCAL behavior, kept for the unauthenticated flows).
//! [`RelayServer::bind_authenticated`] starts one that demands a
//! long-term-credential proof before any allocation exists:
//!
//! 1. a plain `ALLOCATE` is answered with `ALLOCATE-CHALLENGE`
//!    (message 7) carrying the relay's `realm` and a fresh 16-byte
//!    `nonce` — the RFC 5389 §10.2 401/NONCE/REALM model in the SN
//!    control framing;
//! 2. the client retries with `ALLOCATE-AUTH` (message 5):
//!    `payload = [username-len u16][username][realm-len u16][realm]
//!    [auth-nonce 16][MAC 32]`, where `MAC = HMAC-SHA256(key, frame[0..end-32])`
//!    — a message-integrity proof binding the ENTIRE allocation request
//!    (transaction nonce, username, realm, auth-nonce) to the shared
//!    secret; `key = SHA-256(username ":" realm ":" secret)` — the
//!    RFC 5389 §15.4 long-term-key construction with the repo-standard
//!    SHA-2 (the `sha1` crate would be a NEW dependency; `hmac` 0.12
//!    and `sha2` 0.10 are already in this crate's dependency tree via
//!    `transport/quic`/rustls, so the auth adds ZERO new crates);
//! 3. the nonce is SELF-VALIDATING and 5-TUPLE-BOUND:
//!    `nonce = [unix-seconds u64 BE][trunc8-HMAC-SHA256(relay-key,
//!    "SN-relay-nonce" | client-addr | unix-seconds)]` — the relay keeps
//!    NO per-nonce state (challenge floods cannot exhaust memory) and a
//!    nonce issued to one client 5-tuple is refused for another;
//! 4. failure codes follow the RFC model: 401 (unknown user or
//!    integrity mismatch — replied identically so credential probing
//!    cannot distinguish them, and a dummy MAC is computed on unknown
//!    users to blunt a timing oracle), 438 (stale or mis-issued
//!    nonce), plus the existing 437 (allocation mismatch) AFTER the
//!    credential proof. An identical retransmission of a successful
//!    ALLOCATE-AUTH returns the same cached response (RFC 5389 §10.2.2
//!    retransmission semantics); a MODIFIED transaction (a captured
//!    proof replayed under a different transaction nonce) fails the
//!    MAC and is refused with 401 — the proof is transaction-bound.
//!
//! The relay treats everything except this tiny control framing as
//! opaque bytes (L012): authentication gates ALLOCATIONS, never data.
//!
//! # TEST/LOCAL scope of the control protocol
//!
//! The framing is a minimal binary header (magic + type + allocation
//! id) — no allocation lifetimes, no Refresh, no Delete, no channel
//! binding. It exists so real separate processes can exercise allocation
//! and opaque forwarding over real UDP; production TURN interop is
//! R4-007 scope (allocation AUTHENTICATION landed in R4-006 — see the
//! section above). The wire format is documented here and should be
//! registered in `spec/protocol-registry.yaml` by the Tech Lead at
//! integration (workers do not edit `spec/`).
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
//! `ALLOCATE-AUTH` (5; payload = username/realm/nonce/proof — see the
//! authentication section), `SEND` (3; payload = peer address prefix +
//! opaque data).
//! Messages (relay→client): `ALLOCATE-SUCCESS` (2; payload = the relayed
//! address prefix), `DATA` (4; payload = peer address prefix + opaque
//! data), `RELAY-ERROR` (6; payload = error code u16 BE + UTF-8 reason),
//! `ALLOCATE-CHALLENGE` (7; payload = realm + auth nonce).
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

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

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
/// Authenticated allocation (payload = username/realm/nonce/proof).
pub const MSG_ALLOCATE_AUTH: u16 = 5;
/// Relay error report (payload = error code u16 BE + UTF-8 reason).
pub const MSG_RELAY_ERROR: u16 = 6;
/// Auth demand: payload = realm + fresh auth nonce (R4-006).
pub const MSG_ALLOCATE_CHALLENGE: u16 = 7;

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
/// RFC 5389-style 401: wrong credential / integrity mismatch (R4-006).
pub const ERR_UNAUTHORIZED: u16 = 401;
/// RFC 5389-style 438: stale or mis-issued auth nonce (R4-006).
pub const ERR_STALE_NONCE: u16 = 438;

// Authentication framing constants (R4-006; see the module docs).
/// Auth-username cap in bytes (the RFC 5389 USERNAME scale-down).
pub const AUTH_USERNAME_MAX_BYTES: usize = 64;
/// Auth-realm cap in bytes (the RFC 5389 REALM scale-down).
pub const AUTH_REALM_MAX_BYTES: usize = 128;
/// Auth nonce length: 8-byte unix timestamp + 8-byte truncated HMAC.
pub const AUTH_NONCE_LEN: usize = 16;
/// Message-integrity MAC length (HMAC-SHA256).
pub const AUTH_MAC_LEN: usize = 32;
/// How long an issued auth nonce stays valid (RFC 5389 nonce lifetime).
pub const AUTH_NONCE_WINDOW_SECONDS: u64 = 120;

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
// Allocation authentication (R4-006, RFC 5389 §10.2 concepts — see the
// module docs for the model and the framing)
// ---------------------------------------------------------------------------

/// A long-term relay credential (RFC 5389 §10.2 scale-down: username +
/// shared secret; the derived MAC key is `SHA-256(username ":" realm
/// ":" secret)` — the RFC 5389 §15.4 construction with the repo-standard
/// SHA-2 instead of MD5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayCredential {
    pub username: String,
    pub secret: String,
}

impl RelayCredential {
    /// Parse `username:secret` (the CLI / config form). Exactly one `:`
    /// separates them; both parts must be non-empty and the username
    /// must respect the framing cap.
    pub fn parse(text: &str) -> Result<Self, IceError> {
        let (username, secret) = text.split_once(':').ok_or(
            IceError::RelayAuthConfigInvalid {
                reason: "credential must be `username:secret`",
            },
        )?;
        let credential = RelayCredential {
            username: username.to_string(),
            secret: secret.to_string(),
        };
        credential.validate()?;
        Ok(credential)
    }

    /// Fail-closed validation against the framing caps.
    pub fn validate(&self) -> Result<(), IceError> {
        if self.username.is_empty() {
            return Err(IceError::RelayAuthConfigInvalid {
                reason: "credential username must not be empty",
            });
        }
        if self.username.len() > AUTH_USERNAME_MAX_BYTES {
            return Err(IceError::RelayAuthConfigInvalid {
                reason: "credential username exceeds the framing cap",
            });
        }
        if self.secret.is_empty() {
            return Err(IceError::RelayAuthConfigInvalid {
                reason: "credential secret must not be empty",
            });
        }
        Ok(())
    }
}

/// The long-term MAC key derived from a credential (RFC 5389 §15.4
/// construction, SHA-256 instead of the obsolete MD5 — see the module
/// docs; cross-checked against Python's hashlib in the unit tests).
pub fn long_term_key(username: &str, realm: &str, secret: &str) -> [u8; 32] {
    let mut material = Vec::with_capacity(
        username.len() + realm.len() + secret.len() + 2,
    );
    material.extend_from_slice(username.as_bytes());
    material.push(b':');
    material.extend_from_slice(realm.as_bytes());
    material.push(b':');
    material.extend_from_slice(secret.as_bytes());
    Sha256::digest(&material).into()
}

type HmacSha256 = Hmac<Sha256>;

fn hmac_sha256(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key)
        .expect("HMAC accepts any key length");
    mac.update(message);
    mac.finalize().into_bytes().into()
}

fn unix_seconds_now() -> Result<u64, IceError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| IceError::Io(format!("system clock before the epoch: {e}")))
}

/// The self-validating, 5-tuple-bound auth nonce for `client` at
/// `unix_seconds`: `[unix-seconds u64 BE][trunc8 HMAC]`. The relay keeps
/// no per-nonce state — the nonce proves its own freshness and the
/// 5-tuple it was issued to (see the module docs).
pub fn nonce_for(
    relay_key: &[u8; 32],
    client: SocketAddr,
    unix_seconds: u64,
) -> [u8; AUTH_NONCE_LEN] {
    let mut nonce = [0u8; AUTH_NONCE_LEN];
    nonce[..8].copy_from_slice(&unix_seconds.to_be_bytes());
    let mut material = b"SN-relay-nonce".to_vec();
    material.extend_from_slice(&encode_address(client));
    material.extend_from_slice(&unix_seconds.to_be_bytes());
    let tag = hmac_sha256(relay_key, &material);
    nonce[8..].copy_from_slice(&tag[..8]);
    nonce
}

/// Strict nonce validation: the embedded timestamp must be within
/// `window_seconds` of `now_unix`, and the truncated HMAC must match the
/// one the relay would have issued for THIS 5-tuple at that time.
pub fn nonce_valid(
    relay_key: &[u8; 32],
    client: SocketAddr,
    nonce: &[u8; AUTH_NONCE_LEN],
    now_unix: u64,
    window_seconds: u64,
) -> bool {
    let mut seconds = [0u8; 8];
    seconds.copy_from_slice(&nonce[..8]);
    let issued = u64::from_be_bytes(seconds);
    // A wrapped comparison is fine: any |delta| beyond the window fails.
    let delta = now_unix.abs_diff(issued);
    if delta > window_seconds {
        return false;
    }
    nonce_for(relay_key, client, issued) == *nonce
}

/// Encode an ALLOCATE-CHALLENGE payload: `[realm-len u16][realm][nonce]`.
pub fn encode_challenge_payload(
    realm: &str,
    nonce: &[u8; AUTH_NONCE_LEN],
) -> Result<Vec<u8>, IceError> {
    if realm.is_empty() || realm.len() > AUTH_REALM_MAX_BYTES {
        return Err(IceError::RelayAuthConfigInvalid {
            reason: "realm must be 1..=128 bytes",
        });
    }
    let mut payload = Vec::with_capacity(2 + realm.len() + AUTH_NONCE_LEN);
    payload.extend_from_slice(&(realm.len() as u16).to_be_bytes());
    payload.extend_from_slice(realm.as_bytes());
    payload.extend_from_slice(nonce);
    Ok(payload)
}

/// Strict parse of an ALLOCATE-CHALLENGE payload: exact consume, UTF-8
/// realm within the cap, no trailing bytes.
pub fn parse_challenge_payload(
    payload: &[u8],
) -> Result<(String, [u8; AUTH_NONCE_LEN]), IceError> {
    if payload.len() < 2 {
        return Err(IceError::RelayAuthMalformed {
            reason: "challenge payload shorter than the realm length",
        });
    }
    let realm_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if realm_len == 0 || realm_len > AUTH_REALM_MAX_BYTES {
        return Err(IceError::RelayAuthMalformed {
            reason: "challenge realm length out of range",
        });
    }
    let end = 2 + realm_len;
    if payload.len() != end + AUTH_NONCE_LEN {
        return Err(IceError::RelayAuthMalformed {
            reason: "challenge payload length mismatch (trailing or truncated)",
        });
    }
    let realm = std::str::from_utf8(&payload[2..end])
        .map_err(|_| IceError::RelayAuthMalformed {
            reason: "challenge realm is not UTF-8",
        })?
        .to_string();
    let mut nonce = [0u8; AUTH_NONCE_LEN];
    nonce.copy_from_slice(&payload[end..]);
    Ok((realm, nonce))
}

/// A strictly-parsed ALLOCATE-AUTH frame (server side; the client builds
/// with [`encode_allocate_auth`]). `mac_input` is the exact byte string
/// the message-integrity MAC covers — the whole frame minus the MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedAllocateAuth {
    pub username: String,
    pub realm: String,
    pub auth_nonce: [u8; AUTH_NONCE_LEN],
    pub mac: [u8; AUTH_MAC_LEN],
    /// The MAC's input: the full frame without the trailing 32 MAC bytes.
    pub mac_input: Vec<u8>,
}

/// Build the full ALLOCATE-AUTH datagram:
/// `magic | type | transaction-nonce | identity fields | MAC` where
/// `MAC = HMAC-SHA256(key, frame[0..end-32])` binds the whole request.
pub fn encode_allocate_auth(
    transaction_nonce: u64,
    username: &str,
    realm: &str,
    auth_nonce: &[u8; AUTH_NONCE_LEN],
    key: &[u8; 32],
) -> Result<Vec<u8>, IceError> {
    if username.is_empty() || username.len() > AUTH_USERNAME_MAX_BYTES {
        return Err(IceError::RelayAuthConfigInvalid {
            reason: "username must be 1..=64 bytes",
        });
    }
    if realm.is_empty() || realm.len() > AUTH_REALM_MAX_BYTES {
        return Err(IceError::RelayAuthConfigInvalid {
            reason: "realm must be 1..=128 bytes",
        });
    }
    let mut frame = Vec::with_capacity(
        RELAY_HEADER_LEN + 2 + username.len() + 2 + realm.len() + AUTH_NONCE_LEN + AUTH_MAC_LEN,
    );
    frame.extend_from_slice(&RELAY_MAGIC);
    frame.extend_from_slice(&MSG_ALLOCATE_AUTH.to_be_bytes());
    frame.extend_from_slice(&transaction_nonce.to_be_bytes());
    frame.extend_from_slice(&(username.len() as u16).to_be_bytes());
    frame.extend_from_slice(username.as_bytes());
    frame.extend_from_slice(&(realm.len() as u16).to_be_bytes());
    frame.extend_from_slice(realm.as_bytes());
    frame.extend_from_slice(auth_nonce);
    let mac = hmac_sha256(key, &frame);
    frame.extend_from_slice(&mac);
    Ok(frame)
}

/// Strict parse of an ALLOCATE-AUTH control frame payload (the header is
/// already stripped by [`ControlFrame::parse`]; `allocation_id` is the
/// transaction nonce). Exact consume, UTF-8 fields within the caps,
/// structurally complete MAC — fail-closed on anything else.
pub fn parse_allocate_auth(
    allocation_id: u64,
    payload: &[u8],
) -> Result<ParsedAllocateAuth, IceError> {
    let malformed = |reason: &'static str| Err(IceError::RelayAuthMalformed { reason });
    let min = 2 + AUTH_NONCE_LEN + AUTH_MAC_LEN;
    if payload.len() < min + 2 {
        return malformed("auth payload too short for the fixed fields");
    }
    let username_len = u16::from_be_bytes([payload[0], payload[1]]) as usize;
    if username_len == 0 || username_len > AUTH_USERNAME_MAX_BYTES {
        return malformed("auth username length out of range");
    }
    let username_end = 2 + username_len;
    if payload.len() < username_end + 2 {
        return malformed("auth payload truncated before the realm length");
    }
    let username = std::str::from_utf8(&payload[2..username_end])
        .map_err(|_| IceError::RelayAuthMalformed {
            reason: "auth username is not UTF-8",
        })?
        .to_string();
    let realm_len =
        u16::from_be_bytes([payload[username_end], payload[username_end + 1]]) as usize;
    if realm_len == 0 || realm_len > AUTH_REALM_MAX_BYTES {
        return malformed("auth realm length out of range");
    }
    let realm_end = username_end + 2 + realm_len;
    if payload.len() != realm_end + AUTH_NONCE_LEN + AUTH_MAC_LEN {
        return malformed("auth payload length mismatch (trailing or truncated)");
    }
    let realm = std::str::from_utf8(&payload[username_end + 2..realm_end])
        .map_err(|_| IceError::RelayAuthMalformed {
            reason: "auth realm is not UTF-8",
        })?
        .to_string();
    let mut auth_nonce = [0u8; AUTH_NONCE_LEN];
    auth_nonce.copy_from_slice(&payload[realm_end..realm_end + AUTH_NONCE_LEN]);
    let mut mac = [0u8; AUTH_MAC_LEN];
    let mac_at = realm_end + AUTH_NONCE_LEN;
    mac.copy_from_slice(&payload[mac_at..mac_at + AUTH_MAC_LEN]);
    // Reconstruct the MAC input exactly as the encoder built it: the
    // frame header (magic, type, transaction nonce) + identity fields.
    let mut mac_input = Vec::with_capacity(mac_at + RELAY_HEADER_LEN);
    mac_input.extend_from_slice(&RELAY_MAGIC);
    mac_input.extend_from_slice(&MSG_ALLOCATE_AUTH.to_be_bytes());
    mac_input.extend_from_slice(&allocation_id.to_be_bytes());
    mac_input.extend_from_slice(&payload[..mac_at]);
    Ok(ParsedAllocateAuth {
        username,
        realm,
        auth_nonce,
        mac,
        mac_input,
    })
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
                            // An authenticated relay demands a proof this
                            // uncredentialed path cannot produce (typed,
                            // fail-closed — see `allocate_authenticated`).
                            MSG_ALLOCATE_CHALLENGE => {
                                return Err(IceError::RelayAuthRequired)
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

    /// Bind a control socket at `bind` and allocate on the relay at
    /// `relay` with a long-term credential (R4-006): plain ALLOCATE →
    /// ALLOCATE-CHALLENGE (realm + nonce) → ALLOCATE-AUTH carrying the
    /// HMAC-SHA256 message-integrity proof. Wrong credentials and stale
    /// or mis-issued nonces fail closed with typed errors.
    pub fn allocate_authenticated(
        relay: SocketAddr,
        bind: SocketAddr,
        credential: &RelayCredential,
    ) -> Result<Self, IceError> {
        let control = UdpSocket::bind(bind).map_err(|e| {
            IceError::BindFailed(format!("{bind}: {e}"))
        })?;
        Self::authenticate_on(control, relay, credential)
    }

    /// The authenticated allocation dance on an existing socket (see
    /// [`RelayClient::allocate_authenticated`]). A relay that allocates
    /// WITHOUT demanding a proof is accepted (it simply does not require
    /// authentication — documented; the credential config is the
    /// caller's statement of intent, not a relay-side guarantee).
    pub fn authenticate_on(
        control: UdpSocket,
        relay: SocketAddr,
        credential: &RelayCredential,
    ) -> Result<Self, IceError> {
        use std::time::Instant;
        credential.validate()?;
        control
            .set_read_timeout(Some(Duration::from_millis(400)))
            .map_err(|e| IceError::Io(e.to_string()))?;
        let mut buf = vec![0u8; 65_536];
        const ATTEMPTS: u32 = 3;
        let attempt_timeout = Duration::from_millis(400);

        // Step 1: plain ALLOCATE → expect ALLOCATE-CHALLENGE (an
        // ALLOCATE-SUCCESS means the relay does not demand auth).
        let (realm, auth_nonce) = 'challenge: {
            let tx = crate::entropy::random_u64()?;
            let request = ControlFrame {
                msg_type: MSG_ALLOCATE,
                allocation_id: tx,
                payload: Vec::new(),
            }
            .encode();
            for _ in 0..ATTEMPTS {
                control
                    .send_to(&request, relay)
                    .map_err(|e| IceError::Io(e.to_string()))?;
                let deadline = Instant::now() + attempt_timeout;
                loop {
                    if Instant::now() >= deadline {
                        break; // attempt expired
                    }
                    match control.recv_from(&mut buf) {
                        Ok((n, peer)) => {
                            if peer != relay {
                                continue; // unrelated source
                            }
                            let frame = ControlFrame::parse(&buf[..n])?;
                            match frame.msg_type {
                                MSG_ALLOCATE_CHALLENGE => {
                                    let (realm, nonce) =
                                        parse_challenge_payload(&frame.payload)?;
                                    break 'challenge (realm, nonce);
                                }
                                MSG_ALLOCATE_SUCCESS => {
                                    // The relay did not demand a proof:
                                    // accept the allocation (documented).
                                    let (relayed, consumed) =
                                        parse_address(&frame.payload)?;
                                    if frame.payload.len() != consumed {
                                        return Err(IceError::RelayControlMalformed {
                                            reason:
                                                "allocate-success payload has trailing bytes",
                                        });
                                    }
                                    return Ok(RelayClient {
                                        control,
                                        relay_control_addr: relay,
                                        allocation_id: frame.allocation_id,
                                        nonce: tx,
                                        relayed_addr: relayed,
                                    });
                                }
                                MSG_RELAY_ERROR => {
                                    let (code, reason) =
                                        parse_error_payload(&frame.payload)?;
                                    return Err(IceError::RelayAllocateFailed { code, reason });
                                }
                                other => {
                                    return Err(IceError::RelayControlUnexpected {
                                        msg_type: other,
                                    })
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
                            break // attempt expired
                        }
                        Err(_) => break, // transport error: retry the attempt
                    }
                }
            }
            return Err(IceError::RelayTimeout {
                server: relay,
                attempts: ATTEMPTS,
            });
        };

        // Step 2: ALLOCATE-AUTH carrying the message-integrity proof.
        // The MAC binds the whole request (transaction nonce, username,
        // realm, auth nonce), so a captured proof replayed under a
        // different transaction fails at the relay (401).
        let key = long_term_key(&credential.username, &realm, &credential.secret);
        let tx = crate::entropy::random_u64()?;
        let request = encode_allocate_auth(
            tx,
            &credential.username,
            &realm,
            &auth_nonce,
            &key,
        )?;
        for _ in 0..ATTEMPTS {
            control
                .send_to(&request, relay)
                .map_err(|e| IceError::Io(e.to_string()))?;
            let deadline = Instant::now() + attempt_timeout;
            loop {
                if Instant::now() >= deadline {
                    break; // attempt expired
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
                                    nonce: tx,
                                    relayed_addr: relayed,
                                });
                            }
                            MSG_RELAY_ERROR => {
                                let (code, reason) = parse_error_payload(&frame.payload)?;
                                if code == ERR_UNAUTHORIZED || code == ERR_STALE_NONCE {
                                    return Err(IceError::RelayAuthRejected { code, reason });
                                }
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
                        break // attempt expired
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

/// The authenticated relay's configuration (R4-006): the realm, the
/// precomputed long-term MAC key per username, and the relay's private
/// nonce key (fresh per process — a restart invalidates outstanding
/// nonces, which is exactly the desired fail-closed behavior).
struct AuthConfig {
    realm: String,
    key_by_user: HashMap<String, [u8; 32]>,
    nonce_key: [u8; 32],
}

/// The relay server: one control socket, one relayed socket (and one
/// forwarder thread) per allocation. Runs until the process is stopped.
pub struct RelayServer {
    control: Arc<UdpSocket>,
    allocations: Mutex<HashMap<u64, Arc<Allocation>>>,
    by_tuple: Mutex<HashMap<SocketAddr, u64>>,
    next_id: AtomicU64,
    /// When set, allocations require a credential proof (R4-006).
    auth: Option<AuthConfig>,
}

impl RelayServer {
    /// Bind an UNAUTHENTICATED relay (the R4-005 TEST/LOCAL behavior —
    /// kept for the unauthenticated flows; see `bind_authenticated`
    /// for the credential-demanding one). The address MUST have a concrete
    /// (non-wildcard) IP: relayed sockets inherit it, and a wildcard
    /// would produce unusable relayed addresses such as `0.0.0.0:port`
    /// (rejected with `RelayBindUnspecified`).
    pub fn bind(addr: SocketAddr) -> Result<Self, IceError> {
        Self::bind_inner(addr, None)
    }

    /// Bind a relay that REFUSES to allocate without a valid
    /// long-term-credential proof (R4-006; RFC 5389 §10.2 concepts — see
    /// the module docs). `users` is `(username, secret)` pairs; the
    /// long-term MAC keys are precomputed at bind.
    pub fn bind_authenticated(
        addr: SocketAddr,
        realm: &str,
        users: &[(String, String)],
    ) -> Result<Self, IceError> {
        if realm.is_empty() || realm.len() > AUTH_REALM_MAX_BYTES {
            return Err(IceError::RelayAuthConfigInvalid {
                reason: "realm must be 1..=128 bytes",
            });
        }
        if users.is_empty() {
            return Err(IceError::RelayAuthConfigInvalid {
                reason: "authenticated relay needs at least one user",
            });
        }
        let mut key_by_user = HashMap::with_capacity(users.len());
        for (username, secret) in users {
            let credential = RelayCredential {
                username: username.clone(),
                secret: secret.clone(),
            };
            credential.validate()?;
            if key_by_user
                .insert(username.clone(), long_term_key(username, realm, secret))
                .is_some()
            {
                return Err(IceError::RelayAuthConfigInvalid {
                    reason: "duplicate username in the relay user set",
                });
            }
        }
        let mut nonce_key = [0u8; 32];
        crate::entropy::random_bytes(&mut nonce_key)?;
        Self::bind_inner(
            addr,
            Some(AuthConfig {
                realm: realm.to_string(),
                key_by_user,
                nonce_key,
            }),
        )
    }

    fn bind_inner(addr: SocketAddr, auth: Option<AuthConfig>) -> Result<Self, IceError> {
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
            auth,
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
            MSG_ALLOCATE_AUTH => self.handle_allocate_auth(from, frame),
            MSG_SEND => self.handle_send(from, frame),
            // Server→client message types arriving from a client: misuse.
            MSG_ALLOCATE_SUCCESS | MSG_DATA | MSG_RELAY_ERROR | MSG_ALLOCATE_CHALLENGE => {
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
        if let Some(auth) = &self.auth {
            // Authenticated relay: an unauthenticated ALLOCATE ALWAYS
            // gets a fresh challenge (RFC 5389 §10.2 model) — allocation
            // state is never revealed to unauthenticated traffic.
            // Stateless: the nonce carries its own proof, so challenge
            // floods cannot exhaust relay memory.
            let nonce = nonce_for(&auth.nonce_key, from, unix_seconds_now()?);
            let payload = encode_challenge_payload(&auth.realm, &nonce)?;
            let challenge = ControlFrame {
                msg_type: MSG_ALLOCATE_CHALLENGE,
                allocation_id: frame.allocation_id,
                payload,
            };
            return self.send_frame(&challenge.encode(), from);
        }
        self.allocate_or_reply_mismatch(from, frame.allocation_id)
    }

    /// The authenticated allocation path (R4-006): strict parse →
    /// credential proof → nonce freshness → the RFC 8656 5-tuple rules.
    /// Every failure is a typed RELAY-ERROR the relay survives.
    fn handle_allocate_auth(&self, from: SocketAddr, frame: ControlFrame) -> Result<(), IceError> {
        let auth = match &self.auth {
            Some(a) => a,
            None => {
                return self.reply_error(
                    from,
                    frame.allocation_id,
                    ERR_MALFORMED,
                    "authenticated allocation on an unauthenticated relay",
                )
            }
        };
        // 1. Strict structural parse of the identity + proof payload.
        let parsed = match parse_allocate_auth(frame.allocation_id, &frame.payload) {
            Ok(p) => p,
            Err(_) => {
                return self.reply_error(
                    from,
                    frame.allocation_id,
                    ERR_MALFORMED,
                    "allocate-auth payload is structurally invalid",
                )
            }
        };
        // 2. Credential check. Unknown users and wrong secrets get the
        // IDENTICAL 401 reply (no credential-probing oracle), and a
        // dummy MAC is computed on unknown users so the work — and thus
        // the timing — does not leak whether the username exists.
        let key = auth.key_by_user.get(&parsed.username).copied();
        let expected = hmac_sha256(key.as_ref().unwrap_or(&[0u8; 32]), &parsed.mac_input);
        if key.is_none() || expected != parsed.mac {
            return self.reply_error(
                from,
                frame.allocation_id,
                ERR_UNAUTHORIZED,
                "allocation unauthorized",
            );
        }
        // 3. Nonce freshness + 5-tuple binding (self-validating nonce —
        // see the module docs). A nonce issued to another client or an
        // expired one is a typed 438.
        if !nonce_valid(
            &auth.nonce_key,
            from,
            &parsed.auth_nonce,
            unix_seconds_now()?,
            AUTH_NONCE_WINDOW_SECONDS,
        ) {
            return self.reply_error(
                from,
                frame.allocation_id,
                ERR_STALE_NONCE,
                "stale or mis-issued auth nonce",
            );
        }
        // 4. The credential proof held: apply the RFC 8656 5-tuple
        // rules (identical retransmission → cached response; a new
        // transaction on an allocated 5-tuple → 437).
        self.allocate_or_reply_mismatch(from, frame.allocation_id)
    }

    /// The shared RFC 8656 allocation core: retransmission → the same
    /// response; a new transaction on an allocated 5-tuple → 437;
    /// otherwise create the allocation and answer ALLOCATE-SUCCESS.
    fn allocate_or_reply_mismatch(
        &self,
        from: SocketAddr,
        nonce: u64,
    ) -> Result<(), IceError> {
        // One allocation per client 5-tuple (RFC 8656 §5: the 5-tuple
        // identifies the allocation).
        let mut by_tuple = self.by_tuple.lock().expect("by_tuple lock");
        if let Some(id) = by_tuple.get(&from).copied() {
            let allocations = self.allocations.lock().expect("allocations lock");
            if let Some(existing) = allocations.get(&id) {
                if existing.nonce == nonce {
                    // Retransmission of the same allocation request: the
                    // same response (RFC 8656 retransmission rule).
                    let success = ControlFrame {
                        msg_type: MSG_ALLOCATE_SUCCESS,
                        allocation_id: existing.id,
                        payload: encode_address(existing.relayed_addr),
                    };
                    return self.send_frame(&success.encode(), from);
                }
                // A genuinely new allocation request on an allocated 5-tuple.
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

    // ------------------------------------------------------------------
    // Allocation authentication (R4-006)
    // ------------------------------------------------------------------

    /// The long-term key and message-integrity MAC, cross-checked against
    /// Python's hashlib (OpenSSL — an independent implementation of both
    /// SHA-256 and HMAC):
    ///
    /// ```python
    /// import hashlib, hmac
    /// key = hashlib.sha256(b"alice:sharenet.local:secret-password").digest()
    /// frame = (bytes.fromhex("534e0005")
    ///          + (0x1122334455667788).to_bytes(8, "big")
    ///          + (5).to_bytes(2, "big") + b"alice"
    ///          + (14).to_bytes(2, "big") + b"sharenet.local"
    ///          + bytes.fromhex("00112233445566778899aabbccddeeff"))
    /// assert hmac.new(key, frame, hashlib.sha256).digest() == bytes.fromhex(
    ///     "c747488fc4da8ce912b90c4d57026b76afe130ab5a5545ec30127ecad54a7da9")
    /// ```
    #[test]
    fn long_term_key_and_mac_python_cross_check() {
        let key = long_term_key("alice", "sharenet.local", "secret-password");
        assert_eq!(
            key,
            [
                0xa5, 0x72, 0xaa, 0xe0, 0x87, 0x3a, 0xe9, 0x09, 0x3c, 0x25, 0x0c, 0x9c, 0xd1,
                0xf3, 0x7c, 0xc4, 0x32, 0x26, 0x04, 0x61, 0x4a, 0xcb, 0xf8, 0xd2, 0x1e, 0x01,
                0x27, 0x69, 0x53, 0xaf, 0xa9, 0xe6
            ]
        );
        let auth_nonce: [u8; AUTH_NONCE_LEN] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let frame = encode_allocate_auth(
            0x1122_3344_5566_7788,
            "alice",
            "sharenet.local",
            &auth_nonce,
            &key,
        )
        .expect("encode");
        // The 51-byte frame prefix matches the Python construction and
        // the trailing 32 bytes are its HMAC-SHA256.
        let mut want_prefix = Vec::new();
        want_prefix.extend_from_slice(&[0x53, 0x4E, 0x00, 0x05]);
        want_prefix.extend_from_slice(&0x1122_3344_5566_7788u64.to_be_bytes());
        want_prefix.extend_from_slice(&5u16.to_be_bytes());
        want_prefix.extend_from_slice(b"alice");
        want_prefix.extend_from_slice(&14u16.to_be_bytes());
        want_prefix.extend_from_slice(b"sharenet.local");
        want_prefix.extend_from_slice(&auth_nonce);
        assert_eq!(frame[..frame.len() - 32], want_prefix[..]);
        assert_eq!(frame.len(), want_prefix.len() + 32);
        assert_eq!(
            frame[frame.len() - 32..],
            [
                0xc7, 0x47, 0x48, 0x8f, 0xc4, 0xda, 0x8c, 0xe9, 0x12, 0xb9, 0x0c, 0x4d, 0x57,
                0x02, 0x6b, 0x76, 0xaf, 0xe1, 0x30, 0xab, 0x5a, 0x55, 0x45, 0xec, 0x30, 0x12,
                0x7e, 0xca, 0xd5, 0x4a, 0x7d, 0xa9
            ]
        );
        // A wrong secret yields a different MAC (no partial acceptance).
        let wrong = long_term_key("alice", "sharenet.local", "wrong-password");
        let other = encode_allocate_auth(
            0x1122_3344_5566_7788,
            "alice",
            "sharenet.local",
            &auth_nonce,
            &wrong,
        )
        .expect("encode");
        assert_ne!(other[frame.len() - 32..], frame[frame.len() - 32..]);
    }

    #[test]
    fn allocate_auth_roundtrip_and_strict_rejects() {
        let key = long_term_key("bob", "r", "s");
        let nonce: [u8; AUTH_NONCE_LEN] = [7u8; AUTH_NONCE_LEN];
        let frame = encode_allocate_auth(42, "bob", "r", &nonce, &key).expect("encode");
        let parsed_frame = ControlFrame::parse(&frame).expect("frame parses");
        assert_eq!(parsed_frame.msg_type, MSG_ALLOCATE_AUTH);
        assert_eq!(parsed_frame.allocation_id, 42);
        let parsed = parse_allocate_auth(parsed_frame.allocation_id, &parsed_frame.payload)
            .expect("auth parses");
        assert_eq!(parsed.username, "bob");
        assert_eq!(parsed.realm, "r");
        assert_eq!(parsed.auth_nonce, nonce);
        assert_eq!(parsed.mac_input, &frame[..frame.len() - 32]);
        assert_eq!(hmac_sha256(&key, &parsed.mac_input), parsed.mac);

        // Truncated MAC.
        let truncated = ControlFrame::parse(&frame[..frame.len() - 1]).expect("parse");
        assert!(matches!(
            parse_allocate_auth(truncated.allocation_id, &truncated.payload),
            Err(IceError::RelayAuthMalformed { .. })
        ));
        // Trailing garbage.
        let mut trailing = ControlFrame::parse(&frame).expect("parse");
        trailing.payload.push(0);
        assert!(matches!(
            parse_allocate_auth(trailing.allocation_id, &trailing.payload),
            Err(IceError::RelayAuthMalformed { .. })
        ));
        // Bogus username length (claims 64, has 3).
        let mut bogus = ControlFrame::parse(&frame).expect("parse");
        bogus.payload[0] = 0x00;
        bogus.payload[1] = 64;
        assert!(matches!(
            parse_allocate_auth(bogus.allocation_id, &bogus.payload),
            Err(IceError::RelayAuthMalformed { .. })
        ));
        // Non-UTF-8 username.
        let mut evil = ControlFrame {
            msg_type: MSG_ALLOCATE_AUTH,
            allocation_id: 9,
            payload: Vec::new(),
        };
        evil.payload.extend_from_slice(&2u16.to_be_bytes());
        evil.payload.extend_from_slice(&[0xFF, 0xFE]);
        evil.payload.extend_from_slice(&1u16.to_be_bytes());
        evil.payload.push(b'r');
        evil.payload.extend_from_slice(&[0u8; AUTH_NONCE_LEN]);
        evil.payload.extend_from_slice(&[0u8; AUTH_MAC_LEN]);
        assert!(matches!(
            parse_allocate_auth(evil.allocation_id, &evil.payload),
            Err(IceError::RelayAuthMalformed { .. })
        ));
        // Oversize username / realm are refused at encode time too.
        assert!(matches!(
            encode_allocate_auth(1, &"u".repeat(AUTH_USERNAME_MAX_BYTES + 1), "r", &nonce, &key),
            Err(IceError::RelayAuthConfigInvalid { .. })
        ));
        assert!(matches!(
            encode_allocate_auth(1, "u", &"r".repeat(AUTH_REALM_MAX_BYTES + 1), &nonce, &key),
            Err(IceError::RelayAuthConfigInvalid { .. })
        ));
    }

    #[test]
    fn challenge_payload_roundtrip_and_strict_rejects() {
        let nonce = [9u8; AUTH_NONCE_LEN];
        let payload = encode_challenge_payload("sharenet.local", &nonce).expect("encode");
        assert_eq!(
            parse_challenge_payload(&payload).expect("parse"),
            ("sharenet.local".to_string(), nonce)
        );
        // Trailing garbage.
        let mut trailing = payload.clone();
        trailing.push(0);
        assert!(matches!(
            parse_challenge_payload(&trailing),
            Err(IceError::RelayAuthMalformed { .. })
        ));
        // Truncated.
        assert!(matches!(
            parse_challenge_payload(&payload[..payload.len() - 1]),
            Err(IceError::RelayAuthMalformed { .. })
        ));
        // Bogus realm length (claims 128, has 16).
        let mut bogus = payload.clone();
        bogus[0] = 0x00;
        bogus[1] = 128;
        assert!(matches!(
            parse_challenge_payload(&bogus),
            Err(IceError::RelayAuthMalformed { .. })
        ));
        // Non-UTF-8 realm.
        let mut evil = Vec::new();
        evil.extend_from_slice(&1u16.to_be_bytes());
        evil.push(0xFF);
        evil.extend_from_slice(&nonce);
        assert!(matches!(
            parse_challenge_payload(&evil),
            Err(IceError::RelayAuthMalformed { .. })
        ));
        // Empty / oversize realm rejected at encode time.
        assert!(matches!(
            encode_challenge_payload("", &nonce),
            Err(IceError::RelayAuthConfigInvalid { .. })
        ));
    }

    #[test]
    fn nonce_is_fresh_and_five_tuple_bound() {
        let key = [0xABu8; 32];
        let client: SocketAddr = "192.0.2.10:40000".parse().expect("addr");
        let now = 1_700_000_000u64;
        let nonce = nonce_for(&key, client, now);
        // Valid for this client inside the window…
        assert!(nonce_valid(&key, client, &nonce, now, 120));
        assert!(nonce_valid(&key, client, &nonce, now + 120, 120));
        assert!(nonce_valid(&key, client, &nonce, now - 120, 120));
        // …expired past it (both directions).
        assert!(!nonce_valid(&key, client, &nonce, now + 121, 120));
        assert!(!nonce_valid(&key, client, &nonce, now.saturating_sub(121), 120));
        // 5-tuple binding: another client, another port, another relay key.
        let other_client: SocketAddr = "192.0.2.10:40001".parse().expect("addr");
        assert!(!nonce_valid(&key, other_client, &nonce, now, 120));
        let other_key = [0xCDu8; 32];
        assert!(!nonce_valid(&other_key, client, &nonce, now, 120));
        // Tampering with any nonce byte invalidates it.
        let mut tampered = nonce;
        tampered[15] ^= 0x01;
        assert!(!nonce_valid(&key, client, &tampered, now, 120));
        // The timestamp is embedded in the clear; a different timestamp
        // needs the matching truncated HMAC.
        let later = nonce_for(&key, client, now + 1);
        assert_ne!(later, nonce);
        assert!(nonce_valid(&key, client, &later, now + 1, 120));
    }

    #[test]
    fn bind_authenticated_validates_configuration() {
        let bind: SocketAddr = "127.0.0.1:0".parse().expect("addr");
        let users_ok = [("alice".to_string(), "s3cret".to_string())];
        // Realm must be 1..=128 bytes.
        assert!(matches!(
            RelayServer::bind_authenticated(bind, "", &users_ok),
            Err(IceError::RelayAuthConfigInvalid { .. })
        ));
        // At least one user.
        assert!(matches!(
            RelayServer::bind_authenticated(bind, "r", &[]),
            Err(IceError::RelayAuthConfigInvalid { .. })
        ));
        // Empty username / secret refused.
        let bad_user = [("".to_string(), "s".to_string())];
        assert!(matches!(
            RelayServer::bind_authenticated(bind, "r", &bad_user),
            Err(IceError::RelayAuthConfigInvalid { .. })
        ));
        let bad_secret = [("alice".to_string(), String::new())];
        assert!(matches!(
            RelayServer::bind_authenticated(bind, "r", &bad_secret),
            Err(IceError::RelayAuthConfigInvalid { .. })
        ));
        // Duplicate usernames refused.
        let dups = [
            ("alice".to_string(), "a".to_string()),
            ("alice".to_string(), "b".to_string()),
        ];
        assert!(matches!(
            RelayServer::bind_authenticated(bind, "r", &dups),
            Err(IceError::RelayAuthConfigInvalid { .. })
        ));
        // Credential parsing.
        assert!(RelayCredential::parse("alice:s3cret").is_ok());
        assert!(matches!(
            RelayCredential::parse("no-colon"),
            Err(IceError::RelayAuthConfigInvalid { .. })
        ));
        assert!(matches!(
            RelayCredential::parse(":secret"),
            Err(IceError::RelayAuthConfigInvalid { .. })
        ));
        assert!(matches!(
            RelayCredential::parse("alice:"),
            Err(IceError::RelayAuthConfigInvalid { .. })
        ));
    }

    /// In-process (but REAL UDP loopback) authenticated allocation dance:
    /// valid credential succeeds; wrong credential is a typed 401; an
    /// uncredentialed allocate gets the typed `RelayAuthRequired`; the
    /// relay survives everything.
    #[test]
    fn authenticated_allocation_dance_in_process() {
        let relay = RelayServer::bind_authenticated(
            "127.0.0.1:0".parse().expect("addr"),
            "sharenet.local",
            &[("alice".to_string(), "s3cret".to_string())],
        )
        .expect("bind authenticated");
        let addr = relay.control_addr().expect("addr");
        std::thread::Builder::new()
            .name("relay-auth-under-test".into())
            .spawn(move || {
                let _ = relay.run();
            })
            .expect("spawn relay");

        // 1. Valid credential allocates.
        let good = RelayCredential::parse("alice:s3cret").expect("credential");
        let client =
            RelayClient::allocate_authenticated(addr, "127.0.0.1:0".parse().expect("addr"), &good)
                .expect("authenticated allocation");
        assert!(client.relayed_addr().port() > 0);

        // 2. Wrong credential: typed 401 refusal.
        let bad = RelayCredential::parse("alice:wrong").expect("credential");
        let refused = RelayClient::allocate_authenticated(
            addr,
            "127.0.0.1:0".parse().expect("addr"),
            &bad,
        )
        .expect_err("wrong credential must be refused");
        assert!(matches!(
            &refused,
            IceError::RelayAuthRejected { code: 401, .. }
        ));

        // 3. Unknown user: the IDENTICAL typed 401 (no probing oracle).
        let unknown = RelayCredential::parse("mallory:s3cret").expect("credential");
        let refused_unknown = RelayClient::allocate_authenticated(
            addr,
            "127.0.0.1:0".parse().expect("addr"),
            &unknown,
        )
        .expect_err("unknown user must be refused");
        assert_eq!(refused_unknown, refused);

        // 4. An uncredentialed allocate is answered with a challenge,
        // surfaced as the typed `RelayAuthRequired`.
        let unauth = RelayClient::allocate(addr, "127.0.0.1:0".parse().expect("addr"));
        assert!(matches!(&unauth, Err(IceError::RelayAuthRequired)));

        // 5. The relay survived it all: another valid allocation works.
        let again = RelayClient::allocate_authenticated(
            addr,
            "127.0.0.1:0".parse().expect("addr"),
            &good,
        )
        .expect("relay must keep serving valid credentials");
        assert!(again.relayed_addr().port() > 0);
        // The process-exit reap covers the relay thread (no stop API —
        // same as the R4-005 scaffolding relays).
    }

    /// Replay rules for authenticated allocations (in-process, real UDP):
    /// an identical retransmission returns the same cached response; a
    /// captured proof replayed under a DIFFERENT transaction nonce is a
    /// typed 401 (the MAC binds the transaction); the same proof from a
    /// different 5-tuple is a typed 438 (the nonce is 5-tuple-bound).
    #[test]
    fn authenticated_allocation_replay_rules_in_process() {
        let relay = RelayServer::bind_authenticated(
            "127.0.0.1:0".parse().expect("addr"),
            "sharenet.local",
            &[("alice".to_string(), "s3cret".to_string())],
        )
        .expect("bind");
        let relay_addr = relay.control_addr().expect("addr");
        std::thread::Builder::new()
            .name("relay-auth-replay-under-test".into())
            .spawn(move || {
                let _ = relay.run();
            })
            .expect("spawn relay");

        // Do the dance by hand on a raw socket so the exact frames are
        // observable and replayable.
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind");
        sock.set_read_timeout(Some(Duration::from_secs(2))).expect("timeout");
        sock.send_to(
            &ControlFrame {
                msg_type: MSG_ALLOCATE,
                allocation_id: 100,
                payload: Vec::new(),
            }
            .encode(),
            relay_addr,
        )
        .expect("allocate");
        let mut buf = [0u8; 1024];
        let (n, _) = sock.recv_from(&mut buf).expect("challenge");
        let challenge = ControlFrame::parse(&buf[..n]).expect("parse");
        assert_eq!(challenge.msg_type, MSG_ALLOCATE_CHALLENGE);
        let (realm, auth_nonce) = parse_challenge_payload(&challenge.payload).expect("challenge");
        assert_eq!(realm, "sharenet.local");
        let key = long_term_key("alice", &realm, "s3cret");
        let auth_frame = encode_allocate_auth(200, "alice", &realm, &auth_nonce, &key)
            .expect("encode auth");
        sock.send_to(&auth_frame, relay_addr).expect("auth");
        let (n, _) = sock.recv_from(&mut buf).expect("success");
        let success = ControlFrame::parse(&buf[..n]).expect("parse");
        assert_eq!(success.msg_type, MSG_ALLOCATE_SUCCESS);
        let first_id = success.allocation_id;

        // a. Identical retransmission → the SAME cached response.
        sock.send_to(&auth_frame, relay_addr).expect("replay");
        let (n, _) = sock.recv_from(&mut buf).expect("cached success");
        let cached = ControlFrame::parse(&buf[..n]).expect("parse");
        assert_eq!(cached, success, "identical retransmission: same response");

        // b. Captured proof under a DIFFERENT transaction nonce → 401
        //    (the message-integrity MAC binds the whole request).
        let mut forged = auth_frame.clone();
        // transaction nonce lives at bytes 4..12 of the frame
        forged[11] ^= 0x01;
        sock.send_to(&forged, relay_addr).expect("forged");
        let (n, _) = sock.recv_from(&mut buf).expect("401");
        let refused = ControlFrame::parse(&buf[..n]).expect("parse");
        assert_eq!(refused.msg_type, MSG_RELAY_ERROR);
        let code = u16::from_be_bytes([refused.payload[0], refused.payload[1]]);
        assert_eq!(code, 401);

        // c. The same proof from a DIFFERENT 5-tuple → 438 (the nonce
        //    was issued to the first client's address only).
        let other = UdpSocket::bind("127.0.0.1:0").expect("bind");
        other
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        other.send_to(&auth_frame, relay_addr).expect("cross replay");
        let (n, _) = other.recv_from(&mut buf).expect("438");
        let stale = ControlFrame::parse(&buf[..n]).expect("parse");
        assert_eq!(stale.msg_type, MSG_RELAY_ERROR);
        let code = u16::from_be_bytes([stale.payload[0], stale.payload[1]]);
        assert_eq!(code, 438);

        // d. The relay survived the replay storm: a fresh authenticated
        //    allocation still works.
        let good = RelayCredential::parse("alice:s3cret").expect("credential");
        let fresh = RelayClient::allocate_authenticated(
            relay_addr,
            "127.0.0.1:0".parse().expect("addr"),
            &good,
        )
        .expect("relay must survive replays");
        assert!(fresh.relayed_addr().port() > 0);
        assert_ne!(fresh.allocation_id(), first_id);
    }
}
