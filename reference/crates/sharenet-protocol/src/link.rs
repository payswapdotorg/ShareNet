//! Authenticated links (work item R3-001).
//!
//! A [`LinkSession`] is the ShareNet data-plane primitive between two nodes:
//! a mutually-authenticated, replay-protected frame channel over any byte-frame
//! transport (the Wave 1 UDP transport today; Nearby/QUIC adapters later).
//! Both endpoints are authenticated against their R1-001 `NodeIdentity` keys;
//! the session is bound to the exact handshake bytes; `link_id` is
//! commitment-derived (SHA-256 over the full transcript) — caller-selected
//! link IDs are forbidden, mirroring the route-identity law (L013).
//!
//! # Design (registered in `spec/protocol-registry.yaml`)
//!
//! Standards-first (ADR-002): every cryptographic element is a standard
//! primitive, composed in a TLS-1.3-shaped sign-the-transcript exchange —
//! no bespoke ciphers:
//!
//! ```text
//! msg1 (i -> r): {1: 1, 2: e_i}                        // X25519 ephemeral
//! msg2 (r -> i): {1: 1, 2: e_r, 3: node_identity_r,
//!                4: sig_r, 5?: capabilities_r}
//! msg3 (i -> r): {1: 1, 2: node_identity_i, 3: sig_i, 4?: capabilities_i}
//!
//! sig_r = Ed25519_r(SHA-256("sharenet-link-auth-v1/responder"
//!                            || cbor(msg1) || cbor(msg2 w/o field 4)))
//! sig_i = Ed25519_i(SHA-256("sharenet-link-auth-v1/initiator"
//!                            || cbor(msg1) || cbor(msg2)
//!                            || cbor(msg3 w/o field 3)))
//! shared  = X25519(e_i, e_r)
//! salt    = SHA-256(cbor(msg1) || cbor(msg2) || cbor(msg3))
//! okm     = HKDF-SHA256(shared, salt, "sharenet-link-session-v1", 64)
//! key_i2r = okm[0..32]          key_r2i = okm[32..64]
//! link_id = SHA-256("sharenet-link-id-v1"
//!                   || cbor(msg1) || cbor(msg2) || cbor(msg3))
//! ```
//!
//! Each side signs the transcript up to and including its own message
//! content, so a signature simultaneously proves (a) possession of the
//! Ed25519 identity key, (b) agreement to THIS Diffie-Hellman result (the
//! ephemerals are inside the signed transcript), and (c) the signer's
//! `node_identity` (self-certifying: node_id is derived from the signing
//! key). Replaying any old handshake message under new ephemerals fails
//! signature verification (the transcript changes).
//!
//! # Frames
//!
//! Payloads ride as ChaCha20-Poly1305 (RFC 8439) AEAD frames with a
//! strictly monotonic per-direction sequence number (starting at 0):
//!
//! ```text
//! nonce = 0x00000000 || seq_u64be
//! aad   = "sharenet-link-frame-v1" || link_id || direction || seq_u64be
//! frame = AEAD_seal(key_dir, nonce, aad, payload)
//! ```
//!
//! The receiver enforces a replay window (duplicates, too-old and
//! out-of-window sequences rejected) and fails closed on any tag mismatch.
//! Any error (tamper, replay, desync) is terminal for the session — a
//! failed link is never silently recovered (recovery is R7 scope: fresh
//! handshake, fresh link_id, per L014).
//!
//! # Persistence
//!
//! None: sessions are in-memory; the durable identity (R1-001) outlives
//! links. Zeroization: ephemeral secrets and session keys are held in
//! `Zeroizing` buffers and wiped on drop.
//!
//! # Production callers
//!
//! - Today: the multiprocess integration test (a REAL second process over
//!   real UDP sockets) and the `sharenet-link-test-peer` scaffolding binary.
//! - Next: R3-002 advertisement/discovery and R4-001 QUIC tunnel both
//!   consume `LinkSession` as the peer-session primitive.

use core::fmt;

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::cbor::{encode, Value};
use crate::identity::{Identity, NodeIdentity};

/// Scheme version of the LinkAuthentication handshake (v1).
pub const LINK_SCHEME_VERSION: i64 = 1;
/// X25519 public key length.
pub const EPHEMERAL_LEN: usize = 32;
/// Derived session key length per direction.
pub const SESSION_KEY_LEN: usize = 32;
/// link_id length.
pub const LINK_ID_LEN: usize = 32;
/// ChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: usize = 12;
/// Replay window size (in-order deliveries accepted; reorder tolerated
/// within this many sequence numbers behind the highest seen).
pub const REPLAY_WINDOW: u64 = 64;

const RESPONDER_SIGN_CONTEXT: &[u8] = b"sharenet-link-auth-v1/responder";
const INITIATOR_SIGN_CONTEXT: &[u8] = b"sharenet-link-auth-v1/initiator";
const HKDF_INFO: &[u8] = b"sharenet-link-session-v1";
const LINK_ID_CONTEXT: &[u8] = b"sharenet-link-id-v1";
const FRAME_AAD_CONTEXT: &[u8] = b"sharenet-link-frame-v1";
const HKDF_LEN: usize = 64;

/// The byte-frame transport seam a link rides on (send + recv with a
/// timeout). Implemented today by the Wave 1 UDP transport adapters
/// (`sharenet-transport-linux`) and by the in-crate test peer; the
/// Nearby/QUIC adapters implement the same shape later.
pub trait LinkTransport {
    fn send(&mut self, frame: &[u8]) -> Result<(), LinkError>;
    /// Receive one frame; `Ok(None)` = timeout with nothing available.
    fn recv(&mut self) -> Result<Option<Vec<u8>>, LinkError>;
}

/// Typed link failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// A handshake or frame message violated the canonical CBOR profile.
    Cbor(crate::cbor::DecodeError),
    /// Handshake message did not parse as its expected map shape.
    MalformedMessage { which: &'static str, reason: String },
    /// scheme_version != 1.
    SchemeVersionUnsupported { found: i64 },
    /// A node identity inside the handshake failed strict parsing.
    Identity(crate::identity::IdentityError),
    /// Strict Ed25519 verification of a handshake signature failed.
    SignatureInvalid { which: &'static str },
    /// Frame AEAD tag verification failed (tamper, wrong key, desync).
    FrameTagFailed,
    /// Frame sequence was a duplicate or outside the replay window.
    FrameReplay { seq: u64 },
    /// The role byte was invalid.
    DirectionInvalid { found: u8 },
    /// The platform entropy source is unavailable (non-unix hosts have
    /// no configured source in this wave; fail closed).
    EntropyUnavailable,
    /// Underlying transport failure.
    Transport(String),
    /// Verification of the peer's optional capability envelope failed.
    Capability(crate::capability::CapabilityError),
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkError::Cbor(e) => write!(f, "link message CBOR violation: {e}"),
            LinkError::MalformedMessage { which, reason } => {
                write!(f, "malformed link message {which}: {reason}")
            }
            LinkError::SchemeVersionUnsupported { found } => {
                write!(f, "link scheme_version {found} unsupported")
            }
            LinkError::Identity(e) => write!(f, "peer identity rejected: {e}"),
            LinkError::SignatureInvalid { which } => {
                write!(f, "{which} signature verification failed")
            }
            LinkError::FrameTagFailed => write!(f, "frame authentication failed"),
            LinkError::FrameReplay { seq } => {
                write!(f, "frame seq {seq} is a replay or outside the window")
            }
            LinkError::DirectionInvalid { found } => {
                write!(f, "invalid direction byte {found}")
            }
            LinkError::EntropyUnavailable => {
                write!(f, "platform entropy unavailable (supply an ephemeral scalar instead)")
            }
            LinkError::Transport(e) => write!(f, "transport failure: {e}"),
            LinkError::Capability(e) => write!(f, "capability envelope rejected: {e}"),
        }
    }
}

impl std::error::Error for LinkError {}

impl LinkError {
    /// Stable machine name (conformance vectors + harness).
    pub fn name(&self) -> String {
        match self {
            LinkError::Cbor(e) => format!("cbor:{}", e.name()),
            LinkError::MalformedMessage { .. } => "malformed_message".to_string(),
            LinkError::SchemeVersionUnsupported { .. } => "scheme_version_unsupported".to_string(),
            LinkError::Identity(e) => format!("identity:{}", e.name()),
            LinkError::SignatureInvalid { .. } => "signature_invalid".to_string(),
            LinkError::FrameTagFailed => "frame_tag_failed".to_string(),
            LinkError::FrameReplay { .. } => "frame_replay".to_string(),
            LinkError::DirectionInvalid { .. } => "direction_invalid".to_string(),
            LinkError::EntropyUnavailable => "entropy_unavailable".to_string(),
            LinkError::Transport(_) => "transport".to_string(),
            LinkError::Capability(e) => format!("capability:{}", e.name()),
        }
    }
}

// ---------------------------------------------------------------------------
// Handshake wire forms
// ---------------------------------------------------------------------------

/// msg1 (initiator -> responder).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkInitiate {
    /// X25519 ephemeral public key.
    pub e_initiator: [u8; EPHEMERAL_LEN],
}

impl LinkInitiate {
    pub fn to_wire(&self) -> Value {
        Value::Map(vec![
            (Value::Int(1), Value::Int(LINK_SCHEME_VERSION)),
            (Value::Int(2), Value::Bytes(self.e_initiator.to_vec())),
        ])
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire(v: &Value) -> Result<Self, LinkError> {
        let Value::Map(entries) = v else {
            return Err(malformed("msg1", "not a map"));
        };
        let mut scheme: Option<i64> = None;
        let mut e: Option<[u8; EPHEMERAL_LEN]> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(malformed("msg1", "non-integer key"));
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(malformed("msg1", "duplicate field 1"));
                    }
                    let Value::Int(s) = val else {
                        return Err(malformed("msg1", "field 1 type"));
                    };
                    if *s != LINK_SCHEME_VERSION {
                        return Err(LinkError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if e.is_some() {
                        return Err(malformed("msg1", "duplicate field 2"));
                    }
                    let Value::Bytes(b) = val else {
                        return Err(malformed("msg1", "field 2 type"));
                    };
                    if b.len() != EPHEMERAL_LEN {
                        return Err(malformed("msg1", "ephemeral must be 32 bytes"));
                    }
                    e = Some(b.as_slice().try_into().expect("checked"));
                }
                other => return Err(malformed("msg1", &format!("unknown field {other}"))),
            }
        }
        Ok(LinkInitiate {
            e_initiator: e.ok_or_else(|| malformed("msg1", "missing field 2"))?,
        })
    }
}

/// msg2 (responder -> initiator).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkRespond {
    pub e_responder: [u8; EPHEMERAL_LEN],
    pub identity: NodeIdentity,
    pub signature: [u8; 64],
    /// Optional signed capability statement carried during the handshake
    /// (the raw carrying-envelope bytes; parsed + verified by the peer).
    pub capabilities: Option<Vec<u8>>,
}

impl LinkRespond {
    fn content_wire(&self) -> Value {
        let mut entries = vec![
            (Value::Int(1), Value::Int(LINK_SCHEME_VERSION)),
            (Value::Int(2), Value::Bytes(self.e_responder.to_vec())),
            (Value::Int(3), self.identity.to_wire()),
        ];
        if let Some(caps) = &self.capabilities {
            entries.push((Value::Int(5), Value::Bytes(caps.clone())));
        }
        Value::Map(entries)
    }

    pub fn to_wire(&self) -> Value {
        let mut entries = match self.content_wire() {
            Value::Map(e) => e,
            _ => unreachable!(),
        };
        entries.push((Value::Int(4), Value::Bytes(self.signature.to_vec())));
        Value::Map(entries)
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire(v: &Value) -> Result<Self, LinkError> {
        let Value::Map(entries) = v else {
            return Err(malformed("msg2", "not a map"));
        };
        let mut scheme: Option<i64> = None;
        let mut e: Option<[u8; EPHEMERAL_LEN]> = None;
        let mut identity: Option<NodeIdentity> = None;
        let mut signature: Option<[u8; 64]> = None;
        let mut capabilities: Option<Vec<u8>> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(malformed("msg2", "non-integer key"));
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(malformed("msg2", "duplicate field 1"));
                    }
                    let Value::Int(s) = val else {
                        return Err(malformed("msg2", "field 1 type"));
                    };
                    if *s != LINK_SCHEME_VERSION {
                        return Err(LinkError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if e.is_some() {
                        return Err(malformed("msg2", "duplicate field 2"));
                    }
                    let Value::Bytes(b) = val else {
                        return Err(malformed("msg2", "field 2 type"));
                    };
                    if b.len() != EPHEMERAL_LEN {
                        return Err(malformed("msg2", "ephemeral must be 32 bytes"));
                    }
                    e = Some(b.as_slice().try_into().expect("checked"));
                }
                3 => {
                    if identity.is_some() {
                        return Err(malformed("msg2", "duplicate field 3"));
                    }
                    identity = Some(NodeIdentity::from_wire(val).map_err(LinkError::Identity)?);
                }
                4 => {
                    if signature.is_some() {
                        return Err(malformed("msg2", "duplicate field 4"));
                    }
                    let Value::Bytes(b) = val else {
                        return Err(malformed("msg2", "field 4 type"));
                    };
                    if b.len() != 64 {
                        return Err(malformed("msg2", "signature must be 64 bytes"));
                    }
                    signature = Some(b.as_slice().try_into().expect("checked"));
                }
                5 => {
                    if capabilities.is_some() {
                        return Err(malformed("msg2", "duplicate field 5"));
                    }
                    let Value::Bytes(b) = val else {
                        return Err(malformed("msg2", "field 5 type"));
                    };
                    capabilities = Some(b.clone());
                }
                other => return Err(malformed("msg2", &format!("unknown field {other}"))),
            }
        }
        let _ = scheme;
        Ok(LinkRespond {
            e_responder: e.ok_or_else(|| malformed("msg2", "missing field 2"))?,
            identity: identity.ok_or_else(|| malformed("msg2", "missing field 3"))?,
            signature: signature.ok_or_else(|| malformed("msg2", "missing field 4"))?,
            capabilities,
        })
    }
}

/// msg3 (initiator -> responder).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkConfirm {
    pub identity: NodeIdentity,
    pub signature: [u8; 64],
    pub capabilities: Option<Vec<u8>>,
}

impl LinkConfirm {
    fn content_wire(&self) -> Value {
        let mut entries = vec![
            (Value::Int(1), Value::Int(LINK_SCHEME_VERSION)),
            (Value::Int(2), self.identity.to_wire()),
        ];
        if let Some(caps) = &self.capabilities {
            entries.push((Value::Int(4), Value::Bytes(caps.clone())));
        }
        Value::Map(entries)
    }

    pub fn to_wire(&self) -> Value {
        let mut entries = match self.content_wire() {
            Value::Map(e) => e,
            _ => unreachable!(),
        };
        entries.push((Value::Int(3), Value::Bytes(self.signature.to_vec())));
        Value::Map(entries)
    }

    pub fn to_wire_bytes(&self) -> Vec<u8> {
        encode(&self.to_wire()).expect("in-profile")
    }

    pub fn from_wire(v: &Value) -> Result<Self, LinkError> {
        let Value::Map(entries) = v else {
            return Err(malformed("msg3", "not a map"));
        };
        let mut scheme: Option<i64> = None;
        let mut identity: Option<NodeIdentity> = None;
        let mut signature: Option<[u8; 64]> = None;
        let mut capabilities: Option<Vec<u8>> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(malformed("msg3", "non-integer key"));
            };
            match *key {
                1 => {
                    if scheme.is_some() {
                        return Err(malformed("msg3", "duplicate field 1"));
                    }
                    let Value::Int(s) = val else {
                        return Err(malformed("msg3", "field 1 type"));
                    };
                    if *s != LINK_SCHEME_VERSION {
                        return Err(LinkError::SchemeVersionUnsupported { found: *s });
                    }
                    scheme = Some(*s);
                }
                2 => {
                    if identity.is_some() {
                        return Err(malformed("msg3", "duplicate field 2"));
                    }
                    identity = Some(NodeIdentity::from_wire(val).map_err(LinkError::Identity)?);
                }
                3 => {
                    if signature.is_some() {
                        return Err(malformed("msg3", "duplicate field 3"));
                    }
                    let Value::Bytes(b) = val else {
                        return Err(malformed("msg3", "field 3 type"));
                    };
                    if b.len() != 64 {
                        return Err(malformed("msg3", "signature must be 64 bytes"));
                    }
                    signature = Some(b.as_slice().try_into().expect("checked"));
                }
                4 => {
                    if capabilities.is_some() {
                        return Err(malformed("msg3", "duplicate field 4"));
                    }
                    let Value::Bytes(b) = val else {
                        return Err(malformed("msg3", "field 4 type"));
                    };
                    capabilities = Some(b.clone());
                }
                other => return Err(malformed("msg3", &format!("unknown field {other}"))),
            }
        }
        let _ = scheme;
        Ok(LinkConfirm {
            identity: identity.ok_or_else(|| malformed("msg3", "missing field 2"))?,
            signature: signature.ok_or_else(|| malformed("msg3", "missing field 3"))?,
            capabilities,
        })
    }
}

fn malformed(which: &'static str, reason: &str) -> LinkError {
    LinkError::MalformedMessage {
        which,
        reason: reason.to_string(),
    }
}

// ---------------------------------------------------------------------------
// Transcript hashing + key derivation
// ---------------------------------------------------------------------------

fn responder_sign_payload(msg1_bytes: &[u8], msg2_content: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RESPONDER_SIGN_CONTEXT);
    h.update(msg1_bytes);
    h.update(msg2_content);
    h.finalize().into()
}

fn initiator_sign_payload(msg1_bytes: &[u8], msg2_bytes: &[u8], msg3_content: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(INITIATOR_SIGN_CONTEXT);
    h.update(msg1_bytes);
    h.update(msg2_bytes);
    h.update(msg3_content);
    h.finalize().into()
}

fn transcript_salt(msg1_bytes: &[u8], msg2_bytes: &[u8], msg3_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(msg1_bytes);
    h.update(msg2_bytes);
    h.update(msg3_bytes);
    h.finalize().into()
}

fn derive_link_id(msg1_bytes: &[u8], msg2_bytes: &[u8], msg3_bytes: &[u8]) -> [u8; LINK_ID_LEN] {
    let mut h = Sha256::new();
    h.update(LINK_ID_CONTEXT);
    h.update(msg1_bytes);
    h.update(msg2_bytes);
    h.update(msg3_bytes);
    h.finalize().into()
}

fn derive_session_keys(
    shared_secret: &[u8; 32],
    salt: &[u8; 32],
) -> ([u8; SESSION_KEY_LEN], [u8; SESSION_KEY_LEN]) {
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(salt), shared_secret);
    let mut okm = [0u8; HKDF_LEN];
    hk.expand(HKDF_INFO, &mut okm)
        .expect("64 bytes is a valid HKDF-SHA256 length");
    let mut k1 = [0u8; SESSION_KEY_LEN];
    let mut k2 = [0u8; SESSION_KEY_LEN];
    k1.copy_from_slice(&okm[0..32]);
    k2.copy_from_slice(&okm[32..64]);
    (k1, k2)
}

// ---------------------------------------------------------------------------
// Handshake roles
// ---------------------------------------------------------------------------

/// Initiator-side handshake driver.
pub struct LinkInitiator {
    identity: Identity,
    capabilities: Option<Vec<u8>>,
    ephemeral: x25519_dalek::StaticSecret,
}

impl LinkInitiator {
    /// Start a handshake with a fresh ephemeral (OS entropy; unix:
    /// /dev/urandom, non-unix: fail closed — supply a scalar instead).
    pub fn new(
        identity: Identity,
        capabilities: Option<Vec<u8>>,
    ) -> Result<Self, LinkError> {
        let scalar = crate::identity::os_entropy_32().map_err(|_| LinkError::EntropyUnavailable)?;
        Self::from_ephemeral_bytes(&scalar, identity, capabilities)
    }

    /// Fixed ephemeral scalar (clamped internally per RFC 7748 by the
    /// x25519 implementation). For vectors/tests and for callers that
    /// supply their own entropy source.
    pub fn from_ephemeral_bytes(
        scalar: &[u8; 32],
        identity: Identity,
        capabilities: Option<Vec<u8>>,
    ) -> Result<Self, LinkError> {
        let ephemeral = x25519_dalek::StaticSecret::from(*scalar);
        Ok(LinkInitiator {
            identity,
            capabilities,
            ephemeral,
        })
    }

    /// msg1 (send to the responder).
    pub fn initiate(&self) -> LinkInitiate {
        LinkInitiate {
            e_initiator: x25519_dalek::PublicKey::from(&self.ephemeral).to_bytes(),
        }
    }

    /// Consume msg2, verify the responder, produce msg3 and (on success)
    /// the established session.
    pub fn confirm(
        self,
        msg1_bytes: &[u8],
        msg2: &LinkRespond,
        msg2_bytes: &[u8],
    ) -> Result<(LinkConfirm, LinkSession), LinkError> {
        // strict parse already done by from_wire; verify the signature over
        // (msg1 || msg2-content)
        let msg2_content_bytes = encode(&msg2.content_wire()).expect("in-profile");
        let payload = responder_sign_payload(msg1_bytes, &msg2_content_bytes);
        msg2
            .identity
            .verify_detached(&payload, &msg2.signature)
            .map_err(|_| LinkError::SignatureInvalid {
                which: "responder",
            })?;
        // optional capability envelope must verify under the responder identity
        if let Some(env) = &msg2.capabilities {
            verify_capability_envelope(env, &msg2.identity)?;
        }
        let confirm = LinkConfirm {
            identity: self.identity.node_identity().clone(),
            signature: [0u8; 64], // filled below
            capabilities: self.capabilities.clone(),
        };
        let msg3_content_bytes = encode(&confirm.content_wire()).expect("in-profile");
        let payload = initiator_sign_payload(msg1_bytes, msg2_bytes, &msg3_content_bytes);
        let signature = self.identity.sign_detached(&payload);
        let confirm = LinkConfirm {
            identity: confirm.identity,
            signature,
            capabilities: confirm.capabilities,
        };
        let msg3_bytes = confirm.to_wire_bytes();
        // derivation
        let shared = self
            .ephemeral
            .diffie_hellman(&x25519_dalek::PublicKey::from(msg2.e_responder));
        let shared = Zeroizing::new(shared.to_bytes());
        let salt = transcript_salt(msg1_bytes, msg2_bytes, &msg3_bytes);
        let (k_i2r, k_r2i) = derive_session_keys(&shared, &salt);
        let link_id = derive_link_id(msg1_bytes, msg2_bytes, &msg3_bytes);
        let session = LinkSession::new(Role::Initiator, link_id, msg2.identity.clone(), k_i2r, k_r2i);
        Ok((confirm, session))
    }
}

/// Responder-side handshake driver.
pub struct LinkResponder {
    identity: Identity,
    capabilities: Option<Vec<u8>>,
}

impl LinkResponder {
    pub fn new(identity: Identity, capabilities: Option<Vec<u8>>) -> Self {
        LinkResponder {
            identity,
            capabilities,
        }
    }

    /// Consume msg1; produce the SIGNED msg2 with a fresh ephemeral (OS
    /// entropy). The returned pending state finishes the handshake.
    pub fn respond(
        &self,
        msg1: &LinkInitiate,
        msg1_bytes: &[u8],
    ) -> Result<(LinkRespond, LinkResponderPending), LinkError> {
        let scalar = crate::identity::os_entropy_32().map_err(|_| LinkError::EntropyUnavailable)?;
        let pending = LinkResponderPending {
            identity: self.identity.clone(),
            capabilities: self.capabilities.clone(),
            ephemeral: x25519_dalek::StaticSecret::from(scalar),
            initiator_ephemeral: msg1.e_initiator,
        };
        let msg2 = pending.signed_respond(msg1_bytes)?;
        Ok((msg2, pending))
    }

    /// TEST/VECTOR PATH: respond with a FIXED ephemeral scalar (clamped).
    /// Never use for production handshakes.
    pub fn respond_fixed(
        &self,
        msg1: &LinkInitiate,
        msg1_bytes: &[u8],
        scalar: &[u8; 32],
    ) -> Result<(LinkRespond, LinkResponderPending), LinkError> {
        let pending = LinkResponderPending {
            identity: self.identity.clone(),
            capabilities: self.capabilities.clone(),
            ephemeral: x25519_dalek::StaticSecret::from(*scalar),
            initiator_ephemeral: msg1.e_initiator,
        };
        let msg2 = pending.signed_respond(msg1_bytes)?;
        Ok((msg2, pending))
    }
}

/// Responder state between msg2 and msg3.
pub struct LinkResponderPending {
    identity: Identity,
    capabilities: Option<Vec<u8>>,
    ephemeral: x25519_dalek::StaticSecret,
    initiator_ephemeral: [u8; EPHEMERAL_LEN],
}

impl LinkResponderPending {
    /// Build the SIGNED msg2 for the recorded msg1 bytes.
    pub(crate) fn signed_respond(&self, msg1_bytes: &[u8]) -> Result<LinkRespond, LinkError> {
        let partial = LinkRespond {
            e_responder: x25519_dalek::PublicKey::from(&self.ephemeral).to_bytes(),
            identity: self.identity.node_identity().clone(),
            signature: [0u8; 64],
            capabilities: self.capabilities.clone(),
        };
        let content = encode(&partial.content_wire()).expect("in-profile");
        let payload = responder_sign_payload(msg1_bytes, &content);
        let signature = self.identity.sign_detached(&payload);
        Ok(LinkRespond {
            signature,
            ..partial
        })
    }

    /// Consume msg3, verify the initiator, and establish the session.
    pub fn finish(
        self,
        msg1_bytes: &[u8],
        msg2_bytes: &[u8],
        msg3: &LinkConfirm,
        _msg3_bytes: &[u8],
    ) -> Result<LinkSession, LinkError> {
        let msg3_content = encode(&msg3.content_wire()).expect("in-profile");
        let payload = initiator_sign_payload(msg1_bytes, msg2_bytes, &msg3_content);
        msg3
            .identity
            .verify_detached(&payload, &msg3.signature)
            .map_err(|_| LinkError::SignatureInvalid {
                which: "initiator",
            })?;
        if let Some(env) = &msg3.capabilities {
            verify_capability_envelope(env, &msg3.identity)?;
        }
        let shared = self
            .ephemeral
            .diffie_hellman(&x25519_dalek::PublicKey::from(self.initiator_ephemeral));
        let shared = Zeroizing::new(shared.to_bytes());
        let msg3_bytes = msg3.to_wire_bytes();
        let salt = transcript_salt(msg1_bytes, msg2_bytes, &msg3_bytes);
        let (k_i2r, k_r2i) = derive_session_keys(&shared, &salt);
        let link_id = derive_link_id(msg1_bytes, msg2_bytes, &msg3_bytes);
        Ok(LinkSession::new(
            Role::Responder,
            link_id,
            msg3.identity.clone(),
            k_i2r,
            k_r2i,
        ))
    }
}

fn verify_capability_envelope(
    envelope: &[u8],
    signer: &NodeIdentity,
) -> Result<(), LinkError> {
    let signed = crate::capability::SignedCapabilityStatement::from_envelope_bytes(envelope)
        .map_err(LinkError::Capability)?;
    let statement = signed.statement().map_err(LinkError::Capability)?;
    // binding: the statement must bind THIS peer's node_id
    if statement.node_id() != &signer.node_id() {
        return Err(LinkError::Capability(
            crate::capability::CapabilityError::SignerNodeMismatch {
                statement: statement.node_id().to_hex(),
                signer: signer.node_id().to_hex(),
            },
        ));
    }
    // signature under the identity's key
    signer
        .verify_detached(signed.statement_bytes(), signed.signature())
        .map_err(|_| LinkError::SignatureInvalid {
            which: "capability",
        })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Session (frames)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Initiator,
    Responder,
}

/// An established, mutually-authenticated link with replay-protected
/// AEAD frames.
pub struct LinkSession {
    role: Role,
    link_id: [u8; LINK_ID_LEN],
    peer_identity: NodeIdentity,
    key_out: Zeroizing<[u8; SESSION_KEY_LEN]>,
    key_in: Zeroizing<[u8; SESSION_KEY_LEN]>,
    seq_out: u64,
    /// Highest in-order sequence consumed on the incoming direction.
    seq_in_highest: Option<u64>,
    /// Replay window bitmap over (seq_in_highest - 63 ..= seq_in_highest);
    /// bit k = seq_in_highest - k received. Bit 0 = highest itself.
    window: u64,
    /// Established-at wall clock (unix seconds) for diagnostics only.
    established_at_unix: u64,
}

impl LinkSession {
    fn new(
        role: Role,
        link_id: [u8; LINK_ID_LEN],
        peer_identity: NodeIdentity,
        key_i2r: [u8; SESSION_KEY_LEN],
        key_r2i: [u8; SESSION_KEY_LEN],
    ) -> Self {
        let (key_out, key_in) = match role {
            Role::Initiator => (key_i2r, key_r2i),
            Role::Responder => (key_r2i, key_i2r),
        };
        let established = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        LinkSession {
            role,
            link_id,
            peer_identity,
            key_out: Zeroizing::new(key_out),
            key_in: Zeroizing::new(key_in),
            seq_out: 0,
            seq_in_highest: None,
            window: 0,
            established_at_unix: established,
        }
    }

    /// The commitment-derived link identifier.
    pub fn link_id(&self) -> &[u8; LINK_ID_LEN] {
        &self.link_id
    }

    /// The authenticated peer identity.
    pub fn peer_identity(&self) -> &NodeIdentity {
        &self.peer_identity
    }

    /// The peer's derived node_id.
    pub fn peer_node_id(&self) -> crate::identity::NodeId {
        self.peer_identity.node_id()
    }

    /// Wall-clock establishment time (diagnostics only; not authenticated).
    pub fn established_at_unix(&self) -> u64 {
        self.established_at_unix
    }

    /// Number of frames sent on this session.
    pub fn frames_sent(&self) -> u64 {
        self.seq_out
    }

    /// Protect one payload into an outgoing frame.
    pub fn seal(&mut self, payload: &[u8]) -> Result<Vec<u8>, LinkError> {
        let seq = self.seq_out;
        self.seq_out = self
            .seq_out
            .checked_add(1)
            .ok_or_else(|| LinkError::Transport("sequence space exhausted".into()))?;
        seal_frame(&self.key_out, &self.link_id, self.direction_out(), seq, payload)
    }

    /// Incoming bookkeeping (duplicate/old) BEFORE any crypto work; state
    /// is only advanced AFTER the tag verifies.
    fn frame_seq(&self, frame: &[u8]) -> Result<u64, LinkError> {
        if frame.len() < 8 + 16 {
            return Err(LinkError::FrameTagFailed);
        }
        let mut seq_arr = [0u8; 8];
        seq_arr.copy_from_slice(&frame[..8]);
        let seq = u64::from_be_bytes(seq_arr);
        match self.seq_in_highest {
            None => Ok(seq),
            Some(highest) => {
                if seq > highest + REPLAY_WINDOW {
                    return Err(LinkError::FrameReplay { seq });
                }
                if seq < highest {
                    let behind = highest - seq;
                    if behind >= 64 {
                        return Err(LinkError::FrameReplay { seq });
                    }
                    if self.window & (1u64 << behind) != 0 {
                        return Err(LinkError::FrameReplay { seq });
                    }
                } else if seq == highest {
                    return Err(LinkError::FrameReplay { seq });
                }
                Ok(seq)
            }
        }
    }

    fn frame_accepted(&mut self, seq: u64) {
        match self.seq_in_highest {
            None => {
                self.seq_in_highest = Some(seq);
                self.window = 1;
            }
            Some(highest) => {
                if seq > highest {
                    let advance = seq - highest;
                    if advance >= 64 {
                        self.window = 1;
                    } else {
                        self.window = (self.window << advance) | 1;
                    }
                    self.seq_in_highest = Some(seq);
                } else {
                    let behind = highest - seq;
                    self.window |= 1u64 << behind;
                }
            }
        }
    }

    /// Authenticate + decrypt one incoming frame and enforce the replay
    /// window. Any failure is terminal (the caller must drop the session).
    pub fn open(&mut self, frame: &[u8]) -> Result<Vec<u8>, LinkError> {
        let seq = self.frame_seq(frame)?;
        let ciphertext = &frame[8..];
        let payload = open_frame(
            &self.key_in,
            &self.link_id,
            self.direction_in(),
            seq,
            ciphertext,
        )?;
        self.frame_accepted(seq);
        Ok(payload)
    }

    fn direction_out(&self) -> u8 {
        match self.role {
            Role::Initiator => 1,
            Role::Responder => 2,
        }
    }

    fn direction_in(&self) -> u8 {
        match self.role {
            Role::Initiator => 2,
            Role::Responder => 1,
        }
    }
}

fn frame_aad(link_id: &[u8; LINK_ID_LEN], direction: u8, seq: u64) -> Vec<u8> {
    // context (22) || link_id (32) || direction (1) || seq (8) = 63 bytes
    debug_assert_eq!(FRAME_AAD_CONTEXT.len(), 22);
    let mut aad = Vec::with_capacity(FRAME_AAD_CONTEXT.len() + 32 + 1 + 8);
    aad.extend_from_slice(FRAME_AAD_CONTEXT);
    aad.extend_from_slice(link_id);
    aad.push(direction);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad
}

fn frame_nonce(seq: u64) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n[4..].copy_from_slice(&seq.to_be_bytes());
    n
}

fn seal_frame(
    key: &[u8; SESSION_KEY_LEN],
    link_id: &[u8; LINK_ID_LEN],
    direction: u8,
    seq: u64,
    payload: &[u8],
) -> Result<Vec<u8>, LinkError> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let aad = frame_aad(link_id, direction, seq);
    let sealed = cipher
        .encrypt(
            &frame_nonce(seq).into(),
            Payload {
                msg: payload,
                aad: &aad,
            },
        )
        .map_err(|_| LinkError::FrameTagFailed)?;
    let mut out = Vec::with_capacity(8 + sealed.len());
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&sealed);
    Ok(out)
}

fn open_frame(
    key: &[u8; SESSION_KEY_LEN],
    link_id: &[u8; LINK_ID_LEN],
    direction: u8,
    seq: u64,
    ciphertext: &[u8],
) -> Result<Vec<u8>, LinkError> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::ChaCha20Poly1305;
    let cipher = ChaCha20Poly1305::new_from_slice(key).expect("32-byte key");
    let aad = frame_aad(link_id, direction, seq);
    cipher
        .decrypt(
            &frame_nonce(seq).into(),
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| LinkError::FrameTagFailed)
}


#[cfg(test)]
mod tests {
    use super::*;

    fn test_identity(seed: u8) -> Identity {
        Identity::from_seed([seed; 32], 1_700_000_000, None).expect("identity")
    }

    #[test]
    fn full_handshake_and_frames_both_directions() {
        let a = test_identity(1);
        let b = test_identity(2);
        let initiator = LinkInitiator::from_ephemeral_bytes(
            &[0x11u8; 32],
            a.clone(),
            None,
        )
        .unwrap();
        let responder = LinkResponder::new(b.clone(), None);

        let msg1 = initiator.initiate();
        let msg1_bytes = msg1.to_wire_bytes();
        let (msg2, pending) = responder.respond_fixed(&msg1, &msg1_bytes, &[0x33u8; 32]).unwrap();
        let msg2_bytes = msg2.to_wire_bytes();
        let (msg3, session_i) = initiator
            .confirm(&msg1_bytes, &msg2, &msg2_bytes)
            .unwrap();
        let msg3_bytes = msg3.to_wire_bytes();
        let session_r = pending
            .finish(&msg1_bytes, &msg2_bytes, &msg3, &msg3_bytes)
            .unwrap();

        assert_eq!(session_i.link_id(), session_r.link_id());
        assert_eq!(session_i.peer_node_id(), b.node_id());
        assert_eq!(session_r.peer_node_id(), a.node_id());

        // frames: i -> r then r -> i
        let mut si = session_i;
        let mut sr = session_r;
        let f1 = si.seal(b"ping").unwrap();
        let p1 = sr.open(&f1).unwrap();
        assert_eq!(p1, b"ping");
        let f2 = sr.seal(b"pong").unwrap();
        let p2 = si.open(&f2).unwrap();
        assert_eq!(p2, b"pong");

        // replay of f1 must fail
        assert!(matches!(sr.open(&f1), Err(LinkError::FrameReplay { seq: 0 })));
        // tamper must fail
        let mut f3 = si.seal(b"hello world").unwrap();
        let last = f3.len() - 1;
        f3[last] ^= 0x01;
        assert!(matches!(sr.open(&f3), Err(LinkError::FrameTagFailed)));
    }

    #[test]
    fn tampered_msg2_fails() {
        let a = test_identity(1);
        let b = test_identity(2);
        let initiator = LinkInitiator::from_ephemeral_bytes(&[0x22u8; 32], a.clone(), None).unwrap();
        let responder = LinkResponder::new(b.clone(), None);
        let msg1 = initiator.initiate();
        let msg1_bytes = msg1.to_wire_bytes();
        let (mut msg2, _pending) = responder.respond_fixed(&msg1, &msg1_bytes, &[0x44u8; 32]).unwrap();
        // tamper: corrupt the responder ephemeral (changes the DH + signature payload)
        msg2.e_responder[0] ^= 0x01;
        let msg2_bytes = msg2.to_wire_bytes();
        assert!(matches!(
            initiator.confirm(&msg1_bytes, &msg2, &msg2_bytes),
            Err(LinkError::SignatureInvalid { which: "responder" })
        ));
        // NOTE: the pending responder must not be used after this; the
        // initiator drops the handshake (fresh handshake on failure).
    }
}
