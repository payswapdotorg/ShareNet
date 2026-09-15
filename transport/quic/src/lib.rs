//! ShareNet QUIC/TLS tunnel transport (work item R4-001).
//!
//! The Internet-facing tunnel layer per `spec/architecture.md` §8 and
//! architecture lock L010: QUIC + TLS 1.3 via the standard Rust stack
//! (quinn + rustls) — no bespoke transport. Node identities (R1-001)
//! bind the TLS layer: each endpoint presents a self-signed Ed25519
//! certificate whose key IS the node identity key, and peers pin the
//! expected `node_id` (the certificate's public key must derive it).
//!
//! ```text
//! application / link frames
//!     ↓ length-framed tunnel session (this crate)
//! QUIC + TLS 1.3 (quinn)
//!     ↓
//! optional relays forwarding opaque QUIC packets (future R4-005)
//!     ↓
//! gateway → Internet
//! ```
//!
//! The tunnel carries opaque byte frames; ShareNet-level authentication
//! (R3-001 links, R4-002 circuit binding) rides INSIDE the tunnel.
//!
//! # Identity pinning model
//!
//! The client pins the SERVER's node_id (gateway pinning); the server
//! may optionally pin client node_ids. TLS itself proves the peer
//! controls the certificate's private key, so pinning the derived
//! node_id binds the QUIC connection to the ShareNet identity — a
//! man-in-the-middle without the node key cannot complete the
//! handshake with the expected node_id.
//!
//! # Persistence
//!
//! None: tunnels are runtime state (durable circuit state is R4-002/R7
//! scope).
//!
//! # Runtime ownership
//!
//! Each endpoint owns a tokio runtime wrapped in an `Arc` shared with
//! every `TunnelStream` it produced: a stream keeps the runtime (and
//! therefore quinn's endpoint driver) alive, so in-flight frames are
//! still transmitted after the endpoint owner is dropped. The runtime
//! is torn down when the last owner/stream goes away.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, ServerName};

/// Errors of the QUIC tunnel layer.
#[derive(Debug)]
pub enum TunnelError {
    /// Endpoint setup failure.
    Setup(String),
    /// Connection failure (including node pinning rejection).
    Connect(String),
    /// Framed session I/O failure.
    Io(String),
    /// Peer presented an identity that did not match the pinned node.
    NodePinMismatch {
        expected: String,
        presented: String,
    },
    /// The peer closed the stream/session.
    Closed,
    /// Frame too large for the negotiated limit.
    FrameTooLarge { len: usize, max: usize },
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelError::Setup(e) => write!(f, "tunnel setup failure: {e}"),
            TunnelError::Connect(e) => write!(f, "tunnel connect failure: {e}"),
            TunnelError::Io(e) => write!(f, "tunnel I/O failure: {e}"),
            TunnelError::NodePinMismatch { expected, presented } => write!(
                f,
                "peer node mismatch: pinned {expected}, presented {presented}"
            ),
            TunnelError::Closed => write!(f, "tunnel closed"),
            TunnelError::FrameTooLarge { len, max } => {
                write!(f, "frame of {len} bytes exceeds the {max}-byte limit")
            }
        }
    }
}

impl std::error::Error for TunnelError {}

/// Maximum single frame (2 MiB — mirrors the Wave 1 UDP transport bound).
pub const MAX_FRAME: usize = 2 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Identity → certificate material
// ---------------------------------------------------------------------------

/// Build a self-signed Ed25519 certificate from a ShareNet node identity
/// seed (PKCS#8-wrapped, so the TLS key IS the node key).
fn identity_certificate(
    seed: &[u8; 32],
    display_name: &str,
) -> Result<(CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>), TunnelError> {
    let pkcs8: Vec<u8> = [
        &hex_decode("302e020100300506032b657004220420")[..],
        seed,
    ]
    .concat();
    let keypair =
        rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8.clone()),
            &rcgen::PKCS_ED25519,
        )
        .map_err(|e| TunnelError::Setup(format!("identity key: {e}")))?;
    let params = rcgen::CertificateParams::new(vec![display_name.to_string()])
        .map_err(|e| TunnelError::Setup(format!("certificate params: {e}")))?;
    let cert = params
        .self_signed(&keypair)
        .map_err(|e| TunnelError::Setup(format!("self-sign: {e}")))?;
    Ok((
        cert.der().clone(),
        rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8.into()),
    ))
}

fn hex_decode(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex"))
        .collect()
}

/// Extract the Ed25519 public key from a certificate's SPKI.
fn certificate_public_key(cert: &CertificateDer<'_>) -> Result<[u8; 32], TunnelError> {
    let parsed = x509_parser::parse_x509_certificate(cert.as_ref())
        .map_err(|e| TunnelError::Connect(format!("certificate parse: {e}")))?;
    let algorithm = &parsed.1.tbs_certificate.subject_pki.algorithm;
    // Ed25519 OID 1.3.101.112
    const ED25519_OID: &str = "1.3.101.112";
    let oid_str = format!("{}", algorithm.oid());
    if oid_str != ED25519_OID {
        return Err(TunnelError::Connect(format!(
            "expected an Ed25519 certificate, found algorithm {oid_str}"
        )));
    }
    let key_bytes = parsed.1.tbs_certificate.subject_pki.subject_public_key.data;
    if key_bytes.len() != 32 {
        return Err(TunnelError::Connect(format!(
            "expected a 32-byte Ed25519 key, found {}",
            key_bytes.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Derive the ShareNet node_id from an Ed25519 public key (R1-001 rule).
fn node_id_of_public_key(public_key: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    // node_id = SHA-256(canonical_cbor({1: scheme_version, 2: public_key}))
    let preimage: Vec<u8> = vec![
        0xa2, // map(2)
        0x01, 0x01, // 1: 1
        0x02, 0x58, 0x20, // 2: bstr(32)
    ]
    .into_iter()
    .chain(public_key.iter().copied())
    .collect();
    let digest = sha2::Sha256::digest(&preimage);
    let mut id = [0u8; 32];
    id.copy_from_slice(&digest);
    id
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// A QUIC tunnel server endpoint bound to a local address, presenting a
/// node identity certificate.
pub struct TunnelServer {
    endpoint: quinn::Endpoint,
    runtime: Arc<tokio::runtime::Runtime>, // shared with streams: the driver outlives the owner
    identity_seed: [u8; 32],
    expected_clients: Option<Vec<[u8; 32]>>,
}

impl TunnelServer {
    /// Bind a server endpoint presenting `seed`'s node identity.
    ///
    /// `expected_clients`: when set, ONLY these node ids may connect
    /// (client pinning); when None, any client may open a QUIC
    /// connection — ShareNet-level authentication rides inside the
    /// tunnel (documented: the tunnel entry is an unauthenticated
    /// transport unless pinned; R4-002 circuits authenticate).
    pub fn bind(
        addr: SocketAddr,
        seed: [u8; 32],
        expected_clients: Option<Vec<[u8; 32]>>,
    ) -> Result<Self, TunnelError> {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| TunnelError::Setup(format!("runtime: {e}")))?,
        );
        let (cert, key) = identity_certificate(&seed, "sharenet-tunnel-server")?;
        let verifier = Arc::new(NodePinningClientVerifier {
            expected: expected_clients.clone(),
        });
        let mut server_crypto = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(vec![cert], key)
            .map_err(|e| TunnelError::Setup(format!("server TLS: {e}")))?;
        server_crypto.alpn_protocols = vec![b"sharenet-tunnel-v1".to_vec()];
        let config = quinn::ServerConfig::with_crypto(Arc::new(
            quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
                .map_err(|e| TunnelError::Setup(e.to_string()))?,
        ));
        let runtime_for_bind = runtime.clone();
        let endpoint = runtime_for_bind
            .block_on(async move { quinn::Endpoint::server(config, addr) })
            .map_err(|e| TunnelError::Setup(format!("bind {addr}: {e}")))?;
        Ok(TunnelServer {
            endpoint,
            runtime,
            identity_seed: seed,
            expected_clients,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, TunnelError> {
        self.endpoint
            .local_addr()
            .map_err(|e| TunnelError::Io(e.to_string()))
    }

    /// The node_id this server presents (R1-001 derivation of its key).
    pub fn node_id(&self) -> [u8; 32] {
        node_id_of_public_key(&public_of(&self.identity_seed))
    }

    /// Accept the next client connection; returns the framed session.
    ///
    /// QUIC stream signaling: the client-side protocol opens the tunnel
    /// stream and transmits its first frame — `open_bi` alone sends
    /// nothing on the wire, so the stream only materializes here once
    /// the client's first frame (or FIN) arrives.
    pub fn accept(&self) -> Result<TunnelStream, TunnelError> {
        let incoming = self
            .runtime
            .block_on(async { self.endpoint.accept().await })
            .ok_or(TunnelError::Closed)?;
        let conn = self.runtime.block_on(async {
            match incoming.await {
                Ok(c) => Ok(c),
                Err(e) => Err(TunnelError::Connect(e.to_string())),
            }
        })?;
        // the CLIENT initiates the tunnel stream; the server accepts it
        // (completes when the client's first frame arrives)
        let (send, recv) = self.runtime.block_on(async {
            match conn.accept_bi().await {
                Ok(pair) => Ok(pair),
                Err(e) => Err(TunnelError::Connect(e.to_string())),
            }
        })?;
        let _ = &self.expected_clients; // pinning enforced inside the TLS handshake
        Ok(TunnelStream {
            conn,
            send,
            recv,
            runtime: self.runtime.clone(),
        })
    }
}

fn public_of(seed: &[u8; 32]) -> [u8; 32] {
    let sk = ed25519_compat::secret_from_seed(seed);
    ed25519_compat::public_of(&sk)
}

/// Minimal ed25519 helpers (via the protocol crate's dependency tree).
mod ed25519_compat {
    use ed25519_dalek::SigningKey;

    pub fn secret_from_seed(seed: &[u8; 32]) -> SigningKey {
        SigningKey::from_bytes(seed)
    }

    pub fn public_of(sk: &SigningKey) -> [u8; 32] {
        sk.verifying_key().to_bytes()
    }
}

/// rustls client-certificate verifier that pins ShareNet node ids.
#[derive(Debug)]
struct NodePinningClientVerifier {
    expected: Option<Vec<[u8; 32]>>,
}

impl rustls::server::danger::ClientCertVerifier for NodePinningClientVerifier {
    fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
        let key = certificate_public_key(end_entity)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        let presented = node_id_of_public_key(&key);
        match &self.expected {
            None => Ok(rustls::server::danger::ClientCertVerified::assertion()),
            Some(list) => {
                if list.contains(&presented) {
                    Ok(rustls::server::danger::ClientCertVerified::assertion())
                } else {
                    Err(rustls::Error::General(format!(
                        "client node {} not pinned",
                        hex(&presented)
                    )))
                }
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 not allowed".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_self_signed_tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

fn verify_self_signed_tls13(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &rustls::DigitallySignedStruct,
) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
    use ed25519_dalek::Signature;
    use ed25519_dalek::Verifier;
    let key = certificate_public_key(cert)
        .map_err(|e| rustls::Error::General(e.to_string()))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|_| rustls::Error::General("bad public key".into()))?;
    let sig = Signature::from_slice(dss.signature())
        .map_err(|_| rustls::Error::General("bad signature length".into()))?;
    vk.verify(message, &sig)
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadSignature))
        .map(|_| rustls::client::danger::HandshakeSignatureValid::assertion())
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// A QUIC tunnel client that pins the server's node identity and
/// presents its own node identity certificate (so pinning servers can
/// admit it by node id).
pub struct TunnelClient {
    endpoint: quinn::Endpoint,
    runtime: Arc<tokio::runtime::Runtime>, // shared with streams: the driver outlives the owner
    identity_seed: [u8; 32],
}

impl TunnelClient {
    /// Prepare a client presenting `seed`'s node identity.
    pub fn new(seed: [u8; 32]) -> Result<Self, TunnelError> {
        let runtime = Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .map_err(|e| TunnelError::Setup(format!("runtime: {e}")))?,
        );
        let runtime_for_bind = runtime.clone();
        let endpoint = runtime_for_bind
            .block_on(async {
                quinn::Endpoint::client("127.0.0.1:0".parse().expect("addr"))
            })
            .map_err(|e| TunnelError::Setup(e.to_string()))?;
        Ok(TunnelClient {
            endpoint,
            runtime,
            identity_seed: seed,
        })
    }

    /// The node_id this client presents.
    pub fn node_id(&self) -> [u8; 32] {
        node_id_of_public_key(&public_of(&self.identity_seed))
    }

    /// Connect to `addr`, pinning the SERVER's node identity.
    pub fn connect(
        &self,
        addr: SocketAddr,
        expected_server_node_id: [u8; 32],
    ) -> Result<TunnelStream, TunnelError> {
        // The client presents its OWN node identity certificate (server
        // pinning is against this derived node id).
        let (cert, key) = identity_certificate(&self.identity_seed, "sharenet-tunnel-client")?;
        let verifier = Arc::new(NodePinningServerVerifier {
            expected_node: expected_server_node_id,
        });
        let mut crypto = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_client_auth_cert(vec![cert], key)
            .map_err(|e| TunnelError::Connect(format!("client TLS: {e}")))?;
        crypto.alpn_protocols = vec![b"sharenet-tunnel-v1".to_vec()];
        let quic_config = quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(crypto).map_err(|e| TunnelError::Connect(e.to_string()))?,
        ));
        let conn = self.runtime.block_on(async {
            self.endpoint
                .connect_with(quic_config, addr, "sharenet-tunnel-server")
                .map_err(|e| TunnelError::Connect(e.to_string()))?
                .await
                .map_err(|e| TunnelError::Connect(format!("quic connect: {e}")))
        })?;
        // NOTE: open_bi alone sends nothing on the wire (QUIC signals the
        // remote stream only on first use) — callers must send their first
        // frame for the server's accept to complete.
        let (send, recv) = self.runtime.block_on(async {
            conn.open_bi()
                .await
                .map_err(|e| TunnelError::Connect(e.to_string()))
        })?;
        Ok(TunnelStream {
            conn,
            send,
            recv,
            runtime: self.runtime.clone(),
        })
    }
}

/// Server-certificate verifier pinning a ShareNet node id.
#[derive(Debug)]
struct NodePinningServerVerifier {
    expected_node: [u8; 32],
}

impl rustls::client::danger::ServerCertVerifier for NodePinningServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        let key = certificate_public_key(end_entity)
            .map_err(|e| rustls::Error::General(e.to_string()))?;
        let presented = node_id_of_public_key(&key);
        if presented == self.expected_node {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "server node pin mismatch: expected {}, presented {}",
                hex(&self.expected_node),
                hex(&presented)
            )))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 not allowed".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        verify_self_signed_tls13(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![rustls::SignatureScheme::ED25519]
    }
}

// ---------------------------------------------------------------------------
// Framed tunnel session
// ---------------------------------------------------------------------------

/// A length-framed bidirectional tunnel session over one QUIC stream.
///
/// Close semantics (standard QUIC): `finish()` closes the sending half
/// gracefully, but DROPPING the last handle to the underlying connection
/// aborts it immediately — in-flight frames may be lost. Callers that
/// need delivery must keep the stream alive until the peer has consumed
/// the data (e.g. await an application-level acknowledgement).
pub struct TunnelStream {
    conn: quinn::Connection, // owning handle: dropping it closes the tunnel
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    runtime: Arc<tokio::runtime::Runtime>, // keeps the driver alive for in-flight frames
}

impl TunnelStream {
    /// Send one frame (length-prefixed, u32 big-endian).
    pub fn send_frame(&mut self, frame: &[u8]) -> Result<(), TunnelError> {
        check_frame_limit(frame.len())?;
        let mut buf = Vec::with_capacity(4 + frame.len());
        buf.extend_from_slice(&(frame.len() as u32).to_be_bytes());
        buf.extend_from_slice(frame);
        self.runtime
            .block_on(async { self.send.write_all(&buf).await })
            .map_err(|e| TunnelError::Io(e.to_string()))
    }

    /// Receive one frame (blocking).
    pub fn recv_frame(&mut self) -> Result<Vec<u8>, TunnelError> {
        let mut len_buf = [0u8; 4];
        read_exact(&self.runtime, &mut self.recv, &mut len_buf)?;
        let len = u32::from_be_bytes(len_buf) as usize;
        check_frame_limit(len)?;
        let mut frame = vec![0u8; len];
        read_exact(&self.runtime, &mut self.recv, &mut frame)?;
        Ok(frame)
    }

    /// Graceful close of the sending half.
    pub fn finish(&mut self) -> Result<(), TunnelError> {
        self.send
            .finish()
            .map_err(|e| TunnelError::Io(e.to_string()))
    }

    /// The peer's socket address (after the handshake).
    pub fn remote_addr(&self) -> SocketAddr {
        self.conn.remote_address()
    }

    /// Write RAW bytes with no framing, limit check, or flush guarantee.
    /// TEST SCAFFOLDING ONLY: lets an adversarial peer emit malformed
    /// length prefixes (e.g. an oversized frame header) so receivers can
    /// be verified to reject them. Production callers use `send_frame`.
    #[doc(hidden)]
    pub fn send_raw(&mut self, bytes: &[u8]) -> Result<(), TunnelError> {
        self.runtime
            .block_on(async { self.send.write_all(bytes).await })
            .map_err(|e| TunnelError::Io(e.to_string()))
    }
}

fn read_exact(
    runtime: &tokio::runtime::Runtime,
    recv: &mut quinn::RecvStream,
    buf: &mut [u8],
) -> Result<(), TunnelError> {
    runtime
        .block_on(async { recv.read_exact(buf).await })
        .map_err(|e| TunnelError::Io(format!("{e:?}")))
}

/// Frame length limit shared by the send and receive paths.
fn check_frame_limit(len: usize) -> Result<(), TunnelError> {
    if len > MAX_FRAME {
        Err(TunnelError::FrameTooLarge { len, max: MAX_FRAME })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_derivation_matches_r1() {
        // the crate's derivation must equal the protocol core's rule
        let seed = [7u8; 32];
        let id = sharenet_protocol::identity::Identity::from_seed(seed, 0, None)
            .unwrap()
            .node_id();
        assert_eq!(&node_id_of_public_key(&public_of(&seed)), id.as_bytes());
    }

    #[test]
    fn certificate_carries_identity_key() {
        let seed = [9u8; 32];
        let (cert, _) = identity_certificate(&seed, "test").unwrap();
        let key = certificate_public_key(&cert).unwrap();
        assert_eq!(key, public_of(&seed));
    }

    #[test]
    fn client_and_server_node_ids_are_their_identities() {
        // endpoints present exactly the identity their seed derives
        let seed = [0x0Eu8; 32];
        let client = TunnelClient::new(seed).unwrap();
        let want = sharenet_protocol::identity::Identity::from_seed(seed, 0, None)
            .unwrap()
            .node_id();
        assert_eq!(&client.node_id(), want.as_bytes());
    }

    #[test]
    fn oversized_send_rejected_locally() {
        // no I/O needed: the limit is enforced before the socket write
        let oversized = vec![0u8; MAX_FRAME + 1];
        let err = check_frame_limit(oversized.len()).expect_err("oversized frame");
        match err {
            TunnelError::FrameTooLarge { len, max } => {
                assert_eq!(len, MAX_FRAME + 1);
                assert_eq!(max, MAX_FRAME);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod integration {
    use super::*;

    /// In-process round trip with MUTUAL node pinning: the client pins
    /// the server's node id (a wrong pin is rejected by the verifier),
    /// and the server only admits the client's node id.
    ///
    /// The exchange is DETERMINISTIC with respect to QUIC close semantics:
    /// dropping a TunnelStream closes the QUIC connection immediately
    /// (in-flight frames may be lost), so the server echoes, then waits
    /// for the client's "done" frame — which the client only sends
    /// AFTER receiving the echo — before finishing and dropping.
    #[test]
    fn in_process_tunnel_roundtrip_mutual_pinning() {
        let seed_server = [0x5Au8; 32];
        let seed_client = [0x33u8; 32];
        let client_node_id = TunnelClient::new(seed_client).unwrap().node_id();
        let server = TunnelServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            seed_server,
            Some(vec![client_node_id]),
        )
        .expect("bind");
        let addr = server.local_addr().unwrap();
        let expected_server_node_id = server.node_id();

        std::thread::scope(|scope| {
            let server = &server;
            let handle = scope.spawn(move || {
                let mut s = server.accept().expect("accept");
                assert!(s.remote_addr().ip().is_loopback());
                let frame = s.recv_frame().expect("server recv");
                let mut echoed = b"echo:".to_vec();
                echoed.extend_from_slice(&frame);
                s.send_frame(&echoed).expect("server send");
                // the client received the echo before "done" exists: hold
                // the connection open until then so the echo is delivered
                let done = s.recv_frame().expect("server recv done");
                assert_eq!(done, b"done");
                let _ = s.finish();
            });
            let client = TunnelClient::new(seed_client).expect("client");
            let mut tunnel = client
                .connect(addr, expected_server_node_id)
                .expect("connect");
            tunnel.send_frame(b"ping").expect("client send");
            let back = tunnel.recv_frame().expect("client recv");
            assert_eq!(back, b"echo:ping");
            // only now may the server finish without losing the echo
            tunnel.send_frame(b"done").expect("client done");
            tunnel.finish().unwrap();
            handle.join().unwrap();
        });
    }

    /// A client whose node id is NOT pinned by the server is refused.
    /// In TLS 1.3 the client can complete its own handshake view before
    /// the server has verified the client certificate, so refusal is
    /// asserted on TUNNEL USE (the server aborts the connection), not
    /// merely on connect().
    #[test]
    fn unpinned_client_rejected_by_server() {
        let seed_server = [0x5Au8; 32];
        let seed_client = [0x71u8; 32]; // NOT the pinned id
        let pinned_other = TunnelClient::new([0x99u8; 32]).unwrap().node_id();
        let server = TunnelServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            seed_server,
            Some(vec![pinned_other]),
        )
        .expect("bind");
        let addr = server.local_addr().unwrap();
        let expected_server_node_id = server.node_id();

        let server_thread = std::thread::spawn(move || {
            // the handshake must fail on the server side
            let refused = server.accept().is_err();
            assert!(refused, "server must reject the unpinned client");
        });
        let client = TunnelClient::new(seed_client).expect("client");
        match client.connect(addr, expected_server_node_id) {
            Err(_) => {
                // refusal arrived during the handshake: fine
            }
            Ok(mut tunnel) => {
                // refusal arrives as a connection abort on first use
                tunnel.send_frame(b"ping").expect("queued locally");
                assert!(
                    tunnel.recv_frame().is_err(),
                    "server must abort the tunnel of an unpinned client"
                );
            }
        }
        server_thread.join().unwrap();
    }
}
