//! The bridge core: one participant session, owned by the Android
//! packet loop's thread, speaking the TunnelBackhaul contract.
//!
//! The contract (TunnelBackhaul.kt): `forward` is called once per
//! filter-accepted packet on the loop thread, may block (network I/O),
//! returns the response packets, and throwing is a TUNNEL FAILURE
//! (fail closed). This core maps every Rust error to
//! [`BridgeError`] (the JNI layer maps that to the Java exception).

use std::net::SocketAddr;

use sharenet_protocol::identity::Identity;
use sharenet_transport_linux::gateway::{GatewayClient, ParticipantSession};

/// The bridge's API version (bumped on any contract change).
pub const BRIDGE_API_VERSION: i32 = 1;

/// The bridge's own bounded idle timeout default (R10-001's
/// failure-detection idiom: a silently dead gateway errors the
/// blocked reads instead of hanging the loop thread forever).
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 30_000;

/// A typed bridge failure (fail closed — the JNI layer turns this into
/// the Java exception the loop's BackhaulFailure path expects).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BridgeError {
    /// The session was never opened (or is already destroyed).
    NotOpen,
    /// The seed must be exactly 32 bytes.
    BadSeed,
    /// The gateway address could not be parsed.
    BadAddress,
    /// The gateway node id must be 64 hex chars.
    BadNodeId,
    /// Establishment failed (typed reason from the gateway stack).
    Connect(String),
    /// The forward failed (typed reason).
    Forward(String),
    /// The destroy failed (typed reason).
    Destroy(String),
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::NotOpen => write!(f, "bridge session not open"),
            BridgeError::BadSeed => write!(f, "seed must be exactly 32 bytes"),
            BridgeError::BadAddress => write!(f, "gateway address unparseable"),
            BridgeError::BadNodeId => write!(f, "gateway node id must be 64 hex chars"),
            BridgeError::Connect(r) => write!(f, "connect: {r}"),
            BridgeError::Forward(r) => write!(f, "forward: {r}"),
            BridgeError::Destroy(r) => write!(f, "destroy: {r}"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// One participant session behind the seam. `forward` is single-thread
/// by contract (the loop thread); the JNI layer serializes anyway
/// (defensive — an accidental second caller gets a typed error, not a
/// data race).
pub struct BridgeSession {
    session: ParticipantSession,
    identity: Identity,
    destroyed: bool,
}

impl BridgeSession {
    /// Establish the session: identity seed, the gateway's address and
    /// PINNED node id, and the idle timeout (milliseconds; a silently
    /// dead gateway errors the blocked reads after this window).
    pub fn open(
        seed: [u8; 32],
        gateway_addr: SocketAddr,
        gateway_node_id: [u8; 32],
        idle_timeout_ms: u64,
    ) -> Result<Self, BridgeError> {
        let identity = Identity::from_seed(seed, 0, None)
            .map_err(|e| BridgeError::Connect(e.to_string()))?;
        let client = GatewayClient::new(seed, gateway_addr, gateway_node_id);
        let session = client
            .connect_with_idle_timeout(idle_timeout_ms.max(100))
            .map_err(|e| BridgeError::Connect(e.to_string()))?;
        Ok(BridgeSession {
            session,
            identity,
            destroyed: false,
        })
    }

    /// Forward one complete IP packet and return the response packets
    /// (the uplink's request/response semantics: one response per
    /// forwarded packet; more would arrive as further forwards).
    pub fn forward(&mut self, packet: &[u8]) -> Result<Vec<Vec<u8>>, BridgeError> {
        if self.destroyed {
            return Err(BridgeError::NotOpen);
        }
        self.session
            .send_packet(packet)
            .map_err(|e| BridgeError::Forward(e.to_string()))?;
        let response = self
            .session
            .recv_response()
            .map_err(|e| BridgeError::Forward(e.to_string()))?;
        Ok(vec![response])
    }

    /// Destroy the circuit (terminal) with the BYE acknowledgement.
    pub fn destroy(&mut self, reason: &str) -> Result<(), BridgeError> {
        if self.destroyed {
            return Err(BridgeError::NotOpen);
        }
        self.session
            .destroy(&self.identity, reason)
            .map_err(|e| BridgeError::Destroy(e.to_string()))?;
        self.destroyed = true;
        Ok(())
    }

    /// The established circuit's id (diagnostics/telemetry).
    pub fn circuit_id(&self) -> &[u8; 32] {
        self.session.circuit_id()
    }
}
