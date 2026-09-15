//! Integration with the R4-001 QUIC tunnel: candidates are the address
//! source for node-pinned tunnels.
//!
//! Work item R4-005's composition rule: a gathered candidate (host,
//! server-reflexive or relayed) supplies the address a
//! [`sharenet_transport_quic::TunnelClient`] connects to while pinning
//! the SERVER's node id — the tunnel's authentication (self-signed
//! Ed25519 certificate whose key IS the node identity key) is untouched
//! by the candidate source, and relays carry the QUIC datagrams as
//! opaque bytes (L012).
//!
//! - host/srflx candidates: the client connects directly to the
//!   candidate address (a srflx connect target requires NAT hairpin
//!   support on real networks; on loopback the srflx address is the
//!   local address itself);
//! - relayed candidates: the client connects to the relayed address,
//!   where the server side runs a pump (see
//!   [`crate::relay::RelayServerAdapter`]) between the allocation and
//!   its real QUIC endpoint.

use crate::candidate::Candidate;

pub use sharenet_transport_quic::{TunnelClient, TunnelError, TunnelStream};

/// Open a node-pinned QUIC tunnel toward a gathered candidate.
///
/// `client_seed` is the client's node identity seed (R1-001); the server
/// MUST be pinned with `expected_server_node_id` (an unpinned connect is
/// an unauthenticated transport — the tunnel crate's rule). The
/// candidate supplies only the address; every authentication property
/// comes from the R4-001 tunnel layer itself.
pub fn tunnel_connect(
    candidate: &Candidate,
    client_seed: [u8; 32],
    expected_server_node_id: [u8; 32],
) -> Result<TunnelStream, TunnelError> {
    let client = TunnelClient::new(client_seed)?;
    client.connect(candidate.transport_addr(), expected_server_node_id)
}
