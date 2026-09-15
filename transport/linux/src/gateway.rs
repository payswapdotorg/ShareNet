//! Linux gateway forwarding (work item R4-003): the data plane that
//! bridges ShareNet circuits to an external uplink on a Linux gateway
//! host.
//!
//! ```text
//! participant                              Linux gateway
//! TUN / packet source
//!     ↓ CircuitFrame (direction 1, seq 0..)
//! node-pinned QUIC tunnel (R4-001)  ←————→ framed session
//!     ↓
//! CircuitRegistry admission (R4-002: setup → acks → established)
//!     ↓
//! GatewayServer::forward  ————→ uplink UDP socket (the Internet side;
//!                              tests use a real local echo server)
//!     ↑ direction-2 frames  ←———— uplink responses
//! ```
//!
//! The control protocol riding INSIDE the tunnel is runtime state of
//! this module (documented here, not a registry wire object — the
//! registry's circuit objects ride inside it):
//!
//! | byte | meaning | payload |
//! |---|---|---|
//! | 0x01 | ROUTE_PROPOSAL | the signed route proposal envelope (the gateway's acceptance is created from it; the full commitment arrives later inside the circuit setup, where R4-002 admission verifies every acceptance anyway) |
//! | 0x02 | ROUTE_ACCEPTANCE | the gateway's signed route acceptance envelope |
//! | 0x03 | CIRCUIT_SETUP | the signed circuit setup envelope |
//! | 0x04 | CIRCUIT_ACK | the gateway's signed circuit ack envelope |
//! | 0x05 | CIRCUIT_FRAME | the bare circuit frame wire bytes |
//! | 0x06 | CIRCUIT_DESTROY | the signed destroy envelope |
//! | 0x07 | BYE | empty (application-level clean shutdown — the QUIC close-semantics rule: the peer must not lose in-flight frames) |
//!
//! Both sides run a [`CircuitRegistry`](sharenet_protocol::CircuitRegistry)
//! (R4-002): the gateway admits the setup and every frame fail-closed
//! (full route-commitment verification, exact position coverage,
//! per-direction replay namespaces); the participant mirrors the
//! admission so tampering anywhere in the chain is caught on BOTH
//! ends, not just the gateway's.
//!
//! # Persistence
//!
//! None: forwarding is runtime state (durable circuit state is R7
//! scope). Identity material is caller-supplied (seeds); the future
//! `sharenetd` daemon owns durable identity storage.
//!
//! # Scope honesty
//!
//! The uplink here is a per-circuit UDP socket to a configured
//! address (the "Internet side"); full Internet-facing packet
//! forwarding (NAT, address parsing, routing) is R4-007's mission
//! gate. The live TUN path requires /dev/net/tun (gated tests skip
//! honestly on hosts without it — the R2-003 probe discipline); the
//! packet source seam accepts any byte producer.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use sharenet_protocol::circuit::{
    AckOutcome, CircuitDestroy, CircuitFrame, CircuitRegistry, CircuitSetup, CircuitSetupAck,
    CircuitError, DIRECTION_EXIT_TO_INITIATOR, DIRECTION_INITIATOR_TO_EXIT,
};
use sharenet_protocol::identity::Identity;
use sharenet_protocol::route::{
    derive_proposal_id, RouteAcceptance, RouteCommitment, RouteProposal, SignedEnvelope,
};
use sharenet_transport_quic::{TunnelClient, TunnelSender, TunnelServer, TunnelStream};

/// Maximum payload forwarded to the uplink in one datagram (UDP
/// datagram bound; matches the linux crate's frame policy).
pub const GATEWAY_MAX_PACKET: usize = 65_500;
/// How long the gateway waits for uplink responses before an idle tick.
pub const GATEWAY_CONTROL_PREFIX_LEN: usize = 1;

mod control {
    pub const ROUTE_PROPOSAL: u8 = 0x01;
    pub const ROUTE_ACCEPTANCE: u8 = 0x02;
    pub const CIRCUIT_SETUP: u8 = 0x03;
    pub const CIRCUIT_ACK: u8 = 0x04;
    pub const CIRCUIT_FRAME: u8 = 0x05;
    pub const CIRCUIT_DESTROY: u8 = 0x06;
    pub const BYE: u8 = 0x07;
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Debug)]
pub enum GatewayError {
    Setup(String),
    Protocol(String),
    Circuit(CircuitError),
    Io(String),
    Closed,
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GatewayError::Setup(e) => write!(f, "gateway setup: {e}"),
            GatewayError::Protocol(e) => write!(f, "gateway protocol violation: {e}"),
            GatewayError::Circuit(e) => write!(f, "circuit admission: {e}"),
            GatewayError::Io(e) => write!(f, "gateway I/O: {e}"),
            GatewayError::Closed => write!(f, "gateway session closed"),
        }
    }
}

impl std::error::Error for GatewayError {}

impl From<CircuitError> for GatewayError {
    fn from(e: CircuitError) -> Self {
        GatewayError::Circuit(e)
    }
}

impl From<sharenet_protocol::RouteError> for GatewayError {
    fn from(e: sharenet_protocol::RouteError) -> Self {
        GatewayError::Protocol(format!("route: {e}"))
    }
}

// ---------------------------------------------------------------------------
// Gateway side
// ---------------------------------------------------------------------------

/// A Linux gateway endpoint serving one participant at a time over a
/// node-pinned QUIC tunnel, bridging admitted circuit frames to a
/// configured uplink.
pub struct GatewayServer {
    seed: [u8; 32],
    tunnel: TunnelServer,
    uplink: SocketAddr,
}

impl GatewayServer {
    /// Bind the gateway: `seed` is the gateway's node identity seed
    /// (its certificate presents this identity — R4-001 pinning);
    /// `expected_clients` pins the admitted participant node ids when
    /// set.
    pub fn new(
        seed: [u8; 32],
        bind: SocketAddr,
        expected_clients: Option<Vec<[u8; 32]>>,
        uplink: SocketAddr,
    ) -> Result<Self, GatewayError> {
        let tunnel = TunnelServer::bind(bind, seed, expected_clients)
            .map_err(|e| GatewayError::Setup(e.to_string()))?;
        Ok(GatewayServer {
            seed,
            tunnel,
            uplink,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, GatewayError> {
        self.tunnel
            .local_addr()
            .map_err(|e| GatewayError::Setup(e.to_string()))
    }

    /// The gateway's node id (what participants pin).
    pub fn node_id(&self) -> [u8; 32] {
        self.tunnel.node_id()
    }

    /// Serve exactly one participant connection to completion (blocks).
    pub fn serve_once(&self) -> Result<GatewayStats, GatewayError> {
        let mut stream = self
            .tunnel
            .accept()
            .map_err(|e| GatewayError::Io(e.to_string()))?;
        let gateway = Identity::from_seed(self.seed, 0, None)
            .map_err(|e| GatewayError::Setup(e.to_string()))?;
        let mut registry = CircuitRegistry::new();

        // 1. ROUTE_PROPOSAL: verify the participant's proposal (they
        //    are the proposer; the path must contain the gateway) and
        //    reply with our signed acceptance.
        let msg = recv_message(&mut stream)?;
        if msg[0] != control::ROUTE_PROPOSAL {
            return Err(GatewayError::Protocol(format!(
                "expected ROUTE_PROPOSAL, got {:#x}",
                msg[0]
            )));
        }
        let proposal_env = SignedEnvelope::from_envelope_bytes(&msg[GATEWAY_CONTROL_PREFIX_LEN..])
            .map_err(|e| GatewayError::Protocol(format!("proposal envelope: {e}")))?;
        let proposal = RouteProposal::from_wire_bytes(proposal_env.bytes())?;
        proposal
            .proposer_identity()
            .verify_detached(proposal_env.bytes(), proposal_env.signature())
            .map_err(|_| GatewayError::Protocol("proposal signature invalid".into()))?;
        let path = proposal.path().to_vec();
        let gateway_node_id = *gateway.node_id().as_bytes();
        let position = path
            .iter()
            .position(|p| p == &gateway_node_id)
            .ok_or_else(|| GatewayError::Protocol("gateway not on the proposed path".into()))?;
        let proposal_id = derive_proposal_id(proposal_env.bytes());
        // Timestamp discipline: the acceptance anchors to the
        // PROPOSAL'S clock (proposed_at), never our wall clock — the
        // proposer builds the commitment right after receiving this
        // acceptance, and cross-process wall-clock skew (even
        // milliseconds forward) must not break admission.
        let acceptance = RouteAcceptance::new(
            &gateway,
            proposal_id,
            position as u64,
            proposal.proposed_at_unix(),
            600,
        )?;
        let acceptance_env = acceptance.sign(&gateway)?;
        send_message(
            &mut stream,
            control::ROUTE_ACCEPTANCE,
            &acceptance_env.to_envelope_bytes(),
        )?;

        // 2. CIRCUIT_SETUP: admit the setup (full R3-004 + R4-002
        //    verification inside), reply with our circuit ack.
        let msg = recv_message(&mut stream)?;
        if msg[0] != control::CIRCUIT_SETUP {
            return Err(GatewayError::Protocol(format!(
                "expected CIRCUIT_SETUP, got {:#x}",
                msg[0]
            )));
        }
        let setup_env = SignedEnvelope::from_envelope_bytes(&msg[GATEWAY_CONTROL_PREFIX_LEN..])
            .map_err(|e| GatewayError::Protocol(format!("setup envelope: {e}")))?;
        let now_fresh = now_unix();
        let circuit_id = registry.admit_setup(now_fresh, &setup_env)?;
        let setup = CircuitSetup::from_wire_bytes(setup_env.bytes())?;
        // Timestamp discipline: the ack anchors to the SETUP'S clock
        // (issued_at) for the same skew reason as the acceptance.
        let ack = CircuitSetupAck::new(
            circuit_id,
            &setup_env,
            &gateway,
            position as u64,
            setup.issued_at_unix(),
            600,
        )?;
        let ack_env = ack.sign(&gateway)?;
        send_message(&mut stream, control::CIRCUIT_ACK, &ack_env.to_envelope_bytes())?;
        // The gateway's own ack in its registry.
        let _ = registry.admit_ack(now_fresh, &ack_env)?;

        // 2b. The PARTICIPANT'S circuit ack arrives next: without it
        //     the circuit is never established here (position
        //     coverage is exact — both ends must ack).
        let msg = recv_message(&mut stream)?;
        if msg[0] != control::CIRCUIT_ACK {
            return Err(GatewayError::Protocol(format!(
                "expected the participant's CIRCUIT_ACK, got {:#x}",
                msg[0]
            )));
        }
        let participant_ack_env = SignedEnvelope::from_envelope_bytes(&msg[1..])
            .map_err(|e| GatewayError::Protocol(format!("participant ack: {e}")))?;
        let outcome = registry.admit_ack(now_fresh, &participant_ack_env)?;
        if outcome != AckOutcome::Established {
            return Err(GatewayError::Protocol(
                "circuit not established after both acks".into(),
            ));
        }

        // 3. Data plane: split the tunnel so one side can block on the
        //    next participant frame while a dedicated thread forwards
        //    uplink responses back (the halves share the runtime and
        //    the connection lifetime).
        let (sender, mut receiver) = stream.split();
        let sender = Arc::new(Mutex::new(sender));
        // Wildcard bind: the uplink is the INTERNET side — it must be
        // able to reach real external destinations, not only loopback
        // (R4-007: a loopback-bound socket cannot route to the real
        // Internet and fails with EINVAL on send_to). Wildcard also
        // covers the loopback echo stand-ins the tests use.
        let uplink_socket = Arc::new(
            std::net::UdpSocket::bind("0.0.0.0:0")
                .map_err(|e| GatewayError::Setup(format!("uplink socket: {e}")))?,
        );
        uplink_socket
            .set_read_timeout(Some(std::time::Duration::from_millis(50)))
            .map_err(|e| GatewayError::Setup(e.to_string()))?;
        let mut stats = GatewayStats::default();
        let response_state = Arc::new(Mutex::new(0u64)); // direction-2 seq
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let uplink_socket = uplink_socket.clone();
            let sender = sender.clone();
            let response_state = response_state.clone();
            let stop = stop.clone();
            std::thread::Builder::new()
                .name("gateway-uplink-reader".into())
                .spawn(move || {
                    let mut buf = vec![0u8; GATEWAY_MAX_PACKET];
                    while !stop.load(std::sync::atomic::Ordering::SeqCst) {
                        match uplink_socket.recv_from(&mut buf) {
                            Ok((n, _from)) => {
                                let seq = {
                                    let mut s = response_state.lock().expect("seq lock");
                                    let current = *s;
                                    *s += 1;
                                    current
                                };
                                let frame = match CircuitFrame::new(
                                    circuit_id,
                                    DIRECTION_EXIT_TO_INITIATOR,
                                    seq,
                                    buf[..n].to_vec(),
                                ) {
                                    Ok(f) => f,
                                    Err(_) => break,
                                };
                                let mut guard = sender.lock().expect("sender lock");
                                if send_message(&mut *guard, control::CIRCUIT_FRAME, &frame.to_wire_bytes())
                                    .is_err()
                                {
                                    break;
                                }
                            }
                            Err(e)
                                if e.kind() == std::io::ErrorKind::WouldBlock
                                    || e.kind() == std::io::ErrorKind::TimedOut =>
                            {
                                continue // idle tick: re-check the stop flag
                            }
                            Err(_) => break,
                        }
                    }
                })
                .map_err(|e| GatewayError::Io(format!("spawn uplink reader: {e}")))?;
        }

        // 4. Frame loop: participant → uplink. The receiver blocks
        //    here; the sender is free for the response thread.
        loop {
            let msg = receiver.recv_frame().map_err(|e| GatewayError::Io(e.to_string()))?;
            match msg[0] {
                control::CIRCUIT_FRAME => {
                    let frame = CircuitFrame::from_wire_bytes(&msg[GATEWAY_CONTROL_PREFIX_LEN..])?;
                    registry.admit_frame(&frame)?;
                    let payload = frame.payload();
                    if payload.len() > GATEWAY_MAX_PACKET {
                        return Err(GatewayError::Protocol(format!(
                            "packet of {} bytes exceeds the uplink bound",
                            payload.len()
                        )));
                    }
                    uplink_socket
                        .send_to(payload, self.uplink)
                        .map_err(|e| GatewayError::Io(e.to_string()))?;
                    stats.forwarded_up += 1;
                }
                control::CIRCUIT_DESTROY => {
                    let env = SignedEnvelope::from_envelope_bytes(&msg[1..])?;
                    registry.admit_destroy(&env)?;
                    stats.destroy_reason = Some(
                        CircuitDestroy::from_wire_bytes(env.bytes())?
                            .reason()
                            .to_string(),
                    );
                    // Application-level acknowledgement: the participant
                    // waits for this BYE before dropping its side (QUIC
                    // close discards in-flight frames — the destroy must
                    // not race the teardown).
                    let mut guard = sender.lock().expect("sender lock");
                    send_message(&mut *guard, control::BYE, b"")?;
                    break;
                }
                control::BYE => {
                    stats.bye = true;
                    break;
                }
                other => {
                    return Err(GatewayError::Protocol(format!(
                        "unexpected control byte {other:#x}"
                    )));
                }
            }
        }
        // Drain in-flight uplink responses before dropping the stream
        // (QUIC close discards in-flight data): stop accepting new
        // ones after a bounded wait.
        std::thread::sleep(std::time::Duration::from_millis(250));
        stop.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(stats)
    }
}

/// Per-session forwarding counters.
#[derive(Debug, Default, Clone)]
pub struct GatewayStats {
    pub forwarded_up: u64,
    pub destroy_reason: Option<String>,
    pub bye: bool,
}

fn recv_message(stream: &mut TunnelStream) -> Result<Vec<u8>, GatewayError> {
    stream
        .recv_frame()
        .map_err(|e| GatewayError::Io(e.to_string()))
}

fn send_message(
    stream: &mut impl FrameSender,
    kind: u8,
    payload: &[u8],
) -> Result<(), GatewayError> {
    let mut msg = Vec::with_capacity(1 + payload.len());
    msg.push(kind);
    msg.extend_from_slice(payload);
    stream
        .send_frame(&msg)
        .map_err(|e| GatewayError::Io(e.to_string()))
}

/// Anything that can send one framed message (the tunnel stream and
/// its split sender both qualify).
trait FrameSender {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), sharenet_transport_quic::TunnelError>;
}

impl FrameSender for TunnelStream {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), sharenet_transport_quic::TunnelError> {
        TunnelStream::send_frame(self, frame)
    }
}

impl FrameSender for TunnelSender {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), sharenet_transport_quic::TunnelError> {
        TunnelSender::send_frame(self, frame)
    }
}

// ---------------------------------------------------------------------------
// Participant side
// ---------------------------------------------------------------------------

/// A participant endpoint: connects to a gateway with the gateway's
/// node id PINNED (R4-001), establishes a two-node circuit over the
/// committed route (R3-004), and exchanges circuit frames.
pub struct GatewayClient {
    seed: [u8; 32],
    gateway_addr: SocketAddr,
    gateway_node_id: [u8; 32],
}

impl GatewayClient {
    pub fn new(seed: [u8; 32], gateway_addr: SocketAddr, gateway_node_id: [u8; 32]) -> Self {
        GatewayClient {
            seed,
            gateway_addr,
            gateway_node_id,
        }
    }

    /// Connect and run the full establishment handshake. Returns the
    /// established session.
    pub fn connect(&self) -> Result<ParticipantSession, GatewayError> {
        let client = TunnelClient::new(self.seed)
            .map_err(|e| GatewayError::Setup(e.to_string()))?;
        let mut stream = client
            .connect(self.gateway_addr, self.gateway_node_id)
            .map_err(|e| GatewayError::Setup(e.to_string()))?;
        let participant = Identity::from_seed(self.seed, 0, None)
            .map_err(|e| GatewayError::Setup(e.to_string()))?;
        let now = now_unix();

        // 1. Build the route: path = [participant, gateway] (the
        //    canonical sorted order), the participant proposes and
        //    signs its own acceptance; the gateway signs the other.
        let mut path = vec![*participant.node_id().as_bytes(), self.gateway_node_id];
        path.sort();
        let mut proposal_nonce = [0u8; 32];
        proposal_nonce[..8].copy_from_slice(&now.to_be_bytes());
        let proposal = RouteProposal::new(
            &participant,
            path.clone(),
            "live",
            now,
            600,
            proposal_nonce,
        )?;
        let proposal_env = proposal.sign(&participant)?;
        let proposal_id = derive_proposal_id(proposal_env.bytes());
        let participant_position = path
            .iter()
            .position(|p| p == participant.node_id().as_bytes())
            .expect("own position") as u64;
        let participant_acceptance = RouteAcceptance::new(
            &participant,
            proposal_id,
            participant_position,
            proposal.proposed_at_unix(),
            600,
        )?;
        let participant_acceptance_env = participant_acceptance.sign(&participant)?;

        send_message(
            &mut stream,
            control::ROUTE_PROPOSAL,
            &proposal_env.to_envelope_bytes(),
        )?;

        // 2. Gateway's acceptance.
        let msg = recv_message(&mut stream)?;
        if msg[0] != control::ROUTE_ACCEPTANCE {
            return Err(GatewayError::Protocol(format!(
                "expected ROUTE_ACCEPTANCE, got {:#x}",
                msg[0]
            )));
        }
        let gateway_acceptance_env =
            SignedEnvelope::from_envelope_bytes(&msg[1..])
                .map_err(|e| GatewayError::Protocol(format!("gateway acceptance: {e}")))?;
        let commitment = RouteCommitment::build(
            now_unix(),
            proposal_env.clone(),
            vec![participant_acceptance_env.clone(), gateway_acceptance_env.clone()],
        )?;
        let mut circuit_setup_nonce = [0u8; 32];
        circuit_setup_nonce[..8].copy_from_slice(&(now ^ 0x5EED_0000_0000_0000).to_be_bytes());
        let setup = CircuitSetup::new(&commitment, &participant, circuit_setup_nonce, now, 600)?;
        let setup_env = setup.sign(&participant)?;
        send_message(&mut stream, control::CIRCUIT_SETUP, &setup_env.to_envelope_bytes())?;

        // 3. Gateway's circuit ack + own establishment.
        let msg = recv_message(&mut stream)?;
        if msg[0] != control::CIRCUIT_ACK {
            return Err(GatewayError::Protocol(format!(
                "expected CIRCUIT_ACK, got {:#x}",
                msg[0]
            )));
        }
        let gateway_ack_env = SignedEnvelope::from_envelope_bytes(&msg[1..])
            .map_err(|e| GatewayError::Protocol(format!("gateway ack: {e}")))?;
        let circuit_id = setup.circuit_id()?;
        // Timestamp discipline (mirror side): our ack anchors to the
        // setup's issued_at; admissions use fresh clock reads.
        let own_ack = CircuitSetupAck::new(
            circuit_id,
            &setup_env,
            &participant,
            participant_position,
            setup.issued_at_unix(),
            600,
        )?;
        let own_ack_env = own_ack.sign(&participant)?;
        // Deliver OUR ack to the gateway (exact position coverage means
        // both ends must acknowledge — the gateway admits this next).
        send_message(&mut stream, control::CIRCUIT_ACK, &own_ack_env.to_envelope_bytes())?;
        let now_fresh = now_unix();
        let mut registry = CircuitRegistry::new();
        registry.admit_setup(now_fresh, &setup_env)?;
        registry.admit_ack(now_fresh, &own_ack_env)?;
        let outcome = registry.admit_ack(now_fresh, &gateway_ack_env)?;
        if outcome != AckOutcome::Established {
            return Err(GatewayError::Protocol(
                "circuit not established after both acks".into(),
            ));
        }

        Ok(ParticipantSession {
            stream,
            registry,
            circuit_id,
        })
    }
}

/// An established participant session: send packets (direction 1),
/// receive uplink responses (direction 2), destroy when done.
pub struct ParticipantSession {
    stream: TunnelStream,
    registry: CircuitRegistry,
    circuit_id: [u8; 32],
}

impl ParticipantSession {
    /// Forward one packet to the gateway (and through it, the uplink).
    pub fn send_packet(&mut self, packet: &[u8]) -> Result<(), GatewayError> {
        if packet.is_empty() {
            return Err(GatewayError::Protocol("empty packet".into()));
        }
        if packet.len() > GATEWAY_MAX_PACKET {
            return Err(GatewayError::Protocol(format!(
                "packet of {} bytes exceeds the {}-byte bound",
                packet.len(),
                GATEWAY_MAX_PACKET
            )));
        }
        let seq = self
            .registry
            .circuit(&self.circuit_id)
            .and_then(|s| s.next_seq(DIRECTION_INITIATOR_TO_EXIT))
            .ok_or(GatewayError::Closed)?;
        let frame = CircuitFrame::new(self.circuit_id, DIRECTION_INITIATOR_TO_EXIT, seq, packet.to_vec())?;
        self.registry.admit_frame(&frame)?;
        send_message(&mut self.stream, control::CIRCUIT_FRAME, &frame.to_wire_bytes())
    }

    /// Block for the next uplink response (direction 2), admitting it
    /// into the local replay namespace.
    pub fn recv_response(&mut self) -> Result<Vec<u8>, GatewayError> {
        let msg = recv_message(&mut self.stream)?;
        if msg[0] != control::CIRCUIT_FRAME {
            return Err(GatewayError::Protocol(format!(
                "expected CIRCUIT_FRAME, got {:#x}",
                msg[0]
            )));
        }
        let frame = CircuitFrame::from_wire_bytes(&msg[1..])?;
        self.registry.admit_frame(&frame)?;
        Ok(frame.payload().to_vec())
    }

    /// Destroy the circuit (terminal) and wait for the gateway's BYE
    /// acknowledgement (so process teardown never races in-flight
    /// frames — the QUIC close-semantics rule).
    pub fn destroy(
        &mut self,
        participant: &Identity,
        reason: &str,
    ) -> Result<(), GatewayError> {
        let destroy = CircuitDestroy::new(self.circuit_id, participant, reason, now_unix())?;
        let env = destroy.sign(participant)?;
        self.registry.admit_destroy(&env)?;
        send_message(&mut self.stream, control::CIRCUIT_DESTROY, &env.to_envelope_bytes())?;
        let ack = recv_message(&mut self.stream)?;
        if ack.first() != Some(&control::BYE) {
            return Err(GatewayError::Protocol(format!(
                "expected BYE after destroy, got {:#04x?}",
                ack.first()
            )));
        }
        Ok(())
    }

    pub fn circuit_id(&self) -> &[u8; 32] {
        &self.circuit_id
    }
}
