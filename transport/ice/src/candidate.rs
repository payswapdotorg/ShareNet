//! ICE candidate model and gathering (RFC 8445 concepts, work item R4-005).
//!
//! This is the standard ICE candidate model — no new traversal protocol
//! (architecture lock L011):
//!
//! - candidate types: host (a directly bound socket address),
//!   server-reflexive (the XOR-MAPPED-ADDRESS a STUN server observed) and
//!   relayed (a TURN-style allocation's relayed address);
//! - priority = `(2^24)*type_preference + (2^8)*local_preference +
//!   (256 - component_id)` (RFC 8445 §6.1.2.3 recommended type
//!   preferences: host 126, server-reflexive 100, relayed 0);
//! - foundation: a stable string derived from type + base, so candidates
//!   that would fail together share it (RFC 8445 §6.1.1.3's rule that
//!   same type + same base ⇒ same foundation);
//! - gathering produces a frozen `Vec<Candidate>` (host + srflx + relayed)
//!   plus the sockets behind them;
//! - pairing orders the candidate cross-product by the RFC 8445
//!   §6.1.2.3 pair priority formula.
//!
//! Deliberately NOT implemented here (documented for honesty): the full
//! ICE agent state machine, role negotiation, checks with triggered
//! queues and nomination — those are future R4-006/R4-007 scope. The
//! `connectivity_check` helper (in `crate::stun`) runs the check
//! exchange itself.
//!
//! One documented deviation from RFC 8445 §5.1.3: a server-reflexive
//! candidate whose address equals its base is KEPT, not discarded — on a
//! loopback "NAT" (identity mapping) the srflx address IS the local
//! address, and discarding it would make loopback verification
//! impossible. Real multi-homed gathering will revisit this.

use std::net::SocketAddr;

use crate::error::IceError;
use crate::relay::RelayClient;
use crate::stun::{binding_request, StunConfig};

/// ICE candidate types (RFC 8445 §5.1.1 subset relevant to UDP gathering).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateType {
    Host,
    ServerReflexive,
    Relayed,
}

impl CandidateType {
    /// RFC 8445 §6.1.2.3 recommended type preferences.
    pub fn type_preference(self) -> u32 {
        match self {
            CandidateType::Host => 126,
            CandidateType::ServerReflexive => 100,
            CandidateType::Relayed => 0,
        }
    }

    /// The foundation prefix (stable per type).
    pub fn foundation_prefix(self) -> &'static str {
        match self {
            CandidateType::Host => "host",
            CandidateType::ServerReflexive => "srflx",
            CandidateType::Relayed => "relay",
        }
    }
}

/// A gathered ICE candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    candidate_type: CandidateType,
    /// The address peers use to reach this candidate.
    transport_addr: SocketAddr,
    /// The local socket address the candidate is reachable through.
    base_addr: SocketAddr,
    component_id: u32,
    local_preference: u32,
    foundation: String,
}

impl Candidate {
    /// Construct a candidate; `foundation` is derived from type + base.
    pub fn new(
        candidate_type: CandidateType,
        transport_addr: SocketAddr,
        base_addr: SocketAddr,
        component_id: u32,
        local_preference: u32,
    ) -> Result<Self, IceError> {
        if component_id == 0 || component_id > 256 {
            return Err(IceError::CandidateComponentInvalid { component: component_id });
        }
        if local_preference > 0x00FF_FFFF {
            return Err(IceError::CandidateLocalPreferenceInvalid { local_preference });
        }
        let foundation = format!(
            "{}:{}",
            candidate_type.foundation_prefix(),
            base_addr
        );
        Ok(Candidate {
            candidate_type,
            transport_addr,
            base_addr,
            component_id,
            local_preference,
            foundation,
        })
    }

    pub fn candidate_type(&self) -> CandidateType {
        self.candidate_type
    }

    /// The address peers connect to (host address, mapped address or the
    /// relay's relayed address).
    pub fn transport_addr(&self) -> SocketAddr {
        self.transport_addr
    }

    /// The local socket this candidate rides on.
    pub fn base_addr(&self) -> SocketAddr {
        self.base_addr
    }

    pub fn component_id(&self) -> u32 {
        self.component_id
    }

    pub fn local_preference(&self) -> u32 {
        self.local_preference
    }

    /// Stable foundation string (type + base).
    pub fn foundation(&self) -> &str {
        &self.foundation
    }

    /// RFC 8445 §6.1.2.3:
    /// priority = 2^24*type + 2^8*local + (256 - component).
    pub fn priority(&self) -> u32 {
        (1u32 << 24) * self.candidate_type.type_preference()
            + (1u32 << 8) * self.local_preference
            + (256 - self.component_id)
    }
}

/// A local/remote candidate cross-product entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidatePair {
    pub local: Candidate,
    pub remote: Candidate,
}

impl CandidatePair {
    /// RFC 8445 §6.1.2.3 pair priority:
    /// `2^32*MIN(G,D) + 2*MAX(G,D) + (G>D ? 1 : 0)` where G is the
    /// CONTROLLING agent's candidate priority and D the controlled's.
    pub fn priority(&self, local_is_controlling: bool) -> u64 {
        let (g, d) = if local_is_controlling {
            (self.local.priority(), self.remote.priority())
        } else {
            (self.remote.priority(), self.local.priority())
        };
        (1u64 << 32) * (g.min(d) as u64) + 2 * (g.max(d) as u64) + u64::from(g > d)
    }
}

/// Pair every local candidate with every remote candidate, ordered by
/// descending pair priority. (Role negotiation and nomination are future
/// R4-006/R4-007 scope.)
pub fn pair_candidates(
    local: &[Candidate],
    remote: &[Candidate],
    local_is_controlling: bool,
) -> Vec<CandidatePair> {
    let mut pairs: Vec<CandidatePair> = local
        .iter()
        .flat_map(|l| {
            remote
                .iter()
                .map(move |r| CandidatePair {
                    local: l.clone(),
                    remote: r.clone(),
                })
        })
        .collect();
    pairs.sort_by(|a, b| {
        b.priority(local_is_controlling)
            .cmp(&a.priority(local_is_controlling))
    });
    pairs
}

/// Gathering configuration.
#[derive(Debug, Clone)]
pub struct GatherConfig {
    /// Local bind for the host (and server-reflexive) base socket.
    pub bind: SocketAddr,
    /// Optional STUN server to discover the server-reflexive candidate.
    pub stun_server: Option<SocketAddr>,
    /// Optional TURN-style relay control address to allocate a relayed
    /// candidate from.
    pub relay: Option<SocketAddr>,
    /// STUN client behavior used for the srflx binding.
    pub stun: StunConfig,
}

impl Default for GatherConfig {
    fn default() -> Self {
        GatherConfig {
            bind: "127.0.0.1:0".parse().expect("static addr"),
            stun_server: None,
            relay: None,
            stun: StunConfig::default(),
        }
    }
}

/// The frozen result of gathering.
#[derive(Debug)]
pub struct Gathered {
    /// Frozen candidate set (host, then server-reflexive, then relayed —
    /// whichever sources were configured).
    pub candidates: Vec<Candidate>,
    /// The base socket of the host/srflx candidates.
    pub host_socket: std::net::UdpSocket,
    /// The allocation owning the relayed candidate (its base), if any.
    pub relay: Option<RelayClient>,
}

/// Gather candidates (RFC 8445 §5.1.1 subset):
///
/// - bind one UDP socket — its local address is the host candidate;
/// - when `stun_server` is set, run one Binding exchange from that same
///   socket; the XOR-MAPPED-ADDRESS becomes the server-reflexive
///   candidate (base = the host socket);
/// - when `relay` is set, allocate on the TURN-style relay; the relayed
///   address becomes the relayed candidate (base = the allocation's
///   control socket, kept in [`Gathered::relay`]).
///
/// The host candidate is the socket's bound address — a multi-homed host
/// would enumerate interfaces for one host candidate per interface
/// (future scope; tests bind concrete loopback addresses).
pub fn gather(config: &GatherConfig) -> Result<Gathered, IceError> {
    let host_socket = std::net::UdpSocket::bind(config.bind).map_err(|e| {
        IceError::BindFailed(format!("{}: {e}", config.bind))
    })?;
    let base = host_socket
        .local_addr()
        .map_err(|e| IceError::Io(e.to_string()))?;
    let mut candidates = vec![Candidate::new(
        CandidateType::Host,
        base,
        base,
        1,
        65_535,
    )?];

    if let Some(server) = config.stun_server {
        let outcome = binding_request(&host_socket, server, &config.stun)?;
        // Kept even when equal to base — see the module docs (loopback
        // identity NAT makes them equal; RFC 8445 §5.1.3 would discard).
        candidates.push(Candidate::new(
            CandidateType::ServerReflexive,
            outcome.mapped,
            base,
            1,
            65_535,
        )?);
    }

    let mut relay = None;
    if let Some(relay_addr) = config.relay {
        let control_bind = SocketAddr::new(config.bind.ip(), 0);
        let client = RelayClient::allocate(relay_addr, control_bind)?;
        let relayed = client.relayed_addr();
        let control_base = client.local_addr()?;
        candidates.push(Candidate::new(
            CandidateType::Relayed,
            relayed,
            control_base,
            1,
            65_535,
        )?);
        relay = Some(client);
    }

    Ok(Gathered {
        candidates,
        host_socket,
        relay,
    })
}

// ---------------------------------------------------------------------------
// Unit tests: the RFC 8445 formulas, hand-computed
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: SocketAddr = SocketAddr::new(
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 33)),
        49171,
    );

    fn candidate(
        candidate_type: CandidateType,
        local_preference: u32,
        component_id: u32,
    ) -> Candidate {
        Candidate::new(
            candidate_type,
            SocketAddr::new(BASE.ip(), 32853),
            BASE,
            component_id,
            local_preference,
        )
        .expect("valid candidate")
    }

    #[test]
    fn type_preferences_follow_rfc8445_recommendation() {
        // RFC 8445 §6.1.2.3: host 126, server-reflexive 100, relayed 0.
        assert_eq!(CandidateType::Host.type_preference(), 126);
        assert_eq!(CandidateType::ServerReflexive.type_preference(), 100);
        assert_eq!(CandidateType::Relayed.type_preference(), 0);
        assert!(CandidateType::Host.type_preference() > CandidateType::ServerReflexive.type_preference());
        assert!(CandidateType::ServerReflexive.type_preference() > CandidateType::Relayed.type_preference());
    }

    /// priority = 2^24*type + 2^8*local + (256 - component), hand-computed
    /// for the gather() parameters (local 65535, component 1):
    /// host 2130706431, srflx 1694498815, relayed 16777215.
    #[test]
    fn priority_formula_hand_computed() {
        let host = candidate(CandidateType::Host, 65_535, 1);
        let srflx = candidate(CandidateType::ServerReflexive, 65_535, 1);
        let relay = candidate(CandidateType::Relayed, 65_535, 1);
        assert_eq!(host.priority(), 126 * 16_777_216 + 65_535 * 256 + 255);
        assert_eq!(host.priority(), 2_130_706_431);
        assert_eq!(srflx.priority(), 100 * 16_777_216 + 65_535 * 256 + 255);
        assert_eq!(srflx.priority(), 1_694_498_815);
        assert_eq!(relay.priority(), 65_535 * 256 + 255);
        assert_eq!(relay.priority(), 16_777_215);
        assert!(host.priority() > srflx.priority());
        assert!(srflx.priority() > relay.priority());
        // zero local preference, component 1: 126*2^24 + 255
        assert_eq!(candidate(CandidateType::Host, 0, 1).priority(), 2_113_929_471);
    }

    #[test]
    fn priority_scales_with_local_preference_and_component() {
        let a = candidate(CandidateType::Host, 100, 1);
        let b = candidate(CandidateType::Host, 101, 1);
        assert_eq!(b.priority() - a.priority(), 256); // 2^8 per local step
        let c = candidate(CandidateType::Host, 100, 2);
        assert_eq!(a.priority() - c.priority(), 1); // (256 - comp) per step
    }

    #[test]
    fn foundation_is_type_plus_base() {
        let host_a = candidate(CandidateType::Host, 1, 1);
        let host_b = candidate(CandidateType::Host, 2, 1);
        assert_eq!(host_a.foundation(), host_b.foundation()); // same type + base
        let srflx = candidate(CandidateType::ServerReflexive, 1, 1);
        assert_ne!(host_a.foundation(), srflx.foundation()); // type differs
        let other_base = Candidate::new(
            CandidateType::Host,
            SocketAddr::new(BASE.ip(), 32854),
            SocketAddr::new(BASE.ip(), 49172),
            1,
            1,
        )
        .expect("valid");
        assert_ne!(host_a.foundation(), other_base.foundation()); // base differs
        assert!(host_a.foundation().starts_with("host:"));
        assert!(srflx.foundation().starts_with("srflx:"));
    }

    #[test]
    fn candidate_construction_validation() {
        assert!(matches!(
            Candidate::new(CandidateType::Host, BASE, BASE, 0, 1),
            Err(IceError::CandidateComponentInvalid { component: 0 })
        ));
        assert!(matches!(
            Candidate::new(CandidateType::Host, BASE, BASE, 257, 1),
            Err(IceError::CandidateComponentInvalid { component: 257 })
        ));
        assert!(matches!(
            Candidate::new(CandidateType::Host, BASE, BASE, 1, 0x0100_0000),
            Err(IceError::CandidateLocalPreferenceInvalid { local_preference: 0x0100_0000 })
        ));
        assert!(Candidate::new(CandidateType::Host, BASE, BASE, 256, 0x00FF_FFFF).is_ok());
    }

    /// RFC 8445 §6.1.2.3 pair priority:
    /// 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D), hand-computed for candidates
    /// with priorities A = 2113955071 (host, local 100, comp 1) and
    /// B = 2113942270 (host, local 50, comp 2). The min/max terms are
    /// symmetric in the pair; only the controlling-role tie-break bit
    /// differs between the two role assignments.
    #[test]
    fn pair_priority_formula_hand_computed() {
        let a = candidate(CandidateType::Host, 100, 1); // priority 2113955071
        let b = candidate(CandidateType::Host, 50, 2); // priority 2113942270
        assert_eq!(a.priority(), 2_113_955_071);
        assert_eq!(b.priority(), 2_113_942_270);
        let pair = CandidatePair { local: a.clone(), remote: b.clone() };
        // local controlling: G = A, D = B (A > B, so the tie-break is 1)
        assert_eq!(pair.priority(true), 9_079_312_919_509_912_063);
        // local controlled: G = B, D = A (same min/max, tie-break 0)
        assert_eq!(pair.priority(false), 9_079_312_919_509_912_062);
        assert_eq!(pair.priority(true) - pair.priority(false), 1);
        // identity of the pair regardless of role assignment order
        let mirrored = CandidatePair { local: b, remote: a };
        assert_eq!(mirrored.priority(false), pair.priority(true));
        assert_eq!(mirrored.priority(true), pair.priority(false));
    }

    #[test]
    fn pair_candidates_orders_by_descending_priority() {
        let local = [
            candidate(CandidateType::Host, 100, 1),
            candidate(CandidateType::Relayed, 1, 1),
        ];
        let remote = [
            candidate(CandidateType::Host, 50, 2),
            candidate(CandidateType::ServerReflexive, 3, 1),
            candidate(CandidateType::Relayed, 2, 1),
        ];
        let pairs = pair_candidates(&local, &remote, true);
        assert_eq!(pairs.len(), 6); // full cross-product
        let priorities: Vec<u64> = pairs.iter().map(|p| p.priority(true)).collect();
        let mut sorted = priorities.clone();
        sorted.sort_unstable_by(|x, y| y.cmp(x));
        assert_eq!(priorities, sorted); // descending order
        // every combination present exactly once
        for l in &local {
            for r in &remote {
                assert_eq!(
                    pairs
                        .iter()
                        .filter(|p| p.local == *l && p.remote == *r)
                        .count(),
                    1
                );
            }
        }
    }

    #[test]
    fn gather_host_only_without_servers() {
        let gathered = gather(&GatherConfig::default()).expect("gather");
        let local = gathered.host_socket.local_addr().expect("addr");
        assert_eq!(gathered.candidates.len(), 1);
        let host = &gathered.candidates[0];
        assert_eq!(host.candidate_type(), CandidateType::Host);
        assert_eq!(host.transport_addr(), local);
        assert_eq!(host.base_addr(), local);
        assert!(gathered.relay.is_none());
    }
}
