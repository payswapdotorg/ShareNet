//! The ICE agent: candidate pairing, connectivity checks and NOMINATION
//! with restrictive-network fallback (work item R4-006).
//!
//! This is the RFC 8445 agent restricted to what ShareNet's tunnel
//! bring-up needs (L011 — the standard ICE concepts, no invented
//! traversal protocol):
//!
//! 1. **Gather** local candidates with the existing [`crate::candidate`]
//!    API — host (+ server-reflexive via a STUN server when configured)
//!    and, on fallback, a relayed candidate allocated from the TURN-style
//!    relay (with credentials when the relay demands them);
//! 2. **Pair** them with the caller-supplied remote candidates using
//!    [`crate::candidate::pair_candidates`] — the RFC 8445 §6.1.2.3
//!    pair-priority order, which tries DIRECT paths (host/srflx on both
//!    sides) first by construction;
//! 3. **Check** each pair in priority order with the existing
//!    [`crate::stun::connectivity_check`] (RFC 8445 §7 subset) and
//!    **nominate the first working pair**;
//! 4. **Restrictive-network fallback**: when the direct-path checks fail
//!    (timeout, refused, …), the agent falls back to relayed candidates —
//!    remote relayed candidates are checked as part of the priority walk
//!    (the TARGET sits behind a relay), and if every local host/srflx
//!    base failed, the agent ALLOCATES a local relayed candidate from
//!    the configured TURN-style relay and completes the walk through it
//!    (the CLIENT side is restricted too). The local allocation happens
//!    lazily — only at fallback time, so an open network never pays the
//!    relay a single round trip (`no relay allocation used` is a
//!    first-class, testable outcome);
//! 5. **Fail closed**: a hostile/corrupt check response never nominates
//!    anything (the strict parse fails the pair, typed) and the run ends
//!    with the typed [`IceError::AgentNoPath`] carrying the FULL attempt
//!    transcript — reachability is never fabricated.
//!
//! Deliberately NOT implemented here (documented for honesty; they are
//! R4-007 real-network / future agent scope): RFC 8445 role negotiation
//! and role conflicts, consent freshness (§11), triggered checks and
//! peer-reflexive candidates, and multi-component streams. The
//! nomination here is the controlling-agent half only (the remote peer
//! is an ICE-lite responder, exactly what the `ice_peer` scaffolding
//! implements).
//!
//! # Candidate exchange
//!
//! The remote candidate set arrives out-of-band (the caller supplies
//! it); ICE candidate SIGNALING (how peers exchange candidates) is
//! application/daemon scope, not this transport crate. The
//! multiprocess tests demonstrate the intended flow: the peer prints its
//! reachable addresses (READY line), the agent's caller turns them into
//! [`Candidate`]s.
//!
//! # The data path after nomination
//!
//! [`Nomination::pair`] supplies the address source for
//! [`crate::bridge::tunnel_connect`] (R4-001 node-pinned QUIC) exactly as
//! the R4-005 tests did: the nominated pair's REMOTE candidate is the
//! connect target. When the remote candidate is relayed, the relay
//! rides the whole QUIC session transparently (L012). When the agent's
//! own relayed candidate won the nomination (client-side restriction),
//! the local allocation verified the path but is DROPPED when
//! `nominate` returns — on the loopback evidence networks the client can
//! always reach the remote relayed address directly with its QUIC
//! socket, and a data plane that rides the client's OWN allocation
//! requires the real client-side NAT shapes of R4-007 (the tunnel
//! crate's client endpoint currently binds IPv4 loopback only).

use std::net::SocketAddr;

use crate::candidate::{
    gather, pair_candidates, Candidate, CandidatePair, CandidateType, GatherConfig,
};
use crate::error::IceError;
use crate::relay::{RelayClient, RelayCredential};
use crate::stun::{connectivity_check_with, StunConfig};

/// Which kind of path the nominated pair rides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathKind {
    /// Both candidates are host/server-reflexive: a direct path.
    Direct,
    /// The nominated pair includes a relayed candidate (either side):
    /// the path rides a TURN-style relay.
    Relay,
}

impl PathKind {
    /// Classify a pair: any relayed candidate (local or remote) makes it
    /// a relay path.
    pub fn of(pair: &CandidatePair) -> Self {
        let relayed = matches!(
            pair.local.candidate_type(),
            CandidateType::Relayed
        ) || matches!(pair.remote.candidate_type(), CandidateType::Relayed);
        if relayed {
            PathKind::Relay
        } else {
            PathKind::Direct
        }
    }

    /// Stable machine name.
    pub fn name(self) -> &'static str {
        match self {
            PathKind::Direct => "direct",
            PathKind::Relay => "relay",
        }
    }
}

/// One checked candidate pair and its typed outcome: the address the
/// target observed as this side's source on success, or the typed
/// failure of the check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairAttempt {
    pub pair: CandidatePair,
    pub outcome: Result<SocketAddr, IceError>,
}

/// A TURN-style relay endpoint the agent may fall back to, with the
/// long-term credential when the relay demands one (R4-006).
#[derive(Debug, Clone)]
pub struct RelayEndpoint {
    /// The relay's control address.
    pub addr: SocketAddr,
    /// The long-term credential (needed by authenticated relays).
    pub credential: Option<RelayCredential>,
}

/// The agent's configuration.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    /// Local bind for the host (and server-reflexive) base socket.
    pub bind: SocketAddr,
    /// Optional STUN server for server-reflexive gathering.
    pub stun_server: Option<SocketAddr>,
    /// The Binding policy used for the srflx gathering exchange.
    pub stun: StunConfig,
    /// The TURN-style relay to fall back to (with credentials when it
    /// demands them). `None` = no relay fallback: if all pairs fail the
    /// agent reports `AgentNoPath` without ever allocating.
    pub relay: Option<RelayEndpoint>,
    /// The connectivity-check policy (attempts × per-attempt timeout).
    pub check: StunConfig,
}

impl Default for AgentConfig {
    fn default() -> Self {
        AgentConfig {
            bind: "127.0.0.1:0".parse().expect("static addr"),
            stun_server: None,
            stun: StunConfig::default(),
            relay: None,
            check: StunConfig::default(),
        }
    }
}

/// The nomination result: the first working pair, the path it rides and
/// the full attempt transcript.
#[derive(Debug, Clone)]
pub struct Nomination {
    /// The kind of path the nominated pair rides.
    pub path: PathKind,
    /// The nominated (first working) pair. Its REMOTE candidate is the
    /// `tunnel_connect` address source; its LOCAL candidate documents
    /// which base the checks rode.
    pub pair: CandidatePair,
    /// The address the nominated target observed as this agent's source
    /// during the winning check (the host/srflx/relayed address as seen
    /// through whatever NAT/relay the path crossed — informational; a
    /// restrictive network legitimately rewrites it, so it is RECORDED,
    /// never validated against the local candidate).
    pub observed: SocketAddr,
    /// Whether the agent allocated a LOCAL relayed candidate (the
    /// phase-2 client-side fallback). `false` means the relay was never
    /// touched: an open network never allocates.
    pub local_relay_used: bool,
    /// Every pair checked, in attempt order, with its typed outcome.
    pub attempts: Vec<PairAttempt>,
}

/// The loopback address of the relay's family: the local allocation
/// control socket must share the relay's address family (a control bind
/// of the other family cannot send to the relay). Multi-homed control
/// binds are future scope, mirroring `gather`'s single-host-candidate
/// note.
fn loopback_of_family(addr: SocketAddr) -> SocketAddr {
    if addr.is_ipv4() {
        "127.0.0.1:0".parse().expect("static addr")
    } else {
        "[::1]:0".parse().expect("static addr")
    }
}

/// Nominate the first working candidate pair (the R4-006 ICE agent).
///
/// See the module docs for the full policy. Summary:
///
/// - remote candidates must be non-empty (`AgentNoRemoteCandidates`);
/// - phase 1 gathers host (+ srflx when configured; a dead STUN server
///   degrades to host-only — a gathering failure is not a reachability
///   claim and never fabricates one) and walks ALL pairs whose local
///   candidate is host/srflx in RFC 8445 pair-priority order — remote
///   relayed candidates included, so a target-only-reachable-via-relay
///   is nominated as soon as its (lower-priority) pair is checked;
/// - phase 2 (only when every phase-1 pair failed and a relay is
///   configured): allocate a LOCAL relayed candidate — authenticated
///   when the endpoint carries a credential (a failed allocation
///   propagates its typed error, e.g. `RelayAuthRejected`) — and walk
///   the local-relayed pairs. Cross-phase order is a documented ±1
///   deviation from the strict pair-priority interleaving (the
///   G>D tie-bit between local-relayed and remote-relayed pairs —
///   both are relay paths);
/// - the first passing check wins (`Nomination`); per-pair failures are
///   recorded and the walk continues — a hostile response on one pair
///   never poisons another pair's independent check;
/// - if nothing passes: `AgentNoPath` with the full transcript.
pub fn nominate(config: &AgentConfig, remote: &[Candidate]) -> Result<Nomination, IceError> {
    if remote.is_empty() {
        return Err(IceError::AgentNoRemoteCandidates);
    }

    // ------------------------------------------------------------------
    // Phase 1: direct candidates (host + optional srflx). The relay is
    // deliberately NOT configured here — an open network must never
    // allocate from it.
    // ------------------------------------------------------------------
    let mut gather_config = GatherConfig {
        bind: config.bind,
        stun_server: config.stun_server,
        relay: None,
        stun: config.stun.clone(),
    };
    let gathered = match gather(&gather_config) {
        Ok(g) => g,
        Err(e) if config.stun_server.is_some() => {
            // The srflx source failed (e.g. a dead STUN server): degrade
            // to host-only. RFC 8445 gathering is per-source; a failed
            // source removes its candidates without inventing any.
            // (Re-gathering binds a fresh host socket — its address
            // differs from the failed attempt's, which is fine: nothing
            // has been nominated or advertised yet.)
            gather_config.stun_server = None;
            gather(&gather_config).map_err(|retry| {
                // Host gathering itself failing is a hard local error.
                let _ = e;
                retry
            })?
        }
        Err(e) => return Err(e),
    };

    let mut attempts: Vec<PairAttempt> = Vec::new();
    let pairs = pair_candidates(&gathered.candidates, remote, true);
    for pair in pairs {
        let target = pair.remote.transport_addr();
        match connectivity_check_with(&gathered.host_socket, target, &config.check) {
            Ok(observed) => {
                return Ok(Nomination {
                    path: PathKind::of(&pair),
                    pair,
                    observed,
                    local_relay_used: false,
                    attempts,
                });
            }
            Err(e) => attempts.push(PairAttempt {
                pair,
                outcome: Err(e),
            }),
        }
    }

    // ------------------------------------------------------------------
    // Phase 2: local relayed fallback (client-side restriction). Only
    // reached when every host/srflx-base pair failed; allocates from
    // the configured relay — authenticated when it carries a credential.
    // ------------------------------------------------------------------
    if let Some(relay) = &config.relay {
        let control_bind = loopback_of_family(relay.addr);
        let client = match &relay.credential {
            Some(credential) => {
                RelayClient::allocate_authenticated(relay.addr, control_bind, credential)?
            }
            None => RelayClient::allocate(relay.addr, control_bind)?,
        };
        let relayed_addr = client.relayed_addr();
        let control_base = client.local_addr()?;
        let relayed_candidate = Candidate::new(
            CandidateType::Relayed,
            relayed_addr,
            control_base,
            1,
            65_535,
        )?;
        let pairs = pair_candidates(&[relayed_candidate], remote, true);
        for pair in pairs {
            let target = pair.remote.transport_addr();
            match connectivity_check_with(&client, target, &config.check) {
                Ok(observed) => {
                    return Ok(Nomination {
                        path: PathKind::of(&pair),
                        pair,
                        observed,
                        local_relay_used: true,
                        attempts,
                    });
                }
                Err(e) => attempts.push(PairAttempt {
                    pair,
                    outcome: Err(e),
                }),
            }
        }
    }

    Err(IceError::AgentNoPath { attempts })
}

// ---------------------------------------------------------------------------
// Unit tests: path classification, fail-fast, in-process live/lying/dead
// responders (real UDP loopback)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stun::{MessageClass, StunMessage, METHOD_BINDING};
    use std::net::UdpSocket;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    fn host_candidate(addr: SocketAddr, preference: u32) -> Candidate {
        Candidate::new(CandidateType::Host, addr, addr, 1, preference)
            .expect("valid candidate")
    }

    fn relayed_candidate(addr: SocketAddr, base: SocketAddr) -> Candidate {
        Candidate::new(CandidateType::Relayed, addr, base, 1, 65_535)
            .expect("valid candidate")
    }

    #[test]
    fn path_kind_classification() {
        let h = host_candidate("192.0.2.1:1000".parse().expect("addr"), 1);
        let s = Candidate::new(
            CandidateType::ServerReflexive,
            "192.0.2.9:2000".parse().expect("addr"),
            "192.0.2.1:1000".parse().expect("addr"),
            1,
            1,
        )
        .expect("candidate");
        let r = relayed_candidate(
            "192.0.2.5:3000".parse().expect("addr"),
            "192.0.2.1:1000".parse().expect("addr"),
        );
        let pair = |l: &Candidate, r: &Candidate| CandidatePair {
            local: l.clone(),
            remote: r.clone(),
        };
        assert_eq!(PathKind::of(&pair(&h, &h)), PathKind::Direct);
        assert_eq!(PathKind::of(&pair(&h, &s)), PathKind::Direct);
        assert_eq!(PathKind::of(&pair(&s, &h)), PathKind::Direct);
        assert_eq!(PathKind::of(&pair(&s, &s)), PathKind::Direct);
        assert_eq!(PathKind::of(&pair(&h, &r)), PathKind::Relay);
        assert_eq!(PathKind::of(&pair(&r, &h)), PathKind::Relay);
        assert_eq!(PathKind::of(&pair(&s, &r)), PathKind::Relay);
        assert_eq!(PathKind::of(&pair(&r, &r)), PathKind::Relay);
        assert_eq!(PathKind::Direct.name(), "direct");
        assert_eq!(PathKind::Relay.name(), "relay");
    }

    #[test]
    fn empty_remote_candidates_fail_fast() {
        let error = nominate(&AgentConfig::default(), &[]).expect_err("empty remote");
        assert_eq!(error, IceError::AgentNoRemoteCandidates);
    }

    /// A fast check policy for the unit tests (2 × 150 ms keeps the
    /// failing-path walks quick while still exercising real timeouts).
    fn fast_check() -> StunConfig {
        StunConfig {
            software: "sharenet-agent-test".to_string(),
            attempts: 2,
            attempt_timeout: Duration::from_millis(150),
        }
    }

    /// Spawn a thread that answers STUN Binding Requests on `socket`
    /// with `evil = None`, or replies with `evil` garbage instead
    /// (the lying candidate).
    fn stun_responder(
        socket: Arc<UdpSocket>,
        evil: Option<Vec<u8>>,
        stop: Arc<AtomicBool>,
    ) -> std::thread::JoinHandle<()> {
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("timeout");
        std::thread::Builder::new()
            .name("stun-responder".into())
            .spawn(move || {
                let mut buf = [0u8; 65_536];
                while !stop.load(Ordering::SeqCst) {
                    match socket.recv_from(&mut buf) {
                        Ok((n, peer)) => {
                            let response = match &evil {
                                Some(garbage) => garbage.clone(),
                                None => match StunMessage::parse(&buf[..n]) {
                                    Ok(msg)
                                        if msg.class == MessageClass::Request
                                            && msg.method == METHOD_BINDING =>
                                    {
                                        match StunMessage::binding_success(
                                            msg.transaction_id,
                                            peer,
                                            Some("sharenet-agent-test-responder"),
                                        )
                                        .and_then(|m| m.encode())
                                        {
                                            Ok(bytes) => bytes,
                                            Err(_) => continue,
                                        }
                                    }
                                    _ => continue, // not a check: drop
                                },
                            };
                            let _ = socket.send_to(&response, peer);
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
                        Err(_) => return,
                    }
                }
            })
            .expect("spawn responder")
    }

    #[test]
    fn nominates_direct_against_live_responder() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("bind"));
        let addr = socket.local_addr().expect("addr");
        let stop = Arc::new(AtomicBool::new(false));
        let responder = stun_responder(socket.clone(), None, stop.clone());

        let mut config = AgentConfig::default();
        config.check = fast_check();
        let remote = [host_candidate(addr, 65_535)];
        let nomination = nominate(&config, &remote).expect("nomination");
        assert_eq!(nomination.path, PathKind::Direct);
        assert_eq!(nomination.pair.remote.transport_addr(), addr);
        // The winning check ran on the FIRST pair (host→host) with no
        // failed attempts before it.
        assert!(nomination.attempts.is_empty());
        // The responder observed the agent's host base as the source.
        let host_base = nomination.pair.local.transport_addr();
        assert_eq!(nomination.observed, host_base);
        assert!(!nomination.local_relay_used);

        stop.store(true, Ordering::SeqCst);
        responder.join().expect("responder");
    }

    /// A lying candidate: claims to be reachable, answers checks with
    /// garbage. The agent must record the typed failure and nominate
    /// NOTHING (fail-closed; no relay configured → AgentNoPath).
    #[test]
    fn lying_candidate_garbage_responses_fail_closed() {
        // A STUN-shaped response with a CORRUPTED magic cookie: it clears
        // the leading-bits and length checks, so the strict parse fails
        // exactly at the cookie (fail-closed with the typed error).
        let mut garbage = vec![0x00, 0x01, 0x00, 0x00];
        garbage.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // bad cookie
        garbage.extend_from_slice(&[0x42u8; 12]);
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("bind"));
        let addr = socket.local_addr().expect("addr");
        let stop = Arc::new(AtomicBool::new(false));
        let responder = stun_responder(socket.clone(), Some(garbage), stop.clone());

        let mut config = AgentConfig::default();
        config.check = fast_check();
        config.relay = None;
        let remote = [host_candidate(addr, 65_535)];
        let error = nominate(&config, &remote).expect_err("garbage must never nominate");
        match error {
            IceError::AgentNoPath { attempts } => {
                assert_eq!(attempts.len(), 1);
                assert!(matches!(
                    &attempts[0].outcome,
                    Err(IceError::StunBadMagicCookie { .. })
                ));
            }
            other => panic!("expected AgentNoPath, got {other:?}"),
        }

        stop.store(true, Ordering::SeqCst);
        responder.join().expect("responder");
    }

    /// A dead (closed-port) remote with no relay configured: the typed
    /// `AgentNoPath` names what was tried; the fallback never
    /// fabricates reachability (there was nothing to fall back TO).
    #[test]
    fn dead_remote_no_relay_reports_no_path() {
        let gone = UdpSocket::bind("127.0.0.1:0").expect("bind");
        let dead_addr = gone.local_addr().expect("addr");
        drop(gone); // the port is now closed: UDP to it is refused/black-holed

        let mut config = AgentConfig::default();
        config.check = fast_check();
        config.relay = None;
        let remote = [host_candidate(dead_addr, 65_535)];
        let error = nominate(&config, &remote).expect_err("no path");
        match error {
            IceError::AgentNoPath { attempts } => {
                assert_eq!(attempts.len(), 1);
                assert!(matches!(
                    &attempts[0].outcome,
                    Err(IceError::StunTimeout { .. })
                ));
            }
            other => panic!("expected AgentNoPath, got {other:?}"),
        }
    }

    /// A stalled (bound-but-silent) remote: the checks time out typed
    /// (the slow/stalled adversarial case), the agent survives.
    #[test]
    fn stalled_remote_times_out_typed() {
        let silent = UdpSocket::bind("127.0.0.1:0").expect("bind"); // never answers
        let silent_addr = silent.local_addr().expect("addr");

        let mut config = AgentConfig::default();
        config.check = fast_check();
        let remote = [host_candidate(silent_addr, 65_535)];
        let error = nominate(&config, &remote).expect_err("stalled");
        assert!(matches!(
            error,
            IceError::AgentNoPath {
                attempts: ref a
            } if matches!(&a[0].outcome, Err(IceError::StunTimeout { .. }))
        ));
    }
}
