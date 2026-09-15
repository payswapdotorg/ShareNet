//! Active RTT prober (R2-004): ping/pong over a real transport.
//!
//! Sends K probe frames to a peer, correlates the returning frames by a
//! 64-bit correlation id, measures round trips with the LOCAL monotonic
//! clock, and records a [`LinkQualitySample`] per probe — the raw evidence
//! the reliability model (`spec/architecture.md` §2) will consume for
//! routing (R3-003) and admission (R5-005). **Measurement only**: no routing
//! decisions, no policy, no admission logic live here.
//!
//! ## Probe frame (documented wire format — transport-internal, NOT a
//! registered protocol wire object)
//!
//! ```text
//! probe payload :=
//!   0..2   magic        [0x53, 0x4E]  ("SN")
//!   2      kind         u8  (1 = ping, 2 = pong)
//!   3..11  correlation  u64be
//!   11..19 seq          u64be
//!   19..   zero padding to the configured payload size
//! ```
//!
//! The frame rides as the PAYLOAD of the underlying transport's own framing
//! (the Wave 1 length-prefixed UDP frames on Linux, `u64be channelId`
//! envelope on Android) — the prober reuses the transport's frame codec via
//! [`FrameTransport`]; it does not add a second framing layer.
//!
//! A **pong** is any frame from the measured peer whose magic matches and
//! whose correlation id equals the outstanding ping's. The kind byte may be
//! `PING` (a byte-identical echo — the reference responder is the generic
//! `sharenet_transport_linux echo` server) or `PONG` (a dedicated responder
//! rewriting the kind). Anything else is a *foreign* frame: counted, ignored.
//!
//! ## Algorithm (documented)
//!
//! Stop-and-wait: exactly ONE outstanding probe at a time (the correct shape
//! for RTT measurement — no pipelining ambiguity). Per probe:
//!
//! 1. correlation id = `session_base + seq` (session-scoped, unique per
//!    probe within a run; `session_base` is unix-nanoseconds at prober
//!    construction, so pongs from a previous run cannot match);
//! 2. send the ping; the monotonic send timestamp opens the measurement;
//! 3. await a matching pong until the per-attempt deadline (transport
//!    read-timeout driven); foreign frames, frames from other addresses,
//!    malformed frames and non-timeout receive errors are counted and do NOT
//!    abort the attempt;
//! 4. on match: RTT = monotonic now − send timestamp (same clock ⇒ negative
//!    values are unrepresentable; cross-host skew cannot enter), record a
//!    delivered sample;
//! 5. on deadline: re-send the SAME correlation id up to `retries` more
//!    times; when the budget is exhausted record a `lost` sample and
//!    CONTINUE with the next probe (K consecutive losses never abort the
//!    run — a dead peer is measured as loss, not raised as an error);
//! 6. pace probes on a fixed cadence from run start (drift-free).
//!
//! Duplicate/late pongs (a pong whose correlation id was issued EARLIER in
//! this session) are counted as `late_pongs` and ignored — the probe they
//! belonged to has already been recorded. A late pong for the CURRENT
//! outstanding probe that arrives after a retry re-send simply matches the
//! outstanding probe (retries reuse the correlation id).
//!
//! ## Persistence
//!
//! None. A run's evidence lives in the in-memory [`LinkQualityStream`];
//! durable evidence capture is R8-001 scope.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::{Result, TelemetryError};
use crate::sample::{LinkQualitySample, LinkQualityStream, SharedLinkQualityStream};

/// Probe frame magic bytes: ASCII "SN".
pub const PROBE_MAGIC: [u8; 2] = [0x53, 0x4E];
/// Kind byte: a probe request (echoed byte-identically by the reference
/// responder).
pub const PROBE_KIND_PING: u8 = 1;
/// Kind byte: a probe response (dedicated responders may rewrite the kind).
pub const PROBE_KIND_PONG: u8 = 2;
/// Probe frame header size: magic(2) + kind(1) + correlation(8) + seq(8).
pub const PROBE_HEADER_LEN: usize = 19;
/// Default probe frame payload size (header + zero padding).
pub const DEFAULT_PROBE_PAYLOAD_BYTES: usize = 64;
/// Default per-attempt pong timeout.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(250);
/// Default extra attempts after the first send (0 = one shot per probe; a
/// re-sent probe measures retransmission behavior, not clean loss).
pub const DEFAULT_PROBE_RETRIES: u32 = 0;
/// Default pacing between probe starts.
pub const DEFAULT_PROBE_INTERVAL: Duration = Duration::from_millis(10);

/// The transport seam the prober drives (implemented for the Wave 1
/// `UdpTransport` by the `sharenet-transport-linux` crate — see its
/// `telemetry_bridge` module; see the README "Dependency direction" for why
/// the impl lives there).
///
/// The trait mirrors exactly the Wave 1 transport surface the prober needs:
/// framed send, framed receive with a peer address, a read timeout, and the
/// transport's maximum payload. Everything else about the transport stays
/// behind the seam.
pub trait FrameTransport {
    /// Maximum frame payload this transport accepts (used to validate the
    /// probe payload size at run start).
    fn max_payload(&self) -> usize;

    /// Send one frame payload to `peer`.
    ///
    /// # Errors
    /// Typed telemetry errors: [`TelemetryError::SendFailed`] on failure,
    /// [`TelemetryError::TransportClosed`] when the transport is closed.
    fn send_frame(&mut self, peer: SocketAddr, payload: &[u8]) -> Result<()>;

    /// Receive one frame payload into `buf`; returns `(bytes, peer)` on
    /// success.
    ///
    /// Contract (mirrors the Wave 1 `UdpTransport` semantics):
    /// * nothing available now (non-blocking mode or read-timeout expiry)
    ///   → [`TelemetryError::TransportWouldBlock`]; the prober treats this as
    ///   "nothing yet" and re-checks its own deadline;
    ///
    /// # Errors
    /// [`TelemetryError::TransportWouldBlock`] when the timeout expired;
    /// [`TelemetryError::TransportClosed`] when closed; malformed/oversized
    /// datagrams surface as other typed errors (the prober counts them and
    /// keeps waiting — no panic).
    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;

    /// Set the receive timeout. `None` blocks forever (the prober always
    /// sets a finite timeout before receiving).
    ///
    /// # Errors
    /// [`TelemetryError::TimeoutSetup`] on failure.
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<()>;
}

/// A decoded probe frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeFrame {
    pub kind: u8,
    pub correlation_id: u64,
    pub seq: u64,
}

/// Why a received frame is not a usable pong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeDecode {
    /// A well-formed probe frame.
    Probe(ProbeFrame),
    /// Not a probe frame at all (different magic) — foreign traffic.
    NotAProbe,
    /// Claims to be a probe frame but is malformed (too short, bad kind).
    Malformed,
}

/// Encode a ping into `out` (cleared first), zero-padded to `payload_bytes`.
///
/// # Errors
/// [`TelemetryError::InvalidConfig`] when `payload_bytes < PROBE_HEADER_LEN`.
pub fn encode_ping(out: &mut Vec<u8>, correlation_id: u64, seq: u64, payload_bytes: usize) -> Result<()> {
    encode_probe(out, PROBE_KIND_PING, correlation_id, seq, payload_bytes)
}

/// Encode a pong into `out` (dedicated responders only; the prober itself
/// never sends pongs).
///
/// # Errors
/// [`TelemetryError::InvalidConfig`] when `payload_bytes < PROBE_HEADER_LEN`.
pub fn encode_pong(out: &mut Vec<u8>, correlation_id: u64, seq: u64, payload_bytes: usize) -> Result<()> {
    encode_probe(out, PROBE_KIND_PONG, correlation_id, seq, payload_bytes)
}

fn encode_probe(
    out: &mut Vec<u8>,
    kind: u8,
    correlation_id: u64,
    seq: u64,
    payload_bytes: usize,
) -> Result<()> {
    if payload_bytes < PROBE_HEADER_LEN {
        return Err(TelemetryError::InvalidConfig {
            detail: format!("payload_bytes {payload_bytes} < probe header {PROBE_HEADER_LEN}"),
        });
    }
    out.clear();
    out.reserve(payload_bytes);
    out.extend_from_slice(&PROBE_MAGIC);
    out.push(kind);
    out.extend_from_slice(&correlation_id.to_be_bytes());
    out.extend_from_slice(&seq.to_be_bytes());
    out.resize(payload_bytes, 0);
    Ok(())
}

/// Decode a received frame payload as a probe frame (never panics on
/// garbage input).
pub fn decode_probe(payload: &[u8]) -> ProbeDecode {
    if payload.len() < 2 || payload[..2] != PROBE_MAGIC {
        return ProbeDecode::NotAProbe;
    }
    if payload.len() < PROBE_HEADER_LEN {
        return ProbeDecode::Malformed;
    }
    let kind = payload[2];
    if kind != PROBE_KIND_PING && kind != PROBE_KIND_PONG {
        return ProbeDecode::Malformed;
    }
    let correlation_id = u64::from_be_bytes(payload[3..11].try_into().expect("8 bytes"));
    let seq = u64::from_be_bytes(payload[11..19].try_into().expect("8 bytes"));
    ProbeDecode::Probe(ProbeFrame { kind, correlation_id, seq })
}

/// Configuration for one probe run.
#[derive(Debug, Clone)]
pub struct ProbeConfig {
    /// Number of probes (K).
    pub count: u64,
    /// Fixed cadence between probe starts.
    pub interval: Duration,
    /// Per-attempt pong timeout.
    pub timeout: Duration,
    /// Extra attempts (re-sends with the same correlation id) after the
    /// first send fails to produce a pong.
    pub retries: u32,
    /// Probe frame payload size in bytes (header + zero padding).
    pub payload_bytes: usize,
    /// Adapter-level channel id stamped on samples (`0` on channel-less raw
    /// transports).
    pub channel_id: u64,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        ProbeConfig {
            count: 10,
            interval: DEFAULT_PROBE_INTERVAL,
            timeout: DEFAULT_PROBE_TIMEOUT,
            retries: DEFAULT_PROBE_RETRIES,
            payload_bytes: DEFAULT_PROBE_PAYLOAD_BYTES,
            channel_id: 0,
        }
    }
}

impl ProbeConfig {
    fn validate(&self, max_payload: usize) -> Result<()> {
        if self.count == 0 {
            return Err(TelemetryError::InvalidConfig { detail: "count must be > 0".into() });
        }
        if self.timeout.is_zero() {
            return Err(TelemetryError::InvalidConfig { detail: "timeout must be > 0".into() });
        }
        if self.payload_bytes < PROBE_HEADER_LEN {
            return Err(TelemetryError::InvalidConfig {
                detail: format!("payload_bytes {} < probe header {PROBE_HEADER_LEN}", self.payload_bytes),
            });
        }
        if self.payload_bytes > max_payload {
            return Err(TelemetryError::InvalidConfig {
                detail: format!("payload_bytes {} > transport max payload {max_payload}", self.payload_bytes),
            });
        }
        Ok(())
    }
}

/// Result of a completed probe run.
#[derive(Debug)]
pub struct ProbeRun {
    /// The run's session base (correlation ids are `session_base + seq`).
    pub session_id: u64,
    /// Probes that got a pong.
    pub delivered: u64,
    /// Probes that exhausted their retry budget.
    pub lost: u64,
    /// Pongs for correlation ids issued EARLIER in this session (duplicates
    /// arriving after their probe completed). Counted, ignored.
    pub late_pongs: u64,
    /// Frames from other addresses, non-probe frames, malformed probe
    /// frames, and frames with unknown correlation ids. Counted, ignored.
    pub foreign_frames: u64,
    /// Non-timeout, non-closed receive errors (malformed datagrams at the
    /// transport level, oversized frames, ...). Counted; never abort the run.
    pub recv_errors: u64,
    /// Wall-clock run duration.
    pub wall_time: Duration,
    /// The evidence stream filled by the run (shared handle: the same one
    /// `Prober::stream` exposes, so live observers saw the samples too).
    pub stream: SharedLinkQualityStream,
}

impl ProbeRun {
    /// Summarize the run's evidence (see [`crate::stats::summarize`]).
    ///
    /// # Errors
    /// [`TelemetryError::EmptyWindow`] / [`TelemetryError::ClockSkew`] per
    /// the stats layer.
    pub fn summary(&self) -> Result<crate::stats::LinkQualitySummary> {
        self.stream.summarize()
    }
}

/// Stop-and-wait active prober over a [`FrameTransport`].
///
/// One run per prober (a `Prober` is consumed by [`run`](Prober::run));
/// construct a fresh one for the next measurement.
pub struct Prober<T: FrameTransport> {
    transport: Option<T>,
    peer: SocketAddr,
    config: ProbeConfig,
    session_base: u64,
    stream: SharedLinkQualityStream,
    finished: bool,
}

impl<T: FrameTransport> std::fmt::Debug for Prober<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prober")
            .field("peer", &self.peer)
            .field("config", &self.config)
            .field("session_base", &self.session_base)
            .field("stream_len", &self.stream.len())
            .field("finished", &self.finished)
            .finish()
    }
}

impl<T: FrameTransport> Prober<T> {
    /// Build a prober against `peer`. The evidence stream is created with
    /// capacity `config.count` (one sample per probe, no eviction within a
    /// normal run) and is observable LIVE via [`stream`](Prober::stream)
    /// while the run executes.
    ///
    /// # Errors
    /// [`TelemetryError::InvalidConfig`] when the configuration is unusable
    /// (validated against the transport's `max_payload`).
    pub fn new(transport: T, peer: SocketAddr, config: ProbeConfig) -> Result<Prober<T>> {
        let max_payload = transport.max_payload();
        config.validate(max_payload)?;
        let session_base = unix_nanos_now();
        let stream = Arc::new(LinkQualityStream::new(config.count.max(1) as usize)?);
        Ok(Prober {
            transport: Some(transport),
            peer,
            config,
            session_base,
            stream,
            finished: false,
        })
    }

    /// The run's session id (correlation base).
    pub fn session_id(&self) -> u64 {
        self.session_base
    }

    /// Live evidence stream handle (safe to read from another thread while
    /// the run is in flight).
    pub fn stream(&self) -> SharedLinkQualityStream {
        Arc::clone(&self.stream)
    }

    /// Execute the probe run. Blocks for at most
    /// `count * interval + count * (retries + 1) * timeout` (the pacing and
    /// per-attempt deadlines bound it).
    ///
    /// # Errors
    /// * [`TelemetryError::ProberFinished`] on reuse;
    /// * [`TelemetryError::SendFailed`] / [`TelemetryError::TransportClosed`]
    ///   when the send path dies (without sends there is nothing to measure —
    ///   this is the only abort class besides a closed transport);
    /// * [`TelemetryError::TimeoutSetup`] when read-timeout control is lost.
    pub fn run(&mut self) -> Result<ProbeRun> {
        if self.finished {
            return Err(TelemetryError::ProberFinished);
        }
        self.finished = true;
        let mut transport = self.transport.take().expect("run consumes the transport");
        let cfg = self.config.clone();

        let started = Instant::now();
        let mut run = ProbeRun {
            session_id: self.session_base,
            delivered: 0,
            lost: 0,
            late_pongs: 0,
            foreign_frames: 0,
            recv_errors: 0,
            wall_time: Duration::ZERO,
            stream: Arc::clone(&self.stream),
        };

        // Fixed-cadence scheduling from run start (no per-probe drift).
        let mut next_send_at = Instant::now();
        let mut wire = Vec::with_capacity(cfg.payload_bytes);
        let mut recv_buf = vec![0u8; 4 + cfg.payload_bytes.max(64)];

        for seq in 0..cfg.count {
            let correlation_id = self.session_base.wrapping_add(seq);
            let sent_at_unix = unix_nanos_now();

            let mut delivered_rtt: Option<Duration> = None;
            'attempts: for _attempt in 0..=cfg.retries {
                let send_mono = Instant::now();
                encode_ping(&mut wire, correlation_id, seq, cfg.payload_bytes)?;
                transport.send_frame(self.peer, &wire).map_err(|e| {
                    run.wall_time = started.elapsed();
                    e
                })?;

                let deadline = send_mono + cfg.timeout;
                loop {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero() {
                        break; // attempt timed out
                    }
                    // Never hand the socket a zero timeout: std treats
                    // Duration::ZERO as "no timeout" (block forever). Clamp
                    // sub-microsecond remainders up to 1us — the deadline
                    // check above still ends the attempt.
                    let wait = remaining.max(Duration::from_micros(1));
                    transport.set_read_timeout(Some(wait))?;
                    match transport.recv_frame(&mut recv_buf) {
                        Ok((n, from)) => {
                            if from != self.peer {
                                run.foreign_frames += 1;
                                continue;
                            }
                            match decode_probe(&recv_buf[..n]) {
                                ProbeDecode::Probe(pf)
                                    if pf.correlation_id == correlation_id
                                        && pf.seq == seq =>
                                {
                                    let rtt = send_mono.elapsed();
                                    delivered_rtt = Some(rtt);
                                    break 'attempts;
                                }
                                ProbeDecode::Probe(pf) => {
                                    // Not the outstanding probe: either an
                                    // earlier correlation id of this session
                                    // (late/duplicate pong) or an unknown id.
                                    let issued_earlier = pf.correlation_id
                                        .wrapping_sub(self.session_base)
                                        < seq;
                                    if issued_earlier {
                                        run.late_pongs += 1;
                                    } else {
                                        run.foreign_frames += 1;
                                    }
                                }
                                ProbeDecode::NotAProbe | ProbeDecode::Malformed => {
                                    run.foreign_frames += 1;
                                }
                            }
                        }
                        Err(TelemetryError::TransportWouldBlock) => {
                            // Timeout expired mid-wait (or nothing yet):
                            // the deadline check above ends the attempt.
                            if Instant::now() >= deadline {
                                break;
                            }
                        }
                        Err(TelemetryError::TransportClosed) => {
                            run.wall_time = started.elapsed();
                            return Err(TelemetryError::TransportClosed);
                        }
                        Err(_) => {
                            // Malformed/oversized datagram or transient
                            // receive failure: counted, never fatal, never a
                            // panic — keep waiting until the deadline.
                            run.recv_errors += 1;
                        }
                    }
                }
            }

            let sample = match delivered_rtt {
                Some(rtt) => {
                    run.delivered += 1;
                    LinkQualitySample::delivered(
                        cfg.channel_id,
                        seq,
                        sent_at_unix,
                        rtt.as_micros() as u64,
                        cfg.payload_bytes as u32,
                    )
                }
                None => {
                    run.lost += 1;
                    LinkQualitySample::lost(cfg.channel_id, seq, sent_at_unix, cfg.payload_bytes as u32)
                }
            };
            self.stream.push(sample);

            // Pace: wait for the next cadence tick if this probe finished early.
            next_send_at += cfg.interval;
            let now = Instant::now();
            if next_send_at > now {
                std::thread::sleep(next_send_at - now);
            }
        }

        run.wall_time = started.elapsed();
        Ok(run)
    }
}

fn unix_nanos_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_encoding_roundtrip_and_padding() {
        let mut wire = Vec::new();
        encode_ping(&mut wire, 0xAABBCCDDEEFF0011, 7, 64).unwrap();
        assert_eq!(wire.len(), 64);
        assert_eq!(&wire[..2], &PROBE_MAGIC);
        assert_eq!(wire[2], PROBE_KIND_PING);
        assert_eq!(u64::from_be_bytes(wire[3..11].try_into().unwrap()), 0xAABBCCDDEEFF0011);
        assert_eq!(u64::from_be_bytes(wire[11..19].try_into().unwrap()), 7);
        assert!(wire[19..].iter().all(|&b| b == 0), "padding must be zeros");
        match decode_probe(&wire) {
            ProbeDecode::Probe(pf) => {
                assert_eq!(pf.kind, PROBE_KIND_PING);
                assert_eq!(pf.correlation_id, 0xAABBCCDDEEFF0011);
                assert_eq!(pf.seq, 7);
            }
            other => panic!("expected probe, got {other:?}"),
        }
    }

    #[test]
    fn decode_garbage_never_panics() {
        assert_eq!(decode_probe(&[]), ProbeDecode::NotAProbe);
        assert_eq!(decode_probe(&[0x00]), ProbeDecode::NotAProbe);
        assert_eq!(decode_probe(b"XX-payload"), ProbeDecode::NotAProbe);
        // Magic but truncated header.
        assert_eq!(decode_probe(&[PROBE_MAGIC[0], PROBE_MAGIC[1], 1, 4]), ProbeDecode::Malformed);
        // Magic, full length, but an unknown kind byte.
        let mut wire = Vec::new();
        let mut v = Vec::new();
        encode_ping(&mut v, 1, 2, PROBE_HEADER_LEN).unwrap();
        wire.extend_from_slice(&v[..19]);
        wire[2] = 9;
        assert_eq!(decode_probe(&wire), ProbeDecode::Malformed);
    }

    #[test]
    fn encode_rejects_payload_below_header() {
        let mut out = Vec::new();
        assert!(matches!(
            encode_ping(&mut out, 1, 2, PROBE_HEADER_LEN - 1),
            Err(TelemetryError::InvalidConfig { .. })
        ));
    }

    #[test]
    fn config_validation_rejects_zero_count_and_timeout_and_oversized_payload() {
        let mut cfg = ProbeConfig::default();
        cfg.count = 0;
        assert!(matches!(cfg.validate(65_500), Err(TelemetryError::InvalidConfig { .. })));

        let mut cfg = ProbeConfig::default();
        cfg.timeout = Duration::ZERO;
        assert!(matches!(cfg.validate(65_500), Err(TelemetryError::InvalidConfig { .. })));

        let mut cfg = ProbeConfig::default();
        cfg.payload_bytes = 65_501;
        assert!(matches!(cfg.validate(65_500), Err(TelemetryError::InvalidConfig { .. })));

        assert!(ProbeConfig::default().validate(65_500).is_ok());
    }
}
