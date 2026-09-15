//! Bridge: the telemetry prober over the real [`UdpTransport`] (R2-004).
//!
//! Implements the [`FrameTransport`](sharenet_transport_telemetry::probe::FrameTransport)
//! seam (defined in the `sharenet-transport-telemetry` crate) for this
//! crate's [`UdpTransport`], and offers convenience constructors so callers
//! get a working prober in one call.
//!
//! ## Why the impl lives HERE (dependency direction, documented)
//!
//! Cargo forbids cyclic package dependencies. The telemetry crate must stay
//! independent of this crate (the `sharenet_transport_linux` binary — the
//! production `probe-rtt` caller — depends on the telemetry crate), so the
//! prober is generic over `FrameTransport` and the concrete implementation
//! for `UdpTransport` lives in THIS crate, which owns the type (orphan
//! rule). The telemetry crate dev-depends on this crate so its tests run
//! the prober over the REAL transport — the same dev-cycle shape as
//! serde/serde_json.
//!
//! Every method goes through the REAL Wave 1 transport code paths: sends
//! use the length-prefixing frame encoder, receives use the strict
//! one-frame-per-datagram decoder with `MSG_TRUNC` detection, and
//! `WouldBlock` classification (`EAGAIN` from `SO_RCVTIMEO` expiry) matches
//! the prober's "nothing yet" contract. No transport behavior is
//! re-implemented here.

use std::net::SocketAddr;
use std::time::Duration;

use sharenet_transport_telemetry::probe::{FrameTransport, ProbeConfig, Prober};
use sharenet_transport_telemetry::{Result, TelemetryError};

use crate::udp::{UdpError, UdpTransport, MAX_FRAME_PAYLOAD};

impl FrameTransport for UdpTransport {
    fn max_payload(&self) -> usize {
        MAX_FRAME_PAYLOAD
    }

    fn send_frame(&mut self, peer: SocketAddr, payload: &[u8]) -> Result<()> {
        UdpTransport::send_frame_to(self, peer, payload).map_err(|e| match e {
            UdpError::Closed => TelemetryError::TransportClosed,
            other => TelemetryError::SendFailed {
                peer: peer.to_string(),
                detail: other.to_string(),
            },
        })
    }

    fn recv_frame(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        match UdpTransport::recv_frame_from(self, buf) {
            Ok((frame, peer)) => {
                let n = frame.payload.len();
                if n > buf.len() {
                    // Cannot happen (buf is sized for the whole frame by the
                    // caller), but a copy that overflows would be a bug, not
                    // a panic.
                    return Err(TelemetryError::RecvFailed {
                        detail: format!("frame payload {n} exceeds receive buffer {}", buf.len()),
                    });
                }
                buf[..n].copy_from_slice(&frame.payload);
                Ok((n, peer))
            }
            Err(UdpError::Closed) => Err(TelemetryError::TransportClosed),
            Err(UdpError::WouldBlock) => Err(TelemetryError::TransportWouldBlock),
            Err(other) => Err(TelemetryError::RecvFailed { detail: other.to_string() }),
        }
    }

    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> Result<()> {
        UdpTransport::set_read_timeout(self, timeout).map_err(|e| match e {
            UdpError::Closed => TelemetryError::TransportClosed,
            other => TelemetryError::TimeoutSetup { detail: other.to_string() },
        })
    }
}

/// Bind a local UDP transport and build a prober against `peer` in one call
/// (the production path used by the `probe-rtt` subcommand and available to
/// the future sharenetd daemon / R3-003 topology evidence layer).
///
/// # Errors
/// Propagates the bind error and the prober's config validation.
pub fn udp_prober(peer: SocketAddr, config: ProbeConfig) -> Result<Prober<UdpTransport>> {
    let local = SocketAddr::from(([127, 0, 0, 1], 0));
    let transport = UdpTransport::bind(&local).map_err(|e| TelemetryError::RecvFailed {
        detail: format!("bind for prober failed: {e}"),
    })?;
    Prober::new(transport, peer, config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sharenet_transport_telemetry::stats::summarize;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    /// Real loopback sockets: two in-process UdpTransports; the "responder"
    /// echoes probe frames back — real syscalls, no fakes.
    #[test]
    fn bridge_round_trip_over_real_loopback_sockets() {
        let mut responder = UdpTransport::bind(&SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let peer_addr = responder.local_addr();

        let mut cfg = ProbeConfig::default();
        cfg.count = 5;
        cfg.interval = Duration::from_millis(1);
        cfg.timeout = Duration::from_millis(500);

        let mut prober = udp_prober(peer_addr, cfg).unwrap();
        let stream = prober.stream();

        // Responder thread: echo each well-formed frame back to its sender.
        let stop = Arc::new(AtomicBool::new(false));
        let stop_flag = Arc::clone(&stop);
        let responder_thread = std::thread::spawn(move || {
            let mut buf = vec![0u8; 4 + MAX_FRAME_PAYLOAD];
            responder.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
            while !stop_flag.load(Ordering::Relaxed) {
                if let Ok((frame, from)) = responder.recv_frame_from(&mut buf) {
                    let _ = responder.send_frame_to(from, &frame.payload);
                }
            }
        });

        let started = Instant::now();
        let run = prober.run().unwrap();
        stop.store(true, Ordering::Relaxed);
        responder_thread.join().unwrap();

        assert_eq!(run.delivered, 5, "loopback echo must deliver all probes");
        assert_eq!(run.lost, 0);
        let summary = summarize(&stream.snapshot()).unwrap();
        assert_eq!(summary.delivered, 5);
        assert!(summary.ewma_rtt_micros > 0, "real loopback RTT must be measurable");
        assert!(summary.ewma_rtt_micros < 100_000, "loopback RTT must be sane (<100ms), got {}", summary.ewma_rtt_micros);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn bridge_reports_wouldblock_on_timeout() {
        // No responder: a receive with a short timeout must surface
        // TransportWouldBlock (the prober's "nothing yet" signal).
        let mut t = UdpTransport::bind(&SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        t.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
        let mut buf = [0u8; 128];
        let err = t.recv_frame(&mut buf).unwrap_err();
        assert!(matches!(err, TelemetryError::TransportWouldBlock));
    }

    #[test]
    fn bridge_reports_closed_transport() {
        let mut t = UdpTransport::bind(&SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        t.close();
        let mut buf = [0u8; 128];
        assert!(matches!(t.recv_frame(&mut buf), Err(TelemetryError::TransportClosed)));
        assert!(matches!(
            t.send_frame(SocketAddr::from(([127, 0, 0, 1], 9)), b"x"),
            Err(TelemetryError::TransportClosed)
        ));
    }
}
