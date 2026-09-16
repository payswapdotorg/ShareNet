//! The carrying layer seam: whole frames over any byte stream.
//!
//! R6-002's protocol is transport-agnostic by design (work item deps:
//! R6-001 manifests + R4-001 the tunnel it rides in): it runs INSIDE any
//! established byte-stream/tunnel and talks to it only through the small
//! [`TransferStream`] trait — shaped exactly like `transport/quic`'s
//! `TunnelStream::send_frame`/`recv_frame` so the tunnel adapter at
//! integration (R6-005/R10 wiring) is a one-impl bridge, and DTN carries
//! (R6-003) can drive it over any store-and-forward pipe.
//!
//! - [`LengthPrefixed`] adapts any `Read + Write` (a real TCP socket in
//!   the multiprocess evidence; any pipe) with the same u32 big-endian
//!   length prefix and 2 MiB-class frame cap discipline the QUIC tunnel
//!   enforces.
//! - [`DuplexPair`] is an in-memory pair (test vehicle + embedding seam,
//!   the "pipe-driven transport" of the work item).

use std::io::{Read, Write};

use sharenet_protocol::CONTENT_MAX_CHUNK_SIZE;

use crate::error::TransferError;

/// Maximum single frame this protocol will send or accept over a
/// length-prefixed carriage: one full-size chunk (`CONTENT_MAX_CHUNK_SIZE`,
/// the manifest's hard bound) plus header headroom.
///
/// When riding `transport/quic`'s `TunnelStream` (whose own `MAX_FRAME` is
/// exactly 2 MiB), the transfer frame must fit INSIDE one tunnel frame —
/// see the README's honest limits: pick `chunk_size <= MAX_FRAME - 16`
/// for tunnel carriage, or use the TCP/pipe adapters here.
pub const TRANSFER_MAX_FRAME: usize = CONTENT_MAX_CHUNK_SIZE as usize + 64;

/// The transport-agnostic carriage trait: send and receive WHOLE frames.
///
/// Implementors own framing, buffering and their own error surface —
/// this trait is the single seam between the transfer protocol and any
/// carrying layer (TCP socket, QUIC `TunnelStream`, a DTN pipe, an
/// in-memory duplex).
pub trait TransferStream {
    /// Send one whole frame (fail-closed on carriage errors).
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransferError>;
    /// Receive one whole frame. `Err(Closed)` on a clean peer EOF
    /// mid-session (the interrupted-transfer signal).
    fn recv_frame(&mut self) -> Result<Vec<u8>, TransferError>;
}

/// Sharing one carriage by exclusive reference (the session APIs take
/// `&mut S`; this lets callers pass `&mut` to a concrete stream).
impl<S: TransferStream + ?Sized> TransferStream for &mut S {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransferError> {
        (**self).send_frame(frame)
    }
    fn recv_frame(&mut self) -> Result<Vec<u8>, TransferError> {
        (**self).recv_frame()
    }
}

/// u32 big-endian length prefix + payload, capped at
/// [`TRANSFER_MAX_FRAME`] — the tunnel's framing discipline over any
/// `Read + Write`.
///
/// A length prefix larger than the cap fails closed with
/// `FrameTooLarge` BEFORE any allocation (the R4-001 adversarial
/// `0xFFFFFFFF` precedent).
#[derive(Debug)]
pub struct LengthPrefixed<T> {
    inner: T,
}

impl<T: Read + Write> LengthPrefixed<T> {
    pub fn new(inner: T) -> Self {
        LengthPrefixed { inner }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }

    pub fn get_ref(&self) -> &T {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    fn io_err(context: &'static str, e: std::io::Error) -> TransferError {
        match e.kind() {
            std::io::ErrorKind::UnexpectedEof => TransferError::Closed,
            _ => TransferError::Io {
                context,
                source: e.to_string(),
            },
        }
    }
}

impl<T: Read + Write> TransferStream for LengthPrefixed<T> {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransferError> {
        if frame.len() > TRANSFER_MAX_FRAME {
            return Err(TransferError::FrameTooLarge {
                found: frame.len(),
                max: TRANSFER_MAX_FRAME,
            });
        }
        let len = u32::try_from(frame.len()).expect("<= TRANSFER_MAX_FRAME <= u32::MAX");
        self.inner
            .write_all(&len.to_be_bytes())
            .and_then(|_| self.inner.write_all(frame))
            .and_then(|_| self.inner.flush())
            .map_err(|e| Self::io_err("send_frame", e))
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, TransferError> {
        let mut prefix = [0u8; 4];
        read_exact(&mut self.inner, &mut prefix).map_err(|e| Self::io_err("recv_frame", e))?;
        let len = u32::from_be_bytes(prefix) as usize;
        if len > TRANSFER_MAX_FRAME {
            return Err(TransferError::FrameTooLarge {
                found: len,
                max: TRANSFER_MAX_FRAME,
            });
        }
        let mut frame = vec![0u8; len];
        read_exact(&mut self.inner, &mut frame).map_err(|e| Self::io_err("recv_frame", e))?;
        Ok(frame)
    }
}

/// `read_exact` that maps any EOF (before or mid-frame) to
/// `UnexpectedEof` — the carrying stream died mid-session either way;
/// the receiver state persists and the transfer resumes.
fn read_exact<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "closed",
                ))
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// In-memory duplex (pipe-driven transport)
// ---------------------------------------------------------------------------

/// One end of an in-memory duplex TransferStream pair.
///
/// `send_frame` posts to the peer's inbox; `recv_frame` takes from the
/// own inbox. Dropping the other end surfaces as `Closed` on the next
/// receive — exactly the semantics a real socket has, without I/O:
/// deterministic, instant, and usable both by the unit suite and by
/// embedders driving the protocol over an in-process pipe.
#[derive(Debug)]
pub struct DuplexEnd {
    out: std::sync::mpsc::Sender<Vec<u8>>,
    inbox: std::sync::mpsc::Receiver<Vec<u8>>,
    /// Total frames SENT through this end (test assertion seam).
    pub sent_frames: std::cell::Cell<usize>,
    /// Total bytes SENT through this end (test assertion seam).
    pub sent_bytes: std::cell::Cell<usize>,
}

/// A connected pair of in-memory [`TransferStream`] ends.
pub struct DuplexPair {
    /// Hand to the sender role.
    pub a: DuplexEnd,
    /// Hand to the receiver role.
    pub b: DuplexEnd,
}

impl DuplexPair {
    pub fn new() -> Self {
        let (ta, ra) = std::sync::mpsc::channel();
        let (tb, rb) = std::sync::mpsc::channel();
        // ta: a sends -> b receives; tb: b sends -> a receives.
        DuplexPair {
            a: DuplexEnd {
                out: ta,
                inbox: rb,
                sent_frames: std::cell::Cell::new(0),
                sent_bytes: std::cell::Cell::new(0),
            },
            b: DuplexEnd {
                out: tb,
                inbox: ra,
                sent_frames: std::cell::Cell::new(0),
                sent_bytes: std::cell::Cell::new(0),
            },
        }
    }
}

impl TransferStream for DuplexEnd {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransferError> {
        self.out
            .send(frame.to_vec())
            .map_err(|_| TransferError::Closed)?;
        self.sent_frames.set(self.sent_frames.get() + 1);
        self.sent_bytes.set(self.sent_bytes.get() + frame.len());
        Ok(())
    }

    fn recv_frame(&mut self) -> Result<Vec<u8>, TransferError> {
        self.inbox.recv().map_err(|_| TransferError::Closed)
    }
}

/// A wrapping stream that RECORDS every frame sent through it (test
/// seam: capture the receiver's REQUEST rounds to prove exact resume
/// semantics). Receives pass through untouched.
#[derive(Debug)]
pub struct TappingStream<S> {
    inner: S,
    sent: std::sync::mpsc::Sender<Vec<u8>>,
}

impl<S: TransferStream> TappingStream<S> {
    pub fn new(inner: S) -> (Self, std::sync::mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = std::sync::mpsc::channel();
        (TappingStream { inner, sent: tx }, rx)
    }
}

impl<S: TransferStream> TransferStream for TappingStream<S> {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransferError> {
        let _ = self.sent.send(frame.to_vec());
        self.inner.send_frame(frame)
    }
    fn recv_frame(&mut self) -> Result<Vec<u8>, TransferError> {
        self.inner.recv_frame()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::hex;

    /// One half of a raw channel-backed `Read + Write` pipe: writes are
    /// posted to the peer's channel; reads drain the own channel in
    /// order (each `write` arrives as one chunk).
    struct ChannelIo {
        to_peer: std::sync::mpsc::Sender<Vec<u8>>,
        inbox: std::sync::mpsc::Receiver<Vec<u8>>,
        pending: Vec<u8>,
        pos: usize,
    }

    impl ChannelIo {
        /// A crosswired raw pipe pair.
        fn pair() -> (ChannelIo, ChannelIo) {
            let (ta, ra) = std::sync::mpsc::channel();
            let (tb, rb) = std::sync::mpsc::channel();
            (
                ChannelIo {
                    to_peer: ta,
                    inbox: rb,
                    pending: Vec::new(),
                    pos: 0,
                },
                ChannelIo {
                    to_peer: tb,
                    inbox: ra,
                    pending: Vec::new(),
                    pos: 0,
                },
            )
        }
    }

    impl Write for ChannelIo {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.to_peer
                .send(buf.to_vec())
                .map_err(|_| std::io::Error::other("peer gone"))?;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Read for ChannelIo {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.pos >= self.pending.len() {
                match self.inbox.recv_timeout(std::time::Duration::from_secs(5)) {
                    Ok(chunk) => {
                        self.pending = chunk;
                        self.pos = 0;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        return Err(std::io::Error::other("unit-test pipe timeout"))
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "closed",
                        ))
                    }
                }
            }
            let n = buf.len().min(self.pending.len() - self.pos);
            buf[..n].copy_from_slice(&self.pending[self.pos..self.pos + n]);
            self.pos += n;
            Ok(n)
        }
    }

    fn framed_pair() -> (
        LengthPrefixed<ChannelIo>,
        LengthPrefixed<ChannelIo>,
    ) {
        let (a, b) = ChannelIo::pair();
        (LengthPrefixed::new(a), LengthPrefixed::new(b))
    }

    #[test]
    fn length_prefixed_round_trip() {
        let (mut a, mut b) = framed_pair();
        for frame in [
            vec![1u8],
            vec![0u8; 100],
            b"hello sharenet".to_vec(),
            vec![0xffu8; 1000],
        ] {
            a.send_frame(&frame).expect("send");
            let got = b.recv_frame().expect("recv");
            assert_eq!(got, frame);
        }
        // Both directions.
        b.send_frame(&[3, 2, 1]).expect("b->a");
        assert_eq!(a.recv_frame().expect("a<-b"), vec![3, 2, 1]);
    }

    #[test]
    fn oversize_send_fails_closed() {
        let (mut a, _b) = framed_pair();
        let err = a.send_frame(&vec![0u8; TRANSFER_MAX_FRAME + 1]).unwrap_err();
        assert!(matches!(err, TransferError::FrameTooLarge { .. }));
        assert_eq!(err.name(), "frame_too_large");
    }

    #[test]
    fn adversarial_length_prefix_ffffffff_fails_closed() {
        // A forged 0xFFFFFFFF length prefix: rejected BEFORE any
        // allocation, exactly like the R4-001 tunnel.
        let (mut raw_a, mut b) = framed_pair();
        // Inject the raw oversized prefix straight into the pipe.
        raw_a
            .get_mut()
            .write_all(&0xFFFFFFFFu32.to_be_bytes())
            .expect("raw write");
        drop(raw_a); // sender side goes away afterwards
        let err = b.recv_frame().unwrap_err();
        assert!(
            matches!(err, TransferError::FrameTooLarge { found, .. } if found == 0xFFFF_FFFF),
            "expected frame_too_large, got {err:?}"
        );
    }

    #[test]
    fn exact_cap_frame_passes() {
        let (mut a, mut b) = framed_pair();
        let frame = vec![7u8; TRANSFER_MAX_FRAME];
        a.send_frame(&frame).expect("exactly at cap is legal");
        assert_eq!(b.recv_frame().expect("recv"), frame);
    }

    #[test]
    fn peer_eof_surfaces_as_closed() {
        let (a, mut b) = framed_pair();
        drop(a); // sender vanishes mid-session
        let err = b.recv_frame().unwrap_err();
        assert_eq!(err, TransferError::Closed);
        assert_eq!(err.name(), "closed");
    }

    #[test]
    fn mid_frame_truncation_surfaces_as_closed() {
        let (mut a, mut b) = framed_pair();
        // A frame claiming 16 bytes that never fully arrives.
        raw_send(a.get_mut(), &16u32.to_be_bytes());
        raw_send(a.get_mut(), &[0xAA; 3]); // only 3 of 16
        drop(a);
        let err = b.recv_frame().unwrap_err();
        assert_eq!(err, TransferError::Closed);
    }

    #[test]
    fn duplex_pair_round_trip_and_close_semantics() {
        let DuplexPair { mut a, mut b } = DuplexPair::new();
        a.send_frame(&[0x01, 0x02]).expect("a->b");
        assert_eq!(b.recv_frame().expect("b<-a"), vec![0x01, 0x02]);
        b.send_frame(&[0x03]).expect("b->a");
        assert_eq!(a.recv_frame().expect("a<-b"), vec![0x03]);
        assert_eq!(a.sent_frames.get(), 1);
        assert_eq!(a.sent_bytes.get(), 2);
        assert_eq!(b.sent_frames.get(), 1);
        drop(b);
        assert_eq!(a.recv_frame().unwrap_err(), TransferError::Closed);
    }

    #[test]
    fn tapping_stream_records_sent_frames_only() {
        let DuplexPair { mut a, mut b } = DuplexPair::new();
        let (mut tap_a, tap_rx) = TappingStream::new(&mut a);
        tap_a.send_frame(&[9, 9]).expect("send via tap");
        assert_eq!(b.recv_frame().expect("peer got it"), vec![9, 9]);
        b.send_frame(&[1]).expect("b->a");
        assert_eq!(tap_a.recv_frame().expect("passthrough recv"), vec![1]);
        let sent = tap_rx.try_recv().expect("recorded");
        assert_eq!(sent, vec![9, 9]);
        assert!(tap_rx.try_recv().is_err(), "received frames are not recorded");
    }

    #[test]
    fn max_frame_covers_a_full_chunk_plus_headers() {
        // A full-size chunk + the largest message headers must fit.
        assert!(TRANSFER_MAX_FRAME >= CONTENT_MAX_CHUNK_SIZE as usize + 8);
        assert_eq!(hex(&[0xde, 0xad]), "dead"); // evidence-line helper sanity
    }

    fn raw_send(w: &mut impl Write, bytes: &[u8]) {
        w.write_all(bytes).expect("raw write");
    }
}
