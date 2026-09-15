//! Link quality samples and the bounded evidence stream (R2-004).
//!
//! [`LinkQualitySample`] is the raw evidence unit the architecture's
//! reliability model (`spec/architecture.md` §2 — "observed throughput, packet
//! loss and RTT") will consume for routing in R3-003+. [`LinkQualityStream`]
//! is the bounded, thread-safe window that collects them.
//!
//! **Transport-internal, NOT a wire object.** These types are the telemetry
//! layer's own vocabulary. They are deliberately NOT registered in
//! `spec/protocol-registry.yaml` and carry no ShareNet protocol meaning — no
//! identity, no routing, no admission. `channel_id` is the *adapter-level
//! envelope channel* id from Wave 1 (the `u64` channelId of the Android
//! `TransportFrame` envelope; `0` on a raw UDP transport, which has no
//! channels). See the crate README.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::error::{Result, TelemetryError};
use crate::stats::{self, LinkQualitySummary};

/// One link quality observation for one probe attempt.
///
/// Plain data: a `lost` sample records that a probe attempt produced no pong
/// within the configured retries (`rtt_micros` is then `0` by construction and
/// is excluded from all RTT statistics); a delivered sample records the
/// measured round trip.
///
/// RTT is measured with a LOCAL monotonic clock (send timestamp vs receive
/// timestamp on the same host), so a negative RTT is unrepresentable (`u64`)
/// and cross-host clock skew cannot enter the measurement. `rtt_micros == 0`
/// on a DELIVERED sample is treated as clock-skew evidence and rejected by
/// [`stats::summarize`] with [`TelemetryError::ClockSkew`] — never clamped.
///
/// `sent_at_unix_nanos` is the wall-clock send time, for cross-referencing
/// with logs only; it is NEVER used in RTT arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkQualitySample {
    /// Adapter-level envelope channel id (Wave 1 framing). `0` = the default
    /// channel of a channel-less raw transport.
    pub channel_id: u64,
    /// Probe sequence number within a probe run (0-based, strictly
    /// increasing per run).
    pub seq: u64,
    /// Wall-clock send time (unix epoch, nanoseconds) — bookkeeping only.
    pub sent_at_unix_nanos: u64,
    /// Measured round trip in microseconds (valid iff `lost == false`).
    pub rtt_micros: u64,
    /// Probe frame payload size in bytes.
    pub payload_bytes: u32,
    /// `true` when no pong arrived within `1 + retries` attempts.
    pub lost: bool,
}

impl LinkQualitySample {
    /// A delivered sample.
    pub fn delivered(
        channel_id: u64,
        seq: u64,
        sent_at_unix_nanos: u64,
        rtt_micros: u64,
        payload_bytes: u32,
    ) -> LinkQualitySample {
        LinkQualitySample {
            channel_id,
            seq,
            sent_at_unix_nanos,
            rtt_micros,
            payload_bytes,
            lost: false,
        }
    }

    /// A lost sample (no pong within the retry budget).
    pub fn lost(
        channel_id: u64,
        seq: u64,
        sent_at_unix_nanos: u64,
        payload_bytes: u32,
    ) -> LinkQualitySample {
        LinkQualitySample {
            channel_id,
            seq,
            sent_at_unix_nanos,
            rtt_micros: 0,
            payload_bytes,
            lost: true,
        }
    }

    /// Whether this sample carries a usable RTT measurement.
    pub fn has_rtt(&self) -> bool {
        !self.lost
    }
}

/// Bounded, thread-safe window of [`LinkQualitySample`]s.
///
/// ## Overflow policy (documented)
///
/// **Drop-oldest.** When the window is full, pushing a new sample evicts the
/// OLDEST sample. Rationale: routing decisions want *current* link
/// conditions; drop-newest would freeze stale evidence in the window. (Both
/// behaviors are tested: capacity is never exceeded and the oldest samples
/// are exactly the ones evicted.)
///
/// ## Concurrency (documented)
///
/// `Mutex<VecDeque>` — simple, one lock, contention is irrelevant at probe
/// cadences (milliseconds). Lock poisoning is *recovered from*
/// (`into_inner`): the buffer holds plain data and stays structurally valid
/// across an unrelated panic, and discarding telemetry because some other
/// thread panicked would be worse. Insertion order is preserved and visible
/// via [`snapshot`](LinkQualityStream::snapshot); the statistical layer
/// re-sorts by `seq` internally, so summaries are identical regardless of
/// insertion order.
///
/// ## Persistence (documented)
///
/// **None.** The stream is in-memory, process-local streaming state. Durable
/// evidence capture is R8-001's concern (contribution evidence), explicitly
/// not the measurement layer's.
#[derive(Debug)]
pub struct LinkQualityStream {
    inner: Mutex<VecDeque<LinkQualitySample>>,
    capacity: usize,
}

impl LinkQualityStream {
    /// Create a stream holding at most `capacity` samples.
    ///
    /// # Errors
    /// [`TelemetryError::ZeroCapacity`] when `capacity == 0`.
    pub fn new(capacity: usize) -> Result<LinkQualityStream> {
        if capacity == 0 {
            return Err(TelemetryError::ZeroCapacity);
        }
        Ok(LinkQualityStream {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
        })
    }

    /// Maximum number of samples the window retains.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    fn lock(&self) -> MutexGuard<'_, VecDeque<LinkQualitySample>> {
        // Documented poisoning policy: recover (see type docs).
        match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Current number of retained samples.
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the window holds no samples.
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Push a sample, evicting the oldest when full (drop-oldest policy).
    /// Returns the evicted sample when an overflow occurred.
    pub fn push(&self, sample: LinkQualitySample) -> Option<LinkQualitySample> {
        let mut q = self.lock();
        let evicted = if q.len() == self.capacity {
            q.pop_front()
        } else {
            None
        };
        q.push_back(sample);
        evicted
    }

    /// Snapshot of the retained samples in insertion order.
    pub fn snapshot(&self) -> Vec<LinkQualitySample> {
        self.lock().iter().copied().collect()
    }

    /// Drop all retained samples.
    pub fn clear(&self) {
        self.lock().clear();
    }

    /// Summarize the current window (see [`stats::summarize`]).
    ///
    /// # Errors
    /// [`TelemetryError::EmptyWindow`] when no samples were pushed yet;
    /// [`TelemetryError::ClockSkew`] if a delivered sample has
    /// `rtt_micros == 0`.
    pub fn summarize(&self) -> Result<LinkQualitySummary> {
        let snap = self.snapshot();
        stats::summarize(&snap)
    }
}

/// Shared handle type used by probers and future consumers (R3-003 topology
/// evidence, R5-005 admission policy) to observe the same live stream.
pub type SharedLinkQualityStream = Arc<LinkQualityStream>;

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seq: u64, lost: bool) -> LinkQualitySample {
        if lost {
            LinkQualitySample::lost(0, seq, 1_000_000 + seq, 64)
        } else {
            LinkQualitySample::delivered(0, seq, 1_000_000 + seq, 100 + seq, 64)
        }
    }

    #[test]
    fn zero_capacity_is_a_typed_error() {
        assert!(matches!(LinkQualityStream::new(0), Err(TelemetryError::ZeroCapacity)));
    }

    #[test]
    fn overflow_drops_oldest_and_never_exceeds_capacity() {
        let s = LinkQualityStream::new(3).unwrap();
        for seq in 0..10 {
            s.push(sample(seq, false));
            assert!(s.len() <= 3, "capacity must never be exceeded");
        }
        let snap = s.snapshot();
        assert_eq!(snap.len(), 3);
        assert_eq!(
            snap.iter().map(|x| x.seq).collect::<Vec<_>>(),
            vec![7, 8, 9],
            "drop-oldest policy must retain the NEWEST samples"
        );
        // The push that overflows returns the evicted sample.
        assert_eq!(s.push(sample(10, false)).map(|x| x.seq), Some(7));
    }

    #[test]
    fn snapshot_preserves_insertion_order() {
        let s = LinkQualityStream::new(8).unwrap();
        s.push(sample(5, false));
        s.push(sample(2, false));
        s.push(sample(9, false));
        assert_eq!(s.snapshot().iter().map(|x| x.seq).collect::<Vec<_>>(), vec![5, 2, 9]);
        s.clear();
        assert!(s.is_empty());
    }

    #[test]
    fn summarize_on_empty_window_is_a_typed_error() {
        let s = LinkQualityStream::new(4).unwrap();
        assert!(matches!(s.summarize(), Err(TelemetryError::EmptyWindow)));
    }
}
