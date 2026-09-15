//! TUN device abstraction (R2-003).
//!
//! Platform adapter per architecture lock **L009**: this module moves raw IP
//! packets between userspace and the kernel TUN interface. It interprets
//! nothing — no addressing, no routing, no cryptography. Those are protocol
//! core concerns that live above this seam (R4-001/R4-003 will consume this).
//!
//! Two implementations:
//!
//! * [`SystemTunDevice`] — opens the real `/dev/net/tun` and performs the
//!   `TUNSETIFF` ioctl via the `libc` crate (raw syscalls, no helper crates).
//! * [`MemoryTunDevice`] — an in-memory duplex pair used as a **test
//!   vehicle**; it never touches `/dev/net/tun` and is marked as such.
//!
//! All APIs are synchronous; the async wrapper is R4-001 scope.
//!
//! ## Documented policies
//!
//! * **Oversized packet policy: REJECT.** [`TunDevice::write_packet`] rejects
//!   any packet larger than the device MTU with [`TunError::PacketTooLarge`].
//!   No silent splitting: segmentation above the TUN seam is the future
//!   tunnel layer's job (R4-001). Rejecting keeps packet boundaries honest
//!   and failures loud.
//! * **Zero-length packets** are rejected with [`TunError::Unsupported`]; an
//!   empty write is a caller bug, not a packet.
//! * **Interface names** (explicit form) must be 1–15 bytes of
//!   `[A-Za-z0-9._-]`. This is slightly stricter than the kernel (which also
//!   tolerates `:`); the stricter rule avoids `eth0:1`-style alias ambiguity.

use std::collections::VecDeque;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};

/// Path of the Linux TUN control device.
pub const TUN_DEVICE_PATH: &str = "/dev/net/tun";

/// Default MTU assumed for a fresh TUN interface when not queried.
pub const DEFAULT_TUN_MTU: usize = 1500;

/// Typed errors for TUN device operations. No raw `errno` leaks; everything is
/// classified at the syscall boundary.
#[derive(Debug)]
pub enum TunError {
    /// The device or name is already in use (`EBUSY`/`EEXIST`).
    AlreadyInUse { detail: String },
    /// The operation was not permitted (`EACCES`/`EPERM`) — typically missing
    /// `CAP_NET_ADMIN` or restrictive sandboxing.
    Permission { detail: String },
    /// The platform/path does not support TUN here (`ENOENT`, `ENODEV`,
    /// bad ioctl arguments, zero-length packet, …).
    Unsupported { detail: String },
    /// The requested interface name failed validation (see module docs).
    InvalidName { name: String, detail: String },
    /// A non-blocking read found no data available.
    WouldBlock,
    /// The packet exceeds the device MTU (policy: reject, never split).
    PacketTooLarge { len: usize, mtu: usize },
    /// The device (or its peer) is closed; further I/O is refused.
    Closed,
    /// An unclassified I/O failure, with context.
    Io { context: String, source: std::io::Error },
}

impl fmt::Display for TunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunError::AlreadyInUse { detail } => write!(f, "tun device already in use: {detail}"),
            TunError::Permission { detail } => write!(f, "tun permission denied: {detail}"),
            TunError::Unsupported { detail } => write!(f, "tun unsupported on this platform/path: {detail}"),
            TunError::InvalidName { name, detail } => write!(f, "invalid tun interface name {name:?}: {detail}"),
            TunError::WouldBlock => write!(f, "tun read would block (no data available)"),
            TunError::PacketTooLarge { len, mtu } => {
                write!(f, "packet of {len} bytes exceeds tun MTU {mtu} (policy: reject, never split)")
            }
            TunError::Closed => write!(f, "tun device is closed"),
            TunError::Io { context, source } => write!(f, "tun io error during {context}: {source}"),
        }
    }
}

impl std::error::Error for TunError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TunError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl TunError {
    /// Classify a raw OS error from the open/ioctl path into a typed error.
    /// Pure function — unit-tested without any real device.
    pub(crate) fn classify_errno(context: &str, err: &std::io::Error) -> TunError {
        let detail = format!("{context}: {err}");
        match err.raw_os_error() {
            Some(libc::EBUSY) | Some(libc::EEXIST) => TunError::AlreadyInUse { detail },
            Some(libc::EPERM) | Some(libc::EACCES) => TunError::Permission { detail },
            Some(libc::ENOENT) | Some(libc::ENODEV) | Some(libc::ENXIO) | Some(libc::EINVAL) => {
                TunError::Unsupported { detail }
            }
            _ => TunError::Io { context: context.to_string(), source: std::io::Error::new(err.kind(), detail) },
        }
    }
}

/// A synchronous TUN device: moves raw IP packets between userspace and the
/// kernel. This is a *transport seam* — implementations MUST NOT interpret
/// packet contents.
///
/// Construction is per-implementation (a trait-level constructor cannot see
/// platform specifics):
/// * [`SystemTunDevice::open(Option<&str>)`](SystemTunDevice::open) for the
///   real `/dev/net/tun` path,
/// * [`MemoryTunPair::new(usize)`](MemoryTunPair::new) for the test vehicle.
pub trait TunDevice {
    /// The kernel-visible interface name (e.g. `tun0`).
    fn name(&self) -> &str;
    /// The device MTU in bytes.
    fn mtu(&self) -> usize;
    /// Read one packet into `buf`, returning the number of bytes read.
    ///
    /// Blocking mode: waits for a packet. Non-blocking mode (see
    /// [`set_nonblocking`](TunDevice::set_nonblocking)): returns
    /// [`TunError::WouldBlock`] when no packet is queued.
    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunError>;
    /// Write one packet. Oversized (> MTU) and zero-length writes are
    /// rejected — see module docs for the documented policy.
    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, TunError>;
    /// Enable or disable non-blocking mode.
    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TunError>;
    /// Poll (zero timeout) whether a [`read_packet`](TunDevice::read_packet)
    /// would return data now. Never blocks.
    fn poll_read_ready(&mut self) -> Result<bool, TunError>;
    /// Close the device. Subsequent I/O returns [`TunError::Closed`].
    fn close(&mut self) -> Result<(), TunError>;
}

/// Validate an explicit interface name. Stricter than the kernel on purpose
/// (module docs). Pure function.
pub(crate) fn validate_name(name: &str) -> Result<(), TunError> {
    if name.is_empty() {
        return Err(TunError::InvalidName { name: name.to_string(), detail: "must not be empty".into() });
    }
    if name.len() >= libc::IFNAMSIZ {
        return Err(TunError::InvalidName {
            name: name.to_string(),
            detail: format!("must be at most {} bytes", libc::IFNAMSIZ - 1),
        });
    }
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-') {
        return Err(TunError::InvalidName {
            name: name.to_string(),
            detail: "only [A-Za-z0-9._-] allowed (ShareNet policy, stricter than kernel)".into(),
        });
    }
    Ok(())
}

/// Raw `ifreq`-shaped buffer used for `TUNSETIFF` and `SIOCGIFMTU`.
///
/// `struct ifreq` is `{ char ifr_name[16]; union { ... } }`; the union is at
/// least 16 bytes (a `sockaddr`) on Linux. We over-allocate the payload to 24
/// bytes so both the `c_short` flags (offset 0 of the union) and the `int`
/// MTU (offset 0 of the union) fit; the kernel only touches the first
/// `sizeof(struct ifreq)` bytes of what we pass.
#[repr(C)]
struct RawIfreq {
    name: [u8; libc::IFNAMSIZ],
    payload: [u8; 24],
}

impl RawIfreq {
    fn zeroed() -> Self {
        RawIfreq { name: [0u8; libc::IFNAMSIZ], payload: [0u8; 24] }
    }

    /// Write a NUL-terminated interface name (validated beforehand).
    fn set_name(&mut self, name: &str) {
        self.name[..name.len()].copy_from_slice(name.as_bytes());
    }

    fn name_str(&self) -> String {
        let end = self.name.iter().position(|&b| b == 0).unwrap_or(self.name.len());
        String::from_utf8_lossy(&self.name[..end]).into_owned()
    }
}

/// Real TUN device backed by `/dev/net/tun` + `ioctl(TUNSETIFF)`.
///
/// This is the production path for the future Linux gateway forwarding work
/// (R4-003) and the QUIC tunnel (R4-001). Construct with
/// [`SystemTunDevice::open`](SystemTunDevice::open).
pub struct SystemTunDevice {
    fd: i32,
    ifname: String,
    mtu: usize,
    nonblocking: bool,
    closed: bool,
}

impl fmt::Debug for SystemTunDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SystemTunDevice")
            .field("fd", &self.fd)
            .field("name", &self.ifname)
            .field("mtu", &self.mtu)
            .field("nonblocking", &self.nonblocking)
            .field("closed", &self.closed)
            .finish()
    }
}

impl SystemTunDevice {
    /// Open a TUN device.
    ///
    /// * `name: None` — let the kernel pick a free `tunN` name.
    /// * `name: Some(n)` — request an explicit name (validated; must be free).
    ///
    /// Requires `/dev/net/tun` to exist and `CAP_NET_ADMIN` (typically root).
    /// Failures are typed: missing support → [`TunError::Unsupported`],
    /// missing privilege → [`TunError::Permission`], taken name →
    /// [`TunError::AlreadyInUse`].
    pub fn open(name: Option<&str>) -> Result<SystemTunDevice, TunError> {
        let explicit_name = match name {
            None => String::new(), // empty name ⇒ kernel auto-assigns "tun%d"
            Some(n) => {
                validate_name(n)?;
                n.to_string()
            }
        };

        // Open the control device.
        let path_c = format!("{TUN_DEVICE_PATH}\0");
        let fd = unsafe {
            libc::open(path_c.as_ptr() as *const libc::c_char, libc::O_RDWR | libc::O_CLOEXEC)
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            return Err(TunError::classify_errno("open /dev/net/tun", &err));
        }

        // ioctl(TUNSETIFF): attach the fd to a new (or existing) tun interface.
        let mut ifr = RawIfreq::zeroed();
        ifr.set_name(&explicit_name);
        let flags: libc::c_short = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        ifr.payload[0..2].copy_from_slice(&flags.to_ne_bytes());
        let rc = unsafe { libc::ioctl(fd, libc::TUNSETIFF as libc::c_ulong, &mut ifr as *mut RawIfreq) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            // Do not leak the fd on failure.
            unsafe { libc::close(fd) };
            return Err(TunError::classify_errno("ioctl TUNSETIFF", &err));
        }
        // On success the kernel writes the final interface name back into ifr_name.
        let ifname = ifr.name_str();
        if ifname.is_empty() {
            unsafe { libc::close(fd) };
            return Err(TunError::Unsupported { detail: "kernel returned empty interface name".into() });
        }

        let mtu = query_interface_mtu(&ifname).map_err(|e| {
            unsafe { libc::close(fd) };
            e
        })?;

        Ok(SystemTunDevice { fd, ifname, mtu, nonblocking: false, closed: false })
    }

    fn require_open(&self) -> Result<i32, TunError> {
        if self.closed {
            Err(TunError::Closed)
        } else {
            Ok(self.fd)
        }
    }
}

impl TunDevice for SystemTunDevice {
    fn name(&self) -> &str {
        &self.ifname
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        let fd = self.require_open()?;
        if buf.is_empty() {
            return Err(TunError::Unsupported { detail: "read buffer must not be empty".into() });
        }
        loop {
            let n = unsafe {
                libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as libc::size_t)
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                // Linux aliases EWOULDBLOCK to EAGAIN.
                Some(libc::EAGAIN) => return Err(TunError::WouldBlock),
                _ => return Err(TunError::Io { context: "read tun fd".into(), source: err }),
            }
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, TunError> {
        let fd = self.require_open()?;
        if packet.is_empty() {
            return Err(TunError::Unsupported { detail: "zero-length packet (policy: reject)".into() });
        }
        if packet.len() > self.mtu {
            return Err(TunError::PacketTooLarge { len: packet.len(), mtu: self.mtu });
        }
        loop {
            let n = unsafe {
                libc::write(fd, packet.as_ptr() as *const libc::c_void, packet.len() as libc::size_t)
            };
            if n >= 0 {
                return Ok(n as usize);
            }
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::EINTR) => continue,
                // Linux aliases EWOULDBLOCK to EAGAIN.
                Some(libc::EAGAIN) => return Err(TunError::WouldBlock),
                _ => return Err(TunError::Io { context: "write tun fd".into(), source: err }),
            }
        }
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TunError> {
        let fd = self.require_open()?;
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(TunError::Io {
                context: "fcntl F_GETFL".into(),
                source: std::io::Error::last_os_error(),
            });
        }
        let new_flags = if nonblocking { flags | libc::O_NONBLOCK } else { flags & !libc::O_NONBLOCK };
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, new_flags) };
        if rc < 0 {
            return Err(TunError::Io {
                context: "fcntl F_SETFL".into(),
                source: std::io::Error::last_os_error(),
            });
        }
        self.nonblocking = nonblocking;
        Ok(())
    }

    fn poll_read_ready(&mut self) -> Result<bool, TunError> {
        let fd = self.require_open()?;
        let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
        loop {
            let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
            if rc >= 0 {
                return Ok(pfd.revents & libc::POLLIN != 0);
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(TunError::Io { context: "poll tun fd".into(), source: err });
        }
    }

    fn close(&mut self) -> Result<(), TunError> {
        if self.closed {
            return Ok(());
        }
        let rc = unsafe { libc::close(self.fd) };
        self.closed = true;
        if rc < 0 {
            return Err(TunError::Io {
                context: "close tun fd".into(),
                source: std::io::Error::last_os_error(),
            });
        }
        Ok(())
    }
}

impl Drop for SystemTunDevice {
    fn drop(&mut self) {
        if !self.closed {
            unsafe { libc::close(self.fd) };
            self.closed = true;
        }
    }
}

/// Query an interface MTU via `ioctl(SIOCGIFMTU)` on a temporary UDP socket.
fn query_interface_mtu(ifname: &str) -> Result<usize, TunError> {
    // A datagram socket is enough to run interface ioctls.
    let sock = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| TunError::Io { context: "create ioctl socket".into(), source: e })?;
    let mut ifr = RawIfreq::zeroed();
    ifr.set_name(ifname);
    let rc = unsafe {
        libc::ioctl(sock.as_raw_fd(), libc::SIOCGIFMTU as libc::c_ulong, &mut ifr as *mut RawIfreq)
    };
    if rc < 0 {
        return Err(TunError::Io {
            context: "ioctl SIOCGIFMTU".into(),
            source: std::io::Error::last_os_error(),
        });
    }
    let mtu = i32::from_ne_bytes([ifr.payload[0], ifr.payload[1], ifr.payload[2], ifr.payload[3]]);
    if mtu <= 0 {
        // Defensive: should never happen for a live interface.
        return Ok(DEFAULT_TUN_MTU);
    }
    Ok(mtu as usize)
}

use std::os::fd::AsRawFd;

// ---------------------------------------------------------------------------
// MemoryTunDevice — TEST VEHICLE (no /dev/net/tun involved, ever).
// ---------------------------------------------------------------------------

/// Shared, closed-over queue used to model one direction of the in-memory
/// duplex pair.
#[derive(Default)]
struct Channel {
    state: Mutex<ChannelState>,
    ready: Condvar,
}

#[derive(Default)]
struct ChannelState {
    packets: VecDeque<Vec<u8>>,
    /// Set when the writer on this channel has closed; readers drain
    /// remaining packets then observe `Closed`.
    writer_closed: bool,
}

impl Channel {
    fn push(&self, packet: Vec<u8>) {
        let mut state = self.state.lock().expect("memory tun channel lock poisoned");
        state.packets.push_back(packet);
        drop(state);
        self.ready.notify_all();
    }

    fn close_writer(&self) {
        let mut state = self.state.lock().expect("memory tun channel lock poisoned");
        state.writer_closed = true;
        drop(state);
        self.ready.notify_all();
    }

    /// Try to pop a packet that fits in `buf` (peek-first: an oversized
    /// front packet is NOT consumed, so the caller can retry with a bigger
    /// buffer).
    fn try_pop(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        let mut state = self.state.lock().expect("memory tun channel lock poisoned");
        match state.packets.front() {
            None => {
                if state.writer_closed {
                    Err(TunError::Closed)
                } else {
                    Err(TunError::WouldBlock)
                }
            }
            Some(front) => {
                if front.len() > buf.len() {
                    Err(TunError::PacketTooLarge { len: front.len(), mtu: buf.len() })
                } else {
                    let packet = state.packets.pop_front().expect("front checked above");
                    buf[..packet.len()].copy_from_slice(&packet);
                    Ok(packet.len())
                }
            }
        }
    }

    fn has_packets(&self) -> bool {
        let state = self.state.lock().expect("memory tun channel lock poisoned");
        !state.packets.is_empty()
    }

    fn is_writer_closed(&self) -> bool {
        let state = self.state.lock().expect("memory tun channel lock poisoned");
        state.writer_closed
    }

    /// Blocking pop with wakeups on new packets or writer close.
    fn blocking_pop(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        let mut state = self.state.lock().expect("memory tun channel lock poisoned");
        loop {
            match state.packets.front() {
                Some(front) if front.len() > buf.len() => {
                    return Err(TunError::PacketTooLarge { len: front.len(), mtu: buf.len() })
                }
                Some(_) => {
                    let packet = state.packets.pop_front().expect("front checked above");
                    buf[..packet.len()].copy_from_slice(&packet);
                    return Ok(packet.len());
                }
                None if state.writer_closed => return Err(TunError::Closed),
                None => {
                    state = self
                        .ready
                        .wait(state)
                        .expect("memory tun channel lock poisoned");
                }
            }
        }
    }
}

/// **TEST VEHICLE** — one end of an in-memory duplex TUN pair.
///
/// This never touches `/dev/net/tun`; it exists so adapter and framing logic
/// can be exercised on hosts without TUN. Bytes written here are readable on
/// the peer end only (duplex independence).
pub struct MemoryTunDevice {
    ifname: String,
    mtu: usize,
    nonblocking: bool,
    closed: bool,
    /// Packets we write go to the peer via `outgoing`.
    outgoing: Arc<Channel>,
    /// Packets we read arrive from the peer via `incoming`.
    incoming: Arc<Channel>,
}

impl fmt::Debug for MemoryTunDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MemoryTunDevice")
            .field("name", &self.ifname)
            .field("mtu", &self.mtu)
            .field("nonblocking", &self.nonblocking)
            .field("closed", &self.closed)
            .field("is_test_vehicle", &true)
            .finish()
    }
}

impl TunDevice for MemoryTunDevice {
    fn name(&self) -> &str {
        &self.ifname
    }

    fn mtu(&self) -> usize {
        self.mtu
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> Result<usize, TunError> {
        if self.closed {
            return Err(TunError::Closed);
        }
        if buf.is_empty() {
            return Err(TunError::Unsupported { detail: "read buffer must not be empty".into() });
        }
        if self.nonblocking {
            self.incoming.try_pop(buf)
        } else {
            self.incoming.blocking_pop(buf)
        }
    }

    fn write_packet(&mut self, packet: &[u8]) -> Result<usize, TunError> {
        if self.closed {
            return Err(TunError::Closed);
        }
        if packet.is_empty() {
            return Err(TunError::Unsupported { detail: "zero-length packet (policy: reject)".into() });
        }
        if packet.len() > self.mtu {
            return Err(TunError::PacketTooLarge { len: packet.len(), mtu: self.mtu });
        }
        self.outgoing.push(packet.to_vec());
        Ok(packet.len())
    }

    fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), TunError> {
        if self.closed {
            return Err(TunError::Closed);
        }
        self.nonblocking = nonblocking;
        Ok(())
    }

    fn poll_read_ready(&mut self) -> Result<bool, TunError> {
        if self.closed {
            return Err(TunError::Closed);
        }
        Ok(self.incoming.has_packets() || self.incoming.is_writer_closed())
    }

    fn close(&mut self) -> Result<(), TunError> {
        if self.closed {
            return Ok(());
        }
        // Refuse further writes from this end and tell the peer its writer is
        // gone (the peer may still drain packets already queued).
        self.outgoing.close_writer();
        self.closed = true;
        Ok(())
    }
}

impl Drop for MemoryTunDevice {
    fn drop(&mut self) {
        if !self.closed {
            self.outgoing.close_writer();
            self.closed = true;
        }
    }
}

/// **TEST VEHICLE** — a duplex pair of [`MemoryTunDevice`] ends sharing one
/// MTU. Writes on `a` are readable on `b` and vice versa; neither end ever
/// reads back its own writes.
pub struct MemoryTunPair {
    pub a: MemoryTunDevice,
    pub b: MemoryTunDevice,
}

impl MemoryTunPair {
    /// Create a pair with the given MTU (packet-over-MTU writes are rejected).
    pub fn new(mtu: usize) -> MemoryTunPair {
        let a_to_b = Arc::new(Channel::default());
        let b_to_a = Arc::new(Channel::default());
        MemoryTunPair {
            a: MemoryTunDevice {
                ifname: "memtun0".to_string(),
                mtu,
                nonblocking: false,
                closed: false,
                outgoing: Arc::clone(&a_to_b),
                incoming: Arc::clone(&b_to_a),
            },
            b: MemoryTunDevice {
                ifname: "memtun1".to_string(),
                mtu,
                nonblocking: false,
                closed: false,
                outgoing: Arc::clone(&b_to_a),
                incoming: Arc::clone(&a_to_b),
            },
        }
    }
}

// Test-only helper: must be defined before the test module (clippy:
// items_after_test_module).
#[cfg(test)]
impl MemoryTunDevice {
    /// Test-only accessor for the outgoing channel handle, used to simulate
    /// delayed writers/closers from other threads.
    fn clone_channel_outgoing_for_test(&self) -> Arc<Channel> {
        Arc::clone(&self.outgoing)
    }
}

// ---------------------------------------------------------------------------
// Unit tests — all runnable on hosts WITHOUT TUN (pure logic + test vehicle).
// Live SystemTunDevice tests live in tests/tun_gated.rs behind probe_tun().
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_classification_is_typed() {
        let eperm = std::io::Error::from_raw_os_error(libc::EPERM);
        assert!(matches!(TunError::classify_errno("x", &eperm), TunError::Permission { .. }));
        let eacces = std::io::Error::from_raw_os_error(libc::EACCES);
        assert!(matches!(TunError::classify_errno("x", &eacces), TunError::Permission { .. }));
        let ebusy = std::io::Error::from_raw_os_error(libc::EBUSY);
        assert!(matches!(TunError::classify_errno("x", &ebusy), TunError::AlreadyInUse { .. }));
        let eexist = std::io::Error::from_raw_os_error(libc::EEXIST);
        assert!(matches!(TunError::classify_errno("x", &eexist), TunError::AlreadyInUse { .. }));
        let enoent = std::io::Error::from_raw_os_error(libc::ENOENT);
        assert!(matches!(TunError::classify_errno("x", &enoent), TunError::Unsupported { .. }));
        let enodev = std::io::Error::from_raw_os_error(libc::ENODEV);
        assert!(matches!(TunError::classify_errno("x", &enodev), TunError::Unsupported { .. }));
        // Unclassified errno falls back to Io with context preserved.
        let eio = std::io::Error::from_raw_os_error(libc::EIO);
        assert!(matches!(TunError::classify_errno("ctx", &eio), TunError::Io { .. }));
    }

    #[test]
    fn name_validation_rejects_bad_names() {
        for bad in ["", "way_too_long_interface_name_exceeds_15", "eth0/", "has space", "eth0:1", "tab\tname"] {
            assert!(matches!(validate_name(bad), Err(TunError::InvalidName { .. })), "expected reject: {bad:?}");
        }
        for good in ["tun0", "sntun", "sn-tun.9_a", "x"] {
            assert!(validate_name(good).is_ok(), "expected accept: {good:?}");
        }
    }

    #[test]
    fn memory_pair_duplex_independence() {
        let mut pair = MemoryTunPair::new(1500);
        // a → b
        pair.a.write_packet(b"hello-from-a").unwrap();
        // b → a
        pair.b.write_packet(b"hello-from-b").unwrap();

        // Duplex independence: each end reads the PEER's packet, never its own.
        let mut buf = [0u8; 64];
        pair.a.set_nonblocking(true).unwrap();
        let n = pair.a.read_packet(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello-from-b", "a must read b's packet, not its own");
        pair.b.set_nonblocking(true).unwrap();
        let n = pair.b.read_packet(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"hello-from-a", "b must read a's packet, not its own");

        // Drained: further reads WouldBlock on both ends.
        assert!(matches!(pair.a.read_packet(&mut buf), Err(TunError::WouldBlock)));
        assert!(matches!(pair.b.read_packet(&mut buf), Err(TunError::WouldBlock)));
    }

    #[test]
    fn memory_pair_oversized_write_rejected() {
        let mut pair = MemoryTunPair::new(16);
        let big = vec![7u8; 17];
        match pair.a.write_packet(&big) {
            Err(TunError::PacketTooLarge { len: 17, mtu: 16 }) => {}
            other => panic!("expected PacketTooLarge, got {other:?}"),
        }
        // Zero-length writes are rejected too (documented policy).
        assert!(matches!(pair.a.write_packet(&[]), Err(TunError::Unsupported { .. })));
        // And nothing was queued for the peer.
        pair.b.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 32];
        assert!(matches!(pair.b.read_packet(&mut buf), Err(TunError::WouldBlock)));
    }

    #[test]
    fn memory_pair_read_smaller_buffer_than_packet_is_typed_error_without_loss() {
        let mut pair = MemoryTunPair::new(1500);
        pair.a.write_packet(&[9u8; 32]).unwrap();
        pair.b.set_nonblocking(true).unwrap();
        let mut small = [0u8; 8];
        match pair.b.read_packet(&mut small) {
            Err(TunError::PacketTooLarge { len: 32, mtu: 8 }) => {}
            other => panic!("expected PacketTooLarge, got {other:?}"),
        }
        // Packet not consumed: a full-size buffer still reads it.
        let mut full = [0u8; 32];
        let n = pair.b.read_packet(&mut full).unwrap();
        assert_eq!(n, 32);
    }

    #[test]
    fn memory_pair_nonblocking_read_without_data_would_block() {
        let mut pair = MemoryTunPair::new(1500);
        pair.a.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 16];
        assert!(matches!(pair.a.read_packet(&mut buf), Err(TunError::WouldBlock)));
    }

    #[test]
    fn memory_pair_blocking_read_wakes_on_write() {
        let mut pair = MemoryTunPair::new(1500);
        // Writer thread pushes a packet after a short delay; the blocking
        // read on the other end must wake and return it.
        let writer = pair.a.clone_channel_outgoing_for_test();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            writer.push(b"delayed-packet".to_vec());
        });
        let mut buf = [0u8; 64];
        let n = pair.b.read_packet(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"delayed-packet");
        handle.join().unwrap();
    }

    #[test]
    fn memory_pair_close_semantics() {
        let mut pair = MemoryTunPair::new(1500);
        pair.a.write_packet(b"last-words").unwrap();
        pair.a.close().unwrap();

        // Closed end refuses further I/O with typed Closed error.
        assert!(matches!(pair.a.write_packet(b"x"), Err(TunError::Closed)));
        let mut buf = [0u8; 16];
        assert!(matches!(pair.a.read_packet(&mut buf), Err(TunError::Closed)));
        assert!(matches!(pair.a.set_nonblocking(true), Err(TunError::Closed)));

        // Peer drains the queue, then observes Closed (not WouldBlock).
        pair.b.set_nonblocking(true).unwrap();
        let n = pair.b.read_packet(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"last-words");
        assert!(matches!(pair.b.read_packet(&mut buf), Err(TunError::Closed)));

        // Second close is idempotent.
        pair.a.close().unwrap();
    }

    #[test]
    fn memory_pair_blocking_read_returns_closed_when_peer_closes() {
        let mut pair = MemoryTunPair::new(1500);
        let writer = pair.a.clone_channel_outgoing_for_test();
        let handle = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(50));
            writer.close_writer();
        });
        let mut buf = [0u8; 16];
        assert!(matches!(pair.b.read_packet(&mut buf), Err(TunError::Closed)));
        handle.join().unwrap();
    }

    #[test]
    fn memory_pair_poll_read_ready_transitions() {
        let mut pair = MemoryTunPair::new(1500);
        assert!(!pair.b.poll_read_ready().unwrap());
        pair.a.write_packet(b"p").unwrap();
        assert!(pair.b.poll_read_ready().unwrap());
        let mut buf = [0u8; 8];
        pair.b.read_packet(&mut buf).unwrap();
        assert!(!pair.b.poll_read_ready().unwrap());
    }

    #[test]
    fn memory_pair_drop_closes_channel_for_peer() {
        let mut pair = MemoryTunPair::new(1500);
        {
            // Partial move: `a` (original end) is dropped at scope exit, which
            // must close the channel for the surviving peer.
            let mut a = pair.a;
            a.write_packet(b"pre-drop").unwrap();
        }
        // `b` must drain the queued packet, then see Closed.
        pair.b.set_nonblocking(true).unwrap();
        let mut buf = [0u8; 16];
        let n = pair.b.read_packet(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"pre-drop");
        assert!(matches!(pair.b.read_packet(&mut buf), Err(TunError::Closed)));
    }

    #[test]
    fn system_tun_device_error_display_is_human_readable() {
        let e = TunError::PacketTooLarge { len: 2000, mtu: 1500 };
        let s = e.to_string();
        assert!(s.contains("2000") && s.contains("1500"), "display was: {s}");
    }
}

