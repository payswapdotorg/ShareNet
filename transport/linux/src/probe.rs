//! TUN capability probe (R2-003).
//!
//! An *honest runtime probe*: it reports what the host can actually do, not
//! what we wish it could do. The canonical question is "can this process open
//! `/dev/net/tun` and attach a TUN interface right now?", answered by doing
//! exactly that (open + `TUNSETIFF` with a kernel-assigned name, then close —
//! the ephemeral interface disappears with the file descriptor).
//!
//! A probe result of [`TunAvailability::Absent`] or
//! [`TunAvailability::Forbidden`] on a sandboxed CI host is **correct
//! behavior**, not a test failure. Live TUN data-path verification is R4-003
//! scope; [`crate::tun::SystemTunDevice`] is implemented fully regardless.

use crate::tun::{TunError, TUN_DEVICE_PATH};
use std::fmt;

/// Result of probing TUN availability on this host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunAvailability {
    /// `/dev/net/tun` exists and open + `TUNSETIFF` succeeded (interface was
    /// created and destroyed again by the probe).
    Available,
    /// TUN is not present on this host (missing device node or equivalent).
    Absent { reason: String },
    /// TUN exists but this process may not use it (permission denied at open
    /// or ioctl — typically missing `CAP_NET_ADMIN`).
    Forbidden,
}

impl fmt::Display for TunAvailability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TunAvailability::Available => write!(f, "available"),
            TunAvailability::Absent { reason } => write!(f, "absent ({reason})"),
            TunAvailability::Forbidden => write!(f, "forbidden (open or TUNSETIFF denied; needs CAP_NET_ADMIN)"),
        }
    }
}

/// Probe the canonical TUN device path on this host.
///
/// This is a real runtime path: it opens the device and runs `TUNSETIFF`
/// with an empty (kernel-assigned) interface name, then closes the fd. The
/// transient interface vanishes when the fd closes, so the probe is
/// side-effect free.
pub fn probe_tun() -> TunAvailability {
    probe_path(TUN_DEVICE_PATH)
}

/// Probe an arbitrary device path (same logic, parameterized so the
/// "missing device" path is unit-testable without privileges).
pub fn probe_path(path: &str) -> TunAvailability {
    if !std::path::Path::new(path).exists() {
        return TunAvailability::Absent { reason: format!("{path} does not exist") };
    }

    // Open the control device non-blocking so a wedged device cannot hang the probe.
    let path_c = format!("{path}\0");
    let fd = unsafe {
        libc::open(path_c.as_ptr() as *const libc::c_char, libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK)
    };
    if fd < 0 {
        let err = std::io::Error::last_os_error();
        return match err.raw_os_error() {
            Some(libc::EPERM) | Some(libc::EACCES) => TunAvailability::Forbidden,
            Some(libc::ENOENT) => {
                TunAvailability::Absent { reason: format!("{path} disappeared before open: {err}") }
            }
            other => TunAvailability::Absent {
                reason: format!("open {path} failed with os error {other:?}: {err}"),
            },
        };
    }

    // Attach a transient TUN interface (empty name ⇒ kernel assigns tun%d).
    #[repr(C)]
    struct IfreqProbe {
        name: [u8; libc::IFNAMSIZ],
        payload: [u8; 24],
    }
    let mut ifr = IfreqProbe { name: [0u8; libc::IFNAMSIZ], payload: [0u8; 24] };
    let flags: libc::c_short = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
    ifr.payload[0..2].copy_from_slice(&flags.to_ne_bytes());
    let rc = unsafe { libc::ioctl(fd, libc::TUNSETIFF as libc::c_ulong, &mut ifr as *mut IfreqProbe) };
    let ioctl_err = if rc < 0 { Some(std::io::Error::last_os_error()) } else { None };
    // Always close: closing destroys the transient interface.
    unsafe { libc::close(fd) };

    match ioctl_err {
        None => TunAvailability::Available,
        Some(err) => match err.raw_os_error() {
            Some(libc::EPERM) | Some(libc::EACCES) => TunAvailability::Forbidden,
            other => TunAvailability::Absent {
                reason: format!("TUNSETIFF on {path} failed with os error {other:?}: {err}"),
            },
        },
    }
}

/// Convenience: map a [`TunError`] from a failed [`crate::tun::SystemTunDevice`]
/// open into the corresponding availability classification (used by tooling to
/// explain *why* a device open failed).
pub fn availability_from_error(err: &TunError) -> TunAvailability {
    match err {
        TunError::Permission { .. } => TunAvailability::Forbidden,
        TunError::Unsupported { detail } => TunAvailability::Absent { reason: detail.clone() },
        other => TunAvailability::Absent { reason: other.to_string() },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_missing_path_is_absent_without_panic() {
        // Adversarial: the probe target does not exist at all.
        let avail = probe_path("/definitely/not/a/tun/device");
        assert!(
            matches!(avail, TunAvailability::Absent { .. }),
            "expected Absent, got {avail:?}"
        );
    }

    #[test]
    fn probe_regular_file_is_absent_without_panic() {
        // Adversarial: the path exists but is NOT a TUN control device
        // (here: a regular file). open(O_RDWR) succeeds, TUNSETIFF fails.
        let tmp = std::env::temp_dir().join("sharenet_probe_not_a_tun");
        std::fs::write(&tmp, b"not a tun device").unwrap();
        let avail = probe_path(tmp.to_str().unwrap());
        std::fs::remove_file(&tmp).ok();
        assert!(
            matches!(avail, TunAvailability::Absent { .. }),
            "expected Absent for a regular file, got {avail:?}"
        );
    }

    #[test]
    fn probe_tun_never_panics_and_classifies() {
        // On any host this must terminate with a classified result.
        let avail = probe_tun();
        // Print it so `cargo test -- --nocapture` shows the real host answer.
        println!("probe_tun() = {avail}");
        assert!(matches!(
            avail,
            TunAvailability::Available | TunAvailability::Absent { .. } | TunAvailability::Forbidden
        ));
    }

    #[test]
    fn availability_display_is_stable() {
        assert_eq!(TunAvailability::Available.to_string(), "available");
        assert!(TunAvailability::Forbidden.to_string().contains("forbidden"));
        let absent = TunAvailability::Absent { reason: "no node".into() };
        assert_eq!(absent.to_string(), "absent (no node)");
    }
}
