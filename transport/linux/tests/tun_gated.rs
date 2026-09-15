//! SystemTunDevice live tests (R2-003) — **gated on the real probe**.
//!
//! These only run when `probe_tun() == Available` on this host (real
//! `/dev/net/tun` + `CAP_NET_ADMIN`). On sandboxed CI the probe reports
//! Absent/Forbidden and these tests SKIP with a printed reason — that is
//! correct, honest behavior, not a failure. Live TUN *data-path* verification
//! (packets through the interface) is R4-003 scope.

use sharenet_transport_linux::tun::{SystemTunDevice, TunDevice, TunError};
use sharenet_transport_linux::{probe_tun, TunAvailability};

fn tun_available() -> bool {
    let avail = probe_tun();
    println!("gate: probe_tun() = {avail}");
    matches!(avail, TunAvailability::Available)
}

#[test]
fn system_tun_open_auto_name_reports_name_and_mtu() {
    if !tun_available() {
        eprintln!("SKIP: TUN not available on this host (live test, R4-003 will verify on gateway hosts)");
        return;
    }
    let mut dev = SystemTunDevice::open(None).expect("open tun with kernel-assigned name");
    let name = dev.name().to_string();
    assert!(!name.is_empty(), "kernel must report an interface name");
    assert!(dev.mtu() > 0, "MTU must be positive, got {}", dev.mtu());
    dev.close().unwrap();
}

#[test]
fn system_tun_explicit_name_roundtrip_and_reopen_conflict() {
    if !tun_available() {
        eprintln!("SKIP: TUN not available on this host");
        return;
    }
    let name = format!("snt{:04}", std::process::id() % 10_000);
    let mut first = SystemTunDevice::open(Some(&name)).expect("open tun with explicit name");
    assert_eq!(first.name(), name);

    // Second open of the SAME name while the first fd holds it must be a
    // typed AlreadyInUse (EEXIST from the kernel), never a crash.
    match SystemTunDevice::open(Some(&name)) {
        Err(TunError::AlreadyInUse { .. }) => {}
        other => panic!("expected AlreadyInUse for duplicate name, got {other:?}"),
    }

    first.close().unwrap();
    // After close, the name is free again (interface destroyed with the fd).
    // NOTE: name reuse immediately after close can race with kernel cleanup;
    // we only assert the open path returns *some* typed result, not a panic.
    let _ = SystemTunDevice::open(Some(&name));
}

#[test]
fn system_tun_nonblocking_read_would_block_and_poll() {
    if !tun_available() {
        eprintln!("SKIP: TUN not available on this host");
        return;
    }
    let mut dev = SystemTunDevice::open(None).expect("open tun");
    dev.set_nonblocking(true).unwrap();
    assert!(!dev.poll_read_ready().unwrap(), "fresh tun has nothing to read");
    let mut buf = [0u8; 2048];
    match dev.read_packet(&mut buf) {
        Err(TunError::WouldBlock) => {}
        other => panic!("expected WouldBlock on empty non-blocking read, got {other:?}"),
    }
    // Restore blocking mode and close cleanly.
    dev.set_nonblocking(false).unwrap();
    dev.close().unwrap();
    // After close, all I/O is a typed Closed error.
    match dev.read_packet(&mut buf) {
        Err(TunError::Closed) => {}
        other => panic!("expected Closed after close, got {other:?}"),
    }
}

#[test]
fn system_tun_oversized_write_rejected_against_real_mtu() {
    if !tun_available() {
        eprintln!("SKIP: TUN not available on this host");
        return;
    }
    let mut dev = SystemTunDevice::open(None).expect("open tun");
    let mtu = dev.mtu();
    let big = vec![0u8; mtu + 1];
    match dev.write_packet(&big) {
        Err(TunError::PacketTooLarge { len, mtu: m }) => {
            assert_eq!(len, mtu + 1);
            assert_eq!(m, mtu);
        }
        other => panic!("expected PacketTooLarge, got {other:?}"),
    }
    dev.close().unwrap();
}

#[test]
fn system_tun_invalid_names_are_rejected_before_any_syscall() {
    // This one does NOT need TUN: validation happens purely in userspace.
    for bad in ["", "too_long_interface_name_over_15_bytes", "bad/name", "sp ace"] {
        match SystemTunDevice::open(Some(bad)) {
            Err(TunError::InvalidName { .. }) => {}
            other => panic!("expected InvalidName for {bad:?}, got {other:?}"),
        }
    }
}
