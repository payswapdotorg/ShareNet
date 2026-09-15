//! Shared test helpers for the ShareNet protocol core integration tests.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Strict lowercase hex decoder (panics on malformed input; tests only).
pub fn from_hex(s: &str) -> Vec<u8> {
    let s = s.trim();
    assert!(s.len().is_multiple_of(2), "odd-length hex string: {s}");
    let mut out = Vec::with_capacity(s.len() / 2);
    let nib = |c: u8| -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("invalid hex digit in {s}"),
        }
    };
    for pair in s.as_bytes().chunks(2) {
        out.push((nib(pair[0]) << 4) | nib(pair[1]));
    }
    out
}

/// Deterministic splitmix64 PRNG for property tests (no external dependency).
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed.wrapping_add(0x9E3779B97F4A7C15))
    }

    pub fn next_u64(&mut self) -> u64 {
        // splitmix64
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    pub fn next_byte(&mut self) -> u8 {
        (self.next_u64() >> 32) as u8
    }

    pub fn next_bool(&mut self) -> bool {
        (self.next_u64() & 1) == 1
    }

    pub fn next_range(&mut self, bound: u64) -> u64 {
        assert!(bound > 0);
        self.next_u64() % bound
    }
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A temporary directory that removes itself on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> TempDir {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let base = std::env::temp_dir();
        let path = base.join(format!(
            "sharenet-test-{}-{}-{}-{}",
            tag,
            std::process::id(),
            n,
            nanos
        ));
        std::fs::create_dir_all(&path).expect("create test tempdir");
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn join(&self, rel: &str) -> PathBuf {
        self.0.join(rel)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Write bytes to a file, creating parents as needed.
pub fn write_file(path: &Path, bytes: &[u8]) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create parent");
    }
    std::fs::write(path, bytes).expect("write test file");
}

/// Set file permissions on unix.
#[cfg(unix)]
pub fn set_mode(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("set test file mode");
}

/// Read the unix file mode (lower 9 bits).
#[cfg(unix)]
pub fn mode_of(path: &Path) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .expect("metadata for mode")
        .permissions()
        .mode()
        & 0o777
}
