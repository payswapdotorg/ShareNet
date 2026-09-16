//! Shared test scaffolding for the R6-004 verify-level suites
//! (adversarial + restart): real manifests with real chunk hashes
//! (built from real content through the protocol core), offers, peers
//! and temp dirs — the same discipline as the sibling crates' suites.

#![allow(dead_code)]

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use sharenet_dtn::{PeerRef, ServicePriority};
use sharenet_protocol::ContentManifest;
use sharenet_propagation::{ManifestOffer, PropagationPolicy, PropagationParams};

/// A deterministic base time for all test clocks.
pub const NOW: u64 = 1_700_000_500;
/// A comfortable TTL bound for fixtures (10_000s from NOW).
pub const EXPIRY: u64 = NOW + 10_000;

/// The offering peer (opaque bytes, as ever).
pub fn peer() -> PeerRef {
    PeerRef::new(&[0x4e, 0x6f, 0x64, 0x65, 0x50]).expect("valid peer")
}

/// A manifest with `n` chunks of 8 bytes, built from real content seeded
/// by `seed` (so different fixtures derive different content ids).
pub fn fixture(n: usize, seed: u8) -> (ContentManifest, Vec<Vec<u8>>) {
    let content: Vec<u8> = (0..(n * 8))
        .map(|i| (i as u8).wrapping_mul(3).wrapping_add(seed))
        .collect();
    ContentManifest::chunk(&content, 8, "app/test", None, NOW).expect("valid content")
}

/// The standard offer of `bytes` (dtn class, 2 target, `expires`).
pub fn offer<'a>(bytes: &'a [u8], peer: &'a PeerRef, expires: u64) -> ManifestOffer<'a> {
    ManifestOffer::new(bytes, "dtn", expires, 2, peer)
}

/// The default policy.
pub fn policy() -> PropagationPolicy {
    PropagationPolicy::default()
}

/// A policy with the given minimum remaining life.
pub fn policy_with_floor(min: u64) -> PropagationPolicy {
    PropagationPolicy::new(PropagationParams::new(min))
}

/// Take custody of `manifest` (and optionally its chunks) directly
/// through the store's own APIs — the path a daemon drives on the
/// file-backed store; used to set up held state fast.
pub fn seed_bundle(
    store: &mut sharenet_dtn::DtnStoreImage,
    manifest: &ContentManifest,
    chunks: &[Vec<u8>],
    expires_at: u64,
) {
    store
        .admit_manifest(manifest, ServicePriority::Dtn, NOW, expires_at, 2)
        .expect("seed admission");
    for (slot, chunk) in chunks.iter().enumerate() {
        store
            .admit_chunk(&manifest.content_id(), slot, chunk, NOW)
            .expect("seed chunk");
    }
}

/// A unique temp dir (house pattern: tag + pid + nanos).
pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "sharenet-propagation-{}-{}-{}",
            tag,
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("temp dir");
        TempDir { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
