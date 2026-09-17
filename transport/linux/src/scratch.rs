//! Per-run scratch-path preparation — the R10-006 extraction.
//!
//! The `sharenet_loopback` participant builds its per-run projection
//! store (a connectivity-crate [`DurableProjectionStore`]) as a
//! REGULAR FILE at a per-run path inside a state dir the endurance
//! harness REUSES across participant runs. The store's own `create`
//! is fail-closed: it refuses to clobber ANY existing path (correct
//! product law — no silent data loss; load it instead), so the
//! harness-side scratch preparation, not the store, must clear a
//! prior occupant before creating.
//!
//! The R10-006 defect: that cleanup called only `remove_dir_all`,
//! which fails with ENOTDIR on the regular file the store actually
//! persists as, with the error swallowed — a silent no-op. Combined
//! with OS process-id recycling (pid_max 32768, ~100 pids consumed
//! per endurance cycle — the space wraps roughly every 5.5 hours), a
//! stale `b-<pid>.store` left by an earlier run eventually met a
//! participant that drew the same id; `create` (correctly) refused,
//! the participant panicked, and the 24-hour endurance run died at
//! cycle 438/1440. The fix is this helper: remove BOTH occupant
//! forms, the file first, then the directory.
//!
//! Errors are NON-FATAL by design: scratch cleanup must never kill a
//! run by itself — the artifact's own fail-closed `create` remains
//! the last-resort safety.
//!
//! [`DurableProjectionStore`]: sharenet_connectivity::DurableProjectionStore

/// Remove whatever occupies `path` so a fresh per-run scratch
/// artifact can be created there: the regular FILE form first (the
/// observed R10-006 stale-store collision), then the directory form.
/// Never panics; errors are discarded (see the module docs for the
/// law).
pub fn clear_scratch_path(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir_all(path);
}
