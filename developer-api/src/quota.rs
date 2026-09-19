//! The quota / rate-limit MODEL (C2-005): policy types, windowed counters
//! and the over/under decision — no transport, no enforcement caller.
//!
//! # Scope (deliberately narrow)
//!
//! `spec/developer-integration.yaml` lists `quotas/rate limits` among the
//! hosted Developer API's owned surfaces. This module owns the POLICY MODEL:
//! a fixed-window counter per (app, environment), a policy map with a
//! default, and a total decision ([`QuotaDecision::Allowed`] with remaining
//! budget or [`QuotaDecision::Limited`] with a retry-after). Enforcement
//! CALLERS (HTTP middleware, per-scope buckets, burst allowances) arrive in
//! later work items; the hosted deployment (C3-005) owns the real product
//! numbers — the presets here are documented model defaults, not product
//! commitments.
//!
//! # Determinism
//!
//! Fixed windows: the window index is `at / window_secs` — integer division,
//! deterministic, no wall clock, no drifting token buckets. Counters for
//! windows older than the current one are pruned lazily (they can never be
//! consulted again), so state stays bounded.

use crate::ids::{AppId, EnvironmentId, EntryMap};
use serde::{Deserialize, Serialize};
use std::fmt;

/// A fixed-window rate-limit policy.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct QuotaPolicy {
    /// How many requests are allowed per window.
    pub requests_per_window: u64,
    /// The window length in seconds (>= 1).
    pub window_secs: u64,
}

impl QuotaPolicy {
    /// Validate and construct (both fields must be >= 1).
    pub fn new(requests_per_window: u64, window_secs: u64) -> Result<Self, QuotaError> {
        if requests_per_window == 0 || window_secs == 0 {
            return Err(QuotaError::InvalidPolicy);
        }
        Ok(QuotaPolicy { requests_per_window, window_secs })
    }

    /// Documented model default for the free hosted tier (C3-005 owns the
    /// real product numbers).
    pub const FREE_TIER: QuotaPolicy = QuotaPolicy { requests_per_window: 60, window_secs: 60 };

    /// Documented model default for a standard tier.
    pub const STANDARD_TIER: QuotaPolicy = QuotaPolicy { requests_per_window: 600, window_secs: 60 };

    /// The window index containing `at`.
    pub fn window_of(&self, at: u64) -> u64 {
        at / self.window_secs
    }

    /// When the current window resets (unix seconds).
    pub fn window_reset_at(&self, at: u64) -> u64 {
        (self.window_of(at) + 1) * self.window_secs
    }
}

/// The quota decision (total: every request is under or over).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum QuotaDecision {
    /// Under the limit (for `consume`: this request was counted).
    Allowed { remaining: u64, reset_at: u64 },
    /// At/over the limit — the request is refused by the enforcement caller.
    Limited { retry_after_secs: u64, reset_at: u64 },
}

/// Errors of the quota model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaError {
    /// `requests_per_window` and `window_secs` must both be >= 1.
    InvalidPolicy,
}

impl fmt::Display for QuotaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QuotaError::InvalidPolicy => f.write_str("invalid quota policy (limits must be >= 1)"),
        }
    }
}

impl std::error::Error for QuotaError {}

/// The quota engine: per-(app, environment) policies, a default, and
/// windowed counters.
#[derive(Clone, Serialize, Deserialize)]
pub struct QuotaEngine {
    default_policy: QuotaPolicy,
    policies: EntryMap<(AppId, EnvironmentId), QuotaPolicy>,
    counters: EntryMap<(AppId, EnvironmentId, u64), u64>,
}

impl QuotaEngine {
    /// An engine with the given default policy applied to every
    /// (app, environment) without an explicit override.
    pub fn new(default_policy: QuotaPolicy) -> Self {
        QuotaEngine { default_policy, policies: EntryMap::new(), counters: EntryMap::new() }
    }

    /// The default policy for every (app, environment) without an override.
    pub fn default_policy(&self) -> QuotaPolicy {
        self.default_policy
    }

    /// The policy in force for (app, environment) (override or default).
    pub fn policy_for(&self, app: &AppId, env: &EnvironmentId) -> QuotaPolicy {
        self.policies
            .get(&(app.clone(), env.clone()))
            .copied()
            .unwrap_or(self.default_policy)
    }

    /// Set the per-(app, environment) policy override.
    pub fn set_policy(
        &mut self,
        app: &AppId,
        env: &EnvironmentId,
        policy: QuotaPolicy,
    ) -> Result<(), QuotaError> {
        if policy.requests_per_window == 0 || policy.window_secs == 0 {
            return Err(QuotaError::InvalidPolicy);
        }
        self.policies.insert((app.clone(), env.clone()), policy);
        Ok(())
    }

    /// The pure decision for (app, environment) at `at` — does NOT count.
    pub fn evaluate(&self, app: &AppId, env: &EnvironmentId, at: u64) -> QuotaDecision {
        let policy = self.policy_for(app, env);
        let window = policy.window_of(at);
        let used = self.counters.get(&(app.clone(), env.clone(), window)).copied().unwrap_or(0);
        if used < policy.requests_per_window {
            QuotaDecision::Allowed {
                remaining: policy.requests_per_window - used,
                reset_at: policy.window_reset_at(at),
            }
        } else {
            let reset_at = policy.window_reset_at(at);
            QuotaDecision::Limited { retry_after_secs: reset_at - at, reset_at }
        }
    }

    /// The decision AND the count: under the limit ⇒ the request is counted
    /// (idempotent per call — the enforcement caller invokes it once per
    /// admitted request); at/over ⇒ Limited and nothing is counted.
    pub fn consume(&mut self, app: &AppId, env: &EnvironmentId, at: u64) -> QuotaDecision {
        // Prune stale windows lazily (they can never be consulted again).
        self.prune(app, env, at);
        match self.evaluate(app, env, at) {
            QuotaDecision::Allowed { remaining, reset_at } => {
                let policy = self.policy_for(app, env);
                let window = policy.window_of(at);
                let key = (app.clone(), env.clone(), window);
                let counter = self.counters.entry(key).or_insert(0);
                *counter += 1;
                QuotaDecision::Allowed { remaining: remaining - 1, reset_at }
            }
            limited => limited,
        }
    }

    /// Drop counters for windows older than the current one.
    fn prune(&mut self, app: &AppId, env: &EnvironmentId, at: u64) {
        let policy = self.policy_for(app, env);
        let current = policy.window_of(at);
        let mut stale: Vec<(AppId, EnvironmentId, u64)> = Vec::new();
        for key in self.counters.keys() {
            if &key.0 == app && &key.1 == env && key.2 < current {
                stale.push(key.clone());
            }
        }
        for key in stale {
            self.counters.remove(&key);
        }
    }

    /// Total distinct tracked counters (audit/test).
    pub fn tracked_counters(&self) -> usize {
        self.counters.len()
    }
}

impl fmt::Debug for QuotaEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuotaEngine")
            .field("default_policy", &self.default_policy)
            .field("overrides", &self.policies.len())
            .field("counters", &self.counters.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> (AppId, EnvironmentId) {
        (
            AppId::parse("app_aaaaaaaaaaaaaaaa").unwrap(),
            EnvironmentId::parse("env_bbbbbbbbbbbbbbbb").unwrap(),
        )
    }

    #[test]
    fn policy_validation() {
        assert!(QuotaPolicy::new(0, 60).is_err());
        assert!(QuotaPolicy::new(60, 0).is_err());
        assert!(QuotaPolicy::new(1, 1).is_ok());
        assert!(QuotaPolicy::new(60, 60).is_ok());
        let mut engine = QuotaEngine::new(QuotaPolicy::FREE_TIER);
        let (app, env) = ids();
        // set_policy re-validates (struct literals bypass `new` by design —
        // the policy type is data, the constructor is the validator).
        assert!(engine
            .set_policy(&app, &env, QuotaPolicy { requests_per_window: 0, window_secs: 1 })
            .is_err());
    }

    #[test]
    fn window_math_is_fixed_and_deterministic() {
        let policy = QuotaPolicy::new(10, 60).unwrap();
        assert_eq!(policy.window_of(0), 0);
        assert_eq!(policy.window_of(59), 0);
        assert_eq!(policy.window_of(60), 1);
        assert_eq!(policy.window_of(119), 1);
        assert_eq!(policy.window_reset_at(59), 60);
        assert_eq!(policy.window_reset_at(61), 120);
    }

    #[test]
    fn consume_counts_within_the_window_and_limits_at_the_boundary() {
        let mut engine = QuotaEngine::new(QuotaPolicy::new(3, 60).unwrap());
        let (app, env) = ids();
        for i in 0..3 {
            assert!(matches!(
                engine.consume(&app, &env, 100 + i),
                QuotaDecision::Allowed { .. }
            ));
        }
        // The 4th request inside the same window: limited, nothing counted.
        assert_eq!(
            engine.consume(&app, &env, 119),
            QuotaDecision::Limited { retry_after_secs: 1, reset_at: 120 }
        );
        // New window: budget restored.
        assert!(matches!(engine.consume(&app, &env, 120), QuotaDecision::Allowed { .. }));
    }

    #[test]
    fn remaining_counts_down() {
        let mut engine = QuotaEngine::new(QuotaPolicy::new(3, 60).unwrap());
        let (app, env) = ids();
        assert_eq!(engine.evaluate(&app, &env, 10), QuotaDecision::Allowed { remaining: 3, reset_at: 60 });
        assert_eq!(engine.consume(&app, &env, 10), QuotaDecision::Allowed { remaining: 2, reset_at: 60 });
        assert_eq!(engine.consume(&app, &env, 11), QuotaDecision::Allowed { remaining: 1, reset_at: 60 });
        assert_eq!(engine.consume(&app, &env, 12), QuotaDecision::Allowed { remaining: 0, reset_at: 60 });
        assert_eq!(engine.evaluate(&app, &env, 13), QuotaDecision::Limited { retry_after_secs: 47, reset_at: 60 });
    }

    #[test]
    fn per_app_environment_isolation_and_policy_override() {
        let mut engine = QuotaEngine::new(QuotaPolicy::new(1, 60).unwrap());
        let (app_a, env_a) = ids();
        let app_b = AppId::parse("app_cccccccccccccccc").unwrap();
        let env_b = EnvironmentId::parse("env_dddddddddddddddd").unwrap();
        // A consumes the whole default budget; B is unaffected.
        assert!(matches!(engine.consume(&app_a, &env_a, 10), QuotaDecision::Allowed { .. }));
        assert!(matches!(engine.consume(&app_a, &env_a, 11), QuotaDecision::Limited { .. }));
        assert!(matches!(engine.consume(&app_b, &env_b, 11), QuotaDecision::Allowed { .. }));
        // Override A's policy: budget restored immediately.
        engine.set_policy(&app_a, &env_a, QuotaPolicy::new(10, 60).unwrap()).unwrap();
        assert!(matches!(engine.consume(&app_a, &env_a, 12), QuotaDecision::Allowed { .. }));
        assert_eq!(engine.policy_for(&app_a, &env_a), QuotaPolicy::new(10, 60).unwrap());
        assert_eq!(engine.policy_for(&app_b, &env_b), QuotaPolicy::new(1, 60).unwrap());
    }

    #[test]
    fn stale_windows_are_pruned_lazily() {
        let mut engine = QuotaEngine::new(QuotaPolicy::new(100, 60).unwrap());
        let (app, env) = ids();
        engine.consume(&app, &env, 10);
        assert_eq!(engine.tracked_counters(), 1);
        // Each consume prunes windows older than the current one — they can
        // never be consulted again (evaluate only reads the current window).
        engine.consume(&app, &env, 70);
        assert_eq!(engine.tracked_counters(), 1, "previous window is pruned eagerly");
        engine.consume(&app, &env, 130);
        assert_eq!(engine.tracked_counters(), 1);
        // A second app's counters are independent of the pruning.
        let (app_b, env_b) = (
            AppId::parse("app_cccccccccccccccc").unwrap(),
            EnvironmentId::parse("env_dddddddddddddddd").unwrap(),
        );
        engine.consume(&app_b, &env_b, 70);
        assert_eq!(engine.tracked_counters(), 2);
    }

    #[test]
    fn presets_are_sane() {
        assert_eq!(QuotaPolicy::FREE_TIER.requests_per_window, 60);
        assert_eq!(QuotaPolicy::STANDARD_TIER.requests_per_window, 600);
        assert_eq!(QuotaPolicy::FREE_TIER.window_secs, 60);
    }
}
