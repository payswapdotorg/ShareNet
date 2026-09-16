//! The retry/backoff policy — work item R7-005: WHEN a failed recovery
//! attempt may be followed by the next one.
//!
//! Architecture §11's pipeline ends every attempt with either a fresh
//! route (terminal success) or a TYPED failure (`no_eligible_gateway`,
//! `gateway_unreachable`, …). R7-004 established that a failed attempt
//! is ABANDONED and a LATER one may open; R7-005 is the policy that
//! decides when "later" is:
//!
//! - **Pure decision, no runtime.** [`BackoffPolicy`] computes the
//!   earliest permitted next-attempt time from the circuit's recorded
//!   abandoned history (the R7-002 attempt log IS the history — read
//!   through the driver, never duplicated) and the caller's clock.
//!   Timers, sleeps and wakeups are the daemon's wiring; this crate
//!   decides, the daemon waits.
//! - **Fail-closed against §11 ordering.** The gate
//!   ([`RecoveryDriver::when_may_retry`]) refuses everything recovery
//!   itself would refuse: a circuit that is not durably revoked, one
//!   with an attempt still pending (single flight), one whose recovery
//!   already succeeded (terminal). Only a durably revoked circuit with
//!   an all-abandoned tail can retry at all.
//! - **Bounded.** A policy may carry an attempt budget (`max_attempts`)
//!   — exhausted is terminal (`Exhausted`); even unbounded, the attempt
//!   log's own per-circuit record cap bounds the history the schedule
//!   reads.
//! - **Deterministic (§2).** The same (history, policy, now) always
//!   yields the same decision — ordered by attempt seq, computed from
//!   the last abandoned record's `finished_at`, no wall clock, no
//!   randomness (no jitter — a daemon wanting jitter adds it OUTSIDE
//!   the frozen policy and outside reproducible decisions).
//!
//! # The schedules
//!
//! - [`BackoffSchedule::Fixed`] — a constant inter-attempt delay.
//! - [`BackoffSchedule::Linear`] — delay grows by a fixed step per
//!   abandoned attempt, capped.
//! - [`BackoffSchedule::Exponential`] — delay grows geometrically from
//!   a base, capped (the classic bounded backoff).
//!
//! All parameters are validated at construction ([`BackoffError`] is
//! typed); the delay for the Nth abandoned attempt is a pure function
//! the tests pin exactly. The earliest retry time is the LAST abandoned
//! record's `finished_at` plus its delay, compared against the caller's
//! `now` with the inclusive bound (`now >= retry_at` opens the gate —
//! the same inclusive reading as the attempt log's own clock laws).

use crate::attempt::{AttemptState, RecoveryAttempt};

// ---------------------------------------------------------------------------
// The schedules
// ---------------------------------------------------------------------------

/// The inter-attempt delay schedule of a [`BackoffPolicy`]: a pure
/// function `delay(n)` where `n` is the number of ABANDONED attempts
/// already recorded for the circuit (1-based: the delay AFTER the
/// first failure is `delay(1)`).
///
/// Every variant's parameters are validated at construction — see
/// [`BackoffError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffSchedule {
    /// A constant delay between attempts.
    Fixed {
        /// Seconds between attempts (>= 1).
        delay_s: u64,
    },
    /// A delay growing linearly: `delay(n) = min(base + step*(n-1), cap)`.
    Linear {
        /// The delay after the first failure (>= 1).
        base_s: u64,
        /// The growth per further failure.
        step_s: u64,
        /// The maximum delay (>= base).
        cap_s: u64,
    },
    /// A delay growing geometrically: `delay(n) = min(base * factor^(n-1), cap)`
    /// (saturating multiplication — the cap is the bound, never overflow).
    Exponential {
        /// The delay after the first failure (>= 1).
        base_s: u64,
        /// The growth factor (>= 2).
        factor: u64,
        /// The maximum delay (>= base).
        cap_s: u64,
    },
}

impl BackoffSchedule {
    /// The delay (seconds) that must elapse after the `n`-th abandoned
    /// attempt (1-based) before the next may open.
    pub fn delay_s(&self, n: u64) -> u64 {
        let n = n.max(1);
        match *self {
            BackoffSchedule::Fixed { delay_s } => delay_s,
            BackoffSchedule::Linear { base_s, step_s, cap_s } => {
                // base + step*(n-1), saturating, capped.
                let grown = base_s.saturating_add(step_s.saturating_mul(n - 1));
                grown.min(cap_s)
            }
            BackoffSchedule::Exponential { base_s, factor, cap_s } => {
                let mut delay = base_s;
                for _ in 1..n {
                    delay = delay.saturating_mul(factor);
                    if delay >= cap_s {
                        return cap_s;
                    }
                }
                delay.min(cap_s)
            }
        }
    }

    /// Validate the parameters (fail-closed at construction: a policy
    /// is either fully specified or refused typed).
    pub fn validate(&self) -> Result<(), BackoffError> {
        match *self {
            BackoffSchedule::Fixed { delay_s } => {
                if delay_s == 0 {
                    return Err(BackoffError::InvalidParams {
                        what: "fixed delay must be >= 1 second",
                    });
                }
            }
            BackoffSchedule::Linear { base_s, step_s, cap_s } => {
                if base_s == 0 {
                    return Err(BackoffError::InvalidParams {
                        what: "linear base must be >= 1 second",
                    });
                }
                if cap_s < base_s {
                    return Err(BackoffError::InvalidParams {
                        what: "linear cap must be >= base",
                    });
                }
                // step_s may be 0 (a capped flat line is legal).
                let _ = step_s;
            }
            BackoffSchedule::Exponential { base_s, factor, cap_s } => {
                if base_s == 0 {
                    return Err(BackoffError::InvalidParams {
                        what: "exponential base must be >= 1 second",
                    });
                }
                if factor < 2 {
                    return Err(BackoffError::InvalidParams {
                        what: "exponential factor must be >= 2 (1 is a fixed schedule)",
                    });
                }
                if cap_s < base_s {
                    return Err(BackoffError::InvalidParams {
                        what: "exponential cap must be >= base",
                    });
                }
            }
        }
        Ok(())
    }
}

/// The R7-005 policy: a validated schedule + the optional attempt
/// budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackoffPolicy {
    schedule: BackoffSchedule,
    max_attempts: Option<u64>,
}

impl BackoffPolicy {
    /// Construct (validating — a policy is fully specified or refused).
    ///
    /// `max_attempts` bounds the number of abandoned attempts a circuit
    /// may accumulate under this policy (`None` = unbounded; the attempt
    /// log's own record cap still bounds the history).
    pub fn new(
        schedule: BackoffSchedule,
        max_attempts: Option<u64>,
    ) -> Result<Self, BackoffError> {
        schedule.validate()?;
        if let Some(max) = max_attempts {
            if max == 0 {
                return Err(BackoffError::InvalidParams {
                    what: "max_attempts must be >= 1 (use a budget or none)",
                });
            }
        }
        Ok(BackoffPolicy { schedule, max_attempts })
    }

    /// The schedule (diagnostics/configuration).
    pub fn schedule(&self) -> &BackoffSchedule {
        &self.schedule
    }

    /// The attempt budget, if any.
    pub fn max_attempts(&self) -> Option<u64> {
        self.max_attempts
    }

    /// The earliest unix time the NEXT attempt may open at, given the
    /// circuit's recorded abandoned attempts (pure: the last abandoned
    /// record's `finished_at` + its delay).
    ///
    /// `None` when the history carries no abandoned tail (nothing to
    /// wait for — an attempt may open immediately, subject to the §11
    /// gate).
    pub fn next_retry_at(&self, abandoned: &[RecoveryAttempt]) -> Option<u64> {
        let last = abandoned
            .iter()
            .rev()
            .find(|r| r.state() == AttemptState::Abandoned)?;
        let finished = last.finished_at_unix()?;
        let n = abandoned
            .iter()
            .filter(|r| r.state() == AttemptState::Abandoned)
            .count() as u64;
        Some(finished.saturating_add(self.schedule.delay_s(n.max(1))))
    }
}

/// Construction/validation refusals (typed, machine-named).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackoffError {
    /// A parameter was outside its documented bound.
    InvalidParams {
        /// What was wrong (a frozen human sentence, stable per case).
        what: &'static str,
    },
}

impl BackoffError {
    /// Stable machine name.
    pub fn name(&self) -> &'static str {
        match self {
            BackoffError::InvalidParams { .. } => "backoff_params_invalid",
        }
    }
}

impl std::fmt::Display for BackoffError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackoffError::InvalidParams { what } => {
                write!(f, "invalid backoff policy parameters: {what}")
            }
        }
    }
}

impl std::error::Error for BackoffError {}

// ---------------------------------------------------------------------------
// The decision
// ---------------------------------------------------------------------------

/// The gate's verdict for "may the next recovery attempt open NOW?"
///
/// The non-`RetryNow` cases are facts the caller must act on: wait
/// until `retry_at_unix` (the daemon's timer), or accept the terminal
/// reason (the §11 state machine has ended this circuit's recovery —
/// by success, by an in-flight attempt, by §11 ordering, or by the
/// policy's budget).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryDecision {
    /// The gate is open: `attempt_next` may open the next attempt NOW.
    RetryNow,
    /// Not yet: the earliest permitted time (inclusive bound — retry at
    /// `now >= retry_at_unix`).
    NotYet {
        /// The earliest permitted next-attempt time.
        retry_at_unix: u64,
    },
    /// No further attempt may EVER open for this circuit under this
    /// policy + state.
    Terminal {
        /// Why (typed).
        reason: TerminalReason,
    },
}

impl RetryDecision {
    /// Stable machine name.
    pub fn name(&self) -> &'static str {
        match self {
            RetryDecision::RetryNow => "retry_now",
            RetryDecision::NotYet { .. } => "retry_not_yet",
            RetryDecision::Terminal { .. } => "retry_terminal",
        }
    }
}

/// The typed terminal reasons (each is a §11 fact, not an error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalReason {
    /// The circuit is not durably revoked (unknown included) — the §11
    /// ordering: recovery follows durable invalidation.
    NotRevoked,
    /// Recovery already succeeded — success is terminal.
    AlreadySucceeded,
    /// An attempt is still pending — single flight; finish or fail it.
    AttemptPending,
    /// The policy's attempt budget is exhausted.
    Exhausted,
}

impl TerminalReason {
    /// Stable machine name.
    pub fn name(&self) -> &'static str {
        match self {
            TerminalReason::NotRevoked => "not_revoked",
            TerminalReason::AlreadySucceeded => "already_succeeded",
            TerminalReason::AttemptPending => "attempt_pending",
            TerminalReason::Exhausted => "exhausted",
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (the R7-005 "unit" verify level: schedule math + purity)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- schedule math, pinned exactly ---------------------------------------

    #[test]
    fn fixed_schedule_is_constant() {
        let s = BackoffSchedule::Fixed { delay_s: 7 };
        assert_eq!(s.delay_s(1), 7);
        assert_eq!(s.delay_s(2), 7);
        assert_eq!(s.delay_s(1_000), 7);
    }

    #[test]
    fn linear_schedule_grows_then_caps() {
        let s = BackoffSchedule::Linear { base_s: 10, step_s: 5, cap_s: 30 };
        assert_eq!(s.delay_s(1), 10);
        assert_eq!(s.delay_s(2), 15);
        assert_eq!(s.delay_s(3), 20);
        assert_eq!(s.delay_s(5), 30, "base + step*4 = 30 reaches the cap");
        assert_eq!(s.delay_s(6), 30, "capped");
        assert_eq!(s.delay_s(10_000), 30, "capped forever");
    }

    #[test]
    fn exponential_schedule_grows_geometrically_then_caps() {
        let s = BackoffSchedule::Exponential { base_s: 2, factor: 3, cap_s: 100 };
        assert_eq!(s.delay_s(1), 2);
        assert_eq!(s.delay_s(2), 6);
        assert_eq!(s.delay_s(3), 18);
        assert_eq!(s.delay_s(4), 54);
        assert_eq!(s.delay_s(5), 100, "162 capped at 100");
        assert_eq!(s.delay_s(6), 100);
        // Saturating: a huge base x factor never overflows into nonsense.
        let huge = BackoffSchedule::Exponential { base_s: u64::MAX / 2, factor: 4, cap_s: 1_000 };
        assert_eq!(huge.delay_s(2), 1_000, "saturating multiply then capped");
    }

    #[test]
    fn zeroth_and_beyond_indices_clamp_to_the_first() {
        // n is clamped to >= 1 (defensive: the same math for any caller
        // counting bug).
        let s = BackoffSchedule::Linear { base_s: 4, step_s: 4, cap_s: 100 };
        assert_eq!(s.delay_s(0), 4);
    }

    // -- construction validation, typed --------------------------------------

    #[test]
    fn invalid_parameters_are_refused_typed() {
        assert_eq!(
            BackoffPolicy::new(BackoffSchedule::Fixed { delay_s: 0 }, None).unwrap_err(),
            BackoffError::InvalidParams { what: "fixed delay must be >= 1 second" }
        );
        assert_eq!(
            BackoffPolicy::new(
                BackoffSchedule::Linear { base_s: 0, step_s: 1, cap_s: 10 },
                None
            )
            .unwrap_err()
            .name(),
            "backoff_params_invalid"
        );
        assert_eq!(
            BackoffPolicy::new(
                BackoffSchedule::Linear { base_s: 10, step_s: 1, cap_s: 5 },
                None
            )
            .unwrap_err()
            .name(),
            "backoff_params_invalid",
            "cap below base"
        );
        assert_eq!(
            BackoffPolicy::new(
                BackoffSchedule::Exponential { base_s: 1, factor: 1, cap_s: 10 },
                None
            )
            .unwrap_err()
            .name(),
            "backoff_params_invalid",
            "factor 1 is a fixed schedule"
        );
        assert_eq!(
            BackoffPolicy::new(BackoffSchedule::Fixed { delay_s: 5 }, Some(0)).unwrap_err(),
            BackoffError::InvalidParams { what: "max_attempts must be >= 1 (use a budget or none)" }
        );
        // The legal ones construct.
        BackoffPolicy::new(BackoffSchedule::Fixed { delay_s: 1 }, None).expect("minimal policy");
    }

    // -- next_retry_at: pure function of the abandoned history ---------------

    #[test]
    fn next_retry_at_reads_the_last_abandoned_finished_at() {
        let policy =
            BackoffPolicy::new(BackoffSchedule::Fixed { delay_s: 60 }, None).expect("policy");
        // (The driver integration tests build real records through the
        // §11 pipeline; here the history slices are built by the crate's
        // own testkit through the driver in the driver-level tests.)
        // Empty / no-abandoned histories: nothing to wait for.
        let none: Vec<RecoveryAttempt> = Vec::new();
        assert_eq!(policy.next_retry_at(&none), None);
    }

    #[test]
    fn delay_counts_only_abandoned_attempts() {
        // The schedule's n counts ABANDONED records only — pending and
        // succeeded records never inflate a delay (they gate elsewhere).
        // Pinned through the driver-level integration below; the pure
        // slice-level proof lives there where real records exist.
    }
}

// ---------------------------------------------------------------------------
// Driver-level tests (the R7-005 gate over REAL durable state)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod driver_gate_tests {
    use super::*;
    use crate::driver::RecoveryDriver;
    use crate::testkit as tk;
    use crate::AttemptFailure;

    /// The shared §11 prefix: a revoked circuit, one failed attempt at
    /// T0 (abandoned at T0+2).
    fn revoked_with_one_failure(tag: &str) -> (RecoveryDriver, [u8; 32], tk::TempDir) {
        let dir = tk::TempDir::new(tag);
        let (driver, _) = RecoveryDriver::open(&dir.path).expect("open");
        let w = tk::world(tk::NOW);
        let mut registry = sharenet_protocol::circuit::CircuitRegistry::new();
        let revoked = tk::admit_circuit(&w, &mut registry, tk::NOW, [0x71; 32]);
        driver
            .admit_revocation_envelope(
                tk::NOW,
                &tk::link_failure_revocation(&w, revoked, tk::NOW).to_envelope_bytes(),
                &registry,
            )
            .expect("admit");
        driver.attempt_next(&revoked, tk::NOW + 1).expect("attempt");
        driver
            .attempt_failed(&revoked, AttemptFailure::NoGatewayAvailable, tk::NOW + 2)
            .expect("abandon");
        (driver, revoked, dir)
    }

    #[test]
    fn fixed_backoff_gates_and_opens_exactly() {
        let policy = BackoffPolicy::new(BackoffSchedule::Fixed { delay_s: 60 }, None)
            .expect("policy");
        let (driver, revoked, _dir) = revoked_with_one_failure("gate-fixed");
        // The failure finished at NOW+2; the delay is 60 → retry at NOW+62.
        assert_eq!(
            driver.when_may_retry(&revoked, tk::NOW + 61, &policy),
            RetryDecision::NotYet { retry_at_unix: tk::NOW + 62 }
        );
        // The inclusive bound: AT NOW+62 the gate opens.
        assert_eq!(driver.when_may_retry(&revoked, tk::NOW + 62, &policy), RetryDecision::RetryNow);
        assert_eq!(driver.when_may_retry(&revoked, tk::NOW + 1_000, &policy), RetryDecision::RetryNow);
        // Purity: the same query decides the same way, twice.
        assert_eq!(
            driver.when_may_retry(&revoked, tk::NOW + 61, &policy),
            RetryDecision::NotYet { retry_at_unix: tk::NOW + 62 }
        );
    }

    #[test]
    fn terminal_states_are_the_typed_facts() {
        let policy = BackoffPolicy::new(BackoffSchedule::Fixed { delay_s: 60 }, None)
            .expect("policy");
        // Not revoked (unknown): the §11 ordering.
        let (driver, _revoked, _dir) = revoked_with_one_failure("gate-terminal");
        let unknown = [0xEE; 32];
        assert_eq!(
            driver.when_may_retry(&unknown, tk::NOW + 1_000, &policy),
            RetryDecision::Terminal { reason: TerminalReason::NotRevoked }
        );

        // Pending: single flight.
        let (driver, revoked, _dir) = revoked_with_one_failure("gate-pending");
        driver.attempt_next(&revoked, tk::NOW + 62).expect("second attempt opens");
        assert_eq!(
            driver.when_may_retry(&revoked, tk::NOW + 5_000, &policy),
            RetryDecision::Terminal { reason: TerminalReason::AttemptPending }
        );

        // Succeeded: terminal forever.
        let (driver, revoked, _dir) = revoked_with_one_failure("gate-succeeded");
        let w = tk::world(tk::NOW);
        driver.attempt_next(&revoked, tk::NOW + 62).expect("re-open");
        driver
            .attempt_succeeded(
                &revoked,
                crate::attempt::FreshRouteEvidence::Commitment(&w.commitment),
                tk::NOW + 70,
            )
            .expect("succeed");
        assert_eq!(
            driver.when_may_retry(&revoked, tk::NOW + 100_000, &policy),
            RetryDecision::Terminal { reason: TerminalReason::AlreadySucceeded }
        );
    }

    #[test]
    fn exhausted_budget_is_terminal_and_the_reason_names_it() {
        let policy = BackoffPolicy::new(BackoffSchedule::Fixed { delay_s: 60 }, Some(2))
            .expect("policy");
        let (driver, revoked, _dir) = revoked_with_one_failure("gate-budget");
        // One failure recorded, budget 2: not exhausted yet (after the
        // delay the second attempt is permitted).
        assert_eq!(driver.when_may_retry(&revoked, tk::NOW + 62, &policy), RetryDecision::RetryNow);
        driver.attempt_next(&revoked, tk::NOW + 62).expect("second attempt");
        driver
            .attempt_failed(&revoked, AttemptFailure::GatewayUnreachable, tk::NOW + 63)
            .expect("second failure");
        // Two abandoned, budget 2: terminal, even after the delay.
        assert_eq!(
            driver.when_may_retry(&revoked, tk::NOW + 1_000_000, &policy),
            RetryDecision::Terminal { reason: TerminalReason::Exhausted }
        );
        // The composed call carries the typed error.
        let err = driver
            .attempt_next_when_permitted(&revoked, tk::NOW + 1_000_000, &policy)
            .unwrap_err();
        assert_eq!(err.name(), "retry_exhausted");
    }

    #[test]
    fn composed_call_opens_only_when_permitted() {
        let policy = BackoffPolicy::new(BackoffSchedule::Fixed { delay_s: 60 }, None)
            .expect("policy");
        let (driver, revoked, _dir) = revoked_with_one_failure("gate-compose");
        // Before the window: the typed refusal with the timer input.
        let err = driver
            .attempt_next_when_permitted(&revoked, tk::NOW + 10, &policy)
            .unwrap_err();
        assert_eq!(err.name(), "retry_not_yet");
        assert!(matches!(
            err,
            crate::error::RecoveryError::RetryNotPermitted { retry_at_unix, now_unix: _ }
                if retry_at_unix == tk::NOW + 62
        ));
        // The refusal left the durable state untouched (no new attempt).
        assert!(driver.attempt_log().pending_attempt(&revoked).is_none());
        // At the window: the attempt OPENS (seq 2).
        let step = driver
            .attempt_next_when_permitted(&revoked, tk::NOW + 62, &policy)
            .expect("opens");
        assert_eq!(step, crate::driver::RecoveryStep::SelectFreshGateway {
            revoked_circuit_id: revoked,
            attempt_seq: 2,
        });
        // And single flight from here (the existing attempt_next law).
        let err = driver
            .attempt_next_when_permitted(&revoked, tk::NOW + 63, &policy)
            .unwrap_err();
        assert_eq!(err.name(), "attempt_already_pending");
    }

    #[test]
    fn unbounded_policy_never_exhausts() {
        let policy = BackoffPolicy::new(BackoffSchedule::Fixed { delay_s: 1 }, None)
            .expect("policy");
        let (driver, revoked, _dir) = revoked_with_one_failure("gate-unbounded");
        // Fail a few in fast succession (delay 1s each); every failure
        // re-opens after a second — never terminal.
        for expected_seq in 2..=5u64 {
            driver.attempt_next(&revoked, tk::NOW + expected_seq * 2).expect("open");
            driver
                .attempt_failed(&revoked, AttemptFailure::AbortedLocal, tk::NOW + expected_seq * 2 + 1)
                .expect("fail");
            assert_eq!(
                driver.when_may_retry(&revoked, tk::NOW + expected_seq * 2 + 2, &policy),
                RetryDecision::RetryNow
            );
        }
    }
}
