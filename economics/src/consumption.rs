//! R8-004: priority/perk consumption — the SPENDING side of Civic
//! Points (architecture §13: *"Civic Points may provide: priority in
//! ShareNet resource scheduling; preferential access to shared
//! gateways..."*).
//!
//! This module lifts R8-003's v1 no-spend law DELIBERATELY and only
//! here: balances decrease through typed, durable, exactly-once SPEND
//! entries. Every other mutation path still only increases balances.
//!
//! # The frozen v1 perk vocabulary
//!
//! - **priority_scheduling**: a bounded-time grant of the `live`
//!   service class for the contributor's DTN propagation (the §13
//!   "priority in ShareNet resource scheduling", expressed in the SAME
//!   frozen ServicePriority vocabulary the DTN store orders by — no
//!   second vocabulary). Consumption = a spend entry + a grant record
//!   (valid `[spend_at, spend_at + duration)`).
//! - **gateway_preference**: a bounded-time preferential-access mark
//!   for shared gateways (the §11 recovery's gateway selection MAY
//!   consult it; v1 records the grant, the selection composition is
//!   the daemon's).
//!
//! Fee reductions, sponsored connectivity and community rewards (§13's
//! other uses) are settlement/community-program scope — deliberately
//! NOT protocol perks (§13: monetary rewards are a separate settlement
//! program; the protocol does not make points intrinsically redeemable
//! for money).
//!
//! # The laws
//!
//! 1. **Spends are the only decrement.** `spend()` is the one path that
//!    reduces a balance; it is typed, durable (append + fsync in the
//!    file-backed form) and exactly-once per `spend_id`.
//! 2. **No overdraft.** A spend beyond the balance refuses typed;
//!    nothing moves.
//! 3. **Grants are derived, never asserted.** A grant exists only as
//!    the replay of spend entries — callers cannot fabricate one; the
//!    expiry is enforced at read time against the caller's clock.
//! 4. **Priority is the DTN's own vocabulary.** The priority grant
//!    maps onto `live` (the class the store's carry order already
//!    puts first); nothing re-implements ordering.

use std::fmt;

use crate::ledger::LedgerError;

/// The frozen v1 perk kinds (machine names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PerkKind {
    /// "priority_scheduling" — a bounded-time `live`-class grant.
    PriorityScheduling,
    /// "gateway_preference" — a bounded-time preferential-access mark.
    GatewayPreference,
}

impl PerkKind {
    pub const ALL: [PerkKind; 2] = [
        PerkKind::PriorityScheduling,
        PerkKind::GatewayPreference,
    ];

    /// The frozen machine name.
    pub fn as_str(&self) -> &'static str {
        match self {
            PerkKind::PriorityScheduling => "priority_scheduling",
            PerkKind::GatewayPreference => "gateway_preference",
        }
    }

    /// Parse from the machine name (strict; anything else is None).
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "priority_scheduling" => Some(PerkKind::PriorityScheduling),
            "gateway_preference" => Some(PerkKind::GatewayPreference),
            _ => None,
        }
    }
}

impl fmt::Display for PerkKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A consumption failure (typed, machine-named).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpendError {
    PerkUnknown { found: String },
    PointsZero,
    DurationZero,
    /// The balance cannot cover the spend; nothing moved.
    InsufficientBalance { balance: u64, requested: u64 },
    /// The spend_id was already spent — exactly-once (idempotent
    /// re-delivery reports the FIRST spend, nothing moves).
    DuplicateSpend { spend_id: [u8; 32] },
    Ledger(LedgerError),
}

impl fmt::Display for SpendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpendError::PerkUnknown { found } => write!(f, "perk {found:?} not in the frozen set"),
            SpendError::PointsZero => write!(f, "a spend must be at least 1 point"),
            SpendError::DurationZero => write!(f, "a grant duration must be positive"),
            SpendError::InsufficientBalance { balance, requested } => write!(
                f,
                "insufficient balance: {balance} < {requested}"
            ),
            SpendError::DuplicateSpend { spend_id } => write!(
                f,
                "spend {} already consumed (exactly-once)",
                hex32(&spend_id)
            ),
            SpendError::Ledger(e) => write!(f, "ledger: {e}"),
        }
    }
}

impl std::error::Error for SpendError {}

impl From<LedgerError> for SpendError {
    fn from(e: LedgerError) -> Self {
        SpendError::Ledger(e)
    }
}

impl SpendError {
    /// Stable machine name.
    pub fn name(&self) -> &'static str {
        match self {
            SpendError::PerkUnknown { .. } => "perk_unknown",
            SpendError::PointsZero => "points_zero",
            SpendError::DurationZero => "duration_zero",
            SpendError::InsufficientBalance { .. } => "insufficient_balance",
            SpendError::DuplicateSpend { .. } => "duplicate_spend",
            SpendError::Ledger(_) => "ledger",
        }
    }
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// One active grant (derived by replay, read with the caller's clock).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveGrant {
    pub perk: PerkKind,
    /// The grant's own identifier (the spend_id).
    pub spend_id: [u8; 32],
    pub points_spent: u64,
    pub valid_from_unix: u64,
    pub valid_until_unix: u64,
}

impl ActiveGrant {
    /// Whether the grant covers `now`.
    pub fn covers(&self, now_unix: u64) -> bool {
        now_unix >= self.valid_from_unix && now_unix < self.valid_until_unix
    }
}
