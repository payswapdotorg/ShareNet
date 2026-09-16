//! R8-003: the Civic Point ledger — the durable form of the R8-002
//! valuation (architecture §13: *"Civic Points are earned only from
//! verified useful work"*; the ledger is what makes the earning DURABLE).
//!
//! The ledger composes the valuation engine: `award(receipt, now)`
//! prices the receipt through the SAME R8-002 law (kind weights,
//! per-receipt byte cap, window caps, receipt_id idempotency,
//! future-clock refusal) and, when the award is non-zero, appends a
//! [`LedgerEntry`] — the registered CivicPointLedgerEntry durable-state
//! record (contributor, awarded + intrinsic points, the formula
//! version that priced it, the receipt_id evidence link, the window,
//! the append clock).
//!
//! # The laws
//!
//! 1. **The engine prices, the ledger records.** Points are never
//!    caller-supplied — every entry's arithmetic is re-derived from the
//!    receipt through the composed engine.
//! 2. **Exactly-once per receipt_id.** A duplicate is an idempotent
//!    no-op (the engine's own idempotency composed with the entry
//!    log's); a refusal records nothing.
//! 3. **Balances only ever increase (v1).** Spending/perk consumption
//!    is R8-004's and is deliberately absent — there is no code path
//!    here that decrements a balance.
//! 4. **The log is the truth.** Every read view (balances, totals) is
//!    derived by replaying the append-only entries — the snapshot
//!    round-trips byte-identically and reloads fail closed.
//! 5. **Concurrency-safe by construction.** Interior-mutable state
//!    behind one lock (the ReceiptLedger pattern); concurrent award
//!    paths serialize through it with exactly-once semantics.
//!
//! Node-local scope (honest): entries are THIS node's durable
//! accounting, not a cross-node claim — no signature (durable-state,
//! not wire); cross-node balance forms are a future decision if ever
//! (§13 keeps monetary settlement a separate program entirely).

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use sharenet_protocol::cbor::{decode, encode, Value};
use sharenet_protocol::contribution::ContributionReceipt;

use crate::{ValuationEngine, ValuationPolicy, ValuationVerdict, VALUATION_FORMULA_VERSION};

/// The CivicPointLedgerEntry wire version (the durable-state record).
pub const CIVIC_LEDGER_ENTRY_VERSION: i64 = 1;
/// The one frozen v1 entry kind: an award.
pub const ENTRY_KIND_AWARD: i64 = 1;

// ---------------------------------------------------------------------------
// Errors (typed, fail-closed)
// ---------------------------------------------------------------------------

/// A ledger failure (typed, machine-named).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    SnapshotVersion { found: i64 },
    SnapshotMalformed { reason: String },
    FileIo { op: &'static str, source: String },
}

impl fmt::Display for LedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LedgerError::SnapshotVersion { found } => {
                write!(f, "snapshot version {found} != {CIVIC_LEDGER_ENTRY_VERSION}")
            }
            LedgerError::SnapshotMalformed { reason } => {
                write!(f, "snapshot malformed: {reason}")
            }
            LedgerError::FileIo { op, source } => write!(f, "{op}: {source}"),
        }
    }
}

impl std::error::Error for LedgerError {}

impl LedgerError {
    /// Stable machine name.
    pub fn name(&self) -> &'static str {
        match self {
            LedgerError::SnapshotVersion { .. } => "snapshot_version",
            LedgerError::SnapshotMalformed { .. } => "snapshot_malformed",
            LedgerError::FileIo { .. } => "file_io",
        }
    }
}

// ---------------------------------------------------------------------------
// The entry (the registered durable-state record)
// ---------------------------------------------------------------------------

/// One durable award record — the CivicPointLedgerEntry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// The node the points accrued to.
    pub contributor: [u8; 32],
    /// The ISSUER of the priced receipt (the pair's other half — the
    /// reload reconstructs the per-(issuer, contributor) window cap
    /// state from this; a restart must NOT reset the caps).
    pub issuer: [u8; 32],
    /// The post-cap award (>= 1 — zero-point capped receipts record
    /// nothing).
    pub awarded_points: u64,
    /// The pre-cap formula value (the honest pricing record).
    pub intrinsic_points: u64,
    /// The formula version that priced this entry.
    pub formula_version: u32,
    /// The receipt this award priced (the evidence link).
    pub receipt_id: [u8; 32],
    /// The valuation window the award landed in.
    pub window: u64,
    /// The ledger's append clock.
    pub recorded_at_unix: u64,
}

impl LedgerEntry {
    /// Canonical CBOR (the registry schema).
    pub fn to_wire(&self) -> Vec<u8> {
        encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(CIVIC_LEDGER_ENTRY_VERSION)),
            (Value::Int(2), Value::Int(ENTRY_KIND_AWARD)),
            (Value::Int(3), Value::Bytes(self.contributor.to_vec())),
            (Value::Int(4), Value::Int(self.awarded_points as i64)),
            (Value::Int(5), Value::Int(self.intrinsic_points as i64)),
            (Value::Int(6), Value::Int(self.formula_version as i64)),
            (Value::Int(7), Value::Bytes(self.receipt_id.to_vec())),
            (Value::Int(8), Value::Int(self.window as i64)),
            (Value::Int(9), Value::Int(self.recorded_at_unix as i64)),
            (Value::Int(10), Value::Bytes(self.issuer.to_vec())),
        ]))
        .expect("in-profile entry")
    }

    /// Strict parse (fail-closed, typed).
    pub fn from_wire(bytes: &[u8]) -> Result<Self, LedgerError> {
        let v = decode(bytes).map_err(|e| LedgerError::SnapshotMalformed {
            reason: format!("entry cbor: {e}"),
        })?;
        let Value::Map(entries) = v else {
            return Err(LedgerError::SnapshotMalformed {
                reason: "entry not a map".into(),
            });
        };
        let mut contributor: Option<[u8; 32]> = None;
        let mut issuer: Option<[u8; 32]> = None;
        let mut awarded: Option<u64> = None;
        let mut intrinsic: Option<u64> = None;
        let mut formula: Option<u32> = None;
        let mut receipt: Option<[u8; 32]> = None;
        let mut window: Option<u64> = None;
        let mut recorded: Option<u64> = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(LedgerError::SnapshotMalformed {
                    reason: "entry key not an integer".into(),
                });
            };
            let bad = |what: &str| LedgerError::SnapshotMalformed {
                reason: format!("{what} field malformed"),
            };
            match key {
                1 => {
                    let Value::Int(n) = val else {
                        return Err(bad("version"));
                    };
                    if n != CIVIC_LEDGER_ENTRY_VERSION {
                        return Err(LedgerError::SnapshotVersion { found: n });
                    }
                }
                2 => {
                    let Value::Int(kind) = val else {
                        return Err(bad("kind"));
                    };
                    if kind != ENTRY_KIND_AWARD {
                        return Err(LedgerError::SnapshotMalformed {
                            reason: format!("unknown entry kind {kind}"),
                        });
                    }
                }
                3 => {
                    let Value::Bytes(b) = val else {
                        return Err(bad("contributor"));
                    };
                    contributor = Some(
                        b.as_slice()
                            .try_into()
                            .map_err(|_| bad("contributor length"))?,
                    );
                }
                4 => {
                    let Value::Int(n) = val else {
                        return Err(bad("awarded"));
                    };
                    awarded = Some(u64::try_from(n).map_err(|_| bad("awarded"))?);
                }
                5 => {
                    let Value::Int(n) = val else {
                        return Err(bad("intrinsic"));
                    };
                    intrinsic = Some(u64::try_from(n).map_err(|_| bad("intrinsic"))?);
                }
                6 => {
                    let Value::Int(n) = val else {
                        return Err(bad("formula version"));
                    };
                    formula = Some(u32::try_from(n).map_err(|_| bad("formula version"))?);
                }
                7 => {
                    let Value::Bytes(b) = val else {
                        return Err(bad("receipt id"));
                    };
                    receipt = Some(
                        b.as_slice()
                            .try_into()
                            .map_err(|_| bad("receipt id length"))?,
                    );
                }
                8 => {
                    let Value::Int(n) = val else {
                        return Err(bad("window"));
                    };
                    window = Some(u64::try_from(n).map_err(|_| bad("window"))?);
                }
                9 => {
                    let Value::Int(n) = val else {
                        return Err(bad("recorded at"));
                    };
                    recorded = Some(u64::try_from(n).map_err(|_| bad("recorded at"))?);
                }
                10 => {
                    let Value::Bytes(b) = val else {
                        return Err(bad("issuer"));
                    };
                    issuer = Some(
                        b.as_slice()
                            .try_into()
                            .map_err(|_| bad("issuer length"))?,
                    );
                }
                other => {
                    return Err(LedgerError::SnapshotMalformed {
                        reason: format!("unknown entry field {other}"),
                    });
                }
            }
        }
        let contributor = contributor.ok_or_else(|| LedgerError::SnapshotMalformed {
            reason: "contributor missing".into(),
        })?;
        let issuer = issuer.ok_or_else(|| LedgerError::SnapshotMalformed {
            reason: "issuer missing".into(),
        })?;
        let awarded = awarded.ok_or_else(|| LedgerError::SnapshotMalformed {
            reason: "awarded missing".into(),
        })?;
        if awarded == 0 {
            return Err(LedgerError::SnapshotMalformed {
                reason: "zero-point award entry (capped receipts record nothing)".into(),
            });
        }
        Ok(LedgerEntry {
            contributor,
            issuer,
            awarded_points: awarded,
            intrinsic_points: intrinsic.ok_or_else(|| LedgerError::SnapshotMalformed {
                reason: "intrinsic missing".into(),
            })?,
            formula_version: formula.ok_or_else(|| LedgerError::SnapshotMalformed {
                reason: "formula version missing".into(),
            })?,
            receipt_id: receipt.ok_or_else(|| LedgerError::SnapshotMalformed {
                reason: "receipt id missing".into(),
            })?,
            window: window.ok_or_else(|| LedgerError::SnapshotMalformed {
                reason: "window missing".into(),
            })?,
            recorded_at_unix: recorded.ok_or_else(|| LedgerError::SnapshotMalformed {
                reason: "recorded at missing".into(),
            })?,
        })
    }
}

// ---------------------------------------------------------------------------
// The ledger (interior-mutable; the engine prices, the ledger records)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct LedgerState {
    engine: ValuationEngine,
    entries: Vec<LedgerEntry>,
    by_receipt: HashSet<[u8; 32]>,
    balances: HashMap<[u8; 32], u64>,
    window_balances: HashMap<([u8; 32], u64), u64>,
}

/// The outcome of one award call (the composed verdict + what was
/// recorded, if anything).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerVerdict {
    /// The engine's verdict (Awarded/Duplicate/Refused).
    pub valuation: ValuationVerdict,
    /// The durable entry appended, when points were awarded.
    pub entry: Option<LedgerEntry>,
}

/// The Civic Point ledger — the durable accounting over the R8-002
/// valuation engine. Concurrency-safe by construction (one lock).
#[derive(Debug, Clone)]
pub struct CivicPointLedger {
    state: Arc<Mutex<LedgerState>>,
}

impl CivicPointLedger {
    /// A fresh ledger with the default pricing policy.
    pub fn new() -> Self {
        Self::with_policy(ValuationPolicy::default())
    }

    /// A fresh ledger with an explicit pricing policy.
    pub fn with_policy(policy: ValuationPolicy) -> Self {
        Self {
            state: Arc::new(Mutex::new(LedgerState {
                engine: ValuationEngine::with_policy(policy),
                ..LedgerState::default()
            })),
        }
    }

    /// The pricing policy (read view).
    pub fn policy(&self) -> ValuationPolicy {
        self.state
            .lock()
            .expect("ledger lock poisoned")
            .engine
            .policy()
            .clone()
    }

    /// Price one verified receipt and record the award when non-zero.
    /// Exactly-once per receipt_id; refusals and duplicates record
    /// nothing; the pricing is re-derived — never caller-supplied.
    pub fn award(
        &self,
        receipt: &ContributionReceipt,
        now_unix: u64,
    ) -> Result<LedgerVerdict, LedgerError> {
        let mut state = self.state.lock().expect("ledger lock poisoned");
        let valuation = state.engine.value(receipt, now_unix);
        let entry = match &valuation {
            ValuationVerdict::Awarded(a) if a.awarded_points > 0 => {
                let entry = LedgerEntry {
                    contributor: *receipt.contributor_node_id(),
                    issuer: *receipt.issuer_node_id().as_bytes(),
                    awarded_points: a.awarded_points,
                    intrinsic_points: a.intrinsic_points,
                    formula_version: VALUATION_FORMULA_VERSION,
                    receipt_id: receipt.receipt_id(),
                    window: a.window,
                    recorded_at_unix: now_unix,
                };
                debug_assert!(state.by_receipt.insert(entry.receipt_id));
                state
                    .balances
                    .entry(entry.contributor)
                    .and_modify(|b| *b += entry.awarded_points)
                    .or_insert(entry.awarded_points);
                state
                    .window_balances
                    .entry((entry.contributor, entry.window))
                    .and_modify(|b| *b += entry.awarded_points)
                    .or_insert(entry.awarded_points);
                state.entries.push(entry.clone());
                Some(entry)
            }
            _ => None,
        };
        Ok(LedgerVerdict { valuation, entry })
    }

    /// A contributor's total points (the balance; only ever grows in v1).
    pub fn balance(&self, contributor: &[u8; 32]) -> u64 {
        self.state
            .lock()
            .expect("ledger lock poisoned")
            .balances
            .get(contributor)
            .copied()
            .unwrap_or(0)
    }

    /// A contributor's points in one valuation window.
    pub fn window_balance(&self, contributor: &[u8; 32], window: u64) -> u64 {
        self.state
            .lock()
            .expect("ledger lock poisoned")
            .window_balances
            .get(&(*contributor, window))
            .copied()
            .unwrap_or(0)
    }

    /// The total points across all contributors.
    pub fn total_points(&self) -> u64 {
        self.state
            .lock()
            .expect("ledger lock poisoned")
            .balances
            .values()
            .sum()
    }

    /// How many award entries are recorded.
    pub fn entry_count(&self) -> usize {
        self.state.lock().expect("ledger lock poisoned").entries.len()
    }

    /// Whether a receipt_id already has an award entry.
    pub fn contains_award(&self, receipt_id: &[u8; 32]) -> bool {
        self.state
            .lock()
            .expect("ledger lock poisoned")
            .by_receipt
            .contains(receipt_id)
    }

    /// The append-only entries (derived truth replay).
    pub fn entries(&self) -> Vec<LedgerEntry> {
        self.state
            .lock()
            .expect("ledger lock poisoned")
            .entries
            .clone()
    }

    /// Serialize the durable state: canonical CBOR
    /// `{1: version, 2: policy(window_secs, byte cap, pair cap,
    /// contributor cap), 3: [entries]}` — deterministic for equal logical
    /// state.
    pub fn to_snapshot_bytes(&self) -> Vec<u8> {
        let state = self.state.lock().expect("ledger lock poisoned");
        let p = state.engine.policy();
        let entries: Vec<Value> = state.entries.iter().map(|e| {
            Value::Bytes(e.to_wire())
        }).collect();
        encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(CIVIC_LEDGER_ENTRY_VERSION)),
            (
                Value::Int(2),
                Value::Array(vec![
                    Value::Int(p.window_secs() as i64),
                    Value::Int(p.per_receipt_byte_cap() as i64),
                    Value::Int(p.per_pair_window_points() as i64),
                    Value::Int(p.per_contributor_window_points() as i64),
                ]),
            ),
            (Value::Int(3), Value::Array(entries)),
        ]))
        .expect("in-profile snapshot")
    }

    /// Reload from a snapshot (fail-closed, typed). The policy rides the
    /// snapshot (the pricing law must match its own history); every
    /// entry strict-parses and re-derives the balances by replay.
    pub fn from_snapshot_bytes(bytes: &[u8]) -> Result<Self, LedgerError> {
        let v = decode(bytes).map_err(|e| LedgerError::SnapshotMalformed {
            reason: format!("snapshot cbor: {e}"),
        })?;
        let Value::Map(fields) = v else {
            return Err(LedgerError::SnapshotMalformed {
                reason: "snapshot not a map".into(),
            });
        };
        let mut version = None;
        let mut policy_fields: Option<Vec<i64>> = None;
        let mut entry_bytes: Option<Vec<Vec<u8>>> = None;
        for (k, val) in fields {
            let Value::Int(key) = k else {
                return Err(LedgerError::SnapshotMalformed {
                    reason: "snapshot key not an integer".into(),
                });
            };
            match key {
                1 => {
                    if let Value::Int(n) = val {
                        version = Some(n);
                    }
                }
                2 => {
                    if let Value::Array(items) = val {
                        let mut out = Vec::new();
                        for item in items {
                            if let Value::Int(n) = item {
                                out.push(n);
                            }
                        }
                        policy_fields = Some(out);
                    }
                }
                3 => {
                    if let Value::Array(items) = val {
                        let mut out = Vec::new();
                        for item in items {
                            if let Value::Bytes(b) = item {
                                out.push(b);
                            }
                        }
                        entry_bytes = Some(out);
                    }
                }
                other => {
                    return Err(LedgerError::SnapshotMalformed {
                        reason: format!("unknown snapshot field {other}"),
                    });
                }
            }
        }
        if version != Some(CIVIC_LEDGER_ENTRY_VERSION) {
            return Err(LedgerError::SnapshotVersion {
                found: version.unwrap_or(0),
            });
        }
        let Some(policy_vals) = policy_fields else {
            return Err(LedgerError::SnapshotMalformed {
                reason: "policy missing".into(),
            });
        };
        if policy_vals.len() != 4 {
            return Err(LedgerError::SnapshotMalformed {
                reason: format!("policy needs 4 values, found {}", policy_vals.len()),
            });
        }
        let policy = ValuationPolicy::new(
            policy_vals[0] as u64,
            policy_vals[1] as u64,
            policy_vals[2] as u64,
            policy_vals[3] as u64,
        )
        .map_err(|e| LedgerError::SnapshotMalformed {
            reason: format!("policy: {e}"),
        })?;
        let entry_bytes = entry_bytes.unwrap_or_default();
        // Strict-parse every entry; replay the balances AND restore the
        // ENGINE state (the restart law: a reload must not reset the
        // window caps or the receipt idempotency).
        let mut valued = HashSet::new();
        let mut pair_windows: HashMap<([u8; 32], [u8; 32], u64), u64> = HashMap::new();
        let mut entries = Vec::with_capacity(entry_bytes.len());
        let mut balances: HashMap<[u8; 32], u64> = HashMap::new();
        let mut window_balances: HashMap<([u8; 32], u64), u64> = HashMap::new();
        for bytes in entry_bytes {
            let entry = LedgerEntry::from_wire(&bytes)?;
            if !valued.insert(entry.receipt_id) {
                return Err(LedgerError::SnapshotMalformed {
                    reason: "duplicate receipt_id in snapshot".into(),
                });
            }
            *balances.entry(entry.contributor).or_insert(0) += entry.awarded_points;
            *window_balances
                .entry((entry.contributor, entry.window))
                .or_insert(0) += entry.awarded_points;
            *pair_windows
                .entry((entry.issuer, entry.contributor, entry.window))
                .or_insert(0) += entry.awarded_points;
            entries.push(entry);
        }
        // re-derive the contributor window map from the window balances
        let mut contributor_windows: HashMap<([u8; 32], u64), u64> = HashMap::new();
        for ((contributor, window), points) in window_balances.iter() {
            contributor_windows.insert((*contributor, *window), *points);
        }
        let engine = crate::ValuationEngine::restore(policy, valued, pair_windows, contributor_windows);
        let by_receipt = engine_valued_snapshot(&engine);
        Ok(Self {
            state: Arc::new(Mutex::new(LedgerState {
                engine,
                entries,
                by_receipt,
                balances,
                window_balances,
            })),
        })
    }
}

/// The engine's valued-id snapshot (read view for the ledger's own
/// idempotency set after a restore — the two sets hold the same ids by
/// construction: every awarded entry was valued exactly once).
fn engine_valued_snapshot(engine: &crate::ValuationEngine) -> HashSet<[u8; 32]> {
    engine.valued_ids()
}

impl Default for CivicPointLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// The file-backed ledger (the restart verify level: append + fsync per
// entry, the appliance-journal record convention)
// ---------------------------------------------------------------------------

/// The durable file-backed Civic Point ledger: length-prefixed canonical
/// CBOR entries (u32be len || entry bytes — the house frame convention),
/// each append flushed AND fsync'd before the call returns, so a
/// recorded award survives a crash. Reload replays the log fail-closed.
#[derive(Debug)]
pub struct FileCivicPointLedger {
    path: std::path::PathBuf,
    ledger: CivicPointLedger,
    lock: Mutex<std::fs::File>,
}

impl FileCivicPointLedger {
    /// Open or create the ledger file. Existing entries strict-parse and
    /// replay (fail-closed on any tamper/truncation/duplicate); the
    /// pricing policy must be supplied (the file does not carry a
    /// snapshot header — the entry log is the record).
    pub fn open(path: &Path, policy: ValuationPolicy) -> Result<Self, LedgerError> {
        let mut entries: Vec<LedgerEntry> = Vec::new();
        if path.exists() {
            let bytes = std::fs::read(path).map_err(|e| LedgerError::FileIo {
                op: "ledger read",
                source: e.to_string(),
            })?;
            let mut at = 0usize;
            while at < bytes.len() {
                if bytes.len() < at + 4 {
                    return Err(LedgerError::SnapshotMalformed {
                        reason: "truncated record length prefix".into(),
                    });
                }
                let len = u32::from_be_bytes(
                    bytes[at..at + 4].try_into().expect("four bytes checked"),
                ) as usize;
                if bytes.len() < at + 4 + len {
                    return Err(LedgerError::SnapshotMalformed {
                        reason: "truncated record body".into(),
                    });
                }
                entries.push(LedgerEntry::from_wire(&bytes[at + 4..at + 4 + len])?);
                at += 4 + len;
            }
        }
        // Replay into a pure ledger (the log is the truth) AND restore
        // the ENGINE state (the restart law: caps and idempotency must
        // survive the reload — a restart is not a cap reset).
        let ledger = CivicPointLedger::with_policy(policy);
        {
            let mut state = ledger.state.lock().expect("ledger lock poisoned");
            let mut seen = HashSet::new();
            let mut pair_windows: HashMap<([u8; 32], [u8; 32], u64), u64> = HashMap::new();
            for entry in entries {
                if !seen.insert(entry.receipt_id) {
                    return Err(LedgerError::SnapshotMalformed {
                        reason: "duplicate receipt_id in the ledger file".into(),
                    });
                }
                *state
                    .balances
                    .entry(entry.contributor)
                    .or_insert(0) += entry.awarded_points;
                *state
                    .window_balances
                    .entry((entry.contributor, entry.window))
                    .or_insert(0) += entry.awarded_points;
                *pair_windows
                    .entry((entry.issuer, entry.contributor, entry.window))
                    .or_insert(0) += entry.awarded_points;
                state.by_receipt.insert(entry.receipt_id);
                state.entries.push(entry);
            }
            // restore the engine over the same lock
            let mut contributor_windows: HashMap<([u8; 32], u64), u64> = HashMap::new();
            for ((contributor, window), points) in state.window_balances.iter() {
                contributor_windows.insert((*contributor, *window), *points);
            }
            let policy_clone = state.engine.policy().clone();
            state.engine = crate::ValuationEngine::restore(
                policy_clone,
                seen,
                pair_windows,
                contributor_windows,
            );
        }
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| LedgerError::FileIo {
                op: "ledger open",
                source: e.to_string(),
            })?;
        Ok(Self {
            path: path.to_path_buf(),
            ledger,
            lock: Mutex::new(file),
        })
    }

    /// The pure ledger (read views: balances, totals, entries).
    pub fn ledger(&self) -> &CivicPointLedger {
        &self.ledger
    }

    /// Price + durably record one receipt (append + flush + fsync under
    /// the file lock; the pure ledger's own lock serializes the pricing).
    pub fn award(
        &self,
        receipt: &ContributionReceipt,
        now_unix: u64,
    ) -> Result<LedgerVerdict, LedgerError> {
        let verdict = self.ledger.award(receipt, now_unix)?;
        if let Some(entry) = &verdict.entry {
            let mut file = self.lock.lock().expect("file lock poisoned");
            let wire = entry.to_wire();
            let mut framed = Vec::with_capacity(4 + wire.len());
            framed.extend_from_slice(&(wire.len() as u32).to_be_bytes());
            framed.extend_from_slice(&wire);
            file.write_all(&framed).map_err(|e| LedgerError::FileIo {
                op: "ledger append",
                source: e.to_string(),
            })?;
            file.flush().map_err(|e| LedgerError::FileIo {
                op: "ledger flush",
                source: e.to_string(),
            })?;
            #[cfg(unix)]
            #[allow(unsafe_code)] // the ONE audited unsafe: fsync(2) below
            {
                use std::os::unix::io::AsRawFd;
                // SAFETY: fsync(2) on our own file descriptor, opened by
                // this struct — no aliasing, no deallocation, a plain
                // syscall on a live fd.
                let rc = unsafe { libc::fsync(file.as_raw_fd()) };
                if rc != 0 {
                    return Err(LedgerError::FileIo {
                        op: "ledger fsync",
                        source: std::io::Error::last_os_error().to_string(),
                    });
                }
            }
        }
        Ok(verdict)
    }

    /// The file's path (diagnostics).
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapKind, ValuationVerdict};
    use sharenet_protocol::contribution::ContributionKind;
    use sharenet_protocol::identity::Identity;

    const NOW: u64 = 1_700_000_000;

    fn receipt(
        issuer: &Identity,
        contributor: &[u8; 32],
        bytes: u64,
        seq: u64,
        issued_at: u64,
    ) -> ContributionReceipt {
        ContributionReceipt::new(
            issuer,
            *contributor,
            [0xF0; 32],
            ContributionKind::Delivered,
            bytes,
            seq,
            issued_at,
        )
        .expect("receipt builds")
    }

    #[test]
    fn awards_record_the_engine_pricing() {
        let issuer = Identity::from_seed([0x11; 32], NOW, None).unwrap();
        let contributor = [0x22; 32];
        let ledger = CivicPointLedger::new();
        let v = ledger
            .award(&receipt(&issuer, &contributor, 1_000, 1, NOW), NOW)
            .unwrap();
        let ValuationVerdict::Awarded(a) = &v.valuation else {
            panic!("engine must award");
        };
        let entry = v.entry.expect("non-zero award records an entry");
        assert_eq!(entry.contributor, contributor);
        assert_eq!(entry.awarded_points, a.awarded_points);
        assert_eq!(entry.intrinsic_points, a.intrinsic_points);
        assert_eq!(entry.formula_version, VALUATION_FORMULA_VERSION);
        assert_eq!(entry.receipt_id, receipt(&issuer, &contributor, 1_000, 1, NOW).receipt_id());
        assert_eq!(entry.window, a.window);
        assert_eq!(entry.recorded_at_unix, NOW);
        assert_eq!(ledger.balance(&contributor), a.awarded_points);
        assert_eq!(ledger.total_points(), a.awarded_points);
        assert_eq!(ledger.entry_count(), 1);
    }

    #[test]
    fn zero_point_capped_receipts_record_nothing() {
        let issuer = Identity::from_seed([0x11; 32], NOW, None).unwrap();
        let contributor = [0x22; 32];
        let policy = crate::ValuationPolicy::new(3_600, 1_000, 100, 1_000).unwrap();
        let ledger = CivicPointLedger::with_policy(policy);
        // exhaust the pair cap
        ledger
            .award(&receipt(&issuer, &contributor, 100, 1, NOW), NOW)
            .unwrap();
        // a further capped receipt: zero-award → NO entry, valid evidence
        let v = ledger
            .award(&receipt(&issuer, &contributor, 500, 2, NOW), NOW)
            .unwrap();
        let ValuationVerdict::Awarded(a) = &v.valuation else {
            panic!("capped is still Awarded");
        };
        assert_eq!(a.awarded_points, 0);
        assert_eq!(a.bound_by, Some(CapKind::PairWindow));
        assert!(v.entry.is_none(), "zero-point awards record nothing");
        assert_eq!(ledger.entry_count(), 1);
        assert_eq!(ledger.balance(&contributor), 100);
    }

    #[test]
    fn duplicates_and_refusals_record_nothing() {
        let issuer = Identity::from_seed([0x11; 32], NOW, None).unwrap();
        let contributor = [0x22; 32];
        let ledger = CivicPointLedger::new();
        let r = receipt(&issuer, &contributor, 10, 1, NOW);
        ledger.award(&r, NOW).unwrap();
        let dup = ledger.award(&r, NOW).unwrap();
        assert!(matches!(dup.valuation, ValuationVerdict::Duplicate { .. }));
        assert!(dup.entry.is_none());
        assert_eq!(ledger.entry_count(), 1);
        // future refusal: nothing recorded
        let future = receipt(&issuer, &contributor, 10, 2, NOW + 900);
        let refused = ledger.award(&future, NOW).unwrap();
        assert!(matches!(refused.valuation, ValuationVerdict::Refused(_)));
        assert!(refused.entry.is_none());
        assert_eq!(ledger.entry_count(), 1);
    }

    #[test]
    fn snapshot_round_trips_and_replays() {
        let issuer = Identity::from_seed([0x11; 32], NOW, None).unwrap();
        let contributor = [0x22; 32];
        let policy = crate::ValuationPolicy::new(600, 10_000, 500, 800).unwrap();
        let ledger = CivicPointLedger::with_policy(policy);
        for seq in 1..=4u64 {
            ledger
                .award(&receipt(&issuer, &contributor, 400, seq, NOW), NOW)
                .unwrap();
        }
        let snap = ledger.to_snapshot_bytes();
        let reloaded = CivicPointLedger::from_snapshot_bytes(&snap).unwrap();
        assert_eq!(reloaded.balance(&contributor), ledger.balance(&contributor));
        assert_eq!(reloaded.total_points(), ledger.total_points());
        assert_eq!(reloaded.entries(), ledger.entries());
        assert_eq!(reloaded.policy(), ledger.policy());
        // the snapshot is deterministic for equal logical state
        assert_eq!(reloaded.to_snapshot_bytes(), snap);
        // the reloaded ledger keeps pricing (a new receipt awards)
        let v = reloaded
            .award(&receipt(&issuer, &contributor, 10, 5, NOW + 600), NOW + 600)
            .unwrap();
        assert!(v.entry.is_some());
    }
}
