//! R9-003: the dedicated gateway appliance — the long-running service
//! form of the Linux gateway (architecture §16 Phase 3: "Dedicated
//! gateway appliances/community routers").
//!
//! What makes a gateway an APPLIANCE rather than a one-shot binary:
//!
//! 1. **A durable identity**: the appliance's node identity lives in a
//!    0600 seed file under its identity directory, created once with
//!    OS entropy (or an explicit first-run `--seed-hex`) and reloaded
//!    on every start — participants can pin the appliance's node id
//!    across restarts (the R4-003 binary took a fresh `--seed-hex`
//!    argument every run; an appliance must be a STABLE peer).
//! 2. **A serve loop**: sequential participants, each a full
//!    admission-verified circuit session (the R4-003 pipeline: pinned
//!    QUIC tunnel → route commitment → circuit admission fail-closed →
//!    BOTH acks → data plane → BYE), with per-session accounting.
//! 3. **A durable session journal**: an append-only record of every
//!    served session (length-prefixed canonical CBOR — the house
//!    frame convention; no new wire objects, this is appliance-local
//!    durable state, the gateway-control-protocol category). On
//!    restart the journal is reloaded and validated fail-closed
//!    (header node id MUST match the identity's), the session ordinal
//!    resumes where it left off, and the cumulative totals survive.
//!
//! Scope honesty (the sandbox record): the endurance verify level here
//! is a MINUTES-scale multiprocess soak with a mid-run appliance
//! RESTART (`tests/appliance_endurance.rs`); the 24-hour endurance is
//! R10-003's dedicated item. The real-network verify level follows the
//! R4-007 mission-gate discipline: the sandbox's network is
//! restrictive (allowlisted HTTP(S) egress only — raw UDP/TCP blocked),
//! so the real-Internet uplink leg is attempted and recorded as the
//! typed outcome (`REAL_INTERNET_UNAVAILABLE` + skip, never a false
//! pass); the local-echo data plane is the in-sandbox evidence. The
//! R5-005 admission posture is the R4-003 pinned-identity mechanism
//! (`expected_clients` — the appliance admits only participants it
//! pinned, and participants pin the appliance through the SIGNED
//! advertisement, per R4-007).

use std::fmt;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use sharenet_protocol::cbor::{decode, encode, Value};
use sharenet_protocol::identity::Identity;

use crate::gateway::{GatewayServer, GatewayStats};

/// The appliance journal's format version.
pub const APPLIANCE_JOURNAL_VERSION: i64 = 1;
/// The appliance identity seed file name (inside the identity dir).
pub const APPLIANCE_SEED_FILE: &str = "appliance.seed";

// ---------------------------------------------------------------------------
// Errors (typed, fail-closed)
// ---------------------------------------------------------------------------

/// An appliance failure (typed, machine-named).
#[derive(Debug)]
pub enum ApplianceError {
    Io { op: &'static str, source: std::io::Error },
    /// The seed file exists but is not exactly 32 bytes / 0600.
    SeedInvalid { reason: String },
    /// The journal exists but does not parse / does not match the
    /// appliance identity / has a regressed ordinal (fail-closed).
    JournalInvalid { reason: String },
    /// The gateway layer refused (bind/serve).
    Gateway(String),
}

impl fmt::Display for ApplianceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApplianceError::Io { op, source } => write!(f, "{op}: {source}"),
            ApplianceError::SeedInvalid { reason } => {
                write!(f, "appliance seed invalid: {reason}")
            }
            ApplianceError::JournalInvalid { reason } => {
                write!(f, "appliance journal invalid: {reason}")
            }
            ApplianceError::Gateway(e) => write!(f, "gateway: {e}"),
        }
    }
}

impl std::error::Error for ApplianceError {}

impl From<std::io::Error> for ApplianceError {
    fn from(e: std::io::Error) -> Self {
        ApplianceError::Io {
            op: "appliance io",
            source: e,
        }
    }
}

// ---------------------------------------------------------------------------
// The session journal (append-only, length-prefixed canonical CBOR)
// ---------------------------------------------------------------------------

/// One served session as recorded in the journal (the durable evidence).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    /// 1-based, strictly increasing across the appliance's LIFE
    /// (restart included — the ordinal resumes).
    pub ordinal: u64,
    /// The verified participant node id.
    pub participant: [u8; 32],
    /// Direction-1 frames forwarded to the uplink.
    pub forwarded_up: u64,
    /// The session's terminal reason (BYE / destroy reason).
    pub reason: String,
}

impl SessionRecord {
    fn to_wire(&self) -> Vec<u8> {
        encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(2)),
            (Value::Int(2), Value::Int(self.ordinal as i64)),
            (Value::Int(3), Value::Bytes(self.participant.to_vec())),
            (Value::Int(4), Value::Int(self.forwarded_up as i64)),
            (Value::Int(5), Value::Text(self.reason.clone())),
        ]))
        .expect("in-profile record")
    }

    fn from_wire(bytes: &[u8]) -> Result<Self, ApplianceError> {
        let v = decode(bytes).map_err(|e| ApplianceError::JournalInvalid {
            reason: format!("record cbor: {e}"),
        })?;
        let Value::Map(entries) = v else {
            return Err(ApplianceError::JournalInvalid {
                reason: "record not a map".into(),
            });
        };
        let mut ordinal = None;
        let mut participant = None;
        let mut forwarded = None;
        let mut reason = None;
        for (k, val) in entries {
            let Value::Int(key) = k else {
                return Err(ApplianceError::JournalInvalid {
                    reason: "record key not an integer".into(),
                });
            };
            match key {
                1 => {
                    if let Value::Int(kind) = val {
                        if kind != 2 {
                            return Err(ApplianceError::JournalInvalid {
                                reason: format!("record kind {kind} != session(2)"),
                            });
                        }
                    } else {
                        return Err(ApplianceError::JournalInvalid {
                            reason: "record kind not an integer".into(),
                        });
                    }
                }
                2 => {
                    if let Value::Int(n) = val {
                        ordinal = Some(
                            u64::try_from(n).map_err(|_| ApplianceError::JournalInvalid {
                                reason: "ordinal out of range".into(),
                            })?,
                        );
                    }
                }
                3 => {
                    if let Value::Bytes(b) = val {
                        participant = Some(b.as_slice().try_into().map_err(
                            |_| ApplianceError::JournalInvalid {
                                reason: "participant id wrong length".into(),
                            },
                        )?);
                    }
                }
                4 => {
                    if let Value::Int(n) = val {
                        forwarded = Some(
                            u64::try_from(n).map_err(|_| ApplianceError::JournalInvalid {
                                reason: "forwarded out of range".into(),
                            })?,
                        );
                    }
                }
                5 => {
                    if let Value::Text(t) = val {
                        reason = Some(t.clone());
                    }
                }
                _ => {
                    return Err(ApplianceError::JournalInvalid {
                        reason: format!("unknown record field {key}"),
                    });
                }
            }
        }
        Ok(SessionRecord {
            ordinal: ordinal.ok_or_else(|| ApplianceError::JournalInvalid {
                reason: "ordinal missing".into(),
            })?,
            participant: participant.ok_or_else(|| ApplianceError::JournalInvalid {
                reason: "participant missing".into(),
            })?,
            forwarded_up: forwarded.ok_or_else(|| ApplianceError::JournalInvalid {
                reason: "forwarded missing".into(),
            })?,
            reason: reason.unwrap_or_default(),
        })
    }
}

/// The journal: created with a header pinning the appliance's node id,
/// then one session record per served session, appended.
///
/// Integrity scope (honest): the journal's parse is STRICT and
/// fail-closed against structural tampering (record boundaries, header
/// identity, version, ordinal monotonicity, trailing garbage,
/// truncation) — but the records themselves are not
/// hash/MAC-protected in v1: an attacker with write access to the
/// journal file can forge VALUES that parse. Tamper-evident durable
/// evidence is R8-005's audit layer (which will chain over this
/// journal); v1 records the truth of what THIS process served.
#[derive(Debug)]
struct Journal {
    file: std::fs::File,
    sessions: Vec<SessionRecord>,
    total_forwarded: u64,
}

impl Journal {
    /// Open-or-create at `path`; the header must pin `node_id` when it
    /// already exists (fail-closed on mismatch), and is written with
    /// `node_id` when new.
    fn open(path: &Path, node_id: [u8; 32]) -> Result<Self, ApplianceError> {
        if path.exists() {
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .and_then(|mut f| f.read_to_end(&mut bytes))
                .map_err(|e| ApplianceError::Io {
                    op: "journal read",
                    source: e,
                })?;
            let (header_node, sessions, total) = parse_journal(&bytes)?;
            if header_node != node_id {
                return Err(ApplianceError::JournalInvalid {
                    reason: format!(
                        "journal belongs to node {} but this appliance is {}",
                        hex(&header_node),
                        hex(&node_id)
                    ),
                });
            }
            let file = std::fs::OpenOptions::new().append(true).open(path)?;
            Ok(Self {
                file,
                sessions,
                total_forwarded: total,
            })
        } else {
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .append(true)
                .open(path)
                .map_err(|e| ApplianceError::Io {
                    op: "journal create",
                    source: e,
                })?;
            let header = encode(&Value::Map(vec![
                (Value::Int(1), Value::Int(1)),
                (Value::Int(2), Value::Int(APPLIANCE_JOURNAL_VERSION)),
                (Value::Int(3), Value::Bytes(node_id.to_vec())),
            ]))
            .expect("in-profile header");
            write_record(&mut file, &header)?;
            Ok(Self {
                file,
                sessions: Vec::new(),
                total_forwarded: 0,
            })
        }
    }

    fn append(&mut self, record: SessionRecord) -> Result<(), ApplianceError> {
        if let Some(last) = self.sessions.last() {
            if record.ordinal <= last.ordinal {
                return Err(ApplianceError::JournalInvalid {
                    reason: format!(
                        "ordinal {} does not advance past {}",
                        record.ordinal, last.ordinal
                    ),
                });
            }
        }
        write_record(&mut self.file, &record.to_wire())?;
        self.total_forwarded += record.forwarded_up;
        self.sessions.push(record);
        Ok(())
    }
}

/// One length-prefixed record (u32be len || canonical CBOR — the house
/// frame convention) — fsync'd (durable before the caller proceeds).
fn write_record(file: &mut std::fs::File, bytes: &[u8]) -> Result<(), ApplianceError> {
    let len = u32::try_from(bytes.len()).map_err(|_| ApplianceError::JournalInvalid {
        reason: "record too large".into(),
    })?;
    let mut framed = Vec::with_capacity(4 + bytes.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(bytes);
    file.write_all(&framed).map_err(|e| ApplianceError::Io {
        op: "journal append",
        source: e,
    })?;
    file.flush().map_err(|e| ApplianceError::Io {
        op: "journal flush",
        source: e,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // fsync the journal: a recorded session survives a crash.
        let rc = unsafe { libc::fsync(file.as_raw_fd()) };
        if rc != 0 {
            return Err(ApplianceError::Io {
                op: "journal fsync",
                source: std::io::Error::last_os_error(),
            });
        }
    }
    Ok(())
}

/// Parse the whole journal: header first (kind 1), then session records
/// (kind 2), ordinals strictly increasing, no trailing garbage.
fn parse_journal(bytes: &[u8]) -> Result<([u8; 32], Vec<SessionRecord>, u64), ApplianceError> {
    let mut at = 0usize;
    let read_record = |at: &mut usize| -> Option<Vec<u8>> {
        if bytes.len() < *at + 4 {
            return None;
        }
        let len = u32::from_be_bytes(
            bytes[*at..*at + 4]
                .try_into()
                .expect("four bytes were checked"),
        ) as usize;
        let end = at.checked_add(4 + len)?;
        if bytes.len() < end {
            return None;
        }
        let record = bytes[*at + 4..end].to_vec();
        *at = end;
        Some(record)
    };
    // header
    let header = read_record(&mut at).ok_or_else(|| ApplianceError::JournalInvalid {
        reason: "journal missing header".into(),
    })?;
    let v = decode(&header).map_err(|e| ApplianceError::JournalInvalid {
        reason: format!("header cbor: {e}"),
    })?;
    let Value::Map(entries) = v else {
        return Err(ApplianceError::JournalInvalid {
            reason: "header not a map".into(),
        });
    };
    let mut kind = None;
    let mut version = None;
    let mut node = None;
    for (k, val) in entries {
        if let Value::Int(key) = k {
            match key {
                1 => {
                    if let Value::Int(n) = val {
                        kind = Some(n);
                    }
                }
                2 => {
                    if let Value::Int(n) = val {
                        version = Some(n);
                    }
                }
                3 => {
                    if let Value::Bytes(b) = val {
                        node = Some(b.as_slice().try_into().map_err(
                            |_| ApplianceError::JournalInvalid {
                                reason: "header node id wrong length".into(),
                            },
                        )?);
                    }
                }
                _ => {}
            }
        }
    }
    if kind != Some(1) {
        return Err(ApplianceError::JournalInvalid {
            reason: "first record is not a header".into(),
        });
    }
    if version != Some(APPLIANCE_JOURNAL_VERSION) {
        return Err(ApplianceError::JournalInvalid {
            reason: format!(
                "journal version {version:?} != {APPLIANCE_JOURNAL_VERSION}"
            ),
        });
    }
    let node = node.ok_or_else(|| ApplianceError::JournalInvalid {
        reason: "header node id missing".into(),
    })?;
    // sessions
    let mut sessions: Vec<SessionRecord> = Vec::new();
    let mut total = 0u64;
    while at < bytes.len() {
        let record = read_record(&mut at).ok_or_else(|| ApplianceError::JournalInvalid {
            reason: "truncated record at end of journal".into(),
        })?;
        let parsed = SessionRecord::from_wire(&record)?;
        if let Some(last) = sessions.last() {
            if parsed.ordinal <= last.ordinal {
                return Err(ApplianceError::JournalInvalid {
                    reason: format!(
                        "journal ordinals regressed: {} then {}",
                        last.ordinal, parsed.ordinal
                    ),
                });
            }
        }
        total += parsed.forwarded_up;
        sessions.push(parsed);
    }
    Ok((node, sessions, total))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// ---------------------------------------------------------------------------
// The appliance
// ---------------------------------------------------------------------------

/// The appliance configuration (validated at open).
#[derive(Debug, Clone)]
pub struct ApplianceConfig {
    /// The directory holding the appliance's durable identity seed
    /// (created 0700; the seed file itself 0600, exactly 32 bytes).
    pub identity_dir: PathBuf,
    /// The QUIC bind address participants connect to.
    pub bind: SocketAddr,
    /// The Internet-side uplink (per-circuit UDP target).
    pub uplink: SocketAddr,
    /// The journal file path (session evidence, append-only).
    pub journal_path: PathBuf,
    /// Participants this appliance pins (None = admit any pinned-by-
    /// certificate-valid participant — the R4-003 mechanism).
    pub expected_clients: Option<Vec<[u8; 32]>>,
}

/// Cumulative appliance statistics (journal-derived + this run).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApplianceStats {
    /// Sessions served across the appliance's LIFE (journal + this run).
    pub sessions: u64,
    /// Direction-1 frames forwarded across the appliance's LIFE.
    pub total_forwarded_up: u64,
}

/// One served session's outcome (what the journal records).
#[derive(Debug, Clone)]
pub struct SessionOutcome {
    pub record: SessionRecord,
}

/// The dedicated gateway appliance.
pub struct GatewayAppliance {
    /// ONE bound server, MANY sequential sessions (the stable address
    /// participants pin across the appliance's life).
    server: GatewayServer,
    node_id: [u8; 32],
    journal: Journal,
}

impl GatewayAppliance {
    /// Open the appliance: load-or-create the durable identity, open or
    /// create the journal (fail-closed on identity mismatch), verify
    /// everything it can BEFORE binding.
    pub fn open(config: ApplianceConfig) -> Result<Self, ApplianceError> {
        std::fs::create_dir_all(&config.identity_dir).map_err(|e| ApplianceError::Io {
            op: "identity dir create",
            source: e,
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = std::fs::metadata(&config.identity_dir)
                .map_err(|e| ApplianceError::Io {
                    op: "identity dir stat",
                    source: e,
                })?;
            // The seed file inside must not be replaceable by group/other
            // (the IdentityStore's own discipline: created dirs are 0700,
            // existing dirs are checked for writability, not style).
            if meta.permissions().mode() & 0o022 != 0 {
                return Err(ApplianceError::SeedInvalid {
                    reason: format!(
                        "identity dir {:?} must not be group/other-writable (got {:o})",
                        config.identity_dir,
                        meta.permissions().mode() & 0o777
                    ),
                });
            }
        }
        let seed_path = config.identity_dir.join(APPLIANCE_SEED_FILE);
        let seed = load_or_create_seed(&seed_path)?;
        let identity = Identity::from_seed(seed, 0, None).map_err(|e| ApplianceError::SeedInvalid {
            reason: format!("seed does not derive an identity: {e}"),
        })?;
        let node_id = *identity.node_id().as_bytes();
        let journal = Journal::open(&config.journal_path, node_id)?;
        // Bind BEFORE returning: the appliance's address is stable from
        // the moment open() succeeds.
        let server = GatewayServer::new(
            seed,
            config.bind,
            config.expected_clients,
            config.uplink,
        )
        .map_err(|e| ApplianceError::Gateway(e.to_string()))?;
        Ok(Self {
            server,
            node_id,
            journal,
        })
    }

    /// The appliance's durable node id (what participants pin).
    pub fn node_id(&self) -> [u8; 32] {
        self.node_id
    }

    /// The bound address (stable across sessions; print it in READY).
    pub fn local_addr(&self) -> Result<SocketAddr, ApplianceError> {
        self.server
            .local_addr()
            .map_err(|e| ApplianceError::Gateway(e.to_string()))
    }

    /// The next session's ordinal (journal-derived, restart-stable).
    pub fn next_ordinal(&self) -> u64 {
        self.journal.sessions.len() as u64 + 1
    }

    /// Cumulative stats across the appliance's life so far.
    pub fn stats(&self) -> ApplianceStats {
        ApplianceStats {
            sessions: self.journal.sessions.len() as u64,
            total_forwarded_up: self.journal.total_forwarded,
        }
    }

    /// Serve ONE participant session to completion (blocks), journal
    /// it, and return the record.
    pub fn serve_session(&mut self) -> Result<SessionOutcome, ApplianceError> {
        let stats: GatewayStats = self
            .server
            .serve_once()
            .map_err(|e| ApplianceError::Gateway(e.to_string()))?;
        let record = SessionRecord {
            ordinal: self.next_ordinal(),
            participant: stats.participant_node_id,
            forwarded_up: stats.forwarded_up,
            reason: stats
                .destroy_reason
                .unwrap_or_else(|| if stats.bye { "bye".into() } else { "closed".into() }),
        };
        self.journal.append(record.clone())?;
        Ok(SessionOutcome { record })
    }

    /// Serve up to `max` sessions (None = until error), returning the
    /// cumulative stats. Each session is a fresh GatewayServer (the
    /// R4-003 one-participant-per-accept model, looped).
    pub fn serve_sessions(&mut self, max: Option<u64>) -> Result<ApplianceStats, ApplianceError> {
        let mut served: u64 = 0;
        loop {
            if let Some(limit) = max {
                if served >= limit {
                    break;
                }
            }
            self.serve_session()?;
            served += 1;
        }
        Ok(self.stats())
    }
}

/// Load the 32-byte appliance seed (0600, exact length, no symlink) or
/// create it once with OS entropy.
fn load_or_create_seed(path: &Path) -> Result<[u8; 32], ApplianceError> {
    if path.exists() {
        let meta = std::fs::symlink_metadata(path).map_err(|e| ApplianceError::Io {
            op: "seed stat",
            source: e,
        })?;
        if meta.file_type().is_symlink() {
            return Err(ApplianceError::SeedInvalid {
                reason: "seed file is a symlink".into(),
            });
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = meta.permissions().mode();
            if mode & 0o777 != 0o600 {
                return Err(ApplianceError::SeedInvalid {
                    reason: format!("seed file must be 0600 (got {:o})", mode & 0o777),
                });
            }
        }
        let mut buf = [0u8; 32];
        std::fs::File::open(path)
            .and_then(|mut f| f.read_exact(&mut buf))
            .map_err(|e| ApplianceError::Io {
                op: "seed read",
                source: e,
            })?;
        return Ok(buf);
    }
    // create once, atomically, 0600 from creation
    let seed = appliance_entropy_32()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| ApplianceError::Io {
                op: "seed create",
                source: e,
            })?;
        file.write_all(&seed).map_err(|e| ApplianceError::Io {
            op: "seed write",
            source: e,
        })?;
    }
    #[cfg(not(unix))]
    {
        return Err(ApplianceError::SeedInvalid {
            reason: "appliance identity creation is unix-only in v1".into(),
        });
    }
    Ok(seed)
}

/// The appliance's entropy source: /dev/urandom (the same source the
/// protocol core's unix path uses — this crate is Linux-native and
/// says so in its name).
fn appliance_entropy_32() -> Result<[u8; 32], ApplianceError> {
    let mut buf = [0u8; 32];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut buf))
        .map_err(|e| ApplianceError::Io {
            op: "read /dev/urandom",
            source: e,
        })?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sharenet-appliance-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn journal_bytes(records: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for r in records {
            out.extend_from_slice(&(r.len() as u32).to_be_bytes());
            out.extend_from_slice(r);
        }
        out
    }

    #[test]
    fn journal_round_trip_and_ordinal_law() {
        let dir = tempdir("journal");
        let path = dir.join("journal.cbor");
        let node = [0xAA; 32];
        {
            let mut journal = Journal::open(&path, node).unwrap();
            journal
                .append(SessionRecord {
                    ordinal: 1,
                    participant: [0x01; 32],
                    forwarded_up: 10,
                    reason: "bye".into(),
                })
                .unwrap();
            // a non-advancing ordinal is refused (fail-closed)
            assert!(journal
                .append(SessionRecord {
                    ordinal: 1,
                    participant: [0x01; 32],
                    forwarded_up: 5,
                    reason: "bye".into(),
                })
                .is_err());
            journal
                .append(SessionRecord {
                    ordinal: 2,
                    participant: [0x02; 32],
                    forwarded_up: 7,
                    reason: "destroy: operator".into(),
                })
                .unwrap();
        }
        // reload: same identity, sessions + totals survive
        {
            let journal = Journal::open(&path, node).unwrap();
            assert_eq!(journal.sessions.len(), 2);
            assert_eq!(journal.total_forwarded, 17);
            assert_eq!(journal.sessions[0].ordinal, 1);
            assert_eq!(journal.sessions[1].forwarded_up, 7);
        }
        // a DIFFERENT appliance identity is refused (fail-closed)
        {
            let err = Journal::open(&path, [0xBB; 32]).unwrap_err();
            assert!(err.to_string().contains("belongs to node"));
        }
    }

    #[test]
    fn journal_tampering_fails_closed() {
        let dir = tempdir("tamper");
        let path = dir.join("journal.cbor");
        let node = [0xCC; 32];
        {
            let mut journal = Journal::open(&path, node).unwrap();
            journal
                .append(SessionRecord {
                    ordinal: 1,
                    participant: [0x01; 32],
                    forwarded_up: 3,
                    reason: "bye".into(),
                })
                .unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        // STRUCTURAL tampering fails closed: the header's length prefix
        let mut tampered = bytes.clone();
        tampered[0] ^= 0x01;
        assert!(parse_journal(&tampered).is_err(), "header length prefix");
        // the session record's length prefix (right after the header
        // record: 4 + header bytes)
        let header_len = 4 + (u32::from_be_bytes(bytes[0..4].try_into().unwrap()) as usize);
        let mut tampered = bytes.clone();
        tampered[header_len] ^= 0x01;
        assert!(parse_journal(&tampered).is_err(), "record length prefix");
        // trailing garbage after a complete record
        let mut tampered = bytes.clone();
        tampered.push(0x00);
        assert!(parse_journal(&tampered).is_err(), "trailing garbage");
        // a truncated tail (partial record)
        let truncated = &bytes[..bytes.len() - 2];
        assert!(parse_journal(truncated).is_err(), "truncated record");
        // a regressed-ordinal splice: rebuild with duplicated record
        let header = encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Int(APPLIANCE_JOURNAL_VERSION)),
            (Value::Int(3), Value::Bytes(node.to_vec())),
        ]))
        .unwrap();
        let session = SessionRecord {
            ordinal: 1,
            participant: [0x01; 32],
            forwarded_up: 3,
            reason: "bye".into(),
        }
        .to_wire();
        let dup = journal_bytes(&[header, session.clone(), session]);
        assert!(parse_journal(&dup).is_err(), "duplicate ordinal must fail");
    }

    #[test]
    fn wrong_version_journal_is_refused() {
        let dir = tempdir("version");
        let path = dir.join("journal.cbor");
        let header = encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (Value::Int(2), Value::Int(99)),
            (Value::Int(3), Value::Bytes([0xDD; 32].to_vec())),
        ]))
        .unwrap();
        std::fs::write(&path, journal_bytes(&[header])).unwrap();
        assert!(Journal::open(&path, [0xDD; 32]).is_err());
    }
}
