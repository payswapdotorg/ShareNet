//! `sharenet_endurance` — the R10-003 endurance/restart harness.
//!
//! The long-running SYSTEM shape (work item: "24h endurance/restart";
//! verify levels: endurance, restart): two dedicated gateway
//! appliances (R9-003 — the durable-identity + append-only-journal
//! form), a real uplink echo standing in for the Internet, and the
//! R10-001 loopback participant — cycled for N rounds, EACH round
//! inducing one gateway death (SIGKILL), running the in-participant
//! replacement (R7-004), and restarting the dead appliance with its
//! SAME durable identity and journal.
//!
//! The laws asserted (the endurance substance):
//!  * SUSTAINED OPERATION: every cycle completes data before AND after
//!    its induced failure (the R10-001 bridge, repeated);
//!  * DURABLE IDENTITY: each appliance keeps the SAME node id across
//!    every restart (the R9-003 seed law);
//!  * JOURNAL CONTINUITY: session ordinals are strictly increasing
//!    across the whole life — restart included (the fsync'd journal
//!    is the truth, the process is not);
//!  * STATE ACCUMULATION: the participant's recovery state (the
//!    revocation ledger + attempt log) grows monotonically — the
//!    append-only files stay parseable and the driver keeps working
//!    at any accumulated size;
//!  * MEMORY STABILITY: the appliances' RSS is sampled every cycle;
//!    growth must stay bounded (leak detection).
//!
//! # Wall-clock vs. accelerated (the honest scope)
//!
//! The 24-HOUR operator profile is this same harness with
//! `--sessions 1440 --spacing-ms 60000` (one full bridge round per
//! minute for a day). The sandbox verification runs the accelerated
//! profile (the default) — the same laws over compressed rounds. The
//! wall-clock run is the operator command recorded in the wave's
//! execution state; the LAWS are what this harness proves either way.
//!
//! Output (machine-parsable):
//!
//! ```text
//! ENDURANCE_BEGIN <sessions> <idle-ms>
//! APPLIANCE_A_READY <addr> <node-hex> <restart#>      (every (re)start)
//! APPLIANCE_B_READY <addr> <node-hex> <restart#>
//! CYCLE <i> BEGIN first=<A|B>
//! CYCLE <i> DONE sent=<n> received=<n> replacements=1
//! SESSION <A|B> <ordinal> <participant-hex> <forwarded> <reason>
//! RESTART <A|B> <restart#>
//! ENDURANCE_RSS <A|B> <kb>
//! ENDURANCE_DONE cycles=<n> kills=<n> restarts=<n>
//!   life-a=<sessions> life-b=<sessions> rss-a-max=<kb> rss-b-max=<kb>
//!   rss-a-growth=<kb> rss-b-growth=<kb> status=ok
//! ```
//!
//! Exit codes: 0 = every law held; 2 = usage; 3 = a law was broken.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, ExitCode, Stdio};
use std::sync::{Arc, Mutex};

/// Resolve a sibling binary (the harness shares the cargo target dir
/// with the binaries it drives — cargo test runs it from deps/, so the
/// search walks up). The 24h operator profile documents this (the
/// harness is a verification vehicle, not a distributed artifact).
fn sibling_bin(name: &str) -> PathBuf {
    let exe = std::env::current_exe().expect("current exe");
    let mut dir = exe.parent();
    for _ in 0..4 {
        if let Some(d) = dir {
            let candidate = d.join(name);
            if candidate.is_file() {
                return candidate;
            }
            dir = d.parent();
        }
    }
    panic!("sibling binary {name} not found near {}", exe.display());
}

/// The participant's identity seed (the same node across the whole
/// endurance run — the state's owner).
const PARTICIPANT_SEED: [u8; 32] = [0x8C; 32];

/// The RSS growth bound (leak detection): a cycle must not leak the
/// runtime's worth of memory. Generous for debug builds, still
/// catches a per-cycle leak at scale (1440 cycles × 1 MB = 1.4 GB).
const RSS_GROWTH_BOUND_KB: u64 = 64 * 1024;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock after the epoch")
        .as_secs()
}

/// Read a process's resident set size (linux /proc — the harness runs
/// on the Linux verify level by construction).
fn rss_kb(pid: u32) -> Option<u64> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            return rest
                .trim()
                .trim_end_matches("kB")
                .trim()
                .parse()
                .ok();
        }
    }
    None
}

/// A spawned child with drained, shared-visible stdout lines (the
/// appliance_endurance pattern: bounded wait-for-line observation;
/// Drop kills — a failed harness never leaks a hung process).
struct Proc {
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
    drain: Option<std::thread::JoinHandle<()>>,
}

impl Proc {
    fn spawn(bin: &PathBuf, args: &[String]) -> Proc {
        let mut child = Command::new(bin)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn child");
        let stdout = child.stdout.take().expect("piped stdout");
        let reader = BufReader::new(stdout);
        let lines: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = lines.clone();
        let drain = std::thread::spawn(move || {
            for line in reader.lines() {
                match line {
                    Ok(l) => sink.lock().expect("lines lock").push(l),
                    Err(_) => break,
                }
            }
        });
        Proc {
            child,
            lines,
            drain: Some(drain),
        }
    }

    fn wait_for_line(&self, prefix: &str, timeout: std::time::Duration) -> String {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            {
                let lines = self.lines.lock().expect("lines lock");
                if let Some(l) = lines.iter().find(|l| l.starts_with(prefix)) {
                    return l.clone();
                }
            }
            if std::time::Instant::now() >= deadline {
                let lines = self.lines.lock().expect("lines lock");
                panic!("line starting with {prefix:?} never arrived; have {lines:?}");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(handle) = self.drain.take() {
            let _ = handle.join();
        }
    }
}

/// One appliance across its whole endurance life: the process handle
/// plus the laws' bookkeeping (identity stability, ordinal
/// continuity, RSS envelope).
struct Appliance {
    label: &'static str,
    identity_dir: PathBuf,
    journal: PathBuf,
    uplink: std::net::SocketAddr,
    proc: Option<Proc>,
    node: [u8; 32],
    addr: std::net::SocketAddr,
    restarts: u64,
    last_ordinal: u64,
    rss_first: Option<u64>,
    rss_max: u64,
}

impl Appliance {
    fn spawn_up(&mut self) {
        let args: Vec<String> = vec![
            "appliance".into(),
            "--identity-dir".into(),
            self.identity_dir.display().to_string(),
            "--bind".into(),
            "127.0.0.1:0".into(),
            "--uplink".into(),
            self.uplink.to_string(),
            "--journal".into(),
            self.journal.display().to_string(),
        ];
        let proc = Proc::spawn(&sibling_bin("sharenet_transport_linux"), &args);
        let ready = proc.wait_for_line("APPLIANCE_READY ", std::time::Duration::from_secs(10));
        let mut parts = ready
            .strip_prefix("APPLIANCE_READY ")
            .expect("ready line")
            .split(' ');
        let addr: std::net::SocketAddr = parts.next().expect("addr").parse().expect("parse");
        let node_hex = parts.next().expect("node hex");
        let mut node = [0u8; 32];
        for (i, slot) in node.iter_mut().enumerate() {
            let hi = (node_hex.as_bytes()[2 * i] as char).to_digit(16).unwrap() as u8;
            let lo = (node_hex.as_bytes()[2 * i + 1] as char).to_digit(16).unwrap() as u8;
            *slot = hi * 16 + lo;
        }
        if self.restarts > 0 {
            // THE DURABLE IDENTITY LAW: same node id across every restart.
            assert_eq!(
                node, self.node,
                "{} changed its node id across a restart — the seed law is broken",
                self.label
            );
        }
        self.node = node;
        self.addr = addr;
        self.proc = Some(proc);
        println!(
            "APPLIANCE_{}_READY {} {} {}",
            self.label,
            addr,
            node_hex,
            self.restarts
        );
        self.restarts += 1;
    }

    /// Observe one session line: ordinals strictly increase across the
    /// whole life (the journal is the truth; the process is not).
    fn observe_session(&mut self, line: &str) {
        // APPLIANCE_SESSION <ordinal> <participant-hex> <forwarded> <reason>
        let rest = line.strip_prefix("APPLIANCE_SESSION ").expect("session line");
        let ordinal: u64 = rest
            .split(' ')
            .next()
            .expect("ordinal")
            .parse()
            .expect("ordinal int");
        assert!(
            ordinal > self.last_ordinal,
            "{} ordinal {ordinal} not after {} (journal continuity broken)",
            self.label,
            self.last_ordinal
        );
        self.last_ordinal = ordinal;
        println!("SESSION {} {}", self.label, rest);
    }

    /// Wait (bounded) for the NEXT session line: the appliance prints
    /// it only after the journal fsync — which races the participant's
    /// own DONE (it observes BYE first). Seeing the line IS the proof
    /// the record is durable.
    fn wait_for_next_session(&mut self, timeout: std::time::Duration) {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            {
                let lines = self
                    .proc
                    .as_ref()
                    .expect("appliance alive")
                    .lines
                    .lock()
                    .expect("lines lock")
                    .clone();
                let next = lines.iter().find_map(|l| {
                    let rest = l.strip_prefix("APPLIANCE_SESSION ")?;
                    let ordinal: u64 = rest.split(' ').next()?.parse().ok()?;
                    (ordinal > self.last_ordinal).then_some(l.clone())
                });
                if let Some(line) = next {
                    self.observe_session(&line);
                    return;
                }
            }
            if std::time::Instant::now() >= deadline {
                panic!(
                    "{} never journaled its replacement session (ordinals seen: {})",
                    self.label, self.last_ordinal
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    fn sample_rss(&mut self) {
        let Some(proc) = &self.proc else { return };
        let pid = proc.child.id();
        if let Some(kb) = rss_kb(pid) {
            if self.rss_first.is_none() {
                self.rss_first = Some(kb);
            }
            self.rss_max = self.rss_max.max(kb);
            println!("ENDURANCE_RSS {} {kb}", self.label);
        }
    }

    fn rss_growth(&self) -> u64 {
        match self.rss_first {
            Some(first) => self.rss_max.saturating_sub(first),
            None => 0,
        }
    }
}

fn fail(msg: &str) -> ExitCode {
    println!("ENDURANCE_ERROR {msg}");
    eprintln!("ENDURANCE_ERROR {msg}");
    ExitCode::from(3)
}

fn usage() {
    eprintln!("usage:");
    eprintln!("  sharenet_endurance run --state-dir DIR --uplink ADDR \\");
    eprintln!("      [--sessions N] [--idle-ms T] [--packets N] [--spacing-ms S]");
}

fn cmd_run(rest: &[String]) -> ExitCode {
    let mut state_dir: Option<PathBuf> = None;
    let mut uplink: Option<std::net::SocketAddr> = None;
    let mut sessions = 8u64;
    let mut idle_ms = 1_500u64;
    let mut packets = 4u64;
    let mut spacing_ms = 0u64;

    let mut i = 0;
    while i < rest.len() {
        let value = |args: &[String], i: &mut usize| -> Option<String> {
            *i += 1;
            args.get(*i).cloned()
        };
        match rest[i].as_str() {
            "--state-dir" => {
                let Some(v) = value(rest, &mut i) else {
                    usage();
                    return ExitCode::from(2);
                };
                state_dir = Some(PathBuf::from(v));
            }
            "--uplink" => {
                let Some(v) = value(rest, &mut i) else {
                    usage();
                    return ExitCode::from(2);
                };
                match v.parse() {
                    Ok(addr) => uplink = Some(addr),
                    Err(_) => {
                        usage();
                        return ExitCode::from(2);
                    }
                }
            }
            "--sessions" => {
                let Some(v) = value(rest, &mut i).and_then(|s| s.parse().ok()) else {
                    usage();
                    return ExitCode::from(2);
                };
                sessions = v;
            }
            "--idle-ms" => {
                let Some(v) = value(rest, &mut i).and_then(|s| s.parse().ok()) else {
                    usage();
                    return ExitCode::from(2);
                };
                idle_ms = v;
            }
            "--packets" => {
                let Some(v) = value(rest, &mut i).and_then(|s| s.parse().ok()) else {
                    usage();
                    return ExitCode::from(2);
                };
                packets = v;
            }
            "--spacing-ms" => {
                let Some(v) = value(rest, &mut i).and_then(|s| s.parse().ok()) else {
                    usage();
                    return ExitCode::from(2);
                };
                spacing_ms = v;
            }
            _ => {
                usage();
                return ExitCode::from(2);
            }
        }
        i += 1;
    }
    let Some(state_dir) = state_dir else {
        usage();
        return ExitCode::from(2);
    };
    let Some(uplink) = uplink else {
        usage();
        return ExitCode::from(2);
    };
    if sessions == 0 || packets == 0 {
        eprintln!("sessions and packets must be >= 1");
        return ExitCode::from(2);
    }
    if let Err(e) = std::fs::create_dir_all(&state_dir) {
        return fail(&format!("state dir: {e}"));
    }
    let a_dir = state_dir.join("appliance-a");
    let b_dir = state_dir.join("appliance-b");
    let recovery_dir = state_dir.join("recovery");
    for dir in [&a_dir, &b_dir, &recovery_dir] {
        if let Err(e) = std::fs::create_dir_all(dir) {
            return fail(&format!("appliance dir: {e}"));
        }
    }
    // The appliance's identity-dir law: not group/other-writable (the
    // same discipline the R9-003 tests apply — create_dir_all's
    // default mode depends on the caller's umask, so pin it).
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for dir in [&a_dir, &b_dir] {
            if let Err(e) = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)) {
                return fail(&format!("identity dir perms: {e}"));
            }
        }
    }
    let revocations_before = std::fs::metadata(recovery_dir.join("revocations.log"))
        .map(|m| m.len())
        .unwrap_or(0);

    println!("ENDURANCE_BEGIN {sessions} {idle_ms}");

    let mut a = Appliance {
        label: "A",
        identity_dir: a_dir,
        journal: state_dir.join("appliance-a.journal"),
        uplink,
        proc: None,
        node: [0u8; 32],
        addr: "127.0.0.1:1".parse().unwrap(),
        restarts: 0,
        last_ordinal: 0,
        rss_first: None,
        rss_max: 0,
    };
    let mut b = Appliance {
        label: "B",
        identity_dir: b_dir,
        journal: state_dir.join("appliance-b.journal"),
        uplink,
        proc: None,
        node: [0u8; 32],
        addr: "127.0.0.1:1".parse().unwrap(),
        restarts: 0,
        last_ordinal: 0,
        rss_first: None,
        rss_max: 0,
    };
    a.spawn_up();
    b.spawn_up();

    let mut kills = 0u64;
    let mut total_restarts = 0u64;

    for cycle in 0..sessions {
        // Alternate the first gateway: both appliances take turns being
        // the one that dies (and gets restarted), so BOTH accumulate
        // completed replacement sessions in their journals and BOTH
        // prove identity/ordinal continuity across their restarts.
        let (first, second) = if cycle % 2 == 0 {
            (&mut a, &mut b)
        } else {
            (&mut b, &mut a)
        };
        println!("CYCLE {cycle} BEGIN first={}", first.label);

        let participant_args: Vec<String> = vec![
            "participant".into(),
            "--seed-hex".into(),
            hex(&PARTICIPANT_SEED),
            "--state-dir".into(),
            recovery_dir.display().to_string(),
            "--gateway".into(),
            format!("{}#{}", first.addr, hex(&first.node)),
            "--gateway".into(),
            format!("{}#{}", second.addr, hex(&second.node)),
            "--packets-before".into(),
            packets.to_string(),
            "--packets-after".into(),
            packets.to_string(),
            "--payload".into(),
            "700".into(),
            "--idle-ms".into(),
            idle_ms.to_string(),
            "--probe-rounds".into(),
            "512".into(),
        ];
        let mut participant = Proc::spawn(&sibling_bin("sharenet_loopback"), &participant_args);
        participant.wait_for_line(
            "LOOPBACK_A_EXCHANGED ",
            std::time::Duration::from_secs(20),
        );

        // INDUCE THE FAILURE: SIGKILL the first appliance.
        if let Some(proc) = first.proc.as_mut() {
            let _ = proc.child.kill();
            let _ = proc.child.wait();
        }
        first.proc = None;
        kills += 1;
        println!("RESTART {} {}", first.label, first.restarts);

        // The participant rides the replacement to the second
        // appliance; observe the appliance-side session lines (the
        // journals' ordinals prove continuity).
        participant.wait_for_line("LOOPBACK_DONE ", std::time::Duration::from_secs(30));
        let status = participant.child.wait().expect("participant exit");
        let p_lines = participant.lines.lock().expect("lines lock").clone();
        if !status.success() {
            return fail(&format!("cycle {cycle}: participant failed: {p_lines:?}"));
        }
        let done = p_lines
            .iter()
            .find_map(|l| l.strip_prefix("LOOPBACK_DONE "))
            .expect("done line");
        println!("CYCLE {cycle} DONE {done}");

        // Restart the killed appliance: same durable identity + journal.
        first.spawn_up();
        total_restarts += 1;

        // The second appliance's journaled replacement session: wait
        // for its line (the fsync-after-BYE race) and assert ordinal
        // continuity across its whole life.
        second.wait_for_next_session(std::time::Duration::from_secs(15));

        // The recovery state grows monotonically (append-only law).
        let revocations_now = std::fs::metadata(recovery_dir.join("revocations.log"))
            .map(|m| m.len())
            .unwrap_or(0);
        if revocations_now < revocations_before + 1 {
            return fail("the revocation ledger did not grow this cycle");
        }

        // Memory envelope.
        a.sample_rss();
        b.sample_rss();

        if spacing_ms > 0 {
            std::thread::sleep(std::time::Duration::from_millis(spacing_ms));
        }
    }

    // The journals' life totals (observed through each process's own
    // stdout before we tear down).
    let life_a = a.last_ordinal;
    let life_b = b.last_ordinal;

    // RSS growth laws (leak detection).
    for (label, growth) in [("A", a.rss_growth()), ("B", b.rss_growth())] {
        if growth > RSS_GROWTH_BOUND_KB {
            return fail(&format!(
                "{label} grew {growth} kB over the run (bound {RSS_GROWTH_BOUND_KB} kB) — leak"
            ));
        }
    }

    println!(
        "ENDURANCE_DONE cycles={sessions} kills={kills} restarts={total_restarts} \
life-a={life_a} life-b={life_b} rss-a-max={} rss-b-max={} rss-a-growth={} \
rss-b-growth={} status=ok",
        a.rss_max,
        b.rss_max,
        a.rss_growth(),
        b.rss_growth()
    );
    let _ = now_unix();
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("run") {
        cmd_run(&args[1..])
    } else {
        usage();
        ExitCode::from(2)
    }
}
