//! R10-006 — the endurance harness PID-reuse store-collision
//! regression (verify level: multiprocess — the loopback_bridge
//! convention).
//!
//! The defect, observed by the R10-003 24-hour wall-clock endurance
//! run (cycle 438/1440, 2026-09-17 01:09 UTC): the participant's
//! per-run projection store is a REGULAR FILE at
//! `<state-dir>/b-<pid>.store`, but the harness-side cleanup before
//! `create` called only `remove_dir_all` — which fails with ENOTDIR
//! on a regular file, an error the harness swallowed. Every
//! participant run therefore left its `b-<pid>.store` behind in the
//! shared recovery dir, and once the OS recycled a process id
//! (pid_max 32768, ~100 pids consumed per endurance cycle — the
//! space wraps roughly every 5.5 hours), the next participant to
//! draw that id met a stale store file at exactly its own path. The
//! store's fail-closed `create` — CORRECT product law, NOT weakened
//! by the fix — refused to clobber it, the participant panicked in
//! `expect("projection store")`, and the harness's 30-second
//! `LOOPBACK_DONE` wait failed the whole run.
//!
//! The fix lives in the harness-side scratch preparation only:
//! remove BOTH forms of a prior occupant before `create` (the file
//! first, then the directory tree), errors non-fatal — the store's
//! own refusal remains the last-resort safety.
//!
//! Every multiprocess case below drives the REAL participant binary
//! through its REAL per-run path — the process-id component is the
//! production default (there is no override hook to test instead).
//! The occupant is placed at `b-<child-pid>.store` between spawn and
//! the test-induced gateway death, which is strictly before the
//! participant's Phase-4 store preparation — no race exists.
//!
//! Adversarial coverage (each a real test in this file):
//!  1. a REAL stale store FILE at the recycled path — the observed
//!     defect (`recycled_pid_stale_store_file_completes_the_run`);
//!  2. a pre-existing DIRECTORY at the path
//!     (`directory_occupant_at_store_path_completes_the_run`);
//!  3. non-store garbage at the path — deleted and re-created
//!     fresh, never loaded
//!     (`garbage_file_occupant_is_recreated_fresh_never_loaded`);
//!  4. the cleanup never panics on any occupant form — the unit
//!     sweep over the extracted helper
//!     (`scratch_cleanup_never_panics_across_occupant_forms`);
//!  5. the product law intact: `DurableProjectionStore::create`
//!     still refuses an existing path when the cleanup is bypassed
//!     (`store_create_still_refuses_existing_paths`).

use std::io::{BufRead, BufReader};
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sharenet_connectivity::{DurableProjectionStore, StoreError};
use sharenet_protocol::identity::Identity;

const LINUX_BIN: &str = env!("CARGO_BIN_EXE_sharenet_transport_linux");
const LOOPBACK_BIN: &str = env!("CARGO_BIN_EXE_sharenet_loopback");

const GATEWAY_A_SEED: [u8; 32] = [0xA1; 32];
const GATEWAY_B_SEED: [u8; 32] = [0xB2; 32];
const PARTICIPANT_SEED: [u8; 32] = [0x3C; 32];

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (s.as_bytes()[2 * i] as char).to_digit(16).unwrap() as u8;
        let lo = (s.as_bytes()[2 * i + 1] as char).to_digit(16).unwrap() as u8;
        *slot = hi * 16 + lo;
    }
    out
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("wall clock after the epoch")
        .as_secs()
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "sharenet-r10006-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir
}

type SharedLines = Arc<Mutex<Vec<String>>>;

/// Drain a piped stream into a shared line vec (the established
/// multiprocess pattern; stderr is drained too so a chatty child can
/// never block on a full pipe and the evidence is captured).
fn pipe_lines<R: std::io::Read + Send + 'static>(
    pipe: R,
) -> (SharedLines, std::thread::JoinHandle<()>) {
    let lines: SharedLines = Arc::new(Mutex::new(Vec::new()));
    let sink = lines.clone();
    let handle = std::thread::spawn(move || {
        for line in BufReader::new(pipe).lines() {
            match line {
                Ok(l) => sink.lock().expect("lines lock").push(l),
                Err(_) => break,
            }
        }
    });
    (lines, handle)
}

/// A spawned process with BOTH pipes drained into shared vecs (the
/// loopback_bridge `Proc` convention, plus stderr capture so a
/// failing child's panic is part of the test evidence). Drop KILLS
/// the child — a failed test never leaks a hung process.
struct Proc {
    child: Child,
    out: SharedLines,
    err: SharedLines,
    drains: Vec<std::thread::JoinHandle<()>>,
}

impl Proc {
    fn spawn(bin: &str, args: &[String]) -> Proc {
        let mut child = Command::new(bin)
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn process");
        let (out, out_drain) = pipe_lines(child.stdout.take().expect("piped stdout"));
        let (err, err_drain) = pipe_lines(child.stderr.take().expect("piped stderr"));
        Proc {
            child,
            out,
            err,
            drains: vec![out_drain, err_drain],
        }
    }

    /// Wait (bounded) for a stdout line starting with `prefix`.
    fn wait_for_line(&self, prefix: &str, timeout: Duration) -> String {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            {
                let lines = self.out.lock().expect("lines lock");
                if let Some(l) = lines.iter().find(|l| l.starts_with(prefix)) {
                    return l.clone();
                }
            }
            if std::time::Instant::now() >= deadline {
                let lines = self.out.lock().expect("lines lock").clone();
                let err = self.err.lock().expect("lines lock").clone();
                panic!("line starting with {prefix:?} never arrived; stdout: {lines:?} stderr: {err:?}");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Wait (bounded) for the process to EXIT. A clean finish and a
    /// panic both exit promptly; only a hang reaches the bound (the
    /// harness's own 30-second `LOOPBACK_DONE` law). Joins the
    /// drains so both captured pipes are complete.
    fn wait_bounded(
        mut self,
        timeout: Duration,
    ) -> (bool, Option<i32>, Vec<String>, Vec<String>) {
        let deadline = std::time::Instant::now() + timeout;
        let status = loop {
            match self.child.try_wait().expect("process alive or exited") {
                Some(status) => break status,
                None if std::time::Instant::now() >= deadline => {
                    let out = self.out.lock().expect("lines lock").clone();
                    let err = self.err.lock().expect("lines lock").clone();
                    panic!("process did not exit within {timeout:?}; stdout: {out:?} stderr: {err:?}");
                }
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        };
        for handle in self.drains.drain(..) {
            handle.join().expect("drain");
        }
        let out = self.out.lock().expect("lines lock").clone();
        let err = self.err.lock().expect("lines lock").clone();
        (status.success(), status.code(), out, err)
    }

    /// Wait for a clean exit and return (ok, stdout lines).
    fn finish(mut self) -> (bool, Vec<String>) {
        let status = self.child.wait().expect("child exit");
        for handle in self.drains.drain(..) {
            handle.join().expect("drain");
        }
        let out = self.out.lock().expect("lines lock").clone();
        (status.success(), out)
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        for handle in self.drains.drain(..) {
            let _ = handle.join();
        }
    }
}

/// A raw local UDP echo standing in for the Internet (the
/// spawn_internet_echo convention — it is the EXTERNAL network, not
/// ShareNet; never a public DNS server, which answers DNS queries,
/// not echoes).
fn spawn_internet_echo() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind echo");
    let addr = socket.local_addr().expect("addr");
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 65_536];
        while let Ok((n, peer)) = socket.recv_from(&mut buf) {
            if socket.send_to(&buf[..n], peer).is_err() {
                break;
            }
        }
    });
    addr
}

fn spawn_gateway(
    seed: [u8; 32],
    uplink: std::net::SocketAddr,
    pin: &str,
) -> (Proc, std::net::SocketAddr, [u8; 32]) {
    let args: Vec<String> = vec![
        "gateway".into(),
        "--seed-hex".into(),
        hex(&seed),
        "--bind".into(),
        "127.0.0.1:0".into(),
        "--uplink".into(),
        uplink.to_string(),
        "--pin".into(),
        pin.into(),
    ];
    let proc = Proc::spawn(LINUX_BIN, &args);
    let ready = proc.wait_for_line("READY ", Duration::from_secs(10));
    let mut parts = ready
        .strip_prefix("READY ")
        .expect("gateway READY")
        .split(' ');
    let addr: std::net::SocketAddr = parts.next().expect("addr").parse().expect("parse");
    let node_hex = parts.next().expect("node hex");
    (proc, addr, hex_to_32(node_hex))
}

/// What waits at the participant's per-run store path when the run
/// begins (the recycled-PID occupant forms).
enum Occupant {
    /// Nothing — the clean default run.
    Absent,
    /// A regular file with exactly these bytes (a stale store, or
    /// garbage).
    File(Vec<u8>),
    /// A directory (with a nested file, proving the whole tree goes).
    Directory,
}

/// One completed participant bridge run.
struct BridgeRun {
    /// The participant exited with code 0.
    ok: bool,
    /// The raw exit code (101 = a Rust panic; None = a signal).
    code: Option<i32>,
    out: Vec<String>,
    err: Vec<String>,
    /// The participant's own per-run store path — `b-<pid>.store`
    /// under the state dir, the production process-id form.
    store_path: std::path::PathBuf,
}

/// Drive one FULL two-process loopback bridge whose participant meets
/// `occupant` at its own per-run store path: spawn the participant,
/// place the occupant at `b-<child-pid>.store` (strictly before the
/// induced gateway death, hence strictly before the Phase-4 store
/// preparation — no race), kill gateway A after the A-phase exchange,
/// and capture the participant's exit and both pipes.
fn bridge_with_occupant(state_dir: &std::path::Path, occupant: Occupant) -> BridgeRun {
    let internet = spawn_internet_echo();
    let participant_identity =
        Identity::from_seed(PARTICIPANT_SEED, 0, None).expect("participant identity");
    let pin = hex(participant_identity.node_id().as_bytes());

    let (mut gateway_a, addr_a, node_a) = spawn_gateway(GATEWAY_A_SEED, internet, &pin);
    let (gateway_b, addr_b, node_b) = spawn_gateway(GATEWAY_B_SEED, internet, &pin);

    let args: Vec<String> = vec![
        "participant".into(),
        "--seed-hex".into(),
        hex(&PARTICIPANT_SEED),
        "--state-dir".into(),
        state_dir.display().to_string(),
        "--gateway".into(),
        format!("{}#{}", addr_a, hex(&node_a)),
        "--gateway".into(),
        format!("{}#{}", addr_b, hex(&node_b)),
        "--packets-before".into(),
        "4".into(),
        "--packets-after".into(),
        "4".into(),
        "--payload".into(),
        "700".into(),
        "--idle-ms".into(),
        "1500".into(),
        "--probe-rounds".into(),
        "512".into(),
    ];
    let participant = Proc::spawn(LOOPBACK_BIN, &args);

    // The participant's REAL per-run store path: its own process id
    // (the production default — there is no override hook). The
    // occupant goes in NOW, between spawn and the induced gateway
    // death below: nothing touches this path until Phase 4, which
    // requires the death — no race.
    let store_path = state_dir.join(format!("b-{}.store", participant.child.id()));
    match occupant {
        Occupant::Absent => {}
        Occupant::File(bytes) => {
            std::fs::write(&store_path, bytes)
                .expect("place the stale FILE occupant at the per-run store path");
        }
        Occupant::Directory => {
            std::fs::create_dir_all(store_path.join("nested"))
                .expect("place the DIRECTORY occupant at the per-run store path");
            std::fs::write(store_path.join("nested").join("old.txt"), b"prior occupant")
                .expect("nested occupant file");
        }
    }

    // The bridge works on gateway A first (four full exchanges).
    participant.wait_for_line("LOOPBACK_A_EXCHANGED ", Duration::from_secs(20));

    // INDUCE THE GATEWAY DEATH (the loopback_bridge convention): a
    // silent SIGKILL — the participant's bounded idle timeout turns
    // it into the typed failure that unlocks Phase 4 and the store
    // preparation under test.
    gateway_a.child.kill().expect("induce the gateway A death");
    let a_status = gateway_a.child.wait().expect("gateway A exit");
    assert!(
        a_status.code().is_none(),
        "gateway A must die by the induced signal, not a clean exit"
    );

    // The participant either completes (`LOOPBACK_DONE`, exit 0) or
    // fails fast (a panic exits 101 immediately) — both well inside
    // the harness's own 30-second law.
    let (ok, code, out, err) = participant.wait_bounded(Duration::from_secs(30));

    if ok {
        // Gateway B exits cleanly having forwarded the after-packets.
        let (b_ok, b_lines) = gateway_b.finish();
        assert!(b_ok, "gateway B exited cleanly; lines: {b_lines:?}");
        assert!(
            b_lines.iter().any(|l| l == "GATEWAY_DONE 4 completed"),
            "gateway B summary: {b_lines:?}"
        );
    }
    // else: Drop kills gateway B — the participant's own failure is
    // the caller's assertion subject, with both pipes captured.

    BridgeRun {
        ok,
        code,
        out,
        err,
        store_path,
    }
}

/// Adversarial case 1 — THE regression (the observed defect): a prior
/// run's REAL stale store FILE meets a recycled process id.
///
/// Run 1 completes the clean bridge and LEAVES its `b-<pid>.store`
/// behind (the leak, pinned as observed behavior — the fix makes the
/// NEXT run survive the leftover; it does not remove the leftover
/// itself). Run 2 is a fresh process whose own per-run path is
/// pre-seeded with run 1's real store bytes — the exact production
/// collision (2026-09-17 01:09 UTC, cycle 438/1440).
///
/// Before the fix this test FAILS with the participant's panic —
/// `projection store: store file already exists: create refuses to
/// clobber it (load it instead)` — exit code 101, no `LOOPBACK_DONE`.
#[test]
fn recycled_pid_stale_store_file_completes_the_run() {
    // Run 1: the clean bridge.
    let dir1 = temp_dir("recycled-run1");
    let run1 = bridge_with_occupant(&dir1, Occupant::Absent);
    assert!(
        run1.ok,
        "run 1 (the clean bridge) must complete; stderr: {:?}",
        run1.err
    );
    assert!(
        run1.store_path.is_file(),
        "run 1 leaves its per-run store file behind (the observed leak): {}",
        run1.store_path.display()
    );
    // The leftover is a REAL valid store — run 1 wrote it through the
    // store's own flush — so the collision bytes are the production
    // ones, not a synthetic stand-in.
    DurableProjectionStore::load(&run1.store_path, now_unix())
        .expect("run 1's leftover is a valid store file");
    let stale = std::fs::read(&run1.store_path).expect("read run 1's leftover store file");
    std::fs::remove_dir_all(&dir1).ok();

    // Run 2: a fresh state dir whose ONLY prior occupant at the
    // participant's own per-run path is run 1's real stale store
    // bytes — the recycled-PID collision.
    let dir2 = temp_dir("recycled-run2");
    let run2 = bridge_with_occupant(&dir2, Occupant::File(stale));
    assert!(
        run2.ok,
        "the participant must survive a stale store FILE at its own \
         per-run path (the recycled-PID collision); exit code {:?}; \
         stdout: {:?}; stderr: {:?}",
        run2.code, run2.out, run2.err
    );
    assert!(
        run2.out.iter().any(|l| l.starts_with("LOOPBACK_DONE ")),
        "the recycled-PID run completed the whole bridge; stdout: {:?}",
        run2.out
    );
    // And it left its OWN fresh store at the path (this run's, not
    // the stale bytes it met).
    DurableProjectionStore::load(&run2.store_path, now_unix())
        .expect("the surviving run created its own fresh store");
    std::fs::remove_dir_all(&dir2).ok();
}

/// Adversarial case 2: a pre-existing DIRECTORY at the exact per-run
/// store path is also cleared — the run completes. (This was the ONLY
/// occupant form the old `remove_dir_all`-only cleanup handled; the
/// guard keeps it true while the file form is fixed.)
#[test]
fn directory_occupant_at_store_path_completes_the_run() {
    let dir = temp_dir("dir-occupant");
    let run = bridge_with_occupant(&dir, Occupant::Directory);
    assert!(
        run.ok,
        "a DIRECTORY occupant at the per-run store path must be cleared \
         before create; exit code {:?}; stderr: {:?}",
        run.code, run.err
    );
    assert!(
        run.store_path.is_file(),
        "after the run the path holds the participant's regular store FILE: {}",
        run.store_path.display()
    );
    std::fs::remove_dir_all(&dir).ok();
}

/// Adversarial case 3: non-store garbage at the per-run store path is
/// deleted and re-created fresh — never loaded (per-run stores are
/// created fresh; no cross-run reads). Garbage cannot parse (the
/// store fails closed on any malformed file), so the COMPLETED run
/// itself proves the garbage was never loaded; the final file being a
/// VALID store (it loads) and not the garbage proves the re-creation.
#[test]
fn garbage_file_occupant_is_recreated_fresh_never_loaded() {
    let dir = temp_dir("garbage-occupant");
    let garbage = b"NOT-A-STORE\x00\x01\x02 bytes from an unrelated crash, not an \
                    SNCP projection"
        .to_vec();
    let run = bridge_with_occupant(&dir, Occupant::File(garbage.clone()));
    assert!(
        run.ok,
        "a garbage FILE occupant at the per-run store path must be cleared \
         before create; exit code {:?}; stderr: {:?}",
        run.code, run.err
    );
    let fresh = std::fs::read(&run.store_path)
        .expect("the participant wrote its store at the occupied path");
    assert_ne!(
        fresh, garbage,
        "the garbage was replaced, not kept and not extended"
    );
    DurableProjectionStore::load(&run.store_path, now_unix())
        .expect("the final file is a valid fresh store (load fails closed on garbage)");
    std::fs::remove_dir_all(&dir).ok();
}

/// Adversarial case 4 — the cleanup non-panic law: no occupant form
/// makes the scratch cleanup itself panic. The unit sweep over the
/// extracted helper the participant actually calls (every removal is
/// a discarded `Result` by law; this pins it against a future
/// "helpful" unwrap), across every realistic form a recycled path
/// can present.
#[test]
fn scratch_cleanup_never_panics_across_occupant_forms() {
    let dir = temp_dir("scratch-sweep");

    // (a) absent path — and a path whose PARENT does not exist either.
    let absent = dir.join("absent.store");
    sharenet_transport_linux::scratch::clear_scratch_path(&absent);
    assert!(!absent.exists(), "an absent occupant stays absent");
    let orphan = dir.join("no-such-dir").join("orphan.store");
    sharenet_transport_linux::scratch::clear_scratch_path(&orphan);
    assert!(!orphan.exists());

    // (b) an empty regular file.
    let empty = dir.join("empty.store");
    std::fs::write(&empty, b"").expect("empty file");
    sharenet_transport_linux::scratch::clear_scratch_path(&empty);
    assert!(!empty.exists(), "an empty FILE occupant is removed");

    // (c) a garbage regular file.
    let garbage = dir.join("garbage.store");
    std::fs::write(&garbage, b"garbage \x00\xff bytes").expect("garbage file");
    sharenet_transport_linux::scratch::clear_scratch_path(&garbage);
    assert!(!garbage.exists(), "a garbage FILE occupant is removed");

    // (d) a REAL store file (the exact production stale occupant).
    let real = dir.join("real.store");
    let store = DurableProjectionStore::create(&real, 600).expect("create the stale store");
    store.flush().expect("flush");
    drop(store);
    assert!(real.is_file());
    sharenet_transport_linux::scratch::clear_scratch_path(&real);
    assert!(!real.exists(), "a REAL stale store FILE occupant is removed");

    // (e) an empty directory.
    let empty_dir = dir.join("empty-dir.store");
    std::fs::create_dir_all(&empty_dir).expect("empty dir");
    sharenet_transport_linux::scratch::clear_scratch_path(&empty_dir);
    assert!(!empty_dir.exists(), "an empty DIRECTORY occupant is removed");

    // (f) a directory tree (nested file + nested dir + nested file).
    let tree = dir.join("tree.store");
    std::fs::create_dir_all(tree.join("nested").join("deeper")).expect("dir tree");
    std::fs::write(tree.join("nested").join("old.txt"), b"prior").expect("nested file");
    std::fs::write(tree.join("nested").join("deeper").join("old.bin"), [0u8; 16])
        .expect("deeply nested file");
    sharenet_transport_linux::scratch::clear_scratch_path(&tree);
    assert!(!tree.exists(), "a whole DIRECTORY TREE occupant is removed");

    // (g–i) the symlink forms: the LINK is the occupant at the path —
    // it is removed; whatever it points at is NOT chased (the cleanup
    // clears the scratch path itself, nothing beyond it).
    #[cfg(unix)]
    {
        let target_file = dir.join("target-file.bin");
        std::fs::write(&target_file, b"kept").expect("symlink target file");
        let link_file = dir.join("link-file.store");
        std::os::unix::fs::symlink(&target_file, &link_file).expect("symlink to file");
        sharenet_transport_linux::scratch::clear_scratch_path(&link_file);
        assert!(!link_file.exists(), "a symlink-to-FILE occupant is removed");
        assert!(target_file.is_file(), "the symlink target is kept");

        let target_dir = dir.join("target-dir");
        std::fs::create_dir_all(&target_dir).expect("symlink target dir");
        let link_dir = dir.join("link-dir.store");
        std::os::unix::fs::symlink(&target_dir, &link_dir).expect("symlink to dir");
        sharenet_transport_linux::scratch::clear_scratch_path(&link_dir);
        assert!(!link_dir.exists(), "a symlink-to-DIR occupant is removed");
        assert!(target_dir.is_dir(), "the symlinked directory is kept");

        let dangling = dir.join("dangling.store");
        std::os::unix::fs::symlink(dir.join("gone-nowhere"), &dangling)
            .expect("dangling symlink");
        sharenet_transport_linux::scratch::clear_scratch_path(&dangling);
        assert!(!dangling.exists(), "a DANGLING symlink occupant is removed");
    }

    // Reaching this point IS the non-panic proof: no form above made
    // the cleanup panic, and each occupant is gone.
    std::fs::remove_dir_all(&dir).ok();
}

/// Adversarial case 5 — the product law INTACT: the store's
/// fail-closed refusal is CORRECT behavior and was not weakened by
/// the harness-side fix. Direct assertion with the cleanup entirely
/// bypassed: `create` still refuses every existing-path form.
#[test]
fn store_create_still_refuses_existing_paths() {
    let dir = temp_dir("store-law");

    // (a) a REAL prior store file: create → flush → create again.
    let real = dir.join("real.store");
    let store = DurableProjectionStore::create(&real, 600).expect("the first create");
    store.flush().expect("flush");
    drop(store);
    assert_create_refused(&real);

    // (b) a plain file.
    let plain = dir.join("plain.store");
    std::fs::write(&plain, b"not a store at all").expect("plain file");
    assert_create_refused(&plain);

    // (c) a directory.
    let tree = dir.join("dir.store");
    std::fs::create_dir_all(&tree).expect("directory");
    assert_create_refused(&tree);

    std::fs::remove_dir_all(&dir).ok();
}

/// `create` must refuse the existing path with the typed
/// `StoreAlreadyExists` — the no-silent-data-loss law.
fn assert_create_refused(path: &std::path::Path) {
    match DurableProjectionStore::create(path, 600) {
        Err(StoreError::StoreAlreadyExists) => {}
        other => panic!(
            "create must refuse the existing path {} (the fail-closed store \
             law); got {:?}",
            path.display(),
            other
        ),
    }
}
