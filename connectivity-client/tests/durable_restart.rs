//! R5-003 "restart" verification: the durable local health projection
//! against the REAL `AdcosClient`, the REAL `adcos_test_server` process,
//! and REAL process boundaries — the ShareNet side is torn down and
//! reloaded from disk only, once through the `projection_store_probe`
//! child process (a genuine new process) and once in-process.
//!
//! What is proven, per the work item's verify levels:
//!
//! - **state restored** — the reloaded store re-derives the same
//!   `ContractState`/observation log the live store had before the restart;
//! - **staleness typed** — a reload past the freshness bound surfaces
//!   `ProjectionFreshness::Stale` (needs refresh), never fresh data, while
//!   a reload inside the bound surfaces `Fresh`;
//! - **no fabrication after an ADCOS outage** — the reload serves the LAST
//!   ACCEPTED observation with its ORIGINAL freshness metadata (bound ==
//!   original `observed_at + window`, never re-anchored), while a client
//!   facing a dead provider returns the typed `ProviderUnavailable`
//!   (nothing fabricated on either side);
//! - **no sequence regression** — redelivered pre-restart observations are
//!   `IgnoredReplay`; the next strictly greater sequence continues the
//!   stream, accepted across a process boundary;
//! - **terminate survives restart** — the terminal projection persists and
//!   redeliveries (plus an idempotent re-terminate at the provider) change
//!   nothing.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sharenet_connectivity::ConnectivityPort;
use sharenet_connectivity_client::{AdcosClient, AdcosConfig};

const SERVER_BIN: &str = env!("CARGO_BIN_EXE_adcos_test_server");
const PROBE_BIN: &str = env!("CARGO_BIN_EXE_projection_store_probe");

/// The store's freshness window (the provider's bound, persisted in the
/// store header): the tests reload inside the bound (fresh) and far past it
/// (stale) without sleeping.
const WINDOW_SECS: u64 = 600;

struct Server {
    child: Child,
    reader: Option<std::thread::JoinHandle<Vec<String>>>,
}

impl Server {
    fn spawn(extra: &[&str]) -> (Server, std::net::SocketAddr) {
        let mut cmd = Command::new(SERVER_BIN);
        cmd.arg("--bind").arg("127.0.0.1:0");
        for arg in extra {
            cmd.arg(arg);
        }
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn adcos_test_server");
        let stdout = child.stdout.take().expect("stdout");
        let mut reader = BufReader::new(stdout);
        let mut first = String::new();
        reader.read_line(&mut first).expect("READY line");
        let handle = std::thread::spawn(move || {
            let mut lines = Vec::new();
            for line in reader.lines() {
                match line {
                    Ok(l) => lines.push(l),
                    Err(_) => break,
                }
            }
            lines
        });
        let addr = first
            .trim()
            .strip_prefix("READY ")
            .expect("ready line")
            .parse()
            .expect("addr");
        (
            Server {
                child,
                reader: Some(handle),
            },
            addr,
        )
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

fn client(addr: std::net::SocketAddr) -> AdcosClient {
    AdcosClient::new(
        AdcosConfig::new(addr)
            .with_max_attempts(2)
            .with_retry_delay(Duration::from_millis(30)),
    )
    .expect("client")
}

/// Call every test through the TRAIT object — the seam the daemon and the
/// store-wiring caller use.
fn as_port(client: &AdcosClient) -> &dyn ConnectivityPort {
    client
}

fn live_requirement() -> sharenet_connectivity::ConnectivityRequirement {
    sharenet_connectivity::ConnectivityRequirement::new(
        sharenet_connectivity::ServiceClass::Live,
    )
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs()
}

/// A unique store path per test (tag) + process, cleaned up on drop
/// (including any leftover flush temp file).
struct TempStore {
    path: std::path::PathBuf,
}

impl TempStore {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("sharenet-r5003-it-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self {
            path: dir.join(format!("{tag}.store")),
        }
    }

    fn tmp_sibling(&self) -> std::path::PathBuf {
        let mut os = self.path.clone().into_os_string();
        os.push(".tmp");
        std::path::PathBuf::from(os)
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.tmp_sibling());
        let _ = std::fs::remove_dir(self.path.parent().expect("parent"));
    }
}

/// Run the probe child process (a REAL new process) and return its stdout
/// lines; panics with the captured output on a nonzero exit.
fn probe(args: &[&str]) -> Vec<String> {
    let output = Command::new(PROBE_BIN)
        .args(args)
        .stderr(Stdio::piped())
        .output()
        .expect("spawn projection_store_probe");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "probe {:?} failed ({}): stdout={stdout:?} stderr={stderr:?}",
        args,
        output.status
    );
    stdout.lines().map(str::to_string).collect()
}

/// The probe's `HEALTH` line for one contract, as fields:
/// `[HEALTH, hex, state, freshness, fresh_until, obs_count, last_seq, last_observed_at]`.
fn health_line(lines: &[String], contract: &sharenet_connectivity::ConnectivityContractRef) -> Vec<String> {
    let prefix = format!("HEALTH {} ", contract.to_hex());
    let line = lines
        .iter()
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no health line for {}: {lines:?}", contract.to_hex()));
    line.split_whitespace().map(str::to_string).collect()
}

#[test]
fn restart_cycle_state_staleness_sequence_and_terminate() {
    let temp = TempStore::new("cycle");
    let (server, addr) = Server::spawn(&[]);

    // -- Epoch 1 (in-process): acquire, observe, persist. ----------------
    let client_e1 = client(addr);
    let port = as_port(&client_e1);
    let mut store = sharenet_connectivity::DurableProjectionStore::create(&temp.path, WINDOW_SECS)
        .expect("create store");

    let intent = port.create_intent(live_requirement()).expect("intent");
    let offers = port.discover_offers(&intent).expect("offers");
    let c1 = port.accept_offer(&intent, &offers[0]).expect("accept");
    // A second contract is held but never observed: the honest Projected /
    // NoObservation state must survive the restart too.
    let c2 = port.accept_offer(&intent, &offers[1]).expect("accept 2");
    store.register(&c2);

    let first = port.get_assurance(&c1).expect("assurance");
    assert_eq!(first.len(), 1);
    let at1 = first[0].observed_at_unix();
    let seq1 = first[0].sequence();
    assert_eq!(
        store.accept(&first[0]),
        sharenet_connectivity::AcceptOutcome::Accepted
    );
    let health = store.health(&c1).expect("health");
    assert_eq!(health.state(), sharenet_connectivity::ContractState::Active);
    assert_eq!(health.highest_sequence(), Some(seq1));
    store.flush().expect("flush");
    // FULL TEARDOWN: only the file remains.
    drop(store);
    drop(client_e1);

    // -- The outage moment: a fresh client facing a DEAD provider
    //    fabricates nothing (typed ProviderUnavailable); the durable store
    //    is what serves the last accepted evidence. ----------------------
    let dead_addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let dead_client = AdcosClient::new(
        AdcosConfig::new(dead_addr)
            .with_max_attempts(1)
            .with_connect_timeout(Duration::from_millis(250)),
    )
    .expect("dead client");
    match as_port(&dead_client).get_contract(&c1) {
        Err(sharenet_connectivity::PortError::ProviderUnavailable {
            last_observation_fresh_until_unix,
        }) => assert_eq!(last_observation_fresh_until_unix, None),
        other => panic!("expected ProviderUnavailable from the dead provider, got {other:?}"),
    }
    drop(dead_client);

    // -- Epoch 2 (NEW PROCESS): reload from disk only. Twice, with
    //    different clocks: long after (typed STALE, original metadata) and
    //    now (typed FRESH). ----------------------------------------------
    let advanced = now_unix() + 7200;
    let stale_lines = probe(&["inspect", temp.path.to_str().unwrap(), &advanced.to_string()]);
    assert_eq!(stale_lines[0], format!("LOADED 2"));
    let stale = health_line(&stale_lines, &c1);
    assert_eq!(stale[2], "active", "re-derived state restored: {stale:?}");
    assert_eq!(stale[3], "stale", "reload past the bound is typed stale: {stale:?}");
    assert_eq!(stale[4], (at1 + WINDOW_SECS).to_string(), "ORIGINAL bound, never re-anchored");
    assert_eq!(stale[5], "1");
    assert_eq!(stale[6], seq1.to_string());
    assert_eq!(stale[7], at1.to_string(), "last accepted observation served, not fabricated");
    let held = health_line(&stale_lines, &c2);
    assert_eq!(held[2], "projected");
    assert_eq!(held[3], "no_observation");
    assert_eq!(held[5], "0");

    let fresh_lines = probe(&["inspect", temp.path.to_str().unwrap(), &now_unix().to_string()]);
    let fresh = health_line(&fresh_lines, &c1);
    assert_eq!(fresh[2], "active");
    assert_eq!(fresh[3], "fresh", "reload inside the bound is typed fresh: {fresh:?}");
    assert_eq!(fresh[4], (at1 + WINDOW_SECS).to_string());

    // -- Epoch 3 (live continuation): the provider is still up (its own
    //    state is its concern); terminate, fetch the full log, and let a
    //    NEW PROCESS continue the projection across the restart. ---------
    let client_e3 = client(addr);
    // R5-004 known-contract rule: a NEW client knows no contracts, and an
    // observation for an unknown contract is never a trust grant — the
    // daemon's reload path re-registers the durable store's contract list
    // (exactly this call) before it asks for assurance again.
    client_e3.register_known_contract(&c1);
    let port = as_port(&client_e3);
    port.terminate(&c1).expect("terminate");
    let after = port.get_assurance(&c1).expect("assurance after terminate");
    assert_eq!(after.len(), 2, "activated + terminated");
    let terminated = &after[1];
    assert_eq!(terminated.kind(), sharenet_connectivity::ObservationKind::Terminated);
    let seq2 = terminated.sequence();
    assert!(seq2 > seq1, "the provider's sequence continues: {seq2} > {seq1}");
    let at2 = terminated.observed_at_unix();

    // A pre-restart redelivery must NOT regress the reloaded store, and the
    // next sequence must continue — both proven in a fresh process.
    let accept_args = [
        "accept".to_string(),
        temp.path.to_str().unwrap().to_string(),
        now_unix().to_string(),
        c1.to_hex(),
        "terminated".to_string(),
        at2.to_string(),
        seq2.to_string(),
    ];
    let arg_refs: Vec<&str> = accept_args.iter().map(String::as_str).collect();
    let accepted_lines = probe(&arg_refs);
    assert!(accepted_lines.iter().any(|l| l == "OUTCOME accepted"), "{accepted_lines:?}");
    let terminated_health = health_line(&accepted_lines, &c1);
    assert_eq!(terminated_health[2], "terminated", "the child process derived the terminal state");
    assert_eq!(terminated_health[6], seq2.to_string());
    drop(client_e3);

    // -- Epoch 4 (in-process): verify the child's durable write, the
    //    redelivery dedup, and terminate idempotence across restarts. ----
    let mut store = sharenet_connectivity::DurableProjectionStore::load(&temp.path, now_unix())
        .expect("reload after the child's write");
    assert_eq!(
        store.freshness_at_reload(&c1),
        Some(sharenet_connectivity::ProjectionFreshness::Fresh {
            fresh_until_unix: at2 + WINDOW_SECS,
        }),
        "the in-process reload re-validates freshness against the current time"
    );
    let health = store.health(&c1).expect("health");
    assert_eq!(health.state(), sharenet_connectivity::ContractState::Terminated);
    let sequences: Vec<u64> = health.observations().iter().map(|o| o.sequence()).collect();
    assert_eq!(sequences, vec![seq1, seq2], "the full log survived, in order");
    assert_eq!(
        health.last_accepted().unwrap().observation().observed_at_unix(),
        at2
    );
    // Staleness is a pure function of the ORIGINAL metadata + evaluation
    // time — typed Stale past the bound, never fresh data.
    assert_eq!(
        health.freshness(at2 + WINDOW_SECS + 1),
        sharenet_connectivity::ProjectionFreshness::Stale {
            fresh_until_unix: at2 + WINDOW_SECS,
            last_observed_at_unix: at2,
        }
    );

    // No sequence regression: replaying the full post-terminate log is all
    // replays now (the reloaded highest sequence blocks them).
    for observation in &after {
        assert_eq!(
            store.accept(observation),
            sharenet_connectivity::AcceptOutcome::IgnoredReplay {
                sequence: observation.sequence()
            }
        );
    }
    assert_eq!(store.health(&c1).unwrap().state(), sharenet_connectivity::ContractState::Terminated);

    // Terminate idempotence survives the restart: re-terminating at the
    // provider is Ok with NO new observation, and the projection is
    // unchanged after re-fetching.
    let client_e4 = client(addr);
    client_e4.register_known_contract(&c1);
    let port = as_port(&client_e4);
    port.terminate(&c1).expect("terminate is idempotent across restarts");
    let refetched = port.get_assurance(&c1).expect("assurance");
    assert_eq!(refetched.len(), 2, "no new observation for the idempotent re-terminate");
    for observation in &refetched {
        assert_eq!(
            store.accept(observation),
            sharenet_connectivity::AcceptOutcome::IgnoredReplay {
                sequence: observation.sequence()
            }
        );
    }
    assert_eq!(store.health(&c1).unwrap().state(), sharenet_connectivity::ContractState::Terminated);
    drop(client_e4);
    drop(store);
    drop(server);
}

#[test]
fn reload_after_provider_outage_shows_last_accepted_stale_never_fabricated() {
    let temp = TempStore::new("outage");
    // The provider starts DOWN for the first two requests (503 outage).
    let (server, addr) = Server::spawn(&["--fault", "503:2"]);
    let client = client(addr);
    let port = as_port(&client);

    // During the outage the client fabricates nothing: typed
    // ProviderUnavailable, twice (the fault budget spans two calls).
    for _ in 0..2 {
        match port.create_intent(live_requirement()) {
            Err(sharenet_connectivity::PortError::ProviderUnavailable { .. }) => {}
            other => panic!("expected ProviderUnavailable during the outage, got {other:?}"),
        }
    }

    // The provider recovers; ShareNet acquires and accepts one observation.
    let intent = port.create_intent(live_requirement()).expect("recovered intent");
    let offers = port.discover_offers(&intent).expect("offers");
    let c = port.accept_offer(&intent, &offers[0]).expect("accept");
    let mut store = sharenet_connectivity::DurableProjectionStore::create(&temp.path, WINDOW_SECS)
        .expect("create store");
    let first = port.get_assurance(&c).expect("assurance");
    assert_eq!(first.len(), 1);
    let at = first[0].observed_at_unix();
    assert_eq!(
        store.accept(&first[0]),
        sharenet_connectivity::AcceptOutcome::Accepted
    );
    store.flush().expect("flush");
    // FULL TEARDOWN + the provider goes unreachable (killed) — the reload
    // below happens with ADCOS down, purely from local durable state.
    drop(store);
    drop(client);
    drop(server);

    // Reload in a NEW PROCESS, past the freshness bound: the LAST ACCEPTED
    // observation with its ORIGINAL freshness metadata, typed stale.
    let stale_now = at + WINDOW_SECS + 100;
    let lines = probe(&["inspect", temp.path.to_str().unwrap(), &stale_now.to_string()]);
    let health = health_line(&lines, &c);
    assert_eq!(health[2], "active", "the accepted evidence, not a fabricated current state");
    assert_eq!(health[3], "stale");
    assert_eq!(health[4], (at + WINDOW_SECS).to_string(), "the ORIGINAL bound (at + window)");
    assert_eq!(health[7], at.to_string(), "the ORIGINAL observed_at, never re-anchored");
    assert_eq!(health[5], "1");
    assert_eq!(health[6], "1");

    // Same reload in-process, against the typed Rust surface.
    let store = sharenet_connectivity::DurableProjectionStore::load(&temp.path, stale_now)
        .expect("reload while the provider is down");
    assert_eq!(
        store.freshness_at_reload(&c),
        Some(sharenet_connectivity::ProjectionFreshness::Stale {
            fresh_until_unix: at + WINDOW_SECS,
            last_observed_at_unix: at,
        })
    );
    let health = store.health(&c).expect("health");
    let last = health.last_accepted().unwrap();
    assert_eq!(last.observation().observed_at_unix(), at);
    assert_eq!(
        last.observation().kind(),
        sharenet_connectivity::ObservationKind::ContractActivated,
        "the last ACCEPTED observation, exactly as accepted"
    );
    assert_eq!(last.fresh_until_unix(), at + WINDOW_SECS);
    // Local operation continues while the provider is down: the store
    // still reloads (and would flush) without any provider involvement.
    let again = sharenet_connectivity::DurableProjectionStore::load(&temp.path, now_unix())
        .expect("a second reload inside the bound");
    assert_eq!(
        again.freshness_at_reload(&c),
        Some(sharenet_connectivity::ProjectionFreshness::Fresh {
            fresh_until_unix: at + WINDOW_SECS,
        })
    );
}
