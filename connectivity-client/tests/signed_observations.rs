//! R5-004 "signed observations" integration verification: the REAL
//! `AdcosClient` against the REAL (signing) `adcos_test_server` over REAL
//! loopback TCP, feeding ONLY VERIFIED observations into the R5-003
//! `DurableProjectionStore` — including across a restart.
//!
//! What is proven, per the work item's verify levels:
//!
//! - **only-verified feeding** — every observation that reaches the
//!   connectivity layer (and through it the durable store) passed the
//!   protocol core's full admission first: signed envelope decode, strict
//!   statement parse, JSON-wrapper agreement, Ed25519 signature against
//!   the embedded provider identity, the known-contract rule, the
//!   per-(provider node_id, contract_ref) monotonic sequence gate and the
//!   accepting node's freshness window;
//! - **tampered / unsigned / rewritten observations are typed refusals**
//!   that NEVER enter the store — a tampered signature is
//!   `evidence_invalid(signature_invalid)`, an unsigned body is a typed
//!   `UnsignedObservation`, a rewritten JSON wrapper (signature still
//!   valid over the original bytes) is a typed `ObservationDisagreement`;
//!   through the trait they all degrade to `ProviderUnavailable` (an
//!   untrustworthy answer is not an answer);
//! - **the restart** — the persisted log contains only VERIFIED
//!   observations; a reload re-derives the projection from exactly that
//!   log, the reload path re-registers the durable contract list into the
//!   client's known-contract state (the daemon wiring), redeliveries are
//!   store-level replays, and the next provider observation continues the
//!   stream across the process boundary;
//! - **freshness edges over the real wire** — the deterministic
//!   `get_assurance_at` clock drives `not_yet_valid` and `expired`
//!   refusals against the provider's own timestamps.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sharenet_connectivity::{ConnectivityPort, DurableProjectionStore};
use sharenet_connectivity_client::{AdcosClient, AdcosConfig, AdcosError, MalformedReason};
use sharenet_protocol::ConnectivityEvidenceError;

const SERVER_BIN: &str = env!("CARGO_BIN_EXE_adcos_test_server");
const PROBE_BIN: &str = env!("CARGO_BIN_EXE_projection_store_probe");

/// The store's freshness window (the provider's bound, persisted in the
/// store header) — also the client's default admission window.
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
        let dir = std::env::temp_dir().join(format!("sharenet-r5004-it-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self {
            path: dir.join(format!("{tag}.store")),
        }
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let mut os = self.path.clone().into_os_string();
        os.push(".tmp");
        let _ = std::fs::remove_file(std::path::PathBuf::from(os));
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
fn health_line(
    lines: &[String],
    contract: &sharenet_connectivity::ConnectivityContractRef,
) -> Vec<String> {
    let prefix = format!("HEALTH {} ", contract.to_hex());
    let line = lines
        .iter()
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no health line for {}: {lines:?}", contract.to_hex()));
    line.split_whitespace().map(str::to_string).collect()
}

#[test]
fn verified_observations_reach_the_durable_store_and_survive_the_restart() {
    let temp = TempStore::new("cycle");
    let (server, addr) = Server::spawn(&[]);
    let client_e1 = client(addr);
    let port = as_port(&client_e1);
    let mut store = DurableProjectionStore::create(&temp.path, WINDOW_SECS)
        .expect("create store");

    // -- Epoch 1 (in-process): acquire → VERIFIED observation → store. ----
    let intent = port.create_intent(live_requirement()).expect("intent");
    let offers = port.discover_offers(&intent).expect("offers");
    let c1 = port.accept_offer(&intent, &offers[0]).expect("accept");
    // Through the TRAIT (the daemon seam): the client verified the signed
    // envelope before mapping this into domain data.
    let first = port.get_assurance(&c1).expect("assurance");
    assert_eq!(first.len(), 1);
    assert_eq!(
        first[0].kind(),
        sharenet_connectivity::ObservationKind::ContractActivated
    );
    let at1 = first[0].observed_at_unix();
    let seq1 = first[0].sequence();
    assert_eq!(
        store.accept(&first[0]),
        sharenet_connectivity::AcceptOutcome::Accepted
    );
    assert_eq!(
        store.health(&c1).expect("health").state(),
        sharenet_connectivity::ContractState::Active
    );
    store.flush().expect("flush");
    // FULL TEARDOWN: only the verified log on disk remains.
    drop(store);
    drop(client_e1);

    // -- Epoch 2 (REAL new process): the reload re-derives from the
    //    persisted log — which contains ONLY the verified observations. --
    let inspect = probe(&["inspect", temp.path.to_str().unwrap(), &now_unix().to_string()]);
    let health = health_line(&inspect, &c1);
    assert_eq!(inspect[0], "LOADED 1", "exactly one known contract");
    assert_eq!(health[2], "active", "re-derived from the verified log only");
    assert_eq!(health[5], "1", "one observation in the persisted log");
    assert_eq!(health[6], seq1.to_string());

    // -- Epoch 3 (live continuation): the daemon reload wiring — a fresh
    //    client re-registers the DURABLE contract list (the known-contract
    //    rule survives the restart), then the stream continues. ----------
    let client_e3 = client(addr);
    let mut store = DurableProjectionStore::load(&temp.path, now_unix())
        .expect("reload in-process (the daemon's own path)");
    for contract in store.contracts() {
        client_e3.register_known_contract(&contract);
    }
    let port = as_port(&client_e3);
    // The pre-restart redelivery is a store-level replay...
    let redelivered = port.get_assurance(&c1).expect("assurance");
    assert_eq!(redelivered.len(), 1, "still the single activated observation");
    assert_eq!(
        store.accept(&redelivered[0]),
        sharenet_connectivity::AcceptOutcome::IgnoredReplay { sequence: seq1 }
    );
    // ...and the next provider observation (terminate) continues the
    // stream, verified, across the restart.
    port.terminate(&c1).expect("terminate");
    let after = port.get_assurance(&c1).expect("assurance after terminate");
    assert_eq!(after.len(), 2, "activated + terminated");
    let terminated = &after[1];
    assert_eq!(
        terminated.kind(),
        sharenet_connectivity::ObservationKind::Terminated
    );
    let seq2 = terminated.sequence();
    let at2 = terminated.observed_at_unix();
    assert!(seq2 > seq1, "the provider's sequence continues: {seq2} > {seq1}");
    assert_eq!(
        store.accept(&redelivered[0]),
        sharenet_connectivity::AcceptOutcome::IgnoredReplay { sequence: seq1 }
    );
    assert_eq!(
        store.accept(terminated),
        sharenet_connectivity::AcceptOutcome::Accepted
    );
    assert_eq!(
        store.health(&c1).expect("health").state(),
        sharenet_connectivity::ContractState::Terminated
    );
    store.flush().expect("flush after the continuation");
    drop(client_e3);
    drop(store);

    // -- Epoch 4 (REAL new process again): the persisted log still contains
    //    ONLY verified observations — both of them, in order. --------------
    let inspect = probe(&["inspect", temp.path.to_str().unwrap(), &now_unix().to_string()]);
    let health = health_line(&inspect, &c1);
    assert_eq!(health[2], "terminated");
    assert_eq!(health[5], "2", "exactly the two VERIFIED observations");
    assert_eq!(health[6], seq2.to_string());
    assert_eq!(health[7], at2.to_string(), "the last accepted observation");
    let _ = at1;
    drop(server);
}

#[test]
fn tampered_signature_is_refused_and_never_enters_the_store() {
    let temp = TempStore::new("tamper");
    // The first two ASSURANCE responses flip a byte of the signature
    // inside the signed envelope — a mid-stream tamperer (the budget spans
    // the trait call and the inherent call below).
    let (server, addr) = Server::spawn(&["--fault", "tamper_sig:2"]);
    let client = client(addr);
    let port = as_port(&client);
    let mut store = DurableProjectionStore::create(&temp.path, WINDOW_SECS)
        .expect("create store");

    let intent = port.create_intent(live_requirement()).expect("intent");
    let offers = port.discover_offers(&intent).expect("offers");
    let contract = port.accept_offer(&intent, &offers[0]).expect("accept");

    // Through the trait: the untrustworthy answer is NOT an answer
    // (ProviderUnavailable) — nothing is fabricated.
    match port.get_assurance(&contract) {
        Err(sharenet_connectivity::PortError::ProviderUnavailable { .. }) => {}
        other => panic!("expected ProviderUnavailable for a tampered observation, got {other:?}"),
    }
    // Through the inherent surface: the TYPED evidence failure.
    match client.get_assurance(&contract) {
        Err(AdcosError::Evidence(ConnectivityEvidenceError::SignatureInvalid)) => {}
        other => panic!("expected typed signature failure, got {other:?}"),
    }
    // NOTHING entered the store: no observation accepted, no state.
    store.register(&contract);
    let health = store.health(&contract).expect("health");
    assert_eq!(health.state(), sharenet_connectivity::ContractState::Projected);
    assert_eq!(health.observations().len(), 0);
    assert_eq!(health.highest_sequence(), None);
    // And nothing was cached client-side either.
    assert_eq!(client.cached_fresh_until(&contract), None);

    // The provider recovers (fault budget was one): the same contract's
    // stream now verifies and the store receives it.
    let verified = port.get_assurance(&contract).expect("recovered assurance");
    assert_eq!(verified.len(), 1);
    assert_eq!(
        store.accept(&verified[0]),
        sharenet_connectivity::AcceptOutcome::Accepted
    );
    assert_eq!(
        store.health(&contract).expect("health").state(),
        sharenet_connectivity::ContractState::Active
    );
    drop(server);
}

#[test]
fn unsigned_and_rewritten_observations_are_refused_and_never_enter_the_store() {
    // Unsigned: the pre-R5-004 shape (no signed_envelope field). The
    // budget spans the trait call and the inherent call.
    let (unsigned_server, addr) = Server::spawn(&["--fault", "unsigned:2"]);
    let unsigned_client = client(addr);
    let port = as_port(&unsigned_client);
    let intent = port.create_intent(live_requirement()).expect("intent");
    let offers = port.discover_offers(&intent).expect("offers");
    let contract = port.accept_offer(&intent, &offers[0]).expect("accept");
    match unsigned_client.get_assurance(&contract) {
        Err(AdcosError::Malformed {
            reason: MalformedReason::UnsignedObservation,
        }) => {}
        other => panic!("expected typed UnsignedObservation, got {other:?}"),
    }
    // through the trait: ProviderUnavailable, nothing fabricated
    match port.get_assurance(&contract) {
        Err(sharenet_connectivity::PortError::ProviderUnavailable { .. }) => {}
        other => panic!("expected ProviderUnavailable for an unsigned observation, got {other:?}"),
    }
    assert_eq!(unsigned_client.cached_fresh_until(&contract), None);
    drop(unsigned_server);

    // Rewritten JSON wrapper: the signature still verifies over the
    // ORIGINAL bytes, but the wrapper's kind field disagrees.
    let (dto_server, addr) = Server::spawn(&["--fault", "tamper_dto:1"]);
    let dto_client = client(addr);
    let intent = dto_client
        .create_intent(live_requirement())
        .expect("intent");
    let offers = dto_client.discover_offers(&intent).expect("offers");
    let contract = dto_client
        .accept_offer(&intent, &offers[0])
        .expect("accept");
    match dto_client.get_assurance(&contract) {
        Err(AdcosError::Malformed {
            reason: MalformedReason::ObservationDisagreement { field: "kind" },
        }) => {}
        other => panic!("expected typed ObservationDisagreement, got {other:?}"),
    }
    assert_eq!(dto_client.cached_fresh_until(&contract), None);
    drop(dto_server);
}

#[test]
fn freshness_edges_over_the_real_wire_and_unknown_contract_rule() {
    let (server, addr) = Server::spawn(&[]);
    let verifier = client(addr);
    let intent = verifier.create_intent(live_requirement()).expect("intent");
    let offers = verifier.discover_offers(&intent).expect("offers");
    let contract = verifier.accept_offer(&intent, &offers[0]).expect("accept");

    // One verified observation (the deterministic clock seam).
    let verified = verifier
        .get_assurance_at(&contract, now_unix())
        .expect("assurance");
    assert_eq!(verified.len(), 1);
    let seq1 = verified[0].sequence();

    // A NEW observation (terminate) is where the freshness edges bite: a
    // redelivered old sequence is answered by the sequence gate, but the
    // new one is checked against the accepting node's window.
    verifier.terminate(&contract).expect("terminate");
    // Before the observation time: not yet valid (a time-travel probe).
    assert!(matches!(
        verifier.get_assurance_at(&contract, 0),
        Err(AdcosError::Evidence(ConnectivityEvidenceError::NotYetValid { .. }))
    ));
    // Past the exclusive freshness bound (observed_at is the provider's
    // now; now + window + 60 is certainly past its bound): expired.
    let cached = verifier.cached_fresh_until(&contract).expect("cached");
    assert!(matches!(
        verifier.get_assurance_at(&contract, now_unix() + WINDOW_SECS + 60),
        Err(AdcosError::Evidence(ConnectivityEvidenceError::Expired { .. }))
    ));
    assert_eq!(verifier.cached_fresh_until(&contract), Some(cached));
    // At a valid time the same log verifies: the redelivery (seq 1) plus
    // the new terminated observation (seq 2, admitted).
    let after = verifier
        .get_assurance_at(&contract, now_unix())
        .expect("assurance at a valid time");
    assert_eq!(after.len(), 2);
    assert_eq!(after[0].sequence(), seq1, "the redelivered activated observation");
    assert_eq!(
        after[1].kind(),
        sharenet_connectivity::ObservationKind::Terminated
    );
    assert!(after[1].sequence() > seq1);

    // The known-contract rule over the real wire: a FRESH client that
    // never accepted anything refuses the same observation with the typed
    // ContractUnknown (an unknown contract_ref is never a trust grant).
    let fresh_client = client(addr);
    match fresh_client.get_assurance(&contract) {
        Err(AdcosError::Evidence(ConnectivityEvidenceError::ContractUnknown { .. })) => {}
        other => panic!("expected typed ContractUnknown, got {other:?}"),
    }
    // Registering the contract (the reload seam) admits the stream again —
    // the full verified log is returned (dedup is the consumer's policy).
    fresh_client.register_known_contract(&contract);
    let reverified = fresh_client.get_assurance(&contract).expect("assurance");
    assert_eq!(reverified.len(), 2, "the same two verified observations");
    assert_eq!(reverified[1].sequence(), after[1].sequence());
    drop(server);
}
