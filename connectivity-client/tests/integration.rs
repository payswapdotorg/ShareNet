//! R5-002 integration verification: the REAL AdcosClient against the
//! REAL adcos_test_server process over REAL loopback TCP — the full
//! lifecycle, the adcos.md failure semantics, and the adversarial
//! fault modes (503 with cached freshness, dropped connections,
//! garbage bodies).

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use sharenet_connectivity::ConnectivityPort;
use sharenet_connectivity_client::{AdcosClient, AdcosConfig, AdcosError};

const SERVER_BIN: &str = env!("CARGO_BIN_EXE_adcos_test_server");

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
            .with_retry_delay(std::time::Duration::from_millis(30)),
    )
    .expect("client")
}

/// Call every test through the TRAIT object — the seam the future
/// daemon and R5-003/R5-004/R5-005 consumers use (the inherent methods
/// with their richer `AdcosError` surface are unit-tested in-crate).
fn as_port(client: &AdcosClient) -> &dyn ConnectivityPort {
    client
}

fn live_requirement() -> sharenet_connectivity::ConnectivityRequirement {
    sharenet_connectivity::ConnectivityRequirement::new(
        sharenet_connectivity::ServiceClass::Live,
    )
}

#[test]
fn full_lifecycle_against_real_server() {
    let (server, addr) = Server::spawn(&[]);
    let client = client(addr);
    let port = as_port(&client);

    let intent = port.create_intent(live_requirement()).expect("intent");
    let offers = port.discover_offers(&intent).expect("offers");
    assert_eq!(offers.len(), 2, "the server's deterministic offer set");
    let contract = port.accept_offer(&intent, &offers[0]).expect("accept");

    let projection = port.get_contract(&contract).expect("projection");
    assert_eq!(projection.state(), sharenet_connectivity::ContractState::Active);
    assert!(projection.valid_until_unix() > projection.valid_from_unix());

    let observations = port.get_assurance(&contract).expect("assurance");
    assert_eq!(observations.len(), 1);
    assert_eq!(
        observations[0].kind(),
        sharenet_connectivity::ObservationKind::ContractActivated
    );

    let execution = port.get_execution(&contract).expect("execution");
    assert!(execution.throughput_bps() > 0);

    port.terminate(&contract).expect("terminate");
    // Terminate is idempotent at the wire.
    port.terminate(&contract).expect("terminate again");

    // The terminated projection reflects the state; further acquisition
    // on the same contract refuses (the server keeps offers consumed).
    let after = port.get_contract(&contract).expect("projection after");
    assert_eq!(
        after.state(),
        sharenet_connectivity::ContractState::Terminated
    );
    let second = port.accept_offer(&intent, &offers[0]);
    assert!(matches!(
        second,
        Err(sharenet_connectivity::PortError::OfferAlreadyConsumed { .. })
    ));
    let _ = server;
}

#[test]
fn fault_503_then_recovery_with_cached_freshness() {
    // First two calls fail 503; the client must surface
    // ProviderUnavailable and — for a contract-scoped call — carry the
    // cached-observation freshness bound.
    let (server, addr) = Server::spawn(&["--fault", "503:2"]);
    let client = client(addr);
    let port = as_port(&client);

    // Status errors are NOT retried per call (a retried 503 is a
    // semantic choice the transport deliberately does not make), so the
    // fault budget of 2 spans two client calls.
    for _ in 0..2 {
        match port.create_intent(live_requirement()) {
            Err(sharenet_connectivity::PortError::ProviderUnavailable { last_observation_fresh_until_unix }) => {
                // A fresh intent call has no cached observation yet.
                assert_eq!(last_observation_fresh_until_unix, None);
            }
            other => panic!("expected ProviderUnavailable, got {other:?}"),
        }
    }
    // The server recovered: the next call succeeds.
    let intent = port.create_intent(live_requirement()).expect("recovered intent");
    let offers = port.discover_offers(&intent).expect("offers");
    let contract = port.accept_offer(&intent, &offers[0]).expect("accept");
    // Cache an observation first (assurance succeeds), then verify the
    // cached freshness bound through the inherent client API.
    let _ = port.get_assurance(&contract).expect("assurance");
    assert!(client.cached_fresh_until(&contract).is_some());
    let _ = server;
}

#[test]
fn dropped_connection_surfaces_typed_error_and_no_fabrication() {
    let (server, addr) = Server::spawn(&["--fault", "drop:2"]);
    let client = client(addr);
    let port = as_port(&client);

    // A dropped POST is NOT retried by the transport: the request may
    // have been applied server-side (the deliberate safety choice).
    // The fault budget of 2 spans two client calls.
    assert!(
        port.create_intent(live_requirement()).is_err(),
        "a dropped connection must fail typed, never fabricate an intent"
    );
    assert!(
        port.create_intent(live_requirement()).is_err(),
        "the second drop also fails typed"
    );
    // The server recovered.
    let intent = port.create_intent(live_requirement()).expect("recovered");
    let offers = port.discover_offers(&intent);
    assert!(offers.is_ok(), "fault budget exhausted, server healthy");
    let _ = server;
}

#[test]
fn garbage_body_fails_typed() {
    let (server, addr) = Server::spawn(&["--fault", "garbage:2"]);
    let client = client(addr);
    let port = as_port(&client);

    // Through the trait: an untrustworthy answer degrades to
    // ProviderUnavailable (never a fabricated intent)...
    let result = port.create_intent(live_requirement());
    assert!(
        matches!(
            result,
            Err(sharenet_connectivity::PortError::ProviderUnavailable { .. })
        ),
        "a 200 with non-JSON body must degrade to ProviderUnavailable, got {result:?}"
    );
    // ...and through the inherent surface the typed malformed detail is
    // visible for diagnosis.
    use sharenet_connectivity_client::AdcosError;
    let inherent = client.create_intent(live_requirement());
    assert!(
        matches!(inherent, Err(AdcosError::Malformed { .. })),
        "the inherent surface keeps the typed malformed error, got {inherent:?}"
    );
    let _ = server;
}

#[test]
fn two_clients_parallel_lifecycle() {
    let (server, addr) = Server::spawn(&[]);
    let client_a = std::sync::Arc::new(client(addr));
    let client_b = client_a.clone();

    let a = std::thread::spawn(move || {
        for _ in 0..5 {
            let intent = client_a.create_intent(live_requirement()).expect("intent");
            let offers = client_a.discover_offers(&intent).expect("offers");
            let contract = client_a.accept_offer(&intent, &offers[0]).expect("accept");
            client_a.terminate(&contract).expect("terminate");
        }
    });
    let b = std::thread::spawn(move || {
        for _ in 0..5 {
            let intent = client_b.create_intent(live_requirement()).expect("intent");
            let offers = client_b.discover_offers(&intent).expect("offers");
            let contract = client_b.accept_offer(&intent, &offers[1]).expect("accept");
            client_b.terminate(&contract).expect("terminate");
        }
    });
    a.join().expect("a");
    b.join().expect("b");
    let _ = server;
}

#[test]
fn unknown_refs_are_typed_not_found() {
    let (server, addr) = Server::spawn(&[]);
    let client = client(addr);
    let port = as_port(&client);
    let bogus = sharenet_connectivity::ConnectivityIntentRef::from_parts(
        sharenet_connectivity::RefKind::Intent,
        [0xAB; 32],
    )
    .expect("ref");
    match port.discover_offers(&bogus) {
        Err(sharenet_connectivity::PortError::IntentUnknown { .. }) => {}
        other => panic!("expected IntentUnknown, got {other:?}"),
    }
    let _ = server;
}

#[test]
fn config_validation_refuses_zero_attempts() {
    let result = AdcosClient::new(AdcosConfig::new("127.0.0.1:1".parse().unwrap()).with_max_attempts(0));
    assert!(matches!(result, Err(AdcosError::ConfigInvalid { .. })));
}
