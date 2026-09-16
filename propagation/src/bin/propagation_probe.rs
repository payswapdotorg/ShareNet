//! `propagation_probe` — TEST SCAFFOLDING for the R6-005
//! "multiprocess" verify level: REAL separate processes that plan a
//! contact, apply a handover (re-verified reads + one custody record
//! + flush), carry the material across the process boundary as
//! machine-parsable bytes, and take custody at the receiving edge
//! through the R6-004 rules into a DIFFERENT node's store.
//!
//! The ShareNet daemon is modeled as a sequence of probe invocations
//! (the dtn_probe pattern): each process sees the stores ONLY
//! through the bytes on disk, and the handover material ONLY through
//! the pipe (stdout → stdin).
//!
//! Usage:
//!
//! ```text
//! propagation_probe seed     <dir> <seed> <priority> <now> <expires> <target> [chunks]
//! propagation_probe plan     <dir> <now> <gw_hex> <opens> <closes> <valid_until> <max_bytes> <max_bundles> [plan_clock]
//! propagation_probe handover <dir> <now> <gw_hex> <opens> <closes> <valid_until> <max_bytes> <max_bundles>
//! propagation_probe receive  <dir> <now> <peer_hex>            (handover material on stdin)
//! propagation_probe evidence <dir>
//! propagation_probe status   <dir> <now> <content_hex>
//! ```
//!
//! `<seed>` drives DETERMINISTIC content (the same seed always
//! derives the same manifest + chunks in any process). The
//! `plan`/`handover` commands synthesize the R5-005 `Eligible`
//! verdict for `<gw_hex>` valid until `<valid_until>` — test
//! scaffolding: the real daemon derives the verdict by running the
//! admission policy over signed evidence; this probe models the
//! post-admission snapshot the contact layer consumes either way.
//!
//! stdout protocol (machine-parsable, one record per line):
//!
//! ```text
//! SEEDED <content_hex> <chunk_count>                          (seed)
//! VERDICT <plan|nothing_to_forward|refused> [refusal_name]     (plan)
//! STEP <content_hex> <priority> <expires> <count>/<target> <present>/<total> <byte_cost>
//! DEFER <content_hex> <reason_name>
//! DONE <steps> <deferred>                                      (plan end)
//! HANDOVER <content_hex> NOTED <replication_count>            (handover, per applied step)
//! OFFER <content_hex> <priority_name> <expires> <target>       (handover, per bundle)
//! MANIFEST <hex>                                              (handover material)
//! CHUNK <slot> <hex>                                           (handover material)
//! FAILED <content_hex> <forward_error_name>                    (handover, per failed step)
//! RECEIVED <content_hex> <manifest_verdict_name> chunks=<ok>/<dup>/<refused>   (receive)
//! EVIDENCE <kind> <at_unix> <peer_hex> <content_hex>           (evidence)
//! STATUS <bundle_status_name>                                  (status)
//! ERROR <typed_machine_name>                                  (on any failure)
//! ```
//!
//! Exit codes: 0 ok; 2 usage error; 3 typed failure (fail-closed,
//! printed typed).

use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

use sharenet_admission::{
    AdcosEvidenceAnchor, GatewayAdmission, ShareNetEvidenceAnchor,
};
use sharenet_connectivity::{ContractState, ConnectivityContractRef};
use sharenet_dtn::{hex, CustodyRecord, DtnStore, DtnError, PeerRef, ServicePriority};
use sharenet_protocol::ContentManifest;
use sharenet_propagation::{
    ChunkOffer, ContactBudget, ContactOpportunity, ForwardVerdict, ForwarderParams,
    ManifestOffer, OpportunisticForwarder, PropagationPolicy,
};

/// The deterministic chunk size of seeded content (the dtn_probe
/// convention).
const SEED_CHUNK_SIZE: u64 = 12;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [cmd, rest @ ..] => dispatch(cmd, rest),
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}

fn usage() {
    eprintln!("usage: propagation_probe seed     <dir> <seed> <priority> <now> <expires> <target> [chunks]");
    eprintln!("       propagation_probe plan     <dir> <now> <gw_hex> <opens> <closes> <valid_until> <max_bytes> <max_bundles> [plan_clock]");
    eprintln!("       propagation_probe handover <dir> <now> <gw_hex> <opens> <closes> <valid_until> <max_bytes> <max_bundles>");
    eprintln!("       propagation_probe receive  <dir> <now> <peer_hex>");
    eprintln!("       propagation_probe evidence <dir>");
    eprintln!("       propagation_probe status   <dir> <now> <content_hex>");
}

fn dispatch(cmd: &str, rest: &[String]) -> ExitCode {
    match cmd {
        "seed" => cmd_seed(rest),
        "plan" => cmd_plan(rest),
        "handover" => cmd_handover(rest),
        "receive" => cmd_receive(rest),
        "evidence" => cmd_evidence(rest),
        "status" => cmd_status(rest),
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}

// -- deterministic seeded content (the dtn_probe convention) ----------

fn seed_content(seed: u8) -> Vec<u8> {
    let len = 40 + seed as usize;
    (0..len)
        .map(|i| seed.wrapping_mul(31).wrapping_add(i as u8))
        .collect()
}

fn seed_manifest(seed: u8) -> (ContentManifest, Vec<Vec<u8>>) {
    ContentManifest::chunk(
        &seed_content(seed),
        SEED_CHUNK_SIZE,
        "text/plain",
        None,
        1_700_000_000 + seed as u64,
    )
    .expect("seeded content is always valid")
}

// -- parsing helpers ---------------------------------------------------

fn parse_seed(s: &str) -> Result<u8, ExitCode> {
    s.parse::<u8>().map_err(|_| {
        eprintln!("error: seed must be a u8");
        ExitCode::from(2)
    })
}

fn parse_u64(s: &str, what: &str) -> Result<u64, ExitCode> {
    s.parse::<u64>().map_err(|_| {
        eprintln!("error: {what} must be a u64");
        ExitCode::from(2)
    })
}

fn parse_peer(hex_str: &str) -> Result<PeerRef, ExitCode> {
    let bytes = hex::decode(hex_str).map_err(|_| {
        eprintln!("error: peer must be hex");
        ExitCode::from(2)
    })?;
    PeerRef::new(&bytes).map_err(|_| {
        eprintln!("error: peer must be 1..=64 bytes");
        ExitCode::from(2)
    })
}

fn parse_gateway(hex_str: &str) -> Result<[u8; 32], ExitCode> {
    hex::decode_32(hex_str).map_err(|_| {
        eprintln!("error: gateway must be 64 hex chars");
        ExitCode::from(2)
    })
}

fn fail(err: DtnError) -> ExitCode {
    println!("ERROR {}", err.name());
    eprintln!("error: {err}");
    ExitCode::from(3)
}

/// The synthetic Eligible verdict the probe models the daemon's
/// post-admission snapshot with (see the module docs).
fn eligible(gateway: [u8; 32], valid_until: u64) -> GatewayAdmission {
    GatewayAdmission::Eligible {
        gateway_node_id: gateway,
        sharenet: ShareNetEvidenceAnchor {
            link_id: [1; 32],
            observer_node_id: [2; 32],
            observed_at_unix: valid_until.saturating_sub(100),
            expires_at_unix: valid_until,
            loss_ratio_ppm_effective: 0,
            p95_rtt_micros: 1_000,
            fresh_until_unix: valid_until,
        },
        adcos: AdcosEvidenceAnchor {
            contract: ConnectivityContractRef::from_id([3; 32]),
            state: ContractState::Active,
            fresh_until_unix: valid_until,
            last_observed_at_unix: valid_until.saturating_sub(100),
            last_sequence: 1,
            provider_node_id: [4; 32],
        },
        valid_until_unix: valid_until,
    }
}

// -- subcommands --------------------------------------------------------

/// Create a store holding the seeded bundle (its first `chunks`
/// chunks, default all) with a Received custody record — a node
/// that just accepted content off a contact.
fn cmd_seed(args: &[String]) -> ExitCode {
    let [dir, seed_s, priority_s, now_s, expires_s, target_s, rest @ ..] = args else {
        usage();
        return ExitCode::from(2);
    };
    let (dir, seed) = match (PathBuf::from(dir), parse_seed(seed_s)) {
        (dir, Ok(seed)) => (dir, seed),
        (_, Err(code)) => return code,
    };
    let priority = match ServicePriority::from_name(priority_s) {
        Some(p) => p,
        None => {
            eprintln!("error: priority must be live|opportunistic|dtn");
            return ExitCode::from(2);
        }
    };
    let (now, expires, target) = match (
        parse_u64(now_s, "now"),
        parse_u64(expires_s, "expires"),
        target_s.parse::<u32>(),
    ) {
        (Ok(a), Ok(b), Ok(c)) => (a, b, c),
        _ => return ExitCode::from(2),
    };
    let (manifest, chunks) = seed_manifest(seed);
    let take = match rest {
        [] => chunks.len(),
        [n] => n.parse::<usize>().unwrap_or_else(|_| {
            eprintln!("error: chunks must be a usize");
            std::process::exit(2);
        }),
        _ => {
            usage();
            return ExitCode::from(2);
        }
    };
    let mut store = match DtnStore::create(&dir) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let content_id = manifest.content_id();
    if let Err(e) = store.admit_manifest(&manifest, priority, now, expires, target) {
        return fail(e);
    }
    for (slot, chunk) in chunks.iter().enumerate().take(take) {
        if let Err(e) = store.admit_chunk(&content_id, slot, chunk, now) {
            return fail(e);
        }
    }
    let peer = PeerRef::new(&[seed, seed]).expect("2-byte peer");
    if let Err(e) = store.record_evidence(CustodyRecord::received(content_id, now, &peer)) {
        return fail(e);
    }
    if let Err(e) = store.flush() {
        return fail(e);
    }
    println!("SEEDED {} {}", hex::encode(&content_id), chunks.len());
    ExitCode::SUCCESS
}

/// Load the store, build the typed contact window, and print the
/// forwarder's plan (pure decision, nothing is applied).
fn cmd_plan(args: &[String]) -> ExitCode {
    let [dir, now_s, gw_hex, opens_s, closes_s, valid_s, bytes_s, bundles_s, rest @ ..] = args
    else {
        usage();
        return ExitCode::from(2);
    };
    let (now, opens, closes, valid, max_bytes, max_bundles) =
        match (
            parse_u64(now_s, "now"),
            parse_u64(opens_s, "opens"),
            parse_u64(closes_s, "closes"),
            parse_u64(valid_s, "valid_until"),
            parse_u64(bytes_s, "max_bytes"),
            bundles_s.parse::<u32>(),
        ) {
            (Ok(a), Ok(b), Ok(c), Ok(d), Ok(e), Ok(f)) => (a, b, c, d, e, f),
            _ => return ExitCode::from(2),
        };
    let gateway = match parse_gateway(gw_hex) {
        Ok(g) => g,
        Err(code) => return code,
    };
    let plan_clock = match rest {
        [] => now,
        [clock_s] => match parse_u64(clock_s, "plan_clock") {
            Ok(c) => c,
            Err(code) => return code,
        },
        _ => {
            usage();
            return ExitCode::from(2);
        }
    };
    let store = match DtnStore::load(std::path::Path::new(dir), now) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let verdict = eligible(gateway, valid);
    let budget = match ContactBudget::new(max_bytes, max_bundles) {
        Ok(b) => b,
        Err(err) => {
            println!("ERROR {}", err.name());
            eprintln!("error: {err}");
            return ExitCode::from(3);
        }
    };
    let contact = match ContactOpportunity::new(gateway, &verdict, opens, closes, budget) {
        Ok(c) => c,
        Err(err) => {
            println!("ERROR {}", err.name());
            eprintln!("error: {err}");
            return ExitCode::from(3);
        }
    };
    let forwarder = OpportunisticForwarder::new(ForwarderParams::default());
    let outcome = forwarder.plan(&contact, store.image(), plan_clock);
    match outcome {
        ForwardVerdict::NothingToForward => {
            println!("VERDICT nothing_to_forward");
            println!("DONE 0 0");
        }
        ForwardVerdict::Refused(refusal) => {
            println!("VERDICT refused {}", refusal.name());
            println!("DONE 0 0");
        }
        ForwardVerdict::Plan(plan) => {
            println!("VERDICT plan");
            for step in plan.steps() {
                let s = step.summary();
                println!(
                    "STEP {} {} {} {}/{} {}/{} {}",
                    hex::encode(step.content_id()),
                    step.priority(),
                    step.expires_at_unix(),
                    s.replication_count(),
                    s.replication_target(),
                    s.present_chunk_count(),
                    s.chunk_count(),
                    step.byte_cost(),
                );
            }
            for deferred in plan.deferred() {
                println!(
                    "DEFER {} {}",
                    hex::encode(deferred.content_id()),
                    deferred.reason().name()
                );
            }
            println!("DONE {} {}", plan.steps().len(), plan.deferred().len());
        }
    }
    ExitCode::SUCCESS
}

/// Plan AND apply the handover on the file-backed store: every step
/// re-verified at the apply clock, the material read back with
/// re-verification, one custody record per step, one flush. The
/// material is emitted as the machine-parsable wire dump a receiving
/// process consumes (`receive`).
fn cmd_handover(args: &[String]) -> ExitCode {
    let [dir, now_s, gw_hex, opens_s, closes_s, valid_s, bytes_s, bundles_s] = args else {
        usage();
        return ExitCode::from(2);
    };
    let (now, opens, closes, valid, max_bytes, max_bundles) =
        match (
            parse_u64(now_s, "now"),
            parse_u64(opens_s, "opens"),
            parse_u64(closes_s, "closes"),
            parse_u64(valid_s, "valid_until"),
            parse_u64(bytes_s, "max_bytes"),
            bundles_s.parse::<u32>(),
        ) {
            (Ok(a), Ok(b), Ok(c), Ok(d), Ok(e), Ok(f)) => (a, b, c, d, e, f),
            _ => return ExitCode::from(2),
        };
    let gateway = match parse_gateway(gw_hex) {
        Ok(g) => g,
        Err(code) => return code,
    };
    let mut store = match DtnStore::load(std::path::Path::new(dir), now) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let verdict = eligible(gateway, valid);
    let budget = match ContactBudget::new(max_bytes, max_bundles) {
        Ok(b) => b,
        Err(err) => {
            println!("ERROR {}", err.name());
            eprintln!("error: {err}");
            return ExitCode::from(3);
        }
    };
    let contact = match ContactOpportunity::new(gateway, &verdict, opens, closes, budget) {
        Ok(c) => c,
        Err(err) => {
            println!("ERROR {}", err.name());
            eprintln!("error: {err}");
            return ExitCode::from(3);
        }
    };
    let forwarder = OpportunisticForwarder::new(ForwarderParams::default());
    let plan = match forwarder.plan(&contact, store.image(), now) {
        ForwardVerdict::Plan(plan) => plan,
        ForwardVerdict::NothingToForward => {
            println!("VERDICT nothing_to_forward");
            println!("DONE 0 0");
            return ExitCode::SUCCESS;
        }
        ForwardVerdict::Refused(refusal) => {
            println!("VERDICT refused {}", refusal.name());
            println!("DONE 0 0");
            return ExitCode::SUCCESS;
        }
    };
    println!("VERDICT plan");
    let application = forwarder.apply_plan(&mut store, &contact, &plan, now);
    for (step, material) in application.applied() {
        // The custody record (evidence + the replication count's
        // twin), read back from the store that now holds it.
        let count = store
            .image()
            .summary(step.content_id())
            .map(|s| s.replication_count())
            .unwrap_or(0);
        println!(
            "HANDOVER {} NOTED {}",
            hex::encode(step.content_id()),
            count
        );
        println!(
            "OFFER {} {} {} {}",
            hex::encode(step.content_id()),
            step.priority(),
            step.expires_at_unix(),
            step.summary().replication_target(),
        );
        println!("MANIFEST {}", hex::encode(material.manifest_bytes()));
        for (slot, bytes) in material.chunks() {
            println!("CHUNK {slot} {}", hex::encode(bytes));
        }
    }
    for (step, error) in application.failed() {
        println!(
            "FAILED {} {}",
            hex::encode(step.content_id()),
            error.name()
        );
    }
    if let Err(e) = store.flush() {
        return fail(e);
    }
    println!(
        "DONE {} {}",
        application.applied().len(),
        application.failed().len()
    );
    ExitCode::SUCCESS
}

/// The receiving edge across a process boundary: read the handover
/// material from stdin and take custody through the R6-004 rules
/// (decide + the store's own admission APIs) into `<dir>`'s store.
fn cmd_receive(args: &[String]) -> ExitCode {
    let [dir, now_s, peer_hex] = args else {
        usage();
        return ExitCode::from(2);
    };
    let now = match parse_u64(now_s, "now") {
        Ok(n) => n,
        Err(code) => return code,
    };
    let peer = match parse_peer(peer_hex) {
        Ok(p) => p,
        Err(code) => return code,
    };
    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        eprintln!("error: cannot read stdin");
        return ExitCode::from(2);
    }
    // A receiving node starts with an empty custody store (the
    // receiving edge of the multiprocess evidence); an EXISTING store
    // is loaded under the full trust-nothing discipline.
    let path = std::path::Path::new(dir);
    let mut store = if path.join(sharenet_dtn::REGISTRY_FILE_NAME).exists() {
        match DtnStore::load(path, now) {
            Ok(s) => s,
            Err(e) => return fail(e),
        }
    } else {
        match DtnStore::create(path) {
            Ok(s) => s,
            Err(e) => return fail(e),
        }
    };
    let policy = PropagationPolicy::default();
    // Parse the material into whole OFFER groups first (fail-closed on
    // any malformed line BEFORE any custody is taken).
    let mut offers: Vec<MaterialOffer> = Vec::new();
    for line in input.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("OFFER ") {
            let mut parts = rest.split(' ');
            let (Some(_content_hex), Some(priority_name), Some(expires_s), Some(target_s)) =
                (parts.next(), parts.next(), parts.next(), parts.next())
            else {
                eprintln!("error: bad OFFER line");
                return ExitCode::from(2);
            };
            let (Ok(expires), Ok(target)) =
                (expires_s.parse::<u64>(), target_s.parse::<u32>())
            else {
                eprintln!("error: bad OFFER line");
                return ExitCode::from(2);
            };
            offers.push(MaterialOffer {
                priority_name: priority_name.to_owned(),
                expires,
                target,
                manifest: Vec::new(),
                chunks: Vec::new(),
            });
        } else if let Some(rest) = line.strip_prefix("MANIFEST ") {
            let bytes = match hex::decode(rest) {
                Ok(b) => b,
                Err(_) => {
                    eprintln!("error: bad MANIFEST line");
                    return ExitCode::from(2);
                }
            };
            match offers.last_mut() {
                Some(offer) => offer.manifest = bytes,
                None => {
                    eprintln!("error: MANIFEST before OFFER");
                    return ExitCode::from(2);
                }
            }
        } else if let Some(rest) = line.strip_prefix("CHUNK ") {
            let mut parts = rest.split(' ');
            let (Some(slot_s), Some(hex_bytes)) = (parts.next(), parts.next()) else {
                eprintln!("error: bad CHUNK line");
                return ExitCode::from(2);
            };
            let (Ok(slot), Ok(bytes)) =
                (slot_s.parse::<u32>(), hex::decode(hex_bytes))
            else {
                eprintln!("error: bad CHUNK line");
                return ExitCode::from(2);
            };
            match offers.last_mut() {
                Some(offer) => offer.chunks.push((slot, bytes)),
                None => {
                    eprintln!("error: CHUNK before OFFER");
                    return ExitCode::from(2);
                }
            }
        } else if line.starts_with("VERDICT ")
            || line.starts_with("HANDOVER ")
            || line.starts_with("FAILED ")
            || line.starts_with("DONE ")
        {
            // The sender-side protocol lines of a piped-through
            // `handover` output: not material — skip (the fail-closed
            // law applies to everything else).
            continue;
        } else if !line.is_empty() {
            eprintln!("error: unrecognized material line: {line}");
            return ExitCode::from(2);
        }
    }
    // Take custody of each offer group through the R6-004 rules
    // (the daemon's file-backed path: decide over the image, apply
    // through the store's own APIs).
    let mut received = 0u64;
    for offer in &offers {
        // Strict parse once (the R6-001 invariants); the id is
        // derived, never claimed.
        let manifest = match ContentManifest::from_wire_bytes(&offer.manifest) {
            Ok(manifest) => manifest,
            Err(_) => {
                println!("ERROR manifest_malformed");
                eprintln!("error: offered manifest does not parse");
                return ExitCode::from(3);
            }
        };
        let id = manifest.content_id();
        let verdict = policy.decide_manifest(
            &ManifestOffer::new(&offer.manifest, &offer.priority_name, offer.expires, offer.target, &peer),
            store.image(),
            now,
        );
        if let sharenet_propagation::ManifestVerdict::Accept(anchor) = &verdict {
            if let Err(e) = store.admit_manifest(
                &manifest,
                anchor.priority(),
                now,
                offer.expires,
                anchor.replication_target(),
            ) {
                return fail(e);
            }
            if let Err(e) =
                store.record_evidence(CustodyRecord::received(*anchor.content_id(), now, &peer))
            {
                return fail(e);
            }
        }
        // The chunks decide against the (possibly newly) held state:
        // accepted slots land, verified duplicates count, refusals
        // count (nothing stored on the back of one).
        let mut ok = 0u64;
        let mut dup = 0u64;
        let mut refused = 0u64;
        for (slot, bytes) in &offer.chunks {
            let chunk_offer = ChunkOffer::new(id, *slot as usize, bytes);
            match policy.decide_chunk(&chunk_offer, store.image(), now) {
                sharenet_propagation::ChunkVerdict::Accept(_) => {
                    if let Err(e) = store.admit_chunk(&id, *slot as usize, bytes, now) {
                        return fail(e);
                    }
                    ok += 1;
                }
                sharenet_propagation::ChunkVerdict::Duplicate { .. } => dup += 1,
                sharenet_propagation::ChunkVerdict::Refused(_) => refused += 1,
            }
        }
        println!(
            "RECEIVED {} {} chunks={ok}/{dup}/{refused}",
            hex::encode(&id),
            verdict.name()
        );
        received += 1;
    }
    if let Err(e) = store.flush() {
        return fail(e);
    }
    println!("DONE {received}");
    ExitCode::SUCCESS
}

/// One parsed OFFER group of the handover material (the probe's
/// in-memory shape of what crossed the process boundary).
struct MaterialOffer {
    priority_name: String,
    expires: u64,
    target: u32,
    manifest: Vec<u8>,
    chunks: Vec<(u32, Vec<u8>)>,
}


/// The custody evidence log, in append order (the dtn_probe shape).
fn cmd_evidence(args: &[String]) -> ExitCode {
    let [dir] = args else {
        usage();
        return ExitCode::from(2);
    };
    let store = match DtnStore::load(std::path::Path::new(dir), 1_700_000_900) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    for r in store.image().evidence() {
        println!(
            "EVIDENCE {} {} {} {}",
            r.kind(),
            r.at_unix(),
            r.peer().to_hex(),
            hex::encode(r.content_id()),
        );
    }
    println!("DONE {}", store.image().evidence_count());
    ExitCode::SUCCESS
}

/// A held bundle's typed status at a caller clock (the dtn_probe
/// shape).
fn cmd_status(args: &[String]) -> ExitCode {
    let [dir, now_s, content_hex] = args else {
        usage();
        return ExitCode::from(2);
    };
    let (now, id) = match (
        parse_u64(now_s, "now"),
        hex::decode_32(content_hex),
    ) {
        (Ok(n), Ok(i)) => (n, i),
        _ => {
            eprintln!("error: bad args (content must be 64 hex chars)");
            return ExitCode::from(2);
        }
    };
    let store = match DtnStore::load(std::path::Path::new(dir), now) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    match store.image().bundle_status(&id, now) {
        Ok(status) => {
            println!("STATUS {}", status.as_str());
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}
