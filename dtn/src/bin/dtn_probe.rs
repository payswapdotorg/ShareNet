//! `dtn_probe` — TEST SCAFFOLDING for the R6-003 "multiprocess" verify
//! level: a REAL separate process that loads the DTN custody store from
//! disk and continues custody — proving the store survives a process
//! boundary with state, dedup, TTL math and custody records intact.
//!
//! The ShareNet daemon is modeled as a sequence of probe invocations:
//! each is a fresh process that sees the store ONLY through the bytes on
//! disk.
//!
//! Usage:
//!
//! ```text
//! dtn_probe seed        <dir> <seed> <priority> <now> <expires> <target> [chunks]
//! dtn_probe fill-chunks <dir> <seed> [chunks]
//! dtn_probe forward-list <dir> <now>
//! dtn_probe forward-one <dir> <now> <peer_hex>
//! dtn_probe deliver    <dir> <now> <peer_hex>
//! dtn_probe evict       <dir> <now>
//! dtn_probe evidence    <dir>
//! dtn_probe status      <dir> <now> <content_hex>
//! dtn_probe read-chunk  <dir> <seed> <slot>
//! ```
//!
//! `<seed>` drives DETERMINISTIC content (the same seed always derives
//! the same manifest + content id — both here and in the tests, which is
//! how a second process continues a first process's bundle). `<priority>`
//! is a service-class name (`live` | `opportunistic` | `dtn`).
//!
//! stdout protocol (machine-parsable, one record per line):
//!
//! ```text
//! SEEDED <content_hex> <chunk_count>                       (seed)
//! FILLED <content_hex> <present>/<chunk_count>            (fill-chunks)
//! FORWARD <priority> <expires_at> <count>/<target> <present>/<total> <content_hex>
//! DONE <n>                                                  (list end)
//! FORWARDED <content_hex> <replication_count>              (forward-one)
//! DELIVERED <content_hex>                                   (deliver)
//! EVICTED <content_hex>                                     (evict, per bundle)
//! EVIDENCE <kind> <at_unix> <peer_hex> <content_hex>       (evidence)
//! STATUS <status_name>                                      (status)
//! CHUNK <slot> <byte_len>                                   (read-chunk)
//! ERROR <dtn_error_machine_name>                            (on any failure)
//! ```
//!
//! Exit codes: 0 ok; 2 usage error; 3 store error (fail-closed, printed
//! typed).

use std::path::PathBuf;
use std::process::ExitCode;

use sharenet_dtn::{
    hex, CustodyKind, CustodyRecord, DtnStore, DtnError, PeerRef, ServicePriority,
    CONTENT_ID_LEN,
};
use sharenet_protocol::ContentManifest;

/// The deterministic chunk size of seeded content (12 bytes: multi-chunk
/// with a short last chunk for most lengths).
const SEED_CHUNK_SIZE: u64 = 12;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.as_slice() {
        [cmd, rest @ ..] => dispatch(cmd, rest),
        _ => {
            usage();
            ExitCode::from(2)
        }
    };
    code
}

fn usage() {
    eprintln!("usage: dtn_probe seed <dir> <seed> <priority> <now> <expires> <target> [chunks]");
    eprintln!("       dtn_probe fill-chunks <dir> <seed> [chunks]");
    eprintln!("       dtn_probe forward-list <dir> <now>");
    eprintln!("       dtn_probe forward-one <dir> <now> <peer_hex>");
    eprintln!("       dtn_probe deliver <dir> <now> <peer_hex>");
    eprintln!("       dtn_probe evict <dir> <now>");
    eprintln!("       dtn_probe evidence <dir>");
    eprintln!("       dtn_probe status <dir> <now> <content_hex>");
    eprintln!("       dtn_probe read-chunk <dir> <seed> <slot>");
}

fn dispatch(cmd: &str, rest: &[String]) -> ExitCode {
    match cmd {
        "seed" => cmd_seed(rest),
        "fill-chunks" => cmd_fill(rest),
        "forward-list" => cmd_forward_list(rest),
        "forward-one" => cmd_forward_one(rest),
        "deliver" => cmd_deliver(rest),
        "evict" => cmd_evict(rest),
        "evidence" => cmd_evidence(rest),
        "status" => cmd_status(rest),
        "read-chunk" => cmd_read_chunk(rest),
        _ => {
            usage();
            ExitCode::from(2)
        }
    }
}

// -- deterministic seeded content ------------------------------------------

/// Deterministic content bytes for a seed (never empty).
fn seed_content(seed: u8) -> Vec<u8> {
    let len = 40 + seed as usize; // 40..=295 bytes: multi-chunk, short last
    (0..len)
        .map(|i| seed.wrapping_mul(31).wrapping_add(i as u8))
        .collect()
}

/// The manifest + chunks a seed derives (identical in every process).
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

fn fail(err: DtnError) -> ExitCode {
    println!("ERROR {}", err.name());
    eprintln!("error: {err}");
    ExitCode::from(3)
}

// -- subcommands -----------------------------------------------------------

/// Create (or refuse) + admit the seeded manifest, its first `chunks`
/// chunks (default: all), and a Received custody record.
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
        [n] => match n.parse::<usize>() {
            Ok(n) => n,
            Err(_) => return ExitCode::from(2),
        },
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
    let peer = match parse_peer(&format!("{seed:02x}{seed:02x}")) {
        Ok(p) => p,
        Err(code) => return code,
    };
    if let Err(e) = store.record_evidence(CustodyRecord::received(content_id, now, &peer)) {
        return fail(e);
    }
    if let Err(e) = store.flush() {
        return fail(e);
    }
    println!("SEEDED {} {}", hex::encode(&content_id), chunks.len());
    ExitCode::SUCCESS
}

/// Load an existing store and continue custody by admitting more of the
/// seeded bundle's chunks (the process-boundary resume story: a later
/// process completes a partial bundle).
fn cmd_fill(args: &[String]) -> ExitCode {
    let [dir, seed_s, rest @ ..] = args else {
        usage();
        return ExitCode::from(2);
    };
    let (dir, seed) = match (PathBuf::from(dir), parse_seed(seed_s)) {
        (dir, Ok(seed)) => (dir, seed),
        (_, Err(code)) => return code,
    };
    let upto = match rest {
        [] => usize::MAX,
        [n] => match n.parse::<usize>() {
            Ok(n) => n,
            Err(_) => return ExitCode::from(2),
        },
        _ => {
            usage();
            return ExitCode::from(2);
        }
    };
    // A caller clock strictly inside the seed default TTL (the fill is a
    // custody continuation, never an expiry edge — the tests control
    // expiry through forward-list/evict clocks).
    let now = 1_700_000_900;
    let mut store = match DtnStore::load(&dir, now) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let (manifest, chunks) = seed_manifest(seed);
    let content_id = manifest.content_id();
    for (slot, chunk) in chunks.iter().enumerate().take(upto) {
        if let Err(e) = store.admit_chunk(&content_id, slot, chunk, now) {
            return fail(e);
        }
    }
    if let Err(e) = store.flush() {
        return fail(e);
    }
    let present = store.image().present_slots(&content_id).map(|s| s.len()).unwrap_or(0);
    println!(
        "FILLED {} {}/{}",
        hex::encode(&content_id),
        present,
        chunks.len()
    );
    ExitCode::SUCCESS
}

fn cmd_forward_list(args: &[String]) -> ExitCode {
    let [dir, now_s] = args else {
        usage();
        return ExitCode::from(2);
    };
    let (dir, now) = match (PathBuf::from(dir), parse_u64(now_s, "now")) {
        (d, Ok(n)) => (d, n),
        _ => return ExitCode::from(2),
    };
    let store = match DtnStore::load(&dir, now) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let list = store.forward_candidates(now);
    for c in &list {
        let s = c.summary();
        println!(
            "FORWARD {} {} {}/{} {}/{} {}",
            s.priority(),
            s.expires_at_unix(),
            s.replication_count(),
            s.replication_target(),
            s.present_chunk_count(),
            s.chunk_count(),
            hex::encode(s.content_id()),
        );
    }
    println!("DONE {}", list.len());
    ExitCode::SUCCESS
}

fn cmd_forward_one(args: &[String]) -> ExitCode {
    let [dir, now_s, peer_hex] = args else {
        usage();
        return ExitCode::from(2);
    };
    let (dir, now, peer) = match (
        PathBuf::from(dir),
        parse_u64(now_s, "now"),
        parse_peer(peer_hex),
    ) {
        (d, Ok(n), Ok(p)) => (d, n, p),
        _ => return ExitCode::from(2),
    };
    let mut store = match DtnStore::load(&dir, now) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let Some(first) = store.forward_candidates(now).into_iter().next() else {
        println!("DONE 0");
        return ExitCode::SUCCESS;
    };
    let id = *first.content_id();
    if let Err(e) = store.note_forwarded(&id, now, &peer) {
        return fail(e);
    }
    if let Err(e) = store.flush() {
        return fail(e);
    }
    let count = store
        .image()
        .summary(&id)
        .map(|s| s.replication_count())
        .unwrap_or(0);
    println!("FORWARDED {} {count}", hex::encode(&id));
    ExitCode::SUCCESS
}

fn cmd_deliver(args: &[String]) -> ExitCode {
    let [dir, now_s, peer_hex] = args else {
        usage();
        return ExitCode::from(2);
    };
    let (dir, now, peer) = match (
        PathBuf::from(dir),
        parse_u64(now_s, "now"),
        parse_peer(peer_hex),
    ) {
        (d, Ok(n), Ok(p)) => (d, n, p),
        _ => return ExitCode::from(2),
    };
    let mut store = match DtnStore::load(&dir, now) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let Some(first) = store.forward_candidates(now).into_iter().next() else {
        println!("DONE 0");
        return ExitCode::SUCCESS;
    };
    let id = *first.content_id();
    if let Err(e) = store.mark_delivered(&id, now, &peer) {
        return fail(e);
    }
    if let Err(e) = store.flush() {
        return fail(e);
    }
    println!("DELIVERED {}", hex::encode(&id));
    ExitCode::SUCCESS
}

fn cmd_evict(args: &[String]) -> ExitCode {
    let [dir, now_s] = args else {
        usage();
        return ExitCode::from(2);
    };
    let (dir, now) = match (PathBuf::from(dir), parse_u64(now_s, "now")) {
        (d, Ok(n)) => (d, n),
        _ => return ExitCode::from(2),
    };
    let mut store = match DtnStore::load(&dir, now) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let evicted = store.evict_expired(now);
    if let Err(e) = store.flush() {
        return fail(e);
    }
    for id in &evicted {
        println!("EVICTED {}", hex::encode(id));
    }
    println!("DONE {}", evicted.len());
    ExitCode::SUCCESS
}

fn cmd_evidence(args: &[String]) -> ExitCode {
    let [dir] = args else {
        usage();
        return ExitCode::from(2);
    };
    let dir = PathBuf::from(dir);
    let store = match DtnStore::load(&dir, 1_700_000_900) {
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

fn cmd_status(args: &[String]) -> ExitCode {
    let [dir, now_s, content_hex] = args else {
        usage();
        return ExitCode::from(2);
    };
    let (dir, now, id) = match (
        PathBuf::from(dir),
        parse_u64(now_s, "now"),
        hex::decode_32(content_hex),
    ) {
        (d, Ok(n), Ok(i)) => (d, n, i),
        _ => {
            eprintln!("error: bad args (content must be 64 hex chars)");
            return ExitCode::from(2);
        }
    };
    let store = match DtnStore::load(&dir, now) {
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

fn cmd_read_chunk(args: &[String]) -> ExitCode {
    let [dir, seed_s, slot_s] = args else {
        usage();
        return ExitCode::from(2);
    };
    let (dir, seed, slot) = match (
        PathBuf::from(dir),
        parse_seed(seed_s),
        slot_s.parse::<u32>(),
    ) {
        (d, Ok(s), Ok(sl)) => (d, s, sl),
        _ => return ExitCode::from(2),
    };
    let now = 1_700_000_900;
    let store = match DtnStore::load(&dir, now) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    let (manifest, _) = seed_manifest(seed);
    let id: [u8; CONTENT_ID_LEN] = manifest.content_id();
    match store.read_chunk(&id, slot) {
        Ok(bytes) => {
            println!("CHUNK {slot} {}", bytes.len());
            ExitCode::SUCCESS
        }
        Err(e) => fail(e),
    }
}

// Silence the unused-import warning path when compiled without the
// forward path (defensive; CustodyKind is used by future subcommands).
#[allow(dead_code)]
fn _kind_names() -> [&'static str; 3] {
    [
        CustodyKind::Received.as_str(),
        CustodyKind::Forwarded.as_str(),
        CustodyKind::Delivered.as_str(),
    ]
}
