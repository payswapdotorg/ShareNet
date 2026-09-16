//! `sharenet_transfer` — real runtime entrypoint for R6-002: the
//! two-process transfer evidence driver.
//!
//! Subcommands:
//!
//! * `send --addr ADDR --content-file FILE [fault knobs]` — connect to
//!   a receiver and run the sender session over a REAL TCP socket.
//!   Prints machine-parsable evidence lines (OFFER/REQ/CHUNK/COMPLETE/
//!   DELIVERED/OUTCOME) and exits 0 on DELIVERED or on the scripted
//!   interruption, 1 on any typed error, 2 on usage.
//! * `recv --bind ADDR --state-dir DIR [--out FILE] [knobs]` — bind,
//!   print `READY <addr>`, accept ONE connection, run the receiver
//!   session with the file-backed durable store (resume across
//!   processes), write the reassembled content to FILE (default
//!   `<state-dir>/content.bin`) and print the outcome + evidence.
//!
//! The fault knobs are TEST AFFORDANCES (the `--drop-every` discipline):
//! they drive the adversarial multiprocess suite through the REAL
//! protocol code path.
//!
//! * send: `--corrupt-slot N` (first delivery of slot N has one flipped
//!   byte), `--dup-slot N` (one extra duplicate injection), `--wrong-slot
//!   A=B` (deliver chunk B's bytes labeled slot A), `--withhold-slot N`
//!   (skip slot N's first delivery — the receiver sees a premature
//!   COMPLETE), `--lie-chunks` (manifest of A, bytes of B — the lying
//!   manifest), `--stop-after-chunks N` (abort the connection after N
//!   chunk deliveries — the interrupted transfer).
//! * recv: `--ack-id HEX` (send DELIVERED with a forged content id),
//!   `--max-stall-rounds N` (default 4), `--timeout-ms N` (read
//!   timeout, default 30000).
//!
//! `--created-at` (default 1700000000) and `--chunk-size` (default 64)
//! pin the manifest: the same content + same parameters = the same
//! content id across processes (what resume binding requires).

use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use sharenet_transfer::bank::ChunkBank;
use sharenet_transfer::error::{hex, unhex_32, TransferError};
use sharenet_transfer::frame::{LengthPrefixed, TransferStream};
use sharenet_transfer::message::Message;
use sharenet_transfer::session::{
    drive_receiver, receive_offer, ReceiverFaults, ReceiverPolicy, SenderFaults, TransferSender,
};
use sharenet_transfer::store::{chunk_content, ReceiverStore};
use sharenet_protocol::ContentManifest;

const DEFAULT_CHUNK_SIZE: u64 = 64;
const DEFAULT_CREATED_AT: u64 = 1_700_000_000;
const DEFAULT_TIMEOUT_MS: u64 = 30_000;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("send") => cmd_send(&args[1..]),
        Some("recv") => cmd_recv(&args[1..]),
        Some("--help") | Some("-h") | Some("help") | None => {
            print_usage();
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("error: unknown subcommand {other:?}");
            print_usage();
            ExitCode::from(2)
        }
    }
}

fn print_usage() {
    println!("sharenet_transfer — ShareNet resumable content transfer (R6-002)");
    println!();
    println!("USAGE:");
    println!("  sharenet_transfer recv --bind ADDR --state-dir DIR [--out FILE]");
    println!("                        [--ack-id HEX] [--max-stall-rounds N] [--timeout-ms N]");
    println!("      Bind, print READY <addr>, accept one connection, run the receiver");
    println!("      session with the durable state dir (resumes across processes), write");
    println!("      the reassembled content to FILE (default <state-dir>/content.bin).");
    println!("  sharenet_transfer send --addr ADDR --content-file FILE [--chunk-size N]");
    println!("                        [--content-type T] [--created-at N]");
    println!("      Connect and run the sender session over a real TCP socket.");
    println!("      TEST AFFORDANCES (adversarial drivers, default off):");
    println!("      --corrupt-slot N        first delivery of slot N: one flipped byte");
    println!("      --dup-slot N            one extra duplicate copy of chunk N");
    println!("      --wrong-slot A=B        deliver chunk B's bytes labeled as slot A");
    println!("      --withhold-slot N       skip slot N's first delivery (premature COMPLETE)");
    println!("      --lie-chunks            mutate every delivered chunk (lying manifest)");
    println!("      --stop-after-chunks N   abort the connection after N chunk deliveries");
}

// ---------------------------------------------------------------------------
// Arg parsing (hand-rolled, the house pattern)
// ---------------------------------------------------------------------------

/// One `--key value` (or boolean flag) argument source.
struct Args<'a> {
    rest: &'a [String],
}

impl<'a> Args<'a> {
    fn new(rest: &'a [String]) -> Self {
        Args { rest }
    }
    fn value(&mut self, key: &str) -> Option<String> {
        // Supports both `--key value` and `--key=value`.
        let mut i = 0;
        while i < self.rest.len() {
            let arg = &self.rest[i];
            if let Some(v) = arg.strip_prefix(&format!("--{key}=")) {
                self.rest = &self.rest[i + 1..];
                return Some(v.to_string());
            }
            if arg == &format!("--{key}") {
                if i + 1 < self.rest.len() {
                    let v = self.rest[i + 1].clone();
                    self.rest = &self.rest[i + 2..];
                    return Some(v);
                }
                eprintln!("error: --{key} needs a value");
                std::process::exit(2);
            }
            i += 1;
        }
        None
    }
    fn flag(&mut self, key: &str) -> bool {
        self.value(key).is_some()
    }
    fn value_u64(&mut self, key: &str, default: u64) -> u64 {
        match self.value(key) {
            None => default,
            Some(v) => v.parse().unwrap_or_else(|_| {
                eprintln!("error: --{key} expects a number, got {v:?}");
                std::process::exit(2);
            }),
        }
    }
}

fn require(key: &str, value: Option<String>) -> String {
    value.unwrap_or_else(|| {
        eprintln!("error: --{key} is required");
        std::process::exit(2);
    })
}

// ---------------------------------------------------------------------------
// Evidence stream: prints every protocol frame as a machine-parsable
// line (both directions), then hands it to the real carriage.
// ---------------------------------------------------------------------------

struct EvidenceStream<S> {
    inner: S,
    role: &'static str,
}

impl<S: TransferStream> EvidenceStream<S> {
    fn new(inner: S, role: &'static str) -> Self {
        EvidenceStream { inner, role }
    }

    fn describe(&self, msg: &Message) -> String {
        match msg {
            Message::Offer(bytes) => {
                // Logging only: parse is idempotent and adds no trust.
                match ContentManifest::from_wire_bytes(bytes) {
                    Ok(m) => format!(
                        "OFFER {} chunks={} total={}",
                        hex(&m.content_id()),
                        m.chunk_count(),
                        m.total_length()
                    ),
                    Err(_) => "OFFER <unparsable>".to_string(),
                }
            }
            Message::Request(slots) => {
                let csv = slots
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                format!("REQ slots={csv}")
            }
            Message::Chunk { slot, data } => format!("CHUNK slot={slot} len={}", data.len()),
            Message::Complete { content_id } => format!("COMPLETE id={}", hex(content_id)),
            Message::Delivered { content_id } => format!("DELIVERED {}", hex(content_id)),
        }
    }
}

impl<S: TransferStream> TransferStream for EvidenceStream<S> {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), TransferError> {
        if let Ok(msg) = Message::decode(frame) {
            println!("{} > {}", self.role, self.describe(&msg));
        }
        self.inner.send_frame(frame)
    }
    fn recv_frame(&mut self) -> Result<Vec<u8>, TransferError> {
        let frame = self.inner.recv_frame()?;
        if let Ok(msg) = Message::decode(&frame) {
            println!("{} < {}", self.role, self.describe(&msg));
        }
        Ok(frame)
    }
}

fn io_line(err: &TransferError) {
    println!("ERROR {}", err.name());
    eprintln!("{err}");
}

// ---------------------------------------------------------------------------
// recv
// ---------------------------------------------------------------------------

fn cmd_recv(rest: &[String]) -> ExitCode {
    let mut args = Args::new(rest);
    let bind = require("bind", args.value("bind"));
    let state_dir = PathBuf::from(require("state-dir", args.value("state-dir")));
    let out = PathBuf::from(
        args.value("out")
            .unwrap_or_else(|| state_dir.join("content.bin").to_string_lossy().into_owned()),
    );
    let ack_id = args.value("ack-id").and_then(|v| match unhex_32(&v) {
        Some(id) => Some(id),
        None => {
            eprintln!("error: --ack-id expects 64 hex chars");
            std::process::exit(2);
        }
    });
    let max_stall_rounds = args.value_u64("max-stall-rounds", 4) as u32;
    let timeout_ms = args.value_u64("timeout-ms", DEFAULT_TIMEOUT_MS);

    let listener = match TcpListener::bind(&bind) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: bind {bind}: {e}");
            return ExitCode::from(1);
        }
    };
    let local = listener.local_addr().expect("local addr");
    println!("READY {local}");
    let (stream, _peer) = match listener.accept() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("error: accept: {e}");
            return ExitCode::from(1);
        }
    };
    if stream.set_read_timeout(Some(Duration::from_millis(timeout_ms))).is_err() {
        eprintln!("error: set read timeout");
        return ExitCode::from(1);
    }
    let carriage = LengthPrefixed::new(stream);
    let mut ev = EvidenceStream::new(carriage, "recv");

    let manifest = match receive_offer(&mut ev) {
        Ok(m) => m,
        Err(e) => {
            io_line(&e);
            return ExitCode::from(1);
        }
    };
    let mut store = match ReceiverStore::open_or_create(&state_dir, &manifest) {
        Ok(s) => s,
        Err(e) => {
            io_line(&e);
            return ExitCode::from(1);
        }
    };
    let report = store.reload_report();
    println!(
        "RELOAD resumed={} seen={} accepted={} evicted={} tmp_removed={} bitmap_corrupt={} disagreements={}",
        report.resumed,
        report.seen,
        report.accepted,
        report.evicted,
        report.tmp_removed,
        report.bitmap_corrupt,
        report.bitmap_disagreements
    );

    let policy = ReceiverPolicy { max_stall_rounds };
    let faults = ReceiverFaults { ack_id_override: ack_id };
    match drive_receiver(&mut ev, &manifest, &mut store, &policy, &faults) {
        Ok(outcome) => {
            for rej in &outcome.rejections {
                println!("REJECTED slot={} reason={}", rej.slot, rej.cause.name());
            }
            for slot in &outcome.duplicates {
                println!("DUPLICATE slot={slot}");
            }
            for _ in 0..outcome.premature_completions {
                println!("PREMATURE_COMPLETE");
            }
            if let Err(e) = std::fs::write(&out, &outcome.content) {
                eprintln!("error: write content: {e}");
                return ExitCode::from(1);
            }
            println!(
                "OUTCOME delivered {} rounds={} accepted={} rejected={} duplicates={} premature={} chunks={}",
                hex(&outcome.content_id),
                outcome.rounds,
                outcome.accepted,
                outcome.rejections.len(),
                outcome.duplicates.len(),
                outcome.premature_completions,
                store.manifest().chunk_count()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            io_line(&e);
            ExitCode::from(1)
        }
    }
}

// ---------------------------------------------------------------------------
// send
// ---------------------------------------------------------------------------

fn cmd_send(rest: &[String]) -> ExitCode {
    let mut args = Args::new(rest);
    let addr = require("addr", args.value("addr"));
    let content_file = require("content-file", args.value("content-file"));
    let chunk_size = args.value_u64("chunk-size", DEFAULT_CHUNK_SIZE);
    let content_type = args.value("content-type").unwrap_or_else(|| "application/octet-stream".into());
    let created_at = args.value_u64("created-at", DEFAULT_CREATED_AT);

    let corrupt_slot_once = args.value_u64("corrupt-slot", u64::MAX) as u32;
    let dup_slot = args.value_u64("dup-slot", u64::MAX) as u32;
    let wrong_slot = args.value("wrong-slot");
    let withhold_slot = args.value_u64("withhold-slot", u64::MAX) as u32;
    let lie_chunks = args.flag("lie-chunks");
    let stop_after = args.value_u64("stop-after-chunks", u64::MAX) as u32;
    let timeout_ms = args.value_u64("timeout-ms", DEFAULT_TIMEOUT_MS);

    let content = match std::fs::read(&content_file) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: read {content_file}: {e}");
            return ExitCode::from(1);
        }
    };
    let (manifest, chunks) = match chunk_content(&content, chunk_size, &content_type, created_at) {
        Ok(x) => x,
        Err(e) => {
            io_line(&e);
            return ExitCode::from(1);
        }
    };

    let stream = match TcpStream::connect(&addr) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: connect {addr}: {e}");
            return ExitCode::from(1);
        }
    };
    if stream.set_read_timeout(Some(Duration::from_millis(timeout_ms))).is_err() {
        eprintln!("error: set read timeout");
        return ExitCode::from(1);
    }
    let carriage = LengthPrefixed::new(stream);
    let mut ev = EvidenceStream::new(carriage, "send");

    let faults = SenderFaults {
        corrupt_slot_once: if corrupt_slot_once == u32::MAX as u64 as u32 {
            None
        } else {
            Some(corrupt_slot_once)
        },
        duplicate_slot: if dup_slot == u32::MAX as u64 as u32 {
            None
        } else {
            Some(dup_slot)
        },
        wrong_slot_once: wrong_slot.as_deref().and_then(|v| {
            let (a, b) = v.split_once('=')?;
            Some((a.parse().ok()?, b.parse().ok()?))
        }),
        withhold_slot_once: if withhold_slot == u32::MAX as u64 as u32 {
            None
        } else {
            Some(withhold_slot)
        },
        lie_chunk_bytes: lie_chunks,
        stop_after_chunks: if stop_after == u32::MAX as u64 as u32 {
            None
        } else {
            Some(stop_after)
        },
    };

    let mut sender = match TransferSender::new(manifest.clone(), chunks) {
        Ok(s) => s.with_faults(faults),
        Err(e) => {
            io_line(&e);
            return ExitCode::from(1);
        }
    };
    println!(
        "MANIFEST {} chunks={} total={} chunk_size={}",
        hex(&manifest.content_id()),
        manifest.chunk_count(),
        manifest.total_length(),
        manifest.chunk_size()
    );
    match sender.run(&mut ev) {
        Ok(out) => {
            println!("OUTCOME delivered {}", hex(&out.content_id));
            ExitCode::SUCCESS
        }
        Err(TransferError::Interrupted { sent }) => {
            // The scripted interruption: an honest crash simulation.
            println!("OUTCOME interrupted sent={sent}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            io_line(&e);
            ExitCode::from(1)
        }
    }
}
