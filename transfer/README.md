# sharenet-transfer — R6-002 (resumable content transfer)

The receiver-driven chunk-transfer session protocol that moves a chunked,
content-addressed object (an R6-001 `ContentManifest`) from a sender to a
receiver over ANY established byte-stream/tunnel — and can resume from
ANY partial state, across process death, over a real TCP socket.

This is a **documented runtime control protocol** (the same class as the
Linux gateway's tunnel control protocol, R4-003 — NOT a registry wire
object): it rides INSIDE a carrying layer and its only trust authority is
the registered, `content_id`-committed `ContentManifest` carried in the
OFFER. Dependencies are exactly the work item's set — `sharenet-protocol`
(the R6-001 seams) + std — so the crate stays independently buildable and
freezable, exactly what `tools/architecture_check.py` expects of it.

## The protocol

```text
sender                                   receiver
  │ OFFER(manifest bytes)                  │
  │ ────────────────────────────────────► │ strict parse (R6-001 invariants)
  │                                       │ bind the bank: same content id,
  │                                       │   or refuse typed
  │                 REQUEST(missing slots) │ ← the bank's slot bitmap complement
  │ ◄──────────────────────────────────── │
  │ CHUNK(slot, bytes) ─────────────────► │ per-slot verification (length law,
  │ CHUNK(slot, bytes) ─────────────────► │   then hash law); bank ONLY verified
  │ ...                                   │   chunks; bad chunks are CONTAINED
  │ COMPLETE(content_id) ───────────────► │ round terminator — a HINT, never
  │                                       │   authority (premature → re-request)
  │                                       │ bitmap full? → reassemble() — the
  │                                       │   DERIVED completion proof
  │               DELIVERED(content_id)   │
  │ ◄──────────────────────────────────── │
```

| byte | message | direction | payload |
|---|---|---|---|
| 0x01 | OFFER | S→R | manifest canonical CBOR bytes |
| 0x02 | REQUEST | R→S | u32 n + n × u32 slot |
| 0x03 | CHUNK | S→R | u32 slot + chunk bytes |
| 0x04 | COMPLETE | S→R | content_id (32 bytes) |
| 0x05 | DELIVERED | R→S | content_id (32 bytes) |

## What it provides

| Piece | Where | What |
|---|---|---|
| `TransferStream` | `src/frame.rs` | The carriage seam: send/receive WHOLE frames over anything. `LengthPrefixed<T: Read + Write>` (u32 big-endian prefix, `TRANSFER_MAX_FRAME = CONTENT_MAX_CHUNK_SIZE + 64` cap, fail-closed on the adversarial `0xFFFFFFFF` prefix BEFORE allocation — the R4-001 precedent), `DuplexPair` (in-memory pipe), `TappingStream` (test evidence seam). |
| `Message` | `src/message.rs` | The five wire messages, strictly decoded (`Message::decode`): request-count lies refused, content-id messages exactly 32 bytes, unknown type bytes refused, empty frames refused. |
| `SlotBitmap` | `src/bitmap.rs` | The receiver's slot coverage: `SNTRB1\0`-magic binary record (slot count, word count, words, SHA-256 trailer). Every single-byte mutation refused (pinned by test); stray tail padding bits normalized (bit math defined over slots only). |
| `ChunkBank` + `MemoryBank` | `src/bank.rs` | The verified-chunk storage seam. The one hard law: `accept` is called ONLY with chunks the session has ALREADY verified against the manifest slot (`expected_chunk_len` + `chunk_hash` — the R6-001 seams). The bank never re-derives trust; it also never fabricates it (incomplete rows surface as empty vectors; `reassemble`'s per-slot length law catches them). |
| `TransferSender` | `src/session.rs` | The sender: fail-closed BEFORE the wire (every chunk verified at construction — a sender never sends an unverifiable chunk), answers REQUEST rounds, terminates batches with COMPLETE, accepts exactly one correctly-bound DELIVERED. Fault knobs (`SenderFaults`) are TEST AFFORDANCES: corrupt-once, duplicate, wrong-label, withhold-once, lie-chunks, stop-after-chunks. |
| `receive_offer` + `drive_receiver` | `src/session.rs` | The receiver: manifest-only trust, per-chunk containment (bad chunks recorded + re-requested — the transfer continues), premature COMPLETE re-requested (completion is DERIVED, never asserted), stall bound (`max_stall_rounds`, default 4), forged-ack... on the sender side a wrong-id DELIVERED is rejected typed. |
| `ReceiverStore` | `src/store.rs` | The file-backed durable bank (native only, `#[cfg(not(target_family = "wasm"))]` — the same host seam as `connectivity`'s store): `manifest.cbor` (the one authority record), `chunks/chunk-<slot>.bin` (one file per verified chunk), `bitmap.bin` (ADVISORY bookkeeping only). On reload every chunk file is RE-VERIFIED and the bitmap RE-DERIVED: a tampered bitmap fabricates nothing (no chunk file, no bit), disk corruption is evicted per slot and re-fetched — corruption is CONTAINED, unlike a whole-store refusal. Writes are atomic (temp + fsync + rename, the R5-003 discipline). |
| `sharenet_transfer` | `src/bin/sharenet_transfer.rs` | The real runtime entrypoint: `recv --bind ADDR --state-dir DIR` and `send --addr ADDR --content-file FILE` over a REAL TCP socket, printing machine-parsable evidence lines (MANIFEST / READY / RELOAD / OFFER / REQ / CHUNK / COMPLETE / DELIVERED / REJECTED / DUPLICATE / PREMATURE_COMPLETE / OUTCOME / ERROR) plus the adversarial fault knobs above. |

## Restart + multiprocess evidence (verify levels)

`tests/multiprocess_resume.rs` — the work item's restart evidence, run
through the REAL binary over a REAL TCP socket, no in-process shortcuts:

1. **Interrupted**: sender #1 aborts after 6 of 20 chunk deliveries
   (`--stop-after-chunks 6`); receiver #1 exits typed on the carriage
   loss with its 6 verified chunks ON DISK.
2. **Exact resume**: a fresh receiver process re-opens the state dir —
   `RELOAD resumed=true seen=6 accepted=6 evicted=0` (every persisted
   chunk re-verified) — and the second transfer fetches EXACTLY the
   complement: `accepted=14` of `chunks=20`.
3. **Byte-exact**: the reassembled content equals the original file
   byte for byte, and both processes agree on the content id.

Run everything:

```sh
cargo test                 # 71 unit/adversarial + 1 multiprocess integration
```

## Documented laws (and what this is NOT)

- **Manifest-only trust.** Never claimed sizes, counts or completion
  assertions; every chunk verified with the R6-001 seams (length law
  BEFORE hash law — structurally wrong input is never hashed).
- **Completion is derived, never asserted.** COMPLETE is a hint the
  receiver verifies; DELIVERED is the ack of a derived fact — and the
  sender verifies THAT against its own manifest (a forged ack is
  rejected typed, no delivery recorded).
- **Honest scope**: no dedup-by-hash store, TTL, replication or custody
  evidence — that is R6-003's DTN layer (which implements `ChunkBank` on
  top of its content store). No signed delivery receipts — DELIVERED is
  an ack of a derived fact, not future contribution evidence (R8-001
  signs receipts). No windowing/flow control (the whole missing set is
  requested per round — R6-005's opportunistic forwarding composes on
  top). The receiver's DELIVERED does not attest WHO received the
  content — sender/receiver authentication belongs to the carrying layer
  (a node-pinned R4-001 tunnel in production; a bare TCP run is
  unauthenticated carriage, though content integrity still holds).
- **Tunnel carriage limit**: when riding `transport/quic`'s
  `TunnelStream` (whose own `MAX_FRAME` is exactly 2 MiB), pick
  `chunk_size <= MAX_FRAME - 16`, or use the TCP/pipe adapters here.
- **Store limit** (inherited honestly from the R5-003 discipline): the
  atomic write does temp + fsync + rename but no parent-directory fsync
  after the rename.
