# ShareNet Execution State — Tech Lead Log

Authoritative execution evidence, maintained by the Tech Lead per
`docs/tech-lead/SHARENET-ORCHESTRATOR-HANDOFF.md` (roles: evidence collection,
program status). The frozen registry `spec/work-items.yaml` defines the items;
this file records evidence-based completion. `spec/architect/current-state.yaml`
remains the Architect's baseline snapshot (its `IMPLEMENTATION_NOT_STARTED`
status string is pinned by `tools/architecture_check.py`; updating it is an
Architect decision — see Open Architect Decisions).

## Completion records

### R1-001 — Identity binding — COMPLETE (Wave 1)

- Implemented on `work/wave1-w1-protocol-core`, merged to `main` at `f5b2299`.
- Ed25519 (RFC 8032) via ed25519-dalek + zeroize; strict verification
  (malleable S+L rejected); non-canonical point encodings rejected.
- `node_id = SHA-256(canonical_cbor({1: scheme_version, 2: public_key}))` —
  derived, never caller-chosen; display_name/created_at documented as unbound
  metadata.
- Durable store: atomic tmp+fsync+rename, 0600 exact, fail-closed on
  corruption/tamper/loose perms; no silent recreation.
- Production caller: `sharenet-id` CLI (create/show/verify/sign/
  verify-signature) — the same IdentityStore::load_or_create API the future
  sharenet daemon will call at startup.
- Verification achieved: unit + architecture (wasm32-unknown-unknown green,
  L007) + conformance (RFC 8949 deterministic vectors, RFC 8032 §7.1
  TEST 1–3 byte-exact, golden vectors, property + mutation fuzz).
- Tech Lead independent verification (2026-09-15): cargo test 65/65 green;
  wasm32 green; CLI runtime path exercised end-to-end on real files;
  adversarial spot checks reproduced (loose perms fail-closed, signature
  replay rejected, seed-region tamper fails closed rc=1, metadata tamper
  loads with unchanged node_id by design).
- Known gaps (worker-reported, accepted): zeroization verified on live
  buffers + wiring, not on deallocated memory (would require unsafe);
  0600 enforcement is unix-only; entropy is /dev/urandom on unix
  (non-unix callers supply seeds).

### R1-002 — Canonical CBOR wire foundation — COMPLETE (Wave 1)

- ShareNet Canonical CBOR Profile v1: RFC 8949 core deterministic encoding;
  minimal-length ints; definite lengths; bytewise-sorted unique map keys;
  UTF-8 text; simple values false/true/null only; forbidden: tags, all
  floats, indefinite lengths, undefined, trailing bytes.
- Strictness law tested: encode(decode(B)) == B and decode(encode(x)) == x.
- Typed errors naming each violation; no-panic fuzz (~20k inputs) +
  bit-flip/truncation/append mutation fuzz with strictness-law assertion.
- Vectors exported: `reference/crates/sharenet-protocol/tests/vectors/
  cbor_vectors.json` (45 roundtrip + 57 reject cases) — consumed by the
  R1-003 cross-language harness (Wave 2).
- Verification achieved: unit + architecture + conformance (Tech Lead
  re-ran the full suite: 65/65 green).

### R2-001 — Android nearby transport — COMPLETE (Wave 1)

- `transport/android`: Gradle Kotlin project; `contract` module (pure
  Kotlin/JVM seam, zero Android deps) + `nearby` adapter module
  (com.android.library, compileSdk 35 / minSdk 26).
- GMS types contained to `GmsNearbyApi.kt` (verified by grep at
  integration); everything converts to contract types at the facade.
- Strategies injectable (P2P_CLUSTER default); BYTES/STREAM payload policy
  with 32 KiB boundary; ConnectionTracker state machine with typed errors.
- Production caller: `ShareNetTransportService` (manifest-declared Service
  skeleton the future app embeds).
- Verification achieved: unit + architecture + android — real SDK build:
  `:nearby:assembleDebug` AAR produced; `:nearby:testDebugUnitTest` +
  `:contract:test` 54/54 green. Tech Lead independently reproduced the
  full build (Temurin JDK 21, SDK platforms;android-35, Gradle 8.14):
  BUILD SUCCESSFUL, 54/54, AAR 34K.
- Known gaps (worker-reported, accepted): no physical-device GMS run
  (R4-004 real-device level); Service skeleton is compile+unit verified,
  UI/foreground promotion belongs to the embedding app.

### R2-003 — Linux transport/TUN foundation — COMPLETE (Wave 1)

- `transport/linux` crate `sharenet-transport-linux`: TunDevice trait,
  SystemTunDevice (raw libc TUNSETIFF/SIOCGIFMTU), MemoryTunPair test
  vehicle; probe_tun() capability probe; UdpTransport with length-framed
  datagrams, typed errors.
- Production caller: `sharenet_transport_linux` binary (probe/echo) —
  future R4-001/R4-003 consumers named in READMEs.
- Verification achieved: unit + architecture + linux — cargo test 44/44
  green including a REAL two-process echo (std::process::Command, 64
  frames up to 60 KiB, clean shutdown); probe honestly reports TUN
  absence on hosts without /dev/net/tun (exit 2). Tech Lead re-ran the
  full suite + probe.
- Persistence: none (stateless foundation) — confirmed.
- Known gaps (worker-reported, accepted): live TUN data path is R4-003
  scope (sandbox has no /dev/net/tun; gated tests skip with reasons).

### R1-003 — Protocol registry and cross-language harness — COMPLETE (Wave 2)

- `reference/conformance/`: independent TypeScript (bun + node:crypto
  Ed25519) and Python (stdlib-only, pure-Python RFC 8032 — verified against
  RFC 8032 §7.1 TEST 1/2) implementations of the canonical CBOR profile,
  NodeIdentity and CapabilityStatement; Rust leg in the
  `sharenet-conformance` crate (new workspace member; keeps serde out of
  the protocol core).
- `run_harness.sh`: builds + runs all three legs over the COMMITTED
  vectors and diffs byte-for-byte. PASS = 130 canonical lines identical
  (45 CBOR roundtrips with byte-stability, 57 CBOR rejects with exact
  typed error names, 5 identity cases incl. deterministic signature
  reproduction, 5 capability wire/signature reproductions, 10 admission
  outcomes, 8 capability parse rejections).
- Harness caught and fixed real cross-language divergences during
  development (TS major-7 reserved-info precedence, TS JSON i64
  precision, Python empty-map/empty-array ambiguity).
- Production caller: the harness itself (CI/release gate for every wire
  change); consumers are all current and future protocol implementers.
- Verification achieved: conformance (three languages byte-exact).
- Honest limitation (documented in README): TS/Python verify per RFC 8032
  but do not enforce dalek's strictest malleability rules; the Rust core
  remains the cryptographic authority for production.

### R1-004 — Signed capabilities/admission — COMPLETE (Wave 2)

- `reference/crates/sharenet-protocol/src/capability.rs`:
  CapabilityStatement per the registry schema (canonical CBOR, strictly
  ascending capability wire texts, expiry > issue, bounded limits);
  Ed25519 detached signature over the exact canonical bytes; carrying
  envelope {1: statement, 2: signature}; `admit()` = strict parse +
  node_id binding (SHA-256 derivation re-checked against the presented
  key) + strict signature + time window (issued <= now < expires) +
  capability lookup; NO caller-controlled trust booleans; typed errors
  with stable machine names for the cross-language suite.
- Production caller: `sharenet-id capabilities` / `verify-capabilities`
  (exercised end-to-end on real identity files, incl. refused
  expired/tampered admissions at exact second boundaries).
- Vectors: `capability_vectors.json` (5 signed cases, 10 admission
  outcomes incl. the different-key node_id_mismatch scenario, 8 typed
  parse rejections) generated by the crate and validated in cargo test.
- Verification achieved: unit + adversarial (16 tests: cross-statement
  signature replay, wrong-key binding, tamper at text bytes, exact time
  boundaries, envelope malformations, limits bounds, 500-case
  corruption fuzz) + conformance (three languages, see R1-003).
- Persistence: none (stateless wire object; durable revocation is
  R7-001 scope).

### R2-004 — Transport quality telemetry — COMPLETE (Wave 2)

- Implemented by Worker 2 on `work/wave2-w2-telemetry` (pushed 1cf5a98
  before the orchestrator sandbox was reset; branch verified after
  re-cloning — the sandbox loss did not affect the pushed evidence).
- `transport/telemetry` crate: LinkQualitySample/Stream (deterministic
  sliding-window summaries: dedup-by-seq, clock-skew refusal, lost
  samples excluded from RTT stats), EWMA + p50/p95 (linear
  interpolation) + MAD jitter + honest throughput estimate; active
  stop-and-wait ping/pong prober (correlation ids, retry budget, late
  pong accounting, dead-peer-measured-as-loss).
- `transport/linux`: `probe-rtt` binary subcommand (production caller)
  + `telemetry_bridge` implementing the transport seam; Android:
  QualitySample/Recorder/Reporter contract seam wired into
  ShareNetTransportService and NearbyConnectionsAdapter.
- Integration tests: REAL two-process loopback (spawned echo child over
  real UDP sockets): 200-probe reliable phase (>=95% delivered, RTT
  bounds, cross-validated child counters) + induced-1/3-loss phase
  (measured loss within ±0.1 of ground truth); probe_rtt integration
  test drives the real binary.
- Verification achieved (Tech Lead independent): telemetry crate 35
  tests green; linux crate 51 tests green (incl. two-process); Android
  SDK build INDEPENDENTLY REPRODUCED (Temurin JDK 21.0.5,
  platforms;android-35, build-tools;35.0.0, Gradle 8.14, --no-daemon):
  :contract:test + :nearby:testDebugUnitTest 75/75 green (13
  QualityRecorder + 8 NearbyQuality among them), :nearby:assembleDebug
  AAR 38K produced. Scope: 26 files, all under transport/ (0 outside).
- Persistence: none (measurement layer; durable evidence capture is
  R8-001 scope) — documented in the crate.

## Wave 2 integration record (2026-09-15)

- Worker 2 branch `work/wave2-w2-telemetry` (tip 1cf5a98, pushed by the
  worker before the orchestrator sandbox reset; the reset lost the
  worker's chat transcript but NOT the pushed evidence — all verification
  was re-run independently from the branch).
- Worker 1 items R1-003/R1-004 were re-implemented by the Tech Lead
  directly (the dispatched worker session died in the sandbox reset
  with nothing pushed); same contract, same verification standards.
- Merged: `7bd4a33` (W1) then `bfd1e7b` (W2, = new main).
- Registry update at integration: CapabilityStatement maturity →
  implemented (wire schema + signature/envelope rules + admission rule
  + vectors + conformance paths recorded).
- Dispatch mechanics note: the chat-based worker rail is gone with the
  orchestrator sandbox (browser profile, scripts and PAT were not
  persisted); Wave 3+ continues with the Tech Lead as direct
  implementer under the same governance (scope locks, independent
  verification, registry discipline, fresh audits). Push to origin is
  blocked until credentials are re-supplied by the operator.

## Wave 1 integration record (2026-09-15)

- Base: `4d6e3ae` (main + root .gitignore governance hygiene).
- Worker branches: `work/wave1-w1-protocol-core` (tip `0a69337`),
  `work/wave1-w2-transports` (tip `fc563c3`).
- Merged: `f5b2299` (W1), `4de12a2` (W2, = new main).
- Worker 3: idle per frozen dependency graph (no independent READY item;
  R5-001 is roadmap-gated to wave 7).
- Dispatch mechanics note: the chat site rolled task conversations to new
  chat IDs; the queue watcher's false "tablost" on a wedged tab triggered
  one redundant re-dispatch for W1 (the re-dispatched session re-verified
  and replaced the branch with the fully-verified protocol core —
  outcome-positive; mechanism to harden before Wave 2).
- Registry update at integration: `spec/protocol-registry.yaml` —
  NodeIdentity maturity → implemented, wire schema + id derivation +
  vector paths recorded (schema was defined by the Wave 1 worker
  contract and is now frozen by implementation + exported vectors).

### R3-001 — Authenticated links — COMPLETE (Wave 3)

- `reference/crates/sharenet-protocol/src/link.rs`: the three-message
  authenticated key exchange registered in the protocol registry — X25519
  ephemerals, Ed25519 transcript signatures (each side signs the exact
  bytes of the exchange so far, TLS-1.3-shaped), HKDF-SHA256 key
  schedule, ChaCha20-Poly1305 AEAD frames with per-direction strictly
  monotonic sequence numbers and a 64-entry replay window;
  commitment-derived link_id (SHA-256 over the full transcript);
  optional SignedCapabilityStatement envelopes carried and verified
  during the handshake; zeroized ephemerals and session keys; typed
  errors with stable machine names. No new cryptographic primitives
  (ADR-002): everything is X25519/Ed25519/HKDF/ChaCha20-Poly1305.
- Entropy is caller-supplied (unix /dev/urandom fail-closed helper;
  non-unix returns EntropyUnavailable) — no getrandom dependency, so the
  wasm32 platform-independence lock (L007) still holds.
- Production callers: the multiprocess verification below; R3-002
  (advertisement/discovery) and R4-001 (QUIC tunnel) consume
  LinkSession as the peer-session primitive.
- Verification achieved: unit + architecture (wasm32 check green) +
  conformance (link_vectors.json: 3 deterministic handshakes + 3 frames,
  reproduced byte-exactly by Rust, TypeScript and Python legs — the
  cross-language harness now spans 136 lines including X25519/Ed25519/
  HKDF/ChaCha20-Poly1305 agreement across three independent
  implementations; the pure TS and Python AEAD implementations are
  pinned against RFC 8439 §2.8.2, the pure-Python X25519 against
  RFC 7748 §6.1) + multiprocess (two REAL processes over REAL UDP
  sockets: full handshake, 4 frames both directions, echo cross-check,
  tampered-msg2 refusal; peer exits non-zero without msg3).
- Adversarial (beyond the required levels): 11 tests — msg2 replayed
  under a different msg1, msg3 replayed under a different msg2,
  identity substitution, cross-session frame confusion, replay window
  edges (out-of-order, duplicates, far-future), frame tamper, capability
  envelope tamper + cross-node binding, strict wire parsing, zeroize
  drop, link_id distinctness per handshake.

## Wave 3 integration record (2026-09-15)

- Implemented directly by the Tech Lead on
  `work/wave3-w1-authenticated-links` (the worker rail remains gone with
  the sandbox reset; same governance: registry pre-registration commit
  4d04b96 preceded implementation).
- Registry: LinkAuthentication maturity → implemented (schema,
  signature/derivation/frame rules and vectors were pre-registered
  before the code; the implementation matches them byte-for-byte).

### R3-002 — Advertisement/discovery — COMPLETE (Wave 4)

- `reference/crates/sharenet-protocol/src/advertisement.rs`: the
  Advertisement wire object per the registry schema (signed self-
  certifying announcement: NodeIdentity, optional verified capability
  envelope, canonically sorted transport descriptors from the frozen v1
  kind set, freshness window bounded by 600s); content-derived
  advertisement_id = SHA-256(canonical bytes); DiscoveryCache receiver
  pipeline (strict parse → signature against the embedded identity →
  freshness → capability admission → idempotent dedup with
  stale-replay protection: an older ad can never evict a fresher one).
- Production caller: `sharenet-discover` (listen/advertise; --link
  establishes an authenticated link to a discovered endpoint) — the
  same API the future daemon's discovery loop uses.
- Verification achieved: unit + adversarial (tamper, expiry
  boundaries, window bound, unknown kind, unsorted/duplicate/empty
  transports, stale-replay, envelope roundtrip) + multiprocess (two
  REAL processes over REAL UDP: mutual discovery via verified
  advertisements, then a full R3-001 authenticated link to the
  ADVERTISED endpoint with 3 echoed frames; tampered advertisements
  rejected while the listener survives) + conformance
  (advertisement_vectors.json: 3 cases + 6 receive outcomes + 5 typed
  parse rejections — all three language legs byte-identical; the
  cross-language harness now spans 150 lines).
- Persistence: none (discovery is in-memory runtime state; durable
  topology evidence is R3-003 scope).

## Wave 4 integration record (2026-09-15)

- Implemented directly by the Tech Lead on
  `work/wave4-w1-advertisement-discovery`; registry pre-registration
  commit ccc3569 preceded implementation.
- Registry: Advertisement maturity → implemented.

### R3-003 — Authenticated topology evidence — COMPLETE (Wave 5)

- `reference/crates/sharenet-protocol/src/topology.rs`: the
  TopologyEvidence wire object per the registry schema — signed
  one-directional attestations (observer identity inside the signed
  bytes; subject node_id; link observations with caller-mapped R2-004
  quality snapshots including the parts-per-million loss ratio because
  the canonical CBOR profile forbids floats; advertisement observations
  with the observed capability set); content-derived evidence_id;
  parse-time enforcement of every invariant (subject != observer,
  p95 >= p50, loss ratio <= 1e6, established <= observed, bounded
  window).
- TopologyStore: the collector — signature + freshness verification,
  stale-replay protection, and the BILATERAL-LINK rule (a link counts
  only when both endpoints attest the same link_id within their
  windows — the bilateral-acknowledgement anti-gaming requirement).
- Production callers: R3-004 (route commitment) and R5-005 (gateway
  admission) consume the store; the discovery flow's evidence hook is
  the runtime path (verified in the R3-002 multiprocess suite).
- Verification achieved: unit + adversarial (self-attestation, tamper,
  expiry boundaries, quality invariants, stale records, bilateral
  matching incl. expiry intersection) + conformance
  (topology_vectors.json: 3 cases + 4 receive outcomes + 5 typed parse
  rejections; all three language legs byte-identical — the harness now
  spans 162 lines).
- Persistence: none — runtime evidence; durable receipts are R8-001.

## Wave 5 integration record (2026-09-15)

- Implemented directly by the Tech Lead on
  `work/wave5-w1-topology-evidence`; registry pre-registration commit
  a83609a preceded implementation.
- Registry: TopologyEvidence maturity → implemented.

### R3-004 — Route commitment — COMPLETE (Wave 6)

- `reference/crates/sharenet-protocol/src/route.rs`: the three route
  wire objects per the registry schemas — RouteProposal (proposer-
  signed; path of unique node ids in canonical ascending order;
  service class live/opportunistic/dtn; nonce makes every proposal
  new), RouteAcceptance (per-position, bound to the proposal_id,
  identity-matched to the path slot), RouteCommitment (Merkle root
  over the acceptance bytes ordered by position; route_id =
  SHA-256(context || root) — commitment-derived, caller-selected IDs
  impossible by construction per L013).
- Verification is fail-closed end-to-end: proposal signature +
  invariants, per-acceptance signature/binding/freshness, exact
  position coverage, re-derived root and route id. Replacement routes
  (fresh nonce) produce genuinely fresh route ids — vector-verified.
- Production caller: `sharenet-route` CLI (propose/accept/commit/verify
  — real multi-party file-based flow); R4-002 (route-to-circuit
  binding) consumes the verified commitments.
- Verification achieved: unit + conformance (route_vectors.json: 3
  cases incl. fresh-nonce distinctness, 2 tampered-commitment rejects;
  all three language legs byte-identical — harness now 167 lines) +
  adversarial (caller-selected id, missing acceptance, non-path
  identity, expiry, tamper, Merkle reference shape) + multiprocess
  (three REAL processes form a route through the CLI: propose, two
  hop accepts + proposer accept, commit, verify; missing-acceptance
  commitment refused with positions_not_covered; CLI/library
  interop byte-identical).
- Persistence: none — commitments are computed/verified objects;
  durable circuit state is R4/R7 scope.

### R4-001 — QUIC/TLS tunnel — COMPLETE (Wave 6)

- `transport/quic` crate `sharenet-transport-quic`: the Internet-facing
  tunnel per architecture §8 and L010 — QUIC + TLS 1.3 via quinn + rustls
  (the standard Rust stack; no bespoke transport). Each endpoint
  presents a self-signed Ed25519 certificate whose private key IS the
  node identity key (R1-001 seed PKCS#8-wrapped into the TLS key);
  ALPN "sharenet-tunnel-v1"; Ed25519-only signature schemes; TLS 1.2
  refused at both verifiers.
- Identity pinning model: the pinned node identity is derived from the
  certificate's public key by the exact R1-001 rule (unit-verified
  against the protocol core's own derivation); clients pin the
  server's node id; servers may pin admitted client node ids
  (unpinned clients are refused at the handshake — verified on tunnel
  use because TLS 1.3 lets the client complete its handshake view
  before the server has verified the client certificate). Documented
  honestly: an unpinned server entry is an unauthenticated transport;
  ShareNet-level authentication (R3-001 links, R4-002 circuits) rides
  INSIDE the tunnel.
- Framed sessions: length-prefixed frames (u32 BE, MAX_FRAME 2 MiB
  mirrors the Wave 1 UDP bound) enforced on BOTH the send path
  (pre-write) and the receive path (the length prefix) — a receiver
  rejects a bogus 0xFFFFFFFF prefix with FrameTooLarge instead of
  buffering 4 GiB. Close semantics documented: finish() is graceful;
  dropping the last handle aborts (standard QUIC) — the test protocol
  exchanges an application-level "done" frame before exit so process
  teardown never races in-flight frames.
- Runtime lifecycle: each endpoint owns a tokio runtime in an Arc
  shared with every TunnelStream it produced — a stream keeps the
  driver alive so in-flight frames still transmit after the endpoint
  owner is dropped (the drop-race fix; teardown when the last
  owner/stream goes away).
- Production caller: the two-process verification below; R4-002
  (circuit binding), R4-005 (ICE/TURN) and the future daemon/gateways
  construct tunnels through this crate's API (named in the README
  seams section).
- Verification achieved: unit (6: node_id derivation equals the
  protocol core's, certificate carries the identity key, client/server
  node ids are their identities, oversized local send rejected,
  in-process mutual-pinning roundtrip, unpinned client rejected) +
  multiprocess (3: two REAL processes over real loopback QUIC/TLS 1.3
  with the server node pinned and 3 echoed frames; a wrong pin rejected
  at connect; adversarial oversized-frame-header rejected with the
  connection surviving) — the required levels [unit, linux,
  multiprocess] all green on this Linux host. Cross-checks: reference
  workspace 132/0, transport/linux 51/0, wasm32 protocol check green,
  architecture governance PASS.
- Persistence: none (tunnels are runtime state; durable circuit state
  is R4-002/R7 scope).
- Known gaps (honest): relays/ICE/STUN/TURN traversal are R4-005
  scope; gateway data-plane forwarding is R4-003; no non-loopback
  network run in evidence (R4-007/R10 scope).

## Wave 6 integration record (2026-09-15, part 1: R3-004)

- Implemented directly by the Tech Lead on
  `work/wave6-w1-route-commitment`; registry pre-registration bf12c4e
  preceded implementation.
- Registry: RouteProposal/RouteAcceptance/RouteCommitment → implemented.

## Wave 6 integration record (2026-09-15, part 2: R4-001)

- Implemented directly by the Tech Lead on `work/wave6-w2-quic-tunnel`;
  registry commits preceded: the QuicTunnelTransport binding entry was
  registered (a5d0aae) and the stale RouteAcceptance/RouteCommitment
  skeleton duplicates left over from the R3-004 pre-registration were
  removed in the same governance cleanup.
- Registry: QuicTunnelTransport (class transport) → implemented —
  the "quic" advertisement transport kind now has a frozen meaning:
  node-identity-pinned QUIC + TLS 1.3 with opaque length-framed
  sessions.

## Ready set (recomputed from actual predecessor completion)

- R4-002 (route-to-circuit binding) — READY: predecessors R3-004
  COMPLETE and R4-001 COMPLETE.
- R4-005 (ICE/TURN) — READY: predecessor R4-001 COMPLETE.
- R5-001 (ConnectivityPort) — READY (no predecessors; wave-7 eligible
  with R4-002/R4-005).
- R2-002 (Wi-Fi Aware) remains optionally schedulable inside gate R2
  (Tech Lead decision; not on the frozen wave path).

## Open Architect Decisions

1. `spec/architect/current-state.yaml` still declares
   `ARCHITECTURE_FROZEN_IMPLEMENTATION_NOT_STARTED` (pinned verbatim by
   `tools/architecture_check.py`). Implementation has now started and
   Wave 1 items are complete with evidence. The Architect should define
   the next status string and update the governance check together.
2. NodeIdentity wire schema is now recorded in the protocol registry
   (Tech Lead integration edit, evidence-based). Architect review
   requested.

## Evidence index

- Worker completion reports (harvested from task transcripts):
  `scripts/logs/evidence_w1_report.md`, `evidence_w2_report.md`,
  `evidence_w1_v1_report.md` on the orchestrator host (replay2 checkout).
- Raw transcripts: `scripts/logs/transcript_{w1-foreign,w2-foreign,
  proto-foreign}.txt`.
