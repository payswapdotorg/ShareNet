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

### R2-002 — Android Wi-Fi Aware adapter — COMPLETE (2026-09-16, post-closure insert)

- The ONE never-executed roadmap item (roadmap gate R2 note: optional
  insert, runnable once the Android transport seam stabilized). Run as a
  single-worker continuation after program closure; executed by worker
  `sharenet-w2-r202` (instance 3 — two prior instances lost to platform
  session kills; the surviving sandbox was recovered by instance 3).
- Delivery note (new pattern): worker sandboxes carry no GitHub
  credentials by design, so the worker's commits stayed local — the
  work was delivered as a git diff through the sandbox workspace file
  API (`download/r2-002/`), applied by the Tech Lead to
  `work/r2-002-wifi-aware` at df11bd7 (clean apply, tree identical to
  the worker's verify commit 6760700 on WIP 47599cb).
- `transport/android/aware/` Gradle module (16 files, 4209 insertions;
  only non-aware change: the one-line settings.gradle.kts include):
  `AwareApi` facade (pure Kotlin seam), `AndroidAwareApi` platform
  facade (ALL 12 `android.net.wifi.aware` imports confined to this one
  file — L009), `AwareFrameCodec` (4-byte-BE length prefix + u64
  channel envelope, frozen 2 MiB frame law, bounded buffering),
  `AwareLinksAdapter` (contract-typed adapter, ConnectionTracker
  insertion-order determinism), `AwareServiceController`,
  `ShareNetAwareService` (production caller — the Android Service
  lifecycle R2-001 proved for nearby), `FakeAwareApi` + 5 host-JVM
  test suites.
- Adversarial coverage (all 8 contract minimums, host-tested through
  the fake): permission denial typed + retry-after-grant; NAN
  unsupported typed + clean degradation + retryable; session loss
  mid-discovery (insertion-order loss events, idle, re-attach works);
  publish update races last-write-wins, no dupe/miss; datapath refusal
  typed + resource release; stream corruption (short prefix /
  oversized 3 MiB claim vs the 2 MiB law / garbage envelope) typed
  errors, zero buffered frames; double-stop / stop-without-start
  no-throw; quality samples flow to QualityReporter.
- Verification achieved (Tech Lead independent, fresh stack:
  Temurin JDK 21.0.12, platforms;android-35, build-tools;35.0.0,
  Gradle 8.14, --no-daemon): `:aware:testDebugUnitTest` 89/89 green
  (AwareApiFacadeTest 19, AwareFrameCodecTest 19, AwareLinksAdapterTest
  34, AwareQualityTest 9, AwareServiceControllerTest 8); L009 greps
  re-run: 0 aware imports outside AndroidAwareApi.kt, contract module
  pollution-free, adapter/service imports clean;
  `:aware:assembleDebug` BUILD SUCCESSFUL — aware-debug.aar 64,095
  bytes; sibling regression `:nearby:testDebugUnitTest` 39/39,
  `:vpn:testDebugUnitTest` 79/79, `:contract:test` 36/36 — zero
  regression.
- Known gaps (worker-reported, accepted): on-device NAN radio leg
  operator-gated (no Wi-Fi Aware hardware in any sandbox — honest-gap
  pattern mirrors R10-002); no RTT quality samples (frozen
  QualitySampleKind seam carries no RTT kind — recorded as an open
  seam, not fabricated).

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

### R4-002 — Route-to-circuit binding — COMPLETE (Wave 7)

- `reference/crates/sharenet-protocol/src/circuit.rs`: the four circuit
  wire objects per the registry schemas — CircuitSetup (initiator MUST
  be the route proposal's proposer; the embedded RouteCommitment is
  FULLY verified at admission per R3-004; single-use (route_id,
  setup_nonce)), CircuitSetupAck (setup-digest bound to the exact setup
  bytes; accepting identity MUST be path[position]; exactly-once per
  position — a circuit is ESTABLISHED on full position coverage,
  mirroring the R3-004 rule; acks cannot outlive their setup),
  CircuitFrame (direction 1|2 with per-direction strictly monotonic
  seq from 0 — the L014 replay namespace; opaque payload 1..=2 MiB),
  CircuitDestroy (any path member; frozen reason set link_failure/
  policy/completed/replaced; terminal forever, idempotent duplicates).
- circuit_id = SHA-256("sharenet-circuit-id-v1" || route_id ||
  setup_nonce) — commitment-derived through the verified route_id (L013
  discipline), fresh per nonce: a replacement circuit is genuinely
  new with a fresh replay namespace (L014), and a destroyed circuit is
  never resurrected (§11).
- Integrity model (per architecture §9 + ADR-002): frames are NOT
  individually signed — hop-by-hop integrity comes from the carrying
  layers (R3-001 AEAD links / R4-001 pinned QUIC), end-to-end payload
  integrity is R6 content addressing. The frame wire carries binding +
  ordering only. Documented in the registry integrity_rule.
- Verification achieved: unit (4: happy path incl. destroy terminality,
  replacement freshness, non-proposer refusal at construction AND
  admission, replay-namespace enforcement) + adversarial (12: tampered
  setup/ack signatures, commitment tamper inside the setup, nonce
  single-use incl. re-signed fresh bytes, freshness edges, position
  forgery, outsider acks, digest confusion, double-take, ack-outlives-
  setup, frame replay/gap/cross-circuit confusion, destroy membership
  gating + terminal enforcement, strict wire rejects) + conformance
  (circuit_vectors.json: 3 full deterministic flows rebuilt byte-exactly
  by Rust, TypeScript and Python legs incl. the admission replay —
  harness now 177 byte-identical lines). Full sweep: 148 workspace
  tests 0 failed; wasm32 protocol check green; governance PASS.
- Production callers: the CircuitRegistry admission pipeline is the
  seam R4-003 (Linux gateway forwarding) and R4-004 (Android
  VpnService) consume to run live data planes over committed routes.
- Persistence: none — runtime verification state (durable circuit
  state is R4-003/R4-004/R7 scope).

### R4-005 — ICE/TURN — COMPLETE (Wave 7)

- `transport/ice` crate `sharenet-transport-ice`: the NAT-traversal /
  relay layer per L011 (standard STUN/TURN/ICE concepts reused, no
  bespoke NAT protocol) and L012 (relays forward opaque end-to-end
  traffic).
- STUN (RFC 5389 subset): strict codec (magic cookie, 96-bit
  transaction ids, method/class bit encoding, TLV attributes with
  alignment, XOR-MAPPED-ADDRESS, SOFTWARE) + UDP client with
  exact-transaction-id response matching (mismatched responses
  discarded — adversarially verified), 3-attempt retry, fail-closed on
  malformed responses.
- Candidates (RFC 8445 concepts): Host/ServerReflexive/Relayed with
  the standard priority and foundation formulas, gathering,
  priority-ordered pairing, connectivity checks. No agent nomination
  (documented: R4-006/R4-007 scope).
- TURN-style relay (RFC 8656 concepts over UDP): per-5-tuple
  allocations (identical-nonce retransmission → byte-identical
  response; new nonce → 437 allocation mismatch, verified), relayed
  addresses forwarding OPAQUE datagrams (never parsed — L012),
  permission-lite activation; TEST/LOCAL control framing documented
  (no TURN auth — R4-006 scope).
- QUIC integration (R4-001 composition): bridge::tunnel_connect — a
  gathered candidate is the ADDRESS source for a node-pinned QUIC
  tunnel; a full pinned tunnel rides the relay transparently
  (multiprocess-verified).
- Verification achieved: unit (33: hand-computed codec vectors incl.
  the RFC 5389 worked example, strict rejects, formulas) + multiprocess
  + adversarial (11: STUN vs a real stun_server process; wrong-txid
  responses ignored; fail-closed evil responses with exact typed
  errors; opaque echo through the real relay; three candidate types
  with RFC 8445 priorities; a node-pinned QUIC tunnel through the
  relay; wrong pin fails closed while the relay survives; duplicate
  allocation rules; malformed datagrams forwarded opaquely; adversarial
  control frames survived). transport/quic 9/9 no regression.
- Honest limits (documented in the README): local STUN/TURN servers in
  evidence (sandbox cannot reach external ones — real-network shapes
  are R4-007/R10); no TURN authentication (R4-006); no full ICE agent;
  simplified relay permissions.
- Persistence: none.

### R5-001 — ConnectivityPort — COMPLETE (Wave 7)

- `connectivity` crate `sharenet-connectivity`: the ADCOS boundary per
  ADR-001 and spec/integrations/adcos.md — ZERO dependencies (std-only,
  no protocol-core dep, no async runtime): independently freezable as
  the architecture check enforces.
- ConnectivityPort trait = exactly the adcos.md interface
  (createIntent/discoverOffers/acceptOffer/getContract/getAssurance/
  getExecution/terminate) with typed PortError (stable machine names).
- Domain types: three opaque 32-byte refs (NOT wire objects — no CBOR,
  no signatures, documented); versioned requirement (frozen ADR-003
  service classes mirrored without a protocol-core dep); read-only
  contract projection (Projected/Active/Degraded/Terminated per the
  adcos.md event mapping; valid_from < valid_until enforced at
  construction); observations (exactly the six adcos.md event kinds,
  monotonic per-provider sequence); execution projections (plain u64
  counters).
- The law enforcements: observations are read-only data (no API can
  mutate authoritative ShareNet state — proven by test); ADCOS-
  unavailable failure semantics as typed errors with freshness
  metadata (ProviderUnavailable carries the last-observation fresh-
  until; AcquisitionUnauthorized blocks new acquisition; never
  fabricate contract state; never destroy local state) + the caller-
  side ObservationCache caching policy (dedup by strictly-greater
  sequence).
- InMemoryConnectivityPort TEST VEHICLE (clearly marked): deterministic
  virtual clock, injectable failure modes, observation redelivery —
  the seam R5-002 (ADCOS client) tests against; the conformance suite
  is generic and re-runnable by R5-002's real client.
- Verification achieved: unit (29/29: full lifecycle, event-mapping
  state machine, determinism, sequence monotonicity, replay dedup,
  failure semantics, terminate idempotence, unknown-ref rejection,
  read-only-law proof) + architecture (wasm32 check green —
  platform-independent; tools/architecture_check.py PASS; zero
  dependencies verified by Cargo.toml).
- Production caller: R5-002 (ADCOS wire client, wave 8) implements the
  trait — the in-memory provider is the documented test seam until
  then (per the R3-003 precedent of named-future-consumers).
- Persistence: none (projections are runtime state; durable refs are
  R5-003 scope).
- Worker note: implemented by a dispatched subagent (Task 13-c) in one
  clean run; Tech Lead independently re-verified (29/29, wasm32,
  trait-vs-adcos.md interface check) before integration.

### R4-003 — Linux gateway forwarding — COMPLETE (Wave 8)

- `transport/linux/src/gateway.rs`: GatewayServer (pinned QUIC accept →
  R3-004 route commitment verified inside setup admission → R4-002
  circuit setup admitted fail-closed → BOTH acks exchanged so position
  coverage is exact on BOTH ends → established) + per-circuit uplink
  UDP sockets + a dedicated thread turning uplink responses into
  direction-2 frames. GatewayClient/ParticipantSession mirror the
  admission locally — tampering anywhere in the chain is caught on both
  ends.
- Timestamp discipline (design-level fix caught by the multiprocess
  tests): the gateway's acceptance/ack timestamps anchor to the
  PROPOSAL's proposed_at / the SETUP's issued_at — never the gateway
  wall clock — so cross-process clock skew (even millisecond-forward)
  can never break admission.
- Destroy is application-level acknowledged (BYE) before teardown —
  process exit never races in-flight frames (the QUIC close-semantics
  rule).
- `transport/quic`: TunnelStream::split() → TunnelSender/TunnelReceiver
  halves (the data plane needs one side blocking on the next participant
  frame while another thread returns uplink responses; the
  single-stream API cannot express it; drop semantics preserved).
- Verification achieved: multiprocess/adversarial (7: full data plane
  two-process — 5 packets echoed through a real UDP "Internet" echo +
  GATEWAY_DONE handshake; full flow via both real binaries; wrong
  gateway pin fails closed; unpinned participant refused; oversize/empty
  rejected locally; in-process server thread; binary argument hygiene).
  Full sweep: linux crate 58/58 green (38 unit + 7 gateway + 4
  udp_multiprocess + 5 probe_rtt + 4 tun_gated); quic 9/9 no regression;
  governance PASS.
- Production caller: `sharenet-transport-linux` binary `gateway` +
  `participant` subcommands (READY/GATEWAY_DONE/PARTICIPANT_DONE
  protocol) — the on-ramp R4-007 (mission gate real Internet bridge)
  and R7-003/R7-004 (gateway recovery) build on.
- Persistence: none — circuit admission state is runtime state (durable
  is R7 scope per the R7-002 recovery-attempts item).
- Registry note: no registry change — R4-003 consumes registered wire
  objects (RouteCommitment/CircuitSetup/Ack/Frame/Destroy); the tunnel
  control protocol (READY/BYE) is documented runtime state, not wire
  objects.

### R4-004 — Android VpnService — COMPLETE (Wave 8)

- `transport/android/vpn` module (:vpn, com.android.library, compileSdk
  35 / minSdk 26, EMPTY production dependencies): the Android VPN data
  plane. Platform adapter, not protocol semantics (L009, ADR-002).
- Pure-JVM core, unit-tested end-to-end: VpnConfig strict total typed
  validation + PURE toBuilderParams (NetTypes strict IP/CIDR parsing —
  no java.net.InetAddress: no leading-zero octets, no embedded IPv4
  tails in IPv6, routes reject host bits below the prefix, duplicates
  by parsed value); IpPacketFilter (IPv4 deep-strict: IHL/total-length
  equality/protocol policy with fixed test-asserted check order; IPv6
  shallow pass-through with payload-length consistency; best-effort
  FlowKey); PacketLoop (stop flag first; oversized consumed-and-continue;
  post-read stop drops the packet; throwing backhaul = typed terminal
  fail-closed; responses defensively re-filtered before write).
- Android boundary confined to ShareNetVpnService + FdPacketIo: 1:1
  Builder mapping over validated params, setBlocking(true) matching the
  PacketIO contract, loop on a dedicated thread, stop-then-close
  teardown, reconfigure = restart, VpnNotPrepared typed refusal,
  configureBackhaul skeleton wiring (no factory installed = never starts
  a loop with no backhaul).
- Seams: PacketIO (fd I/O; pipe-backed fake in tests), TunnelBackhaul
  (the tunnel join point — the JNI bridge to the Rust QUIC TunnelStream
  is R10-002 scope; no NDK in this wave, deliberately).
- Verification achieved: unit (67/67: 25 filter + 28 config + 14 loop,
  incl. stop-flag races: stop-before-run, concurrent stop, stop during
  blocked read, re-entrant stop from inside the backhaul) + android
  (REAL SDK build: :vpn:assembleDebug AAR 68750 bytes against
  platforms;android-35). Two test bugs fixed at integration: the
  IHL-below-minimum shape must carry ≥20 bytes so ShortHeader does not
  shadow BadHeaderLength; PacketPipe needed closeTunSide() so a
  same-thread run()+receive() drains instead of blocking forever.
- Known gaps (accepted, documented): no on-device verification (real
  TUN, consent flow) — R10-002 scope per the work item's real-device
  verify level; no JNI backhaul (R10-002); IPv6 filter is
  pass-through-only (documented seam).
- Implemented by a dispatched subagent that died mid-work leaving
  high-quality WIP; completed by the Tech Lead (fixed the two test
  bugs, wrote the README, verified, committed).

### R5-002 — ADCOS client — COMPLETE (Wave 8)

- `connectivity-client/` crate `sharenet-connectivity-client`: the wire
  client `spec/integrations/adcos.md` mandates — "The actual wire client
  speaks the ADCOS developer API. The domain does not import ADCOS server
  internals." AdcosClient implements the parent crate's ConnectivityPort
  trait against a minimal JSON-over-HTTP/1.1 mapping of the ADCOS
  developer API over std TCP. It is the boundary ADAPTER — the only
  place in ShareNet that knows the ADCOS transport format.
- Deliberately tiny dependency set: sharenet-connectivity (the boundary
  being implemented) + serde/serde_json (the JSON bodies live ONLY here
  — the parent connectivity crate stays zero-dependency). No protocol
  core, no async runtime, no HTTP framework, no TLS (documented as
  future hardening in the README).
- Layout: wire (DTOs, endpoint builders/parsers, typed error envelope —
  the PortError machine names are the wire error vocabulary), http
  (hand-rolled minimal HTTP/1.1 codec, strict parsing), hex (strict
  lowercase-hex for the 32-byte opaque refs), error (AdcosError — full
  typed surface flattened into PortError at the trait boundary),
  transport (std TCP dial/write/read with timeouts and method-aware
  host-only retry), client (the ConnectivityPort impl).
- Failure semantics per adcos.md: ProviderUnavailable carries the
  caller cache's freshness bound; AcquisitionUnauthorized blocks
  acquisition only; unknown refs typed NotFound; the client never
  fabricates contract state (the parent crate's ObservationCache law).
- Platform independence: the domain mapping (wire/http/hex/error) is
  pure data and compiles for wasm32-unknown-unknown; the TCP transport
  and client are gated #[cfg(not(target_family = "wasm"))].
- Verification achieved: unit (33) + integration (7, against the
  adcos_test_server TEST SCAFFOLDING binary — a real std::TCP server
  speaking exactly this wire shape over a deterministic in-memory
  store with injectable faults: connection drop, 503 + recovery with
  cached freshness, garbage body, parallel clients, full lifecycle,
  typed not-found; the suite re-runs the parent crate's generic
  conformance_core battery against this client) — 40/40 green; wasm32
  check green; zero build warnings; governance PASS.
- Production caller: R5-003 (contract projection) builds on this
  client; the seam is the ConnectivityPort trait.
- Persistence: none — the ADCOS server is the contract authority (the
  no-second-contract-authority law); the client caches only read-only
  observations per the parent crate's policy type.
- Registry note: no registry change — the client consumes the
  adcos.md-frozen boundary and speaks an EXTERNAL API (adapter rule:
  no ShareNet wire objects originate here).

## Wave 7 integration record (2026-09-15)

- R4-002 implemented by the Tech Lead on `work/wave7-a-circuit-binding`
  (registry pre-registration ee47254 preceded implementation 50040c1).
- R4-005 implemented on `work/wave7-b-ice-turn` (d9482fb) — started by
  two subagent dispatches that both hit context deadlines mid-work;
  completed by the Tech Lead (repaired a dangling test variable, an
  evil-mode expectation, restructured the STUN server-per-step test,
  wrote the README).
- R5-001 implemented on `work/wave7-c-connectivity-port` (44d7536) by a
  subagent; independently verified at integration.
- Merged: 4b58541 (W1) → d594f7a (W2) → 317c622 (W3, = new main).
- Registry: the four circuit wire objects → implemented (this commit).

## Wave 8 integration record (2026-09-15)

- R4-003 implemented by the Tech Lead directly on main (0e944c1) in the
  main checkout; the two worktree dispatches (w8b, w8c) ran in parallel
  git worktrees (the shared-checkout race lesson from Wave 7 applied).
- R4-004 implemented on `work/wave8-b-android-vpn` (7d20ff6) — a
  dispatched subagent died mid-work leaving high-quality WIP (all nine
  production sources + six test files + the :vpn Gradle module); the
  Tech Lead completed it: fixed two test bugs (the IHL-below-minimum
  shape was shadowed by ShortHeader; PacketPipe lacked closeTunSide()
  so same-thread run()+receive() hung forever), wrote the module README,
  re-ran the real-SDK build (67/67 + AAR), committed.
- R5-002 implemented on `work/wave8-c-adcos-client` (c30066d) by a
  dispatched subagent (one clean run); independently re-verified at
  integration: 40/40 tests, wasm32 check green, zero warnings.
- Merged: 7728204 (R4-004) → 3766654 (R5-002, = new main); R4-003 was
  already on main. Zero merge conflicts (disjoint file scopes:
  transport/android/vpn, connectivity-client, transport/linux).
- Registry: NO registry change in Wave 8 — all three items consume
  already-registered wire objects or frozen boundary specs (R4-003:
  registered route/circuit objects + documented runtime control
  protocol; R4-004: platform adapter, no wire objects; R5-002: adapter
  for the external ADCOS developer API per adcos.md). Recorded here
  per the registry-update-before-implementation rule's scope (ShareNet
  wire objects only).
- Fresh audit on merged main: reference 148/0, connectivity 29/0,
  connectivity-client 40/0, linux 58/58 incl. gateway multiprocess,
  quic 9/9, ice 44/0, telemetry 35/0, wasm32 protocol check green,
  conformance harness PASS (177 byte-identical lines), Android
  :vpn:testDebugUnitTest 67/0 + :vpn:assembleDebug AAR, governance
  PASS. (Full sweep performed post-merge — see audit log below.)

### R4-006 — Restrictive-network fallback — COMPLETE (Wave 9)

- `transport/ice/src/agent.rs`: the ICE agent nomination (RFC 8445
  controlling-agent subset) — gather host (+srflx), walk ALL pairs in
  pair-priority order (direct first by construction) with connectivity
  checks, nominate the FIRST working pair; when every host/srflx base
  fails and a relay is configured, allocate a LOCAL relayed candidate
  (authenticated when credentialed) and complete the walk through it.
  Open networks never touch the relay (local_relay_used == false is a
  tested outcome); per-pair typed failures never poison the walk; no
  path → AgentNoPath with the FULL attempt transcript. Deliberately
  not implemented (documented): role negotiation/conflicts, consent
  freshness §11, triggered checks, peer-reflexive candidates,
  multi-component (the remote is an ICE-lite responder).
- `transport/ice/src/relay.rs`: long-term-credential allocation auth
  (RFC 5389 §10.2 / RFC 8489 §9 model over the SN control framing;
  HMAC-SHA-256 message integrity over exact request bytes — hmac+sha2
  were already in the dependency tree, zero new crates): 401 challenge
  (nonce + realm) → keyed response; wrong credential typed
  RelayAuthRejected; replayed nonce typed refusal; adversarial auth
  never harms the relay. turn_relay gained --auth/--realm; new ice_peer
  binary (ICE-lite peer, RFC 7983-style STUN/data demux).
- Verification achieved: unit (6 new: classification, fail-fast,
  direct-vs-live-responder, lying-candidate fails closed, dead-remote
  NoPath typed, stalled timeout) + integration/adversarial (5 new
  multiprocess vs REAL ice_peer/turn_relay processes: direct
  nomination + tunnel through the nominated pair; relay-only target →
  relayed pair + tunnel through the relay; dead hostile direct
  candidate fails typed while the relayed pair wins; agent phase-2
  wrong-credential → typed refusal + relay survives; authenticated
  relay serves the agent path end-to-end) — 62/62 total (46 unit + 16
  multiprocess). Governance PASS.
- Honest gaps (documented): client-side local-relay data plane needs
  real NAT shapes (R4-007/R10); SN control framing not wire-interop
  with production TURN servers (future adapter work).
- Implemented by a dispatched subagent that died at its context
  deadline after writing the library + binaries + unit tests; Tech
  Lead completed (added the 5 multiprocess evidence tests, fixed the
  ice_peer READY line to carry the node id, rewrote the README known
  limits), verified, committed 874ef2d.

### R4-007 — Mission gate real Internet bridge — COMPLETE (Wave 9)

- `transport/linux/tests/mission_gate.rs` + `MISSION-GATE.md` (the
  evidence report) + the `probe-uplink` subcommand. Tech Lead direct
  work.
- mission_gate_full_stack: the COMPLETE control-plane chain on real
  sockets — identity → signed capability → advertisement discovery
  with capability admission → authenticated link (sealed frames) to the
  ADVERTISED udp endpoint → route commitment + circuit admission inside
  the pinned QUIC tunnel → data plane (5 packets cross, responses
  return). The participant learns the gateway identity + BOTH
  transport endpoints from the SIGNED advertisement (nothing
  hardcoded); rediscovery idempotent (Duplicate); link_id equality
  cross-side asserted.
- mission_gate_real_internet_crossing: the REAL-NETWORK leg — the
  gateway uplink at a real public resolver (8.8.8.8:53 with 9.9.9.9 /
  1.1.1.1 / 8.8.4.4 fallbacks); the participant's DNS query for
  example.com. returns as a REAL response (txid echo + QR bit +
  question echo; 61 bytes observed) THROUGH THE ENTIRE SHARENET
  STACK. Live-egress-gated (tun_gated discipline: prints
  REAL_INTERNET_UNAVAILABLE and skips on fully restrictive networks —
  never a false pass).
- mission_gate_refuses_tampered_capability_on_ramp: tampered
  capability envelope in the advertisement fails discovery closed.
- GATEWAY FIX found by the real leg: the uplink socket was
  loopback-bound (EINVAL on real destinations) — now wildcard-bound
  (the Internet side); all prior gateway tests still green.
- Measured environment policy (probe-uplink evidence): UDP/53 open to
  public resolvers (6/6 answered); other UDP ports + raw TCP blocked;
  HTTPS allowlisted. The DNS-based crossing is the strongest
  real-network verification achievable from this host; exit codes
  typed (0 reachable / 3 unreachable / 2 usage).
- Verification achieved: linux 61/61 (58 + 3 mission), quic 9/9
  no-regression, governance PASS. Honest gaps recorded in
  MISSION-GATE.md: Android device leg (R10-002 JNI bridge + device),
  non-DNS destinations (need open-UDP network), real NAT shapes,
  endurance (R10-003).

### R5-003 — Contract projection — COMPLETE (Wave 9)

- `connectivity/src/store.rs`: the durable local health projection per
  adcos.md — persistence INSIDE the zero-dependency connectivity crate
  (std file I/O only; the pure model+codec compiles on wasm32, the
  file-backed store is gated non-wasm with the host seam documented).
  Private node-local binary image v1 ("SNCP" magic, version+flags,
  freshness window, records sorted by opaque id, 17 bytes/observation,
  CRC-32/IEEE trailer; 4 MiB cap; atomic flush = temp+fsync+rename;
  create never clobbers).
- Restart semantics as code: load re-DERIVES every state by folding
  the event mapping over the persisted log (a disagreeing persisted
  summary → typed SummaryDisagrees, whole store refused); freshness
  re-validated against caller-supplied CURRENT time (typed
  ProjectionFreshness::{NoObservation,Fresh,Stale} — stale is
  needs-refresh, never fresh); no-fabrication (reload serves the last
  accepted observation with ORIGINAL freshness metadata, never
  re-anchored); fail-closed corruption handling (every truncation and
  every single-byte mutation of a valid image rejected — including
  tamperers who recompute the CRC); no sequence regression across
  restarts.
- Integration with the real R5-002 stack: projection_store_probe
  binary (REAL new process: inspect/accept; machine-parsable stdout)
  + tests/durable_restart.rs — epoch 1 in-process (real AdcosClient +
  real adcos_test_server over loopback TCP), dead-provider probe
  (typed ProviderUnavailable, nothing fabricated), epoch 2/3 child
  processes reload/continue across the boundary (terminate idempotence
  preserved), epoch 4 verifies the child's durable write + redelivery
  dedup; second test = 503 outage prelude, provider killed, full
  teardown, reload shows last-accepted with original freshness, typed
  stale.
- Verification achieved: connectivity 50/50 (38 unit incl. 21 store
  tests + 12 conformance), connectivity-client 42/42, wasm32 green,
  zero warnings, governance PASS. Independently re-verified by the
  Tech Lead at integration.
- Honest gaps (documented): single-writer no locking, no parent-dir
  fsync, full-image rewrite per flush, 4 MiB cap; production caller =
  the future daemon wiring get_assurance → store; observations remain
  provider-asserted until R5-004 signs them.

## Wave 9 integration record (2026-09-15)

- R4-006 on `work/wave9-a-ice-fallback` (874ef2d): subagent died at
  context deadline mid-work; Tech Lead completed (5 multiprocess
  evidence tests, ice_peer READY node-id fix, README), merged 7b35182.
- R4-007 direct on main (c10e9bc): mission-gate composition + the
  verified real-Internet crossing + the gateway wildcard-bind fix +
  probe-uplink + MISSION-GATE.md.
- R5-003 on `work/wave9-b-contract-projection` (b5788fa): subagent,
  one clean run; Tech Lead independently re-verified; merged c5b61d8.
- Registry: NO registry change — R4-006/R4-007 are transport-layer
  runtime behavior over registered objects; R5-003's store image is
  node-local durable state, never a wire object (documented in its
  record).
- Fresh audit on merged main: reference 148/0, connectivity 50/0,
  connectivity-client 42/0, linux 61/61 (incl. 3 mission-gate tests
  and the real-Internet leg), quic 9/9, ice 62/62, telemetry 35/0,
  wasm32 protocol check green, conformance harness PASS (177 lines),
  Android :vpn 67/67 + AAR, governance PASS.

### R5-004 — Signed observations — COMPLETE (Wave 10)

- Registry: SignedConnectivityObservation pre-registered (187018f)
  BEFORE implementation; maturity → implemented at integration.
- `reference/crates/sharenet-protocol/src/connectivity_evidence.rs`:
  the wire object per the registry schema — provider-signed connectivity
  observation (the frozen six machine names shared with the connectivity
  domain, sequence >= 1 strictly increasing per (provider, contract),
  optional integer execution map, provider NodeIdentity with R1-001
  derivation). Ed25519 detached signature over exact canonical bytes;
  CapabilityStatement-style carrying envelope. ObservationAdmission = the
  R5-003 store's trust boundary as code: strict parse + identity
  derivation + signature + known-contract rule + sequence advance + the
  ACCEPTING node's freshness window (caller-supplied clock). Trust
  boundary honesty in the module docs: attests neither ShareNet packet
  delivery nor provider fulfillment.
- Tests: 8 unit + 12 adversarial (per-field tamper, foreign key,
  replay/regression, cross-contract confusion, envelope confusion,
  execution-map violations, non-canonical encodings) — reference
  168/0 (was 148). connectivity_evidence_vectors.json + all three
  conformance legs — harness now 218 byte-identical lines (was 177).
- Integration with the real stack: adcos_test_server produces SIGNED
  evidence (provider identity); AdcosClient verifies via the protocol
  core BEFORE anything reaches the connectivity domain;
  tests/signed_observations.rs — verified observations reach the
  R5-003 DurableProjectionStore and survive the restart; unsigned/
  rewritten observations refused typed and NEVER enter the store;
  freshness edges + unknown-contract rule over the real wire —
  connectivity-client 50/50 (was 42).
- connectivity/src/ UNTOUCHED (ADR-001 intact — the trust boundary is
  the adapter-side verification, documented in both READMEs).
- wasm32 green; governance PASS. Implemented by a dispatched subagent
  that died at its context deadline with the work complete-but-
  uncommitted; Tech Lead verified all suites independently, fixed the
  registry kind vocabulary to the frozen machine names, committed
  d32dcae, merged d5b744f.

## Wave 10 integration record (2026-09-15)

- Single-item wave: R5-004 (registry pre-registration 187018f →
  implementation d32dcae → merge d5b744f → registry maturity +
  EXECUTION-STATE this commit).
- Fresh audit on merged main: reference 168/0, connectivity 50/0,
  connectivity-client 50/0, linux 61/61, quic 9/9, ice 62/62,
  telemetry 35/0, wasm32 green, conformance harness PASS (218 lines),
  Android :vpn 67/67 + AAR, governance PASS.

### R5-005 — Gateway admission/backhaul policy — COMPLETE (Wave 11)

- `admission/` crate `sharenet-admission`: the pure two-factor decision
  engine per adcos.md — a gateway is ShareNet-eligible only when BOTH
  (1) authenticated ShareNet node/link evidence (R3-003
  SignedTopologyEvidence: strict parse + Ed25519 + subject binding +
  freshness window = earlier of observer expiry and observed_at +
  window) AND (2) acceptable ADCOS-backed connectivity evidence
  (R5-003 projection through its typed surface with the R5-004 trust
  boundary DERIVED, not trusted: observations re-verified, unique
  (provider, sequence), every log entry covered, snapshot
  self-consistency, Active + Fresh at the decision clock) hold.
- Typed GatewayAdmission::{Eligible, Ineligible{reasons}} with machine
  names; fail-closed on either side missing; exact integer ppm quality
  floor (u128 intermediates; the WORSE of stated ratio and
  counters-derived ratio — an internally inconsistent observer is
  judged by its counters); latency in exact microseconds. Deterministic
  for a fixed evidence snapshot (architecture §2). Honest boundary:
  grants no packet-delivery or fulfillment attestation.
- Verification: 25 tests (integration: real TopologyEvidence + real
  signed observations + a real DurableProjectionStore; adversarial:
  wrong-node binding, tampered evidence, one-sided, determinism,
  parameter edges, counter-vs-stated inconsistency) + wasm32 green +
  governance PASS. Deps exactly sharenet-protocol +
  sharenet-connectivity (ADR-001 intact — connectivity/src/ untouched).

### R6-001 — Content addressing/manifests — COMPLETE (Wave 11)

- Registry: ContentManifest pre-registered BEFORE implementation;
  maturity → implemented at integration (metadata text-value bound
  1..=256 bytes and the length-before-hash law ordering confirmed by
  the Tech Lead).
- `reference/crates/sharenet-protocol/src/content.rs`: the
  content-addressed foundation per architecture §12 — ContentManifest
  (chunk_size 1..=2 MiB = the CircuitFrame payload bound, exact
  chunk_hashes count, bounded metadata), content_id =
  SHA-256(canonical manifest) (commitment-derived identity, L013);
  chunk()/reassemble() with per-slot typed errors (per-slot length law
  BEFORE hash law; MissingChunk = verified-prefix semantics naming the
  first missing slot — exactly what R6-002 resume re-requests;
  ExtraChunk catches duplicates/injections).
- Verification: unit (9) + adversarial (20: manifest-only trust —
  claimed-length lies that keep geometry matching still fail every
  reassembly path, tested both directions) + conformance
  (content_vectors.json: 4 cases, 12 reassembly outcomes, 19 parse
  rejections; harness now 283 byte-identical lines). reference
  218/218. wasm32 green.

### R7-001 — Failure detector/revocation — COMPLETE (Wave 11)

- Registry: CircuitRevocation pre-registered BEFORE implementation;
  maturity → implemented at integration.
- `reference/crates/sharenet-protocol/src/revocation.rs`: the durable
  authoritative failure record (L015) — path-member-signed (verified
  against the revoked circuit's COMMITTED path, never caller-asserted),
  frozen reasons (link_failure, evidence_timeout, policy, operator),
  bounded honest evidence map. RevocationLedger: idempotent per
  (circuit, revoker), second-revoker recorded never un-revokes,
  is_revoked authoritative, L015 ENFORCED (setup/ack/frame admission
  refused for a revoked circuit_id even with runtime destroy state
  lost; durability via an injectable snapshot seam — full durable
  files R7-002 scope). FailureDetector (runtime): typed verdicts
  (LinkFailure{missed_acks}, EvidenceTimeout{stale_since}, Policy,
  Operator) — deterministic, caller-supplied clock, the input to
  revocation construction.
- Verification: unit + adversarial (21: per-field tamper, foreign
  key, non-path-member, future timestamp, evidence violations,
  envelope confusion, revoked-circuit admission refusal) + conformance
  (revocation_vectors.json: 4 full route+circuit chain rebuilds, 9
  receive-ledger outcomes, 13 parse + 4 envelope rejects; harness 283
  lines). wasm32 green; governance PASS.

## Wave 11 integration record (2026-09-15)

- The biggest parallel wave: three items, three worktrees, three
  dispatches. R6-001 (11-b) completed clean in one run (1b352fe). R7-001
  (11-a) and R5-005 (11-c) subagents BOTH died at their context
  deadlines with complete-but-uncommitted work — the recurring failure
  mode; Tech Lead verified both (R7-001's conformance legs were
  unwritten: dispatched a focused wiring agent that completed the three
  runner integrations in one bounded run).
- Merges: d8d201b (R6-001) → 901c401 (R7-001; runner/vector same-insert
  conflicts resolved keeping both sections; one missing for-loop brace
  fixed at the content/revocation seam) → aba3973 (R5-005).
- Registry: ContentManifest + CircuitRevocation → implemented.
- Fresh audit on merged main: reference 218/218, admission 25/25,
  connectivity 50/50, connectivity-client 50/50, linux 61/61, wasm32
  green, conformance harness PASS (283 byte-identical lines — up from
  218 at wave 10 start), governance PASS. 27 of 48 work items complete.

## Wave 12 integration record (2026-09-15)

- Continued from the w12-inflight handoff: all three crates existed as
  complete-but-uncommitted WIP in three worktrees (the recurring
  failure mode — check the worktree before re-dispatching). Tech Lead
  completion, not re-dispatch: w12a needed compile fixes (2 errors) +
  test-suite repair (4 test bugs: struct destructuring as tuple, tuple
  arity, borrow overlap, wrong pinned constants) + the multiprocess
  resume evidence test + README; w12b needed the file-backed restart
  tests + the adversarial dominant-priority-expired TTL test + the
  multiprocess carry suite + README; w12c's completion dispatch died at
  the platform context deadline AFTER writing its suites — Tech Lead
  fixed its two broken tests (a hang-by-spin converted to a bounded
  failure; a mis-clocked §11 freshness scenario whose commitment did
  not actually predate the revocation) + README.
- Merges: be71ff0 (R6-002) → 4e2c2f6 (R6-003) → fb7536a (R7-002) —
  clean; each branch adds only its own crate at the repo root. No
  registry changes: all three layers are documented runtime-control /
  node-local state, NOT wire objects (the same class as R4-003's
  tunnel control protocol and R5-003's store).
- Honest scope carried into the ready set: R6-002 defers signed
  delivery receipts to R8-001 and windowing to R6-005; R6-003 defers
  forwarding policy (R6-005 + R5-005 admission composition) and
  receiving-side cross-node rules (R6-004); R7-002 defers gateway
  selection/route construction (R7-003), replacement circuits (R7-004),
  retry/backoff (R7-005) and cross-recovery coordination (R7-006).
- Fresh audit on merged main: reference 218/218, admission 25/25,
  connectivity 50/50, connectivity-client 50/50, linux 61/61, transfer
  72/72, dtn 34/34, recovery 41/41 (551 total), wasm32 green
  (protocol, connectivity, connectivity-client, dtn libs), conformance
  harness PASS (283 byte-identical lines), governance PASS. 30 of 48
  work items complete.

## Wave 13 integration record (2026-09-15)

- Two-way parallel wave. R6-004 (13-a) completed CLEAN in one bounded
  dispatch: sharenet-propagation, the pure R5-005-style decision engine
  for receiving-side cross-node rules (dedup/integrity/TTL floor/
  priority), composing the R6-003 store, 46 tests (26 unit + 16
  adversarial + 4 restart), wasm32 lib clean. R7-003 (13-b) subagent
  died at its platform deadline with complete-but-uncommitted work (the
  recurring mode): gateway selection composing the REAL R5-005 policy
  (only Eligible selects, signature verification at selection time,
  deterministic ascending-id tie-break, typed no_eligible_gateway /
  duplicate_gateway_candidate) + establish_fresh_route (R3-004 chain,
  admission-freshness at construction) + recovery_probe + 56 green
  tests — Tech Lead verified, completed the README, committed.
- Merges: 7e6ae9d (R6-004) → 673dbc7 (R7-003) — clean, disjoint crates.
- Fresh audit on merged main: reference 218, propagation 46, recovery
  56, admission 25, connectivity 50, dtn 34, linux 61, transfer 72 (562
  total), wasm32 green (protocol, connectivity, connectivity-client,
  dtn, propagation libs), conformance harness PASS (283 byte-identical
  lines), governance PASS. 32 of 48 work items complete.

## Wave 14 integration record (2026-09-15)

- Two-way parallel wave, both dispatches died at platform context
  deadlines AFTER doing most of the work (the recurring mode — check
  the worktree, complete, never re-dispatch from scratch): Tech Lead
  completed R6-005 (the simulation + probe existed; wrote the
  multiprocess suite, fixed three probe bugs the dead agent never ran
  into: receive auto-creates a fresh receiving store, consumes
  piped-through protocol lines, parses the full OFFER line) and R7-004
  (the replacement + zeroization stage existed with 62 green tests;
  wrote the 6 adversarial legs + the four-role multiprocess test, and
  fixed the probe's establish-replacement to re-derive the gateway
  through the PURE selection layer — the attempt-bound select_gateway
  cannot run once the attempt is terminal).
- Merges: clean, disjoint crates. R6-005 = the contact model + the
  forwarder (budget-bounded priority-ordered plans, typed TTL defers,
  landed-handovers-only custody) + the seeded deterministic
  contact-graph simulation (byte-identical traces) + the multiprocess
  handover. R7-004 = record_zeroization (durable typed §11 fact) +
  establish_replacement_circuit (zeroization-gated, record-bound,
  L014-fresh, R4-002-admitted through the L015-gated registry,
  single-flight).
- Fresh audit on merged main: reference 218, propagation 73, recovery
  69, admission 25, connectivity 50, dtn 34, transfer 72, linux 61 (602
  total), wasm32 green (protocol, connectivity, connectivity-client,
  dtn, propagation libs), conformance harness PASS (283 lines),
  governance PASS. 34 of 48 work items complete.

## Wave 15 integration record (2026-09-15)

- Single-item wave. The R7-005 dispatch died at the platform context
  deadline BEFORE writing anything (clean worktree); Tech Lead
  implemented directly: `recovery/src/backoff.rs` (pure, validated
  schedules: fixed/linear/exponential-capped with saturating math and
  exact pinned bounds; typed RetryDecision/TerminalReason vocabulary;
  the attempt log IS the history — read, never duplicated; no wall
  clock, no timers, no jitter), the driver gate `when_may_retry`
  (§11-ordered, single-flight, success-terminal, budget-exhausted,
  inclusive window bound) and `attempt_next_when_permitted` (composed;
  typed retry_not_yet carrying the daemon's timer input +
  retry_exhausted).
- Merge: clean. Fresh audit: recovery 83/83, reference 218/218,
  conformance harness PASS (283 lines), governance PASS. 35 of 48 work
  items complete.

## Wave 16 integration record (2026-09-15)

- Single-item wave; dispatch skipped (the 15-a pattern: direct Tech
  Lead implementation is faster and more reliable for single-crate
  extensions). R7-006 delivered: the coordination view
  (`recoveries(now, policy)` — typed in-flight/retryable/awaiting/
  terminal states, deterministic id order, the daemon scheduler's pure
  input), the terminal cleanup (`cleanup_terminal` — prunes ABANDONED
  history age-gated and typed, retaining the terminal record + high
  water + §11 anchor + zeroization; the L015 LEDGER never touched; a
  cleaned circuit stays `recovery_already_complete` — no
  resurrection), and the L014 second-failure cycle (the replacement
  circuit revoked in turn opens its OWN fresh recovery — end-to-end
  in-lib and across processes via the new probe commands
  abandon/recoveries/cleanup/revoke-replacement).
- Fresh audit: recovery 90/90, reference 218/218, conformance harness
  PASS (283 lines), governance PASS. 36 of 48 work items complete.
  **GATE R7 (failure handling/recovery) IS NOW COMPLETE** — all six
  items R7-001..R7-006 integrated.

## Wave 17 integration record (2026-09-16)

- Two-way parallel wave, both legs completed from WIP after dispatch
  deaths (the w13/w14 pattern):
  * R8-001 (contribution evidence): the pre-registered
    ContributionReceipt schema implemented in `contribution.rs` —
    bilateral recipient-signed acknowledgement (the RECEIVING
    counterparty signs), contributor != issuer (self-receipt excluded at
    construction AND parse), frozen kinds {carried, delivered},
    receipt_seq strictly increasing per (issuer, contributor) pair,
    issued_at <= the verifying clock, receipt_id = SHA-256(canonical
    bytes) (L013), the ReceiptLedger (admit order: signature → future →
    receipt_id idempotency → sequence law; identical re-delivery is
    Duplicate, a repeated sequence on different bytes is refused typed,
    refusals record nothing), manifest-binding checks
    (content_id_match + delivered_bytes <= total), fail-closed snapshot
    round-trip. 15 adversarial legs (the 4 mid-fix WIP failures were
    TEST expectations corrected to the house parse-first law:
    scheme-version/identity refusals fire before the signature check;
    the duplicate-key law fires at the canonical-CBOR layer with
    hand-spliced bytes; the namespace-regression leg re-delivers a
    DIFFERENT named object). Conformance: contribution_vectors.json (8
    cases / 11 shared-ledger admit legs / 12 parse + 5 envelope rejects)
    re-derived by Rust + TS + Python; harness 319 byte-identical lines
    (was 283). Registry: maturity registered → implemented.
  * R9-001 (iOS Network.framework participant): `transport/ios/`
    Swift package (ShareNetParticipant) — Contract/ seam (pure
    Foundation: ParticipantTransport/TransportListener/TransportEvent/
    TransportFrame/TransportError/EndpointID, FrameCodec 4-byte
    length-prefix, SendWindow backpressure, ConnectionTracker ladder),
    Link/ (R3-001 adapter side: engine seams = the protocol core's
    presence, msg1→msg2→msg3 driver with one overall deadline +
    fresh-engine-per-attempt, LinkEnvelope, AuthenticatedLink with the
    terminal/malformed discipline), Participant/ (the only
    Network.framework layer: NWParticipantTransport, NWLinkTransport,
    Bonjour browse/advertise, validated configuration). 32 XCTest
    functions WRITTEN NOT EXECUTED (no Swift toolchain in the sandbox —
    requires macOS 13+/Xcode 15+; the "ios" verify level is honestly
    OPEN). The "architecture" verify level delivered:
    `docs/architecture/ios-participant.md` (the seam map onto the frozen
    architecture + recorded gaps: no production engine until the
    Rust-core FFI bridge — the same deferral as Android's JNI for
    R10-002; Packet Tunnel Provider is R9-002).
- Both dispatches (17-a subagent, 17-b subagent) died at platform
  context deadlines mid-work; the Tech Lead completed both directly
  from the WIP (17-a: 4 adversarial test-expectation fixes + the full
  vectors/conformance build-out; 17-b: Swift review + API-consistency
  fix (non-throwing init default), README + architecture record,
  commit).
- Integration fix: `transfer` had one genuinely racy test
  (`forged_complete_before_any_chunk_is_contained` — the forged
  COMPLETE consumes the receiver's first round; the re-request races
  the receiver's benign post-completion shutdown under the full
  parallel suite). Fixed with the benign-shutdown tolerance after at
  least one responded round (the receiver's outcome stays the
  independently-asserted oracle); 5/5 full-suite runs green.
- Fresh audit (2026-09-16): reference 243/243 (protocol+conformance
  test binaries), propagation 73/73, recovery 90/90, admission 25/25,
  connectivity 50/50, connectivity-client 50/50, dtn 34/34, transfer
  72/72, linux 61/61, quic 9/9, ice 62/62, telemetry 35/35 — 804 tests
  green. wasm32 reference clean. Conformance harness PASS (319 lines).
  Governance PASS. 38 of 48 work items complete.

## Wave 18 integration record (2026-09-16)

- Two-way parallel wave, both legs direct Tech Lead work after dispatch
  deaths (the established pattern):
  * R8-002 (useful-work valuation): NEW crate `economics/`
    (sharenet-economics) — VALUATION_FORMULA_VERSION = 1 (architecture
    §13 "versioned and explicit"): billable = min(delivered_bytes,
    per-receipt cap); intrinsic = kind weight (carried 1.0× / delivered
    1.5×, basis points, truncating integer math); award = min(intrinsic,
    pair-cap remaining, contributor-cap remaining); window =
    issued_at/window_secs. The §14 minimums this layer owns:
    per-counterparty + per-time-window caps (pair AND
    contributor-across-issuers — the Sybil bound), contribution-quality
    weighting. Capped receipts stay valid evidence (verdict reports
    intrinsic/awarded/binding cap — never refused). Defense in depth:
    receipt_id idempotency, future-clock refusal. sim.rs (the
    simulation verify level): seeded deterministic adversarial
    simulation — the 8-issuer sybil ring's 160k/window potential held at
    the 50k contributor cap, circular pair bounded by its two
    directional pair caps, window straddler never double-bills,
    zero cap violations every seeded run; economics_sim driver prints
    the byte-identical report line. 28 tests (14 unit+sim, 14
    adversarial), zero warnings, wasm32 clean, governance PASS. Honest
    scope: durability R8-003, consumption R8-004, anomaly DETECTION
    R8-005 (the caps bound abuse, they do not catch it).
  * R9-003 (dedicated gateway appliance): transport/linux
    src/appliance.rs + the `appliance` subcommand — the long-running
    service form: durable identity (0600 seed file, created once from
    /dev/urandom, same node id across restarts), one stable bound
    address, sequential admission-verified sessions, append-only CBOR
    session journal (fsync'd per record; fail-closed reload). The
    endurance verify level: multiprocess soak with a MID-RUN HARD
    RESTART — durable identity, ordinal continuity (resumes at 5 after
    4 journaled) and cumulative totals all proven. The real-network
    verify level: a REAL 61-byte DNS response from 8.8.8.8 through the
    ENTIRE appliance stack (the R4-007 gated discipline; typed
    REAL_INTERNET_UNAVAILABLE skip on restrictive networks). 66 linux
    tests green (61 prior + 3 journal + 2 endurance), zero warnings.
    Endurance honesty: minutes-scale here; 24h endurance is R10-003's.
- Fresh audit (2026-09-16): economics 28/28, linux 66/66, governance
  PASS. 40 of 48 work items complete.

## Wave 19 integration record (2026-09-16)

- Single-item wave; direct Tech Lead implementation (the w15/w16
  pattern). R8-003 delivered: economics/src/ledger.rs — the Civic Point
  ledger as the DURABLE form of the R8-002 valuation. CivicPointLedger
  composes the engine (award() re-derives all pricing — never
  caller-supplied points) and appends a LedgerEntry per non-zero award
  (the registered CivicPointLedgerEntry durable-state record). The
  RESTART LAW — the design's sharpest edge, found by the restart suite:
  the reload must restore the ENGINE state (valued ids + per-pair +
  per-contributor window totals), else a restart resets the window caps
  (a farming-by-restart vector); ValuationEngine::restore() is the seam,
  the entry carries the issuer node_id (field 10) for the pair-totals
  reconstruction, and the adversarial leg proves the cap binds across
  the restart while a NEW window still pays. FileCivicPointLedger
  (fsync-per-entry appends, fail-closed reload) + the snapshot
  round-trip cover both durability forms. Balances only ever increase
  (no spend path exists — R8-004 owns consumption). One audited unsafe
  (fsync(2)) under crate-level deny(unsafe_code) + local allow.
- Fresh audit: economics 41/41 (18 unit + 6 restart + 3 concurrency +
  14 adversarial), zero warnings, wasm32 clean, governance PASS.
  41 of 48 work items complete.

## Wave 20 integration record (2026-09-16)

- Three-way wave, direct Tech Lead work:
  * R8-004 (priority/perk consumption): economics/src/consumption.rs +
    the ledger's spend path — the ONLY balance-decreasing operation
    (typed, exactly-once per spend_id, no overdraft, nothing moves on
    refusal). Frozen v1 perks: priority_scheduling (a bounded-time
    live-class grant in the DTN's OWN ServicePriority vocabulary) +
    gateway_preference; fee reductions/sponsored connectivity/community
    rewards documented as settlement-program scope. THE INTEGRATION
    LEG: a contributor holding an active grant gets their bundle
    carried FIRST by the DtnStoreImage's own carry order (granted
    bundle admitted SECOND still carries first — live > dtn; without
    the grant, insertion order holds). Adversarial: overspend,
    double-spend, expired grants (half-open interval), spends survive
    the durable restart, balances never negative. 48 economics tests
    green, zero warnings, wasm32 clean.
  * R9-002 (iOS Packet Tunnel evaluation): the platform verify level
    honestly recorded OUT OF SCOPE (no Swift toolchain — the R9-001
    gap; requires macOS/Xcode + the networkextension entitlement +
    Apple's manual approval). The evaluation criteria delivered
    (docs/architecture/wave20-platform-items.md): the entitlement
    gate, the ready Contract/ seam, the FFI prerequisite (the R10-002
    bridge class), and the per-deployment tunnel-vs-participant
    decision architecture §16 itself leaves open.
  * R9-004 (additional access adapters): the architecture analysis
    (same doc) — additional access technologies are ADCOS
    provider-side and NEVER enter transport/; the ShareNet-side surface
    for every one of them is the SAME implemented, tested,
    conformance-pinned boundary (ConnectivityPort → signed
    observations → R5-003 store → R5-005 admission → R7-003/004
    selection and replacement), exercised end-to-end over the real
    developer API by connectivity-client. No new ShareNet-side code is
    required for a new access technology — the boundary absorbing
    provider diversity IS the design working. The specific-provider
    live-egress leg is ADCOS-rollout-driven, outside this sandbox.
- Fresh audit: economics 48/48, governance PASS. 44 of 48 work items
  complete.

## Ready set (recomputed from actual predecessor completion)

- Wave 21 (single): R8-005 (anti-gaming/audit — R8-003 ✓ + R8-004 ✓;
  verify: adversarial, simulation — the anomaly detection over the
  ledger the caps currently only bound). Waves 22–24: R10-001..R10-005
  (the integration gate: two-process loopback, the Android real-device
  bridge incl. the FFI/JNI work, 24h endurance, failure injection, the
  four-week competitor simulation).
- R2-002 (Wi-Fi Aware) remains optionally schedulable inside gate R2
  (Tech Lead decision; not on the frozen wave path).

## Wave 21 integration record (2026-09-16)

- Single-item wave; direct Tech Lead implementation (the w15/w16/w19
  pattern). R8-005 delivered: economics/src/antigaming.rs — the
  anomaly DETECTION + audit layer (§14's "anomaly detection" minimum;
  Waves 17–20 delivered the BOUNDS, this wave delivers the CATCH).
  Ten frozen v1 rules — 4 integrity (ledger invariant re-derivation
  incl. duplicated receipt_ids inside the audited set, unknown
  formula versions flagged not guessed at, append-clock regression,
  spend-side exactly-once/no-overdraft re-checked from the outside) +
  6 anomaly (pair cap-saturation streaks; contributor-across-issuers
  saturation — the k-issuer Sybil shape where NO single pair looks
  guilty; reciprocal award rings via deterministic Tarjan SCC over
  the issuer→contributor graph — catches the size-3 cycle A→B→C→A no
  pairwise check could see; repeated identical intrinsic magnitudes —
  real traffic varies, scripts repeat; intrinsic-exceeds-awarded
  streaks — the visible overshoot is the last partially-capped
  receipt's intrinsic, because fully-capped receipts record nothing
  by the ledger's own registered law, the threshold IS the
  comparison; single-issuer concentration in MATERIAL windows —
  material = max(floor, ratio × contributor cap), because
  concentration at low volume is a single honest neighbor). The
  AuditReport is the registered AntigamingAuditReport durable-state
  record (registered ahead of implementation, commit 704ad74):
  canonical CBOR, fail-closed strict parse, derived verdict
  (clean/under_review/gaming_suspected), policy fingerprint — the
  determinism law (identical inputs → byte-identical report) is the
  audit's own integrity, proven by the restart test (audit → reload
  from disk → audit → byte-identical). Detection is NOT adjudication:
  the report revokes nothing (enforcement stays with the §14 caps;
  a deployment decides what to do with a named suspect).
- Adversarial: every gaming cohort named with its exact kind; every
  evasion attempted (jitter farmer still caught by sum-based
  saturation; below-threshold reciprocity NOT a ring; alternating-
  window saturation NOT a streak — the conservative-threshold
  honesty); 16 seeded honest cohorts → zero findings; tampered logs
  (pair total above cap, duplicated receipt_id) → HIGH; unknown
  formula version → HIGH; clock regression → LOW; forged spend list
  (duplicate spend_id) → HIGH.
- Simulation verify level: run_antigaming_simulation (seeded, the
  economics_sim pattern) — an honest mesh + six gaming cohorts (pair
  farmer, k-issuer Sybil family, reciprocal ring, magnitude
  repeater, every-window blaster, concentrated feeder): every cohort
  caught, the honest mesh NEVER flagged, the log lawful, the line
  deterministic (antigaming_sim driver, exit 1 on any detection
  failure).
- Fresh audit: economics 55/55 (41 lib: 20 unit + 21
  adversarial/sim; 14 restart/concurrency/perk/adversarial test
  targets), zero lib warnings, wasm32 clean, clippy clean (the new
  code), governance PASS.
- COUNT CORRECTION (Tech Lead arithmetic audit, prompted by the
  external review): the Wave 20 record said "44 of 48 work items
  complete" — that count was WRONG. The honest count after Wave 20
  was 41 of 48 (48 registry items − 7 then-open: R8-005, R9-001
  [ios level open], R9-002 [platform level open], R10-001..R10-005).
  With R8-005 complete the count is 42 of 48, six open: R9-001 (ios
  level), R9-002 (platform level), R10-001..R10-005. The ready-set
  sections (which always listed the true open set) were correct all
  along; only the summary counters drifted. Both R9 items are
  recorded as architecture/evaluation-complete with their platform
  legs honestly open (Swift toolchain / macOS runner absent in this
  sandbox) — see their completion records and the Wave 20 record.

## Ready set (recomputed after Wave 21)

- Wave 22 (two-way): R10-001 (two-process Linux loopback — deps
  R4-007 ✓ + R7-004 ✓; verify: multiprocess) + R10-002 (Android
  real-device bridge — deps R4-007 ✓ + R7-004 ✓; verify:
  real-device, real-network — includes the JNI/FFI work deferred
  from R4-004). Wave 23: R10-003 + R10-004 (deps R10-001, R10-002,
  R7-006 ✓). Wave 24: R10-005 (deps R8-005 ✓, R10-004).
- R2-002 (Wi-Fi Aware) remains optionally schedulable inside gate R2
  (Tech Lead decision; not on the frozen wave path).

## Wave 22 integration record (2026-09-16)

- Two-way wave, direct Tech Lead work:
  * R10-001 (two-process Linux loopback): NEW binary
    `sharenet_loopback` (transport/linux) — the participant role that
    composes the LIVE gateway session with the durable recovery
    pipeline over the REAL wire evidence. Additive seams:
    `ParticipantSession::wire_evidence()` (the exact signed
    route/circuit envelopes exchanged on the tunnel's control
    stream), `ParticipantSession::registry()`,
    `GatewayClient::connect_with_idle_timeout` +
    `TunnelClient::connect_with_idle_timeout` (>= 100 ms, fail-closed
    — the silent-death failure-detection idiom; defaults unchanged).
    The multiprocess test: gateway A + gateway B + participant, real
    processes, loopback UDP "Internet"; the test SIGKILLs gateway A
    after observing the working exchange; the participant detects
    (typed), revokes (R7-001), attempts + selects (R7-003, from
    verified candidate evidence), establishes the live replacement on
    B, records the fresh route + zeroization + replacement circuit
    (R7-004) FROM THE REAL WIRE ENVELOPES — the durable replacement
    circuit id IS the live session's circuit id (asserted in the
    binary and again in the test). Plus the real-Internet variant
    (the R4-007 honest-skip discipline): a REAL DNS response from a
    public resolver rides the REPLACEMENT session — gateway A died
    between the two queries; the second answer crossed the real
    Internet through the replacement circuit. transport/linux 73
    green (41 lib + 32 integration), quic 9 green, zero warnings.
  * R10-002 (Android real-device bridge): NEW crate
    transport/android-bridge (rlib + cdylib) — the TunnelBackhaul
    seam's production implementation: a GatewayClient participant
    session behind the frozen BridgeNative JNI surface (v1). Host
    tests drive the REAL stack (in-process GatewayServer + loopback
    uplink echo: forward, wrong-pin fail-closed,
    destroy-then-forward fail-closed, export surface); the cdylib
    builds with all four symbols (nm-verified). Kotlin side:
    BridgeNative.kt (external funs + the injectable
    BridgeNativeLibrary seam) + JniTunnelBackhaul.kt (the production
    backhaul: strict laws, ABI check, typed BackhaulFailure on every
    failure path, exactly-once close); JVM tests incl. the FULL
    PacketLoop over the bridge seam and the dead-bridge fail-closed
    path. Android: 92 tests green, AARs assemble. HONEST GAP: no NDK
    or physical device in this sandbox — the on-device leg
    (cargo-ndk build, install, ACTION_START + consent, real radio
    traffic) is the operator runbook in vpn/README.md §The JNI
    bridge. The real-network leg the work item asks for is carried
    by R10-001's real-Internet test (the same GatewayClient session
    over a real resolver) and the R4-007/R9-003 real-network
    records; the device-specific radio/TUN behavior is the only
    unexercised remainder.
- Fresh audit: android-bridge 5/5 host, transport/linux 73, quic 9,
  vpn 92 (contract+vpn+nearby, real SDK build), governance PASS.
  44 of 48 work items complete (open: R9-001 ios level, R9-002
  platform level, R10-003, R10-004, R10-005 — see the honest-gap
  records).

## Ready set (recomputed after Wave 22)

- Wave 23 (two-way): R10-003 (24h endurance/restart — deps R10-001 ✓
  + R10-002 ✓ + R7-006 ✓; verify: endurance, restart) + R10-004
  (failure injection/recovery validation — deps R10-001 ✓ + R10-002 ✓
  + R7-006 ✓; verify: adversarial, multiprocess, real-device). Wave
  24: R10-005 (deps R8-005 ✓, R10-004).
- R2-002 (Wi-Fi Aware) remains optionally schedulable inside gate R2
  (Tech Lead decision; not on the frozen wave path).

## Wave 23 integration record (2026-09-16)

- Two-way wave, direct Tech Lead work:
  * R10-003 (endurance/restart): NEW binary `sharenet_endurance` —
    the sustained two-appliance bridge: two R9-003 appliances (durable
    identity + append-only journal) + the R10-001 participant, cycled
    with one induced SIGKILL and one restart per cycle, alternating
    roles so both appliances accumulate journaled replacement
    sessions. The LAWS: sustained operation (data before AND after
    each failure), durable identity (same node id across every
    restart), journal continuity (ordinals strictly increasing across
    the whole life — the harness waits for the fsync'd session line,
    the journal is the truth the process is not), state accumulation
    (the revocation ledger grows monotonically), memory stability
    (per-cycle RSS sampling, 64 MB growth bound). The 24-HOUR operator
    profile is the same harness (`--sessions 1440 --spacing-ms 60000`
    = one bridge round per minute for a day, --uplink a real
    upstream); the sandbox verification is the accelerated profile
    (8 cycles / 8 kills / 8 restarts) — the laws are identical. Two
    real participant bugs the endurance run exposed and fixed: the
    per-run projection store (create refuses an existing dir) and the
    fresh decision clock at the wire-evidence phase (a pre-connect
    clock lags the envelopes' timestamps across a second boundary —
    R3-004's proposal_not_yet_valid).
  * R10-004 (failure injection/recovery): four injected-failure
    scenarios against real processes: the LINK-failure shape (gateway
    alive, its INTERNET dies — the most realistic bridge failure; the
    idle timeout + revocation + replacement carry the traffic through
    the other gateway's live uplink), the TOTAL-OUTAGE shape (both
    gateways die mid-session — the participant fails CLOSED, BOUNDED,
    then the system recovers with fresh gateways), DEAD-ON-ARRIVAL
    (fast typed connect failure), and the HOSTILE uplink (garbage
    answers carried verbatim, nothing crashes — the bridge is a data
    plane, not a parser). The real-device leg is the R10-002 operator
    runbook; the JVM fail-closed behavior is JniTunnelBackhaulTest's
    dead-bridge loop test.
- Fresh audit: transport/linux 80 green (41 lib + 39 integration:
  2 loopback + 1 endurance + 4 failure-injection + 32 prior), zero
  warnings on the new code, governance PASS. 46 of 48 work items
  complete (open: R9-001 ios level, R9-002 platform level — the
  honest-gap records — and R10-005).

## Ready set (recomputed after Wave 23)

- Wave 24 (single): R10-005 (four-week competitor simulation — deps
  R8-005 ✓ + R10-004 ✓; verify: simulation, reproducibility).
- R2-002 (Wi-Fi Aware) remains optionally schedulable inside gate R2
  (Tech Lead decision; not on the frozen wave path).

## Wave 24 integration record (2026-09-16)

- Single-item wave; direct Tech Lead implementation. R10-005
  delivered: economics/src/competitor_sim.rs + the competitor_sim
  driver — a seeded, deterministic month of competition (28 days × 24
  windows) through the REAL CivicPointLedger with WEEKLY + final
  audits by the REAL R8-005 detector. The world: an honest,
  multi-issuer, failure-gapped cohort (15% of windows lost to
  outages — a gap is not a pattern) against the six gamer strategies
  (farmer, Sybil family, reciprocal ring, magnitude repeater,
  every-window blaster, farm-and-spender exercising lawful perk
  consumption). The laws: every gamer cohort named at every weekly
  audit (135 gamer findings in the default seed-42 month); ZERO
  honest false positives across seeds and at 40% outage; ZERO
  ledger-integrity violations (the caps hold a month of gaming); the
  gamers' yield exactly what the caps allow; byte-identical report
  per seed (md5-verified), different seed → different month. The
  month-scale audit forced a REAL detector fix (same results,
  byte-identical report): the concentration rule now pre-indexes
  per-(contributor, window) top-issuer totals in one pass instead of
  rescanning all entries per window (minutes → milliseconds at 40k
  entries).
- Fresh audit: economics 44 lib (3 new) + 9 test targets green, zero
  warnings, wasm32 clean, clippy clean, governance PASS.

## PROGRAM CLOSURE (2026-09-16) — the frozen path is executed

- ALL 24 WAVES OF THE FROZEN PATH ARE EXECUTED. Work items: 46 of 48
  fully verified with evidence; 2 further (R9-001, R9-002) complete
  at their delivered scope (architecture / evaluation) with their
  Apple-gated platform verify legs honestly recorded as open — the
  only unexecuted verifications in the program, each with its
  operator step now recorded in spec/architect/current-state.yaml
  (honest_gaps). R2-002 (Wi-Fi Aware) remains the recorded optional
  off-path item (Tech Lead decision, unchanged).
- ARCHITECT CLOSURE DECISIONS (Open Architect Decisions RESOLVED):
  1. spec/architect/current-state.yaml now declares
     FROZEN_PATH_EXECUTION_COMPLETE (supersedes the R0 baseline
     string; tools/architecture_check.py pins the new string
     verbatim — updated in the same change, per the decision's own
     requirement). The file now records completed_gates [R0..R10],
     active_gate NONE, and the honest_gaps list with operator steps.
     The NodeIdentity wire-schema registry review request is folded
     into the registry's own status_note trail (registered Wave 17
     integration; the schema carried three-language conformance).
  2. spec/roadmap.yaml gate statuses updated from their planning-time
     values to the executed truth (COMPLETE; R9 =
     COMPLETE_PLATFORM_GAPS_RECORDED, R10 =
     COMPLETE_OPERATOR_RUNBOOKS_RECORDED).
- The honest-gaps ledger at closure: R9-001 ios (no Swift toolchain
  in any build sandbox used — re-confirmed at closure), R9-002
  platform (macOS/Xcode/entitlement), R10-002 device (NDK/phone —
  the bridge itself is implemented + host-verified against the real
  stack), R10-003 wall-clock (the accelerated-profile laws are
  proven; the 24h profile is the operator command). Every gap names
  its operator step.
- Final program audit: see the fresh-audit record below.

## Final program audit (fresh, at closure 2026-09-16)

Rust test totals (cargo test, all targets, all green):
sharenet-protocol 243; propagation 73; admission 25; connectivity 50;
recovery 90; dtn 34; transfer 72; connectivity-client 50; economics
74; transport/linux 73 (incl. the 2 loopback bridge + 1 endurance + 4
failure-injection integration tests); transport/quic 9;
transport/android-bridge 5; transport/ice 62; transport/telemetry 35
— 895 tests green across 15 crates. Cross-language conformance
harness: PASS (three languages byte-identical across 319 lines).
wasm32: economics + protocol clean (this closure's rebuilds). Android:
:vpn 92 + :contract + :nearby green, AARs assemble (real SDK build,
the R10-002 record). Governance: PASS (against the NEW closure status
string). Honest note: sharenet-conformance's bin carries pre-existing
dead-code warnings in its vector scaffolding (present since its wave;
untouched by the closure).

## Closure verification addendum (2026-09-16, post-closure audit session)

- **iOS honest gap materially narrowed (R9-001).** A Swift toolchain was
  installed in the sandbox (Swift 6.1.2, x86_64-unknown-linux-gnu,
  user-local tarball + locally extracted libncurses6/libtinfo6 — no sudo;
  exact repro recorded). The ShareNetParticipant package now COMPILES and
  its full pure-logic XCTest suite EXECUTES GREEN on Linux:
  `Executed 32 tests, with 0 failures (0 unexpected) in 0.413s`
  (ConnectionTracker 14, FrameCodec 10, SendWindow 8). Process and findings:
  (1) the baseline unguarded build failed exactly as the gap recorded
  (`no such module 'Network'`) — now hard evidence; (2) the four
  Network.framework adapter files are guarded `#if canImport(Network)`
  (identical compilation where Network.framework exists; excluded on
  Linux); (3) compiling surfaced and fixed TWO real never-compiled
  defects — a SendWindow stored/computed property name collision, and
  unqualified `guard case .case = error` test patterns that do not resolve
  against untyped error existentials (qualified to `TransportError.`).
  The "ios" verify level of R9-001 REMAINS OPEN, narrowed to the Apple-only
  adapter layer (its compile/execution and any Apple-platform compile of
  the guarded files require macOS 13+/Xcode 15+). Updated: transport/ios
  Package.swift + README.md ("Sandbox honesty" — evidence record),
  docs/architecture/ios-participant.md, spec/architect/current-state.yaml
  (honest_gaps R9-001-ios). R9-002's platform leg is unchanged
  (entitlement-gated).
- **Definitive work-item count ladder (registry-computed).** The final
  closure record's "46 of 48 fully verified + 2 at delivered scope" was
  computed directly against the 48-item registry and is CORRECT
  (R2-002 is not a registry item — it is the roadmap-noted optional
  off-path item; the registry's R2 gate has three items). This addendum
  records the registry-computed ladder for the intermediate wave records,
  closing the residual drift the Wave 21 correction diagnosed but did not
  fully eliminate (its own corrected counter still carried a +1 residual,
  inherited by the Wave 22/23 records): fully-verified counts were
  after Wave 20 → 40 (not 41), after Wave 21 → 41 (not 42), after Wave 22
  → 43 (not 44), after Wave 23 → 45 (not 46), after Wave 24 → 46 ✓
  (+ R9-001/R9-002 at delivered scope = 48). Same lesson as the Wave 21
  correction, now fully applied: the ready-set open lists were always
  right; only the summary counters drifted, and the closure number was
  computed against the registry, not the ladder.
- **Open Architect Decisions section corrected.** The standing section
  below still listed the two decisions as open (stale from the wave-1/2
  era); both were RESOLVED by the PROGRAM CLOSURE record above and are
  now marked resolved in place.

## Open Architect Decisions

1. RESOLVED at closure (see PROGRAM CLOSURE above):
   `spec/architect/current-state.yaml` now declares
   `FROZEN_PATH_EXECUTION_COMPLETE`; `tools/architecture_check.py` pins the
   new status string verbatim (updated in the same change as the status
   flip, per this decision's own requirement). The NodeIdentity
   wire-schema registry review request (decision 2) is folded into the
   registry's own status_note trail (registered at Wave 17 integration;
   the schema carries three-language conformance since R8-001).
2. RESOLVED at closure: NodeIdentity wire schema recorded in the protocol
   registry with evidence-based status notes; no further Architect action
   requested.

## Evidence index

- Worker completion reports (harvested from task transcripts):
  `scripts/logs/evidence_w1_report.md`, `evidence_w2_report.md`,
  `evidence_w1_v1_report.md` on the orchestrator host (replay2 checkout).
- Raw transcripts: `scripts/logs/transcript_{w1-foreign,w2-foreign,
  proto-foreign}.txt`.

## R10-006 execution record (2026-09-17) — post-closure defect fix

- **Trigger**: the R10-003 24-hour wall-clock endurance run (operator
  profile, re-armed after the sandbox reset) died at cycle 438/1440 at
  01:09 UTC — `sharenet_loopback` panicked at `sharenet_loopback.rs:234`
  (`projection store: StoreAlreadyExists`) and the harness failed fast.
- **Root cause** (Tech Lead forensics, verified in code and on disk): the
  participant's per-run projection store is a REGULAR FILE, and
  `DurableProjectionStore::create` fail-closed refuses ANY existing path
  (correct product law — no silent data loss). The harness's scratch
  cleanup called `remove_dir_all` — ENOTDIR on a file, error swallowed:
  a SILENT NO-OP. 438 stale `b-<pid>.store` files had accumulated in the
  shared recovery dir (exactly one per cycle); with pid_max 32768 and
  ~100 PIDs consumed per cycle, the PID space wraps every ~5.5 h, and
  cycle 438's participant drew the recycled PID 21255 (first used at
  cycle ~19). The Wave-23 record's "create refuses an existing dir"
  note shows the cleanup intent existed but used the wrong syscall —
  a latent defect in the R10-003 deliverable that ONLY a sustained
  wall-clock run could catch (the accelerated profile is 8 cycles,
  well inside the first PID-space wrap). The 24 h run did exactly what
  it exists to do.
- **Dispatch**: worker `sharenet-w2-r1006` (the operator's standing rule
  — workers implement). Contract: fix the harness cleanup to remove BOTH
  occupant forms; NO changes to connectivity (the store's law stands);
  regression test that FAILS on current code; five adversarial
  minimums; accelerated endurance profile with a LOCAL UDP echo.
  Delivery via the R2-002 pattern (worker sandboxes carry no
  credentials): artifacts in the sandbox `download/r10-006/` (work.diff
  731 lines, commits.txt, status.txt, worklog.md), harvested through
  the workspace files API — which since R2-002 no longer requires the
  workspace_id (chatId alone resolves the chat's active workspace).
- **Worker delivery**: branch `work/r10-006-endurance-store-collision`,
  commits 8e5c26d (red tests) + 65b0b58 (fix), 4 files, +678/−4:
  `src/scratch.rs` (NEW `clear_scratch_path`: remove_file then
  remove_dir_all, errors non-fatal by law), `src/lib.rs` (module + doc
  entry), `src/bin/sharenet_loopback.rs` (uses the helper; call-site
  comment corrected), `tests/store_collision.rs` (623 lines).
- **Tech Lead independent verification** (this sandbox, never trusted):
  - RED reproduced on pristine main + the tests only: the regression
    case (`recycled_pid_stale_store_file_completes_the_run`) failed with
    the EXACT production panic (exit 101, Phase 4 after
    LOOPBACK_ATTEMPT 1, no LOOPBACK_DONE); the garbage-file case
    failed; the directory case PASSED (the defect's file/dir
    asymmetry); the store-law case PASSED — matching the worker's red
    matrix exactly.
  - `cargo test -p sharenet-transport-linux` at HEAD: **78 passed / 0
    failed** (73 baseline + 5 new), including
    `accelerated_endurance_profile_holds_every_law` (8 cycles / 8
    kills / 8 restarts).
  - `store_collision` 5/5 across three runs; zero warnings on the new
    code.
  - Adversarial substance read: real multiprocess bridges (two gateway
    processes + the real participant binary); the occupant placed at
    the child's REAL per-run path between spawn and the induced gateway
    death — strictly before the Phase-4 store preparation, no race;
    case 1 reuses run 1's REAL stale store bytes (load-verified) as
    run 2's collision; case 5 bypasses the cleanup entirely and pins
    the store's refuse-to-clobber law (file/plain/dir, typed).
- **Integration**: applied cleanly at 81c70d2, committed with full
  provenance, governance PASS, merged to main, pushed.
- **Honest note on run 1**: the first 24 h certificate attempt is DEAD
  at 438/1440 by this now-fixed harness defect (all laws green at
  death: identity stable across 219 restarts, RSS ~4.5 MB bounded,
  ordinals continuous). Run 2 (re-armed 02:41 UTC the same day, same
  state dir — journals continue, ordinals carried across the harness
  restart) is expected to certify; the sweep also recorded that
  run 1's failure was NOT a product failure.

## Endurance re-arm record (2026-09-17, orchestrator infrastructure)

- `/home/z/endurance/sweeper.sh`: every 5 min deletes `b-*.store` files
  older than 30 min from the shared recovery dir — a stale file can
  only collide after ≥1 full PID-space wrap (~5.5 h at current churn),
  so the 30-minute rule is >10× margin. This bridges run 2 only; the
  repo fix (R10-006) is the durable answer.
- Run 2 launched via `launch_detached.py` (the plain nohup pattern dies
  at the tool-call process-group boundary — the setsid pattern is the
  law for long-lived orchestrator processes), same state dir: identity
  continuity verified across the harness restart (same node ids, same
  participant identity, journal ordinals continued 219→220+).

## R10-003 certificate record (2026-09-18) — the 24h wall-clock endurance is CERTIFIED

- **The run**: `sharenet_endurance run --state-dir state-24h --uplink 127.0.0.1:35353
  --sessions 1440 --spacing-ms 60000` (run 2, same state dir as run 1), launched
  2026-09-17 02:41 UTC via the setsid law, completed 2026-09-18 03:28 UTC —
  **24 h 47 m continuous wall-clock** (the 60 s × 1440 spacing floor is 24 h;
  per-cycle overhead ~2 s makes 24 h 47 m the honest span).
- **The DONE line (harness verdict after its own law enforcement)**:
  `ENDURANCE_DONE cycles=1440 kills=1440 restarts=1440 life-a=939 life-b=940
  rss-a-max=5792 rss-b-max=6272 rss-a-growth=1420 rss-b-growth=1768 status=ok`
- **Independent Tech Lead re-derivation (never trusted; from the raw log)**:
  cycles numbered 0..1439 = 1440 contiguous, 1440 sessions completed,
  1440 restarts (ordinals A=720 / B=720); **zero panics, zero ENDURANCE_ERROR**
  in the run-2 window; exactly 2 distinct node ids
  (`c64bd8c5…` A, `0df5399d…` B) and 1 identity (`f2ee4e21…`) across all
  1440 cycles; RSS growth re-derived to the digit (A: 5792−4372=1420,
  B: 6272−4504=1768 — matches the DONE line exactly) against the 64 MB
  leak bound = 37–46× margin.
- **The durability evidence the run 1 → run 2 boundary provides**: run 1 died
  mid-journal at SESSION B 220 (the R10-006 harness defect); run 2's first
  session is SESSION B **221** — the journal ordinals continued across a REAL
  harness death with the same node ids and identity. The certificate run
  itself began from the recovered state and completed 1440 cycles on top of it.
- **Unattended-monitoring record (the 20 h gap no human watched)**: a
  self-healing watchdog (never touches the harness; auto-revives the sweeper
  PID-collision defense and the udp uplink — revive path live-tested at
  15 s) held the run with zero alerts, hourly checkpoints all panics=0;
  evidence file: `docs/tech-lead/endurance-24h-certificate-evidence.txt`
  (summary + log tail + ps + store population + sweeper state at capture).
- **Closure**: the R10-003-wall-clock honest gap is CLOSED — removed from
  `spec/architect/current-state.yaml` honest_gaps (4 remain, all
  operator-hardware legs with recorded runbooks). Run 1's death remains
  honestly recorded above (harness defect, fixed by R10-006 at 660e819,
  never a product failure).

## R10-003 certificate precision amendment (2026-09-18, second independent re-verification)

- A post-commit independent re-derivation (session resumed after context
  exhaustion; raw log only, neither the committed record nor the watchdog
  evidence trusted) reproduced **every digit** of the record above: 1440
  contiguous CYCLE DONE lines (cycles numbered 0..1439), 1440 RESTART lines,
  0 panics / 0 ENDURANCE_ERROR inside the window, 2 node ids + 1 identity
  throughout, SESSION ordinals A 220→939 / B 221→940, RSS first/max
  A 4372→5792 / B 4504→6272 (growth 1420 / 1768 KB; the stricter max−min
  reading is 2652 / 3120 KB — both 2–5 % of the 64 MB bound).
- **Window definition made explicit**: the certified run-2 window begins at
  the log's LAST `ENDURANCE_BEGIN` (02:41 UTC launch, pid 27171). A first
  02:40 re-arm attempt immediately prior completed exactly one cycle
  (SESSION B 220 — the journal continuation step) and exited silently with
  no panic line; its single cycle is not part of the 1440. The re-arm
  record's "ordinals continued 219→220+" above already reflects this;
  this amendment names the aborted attempt explicitly so the window
  boundary is reproducible by any future auditor.
- **Watchdog display artifact (cosmetic)**: the captured evidence summary
  reads `cycles_done: 1439` because the watchdog's window heuristic
  ("after last CYCLE 1 BEGIN") excluded the final harness's CYCLE 0.
  The DONE-line detection and the operator notification were correct;
  only the internal progress counter was off by one. Raw-log truth: 1440.
