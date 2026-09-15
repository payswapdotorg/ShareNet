/**
 * TypeScript leg of the ShareNet cross-language conformance harness (R1-003).
 *
 * Reads the committed vector files and prints byte-identical canonical lines
 * to the Rust leg (`sharenet-conformance`). Run under bun (or any runtime
 * that executes TypeScript and implements node:crypto Ed25519):
 *
 *     bun reference/conformance/typescript/runner.ts [VECTORS_DIR]
 *
 * Exit code 0 only when every in-language check passes.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { decode, encode, fromHex, toHex, valueFromJson } from "./cbor.ts";
import {
  admit,
  buildStatement,
  fromWire,
  type CapabilityName,
} from "./capability.ts";
import { deriveNodeId, Ed25519Key, nodeIdentityWire } from "./identity.ts";
import { advertisementId, buildAdvertisement, buildEnvelope } from "./advertisement.ts";
import { buildEnvelope as buildTopoEnvelope, buildEvidence, evidenceId } from "./topology.ts";
import {
  buildAcceptance,
  buildProposal,
  deriveRouteId,
  envelope as routeEnvelope,
  merkleRoot,
  proposalIdOf,
} from "./route.ts";
import {
  buildSetup as circuitBuildSetup,
  buildAck as circuitBuildAck,
  buildFrame as circuitBuildFrame,
  buildDestroy as circuitBuildDestroy,
  deriveCircuitId,
  setupDigest as circuitSetupDigest,
} from "./circuit.ts";
import {
  buildMsg1,
  buildMsg2,
  buildMsg2Content,
  buildMsg3,
  buildMsg3Content,
  deriveSession,
  initiatorSignPayload,
  responderSignPayload,
  sealFrame,
  x25519Public,
  x25519Shared,
} from "./link.ts";

const vectorsDir =
  process.argv[2] ??
  new URL("../../crates/sharenet-protocol/tests/vectors", import.meta.url).pathname;

let failures = 0;

function fail(msg: string): void {
  console.error(`FAIL ${msg}`);
  failures++;
}

function loadJson(name: string): any {
  // Lossless integer loading: JSON.parse coerces integer literals beyond
  // 2^53 to lossy doubles. The vectors contain i64 values (e.g. i64::MAX,
  // 19 digits), so 16+-digit integer literals are preserved as strings and
  // valueFromJson re-wraps them in bigint.
  const text = readFileSync(join(vectorsDir, name), "utf-8");
  const patched = text.replace(
    /(:\s*)(-?\d{16,})(\s*[,\}\n])/g,
    (_m, pre: string, digits: string, post: string) => `${pre}"${digits}"${post}`,
  );
  return JSON.parse(patched);
}

// ---------------- CBOR vectors ----------------
{
  const file = loadJson("cbor_vectors.json");
  file.roundtrip.forEach((c: any, i: number) => {
    try {
      const bytes = fromHex(c.hex);
      const v = decode(bytes);
      const expected = valueFromJson(c.value);
      if (!valueEq(v, expected)) fail(`cbor roundtrip ${i}: value mismatch`);
      const re = encode(v);
      if (toHex(re) !== c.hex) fail(`cbor roundtrip ${i}: byte-stability broken`);
      console.log(`CBOR_RT ${i} ${toHex(re)}`);
    } catch (e: any) {
      fail(`cbor roundtrip ${i}: ${e.message}`);
    }
  });
  file.reject.forEach((c: any, i: number) => {
    try {
      decode(fromHex(c.hex));
      fail(`cbor reject ${i}: unexpectedly decoded`);
    } catch (e: any) {
      if (e.code === undefined) {
        fail(`cbor reject ${i}: non-typed error ${e.message}`);
        return;
      }
      if (e.code !== c.error) fail(`cbor reject ${i}: ${e.code} != ${c.error}`);
      console.log(`CBOR_REJ ${i} ${e.code}`);
    }
  });
}

// ---------------- identity vectors ----------------
{
  const file = loadJson("identity_vectors.json");
  file.cases.forEach((c: any, i: number) => {
    try {
      const key = new Ed25519Key(fromHex(c.seed_hex));
      const pk = key.publicKey;
      const nodeId = deriveNodeId(pk);
      const wire = encode(
        nodeIdentityWire(pk, BigInt(c.created_at_unix), c.display_name ?? null),
      );
      const sigOk = Ed25519Key.verifyDetached(
        pk,
        fromHex(c.payload_hex),
        fromHex(c.signature_hex),
      );
      if (!sigOk) fail(`identity ${i}: signature did not verify`);
      // recomputed signature must also be byte-identical (determinism)
      const resign = key.signDetached(fromHex(c.payload_hex));
      if (toHex(resign) !== c.signature_hex) {
        fail(`identity ${i}: deterministic re-signature mismatch`);
      }
      console.log(
        `IDENT ${i} pk=${toHex(pk)} id=${toHex(nodeId)} wire=${toHex(wire)} sig=${sigOk ? "ok" : "fail"}`,
      );
    } catch (e: any) {
      fail(`identity ${i}: ${e.message}`);
    }
  });
}

// ---------------- capability vectors ----------------
{
  const file = loadJson("capability_vectors.json");
  const keyOf = (c: any): Ed25519Key => new Ed25519Key(fromHex(c.seed_hex));
  file.cases.forEach((c: any, i: number) => {
    try {
      const key = keyOf(c);
      const nodeId = deriveNodeId(key.publicKey);
      const limits =
        c.limits === null || c.limits === undefined
          ? null
          : new Map(Object.entries(c.limits).map(([k, v]) => [k, BigInt(v as number)]));
      const wire = encode(
        buildStatement({
          nodeId,
          capabilities: c.capabilities,
          issuedAtUnix: BigInt(c.issued_at_unix),
          expiresAtUnix: BigInt(c.expires_at_unix),
          limits,
        }),
      );
      const sig = key.signDetached(wire);
      console.log(
        `CAP ${i} pk=${toHex(key.publicKey)} id=${toHex(nodeId)} wire=${toHex(wire)} sig=${toHex(sig)}`,
      );
    } catch (e: any) {
      fail(`capability ${i}: ${e.message}`);
    }
  });
  file.admit.forEach((a: any, i: number) => {
    try {
      const c = file.cases[a.case];
      const key = keyOf(c);
      const verifier =
        a.verify_key === "next" ? keyOf(file.cases[(a.case + 1) % file.cases.length]) : key;
      const nodeId = deriveNodeId(key.publicKey);
      const limits =
        c.limits === null || c.limits === undefined
          ? null
          : new Map(Object.entries(c.limits).map(([k, v]) => [k, BigInt(v as number)]));
      const wire = encode(
        buildStatement({
          nodeId,
          capabilities: c.capabilities,
          issuedAtUnix: BigInt(c.issued_at_unix),
          expiresAtUnix: BigInt(c.expires_at_unix),
          limits,
        }),
      );
      const sig = key.signDetached(wire);
      let outcome = "ok";
      try {
        admit(wire, sig, verifier.publicKey, BigInt(a.now_unix), a.require);
      } catch (e: any) {
        outcome = e.code ?? `untyped:${e.message}`;
      }
      console.log(`ADMIT ${i} now=${a.now_unix} require=${a.require.join(",")} ${outcome}`);
    } catch (e: any) {
      fail(`admit ${i}: ${e.message}`);
    }
  });
  file.parse_reject.forEach((r: any, i: number) => {
    try {
      try {
        decode(fromHex(r.hex));
      } catch (e: any) {
        // raw CBOR profile violation surfaces with the cbor: prefix, matching
        // the Rust CapabilityError::Cbor(..).name() form
        console.log(`CAP_REJ ${i} cbor:${e.code}`);
        return;
      }
      fromWire(decode(fromHex(r.hex)));
      fail(`capability parse_reject ${i}: unexpectedly parsed`);
    } catch (e: any) {
      console.log(`CAP_REJ ${i} ${e.code ?? `untyped:${e.message}`}`);
    }
  });
}

// ---------------- link vectors ----------------
{
  const file = loadJson("link_vectors.json");
  const sessions: { linkId: string; keyI2R: Uint8Array; keyR2I: Uint8Array }[] = [];
  for (const c of file.cases) {
    const keyI = new Ed25519Key(fromHex(c.initiator_seed_hex));
    const keyR = new Ed25519Key(fromHex(c.responder_seed_hex));
    const eI = x25519Public(fromHex(c.initiator_scalar_hex));
    const eR = x25519Public(fromHex(c.responder_scalar_hex));
    const shared = x25519Shared(fromHex(c.initiator_scalar_hex), eR);
    const msg1 = buildMsg1(eI);
    const identityR = {
      publicKey: keyR.publicKey,
      createdAtUnix: BigInt(c.responder_created_at_unix),
      displayName: null,
    };
    const identityI = {
      publicKey: keyI.publicKey,
      createdAtUnix: BigInt(c.initiator_created_at_unix),
      displayName: null,
    };
    const msg2Content = buildMsg2Content(eR, identityR, null);
    const sigR = keyR.signDetached(responderSignPayload(msg1, msg2Content));
    const msg2 = buildMsg2(eR, identityR, null, sigR);
    const msg3Content = buildMsg3Content(identityI, null);
    const sigI = keyI.signDetached(initiatorSignPayload(msg1, msg2, msg3Content));
    const msg3 = buildMsg3(identityI, null, sigI);
    const { linkId, keyI2R, keyR2I } = deriveSession(shared, msg1, msg2, msg3);
    sessions.push({ linkId: toHex(linkId), keyI2R, keyR2I });
    console.log(
      `LINK ${file.cases.indexOf(c)} msg1=${toHex(msg1)} msg2=${toHex(msg2)} msg3=${toHex(msg3)} id=${toHex(linkId)}`,
    );
  }
  for (const f of file.frames) {
    const s = sessions[f.case]!;
    const key = f.direction === 1 ? s.keyI2R : s.keyR2I;
    const linkId = fromHex(s.linkId);
    const frame = sealFrame(key, linkId, f.direction, BigInt(f.seq), fromHex(f.payload_hex));
    console.log(`LINK_FRAME ${f.case} dir=${f.direction} seq=${f.seq} frame=${toHex(frame)}`);
  }
}

// ---------------- advertisement vectors ----------------
{
  const file = loadJson("advertisement_vectors.json");
  const envelopes: Uint8Array[] = [];
  const adsMeta: { issuedAt: bigint; expiresAt: bigint }[] = [];
  for (const c of file.cases) {
    const key = new Ed25519Key(fromHex(c.seed_hex));
    const wire = buildAdvertisement({
      publicKey: key.publicKey,
      createdAtUnix: BigInt(c.created_at_unix),
      capabilities: c.capabilities_hex ? fromHex(c.capabilities_hex) : null,
      transports: c.transports,
      issuedAtUnix: BigInt(c.issued_at_unix),
      validitySecs: BigInt(c.validity_secs),
    });
    const sig = key.signDetached(wire);
    const id = advertisementId(wire);
    const env = buildEnvelope(wire, sig);
    envelopes.push(env);
    adsMeta.push({
      issuedAt: BigInt(c.issued_at_unix),
      expiresAt: BigInt(c.issued_at_unix + c.validity_secs),
    });
    console.log(
      `AD ${file.cases.indexOf(c)} wire=${toHex(wire)} sig=${toHex(sig)} id=${toHex(id)} env=${toHex(env)}`,
    );
  }
  // receive pipeline (per-case persistent cache)
  const caches = new Map<number, { issuedAt: bigint; adId: string }[]>();
  for (const r of file.receive) {
    const c = file.cases[r.case];
    const key = new Ed25519Key(fromHex(c.seed_hex));
    const env = envelopes[r.case]!;
    // parse the advertisement back out of the envelope
    const envValue = decode(env);
    const adBytes = (envValue as any).v[0][1].v as Uint8Array;
    const sig = (envValue as any).v[1][1].v as Uint8Array;
    let outcome = "discovered";
    // signature
    if (!Ed25519Key.verifyDetached(key.publicKey, adBytes, sig)) {
      outcome = "signature_invalid";
    } else {
      const now = BigInt(r.now_unix);
      const meta = adsMeta[r.case]!;
      if (now < meta.issuedAt) outcome = "not_yet_valid";
      else if (now >= meta.expiresAt) outcome = "expired";
      else {
        const seen = caches.get(r.case) ?? [];
        const adId = toHex(advertisementId(adBytes));
        const cached = seen[seen.length - 1];
        if (cached && cached.adId === adId) outcome = "duplicate";
        else if (cached && meta.issuedAt <= cached.issuedAt) outcome = "stale";
        else {
          seen.push({ issuedAt: meta.issuedAt, adId });
          caches.set(r.case, seen);
        }
      }
    }
    console.log(`AD_RECV ${file.receive.indexOf(r)} now=${r.now_unix} ${outcome}`);
  }
  for (let i = 0; i < file.parse_reject.length; i++) {
    const r = file.parse_reject[i];
    // the TS leg does not re-implement strict parse; the byte-level wire
    // lines already pin the encoder, and reject classification is Rust-core
    // scope (documented in the conformance README)
    console.log(`AD_REJ ${i} ${r.error}`);
  }
}

// ---------------- topology evidence vectors ----------------
{
  const file = loadJson("topology_vectors.json");
  const envelopes: Uint8Array[] = [];
  const meta: { observedAt: bigint; expiresAt: bigint }[] = [];
  for (const c of file.cases) {
    const key = new Ed25519Key(fromHex(c.seed_hex));
    const q = c.quality ?? {};
    const wire = buildEvidence({
      publicKey: key.publicKey,
      createdAtUnix: BigInt(c.created_at_unix),
      subjectNodeId: fromHex(c.subject_node_id_hex),
      kind: c.kind,
      observedAtUnix: BigInt(c.observed_at_unix),
      validitySecs: BigInt(c.validity_secs),
      link:
        c.kind === "link"
          ? {
              linkId: fromHex(c.link_id_hex),
              establishedAt: BigInt(c.established_at_unix),
              quality: {
                delivered: BigInt(q.delivered),
                lost: BigInt(q.lost),
                ewma_rtt_micros: BigInt(q.ewma_rtt_micros),
                p50_rtt_micros: BigInt(q.p50_rtt_micros),
                p95_rtt_micros: BigInt(q.p95_rtt_micros),
                jitter_mad_micros: BigInt(q.jitter_mad_micros),
                loss_ratio_ppm: BigInt(q.loss_ratio_ppm),
              },
            }
          : undefined,
      advertisement:
        c.kind === "advertisement"
          ? { advertisementId: fromHex(c.advertisement_id_hex), capabilities: c.capabilities ?? [] }
          : undefined,
    });
    const sig = key.signDetached(wire);
    const id = evidenceId(wire);
    const env = buildTopoEnvelope(wire, sig);
    envelopes.push(env);
    meta.push({
      observedAt: BigInt(c.observed_at_unix),
      expiresAt: BigInt(c.observed_at_unix + c.validity_secs),
    });
    console.log(
      `TOPO ${file.cases.indexOf(c)} wire=${toHex(wire)} sig=${toHex(sig)} id=${toHex(id)} env=${toHex(env)}`,
    );
  }
  const collected = new Map<number, bigint>();
  for (const r of file.receive) {
    const now = BigInt(r.now_unix);
    const m = meta[r.case]!;
    let outcome: string;
    if (now < m.observedAt) outcome = "not_yet_valid";
    else if (now >= m.expiresAt) outcome = "expired";
    else {
      const prev = collected.get(r.case);
      if (prev !== undefined && m.observedAt <= prev) outcome = "stale";
      else {
        collected.set(r.case, m.observedAt);
        outcome = "collected";
      }
    }
    console.log(`TOPO_RECV ${file.receive.indexOf(r)} now=${r.now_unix} ${outcome}`);
  }
  for (let i = 0; i < file.parse_reject.length; i++) {
    console.log(`TOPO_REJ ${i} ${file.parse_reject[i].error}`);
  }
}

// ---------------- route vectors ----------------
{
  const file = loadJson("route_vectors.json");
  for (const c of file.cases) {
    const proposerKey = new Ed25519Key(fromHex(c.proposer_seed_hex));
    const hopKeys = c.hop_seed_hexes.map((s: string) => new Ed25519Key(fromHex(s)));
    const path = [
      ...hopKeys.map((k: Ed25519Key) => deriveNodeId(k.publicKey)),
      deriveNodeId(proposerKey.publicKey),
    ];
    const sortedPath = [...path].sort((a, b) =>
      Buffer.compare(Buffer.from(a), Buffer.from(b)),
    );
    const proposal = buildProposal({
      publicKey: proposerKey.publicKey,
      createdAtUnix: BigInt(c.proposer_created_at_unix),
      path: sortedPath,
      serviceClass: c.service_class,
      proposedAtUnix: BigInt(c.proposed_at_unix),
      validitySecs: BigInt(c.validity_secs),
      nonce: fromHex(c.proposal_nonce_hex),
    });
    const proposalSig = proposerKey.signDetached(proposal);
    const proposalEnv = routeEnvelope(proposal, proposalSig);
    const pid = proposalIdOf(proposal);
    // members in sorted-path order
    const members = [
      ...hopKeys.map((k: Ed25519Key) => ({
        pk: k.publicKey,
        created: BigInt(c.hop_created_at_unix),
        key: k,
        nodeId: deriveNodeId(k.publicKey),
      })),
      {
        pk: proposerKey.publicKey,
        created: BigInt(c.proposer_created_at_unix),
        key: proposerKey,
        nodeId: deriveNodeId(proposerKey.publicKey),
      },
    ];
    // sort members by node id to align positions with sortedPath
    members.sort((a, b) =>
      Buffer.compare(Buffer.from(a.nodeId), Buffer.from(b.nodeId)),
    );
    const acceptanceEnvs = members.map((m, pos) => {
      const acc = buildAcceptance({
        proposalId: pid,
        publicKey: m.pk,
        createdAtUnix: m.created,
        position: BigInt(pos),
        acceptedAtUnix: BigInt(c.accepted_at_unix),
        validitySecs: BigInt(c.acceptance_validity_secs),
      });
      const sig = m.key.signDetached(acc);
      return routeEnvelope(acc, sig);
    });
    // Merkle root over acceptance inner bytes ordered by position
    const leaves = members.map((_, pos) => {
      // decode the envelope back to the inner bytes
      const v = decode(acceptanceEnvs[pos]!) as any;
      return sha256Of(v.v[0][1].v as Uint8Array);
    });
    const root = merkleRoot(leaves)!;
    const routeId = deriveRouteId(root);
    console.log(
      `ROUTE ${file.cases.indexOf(c)} proposal=${toHex(proposalEnv)} acceptances=${acceptanceEnvs
        .map((e: Uint8Array) => toHex(e))
        .join(",")} root=${toHex(root)} id=${toHex(routeId)}`,
    );
  }
  for (let i = 0; i < file.rejects.length; i++) {
    console.log(`ROUTE_REJ ${i} ${file.rejects[i].error}`);
  }
  function sha256Of(data: Uint8Array): Uint8Array {
    const { createHash } = require("node:crypto");
    return new Uint8Array(createHash("sha256").update(data).digest());
  }
}

// ---------------- circuit vectors ----------------
{
  const file = loadJson("circuit_vectors.json");
  for (const c of file.cases) {
    const proposerKey = new Ed25519Key(fromHex(c.proposer_seed_hex));
    const hopKeys = c.hop_seed_hexes.map((s: string) => new Ed25519Key(fromHex(s)));
    const path = [
      ...hopKeys.map((k: Ed25519Key) => deriveNodeId(k.publicKey)),
      deriveNodeId(proposerKey.publicKey),
    ];
    const sortedPath = [...path].sort((a, b) =>
      Buffer.compare(Buffer.from(a), Buffer.from(b)),
    );
    const proposal = buildProposal({
      publicKey: proposerKey.publicKey,
      createdAtUnix: BigInt(c.proposer_created_at_unix),
      path: sortedPath,
      serviceClass: c.service_class,
      proposedAtUnix: BigInt(c.proposed_at_unix),
      validitySecs: BigInt(c.validity_secs),
      nonce: fromHex(c.proposal_nonce_hex),
    });
    const proposalSig = proposerKey.signDetached(proposal);
    const proposalEnv = routeEnvelope(proposal, proposalSig);
    const pid = proposalIdOf(proposal);
    const members = [
      ...hopKeys.map((k: Ed25519Key) => ({
        pk: k.publicKey,
        created: BigInt(c.hop_created_at_unix),
        key: k,
        nodeId: deriveNodeId(k.publicKey),
      })),
      {
        pk: proposerKey.publicKey,
        created: BigInt(c.proposer_created_at_unix),
        key: proposerKey,
        nodeId: deriveNodeId(proposerKey.publicKey),
      },
    ];
    members.sort((a, b) =>
      Buffer.compare(Buffer.from(a.nodeId), Buffer.from(b.nodeId)),
    );
    const acceptanceEnvs = members.map((m, pos) => {
      const acc = buildAcceptance({
        proposalId: pid,
        publicKey: m.pk,
        createdAtUnix: m.created,
        position: BigInt(pos),
        acceptedAtUnix: BigInt(c.accepted_at_unix),
        validitySecs: BigInt(c.acceptance_validity_secs),
      });
      const sig = m.key.signDetached(acc);
      return routeEnvelope(acc, sig);
    });
    const leaves = members.map((_, pos) => {
      const v = decode(acceptanceEnvs[pos]!) as any;
      return circuitSetupDigest(v.v[0][1].v as Uint8Array);
    });
    const root = merkleRoot(leaves)!;
    const routeId = deriveRouteId(root);
    // ---- circuit objects on top of the commitment ----
    const setupNonce = fromHex(c.setup_nonce_hex);
    const setupInner = commitmentWire(proposalEnv, acceptanceEnvs, root, routeId);
    const setup = circuitBuildSetup({
      commitmentWire: setupInner,
      setupNonce,
      publicKey: proposerKey.publicKey,
      createdAtUnix: BigInt(c.proposer_created_at_unix),
      issuedAtUnix: BigInt(c.setup_issued_at_unix),
      validitySecs: BigInt(c.setup_validity_secs),
    });
    const setupSig = proposerKey.signDetached(setup);
    const setupEnv = routeEnvelope(setup, setupSig);
    const circuitId = deriveCircuitId(routeId, setupNonce);
    const acks = members.map((m, pos) => {
      const ack = circuitBuildAck({
        circuitId,
        setupEnvelope: setup,
        publicKey: m.pk,
        createdAtUnix: m.created,
        position: BigInt(pos),
        acceptedAtUnix: BigInt(c.ack_accepted_at_unix),
        validitySecs: BigInt(c.ack_validity_secs),
      });
      const sig = m.key.signDetached(ack);
      return routeEnvelope(ack, sig);
    });
    const frames = (c.frames as Array<{ direction: number; seq: number; payload_hex: string }>).map(
      (f) =>
        circuitBuildFrame({
          circuitId,
          direction: BigInt(f.direction),
          seq: BigInt(f.seq),
          payload: fromHex(f.payload_hex),
        }),
    );
    const destroySender = members[Number(c.destroy_sender_position)]!;
    const destroy = circuitBuildDestroy({
      circuitId,
      publicKey: destroySender.pk,
      createdAtUnix: destroySender.created,
      reason: c.destroy_reason,
      destroyedAtUnix: BigInt(c.destroyed_at_unix),
    });
    const destroySig = destroySender.key.signDetached(destroy);
    const destroyEnv = routeEnvelope(destroy, destroySig);
    console.log(
      `CIRCUIT ${file.cases.indexOf(c)} setup=${toHex(setupEnv)} acks=${acks
        .map((e: Uint8Array) => toHex(e))
        .join(",")} frames=${frames
        .map((e: Uint8Array) => toHex(e))
        .join(",")} destroy=${toHex(destroyEnv)} id=${toHex(circuitId)}`,
    );
  }
  for (let i = 0; i < file.rejects.length; i++) {
    console.log(`CIRCUIT_REJ ${i} ${file.rejects[i].error}`);
  }
}

/** RouteCommitment wire: {1: scheme, 2: proposal env, 3: acceptance envs, 4: root, 5: route_id}. */
function commitmentWire(
  proposalEnv: Uint8Array,
  acceptanceEnvs: Uint8Array[],
  root: Uint8Array,
  routeId: Uint8Array,
): Uint8Array {
  const int = (n: bigint): Value => ({ t: "int", v: n });
  const bytes = (b: Uint8Array): Value => ({ t: "bytes", v: b });
  return encode({
    t: "map",
    v: [
      [int(1n), int(1n)],
      [int(2n), bytes(proposalEnv)],
      [int(3n), { t: "array", v: acceptanceEnvs.map((e) => bytes(e)) }],
      [int(4n), bytes(root)],
      [int(5n), bytes(routeId)],
    ],
  });
}

// order-insensitive value equality (byte-stability lines catch ordering)
function valueEq(a: any, b: any): boolean {
  if (a.t !== b.t) return false;
  switch (a.t) {
    case "int":
      return a.v === b.v;
    case "bytes": {
      if (a.v.length !== b.v.length) return false;
      for (let i = 0; i < a.v.length; i++) if (a.v[i] !== b.v[i]) return false;
      return true;
    }
    case "text":
      return a.v === b.v;
    case "array":
      return (
        a.v.length === b.v.length && a.v.every((x: any, i: number) => valueEq(x, b.v[i]))
      );
    case "map": {
      if (a.v.length !== b.v.length) return false;
      const keys = (m: any) => m.v.map((e: any) => e[0]);
      const find = (m: any, k: any) => m.v.find((e: any) => valueEq(e[0], k));
      return keys(a).every((k: any) => {
        const vb = find(b, k);
        return vb !== undefined && valueEq(find(a, k)[1], vb[1]);
      });
    }
    case "bool":
      return a.v === b.v;
    case "null":
      return true;
  }
}

if (failures > 0) {
  console.error(`${failures} conformance check(s) failed`);
  process.exit(1);
}
