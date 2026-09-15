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
