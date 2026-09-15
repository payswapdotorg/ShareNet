/** ShareNet route-to-circuit binding — TypeScript conformance leg (R4-002). */

import { createHash } from "node:crypto";
import type { Value } from "./cbor.ts";
import { encode } from "./cbor.ts";
import { nodeIdentityWire } from "./identity.ts";

const int = (n: bigint): Value => ({ t: "int", v: n });
const txt = (s: string): Value => ({ t: "text", v: s });
const bytes = (b: Uint8Array): Value => ({ t: "bytes", v: b });

function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

/** CircuitSetup wire: {1: scheme, 2: commitment, 3: nonce, 4: initiator, 5: issued, 6: expires}. */
export function buildSetup(opts: {
  commitmentWire: Uint8Array;
  setupNonce: Uint8Array;
  publicKey: Uint8Array;
  createdAtUnix: bigint;
  issuedAtUnix: bigint;
  validitySecs: bigint;
}): Uint8Array {
  return encode({
    t: "map",
    v: [
      [int(1n), int(1n)],
      [int(2n), bytes(opts.commitmentWire)],
      [int(3n), bytes(opts.setupNonce)],
      [int(4n), nodeIdentityWire(opts.publicKey, opts.createdAtUnix, null)],
      [int(5n), int(opts.issuedAtUnix)],
      [int(6n), int(opts.issuedAtUnix + opts.validitySecs)],
    ],
  });
}

/** CircuitSetupAck wire: {1: scheme, 2: circuit_id, 3: setup_digest, 4: accepting, 5: position, 6: accepted_at, 7: expires_at}. */
export function buildAck(opts: {
  circuitId: Uint8Array;
  setupEnvelope: Uint8Array;
  publicKey: Uint8Array;
  createdAtUnix: bigint;
  position: bigint;
  acceptedAtUnix: bigint;
  validitySecs: bigint;
}): Uint8Array {
  return encode({
    t: "map",
    v: [
      [int(1n), int(1n)],
      [int(2n), bytes(opts.circuitId)],
      [int(3n), bytes(sha256(opts.setupEnvelope))],
      [int(4n), nodeIdentityWire(opts.publicKey, opts.createdAtUnix, null)],
      [int(5n), int(opts.position)],
      [int(6n), int(opts.acceptedAtUnix)],
      [int(7n), int(opts.acceptedAtUnix + opts.validitySecs)],
    ],
  });
}

/** CircuitFrame wire: {1: scheme, 2: circuit_id, 3: direction, 4: seq, 5: payload}. */
export function buildFrame(opts: {
  circuitId: Uint8Array;
  direction: bigint;
  seq: bigint;
  payload: Uint8Array;
}): Uint8Array {
  return encode({
    t: "map",
    v: [
      [int(1n), int(1n)],
      [int(2n), bytes(opts.circuitId)],
      [int(3n), int(opts.direction)],
      [int(4n), int(opts.seq)],
      [int(5n), bytes(opts.payload)],
    ],
  });
}

/** CircuitDestroy wire: {1: scheme, 2: circuit_id, 3: sender, 4: reason, 5: destroyed_at}. */
export function buildDestroy(opts: {
  circuitId: Uint8Array;
  publicKey: Uint8Array;
  createdAtUnix: bigint;
  reason: string;
  destroyedAtUnix: bigint;
}): Uint8Array {
  return encode({
    t: "map",
    v: [
      [int(1n), int(1n)],
      [int(2n), bytes(opts.circuitId)],
      [int(3n), nodeIdentityWire(opts.publicKey, opts.createdAtUnix, null)],
      [int(4n), txt(opts.reason)],
      [int(5n), int(opts.destroyedAtUnix)],
    ],
  });
}

/** circuit_id = SHA-256("sharenet-circuit-id-v1" || route_id || setup_nonce). */
export function deriveCircuitId(routeId: Uint8Array, setupNonce: Uint8Array): Uint8Array {
  return sha256(
    new TextEncoder().encode("sharenet-circuit-id-v1"),
    routeId,
    setupNonce,
  );
}

/** The ack binding digest: SHA-256 of the signed setup envelope bytes. */
export function setupDigest(setupEnvelope: Uint8Array): Uint8Array {
  return sha256(setupEnvelope);
}
