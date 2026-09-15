/** ShareNet route commitment — TypeScript conformance leg (R3-004). */

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

export function buildProposal(opts: {
  publicKey: Uint8Array;
  createdAtUnix: bigint;
  path: Uint8Array[];
  serviceClass: string;
  proposedAtUnix: bigint;
  validitySecs: bigint;
  nonce: Uint8Array;
}): Uint8Array {
  const sorted = [...opts.path].sort((a, b) =>
    Buffer.compare(Buffer.from(a), Buffer.from(b)),
  );
  return encode({
    t: "map",
    v: [
      [int(1n), int(1n)],
      [int(2n), nodeIdentityWire(opts.publicKey, opts.createdAtUnix, null)],
      [int(3n), { t: "array", v: sorted.map((p) => bytes(p)) }],
      [int(4n), txt(opts.serviceClass)],
      [int(5n), int(opts.proposedAtUnix)],
      [int(6n), int(opts.proposedAtUnix + opts.validitySecs)],
      [int(7n), bytes(opts.nonce)],
    ],
  });
}

export function buildAcceptance(opts: {
  proposalId: Uint8Array;
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
      [int(2n), bytes(opts.proposalId)],
      [int(3n), nodeIdentityWire(opts.publicKey, opts.createdAtUnix, null)],
      [int(4n), int(opts.position)],
      [int(5n), int(opts.acceptedAtUnix)],
      [int(6n), int(opts.acceptedAtUnix + opts.validitySecs)],
    ],
  });
}

export function envelope(inner: Uint8Array, signature: Uint8Array): Uint8Array {
  return encode({
    t: "map",
    v: [
      [int(1n), bytes(inner)] as [Value, Value],
      [int(2n), bytes(signature)] as [Value, Value],
    ],
  });
}

export function proposalIdOf(proposal: Uint8Array): Uint8Array {
  return sha256(proposal);
}

export function merkleRoot(leaves: Uint8Array[]): Uint8Array | null {
  if (leaves.length === 0) return null;
  const pair = (a: Uint8Array, b: Uint8Array) => sha256(a, b);
  if (leaves.length === 1) return pair(leaves[0]!, leaves[0]!);
  let level = [...leaves];
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const a = level[i]!;
      const b = i + 1 < level.length ? level[i + 1]! : level[i]!;
      next.push(pair(a, b));
    }
    level = next;
  }
  return level[0]!;
}

export function deriveRouteId(root: Uint8Array): Uint8Array {
  return sha256(new TextEncoder().encode("sharenet-route-id-v1"), root);
}
