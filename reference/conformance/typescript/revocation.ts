/** ShareNet circuit revocation — TypeScript conformance leg (R7-001). */

import type { Value } from "./cbor.ts";
import { encode } from "./cbor.ts";
import { nodeIdentityWire } from "./identity.ts";

const int = (n: bigint): Value => ({ t: "int", v: n });
const txt = (s: string): Value => ({ t: "text", v: s });
const bytes = (b: Uint8Array): Value => ({ t: "bytes", v: b });

/** CircuitRevocation wire: {1: scheme, 2: circuit_id, 3: revoker, 4: reason,
 * 5: evidence (optional map text -> int|text), 6: revoked_at}.
 * The evidence map (when present) MUST carry a "failure_kind" text entry
 * plus at most 8 further int/text fields; null = the absent legal form. */
export function buildRevocation(opts: {
  circuitId: Uint8Array;
  publicKey: Uint8Array;
  createdAtUnix: bigint;
  reason: string;
  evidence: Map<string, bigint | string> | null;
  revokedAtUnix: bigint;
}): Uint8Array {
  const entries: [Value, Value][] = [
    [int(1n), int(1n)],
    [int(2n), bytes(opts.circuitId)],
    [int(3n), nodeIdentityWire(opts.publicKey, opts.createdAtUnix, null)],
    [int(4n), txt(opts.reason)],
  ];
  if (opts.evidence !== null) {
    const ev: [Value, Value][] = [...opts.evidence.entries()].map(([k, v]) => [
      txt(k),
      typeof v === "bigint" ? int(v) : txt(v),
    ]);
    entries.push([int(5n), { t: "map", v: ev }]);
  }
  entries.push([int(6n), int(opts.revokedAtUnix)]);
  return encode({ t: "map", v: entries });
}

/** The carrying envelope: {1: revocation (bstr), 2: signature (64-byte bstr)}. */
export function revocationEnvelope(revocation: Uint8Array, signature: Uint8Array): Uint8Array {
  return encode({
    t: "map",
    v: [
      [int(1n), bytes(revocation)],
      [int(2n), bytes(signature)],
    ],
  });
}
