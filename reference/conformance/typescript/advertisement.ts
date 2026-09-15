/**
 * ShareNet Advertisement — TypeScript conformance implementation
 * (R3-002; object defined in the Rust reference core).
 */

import { createHash } from "node:crypto";
import type { Value } from "./cbor.ts";
import { encode } from "./cbor.ts";
import { nodeIdentityWire } from "./identity.ts";

export const AD_MAX_WINDOW = 600n;

export function buildAdvertisement(opts: {
  publicKey: Uint8Array;
  createdAtUnix: bigint;
  capabilities: Uint8Array | null;
  transports: { kind: string; endpoint: string }[];
  issuedAtUnix: bigint;
  validitySecs: bigint;
}): Uint8Array {
  const sorted = [...opts.transports].sort((a, b) =>
    a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : a.endpoint < b.endpoint ? -1 : a.endpoint > b.endpoint ? 1 : 0,
  );
  const int = (n: bigint): Value => ({ t: "int", v: n });
  const txt = (s: string): Value => ({ t: "text", v: s });
  const entries: [Value, Value][] = [
    [int(1n), int(1n)],
    [int(2n), nodeIdentityWire(opts.publicKey, opts.createdAtUnix, null)],
  ];
  if (opts.capabilities !== null) {
    entries.push([int(3n), { t: "bytes", v: opts.capabilities }]);
  }
  entries.push([
    int(4n),
    {
      t: "array",
      v: sorted.map(
        (t): Value => ({
          t: "map",
          v: [
            [int(1n), txt(t.kind)] as [Value, Value],
            [int(2n), txt(t.endpoint)] as [Value, Value],
          ],
        }),
      ),
    },
  ]);
  entries.push([int(5n), int(opts.issuedAtUnix)]);
  entries.push([int(6n), int(opts.issuedAtUnix + opts.validitySecs)]);
  return encode({ t: "map", v: entries });
}

export function advertisementId(wire: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(wire).digest());
}

export function buildEnvelope(
  advertisement: Uint8Array,
  signature: Uint8Array,
): Uint8Array {
  const int = (n: bigint): Value => ({ t: "int", v: n });
  return encode({
    t: "map",
    v: [
      [int(1n), { t: "bytes", v: advertisement }] as [Value, Value],
      [int(2n), { t: "bytes", v: signature }] as [Value, Value],
    ],
  });
}
