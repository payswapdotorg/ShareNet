/**
 * ShareNet SignedConnectivityObservation — TypeScript conformance
 * implementation (R5-004).
 */

import type { Value } from "./cbor.ts";
import { encode } from "./cbor.ts";
import { nodeIdentityWire } from "./identity.ts";

/** The frozen six adcos.md event machine names (in mapping order). */
export const KINDS = [
  "contract_activated",
  "execution_state_changed",
  "degraded",
  "assurance_available",
  "failover_replan",
  "terminated",
] as const;

export const SEQUENCE_MIN = 1;
export const EXECUTION_MAX_ENTRIES = 16;
export const EXECUTION_MAX_KEY_BYTES = 64;

/**
 * The canonical observation statement bytes (the registry schema):
 * {1: scheme, 2: provider NodeIdentity, 3: contract_ref, 4: kind,
 *  5: observed_at, 6: sequence, 7?: execution map}.
 */
export function buildObservation(opts: {
  publicKey: Uint8Array;
  createdAtUnix: bigint;
  contractRef: Uint8Array;
  kind: string;
  observedAtUnix: bigint;
  sequence: bigint;
  execution?: Map<string, bigint> | null;
}): Uint8Array {
  const int = (n: bigint): Value => ({ t: "int", v: n });
  const txt = (s: string): Value => ({ t: "text", v: s });
  const bytes = (b: Uint8Array): Value => ({ t: "bytes", v: b });
  const entries: [Value, Value][] = [
    [int(1n), int(1n)],
    [int(2n), nodeIdentityWire(opts.publicKey, opts.createdAtUnix, null)],
    [int(3n), bytes(opts.contractRef)],
    [int(4n), txt(opts.kind)],
    [int(5n), int(opts.observedAtUnix)],
    [int(6n), int(opts.sequence)],
  ];
  if (opts.execution !== null && opts.execution !== undefined) {
    // canonical CBOR map keys: bytewise-ascending text order
    const keys = [...opts.execution.keys()].sort();
    entries.push([
      int(7n),
      {
        t: "map",
        v: keys.map((k) => [txt(k), int(opts.execution!.get(k)!)] as [Value, Value]),
      },
    ]);
  }
  return encode({ t: "map", v: entries });
}

/** The carrying envelope: {1: observation (bstr), 2: signature (64-byte bstr)}. */
export function buildEnvelope(observation: Uint8Array, signature: Uint8Array): Uint8Array {
  const int = (n: bigint): Value => ({ t: "int", v: n });
  return encode({
    t: "map",
    v: [
      [int(1n), { t: "bytes", v: observation }] as [Value, Value],
      [int(2n), { t: "bytes", v: signature }] as [Value, Value],
    ],
  });
}
