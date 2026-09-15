/** ShareNet TopologyEvidence — TypeScript conformance implementation (R3-003). */

import { createHash } from "node:crypto";
import type { Value } from "./cbor.ts";
import { encode } from "./cbor.ts";
import { nodeIdentityWire } from "./identity.ts";

export function buildEvidence(opts: {
  publicKey: Uint8Array;
  createdAtUnix: bigint;
  subjectNodeId: Uint8Array;
  kind: "link" | "advertisement";
  observedAtUnix: bigint;
  validitySecs: bigint;
  link?: { linkId: Uint8Array; establishedAt: bigint; quality: Record<string, bigint> };
  advertisement?: { advertisementId: Uint8Array; capabilities: string[] };
}): Uint8Array {
  const int = (n: bigint): Value => ({ t: "int", v: n });
  const txt = (s: string): Value => ({ t: "text", v: s });
  const bytes = (b: Uint8Array): Value => ({ t: "bytes", v: b });
  let obsMap: Value;
  if (opts.kind === "link") {
    const q = opts.link!.quality;
    obsMap = {
      t: "map",
      v: [
        [int(1n), bytes(opts.link!.linkId)],
        [int(2n), int(opts.link!.establishedAt)],
        [int(3n), int(q.delivered)],
        [int(4n), int(q.lost)],
        [int(5n), int(q.ewma_rtt_micros)],
        [int(6n), int(q.p50_rtt_micros)],
        [int(7n), int(q.p95_rtt_micros)],
        [int(8n), int(q.jitter_mad_micros)],
        [int(9n), int(q.loss_ratio_ppm)],
      ],
    };
  } else {
    obsMap = {
      t: "map",
      v: [
        [int(1n), bytes(opts.advertisement!.advertisementId)],
        [int(2n), { t: "array", v: opts.advertisement!.capabilities.map((c) => txt(c)) }],
      ],
    };
  }
  const entries: [Value, Value][] = [
    [int(1n), int(1n)],
    [int(2n), nodeIdentityWire(opts.publicKey, opts.createdAtUnix, null)],
    [int(3n), bytes(opts.subjectNodeId)],
    [int(4n), txt(opts.kind)],
    [int(5n), int(opts.observedAtUnix)],
    [int(6n), int(opts.observedAtUnix + opts.validitySecs)],
    [int(7n), obsMap],
  ];
  return encode({ t: "map", v: entries });
}

export function evidenceId(wire: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(wire).digest());
}

export function buildEnvelope(evidence: Uint8Array, signature: Uint8Array): Uint8Array {
  const int = (n: bigint): Value => ({ t: "int", v: n });
  return encode({
    t: "map",
    v: [
      [int(1n), { t: "bytes", v: evidence }] as [Value, Value],
      [int(2n), { t: "bytes", v: signature }] as [Value, Value],
    ],
  });
}
