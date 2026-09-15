/**
 * ShareNet ContentManifest — TypeScript conformance implementation
 * (work item R6-001).
 *
 * The manifest is the named object: content_id = SHA-256(canonical CBOR
 * bytes). The chunk discipline (build from actual chunk hashes; reassemble
 * verifying every hash in order + exact total byte count, fail-closed with
 * the slot index) mirrors the Rust reference core; the vectors pin all of
 * it byte-exactly across the three legs.
 */

import { createHash } from "node:crypto";
import type { Value } from "./cbor.ts";
import { encode } from "./cbor.ts";

/** A metadata value: bounded text or integer (never interpreted). */
export type MetadataValue = { t: "text"; v: string } | { t: "int"; v: bigint };

export const CONTENT_MAX_CHUNK_SIZE = 2_097_152n;

export function chunkHash(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

/**
 * Split content into chunk_size chunks (last may be shorter) and build the
 * manifest wire bytes from the SHA-256 hashes of the ACTUAL chunks.
 * Returns the wire bytes, the content_id and the chunk hashes.
 */
export function buildManifest(opts: {
  content: Uint8Array;
  chunkSize: bigint;
  contentType: string;
  metadata?: Map<string, MetadataValue> | null;
  createdAtUnix: bigint;
}): { wire: Uint8Array; contentId: Uint8Array; chunkHashes: Uint8Array[]; chunks: Uint8Array[] } {
  const int = (n: bigint): Value => ({ t: "int", v: n });
  const txt = (s: string): Value => ({ t: "text", v: s });
  const bytes = (b: Uint8Array): Value => ({ t: "bytes", v: b });
  const size = Number(opts.chunkSize);
  const chunks: Uint8Array[] = [];
  for (let at = 0; at < opts.content.length; at += size) {
    chunks.push(opts.content.slice(at, at + size));
  }
  const hashes = chunks.map((c) => chunkHash(c));
  const entries: [Value, Value][] = [
    [int(1n), int(1n)],
    [int(2n), int(opts.chunkSize)],
    [int(3n), int(BigInt(opts.content.length))],
    [
      int(4n),
      { t: "array", v: hashes.map((h) => bytes(h)) },
    ],
    [int(5n), txt(opts.contentType)],
  ];
  if (opts.metadata !== null && opts.metadata !== undefined) {
    // canonical CBOR map keys: bytewise-ascending text order
    const keys = [...opts.metadata.keys()].sort();
    entries.push([
      int(6n),
      {
        t: "map",
        v: keys.map((k) => {
          const v = opts.metadata!.get(k)!;
          return [txt(k), v.t === "int" ? int(v.v) : txt(v.v)] as [Value, Value];
        }),
      },
    ]);
  }
  entries.push([int(7n), int(opts.createdAtUnix)]);
  const wire = encode({ t: "map", v: entries });
  return { wire, contentId: chunkHash(wire), chunkHashes: hashes, chunks };
}

/**
 * The reassembly discipline (fail-closed, slot-indexed). Returns "ok" or
 * the typed outcome string; never partially accepts.
 */
export function reassemble(opts: {
  chunkSize: bigint;
  totalLength: bigint;
  chunkHashes: Uint8Array[];
  chunks: Uint8Array[];
}): string {
  const n = opts.chunkHashes.length;
  const provided = opts.chunks.length;
  const expectedLen = (slot: number): bigint =>
    slot + 1 === n
      ? opts.totalLength - (BigInt(n) - 1n) * opts.chunkSize
      : opts.chunkSize;
  const check = Math.min(provided, n);
  for (let slot = 0; slot < check; slot++) {
    const data = opts.chunks[slot]!;
    const expected = expectedLen(slot);
    if (BigInt(data.length) !== expected) {
      return `chunk_length_wrong slot=${slot}`;
    }
    const h = chunkHash(data);
    const want = opts.chunkHashes[slot]!;
    if (h.length !== want.length || !h.every((b, i) => b === want[i])) {
      return `chunk_hash_mismatch slot=${slot}`;
    }
  }
  if (provided < n) return `missing_chunk slot=${provided}`;
  if (provided > n) return `extra_chunk slot=${n}`;
  return "ok";
}

/** Apply one reassembly mutation (the frozen vocabulary shared by all
 * three conformance legs). */
export function applyMutation(
  chunks: Uint8Array[],
  mutation: string,
  slot: number | null,
): Uint8Array[] {
  const out = chunks.map((c) => new Uint8Array(c));
  const s = slot ?? 0;
  switch (mutation) {
    case "swap_first_two": {
      const tmp = out[0]!;
      out[0] = out[1]!;
      out[1] = tmp;
      return out;
    }
    case "corrupt_slot": {
      out[s] = new Uint8Array(out[s]!);
      out[s]![0]! ^= 0x80;
      return out;
    }
    case "drop_last":
      out.pop();
      return out;
    case "drop_middle":
      out.splice(s, 1);
      return out;
    case "extra_last":
      out.push(new Uint8Array(out[out.length - 1]!));
      return out;
    case "short_last": {
      const last = out[out.length - 1]!;
      out[out.length - 1] = last.slice(0, last.length - 1);
      return out;
    }
    case "short_first":
      out[0] = out[0]!.slice(0, out[0]!.length - 1);
      return out;
    case "replace_slot_with_prev":
      out[s] = new Uint8Array(out[s - 1]!);
      return out;
    default:
      throw new Error(`unknown content mutation ${mutation}`);
  }
}
