/**
 * ShareNet ContributionReceipt — TypeScript conformance implementation
 * (work item R8-001).
 *
 * The receipt is the bilateral recipient-signed acknowledgement: the
 * RECEIVING counterparty (the issuer) signs, the contributor can never be
 * the issuer, and receipt_id = SHA-256(canonical receipt bytes) — the
 * commitment-derived identity (L013), so any change is a different named
 * object. The registry admission rule (signature → future clock →
 * receipt_id idempotency → the per-(issuer, contributor) monotonic
 * sequence law) is mirrored by the runner's ledger exactly as the Rust
 * core orders it.
 */

import { createHash } from "node:crypto";
import type { Value } from "./cbor.ts";
import { encode } from "./cbor.ts";
import { nodeIdentityWire } from "./identity.ts";

/** The frozen v1 contribution kinds (machine names shared with the Rust core). */
export const KINDS = ["carried", "delivered"] as const;

export const RECEIPT_SEQ_MIN = 1n;
export const DELIVERED_BYTES_MAX = 1n << 40n;

/** receipt_id = SHA-256(canonical receipt bytes) — the named object. */
export function receiptId(receipt: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(receipt).digest());
}

/**
 * The canonical receipt bytes (the registry schema):
 * {1: scheme (=1), 2: issuer NodeIdentity, 3: contributor_node_id,
 *  4: content_id, 5: kind, 6: delivered_bytes, 7: receipt_seq,
 *  8: issued_at_unix}.
 */
export function buildReceipt(opts: {
  publicKey: Uint8Array;
  createdAtUnix: bigint;
  contributorNodeId: Uint8Array;
  contentId: Uint8Array;
  kind: string;
  deliveredBytes: bigint;
  receiptSeq: bigint;
  issuedAtUnix: bigint;
}): Uint8Array {
  const int = (n: bigint): Value => ({ t: "int", v: n });
  const txt = (s: string): Value => ({ t: "text", v: s });
  const bytes = (b: Uint8Array): Value => ({ t: "bytes", v: b });
  return encode({
    t: "map",
    v: [
      [int(1n), int(1n)] as [Value, Value],
      [int(2n), nodeIdentityWire(opts.publicKey, opts.createdAtUnix, null)] as [Value, Value],
      [int(3n), bytes(opts.contributorNodeId)] as [Value, Value],
      [int(4n), bytes(opts.contentId)] as [Value, Value],
      [int(5n), txt(opts.kind)] as [Value, Value],
      [int(6n), int(opts.deliveredBytes)] as [Value, Value],
      [int(7n), int(opts.receiptSeq)] as [Value, Value],
      [int(8n), int(opts.issuedAtUnix)] as [Value, Value],
    ],
  });
}

/** The carrying envelope: {1: receipt (bstr), 2: signature (64-byte bstr)}. */
export function buildEnvelope(receipt: Uint8Array, signature: Uint8Array): Uint8Array {
  const int = (n: bigint): Value => ({ t: "int", v: n });
  return encode({
    t: "map",
    v: [
      [int(1n), { t: "bytes", v: receipt }] as [Value, Value],
      [int(2n), { t: "bytes", v: signature }] as [Value, Value],
    ],
  });
}
