/**
 * ShareNet CapabilityStatement — TypeScript conformance implementation
 * (R1-003, object defined by R1-004 in the Rust reference core).
 *
 * Schema (spec/protocol-registry.yaml):
 * {1: scheme_version (=1), 2: node_id (32-byte bstr), 3: capabilities
 *  (strictly ascending wire texts), 4: issued_at_unix, 5: expires_at_unix
 *  (> issued_at), 6?: limits (map text -> int, <= 32 entries, keys 1..=64
 *  bytes)}.
 *
 * Admission = strict parse + node_id binding + strict Ed25519 over the exact
 * statement bytes + time window (issued <= now < expires) + capability
 * lookup. Error names match the Rust `CapabilityError::name()` /
 * `AdmissionError::name()` strings exactly for the cross-language diff.
 */

import type { Value } from "./cbor.ts";
import { decode, encode } from "./cbor.ts";
import { deriveNodeId, Ed25519Key } from "./identity.ts";

export const CAP_SCHEME_VERSION = 1n;
export const MAX_LIMITS_ENTRIES = 32;
export const MAX_LIMIT_KEY_BYTES = 64;

const WIRE_TEXTS = ["dtn_custodian", "gateway", "infrastructure", "relay"] as const;
export type CapabilityName = (typeof WIRE_TEXTS)[number];

export class CapabilityError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

export class AdmissionError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
  }
}

export interface StatementFields {
  nodeId: Uint8Array;
  capabilities: CapabilityName[];
  issuedAtUnix: bigint;
  expiresAtUnix: bigint;
  limits: Map<string, bigint> | null;
}

function checkTimestamp(field: string, t: bigint): void {
  if (t < 0n) throw new CapabilityError("timestamp_negative", `${field} negative`);
  if (t > 9223372036854775807n) {
    throw new CapabilityError("timestamp_out_of_range", `${field} out of range`);
  }
}

export function buildStatement(f: StatementFields): Value {
  if (f.capabilities.length === 0) {
    throw new CapabilityError("capabilities_empty", "empty capabilities");
  }
  // canonical order: strictly ascending bytewise order of wire texts
  const sorted = [...new Set(f.capabilities)].sort((a, b) =>
    a < b ? -1 : a > b ? 1 : 0,
  );
  if (sorted.length !== f.capabilities.length) {
    throw new CapabilityError("capabilities_not_sorted", "duplicate capabilities");
  }
  if (f.expiresAtUnix <= f.issuedAtUnix) {
    throw new CapabilityError(
      "expiry_not_after_issue",
      "expires_at must be strictly after issued_at",
    );
  }
  checkTimestamp("issued_at", f.issuedAtUnix);
  checkTimestamp("expires_at", f.expiresAtUnix);
  if (f.limits !== null) {
    if (f.limits.size > MAX_LIMITS_ENTRIES) {
      throw new CapabilityError("limits_too_many_entries", "too many limit entries");
    }
    for (const k of f.limits.keys()) {
      const bytes = new TextEncoder().encode(k);
      if (bytes.length === 0 || bytes.length > MAX_LIMIT_KEY_BYTES) {
        throw new CapabilityError("limit_key_invalid", "limit key length invalid");
      }
    }
  }
  const entries: [Value, Value][] = [
    [{ t: "int", v: 1n }, { t: "int", v: CAP_SCHEME_VERSION }],
    [{ t: "int", v: 2n }, { t: "bytes", v: f.nodeId }],
    [
      { t: "int", v: 3n },
      { t: "array", v: sorted.map((c) => ({ t: "text", v: c }) as Value) },
    ],
    [{ t: "int", v: 4n }, { t: "int", v: f.issuedAtUnix }],
    [{ t: "int", v: 5n }, { t: "int", v: f.expiresAtUnix }],
  ];
  if (f.limits !== null) {
    const limitEntries: [Value, Value][] = [...f.limits.entries()]
      .map(([k, v]) => [{ t: "text", v: k }, { t: "int", v }] as [Value, Value])
      .sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    entries.push([{ t: "int", v: 6n }, { t: "map", v: limitEntries }]);
  }
  return { t: "map", v: entries };
}

export interface ParsedStatement {
  nodeId: Uint8Array;
  capabilities: CapabilityName[];
  issuedAtUnix: bigint;
  expiresAtUnix: bigint;
  limits: Map<string, bigint> | null;
}

export function parseStatement(bytes: Uint8Array): ParsedStatement {
  let v: Value;
  try {
    v = decode(bytes);
  } catch (e: any) {
    throw new CapabilityError(`cbor:${e.code}`, `CBOR profile violation: ${e.message}`);
  }
  return fromWire(v);
}

export function fromWire(v: Value): ParsedStatement {
  if (v.t !== "map") throw new CapabilityError("not_a_map", "statement must be a map");
  let scheme: bigint | null = null;
  let nodeId: Uint8Array | null = null;
  let capabilities: CapabilityName[] | null = null;
  let issuedAt: bigint | null = null;
  let expiresAt: bigint | null = null;
  let limits: Map<string, bigint> | null = null;
  for (const [k, val] of v.v) {
    if (k.t !== "int") throw new CapabilityError("key_not_an_integer", "non-integer key");
    switch (k.v) {
      case 1n: {
        if (scheme !== null) throw new CapabilityError("duplicate_field", "duplicate field 1");
        if (val.t !== "int") {
          throw new CapabilityError("field_not_expected_type", "field 1 type");
        }
        if (val.v !== CAP_SCHEME_VERSION) {
          throw new CapabilityError("scheme_version_unsupported", "scheme version");
        }
        scheme = val.v;
        break;
      }
      case 2n: {
        if (nodeId !== null) throw new CapabilityError("duplicate_field", "duplicate field 2");
        if (val.t !== "bytes") {
          throw new CapabilityError("field_not_expected_type", "field 2 type");
        }
        if (val.v.length !== 32) {
          throw new CapabilityError("node_id_wrong_length", "node_id length");
        }
        nodeId = val.v;
        break;
      }
      case 3n: {
        if (capabilities !== null) {
          throw new CapabilityError("duplicate_field", "duplicate field 3");
        }
        if (val.t !== "array") {
          throw new CapabilityError("field_not_expected_type", "field 3 type");
        }
        if (val.v.length === 0) {
          throw new CapabilityError("capabilities_empty", "empty capabilities");
        }
        const caps: CapabilityName[] = [];
        val.v.forEach((item, i) => {
          if (item.t !== "text") {
            throw new CapabilityError("capability_not_text", "capability not text");
          }
          if (i > 0 && !(item.v > caps[i - 1]!)) {
            throw new CapabilityError(
              "capabilities_not_sorted",
              "unsorted or duplicate capabilities",
            );
          }
          if (!(WIRE_TEXTS as readonly string[]).includes(item.v)) {
            throw new CapabilityError("unknown_capability", `unknown capability ${item.v}`);
          }
          caps.push(item.v as CapabilityName);
        });
        capabilities = caps;
        break;
      }
      case 4n: {
        if (issuedAt !== null) throw new CapabilityError("duplicate_field", "duplicate field 4");
        if (val.t !== "int") {
          throw new CapabilityError("field_not_expected_type", "field 4 type");
        }
        if (val.v < 0n) {
          throw new CapabilityError("timestamp_negative", "issued_at negative");
        }
        issuedAt = val.v;
        break;
      }
      case 5n: {
        if (expiresAt !== null) throw new CapabilityError("duplicate_field", "duplicate field 5");
        if (val.t !== "int") {
          throw new CapabilityError("field_not_expected_type", "field 5 type");
        }
        if (val.v < 0n) {
          throw new CapabilityError("timestamp_negative", "expires_at negative");
        }
        expiresAt = val.v;
        break;
      }
      case 6n: {
        if (limits !== null) throw new CapabilityError("duplicate_field", "duplicate field 6");
        if (val.t !== "map") {
          throw new CapabilityError("field_not_expected_type", "field 6 type");
        }
        if (val.v.length > MAX_LIMITS_ENTRIES) {
          throw new CapabilityError("limits_too_many_entries", "too many limits");
        }
        const m = new Map<string, bigint>();
        for (const [lk, lv] of val.v) {
          if (lk.t !== "text" || lv.t !== "int") {
            throw new CapabilityError("limit_entry_malformed", "limit entry malformed");
          }
          const bytes = new TextEncoder().encode(lk.v);
          if (bytes.length === 0 || bytes.length > MAX_LIMIT_KEY_BYTES) {
            throw new CapabilityError("limit_key_invalid", "limit key length");
          }
          m.set(lk.v, lv.v);
        }
        limits = m;
        break;
      }
      default:
        throw new CapabilityError("unknown_field", `unknown field ${k.v}`);
    }
  }
  if (scheme === null) throw new CapabilityError("missing_field", "missing field 1");
  if (nodeId === null) throw new CapabilityError("missing_field", "missing field 2");
  if (capabilities === null) throw new CapabilityError("missing_field", "missing field 3");
  if (issuedAt === null) throw new CapabilityError("missing_field", "missing field 4");
  if (expiresAt === null) throw new CapabilityError("missing_field", "missing field 5");
  if (expiresAt <= issuedAt) {
    throw new CapabilityError("expiry_not_after_issue", "expiry must follow issue");
  }
  return {
    nodeId,
    capabilities,
    issuedAtUnix: issuedAt,
    expiresAtUnix: expiresAt,
    limits,
  };
}

/** Full admission (parse + binding + verify + window + lookup). */
export function admit(
  statementBytes: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
  nowUnix: bigint,
  required: CapabilityName[],
): ParsedStatement {
  let st: ParsedStatement;
  try {
    st = parseStatement(statementBytes);
  } catch (e: any) {
    if (e instanceof CapabilityError) {
      throw new AdmissionError(`statement:${e.code}`, e.message);
    }
    throw e;
  }
  const derived = deriveNodeId(publicKey);
  if (!bytesEq(st.nodeId, derived)) {
    throw new AdmissionError("node_id_mismatch", "node_id binding failed");
  }
  if (signature.length !== 64) {
    throw new AdmissionError("signature_encoding_invalid", "signature length");
  }
  if (!Ed25519Key.verifyDetached(publicKey, statementBytes, signature)) {
    throw new AdmissionError("verification_failed", "signature verification failed");
  }
  if (nowUnix < st.issuedAtUnix) {
    throw new AdmissionError("not_yet_valid", "now < issued_at");
  }
  if (nowUnix >= st.expiresAtUnix) {
    throw new AdmissionError("expired", "now >= expires_at");
  }
  for (const c of required) {
    if (!st.capabilities.includes(c)) {
      throw new AdmissionError("capability_not_held", `capability ${c} not held`);
    }
  }
  return st;
}

function bytesEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export { encode as encodeValue };
