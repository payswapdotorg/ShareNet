/**
 * ShareNet Canonical CBOR Profile v1 — TypeScript conformance implementation
 * (work item R1-003, profile defined by R1-002 in the Rust reference core).
 *
 * This is an INDEPENDENT reimplementation of the profile pinned by
 * `reference/crates/sharenet-protocol/tests/vectors/cbor_vectors.json`. It
 * must agree with the Rust core byte-for-byte on every vector; any divergence
 * is a profile break caught by `run_harness.sh`.
 *
 * Profile (normative, identical to the Rust `cbor.rs`):
 * - values: int (i64 range), bytes, UTF-8 text, array, map (unique keys,
 *   canonically sorted), false/true/null;
 * - minimal-length integers and lengths only; definite lengths only;
 * - map keys sorted by bytewise lexicographic order of their canonical
 *   encodings; duplicates forbidden;
 * - forbidden: tags, floats, indefinite lengths, undefined, other simple
 *   values, trailing bytes, non-minimal integers, invalid UTF-8, truncation;
 * - nesting depth capped at 128 in both directions.
 *
 * Error names match the Rust `DecodeError::name()` strings exactly
 * (EmptyInput, Truncated, TrailingBytes, ReservedAdditionalInfo,
 * IndefiniteLength, NonMinimalInteger, UnsortedMapKeys, DuplicateMapKey,
 * IntegerOutOfRange, TagNotAllowed, FloatNotAllowed, UndefinedNotAllowed,
 * SimpleValueNotAllowed, BreakByteNotAllowed, InvalidUtf8,
 * DepthLimitExceeded) so the conformance harness can diff reject outcomes
 * across languages.
 *
 * Integers use JS `bigint` (the profile's i64 range exceeds Number).
 */

export const MAX_DEPTH = 128;

export type Value =
  | { t: "int"; v: bigint }
  | { t: "bytes"; v: Uint8Array }
  | { t: "text"; v: string }
  | { t: "array"; v: Value[] }
  | { t: "map"; v: [Value, Value][] }
  | { t: "bool"; v: boolean }
  | { t: "null" };

const I64_MAX = 9223372036854775807n;

export class DecodeError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

export class EncodeError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}

class Reader {
  pos = 0;
  constructor(readonly buf: Uint8Array) {}

  take(): number {
    if (this.pos >= this.buf.length) {
      throw new DecodeError("Truncated", `truncated at ${this.pos}`);
    }
    return this.buf[this.pos++]!;
  }

  takeN(n: bigint): Uint8Array {
    const avail = BigInt(this.buf.length - this.pos);
    if (n > avail) {
      throw new DecodeError("Truncated", `truncated at ${this.pos}`);
    }
    const len = Number(n);
    const s = this.buf.subarray(this.pos, this.pos + len);
    this.pos += len;
    return s;
  }
}

function readArg(r: Reader, ai: number, at: number): bigint {
  if (ai <= 23) return BigInt(ai);
  if (ai === 24) {
    const b = r.take();
    if (b <= 23) {
      throw new DecodeError("NonMinimalInteger", `non-minimal integer at ${at}`);
    }
    return BigInt(b);
  }
  if (ai === 25) {
    const s = r.takeN(2n);
    const v = (BigInt(s[0]!) << 8n) | BigInt(s[1]!);
    if (v <= 0xffn) {
      throw new DecodeError("NonMinimalInteger", `non-minimal integer at ${at}`);
    }
    return v;
  }
  if (ai === 26) {
    const s = r.takeN(4n);
    let v = 0n;
    for (let i = 0; i < 4; i++) v = (v << 8n) | BigInt(s[i]!);
    if (v <= 0xffffn) {
      throw new DecodeError("NonMinimalInteger", `non-minimal integer at ${at}`);
    }
    return v;
  }
  if (ai === 27) {
    const s = r.takeN(8n);
    let v = 0n;
    for (let i = 0; i < 8; i++) v = (v << 8n) | BigInt(s[i]!);
    if (v <= 0xffffffffn) {
      throw new DecodeError("NonMinimalInteger", `non-minimal integer at ${at}`);
    }
    return v;
  }
  if (ai === 31) {
    // Reached only for major types 0/1/6 (majors 2-5 route to readLen first).
    throw new DecodeError("ReservedAdditionalInfo", `reserved additional info at ${at}`);
  }
  // 28..=30
  throw new DecodeError("ReservedAdditionalInfo", `reserved additional info at ${at}`);
}

function readLen(r: Reader, ai: number, at: number): bigint {
  if (ai === 31) {
    throw new DecodeError("IndefiniteLength", `indefinite length at ${at}`);
  }
  return readArg(r, ai, at);
}

function cmpBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! < b[i]! ? -1 : 1;
  }
  if (a.length !== b.length) return a.length < b.length ? -1 : 1;
  return 0;
}

const utf8Decoder = new TextDecoder("utf-8", { fatal: true });
const utf8Encoder = new TextEncoder();

function readValue(r: Reader, depth: number): Value {
  if (depth > MAX_DEPTH) {
    throw new DecodeError("DepthLimitExceeded", `depth > ${MAX_DEPTH} at ${r.pos}`);
  }
  const at = r.pos;
  const ib = r.take();
  const major = ib >> 5;
  const ai = ib & 0x1f;
  switch (major) {
    case 0: {
      const n = readArg(r, ai, at);
      if (n > I64_MAX) {
        throw new DecodeError("IntegerOutOfRange", `integer out of range at ${at}`);
      }
      return { t: "int", v: n };
    }
    case 1: {
      const n = readArg(r, ai, at);
      if (n > I64_MAX) {
        throw new DecodeError("IntegerOutOfRange", `integer out of range at ${at}`);
      }
      return { t: "int", v: -1n - n };
    }
    case 2: {
      const len = readLen(r, ai, at);
      return { t: "bytes", v: new Uint8Array(r.takeN(len)) };
    }
    case 3: {
      const len = readLen(r, ai, at);
      const bytes = r.takeN(len);
      let text: string;
      try {
        text = utf8Decoder.decode(bytes);
      } catch {
        throw new DecodeError("InvalidUtf8", `invalid UTF-8 at ${at}`);
      }
      return { t: "text", v: text };
    }
    case 4: {
      const n = readLen(r, ai, at);
      const items: Value[] = [];
      for (let i = 0n; i < n; i++) {
        items.push(readValue(r, depth + 1));
      }
      return { t: "array", v: items };
    }
    case 5: {
      const n = readLen(r, ai, at);
      const entries: [Value, Value][] = [];
      let prev: Uint8Array | null = null;
      for (let i = 0n; i < n; i++) {
        const keyStart = r.pos;
        const k = readValue(r, depth + 1);
        const keyEnd = r.pos;
        const cur = r.buf.subarray(keyStart, keyEnd);
        if (prev !== null) {
          const c = cmpBytes(cur, prev);
          if (c === 0) {
            throw new DecodeError("DuplicateMapKey", `duplicate map key at ${keyStart}`);
          }
          if (c < 0) {
            throw new DecodeError("UnsortedMapKeys", `unsorted map keys at ${keyStart}`);
          }
        }
        const v = readValue(r, depth + 1);
        entries.push([k, v]);
        prev = cur;
      }
      return { t: "map", v: entries };
    }
    case 6: {
      const tag = readArg(r, ai, at);
      throw new DecodeError("TagNotAllowed", `tag ${tag} at ${at}`);
    }
    case 7: {
      if (ai === 20) return { t: "bool", v: false };
      if (ai === 21) return { t: "bool", v: true };
      if (ai === 22) return { t: "null" } as Value;
      if (ai === 23) {
        throw new DecodeError("UndefinedNotAllowed", `undefined at ${at}`);
      }
      if (ai === 24) {
        const v = r.take();
        throw new DecodeError("SimpleValueNotAllowed", `simple value ${v} at ${at}`);
      }
      if (ai === 25 || ai === 26 || ai === 27) {
        throw new DecodeError("FloatNotAllowed", `float at ${at}`);
      }
      if (ai === 31) {
        throw new DecodeError("BreakByteNotAllowed", `break byte at ${at}`);
      }
      if (ai >= 28 && ai <= 30) {
        throw new DecodeError("ReservedAdditionalInfo", `reserved additional info at ${at}`);
      }
      throw new DecodeError("SimpleValueNotAllowed", `simple value ${ai} at ${at}`);
    }
    default:
      throw new Error("unreachable: major is 3 bits");
  }
}

export function decode(bytes: Uint8Array): Value {
  if (bytes.length === 0) {
    throw new DecodeError("EmptyInput", "empty input");
  }
  const r = new Reader(bytes);
  const value = readValue(r, 1);
  if (r.pos !== bytes.length) {
    throw new DecodeError(
      "TrailingBytes",
      `trailing bytes at ${r.pos} (${bytes.length - r.pos} extra)`,
    );
  }
  return value;
}

function writeHead(major: number, arg: bigint, out: number[]) {
  const m = major << 5;
  if (arg <= 23n) {
    out.push(m | Number(arg));
  } else if (arg <= 0xffn) {
    out.push(m | 24, Number(arg));
  } else if (arg <= 0xffffn) {
    out.push(m | 25, Number(arg >> 8n), Number(arg & 0xffn));
  } else if (arg <= 0xffffffffn) {
    out.push(m | 26);
    for (let i = 3; i >= 0; i--) out.push(Number((arg >> BigInt(8 * i)) & 0xffn));
  } else {
    out.push(m | 27);
    for (let i = 7; i >= 0; i--) out.push(Number((arg >> BigInt(8 * i)) & 0xffn));
  }
}

function writeValue(value: Value, out: number[], depth: number): void {
  if (depth > MAX_DEPTH) {
    throw new EncodeError("DepthLimitExceeded", `depth > ${MAX_DEPTH}`);
  }
  switch (value.t) {
    case "int":
      if (value.v >= 0n) {
        writeHead(0, value.v, out);
      } else {
        writeHead(1, -1n - value.v, out);
      }
      break;
    case "bytes":
      writeHead(2, BigInt(value.v.length), out);
      for (const b of value.v) out.push(b);
      break;
    case "text": {
      const b = utf8Encoder.encode(value.v);
      writeHead(3, BigInt(b.length), out);
      for (const x of b) out.push(x);
      break;
    }
    case "array":
      writeHead(4, BigInt(value.v.length), out);
      for (const item of value.v) writeValue(item, out, depth + 1);
      break;
    case "map": {
      const keyed = value.v.map(([k], i) => {
        const kb: number[] = [];
        writeValue(k, kb, depth + 1);
        return { kb: Uint8Array.from(kb), i };
      });
      keyed.sort((a, b) => cmpBytes(a.kb, b.kb));
      for (let j = 1; j < keyed.length; j++) {
        if (cmpBytes(keyed[j - 1]!.kb, keyed[j]!.kb) === 0) {
          throw new EncodeError("DuplicateMapKey", `duplicate key at index ${keyed[j]!.i}`);
        }
      }
      writeHead(5, BigInt(value.v.length), out);
      for (const { kb, i } of keyed) {
        for (const x of kb) out.push(x);
        writeValue(value.v[i]![1], out, depth + 1);
      }
      break;
    }
    case "bool":
      out.push(value.v ? 0xf5 : 0xf4);
      break;
    case "null":
      out.push(0xf6);
      break;
  }
}

export function encode(value: Value): Uint8Array {
  const out: number[] = [];
  writeValue(value, out, 1);
  return Uint8Array.from(out);
}

// ---------------------------------------------------------------------------
// JSON value model bridge (vectors store CBOR values as JSON)
// ---------------------------------------------------------------------------

export function valueFromJson(j: any): Value {
  switch (j.type) {
    case "int":
      return { t: "int", v: BigInt(j.value) };
    case "bytes":
      return { t: "bytes", v: fromHex(j.hex) };
    case "text":
      return { t: "text", v: j.value };
    case "array":
      return { t: "array", v: j.items.map(valueFromJson) };
    case "map":
      return {
        t: "map",
        v: j.entries.map(
          (e: any) => [valueFromJson(e.key), valueFromJson(e.value)] as [Value, Value],
        ),
      };
    case "bool":
      return { t: "bool", v: j.value };
    case "null":
      return { t: "null" } as Value;
    default:
      throw new Error(`unknown JSON value type ${j.type}`);
  }
}

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += b.toString(16).padStart(2, "0");
  return s;
}

export function fromHex(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}
