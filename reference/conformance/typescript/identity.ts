/**
 * ShareNet node identity — TypeScript conformance implementation (R1-003,
 * object defined by R1-001 in the Rust reference core).
 *
 * Derives Ed25519 key pairs from seeds via node:crypto's RFC 8032
 * implementation (raw seeds wrapped in the standard PKCS#8/SPKI envelopes),
 * derives `node_id = SHA-256(canonical_cbor({1: scheme_version, 2:
 * public_key}))` and builds the NodeIdentity wire map.
 *
 * Conformance scope note (honest limitation, documented at the harness
 * level): node:crypto verifies per RFC 8032; the Rust core additionally
 * rejects malleable S encodings and non-canonical points (verify_strict).
 * The committed vectors contain only well-formed signatures, which both
 * accept; the adversarial malleability suite is Rust-core scope.
 */

import { createHash, createPrivateKey, createPublicKey, sign, verify } from "node:crypto";
import type { Value } from "./cbor.ts";
import { encode, fromHex, toHex } from "./cbor.ts";

export const SCHEME_VERSION = 1n;
export const SEED_LEN = 32;
export const PUBLIC_KEY_LEN = 32;
export const SIGNATURE_LEN = 64;
export const NODE_ID_LEN = 32;
export const MAX_DISPLAY_NAME_BYTES = 64;

const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Ed25519 key pair derived from a 32-byte seed (RFC 8032). */
export class Ed25519Key {
  readonly seed: Uint8Array;
  readonly publicKey: Uint8Array;

  constructor(seed: Uint8Array) {
    if (seed.length !== SEED_LEN) throw new Error(`seed must be ${SEED_LEN} bytes`);
    this.seed = seed;
    const priv = createPrivateKey({
      key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]),
      format: "der",
      type: "pkcs8",
    });
    const spki = createPublicKey(priv).export({ format: "der", type: "spki" });
    // spki = prefix (12 bytes) + raw public key (32 bytes)
    this.publicKey = new Uint8Array(spki.subarray(SPKI_PREFIX.length));
  }

  /** Deterministic RFC 8032 detached signature over the payload. */
  signDetached(payload: Uint8Array): Uint8Array {
    const priv = createPrivateKey({
      key: Buffer.concat([PKCS8_PREFIX, Buffer.from(this.seed)]),
      format: "der",
      type: "pkcs8",
    });
    return new Uint8Array(sign(null, Buffer.from(payload), priv));
  }

  /** RFC 8032 verification with the pair's public key. */
  static verifyDetached(
    publicKey: Uint8Array,
    payload: Uint8Array,
    signature: Uint8Array,
  ): boolean {
    if (publicKey.length !== PUBLIC_KEY_LEN || signature.length !== SIGNATURE_LEN) return false;
    try {
      const pub = createPublicKey({
        key: Buffer.concat([SPKI_PREFIX, Buffer.from(publicKey)]),
        format: "der",
        type: "spki",
      });
      return verify(null, Buffer.from(payload), pub, Buffer.from(signature));
    } catch {
      return false;
    }
  }
}

/** node_id = SHA-256(canonical_cbor({1: scheme_version, 2: public_key})). */
export function deriveNodeId(publicKey: Uint8Array): Uint8Array {
  const preimage = encode({
    t: "map",
    v: [
      [{ t: "int", v: 1n }, { t: "int", v: SCHEME_VERSION }],
      [{ t: "int", v: 2n }, { t: "bytes", v: publicKey }],
    ],
  });
  return new Uint8Array(createHash("sha256").update(preimage).digest());
}

/**
 * The NodeIdentity wire map (R1-001):
 * {1: scheme_version, 2: public_key, 3: created_at_unix, 4?: display_name}.
 * display_name is limited to 64 bytes of UTF-8.
 */
export function nodeIdentityWire(
  publicKey: Uint8Array,
  createdAtUnix: bigint,
  displayName: string | null,
): Value {
  const entries: [Value, Value][] = [
    [{ t: "int", v: 1n }, { t: "int", v: SCHEME_VERSION }],
    [{ t: "int", v: 2n }, { t: "bytes", v: publicKey }],
    [{ t: "int", v: 3n }, { t: "int", v: createdAtUnix }],
  ];
  if (displayName !== null) {
    const bytes = new TextEncoder().encode(displayName);
    if (bytes.length > MAX_DISPLAY_NAME_BYTES) {
      throw new Error("display name exceeds 64 bytes");
    }
    entries.push([{ t: "int", v: 4n }, { t: "text", v: displayName }]);
  }
  return { t: "map", v: entries };
}

export { fromHex, toHex };
