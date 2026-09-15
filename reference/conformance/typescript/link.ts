/**
 * ShareNet authenticated links — TypeScript conformance implementation
 * (R3-003 conformance legs; object defined by R3-001 in the Rust core).
 *
 * Re-implements the registered handshake + frame rules using node:crypto
 * (X25519 via KeyObjects, HKDF) and the in-tree RFC 8439 AEAD so the
 * committed link vectors reproduce byte-exactly. Conformance only — not
 * production crypto (see the Rust protocol core for that).
 */

import { createHash, createPrivateKey, createPublicKey, diffieHellman, hkdfSync } from "node:crypto";
import { aeadSeal } from "./chacha20poly1305.ts";
import type { Value } from "./cbor.ts";
import { encode } from "./cbor.ts";

/** CBOR map value in the TS value model. */
function m(entries: [Value, Value][]): Value {
  return { t: "map", v: entries };
}
import { nodeIdentityWire } from "./identity.ts";

const X25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const X25519_SPKI_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

export const RESPONDER_SIGN_CONTEXT = "sharenet-link-auth-v1/responder";
export const INITIATOR_SIGN_CONTEXT = "sharenet-link-auth-v1/initiator";
export const HKDF_INFO = Buffer.from("sharenet-link-session-v1");
export const LINK_ID_CONTEXT = "sharenet-link-id-v1";
export const FRAME_AAD_CONTEXT = "sharenet-link-frame-v1";

/** X25519 public key from a (raw) 32-byte scalar. */
export function x25519Public(scalar: Uint8Array): Uint8Array {
  const priv = createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(scalar)]),
    format: "der",
    type: "pkcs8",
  });
  const spki = createPublicKey(priv).export({ format: "der", type: "spki" }) as Buffer;
  return new Uint8Array(spki.subarray(X25519_SPKI_PREFIX.length));
}

/** X25519 shared secret from a raw scalar + raw peer public key. */
export function x25519Shared(scalar: Uint8Array, peerPublic: Uint8Array): Uint8Array {
  const priv = createPrivateKey({
    key: Buffer.concat([X25519_PKCS8_PREFIX, Buffer.from(scalar)]),
    format: "der",
    type: "pkcs8",
  });
  const pub = createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, Buffer.from(peerPublic)]),
    format: "der",
    type: "spki",
  });
  return new Uint8Array(diffieHellman({ privateKey: priv, publicKey: pub }));
}

export function sha256(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

export interface NodeIdentityFields {
  publicKey: Uint8Array;
  createdAtUnix: bigint;
  displayName: string | null;
}

/** msg1 wire: {1: 1, 2: e_i}. */
export function buildMsg1(eInitiator: Uint8Array): Uint8Array {
  return encode(
    m([
      [{ t: "int", v: 1n }, { t: "int", v: 1n }],
      [{ t: "int", v: 2n }, { t: "bytes", v: eInitiator }],
    ]),
  );
}

/** msg2 content wire (no signature): {1: 1, 2: e_r, 3: identity, 5?: caps}. */
export function buildMsg2Content(
  eResponder: Uint8Array,
  identity: NodeIdentityFields,
  capabilities: Uint8Array | null,
): Uint8Array {
  const entries: [Value, Value][] = [
    [{ t: "int", v: 1n }, { t: "int", v: 1n }],
    [{ t: "int", v: 2n }, { t: "bytes", v: eResponder }],
    [
      { t: "int", v: 3n },
      nodeIdentityWire(identity.publicKey, identity.createdAtUnix, identity.displayName),
    ],
  ];
  if (capabilities !== null) {
    entries.push([{ t: "int", v: 5n }, { t: "bytes", v: capabilities }]);
  }
  return encode(m(entries));
}

export function buildMsg2(
  eResponder: Uint8Array,
  identity: NodeIdentityFields,
  capabilities: Uint8Array | null,
  signature: Uint8Array,
): Uint8Array {
  const entries: [Value, Value][] = [
    [{ t: "int", v: 1n }, { t: "int", v: 1n }],
    [{ t: "int", v: 2n }, { t: "bytes", v: eResponder }],
    [
      { t: "int", v: 3n },
      nodeIdentityWire(identity.publicKey, identity.createdAtUnix, identity.displayName),
    ],
    [{ t: "int", v: 4n }, { t: "bytes", v: signature }],
  ];
  if (capabilities !== null) {
    entries.push([{ t: "int", v: 5n }, { t: "bytes", v: capabilities }]);
  }
  return encode(m(entries));
}

/** msg3 content wire (no signature): {1: 1, 2: identity, 4?: caps}. */
export function buildMsg3Content(
  identity: NodeIdentityFields,
  capabilities: Uint8Array | null,
): Uint8Array {
  const entries: [Value, Value][] = [
    [{ t: "int", v: 1n }, { t: "int", v: 1n }],
    [
      { t: "int", v: 2n },
      nodeIdentityWire(identity.publicKey, identity.createdAtUnix, identity.displayName),
    ],
  ];
  if (capabilities !== null) {
    entries.push([{ t: "int", v: 4n }, { t: "bytes", v: capabilities }]);
  }
  return encode(m(entries));
}

export function buildMsg3(
  identity: NodeIdentityFields,
  capabilities: Uint8Array | null,
  signature: Uint8Array,
): Uint8Array {
  const entries: [Value, Value][] = [
    [{ t: "int", v: 1n }, { t: "int", v: 1n }],
    [
      { t: "int", v: 2n },
      nodeIdentityWire(identity.publicKey, identity.createdAtUnix, identity.displayName),
    ],
    [{ t: "int", v: 3n }, { t: "bytes", v: signature }],
  ];
  if (capabilities !== null) {
    entries.push([{ t: "int", v: 4n }, { t: "bytes", v: capabilities }]);
  }
  return encode(m(entries));
}

export function responderSignPayload(msg1: Uint8Array, msg2Content: Uint8Array): Uint8Array {
  return sha256(
    new TextEncoder().encode(RESPONDER_SIGN_CONTEXT),
    msg1,
    msg2Content,
  );
}

export function initiatorSignPayload(
  msg1: Uint8Array,
  msg2: Uint8Array,
  msg3Content: Uint8Array,
): Uint8Array {
  return sha256(
    new TextEncoder().encode(INITIATOR_SIGN_CONTEXT),
    msg1,
    msg2,
    msg3Content,
  );
}

export function deriveSession(
  sharedSecret: Uint8Array,
  msg1: Uint8Array,
  msg2: Uint8Array,
  msg3: Uint8Array,
): { linkId: Uint8Array; keyI2R: Uint8Array; keyR2I: Uint8Array } {
  const salt = sha256(msg1, msg2, msg3);
  const okm = new Uint8Array(
    hkdfSync("sha256", Buffer.from(sharedSecret), Buffer.from(salt), HKDF_INFO, 64),
  );
  const keyI2R = okm.slice(0, 32);
  const keyR2I = okm.slice(32, 64);
  const linkId = sha256(
    new TextEncoder().encode(LINK_ID_CONTEXT),
    msg1,
    msg2,
    msg3,
  );
  return { linkId, keyI2R, keyR2I };
}

/** Seal one link frame: seq(8, be) || AEAD(key, nonce, aad, payload). */
export function sealFrame(
  key: Uint8Array,
  linkId: Uint8Array,
  direction: 1 | 2,
  seq: bigint,
  payload: Uint8Array,
): Uint8Array {
  const nonce = new Uint8Array(12);
  new DataView(nonce.buffer).setBigUint64(4, seq, false);
  const aad = new Uint8Array(22 + 32 + 1 + 8);
  aad.set(new TextEncoder().encode(FRAME_AAD_CONTEXT), 0);
  aad.set(linkId, 22);
  aad[54] = direction;
  new DataView(aad.buffer).setBigUint64(55, seq, false);
  const sealed = aeadSeal(key, nonce, aad, payload);
  const out = new Uint8Array(8 + sealed.length);
  new DataView(out.buffer).setBigUint64(0, seq, false);
  out.set(sealed, 8);
  return out;
}
