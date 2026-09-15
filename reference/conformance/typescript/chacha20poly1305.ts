/**
 * ChaCha20-Poly1305 AEAD (RFC 8439) — TypeScript conformance implementation.
 *
 * Pure reimplementation of the RFC 8439 reference construction for the
 * cross-language link vectors (R3-003 conformance legs). NOT hardened for
 * production: it is deliberately simple and testable. The Rust protocol
 * core uses the audited RustCrypto implementation; this exists to
 * independently reproduce the frame bytes.
 */

function rotl(v: number, c: number): number {
  return ((v << c) | (v >>> (32 - c))) >>> 0;
}

function quarterRound(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0; s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0; s[b] = rotl(s[b] ^ s[c], 7);
}

/** One ChaCha20 block (RFC 8439 §2.3). */
function chachaBlock(key: Uint32Array, counter: number, nonce: Uint32Array): Uint8Array {
  const state = new Uint32Array(16);
  state.set(key.subarray(0, 8), 4);
  state[12] = counter >>> 0;
  state.set(nonce.subarray(0, 3), 13);
  const working = new Uint32Array(state);
  working[0] = 0x61707865; working[1] = 0x3320646e;
  working[2] = 0x79622d32; working[3] = 0x6b206574;
  for (let i = 0; i < 10; i++) {
    quarterRound(working, 0, 4, 8, 12);
    quarterRound(working, 1, 5, 9, 13);
    quarterRound(working, 2, 6, 10, 14);
    quarterRound(working, 3, 7, 11, 15);
    quarterRound(working, 0, 5, 10, 15);
    quarterRound(working, 1, 6, 11, 12);
    quarterRound(working, 2, 7, 8, 13);
    quarterRound(working, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
  for (let i = 0; i < 16; i++) {
    const v = (working[i]! + (i < 4 ? [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574][i]! : i < 12 ? key[i - 4]! : i === 12 ? counter >>> 0 : nonce[i - 13]!)) >>> 0;
    dv.setUint32(i * 4, v, true);
  }
  return out;
}

/** ChaCha20 encryption/decryption of a message (RFC 8439 §2.4). */
function chacha20(key: Uint8Array, counter: number, nonce: Uint8Array, data: Uint8Array): Uint8Array {
  const k = new Uint32Array(8);
  const kdv = new DataView(key.buffer, key.byteOffset, key.byteLength);
  for (let i = 0; i < 8; i++) k[i] = kdv.getUint32(i * 4, true);
  const n = new Uint32Array(3);
  const ndv = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
  for (let i = 0; i < 3; i++) n[i] = ndv.getUint32(i * 4, true);
  const out = new Uint8Array(data.length);
  for (let off = 0; off < data.length; off += 64) {
    const block = chachaBlock(k, counter + Math.floor(off / 64), n);
    const len = Math.min(64, data.length - off);
    for (let i = 0; i < len; i++) out[off + i] = data[off + i]! ^ block[i]!;
  }
  return out;
}

/** Poly1305 MAC (RFC 8439 §2.5) over the message with a 32-byte key. */
function poly1305(key: Uint8Array, msg: Uint8Array): Uint8Array {
  const mask = (1n << 130n) - 1n; // not used; see below
  const p = (1n << 130n) - 5n;
  const clamp = (n: bigint) => n & 0x0ffffffc0ffffffc0ffffffc0fffffffn;
  const rdv = new DataView(key.buffer, key.byteOffset, key.byteLength);
  const r = clamp(BigInt(rdv.getUint32(0, true)) | (BigInt(rdv.getUint32(4, true)) << 32n) |
    (BigInt(rdv.getUint32(8, true)) << 64n) | (BigInt(rdv.getUint32(12, true)) << 96n));
  const s = BigInt(rdv.getUint32(16, true)) | (BigInt(rdv.getUint32(20, true)) << 32n) |
    (BigInt(rdv.getUint32(24, true)) << 64n) | (BigInt(rdv.getUint32(28, true)) << 96n);
  let acc = 0n;
  for (let i = 0; i < msg.length; i += 16) {
    const len = Math.min(16, msg.length - i);
    let n = 0n;
    for (let j = len - 1; j >= 0; j--) {
      n = (n << 8n) | BigInt(msg[i + j]!);
    }
    n = (n | (1n << BigInt(8 * len))) & mask; // append the length byte
    acc = (acc + n) * r % p;
  }
  acc = (acc + s) & ((1n << 128n) - 1n);
  const out = new Uint8Array(16);
  const odv = new DataView(out.buffer, out.byteOffset, out.byteLength);
  const lo = acc & 0xffffffffn;
  const mid = (acc >> 32n) & 0xffffffffn;
  const hi = (acc >> 64n) & 0xffffffffn;
  const top = acc >> 96n;
  odv.setUint32(0, Number(lo), true);
  odv.setUint32(4, Number(mid), true);
  odv.setUint32(8, Number(hi), true);
  odv.setUint32(12, Number(top), true);
  return out;
}

function pad16(data: Uint8Array): Uint8Array {
  if (data.length % 16 === 0) return new Uint8Array(0);
  return new Uint8Array(16 - (data.length % 16));
}

function le64(n: number): Uint8Array {
  const out = new Uint8Array(8);
  const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
  dv.setBigUint64(0, BigInt(n), true);
  return out;
}

/** RFC 8439 §2.8 AEAD seal. Returns ciphertext||tag. */
export function aeadSeal(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const counter = 1;
  const otk = chachaBlock(
    (() => {
      const k = new Uint32Array(8);
      const kd = new DataView(key.buffer, key.byteOffset, key.byteLength);
      for (let i = 0; i < 8; i++) k[i] = kd.getUint32(i * 4, true);
      return k;
    })(),
    0,
    (() => {
      const n = new Uint32Array(3);
      const nd = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
      for (let i = 0; i < 3; i++) n[i] = nd.getUint32(i * 4, true);
      return n;
    })(),
  ).subarray(0, 32);
  const ciphertext = chacha20(key, counter, nonce, plaintext);
  const macData = new Uint8Array(
    aad.length + pad16(aad).length + ciphertext.length + pad16(ciphertext).length + 16,
  );
  let off = 0;
  macData.set(aad, off); off += aad.length;
  macData.set(pad16(aad), off); off += pad16(aad).length;
  macData.set(ciphertext, off); off += ciphertext.length;
  macData.set(pad16(ciphertext), off); off += pad16(ciphertext).length;
  macData.set(le64(aad.length), off); off += 8;
  macData.set(le64(ciphertext.length), off);
  const tag = poly1305(otk, macData);
  const out = new Uint8Array(ciphertext.length + 16);
  out.set(ciphertext, 0);
  out.set(tag, ciphertext.length);
  return out;
}

/** RFC 8439 §2.8 AEAD open. Throws on tag mismatch. */
export function aeadOpen(
  key: Uint8Array,
  nonce: Uint8Array,
  aad: Uint8Array,
  sealed: Uint8Array,
): Uint8Array {
  if (sealed.length < 16) throw new Error("ciphertext too short");
  const ciphertext = sealed.subarray(0, sealed.length - 16);
  const tag = sealed.subarray(sealed.length - 16);
  const recomputed = aeadSeal(key, nonce, aad, ciphertext);
  const expectedTag = recomputed.subarray(ciphertext.length);
  // constant-time-ish compare
  let diff = 0;
  for (let i = 0; i < 16; i++) diff |= tag[i]! ^ expectedTag[i]!;
  if (diff !== 0) throw new Error("tag mismatch");
  return chacha20(key, 1, nonce, ciphertext);
}

// ---------------------------------------------------------------------------
// RFC 8439 §2.5.2 self-test (Poly1305) + §2.4.2 (ChaCha20) at import time is
// skipped; correctness is pinned by the cross-language vector diff.
// ---------------------------------------------------------------------------
export const _internal = { chachaBlock, chacha20, poly1305 };
