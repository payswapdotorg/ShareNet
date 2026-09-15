"""Pure-Python ChaCha20-Poly1305 AEAD (RFC 8439) — conformance leg only.

Reference implementation of §2.4 (ChaCha20), §2.5 (Poly1305) and §2.8
(the AEAD construction). Not hardened; the Rust core (RustCrypto) is the
production authority. Correctness is pinned by the cross-language vectors.
"""

from __future__ import annotations

import struct

MASK32 = 0xFFFFFFFF


def _rotl(v: int, c: int) -> int:
    return ((v << c) | (v >> (32 - c))) & MASK32


def _quarter(state: list, a: int, b: int, c: int, d: int) -> None:
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl(state[d] ^ state[a], 16)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl(state[b] ^ state[c], 12)
    state[a] = (state[a] + state[b]) & MASK32
    state[d] = _rotl(state[d] ^ state[a], 8)
    state[c] = (state[c] + state[d]) & MASK32
    state[b] = _rotl(state[b] ^ state[c], 7)


def _chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    consts = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state = (
        consts
        + list(struct.unpack("<8I", key[:32]))
        + [counter & MASK32]
        + list(struct.unpack("<3I", nonce[:12]))
    )
    w = list(state)
    for _ in range(10):
        _quarter(w, 0, 4, 8, 12)
        _quarter(w, 1, 5, 9, 13)
        _quarter(w, 2, 6, 10, 14)
        _quarter(w, 3, 7, 11, 15)
        _quarter(w, 0, 5, 10, 15)
        _quarter(w, 1, 6, 11, 12)
        _quarter(w, 2, 7, 8, 13)
        _quarter(w, 3, 4, 9, 14)
    out = b""
    for i in range(16):
        out += struct.pack("<I", (w[i] + state[i]) & MASK32)
    return out


def _chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for off in range(0, len(data), 64):
        block = _chacha_block(key, counter + off // 64, nonce)
        chunk = data[off : off + 64]
        out.extend(x ^ y for x, y in zip(chunk, block))
    return bytes(out)


def _poly1305(key: bytes, msg: bytes) -> bytes:
    p = (1 << 130) - 5
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i : i + 16]
        n = int.from_bytes(block, "little") | (1 << (8 * len(block)))
        acc = ((acc + n) * r) % p
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def _pad16(data: bytes) -> bytes:
    if len(data) % 16 == 0:
        return b""
    return b"\x00" * (16 - len(data) % 16)


def aead_seal(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """RFC 8439 §2.8: returns ciphertext || tag."""
    otk = _chacha_block(key, 0, nonce)[:32]
    ciphertext = _chacha20(key, 1, nonce, plaintext)
    mac = (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )
    tag = _poly1305(otk, mac)
    return ciphertext + tag


def aead_open(key: bytes, nonce: bytes, aad: bytes, sealed: bytes) -> bytes:
    """RFC 8439 §2.8: verifies the tag; raises ValueError on mismatch."""
    if len(sealed) < 16:
        raise ValueError("ciphertext too short")
    ciphertext, tag = sealed[:-16], sealed[-16:]
    otk = _chacha_block(key, 0, nonce)[:32]
    mac = (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + struct.pack("<Q", len(aad))
        + struct.pack("<Q", len(ciphertext))
    )
    expected = _poly1305(otk, mac)
    if not _ct_eq(tag, expected):
        raise ValueError("tag mismatch")
    return _chacha20(key, 1, nonce, ciphertext)


def _ct_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0
