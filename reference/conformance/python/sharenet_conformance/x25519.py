"""Pure-Python X25519 (RFC 7748) — conformance leg only.

Reference implementation of the Montgomery ladder from RFC 7748 §5.
Not constant-time; conformance only (the Rust core is the authority).
"""

from __future__ import annotations

P = 2**255 - 19
A24 = 121665


def clamp_scalar(k: bytes) -> int:
    v = bytearray(k)
    v[0] &= 248
    v[31] &= 127
    v[31] |= 64
    return int.from_bytes(bytes(v), "little")


def x25519(scalar: bytes, u: bytes) -> bytes:
    """RFC 7748 §5 scalar multiplication of the point u (32 bytes)."""
    k = clamp_scalar(scalar)
    x1 = int.from_bytes(u, "little") & ((1 << 255) - 1)
    x2, z2 = 1, 0
    x3, z3 = x1, 1
    swap = 0
    for t in reversed(range(255)):
        k_t = (k >> t) & 1
        swap ^= k_t
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = k_t
        a = (x2 + z2) % P
        aa = (a * a) % P
        b = (x2 - z2) % P
        bb = (b * b) % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = (d * a) % P
        cb = (c * b) % P
        x3 = (da + cb) % P
        x3 = (x3 * x3) % P
        t_ = (da - cb) % P
        z3 = (x1 * t_ * t_) % P
        x2 = (aa * bb) % P
        z2 = (e * (aa + A24 * e)) % P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, P - 2, P)) % P).to_bytes(32, "little")


BASE_POINT = (9).to_bytes(32, "little")


def public_from_scalar(scalar: bytes) -> bytes:
    return x25519(scalar, BASE_POINT)


def shared(scalar: bytes, peer_public: bytes) -> bytes:
    return x25519(scalar, peer_public)
