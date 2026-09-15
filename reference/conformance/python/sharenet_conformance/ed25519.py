"""Pure-Python Ed25519 (RFC 8032) — conformance leg only.

Adapted from the algorithm description in RFC 8032 §5.1 (the normative
reference; the shape follows the standard derivation). This implementation
is deliberately dependency-free (stdlib only) so the conformance harness can
run anywhere Python runs. It is NOT constant-time and MUST NOT be used for
production signing: the ShareNet protocol core (Rust, ed25519-dalek) is the
cryptographic authority. Here it exists to independently reproduce the
deterministic signatures and verifications of the committed vectors.

Verification enforces the RFC 8032 checks: S in [0, L), canonical point
decoding (y < p; x=0 with sign bit set rejected).
"""

from __future__ import annotations

import hashlib

p = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
d = (-121665 * pow(121666, p - 2, p)) % p
I = pow(2, (p - 1) // 4, p)


def _inv(x: int) -> int:
    return pow(x, p - 2, p)


def _xrecover(y: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1) % p
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = (x * I) % p
    if (x * x - xx) % p != 0:
        raise ValueError("point is not on the curve")
    if x % 2 != 0:
        x = p - x
    return x


_By = (4 * _inv(5)) % p
_Bx = _xrecover(_By)
_B = (_Bx, _By, 1, (_Bx * _By) % p)  # extended coordinates (X, Y, Z, T)
_IDENT = (0, 1, 1, 0)


def _edwards_add(P, Q):
    (x1, y1, z1, t1) = P
    (x2, y2, z2, t2) = Q
    a = (y1 - x1) * (y2 - x2) % p
    b = (y1 + x1) * (y2 + x2) % p
    c = t1 * 2 * d * t2 % p
    dd = z1 * 2 * z2 % p
    e = b - a
    f = dd - c
    g = dd + c
    h = b + a
    return (e * f % p, g * h % p, f * g % p, e * h % p)


def _scalarmult(P, e: int):
    if e == 0:
        return _IDENT
    Q = _IDENT
    for bit in bin(e)[2:]:
        Q = _edwards_add(Q, Q)
        if bit == "1":
            Q = _edwards_add(Q, P)
    return Q


def _point_compress(P) -> bytes:
    (x, y, z, _) = P
    zi = _inv(z)
    x = x * zi % p
    y = y * zi % p
    return ((int(y) | ((int(x) & 1) << 255))).to_bytes(32, "little")


def _point_decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    if y >= p:
        return None
    x = _xrecover(y)
    if x == 0 and sign == 1:
        return None  # non-canonical encoding of a small-order point
    if x % 2 != sign:
        x = p - x
    return (x, y, 1, (x * y) % p)


def _sha512(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _secret_expand(seed: bytes):
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _sha512(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return (a, h[32:])


def public_key(seed: bytes) -> bytes:
    (a, _) = _secret_expand(seed)
    return _point_compress(_scalarmult(_B, a))


def sign(seed: bytes, msg: bytes) -> bytes:
    (a, prefix) = _secret_expand(seed)
    A = _point_compress(_scalarmult(_B, a))
    r = int.from_bytes(_sha512(prefix + msg), "little") % L
    R = _point_compress(_scalarmult(_B, r))
    h = int.from_bytes(_sha512(R + A + msg), "little") % L
    s = (r + h * a) % L
    return R + s.to_bytes(32, "little")


def verify(public: bytes, msg: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    A = _point_decompress(public)
    if A is None:
        return False
    Rs = signature[:32]
    R = _point_decompress(Rs)
    if R is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    h = int.from_bytes(_sha512(Rs + public + msg), "little") % L
    sB = _scalarmult(_B, s)
    hA = _scalarmult(A, h)
    RhA = _edwards_add(R, hA)
    return _point_equal(sB, RhA)


def _point_equal(P, Q) -> bool:
    # points in extended coordinates are equal iff x1*z2 == x2*z1 and
    # y1*z2 == y2*z1 (projective equality)
    (x1, y1, z1, _) = P
    (x2, y2, z2, _) = Q
    if (x1 * z2 - x2 * z1) % p != 0:
        return False
    if (y1 * z2 - y2 * z1) % p != 0:
        return False
    return True
