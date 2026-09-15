"""ShareNet node identity — Python conformance implementation (R1-003).

node_id = SHA-256(canonical_cbor({1: scheme_version, 2: public_key}));
NodeIdentity wire = {1: 1, 2: public_key, 3: created_at_unix, 4?: display_name}.
"""

from __future__ import annotations

import hashlib

from . import ed25519
from .cbor import CborMap, encode

SCHEME_VERSION = 1
SEED_LEN = 32
PUBLIC_KEY_LEN = 32
SIGNATURE_LEN = 64
NODE_ID_LEN = 32
MAX_DISPLAY_NAME_BYTES = 64


def public_key(seed: bytes) -> bytes:
    return ed25519.public_key(seed)


def derive_node_id(pub: bytes) -> bytes:
    preimage = encode(CborMap([(1, SCHEME_VERSION), (2, bytes(pub))]))
    return hashlib.sha256(preimage).digest()


def node_identity_wire(pub: bytes, created_at_unix: int, display_name: str | None):
    entries = [
        (1, SCHEME_VERSION),
        (2, bytes(pub)),
        (3, created_at_unix),
    ]
    if display_name is not None:
        if len(display_name.encode("utf-8")) > MAX_DISPLAY_NAME_BYTES:
            raise ValueError("display name exceeds 64 bytes")
        entries.append((4, display_name))
    return encode(CborMap(entries))


def sign_detached(seed: bytes, payload: bytes) -> bytes:
    return ed25519.sign(seed, payload)


def verify_detached(pub: bytes, payload: bytes, signature: bytes) -> bool:
    return ed25519.verify(pub, payload, signature)
