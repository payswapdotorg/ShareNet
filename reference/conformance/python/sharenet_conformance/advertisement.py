"""ShareNet Advertisement — Python conformance implementation (R3-002)."""

from __future__ import annotations

import hashlib

from .cbor import CborMap, encode
from .identity import node_identity_wire, public_key as pk_from_seed


def build_advertisement(
    seed: bytes,
    created_at: int,
    capabilities: bytes | None,
    transports: list[dict],
    issued_at: int,
    validity_secs: int,
) -> bytes:
    from . import ed25519

    pub = ed25519.public_key(seed)
    sorted_t = sorted(transports, key=lambda t: (t["kind"], t["endpoint"]))
    identity = CborMap([(1, 1), (2, pub), (3, created_at)])
    entries: list = [
        (1, 1),
        (2, identity),
    ]
    if capabilities is not None:
        entries.append((3, capabilities))
    entries.append(
        (
            4,
            [
                CborMap([(1, t["kind"]), (2, t["endpoint"])])
                for t in sorted_t
            ],
        )
    )
    entries.append((5, issued_at))
    entries.append((6, issued_at + validity_secs))
    return encode(CborMap(entries))


def advertisement_id(wire: bytes) -> bytes:
    return hashlib.sha256(wire).digest()


def build_envelope(advertisement: bytes, signature: bytes) -> bytes:
    return encode(CborMap([(1, advertisement), (2, signature)]))
