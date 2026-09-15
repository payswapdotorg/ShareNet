"""ShareNet route commitment — Python conformance leg (R3-004)."""

from __future__ import annotations

import hashlib

from .cbor import CborMap, encode
from .identity import node_identity_wire


def _sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def build_proposal(pub: bytes, created: int, path: list[bytes], service: str,
                   proposed_at: int, validity: int, nonce: bytes) -> bytes:
    sorted_path = sorted(path)
    identity = CborMap([(1, 1), (2, pub), (3, created)])
    return encode(
        CborMap(
            [
                (1, 1),
                (2, identity),
                (3, sorted_path),
                (4, service),
                (5, proposed_at),
                (6, proposed_at + validity),
                (7, nonce),
            ]
        )
    )


def build_acceptance(proposal_id: bytes, pub: bytes, created: int, position: int,
                     accepted_at: int, validity: int) -> bytes:
    identity = CborMap([(1, 1), (2, pub), (3, created)])
    return encode(
        CborMap(
            [
                (1, 1),
                (2, proposal_id),
                (3, identity),
                (4, position),
                (5, accepted_at),
                (6, accepted_at + validity),
            ]
        )
    )


def envelope(inner: bytes, signature: bytes) -> bytes:
    return encode(CborMap([(1, inner), (2, signature)]))


def proposal_id_of(proposal: bytes) -> bytes:
    return _sha256(proposal)


def merkle_root(leaves: list[bytes]) -> bytes | None:
    if not leaves:
        return None
    if len(leaves) == 1:
        return _sha256(leaves[0], leaves[0])
    level = list(leaves)
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            a = level[i]
            b = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(_sha256(a, b))
        level = nxt
    return level[0]


def derive_route_id(root: bytes) -> bytes:
    return _sha256(b"sharenet-route-id-v1", root)
