"""ShareNet TopologyEvidence — Python conformance implementation (R3-003)."""

from __future__ import annotations

import hashlib

from .cbor import CborMap, encode
from .identity import node_identity_wire


def build_evidence(
    seed: bytes,
    created_at: int,
    subject_node_id: bytes,
    kind: str,
    observed_at: int,
    validity_secs: int,
    link: dict | None = None,
    advertisement: dict | None = None,
) -> bytes:
    from . import ed25519

    pub = ed25519.public_key(seed)
    identity = CborMap([(1, 1), (2, pub), (3, created_at)])
    if kind == "link":
        q = link["quality"]
        obs = CborMap(
            [
                (1, link["link_id"]),
                (2, link["established_at"]),
                (3, q["delivered"]),
                (4, q["lost"]),
                (5, q["ewma_rtt_micros"]),
                (6, q["p50_rtt_micros"]),
                (7, q["p95_rtt_micros"]),
                (8, q["jitter_mad_micros"]),
                (9, q["loss_ratio_ppm"]),
            ]
        )
    else:
        obs = CborMap(
            [
                (1, advertisement["advertisement_id"]),
                (2, advertisement["capabilities"]),
            ]
        )
    entries: list = [
        (1, 1),
        (2, identity),
        (3, subject_node_id),
        (4, kind),
        (5, observed_at),
        (6, observed_at + validity_secs),
        (7, obs),
    ]
    return encode(CborMap(entries))


def evidence_id(wire: bytes) -> bytes:
    return hashlib.sha256(wire).digest()


def build_envelope(evidence: bytes, signature: bytes) -> bytes:
    return encode(CborMap([(1, evidence), (2, signature)]))
