"""ShareNet ContributionReceipt — Python conformance implementation (R8-001).

The receipt is the bilateral recipient-signed acknowledgement: the RECEIVING
counterparty (the issuer) signs, the contributor can never be the issuer,
and receipt_id = SHA-256(canonical receipt bytes) — the commitment-derived
identity (L013), so any change is a different named object. The runner
mirrors the registry admission rule in the Rust core's evaluation order
(signature, future clock, receipt_id idempotency, the per-(issuer,
contributor) monotonic sequence law).
"""

from __future__ import annotations

import hashlib

from .cbor import CborMap, encode

# The frozen v1 contribution kinds (machine names shared with the Rust core).
KINDS = ["carried", "delivered"]

RECEIPT_SEQ_MIN = 1
DELIVERED_BYTES_MAX = 1 << 40


def receipt_id(receipt: bytes) -> bytes:
    """receipt_id = SHA-256(canonical receipt bytes) — the named object."""
    return hashlib.sha256(receipt).digest()


def build_receipt(
    public_key: bytes,
    created_at: int,
    contributor_node_id: bytes,
    content_id: bytes,
    kind: str,
    delivered_bytes: int,
    receipt_seq: int,
    issued_at: int,
) -> bytes:
    """The canonical receipt bytes (the registry schema):
    {1: scheme (=1), 2: issuer NodeIdentity, 3: contributor_node_id,
     4: content_id, 5: kind, 6: delivered_bytes, 7: receipt_seq,
     8: issued_at_unix}.
    """
    # the issuer NodeIdentity rides as a NESTED canonical map (field 2),
    # never as a bstr-wrapped pre-encoding (the byte-exactness law — the
    # same discipline as the connectivity evidence leg)
    identity = CborMap([(1, 1), (2, public_key), (3, created_at)])
    entries: list = [
        (1, 1),
        (2, identity),
        (3, contributor_node_id),
        (4, content_id),
        (5, kind),
        (6, delivered_bytes),
        (7, receipt_seq),
        (8, issued_at),
    ]
    return encode(CborMap(entries))


def build_envelope(receipt: bytes, signature: bytes) -> bytes:
    """The carrying envelope: {1: receipt (bstr), 2: signature (64-byte bstr)}."""
    return encode(CborMap([(1, receipt), (2, signature)]))
