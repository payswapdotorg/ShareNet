"""ShareNet circuit revocation — Python conformance leg (R7-001)."""

from .cbor import CborMap, encode


def _identity(pub: bytes, created_at_unix: int) -> CborMap:
    # nested map (NOT the encoded identity wire bytes)
    return CborMap([(1, 1), (2, bytes(pub)), (3, created_at_unix)])


def build_revocation(circuit_id: bytes, public_key: bytes, created_at_unix: int,
                     reason: str, evidence, revoked_at_unix: int) -> bytes:
    """CircuitRevocation wire: {1: scheme, 2: circuit_id, 3: revoker, 4: reason,
    5: evidence (optional map text -> int|text), 6: revoked_at}.

    The evidence map (when present) MUST carry a "failure_kind" text entry
    plus at most 8 further int/text fields; None = the absent legal form.
    """
    entries = [
        (1, 1),
        (2, circuit_id),
        (3, _identity(public_key, created_at_unix)),
        (4, reason),
    ]
    if evidence is not None:
        entries.append((5, CborMap([(k, v) for (k, v) in sorted(evidence.items())])))
    entries.append((6, revoked_at_unix))
    return encode(CborMap(entries))


def revocation_envelope(revocation: bytes, signature: bytes) -> bytes:
    """The carrying envelope: {1: revocation (bstr), 2: signature (64-byte bstr)}."""
    return encode(CborMap([(1, revocation), (2, signature)]))
