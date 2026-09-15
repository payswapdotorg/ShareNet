"""ShareNet route-to-circuit binding — Python conformance leg (R4-002)."""

import hashlib

from .cbor import CborMap, encode


def _identity(pub: bytes, created_at_unix: int) -> CborMap:
    # nested map (NOT the encoded identity wire bytes)
    return CborMap([(1, 1), (2, bytes(pub)), (3, created_at_unix)])


def build_setup(commitment_wire: bytes, setup_nonce: bytes, public_key: bytes,
                created_at_unix: int, issued_at_unix: int, validity_secs: int) -> bytes:
    """CircuitSetup wire: {1: scheme, 2: commitment, 3: nonce, 4: initiator, 5: issued, 6: expires}."""
    return encode(
        CborMap(
            [
                (1, 1),
                (2, commitment_wire),
                (3, setup_nonce),
                (4, _identity(public_key, created_at_unix)),
                (5, issued_at_unix),
                (6, issued_at_unix + validity_secs),
            ]
        )
    )


def build_ack(circuit_id: bytes, setup_envelope: bytes, public_key: bytes,
              created_at_unix: int, position: int, accepted_at_unix: int,
              validity_secs: int) -> bytes:
    """CircuitSetupAck wire: {1: scheme, 2: circuit_id, 3: setup_digest, 4: accepting,
    5: position, 6: accepted_at, 7: expires_at}."""
    return encode(
        CborMap(
            [
                (1, 1),
                (2, circuit_id),
                (3, hashlib.sha256(setup_envelope).digest()),
                (4, _identity(public_key, created_at_unix)),
                (5, position),
                (6, accepted_at_unix),
                (7, accepted_at_unix + validity_secs),
            ]
        )
    )


def build_frame(circuit_id: bytes, direction: int, seq: int, payload: bytes) -> bytes:
    """CircuitFrame wire: {1: scheme, 2: circuit_id, 3: direction, 4: seq, 5: payload}."""
    return encode(
        CborMap(
            [
                (1, 1),
                (2, circuit_id),
                (3, direction),
                (4, seq),
                (5, payload),
            ]
        )
    )


def build_destroy(circuit_id: bytes, public_key: bytes, created_at_unix: int,
                  reason: str, destroyed_at_unix: int) -> bytes:
    """CircuitDestroy wire: {1: scheme, 2: circuit_id, 3: sender, 4: reason, 5: destroyed_at}."""
    return encode(
        CborMap(
            [
                (1, 1),
                (2, circuit_id),
                (3, _identity(public_key, created_at_unix)),
                (4, reason),
                (5, destroyed_at_unix),
            ]
        )
    )


def derive_circuit_id(route_id: bytes, setup_nonce: bytes) -> bytes:
    """circuit_id = SHA-256("sharenet-circuit-id-v1" || route_id || setup_nonce)."""
    return hashlib.sha256(
        b"sharenet-circuit-id-v1" + route_id + setup_nonce
    ).digest()


def commitment_wire(proposal_env: bytes, acceptance_envs, root: bytes, route_id: bytes) -> bytes:
    """RouteCommitment wire: {1: scheme, 2: proposal env, 3: acceptance envs,
    4: root, 5: route_id}."""
    return encode(
        CborMap(
            [
                (1, 1),
                (2, proposal_env),
                (3, list(acceptance_envs)),
                (4, root),
                (5, route_id),
            ]
        )
    )
