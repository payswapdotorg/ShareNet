"""ShareNet authenticated links — Python conformance implementation
(R3-003 conformance legs; object defined by R3-001 in the Rust core).

Re-implements the registered handshake + frame derivation with the
stdlib (hashlib/hmac) plus the in-tree pure-Python X25519 and
ChaCha20-Poly1305. Conformance only.
"""

from __future__ import annotations

import hashlib
import hmac

from . import chacha20poly1305 as aead
from . import x25519
from .cbor import CborMap, encode

RESPONDER_SIGN_CONTEXT = b"sharenet-link-auth-v1/responder"
INITIATOR_SIGN_CONTEXT = b"sharenet-link-auth-v1/initiator"
HKDF_INFO = b"sharenet-link-session-v1"
LINK_ID_CONTEXT = b"sharenet-link-id-v1"
FRAME_AAD_CONTEXT = b"sharenet-link-frame-v1"


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def build_msg1(e_initiator: bytes) -> bytes:
    return encode(CborMap([(1, 1), (2, e_initiator)]))


def build_msg2_content(
    e_responder: bytes, identity_pk: bytes, identity_created: int, capabilities: bytes | None
) -> bytes:
    identity = CborMap(
        [
            (1, 1),
            (2, identity_pk),
            (3, identity_created),
        ]
    )
    entries = [
        (1, 1),
        (2, e_responder),
        (3, identity),
    ]
    if capabilities is not None:
        entries.append((5, capabilities))
    return encode(CborMap(entries))


def build_msg2(
    e_responder: bytes,
    identity_pk: bytes,
    identity_created: int,
    capabilities: bytes | None,
    signature: bytes,
) -> bytes:
    identity = CborMap(
        [
            (1, 1),
            (2, identity_pk),
            (3, identity_created),
        ]
    )
    entries = [
        (1, 1),
        (2, e_responder),
        (3, identity),
        (4, signature),
    ]
    if capabilities is not None:
        entries.append((5, capabilities))
    return encode(CborMap(entries))


def build_msg3_content(
    identity_pk: bytes, identity_created: int, capabilities: bytes | None
) -> bytes:
    identity = CborMap(
        [
            (1, 1),
            (2, identity_pk),
            (3, identity_created),
        ]
    )
    entries = [
        (1, 1),
        (2, identity),
    ]
    if capabilities is not None:
        entries.append((4, capabilities))
    return encode(CborMap(entries))


def build_msg3(
    identity_pk: bytes,
    identity_created: int,
    capabilities: bytes | None,
    signature: bytes,
) -> bytes:
    identity = CborMap(
        [
            (1, 1),
            (2, identity_pk),
            (3, identity_created),
        ]
    )
    entries = [
        (1, 1),
        (2, identity),
        (3, signature),
    ]
    if capabilities is not None:
        entries.append((4, capabilities))
    return encode(CborMap(entries))


def responder_sign_payload(msg1: bytes, msg2_content: bytes) -> bytes:
    return sha256(RESPONDER_SIGN_CONTEXT, msg1, msg2_content)


def initiator_sign_payload(msg1: bytes, msg2: bytes, msg3_content: bytes) -> bytes:
    return sha256(INITIATOR_SIGN_CONTEXT, msg1, msg2, msg3_content)


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    # RFC 5869 (extract + expand) over hmac-sha256
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def derive_session(shared: bytes, msg1: bytes, msg2: bytes, msg3: bytes):
    salt = sha256(msg1, msg2, msg3)
    okm = hkdf_sha256(shared, salt, HKDF_INFO, 64)
    key_i2r, key_r2i = okm[:32], okm[32:]
    link_id = sha256(LINK_ID_CONTEXT, msg1, msg2, msg3)
    return link_id, key_i2r, key_r2i


def seal_frame(
    key: bytes, link_id: bytes, direction: int, seq: int, payload: bytes
) -> bytes:
    nonce = b"\x00\x00\x00\x00" + seq.to_bytes(8, "big")
    aad = FRAME_AAD_CONTEXT + link_id + bytes([direction]) + seq.to_bytes(8, "big")
    sealed = aead.aead_seal(key, nonce, aad, payload)
    return seq.to_bytes(8, "big") + sealed
