"""ShareNet CapabilityStatement — Python conformance implementation
(R1-003; object defined by R1-004 in the Rust reference core).

Schema and admission rule identical to the Rust core; error names match
``CapabilityError::name()`` / ``AdmissionError::name()`` for the
cross-language diff.
"""

from __future__ import annotations

from . import ed25519
from .cbor import CborMap, decode, encode
from .identity import derive_node_id

CAP_SCHEME_VERSION = 1
MAX_LIMITS_ENTRIES = 32
MAX_LIMIT_KEY_BYTES = 64

WIRE_TEXTS = ("dtn_custodian", "gateway", "infrastructure", "relay")

I64_MAX = 2**63 - 1


class CapabilityError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class AdmissionError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _check_timestamp(field: str, t: int) -> None:
    if t < 0:
        raise CapabilityError("timestamp_negative", f"{field} negative")
    if t > I64_MAX:
        raise CapabilityError("timestamp_out_of_range", f"{field} out of range")


def build_statement(
    node_id: bytes,
    capabilities: list[str],
    issued_at: int,
    expires_at: int,
    limits: dict[str, int] | None,
) -> bytes:
    if not capabilities:
        raise CapabilityError("capabilities_empty", "empty capabilities")
    sorted_caps = sorted(set(capabilities))
    if len(sorted_caps) != len(capabilities):
        raise CapabilityError("capabilities_not_sorted", "duplicate capabilities")
    for c in sorted_caps:
        if c not in WIRE_TEXTS:
            raise CapabilityError("unknown_capability", f"unknown capability {c}")
    if expires_at <= issued_at:
        raise CapabilityError("expiry_not_after_issue", "expires_at must follow issued_at")
    _check_timestamp("issued_at", issued_at)
    _check_timestamp("expires_at", expires_at)
    if limits is not None:
        if len(limits) > MAX_LIMITS_ENTRIES:
            raise CapabilityError("limits_too_many_entries", "too many limits")
        for k in limits:
            b = k.encode("utf-8")
            if len(b) == 0 or len(b) > MAX_LIMIT_KEY_BYTES:
                raise CapabilityError("limit_key_invalid", "limit key length invalid")
    entries = [
        (1, CAP_SCHEME_VERSION),
        (2, bytes(node_id)),
        (3, sorted_caps),
        (4, issued_at),
        (5, expires_at),
    ]
    if limits is not None:
        entries.append((6, CborMap(sorted((k, v) for k, v in limits.items()))))
    return encode(CborMap(entries))


class ParsedStatement:
    __slots__ = ("node_id", "capabilities", "issued_at_unix", "expires_at_unix", "limits")

    def __init__(self, node_id, capabilities, issued_at, expires_at, limits):
        self.node_id = node_id
        self.capabilities = capabilities
        self.issued_at_unix = issued_at
        self.expires_at_unix = expires_at
        self.limits = limits


def _from_wire(v):
    if not isinstance(v, CborMap):
        raise CapabilityError("not_a_map", "statement must be a map")
    scheme = None
    node_id = None
    capabilities = None
    issued_at = None
    expires_at = None
    limits = None
    for k, val in v:
        if not isinstance(k, int) or isinstance(k, bool):
            raise CapabilityError("key_not_an_integer", "non-integer key")
        if k == 1:
            if scheme is not None:
                raise CapabilityError("duplicate_field", "duplicate field 1")
            if not isinstance(val, int) or isinstance(val, bool):
                raise CapabilityError("field_not_expected_type", "field 1 type")
            if val != CAP_SCHEME_VERSION:
                raise CapabilityError("scheme_version_unsupported", "scheme version")
            scheme = val
        elif k == 2:
            if node_id is not None:
                raise CapabilityError("duplicate_field", "duplicate field 2")
            if not isinstance(val, (bytes, bytearray)):
                raise CapabilityError("field_not_expected_type", "field 2 type")
            if len(val) != 32:
                raise CapabilityError("node_id_wrong_length", "node_id length")
            node_id = bytes(val)
        elif k == 3:
            if capabilities is not None:
                raise CapabilityError("duplicate_field", "duplicate field 3")
            if not isinstance(val, list):
                raise CapabilityError("field_not_expected_type", "field 3 type")
            if not val:
                raise CapabilityError("capabilities_empty", "empty capabilities")
            caps = []
            for i, item in enumerate(val):
                if not isinstance(item, str):
                    raise CapabilityError("capability_not_text", "capability not text")
                if i > 0 and not (item > caps[i - 1]):
                    raise CapabilityError(
                        "capabilities_not_sorted", "unsorted or duplicate capabilities"
                    )
                if item not in WIRE_TEXTS:
                    raise CapabilityError("unknown_capability", f"unknown capability {item}")
                caps.append(item)
            capabilities = caps
        elif k == 4:
            if issued_at is not None:
                raise CapabilityError("duplicate_field", "duplicate field 4")
            if not isinstance(val, int) or isinstance(val, bool):
                raise CapabilityError("field_not_expected_type", "field 4 type")
            if val < 0:
                raise CapabilityError("timestamp_negative", "issued_at negative")
            issued_at = val
        elif k == 5:
            if expires_at is not None:
                raise CapabilityError("duplicate_field", "duplicate field 5")
            if not isinstance(val, int) or isinstance(val, bool):
                raise CapabilityError("field_not_expected_type", "field 5 type")
            if val < 0:
                raise CapabilityError("timestamp_negative", "expires_at negative")
            expires_at = val
        elif k == 6:
            if limits is not None:
                raise CapabilityError("duplicate_field", "duplicate field 6")
            if not (isinstance(val, list) and all(isinstance(e, tuple) for e in val)):
                raise CapabilityError("field_not_expected_type", "field 6 type")
            if len(val) > MAX_LIMITS_ENTRIES:
                raise CapabilityError("limits_too_many_entries", "too many limits")
            m: dict[str, int] = {}
            for lk, lv in val:
                if not isinstance(lk, str) or not isinstance(lv, int) or isinstance(lv, bool):
                    raise CapabilityError("limit_entry_malformed", "limit entry malformed")
                b = lk.encode("utf-8")
                if len(b) == 0 or len(b) > MAX_LIMIT_KEY_BYTES:
                    raise CapabilityError("limit_key_invalid", "limit key length")
                m[lk] = lv
            limits = m
        else:
            raise CapabilityError("unknown_field", f"unknown field {k}")
    if scheme is None:
        raise CapabilityError("missing_field", "missing field 1")
    if node_id is None:
        raise CapabilityError("missing_field", "missing field 2")
    if capabilities is None:
        raise CapabilityError("missing_field", "missing field 3")
    if issued_at is None:
        raise CapabilityError("missing_field", "missing field 4")
    if expires_at is None:
        raise CapabilityError("missing_field", "missing field 5")
    if expires_at <= issued_at:
        raise CapabilityError("expiry_not_after_issue", "expiry must follow issue")
    return ParsedStatement(node_id, capabilities, issued_at, expires_at, limits)


def parse_statement(data: bytes) -> ParsedStatement:
    try:
        v = decode(data)
    except Exception as e:
        code = getattr(e, "code", "Unknown")
        raise CapabilityError(f"cbor:{code}", f"CBOR profile violation: {e}") from None
    return _from_wire(v)


def admit(
    statement_bytes: bytes,
    signature: bytes,
    public_key: bytes,
    now_unix: int,
    required: list[str],
) -> ParsedStatement:
    try:
        st = parse_statement(statement_bytes)
    except CapabilityError as e:
        raise AdmissionError(f"statement:{e.code}", str(e)) from None
    derived = derive_node_id(public_key)
    if st.node_id != derived:
        raise AdmissionError("node_id_mismatch", "node_id binding failed")
    if len(signature) != 64:
        raise AdmissionError("signature_encoding_invalid", "signature length")
    if not ed25519.verify(public_key, statement_bytes, signature):
        raise AdmissionError("verification_failed", "signature verification failed")
    if now_unix < st.issued_at_unix:
        raise AdmissionError("not_yet_valid", "now < issued_at")
    if now_unix >= st.expires_at_unix:
        raise AdmissionError("expired", "now >= expires_at")
    for c in required:
        if c not in st.capabilities:
            raise AdmissionError("capability_not_held", f"capability {c} not held")
    return st
