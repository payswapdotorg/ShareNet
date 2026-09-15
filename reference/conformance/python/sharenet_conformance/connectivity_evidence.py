"""ShareNet SignedConnectivityObservation — Python conformance implementation (R5-004)."""

from __future__ import annotations

from .cbor import CborMap, encode

# The frozen six adcos.md event machine names (in mapping order).
KINDS = [
    "contract_activated",
    "execution_state_changed",
    "degraded",
    "assurance_available",
    "failover_replan",
    "terminated",
]

SEQUENCE_MIN = 1
EXECUTION_MAX_ENTRIES = 16
EXECUTION_MAX_KEY_BYTES = 64


def build_observation(
    public_key: bytes,
    created_at: int,
    contract_ref: bytes,
    kind: str,
    observed_at: int,
    sequence: int,
    execution: dict[str, int] | None = None,
) -> bytes:
    """The canonical observation statement bytes (the registry schema)."""
    # the provider NodeIdentity rides as a NESTED canonical map (field 2),
    # never as a bstr-wrapped pre-encoding (the byte-exactness law)
    identity = CborMap([(1, 1), (2, public_key), (3, created_at)])
    entries: list = [
        (1, 1),
        (2, identity),
        (3, contract_ref),
        (4, kind),
        (5, observed_at),
        (6, sequence),
    ]
    if execution is not None:
        # canonical CBOR map keys: bytewise-ascending text order
        entries.append((7, CborMap([(k, execution[k]) for k in sorted(execution)])))
    return encode(CborMap(entries))


def build_envelope(observation: bytes, signature: bytes) -> bytes:
    """The carrying envelope: {1: observation (bstr), 2: signature (64-byte bstr)}."""
    return encode(CborMap([(1, observation), (2, signature)]))


class AdmissionError(Exception):
    """Typed admission failure (machine-named, mirroring the Rust core)."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ObservationAdmission:
    """The registry admission rule: parse-order verification with the
    per-(provider node_id, contract_ref) monotonic sequence gate, the
    known-contract set and the accepting node's freshness window.

    The conformance runner only drives the paths the vectors exercise
    (signature, contract, sequence, freshness) on already-built statements;
    the strict CBOR/statement parse is Rust-core scope.
    """

    def __init__(self, freshness_window_secs: int):
        self.window = freshness_window_secs
        self.highest: dict[tuple[bytes, bytes], int] = {}
        self.known: set[bytes] = set()

    def register_contract(self, contract_ref: bytes) -> None:
        self.known.add(contract_ref)

    def receive(
        self,
        provider_node_id: bytes,
        contract_ref: bytes,
        observed_at: int,
        sequence: int,
        signature_ok: bool,
        now_unix: int,
    ) -> str:
        """Returns "admitted" / "sequence_stale" or raises AdmissionError."""
        if not signature_ok:
            raise AdmissionError("signature_invalid")
        if contract_ref not in self.known:
            raise AdmissionError("contract_unknown")
        key = (provider_node_id, contract_ref)
        if key in self.highest and sequence <= self.highest[key]:
            return "sequence_stale"
        if now_unix < observed_at:
            raise AdmissionError("not_yet_valid")
        if now_unix >= observed_at + self.window:
            raise AdmissionError("expired")
        self.highest[key] = sequence
        return "admitted"
