#!/usr/bin/env python3
"""One-shot generator for connectivity_evidence_vectors.json (R5-004).

Builds every case with the SAME Python conformance modules the harness leg
uses (ed25519 + cbor + connectivity_evidence), so the committed expected
hex is exactly what the legs re-derive. The cross-language harness then
re-derives everything again in Rust and TypeScript — the committed hex is
never trusted by the harness (each leg recomputes and the three-way diff
catches any drift).

Usage: python3 gen_connectivity_vectors.py   (from reference/conformance/)
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "python"))

from sharenet_conformance import connectivity_evidence as ce
from sharenet_conformance import ed25519
from sharenet_conformance.cbor import CborMap, encode

SEED_A = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
SEED_B = bytes.fromhex(
    "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
)
# A third identity used ONLY for the foreign-signer mutation (never a case
# provider, so its signature can never be the right one).
SEED_FOREIGN = bytes([0xEE] * 32)

CONTRACT_X = bytes([0x01] * 32)
CONTRACT_Y = bytes([0x02] * 32)
CONTRACT_Z = bytes([0x03] * 32)

CASES = [
    # (note, seed, created_at, contract, kind, observed_at, sequence, execution)
    ("contract_activated, minimal, no execution map",
     SEED_A, 0, CONTRACT_X, "contract_activated", 1000, 1, None),
    ("execution_state_changed with an execution counter map",
     SEED_A, 0, CONTRACT_X, "execution_state_changed", 1010, 2,
     {"uplink_bytes": 2048, "active_sessions": 1}),
    ("degraded, no execution map",
     SEED_A, 0, CONTRACT_X, "degraded", 1020, 3, None),
    ("assurance_available with a single counter",
     SEED_A, 0, CONTRACT_X, "assurance_available", 1030, 4,
     {"assurance_level": 3}),
    ("failover_replan, no execution map",
     SEED_A, 0, CONTRACT_X, "failover_replan", 1040, 5, None),
    ("terminated, no execution map",
     SEED_A, 0, CONTRACT_X, "terminated", 1050, 6, None),
    ("cross-contract: same provider, same sequence, different contract",
     SEED_A, 0, CONTRACT_Y, "assurance_available", 1005, 1, None),
    ("cross-provider: same contract, same sequence, different provider",
     SEED_B, 1, CONTRACT_X, "degraded", 1015, 1, {"reconnects": 2}),
    ("contract never registered at the accepting node (unknown contract)",
     SEED_A, 0, CONTRACT_Z, "failover_replan", 1060, 9, None),
    ("freshness-window probe (zero window + bound edge)",
     SEED_A, 0, CONTRACT_Z, "degraded", 1070, 10, None),
]

# (case, now_unix, window_secs, contract_known, mutation, expect)
# All entries share ONE accepting-node policy (window 600) and ONE
# admission tracker — the sequence namespace is (provider node_id,
# contract_ref), so the receive order IS the test.
RECEIVE = [
    (0, 1050, 600, True, None, "admitted"),
    (0, 1050, 600, True, None, "sequence_stale"),
    (1, 1050, 600, True, None, "admitted"),
    (3, 1060, 600, True, None, "admitted"),
    (2, 1060, 600, True, None, "sequence_stale"),
    (6, 1060, 600, True, None, "admitted"),
    (8, 1070, 600, False, None, "contract_unknown"),
    (8, 999, 600, True, None, "not_yet_valid"),
    (8, 1120, 600, True, None, "admitted"),
    (9, 1670, 600, True, None, "expired"),
    (9, 1669, 600, True, None, "admitted"),
    (4, 1040, 600, True, None, "admitted"),
    (7, 1060, 600, True, None, "admitted"),
    (0, 1060, 600, True, "tamper_signature", "signature_invalid"),
    (1, 1060, 600, True, "foreign_signer", "signature_invalid"),
    (5, 1050, 600, True, None, "admitted"),
    (5, 1050, 600, True, None, "sequence_stale"),
]


def build_case(idx):
    (note, seed, created_at, contract, kind, observed_at, sequence, execution) = CASES[idx]
    pub = ed25519.public_key(seed)
    wire = ce.build_observation(
        pub, created_at, contract, kind, observed_at, sequence, execution
    )
    sig = ed25519.sign(seed, wire)
    env = ce.build_envelope(wire, sig)
    return {
        "note": note,
        "seed_hex": seed.hex(),
        "created_at_unix": created_at,
        "contract_ref_hex": contract.hex(),
        "kind": kind,
        "observed_at_unix": observed_at,
        "sequence": sequence,
        "execution": execution,
        "wire_hex": wire.hex(),
        "sig_hex": sig.hex(),
        "env_hex": env.hex(),
    }


def identity_wire(seed, created_at):
    pub = ed25519.public_key(seed)
    return CborMap([(1, 1), (2, pub), (3, created_at)])


def statement(entries):
    return encode(CborMap(entries))


def base_entries(idx, **override):
    """The six fixed fields of case `idx`, with per-test overrides."""
    (_, seed, created_at, contract, kind, observed_at, sequence, execution) = CASES[idx]
    entries = [
        (1, override.get("scheme", 1)),
        (2, identity_wire(seed, created_at)),
        (3, override.get("contract", contract)),
        (4, override.get("kind", kind)),
        (5, override.get("observed_at", observed_at)),
        (6, override.get("sequence", sequence)),
    ]
    if "execution" in override:
        entries.append((7, override["execution"]))
    return entries


def parse_reject_hexes():
    rejects = []

    # scheme_version 2
    rejects.append((
        statement(base_entries(0, scheme=2)),
        "scheme_version_unsupported",
        "wrong scheme version",
    ))
    # not a map (an array)
    rejects.append((encode([1, 2, 3]), "not_a_map", "top-level item is an array"))
    # unknown kind
    rejects.append((
        statement(base_entries(0, kind="contract_reactivated")),
        "kind_unknown",
        "kind text outside the frozen six",
    ))
    # sequence 0 (reserved)
    rejects.append((
        statement(base_entries(0, sequence=0)),
        "sequence_below_minimum",
        "sequence below the reserved minimum 1",
    ))
    # contract_ref of 31 bytes
    rejects.append((
        statement(base_entries(0, contract=bytes([0x01] * 31))),
        "contract_ref_wrong_length",
        "contract_ref must be 32 bytes",
    ))
    # execution map with 17 entries
    too_many = CborMap([(f"counter_{i:02}", i) for i in range(17)])
    rejects.append((
        statement(base_entries(1, execution=too_many)),
        "execution_too_many_entries",
        "execution map over the 16-entry bound",
    ))
    # execution entry value is text
    wrong_value = CborMap([("uplink_bytes", "not-an-int")])
    rejects.append((
        statement(base_entries(1, execution=wrong_value)),
        "execution_entry_malformed",
        "execution entry is not text -> int",
    ))
    # execution entry key is empty text
    empty_key = CborMap([("", 1)])
    rejects.append((
        statement(base_entries(1, execution=empty_key)),
        "execution_key_invalid",
        "execution key of 0 bytes",
    ))
    # missing the sequence field
    entries = base_entries(0)
    del entries[5]
    rejects.append((statement(entries), "missing_field", "sequence field absent"))
    # trailing bytes after the complete map
    rejects.append((
        statement(base_entries(0)) + b"\x00",
        "cbor:TrailingBytes",
        "trailing byte after the map",
    ))
    return rejects


def envelope_reject_hexes():
    rejects = []
    wire = bytes.fromhex(build_case(0)["wire_hex"])
    sig = bytes.fromhex(build_case(0)["sig_hex"])

    # signature of 63 bytes
    rejects.append((
        encode(CborMap([(1, wire), (2, sig[:63])])),
        "signature_wrong_length",
        "envelope signature of 63 bytes",
    ))
    # three entries
    rejects.append((
        encode(CborMap([(1, wire), (2, sig), (3, 1)])),
        "envelope_wrong_entry_count",
        "envelope with a third field",
    ))
    # field 1 is text
    rejects.append((
        encode(CborMap([(1, "not-bytes"), (2, sig)])),
        "field_not_expected_type",
        "envelope field 1 is text",
    ))
    # envelope is an array
    rejects.append((encode([wire, sig]), "not_a_map", "envelope is an array"))
    return rejects


def main():
    vectors = {
        "scheme": "sharenet-connectivity-evidence-vectors-v1",
        "description": (
            "SignedConnectivityObservation conformance vectors (R5-004): "
            "provider-signed contract-lifecycle observations per the protocol "
            "registry entry — all six adcos.md event kinds, sequence "
            "advancement/regression, cross-contract and cross-provider "
            "sequence namespaces, the optional execution counter map, "
            "tampered/foreign signatures, the unknown-contract rule and "
            "freshness edges, plus strict statement/envelope parse "
            "rejections. Every hex is re-derived by all three legs; the "
            "committed values are the pinned expectations."
        ),
        "cases": [build_case(i) for i in range(len(CASES))],
        "receive": [
            {
                "case": case,
                "now_unix": now,
                "window_secs": window,
                "contract_known": known,
                "mutation": mutation,
                "expect": expect,
            }
            for (case, now, window, known, mutation, expect) in RECEIVE
        ],
        "parse_reject": [
            {"hex": hexes.hex(), "error": error, "note": note}
            for (hexes, error, note) in parse_reject_hexes()
        ],
        "envelope_reject": [
            {"hex": hexes.hex(), "error": error, "note": note}
            for (hexes, error, note) in envelope_reject_hexes()
        ],
    }
    out = Path(__file__).resolve().parent.parent / (
        "crates/sharenet-protocol/tests/vectors/connectivity_evidence_vectors.json"
    )
    out.write_text(json.dumps(vectors, indent=1) + "\n")
    print(f"wrote {out}")
    print(f"cases={len(vectors['cases'])} receive={len(vectors['receive'])} "
          f"parse_reject={len(vectors['parse_reject'])} "
          f"envelope_reject={len(vectors['envelope_reject'])}")


if __name__ == "__main__":
    main()
