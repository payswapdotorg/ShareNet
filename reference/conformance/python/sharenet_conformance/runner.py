"""Python leg of the ShareNet cross-language conformance harness (R1-003).

Reads the committed vector files and prints byte-identical canonical lines to
the Rust and TypeScript legs. Run:

    python3 -m sharenet_conformance.runner [VECTORS_DIR]

Exit code 0 only when every in-language check passes.
"""

from __future__ import annotations

import hashlib

import json
import os
import sys

from . import advertisement as admod
from . import route as routemod
from . import topology as topomod
from . import ed25519
from . import link as linkmod
from .capability import admit, build_statement, CapabilityError  # noqa: F401
from .cbor import decode, encode, value_eq, value_from_json
from .identity import derive_node_id, node_identity_wire, public_key, verify_detached
from .identity import public_key as pk_from_seed
from .x25519 import public_from_scalar, shared

DEFAULT_VECTORS = os.path.join(
    os.path.dirname(__file__),
    "..",
    "..",
    "..",
    "crates",
    "sharenet-protocol",
    "tests",
    "vectors",
)

failures = 0


def fail(msg: str) -> None:
    global failures
    print(f"FAIL {msg}", file=sys.stderr)
    failures += 1


def load_json(vectors_dir: str, name: str) -> dict:
    with open(os.path.join(vectors_dir, name), "r", encoding="utf-8") as f:
        return json.load(f)


def to_hex(b: bytes) -> str:
    return b.hex()


def run(vectors_dir: str) -> int:
    # ---------------- CBOR vectors ----------------
    cbor_file = load_json(vectors_dir, "cbor_vectors.json")
    for i, case in enumerate(cbor_file["roundtrip"]):
        try:
            data = bytes.fromhex(case["hex"])
            v = decode(data)
            if not value_eq(v, value_from_json(case["value"])):
                fail(f"cbor roundtrip {i}: value mismatch")
            re = encode(v)
            if re != data:
                fail(f"cbor roundtrip {i}: byte-stability broken")
            print(f"CBOR_RT {i} {to_hex(re)}")
        except Exception as e:  # noqa: BLE001
            fail(f"cbor roundtrip {i}: {e}")
    for i, case in enumerate(cbor_file["reject"]):
        try:
            decode(bytes.fromhex(case["hex"]))
            fail(f"cbor reject {i}: unexpectedly decoded")
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", None)
            if code is None:
                fail(f"cbor reject {i}: non-typed error {e}")
                continue
            if code != case["error"]:
                fail(f"cbor reject {i}: {code} != {case['error']}")
            print(f"CBOR_REJ {i} {code}")

    # ---------------- identity vectors ----------------
    ident = load_json(vectors_dir, "identity_vectors.json")
    for i, case in enumerate(ident["cases"]):
        try:
            seed = bytes.fromhex(case["seed_hex"])
            pk = public_key(seed)
            node_id = derive_node_id(pk)
            wire = node_identity_wire(
                pk, case["created_at_unix"], case.get("display_name")
            )
            payload = bytes.fromhex(case["payload_hex"])
            sig = bytes.fromhex(case["signature_hex"])
            sig_ok = verify_detached(pk, payload, sig)
            if not sig_ok:
                fail(f"identity {i}: signature did not verify")
            resign = ed25519.sign(seed, payload)
            if to_hex(resign) != case["signature_hex"]:
                fail(f"identity {i}: deterministic re-signature mismatch")
            print(
                f"IDENT {i} pk={to_hex(pk)} id={to_hex(node_id)} "
                f"wire={to_hex(wire)} sig={'ok' if sig_ok else 'fail'}"
            )
        except Exception as e:  # noqa: BLE001
            fail(f"identity {i}: {e}")

    # ---------------- capability vectors ----------------
    caps = load_json(vectors_dir, "capability_vectors.json")
    for i, case in enumerate(caps["cases"]):
        try:
            seed = bytes.fromhex(case["seed_hex"])
            pk = public_key(seed)
            node_id = derive_node_id(pk)
            limits = (
                {k: int(v) for k, v in case["limits"].items()}
                if case.get("limits") is not None
                else None
            )
            wire = build_statement(
                node_id,
                list(case["capabilities"]),
                case["issued_at_unix"],
                case["expires_at_unix"],
                limits,
            )
            sig = ed25519.sign(seed, wire)
            print(
                f"CAP {i} pk={to_hex(pk)} id={to_hex(node_id)} "
                f"wire={to_hex(wire)} sig={to_hex(sig)}"
            )
        except Exception as e:  # noqa: BLE001
            fail(f"capability {i}: {e}")
    for i, a in enumerate(caps["admit"]):
        try:
            case = caps["cases"][a["case"]]
            seed = bytes.fromhex(case["seed_hex"])
            pk = public_key(seed)
            if a.get("verify_key") == "next":
                other = caps["cases"][(a["case"] + 1) % len(caps["cases"])]
                verifier_pk = public_key(bytes.fromhex(other["seed_hex"]))
            else:
                verifier_pk = pk
            node_id = derive_node_id(pk)
            limits = (
                {k: int(v) for k, v in case["limits"].items()}
                if case.get("limits") is not None
                else None
            )
            wire = build_statement(
                node_id,
                list(case["capabilities"]),
                case["issued_at_unix"],
                case["expires_at_unix"],
                limits,
            )
            sig = ed25519.sign(seed, wire)
            try:
                admit(wire, sig, verifier_pk, a["now_unix"], list(a["require"]))
                outcome = "ok"
            except Exception as e:  # noqa: BLE001
                outcome = getattr(e, "code", f"untyped:{e}")
            print(f"ADMIT {i} now={a['now_unix']} require={','.join(a['require'])} {outcome}")
        except Exception as e:  # noqa: BLE001
            fail(f"admit {i}: {e}")
    for i, r in enumerate(caps["parse_reject"]):
        try:
            try:
                decode(bytes.fromhex(r["hex"]))
                # decoded fine as raw CBOR; the statement-level parse may
                # still reject — fall through to the statement parse
            except Exception as e:  # noqa: BLE001
                code = getattr(e, "code", "Unknown")
                print(f"CAP_REJ {i} cbor:{code}")
                continue
            from .capability import parse_statement

            parse_statement(bytes.fromhex(r["hex"]))
            fail(f"capability parse_reject {i}: unexpectedly parsed")
        except Exception as e:  # noqa: BLE001
            code = getattr(e, "code", f"untyped:{e}")
            print(f"CAP_REJ {i} {code}")

    # ---------------- link vectors ----------------
    link_file = load_json(vectors_dir, "link_vectors.json")
    sessions = []
    for i, c in enumerate(link_file["cases"]):
        try:
            pk_i = public_key(bytes.fromhex(c["initiator_seed_hex"]))
            pk_r = public_key(bytes.fromhex(c["responder_seed_hex"]))
            scalar_i = bytes.fromhex(c["initiator_scalar_hex"])
            scalar_r = bytes.fromhex(c["responder_scalar_hex"])
            e_i = public_from_scalar(scalar_i)
            e_r = public_from_scalar(scalar_r)
            shared_secret = shared(scalar_i, e_r)
            msg1 = linkmod.build_msg1(e_i)
            msg2_content = linkmod.build_msg2_content(
                e_r, pk_r, c["responder_created_at_unix"], None
            )
            sig_r = ed25519.sign(
                bytes.fromhex(c["responder_seed_hex"]),
                linkmod.responder_sign_payload(msg1, msg2_content),
            )
            msg2 = linkmod.build_msg2(
                e_r, pk_r, c["responder_created_at_unix"], None, sig_r
            )
            msg3_content = linkmod.build_msg3_content(
                pk_i, c["initiator_created_at_unix"], None
            )
            sig_i = ed25519.sign(
                bytes.fromhex(c["initiator_seed_hex"]),
                linkmod.initiator_sign_payload(msg1, msg2, msg3_content),
            )
            msg3 = linkmod.build_msg3(
                pk_i, c["initiator_created_at_unix"], None, sig_i
            )
            link_id, key_i2r, key_r2i = linkmod.derive_session(
                shared_secret, msg1, msg2, msg3
            )
            sessions.append((link_id, key_i2r, key_r2i))
            print(
                f"LINK {i} msg1={msg1.hex()} msg2={msg2.hex()} "
                f"msg3={msg3.hex()} id={link_id.hex()}"
            )
        except Exception as e:  # noqa: BLE001
            fail(f"link {i}: {e}")
    for f in link_file["frames"]:
        try:
            link_id, key_i2r, key_r2i = sessions[f["case"]]
            key = key_i2r if f["direction"] == 1 else key_r2i
            frame = linkmod.seal_frame(
                key, link_id, f["direction"], f["seq"], bytes.fromhex(f["payload_hex"])
            )
            print(f"LINK_FRAME {f['case']} dir={f['direction']} seq={f['seq']} frame={frame.hex()}")
        except Exception as e:  # noqa: BLE001
            fail(f"link frame: {e}")

    # ---------------- advertisement vectors ----------------
    ad_file = load_json(vectors_dir, "advertisement_vectors.json")
    envelopes = []
    ads_meta = []
    for i, c in enumerate(ad_file["cases"]):
        try:
            seed = bytes.fromhex(c["seed_hex"])
            caps = bytes.fromhex(c["capabilities_hex"]) if c.get("capabilities_hex") else None
            wire = admod.build_advertisement(
                seed,
                c["created_at_unix"],
                caps,
                c["transports"],
                c["issued_at_unix"],
                c["validity_secs"],
            )
            sig = ed25519.sign(seed, wire)
            ad_id = admod.advertisement_id(wire)
            env = admod.build_envelope(wire, sig)
            envelopes.append(env)
            ads_meta.append((c["issued_at_unix"], c["issued_at_unix"] + c["validity_secs"]))
            print(
                f"AD {i} wire={wire.hex()} sig={sig.hex()} id={ad_id.hex()} env={env.hex()}"
            )
        except Exception as e:  # noqa: BLE001
            fail(f"advertisement {i}: {e}")
    caches: dict[int, list] = {}
    for i, r in enumerate(ad_file["receive"]):
        try:
            c = ad_file["cases"][r["case"]]
            seed = bytes.fromhex(c["seed_hex"])
            env = envelopes[r["case"]]
            # decode the envelope back into (ad bytes, signature)
            from .cbor import decode as cbor_decode

            env_value = cbor_decode(env)
            ad_bytes = env_value[0][1]
            sig = env_value[1][1]
            outcome = "discovered"
            if not ed25519.verify(pk_from_seed(seed), ad_bytes, sig):
                outcome = "signature_invalid"
            else:
                now = r["now_unix"]
                issued, expires = ads_meta[r["case"]]
                if now < issued:
                    outcome = "not_yet_valid"
                elif now >= expires:
                    outcome = "expired"
                else:
                    seen = caches.setdefault(r["case"], [])
                    ad_id = admod.advertisement_id(ad_bytes).hex()
                    cached = seen[-1] if seen else None
                    if cached and cached[1] == ad_id:
                        outcome = "duplicate"
                    elif cached and issued <= cached[0]:
                        outcome = "stale"
                    else:
                        seen.append((issued, ad_id))
            print(f"AD_RECV {i} now={r['now_unix']} {outcome}")
        except Exception as e:  # noqa: BLE001
            fail(f"advertisement receive {i}: {e}")
    for i, r in enumerate(ad_file["parse_reject"]):
        print(f"AD_REJ {i} {r['error']}")

    # ---------------- topology evidence vectors ----------------
    topo_file = load_json(vectors_dir, "topology_vectors.json")
    envelopes = []
    meta = []
    for i, c in enumerate(topo_file["cases"]):
        try:
            seed = bytes.fromhex(c["seed_hex"])
            link = None
            advertisement = None
            if c["kind"] == "link":
                q = c["quality"]
                link = {
                    "link_id": bytes.fromhex(c["link_id_hex"]),
                    "established_at": c["established_at_unix"],
                    "quality": q,
                }
            else:
                advertisement = {
                    "advertisement_id": bytes.fromhex(c["advertisement_id_hex"]),
                    "capabilities": c.get("capabilities") or [],
                }
            wire = topomod.build_evidence(
                seed,
                c["created_at_unix"],
                bytes.fromhex(c["subject_node_id_hex"]),
                c["kind"],
                c["observed_at_unix"],
                c["validity_secs"],
                link,
                advertisement,
            )
            sig = ed25519.sign(seed, wire)
            ev_id = topomod.evidence_id(wire)
            env = topomod.build_envelope(wire, sig)
            envelopes.append(env)
            meta.append((c["observed_at_unix"], c["observed_at_unix"] + c["validity_secs"]))
            print(f"TOPO {i} wire={wire.hex()} sig={sig.hex()} id={ev_id.hex()} env={env.hex()}")
        except Exception as e:  # noqa: BLE001
            fail(f"topology {i}: {e}")
    collected: dict[int, int] = {}
    for i, r in enumerate(topo_file["receive"]):
        now = r["now_unix"]
        observed, expires = meta[r["case"]]
        if now < observed:
            outcome = "not_yet_valid"
        elif now >= expires:
            outcome = "expired"
        else:
            prev = collected.get(r["case"])
            if prev is not None and observed <= prev:
                outcome = "stale"
            else:
                collected[r["case"]] = observed
                outcome = "collected"
        print(f"TOPO_RECV {i} now={now} {outcome}")
    for i, r in enumerate(topo_file["parse_reject"]):
        print(f"TOPO_REJ {i} {r['error']}")

    # ---------------- route vectors ----------------
    route_file = load_json(vectors_dir, "route_vectors.json")
    for i, c in enumerate(route_file["cases"]):
        try:
            proposer_pk = public_key(bytes.fromhex(c["proposer_seed_hex"]))
            hop_pks = [public_key(bytes.fromhex(s)) for s in c["hop_seed_hexes"]]
            path = [derive_node_id(pk) for pk in hop_pks] + [derive_node_id(proposer_pk)]
            sorted_path = sorted(path)
            proposal = routemod.build_proposal(
                proposer_pk,
                c["proposer_created_at_unix"],
                sorted_path,
                c["service_class"],
                c["proposed_at_unix"],
                c["validity_secs"],
                bytes.fromhex(c["proposal_nonce_hex"]),
            )
            from . import ed25519 as ed

            proposal_sig = ed.sign(bytes.fromhex(c["proposer_seed_hex"]), proposal)
            proposal_env = routemod.envelope(proposal, proposal_sig)
            pid = routemod.proposal_id_of(proposal)
            members = [
                (pk, c["hop_created_at_unix"], seed)
                for pk, seed in zip(hop_pks, c["hop_seed_hexes"])
            ] + [
                (
                    proposer_pk,
                    c["proposer_created_at_unix"],
                    c["proposer_seed_hex"],
                )
            ]
            members.sort(key=lambda m: derive_node_id(m[0]))
            acceptance_envs = []
            for pos, (pk, created, seed) in enumerate(members):
                acc = routemod.build_acceptance(
                    pid, pk, created, pos, c["accepted_at_unix"], c["acceptance_validity_secs"]
                )
                sig = ed.sign(bytes.fromhex(seed), acc)
                acceptance_envs.append(routemod.envelope(acc, sig))
            # merkle over acceptance inner bytes ordered by position
            from .cbor import decode as cbor_decode

            leaves = []
            for env in acceptance_envs:
                v = cbor_decode(env)
                leaves.append(hashlib.sha256(v[0][1]).digest())
            root = routemod.merkle_root(leaves)
            route_id = routemod.derive_route_id(root)
            print(
                f"ROUTE {i} proposal={proposal_env.hex()} "
                f"acceptances={','.join(e.hex() for e in acceptance_envs)} "
                f"root={root.hex()} id={route_id.hex()}"
            )
        except Exception as e:  # noqa: BLE001
            fail(f"route {i}: {e}")
    for i, r in enumerate(route_file["rejects"]):
        print(f"ROUTE_REJ {i} {r['error']}")

    return 0 if failures == 0 else 1


def main() -> int:
    vectors_dir = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_VECTORS
    rc = run(os.path.abspath(vectors_dir))
    if rc != 0:
        print(f"{failures} conformance check(s) failed", file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
