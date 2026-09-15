"""ShareNet ContentManifest — Python conformance implementation (R6-001).

The manifest is the named object: content_id = SHA-256(canonical CBOR
bytes). The chunk discipline (build from actual chunk hashes; reassemble
verifying every hash in order + exact total byte count, fail-closed with
the slot index) mirrors the Rust reference core; the vectors pin all of it
byte-exactly across the three legs.
"""

from __future__ import annotations

import hashlib

from .cbor import CborMap, encode

CONTENT_MAX_CHUNK_SIZE = 2_097_152


def chunk_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def split_chunks(content: bytes, chunk_size: int) -> list[bytes]:
    return [content[i : i + chunk_size] for i in range(0, len(content), chunk_size)]


def build_manifest(
    content: bytes,
    chunk_size: int,
    content_type: str,
    metadata: dict[str, object] | None,
    created_at: int,
) -> tuple[bytes, bytes, list[bytes]]:
    """Build the canonical manifest bytes, the content_id and the chunk
    hashes from the ACTUAL chunks."""
    chunks = split_chunks(content, chunk_size)
    hashes = [chunk_hash(c) for c in chunks]
    entries: list = [
        (1, 1),
        (2, chunk_size),
        (3, len(content)),
        (4, [h for h in hashes]),
        (5, content_type),
    ]
    if metadata is not None:
        # canonical CBOR map keys: bytewise-ascending text order
        entries.append((6, CborMap([(k, metadata[k]) for k in sorted(metadata)])))
    entries.append((7, created_at))
    wire = encode(CborMap(entries))
    return wire, chunk_hash(wire), hashes


def reassemble(
    chunk_size: int,
    total_length: int,
    chunk_hashes: list[bytes],
    chunks: list[bytes],
) -> str:
    """The reassembly discipline (fail-closed, slot-indexed). Returns "ok"
    or the typed outcome string; never partially accepts."""
    n = len(chunk_hashes)
    provided = len(chunks)

    def expected_len(slot: int) -> int:
        if slot + 1 == n:
            return total_length - (n - 1) * chunk_size
        return chunk_size

    for slot in range(min(provided, n)):
        data = chunks[slot]
        if len(data) != expected_len(slot):
            return f"chunk_length_wrong slot={slot}"
        if chunk_hash(data) != chunk_hashes[slot]:
            return f"chunk_hash_mismatch slot={slot}"
    if provided < n:
        return f"missing_chunk slot={provided}"
    if provided > n:
        return f"extra_chunk slot={n}"
    return "ok"


def apply_mutation(chunks: list[bytes], mutation: str, slot: int | None) -> list[bytes]:
    """Apply one reassembly mutation (the frozen vocabulary shared by all
    three conformance legs)."""
    out = [bytes(c) for c in chunks]
    s = slot if slot is not None else 0
    if mutation == "swap_first_two":
        out[0], out[1] = out[1], out[0]
    elif mutation == "corrupt_slot":
        b = bytearray(out[s])
        b[0] ^= 0x80
        out[s] = bytes(b)
    elif mutation == "drop_last":
        out.pop()
    elif mutation == "drop_middle":
        out.pop(s)
    elif mutation == "extra_last":
        out.append(out[-1])
    elif mutation == "short_last":
        out[-1] = out[-1][:-1]
    elif mutation == "short_first":
        out[0] = out[0][:-1]
    elif mutation == "replace_slot_with_prev":
        out[s] = out[s - 1]
    else:
        raise ValueError(f"unknown content mutation {mutation!r}")
    return out
