"""ShareNet Canonical CBOR Profile v1 — Python conformance implementation
(work item R1-003, profile defined by R1-002 in the Rust reference core).

Independent reimplementation pinned by the committed vectors; must agree
with the Rust and TypeScript legs byte-for-byte. Error names match the Rust
``DecodeError::name()`` strings exactly for the cross-language diff.
"""

from __future__ import annotations

MAX_DEPTH = 128

I64_MAX = 2**63 - 1

# Value model: int | bytes | str | list | list[tuple[k, v]] | bool | None


class DecodeError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class EncodeError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class CborMap(list):
    """A CBOR map: a list of (key, value) tuples.

    A distinct type (vs plain list = array) so EMPTY maps and EMPTY arrays
    stay distinguishable — the value model must round-trip losslessly.
    """


class _Reader:
    __slots__ = ("buf", "pos")

    def __init__(self, buf: bytes):
        self.buf = buf
        self.pos = 0

    def take(self) -> int:
        if self.pos >= len(self.buf):
            raise DecodeError("Truncated", f"truncated at {self.pos}")
        b = self.buf[self.pos]
        self.pos += 1
        return b

    def take_n(self, n: int) -> bytes:
        if n > len(self.buf) - self.pos:
            raise DecodeError("Truncated", f"truncated at {self.pos}")
        s = self.buf[self.pos : self.pos + n]
        self.pos += n
        return s


def _read_arg(r: _Reader, ai: int, at: int) -> int:
    if ai <= 23:
        return ai
    if ai == 24:
        b = r.take()
        if b <= 23:
            raise DecodeError("NonMinimalInteger", f"non-minimal integer at {at}")
        return b
    if ai == 25:
        s = r.take_n(2)
        v = int.from_bytes(s, "big")
        if v <= 0xFF:
            raise DecodeError("NonMinimalInteger", f"non-minimal integer at {at}")
        return v
    if ai == 26:
        s = r.take_n(4)
        v = int.from_bytes(s, "big")
        if v <= 0xFFFF:
            raise DecodeError("NonMinimalInteger", f"non-minimal integer at {at}")
        return v
    if ai == 27:
        s = r.take_n(8)
        v = int.from_bytes(s, "big")
        if v <= 0xFFFFFFFF:
            raise DecodeError("NonMinimalInteger", f"non-minimal integer at {at}")
        return v
    if ai == 31:
        # reached only for major types 0/1/6 (majors 2-5 route to _read_len)
        raise DecodeError("ReservedAdditionalInfo", f"reserved additional info at {at}")
    # 28..=30
    raise DecodeError("ReservedAdditionalInfo", f"reserved additional info at {at}")


def _read_len(r: _Reader, ai: int, at: int) -> int:
    if ai == 31:
        raise DecodeError("IndefiniteLength", f"indefinite length at {at}")
    return _read_arg(r, ai, at)


def _read_value(r: _Reader, depth: int):
    if depth > MAX_DEPTH:
        raise DecodeError("DepthLimitExceeded", f"depth > {MAX_DEPTH} at {r.pos}")
    at = r.pos
    ib = r.take()
    major = ib >> 5
    ai = ib & 0x1F
    if major == 0:
        n = _read_arg(r, ai, at)
        if n > I64_MAX:
            raise DecodeError("IntegerOutOfRange", f"integer out of range at {at}")
        return n
    if major == 1:
        n = _read_arg(r, ai, at)
        if n > I64_MAX:
            raise DecodeError("IntegerOutOfRange", f"integer out of range at {at}")
        return -1 - n
    if major == 2:
        length = _read_len(r, ai, at)
        return bytes(r.take_n(length))
    if major == 3:
        length = _read_len(r, ai, at)
        raw = r.take_n(length)
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            raise DecodeError("InvalidUtf8", f"invalid UTF-8 at {at}") from None
    if major == 4:
        n = _read_len(r, ai, at)
        items = []
        for _ in range(n):
            items.append(_read_value(r, depth + 1))
        return items
    if major == 5:
        n = _read_len(r, ai, at)
        entries: list[tuple] = []
        prev: bytes | None = None
        for _ in range(n):
            key_start = r.pos
            k = _read_value(r, depth + 1)
            key_end = r.pos
            cur = bytes(r.buf[key_start:key_end])
            if prev is not None:
                if cur == prev:
                    raise DecodeError("DuplicateMapKey", f"duplicate map key at {key_start}")
                if cur < prev:
                    raise DecodeError("UnsortedMapKeys", f"unsorted map keys at {key_start}")
            v = _read_value(r, depth + 1)
            entries.append((k, v))
            prev = cur
        return CborMap(entries)
    if major == 6:
        tag = _read_arg(r, ai, at)
        raise DecodeError("TagNotAllowed", f"tag {tag} at {at}")
    # major 7
    if ai == 20:
        return False
    if ai == 21:
        return True
    if ai == 22:
        return None
    if ai == 23:
        raise DecodeError("UndefinedNotAllowed", f"undefined at {at}")
    if ai == 24:
        v = r.take()
        raise DecodeError("SimpleValueNotAllowed", f"simple value {v} at {at}")
    if ai in (25, 26, 27):
        raise DecodeError("FloatNotAllowed", f"float at {at}")
    if ai == 31:
        raise DecodeError("BreakByteNotAllowed", f"break byte at {at}")
    if 28 <= ai <= 30:
        raise DecodeError("ReservedAdditionalInfo", f"reserved additional info at {at}")
    raise DecodeError("SimpleValueNotAllowed", f"simple value {ai} at {at}")


def decode(data: bytes):
    if len(data) == 0:
        raise DecodeError("EmptyInput", "empty input")
    r = _Reader(data)
    value = _read_value(r, 1)
    if r.pos != len(data):
        raise DecodeError(
            "TrailingBytes", f"trailing bytes at {r.pos} ({len(data) - r.pos} extra)"
        )
    return value


def _write_head(major: int, arg: int, out: bytearray) -> None:
    m = major << 5
    if arg <= 23:
        out.append(m | arg)
    elif arg <= 0xFF:
        out.append(m | 24)
        out.append(arg)
    elif arg <= 0xFFFF:
        out.append(m | 25)
        out.extend(arg.to_bytes(2, "big"))
    elif arg <= 0xFFFFFFFF:
        out.append(m | 26)
        out.extend(arg.to_bytes(4, "big"))
    else:
        out.append(m | 27)
        out.extend(arg.to_bytes(8, "big"))


def _write_value(value, out: bytearray, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise EncodeError("DepthLimitExceeded", f"depth > {MAX_DEPTH}")
    if isinstance(value, bool):
        out.append(0xF5 if value else 0xF4)
        return
    if value is None:
        out.append(0xF6)
        return
    if isinstance(value, int):
        if value >= 0:
            _write_head(0, value, out)
        else:
            _write_head(1, -1 - value, out)
        return
    if isinstance(value, (bytes, bytearray)):
        _write_head(2, len(value), out)
        out.extend(value)
        return
    if isinstance(value, str):
        b = value.encode("utf-8")
        _write_head(3, len(b), out)
        out.extend(b)
        return
    if isinstance(value, CborMap):
        keyed = []
        for i, (k, _) in enumerate(value):
            kb = bytearray()
            _write_value(k, kb, depth + 1)
            keyed.append((bytes(kb), i))
        keyed.sort(key=lambda t: t[0])
        for j in range(1, len(keyed)):
            if keyed[j - 1][0] == keyed[j][0]:
                raise EncodeError("DuplicateMapKey", f"duplicate key at index {keyed[j][1]}")
        _write_head(5, len(value), out)
        for kb, i in keyed:
            out.extend(kb)
            _write_value(value[i][1], out, depth + 1)
        return
    if isinstance(value, list):
        _write_head(4, len(value), out)
        for item in value:
            _write_value(item, out, depth + 1)
        return
    raise EncodeError("UnsupportedValue", f"unsupported value {type(value)}")


def encode(value) -> bytes:
    out = bytearray()
    _write_value(value, out, 1)
    return bytes(out)


def value_from_json(j: dict):
    t = j["type"]
    if t == "int":
        return int(j["value"])
    if t == "bytes":
        return bytes.fromhex(j["hex"])
    if t == "text":
        return j["value"]
    if t == "array":
        return [value_from_json(x) for x in j["items"]]
    if t == "map":
        return CborMap(
            (value_from_json(e["key"]), value_from_json(e["value"])) for e in j["entries"]
        )
    if t == "bool":
        return bool(j["value"])
    if t == "null":
        return None
    raise ValueError(f"unknown JSON value type {t}")


def value_eq(a, b) -> bool:
    """Order-insensitive value equality (map entries as multisets)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, int) and isinstance(b, int):
        return a == b
    if isinstance(a, (bytes, bytearray)) and isinstance(b, (bytes, bytearray)):
        return bytes(a) == bytes(b)
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        a_map = a if isinstance(a, CborMap) else None
        b_map = b if isinstance(b, CborMap) else None
        if (a_map is None) != (b_map is None):
            return False
        if a_map is not None and b_map is not None:
            if len(a_map) != len(b_map):
                return False
            b_dict: dict = {}
            for k, v in b_map:
                b_dict.setdefault(_hashable(k), []).append(v)
            for k, v in a_map:
                bucket = b_dict.get(_hashable(k))
                if bucket is None or not any(value_eq(v, x) for x in bucket):
                    return False
            return True
        if len(a) != len(b):
            return False
        return all(value_eq(x, y) for x, y in zip(a, b))
    return False


def _as_map(v: list):
    if v and all(isinstance(e, tuple) and len(e) == 2 for e in v):
        return v
    return None


def _hashable(v):
    if isinstance(v, CborMap):
        return ("map", tuple((_hashable(k), _hashable(x)) for k, x in v))
    if isinstance(v, list):
        return ("arr", tuple(_hashable(x) for x in v))
    if isinstance(v, (bytes, bytearray)):
        return ("b", bytes(v))
    return (type(v).__name__, v)


def to_hex(data: bytes) -> str:
    return data.hex()
