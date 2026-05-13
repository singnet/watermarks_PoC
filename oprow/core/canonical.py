"""Deterministic canonical CBOR and debug JSON for OProW.

OProW signs and hashes structured protocol objects.  That makes deterministic
serialization a security boundary: two implementations must produce identical
bytes for the same manifest core or the signatures and locators will disagree.

This Step 1 encoder intentionally supports a small CBOR subset: null, booleans,
integers, byte strings, text strings, arrays, and maps.  It rejects floats and
unknown object types.  Production code may later swap the internal encoder for a
vetted CBOR package, but callers should continue using this module as the single
API for bytes that are signed or addressed.
"""

from __future__ import annotations

import dataclasses
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Protocol, runtime_checkable

from .errors import CanonicalizationError


@runtime_checkable
class Canonicalizable(Protocol):
    """Protocol objects expose their own primitive wire representation."""
    def to_canonical(self) -> Any: ...


@runtime_checkable
class JSONSerializable(Protocol):
    """Optional human/debug JSON representation."""
    def to_json_value(self) -> Any: ...


def normalize_datetime(dt: datetime) -> str:
    """Normalize a timezone-aware datetime to UTC RFC3339 text."""
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise CanonicalizationError("timezone-naive datetimes are not canonical")
    utc = dt.astimezone(timezone.utc)
    frac = f".{utc.microsecond:06d}".rstrip("0") if utc.microsecond else ""
    return utc.strftime(f"%Y-%m-%dT%H:%M:%S{frac}Z")


def to_canonical_primitive(value: Any) -> Any:
    """Convert a Python/OProW object to canonical primitive form."""
    if isinstance(value, Canonicalizable):
        return to_canonical_primitive(value.to_canonical())
    if isinstance(value, Enum):
        return to_canonical_primitive(value.value)
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floats are not allowed; use integers/fixed-point/string encodings")
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        return normalize_datetime(value)
    if isinstance(value, (list, tuple)):
        return [to_canonical_primitive(x) for x in value]
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalizationError(f"canonical maps must have string keys, got {type(k)!r}")
            out[k] = to_canonical_primitive(v)
        return out
    if dataclasses.is_dataclass(value):
        return {f.name: to_canonical_primitive(getattr(value, f.name)) for f in dataclasses.fields(value)}
    raise CanonicalizationError(f"object of type {type(value)!r} is not canonicalizable")


def _head(major: int, length: int) -> bytes:
    """Encode CBOR major type + definite length in shortest form."""
    prefix = major << 5
    if length < 0:
        raise CanonicalizationError("negative CBOR length")
    if length < 24:
        return bytes([prefix | length])
    if length <= 0xFF:
        return bytes([prefix | 24, length])
    if length <= 0xFFFF:
        return bytes([prefix | 25]) + length.to_bytes(2, "big")
    if length <= 0xFFFFFFFF:
        return bytes([prefix | 26]) + length.to_bytes(4, "big")
    if length <= 0xFFFFFFFFFFFFFFFF:
        return bytes([prefix | 27]) + length.to_bytes(8, "big")
    raise CanonicalizationError("CBOR length exceeds 64-bit range")


def _encode(value: Any) -> bytes:
    """Encode restricted primitives as deterministic CBOR."""
    if value is None:
        return b"\xf6"
    if value is False:
        return b"\xf4"
    if value is True:
        return b"\xf5"
    if isinstance(value, int):
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if isinstance(value, bytes):
        return _head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if isinstance(value, list):
        parts = [_encode(x) for x in value]
        return _head(4, len(parts)) + b"".join(parts)
    if isinstance(value, dict):
        # Deterministic CBOR sorts maps by the encoded key bytes.  We restrict
        # keys to strings, so this is stable and avoids locale-dependent sorting.
        pairs = [(_encode(k), _encode(v)) for k, v in value.items()]
        pairs.sort(key=lambda kv: kv[0])
        return _head(5, len(pairs)) + b"".join(k + v for k, v in pairs)
    raise CanonicalizationError(f"unsupported CBOR primitive: {type(value)!r}")


def canonical_cbor_dumps(value: Any) -> bytes:
    """Return deterministic CBOR bytes for signing/hash-addressing."""
    return _encode(to_canonical_primitive(value))


def _to_json_primitive(value: Any) -> Any:
    """Convert to deterministic debug JSON primitives."""
    if isinstance(value, JSONSerializable):
        return _to_json_primitive(value.to_json_value())
    if isinstance(value, Canonicalizable):
        return _to_json_primitive(value.to_canonical())
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return normalize_datetime(value)
    if isinstance(value, bytes):
        import base64
        return {"$bytes_b64u": base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")}
    if isinstance(value, (bytearray, memoryview)):
        return _to_json_primitive(bytes(value))
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        raise CanonicalizationError("floats are not allowed in debug JSON either")
    if isinstance(value, (list, tuple)):
        return [_to_json_primitive(x) for x in value]
    if isinstance(value, Mapping):
        return {str(k): _to_json_primitive(v) for k, v in value.items()}
    if dataclasses.is_dataclass(value):
        return {f.name: _to_json_primitive(getattr(value, f.name)) for f in dataclasses.fields(value)}
    raise CanonicalizationError(f"object of type {type(value)!r} is not JSON serializable")


def canonical_json_dumps(value: Any) -> bytes:
    """Deterministic UTF-8 JSON for humans/tests, not the signing path."""
    return json.dumps(_to_json_primitive(value), ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

# ---------------------------------------------------------------------------
# Restricted canonical CBOR decoder (Step 4 addition)
# ---------------------------------------------------------------------------
#
# Step 1 only needed a deterministic encoder because locally constructed
# manifests were signed and addressed in memory.  Step 4 introduces resolvers:
# bytes arrive from embedded metadata, sidecar files, CAS directories, or HTTP
# gateways and must be parsed back into protocol objects.  We therefore provide a
# *small* decoder for exactly the subset our encoder emits.
#
# This is not intended to be a general-purpose CBOR implementation.  It accepts:
#   - null, booleans
#   - positive and negative integers
#   - definite byte strings
#   - definite UTF-8 text strings
#   - definite arrays
#   - definite maps with text-string keys
#
# It rejects floats, tags, indefinite lengths, duplicate map keys, and non-string
# map keys.  The companion ``require_canonical`` mode re-encodes the decoded
# primitive and requires a byte-for-byte match.  This matters because OProW's
# FULL160 locator is a hash of the canonical SignedManifest bytes: accepting a
# non-canonical alternate representation would make storage/debugging confusing
# and would mask interop bugs.


def _decode_head(data: bytes, offset: int) -> tuple[int, int, int]:
    """Decode one CBOR head and return ``(major, argument, new_offset)``.

    The additional-information values 24..27 encode the integer/length in 1, 2,
    4, or 8 following bytes.  Value 31 is the indefinite-length marker and is
    deliberately rejected because canonical OProW encodings are definite-length.
    """
    if offset >= len(data):
        raise CanonicalizationError("truncated CBOR input")
    first = data[offset]
    offset += 1
    major = first >> 5
    ai = first & 0x1F
    if ai < 24:
        return major, ai, offset
    if ai == 24:
        nbytes = 1
    elif ai == 25:
        nbytes = 2
    elif ai == 26:
        nbytes = 4
    elif ai == 27:
        nbytes = 8
    elif ai == 31:
        raise CanonicalizationError("indefinite-length CBOR is not canonical")
    else:
        raise CanonicalizationError(f"reserved CBOR additional-info value {ai}")
    end = offset + nbytes
    if end > len(data):
        raise CanonicalizationError("truncated CBOR integer/length")
    arg = int.from_bytes(data[offset:end], "big")

    # Enforce shortest-form integers/lengths.  The encoder always uses shortest
    # form, so this check is a useful early canonicality guard.
    if ai == 24 and arg < 24:
        raise CanonicalizationError("non-canonical CBOR: one-byte length used for value < 24")
    if ai == 25 and arg <= 0xFF:
        raise CanonicalizationError("non-canonical CBOR: two-byte length used for value <= 255")
    if ai == 26 and arg <= 0xFFFF:
        raise CanonicalizationError("non-canonical CBOR: four-byte length used for value <= 65535")
    if ai == 27 and arg <= 0xFFFFFFFF:
        raise CanonicalizationError("non-canonical CBOR: eight-byte length used for value <= 2^32-1")
    return major, arg, end


def _decode_at(data: bytes, offset: int) -> tuple[Any, int]:
    """Recursive decoder for the restricted OProW CBOR subset."""
    major, arg, offset = _decode_head(data, offset)

    if major == 0:  # unsigned int
        return arg, offset
    if major == 1:  # negative int: -1 - n
        return -1 - arg, offset
    if major == 2:  # byte string
        end = offset + arg
        if end > len(data):
            raise CanonicalizationError("truncated CBOR byte string")
        return data[offset:end], end
    if major == 3:  # UTF-8 text string
        end = offset + arg
        if end > len(data):
            raise CanonicalizationError("truncated CBOR text string")
        try:
            return data[offset:end].decode("utf-8"), end
        except UnicodeDecodeError as exc:
            raise CanonicalizationError("invalid UTF-8 in CBOR text string") from exc
    if major == 4:  # array
        out: list[Any] = []
        for _ in range(arg):
            item, offset = _decode_at(data, offset)
            out.append(item)
        return out, offset
    if major == 5:  # map
        out: dict[str, Any] = {}
        last_key_encoding: bytes | None = None
        for _ in range(arg):
            key_start = offset
            key, offset = _decode_at(data, offset)
            key_encoding = data[key_start:offset]
            if not isinstance(key, str):
                raise CanonicalizationError("OProW canonical maps require text-string keys")
            if key in out:
                raise CanonicalizationError(f"duplicate CBOR map key: {key!r}")
            # Canonical CBOR sorts map keys by the encoded key bytes.  Enforcing
            # monotonic order here catches non-canonical but semantically equal
            # encodings before they reach signature/locator logic.
            if last_key_encoding is not None and key_encoding < last_key_encoding:
                raise CanonicalizationError("non-canonical CBOR: map keys are not sorted by encoded bytes")
            last_key_encoding = key_encoding
            value, offset = _decode_at(data, offset)
            out[key] = value
        return out, offset
    if major == 7:
        if arg == 20:
            return False, offset
        if arg == 21:
            return True, offset
        if arg == 22:
            return None, offset
        raise CanonicalizationError("unsupported CBOR simple/float value")

    # Major type 6 is tag; major type 7 includes floats/simple values.  Tags are
    # intentionally not part of the Step 1 canonical subset because typed OProW
    # objects carry their type in schema fields rather than CBOR tags.
    raise CanonicalizationError(f"unsupported CBOR major type {major}")


def canonical_cbor_loads(data: bytes, *, require_canonical: bool = True) -> Any:
    """Decode restricted OProW CBOR bytes into primitive Python values.

    Parameters
    ----------
    data:
        Bytes emitted by ``canonical_cbor_dumps``.
    require_canonical:
        If true, re-encode the decoded primitive and require byte-for-byte
        equality with ``data``.  Resolvers should keep this enabled for signed
        manifests because non-canonical input is a protocol error.
    """
    if not isinstance(data, bytes):
        data = bytes(data)
    value, offset = _decode_at(data, 0)
    if offset != len(data):
        raise CanonicalizationError("trailing bytes after CBOR object")
    if require_canonical:
        encoded = canonical_cbor_dumps(value)
        if encoded != data:
            raise CanonicalizationError("CBOR input is not in OProW canonical form")
    return value
