"""Bit-level helpers for the Step 12 watermark reference implementation.

OProW's watermark payload is intentionally specified at the *bit* level: the
paper-level design uses a 4-bit protocol version, a 12-bit watermark algorithm
identifier, an 8-bit flags field, and then either a 160-bit FULL160 locator or a
64-bit SHORT64-style locator.  Python, however, normally manipulates bytes and
integers.  This module provides the small, explicit conversion layer between
those worlds.

The implementation choices are deliberately conservative:

* Bits are represented as Python ``int`` values, each either ``0`` or ``1``.
  This is not the most memory-efficient representation, but it is transparent
  and easy for a future implementation agent to inspect.
* Multi-bit integers are encoded most-significant-bit first.  This is the same
  convention used by network byte order and by most bit diagrams in protocol
  specifications.
* ``bits_to_bytes`` pads the final byte with zeros by default.  That makes CRC
  computation over non-byte-aligned future extensions deterministic, even though
  the current Step 12 payload layouts are byte-aligned.

Production implementations can replace this module with a bitarray-backed or
Rust-backed implementation without changing the public watermark APIs.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from oprow.core.errors import ValidationError


def validate_bit(bit: int) -> int:
    """Return ``bit`` as 0/1 or raise ``ValidationError``.

    Keeping this check centralized prevents surprising protocol encodings such
    as ``True``/``False``/``2`` silently slipping into a frame.  ``bool`` is a
    subclass of ``int`` in Python, so it is accepted and normalized.
    """

    b = int(bit)
    if b not in (0, 1):
        raise ValidationError(f"expected bit 0 or 1, got {bit!r}")
    return b


def normalize_bits(bits: Iterable[int]) -> list[int]:
    """Materialize an iterable of bits as a validated list of 0/1 integers."""

    return [validate_bit(b) for b in bits]


def int_to_bits(value: int, width: int) -> list[int]:
    """Encode ``value`` as exactly ``width`` big-endian bits.

    Example: ``int_to_bits(5, 4)`` returns ``[0, 1, 0, 1]``.
    """

    if width < 0:
        raise ValidationError("bit width must be non-negative")
    if value < 0:
        raise ValidationError("cannot encode negative integers as unsigned bits")
    if width == 0:
        if value != 0:
            raise ValidationError("non-zero value cannot be encoded with width 0")
        return []
    if value >= (1 << width):
        raise ValidationError(f"value {value} does not fit in {width} bits")
    return [(value >> shift) & 1 for shift in range(width - 1, -1, -1)]


def bits_to_int(bits: Sequence[int]) -> int:
    """Decode big-endian bits into an unsigned integer."""

    out = 0
    for b in bits:
        out = (out << 1) | validate_bit(b)
    return out


def bytes_to_bits(data: bytes) -> list[int]:
    """Convert bytes to a big-endian bit list."""

    out: list[int] = []
    for byte in data:
        out.extend(int_to_bits(byte, 8))
    return out


def bits_to_bytes(bits: Sequence[int], *, pad: bool = True) -> bytes:
    """Convert a big-endian bit list to bytes.

    If ``pad`` is true, a non-byte-aligned tail is padded with zero bits.  If it
    is false, the function raises on non-byte-aligned input.  Current OProW
    watermark payloads are byte-aligned, but the framing layer uses this helper
    with explicit padding for future-proof CRC calculation.
    """

    normalized = normalize_bits(bits)
    if not normalized:
        return b""
    if len(normalized) % 8:
        if not pad:
            raise ValidationError(f"bit length {len(normalized)} is not byte-aligned")
        normalized = normalized + [0] * (8 - (len(normalized) % 8))
    out = bytearray()
    for i in range(0, len(normalized), 8):
        out.append(bits_to_int(normalized[i : i + 8]))
    return bytes(out)


def xor_bits(left: Sequence[int], right: Sequence[int]) -> list[int]:
    """Bitwise XOR for equal-length bit sequences."""

    if len(left) != len(right):
        raise ValidationError("xor_bits requires equal-length inputs")
    return [validate_bit(a) ^ validate_bit(b) for a, b in zip(left, right)]
