"""Hypervector primitives for OProW Step 8.

This module implements the smallest possible *deterministic* hypervector layer
needed for the SHORT64-HV experiment.  It deliberately avoids depending on a
large HDC framework in the reference package.  A production or research build may
replace these functions with ``torchhd``, FAISS-backed indexing, SIMD bitsets, or
GPU kernels, but the protocol-facing behavior should remain the same.

Theory implemented here
=======================

Hyperdimensional computing (HDC), also called Vector Symbolic Architecture
(VSA), represents objects as very high-dimensional vectors.  In OProW we do not
use HDC as cryptography and we do not ask it to compress 160 bits of manifest
entropy into a 64-bit watermark.  Instead, HDC is a fuzzy *routing* layer:

    media artifact -> PED -> hypervector -> coarse route tokens

The route tokens help a resolver find a small candidate set for a SHORT64
watermark.  Final provenance verification still requires:

    locator self-consistency + manifest signatures + essence hash + trust policy

This file therefore implements only operations that are safe for routing:

* deterministic random hypervector generation from public seeds;
* binary/bipolar conversion;
* Hamming distance for diagnostics and benchmarking;
* bundling by majority vote.

Privacy note
============

A raw hypervector can function as a media fingerprint.  The public resolver API
introduced later must not receive raw hypervectors.  The routing module hashes
coarse band codes into route keys; this module simply provides local vector
operations for the verifier/indexer.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Iterable

import numpy as np

from oprow.core.errors import ValidationError
from oprow.core.hashes import frame_parts


def _bytes_for_bits(n_bits: int) -> int:
    if n_bits <= 0:
        raise ValidationError("bit length must be positive")
    return (n_bits + 7) // 8


def _mask_unused_trailing_bits(data: bytes, dimension: int) -> bytes:
    """Zero padding bits after ``dimension`` in a MSB-first packed bitstring.

    NumPy's ``packbits(..., bitorder='big')`` packs the first bit into the most
    significant bit of the first byte and pads the final byte with zeros in the
    least-significant positions.  OProW reference vectors use the same convention
    so canonical byte strings are stable.
    """
    n = _bytes_for_bits(dimension)
    raw = bytearray(bytes(data[:n]))
    if len(raw) != n:
        raise ValidationError(f"expected {n} bytes for {dimension} bits, got {len(raw)}")
    unused = (8 - (dimension % 8)) % 8
    if unused:
        raw[-1] &= (0xFF << unused) & 0xFF
    return bytes(raw)


def expand_public_random_bits(domain: str, parts: Iterable[bytes], dimension: int) -> bytes:
    """Expand public seed material into a deterministic packed bit vector.

    This is not used as a cryptographic key stream.  It is a reproducible source
    of pseudo-random hypervectors for profile-defined HDC encoders.  SHAKE-256 is
    used because it is deterministic, widely available in Python's standard
    library, and can produce arbitrary-length output without loop bookkeeping.
    """
    preimage = frame_parts(domain, list(parts))
    out = hashlib.shake_256(preimage).digest(_bytes_for_bits(dimension))
    return _mask_unused_trailing_bits(out, dimension)


@dataclass(frozen=True)
class HyperVector:
    """Packed binary hypervector.

    OProW stores binary hypervectors as ``bytes`` plus an explicit dimension.
    The mathematical interpretation is usually bipolar:

        bit 0 -> +1
        bit 1 -> -1

    That mapping is conventional in HDC because binding can be implemented as
    XOR and bundling can be implemented as majority vote.  We keep the packed
    binary form because it is compact and easy to hash into route tokens.
    """

    bits: bytes
    dimension: int

    def __post_init__(self) -> None:
        object.__setattr__(self, "bits", _mask_unused_trailing_bits(self.bits, self.dimension))

    @classmethod
    def from_bool_array(cls, values: np.ndarray | Iterable[bool]) -> "HyperVector":
        """Create a hypervector from a boolean array using MSB-first packing."""
        arr = np.asarray(list(values) if not isinstance(values, np.ndarray) else values, dtype=np.bool_).reshape(-1)
        if arr.size <= 0:
            raise ValidationError("cannot build HyperVector from empty array")
        packed = np.packbits(arr.astype(np.uint8), bitorder="big").tobytes()
        return cls(bits=packed, dimension=int(arr.size))

    @classmethod
    def random(cls, *, domain: str, parts: Iterable[bytes], dimension: int) -> "HyperVector":
        """Create a deterministic public random hypervector."""
        return cls(expand_public_random_bits(domain, parts, dimension), dimension)

    def to_bool_array(self) -> np.ndarray:
        """Return a ``dimension``-length boolean NumPy array."""
        unpacked = np.unpackbits(np.frombuffer(self.bits, dtype=np.uint8), bitorder="big")
        return unpacked[: self.dimension].astype(np.bool_)

    def to_bipolar_array(self) -> np.ndarray:
        """Return +1/-1 int16 values where 0-bit is +1 and 1-bit is -1."""
        b = self.to_bool_array()
        return np.where(b, -1, 1).astype(np.int16)

    def xor(self, other: "HyperVector") -> "HyperVector":
        """HDC binding for binary vectors.

        In bipolar notation binding is element-wise multiplication.  In binary
        notation with the mapping above, the same operation is XOR.
        """
        self._require_same_dimension(other)
        return HyperVector(bytes(a ^ b for a, b in zip(self.bits, other.bits)), self.dimension)

    def hamming_distance(self, other: "HyperVector") -> int:
        """Return the number of differing bits.

        This is useful for diagnostics and benchmarks, not final verification.
        A low Hamming distance indicates similar HDC routing descriptors, not
        signed provenance.
        """
        self._require_same_dimension(other)
        return int(np.count_nonzero(np.bitwise_xor(self.to_bool_array(), other.to_bool_array())))

    def normalized_hamming_distance(self, other: "HyperVector") -> float:
        return self.hamming_distance(other) / float(self.dimension)

    def bit_slice(self, start: int, length: int) -> bytes:
        """Return a packed MSB-first slice of bits.

        Route-token derivation uses this to take a small band code from a larger
        hypervector band.  The returned bytes are still not sent directly to a
        public resolver; routing hashes them into opaque route keys.
        """
        if start < 0 or length <= 0 or start + length > self.dimension:
            raise ValidationError("invalid hypervector bit slice")
        arr = self.to_bool_array()[start : start + length]
        return np.packbits(arr.astype(np.uint8), bitorder="big").tobytes()

    def band_slice(self, *, band_id: int, num_bands: int, bits_per_band: int) -> bytes:
        """Return the first ``bits_per_band`` bits of a contiguous HDC band."""
        if num_bands <= 0 or self.dimension % num_bands != 0:
            raise ValidationError("dimension must be divisible by num_bands")
        if not (0 <= band_id < num_bands):
            raise ValidationError("band_id out of range")
        band_width = self.dimension // num_bands
        if bits_per_band <= 0 or bits_per_band > band_width:
            raise ValidationError("bits_per_band must fit inside each band")
        return self.bit_slice(band_id * band_width, bits_per_band)

    def _require_same_dimension(self, other: "HyperVector") -> None:
        if self.dimension != other.dimension:
            raise ValidationError(f"dimension mismatch: {self.dimension} != {other.dimension}")

    def to_canonical(self) -> dict[str, object]:
        return {"dimension": self.dimension, "bits": self.bits}


class MajorityBundler:
    """Incremental HDC bundler using signed integer vote counts.

    Bundling is the HDC operation that superposes many vectors into one vector.
    Each added vector contributes +1 for a zero bit and -1 for a one bit.  The
    final vector uses the sign of each accumulated coordinate.  Ties are broken
    deterministically by the coordinate parity so that the result is stable.
    """

    def __init__(self, dimension: int):
        if dimension <= 0:
            raise ValidationError("dimension must be positive")
        self.dimension = dimension
        self._counts = np.zeros(dimension, dtype=np.int32)
        self._items = 0

    @property
    def items(self) -> int:
        return self._items

    def add(self, hv: HyperVector) -> None:
        if hv.dimension != self.dimension:
            raise ValidationError("cannot bundle hypervectors with different dimensions")
        self._counts += hv.to_bipolar_array().astype(np.int32)
        self._items += 1

    def result(self) -> HyperVector:
        if self._items == 0:
            raise ValidationError("cannot bundle zero hypervectors")
        tie_break = (np.arange(self.dimension) % 2).astype(np.int32)
        # counts < 0 -> bit 1.  counts > 0 -> bit 0.  counts == 0 uses a fixed
        # alternating pattern rather than random data for deterministic output.
        bits = np.where(self._counts < 0, True, np.where(self._counts > 0, False, tie_break.astype(bool)))
        return HyperVector.from_bool_array(bits)


def bundle_majority(vectors: Iterable[HyperVector]) -> HyperVector:
    """Bundle a finite iterable of hypervectors by majority vote."""
    vectors = list(vectors)
    if not vectors:
        raise ValidationError("cannot bundle an empty vector list")
    bundler = MajorityBundler(vectors[0].dimension)
    for hv in vectors:
        bundler.add(hv)
    return bundler.result()
