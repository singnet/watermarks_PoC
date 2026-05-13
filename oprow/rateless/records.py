"""Compact tile records for the Step 13 rateless watermark experiment.

The rateless equation layer says that a media region should carry a pair
``(equation_id, rhs_bit)``.  This file defines a tiny binary record for carrying
that pair inside a local tile/window.

Record layout
-------------
The reference record is 56 bits:

    16 bits  preamble       ASCII "OR" (OProW Rateless)
     4 bits  version        currently 1
    16 bits  equation_id    tile/window equation identifier
     1 bit   rhs            equation response bit
     3 bits  reserved       currently 000
    16 bits  crc16          CRC over version|id|rhs|reserved

A production robust carrier might use BCH/LDPC codes, sync templates, and soft
confidence values.  The Step 13 reference profile simply repeats this 56-bit
record within each tile and majority-decodes each bit.  This is intentionally
small enough to fit into a 16x16 alpha-LSB tile with three repetitions:

    56 record bits × 3 = 168 carrier bits < 256 pixels.

Security boundary
-----------------
A valid tile CRC only means one local equation was recovered.  It does not prove
provenance.  Only after enough independent equations reconstruct the FULL160
manifest key can the normal OProW verifier resolve and check the signed manifest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Sequence

from oprow.core.errors import ValidationError
from oprow.watermark.bits import bits_to_bytes, bits_to_int, bytes_to_bits, int_to_bits, normalize_bits
from oprow.watermark.crc import crc16_ccitt_false

RATELESS_RECORD_VERSION = 1
RATELESS_TILE_PREAMBLE_BYTES = b"OR"
RATELESS_TILE_PREAMBLE_BITS = bytes_to_bits(RATELESS_TILE_PREAMBLE_BYTES)
RATELESS_RECORD_ID_BITS = 16
RATELESS_RECORD_RESERVED_BITS = 3
RATELESS_RECORD_CRC_BITS = 16
RATELESS_RECORD_BITS = 16 + 4 + RATELESS_RECORD_ID_BITS + 1 + RATELESS_RECORD_RESERVED_BITS + RATELESS_RECORD_CRC_BITS


@dataclass(frozen=True)
class RatelessTileRecord:
    """One local carrier record: equation ID plus RHS bit."""

    equation_id: int
    rhs: int
    version: int = RATELESS_RECORD_VERSION
    reserved: int = 0

    def __post_init__(self) -> None:
        if not (0 <= self.version <= 0xF):
            raise ValidationError("rateless record version must fit in 4 bits")
        if not (0 <= self.equation_id < (1 << RATELESS_RECORD_ID_BITS)):
            raise ValidationError(f"equation_id must fit in {RATELESS_RECORD_ID_BITS} bits")
        if int(self.rhs) not in (0, 1):
            raise ValidationError("rateless record rhs must be 0/1")
        if not (0 <= self.reserved < (1 << RATELESS_RECORD_RESERVED_BITS)):
            raise ValidationError("rateless record reserved field out of range")

    def protected_bits(self) -> list[int]:
        """Bits covered by the CRC.

        The preamble is not CRC-covered because it is a synchronization marker.
        Corrupting the preamble usually causes record rejection before CRC.
        """

        bits: list[int] = []
        bits.extend(int_to_bits(self.version, 4))
        bits.extend(int_to_bits(self.equation_id, RATELESS_RECORD_ID_BITS))
        bits.append(int(self.rhs))
        bits.extend(int_to_bits(self.reserved, RATELESS_RECORD_RESERVED_BITS))
        return bits

    def crc16(self) -> int:
        """CRC-16/CCITT-FALSE over the protected fields."""

        return crc16_ccitt_false(bits_to_bytes(self.protected_bits(), pad=True))

    def to_bits(self) -> list[int]:
        """Serialize the record to exactly ``RATELESS_RECORD_BITS`` bits."""

        bits = list(RATELESS_TILE_PREAMBLE_BITS)
        bits.extend(self.protected_bits())
        bits.extend(int_to_bits(self.crc16(), RATELESS_RECORD_CRC_BITS))
        if len(bits) != RATELESS_RECORD_BITS:
            raise AssertionError("rateless record layout length mismatch")
        return bits

    @classmethod
    def decode_bits(cls, bits: Sequence[int], *, require_crc: bool = True) -> "RatelessTileRecord":
        """Decode a tile record and optionally check CRC."""

        b = normalize_bits(bits)
        if len(b) < RATELESS_RECORD_BITS:
            raise ValidationError(f"rateless tile record needs {RATELESS_RECORD_BITS} bits, got {len(b)}")
        b = b[:RATELESS_RECORD_BITS]
        if b[: len(RATELESS_TILE_PREAMBLE_BITS)] != RATELESS_TILE_PREAMBLE_BITS:
            raise ValidationError("rateless tile preamble not found")
        pos = len(RATELESS_TILE_PREAMBLE_BITS)
        version = bits_to_int(b[pos : pos + 4]); pos += 4
        equation_id = bits_to_int(b[pos : pos + RATELESS_RECORD_ID_BITS]); pos += RATELESS_RECORD_ID_BITS
        rhs = bits_to_int(b[pos : pos + 1]); pos += 1
        reserved = bits_to_int(b[pos : pos + RATELESS_RECORD_RESERVED_BITS]); pos += RATELESS_RECORD_RESERVED_BITS
        crc = bits_to_int(b[pos : pos + RATELESS_RECORD_CRC_BITS])
        record = cls(equation_id=equation_id, rhs=rhs, version=version, reserved=reserved)
        if require_crc and record.crc16() != crc:
            raise ValidationError(f"rateless tile CRC mismatch: expected {record.crc16():04x}, got {crc:04x}")
        return record


@dataclass(frozen=True)
class RepeatedRecordDecode:
    """Decoded repeated tile record plus diagnostics."""

    record: RatelessTileRecord
    repetitions: int
    bit_disagreements: int
    confidence: float
    diagnostics: dict[str, object] = field(default_factory=dict)


def encode_repeated_record(record: RatelessTileRecord, *, repetitions: int) -> list[int]:
    """Repeat a tile record bitstream ``repetitions`` times."""

    if repetitions <= 0:
        raise ValidationError("record repetitions must be positive")
    base = record.to_bits()
    return base * repetitions


def majority_decode_repeated_record(bits: Sequence[int], *, repetitions: int) -> RepeatedRecordDecode:
    """Majority-decode a repeated tile record.

    The input sequence may contain more bits than required; only the prefix
    containing ``repetitions`` copies is consumed.  Confidence is a simple 0..1
    score: the fraction of per-bit votes that agreed with the majority.  Future
    soft-decision carriers can replace this with log-likelihoods.
    """

    if repetitions <= 0:
        raise ValidationError("record repetitions must be positive")
    needed = RATELESS_RECORD_BITS * repetitions
    carrier = normalize_bits(bits)
    if len(carrier) < needed:
        raise ValidationError(f"not enough tile carrier bits: need {needed}, got {len(carrier)}")
    decoded: list[int] = []
    disagreements = 0
    total_votes = RATELESS_RECORD_BITS * repetitions
    for i in range(RATELESS_RECORD_BITS):
        votes = [carrier[i + copy * RATELESS_RECORD_BITS] for copy in range(repetitions)]
        ones = sum(votes)
        zeros = repetitions - ones
        bit = 1 if ones > zeros else 0
        decoded.append(bit)
        disagreements += min(ones, zeros)
    record = RatelessTileRecord.decode_bits(decoded, require_crc=True)
    confidence = 1.0 - (disagreements / total_votes if total_votes else 0.0)
    return RepeatedRecordDecode(
        record=record,
        repetitions=repetitions,
        bit_disagreements=disagreements,
        confidence=confidence,
        diagnostics={"needed_bits": needed, "record_bits": RATELESS_RECORD_BITS},
    )
