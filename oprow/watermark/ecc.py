"""Toy error-correction layer used by Step 12 watermark profiles.

Real robust watermark systems normally use stronger codes: BCH, Reed--Solomon,
LDPC, turbo codes, or rateless constructions, often with soft-decision decoding.
The OProW proposal explicitly says the watermark payload must be expanded by ECC
and repetition because media transforms are noisy.  Implementing a full
production-grade code is outside Step 12's reference scope, so this file starts
with the smallest useful code: an odd repetition code with majority decoding.

Why include such a simple code?

* It makes the payload-vs-physics tradeoff concrete.  A 200-bit FULL160 payload
  becomes 600 embedded carrier bits with repetition=3 before sync overhead.
* It gives all watermark profiles a shared codec boundary.  Later steps can swap
  in BCH/LDPC without changing payload or resolver logic.
* It supports literate tests for noisy extraction: one corrupted carrier bit in
  a triple should not corrupt the recovered payload bit.

This module should therefore be read as an educational/reference codec, not as a
claim that repetition coding is sufficient for hostile social-media pipelines.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

from oprow.core.errors import ValidationError
from .bits import normalize_bits


@dataclass(frozen=True)
class RepetitionDecodeReport:
    """Diagnostics produced by majority decoding.

    ``corrected_groups`` counts groups where the individual carrier bits did not
    all agree.  It is a useful extractor-health signal, but it is not a security
    signal.  A malicious attacker can always create confidently wrong carrier
    bits; later manifest verification must catch that.
    """

    decoded_bits: list[int]
    repetitions: int
    groups_seen: int
    corrected_groups: int
    confidences: list[float] = field(default_factory=list)


@dataclass(frozen=True)
class RepetitionCode:
    """Odd repetition code with majority decoding.

    ``repetitions`` must be positive and odd.  For each input bit, encoding emits
    that bit ``repetitions`` times.  Decoding groups carrier bits in the same
    fixed order and takes the majority value.
    """

    repetitions: int = 3

    def __post_init__(self) -> None:
        if self.repetitions <= 0:
            raise ValidationError("repetitions must be positive")
        if self.repetitions % 2 == 0:
            raise ValidationError("repetitions must be odd so majority decoding is unambiguous")

    def encode(self, bits: Iterable[int]) -> list[int]:
        """Repeat each input bit ``repetitions`` times."""

        out: list[int] = []
        for bit in normalize_bits(bits):
            out.extend([bit] * self.repetitions)
        return out

    def decode(self, carrier_bits: Sequence[int]) -> RepetitionDecodeReport:
        """Majority-decode carrier bits.

        Incomplete trailing carrier groups are ignored.  This is intentional:
        image/audio/video profiles may expose more carrier positions than were
        actually used.  The framed watermark layer later checks the preamble,
        length, and payload CRC.
        """

        bits = normalize_bits(carrier_bits)
        groups = len(bits) // self.repetitions
        decoded: list[int] = []
        confidences: list[float] = []
        corrected = 0
        for i in range(groups):
            chunk = bits[i * self.repetitions : (i + 1) * self.repetitions]
            ones = sum(chunk)
            zeros = self.repetitions - ones
            value = 1 if ones > zeros else 0
            decoded.append(value)
            margin = abs(ones - zeros)
            confidences.append(margin / self.repetitions)
            if not (ones == 0 or zeros == 0):
                corrected += 1
        return RepetitionDecodeReport(
            decoded_bits=decoded,
            repetitions=self.repetitions,
            groups_seen=groups,
            corrected_groups=corrected,
            confidences=confidences,
        )
