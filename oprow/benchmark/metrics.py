"""Metric helpers for OProW benchmark suites.

The OProW proposal repeatedly stresses that robustness claims need hard data:
watermark extraction success after compression/crop/screenshot pipelines,
PED/essence stability under benign transforms, HDC candidate ambiguity under
large corpora, and adversarial failure modes.  This module implements basic
image and bit metrics used by those suites.

None of these metrics are security proofs.  They are diagnostic instruments.
For example, high PSNR says the watermark is visually gentle; it does not say
the watermark survives a hostile platform.  Low HDC Hamming distance says two
artifacts route similarly; it does not verify provenance.  The benchmark reports
therefore label metrics carefully and leave final verification to the Step 5
orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from math import isfinite, log10
from typing import Iterable, Sequence

import numpy as np
from PIL import Image, ImageOps

from oprow.core.errors import ValidationError
from oprow.core.models import Artifact


_RESAMPLING = getattr(Image, "Resampling", Image)


def decode_rgb_array(artifact: Artifact, *, size: tuple[int, int] | None = None) -> np.ndarray:
    """Decode an artifact to an RGB uint8 array.

    If ``size`` is provided, the image is resized with deterministic Pillow
    bicubic resampling.  Benchmarks use this to compare a transformed image back
    to the original resolution for PSNR/MSE diagnostics.
    """

    try:
        with Image.open(BytesIO(artifact.read_bytes())) as img:
            rgb = ImageOps.exif_transpose(img).convert("RGB")
            if size is not None and rgb.size != size:
                rgb = rgb.resize(size, resample=_RESAMPLING.BICUBIC)
            return np.asarray(rgb, dtype=np.uint8)
    except Exception as exc:
        raise ValidationError(f"failed to decode image artifact for metrics: {exc}") from exc


def mse_rgb(reference: Artifact, candidate: Artifact) -> float:
    """Mean squared RGB error after resizing candidate to reference dimensions."""

    ref = decode_rgb_array(reference)
    cand = decode_rgb_array(candidate, size=(ref.shape[1], ref.shape[0]))
    diff = ref.astype(np.float64) - cand.astype(np.float64)
    return float(np.mean(diff * diff))


def psnr_rgb(reference: Artifact, candidate: Artifact) -> float:
    """Peak signal-to-noise ratio in dB for RGB images.

    Infinite PSNR is mathematically possible when arrays are identical.  JSON
    reports and dashboards handle finite values more easily, so the function
    returns ``float('inf')`` and report serializers preserve it as a JSON number
    only if the host JSON library permits it.  Callers can use
    ``finite_psnr_rgb`` when strict JSON compatibility matters.
    """

    mse = mse_rgb(reference, candidate)
    if mse == 0.0:
        return float("inf")
    return 20.0 * log10(255.0 / (mse**0.5))


def finite_psnr_rgb(reference: Artifact, candidate: Artifact, *, identical_value: float = 99.0) -> float:
    """Return PSNR but map infinity to a finite sentinel for JSON reports."""

    value = psnr_rgb(reference, candidate)
    return float(value if isfinite(value) else identical_value)


def byte_difference_fraction(a: bytes, b: bytes) -> float:
    """Fraction of byte positions that differ over the overlapping prefix.

    If the byte strings have different lengths, the length delta contributes as
    additional differing bytes.  This is a crude container-level diagnostic and
    should not be confused with perceptual or cryptographic matching.
    """

    max_len = max(len(a), len(b))
    if max_len == 0:
        return 0.0
    common = min(len(a), len(b))
    differing = sum(1 for x, y in zip(a[:common], b[:common]) if x != y)
    differing += max_len - common
    return differing / float(max_len)


def hamming_fraction_bits(a: Sequence[int] | bytes, b: Sequence[int] | bytes) -> float:
    """Return normalized Hamming distance for bit-like sequences or bytes."""

    if isinstance(a, bytes):
        aa = np.unpackbits(np.frombuffer(a, dtype=np.uint8), bitorder="big")
    else:
        aa = np.asarray(list(a), dtype=np.uint8)
    if isinstance(b, bytes):
        bb = np.unpackbits(np.frombuffer(b, dtype=np.uint8), bitorder="big")
    else:
        bb = np.asarray(list(b), dtype=np.uint8)
    n = min(aa.size, bb.size)
    if n == 0:
        raise ValidationError("cannot compute Hamming fraction over empty sequences")
    diff = int(np.count_nonzero(aa[:n] != bb[:n])) + abs(int(aa.size) - int(bb.size))
    return diff / float(max(int(aa.size), int(bb.size)))


@dataclass(frozen=True)
class ConfusionCounts:
    """Tiny binary-classification count helper for benchmark summaries."""

    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0

    @property
    def total(self) -> int:
        return self.true_positive + self.false_positive + self.true_negative + self.false_negative

    @property
    def accuracy(self) -> float | None:
        return None if self.total == 0 else (self.true_positive + self.true_negative) / self.total

    @property
    def precision(self) -> float | None:
        denom = self.true_positive + self.false_positive
        return None if denom == 0 else self.true_positive / denom

    @property
    def recall(self) -> float | None:
        denom = self.true_positive + self.false_negative
        return None if denom == 0 else self.true_positive / denom

    def to_dict(self) -> dict[str, float | int | None]:
        return {
            "true_positive": self.true_positive,
            "false_positive": self.false_positive,
            "true_negative": self.true_negative,
            "false_negative": self.false_negative,
            "total": self.total,
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
        }


def summarize_boolean_outcomes(outcomes: Iterable[bool]) -> dict[str, float | int]:
    values = list(bool(v) for v in outcomes)
    n = len(values)
    positives = sum(1 for v in values if v)
    return {"count": n, "true": positives, "false": n - positives, "true_fraction": 0.0 if n == 0 else positives / n}


__all__ = [
    "ConfusionCounts",
    "byte_difference_fraction",
    "decode_rgb_array",
    "finite_psnr_rgb",
    "hamming_fraction_bits",
    "mse_rgb",
    "psnr_rgb",
    "summarize_boolean_outcomes",
]
