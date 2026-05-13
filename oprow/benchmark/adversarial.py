"""Adversarial probes for OProW watermark/essence verification.

The OProW design makes a crucial promise: attacks on the retrieval layer should
not become false provenance.  If an adversary strips a watermark, creates an HDC
collision, or copies a watermark from one image to another, the system should at
worst return ``NO_WATERMARK``, ``CONTENT_MISMATCH``, ``AMBIGUOUS``, or a similar
non-verified state.

This module implements small deterministic probes for that behavior.  They are
not a complete adversarial ML suite.  They are CI-friendly checks that the
reference implementation preserves the security boundary:

    watermark/HDC/resolver == candidate discovery
    signature + essence + trust policy == verification
"""

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO
from typing import Any

import numpy as np
from PIL import Image, ImageOps

from oprow.core.models import Artifact
from oprow.verification.result import VerificationResult

from .reports import BenchmarkCase, MetricSample
from .transforms import ArtifactTransform, TransformSuite


@dataclass(frozen=True)
class AlphaLSBStripTransform:
    """Destroy alpha-LSB carriers while leaving RGB unchanged.

    This is hostile to the Step 12/13 alpha reference carriers.  It deliberately
    does not model production watermark attacks; it is a simple regression test
    for the rule that a stripped locator must not verify.
    """

    name: str = "alpha_lsb_strip"
    alpha_value: int = 255

    def apply(self, artifact: Artifact) -> Artifact:
        with Image.open(BytesIO(artifact.read_bytes())) as img:
            rgba = ImageOps.exif_transpose(img).convert("RGBA")
        arr = np.asarray(rgba, dtype=np.uint8).copy()
        arr[:, :, 3] = int(self.alpha_value) & 0xFE  # force low bit to zero
        out = Image.fromarray(arr, mode="RGBA")
        buf = BytesIO()
        out.save(buf, format="PNG")
        return Artifact.from_bytes(buf.getvalue(), media_type="image/png", metadata={**artifact.metadata, "transform": self.name})


@dataclass(frozen=True)
class RandomRectangleOcclusionTransform:
    """Paint a deterministic rectangle over the RGB content.

    Occlusion is a content attack rather than just a channel transform.  A robust
    watermark may still extract after occlusion, but the signed essence hash
    should generally change.  Final verification must therefore fail unless the
    manifest explicitly supports region-level partial verification.
    """

    fraction: float = 0.20
    seed: int = 7
    color: tuple[int, int, int] = (0, 0, 0)
    name: str | None = None

    def __post_init__(self) -> None:
        if not (0 < self.fraction < 1):
            raise ValueError("fraction must be in (0, 1)")
        if self.name is None:
            object.__setattr__(self, "name", f"occlusion_{self.fraction:g}")

    def apply(self, artifact: Artifact) -> Artifact:
        with Image.open(BytesIO(artifact.read_bytes())) as img:
            rgb = ImageOps.exif_transpose(img).convert("RGB")
        arr = np.asarray(rgb, dtype=np.uint8).copy()
        h, w = arr.shape[:2]
        rect_w = max(1, int(round(w * self.fraction)))
        rect_h = max(1, int(round(h * self.fraction)))
        rng = np.random.default_rng(self.seed)
        x0 = int(rng.integers(0, max(1, w - rect_w + 1)))
        y0 = int(rng.integers(0, max(1, h - rect_h + 1)))
        arr[y0 : y0 + rect_h, x0 : x0 + rect_w, :] = np.asarray(self.color, dtype=np.uint8)
        out = Image.fromarray(arr, mode="RGB")
        buf = BytesIO()
        out.save(buf, format="PNG")
        return Artifact.from_bytes(buf.getvalue(), media_type="image/png", metadata={**artifact.metadata, "transform": self.name})


@dataclass(frozen=True)
class TileAlphaErasureTransform:
    """Erase alpha-LSB records in a prefix of tiles.

    This is useful for rateless FULL160 experiments.  A rateless profile should
    tolerate some erasures if enough independent equations survive; once rank is
    too low, extraction should fail rather than guess a locator.
    """

    tile_size: int = 16
    erase_tiles: int = 32
    name: str | None = None

    def __post_init__(self) -> None:
        if self.tile_size <= 0 or self.erase_tiles < 0:
            raise ValueError("tile_size must be positive and erase_tiles non-negative")
        if self.name is None:
            object.__setattr__(self, "name", f"tile_alpha_erasure_{self.erase_tiles}")

    def apply(self, artifact: Artifact) -> Artifact:
        with Image.open(BytesIO(artifact.read_bytes())) as img:
            rgba = ImageOps.exif_transpose(img).convert("RGBA")
        arr = np.asarray(rgba, dtype=np.uint8).copy()
        width, height = rgba.size
        erased = 0
        for ty in range(height // self.tile_size):
            for tx in range(width // self.tile_size):
                if erased >= self.erase_tiles:
                    break
                x0, y0 = tx * self.tile_size, ty * self.tile_size
                arr[y0 : y0 + self.tile_size, x0 : x0 + self.tile_size, 3] &= 0xFE
                erased += 1
            if erased >= self.erase_tiles:
                break
        out = Image.fromarray(arr, mode="RGBA")
        buf = BytesIO()
        out.save(buf, format="PNG")
        return Artifact.from_bytes(buf.getvalue(), media_type="image/png", metadata={**artifact.metadata, "transform": self.name, "erased_tiles": erased})


def copy_alpha_lsb_carrier(source_watermarked: Artifact, target_visible: Artifact) -> Artifact:
    """Copy alpha LSBs from a watermarked source onto a target's RGB content.

    This models a toy copy/paste watermark attack for the Step 12 alpha carrier:
    the target receives the source locator but keeps its own visible pixels.  If
    the verifier then resolves the source manifest, the essence check should
    fail with ``CONTENT_MISMATCH`` rather than returning verified provenance.
    """

    with Image.open(BytesIO(source_watermarked.read_bytes())) as s_img:
        s = ImageOps.exif_transpose(s_img).convert("RGBA")
    with Image.open(BytesIO(target_visible.read_bytes())) as t_img:
        t = ImageOps.exif_transpose(t_img).convert("RGBA")
    if t.size != s.size:
        t = t.resize(s.size, resample=getattr(Image, "Resampling", Image).BICUBIC)
    s_arr = np.asarray(s, dtype=np.uint8)
    t_arr = np.asarray(t, dtype=np.uint8).copy()
    # Preserve target alpha high bits but overwrite the low bit with source
    # carrier data.  For opaque targets this means alpha values become 254/255.
    t_arr[:, :, 3] = (t_arr[:, :, 3] & 0xFE) | (s_arr[:, :, 3] & 0x01)
    out = Image.fromarray(t_arr, mode="RGBA")
    buf = BytesIO()
    out.save(buf, format="PNG")
    return Artifact.from_bytes(buf.getvalue(), media_type="image/png", metadata={**target_visible.metadata, "attack": "copy_alpha_lsb_carrier"})


@dataclass(frozen=True)
class AdversarialVerificationCase:
    """Record final verifier behavior for one adversarial probe."""

    name: str
    artifact_id: str
    attack: str
    expected_not_verified: bool
    verification: VerificationResult
    diagnostics: dict[str, Any] = field(default_factory=dict)

    def to_case(self) -> BenchmarkCase:
        verified = self.verification.verified
        return BenchmarkCase(
            kind="adversarial_verification",
            name=self.name,
            artifact_id=self.artifact_id,
            transform=self.attack,
            profile_id="full_verifier",
            status="safe_rejection" if self.expected_not_verified and not verified else "unexpected_verification" if verified else "measured",
            metrics=[MetricSample("verified", verified), MetricSample("expected_not_verified", self.expected_not_verified)],
            diagnostics={"verification_status": self.verification.status.value, **self.diagnostics},
        )


def adversarial_image_transform_suite() -> TransformSuite:
    return TransformSuite(
        name="adversarial_image",
        description="CI-friendly hostile transforms for stripping, occlusion, and rateless erasures.",
        transforms=(
            AlphaLSBStripTransform(),
            RandomRectangleOcclusionTransform(fraction=0.25, seed=17),
            TileAlphaErasureTransform(tile_size=16, erase_tiles=64),
        ),
    )


__all__ = [
    "AdversarialVerificationCase",
    "AlphaLSBStripTransform",
    "RandomRectangleOcclusionTransform",
    "TileAlphaErasureTransform",
    "adversarial_image_transform_suite",
    "copy_alpha_lsb_carrier",
]
