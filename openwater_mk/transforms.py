"""Channel-robustness transforms wired into the demo CLI.

The transforms themselves come from the vendored oprow benchmark suite.
This module just names the subset exposed via the CLI ``--transform`` flag.

Tier 2 expands the matrix with:

- ``jpeg_q70`` — mid-quality JPEG; the inflection point where the SDK's
  stock DCT-QIM profile starts losing bits on the synthetic corpus.
- ``jpeg_cascade_85_70`` — two-stage JPEG round-trip; approximates a
  re-upload through a service that always recompresses.
- ``social_pipeline`` — the SDK's social-media normalization (max edge
  resize + JPEG). Tests geometry recovery, which the V0 carriers
  intentionally do not implement; expected to drop the locator until
  Tier 2.5 ships a sync template.
- ``resize_0_9`` — modest bicubic downscale. Same geometry expectation.
"""
from __future__ import annotations

from dataclasses import dataclass

from oprow.benchmark.transforms import (
    JPEGRecompressTransform,
    PNGRoundTripTransform,
    ResizeTransform,
    SocialPipelineTransform,
)
from oprow.core.models import Artifact


@dataclass(frozen=True)
class _ComposeTransform:
    """Apply a sequence of transforms in order.

    The vendored SDK exposes ``SocialPipelineTransform`` for resize+JPEG
    but does not ship a generic compose primitive, so we add a tiny one
    here. ``name`` is what shows up in the artifact metadata.
    """

    stages: tuple
    name: str

    def apply(self, artifact: Artifact) -> Artifact:
        out = artifact
        for stage in self.stages:
            out = stage.apply(out)
        return out


TRANSFORMS = {
    "png_rgba": PNGRoundTripTransform(mode="RGBA", name="png_roundtrip_rgba"),
    "png_rgb": PNGRoundTripTransform(mode="RGB", name="png_roundtrip_rgb"),
    "jpeg_q82": JPEGRecompressTransform(quality=82),
    "jpeg_q70": JPEGRecompressTransform(quality=70),
    "jpeg_q60": JPEGRecompressTransform(quality=60),
    "jpeg_cascade_85_70": _ComposeTransform(
        stages=(
            JPEGRecompressTransform(quality=85, name="jpeg_q85_first"),
            JPEGRecompressTransform(quality=70, name="jpeg_q70_second"),
        ),
        name="jpeg_cascade_85_70",
    ),
    "social_pipeline": SocialPipelineTransform(max_edge=160, jpeg_quality=78, name="social_pipeline_max160_q78"),
    "resize_0_9": ResizeTransform(scale=0.9, name="resize_0_9"),
}

__all__ = ["TRANSFORMS"]
