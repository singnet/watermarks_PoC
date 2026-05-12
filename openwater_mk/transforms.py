"""Channel-robustness transforms wired into the demo CLI.

The transforms themselves come from the upstream oprow benchmark suite.
This module just names the subset exposed via the CLI ``--transform`` flag.
"""
from __future__ import annotations

from oprow.benchmark.transforms import (
    JPEGRecompressTransform,
    PNGRoundTripTransform,
)

TRANSFORMS = {
    "png_rgba": PNGRoundTripTransform(mode="RGBA", name="png_roundtrip_rgba"),
    "png_rgb": PNGRoundTripTransform(mode="RGB", name="png_roundtrip_rgb"),
    "jpeg_q82": JPEGRecompressTransform(quality=82),
    "jpeg_q60": JPEGRecompressTransform(quality=60),
}

__all__ = ["TRANSFORMS"]
