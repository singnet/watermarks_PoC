"""Small synthetic media samples for OProW benchmarks and tests.

A serious OProW evaluation needs real corpora: photographs, generated images,
news imagery, screenshots, social-media transcodes, video/audio samples, and
adversarially generated near-collisions.  The reference SDK cannot ship those
corpora.  This module provides tiny deterministic synthetic images so unit tests
and examples can run anywhere.

The samples are intentionally simple but not uniform.  They contain gradients,
stripes, and geometric shapes so PED/HDC/watermark code has nontrivial content
to process.  Each function returns an ``Artifact`` with a stable ``artifact_id``
in metadata, making benchmark reports readable.
"""

from __future__ import annotations

from io import BytesIO
from typing import Iterable

import numpy as np
from PIL import Image, ImageDraw

from oprow.core.models import Artifact


def _artifact_from_rgb_array(arr: np.ndarray, *, artifact_id: str) -> Artifact:
    img = Image.fromarray(np.asarray(arr, dtype=np.uint8), mode="RGB")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return Artifact.from_bytes(buf.getvalue(), media_type="image/png", metadata={"artifact_id": artifact_id})


def gradient_sample(*, size: tuple[int, int] = (192, 192), artifact_id: str = "gradient") -> Artifact:
    """Create a smooth RGB gradient with a contrasting diagonal stripe."""

    w, h = size
    x = np.linspace(0, 255, w, dtype=np.float32)[None, :]
    y = np.linspace(0, 255, h, dtype=np.float32)[:, None]
    arr = np.zeros((h, w, 3), dtype=np.uint8)
    arr[:, :, 0] = np.clip(x, 0, 255).astype(np.uint8)
    arr[:, :, 1] = np.clip(y, 0, 255).astype(np.uint8)
    arr[:, :, 2] = np.clip(180 - 0.35 * x + 0.25 * y, 0, 255).astype(np.uint8)
    for i in range(min(w, h)):
        arr[max(0, i - 1) : min(h, i + 2), i, :] = (245, 230, 70)
    return _artifact_from_rgb_array(arr, artifact_id=artifact_id)


def checker_sample(*, size: tuple[int, int] = (192, 192), block: int = 16, artifact_id: str = "checker") -> Artifact:
    """Create a checkerboard with colored circles and rectangles."""

    w, h = size
    arr = np.zeros((h, w, 3), dtype=np.uint8)
    for y in range(h):
        for x in range(w):
            if ((x // block) + (y // block)) % 2 == 0:
                arr[y, x] = (70, 120, 200)
            else:
                arr[y, x] = (210, 235, 245)
    img = Image.fromarray(arr, mode="RGB")
    draw = ImageDraw.Draw(img)
    draw.ellipse((w // 5, h // 5, w // 2, h // 2), fill=(240, 80, 80))
    draw.rectangle((w // 2, h // 2, w - w // 8, h - h // 5), fill=(60, 170, 90))
    buf = BytesIO()
    img.save(buf, format="PNG")
    return Artifact.from_bytes(buf.getvalue(), media_type="image/png", metadata={"artifact_id": artifact_id})


def solid_with_stripe_sample(*, size: tuple[int, int] = (192, 192), artifact_id: str = "stripe") -> Artifact:
    """Create a mostly solid image with a horizontal stripe.

    This resembles the simple examples used in earlier steps and is useful for
    watermark tests because the RGB essence is easy to compare before/after
    alpha-LSB embedding.
    """

    img = Image.new("RGB", size, color=(82, 118, 180))
    draw = ImageDraw.Draw(img)
    w, h = size
    draw.rectangle((w // 8, h // 2 - 10, w - w // 8, h // 2 + 10), fill=(245, 230, 70))
    buf = BytesIO()
    img.save(buf, format="PNG")
    return Artifact.from_bytes(buf.getvalue(), media_type="image/png", metadata={"artifact_id": artifact_id})


def default_synthetic_image_corpus() -> list[Artifact]:
    """Return a tiny deterministic image corpus for smoke benchmarks."""

    return [gradient_sample(), checker_sample(), solid_with_stripe_sample()]


__all__ = [
    "checker_sample",
    "default_synthetic_image_corpus",
    "gradient_sample",
    "solid_with_stripe_sample",
]
