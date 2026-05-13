"""Image transform suite for OProW robustness benchmarking.

OProW's watermark and essence layers are designed for the ugly distribution
reality of modern media: social platforms resize and recompress images, users
crop screenshots, messaging apps strip metadata, and forensic archives may keep
exact bytes.  A reference SDK therefore needs a repeatable transform harness.

This module implements deterministic, local image transforms.  They are not a
substitute for testing against real platforms, but they give the development
team a stable baseline for CI and for comparing watermark/PED/HDC profiles.

Terminology
===========

* *Benign transform*: something a normal distribution channel may do, such as a
  JPEG round-trip or resize.  A robust profile should usually survive it.
* *Hostile transform*: something that intentionally destroys a carrier or causes
  ambiguity.  Surviving it may be impossible; the correct OProW behavior is to
  return unverified/ambiguous rather than a false verification.

The transforms all accept and return ``Artifact`` objects.  They deliberately do
not inspect manifests or trust policy.  That keeps the harness aligned with the
OProW architecture: media degradation is measured separately from provenance
verification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO
from typing import Any, Iterable, Protocol

import numpy as np
from PIL import Image, ImageEnhance, ImageFilter, ImageOps

from oprow.core.errors import ValidationError
from oprow.core.models import Artifact


_RESAMPLING = getattr(Image, "Resampling", Image)


class ArtifactTransform(Protocol):
    """Protocol for deterministic benchmark transforms."""

    name: str

    def apply(self, artifact: Artifact) -> Artifact:
        ...


@dataclass(frozen=True)
class TransformApplication:
    """Result of applying a transform.

    ``succeeded`` is false when decoding or transform execution failed.  The
    benchmark runners record this as a case rather than crashing an entire suite,
    because unsupported media is common in exploratory robustness testing.
    """

    transform_name: str
    artifact: Artifact | None
    succeeded: bool
    diagnostics: dict[str, Any] = field(default_factory=dict)
    error: str | None = None


def _decode_image(artifact: Artifact, *, mode: str = "RGB") -> Image.Image:
    try:
        with Image.open(BytesIO(artifact.read_bytes())) as img:
            return ImageOps.exif_transpose(img).convert(mode)
    except Exception as exc:
        raise ValidationError(f"failed to decode image for transform: {exc}") from exc


def _artifact_from_image(image: Image.Image, *, fmt: str = "PNG", media_type: str | None = None, metadata: dict[str, Any] | None = None, **save_kwargs: Any) -> Artifact:
    buf = BytesIO()
    image.save(buf, format=fmt, **save_kwargs)
    mt = media_type or ("image/jpeg" if fmt.upper() in {"JPEG", "JPG"} else "image/png")
    return Artifact.from_bytes(buf.getvalue(), media_type=mt, metadata=metadata or {})


@dataclass(frozen=True)
class IdentityTransform:
    """Return the original bytes unchanged.

    This transform is useful as a control row: watermark extraction and essence
    matching should succeed unless embedding itself broke something.
    """

    name: str = "identity"

    def apply(self, artifact: Artifact) -> Artifact:
        return Artifact.from_bytes(artifact.read_bytes(), media_type=artifact.media_type, metadata=dict(artifact.metadata))


@dataclass(frozen=True)
class PNGRoundTripTransform:
    """Decode to RGB/RGBA and save as PNG.

    The transform strips most container metadata and normalizes the container,
    which approximates a metadata-stripping channel while keeping pixels mostly
    unchanged.  It destroys carriers that depend on non-image metadata, but it
    should preserve RGB-visible content.
    """

    name: str = "png_roundtrip"
    mode: str = "RGB"

    def apply(self, artifact: Artifact) -> Artifact:
        img = _decode_image(artifact, mode=self.mode)
        return _artifact_from_image(img, fmt="PNG", media_type="image/png", metadata={"transform": self.name})


@dataclass(frozen=True)
class JPEGRecompressTransform:
    """Save an image as JPEG at a fixed quality.

    This is the canonical still-image lossy transform for OProW testing.  It is
    expected to destroy alpha-channel reference watermarks and to stress DCT/QIM
    prototypes, while a good PED profile should remain stable enough under
    moderate quality settings.
    """

    quality: int = 82
    name: str | None = None

    def __post_init__(self) -> None:
        if not (1 <= self.quality <= 100):
            raise ValidationError("JPEG quality must be in 1..100")
        if self.name is None:
            object.__setattr__(self, "name", f"jpeg_q{self.quality}")

    def apply(self, artifact: Artifact) -> Artifact:
        img = _decode_image(artifact, mode="RGB")
        return _artifact_from_image(img, fmt="JPEG", media_type="image/jpeg", metadata={"transform": self.name}, quality=self.quality, optimize=False)


@dataclass(frozen=True)
class ResizeTransform:
    """Resize by scale or explicit size and save as PNG."""

    scale: float | None = None
    size: tuple[int, int] | None = None
    name: str | None = None

    def __post_init__(self) -> None:
        if self.scale is None and self.size is None:
            raise ValidationError("ResizeTransform requires scale or size")
        if self.scale is not None and self.scale <= 0:
            raise ValidationError("resize scale must be positive")
        if self.name is None:
            label = f"scale_{self.scale:g}" if self.scale is not None else f"resize_{self.size[0]}x{self.size[1]}"
            object.__setattr__(self, "name", label)

    def apply(self, artifact: Artifact) -> Artifact:
        img = _decode_image(artifact, mode="RGB")
        if self.size is not None:
            new_size = self.size
        else:
            new_size = (max(1, int(round(img.size[0] * float(self.scale)))), max(1, int(round(img.size[1] * float(self.scale)))))
        out = img.resize(new_size, resample=_RESAMPLING.BICUBIC)
        return _artifact_from_image(out, fmt="PNG", media_type="image/png", metadata={"transform": self.name, "size": new_size})


@dataclass(frozen=True)
class CenterCropTransform:
    """Crop the central region, optionally resizing back to original size."""

    keep_fraction: float = 0.80
    resize_back: bool = False
    name: str | None = None

    def __post_init__(self) -> None:
        if not (0 < self.keep_fraction <= 1):
            raise ValidationError("keep_fraction must be in (0, 1]")
        if self.name is None:
            suffix = "_resizeback" if self.resize_back else ""
            object.__setattr__(self, "name", f"center_crop_{self.keep_fraction:g}{suffix}")

    def apply(self, artifact: Artifact) -> Artifact:
        img = _decode_image(artifact, mode="RGB")
        w, h = img.size
        nw, nh = max(1, int(round(w * self.keep_fraction))), max(1, int(round(h * self.keep_fraction)))
        x0 = (w - nw) // 2
        y0 = (h - nh) // 2
        cropped = img.crop((x0, y0, x0 + nw, y0 + nh))
        if self.resize_back:
            cropped = cropped.resize((w, h), resample=_RESAMPLING.BICUBIC)
        return _artifact_from_image(cropped, fmt="PNG", media_type="image/png", metadata={"transform": self.name})


@dataclass(frozen=True)
class GaussianNoiseTransform:
    """Add deterministic RGB Gaussian noise and save as PNG."""

    sigma: float = 3.0
    seed: int = 1
    name: str | None = None

    def __post_init__(self) -> None:
        if self.sigma < 0:
            raise ValidationError("sigma must be non-negative")
        if self.name is None:
            object.__setattr__(self, "name", f"gaussian_noise_sigma{self.sigma:g}")

    def apply(self, artifact: Artifact) -> Artifact:
        img = _decode_image(artifact, mode="RGB")
        arr = np.asarray(img, dtype=np.float32)
        rng = np.random.default_rng(self.seed)
        noisy = np.clip(arr + rng.normal(0.0, self.sigma, size=arr.shape), 0, 255).astype(np.uint8)
        return _artifact_from_image(Image.fromarray(noisy, mode="RGB"), fmt="PNG", media_type="image/png", metadata={"transform": self.name})


@dataclass(frozen=True)
class GaussianBlurTransform:
    """Apply a small deterministic Gaussian blur."""

    radius: float = 0.75
    name: str | None = None

    def __post_init__(self) -> None:
        if self.radius < 0:
            raise ValidationError("blur radius must be non-negative")
        if self.name is None:
            object.__setattr__(self, "name", f"gaussian_blur_r{self.radius:g}")

    def apply(self, artifact: Artifact) -> Artifact:
        img = _decode_image(artifact, mode="RGB")
        out = img.filter(ImageFilter.GaussianBlur(radius=self.radius))
        return _artifact_from_image(out, fmt="PNG", media_type="image/png", metadata={"transform": self.name})


@dataclass(frozen=True)
class BrightnessContrastTransform:
    """Adjust brightness and contrast with Pillow's deterministic enhancers."""

    brightness: float = 1.05
    contrast: float = 1.05
    name: str | None = None

    def __post_init__(self) -> None:
        if self.brightness <= 0 or self.contrast <= 0:
            raise ValidationError("brightness and contrast factors must be positive")
        if self.name is None:
            object.__setattr__(self, "name", f"brightness{self.brightness:g}_contrast{self.contrast:g}")

    def apply(self, artifact: Artifact) -> Artifact:
        img = _decode_image(artifact, mode="RGB")
        img = ImageEnhance.Brightness(img).enhance(self.brightness)
        img = ImageEnhance.Contrast(img).enhance(self.contrast)
        return _artifact_from_image(img, fmt="PNG", media_type="image/png", metadata={"transform": self.name})


@dataclass(frozen=True)
class ScreenshotSimulationTransform:
    """A cheap deterministic stand-in for screenshot/re-display pipelines.

    Real screenshot tests should be performed on actual OS/platform stacks.  This
    transform approximates the common damage: RGB compositing, resampling, and a
    JPEG-like lossy round trip.  It is useful in CI because it is local and
    deterministic.
    """

    scale_up: float = 1.25
    jpeg_quality: int = 88
    name: str = "screenshot_sim"

    def apply(self, artifact: Artifact) -> Artifact:
        img = _decode_image(artifact, mode="RGB")
        original = img.size
        up = (max(1, int(round(original[0] * self.scale_up))), max(1, int(round(original[1] * self.scale_up))))
        sim = img.resize(up, resample=_RESAMPLING.BICUBIC).resize(original, resample=_RESAMPLING.BICUBIC)
        # JPEG round-trip in memory, then return as PNG so downstream tools can
        # read it without caring about JPEG metadata.
        tmp = BytesIO()
        sim.save(tmp, format="JPEG", quality=self.jpeg_quality, optimize=False)
        tmp.seek(0)
        with Image.open(tmp) as j:
            out = j.convert("RGB")
        return _artifact_from_image(out, fmt="PNG", media_type="image/png", metadata={"transform": self.name})


@dataclass(frozen=True)
class SocialPipelineTransform:
    """Approximate a social-media image normalization pipeline.

    The transform bounds the maximum edge length, strips alpha/metadata, and
    recompresses as JPEG.  It is intentionally generic; real OProW deployment
    should supplement it with platform-specific captures.
    """

    max_edge: int = 1080
    jpeg_quality: int = 82
    name: str = "social_pipeline_generic"

    def apply(self, artifact: Artifact) -> Artifact:
        img = _decode_image(artifact, mode="RGB")
        w, h = img.size
        scale = min(1.0, self.max_edge / float(max(w, h)))
        if scale < 1.0:
            img = img.resize((max(1, int(round(w * scale))), max(1, int(round(h * scale)))), resample=_RESAMPLING.LANCZOS)
        return _artifact_from_image(img, fmt="JPEG", media_type="image/jpeg", metadata={"transform": self.name}, quality=self.jpeg_quality, optimize=False)


def safe_apply_transform(transform: ArtifactTransform, artifact: Artifact) -> TransformApplication:
    """Apply a transform and convert exceptions into structured diagnostics."""

    try:
        out = transform.apply(artifact)
        return TransformApplication(transform_name=transform.name, artifact=out, succeeded=True)
    except Exception as exc:  # pragma: no cover - rare unsupported-media path
        return TransformApplication(transform_name=transform.name, artifact=None, succeeded=False, error=str(exc))


@dataclass(frozen=True)
class TransformSuite:
    """Named collection of deterministic transforms."""

    name: str
    transforms: tuple[ArtifactTransform, ...]
    description: str = ""

    def apply(self, artifact: Artifact) -> list[TransformApplication]:
        return [safe_apply_transform(t, artifact) for t in self.transforms]

    def names(self) -> list[str]:
        return [t.name for t in self.transforms]


# Default suites are small enough for CI.  They are deliberately not exhaustive.
def quick_image_transform_suite() -> TransformSuite:
    return TransformSuite(
        name="quick_image",
        description="Small deterministic smoke suite for CI and examples.",
        transforms=(
            IdentityTransform(),
            PNGRoundTripTransform(),
            JPEGRecompressTransform(quality=90),
            ResizeTransform(scale=0.75),
        ),
    )


def hostile_image_transform_suite() -> TransformSuite:
    return TransformSuite(
        name="hostile_image",
        description="More aggressive still-image transforms for research diagnostics.",
        transforms=(
            IdentityTransform(),
            JPEGRecompressTransform(quality=70),
            CenterCropTransform(keep_fraction=0.75, resize_back=True),
            GaussianNoiseTransform(sigma=8.0, seed=99),
            GaussianBlurTransform(radius=1.25),
            BrightnessContrastTransform(brightness=1.10, contrast=1.15),
            ScreenshotSimulationTransform(),
            SocialPipelineTransform(max_edge=640, jpeg_quality=78),
        ),
    )


__all__ = [
    "ArtifactTransform",
    "BrightnessContrastTransform",
    "CenterCropTransform",
    "GaussianBlurTransform",
    "GaussianNoiseTransform",
    "IdentityTransform",
    "JPEGRecompressTransform",
    "PNGRoundTripTransform",
    "ResizeTransform",
    "ScreenshotSimulationTransform",
    "SocialPipelineTransform",
    "TransformApplication",
    "TransformSuite",
    "hostile_image_transform_suite",
    "quick_image_transform_suite",
    "safe_apply_transform",
]
