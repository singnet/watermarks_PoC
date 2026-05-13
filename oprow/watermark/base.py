"""Base classes for the Step 12 watermark layer.

OProW's watermark layer is deliberately a *retrieval* layer, not a trust layer.
A watermark embeds a compact pointer to a signed manifest.  Extracting that
pointer is useful, but it is not itself evidence that the media is authentic.
The full verifier must still perform the later checks developed in Steps 1--11:
locator self-consistency, manifest signatures, essence/content binding,
authenticated index proofs where applicable, and local trust policy.

This module provides the shared object model for watermark profiles:

* ``WatermarkPayload`` lives in ``payload.py`` and encodes the compact pointer.
* A ``WatermarkProfile`` embeds/extracts the ECC-framed payload in a specific
  media carrier.
* ``WatermarkExtraction`` carries a decoded payload/locator plus diagnostics.
* ``WatermarkRegistry`` allows algorithm agility, matching the OProW principle
  that watermark algorithms evolve independently from the manifest format.

The profiles included in Step 12 are intentionally reference profiles.  One is a
lossless PNG alpha-channel LSB carrier for testing; the other is a pure-Python
DCT/QIM prototype.  Neither should be mistaken for a production social-media
watermark.  They make the protocol boundary concrete so stronger native
watermark engines can be plugged in later.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from oprow.core.errors import OProWError, ValidationError
from oprow.core.models import Artifact, ManifestLocator
from .ecc import RepetitionCode
from .payload import WatermarkFrameCodec, WatermarkPayload


class WatermarkError(OProWError):
    """Base class for watermark-layer failures."""


class WatermarkCapacityError(WatermarkError):
    """Raised when the media carrier cannot hold the framed payload."""


class WatermarkExtractionStatus(str, Enum):
    """Extractor outcome before full provenance verification."""

    EXTRACTED = "extracted"
    NO_WATERMARK = "no_watermark"
    CRC_FAILED = "crc_failed"
    CAPACITY_ERROR = "capacity_error"
    UNSUPPORTED_MEDIA = "unsupported_media"
    ERROR = "error"


@dataclass(frozen=True)
class WatermarkStrength:
    """Tunable carrier/ECC parameters for a watermark profile.

    ``repetitions`` controls the toy Step 12 ECC expansion.  ``qim_delta`` is
    used by the DCT/QIM prototype.  ``description`` is recorded in diagnostics
    so tests and examples can show which robustness/quality tradeoff was chosen.
    """

    name: str = "reference-default"
    repetitions: int = 3
    qim_delta: float = 36.0
    description: str = "Reference strength; not production calibrated."

    def frame_codec(self) -> WatermarkFrameCodec:
        return WatermarkFrameCodec(ecc=RepetitionCode(self.repetitions))


@dataclass(frozen=True)
class WatermarkEmbedResult:
    """Output of a watermark embedding operation."""

    artifact: Artifact
    payload: WatermarkPayload
    locator: ManifestLocator
    profile_id: str
    diagnostics: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class WatermarkExtraction:
    """Output of watermark extraction.

    The ``locator`` field is convenient for resolver/verifier integration, but
    callers should remember that it is not authoritative until full provenance
    verification succeeds.
    """

    status: WatermarkExtractionStatus
    payload: WatermarkPayload | None = None
    locator: ManifestLocator | None = None
    profile_id: str | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def extracted(self) -> bool:
        return self.status == WatermarkExtractionStatus.EXTRACTED and self.locator is not None


class WatermarkProfile(Protocol):
    """Protocol implemented by concrete media watermark profiles."""

    alg_id: str
    numeric_id: int
    media_types: set[str]

    def capacity_bits(self, artifact: Artifact, *, strength: WatermarkStrength | None = None) -> int:
        """Return approximate embedded carrier-bit capacity for this artifact."""
        ...

    def embed(self, artifact: Artifact, payload: WatermarkPayload, *, strength: WatermarkStrength | None = None) -> WatermarkEmbedResult:
        """Embed a payload and return a new artifact."""
        ...

    def extract(self, artifact: Artifact, *, strength: WatermarkStrength | None = None, hdc_profile_id: str | None = None) -> WatermarkExtraction:
        """Extract a payload/locator from an artifact."""
        ...


@dataclass
class WatermarkRegistry:
    """Simple in-process registry for watermark profiles.

    Protocol specs generally need public algorithm registries.  A Python SDK
    also needs a local registry so tests, examples, and applications can select
    profiles by string ID or compact numeric ID.
    """

    by_alg_id: dict[str, WatermarkProfile] = field(default_factory=dict)
    by_numeric_id: dict[int, WatermarkProfile] = field(default_factory=dict)

    def register(self, profile: WatermarkProfile) -> None:
        if profile.alg_id in self.by_alg_id:
            raise ValidationError(f"watermark profile already registered: {profile.alg_id}")
        if profile.numeric_id in self.by_numeric_id:
            raise ValidationError(f"watermark numeric ID already registered: {profile.numeric_id}")
        self.by_alg_id[profile.alg_id] = profile
        self.by_numeric_id[profile.numeric_id] = profile

    def get(self, alg_id: str) -> WatermarkProfile:
        try:
            return self.by_alg_id[alg_id]
        except KeyError as exc:
            raise ValidationError(f"unknown watermark profile: {alg_id}") from exc

    def get_numeric(self, numeric_id: int) -> WatermarkProfile:
        try:
            return self.by_numeric_id[numeric_id]
        except KeyError as exc:
            raise ValidationError(f"unknown watermark numeric ID: {numeric_id}") from exc
