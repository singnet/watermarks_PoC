"""HDC profile definitions for SHORT64-HV routing.

An HDC profile is a protocol-facing object, not merely a tuning parameter bag.
Every field that affects route-token derivation must be stable and versioned,
because indexers and verifiers must compute identical route keys from the same
artifact.  Future OProW registries may define multiple profiles for images,
audio, and video.  Step 8 ships one small image-oriented baseline:

    HV-PED-IMG-1-D8192

The profile says:

* compute the artifact PED using ``PED-IMG-1``;
* convert the PED into an 8192-dimensional binary hypervector;
* split the hypervector into 16 route bands;
* derive 16-bit band codes for resolver routing.

The HDC descriptor is never final proof.  It only reduces the number of
candidate manifests that need full OProW verification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from oprow.core.errors import ValidationError
from oprow.essence import PED_IMG_1_ALG_ID


DEFAULT_HDC_PROFILE_ID = "HV-PED-IMG-1-D8192"
DEFAULT_HDC_SEED = b"OProW-HDC-ImagePED1-DefaultSeed-v1"
DEFAULT_HDC_EPOCH = "global"
DEFAULT_ROUTE_EPOCH = DEFAULT_HDC_EPOCH


@dataclass(frozen=True)
class HDCProfile:
    """Registered HDC routing profile.

    ``value_quantization_levels`` matters for robustness.  The baseline encoder
    maps each PED byte into one of a small number of bins before assigning a
    value hypervector.  If the PED block mean shifts by a few levels after JPEG
    recompression, it often remains in the same bin and therefore contributes the
    same HDC symbol.  This is not a formal robustness proof; it is a pragmatic
    starting point for benchmarking.
    """

    profile_id: str = DEFAULT_HDC_PROFILE_ID
    ped_profile_id: str = PED_IMG_1_ALG_ID
    dimension: int = 8192
    encoder_id: str = "symbolic-bundling-v1"
    seed: bytes = DEFAULT_HDC_SEED
    num_bands: int = 16
    bits_per_band: int = 16
    value_quantization_levels: int = 16
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.profile_id:
            raise ValidationError("HDCProfile.profile_id must be non-empty")
        if not self.ped_profile_id:
            raise ValidationError("HDCProfile.ped_profile_id must be non-empty")
        if self.dimension <= 0:
            raise ValidationError("HDCProfile.dimension must be positive")
        if self.num_bands <= 0 or self.dimension % self.num_bands != 0:
            raise ValidationError("HDCProfile.dimension must be divisible by num_bands")
        band_width = self.dimension // self.num_bands
        if self.bits_per_band <= 0 or self.bits_per_band > band_width:
            raise ValidationError("bits_per_band must fit inside a band")
        if not (2 <= self.value_quantization_levels <= 256):
            raise ValidationError("value_quantization_levels must be between 2 and 256")

    def band_width(self) -> int:
        return self.dimension // self.num_bands

    def to_canonical(self) -> dict[str, object]:
        return {
            "profile_id": self.profile_id,
            "ped_profile_id": self.ped_profile_id,
            "dimension": self.dimension,
            "encoder_id": self.encoder_id,
            "seed": self.seed,
            "num_bands": self.num_bands,
            "bits_per_band": self.bits_per_band,
            "value_quantization_levels": self.value_quantization_levels,
            "metadata": self.metadata,
        }


def default_hdc_profile(**overrides: Any) -> HDCProfile:
    """Return the Step 8 baseline profile instance.

    Tests and research harnesses may pass overrides such as ``dimension`` or
    ``num_bands``.  Production profiles should use stable profile IDs that
    reflect those choices, because the profile ID is part of route-token
    derivation.
    """
    return HDCProfile(**overrides)
