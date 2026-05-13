"""Lossless PNG alpha-LSB reference watermark profile.

This profile exists for one reason: to make the end-to-end OProW watermark path
executable in a compact Python reference implementation.  It embeds the ECC-
framed watermark bitstream into the least significant bit of the PNG alpha
channel, one carrier bit per pixel.

Security and robustness caveats are intentionally explicit:

* This profile is **not** robust against JPEG conversion, alpha-channel stripping,
  compositing, screenshots, or most social-media pipelines.
* It is useful for deterministic unit tests because it leaves visible RGB values
  unchanged.  OProW's PED-IMG-1 essence hash ignores alpha after RGB conversion,
  so this carrier lets us test the full signed-manifest/locator/verifier stack
  without perturbing the signed image essence.
* It demonstrates the payload/ECC/framing contract shared by all watermark
  profiles.  A production DCT/spread-spectrum/native backend can replace the
  carrier while keeping the same ``WatermarkPayload`` and resolver logic.

The profile outputs PNG/RGBA artifacts even if the input was JPEG or RGB.  That
container conversion is another reason this is a reference/test carrier only.
"""

from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from typing import Any

import numpy as np
from PIL import Image, ImageOps

from oprow.core.enums import PointerMode
from oprow.core.errors import ValidationError
from oprow.core.models import Artifact
from .base import (
    WatermarkCapacityError,
    WatermarkEmbedResult,
    WatermarkExtraction,
    WatermarkExtractionStatus,
    WatermarkStrength,
)
from .payload import IMG_ALPHA_LSB_REF_NUMERIC_ID, WatermarkPayload

IMG_ALPHA_LSB_REF_ALG_ID = "IMG-ALPHA-LSB-REF-1"


@dataclass(frozen=True)
class AlphaLSBImageWatermarkProfile:
    """Reference profile that stores carrier bits in alpha-channel LSBs."""

    alg_id: str = IMG_ALPHA_LSB_REF_ALG_ID
    numeric_id: int = IMG_ALPHA_LSB_REF_NUMERIC_ID
    media_types: set[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.media_types is None:
            object.__setattr__(self, "media_types", {"image/png", "image/jpeg", "image/webp", "image/*"})

    def _decode_rgba(self, artifact: Artifact) -> Image.Image:
        try:
            with Image.open(BytesIO(artifact.read_bytes())) as img:
                normalized = ImageOps.exif_transpose(img)
                return normalized.convert("RGBA")
        except Exception as exc:
            raise ValidationError(f"failed to decode image for alpha-LSB watermarking: {exc}") from exc

    def capacity_bits(self, artifact: Artifact, *, strength: WatermarkStrength | None = None) -> int:
        """One alpha LSB is available per pixel."""

        image = self._decode_rgba(artifact)
        return image.size[0] * image.size[1]

    def embed(self, artifact: Artifact, payload: WatermarkPayload, *, strength: WatermarkStrength | None = None) -> WatermarkEmbedResult:
        """Embed payload bits into the alpha-channel LSBs.

        Algorithm:
          1. Decode to RGBA and normalize EXIF orientation.
          2. Encode ``payload`` as ``preamble || length || payload || ECC``.
          3. Flatten the alpha channel and overwrite the low bit of the first
             ``N`` pixels.
          4. Save as PNG and return a new ``Artifact``.

        The RGB values are not changed.  The alpha channel changes from 255 to
        either 254 or 255 for fully opaque inputs, which is visually negligible
        in typical renderers and keeps Step 3's RGB PED stable for tests.
        """

        strength = strength or WatermarkStrength(name="alpha-lsb-reference", repetitions=3)
        codec = strength.frame_codec()
        carrier_bits = codec.encode_payload(payload)

        image = self._decode_rgba(artifact)
        arr = np.array(image, dtype=np.uint8, copy=True)
        capacity = arr.shape[0] * arr.shape[1]
        if len(carrier_bits) > capacity:
            raise WatermarkCapacityError(f"alpha-LSB capacity {capacity} bits is insufficient for {len(carrier_bits)} framed bits")

        alpha = arr[:, :, 3].reshape(-1)
        for i, bit in enumerate(carrier_bits):
            alpha[i] = (int(alpha[i]) & 0xFE) | int(bit)
        arr[:, :, 3] = alpha.reshape(arr.shape[0], arr.shape[1])

        out_img = Image.fromarray(arr, mode="RGBA")
        buf = BytesIO()
        out_img.save(buf, format="PNG")
        locator = payload.to_locator()
        return WatermarkEmbedResult(
            artifact=Artifact.from_bytes(buf.getvalue(), media_type="image/png", metadata={**artifact.metadata, "oprow_watermark_profile": self.alg_id}),
            payload=payload,
            locator=locator,
            profile_id=self.alg_id,
            diagnostics={
                "carrier": "alpha_lsb",
                "capacity_bits": capacity,
                "used_carrier_bits": len(carrier_bits),
                "payload_bits": len(payload.to_bits()),
                "repetitions": strength.repetitions,
                "pointer_mode": payload.pointer_mode.value,
            },
        )

    def extract(self, artifact: Artifact, *, strength: WatermarkStrength | None = None, hdc_profile_id: str | None = None) -> WatermarkExtraction:
        """Extract a payload from alpha-channel LSBs."""

        strength = strength or WatermarkStrength(name="alpha-lsb-reference", repetitions=3)
        codec = strength.frame_codec()
        try:
            image = self._decode_rgba(artifact)
            arr = np.asarray(image, dtype=np.uint8)
            carrier_bits = (arr[:, :, 3].reshape(-1) & 1).astype(np.uint8).tolist()
            payload, frame = codec.decode_payload(carrier_bits, hdc_profile_id=hdc_profile_id)
            locator = payload.to_locator()
            return WatermarkExtraction(
                status=WatermarkExtractionStatus.EXTRACTED,
                payload=payload,
                locator=locator,
                profile_id=self.alg_id,
                diagnostics={
                    "carrier": "alpha_lsb",
                    "carrier_bits_seen": len(carrier_bits),
                    "payload_bits": len(frame.payload_bits),
                    "decoded_bits_seen": frame.decoded_bits_seen,
                    "preamble_offset": frame.preamble_offset,
                    "corrected_groups": frame.repetition_report.corrected_groups,
                    "repetitions": frame.repetition_report.repetitions,
                    "pointer_mode": payload.pointer_mode.value,
                },
            )
        except ValidationError as exc:
            # CRC and preamble failures are represented as no-watermark/CRC-style
            # extraction failures, not Python exceptions, because verification UI
            # should be able to say "no usable provenance watermark" gracefully.
            msg = str(exc)
            status = WatermarkExtractionStatus.CRC_FAILED if "CRC" in msg.upper() else WatermarkExtractionStatus.NO_WATERMARK
            return WatermarkExtraction(status=status, profile_id=self.alg_id, error=msg, diagnostics={"carrier": "alpha_lsb"})
        except Exception as exc:
            return WatermarkExtraction(status=WatermarkExtractionStatus.ERROR, profile_id=self.alg_id, error=str(exc), diagnostics={"carrier": "alpha_lsb"})
