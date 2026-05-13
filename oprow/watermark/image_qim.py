"""Pure-Python image DCT/QIM watermark prototype.

The OProW proposal's baseline image watermark family is "block-DCT QIM with
synchronization": embed payload bits in mid-frequency DCT coefficients of the
luminance channel, then use ECC/repetition and a sync template to survive common
media transforms.  Production-grade implementations require careful perceptual
modeling, geometry recovery, JPEG-aware coefficient handling, and extensive
benchmarking.

This Step 12 profile implements a minimal, transparent prototype:

* RGB image -> YCbCr; only the Y/luminance plane is modified.
* The image is split into 8x8 blocks.
* One mid-frequency coefficient per block, by default (3, 2), carries one
  framed/ECC bit.
* Quantization Index Modulation (QIM) encodes the bit as the parity of the
  nearest quantization index for that coefficient.
* A fixed "OPRW" preamble in the frame acts as toy synchronization.

This is not a finished robust watermark.  Its value is architectural: it shows
where a real DCT/spread-spectrum backend plugs into the same payload, ECC, and
verification stack used by the simpler alpha-LSB carrier.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from io import BytesIO
import random
from typing import Sequence

import numpy as np
from PIL import Image, ImageOps

from oprow.core.errors import ValidationError
from oprow.core.hashes import h256
from oprow.core.models import Artifact
from .base import (
    WatermarkCapacityError,
    WatermarkEmbedResult,
    WatermarkExtraction,
    WatermarkExtractionStatus,
    WatermarkStrength,
)
from .payload import IMG_DCT_QIM_REF_NUMERIC_ID, WatermarkPayload

IMG_DCT_QIM_REF_ALG_ID = "IMG-DCT-QIM-REF-1"


@lru_cache(maxsize=1)
def _dct8_matrix() -> np.ndarray:
    """Return the orthonormal 8x8 DCT-II transform matrix."""

    n = 8
    mat = np.zeros((n, n), dtype=np.float64)
    for k in range(n):
        scale = np.sqrt(1.0 / n) if k == 0 else np.sqrt(2.0 / n)
        for x in range(n):
            mat[k, x] = scale * np.cos(np.pi * (x + 0.5) * k / n)
    return mat


def _block_dct(block: np.ndarray) -> np.ndarray:
    c = _dct8_matrix()
    return c @ block @ c.T


def _block_idct(coeff: np.ndarray) -> np.ndarray:
    c = _dct8_matrix()
    return c.T @ coeff @ c


def _qim_embed_coefficient(value: float, bit: int, delta: float) -> float:
    """Encode ``bit`` as parity of the rounded quantization index."""

    if delta <= 0:
        raise ValidationError("qim_delta must be positive")
    q = int(round(value / delta))
    desired = int(bit) & 1
    if (q & 1) != desired:
        # Move to the adjacent quantization point requiring the smaller absolute
        # coefficient change.  For ties, choose the direction preserving sign.
        up = q + 1
        down = q - 1
        up_err = abs(value - up * delta)
        down_err = abs(value - down * delta)
        if up_err < down_err:
            q = up
        elif down_err < up_err:
            q = down
        else:
            q = up if value >= 0 else down
    return float(q * delta)


def _qim_extract_bit(value: float, delta: float) -> int:
    if delta <= 0:
        raise ValidationError("qim_delta must be positive")
    return int(round(value / delta)) & 1


def _carrier_block_order(width: int, height: int, seed: bytes) -> list[tuple[int, int]]:
    """Return deterministic pseudo-random 8x8 block coordinates.

    A real watermark would spread bits pseudo-randomly across perceptually safe
    blocks.  Here we use a deterministic shuffle from a public seed so embedding
    and extraction agree without a secret key.
    """

    blocks_x = width // 8
    blocks_y = height // 8
    coords = [(by, bx) for by in range(blocks_y) for bx in range(blocks_x)]
    rnd_seed = int.from_bytes(h256(seed + width.to_bytes(4, "big") + height.to_bytes(4, "big"))[:8], "big")
    rnd = random.Random(rnd_seed)
    rnd.shuffle(coords)
    return coords


@dataclass(frozen=True)
class DCTQIMImageWatermarkProfile:
    """Reference block-DCT/QIM image watermark profile."""

    alg_id: str = IMG_DCT_QIM_REF_ALG_ID
    numeric_id: int = IMG_DCT_QIM_REF_NUMERIC_ID
    coefficient: tuple[int, int] = (3, 2)
    seed: bytes = b"OProW-IMG-DCT-QIM-REF-1"
    media_types: set[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.media_types is None:
            object.__setattr__(self, "media_types", {"image/png", "image/jpeg", "image/webp", "image/*"})
        u, v = self.coefficient
        if not (0 <= u < 8 and 0 <= v < 8):
            raise ValidationError("DCT coefficient indices must be in 0..7")
        if (u, v) == (0, 0):
            raise ValidationError("DCT/QIM reference profile must not use the DC coefficient")

    def _decode_ycbcr(self, artifact: Artifact) -> tuple[Image.Image, np.ndarray]:
        try:
            with Image.open(BytesIO(artifact.read_bytes())) as img:
                normalized = ImageOps.exif_transpose(img).convert("YCbCr")
                return normalized, np.asarray(normalized, dtype=np.float64)
        except Exception as exc:
            raise ValidationError(f"failed to decode image for DCT/QIM watermarking: {exc}") from exc

    def capacity_bits(self, artifact: Artifact, *, strength: WatermarkStrength | None = None) -> int:
        image, _ = self._decode_ycbcr(artifact)
        return (image.size[0] // 8) * (image.size[1] // 8)

    def embed(self, artifact: Artifact, payload: WatermarkPayload, *, strength: WatermarkStrength | None = None) -> WatermarkEmbedResult:
        """Embed framed payload bits into mid-frequency DCT coefficients."""

        strength = strength or WatermarkStrength(name="dct-qim-reference", repetitions=1, qim_delta=48.0)
        codec = strength.frame_codec()
        carrier_bits = codec.encode_payload(payload)
        image, arr = self._decode_ycbcr(artifact)
        width, height = image.size
        order = _carrier_block_order(width, height, self.seed)
        if len(carrier_bits) > len(order):
            raise WatermarkCapacityError(f"DCT/QIM capacity {len(order)} bits is insufficient for {len(carrier_bits)} framed bits")

        y = arr[:, :, 0].copy()
        u, v = self.coefficient
        for bit, (by, bx) in zip(carrier_bits, order):
            y0, x0 = by * 8, bx * 8
            block = y[y0 : y0 + 8, x0 : x0 + 8] - 128.0
            coeff = _block_dct(block)
            coeff[u, v] = _qim_embed_coefficient(coeff[u, v], bit, strength.qim_delta)
            new_block = _block_idct(coeff) + 128.0
            y[y0 : y0 + 8, x0 : x0 + 8] = np.clip(np.rint(new_block), 0, 255)

        arr[:, :, 0] = y
        out_ycbcr = Image.fromarray(np.clip(np.rint(arr), 0, 255).astype(np.uint8), mode="YCbCr")
        out_rgb = out_ycbcr.convert("RGB")
        buf = BytesIO()
        out_rgb.save(buf, format="PNG")
        return WatermarkEmbedResult(
            artifact=Artifact.from_bytes(buf.getvalue(), media_type="image/png", metadata={**artifact.metadata, "oprow_watermark_profile": self.alg_id}),
            payload=payload,
            locator=payload.to_locator(),
            profile_id=self.alg_id,
            diagnostics={
                "carrier": "dct_qim",
                "capacity_bits": len(order),
                "used_carrier_bits": len(carrier_bits),
                "payload_bits": len(payload.to_bits()),
                "repetitions": strength.repetitions,
                "qim_delta": strength.qim_delta,
                "coefficient": self.coefficient,
            },
        )

    def extract(self, artifact: Artifact, *, strength: WatermarkStrength | None = None, hdc_profile_id: str | None = None) -> WatermarkExtraction:
        """Extract the DCT/QIM bitstream and decode it as an OProW payload."""

        strength = strength or WatermarkStrength(name="dct-qim-reference", repetitions=1, qim_delta=48.0)
        codec = strength.frame_codec()
        try:
            image, arr = self._decode_ycbcr(artifact)
            width, height = image.size
            order = _carrier_block_order(width, height, self.seed)
            y = arr[:, :, 0]
            u, v = self.coefficient
            carrier_bits: list[int] = []
            for by, bx in order:
                y0, x0 = by * 8, bx * 8
                block = y[y0 : y0 + 8, x0 : x0 + 8] - 128.0
                coeff = _block_dct(block)
                carrier_bits.append(_qim_extract_bit(coeff[u, v], strength.qim_delta))
            payload, frame = codec.decode_payload(carrier_bits, hdc_profile_id=hdc_profile_id)
            return WatermarkExtraction(
                status=WatermarkExtractionStatus.EXTRACTED,
                payload=payload,
                locator=payload.to_locator(),
                profile_id=self.alg_id,
                diagnostics={
                    "carrier": "dct_qim",
                    "carrier_bits_seen": len(carrier_bits),
                    "payload_bits": len(frame.payload_bits),
                    "decoded_bits_seen": frame.decoded_bits_seen,
                    "corrected_groups": frame.repetition_report.corrected_groups,
                    "repetitions": frame.repetition_report.repetitions,
                    "qim_delta": strength.qim_delta,
                    "coefficient": self.coefficient,
                },
            )
        except ValidationError as exc:
            msg = str(exc)
            status = WatermarkExtractionStatus.CRC_FAILED if "CRC" in msg.upper() else WatermarkExtractionStatus.NO_WATERMARK
            return WatermarkExtraction(status=status, profile_id=self.alg_id, error=msg, diagnostics={"carrier": "dct_qim"})
        except Exception as exc:
            return WatermarkExtraction(status=WatermarkExtractionStatus.ERROR, profile_id=self.alg_id, error=str(exc), diagnostics={"carrier": "dct_qim"})
