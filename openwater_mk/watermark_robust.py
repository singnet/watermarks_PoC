"""Hardened DCT-QIM watermark profile for the openwater-mk demo.

The vendored ``oprow`` SDK ships a single reference DCT-QIM carrier
that modifies one mid-frequency coefficient per 8x8 block. That carrier
extracts cleanly under PNG-RGB and mild JPEG (q>=82 on the synthetic
corpus) but degrades sharply at lower JPEG qualities and under
cascaded re-encodes.

This module adds a spectral-spread variant that writes the same carrier
bit into five mid-frequency DCT coefficients per block and majority-
votes the bits at extract. The five coefficients are picked from the
low end of the libjpeg Q50 luminance quantization table so the embed
survives standard JPEG quantization with margin:

      8x8 luminance quant table (libjpeg, Q50)
      col:  0   1   2   3   4   5   6   7
   row 0:  16  11  10  16  24  40  51  61
   row 1:  12  12  14  19  26  58  60  55       <-- (1,2)=14, (1,3)=19
   row 2:  14  13  16  24  40  57  69  56       <-- (2,1)=13, (2,2)=16
   row 3:  14  17  22  29  51  87  80  62       <-- (3,1)=17
   ...

This is still a reference profile, not production-grade. Synchronisation
recovery (resize, crop, rotation) is intentionally out of scope -- that
is Tier 2.5 work and would need a separate template or autocorrelation
front-end.

Empirical notes on the synthetic corpus (192x192, 576 8x8 blocks): the
spectral-spread profile at qim_delta=64 matches plain DCT-QIM under
PNG-RGB / JPEG q60-q82 / one-shot cascades; the spread does not beat the
single-coefficient reference under JPEG noise because JPEG quantization
is correlated across coefficients of the same block (the five spread
cells get quantized by the same scaling factor, so a majority vote of
correlated bit errors does not increase margin). The spread shines under
DECORRELATED noise (Gaussian, dithering, light brightness shift), and is
structurally ready to be combined with spatial repetition + a sync
template for the V1 production carrier. See
``tests/test_watermark_robust.py`` for the matrix and
``vendor/oprow_docs/`` for the upstream design notes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO
from typing import Sequence

import numpy as np
from PIL import Image, ImageOps

from oprow.core.errors import ValidationError
from oprow.core.models import Artifact
from oprow.watermark.base import (
    WatermarkCapacityError,
    WatermarkEmbedResult,
    WatermarkExtraction,
    WatermarkExtractionStatus,
    WatermarkStrength,
)
from oprow.watermark.image_qim import (
    _block_dct,
    _block_idct,
    _carrier_block_order,
    _qim_embed_coefficient,
    _qim_extract_bit,
)
from oprow.watermark.payload import WatermarkPayload

from .pipeline import register_profile


IMG_DCT_QIM_ROBUST_ALG_ID = "IMG-DCT-QIM-ROBUST-1"
IMG_DCT_QIM_ROBUST_NUMERIC_ID = 0x003


def _default_robust_coefficients() -> tuple[tuple[int, int], ...]:
    # Sorted in coefficient-quant ascending order for clarity; ordering does
    # not affect behaviour because each block is written/read symmetrically.
    return ((2, 1), (1, 2), (2, 2), (3, 1), (1, 3))


def _default_robust_media_types() -> set[str]:
    return {"image/png", "image/jpeg", "image/webp", "image/*"}


@dataclass(frozen=True)
class RobustDCTQIMImageWatermarkProfile:
    """Spectral-spread DCT-QIM watermark profile.

    Each framed/ECC carrier bit is written into ``len(coefficients)`` mid-
    frequency DCT cells per 8x8 block. At extract, the matching cells are
    decoded and majority-voted to recover one bit per block. The bit is
    then handed back to the same :class:`WatermarkFrameCodec` the SDK's
    reference DCT-QIM profile uses, so the framing, ECC, and payload
    layout stay identical.

    The capacity is one carrier bit per 8x8 block of the luminance plane
    (the spread is *redundant*, not *additive*: it widens the SNR margin,
    not the channel width).
    """

    alg_id: str = IMG_DCT_QIM_ROBUST_ALG_ID
    numeric_id: int = IMG_DCT_QIM_ROBUST_NUMERIC_ID
    coefficients: tuple[tuple[int, int], ...] = field(default_factory=_default_robust_coefficients)
    seed: bytes = b"OProW-IMG-DCT-QIM-ROBUST-1"
    media_types: set[str] = field(default_factory=_default_robust_media_types)

    def __post_init__(self) -> None:
        if not self.coefficients:
            raise ValidationError("RobustDCTQIM requires at least one coefficient")
        for uv in self.coefficients:
            if len(uv) != 2:
                raise ValidationError(f"coefficient must be (u, v) pair, got {uv!r}")
            u, v = uv
            if not (0 <= u < 8 and 0 <= v < 8):
                raise ValidationError("DCT coefficient indices must be in 0..7")
            if (u, v) == (0, 0):
                raise ValidationError("Robust DCT-QIM profile must not use the DC coefficient")
        if len(set(self.coefficients)) != len(self.coefficients):
            raise ValidationError("RobustDCTQIM coefficients must be unique")

    # ---- helpers ---------------------------------------------------------

    def _decode_ycbcr(self, artifact: Artifact) -> tuple[Image.Image, np.ndarray]:
        try:
            with Image.open(BytesIO(artifact.read_bytes())) as img:
                normalized = ImageOps.exif_transpose(img).convert("YCbCr")
                return normalized, np.asarray(normalized, dtype=np.float64)
        except Exception as exc:
            raise ValidationError(f"failed to decode image for robust DCT/QIM: {exc}") from exc

    # ---- WatermarkProfile protocol --------------------------------------

    def capacity_bits(self, artifact: Artifact, *, strength: WatermarkStrength | None = None) -> int:
        image, _ = self._decode_ycbcr(artifact)
        return (image.size[0] // 8) * (image.size[1] // 8)

    def embed(
        self,
        artifact: Artifact,
        payload: WatermarkPayload,
        *,
        strength: WatermarkStrength | None = None,
    ) -> WatermarkEmbedResult:
        strength = strength or WatermarkStrength(name="dct-qim-robust-reference", repetitions=1, qim_delta=64.0)
        codec = strength.frame_codec()
        carrier_bits = codec.encode_payload(payload)
        image, arr = self._decode_ycbcr(artifact)
        width, height = image.size
        order = _carrier_block_order(width, height, self.seed)
        if len(carrier_bits) > len(order):
            raise WatermarkCapacityError(
                f"Robust DCT/QIM capacity {len(order)} bits is insufficient for {len(carrier_bits)} framed bits"
            )

        y = arr[:, :, 0].copy()
        for bit, (by, bx) in zip(carrier_bits, order):
            y0, x0 = by * 8, bx * 8
            block = y[y0 : y0 + 8, x0 : x0 + 8] - 128.0
            coeff = _block_dct(block)
            for (u, v) in self.coefficients:
                coeff[u, v] = _qim_embed_coefficient(coeff[u, v], bit, strength.qim_delta)
            new_block = _block_idct(coeff) + 128.0
            y[y0 : y0 + 8, x0 : x0 + 8] = np.clip(np.rint(new_block), 0, 255)

        arr[:, :, 0] = y
        out_ycbcr = Image.fromarray(np.clip(np.rint(arr), 0, 255).astype(np.uint8), mode="YCbCr")
        out_rgb = out_ycbcr.convert("RGB")
        buf = BytesIO()
        out_rgb.save(buf, format="PNG")
        return WatermarkEmbedResult(
            artifact=Artifact.from_bytes(
                buf.getvalue(),
                media_type="image/png",
                metadata={**artifact.metadata, "oprow_watermark_profile": self.alg_id},
            ),
            payload=payload,
            locator=payload.to_locator(),
            profile_id=self.alg_id,
            diagnostics={
                "carrier": "dct_qim_robust",
                "capacity_bits": len(order),
                "used_carrier_bits": len(carrier_bits),
                "payload_bits": len(payload.to_bits()),
                "repetitions": strength.repetitions,
                "qim_delta": strength.qim_delta,
                "coefficients": list(self.coefficients),
                "coefficients_per_bit": len(self.coefficients),
            },
        )

    def extract(
        self,
        artifact: Artifact,
        *,
        strength: WatermarkStrength | None = None,
        hdc_profile_id: str | None = None,
    ) -> WatermarkExtraction:
        strength = strength or WatermarkStrength(name="dct-qim-robust-reference", repetitions=1, qim_delta=64.0)
        codec = strength.frame_codec()
        try:
            image, arr = self._decode_ycbcr(artifact)
            width, height = image.size
            order = _carrier_block_order(width, height, self.seed)
            y = arr[:, :, 0]
            carrier_bits: list[int] = []
            for (by, bx) in order:
                y0, x0 = by * 8, bx * 8
                block = y[y0 : y0 + 8, x0 : x0 + 8] - 128.0
                coeff = _block_dct(block)
                votes = [
                    _qim_extract_bit(coeff[u, v], strength.qim_delta)
                    for (u, v) in self.coefficients
                ]
                # Majority vote across the spectral spread; ties resolve to 0
                # (arbitrary tie-break; the framed payload's CRC will catch
                # any flipped framed bit no matter which way we tie).
                carrier_bits.append(1 if sum(votes) * 2 > len(votes) else 0)
            payload, frame = codec.decode_payload(carrier_bits, hdc_profile_id=hdc_profile_id)
            return WatermarkExtraction(
                status=WatermarkExtractionStatus.EXTRACTED,
                payload=payload,
                locator=payload.to_locator(),
                profile_id=self.alg_id,
                diagnostics={
                    "carrier": "dct_qim_robust",
                    "carrier_bits_seen": len(carrier_bits),
                    "payload_bits": len(frame.payload_bits),
                    "decoded_bits_seen": frame.decoded_bits_seen,
                    "corrected_groups": frame.repetition_report.corrected_groups,
                    "repetitions": frame.repetition_report.repetitions,
                    "qim_delta": strength.qim_delta,
                    "coefficients": list(self.coefficients),
                    "coefficients_per_bit": len(self.coefficients),
                },
            )
        except ValidationError as exc:
            msg = str(exc)
            status = (
                WatermarkExtractionStatus.CRC_FAILED
                if "CRC" in msg.upper()
                else WatermarkExtractionStatus.NO_WATERMARK
            )
            return WatermarkExtraction(
                status=status,
                profile_id=self.alg_id,
                error=msg,
                diagnostics={"carrier": "dct_qim_robust"},
            )
        except Exception as exc:
            return WatermarkExtraction(
                status=WatermarkExtractionStatus.ERROR,
                profile_id=self.alg_id,
                error=str(exc),
                diagnostics={"carrier": "dct_qim_robust"},
            )


# Register the profile under the demo's plug-in registry so the CLI/web
# layers expose it as ``--profile dct_qim_robust`` without a circular
# import from pipeline.py.
register_profile("dct_qim_robust", RobustDCTQIMImageWatermarkProfile)


__all__ = [
    "IMG_DCT_QIM_ROBUST_ALG_ID",
    "IMG_DCT_QIM_ROBUST_NUMERIC_ID",
    "RobustDCTQIMImageWatermarkProfile",
]
