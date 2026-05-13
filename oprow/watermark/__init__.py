"""Step 13 OProW watermark reference implementation.

The package exports payload/framing helpers, a toy ECC layer, two image carrier
profiles, and workflow helpers that connect extraction to the Step 5 verifier.
"""

from .bits import bits_to_bytes, bits_to_int, bytes_to_bits, int_to_bits, normalize_bits, xor_bits
from .crc import crc16_ccitt_false
from .ecc import RepetitionCode, RepetitionDecodeReport
from .payload import (
    FRAME_LENGTH_BITS,
    FRAME_PREAMBLE_BITS,
    IMG_ALPHA_LSB_REF_NUMERIC_ID,
    IMG_DCT_QIM_REF_NUMERIC_ID,
    POINTER_MODE_FLAG_MASK,
    WATERMARK_PAYLOAD_VERSION,
    WatermarkFrameCodec,
    WatermarkFrameDecodeReport,
    WatermarkPayload,
    payload_bit_length_for_mode,
)
from .base import (
    WatermarkCapacityError,
    WatermarkEmbedResult,
    WatermarkError,
    WatermarkExtraction,
    WatermarkExtractionStatus,
    WatermarkProfile,
    WatermarkRegistry,
    WatermarkStrength,
)
from .image_lsb import AlphaLSBImageWatermarkProfile, IMG_ALPHA_LSB_REF_ALG_ID
from .image_qim import DCTQIMImageWatermarkProfile, IMG_DCT_QIM_REF_ALG_ID
from .workflow import (
    WatermarkVerificationReport,
    embed_manifest_locator,
    extract_locator,
    payload_for_manifest,
    verify_artifact_from_watermark,
)


def default_watermark_registry() -> WatermarkRegistry:
    """Return a registry containing the Step 12 reference image profiles."""

    registry = WatermarkRegistry()
    registry.register(AlphaLSBImageWatermarkProfile())
    registry.register(DCTQIMImageWatermarkProfile())
    return registry


DEFAULT_WATERMARK_REGISTRY = default_watermark_registry()

__all__ = [name for name in globals() if not name.startswith("_")]
