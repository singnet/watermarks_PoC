"""Baseline still-image essence profile: ``PED-IMG-1``.

This file implements the image PED sketched in the OProW draft:

1. Decode image to RGB and normalize EXIF orientation.
2. Convert RGB to an 8-bit luminance plane using fixed integer coefficients:

       Y = floor((77 R + 150 G + 29 B + 128) / 256)

   This approximates sRGB luma while avoiding platform-specific floating point
   color conversions.
3. Resize luminance to 256 x 256 using a deterministic bilinear resampler.
4. Compute a 32 x 32 grid of 8 x 8 block means, stored as 1024 bytes.
5. Resize luminance to 64 x 64, compute a 2D DCT, and encode signs of the
   upper-left 16 x 16 coefficients excluding DC.  This yields 255 bits, padded
   to 32 bytes.
6. Concatenate block means and DCT sign bytes.  The baseline PED length is
   therefore 1024 + 32 = 1056 bytes.

Implementation choices and caveats:

* The resampler is implemented in NumPy instead of relying on Pillow's resize,
  because image libraries may use slightly different kernel details.  The
  coordinate mapping is center-aligned:

      src = (dst + 0.5) * src_size / dst_size - 0.5

  Values outside the image are clamped to the edge.  Final luminance samples are
  rounded with floor(x + 0.5) and clipped to [0, 255].
* The DCT is a deterministic orthonormal type-II transform implemented as
  matrix multiplication.  This is fine for 64 x 64 reference code.  Production
  implementations may use optimized DCT libraries, but they should be validated
  against test vectors because tiny DCT sign changes alter the PED hash.
* This first draft is intentionally simple.  It is a *profile implementation*,
  not a claim that PED-IMG-1 is robust enough for all hostile channels.  The
  benchmark harness in Step 14 should measure false mismatch and false match
  behavior under JPEG/WebP recompression, resize, crop, screenshot simulation,
  and adversarial transformations.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from io import BytesIO
from typing import Tuple

import numpy as np
from PIL import Image, ImageOps

from ..core.errors import ValidationError
from ..core.hashes import frame_parts
from ..core.identifiers import Hash256
from ..core.models import Artifact, ArtifactBinding
from .base import BaseEssenceProfile, EssenceComputation
from .strict import compute_strict_byte_hash

PED_IMG_1_ALG_ID = "PED-IMG-1"
PED_IMG_1_BLOCK_MEAN_SIZE = 1024
PED_IMG_1_DCT_SIGN_BITS = 255
PED_IMG_1_DCT_SIGN_BYTES = 32
PED_IMG_1_LENGTH = PED_IMG_1_BLOCK_MEAN_SIZE + PED_IMG_1_DCT_SIGN_BYTES


@dataclass(frozen=True)
class ImagePED1Components:
    """Parsed components of a PED-IMG-1 byte string.

    The benchmark and HDC stages will often want component-level distances rather
    than just all-or-nothing hash equality.  Keeping this small parser in Step 3
    avoids reimplementing the byte layout later.
    """

    block_means_32x32: np.ndarray  # uint8 shape (32, 32)
    dct_sign_bits_255: np.ndarray  # uint8/bool shape (255,)


@dataclass(frozen=True)
class ImagePED1Distance:
    """Simple diagnostic distance between two PED-IMG-1 descriptors.

    This is not a normative verifier decision.  It is a research/benchmarking
    helper and a precursor to HDC routing.  The signed essence commitment remains
    the cryptographic hash of the full PED bytes.
    """

    mean_absolute_block_delta: float
    max_block_delta: int
    dct_sign_hamming: int
    dct_sign_hamming_fraction: float


def decode_image_to_rgb(artifact: Artifact) -> Image.Image:
    """Decode an OProW ``Artifact`` into an EXIF-normalized RGB Pillow image.

    OProW wants essence hashing to be about visual content, not container
    details.  EXIF orientation is a common source of apparent mismatch: the same
    photo may be stored as unrotated pixels plus an orientation tag, or as
    already-rotated pixels with no tag.  ``ImageOps.exif_transpose`` normalizes
    that case before we compute luminance.
    """
    raw = artifact.read_bytes()
    try:
        with Image.open(BytesIO(raw)) as img:
            normalized = ImageOps.exif_transpose(img)
            return normalized.convert("RGB")
    except Exception as exc:
        raise ValidationError(f"failed to decode image artifact as RGB: {exc}") from exc


def rgb_image_to_luminance_u8(image: Image.Image) -> np.ndarray:
    """Convert an RGB Pillow image to the fixed OProW luminance plane.

    The formula is integer-only and deliberately does not call color-management
    routines.  This improves reproducibility.  The coefficients sum to 256, so a
    white pixel maps to 255 and a black pixel maps to 0.
    """
    rgb = np.asarray(image.convert("RGB"), dtype=np.uint16)
    if rgb.ndim != 3 or rgb.shape[2] != 3:
        raise ValidationError(f"expected RGB image array with 3 channels, got shape {rgb.shape}")
    r = rgb[:, :, 0]
    g = rgb[:, :, 1]
    b = rgb[:, :, 2]
    y = (77 * r + 150 * g + 29 * b + 128) // 256
    return np.clip(y, 0, 255).astype(np.uint8)


def resize_bilinear_u8(src: np.ndarray, width: int, height: int) -> np.ndarray:
    """Deterministically resize a 2D uint8 image with bilinear interpolation.

    This function specifies the coordinate transform explicitly.  It is slower
    than optimized image-library resize functions but stable and easy to test.
    The input is interpreted as samples at pixel centers.  Destination pixel
    centers are mapped back into source coordinates by center alignment:

        x_src = (x_dst + 0.5) * src_width / dst_width - 0.5
        y_src = (y_dst + 0.5) * src_height / dst_height - 0.5

    The source coordinate is clamped to the valid image rectangle.  The four
    nearest samples are bilinearly mixed in float64 and rounded with
    ``floor(value + 0.5)``.  This avoids banker's rounding and makes the rule
    precise for test vectors.
    """
    arr = np.asarray(src)
    if arr.ndim != 2:
        raise ValidationError(f"resize_bilinear_u8 expects a 2D luminance plane, got shape {arr.shape}")
    if width <= 0 or height <= 0:
        raise ValidationError("resize target dimensions must be positive")
    src_h, src_w = arr.shape
    if src_h <= 0 or src_w <= 0:
        raise ValidationError("cannot resize empty image")

    arr_f = arr.astype(np.float64)

    # Destination grid -> source coordinates, with center-aligned mapping.
    ys = (np.arange(height, dtype=np.float64) + 0.5) * (src_h / height) - 0.5
    xs = (np.arange(width, dtype=np.float64) + 0.5) * (src_w / width) - 0.5
    ys = np.clip(ys, 0.0, max(src_h - 1, 0))
    xs = np.clip(xs, 0.0, max(src_w - 1, 0))

    y0 = np.floor(ys).astype(np.int64)
    x0 = np.floor(xs).astype(np.int64)
    y1 = np.minimum(y0 + 1, src_h - 1)
    x1 = np.minimum(x0 + 1, src_w - 1)
    wy = ys - y0
    wx = xs - x0

    # Vectorized separable bilinear interpolation.  Shape annotations:
    # top/bottom:    (height, width)
    # interpolated:  (height, width)
    top = (1.0 - wx)[None, :] * arr_f[y0[:, None], x0[None, :]] + wx[None, :] * arr_f[y0[:, None], x1[None, :]]
    bottom = (1.0 - wx)[None, :] * arr_f[y1[:, None], x0[None, :]] + wx[None, :] * arr_f[y1[:, None], x1[None, :]]
    out = (1.0 - wy)[:, None] * top + wy[:, None] * bottom
    return np.clip(np.floor(out + 0.5), 0, 255).astype(np.uint8)


def block_means_32x32(y_256: np.ndarray) -> np.ndarray:
    """Return the 32 x 32 grid of rounded 8 x 8 block means."""
    arr = np.asarray(y_256, dtype=np.uint16)
    if arr.shape != (256, 256):
        raise ValidationError(f"block_means_32x32 requires shape (256, 256), got {arr.shape}")
    # Reshape into [block_y, within_y, block_x, within_x].  Integer rounding to
    # nearest is (sum + 32) // 64 because each block has 64 pixels.
    sums = arr.reshape(32, 8, 32, 8).sum(axis=(1, 3), dtype=np.uint32)
    means = (sums + 32) // 64
    return means.astype(np.uint8)


@lru_cache(maxsize=4)
def _orthonormal_dct_matrix(n: int) -> np.ndarray:
    """Return the n x n orthonormal DCT-II transform matrix."""
    k = np.arange(n, dtype=np.float64)[:, None]
    x = np.arange(n, dtype=np.float64)[None, :]
    mat = np.cos(np.pi * (x + 0.5) * k / n)
    mat[0, :] *= np.sqrt(1.0 / n)
    if n > 1:
        mat[1:, :] *= np.sqrt(2.0 / n)
    return mat


def dct_sign_sketch_255(y_64: np.ndarray) -> np.ndarray:
    """Return the 255 sign bits from top-left 16 x 16 DCT coefficients.

    The DC coefficient at [0, 0] is excluded.  Bits are ordered row-major over
    the 16 x 16 region.  A negative coefficient maps to bit 1; zero or positive
    maps to bit 0, matching the draft profile.
    """
    arr = np.asarray(y_64, dtype=np.float64)
    if arr.shape != (64, 64):
        raise ValidationError(f"dct_sign_sketch_255 requires shape (64, 64), got {arr.shape}")
    c = _orthonormal_dct_matrix(64)
    coeff = c @ arr @ c.T
    low = coeff[:16, :16].reshape(-1)
    ac = low[1:]  # remove DC
    bits = (ac < 0.0).astype(np.uint8)
    if bits.shape[0] != PED_IMG_1_DCT_SIGN_BITS:
        raise AssertionError("internal DCT sign sketch length error")
    return bits


def pack_bits_msb(bits: np.ndarray, padded_length_bytes: int | None = None) -> bytes:
    """Pack 0/1 bits in MSB-first order with zero padding at the tail."""
    b = np.asarray(bits, dtype=np.uint8).reshape(-1)
    if np.any((b != 0) & (b != 1)):
        raise ValidationError("pack_bits_msb expects only 0/1 values")
    packed = np.packbits(b, bitorder="big").tobytes()
    if padded_length_bytes is not None:
        if len(packed) > padded_length_bytes:
            raise ValidationError("packed bit string exceeds requested padded length")
        packed += b"\x00" * (padded_length_bytes - len(packed))
    return packed


def unpack_bits_msb(data: bytes, bit_count: int) -> np.ndarray:
    """Inverse of ``pack_bits_msb`` for diagnostics/tests."""
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8), bitorder="big")
    if bit_count > bits.shape[0]:
        raise ValidationError("requested more bits than available in packed data")
    return bits[:bit_count].astype(np.uint8)


def compute_ped_img1_bytes(artifact: Artifact) -> bytes:
    """Compute the raw 1056-byte PED-IMG-1 descriptor for an artifact."""
    image = decode_image_to_rgb(artifact)
    y = rgb_image_to_luminance_u8(image)
    y_256 = resize_bilinear_u8(y, 256, 256)
    means = block_means_32x32(y_256)
    y_64 = resize_bilinear_u8(y, 64, 64)
    sign_bits = dct_sign_sketch_255(y_64)
    dct_bytes = pack_bits_msb(sign_bits, padded_length_bytes=PED_IMG_1_DCT_SIGN_BYTES)
    ped = means.reshape(-1).tobytes() + dct_bytes
    if len(ped) != PED_IMG_1_LENGTH:
        raise AssertionError(f"PED-IMG-1 length should be {PED_IMG_1_LENGTH}, got {len(ped)}")
    return ped


def parse_ped_img1(ped: bytes) -> ImagePED1Components:
    """Parse PED-IMG-1 bytes into block means and DCT-sign bits."""
    raw = bytes(ped)
    if len(raw) != PED_IMG_1_LENGTH:
        raise ValidationError(f"PED-IMG-1 must be {PED_IMG_1_LENGTH} bytes, got {len(raw)}")
    means = np.frombuffer(raw[:PED_IMG_1_BLOCK_MEAN_SIZE], dtype=np.uint8).reshape(32, 32).copy()
    dct_packed = raw[PED_IMG_1_BLOCK_MEAN_SIZE:]
    bits = unpack_bits_msb(dct_packed, PED_IMG_1_DCT_SIGN_BITS)
    return ImagePED1Components(block_means_32x32=means, dct_sign_bits_255=bits)


def compare_ped_img1(a: bytes, b: bytes) -> ImagePED1Distance:
    """Return simple diagnostic distances between two PED-IMG-1 descriptors."""
    ca = parse_ped_img1(a)
    cb = parse_ped_img1(b)
    delta = np.abs(ca.block_means_32x32.astype(np.int16) - cb.block_means_32x32.astype(np.int16))
    hamming = int(np.count_nonzero(ca.dct_sign_bits_255 != cb.dct_sign_bits_255))
    return ImagePED1Distance(
        mean_absolute_block_delta=float(delta.mean()),
        max_block_delta=int(delta.max()),
        dct_sign_hamming=hamming,
        dct_sign_hamming_fraction=hamming / PED_IMG_1_DCT_SIGN_BITS,
    )


class ImagePED1(BaseEssenceProfile):
    """Reference implementation of the baseline still-image PED profile."""

    alg_id = PED_IMG_1_ALG_ID
    media_types = {"image/jpeg", "image/png", "image/webp", "image/tiff", "image/bmp", "image/gif"}

    def compute_ped(self, artifact: Artifact) -> bytes:
        return compute_ped_img1_bytes(artifact)

    def compute(self, artifact: Artifact) -> EssenceComputation:
        result = super().compute(artifact)
        # Enrich metadata with deterministic layout details.  This is useful for
        # debugging and for later HDC profile negotiation; it is not normally
        # written into the signed manifest unless an application chooses to do so.
        return EssenceComputation(
            alg_id=result.alg_id,
            ped=result.ped,
            essence_hash=result.essence_hash,
            media_type=result.media_type,
            metadata={
                **result.metadata,
                "profile_family": "image-ped",
                "block_means": "32x32 rounded means over 256x256 luminance",
                "dct_sign_bits": PED_IMG_1_DCT_SIGN_BITS,
                "ped_layout": "1024B block means || 32B packed DCT signs",
            },
        )

    def build_artifact_binding(
        self,
        artifact: Artifact,
        *,
        wm_alg_id: str | None = None,
        include_strict_byte_hash: bool = False,
        include_strict_decode_hash: bool = False,
    ) -> ArtifactBinding:
        """Compute an ``ArtifactBinding`` suitable for a ManifestCore.

        ``strict_byte_hash`` is exact container hashing and is useful in archival
        contexts.  ``strict_decode_hash`` is a deterministic hash of normalized
        RGB pixels; it is more stable than bytes but still brittle under JPEG
        recompression.  Both are optional supplements to the primary PED hash.
        """
        computation = self.compute(artifact)
        strict_byte = compute_strict_byte_hash(artifact) if include_strict_byte_hash else None
        strict_decode = compute_strict_decode_rgb_hash(artifact) if include_strict_decode_hash else None
        return computation.to_artifact_binding(
            wm_alg_id=wm_alg_id,
            strict_byte_hash=strict_byte,
            strict_decode_hash=strict_decode,
        )


def compute_ped_img1(artifact: Artifact) -> bytes:
    """Convenience function for callers that do not need a profile object."""
    return ImagePED1().compute_ped(artifact)


def compute_essence_img1(artifact: Artifact) -> EssenceComputation:
    """Convenience function returning PED plus hash for ``PED-IMG-1``."""
    return ImagePED1().compute(artifact)


def compute_essence_hash_img1(artifact: Artifact) -> Hash256:
    """Convenience function returning the signed PED commitment only."""
    return ImagePED1().compute_hash(artifact)


def compute_strict_decode_rgb_hash(artifact: Artifact) -> Hash256:
    """Hash normalized decoded RGB pixels for exact-ish closed-loop workflows.

    The preimage includes width and height using Step 1 length framing.  This is
    not the default OProW binding because lossy recompression changes pixels, but
    it is useful for tests, archives, and debugging copy/paste attacks.
    """
    image = decode_image_to_rgb(artifact)
    rgb = np.asarray(image, dtype=np.uint8)
    h, w = rgb.shape[:2]
    preimage = frame_parts(
        "oprow-strict-decode-rgb-v1",
        [w.to_bytes(8, "big"), h.to_bytes(8, "big"), rgb.tobytes()],
    )
    return Hash256.from_data(preimage)
