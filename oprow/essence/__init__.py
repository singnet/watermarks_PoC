"""OProW Step 3 essence hashing API.

Public exports are intentionally split into:

* profile/registry abstractions (for algorithm agility),
* the baseline image profile ``PED-IMG-1``, and
* strict supplemental hashes for closed-loop workflows.
"""

from .base import BaseEssenceProfile, EssenceComputation, EssenceProfile, ped_hash
from .image import (
    ImagePED1,
    ImagePED1Components,
    ImagePED1Distance,
    PED_IMG_1_ALG_ID,
    PED_IMG_1_LENGTH,
    block_means_32x32,
    compare_ped_img1,
    compute_essence_hash_img1,
    compute_essence_img1,
    compute_ped_img1,
    compute_strict_decode_rgb_hash,
    decode_image_to_rgb,
    dct_sign_sketch_255,
    parse_ped_img1,
    resize_bilinear_u8,
    rgb_image_to_luminance_u8,
)
from .registry import DEFAULT_ESSENCE_REGISTRY, EssenceRegistry, build_artifact_binding, compute_essence_hash, default_essence_registry
from .strict import compute_strict_byte_hash

__all__ = [
    "BaseEssenceProfile", "DEFAULT_ESSENCE_REGISTRY", "EssenceComputation",
    "EssenceProfile", "EssenceRegistry", "ImagePED1", "ImagePED1Components",
    "ImagePED1Distance", "PED_IMG_1_ALG_ID", "PED_IMG_1_LENGTH",
    "block_means_32x32", "build_artifact_binding", "compare_ped_img1",
    "compute_essence_hash", "compute_essence_hash_img1", "compute_essence_img1",
    "compute_ped_img1", "compute_strict_byte_hash", "compute_strict_decode_rgb_hash",
    "decode_image_to_rgb", "default_essence_registry", "dct_sign_sketch_255",
    "parse_ped_img1", "ped_hash", "resize_bilinear_u8", "rgb_image_to_luminance_u8",
]
