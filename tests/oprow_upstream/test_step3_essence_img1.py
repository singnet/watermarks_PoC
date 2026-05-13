from datetime import datetime, timezone
from io import BytesIO

import numpy as np
from PIL import Image

from oprow import (
    Artifact,
    GenerationClaim,
    Hash256,
    ImagePED1,
    ManifestCore,
    MemoryKeyRegistry,
    OProWSigner,
    PED_IMG_1_ALG_ID,
    PED_IMG_1_LENGTH,
    PointerMode,
    create_signed_manifest,
    generate_ed25519_keypair,
    verify_manifest_signatures,
)
from oprow.core.enums import SignatureRole
from oprow.essence.image import (
    block_means_32x32,
    compare_ped_img1,
    compute_ped_img1,
    compute_strict_decode_rgb_hash,
    parse_ped_img1,
    resize_bilinear_u8,
    rgb_image_to_luminance_u8,
)
from oprow.essence.registry import build_artifact_binding, compute_essence_hash
from oprow.essence.strict import compute_strict_byte_hash


def make_png_artifact(width=96, height=64) -> Artifact:
    """Create a deterministic RGB gradient image for tests."""
    x = np.arange(width, dtype=np.uint16)[None, :]
    y = np.arange(height, dtype=np.uint16)[:, None]
    r = ((x * 3 + y * 5) % 256).astype(np.uint8)
    g = ((x * 7 + y * 2) % 256).astype(np.uint8)
    b = ((x * 11 + y * 13) % 256).astype(np.uint8)
    rgb = np.stack([r, g, b], axis=2)
    img = Image.fromarray(rgb, mode="RGB")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return Artifact.from_bytes(buf.getvalue(), media_type="image/png")


def test_luminance_formula_known_pixels():
    img = Image.new("RGB", (3, 1))
    img.putpixel((0, 0), (0, 0, 0))
    img.putpixel((1, 0), (255, 255, 255))
    img.putpixel((2, 0), (255, 0, 0))
    y = rgb_image_to_luminance_u8(img)
    assert y[0, 0] == 0
    assert y[0, 1] == 255
    assert y[0, 2] == 77


def test_reference_resizer_preserves_constant_image():
    src = np.full((17, 23), 123, dtype=np.uint8)
    out = resize_bilinear_u8(src, 256, 256)
    assert out.shape == (256, 256)
    assert out.dtype == np.uint8
    assert int(out.min()) == 123
    assert int(out.max()) == 123


def test_block_means_on_constant_image_are_constant():
    y = np.full((256, 256), 200, dtype=np.uint8)
    means = block_means_32x32(y)
    assert means.shape == (32, 32)
    assert means.dtype == np.uint8
    assert np.all(means == 200)


def test_ped_img1_has_expected_layout_and_is_deterministic():
    artifact = make_png_artifact()
    ped_a = compute_ped_img1(artifact)
    ped_b = compute_ped_img1(artifact)
    assert ped_a == ped_b
    assert len(ped_a) == PED_IMG_1_LENGTH

    parsed = parse_ped_img1(ped_a)
    assert parsed.block_means_32x32.shape == (32, 32)
    assert parsed.dct_sign_bits_255.shape == (255,)


def test_ped_distance_detects_different_images():
    a = make_png_artifact(width=96, height=64)
    b = make_png_artifact(width=80, height=80)
    dist = compare_ped_img1(compute_ped_img1(a), compute_ped_img1(b))
    assert dist.mean_absolute_block_delta > 0.0 or dist.dct_sign_hamming > 0


def test_essence_hash_and_binding_are_manifest_ready():
    artifact = make_png_artifact()
    binding = build_artifact_binding(
        artifact,
        alg_id=PED_IMG_1_ALG_ID,
        wm_alg_id="IMG-DCT-QIM-1",
        include_strict_byte_hash=True,
        include_strict_decode_hash=True,
    )
    assert binding.essence_alg_id == PED_IMG_1_ALG_ID
    assert isinstance(binding.essence_hash, Hash256)
    assert binding.strict_byte_hash == compute_strict_byte_hash(artifact)
    assert binding.strict_decode_hash == compute_strict_decode_rgb_hash(artifact)

    core = ManifestCore(
        version=1,
        artifact=binding,
        claims=[GenerationClaim(model_id="step3-test-model")],
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)])
    assert signed.short_id_hash_truncated() is not None
    report = verify_manifest_signatures(signed, MemoryKeyRegistry.from_public_keys([key.public]))
    assert report.has_valid_signature


def test_registry_compute_hash_matches_profile():
    artifact = make_png_artifact()
    assert compute_essence_hash(artifact, PED_IMG_1_ALG_ID) == ImagePED1().compute_hash(artifact)
