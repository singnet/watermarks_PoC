from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO

from PIL import Image

from oprow import (
    AlphaLSBImageWatermarkProfile,
    Artifact,
    CASResolver,
    DCTQIMImageWatermarkProfile,
    GenerationClaim,
    ManifestCore,
    ManifestLocator,
    MemoryCAS,
    MemoryKeyRegistry,
    OProWSigner,
    PointerMode,
    RepetitionCode,
    TrustPolicyStub,
    VerificationStatus,
    WatermarkFrameCodec,
    WatermarkPayload,
    WatermarkStrength,
    build_artifact_binding,
    create_signed_manifest,
    embed_manifest_locator,
    extract_locator,
    generate_ed25519_keypair,
    verify_artifact_from_watermark,
)
from oprow.core.enums import SignatureRole

FIXED_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_png(size=(128, 128), color=(90, 120, 180), stripe=(240, 230, 60)) -> bytes:
    img = Image.new("RGB", size, color=color)
    for x in range(size[0] // 8, size[0] - size[0] // 8):
        for y in range(size[1] // 2 - 8, size[1] // 2 + 8):
            img.putpixel((x, y), stripe)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


@dataclass
class BuiltArtifact:
    artifact: Artifact
    signed: object
    locator: ManifestLocator
    key_registry: MemoryKeyRegistry
    key_id: str


def build_signed_image(*, wm_alg_id="IMG-ALPHA-LSB-REF-1", size=(128, 128)) -> BuiltArtifact:
    artifact = Artifact.from_bytes(make_png(size=size), media_type="image/png")
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    binding = build_artifact_binding(artifact, wm_alg_id=wm_alg_id)
    core = ManifestCore(version=1, artifact=binding, claims=[GenerationClaim(model_id="step12-model")], created_at=FIXED_TIME)
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.FULL160)
    return BuiltArtifact(artifact, signed, locator, MemoryKeyRegistry.from_public_keys([key.public]), str(key.kid))


def test_watermark_payload_round_trips_full160_and_short64_hv():
    built = build_signed_image()
    alpha = AlphaLSBImageWatermarkProfile()

    full_payload = WatermarkPayload.from_locator(built.locator, wm_alg_id=alpha.numeric_id)
    decoded_full = WatermarkPayload.decode_bits(full_payload.to_bits())
    assert decoded_full.pointer_mode == PointerMode.FULL160
    assert decoded_full.pointer == built.locator.value
    assert decoded_full.to_locator().value == built.locator.value

    short_locator = ManifestLocator.from_signed_manifest(built.signed, mode=PointerMode.SHORT64_HV, hdc_profile_id="HV-PED-IMG-1-D8192")
    short_payload = WatermarkPayload.from_locator(short_locator, wm_alg_id=alpha.numeric_id)
    decoded_short = WatermarkPayload.decode_bits(short_payload.to_bits(), hdc_profile_id="HV-PED-IMG-1-D8192")
    assert decoded_short.pointer_mode == PointerMode.SHORT64_HV
    assert decoded_short.pointer == short_locator.value
    assert decoded_short.to_locator().hdc_profile_id == "HV-PED-IMG-1-D8192"


def test_repetition_codec_corrects_one_corrupted_bit_per_triple():
    bits = [0, 1, 1, 0, 1, 0]
    code = RepetitionCode(3)
    encoded = code.encode(bits)
    # Flip one carrier bit in two different triples.  Majority decoding should
    # recover the original payload bits and record that corrections happened.
    encoded[1] ^= 1
    encoded[7] ^= 1
    report = code.decode(encoded)
    assert report.decoded_bits == bits
    assert report.corrected_groups == 2


def test_frame_codec_round_trips_payload_with_ecc():
    built = build_signed_image()
    profile = AlphaLSBImageWatermarkProfile()
    payload = WatermarkPayload.from_locator(built.locator, wm_alg_id=profile.numeric_id)
    codec = WatermarkFrameCodec(ecc=RepetitionCode(3))

    carrier = codec.encode_payload(payload)
    # Simulate one noisy carrier bit in the preamble frame.  Repetition ECC
    # should correct it before payload CRC is checked.
    carrier[10] ^= 1
    decoded, frame = codec.decode_payload(carrier)
    assert decoded.pointer == payload.pointer
    assert frame.repetition_report.corrected_groups == 1


def test_alpha_lsb_profile_embeds_and_extracts_full160_locator():
    built = build_signed_image()
    profile = AlphaLSBImageWatermarkProfile()
    strength = WatermarkStrength(name="test-alpha", repetitions=3)

    embedded = embed_manifest_locator(
        built.artifact,
        built.signed,
        pointer_mode=PointerMode.FULL160,
        watermark_profile=profile,
        strength=strength,
    )
    extraction = extract_locator(embedded.artifact, watermark_profile=profile, strength=strength)

    assert extraction.extracted
    assert extraction.locator == built.locator
    assert embedded.diagnostics["used_carrier_bits"] > 0
    assert embedded.artifact.media_type == "image/png"


def test_alpha_lsb_watermarked_artifact_still_verifies_against_original_manifest():
    built = build_signed_image()
    profile = AlphaLSBImageWatermarkProfile()
    strength = WatermarkStrength(name="test-alpha", repetitions=3)
    embedded = embed_manifest_locator(
        built.artifact,
        built.signed,
        pointer_mode=PointerMode.FULL160,
        watermark_profile=profile,
        strength=strength,
    )

    cas = MemoryCAS()
    cas.put_manifest(built.signed)
    report = verify_artifact_from_watermark(
        embedded.artifact,
        watermark_profile=profile,
        strength=strength,
        resolver=CASResolver([cas]),
        key_resolver=built.key_registry,
        trust_policy=TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}),
    )

    assert report.extraction.extracted
    assert report.verification is not None
    assert report.verification.status == VerificationStatus.VERIFIED
    assert report.verified


def test_dct_qim_reference_profile_extracts_short64_on_large_image():
    built = build_signed_image(wm_alg_id="IMG-DCT-QIM-REF-1", size=(256, 256))
    profile = DCTQIMImageWatermarkProfile()
    strength = WatermarkStrength(name="test-dct", repetitions=1, qim_delta=64.0)

    embedded = embed_manifest_locator(
        built.artifact,
        built.signed,
        pointer_mode=PointerMode.SHORT64,
        watermark_profile=profile,
        strength=strength,
    )
    extraction = extract_locator(embedded.artifact, watermark_profile=profile, strength=strength)

    assert extraction.extracted, extraction.error
    assert extraction.locator is not None
    assert extraction.locator.mode == PointerMode.SHORT64
    assert extraction.locator.value == built.signed.short_id_hash_truncated()
