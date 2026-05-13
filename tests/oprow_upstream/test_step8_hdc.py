from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO

from PIL import Image

from oprow import (
    Artifact,
    GenerationClaim,
    HDCRouter,
    ManifestCore,
    ManifestLocator,
    MemoryKeyRegistry,
    MemoryShort64HVIndex,
    OProWSigner,
    PointerMode,
    RoutePrecision,
    Short64HVRouteResolver,
    SparseTernaryHDCEncoder,
    TrustPolicyStub,
    VerificationStatus,
    build_artifact_binding,
    default_hdc_profile,
    create_signed_manifest,
    generate_ed25519_keypair,
    short_id_prefix_bytes,
    verify_artifact_with_locator,
)
from oprow.core.enums import SignatureRole
from oprow.resolution import ResolutionRequest, ResolutionStatus

FIXED_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_jpeg(color=(90, 110, 180), stripe=(240, 230, 60)) -> bytes:
    img = Image.new("RGB", (96, 96), color=color)
    for x in range(10, 86):
        for y in range(40, 52):
            img.putpixel((x, y), stripe)
    buf = BytesIO()
    img.save(buf, format="JPEG", quality=92)
    return buf.getvalue()


@dataclass
class BuiltHVArtifact:
    artifact: Artifact
    signed: object
    locator: ManifestLocator
    key_registry: MemoryKeyRegistry
    key_id: str


def build_signed_image(model_id="step8-model", *, color=(90, 110, 180)) -> BuiltHVArtifact:
    artifact = Artifact.from_bytes(make_jpeg(color=color), media_type="image/jpeg")
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    binding = build_artifact_binding(artifact, wm_alg_id="test-watermark")
    core = ManifestCore(version=1, artifact=binding, claims=[GenerationClaim(model_id=model_id)], created_at=FIXED_TIME)
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    profile = default_hdc_profile(profile_id="HV-PED-IMG-1-D1024-SPARSE-test", dimension=1024, num_bands=8, bits_per_band=12, value_quantization_levels=16)
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.SHORT64_HV, hdc_profile_id=profile.profile_id)
    return BuiltHVArtifact(artifact, signed, locator, MemoryKeyRegistry.from_public_keys([key.public]), str(key.kid))


def small_profile():
    # Tests use a smaller dimension so the suite remains fast while still
    # exercising the exact same algorithms and packing rules as the default
    # 8192-dimensional profile.
    return default_hdc_profile(profile_id="HV-PED-IMG-1-D1024-SPARSE-test", dimension=1024, num_bands=8, bits_per_band=12, value_quantization_levels=16)


def test_hdc_encoder_is_deterministic_for_same_artifact():
    built = build_signed_image()
    profile = small_profile()
    encoder = SparseTernaryHDCEncoder(profile=profile)

    enc1 = encoder.encode_artifact(built.artifact)
    enc2 = encoder.encode_artifact(built.artifact)
    hv1 = enc1.hypervector
    hv2 = enc2.hypervector

    assert hv1.bits == hv2.bits
    assert hv1.dimension == 1024
    assert enc1.profile.profile_id == profile.profile_id
    assert hv1.hamming_distance(hv2) == 0


def test_route_tokens_are_deterministic_and_do_not_equal_raw_hv():
    built = build_signed_image()
    profile = small_profile()
    encoder = SparseTernaryHDCEncoder(profile=profile)
    encoding = encoder.encode_artifact(built.artifact)
    router = HDCRouter(profile)

    tokens1 = router.derive_route_tokens(short_id=built.locator.value, hv=encoding)
    tokens2 = router.derive_route_tokens(short_id=built.locator.value, hv=encoding)

    assert [t.route_key for t in tokens1] == [t.route_key for t in tokens2]
    assert len(tokens1) == profile.num_bands
    # The route key is a 32-byte hash commitment.  It should not expose the raw
    # hypervector bytes directly.
    assert tokens1[0].route_key.value not in encoding.hypervector.bits


def test_short_id_prefix_masks_partial_byte():
    built = build_signed_image()
    full = built.locator.value.value
    prefix_20 = short_id_prefix_bytes(built.locator.value, 20)

    assert len(prefix_20) == 3
    assert prefix_20[:2] == full[:2]
    assert prefix_20[2] & 0x0F == 0


def test_memory_short64_hv_index_resolves_embedded_manifest_bytes():
    built = build_signed_image()
    profile = small_profile()
    locator = ManifestLocator.from_signed_manifest(built.signed, mode=PointerMode.SHORT64_HV, hdc_profile_id=profile.profile_id)
    index = MemoryShort64HVIndex(profile=profile)
    index.add_manifest(built.signed, artifact=built.artifact, include_document_bytes=True)

    result = Short64HVRouteResolver(index).resolve(ResolutionRequest(locator=locator, artifact=built.artifact))

    assert result.status == ResolutionStatus.FOUND
    assert len(result.candidates) == 1
    assert result.candidates[0].manifest.short_id_hash_truncated() == locator.value


def test_step8_verifier_accepts_short64_hv_after_signature_essence_and_trust():
    built = build_signed_image()
    profile = small_profile()
    locator = ManifestLocator.from_signed_manifest(built.signed, mode=PointerMode.SHORT64_HV, hdc_profile_id=profile.profile_id)
    index = MemoryShort64HVIndex(profile=profile)
    index.add_manifest(built.signed, artifact=built.artifact, include_document_bytes=True)

    result = verify_artifact_with_locator(
        built.artifact,
        locator,
        resolver=Short64HVRouteResolver(index),
        key_resolver=built.key_registry,
        trust_policy=TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}),
    )

    assert result.status == VerificationStatus.VERIFIED
    assert result.verified


def test_hdc_route_miss_does_not_verify_different_media():
    built_a = build_signed_image("a", color=(90, 110, 180))
    built_b = build_signed_image("b", color=(30, 180, 60))
    profile = small_profile()
    locator_a = ManifestLocator.from_signed_manifest(built_a.signed, mode=PointerMode.SHORT64_HV, hdc_profile_id=profile.profile_id)

    index = MemoryShort64HVIndex(profile=profile)
    index.add_manifest(built_a.signed, artifact=built_a.artifact, include_document_bytes=True)

    # Use A's locator but B's artifact.  Depending on the coarse route settings,
    # this may be a lookup miss or may return candidates.  Either way the final
    # verifier must not return VERIFIED because B's essence does not match A's
    # signed manifest.
    result = verify_artifact_with_locator(
        built_b.artifact,
        locator_a,
        resolver=Short64HVRouteResolver(index),
        key_resolver=built_a.key_registry,
        trust_policy=TrustPolicyStub(trusted_key_ids={built_a.key_id}, accepted_roles={"tool"}),
    )

    assert result.status in {VerificationStatus.MANIFEST_NOT_FOUND, VerificationStatus.CONTENT_MISMATCH}
    assert not result.verified


def test_route_precision_can_use_broader_short_prefix():
    built = build_signed_image()
    profile = small_profile()
    encoder = SparseTernaryHDCEncoder(profile=profile)
    encoding = encoder.encode_artifact(built.artifact)
    router = HDCRouter(profile)

    narrow = router.derive_route_tokens(short_id=built.locator.value, hv=encoding, precision=RoutePrecision(short_prefix_bits=64, hv_band_bits=12))
    broad = router.derive_route_tokens(short_id=built.locator.value, hv=encoding, precision=RoutePrecision(short_prefix_bits=16, hv_band_bits=12))

    assert narrow[0].route_key != broad[0].route_key
    assert len(broad[0].short_prefix) == 2
