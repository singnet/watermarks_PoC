from __future__ import annotations

from datetime import datetime, timezone

from oprow import (
    AlphaLSBImageWatermarkProfile,
    Artifact,
    CASResolver,
    GenerationClaim,
    HDCProfile,
    IdentityTransform,
    ImagePED1,
    ManifestCore,
    ManifestKey,
    MemoryCAS,
    MemoryKeyRegistry,
    OProWSigner,
    PointerMode,
    ShortId,
    SymbolicBundlingHDCEncoder,
    TrustPolicyStub,
    VerificationStatus,
    WatermarkPayload,
    WatermarkStrength,
    benchmark_essence_profile,
    benchmark_hdc_stability,
    benchmark_watermark_profile,
    build_artifact_binding,
    checker_sample,
    constant_payload_factory,
    copy_alpha_lsb_carrier,
    create_signed_manifest,
    default_synthetic_image_corpus,
    embed_manifest_locator,
    generate_ed25519_keypair,
    quick_image_transform_suite,
    solid_with_stripe_sample,
    verify_artifact_from_watermark,
)
from oprow.core.enums import SignatureRole

FIXED_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def test_quick_transform_suite_and_essence_benchmark_identity_match():
    artifact = solid_with_stripe_sample(size=(128, 128), artifact_id="essence-smoke")
    suite = quick_image_transform_suite()

    report = benchmark_essence_profile(profile=ImagePED1(), artifacts=[artifact], transforms=suite)

    assert len(report.cases) == len(suite.transforms)
    identity = next(c for c in report.cases if c.transform == "identity")
    assert identity.status == "essence_match"
    assert identity.metric_map()["essence_hash_matches"] is True
    assert "status_counts" in report.summary()
    assert "essence_match" in report.to_json()


def test_alpha_lsb_watermark_benchmark_recovers_locator_under_identity():
    profile = AlphaLSBImageWatermarkProfile()
    payload = WatermarkPayload(
        version=1,
        wm_alg_id=profile.numeric_id,
        pointer_mode=PointerMode.FULL160,
        pointer=ManifestKey(b"\x11" * 20),
    ).with_computed_crc()
    artifact = solid_with_stripe_sample(size=(128, 128), artifact_id="wm-smoke")
    strength = WatermarkStrength(name="test-alpha", repetitions=3)

    report = benchmark_watermark_profile(
        profile=profile,
        artifacts=[artifact],
        payload_factory=constant_payload_factory(payload),
        transforms=[IdentityTransform()],
        strength=strength,
    )

    assert len(report.cases) == 1
    case = report.cases[0]
    assert case.status == "locator_match"
    assert case.metric_map()["watermark_extracted"] is True
    assert case.metric_map()["locator_matches"] is True


def test_hdc_benchmark_identity_distance_is_zero():
    artifact = solid_with_stripe_sample(size=(96, 96), artifact_id="hdc-smoke")
    # Use a small profile in the unit test so the symbolic-bundling encoder runs
    # quickly.  Real experiments should use the default 8192-dimensional profile
    # or a registered production profile.
    profile = HDCProfile(
        profile_id="HV-PED-IMG-1-D512-TEST",
        dimension=512,
        num_bands=8,
        bits_per_band=8,
        value_quantization_levels=16,
    )
    encoder = SymbolicBundlingHDCEncoder(profile)

    report = benchmark_hdc_stability(
        encoder=encoder,
        artifacts=[artifact],
        transforms=[IdentityTransform()],
        short_id=ShortId(b"\x22" * 8),
    )

    assert len(report.cases) == 1
    case = report.cases[0]
    assert case.status == "hdc_measured"
    assert case.metric_map()["hdc_normalized_hamming"] == 0.0
    assert case.metric_map()["route_token_overlap_fraction"] == 1.0


def test_copy_paste_alpha_watermark_attack_is_rejected_by_essence_check():
    source = solid_with_stripe_sample(size=(192, 192), artifact_id="source")
    target = checker_sample(size=(192, 192), artifact_id="target")
    profile = AlphaLSBImageWatermarkProfile()
    strength = WatermarkStrength(name="attack-test-alpha", repetitions=3)

    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    binding = build_artifact_binding(source, wm_alg_id=profile.alg_id)
    core = ManifestCore(
        version=1,
        artifact=binding,
        claims=[GenerationClaim(model_id="step14-copy-attack-test")],
        created_at=FIXED_TIME,
    )
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    embedded = embed_manifest_locator(
        source,
        signed,
        pointer_mode=PointerMode.FULL160,
        watermark_profile=profile,
        strength=strength,
    )

    attacked = copy_alpha_lsb_carrier(embedded.artifact, target)
    cas = MemoryCAS()
    cas.put_manifest(signed)
    result = verify_artifact_from_watermark(
        attacked,
        watermark_profile=profile,
        strength=strength,
        resolver=CASResolver([cas]),
        key_resolver=MemoryKeyRegistry.from_public_keys([key.public]),
        trust_policy=TrustPolicyStub(trusted_key_ids={str(key.kid)}, accepted_roles={"tool"}),
    )

    assert result.extraction.extracted
    assert result.verification is not None
    assert result.verification.status == VerificationStatus.CONTENT_MISMATCH
    assert not result.verified


def test_combined_synthetic_corpus_has_named_artifacts():
    corpus = default_synthetic_image_corpus()
    assert len(corpus) == 3
    assert {a.metadata["artifact_id"] for a in corpus} == {"gradient", "checker", "stripe"}
