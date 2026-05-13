from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO

from PIL import Image

from oprow import (
    Artifact,
    AuthenticatedShort64HVIndex,
    GenerationClaim,
    ManifestCore,
    ManifestLocator,
    MemoryKeyRegistry,
    OProWSigner,
    PointerMode,
    PrivacyPreservingAuthenticatedShort64HVResolver,
    RelayQueryBatch,
    Short64HVPrivacyPlanner,
    StaticCoverRouteSampler,
    TrustPolicyStub,
    VerificationStatus,
    add_manifest_for_privacy_policies,
    build_artifact_binding,
    create_signed_manifest,
    default_hdc_profile,
    generate_ed25519_keypair,
    k_anonymous_bucket_policy,
    relay_cover_policy,
    verify_artifact_with_locator,
)
from oprow.core.enums import SignatureRole
from oprow.hdc import SparseTernaryHDCEncoder

FIXED_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_jpeg(color=(100, 90, 170), stripe=(240, 230, 70)) -> bytes:
    img = Image.new("RGB", (96, 96), color=color)
    for x in range(12, 84):
        for y in range(36, 52):
            img.putpixel((x, y), stripe)
    buf = BytesIO()
    img.save(buf, format="JPEG", quality=92)
    return buf.getvalue()


@dataclass
class BuiltArtifact:
    artifact: Artifact
    signed: object
    locator: ManifestLocator
    key_registry: MemoryKeyRegistry
    key_id: str


def small_profile():
    return default_hdc_profile(profile_id="HV-PED-IMG-1-D1024-SPARSE-step10", dimension=1024, num_bands=8, bits_per_band=12, value_quantization_levels=16)


def build_signed_image(model_id="step10-model", *, color=(100, 90, 170)) -> BuiltArtifact:
    artifact = Artifact.from_bytes(make_jpeg(color=color), media_type="image/jpeg")
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    binding = build_artifact_binding(artifact, wm_alg_id="test-watermark")
    core = ManifestCore(version=1, artifact=binding, claims=[GenerationClaim(model_id=model_id)], created_at=FIXED_TIME)
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    profile = small_profile()
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.SHORT64_HV, hdc_profile_id=profile.profile_id)
    return BuiltArtifact(artifact, signed, locator, MemoryKeyRegistry.from_public_keys([key.public]), str(key.kid))


def test_p1_query_plan_uses_coarse_route_tokens_and_redacted_public_shape():
    built = build_signed_image()
    profile = small_profile()
    policy = k_anonymous_bucket_policy(min_anonymity_set=1, max_candidate_bucket=64)
    index = AuthenticatedShort64HVIndex(profile=profile)
    add_manifest_for_privacy_policies(index, built.signed, artifact=built.artifact, policies=[policy], include_document_bytes=True)

    encoder = SparseTernaryHDCEncoder(profile=profile)
    hv = encoder.encode_artifact(built.artifact).hypervector
    planner = Short64HVPrivacyPlanner(stats_provider=index)
    plan = planner.plan(short_id=built.locator.value, hv=hv, profile=profile, policy=policy)

    assert plan.policy.profile.value == "P1_K_ANON_BUCKET"
    assert plan.selected_precision.short_prefix_bits < 64
    assert plan.real_queries
    public_queries = plan.public_queries()
    assert "kind" not in public_queries[0]
    assert built.locator.value.to_hex() not in str(public_queries)
    assert plan.selected_estimate is not None
    assert plan.selected_estimate.estimated_candidates is not None


def test_p1_privacy_preserving_authenticated_resolver_still_verifies_after_full_checks():
    built = build_signed_image()
    profile = small_profile()
    policy = k_anonymous_bucket_policy(min_anonymity_set=1, max_candidate_bucket=64)
    index = AuthenticatedShort64HVIndex(profile=profile)
    add_manifest_for_privacy_policies(index, built.signed, artifact=built.artifact, policies=[policy], include_document_bytes=True)

    result = verify_artifact_with_locator(
        built.artifact,
        built.locator,
        resolver=PrivacyPreservingAuthenticatedShort64HVResolver(index, expected_root=index.root_record().root_hash, privacy_policy=policy),
        key_resolver=built.key_registry,
        trust_policy=TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}),
    )

    assert result.status == VerificationStatus.VERIFIED
    assert result.resolution is not None
    route_diag = next(ev for ev in result.resolution.diagnostics if ev.event == "authenticated_route_lookup")
    assert route_diag.data["privacy_plan"]["policy"]["profile"] == "P1_K_ANON_BUCKET"


def test_p2_cover_queries_are_added_but_not_labeled_in_public_batch():
    built = build_signed_image("real", color=(100, 90, 170))
    cover = build_signed_image("cover", color=(30, 180, 130))
    profile = small_profile()
    policy = relay_cover_policy(min_anonymity_set=1, max_candidate_bucket=128, cover_query_count=2)
    index = AuthenticatedShort64HVIndex(profile=profile)
    add_manifest_for_privacy_policies(index, built.signed, artifact=built.artifact, policies=[policy], include_document_bytes=True)
    add_manifest_for_privacy_policies(index, cover.signed, artifact=cover.artifact, policies=[policy], include_document_bytes=True)

    sampler = StaticCoverRouteSampler.from_index(index)
    encoder = SparseTernaryHDCEncoder(profile=profile)
    hv = encoder.encode_artifact(built.artifact).hypervector
    planner = Short64HVPrivacyPlanner(stats_provider=index, cover_sampler=sampler)
    plan = planner.plan(short_id=built.locator.value, hv=hv, profile=profile, policy=policy)
    batch = RelayQueryBatch.from_plan(plan)

    assert len(plan.cover_queries) > 0
    assert len(plan.all_queries) == len(plan.real_queries) + len(plan.cover_queries)
    assert all("kind" not in q for q in batch.public_queries)
    assert batch.metadata["privacy_profile"] == "P2_RELAY_COVER"

    result = verify_artifact_with_locator(
        built.artifact,
        built.locator,
        resolver=PrivacyPreservingAuthenticatedShort64HVResolver(
            index,
            expected_root=index.root_record().root_hash,
            privacy_policy=policy,
            cover_sampler=sampler,
        ),
        key_resolver=built.key_registry,
        trust_policy=TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}),
    )

    assert result.status == VerificationStatus.VERIFIED
    route_diag = next(ev for ev in result.resolution.diagnostics if ev.event == "authenticated_route_lookup")
    assert route_diag.data["privacy_plan"]["cover_query_count"] > 0
