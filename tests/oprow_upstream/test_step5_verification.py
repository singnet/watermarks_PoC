from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO

from PIL import Image

from oprow import (
    Artifact,
    CASResolver,
    GenerationClaim,
    Hash256,
    ManifestCore,
    ManifestEnvelope,
    ManifestLocator,
    MemoryCAS,
    MemoryKeyRegistry,
    OProWSigner,
    PointerMode,
    ResolutionCandidate,
    ResolutionRequest,
    ResolutionResult,
    ResolutionStatus,
    TrustPolicyStub,
    VerificationStatus,
    build_artifact_binding,
    create_signed_manifest,
    generate_ed25519_keypair,
    verify_artifact_with_locator,
)
from oprow.core.enums import SignatureRole
from oprow.core.policy import ResolutionLimits
from oprow.resolution.base import CandidateValidationStatus

FIXED_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_jpeg(color=(80, 120, 180), stripe=(230, 230, 40)) -> bytes:
    img = Image.new("RGB", (96, 96), color=color)
    for x in range(12, 84):
        for y in range(42, 50):
            img.putpixel((x, y), stripe)
    buf = BytesIO(); img.save(buf, format="JPEG", quality=92)
    return buf.getvalue()


@dataclass
class BuiltArtifact:
    artifact: Artifact
    signed: object
    locator: ManifestLocator
    key_registry: MemoryKeyRegistry
    key_id: str


def build_signed_image(model_id="step5-model") -> BuiltArtifact:
    artifact = Artifact.from_bytes(make_jpeg(), media_type="image/jpeg")
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    binding = build_artifact_binding(artifact, wm_alg_id="test-watermark")
    core = ManifestCore(version=1, artifact=binding, claims=[GenerationClaim(model_id=model_id)], created_at=FIXED_TIME)
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.FULL160)
    return BuiltArtifact(artifact, signed, locator, MemoryKeyRegistry.from_public_keys([key.public]), str(key.kid))


def verify_from_memory_cas(built: BuiltArtifact, trust_policy: TrustPolicyStub):
    cas = MemoryCAS(); cas.put_manifest(built.signed)
    return verify_artifact_with_locator(
        built.artifact,
        built.locator,
        resolver=CASResolver([cas]),
        key_resolver=built.key_registry,
        trust_policy=trust_policy,
    )


def test_step5_verified_when_signature_essence_and_trust_pass():
    built = build_signed_image()
    result = verify_from_memory_cas(built, TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}))
    assert result.status == VerificationStatus.VERIFIED
    assert result.verified
    assert len(result.trusted_claims) == 1
    assert result.trusted_claims[0].type == "generation"
    assert len(result.valid_signatures) == 1


def test_step5_signed_but_untrusted_when_key_not_in_policy():
    built = build_signed_image()
    result = verify_from_memory_cas(built, TrustPolicyStub(trusted_key_ids=set(), accepted_roles={"tool"}))
    assert result.status == VerificationStatus.SIGNED_BUT_UNTRUSTED
    assert result.verified_manifests
    assert result.valid_signatures
    assert not result.trusted_claims


def test_step5_no_valid_signatures_when_key_missing():
    built = build_signed_image()
    cas = MemoryCAS(); cas.put_manifest(built.signed)
    result = verify_artifact_with_locator(
        built.artifact,
        built.locator,
        resolver=CASResolver([cas]),
        key_resolver=MemoryKeyRegistry(),
        trust_policy=TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}),
    )
    assert result.status == VerificationStatus.NO_VALID_SIGNATURES


def test_step5_content_mismatch_when_artifact_essence_differs():
    built = build_signed_image()
    different_artifact = Artifact.from_bytes(make_jpeg(color=(5, 200, 30), stripe=(250, 0, 0)), media_type="image/jpeg")
    cas = MemoryCAS(); cas.put_manifest(built.signed)
    result = verify_artifact_with_locator(
        different_artifact,
        built.locator,
        resolver=CASResolver([cas]),
        key_resolver=built.key_registry,
        trust_policy=TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}),
    )
    assert result.status == VerificationStatus.CONTENT_MISMATCH
    assert result.candidate_reports[0].essence_check is not None
    assert not result.candidate_reports[0].essence_check.matched


def test_step5_manifest_not_found_when_resolver_misses():
    built = build_signed_image()
    result = verify_artifact_with_locator(
        built.artifact,
        built.locator,
        resolver=CASResolver([MemoryCAS()]),
        key_resolver=built.key_registry,
        trust_policy=TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}),
    )
    assert result.status == VerificationStatus.MANIFEST_NOT_FOUND


class FloodResolver:
    name = "flood"

    def __init__(self, candidate: ResolutionCandidate, count: int):
        self.candidate = candidate
        self.count = count

    def resolve(self, request: ResolutionRequest) -> ResolutionResult:
        return ResolutionResult(status=ResolutionStatus.FOUND, candidates=[self.candidate] * self.count)


def test_step5_candidate_flood_is_not_verified():
    built = build_signed_image()
    envelope = ManifestEnvelope(manifest=built.signed, locator=built.locator)
    candidate = ResolutionCandidate(envelope=envelope, source="synthetic-flood", validation_status=CandidateValidationStatus.LOCATOR_MATCH)
    result = verify_artifact_with_locator(
        built.artifact,
        built.locator,
        resolver=FloodResolver(candidate, count=3),
        key_resolver=built.key_registry,
        trust_policy=TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}, limits=ResolutionLimits(max_candidates=2)),
    )
    assert result.status == VerificationStatus.RESOLUTION_CANDIDATE_FLOOD


def test_step5_unsupported_essence_profile_is_explicit():
    built = build_signed_image()
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    good_binding = build_artifact_binding(built.artifact, wm_alg_id="test-watermark")
    bad_binding = type(good_binding)(
        media_type=good_binding.media_type,
        essence_alg_id="PED-IMG-DOES-NOT-EXIST",
        essence_hash=Hash256.from_data(b"placeholder"),
        hash_alg=good_binding.hash_alg,
        wm_alg_id=good_binding.wm_alg_id,
    )
    core = ManifestCore(version=1, artifact=bad_binding, claims=[GenerationClaim(model_id="bad-profile")], created_at=FIXED_TIME)
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.FULL160)
    cas = MemoryCAS(); cas.put_manifest(signed)
    result = verify_artifact_with_locator(
        built.artifact,
        locator,
        resolver=CASResolver([cas]),
        key_resolver=MemoryKeyRegistry.from_public_keys([key.public]),
        trust_policy=TrustPolicyStub(trusted_key_ids={str(key.kid)}, accepted_roles={"tool"}),
    )
    assert result.status == VerificationStatus.UNSUPPORTED_ESSENCE_PROFILE
