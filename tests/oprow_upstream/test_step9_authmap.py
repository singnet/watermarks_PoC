from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO

from PIL import Image

from oprow import (
    Artifact,
    AuthenticatedShort64HVIndex,
    AuthenticatedShort64HVRouteResolver,
    GenerationClaim,
    Hash256,
    ManifestCore,
    ManifestLocator,
    MemoryKeyRegistry,
    OProWSigner,
    PointerMode,
    RoutePrecision,
    SparseMerkleMap,
    SparseTernaryHDCEncoder,
    TrustPolicyStub,
    VerificationStatus,
    build_artifact_binding,
    create_signed_manifest,
    default_hdc_profile,
    generate_ed25519_keypair,
    verify_artifact_with_locator,
)
from oprow.authmap import RouteCandidateSet, route_candidate_set_from_primitive
from oprow.core.canonical import canonical_cbor_loads
from oprow.core.enums import SignatureRole
from oprow.core.hashes import hash_framed
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
class BuiltAuthArtifact:
    artifact: Artifact
    signed: object
    locator: ManifestLocator
    key_registry: MemoryKeyRegistry
    key_id: str


def small_profile():
    return default_hdc_profile(profile_id="HV-PED-IMG-1-D1024-SPARSE-step9", dimension=1024, num_bands=8, bits_per_band=12, value_quantization_levels=16)


def build_signed_image(model_id="step9-model", *, color=(90, 110, 180)) -> BuiltAuthArtifact:
    artifact = Artifact.from_bytes(make_jpeg(color=color), media_type="image/jpeg")
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    binding = build_artifact_binding(artifact, wm_alg_id="test-watermark")
    core = ManifestCore(version=1, artifact=binding, claims=[GenerationClaim(model_id=model_id)], created_at=FIXED_TIME)
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.SHORT64_HV, hdc_profile_id=small_profile().profile_id)
    return BuiltAuthArtifact(artifact, signed, locator, MemoryKeyRegistry.from_public_keys([key.public]), str(key.kid))


def hkey(label: bytes) -> Hash256:
    return Hash256(hash_framed("test-step9-key", label))


def test_sparse_merkle_map_inclusion_noninclusion_and_tamper_detection():
    smt = SparseMerkleMap()
    key_a = hkey(b"a")
    key_b = hkey(b"b")
    missing = hkey(b"missing")
    smt.set(key_a, b"candidate-set-A")
    smt.set(key_b, b"candidate-set-B")
    root = smt.root_hash()

    opening_a = smt.open(key_a)
    assert opening_a.verify()
    assert opening_a.proof.verify(root, b"candidate-set-A")
    assert not opening_a.proof.verify(root, b"tampered")

    missing_opening = smt.open(missing)
    assert missing_opening.value is None
    assert missing_opening.verify()
    assert missing_opening.proof.verify(root, None)

    smt.set(key_a, b"candidate-set-A2")
    assert smt.root_hash() != root


def test_route_candidate_set_canonical_round_trip():
    built = build_signed_image()
    index = AuthenticatedShort64HVIndex(profile=small_profile())
    ref = index.add_manifest(built.signed, artifact=built.artifact, include_document_bytes=True)
    route_key = next(iter(index._by_route_key))  # internal use is fine in a white-box reference test
    candidate_set = RouteCandidateSet(route_key=route_key, references=[ref])

    primitive = canonical_cbor_loads(candidate_set.canonical_bytes())
    parsed = route_candidate_set_from_primitive(primitive)

    assert parsed.route_key == candidate_set.route_key
    assert parsed.references[0].short_id == ref.short_id
    assert parsed.canonical_bytes() == candidate_set.canonical_bytes()


def test_authenticated_short64_hv_index_opens_route_key_with_valid_proof():
    built = build_signed_image()
    profile = small_profile()
    index = AuthenticatedShort64HVIndex(profile=profile)
    index.add_manifest(built.signed, artifact=built.artifact, include_document_bytes=True)

    encoder = SparseTernaryHDCEncoder(profile=profile)
    encoding = encoder.encode_artifact(built.artifact)
    token_set = index.profile and __import__("oprow.hdc.routing", fromlist=["derive_route_tokens"]).derive_route_tokens(
        short_id=built.locator.value,
        encoding=encoding,
        profile=profile,
    )
    opening = index.open_route_key(token_set.tokens[0].route_key)

    assert opening.exists
    assert opening.verify()
    assert opening.root_record.root_hash == index.root_record().root_hash
    assert opening.references[0].short_id == built.locator.value


def test_authenticated_short64_hv_resolver_returns_candidates_only_after_proof_verification():
    built = build_signed_image()
    profile = small_profile()
    locator = ManifestLocator.from_signed_manifest(built.signed, mode=PointerMode.SHORT64_HV, hdc_profile_id=profile.profile_id)
    index = AuthenticatedShort64HVIndex(profile=profile)
    index.add_manifest(built.signed, artifact=built.artifact, include_document_bytes=True)
    root = index.root_record().root_hash

    result = AuthenticatedShort64HVRouteResolver(index, expected_root=root).resolve(ResolutionRequest(locator=locator, artifact=built.artifact))

    assert result.status == ResolutionStatus.FOUND
    assert len(result.candidates) == 1
    assert any(ev.event == "authenticated_route_lookup" for ev in result.diagnostics)


def test_authenticated_short64_hv_wrong_expected_root_fails_as_index_proof_failure():
    built = build_signed_image()
    profile = small_profile()
    locator = ManifestLocator.from_signed_manifest(built.signed, mode=PointerMode.SHORT64_HV, hdc_profile_id=profile.profile_id)
    index = AuthenticatedShort64HVIndex(profile=profile)
    index.add_manifest(built.signed, artifact=built.artifact, include_document_bytes=True)
    wrong_root = Hash256(hash_framed("test-step9-wrong-root", b"wrong"))

    result = AuthenticatedShort64HVRouteResolver(index, expected_root=wrong_root).resolve(ResolutionRequest(locator=locator, artifact=built.artifact))

    assert result.status == ResolutionStatus.ERROR
    assert any(ev.event == "index_proof_failed" for ev in result.diagnostics)


def test_step9_verifier_accepts_authenticated_short64_hv_after_signature_essence_and_trust():
    built = build_signed_image()
    profile = small_profile()
    locator = ManifestLocator.from_signed_manifest(built.signed, mode=PointerMode.SHORT64_HV, hdc_profile_id=profile.profile_id)
    index = AuthenticatedShort64HVIndex(profile=profile)
    index.add_manifest(built.signed, artifact=built.artifact, include_document_bytes=True)

    result = verify_artifact_with_locator(
        built.artifact,
        locator,
        resolver=AuthenticatedShort64HVRouteResolver(index, expected_root=index.root_record().root_hash),
        key_resolver=built.key_registry,
        trust_policy=TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}),
    )

    assert result.status == VerificationStatus.VERIFIED
    assert result.verified


def test_step9_verifier_reports_index_proof_failure_for_wrong_root():
    built = build_signed_image()
    profile = small_profile()
    locator = ManifestLocator.from_signed_manifest(built.signed, mode=PointerMode.SHORT64_HV, hdc_profile_id=profile.profile_id)
    index = AuthenticatedShort64HVIndex(profile=profile)
    index.add_manifest(built.signed, artifact=built.artifact, include_document_bytes=True)
    wrong_root = Hash256(hash_framed("test-step9-wrong-root", b"wrong"))

    result = verify_artifact_with_locator(
        built.artifact,
        locator,
        resolver=AuthenticatedShort64HVRouteResolver(index, expected_root=wrong_root),
        key_resolver=built.key_registry,
        trust_policy=TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}),
    )

    assert result.status == VerificationStatus.INDEX_PROOF_FAILED
    assert not result.verified
