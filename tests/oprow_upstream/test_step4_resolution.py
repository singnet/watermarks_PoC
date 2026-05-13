from datetime import datetime, timezone

from oprow import (
    Artifact,
    ArtifactBinding,
    CASResolver,
    CandidateValidationStatus,
    CompositeResolver,
    EmbeddedManifestResolver,
    FileCAS,
    GenerationClaim,
    Hash256,
    LocalPathResolver,
    ManifestCore,
    ManifestLocator,
    MemoryCAS,
    OProWSigner,
    PointerMode,
    ResolutionRequest,
    ResolutionStatus,
    create_signed_manifest,
    generate_ed25519_keypair,
    signed_manifest_from_bytes,
)
from oprow.core.canonical import canonical_cbor_loads
from oprow.core.enums import SignatureRole


FIXED_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_signed_manifest(model_id: str = "step4-model"):
    binding = ArtifactBinding(
        media_type="image/jpeg",
        essence_alg_id="PED-IMG-1",
        essence_hash=Hash256.from_data(f"step4-test-ped:{model_id}".encode()),
        wm_alg_id="IMG-DCT-QIM-1",
    )
    core = ManifestCore(
        version=1,
        artifact=binding,
        claims=[GenerationClaim(model_id=model_id)],
        created_at=FIXED_TIME,
    )
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    return create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)


def test_canonical_cbor_loads_round_trips_signed_manifest():
    signed = make_signed_manifest()
    data = signed.canonical_bytes()
    primitive = canonical_cbor_loads(data)
    assert primitive["core"]["manifest_version"] == 1
    decoded = signed_manifest_from_bytes(data)
    assert decoded.canonical_bytes() == data
    assert decoded.manifest_key() == signed.manifest_key()


def test_memory_cas_resolver_finds_full160_manifest():
    signed = make_signed_manifest()
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.FULL160)
    cas = MemoryCAS()
    cas.put_manifest(signed)

    result = CASResolver([cas]).resolve(ResolutionRequest(locator=locator))

    assert result.status == ResolutionStatus.FOUND
    assert len(result.candidates) == 1
    assert result.candidates[0].validation_status == CandidateValidationStatus.LOCATOR_MATCH
    assert result.candidates[0].manifest.manifest_key() == signed.manifest_key()


def test_memory_cas_miss_for_wrong_full160_locator():
    signed_a = make_signed_manifest("a")
    signed_b = make_signed_manifest("b")
    locator_a = ManifestLocator.from_signed_manifest(signed_a, mode=PointerMode.FULL160)
    cas = MemoryCAS()
    cas.put_manifest(signed_b)
    result = CASResolver([cas]).resolve(ResolutionRequest(locator=locator_a))
    assert result.status == ResolutionStatus.NOT_FOUND
    assert not result.candidates


def test_embedded_resolver_reads_manifest_bytes_from_artifact_metadata():
    signed = make_signed_manifest()
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.FULL160)
    artifact = Artifact.from_bytes(b"fake image bytes", media_type="image/jpeg", metadata={"oprow_manifest_bytes": signed.canonical_bytes()})

    result = EmbeddedManifestResolver().resolve(ResolutionRequest(locator=locator, artifact=artifact))

    assert result.status == ResolutionStatus.FOUND
    assert result.candidates[0].source.startswith("artifact.metadata")


def test_file_cas_and_local_path_resolver(tmp_path):
    signed = make_signed_manifest()
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.FULL160)

    file_cas = FileCAS(tmp_path / "cas")
    file_cas.put_manifest(signed)
    cas_result = CASResolver([file_cas]).resolve(ResolutionRequest(locator=locator))
    assert cas_result.status == ResolutionStatus.FOUND

    local = LocalPathResolver(search_dirs=[tmp_path / "cas"])
    local_result = local.resolve(ResolutionRequest(locator=locator))
    assert local_result.status == ResolutionStatus.FOUND
    assert local_result.candidates[0].manifest.manifest_key() == signed.manifest_key()


def test_sidecar_resolution_next_to_artifact(tmp_path):
    signed = make_signed_manifest()
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.FULL160)
    artifact_path = tmp_path / "image.jpg"
    artifact_path.write_bytes(b"not actually an image")
    sidecar = tmp_path / "image.jpg.oprow"
    sidecar.write_bytes(signed.canonical_bytes())

    artifact = Artifact.from_path(artifact_path, media_type="image/jpeg")
    result = LocalPathResolver().resolve(ResolutionRequest(locator=locator, artifact=artifact))
    assert result.status == ResolutionStatus.FOUND
    assert "image.jpg.oprow" in result.candidates[0].source


def test_composite_resolver_prefers_embedded_before_cas():
    signed = make_signed_manifest()
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.FULL160)
    cas = MemoryCAS()
    cas.put_manifest(signed)
    artifact = Artifact.from_bytes(b"fake", media_type="image/jpeg", metadata={"oprow_manifest_bytes": signed.canonical_bytes()})

    composite = CompositeResolver([EmbeddedManifestResolver(), CASResolver([cas])], stop_on_first_found=True)
    result = composite.resolve(ResolutionRequest(locator=locator, artifact=artifact))

    assert result.status == ResolutionStatus.FOUND
    assert len(result.candidates) == 1
    assert result.candidates[0].source.startswith("artifact.metadata")
