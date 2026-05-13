from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO

from PIL import Image

from oprow import (
    Artifact,
    CASResolver,
    GenerationClaim,
    ManifestCore,
    ManifestLocator,
    MemoryCAS,
    MemoryKeyRegistry,
    MemoryShort64Index,
    NamespaceId,
    OProWSigner,
    PointerMode,
    ResolutionRequest,
    ResolutionStatus,
    Short64IndexReference,
    Short64IndexResolver,
    TrustPolicyStub,
    VerificationStatus,
    build_artifact_binding,
    create_signed_manifest,
    generate_ed25519_keypair,
    make_namespaced_short_id,
    verify_artifact_with_locator,
)
from oprow.core.enums import SignatureRole
from oprow.short64 import FileShort64Index

FIXED_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_jpeg(color=(90, 110, 180), stripe=(240, 230, 60)) -> bytes:
    img = Image.new("RGB", (96, 96), color=color)
    for x in range(10, 86):
        for y in range(40, 52):
            img.putpixel((x, y), stripe)
    buf = BytesIO(); img.save(buf, format="JPEG", quality=92)
    return buf.getvalue()


@dataclass
class BuiltShort64Artifact:
    artifact: Artifact
    signed: object
    locator: ManifestLocator
    key_registry: MemoryKeyRegistry
    key_id: str


def build_signed_image(model_id="step7-model", *, color=(90, 110, 180)) -> BuiltShort64Artifact:
    artifact = Artifact.from_bytes(make_jpeg(color=color), media_type="image/jpeg")
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    binding = build_artifact_binding(artifact, wm_alg_id="test-watermark")
    core = ManifestCore(version=1, artifact=binding, claims=[GenerationClaim(model_id=model_id)], created_at=FIXED_TIME)
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.SHORT64)
    return BuiltShort64Artifact(artifact, signed, locator, MemoryKeyRegistry.from_public_keys([key.public]), str(key.kid))


def test_memory_short64_index_resolves_embedded_manifest_bytes():
    built = build_signed_image()
    index = MemoryShort64Index()
    ref = index.add_manifest(built.signed, include_document_bytes=True)

    assert ref.short_id == built.locator.value

    result = Short64IndexResolver(index).resolve(ResolutionRequest(locator=built.locator, artifact=built.artifact))

    assert result.status == ResolutionStatus.FOUND
    assert len(result.candidates) == 1
    assert result.candidates[0].manifest.short_id_hash_truncated() == built.locator.value


def test_short64_resolver_can_fetch_indirect_manifest_from_backing_cas():
    built = build_signed_image()
    cas = MemoryCAS(); cas.put_manifest(built.signed)
    index = MemoryShort64Index(); index.add_manifest(built.signed, include_document_bytes=False)

    resolver = Short64IndexResolver(index, backing_resolver=CASResolver([cas]))
    result = resolver.resolve(ResolutionRequest(locator=built.locator, artifact=built.artifact))

    assert result.status == ResolutionStatus.FOUND
    assert len(result.candidates) == 1
    assert result.candidates[0].manifest.manifest_key() == built.signed.manifest_key()


def test_step7_verifier_accepts_short64_after_signature_essence_and_trust():
    built = build_signed_image()
    index = MemoryShort64Index(); index.add_manifest(built.signed, include_document_bytes=True)

    result = verify_artifact_with_locator(
        built.artifact,
        built.locator,
        resolver=Short64IndexResolver(index),
        key_resolver=built.key_registry,
        trust_policy=TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}),
    )

    assert result.status == VerificationStatus.VERIFIED
    assert result.verified
    assert result.verified_manifests[0].short_id_hash_truncated() == built.locator.value


def test_malicious_short64_index_mapping_does_not_survive_self_consistency():
    built_a = build_signed_image("a", color=(90, 110, 180))
    built_b = build_signed_image("b", color=(40, 160, 100))
    index = MemoryShort64Index()

    # Malicious mapping: B's manifest bytes under A's short ID.  The resolver
    # recomputes Trunc64(H256(B)) and rejects it before final verification.
    index.add_reference(
        Short64IndexReference(
            short_id=built_a.locator.value,
            manifest_key=built_b.signed.manifest_key(),
            document_bytes=built_b.signed.canonical_bytes(),
            metadata={"malicious_test": True},
        )
    )

    result = Short64IndexResolver(index).resolve(ResolutionRequest(locator=built_a.locator, artifact=built_a.artifact))

    assert result.status == ResolutionStatus.NOT_FOUND
    assert not result.candidates


def test_file_short64_index_snapshot_round_trips(tmp_path):
    built = build_signed_image()
    path = tmp_path / "short64-index.cbor"

    file_index = FileShort64Index(path)
    file_index.add_manifest(built.signed, include_document_bytes=True)

    reloaded = FileShort64Index(path)
    lookup = reloaded.lookup(built.locator.value)

    assert lookup.found
    assert lookup.complete
    assert lookup.references[0].short_id == built.locator.value
    assert lookup.references[0].manifest_key == built.signed.manifest_key()


def test_namespaced_short_id_helper_is_prefix_preserving():
    ns = NamespaceId.from_hex("a1b2")
    sid = make_namespaced_short_id(ns, 7)

    assert sid.value.startswith(ns.value)
    assert len(sid.value) == 8
