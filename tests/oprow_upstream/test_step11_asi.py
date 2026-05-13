from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from io import BytesIO

from PIL import Image

from oprow import (
    ASIChainTrustBackend,
    AnchorObjectType,
    AnchorRecord,
    Artifact,
    AuthenticatedShort64HVIndex,
    GenerationClaim,
    Hash256,
    KeyId,
    ManifestCore,
    ManifestLocator,
    MemoryKeyRegistry,
    MemoryTrustBackend,
    NamespaceId,
    NamespaceRecord,
    OProWSigner,
    PointerMode,
    Short64HVPrivacyPlanner,
    TrustBundleDescriptor,
    TrustPolicyStub,
    VerificationStatus,
    build_artifact_binding,
    create_signed_manifest,
    default_hdc_profile,
    generate_ed25519_keypair,
    index_root_to_anchor_record,
    render_anchor_source_term,
    verify_artifact_with_locator,
)
from oprow.core.enums import SignatureRole, TrustEvidenceType
from oprow.core.hashes import hash_framed
from oprow.privacy import add_manifest_for_privacy_policies, k_anonymous_bucket_policy
from oprow.resolution import PrivacyPreservingAuthenticatedShort64HVResolver
from oprow.trust import TransparencyRootRecord, domain_hash_for_test_anchor

FIXED_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_jpeg(color=(80, 120, 170), stripe=(250, 220, 70)) -> bytes:
    img = Image.new("RGB", (96, 96), color=color)
    for x in range(14, 82):
        for y in range(38, 54):
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
    return default_hdc_profile(profile_id="HV-PED-IMG-1-D1024-SPARSE-step11", dimension=1024, num_bands=8, bits_per_band=12, value_quantization_levels=16)


def build_signed_image(model_id="step11-model") -> BuiltArtifact:
    artifact = Artifact.from_bytes(make_jpeg(), media_type="image/jpeg")
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    binding = build_artifact_binding(artifact, wm_alg_id="test-watermark")
    core = ManifestCore(version=1, artifact=binding, claims=[GenerationClaim(model_id=model_id)], created_at=FIXED_TIME)
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    profile = small_profile()
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.SHORT64_HV, hdc_profile_id=profile.profile_id)
    return BuiltArtifact(artifact, signed, locator, MemoryKeyRegistry.from_public_keys([key.public]), str(key.kid))


def test_memory_trust_backend_publishes_and_verifies_generic_anchor():
    backend = MemoryTrustBackend()
    root = domain_hash_for_test_anchor("generic", b"hello")
    anchor = AnchorRecord.generic(root, subject_id="unit-test", body={"purpose": "generic anchor"})

    receipt = backend.publish_anchor(anchor)
    check = backend.verify_anchor(anchor, receipt)

    assert check.ok
    assert check.reason == "anchor_verified"
    assert receipt.anchored_object_hash == root
    assert receipt.anchored_record_hash == anchor.record_hash()

    tampered = AnchorRecord.generic(Hash256(hash_framed("step11-tamper", b"x")), subject_id="unit-test")
    assert not backend.verify_anchor(tampered, receipt).ok


def test_index_root_can_be_anchored_without_exposing_route_keys_or_hdc_vectors():
    built = build_signed_image()
    profile = small_profile()
    index = AuthenticatedShort64HVIndex(profile=profile)
    policy = k_anonymous_bucket_policy(min_anonymity_set=1, max_candidate_bucket=64)
    add_manifest_for_privacy_policies(index, built.signed, artifact=built.artifact, policies=[policy], include_document_bytes=True)
    root_record = index.root_record()

    anchor = index_root_to_anchor_record(root_record)
    assert anchor.object_type_value == AnchorObjectType.INDEX_ROOT.value
    assert "root_hash" in anchor.body
    assert "hypervector" not in str(anchor.body).lower()
    assert "raw_ped" not in str(anchor.body).lower()

    backend = MemoryTrustBackend()
    receipt = backend.publish_index_root(root_record)
    check = backend.verify_index_root(root_record, receipt)

    assert check.ok
    assert receipt.anchored_object_hash == root_record.record_hash()


def test_asi_chain_mock_backend_publishes_anchor_receipt_and_verifies_it():
    transparency_root = TransparencyRootRecord(
        log_id="oprow-kt-test-log",
        tree_size=3,
        root_hash=domain_hash_for_test_anchor("kt-root", b"r"),
        period_start=FIXED_TIME,
        period_end=FIXED_TIME,
    )
    anchor = transparency_root.to_anchor_record()
    backend = ASIChainTrustBackend.mock_devnet()

    receipt = backend.publish_anchor(anchor)
    check = backend.verify_anchor(anchor, receipt)

    assert receipt.backend_id == "asi-chain"
    assert receipt.network == "mock-devnet"
    assert check.ok
    assert "asi_chain_receipt" in receipt.metadata
    assert anchor.record_hash().to_hex() in receipt.metadata["rholang_term"]
    assert anchor.object_hash.to_hex() in receipt.metadata["rholang_term"]

    evidence = backend.receipt_to_trust_evidence(receipt)
    assert evidence.evidence_type == TrustEvidenceType.ASI_CHAIN_RECEIPT


def test_rendered_rholang_term_contains_only_anchor_commitments_not_media_bytes():
    object_hash = domain_hash_for_test_anchor("render", b"object")
    anchor = AnchorRecord.generic(object_hash, subject_id="render-test", body={"index_id": "idx", "route_key_count": 8})
    from oprow import ASIAnchorPayload

    payload = ASIAnchorPayload.from_anchor_record(anchor)
    term = render_anchor_source_term(payload)

    assert anchor.record_hash().to_hex() in term
    assert object_hash.to_hex() in term
    assert "route_key_count" in term
    assert "raw_hypervector" not in term
    assert "raw_ped" not in term


def test_namespace_and_trust_bundle_records_are_published_and_resolved():
    backend = ASIChainTrustBackend.mock_devnet()
    ns = NamespaceRecord(
        namespace_id=NamespaceId(b"AI"),
        controller_kid=KeyId("did:example:asi#controller"),
        display_name="ASI generated media namespace",
    )
    bundle = TrustBundleDescriptor(
        bundle_id="asi-ai-tools",
        bundle_version="2026.01",
        bundle_hash=domain_hash_for_test_anchor("bundle", b"asi"),
        issuer_kid=KeyId("did:example:asi#bundle-issuer"),
        bundle_uri="ipfs://example-bundle-cid",
    )

    ns_receipt = backend.publish_namespace_record(ns)
    bundle_receipt = backend.publish_trust_bundle(bundle)

    assert backend.verify_anchor(ns.to_anchor_record(), ns_receipt).ok
    assert backend.verify_anchor(bundle.to_anchor_record(), bundle_receipt).ok
    assert backend.resolve_namespace(NamespaceId(b"AI")) == ns
    assert backend.resolve_trust_bundle("asi-ai-tools", "2026.01") == bundle


def test_anchored_index_root_receipt_can_be_used_alongside_final_verification():
    built = build_signed_image()
    profile = small_profile()
    index = AuthenticatedShort64HVIndex(profile=profile)
    policy = k_anonymous_bucket_policy(min_anonymity_set=1, max_candidate_bucket=64)
    add_manifest_for_privacy_policies(index, built.signed, artifact=built.artifact, policies=[policy], include_document_bytes=True)

    backend = ASIChainTrustBackend.mock_devnet()
    receipt = backend.publish_index_root(index.root_record())
    assert backend.verify_index_root(index.root_record(), receipt).ok

    # The receipt is external accountability evidence.  The verifier still uses
    # the Step 5/9/10 media path: authenticated route lookup, manifest signature,
    # essence check, and local key policy.  Anchoring does not replace these.
    result = verify_artifact_with_locator(
        built.artifact,
        built.locator,
        resolver=PrivacyPreservingAuthenticatedShort64HVResolver(index, expected_root=index.root_record().root_hash, privacy_policy=policy),
        key_resolver=built.key_registry,
        trust_policy=TrustPolicyStub(trusted_key_ids={built.key_id}, accepted_roles={"tool"}),
    )

    assert result.status == VerificationStatus.VERIFIED
    assert result.verified
