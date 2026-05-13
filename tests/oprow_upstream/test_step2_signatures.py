from dataclasses import replace
from datetime import datetime, timezone

import pytest

from oprow import (
    ArtifactBinding,
    GenerationClaim,
    Hash256,
    ManifestCore,
    ManifestLocator,
    MemoryKeyRegistry,
    OProWSigner,
    PointerMode,
    SignedManifest,
    create_signed_manifest,
    generate_ed25519_keypair,
    generate_p256_keypair,
    verify_locator_self_consistency,
    verify_manifest_signatures,
)
from oprow.core.enums import SignatureRole
from oprow.core.errors import ValidationError

FIXED_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_core(model_id="model-x") -> ManifestCore:
    binding = ArtifactBinding(
        media_type="image/jpeg",
        essence_alg_id="PED-IMG-1",
        essence_hash=Hash256.from_data(b"ped"),
        wm_alg_id="IMG-DCT-QIM-1",
    )
    return ManifestCore(
        version=1,
        artifact=binding,
        claims=[GenerationClaim(model_id=model_id)],
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )


def test_ed25519_signature_verifies():
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    signed = create_signed_manifest(make_core(), [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    registry = MemoryKeyRegistry.from_public_keys([key.public])
    report = verify_manifest_signatures(signed, registry)
    assert report.has_valid_signature
    assert len(report.valid_checks) == 1
    assert report.valid_checks[0].reason == "valid"


def test_es256_signature_verifies():
    key = generate_p256_keypair(roles=[SignatureRole.CREATOR])
    signed = create_signed_manifest(make_core(), [OProWSigner(key, SignatureRole.CREATOR)], signed_at=FIXED_TIME)
    registry = MemoryKeyRegistry.from_public_keys([key.public])
    report = verify_manifest_signatures(signed, registry)
    assert report.has_valid_signature


def test_missing_key_is_reported():
    key = generate_ed25519_keypair()
    signed = create_signed_manifest(make_core(), [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    report = verify_manifest_signatures(signed, MemoryKeyRegistry())
    assert not report.has_valid_signature
    assert report.invalid_checks[0].reason == "missing_public_key"


def test_tampering_with_manifest_core_invalidates_signature():
    key = generate_ed25519_keypair()
    signed = create_signed_manifest(make_core("model-a"), [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    registry = MemoryKeyRegistry.from_public_keys([key.public])
    tampered = SignedManifest(core=make_core("model-b"), signatures=signed.signatures)
    report = verify_manifest_signatures(tampered, registry)
    assert not report.has_valid_signature
    assert report.invalid_checks[0].reason == "invalid_signature"


def test_tampering_with_protected_role_invalidates_signature():
    key = generate_ed25519_keypair()
    signed = create_signed_manifest(make_core(), [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    registry = MemoryKeyRegistry.from_public_keys([key.public])
    tampered_sig = replace(signed.signatures[0], role=SignatureRole.NOTARY)
    tampered = SignedManifest(core=signed.core, signatures=[tampered_sig])
    report = verify_manifest_signatures(tampered, registry)
    assert not report.has_valid_signature
    assert report.invalid_checks[0].reason == "invalid_signature"


def test_full160_locator_matches_signed_manifest_bytes():
    key = generate_ed25519_keypair()
    signed = create_signed_manifest(make_core(), [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.FULL160)
    assert verify_locator_self_consistency(signed, locator)


def test_short64_locator_matches_signed_manifest_bytes():
    key = generate_ed25519_keypair()
    signed = create_signed_manifest(make_core(), [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.SHORT64)
    assert verify_locator_self_consistency(signed, locator)


def test_signature_order_is_canonical_for_deterministic_signatures():
    key_a = generate_ed25519_keypair()
    key_b = generate_ed25519_keypair()
    core = make_core()
    signed_ab = create_signed_manifest(
        core,
        [OProWSigner(key_a, SignatureRole.TOOL), OProWSigner(key_b, SignatureRole.NOTARY)],
        signed_at=FIXED_TIME,
    )
    signed_ba = create_signed_manifest(
        core,
        [OProWSigner(key_b, SignatureRole.NOTARY), OProWSigner(key_a, SignatureRole.TOOL)],
        signed_at=FIXED_TIME,
    )
    assert signed_ab.canonical_bytes() == signed_ba.canonical_bytes()
    assert signed_ab.manifest_key() == signed_ba.manifest_key()


def test_require_any_valid_raises_when_all_invalid():
    key = generate_ed25519_keypair()
    signed = create_signed_manifest(make_core(), [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    report = verify_manifest_signatures(signed, MemoryKeyRegistry())
    with pytest.raises(ValidationError):
        report.require_any_valid()
