from datetime import datetime, timezone

import pytest

from oprow import (
    ArtifactBinding,
    GenerationClaim,
    Hash256,
    KeyId,
    ManifestCore,
    ManifestEnvelope,
    ManifestKey,
    ManifestLocator,
    PointerMode,
    ShortId,
    SignatureRecord,
    SignedManifest,
    canonical_cbor_dumps,
)
from oprow.core.enums import SignatureRole
from oprow.core.errors import CanonicalizationError, IdentifierError, ValidationError


def make_signed_manifest() -> SignedManifest:
    binding = ArtifactBinding(
        media_type="image/jpeg",
        essence_alg_id="PED-IMG-1",
        essence_hash=Hash256.from_data(b"ped"),
        wm_alg_id="IMG-DCT-QIM-1",
    )
    core = ManifestCore(
        version=1,
        artifact=binding,
        claims=[GenerationClaim(model_id="model-x")],
        created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
    )
    sig = SignatureRecord(
        kid=KeyId("did:example:tool#k"),
        alg="TEST",
        signature=b"sig",
        role=SignatureRole.TOOL,
    )
    return SignedManifest(core=core, signatures=[sig])


def test_identifier_lengths_are_enforced():
    with pytest.raises(IdentifierError):
        ManifestKey(b"too short")
    with pytest.raises(IdentifierError):
        ShortId(b"1234567")


def test_canonical_cbor_is_dict_order_independent():
    assert canonical_cbor_dumps({"b": 2, "a": 1}) == canonical_cbor_dumps({"a": 1, "b": 2})


def test_canonicalization_rejects_floats():
    with pytest.raises(CanonicalizationError):
        canonical_cbor_dumps({"score": 0.5})


def test_manifest_locator_is_stable_and_not_self_referential():
    signed = make_signed_manifest()
    locator = ManifestLocator.from_signed_manifest(signed, mode=PointerMode.FULL160)
    assert locator.value == signed.manifest_key()
    envelope = ManifestEnvelope(manifest=signed, locator=locator)
    assert envelope.addressed_bytes() == signed.canonical_bytes()
    assert envelope.canonical_bytes() != signed.canonical_bytes()


def test_wrong_full160_locator_is_rejected():
    signed = make_signed_manifest()
    bad = ManifestLocator(mode=PointerMode.FULL160, value=ManifestKey(b"\x00" * 20))
    with pytest.raises(ValidationError):
        ManifestEnvelope(manifest=signed, locator=bad)


def test_short64_locator_type_validation():
    with pytest.raises(ValidationError):
        ManifestLocator(mode=PointerMode.SHORT64, value=ManifestKey(b"\x00" * 20))
