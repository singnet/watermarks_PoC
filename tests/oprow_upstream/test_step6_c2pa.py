from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO

from PIL import Image

from oprow import (
    Artifact,
    C2PAAdapter,
    C2PA_SOFT_BINDING_LABEL,
    GenerationClaim,
    ManifestCore,
    ManifestEnvelope,
    ManifestLocator,
    OPROW_ESSENCE_ASSERTION_LABEL,
    OPROW_LOCATOR_ASSERTION_LABEL,
    OPROW_MANIFEST_ASSERTION_LABEL,
    PointerMode,
    SoftBindingMatchRequest,
    TrustEvidence,
    build_artifact_binding,
    build_match_response_for_store,
    create_signed_manifest,
    extract_oprow_locator_from_soft_binding,
    generate_ed25519_keypair,
    make_oprow_soft_binding_assertion,
    c2pa_manifest_to_debug_dict,
    OProWSigner,
)
from oprow.core.enums import SignatureRole, TrustEvidenceType

FIXED_TIME = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def make_jpeg() -> bytes:
    img = Image.new("RGB", (96, 96), color=(72, 120, 200))
    for x in range(20, 76):
        for y in range(36, 56):
            img.putpixel((x, y), (235, 225, 20))
    buf = BytesIO()
    img.save(buf, format="JPEG", quality=92)
    return buf.getvalue()


def build_signed_manifest_and_envelope(pointer_mode=PointerMode.FULL160):
    artifact = Artifact.from_bytes(make_jpeg(), media_type="image/jpeg")
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    binding = build_artifact_binding(artifact, wm_alg_id="test-watermark-profile")
    core = ManifestCore(
        version=1,
        artifact=binding,
        claims=[GenerationClaim(model_id="step6-c2pa-model")],
        created_at=FIXED_TIME,
    )
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)], signed_at=FIXED_TIME)
    locator = ManifestLocator.from_signed_manifest(signed, mode=pointer_mode)
    envelope = ManifestEnvelope(
        manifest=signed,
        locator=locator,
        trust_evidence=[
            TrustEvidence(
                TrustEvidenceType.C2PA_EVIDENCE,
                {"note": "test evidence kept outside SignedManifest"},
            )
        ],
    )
    return signed, locator, envelope


def test_step6_soft_binding_round_trips_full160_locator():
    _signed, locator, _envelope = build_signed_manifest_and_envelope(PointerMode.FULL160)
    assertion = make_oprow_soft_binding_assertion(locator)

    assert assertion.label == C2PA_SOFT_BINDING_LABEL
    recovered = extract_oprow_locator_from_soft_binding(assertion)
    assert recovered.mode == locator.mode
    assert recovered.value == locator.value
    assert recovered.derivation_profile == locator.derivation_profile


def test_step6_adapter_exports_expected_assertions_and_round_trips_manifest():
    signed, locator, envelope = build_signed_manifest_and_envelope(PointerMode.FULL160)
    result = C2PAAdapter().to_c2pa_manifest(envelope)
    c2pa_manifest = result.manifest

    labels = {a.label for a in c2pa_manifest.assertions}
    assert OPROW_MANIFEST_ASSERTION_LABEL in labels
    assert OPROW_ESSENCE_ASSERTION_LABEL in labels
    assert OPROW_LOCATOR_ASSERTION_LABEL in labels
    assert C2PA_SOFT_BINDING_LABEL in labels

    recovered_signed = C2PAAdapter().from_c2pa_manifest(c2pa_manifest)
    assert recovered_signed.canonical_bytes() == signed.canonical_bytes()

    recovered_locator = C2PAAdapter().locator_from_c2pa_manifest(c2pa_manifest)
    assert recovered_locator.value == locator.value

    # The debug dict is canonical-primitives-only: safe for deterministic JSON
    # rendering by oprow.core.canonical.canonical_json_dumps.
    debug = c2pa_manifest_to_debug_dict(c2pa_manifest)
    assert debug["manifest_id"].startswith("urn:oprow:c2pa-manifest:")


def test_step6_adapter_can_export_short64_hv_locator_without_raw_hdc():
    signed, _locator, _envelope = build_signed_manifest_and_envelope(PointerMode.FULL160)
    hv_locator = ManifestLocator.from_signed_manifest(
        signed,
        mode=PointerMode.SHORT64_HV,
        hdc_profile_id="HV-PED-IMG-1-D8192",
    )
    envelope = ManifestEnvelope(manifest=signed, locator=hv_locator)
    c2pa_manifest = C2PAAdapter().to_c2pa_manifest(envelope).manifest

    recovered = C2PAAdapter().locator_from_c2pa_manifest(c2pa_manifest)
    assert recovered.mode == PointerMode.SHORT64_HV
    assert recovered.hdc_profile_id == "HV-PED-IMG-1-D8192"

    soft = c2pa_manifest.assertion_by_label(C2PA_SOFT_BINDING_LABEL)[0]
    body_text = repr(soft.data)
    assert "HV-PED-IMG-1-D8192" in body_text
    assert "hypervector" not in body_text.lower()
    assert "route_key" not in body_text.lower()


def test_step6_manifest_store_and_repository_response_shapes():
    _signed, _locator, envelope = build_signed_manifest_and_envelope(PointerMode.FULL160)
    store = C2PAAdapter().to_c2pa_manifest_store(envelope)
    active = store.active_manifest()
    soft = active.assertion_by_label(C2PA_SOFT_BINDING_LABEL)[0]

    request = SoftBindingMatchRequest.from_soft_binding_assertion(soft, return_manifest_store=True)
    assert request.alg == soft.data["alg"]
    assert request.return_manifest_store

    response = build_match_response_for_store(store, uri="https://repo.example/manifests/demo")
    assert response.matches[0].manifest_id == active.manifest_id
    assert response.matches[0].manifest_store_hash is not None
    assert response.manifest_stores[0].active_manifest().manifest_id == active.manifest_id
