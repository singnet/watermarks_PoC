"""Adapter between OProW signed manifests and C2PA-style manifests.

This module is the center of Step 6. It answers a strategic design question:

    How can OProW be framed as a C2PA Durable Content Credentials profile
    without making OProW's core verifier depend on the C2PA packaging stack?

The answer implemented here is an adapter boundary:

* OProW keeps its own canonical ``SignedManifest`` and verification rules.
* A C2PA manifest receives standard-looking assertions, especially
  ``c2pa.soft-binding``, plus OProW-specific extension assertions.
* The exact OProW signed manifest bytes are preserved in a custom assertion so
  round-tripping and OProW verification remain lossless.
* A production bridge can later replace these C2PA-like dataclasses with calls
  to an official C2PA SDK while keeping this module's high-level API.

Important non-goal
==================

This file does not produce a normative C2PA JUMBF/COSE Manifest Store. It is a
first-draft architecture implementation for another coding agent to extend. The
comments intentionally spell out the mapping choices and where the official C2PA
SDK should take over.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from oprow.core.canonical import to_canonical_primitive
from oprow.core.enums import PointerMode, TrustEvidenceType
from oprow.core.errors import ValidationError
from oprow.core.hashes import h256
from oprow.core.models import Claim, ManifestEnvelope, ManifestLocator, SignedManifest, TrustEvidence
from oprow.manifest.codec import signed_manifest_from_bytes, signed_manifest_to_bytes

from .models import (
    C2PA_ACTIONS_LABEL,
    C2PA_SOFT_BINDING_LABEL,
    C2PAAdapterResult,
    C2PAAssertion,
    C2PAClaim,
    C2PAManifest,
    C2PAManifestStore,
    C2PAMappingNote,
    OPROW_ESSENCE_ASSERTION_LABEL,
    OPROW_LOCATOR_ASSERTION_LABEL,
    OPROW_MANIFEST_ASSERTION_LABEL,
    OPROW_SIGNATURE_SUMMARY_ASSERTION_LABEL,
    OPROW_TRUST_EVIDENCE_ASSERTION_LABEL,
)
from .soft_binding import SoftBindingOptions, extract_oprow_locator_from_soft_binding, make_oprow_soft_binding_assertion


@dataclass(frozen=True)
class C2PAAdapterOptions:
    """Configuration for OProW -> C2PA mapping.

    ``claim_generator`` identifies the software component generating the C2PA
    claim. In a real C2PA manifest this would likely be more structured and
    backed by a signing credential. Here it is a deterministic string so tests
    and examples are stable.

    ``include_oprow_manifest_bytes`` defaults to True because it is the cleanest
    way to make this skeleton lossless: consumers that understand OProW can pull
    the bytes out and run the normal OProW verifier. Consumers that do not
    understand OProW can still inspect standard and semi-standard assertions.

    ``include_trust_evidence`` controls whether envelope-level evidence such as
    future ASI:chain receipts or transparency proofs are exported as a custom
    C2PA assertion. That evidence stays outside OProW's addressed manifest in
    order to avoid self-reference.
    """

    claim_generator: str = "oprow-python-reference/step6-c2pa-adapter"
    title: str = "OProW provenance manifest"
    include_oprow_manifest_bytes: bool = True
    include_signature_summary: bool = True
    include_trust_evidence: bool = True
    include_actions_assertion: bool = True
    include_soft_binding: bool = True
    c2pa_manifest_id_prefix: str = "urn:oprow:c2pa-manifest:"
    soft_binding_options: SoftBindingOptions = field(default_factory=SoftBindingOptions)


def _drop_absent(m: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in m.items() if v is not None and v != [] and v != {}}


def c2pa_manifest_id_for_signed_manifest(manifest: SignedManifest, prefix: str = "urn:oprow:c2pa-manifest:") -> str:
    """Derive a deterministic adapter manifest ID from OProW SignedManifest bytes."""
    return prefix + manifest.manifest_hash().to_hex()


def c2pa_instance_id_for_signed_manifest(manifest: SignedManifest) -> str:
    """Derive a deterministic C2PA-ish instance ID from OProW SignedManifest bytes."""
    return "urn:oprow:asset-instance:" + h256(b"oprow-c2pa-instance\x00" + manifest.canonical_bytes()).hex()


def make_oprow_manifest_assertion(manifest: SignedManifest) -> C2PAAssertion:
    """Embed exact OProW SignedManifest bytes as a custom C2PA assertion.

    This is the lossless bridge. A C2PA-only tool may ignore this assertion; an
    OProW-aware verifier can recover the exact signed/addressed object and then
    run OProW verification. Storing the bytes in an assertion is also safer than
    trying to map every OProW feature into first-class C2PA structures too early.
    """
    payload = signed_manifest_to_bytes(manifest)
    return C2PAAssertion(
        label=OPROW_MANIFEST_ASSERTION_LABEL,
        kind="cbor",
        data={
            "profile": "oprow.signed-manifest.v1",
            "canonical_signed_manifest": payload,
            "manifest_hash_sha256": manifest.manifest_hash(),
            "manifest_key_h160": manifest.manifest_key(),
            "manifest_short_id_trunc64": manifest.short_id_hash_truncated(),
        },
    )


def make_locator_assertion(locator: ManifestLocator) -> C2PAAssertion:
    """Expose the OProW locator as a custom assertion.

    The standard ``c2pa.soft-binding`` assertion already carries an OProW locator
    block. This custom assertion is redundant by design: it gives C2PA-aware
    debugging tools an obvious place to find the pointer mode and derivation
    profile without understanding the soft-binding algorithm-specific bytes.
    """
    return C2PAAssertion(
        label=OPROW_LOCATOR_ASSERTION_LABEL,
        data={
            "mode": locator.mode.value,
            "value": locator.value,
            "namespace_id": locator.namespace_id,
            "hdc_profile_id": locator.hdc_profile_id,
            "derivation_profile": locator.derivation_profile,
        },
    )


def make_essence_assertion(manifest: SignedManifest) -> C2PAAssertion:
    """Expose OProW's perceptual essence commitment as a custom assertion.

    C2PA has hard-binding hash assertions for exact content structures. OProW's
    primary binding is a hash of a registered Perceptual Essence Descriptor
    (PED), such as PED-IMG-1, chosen to survive common lossy distribution. Until
    a first-class C2PA assertion/profile is registered for this, we preserve it
    as an OProW namespaced assertion.
    """
    artifact = manifest.core.artifact
    return C2PAAssertion(
        label=OPROW_ESSENCE_ASSERTION_LABEL,
        data=_drop_absent({
            "media_type": artifact.media_type,
            "essence_alg_id": artifact.essence_alg_id,
            "essence_hash": artifact.essence_hash,
            "hash_alg": artifact.hash_alg.value if hasattr(artifact.hash_alg, "value") else str(artifact.hash_alg),
            "strict_byte_hash": artifact.strict_byte_hash,
            "strict_decode_hash": artifact.strict_decode_hash,
            "region_commitments": artifact.region_commitments,
        }),
    )


def _claim_to_action(claim: Claim, index: int) -> dict[str, Any]:
    """Map an OProW claim to a draft C2PA actions entry.

    This is intentionally conservative. We preserve the original OProW claim
    body in namespaced parameters and choose a broad C2PA-style action label. A
    production bridge should replace these placeholders with the current C2PA
    actions vocabulary and any richer action/ingredient structures.
    """
    typ = claim.type
    if typ == "capture":
        action = "c2pa.created"
    elif typ == "generation":
        action = "c2pa.created"
    elif typ == "edit":
        action = "c2pa.edited"
    elif typ == "notary":
        action = "org.oprow.notarized"
    else:
        action = "org.oprow.claim"

    return _drop_absent({
        "action": action,
        "softwareAgent": claim.body.get("tool_id") or claim.body.get("model_id") or "OProW",
        "parameters": {
            "org.oprow.claimIndex": index,
            "org.oprow.claimType": typ,
            "org.oprow.claimBody": dict(claim.body),
        },
    })


def make_actions_assertion(claims: Iterable[Claim]) -> C2PAAssertion:
    """Build a draft ``c2pa.actions`` assertion from OProW claims."""
    actions = [_claim_to_action(claim, i) for i, claim in enumerate(claims)]
    return C2PAAssertion(label=C2PA_ACTIONS_LABEL, data={"actions": actions})


def make_signature_summary_assertion(manifest: SignedManifest) -> C2PAAssertion:
    """Summarize OProW signatures without pretending they are C2PA signatures."""
    records = []
    for sig in manifest.signatures:
        records.append(_drop_absent({
            "kid": str(sig.kid),
            "alg": sig.alg,
            "role": sig.role.value if hasattr(sig.role, "value") else str(sig.role),
            "signed_at": sig.signed_at,
            "signature_len": len(sig.signature),
            "certificate_chain_len": len(sig.certificate_chain),
            "metadata": sig.metadata,
        }))
    return C2PAAssertion(
        label=OPROW_SIGNATURE_SUMMARY_ASSERTION_LABEL,
        data={
            "warning": "These are OProW manifest signatures, not a C2PA COSE claim signature.",
            "records": records,
        },
    )


def make_trust_evidence_assertion(evidence: list[TrustEvidence]) -> C2PAAssertion | None:
    """Export envelope-level trust evidence as a custom C2PA assertion.

    Trust evidence remains outside the OProW SignedManifest so that the manifest
    locator is stable. This function preserves that evidence in C2PA space for
    diagnostics and future verifier extensions, but it is not part of the C2PA
    claim signature in this skeleton.
    """
    if not evidence:
        return None
    rows = []
    for item in evidence:
        typ = item.evidence_type.value if isinstance(item.evidence_type, TrustEvidenceType) else str(item.evidence_type)
        rows.append({"type": typ, "body": dict(item.body)})
    return C2PAAssertion(label=OPROW_TRUST_EVIDENCE_ASSERTION_LABEL, data={"evidence": rows})


class C2PAAdapter:
    """High-level OProW/C2PA bridge used by Step 6 examples and tests."""

    def __init__(self, options: C2PAAdapterOptions | None = None):
        self.options = options or C2PAAdapterOptions()

    def to_c2pa_manifest(self, source: SignedManifest | ManifestEnvelope) -> C2PAAdapterResult:
        """Convert an OProW SignedManifest/Envelope to a C2PA-like Manifest.

        Algorithm embodied
        ------------------
        1. Normalize ``source`` into ``SignedManifest`` plus ``ManifestLocator``.
        2. Add an exact OProW manifest assertion for lossless recovery.
        3. Add a ``c2pa.soft-binding`` assertion carrying the OProW locator.
        4. Add C2PA-ish action and OProW essence/signature assertions.
        5. Build a minimal claim referencing all assertions.

        The result is not a normative C2PA wire object, but it captures the
        adapter contract that a future official-SDK bridge should implement.
        """
        if isinstance(source, ManifestEnvelope):
            manifest = source.manifest
            locator = source.locator
            trust_evidence = list(source.trust_evidence)
        elif isinstance(source, SignedManifest):
            manifest = source
            locator = ManifestLocator.from_signed_manifest(manifest, mode=PointerMode.FULL160)
            trust_evidence = []
        else:
            raise ValidationError("source must be SignedManifest or ManifestEnvelope")

        assertions: list[C2PAAssertion] = []
        notes: list[C2PAMappingNote] = []

        if self.options.include_oprow_manifest_bytes:
            assertions.append(make_oprow_manifest_assertion(manifest))
            notes.append(C2PAMappingNote("oprow_bytes_embedded", "Exact OProW SignedManifest bytes embedded in custom assertion."))
        else:
            notes.append(C2PAMappingNote("oprow_bytes_omitted", "Exact OProW SignedManifest bytes were not embedded; reverse mapping may be lossy.", severity="warning"))

        assertions.append(make_essence_assertion(manifest))
        assertions.append(make_locator_assertion(locator))

        if self.options.include_soft_binding:
            assertions.append(make_oprow_soft_binding_assertion(locator, options=self.options.soft_binding_options))
            notes.append(C2PAMappingNote("soft_binding_added", "Added c2pa.soft-binding assertion for OProW Durable Content Credentials lookup."))

        if self.options.include_actions_assertion:
            assertions.append(make_actions_assertion(manifest.core.claims))
            notes.append(C2PAMappingNote("actions_approximate", "Mapped OProW claims to draft C2PA actions; production bridge should normalize vocabulary.", severity="warning"))

        if self.options.include_signature_summary:
            assertions.append(make_signature_summary_assertion(manifest))
            notes.append(C2PAMappingNote("signature_summary_added", "OProW signature summary added; not a C2PA COSE signature."))

        if self.options.include_trust_evidence:
            trust_assertion = make_trust_evidence_assertion(trust_evidence)
            if trust_assertion is not None:
                assertions.append(trust_assertion)
                notes.append(C2PAMappingNote("trust_evidence_preserved", "Envelope-level trust evidence preserved as custom C2PA assertion."))

        assertion_refs = [assertion.assertion_ref(i) for i, assertion in enumerate(assertions)]
        claim = C2PAClaim(
            claim_generator=self.options.claim_generator,
            format=manifest.core.artifact.media_type,
            instance_id=c2pa_instance_id_for_signed_manifest(manifest),
            assertion_refs=assertion_refs,
            title=self.options.title,
            metadata={
                "org.oprow.profile": "oprow-c2pa-durable-content-credentials-profile-v1",
                "org.oprow.mapping": "draft-step6-skeleton",
            },
        )
        c2pa_manifest = C2PAManifest(
            manifest_id=c2pa_manifest_id_for_signed_manifest(manifest, self.options.c2pa_manifest_id_prefix),
            claim=claim,
            assertions=assertions,
            active=True,
            signature_info={
                "status": "not_c2pa_signed_by_this_skeleton",
                "note": "Use an official C2PA SDK to package/sign this manifest for production.",
            },
            metadata={
                "org.oprow.manifestKey": manifest.manifest_key().to_hex(),
                "org.oprow.shortId": manifest.short_id_hash_truncated().to_hex(),
                "org.oprow.pointerMode": locator.mode.value,
            },
        )
        return C2PAAdapterResult(manifest=c2pa_manifest, mapping_notes=notes)

    def to_c2pa_manifest_store(self, source: SignedManifest | ManifestEnvelope) -> C2PAManifestStore:
        """Wrap the mapped manifest in a minimal manifest store."""
        result = self.to_c2pa_manifest(source)
        return C2PAManifestStore(
            active_manifest_id=result.manifest.manifest_id,
            manifests=[result.manifest],
            metadata={
                "org.oprow.mappingNotes": [note.to_canonical() for note in result.mapping_notes],
                "org.oprow.storeProfile": "oprow-c2pa-store-skeleton-v1",
            },
        )

    def from_c2pa_manifest(self, manifest: C2PAManifest) -> SignedManifest:
        """Recover the exact OProW SignedManifest from a mapped C2PA manifest.

        This reverse path requires the custom ``org.oprow.manifest.v1`` assertion
        created by ``make_oprow_manifest_assertion``. A generic C2PA manifest
        from another implementation may not contain this assertion; in that case
        a later production adapter would need to map C2PA assertions into an
        OProW ManifestCore and obtain or create signatures separately.
        """
        matches = manifest.assertion_by_label(OPROW_MANIFEST_ASSERTION_LABEL)
        if not matches:
            raise ValidationError("C2PA manifest does not contain an OProW signed-manifest assertion")
        payload = matches[0].data.get("canonical_signed_manifest")
        if not isinstance(payload, bytes):
            raise ValidationError("OProW signed-manifest assertion payload is not bytes")
        return signed_manifest_from_bytes(payload)

    def locator_from_c2pa_manifest(self, manifest: C2PAManifest) -> ManifestLocator:
        """Recover an OProW locator from the first OProW soft-binding assertion."""
        matches = manifest.assertion_by_label(C2PA_SOFT_BINDING_LABEL)
        if not matches:
            raise ValidationError("C2PA manifest does not contain a c2pa.soft-binding assertion")
        return extract_oprow_locator_from_soft_binding(matches[0])


def c2pa_manifest_to_debug_dict(manifest: C2PAManifest) -> dict[str, Any]:
    """Return the canonical primitive form for JSON/debug display.

    This helper avoids promising that the output is official C2PA crJSON. It is
    simply the adapter object's canonical primitive map. The official C2PA SDK
    bridge should own any final JUMBF/crJSON emission.
    """
    return to_canonical_primitive(manifest)


def parse_embedded_oprow_manifest_assertion_bytes(assertion: C2PAAssertion) -> SignedManifest:
    """Parse a custom OProW manifest assertion into a SignedManifest."""
    if assertion.label != OPROW_MANIFEST_ASSERTION_LABEL:
        raise ValidationError("assertion is not an OProW manifest assertion")
    payload = assertion.data.get("canonical_signed_manifest")
    if not isinstance(payload, bytes):
        raise ValidationError("OProW manifest assertion does not contain bytes")
    return signed_manifest_from_bytes(payload)
