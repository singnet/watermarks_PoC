"""OProW <-> C2PA soft-binding helpers.

C2PA Durable Content Credentials use *soft bindings* to rediscover a manifest
store after embedded metadata has been stripped. C2PA is intentionally agnostic
about the concrete soft-binding algorithm: a binding may be an invisible
watermark, a fingerprint, or another registered technology. OProW's watermark
pointer is a natural C2PA soft binding:

    watermark extracts OProW locator  ->  locator queries repository/index
    repository returns manifest/store ->  verifier validates content/signatures

This file implements the draft C2PA assertion shape for OProW locators. The
assertion is labeled ``c2pa.soft-binding`` and contains algorithm-specific block
values. For this Step 6 skeleton, the block value is canonical CBOR for the
``ManifestLocator`` primitive. This has three useful properties:

1. It is compact and deterministic.
2. It does not expose creator metadata, locations, prompts, or private claims.
3. It can represent FULL160, SHORT64, SHORT64-HV, and future rateless modes.

Security caveat
===============

A soft binding is a retrieval hint, not proof of provenance. The final verifier
must still require OProW locator self-consistency, signature verification,
essence matching, and trust-policy acceptance. This mirrors the OProW design
principle that watermark/HDC/C2PA discovery helps **find** candidate manifests;
cryptography and essence commitments **verify** them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from oprow.core.canonical import canonical_cbor_dumps, canonical_cbor_loads
from oprow.core.enums import PointerMode
from oprow.core.errors import ValidationError
from oprow.core.models import ManifestLocator
from oprow.manifest.codec import manifest_locator_from_primitive

from .models import C2PAAssertion, C2PA_SOFT_BINDING_LABEL


OPROW_SOFT_BINDING_FULL160_ALG = "org.oprow.watermark.full160.v1"
OPROW_SOFT_BINDING_SHORT64_ALG = "org.oprow.watermark.short64.v1"
OPROW_SOFT_BINDING_SHORT64_HV_ALG = "org.oprow.watermark.short64-hv.v1"
OPROW_SOFT_BINDING_FULL160_RATELESS_ALG = "org.oprow.watermark.full160-rateless.v1"


def soft_binding_alg_for_locator(locator: ManifestLocator) -> str:
    """Choose the draft C2PA soft-binding algorithm ID for a locator."""
    if locator.mode == PointerMode.FULL160:
        return OPROW_SOFT_BINDING_FULL160_ALG
    if locator.mode == PointerMode.SHORT64:
        return OPROW_SOFT_BINDING_SHORT64_ALG
    if locator.mode == PointerMode.SHORT64_HV:
        return OPROW_SOFT_BINDING_SHORT64_HV_ALG
    if locator.mode == PointerMode.FULL160_RATELESS:
        return OPROW_SOFT_BINDING_FULL160_RATELESS_ALG
    raise ValidationError(f"unsupported OProW pointer mode for C2PA soft binding: {locator.mode!r}")


def locator_to_soft_binding_value(locator: ManifestLocator) -> bytes:
    """Encode a locator as algorithm-specific C2PA soft-binding block value.

    The block value is not a raw hypervector or media fingerprint. It is only the
    OProW pointer recovered from the watermark or metadata. For SHORT64-HV, the
    value includes the HDC profile identifier but **not** the HDC descriptor,
    route buckets, or privacy-sensitive lookup tokens. Those are computed
    client-side during resolution in later steps.
    """
    return canonical_cbor_dumps(locator)


def locator_from_soft_binding_value(value: bytes) -> ManifestLocator:
    """Parse the OProW locator stored in a soft-binding block value."""
    primitive = canonical_cbor_loads(value, require_canonical=True)
    return manifest_locator_from_primitive(primitive)


@dataclass(frozen=True)
class SoftBindingOptions:
    """Options controlling the draft soft-binding assertion.

    ``name`` is human-facing. ``metadata`` is intentionally not used for final
    verification; it gives C2PA tools information about the binding technology
    and the bridge version. C2PA validators should validate the binding from the
    normative fields, not from metadata.
    """

    name: str = "OProW watermark locator"
    binding_metadata: dict[str, Any] = field(default_factory=dict)
    alg_params: bytes | None = None
    scope: Mapping[str, Any] = field(default_factory=dict)


def make_oprow_soft_binding_assertion(locator: ManifestLocator, *, options: SoftBindingOptions | None = None) -> C2PAAssertion:
    """Create a C2PA ``c2pa.soft-binding`` assertion for an OProW locator.

    Algorithm embodied
    ------------------
    1. Select a draft OProW soft-binding algorithm ID from the pointer mode.
    2. Encode the full locator as deterministic CBOR.
    3. Place that value into one block whose scope defaults to the whole asset.
    4. Store explanatory metadata using OProW namespaced keys.

    This mirrors the Durable Content Credentials pattern where an invisible
    watermark embeds a unique identifier used to look up the active manifest,
    while a fingerprint/essence check later mitigates watermark transfer.
    """
    options = options or SoftBindingOptions()
    alg = soft_binding_alg_for_locator(locator)
    metadata = {
        "description": "OProW locator recovered from an in-band watermark or compatible signpost.",
        "org.oprow.pointerMode": locator.mode.value,
        "org.oprow.locatorDerivation": locator.derivation_profile,
        **options.binding_metadata,
    }
    if locator.namespace_id is not None:
        metadata["org.oprow.namespaceId"] = locator.namespace_id.to_hex()
    if locator.hdc_profile_id is not None:
        metadata["org.oprow.hdcProfileId"] = locator.hdc_profile_id

    body: dict[str, Any] = {
        "alg": alg,
        "name": options.name,
        "blocks": [{"scope": dict(options.scope), "value": locator_to_soft_binding_value(locator)}],
        "bindingMetadata": metadata,
    }
    if options.alg_params is not None:
        body["alg-params"] = options.alg_params
    return C2PAAssertion(label=C2PA_SOFT_BINDING_LABEL, data=body)


def extract_oprow_locator_from_soft_binding(assertion: C2PAAssertion) -> ManifestLocator:
    """Extract the first OProW locator from a draft soft-binding assertion."""
    if assertion.label != C2PA_SOFT_BINDING_LABEL:
        raise ValidationError("not a C2PA soft-binding assertion")
    alg = assertion.data.get("alg")
    if alg not in {
        OPROW_SOFT_BINDING_FULL160_ALG,
        OPROW_SOFT_BINDING_SHORT64_ALG,
        OPROW_SOFT_BINDING_SHORT64_HV_ALG,
        OPROW_SOFT_BINDING_FULL160_RATELESS_ALG,
    }:
        raise ValidationError(f"soft-binding assertion does not use an OProW algorithm: {alg!r}")
    blocks = assertion.data.get("blocks")
    if not isinstance(blocks, list) or not blocks:
        raise ValidationError("soft-binding assertion has no blocks")
    first = blocks[0]
    if not isinstance(first, Mapping) or not isinstance(first.get("value"), bytes):
        raise ValidationError("soft-binding block value is not bytes")
    return locator_from_soft_binding_value(first["value"])
