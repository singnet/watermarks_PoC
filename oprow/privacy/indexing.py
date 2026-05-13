"""Index-publication helpers for privacy-aware SHORT64-HV routing.

A P1/P2 verifier can only find candidates if the indexer published route tokens
at the precisions the verifier may query.  This helper adds a manifest at every
precision required by one or more privacy policies.  It works with both the Step
8 unauthenticated index and the Step 9 authenticated index because both expose a
compatible ``add_manifest(..., precision=...)`` method.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from oprow.core.identifiers import NamespaceId
from oprow.core.models import Artifact, SignedManifest, StorageHint
from oprow.hdc.encoders import HDCEncoder
from oprow.hdc.profiles import HDCProfile
from oprow.hdc.routing import RoutePrecision

from .profiles import Short64HVPrivacyPolicy, unique_precisions


@dataclass(frozen=True)
class PrivacyIndexedReference:
    reference: Any
    precision: RoutePrecision


def precisions_for_policies(policies: Iterable[Short64HVPrivacyPolicy], hdc_profile: HDCProfile) -> tuple[RoutePrecision, ...]:
    precisions: list[RoutePrecision] = []
    for policy in policies:
        precisions.extend(policy.effective_precisions(hdc_profile))
    return unique_precisions(precisions, hdc_profile)


def add_manifest_for_privacy_policies(
    index: Any,
    manifest: SignedManifest,
    *,
    artifact: Artifact,
    policies: Iterable[Short64HVPrivacyPolicy],
    encoder: HDCEncoder | None = None,
    include_document_bytes: bool = True,
    namespace_id: NamespaceId | None = None,
    storage_hints: Iterable[StorageHint] | None = None,
    metadata: dict[str, object] | None = None,
) -> list[PrivacyIndexedReference]:
    hdc_profile = getattr(index, "profile", None)
    if hdc_profile is None:
        raise TypeError("index must expose a .profile HDCProfile attribute")
    out: list[PrivacyIndexedReference] = []
    for precision in precisions_for_policies(policies, hdc_profile):
        ref = index.add_manifest(
            manifest,
            artifact=artifact,
            encoder=encoder,
            include_document_bytes=include_document_bytes,
            namespace_id=namespace_id,
            storage_hints=storage_hints,
            precision=precision,
            metadata={"privacy_precision": precision.to_canonical(), **dict(metadata or {})},
        )
        out.append(PrivacyIndexedReference(reference=ref, precision=precision))
    return out
