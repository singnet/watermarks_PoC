"""High-level watermark workflow helpers.

The lower-level profiles know how to embed and extract ``WatermarkPayload`` bits,
but most callers want to work with OProW objects: signed manifests, locators,
resolvers, and verification policies.  This file connects those pieces while
preserving the critical architecture rule:

    watermark extraction finds a locator; it does not verify provenance.

``verify_artifact_from_watermark`` therefore performs two stages:

1. Extract locator from the artifact using a watermark profile.
2. Call the Step 5 verifier with that locator, resolver, key resolver, and trust
   policy.

This keeps the watermark layer modular.  A stronger production extractor can
replace the Step 12 reference profiles without changing manifest verification or
trust evaluation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from oprow.core.enums import PointerMode
from oprow.core.errors import ValidationError
from oprow.core.models import Artifact, ManifestLocator, SignedManifest
from oprow.core.policy import TrustPolicyStub
from oprow.manifest.keys import KeyResolver
from oprow.resolution.base import Resolver
from oprow.verification.orchestrator import verify_artifact_with_locator
from oprow.verification.result import VerificationResult, VerificationStatus
from .base import WatermarkEmbedResult, WatermarkExtraction, WatermarkExtractionStatus, WatermarkProfile, WatermarkStrength
from .payload import WatermarkPayload


@dataclass(frozen=True)
class WatermarkVerificationReport:
    """Combined output of extraction plus full OProW verification."""

    extraction: WatermarkExtraction
    verification: VerificationResult | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)

    @property
    def verified(self) -> bool:
        return bool(self.verification and self.verification.verified)


# Local minimal result factory for extraction failures.  We reuse the Step 5
# ``VerificationResult`` type so downstream UI code has one status vocabulary.
def _verification_result_for_extraction_failure(extraction: WatermarkExtraction) -> VerificationResult:
    if extraction.status == WatermarkExtractionStatus.NO_WATERMARK:
        status = VerificationStatus.NO_WATERMARK
    else:
        # CRC failures and extractor errors are best represented as "no valid
        # candidate" at the provenance layer: no trustworthy locator was
        # recovered, so there is no manifest to verify.
        status = VerificationStatus.NO_VALID_CANDIDATE
    return VerificationResult(status=status, warnings=[extraction.error] if extraction.error else [])


def payload_for_manifest(
    manifest: SignedManifest,
    *,
    pointer_mode: PointerMode,
    watermark_profile: WatermarkProfile,
    hdc_profile_id: str | None = None,
) -> WatermarkPayload:
    """Create a watermark payload for a signed manifest and pointer mode."""

    return WatermarkPayload.from_signed_manifest(
        manifest,
        pointer_mode=pointer_mode,
        wm_alg_id=watermark_profile.numeric_id,
        hdc_profile_id=hdc_profile_id,
    )


def embed_manifest_locator(
    artifact: Artifact,
    manifest: SignedManifest,
    *,
    pointer_mode: PointerMode,
    watermark_profile: WatermarkProfile,
    strength: WatermarkStrength | None = None,
    hdc_profile_id: str | None = None,
) -> WatermarkEmbedResult:
    """Derive a manifest locator, encode it, and embed it in ``artifact``."""

    payload = payload_for_manifest(
        manifest,
        pointer_mode=pointer_mode,
        watermark_profile=watermark_profile,
        hdc_profile_id=hdc_profile_id,
    )
    return watermark_profile.embed(artifact, payload, strength=strength)


def extract_locator(
    artifact: Artifact,
    *,
    watermark_profile: WatermarkProfile,
    strength: WatermarkStrength | None = None,
    hdc_profile_id: str | None = None,
) -> WatermarkExtraction:
    """Extract a locator from an artifact using the selected profile."""

    return watermark_profile.extract(artifact, strength=strength, hdc_profile_id=hdc_profile_id)


def verify_artifact_from_watermark(
    artifact: Artifact,
    *,
    watermark_profile: WatermarkProfile,
    resolver: Resolver,
    key_resolver: KeyResolver,
    trust_policy: TrustPolicyStub | None = None,
    strength: WatermarkStrength | None = None,
    hdc_profile_id: str | None = None,
) -> WatermarkVerificationReport:
    """Extract a watermark locator and run full OProW verification.

    The verifier result is ``VERIFIED`` only if all normal Step 5 checks pass.
    A successfully extracted locator with a bad signature or mismatched essence
    will still be rejected by ``verify_artifact_with_locator``.
    """

    extraction = extract_locator(
        artifact,
        watermark_profile=watermark_profile,
        strength=strength,
        hdc_profile_id=hdc_profile_id,
    )
    if not extraction.extracted or extraction.locator is None:
        return WatermarkVerificationReport(
            extraction=extraction,
            verification=_verification_result_for_extraction_failure(extraction),
            diagnostics={"stage": "watermark_extraction_failed"},
        )
    verification = verify_artifact_with_locator(
        artifact,
        extraction.locator,
        resolver=resolver,
        key_resolver=key_resolver,
        trust_policy=trust_policy,
    )
    return WatermarkVerificationReport(
        extraction=extraction,
        verification=verification,
        diagnostics={"stage": "full_verification", "locator_mode": extraction.locator.mode.value},
    )
