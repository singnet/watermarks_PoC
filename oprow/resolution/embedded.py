"""Embedded-manifest resolver.

Embedded lookup is ideal for privacy and offline use because the verifier does
not contact an external resolver.  It is fragile, however: platforms often strip
metadata.  OProW therefore treats embedded manifests as a fast optimization,
not as the only storage layer.

This first draft does not parse real EXIF/XMP/JUMBF/C2PA boxes.  It reads
prototype fields from ``Artifact.metadata`` so the rest of the resolver stack can
be tested before container parsers are added.
"""

from __future__ import annotations

from dataclasses import dataclass

from oprow.core.models import ManifestEnvelope, ManifestLocator, SignedManifest
from oprow.manifest.verification import verify_locator_self_consistency
from .base import CandidateValidationStatus, ResolutionCandidate, ResolutionRequest, ResolutionResult, ResolverDiagnosticEvent, candidate_from_document_bytes, result_from_candidates


@dataclass
class EmbeddedManifestResolver:
    """Resolve OProW manifest bytes supplied in ``Artifact.metadata``."""

    name: str = "embedded"

    def resolve(self, request: ResolutionRequest) -> ResolutionResult:
        if request.artifact is None:
            return ResolutionResult.not_found(self.name, "no artifact supplied")
        md = request.artifact.metadata or {}
        diagnostics: list[ResolverDiagnosticEvent] = []
        candidates: list[ResolutionCandidate] = []

        for key in ("oprow_manifest_bytes", "oprow_envelope_bytes"):
            raw = md.get(key)
            if raw is None:
                continue
            if not isinstance(raw, bytes):
                diagnostics.append(ResolverDiagnosticEvent(self.name, "ignored", f"metadata {key} is not bytes"))
                continue
            try:
                candidates.append(candidate_from_document_bytes(raw, request_locator=request.locator, source=f"artifact.metadata:{key}"))
            except Exception as exc:
                diagnostics.append(ResolverDiagnosticEvent(self.name, "decode_failed", f"{key}: {exc}"))

        env = md.get("oprow_envelope")
        if isinstance(env, ManifestEnvelope):
            status = CandidateValidationStatus.LOCATOR_MATCH if verify_locator_self_consistency(env.manifest, request.locator) else CandidateValidationStatus.LOCATOR_MISMATCH
            candidates.append(ResolutionCandidate(envelope=env, source="artifact.metadata:oprow_envelope", validation_status=status))

        man = md.get("oprow_manifest")
        if isinstance(man, SignedManifest):
            env2 = ManifestEnvelope(manifest=man, locator=ManifestLocator.from_signed_manifest(man))
            status = CandidateValidationStatus.LOCATOR_MATCH if verify_locator_self_consistency(man, request.locator) else CandidateValidationStatus.LOCATOR_MISMATCH
            candidates.append(ResolutionCandidate(envelope=env2, source="artifact.metadata:oprow_manifest", validation_status=status))

        if not candidates:
            return ResolutionResult.not_found(self.name, "no embedded OProW metadata fields")
        return result_from_candidates(self.name, candidates, diagnostics)
