"""End-to-end provenance verification orchestrator for OProW Step 5.

This is the first module that assembles the earlier layers into the OProW
verification flow:

    recovered locator -> resolver -> candidate manifests -> locator check
    -> signature check -> essence/content check -> local trust policy -> status

Step 5 starts from an explicit ``ManifestLocator`` because real watermark
extraction is scheduled for Step 12.  Keeping extraction separate is a security
advantage: the core verifier does not care whether the locator came from a
watermark, C2PA soft binding, sidecar, metadata, or a future SHORT64-HV route.
It still applies the same acceptance rules.

Safety rule implemented here:

    Resolution is not trust.  Storage, indices, HTTP gateways, and future HDC
    routes only provide candidates.  A candidate is accepted only if locator
    self-consistency, signatures, essence matching, and local trust all pass.

That rule is what prevents short-ID collisions, malicious resolvers, or HDC
bucket collisions from turning into false verification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from oprow.core.enums import PointerMode
from oprow.core.errors import OProWError, UnsupportedAlgorithmError
from oprow.core.models import Artifact, ManifestLocator, SignedManifest, StorageHint
from oprow.core.policy import ResolutionLimits, TrustPolicyStub
from oprow.essence.registry import EssenceRegistry, default_essence_registry
from oprow.manifest.keys import KeyResolver
from oprow.manifest.verification import verify_locator_self_consistency, verify_manifest_signatures
from oprow.resolution.base import CandidateValidationStatus, ResolutionCandidate, ResolutionRequest, ResolutionResult, ResolutionStatus, Resolver

from .result import CandidateVerification, EssenceCheck, VerificationResult, VerificationStatus
from .trust import SimpleTrustEvaluator


@dataclass(frozen=True)
class VerificationContext:
    """Dependencies and policy knobs for a verification run."""

    resolver: Resolver
    key_resolver: KeyResolver
    essence_registry: EssenceRegistry = field(default_factory=default_essence_registry)
    trust_policy: TrustPolicyStub = field(default_factory=TrustPolicyStub)
    limits: ResolutionLimits | None = None
    require_resolver_locator_match: bool = True

    def effective_limits(self) -> ResolutionLimits:
        return self.limits or self.trust_policy.limits


@dataclass(frozen=True)
class VerificationInput:
    """Artifact plus locator recovered by a watermark/metadata layer."""

    artifact: Artifact
    locator: ManifestLocator
    storage_hints: list[StorageHint] = field(default_factory=list)
    allow_network: bool = True
    metadata: dict[str, object] = field(default_factory=dict)


class ProvenanceVerifier:
    """High-level Step 5 verifier object."""

    def __init__(self, context: VerificationContext):
        self.context = context
        self.trust_evaluator = SimpleTrustEvaluator(context.trust_policy)

    def verify(self, verification_input: VerificationInput) -> VerificationResult:
        """Run resolution and candidate verification, returning rich status."""
        limits = self.context.effective_limits()
        request = ResolutionRequest(
            locator=verification_input.locator,
            artifact=verification_input.artifact,
            storage_hints=list(verification_input.storage_hints),
            allow_network=verification_input.allow_network,
            max_candidates=limits.max_candidates,
            metadata=dict(verification_input.metadata),
        )

        try:
            resolution = self.context.resolver.resolve(request)
        except Exception as exc:
            return VerificationResult(
                status=VerificationStatus.RESOLUTION_ERROR,
                warnings=[f"resolver raised {exc.__class__.__name__}: {exc}"],
                diagnostics={"stage": "resolution", "exception": repr(exc)},
            )

        if resolution.status == ResolutionStatus.ERROR and not resolution.candidates:
            proof_failed = any(event.event == "index_proof_failed" for event in resolution.diagnostics)
            return VerificationResult(
                status=VerificationStatus.INDEX_PROOF_FAILED if proof_failed else VerificationStatus.RESOLUTION_ERROR,
                resolution=resolution,
                warnings=list(resolution.errors) or (["authenticated index proof failed"] if proof_failed else ["resolver returned error"]),
            )
        if not resolution.candidates:
            return VerificationResult(
                status=VerificationStatus.MANIFEST_NOT_FOUND,
                resolution=resolution,
                warnings=["no candidate manifest resolved for locator"],
            )
        if len(resolution.candidates) > limits.max_candidates:
            return VerificationResult(
                status=VerificationStatus.RESOLUTION_CANDIDATE_FLOOD,
                resolution=resolution,
                warnings=[f"resolver returned {len(resolution.candidates)} candidates, limit is {limits.max_candidates}"],
                diagnostics={"candidate_count": len(resolution.candidates), "limit": limits.max_candidates},
            )

        reports: list[CandidateVerification] = []
        for candidate in resolution.candidates[: limits.max_manifest_fetches]:
            reports.append(self.verify_candidate(verification_input.artifact, verification_input.locator, candidate))

        if len(resolution.candidates) > limits.max_manifest_fetches:
            return VerificationResult(
                status=VerificationStatus.RESOLUTION_CANDIDATE_FLOOD,
                resolution=resolution,
                candidate_reports=reports,
                warnings=[f"candidate fetch limit exceeded: {len(resolution.candidates)} > {limits.max_manifest_fetches}"],
            )

        return self.classify_reports(reports, resolution)

    def verify_candidate(self, artifact: Artifact, request_locator: ManifestLocator, candidate: ResolutionCandidate) -> CandidateVerification:
        """Verify one resolver candidate.

        The order is cheap-to-expensive and security-preserving:
        locator check, signature check, essence recomputation, trust policy.
        """
        warnings: list[str] = []
        diagnostics = {
            "source": candidate.source,
            "resolver_candidate_status": candidate.validation_status.value,
            "locator_mode": request_locator.mode.value,
        }

        locator_ok = verify_locator_self_consistency(candidate.manifest, request_locator)
        if self.context.require_resolver_locator_match and candidate.validation_status != CandidateValidationStatus.LOCATOR_MATCH:
            locator_ok = False
            warnings.append(f"resolver candidate was not marked locator_match: {candidate.validation_status.value}")
        if not locator_ok:
            return CandidateVerification(
                envelope=candidate.envelope,
                source=candidate.source,
                status=self._locator_mismatch_status(request_locator),
                locator_ok=False,
                warnings=warnings,
                diagnostics=diagnostics,
            )

        try:
            signature_report = verify_manifest_signatures(candidate.manifest, self.context.key_resolver)
        except Exception as exc:
            return CandidateVerification(
                envelope=candidate.envelope,
                source=candidate.source,
                status=VerificationStatus.NO_VALID_SIGNATURES,
                locator_ok=True,
                warnings=[*warnings, f"signature verification raised {exc.__class__.__name__}: {exc}"],
                diagnostics={**diagnostics, "stage": "signature", "exception": repr(exc)},
            )
        if not signature_report.has_valid_signature:
            return CandidateVerification(
                envelope=candidate.envelope,
                source=candidate.source,
                status=VerificationStatus.NO_VALID_SIGNATURES,
                locator_ok=True,
                signature_report=signature_report,
                warnings=warnings,
                diagnostics={**diagnostics, "valid_signature_count": 0},
            )

        essence_check = self._check_essence(artifact, candidate.manifest)
        if not essence_check.matched:
            if essence_check.reason == "unsupported_essence_profile":
                status = VerificationStatus.UNSUPPORTED_ESSENCE_PROFILE
            elif essence_check.reason.startswith("essence_computation_error"):
                status = VerificationStatus.ESSENCE_COMPUTATION_FAILED
            else:
                status = VerificationStatus.CONTENT_MISMATCH
            return CandidateVerification(
                envelope=candidate.envelope,
                source=candidate.source,
                status=status,
                locator_ok=True,
                signature_report=signature_report,
                essence_check=essence_check,
                warnings=warnings,
                diagnostics={**diagnostics, "valid_signature_count": len(signature_report.valid_checks)},
            )

        trust_decision = self.trust_evaluator.evaluate(candidate.manifest, signature_report)
        if not trust_decision.accepted:
            return CandidateVerification(
                envelope=candidate.envelope,
                source=candidate.source,
                status=VerificationStatus.SIGNED_BUT_UNTRUSTED,
                locator_ok=True,
                signature_report=signature_report,
                essence_check=essence_check,
                trust_decision=trust_decision,
                warnings=warnings,
                diagnostics={**diagnostics, "trust_reason": trust_decision.reason},
            )

        return CandidateVerification(
            envelope=candidate.envelope,
            source=candidate.source,
            status=VerificationStatus.VERIFIED,
            locator_ok=True,
            signature_report=signature_report,
            essence_check=essence_check,
            trust_decision=trust_decision,
            warnings=warnings,
            diagnostics={**diagnostics, "trust_reason": trust_decision.reason},
        )

    def _check_essence(self, artifact: Artifact, manifest: SignedManifest) -> EssenceCheck:
        binding = manifest.core.artifact
        try:
            computed = self.context.essence_registry.compute_hash(artifact, binding.essence_alg_id)
        except UnsupportedAlgorithmError:
            return EssenceCheck(binding.essence_alg_id, binding.essence_hash, None, False, "unsupported_essence_profile")
        except OProWError as exc:
            return EssenceCheck(binding.essence_alg_id, binding.essence_hash, None, False, f"essence_computation_error:{exc.__class__.__name__}", {"message": str(exc)})
        except Exception as exc:
            return EssenceCheck(binding.essence_alg_id, binding.essence_hash, None, False, f"essence_computation_error:{exc.__class__.__name__}", {"message": str(exc)})
        if computed != binding.essence_hash:
            return EssenceCheck(binding.essence_alg_id, binding.essence_hash, computed, False, "essence_hash_mismatch")
        return EssenceCheck(binding.essence_alg_id, binding.essence_hash, computed, True, "matched")

    @staticmethod
    def _locator_mismatch_status(locator: ManifestLocator) -> VerificationStatus:
        if locator.mode in (PointerMode.FULL160, PointerMode.FULL160_RATELESS):
            return VerificationStatus.MANIFEST_KEY_MISMATCH
        if locator.mode in (PointerMode.SHORT64, PointerMode.SHORT64_HV):
            return VerificationStatus.MANIFEST_SHORT_ID_MISMATCH
        return VerificationStatus.UNSUPPORTED_POINTER_MODE

    def classify_reports(self, reports: list[CandidateVerification], resolution: ResolutionResult | None = None) -> VerificationResult:
        """Aggregate per-candidate reports into one final result."""
        trusted_valid = [r for r in reports if r.trusted_valid]
        cryptographically_valid = [r for r in reports if r.cryptographically_valid]
        warnings = [w for r in reports for w in r.warnings]

        if len(trusted_valid) == 1:
            r = trusted_valid[0]
            return VerificationResult(
                status=VerificationStatus.VERIFIED,
                verified_manifests=[r.manifest],
                trusted_claims=list(r.trust_decision.accepted_claims if r.trust_decision else []),
                valid_signatures=list(r.signature_report.valid_records if r.signature_report else []),
                candidate_reports=reports,
                resolution=resolution,
                warnings=warnings,
            )

        if len(trusted_valid) > 1:
            if self._same_manifest_core(trusted_valid):
                return VerificationResult(
                    status=VerificationStatus.VERIFIED,
                    verified_manifests=[r.manifest for r in trusted_valid],
                    trusted_claims=list(trusted_valid[0].manifest.core.claims),
                    valid_signatures=self._collect_valid_signatures(trusted_valid),
                    candidate_reports=reports,
                    resolution=resolution,
                    warnings=[*warnings, "multiple valid candidates share the same ManifestCore"],
                )
            if self._has_obvious_claim_conflict(trusted_valid):
                return VerificationResult(
                    status=VerificationStatus.CONFLICTING_PROVENANCE,
                    verified_manifests=[r.manifest for r in trusted_valid],
                    valid_signatures=self._collect_valid_signatures(trusted_valid),
                    candidate_reports=reports,
                    resolution=resolution,
                    warnings=[*warnings, "multiple trusted candidates make conflicting top-level origin claims"],
                )
            return VerificationResult(
                status=VerificationStatus.AMBIGUOUS_MULTIPLE_VALID,
                verified_manifests=[r.manifest for r in trusted_valid],
                valid_signatures=self._collect_valid_signatures(trusted_valid),
                candidate_reports=reports,
                resolution=resolution,
                warnings=[*warnings, "multiple trusted candidates passed; policy disambiguation required"],
            )

        if cryptographically_valid:
            return VerificationResult(
                status=VerificationStatus.SIGNED_BUT_UNTRUSTED,
                verified_manifests=[r.manifest for r in cryptographically_valid],
                valid_signatures=self._collect_valid_signatures(cryptographically_valid),
                candidate_reports=reports,
                resolution=resolution,
                warnings=[*warnings, "signed and content-bound, but not trusted under local policy"],
            )

        return VerificationResult(
            status=self._best_failure_status(reports),
            candidate_reports=reports,
            resolution=resolution,
            warnings=warnings,
        )

    @staticmethod
    def _collect_valid_signatures(reports: Iterable[CandidateVerification]):
        out = []
        for r in reports:
            if r.signature_report:
                out.extend(r.signature_report.valid_records)
        return out

    @staticmethod
    def _same_manifest_core(reports: list[CandidateVerification]) -> bool:
        if not reports:
            return False
        first = reports[0].manifest.core.canonical_bytes()
        return all(r.manifest.core.canonical_bytes() == first for r in reports)

    @staticmethod
    def _has_obvious_claim_conflict(reports: list[CandidateVerification]) -> bool:
        # This intentionally detects only simple conflicts.  Rich semantics are
        # left to future policy engines.
        sets = [frozenset(str(c.type) for c in r.manifest.core.claims) for r in reports]
        capture_only = any("capture" in s and "generation" not in s and "edit" not in s for s in sets)
        generation_only = any("generation" in s and "capture" not in s and "edit" not in s for s in sets)
        return capture_only and generation_only

    @staticmethod
    def _best_failure_status(reports: list[CandidateVerification]) -> VerificationStatus:
        if not reports:
            return VerificationStatus.MANIFEST_NOT_FOUND
        priority = [
            VerificationStatus.CONTENT_MISMATCH,
            VerificationStatus.ESSENCE_COMPUTATION_FAILED,
            VerificationStatus.UNSUPPORTED_ESSENCE_PROFILE,
            VerificationStatus.NO_VALID_SIGNATURES,
            VerificationStatus.MANIFEST_KEY_MISMATCH,
            VerificationStatus.MANIFEST_SHORT_ID_MISMATCH,
            VerificationStatus.UNSUPPORTED_POINTER_MODE,
        ]
        statuses = {r.status for r in reports}
        for status in priority:
            if status in statuses:
                return status
        return VerificationStatus.NO_VALID_CANDIDATE


def verify_artifact_with_locator(
    artifact: Artifact,
    locator: ManifestLocator,
    *,
    resolver: Resolver,
    key_resolver: KeyResolver,
    essence_registry: EssenceRegistry | None = None,
    trust_policy: TrustPolicyStub | None = None,
    storage_hints: list[StorageHint] | None = None,
    allow_network: bool = True,
) -> VerificationResult:
    """Convenience wrapper used by examples and future watermark extractors."""
    verifier = ProvenanceVerifier(
        VerificationContext(
            resolver=resolver,
            key_resolver=key_resolver,
            essence_registry=essence_registry or default_essence_registry(),
            trust_policy=trust_policy or TrustPolicyStub(),
        )
    )
    return verifier.verify(
        VerificationInput(
            artifact=artifact,
            locator=locator,
            storage_hints=list(storage_hints or []),
            allow_network=allow_network,
        )
    )
