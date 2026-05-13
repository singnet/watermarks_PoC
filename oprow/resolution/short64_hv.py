"""Resolver for the Step 8 SHORT64-HV route index.

SHORT64-HV is the first OProW path where the media itself helps route lookup.
The watermark carries only an 8-byte short ID, while the verifier computes an
HDC hypervector from the received artifact's PED and derives opaque route keys.
The index returns candidate manifests from buckets keyed by those route keys.

The security rule is unchanged from Step 7:

    HDC route hit != provenance verification

This resolver returns candidates only after checking hash-truncated short-ID
self-consistency.  The Step 5 verifier still performs signature verification,
essence/content matching, and trust-policy evaluation before returning VERIFIED.

This resolver is intentionally unauthenticated and non-private beyond the hashed
route-token mechanics.  Step 9 adds authenticated-map completeness proofs; Step
10 adds privacy profiles such as k-anonymous buckets and cover queries.
"""

from __future__ import annotations

from dataclasses import dataclass

from oprow.core.enums import PointerMode
from oprow.core.identifiers import ManifestKey, ShortId
from oprow.core.models import ManifestLocator
from oprow.hdc import HDCEncoder, HDCRouter, RoutePrecision, Short64HVIndex, SparseTernaryHDCEncoder
from oprow.privacy import CoverRouteSampler, Short64HVPrivacyPlanner, Short64HVPrivacyPolicy
from oprow.manifest.codec import signed_manifest_to_bytes
from oprow.short64 import HASH_TRUNCATED_DERIVATION, Short64IndexReference
from .base import (
    ResolutionCandidate,
    ResolutionRequest,
    ResolutionResult,
    ResolutionStatus,
    Resolver,
    ResolverDiagnosticEvent,
    candidate_from_document_bytes,
    deduplicate_candidates,
    filter_matching_candidates,
)


@dataclass
class Short64HVRouteResolver:
    """Resolve ``PointerMode.SHORT64_HV`` locators through an HDC route index."""

    index: Short64HVIndex
    backing_resolver: Resolver | None = None
    encoder: HDCEncoder | None = None
    router: HDCRouter | None = None
    precision: RoutePrecision | None = None
    min_token_matches: int = 1
    privacy_policy: Short64HVPrivacyPolicy | None = None
    privacy_planner: Short64HVPrivacyPlanner | None = None
    cover_sampler: CoverRouteSampler | None = None
    stats_provider: object | None = None
    name: str = "short64_hv_route"
    require_hash_truncated: bool = True

    def __post_init__(self) -> None:
        if self.router is None:
            self.router = HDCRouter(self.index.profile)
        if self.encoder is None:
            self.encoder = SparseTernaryHDCEncoder(profile=self.index.profile)

    def resolve(self, request: ResolutionRequest) -> ResolutionResult:
        if request.locator.mode != PointerMode.SHORT64_HV:
            return ResolutionResult.unsupported(self.name, f"Short64HVRouteResolver handles short64_hv, not {request.locator.mode.value}")
        if not isinstance(request.locator.value, ShortId):
            return ResolutionResult.unsupported(self.name, "SHORT64-HV locator value is not a ShortId")
        if request.artifact is None:
            return ResolutionResult.unsupported(self.name, "SHORT64-HV resolution requires artifact bytes to compute HDC route tokens")
        if self.require_hash_truncated and request.locator.derivation_profile != HASH_TRUNCATED_DERIVATION:
            return ResolutionResult.unsupported(self.name, f"unsupported SHORT64-HV derivation profile: {request.locator.derivation_profile}")
        if request.locator.hdc_profile_id and request.locator.hdc_profile_id != self.index.profile.profile_id:
            return ResolutionResult.unsupported(self.name, f"locator HDC profile {request.locator.hdc_profile_id!r} does not match index profile {self.index.profile.profile_id!r}")

        assert self.router is not None and self.encoder is not None
        try:
            hv = self.encoder.encode_artifact(request.artifact)
            query_plan = None
            if self.privacy_policy is not None or self.privacy_planner is not None:
                planner = self.privacy_planner or Short64HVPrivacyPlanner(
                    stats_provider=self.stats_provider or self.index,
                    cover_sampler=self.cover_sampler,
                )
                query_plan = planner.plan(
                    short_id=request.locator.value,
                    hv=hv.hypervector if hasattr(hv, "hypervector") else hv,
                    profile=self.index.profile,
                    router=self.router,
                    namespace_id=request.locator.namespace_id,
                    epoch_id=getattr(self.index, "epoch_id", "global"),
                    policy=self.privacy_policy,
                    fallback_precision=self.precision,
                )
                route_tokens = query_plan.route_tokens_for_lookup
                effective_min_token_matches = max(self.min_token_matches, query_plan.policy.min_token_matches)
            else:
                route_tokens = self.router.derive_route_tokens(
                    short_id=request.locator.value,
                    hv=hv,
                    namespace_id=request.locator.namespace_id,
                    precision=self.precision,
                )
                effective_min_token_matches = self.min_token_matches

            lookup = self.index.lookup_tokens(
                route_tokens,
                short_id=request.locator.value,
                namespace_id=request.locator.namespace_id,
                min_token_matches=effective_min_token_matches,
                max_results=request.max_candidates + 1 if request.max_candidates > 0 else 1,
            )
        except Exception as exc:
            return ResolutionResult.error(self.name, exc, "SHORT64-HV route lookup failed")

        diagnostics: list[ResolverDiagnosticEvent] = [
            ResolverDiagnosticEvent(
                self.name,
                "route_lookup",
                data={
                    "short_id": request.locator.value.to_hex(),
                    "hdc_profile_id": self.index.profile.profile_id,
                    "route_tokens": len(route_tokens),
                    "references": len(lookup.references),
                    "complete": lookup.complete,
                    "total_available": lookup.total_available,
                    "min_token_matches": effective_min_token_matches,
                    "index": getattr(self.index, "name", self.index.__class__.__name__),
                    "lookup_diagnostics": lookup.diagnostics,
                    "privacy_plan": query_plan.to_diagnostics() if query_plan is not None else None,
                },
            )
        ]
        if not lookup.complete:
            diagnostics.append(
                ResolverDiagnosticEvent(
                    self.name,
                    "candidate_set_truncated",
                    "index had more references than requested; treat as possible candidate flood",
                    {"total_available": lookup.total_available, "returned": len(lookup.references)},
                )
            )
        if not lookup.references:
            return ResolutionResult.not_found(self.name, "short64_hv route produced no candidate references")

        candidates: list[ResolutionCandidate] = []
        errors: list[str] = []
        for ref in lookup.references:
            try:
                candidates.extend(self._candidates_from_reference(ref, request))
            except Exception as exc:
                msg = f"SHORT64-HV reference failed: {exc}"
                errors.append(msg)
                diagnostics.append(ResolverDiagnosticEvent(self.name, "reference_failed", msg, {"short_id": ref.short_id.to_hex()}))

        deduped = deduplicate_candidates(candidates)
        matching = filter_matching_candidates(deduped)
        diagnostics.append(ResolverDiagnosticEvent(self.name, "candidates", data={"seen": len(deduped), "matching": len(matching)}))
        if not matching:
            return ResolutionResult(status=ResolutionStatus.ERROR if errors else ResolutionStatus.NOT_FOUND, candidates=[], diagnostics=diagnostics, errors=errors)
        status = ResolutionStatus.PARTIAL if not lookup.complete or len(matching) > request.max_candidates else ResolutionStatus.FOUND
        return ResolutionResult(status=status, candidates=matching, diagnostics=diagnostics, errors=errors)

    def _candidates_from_reference(self, ref: Short64IndexReference, request: ResolutionRequest) -> list[ResolutionCandidate]:
        out: list[ResolutionCandidate] = []
        if self.require_hash_truncated and ref.derivation_profile != request.locator.derivation_profile:
            return out
        if ref.document_bytes is not None:
            c = candidate_from_document_bytes(ref.document_bytes, request_locator=request.locator, source=f"short64-hv:{getattr(self.index, 'name', self.index.__class__.__name__)}:inline")
            out.append(self._with_diagnostics(c, ref))
            return out

        if ref.manifest_key is not None and self.backing_resolver is not None:
            full_locator = ManifestLocator(mode=PointerMode.FULL160, value=ref.manifest_key)
            full_result = self.backing_resolver.resolve(
                ResolutionRequest(
                    locator=full_locator,
                    artifact=request.artifact,
                    storage_hints=list(ref.storage_hints) or list(request.storage_hints),
                    allow_network=request.allow_network,
                    max_candidates=request.max_candidates,
                    max_bytes=request.max_bytes,
                    metadata={**request.metadata, "short64_hv_ref": ref.to_canonical()},
                )
            )
            for fc in full_result.candidates:
                raw = fc.raw_bytes or signed_manifest_to_bytes(fc.manifest)
                c = candidate_from_document_bytes(raw, request_locator=request.locator, source=f"short64-hv-via:{fc.source}")
                out.append(self._with_diagnostics(c, ref))
        return out

    @staticmethod
    def _with_diagnostics(candidate: ResolutionCandidate, ref: Short64IndexReference) -> ResolutionCandidate:
        diagnostics = dict(candidate.diagnostics)
        diagnostics["short64_hv_index_reference"] = {
            "short_id": ref.short_id.to_hex(),
            "manifest_key": ref.manifest_key.to_hex() if isinstance(ref.manifest_key, ManifestKey) else None,
            "derivation_profile": ref.derivation_profile,
            "namespace_id": ref.namespace_id.to_hex() if ref.namespace_id is not None else None,
            "has_document_bytes": ref.document_bytes is not None,
        }
        return ResolutionCandidate(
            envelope=candidate.envelope,
            source=candidate.source,
            validation_status=candidate.validation_status,
            raw_bytes=candidate.raw_bytes,
            diagnostics=diagnostics,
        )
