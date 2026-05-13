"""Resolver for the Step 7 plain SHORT64 index.

This file bridges the Step 4 ``Resolver`` API and the Step 7 short-ID index.
It implements the lookup path used when a watermark extracted from media carries
only an 8-byte ``ShortId`` rather than a FULL160 manifest key.

Security model
==============

A SHORT64 index is not authoritative.  It can be incomplete, malicious, or
flooded.  The resolver therefore treats index rows as candidate-discovery hints:

    1. query index by short_id;
    2. obtain document bytes directly or through a backing FULL160 resolver;
    3. parse candidate document;
    4. check hash-truncated short-ID self-consistency;
    5. return matching candidates for the verifier.

The final OProW verification result is still produced by the Step 5 orchestrator
after signature, essence/content, and local trust-policy checks.  HDC routing,
authenticated map completeness, and lookup privacy are intentionally absent here
and deferred to Steps 8--10.
"""

from __future__ import annotations

from dataclasses import dataclass

from oprow.core.enums import PointerMode
from oprow.core.identifiers import ManifestKey, ShortId
from oprow.core.models import ManifestLocator
from oprow.manifest.codec import signed_manifest_to_bytes
from oprow.short64 import HASH_TRUNCATED_DERIVATION, Short64Index, Short64IndexReference
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
class Short64IndexResolver:
    """Resolve ``PointerMode.SHORT64`` locators through a plain short-ID index."""

    index: Short64Index
    backing_resolver: Resolver | None = None
    name: str = "short64_index"
    require_hash_truncated: bool = True

    def resolve(self, request: ResolutionRequest) -> ResolutionResult:
        if request.locator.mode != PointerMode.SHORT64:
            return ResolutionResult.unsupported(self.name, f"Short64IndexResolver handles short64, not {request.locator.mode.value}")
        if not isinstance(request.locator.value, ShortId):
            return ResolutionResult.unsupported(self.name, "SHORT64 locator value is not a ShortId")
        if self.require_hash_truncated and request.locator.derivation_profile != HASH_TRUNCATED_DERIVATION:
            return ResolutionResult.unsupported(self.name, f"unsupported SHORT64 derivation profile: {request.locator.derivation_profile}")

        max_lookup = request.max_candidates + 1 if request.max_candidates > 0 else 1
        try:
            lookup = self.index.lookup(
                request.locator.value,
                namespace_id=request.locator.namespace_id,
                derivation_profile=request.locator.derivation_profile if self.require_hash_truncated else None,
                max_results=max_lookup,
            )
        except Exception as exc:
            return ResolutionResult.error(self.name, exc, "SHORT64 index lookup failed")

        diagnostics: list[ResolverDiagnosticEvent] = [
            ResolverDiagnosticEvent(
                self.name,
                "lookup",
                data={
                    "short_id": request.locator.value.to_hex(),
                    "references": len(lookup.references),
                    "complete": lookup.complete,
                    "total_available": lookup.total_available,
                    "index": getattr(self.index, "name", self.index.__class__.__name__),
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
            return ResolutionResult.not_found(self.name, "short ID not present in index")

        candidates: list[ResolutionCandidate] = []
        errors: list[str] = []
        for ref in lookup.references:
            try:
                candidates.extend(self._candidates_from_reference(ref, request))
            except Exception as exc:
                msg = f"SHORT64 reference failed: {exc}"
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
            c = candidate_from_document_bytes(ref.document_bytes, request_locator=request.locator, source=f"short64:{getattr(self.index, 'name', self.index.__class__.__name__)}:inline")
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
                    metadata={**request.metadata, "short64_ref": ref.to_canonical()},
                )
            )
            for fc in full_result.candidates:
                raw = fc.raw_bytes or signed_manifest_to_bytes(fc.manifest)
                c = candidate_from_document_bytes(raw, request_locator=request.locator, source=f"short64-via:{fc.source}")
                out.append(self._with_diagnostics(c, ref))
        return out

    @staticmethod
    def _with_diagnostics(candidate: ResolutionCandidate, ref: Short64IndexReference) -> ResolutionCandidate:
        diagnostics = dict(candidate.diagnostics)
        diagnostics["short64_index_reference"] = {
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
