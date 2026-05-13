"""Composite resolver orchestration.

The usual OProW lookup order is local and low-leakage first, then redundant
storage and network gateways:

    embedded metadata -> sidecar/local cache -> CAS/DHT -> HTTP gateways

The composite resolver implements this ordering while keeping each backend
replaceable.  It can stop after the first successful backend for privacy/speed or
continue to collect redundant candidates and diagnostics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .base import ResolutionRequest, ResolutionResult, ResolutionStatus, Resolver, ResolverDiagnosticEvent, deduplicate_candidates


@dataclass
class CompositeResolver:
    """Try multiple resolver backends under one public Resolver API."""

    resolvers: list[Resolver] = field(default_factory=list)
    stop_on_first_found: bool = True
    name: str = "composite"

    def __init__(self, resolvers: Iterable[Resolver] | None = None, *, stop_on_first_found: bool = True, name: str = "composite"):
        self.resolvers = list(resolvers or [])
        self.stop_on_first_found = stop_on_first_found
        self.name = name

    def resolve(self, request: ResolutionRequest) -> ResolutionResult:
        all_candidates = []
        all_diagnostics: list[ResolverDiagnosticEvent] = [ResolverDiagnosticEvent(self.name, "start", data={"resolvers": [getattr(r, "name", r.__class__.__name__) for r in self.resolvers]})]
        all_errors: list[str] = []
        for resolver in self.resolvers:
            result = resolver.resolve(request)
            all_candidates.extend(result.candidates)
            all_diagnostics.extend(result.diagnostics)
            all_errors.extend(result.errors)
            if result.candidates and self.stop_on_first_found:
                all_diagnostics.append(ResolverDiagnosticEvent(self.name, "stop_on_first_found", data={"resolver": getattr(resolver, "name", resolver.__class__.__name__)}))
                break
        deduped = deduplicate_candidates(all_candidates)
        status = ResolutionStatus.FOUND if deduped else (ResolutionStatus.ERROR if all_errors else ResolutionStatus.NOT_FOUND)
        all_diagnostics.append(ResolverDiagnosticEvent(self.name, "done", data={"candidate_count": len(deduped), "errors": len(all_errors)}))
        return ResolutionResult(status=status, candidates=deduped, diagnostics=all_diagnostics, errors=all_errors)
