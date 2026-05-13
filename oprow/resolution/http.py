"""HTTP gateway resolver.

HTTP gateways are an availability layer, not a trust layer.  They can return
corrupt, stale, or malicious bytes, so every response is parsed and checked
against the recovered locator before it becomes a candidate.  Later verification
still checks signatures, essence hashes, and trust policy.

This first draft uses stdlib ``urllib`` to avoid adding dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

from oprow.core.enums import StorageHintType
from oprow.core.identifiers import ManifestKey, ShortId
from .base import ResolutionCandidate, ResolutionRequest, ResolutionResult, ResolverDiagnosticEvent, candidate_from_document_bytes, result_from_candidates


@dataclass
class HTTPGatewayResolver:
    """Resolve manifest documents via HTTP(S) URL templates and hints."""

    url_templates: list[str] = field(default_factory=list)
    timeout_seconds: float = 5.0
    user_agent: str = "oprow-reference-sdk/0.4"
    name: str = "http_gateway"

    def _format_template(self, template: str, request: ResolutionRequest) -> str:
        loc = request.locator
        variables = {
            "manifest_key": quote(loc.value.to_hex() if isinstance(loc.value, ManifestKey) else ""),
            "short_id": quote(loc.value.to_hex() if isinstance(loc.value, ShortId) else ""),
            "locator_hex": quote(loc.value.to_hex()),
            "mode": quote(loc.mode.value),
        }
        return template.format(**variables)

    def _urls_from_hints(self, request: ResolutionRequest) -> list[str]:
        out: list[str] = []
        for hint in request.storage_hints:
            typ = hint.hint_type.value if isinstance(hint.hint_type, StorageHintType) else str(hint.hint_type)
            if typ == StorageHintType.HTTP.value or hint.uri.startswith("http://") or hint.uri.startswith("https://"):
                out.append(hint.uri)
        return out

    def _candidate_urls(self, request: ResolutionRequest) -> list[str]:
        urls = [self._format_template(t, request) for t in self.url_templates]
        urls.extend(self._urls_from_hints(request))
        seen: set[str] = set()
        out: list[str] = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                out.append(u)
        return out

    def _fetch(self, url: str, max_bytes: int) -> bytes:
        req = Request(url, headers={"User-Agent": self.user_agent})
        with urlopen(req, timeout=self.timeout_seconds) as response:  # nosec - user-configured resolver URL
            chunks: list[bytes] = []
            total = 0
            while True:
                block = response.read(min(65536, max_bytes + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
                if total > max_bytes:
                    raise ValueError(f"HTTP response exceeds max_bytes ({total} > {max_bytes})")
            return b"".join(chunks)

    def resolve(self, request: ResolutionRequest) -> ResolutionResult:
        if not request.allow_network:
            return ResolutionResult.unsupported(self.name, "network resolution disabled by request")
        diagnostics: list[ResolverDiagnosticEvent] = []
        candidates: list[ResolutionCandidate] = []
        for url in self._candidate_urls(request):
            if len(candidates) >= request.max_candidates:
                diagnostics.append(ResolverDiagnosticEvent(self.name, "candidate_cap", data={"max_candidates": request.max_candidates}))
                break
            try:
                raw = self._fetch(url, request.max_bytes)
                candidates.append(candidate_from_document_bytes(raw, request_locator=request.locator, source=f"http:{url}"))
            except (HTTPError, URLError, TimeoutError, OSError, ValueError, Exception) as exc:
                diagnostics.append(ResolverDiagnosticEvent(self.name, "fetch_or_decode_failed", str(exc), {"url": url}))
        if not candidates:
            return ResolutionResult.not_found(self.name, "no HTTP gateway returned a matching manifest")
        return result_from_candidates(self.name, candidates, diagnostics)
