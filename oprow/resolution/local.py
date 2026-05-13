"""Local path and sidecar resolvers.

A local filename is a retrieval hint, not a trust root.  The bytes must still
parse as a manifest/envelope and match the recovered locator.  This file supports
explicit local-path hints, sidecars next to the artifact, and locator-named files
inside configured search directories.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote, urlparse

from oprow.core.enums import StorageHintType
from oprow.core.models import StorageHint
from .base import ResolutionCandidate, ResolutionRequest, ResolutionResult, ResolverDiagnosticEvent, candidate_from_document_bytes, read_limited_file, result_from_candidates


_LOCAL_HINT_TYPES = {StorageHintType.LOCAL_PATH.value, StorageHintType.SIDECAR.value, "file", "path"}


@dataclass
class LocalPathResolver:
    """Resolve manifests from sidecar files and local search directories."""

    search_dirs: list[Path | str] = field(default_factory=list)
    sidecar_suffixes: tuple[str, ...] = (".oprow", ".oprow.cbor", ".oprow-manifest", ".oprow-manifest.cbor")
    name: str = "local_path"

    def __post_init__(self) -> None:
        self.search_dirs = [Path(p) for p in self.search_dirs]

    def _path_from_hint(self, hint: StorageHint) -> Path | None:
        typ = hint.hint_type.value if isinstance(hint.hint_type, StorageHintType) else str(hint.hint_type)
        if typ not in _LOCAL_HINT_TYPES:
            return None
        parsed = urlparse(hint.uri)
        if parsed.scheme == "file":
            return Path(unquote(parsed.path))
        if parsed.scheme == "":
            return Path(hint.uri)
        return None

    def _paths_from_hints(self, request: ResolutionRequest) -> list[Path]:
        return [p for h in request.storage_hints if (p := self._path_from_hint(h)) is not None]

    def _sidecar_paths(self, request: ResolutionRequest) -> list[Path]:
        if request.artifact is None or request.artifact.path is None:
            return []
        base = Path(request.artifact.path)
        return [Path(str(base) + suffix) for suffix in self.sidecar_suffixes]

    def _locator_paths(self, request: ResolutionRequest) -> list[Path]:
        h = request.locator.value.to_hex()
        names = [f"{h}.oprow.cbor", f"{h}.oprow", f"{h}.cbor", h]
        out: list[Path] = []
        for root in self.search_dirs:
            for name in names:
                out.append(root / name)
            if len(h) > 4:
                out.append(root / h[:2] / f"{h}.oprow.cbor")
        return out

    def _all_paths(self, request: ResolutionRequest) -> list[Path]:
        seen: set[Path] = set()
        out: list[Path] = []
        for p in [*self._paths_from_hints(request), *self._sidecar_paths(request), *self._locator_paths(request)]:
            p = p.expanduser()
            if p not in seen:
                seen.add(p)
                out.append(p)
        return out

    def resolve(self, request: ResolutionRequest) -> ResolutionResult:
        diagnostics: list[ResolverDiagnosticEvent] = []
        candidates: list[ResolutionCandidate] = []
        for path in self._all_paths(request):
            if len(candidates) >= request.max_candidates:
                diagnostics.append(ResolverDiagnosticEvent(self.name, "candidate_cap", data={"max_candidates": request.max_candidates}))
                break
            if not path.exists() or not path.is_file():
                continue
            try:
                raw = read_limited_file(path, request.max_bytes)
                candidates.append(candidate_from_document_bytes(raw, request_locator=request.locator, source=f"file:{path}"))
            except Exception as exc:
                diagnostics.append(ResolverDiagnosticEvent(self.name, "read_or_decode_failed", str(exc), {"path": str(path)}))
        if not candidates:
            return ResolutionResult.not_found(self.name, "no matching local files or sidecars")
        return result_from_candidates(self.name, candidates, diagnostics)
