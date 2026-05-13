"""Content-addressed storage (CAS) helpers and resolver.

In FULL160 mode, the watermark carries ``H160(canonical_cbor(SignedManifest))``.
A CAS node does not need to be trusted for integrity: if it serves different
bytes, locator self-consistency fails.  CAS still does not solve availability;
someone must store/pin/cache the manifest bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Protocol

from oprow.core.enums import PointerMode, StorageHintType
from oprow.core.errors import ValidationError
from oprow.core.identifiers import ManifestKey
from oprow.core.models import ManifestEnvelope, SignedManifest, StorageHint
from oprow.manifest.codec import signed_manifest_to_bytes
from .base import ResolutionCandidate, ResolutionRequest, ResolutionResult, ResolverDiagnosticEvent, candidate_from_document_bytes, result_from_candidates


class CASStore(Protocol):
    """Minimal content-addressed store protocol."""

    name: str
    def put_bytes(self, data: bytes) -> ManifestKey: ...
    def get_bytes(self, key: ManifestKey) -> bytes | None: ...


@dataclass
class MemoryCAS:
    """In-memory CAS for tests and local prototypes."""

    name: str = "memory_cas"
    _items: dict[ManifestKey, bytes] = field(default_factory=dict)

    def put_bytes(self, data: bytes) -> ManifestKey:
        key = ManifestKey.from_manifest_bytes(data)
        self._items[key] = bytes(data)
        return key

    def put_manifest(self, manifest: SignedManifest) -> ManifestKey:
        data = signed_manifest_to_bytes(manifest)
        key = self.put_bytes(data)
        if key != manifest.manifest_key():
            raise ValidationError("CAS key mismatch for manifest")
        return key

    def put_envelope(self, envelope: ManifestEnvelope) -> ManifestKey:
        return self.put_manifest(envelope.manifest)

    def get_bytes(self, key: ManifestKey) -> bytes | None:
        return self._items.get(key)


@dataclass
class FileCAS:
    """Tiny file-backed CAS with two-character directory fanout."""

    root: Path | str
    name: str = "file_cas"

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)

    def path_for_key(self, key: ManifestKey) -> Path:
        h = key.to_hex()
        return self.root / h[:2] / f"{h}.oprow.cbor"

    def put_bytes(self, data: bytes) -> ManifestKey:
        key = ManifestKey.from_manifest_bytes(data)
        path = self.path_for_key(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bytes(data))
        return key

    def put_manifest(self, manifest: SignedManifest) -> ManifestKey:
        data = signed_manifest_to_bytes(manifest)
        key = self.put_bytes(data)
        if key != manifest.manifest_key():
            raise ValidationError("CAS key mismatch for manifest")
        return key

    def get_bytes(self, key: ManifestKey) -> bytes | None:
        path = self.path_for_key(key)
        return path.read_bytes() if path.exists() else None

    def storage_hint_for_manifest(self, manifest: SignedManifest) -> StorageHint:
        key = manifest.manifest_key()
        return StorageHint(hint_type=StorageHintType.LOCAL_PATH, uri=str(self.path_for_key(key)))


@dataclass
class CASResolver:
    """Resolve FULL160 manifests from one or more CAS stores."""

    stores: list[CASStore]
    name: str = "cas"

    def __init__(self, stores: Iterable[CASStore] | None = None, *, name: str = "cas"):
        self.stores = list(stores or [])
        self.name = name

    def resolve(self, request: ResolutionRequest) -> ResolutionResult:
        if request.locator.mode not in (PointerMode.FULL160, PointerMode.FULL160_RATELESS):
            return ResolutionResult.unsupported(self.name, f"CASResolver handles FULL160-like locators, not {request.locator.mode.value}")
        key = request.locator.value
        if not isinstance(key, ManifestKey):
            return ResolutionResult.unsupported(self.name, "locator value is not a ManifestKey")

        diagnostics: list[ResolverDiagnosticEvent] = []
        candidates: list[ResolutionCandidate] = []
        for store in self.stores:
            if len(candidates) >= request.max_candidates:
                diagnostics.append(ResolverDiagnosticEvent(self.name, "candidate_cap", data={"max_candidates": request.max_candidates}))
                break
            try:
                raw = store.get_bytes(key)
            except Exception as exc:
                diagnostics.append(ResolverDiagnosticEvent(self.name, "store_error", str(exc), {"store": getattr(store, "name", store.__class__.__name__)}))
                continue
            if raw is None:
                diagnostics.append(ResolverDiagnosticEvent(self.name, "miss", data={"store": getattr(store, "name", store.__class__.__name__)}))
                continue
            if len(raw) > request.max_bytes:
                diagnostics.append(ResolverDiagnosticEvent(self.name, "too_large", data={"bytes": len(raw)}))
                continue
            try:
                candidates.append(candidate_from_document_bytes(raw, request_locator=request.locator, source=f"cas:{getattr(store, 'name', store.__class__.__name__)}"))
            except Exception as exc:
                diagnostics.append(ResolverDiagnosticEvent(self.name, "decode_failed", str(exc), {"store": getattr(store, "name", store.__class__.__name__)}))
        if not candidates:
            return ResolutionResult.not_found(self.name, "CAS stores did not return a matching manifest")
        return result_from_candidates(self.name, candidates, diagnostics)
