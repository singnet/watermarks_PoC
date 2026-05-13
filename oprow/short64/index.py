"""Plain non-HDC SHORT64 index stores.

The data structure is intentionally simple: ``ShortId -> list[references]``.
The list is important.  At scale a 64-bit identifier can collide, and a malicious
index can also flood a bucket.  The resolver and verifier should see that
ambiguity instead of silently replacing older rows with newer rows.

This Step 7 module does not prove completeness.  A public resolver may omit
records.  Step 9 will introduce authenticated maps so a resolver can prove the
complete candidate set for a key.  Until then, this index is a reference/local
prototype and an input to the richer verification pipeline.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Protocol

from oprow.core.errors import ValidationError
from oprow.core.identifiers import NamespaceId, ShortId
from oprow.core.models import SignedManifest, StorageHint
from .models import (
    HASH_TRUNCATED_DERIVATION,
    Short64IndexReference,
    Short64IndexSnapshot,
    Short64LookupResult,
    short64_snapshot_from_bytes,
)


class Short64Index(Protocol):
    """Minimal protocol consumed by ``Short64IndexResolver``."""

    name: str

    def lookup(
        self,
        short_id: ShortId,
        *,
        namespace_id: NamespaceId | None = None,
        derivation_profile: str | None = None,
        max_results: int | None = None,
    ) -> Short64LookupResult:
        ...


@dataclass
class MemoryShort64Index:
    """Mutable in-memory SHORT64 index for tests, demos, and local caches."""

    name: str = "memory_short64_index"
    metadata: dict[str, object] = field(default_factory=dict)
    _records: dict[ShortId, list[Short64IndexReference]] = field(default_factory=lambda: defaultdict(list))

    def add_reference(self, reference: Short64IndexReference) -> None:
        bucket = self._records.setdefault(reference.short_id, [])
        key = self._dedupe_key(reference)
        if any(self._dedupe_key(existing) == key for existing in bucket):
            return
        bucket.append(reference)

    def add_manifest(
        self,
        manifest: SignedManifest,
        *,
        include_document_bytes: bool = True,
        storage_hints: list[StorageHint] | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> Short64IndexReference:
        ref = Short64IndexReference.from_signed_manifest(
            manifest,
            include_document_bytes=include_document_bytes,
            storage_hints=storage_hints or [],
            metadata=dict(metadata or {}),
        )
        self.add_reference(ref)
        return ref

    def lookup(
        self,
        short_id: ShortId,
        *,
        namespace_id: NamespaceId | None = None,
        derivation_profile: str | None = None,
        max_results: int | None = None,
    ) -> Short64LookupResult:
        if max_results is not None and max_results <= 0:
            raise ValidationError("max_results must be positive")
        refs = list(self._records.get(short_id, []))
        if namespace_id is not None:
            refs = [r for r in refs if r.namespace_id == namespace_id]
        if derivation_profile is not None:
            refs = [r for r in refs if r.derivation_profile == derivation_profile]
        total = len(refs)
        complete = True
        if max_results is not None and len(refs) > max_results:
            refs = refs[:max_results]
            complete = False
        return Short64LookupResult(
            short_id=short_id,
            references=refs,
            complete=complete,
            total_available=total,
            diagnostics={"index": self.name},
        )

    def to_snapshot(self) -> Short64IndexSnapshot:
        return Short64IndexSnapshot(version=1, records=[r for bucket in self._records.values() for r in bucket], metadata=dict(self.metadata))

    def to_snapshot_bytes(self) -> bytes:
        return self.to_snapshot().canonical_bytes()

    @classmethod
    def from_snapshot(cls, snapshot: Short64IndexSnapshot, *, name: str = "memory_short64_index") -> "MemoryShort64Index":
        idx = cls(name=name, metadata=dict(snapshot.metadata))
        for ref in snapshot.records:
            idx.add_reference(ref)
        return idx

    @classmethod
    def from_snapshot_bytes(cls, data: bytes, *, name: str = "memory_short64_index") -> "MemoryShort64Index":
        return cls.from_snapshot(short64_snapshot_from_bytes(data), name=name)

    @staticmethod
    def _dedupe_key(reference: Short64IndexReference) -> tuple[bytes, bytes, str]:
        return (
            reference.manifest_key.value if reference.manifest_key else b"",
            reference.document_bytes or b"",
            reference.derivation_profile,
        )


@dataclass
class FileShort64Index:
    """Tiny file-backed full-snapshot index.

    This is not a concurrent database.  It exists so examples and downstream
    coding agents can persist a Step 7 index between runs.  Production indexers
    should replace it with a real database and, eventually, authenticated maps.
    """

    path: Path | str
    name: str = "file_short64_index"

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if not self.path.exists():
            self._write_memory(MemoryShort64Index(name=self.name))

    def _read_memory(self) -> MemoryShort64Index:
        return MemoryShort64Index.from_snapshot_bytes(self.path.read_bytes(), name=self.name)

    def _write_memory(self, memory: MemoryShort64Index) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_bytes(memory.to_snapshot_bytes())
        tmp.replace(self.path)

    def add_reference(self, reference: Short64IndexReference) -> None:
        memory = self._read_memory()
        memory.add_reference(reference)
        self._write_memory(memory)

    def add_manifest(self, manifest: SignedManifest, *, include_document_bytes: bool = True, storage_hints: list[StorageHint] | None = None, metadata: Mapping[str, object] | None = None) -> Short64IndexReference:
        ref = Short64IndexReference.from_signed_manifest(manifest, include_document_bytes=include_document_bytes, storage_hints=storage_hints or [], metadata=dict(metadata or {}))
        self.add_reference(ref)
        return ref

    def lookup(self, short_id: ShortId, *, namespace_id: NamespaceId | None = None, derivation_profile: str | None = None, max_results: int | None = None) -> Short64LookupResult:
        return self._read_memory().lookup(short_id, namespace_id=namespace_id, derivation_profile=derivation_profile, max_results=max_results)


def build_hash_truncated_short64_index(manifests: list[SignedManifest], *, include_document_bytes: bool = True) -> MemoryShort64Index:
    idx = MemoryShort64Index()
    for manifest in manifests:
        idx.add_manifest(manifest, include_document_bytes=include_document_bytes, metadata={"profile": HASH_TRUNCATED_DERIVATION})
    return idx
