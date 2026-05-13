"""Plain SHORT64 index data models for OProW Step 7.

OProW's FULL160 pointer mode embeds a 20-byte content-addressed manifest key:

    H160(canonical_cbor(SignedManifest))

That gives strong substitution resistance, but it can be too large for hostile
watermark channels after headers, synchronization, repetition, and ECC.  SHORT64
is the fallback: embed only an 8-byte routing key.  The price is ambiguity.  A
64-bit value must not be treated as a global proof of identity; it is only an
index key that returns *candidate* manifests.

The default Step 7 derivation is self-checkable:

    short_id = Trunc64(H256(canonical_cbor(SignedManifest)))

After lookup, every candidate must still pass locator self-consistency,
signature verification, essence/content binding, and local trust policy.  Later
steps add HDC routing, authenticated map proofs, privacy profiles, and ASI:chain
anchoring.  This file deliberately implements only the plain, non-HDC layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from oprow.core.canonical import canonical_cbor_dumps, canonical_cbor_loads
from oprow.core.enums import HashAlgorithm
from oprow.core.errors import ValidationError
from oprow.core.identifiers import Hash256, ManifestKey, NamespaceId, ShortId
from oprow.core.models import SignedManifest, StorageHint
from oprow.manifest.codec import signed_manifest_to_bytes

HASH_TRUNCATED_DERIVATION = "hash_truncated"
NAMESPACED_REGISTRY_DERIVATION = "namespaced_registry"
SUPPORTED_SHORT64_DERIVATIONS = {HASH_TRUNCATED_DERIVATION, NAMESPACED_REGISTRY_DERIVATION}


def _drop_absent(m: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in m.items() if v is not None and v != [] and v != {}}


def _parse_datetime(value: Any, label: str) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValidationError(f"{label} must be UTC RFC3339 text ending in Z")
    body = value[:-1]
    try:
        if "." in body:
            dt = datetime.strptime(body, "%Y-%m-%dT%H:%M:%S.%f")
        else:
            dt = datetime.strptime(body, "%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise ValidationError(f"invalid datetime for {label}: {value!r}") from exc
    return dt.replace(tzinfo=timezone.utc)


def make_namespaced_short_id(namespace_id: NamespaceId, local_id: int | bytes | bytearray | memoryview, *, total_bytes: int = 8) -> ShortId:
    """Construct an experimental namespace-assigned SHORT64 value.

    Layout::

        short_id = namespace_id || local_artifact_id

    This is useful for future registry-assigned IDs, where a namespace owner can
    avoid collisions inside its namespace.  Step 7 does not yet treat this as a
    self-verifying pointer; authenticated index/namespace evidence is deferred.
    """
    ns = bytes(namespace_id)
    if len(ns) >= total_bytes:
        raise ValidationError("namespace_id leaves no room for local artifact id")
    local_len = total_bytes - len(ns)
    if isinstance(local_id, int):
        if local_id < 0 or local_id >= (1 << (8 * local_len)):
            raise ValidationError(f"local_id integer does not fit in {local_len} bytes")
        local = local_id.to_bytes(local_len, "big")
    else:
        raw = bytes(local_id)
        if len(raw) > local_len:
            raise ValidationError(f"local_id bytes exceed {local_len} bytes")
        local = raw.rjust(local_len, b"\x00")
    return ShortId(ns + local)


@dataclass(frozen=True)
class Short64IndexReference:
    """One row in a plain SHORT64 index bucket.

    The row can inline a canonical manifest/envelope document, or it can carry a
    FULL160 ``manifest_key`` plus storage hints so a backing resolver can fetch
    the document.  Either way, this record is a retrieval hint rather than trust
    evidence.  A malicious index can map a short ID to the wrong manifest; the
    resolver/verifier must catch that by recomputing the short ID from returned
    manifest bytes.
    """

    short_id: ShortId
    manifest_key: ManifestKey | None = None
    manifest_hash: Hash256 | None = None
    document_bytes: bytes | None = None
    storage_hints: list[StorageHint] = field(default_factory=list)
    namespace_id: NamespaceId | None = None
    derivation_profile: str = HASH_TRUNCATED_DERIVATION
    created_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.derivation_profile not in SUPPORTED_SHORT64_DERIVATIONS:
            raise ValidationError(f"unsupported SHORT64 derivation profile: {self.derivation_profile!r}")
        if self.document_bytes is None and self.manifest_key is None and not self.storage_hints:
            raise ValidationError("Short64IndexReference requires document_bytes, manifest_key, or storage_hints")
        if self.document_bytes is not None and not isinstance(self.document_bytes, bytes):
            object.__setattr__(self, "document_bytes", bytes(self.document_bytes))

    @classmethod
    def from_signed_manifest(
        cls,
        manifest: SignedManifest,
        *,
        include_document_bytes: bool = True,
        storage_hints: Iterable[StorageHint] | None = None,
        created_at: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
        hash_alg: str | HashAlgorithm = HashAlgorithm.SHA256,
    ) -> "Short64IndexReference":
        data = signed_manifest_to_bytes(manifest) if include_document_bytes else None
        canonical = manifest.canonical_bytes()
        return cls(
            short_id=manifest.short_id_hash_truncated(hash_alg),
            manifest_key=manifest.manifest_key(hash_alg),
            manifest_hash=manifest.manifest_hash(hash_alg),
            document_bytes=data,
            storage_hints=list(storage_hints or []),
            derivation_profile=HASH_TRUNCATED_DERIVATION,
            created_at=created_at,
            metadata=dict(metadata or {}),
        )

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({
            "short_id": self.short_id,
            "manifest_key": self.manifest_key,
            "manifest_hash": self.manifest_hash,
            "document_bytes": self.document_bytes,
            "storage_hints": self.storage_hints,
            "namespace_id": self.namespace_id,
            "derivation_profile": self.derivation_profile,
            "created_at": self.created_at,
            "metadata": self.metadata,
        })


@dataclass(frozen=True)
class Short64LookupResult:
    """Output of a short-ID lookup before provenance verification."""

    short_id: ShortId
    references: list[Short64IndexReference] = field(default_factory=list)
    complete: bool = True
    total_available: int | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)

    @property
    def found(self) -> bool:
        return bool(self.references)

    @property
    def candidate_count(self) -> int:
        return len(self.references)


@dataclass(frozen=True)
class Short64IndexSnapshot:
    """Canonical full snapshot used by the simple file-backed index.

    This is not an authenticated map.  It is merely deterministic storage for
    Step 7.  Step 9 can Merkleize or replace this representation.
    """

    version: int
    records: list[Short64IndexReference]
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.version <= 0:
            raise ValidationError("Short64IndexSnapshot.version must be positive")

    def to_canonical(self) -> dict[str, Any]:
        records = sorted(
            self.records,
            key=lambda r: (r.short_id.value, r.manifest_key.value if r.manifest_key else b"", r.document_bytes or b""),
        )
        return _drop_absent({"version": self.version, "records": records, "metadata": self.metadata})

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)


def _storage_hint_from_primitive(value: Any) -> StorageHint:
    from oprow.manifest.codec import storage_hint_from_primitive
    return storage_hint_from_primitive(value)


def short64_reference_from_primitive(value: Any) -> Short64IndexReference:
    if not isinstance(value, Mapping):
        raise ValidationError("Short64IndexReference primitive must be a map")
    sid = value.get("short_id")
    if not isinstance(sid, bytes):
        raise ValidationError("short_id must be bytes")
    raw_key = value.get("manifest_key")
    raw_hash = value.get("manifest_hash")
    raw_ns = value.get("namespace_id")
    hints = value.get("storage_hints", [])
    if not isinstance(hints, list):
        raise ValidationError("storage_hints must be a list")
    doc = value.get("document_bytes")
    if doc is not None and not isinstance(doc, bytes):
        raise ValidationError("document_bytes must be bytes")
    metadata = value.get("metadata", {})
    if not isinstance(metadata, Mapping):
        raise ValidationError("metadata must be a map")
    return Short64IndexReference(
        short_id=ShortId(sid),
        manifest_key=ManifestKey(raw_key) if raw_key is not None else None,
        manifest_hash=Hash256(raw_hash) if raw_hash is not None else None,
        document_bytes=doc,
        storage_hints=[_storage_hint_from_primitive(x) for x in hints],
        namespace_id=NamespaceId(raw_ns) if raw_ns is not None else None,
        derivation_profile=str(value.get("derivation_profile", HASH_TRUNCATED_DERIVATION)),
        created_at=_parse_datetime(value.get("created_at"), "created_at"),
        metadata=dict(metadata),
    )


def short64_snapshot_from_bytes(data: bytes, *, require_canonical: bool = True) -> Short64IndexSnapshot:
    primitive = canonical_cbor_loads(data, require_canonical=require_canonical)
    if not isinstance(primitive, Mapping):
        raise ValidationError("Short64IndexSnapshot must decode to a map")
    records = primitive.get("records", [])
    if not isinstance(records, list):
        raise ValidationError("records must be a list")
    metadata = primitive.get("metadata", {})
    if not isinstance(metadata, Mapping):
        raise ValidationError("metadata must be a map")
    return Short64IndexSnapshot(
        version=int(primitive.get("version", 1)),
        records=[short64_reference_from_primitive(x) for x in records],
        metadata=dict(metadata),
    )
