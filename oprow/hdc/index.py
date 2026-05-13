"""Unauthenticated SHORT64-HV route index for Step 8.

This file intentionally implements only the *routing* part of SHORT64-HV.  It is
an in-memory index mapping opaque HDC route keys to candidate manifest
references.  It does not prove completeness, does not anchor roots, and does not
protect query privacy.  Those are the subjects of Steps 9 and 10.

Security model
==============

The index is untrusted.  It may omit candidates or return malicious candidates.
That is acceptable because the verifier treats it only as candidate discovery:

    route key -> candidate manifest references -> full OProW verification

A route hit never means the media is verified.  It means only that the candidate
manifest is worth fetching and checking against the recovered short ID,
signatures, essence hash, and trust policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable, Protocol

from oprow.core.identifiers import Hash256, NamespaceId, ShortId
from oprow.core.models import SignedManifest, StorageHint
from oprow.short64 import HASH_TRUNCATED_DERIVATION, Short64IndexReference
from oprow.manifest.codec import signed_manifest_to_bytes
from oprow.core.models import Artifact

from .encoders import HDCEncoder, HDCEncoding
from .profiles import DEFAULT_HDC_EPOCH
from .routing import RoutePrecision, RouteToken, RouteTokenSet, derive_route_tokens


@dataclass(frozen=True)
class Short64HVIndexedManifest:
    """Diagnostic record returned when adding a manifest to the route index."""

    reference: Short64IndexReference
    route_tokens: RouteTokenSet
    hdc_encoding: HDCEncoding


@dataclass(frozen=True)
class Short64HVLookupResult:
    """Candidate references discovered by querying several route tokens."""

    route_tokens: list[RouteToken]
    references: list[Short64IndexReference]
    route_hit_counts: dict[str, int] = field(default_factory=dict)
    complete: bool = True
    total_available: int | None = None
    diagnostics: dict[str, object] = field(default_factory=dict)

    @property
    def found(self) -> bool:
        return bool(self.references)

    @property
    def candidate_count(self) -> int:
        return len(self.references)


class Short64HVRouteIndex(Protocol):
    """Protocol for Step 8 route indices."""

    name: str

    def add_reference(self, reference: Short64IndexReference, tokens: Iterable[RouteToken]) -> None:
        ...

    def lookup(self, tokens: Iterable[RouteToken], *, max_results: int | None = None) -> Short64HVLookupResult:
        ...


class MemoryShort64HVRouteIndex:
    """Simple in-memory route-key -> candidate-reference multimap.

    Candidate sets are deduplicated by manifest key where possible.  The index
    also reports how many route tokens hit each candidate; resolvers can use that
    as a ranking diagnostic, but it is not a trust signal.
    """

    def __init__(self, *, name: str = "memory-short64-hv-index"):
        self.name = name
        self._by_route_key: dict[Hash256, list[Short64IndexReference]] = {}

    def add_reference(self, reference: Short64IndexReference, tokens: Iterable[RouteToken]) -> None:
        for token in tokens:
            bucket = self._by_route_key.setdefault(token.route_key, [])
            if not any(_reference_key(r) == _reference_key(reference) for r in bucket):
                bucket.append(reference)

    def add_manifest(
        self,
        manifest: SignedManifest,
        artifact: Artifact,
        *,
        encoder: HDCEncoder,
        include_document_bytes: bool = True,
        namespace_id: NamespaceId | None = None,
        storage_hints: Iterable[StorageHint] | None = None,
        epoch_id: str = DEFAULT_HDC_EPOCH,
        precision: RoutePrecision | None = None,
        created_at: datetime | None = None,
        metadata: dict[str, object] | None = None,
    ) -> Short64HVIndexedManifest:
        """Compute HDC route tokens and insert a manifest reference.

        The indexer needs the original artifact or a trusted cached PED/HDC
        descriptor.  In this draft we recompute from the artifact to keep the
        data path obvious.
        """
        encoding = encoder.encode_artifact(artifact)
        short_id = manifest.short_id_hash_truncated()
        token_set = derive_route_tokens(
            short_id=short_id,
            encoding=encoding,
            namespace_id=namespace_id,
            epoch_id=epoch_id,
            precision=precision,
        )
        ref = Short64IndexReference(
            short_id=short_id,
            manifest_key=manifest.manifest_key(),
            manifest_hash=manifest.manifest_hash(),
            document_bytes=signed_manifest_to_bytes(manifest) if include_document_bytes else None,
            storage_hints=list(storage_hints or []),
            namespace_id=namespace_id,
            derivation_profile=HASH_TRUNCATED_DERIVATION,
            created_at=created_at,
            metadata={
                "short64_hv_profile_id": encoding.profile.profile_id,
                "hdc_ped_alg_id": encoding.ped_alg_id,
                "hdc_ped_hash": encoding.ped_hash.to_hex(),
                **dict(metadata or {}),
            },
        )
        self.add_reference(ref, token_set.tokens)
        return Short64HVIndexedManifest(reference=ref, route_tokens=token_set, hdc_encoding=encoding)

    def lookup(self, tokens: Iterable[RouteToken], *, max_results: int | None = None) -> Short64HVLookupResult:
        token_list = list(tokens)
        hit_counts: dict[str, int] = {}
        by_key: dict[str, Short64IndexReference] = {}
        total_hits = 0
        for token in token_list:
            bucket = self._by_route_key.get(token.route_key, [])
            total_hits += len(bucket)
            for ref in bucket:
                key = _reference_key(ref)
                by_key.setdefault(key, ref)
                hit_counts[key] = hit_counts.get(key, 0) + 1
        ordered = sorted(by_key.values(), key=lambda r: (-hit_counts[_reference_key(r)], _reference_key(r)))
        total_available = len(ordered)
        complete = True
        if max_results is not None and len(ordered) > max_results:
            ordered = ordered[:max_results]
            complete = False
        return Short64HVLookupResult(
            route_tokens=token_list,
            references=ordered,
            route_hit_counts=hit_counts,
            complete=complete,
            total_available=total_available,
            diagnostics={"route_tokens": len(token_list), "raw_bucket_hits": total_hits, "unique_candidates": total_available},
        )


def _reference_key(ref: Short64IndexReference) -> str:
    if ref.manifest_key is not None:
        return "mk:" + ref.manifest_key.to_hex()
    if ref.document_bytes is not None:
        # A non-cryptographic fallback key is fine for in-memory deduplication;
        # final verification still hashes canonical manifest bytes.
        return "doc:" + str(hash(ref.document_bytes))
    return "sid:" + ref.short_id.to_hex()


# ---------------------------------------------------------------------------
# Compatibility/convenience API for the Step 8 resolver.
# ---------------------------------------------------------------------------
from oprow.short64.models import Short64LookupResult
from .profiles import HDCProfile, default_hdc_profile
from .encoders import SymbolicBundlingHDCEncoder


class Short64HVIndex(Protocol):
    """Protocol consumed by the Step 8 ``Short64HVRouteResolver``."""

    name: str
    profile: HDCProfile

    def lookup_tokens(
        self,
        route_tokens: list[RouteToken],
        *,
        short_id: ShortId | None = None,
        namespace_id: NamespaceId | None = None,
        min_token_matches: int = 1,
        max_results: int | None = None,
    ) -> Short64LookupResult:
        ...


class MemoryShort64HVIndex(MemoryShort64HVRouteIndex):
    """Profile-aware wrapper around ``MemoryShort64HVRouteIndex``.

    The original Step 8 route index stores opaque route-key buckets.  This wrapper
    supplies a configured HDC profile and a ``lookup_tokens`` method whose return
    type mirrors the Step 7 ``Short64LookupResult``.  That lets the resolver share
    most of the Step 7 candidate-handling logic.
    """

    def __init__(self, profile: HDCProfile | None = None, *, name: str = "memory-short64-hv-index"):
        super().__init__(name=name)
        self.profile = profile or default_hdc_profile()

    def add_manifest(
        self,
        manifest: SignedManifest,
        *,
        artifact: Artifact,
        encoder: HDCEncoder | None = None,
        include_document_bytes: bool = True,
        namespace_id: NamespaceId | None = None,
        storage_hints: Iterable[StorageHint] | None = None,
        epoch_id: str = DEFAULT_HDC_EPOCH,
        precision: RoutePrecision | None = None,
        created_at: datetime | None = None,
        metadata: dict[str, object] | None = None,
    ) -> Short64IndexReference:
        enc = encoder or SymbolicBundlingHDCEncoder(self.profile)
        indexed = super().add_manifest(
            manifest,
            artifact,
            encoder=enc,
            include_document_bytes=include_document_bytes,
            namespace_id=namespace_id,
            storage_hints=storage_hints,
            epoch_id=epoch_id,
            precision=precision,
            created_at=created_at,
            metadata=metadata,
        )
        return indexed.reference

    def lookup_tokens(
        self,
        route_tokens: list[RouteToken],
        *,
        short_id: ShortId | None = None,
        namespace_id: NamespaceId | None = None,
        min_token_matches: int = 1,
        max_results: int | None = None,
    ) -> Short64LookupResult:
        if min_token_matches <= 0:
            raise ValueError("min_token_matches must be positive")
        raw = super().lookup(route_tokens, max_results=None)
        refs: list[Short64IndexReference] = []
        for ref in raw.references:
            if short_id is not None and ref.short_id != short_id:
                continue
            if namespace_id is not None and ref.namespace_id != namespace_id:
                continue
            key = _reference_key(ref)
            if raw.route_hit_counts.get(key, 0) < min_token_matches:
                continue
            refs.append(ref)
        total_available = len(refs)
        complete = True
        if max_results is not None and len(refs) > max_results:
            refs = refs[:max_results]
            complete = False
        result_sid = short_id if short_id is not None else (refs[0].short_id if refs else ShortId(b"\x00" * 8))
        return Short64LookupResult(
            short_id=result_sid,
            references=refs,
            complete=complete,
            total_available=total_available,
            diagnostics={
                **raw.diagnostics,
                "hdc_profile_id": self.profile.profile_id,
                "min_token_matches": min_token_matches,
                "route_hit_counts": raw.route_hit_counts,
            },
        )

    def route_key_count(self) -> int:
        return len(self._by_route_key)

    def public_route_keys(self) -> list[Hash256]:
        """Return opaque route keys for cover-query sampling.

        This Step 10 helper exposes only committed route-key hashes.  It does not
        expose raw PEDs, raw hypervectors, media bytes, or query logs.
        """
        return sorted(self._by_route_key.keys(), key=lambda k: k.value)

    def route_keys(self) -> list[Hash256]:
        """Alias for ``public_route_keys`` used by privacy samplers."""
        return self.public_route_keys()


def build_short64_hv_index(
    manifests_and_artifacts: Iterable[tuple[SignedManifest, Artifact]],
    *,
    profile: HDCProfile | None = None,
    include_document_bytes: bool = True,
) -> MemoryShort64HVIndex:
    idx = MemoryShort64HVIndex(profile=profile or default_hdc_profile())
    for manifest, artifact in manifests_and_artifacts:
        idx.add_manifest(manifest, artifact=artifact, include_document_bytes=include_document_bytes)
    return idx
