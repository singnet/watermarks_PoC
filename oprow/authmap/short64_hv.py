"""Authenticated SHORT64-HV route-index layer for OProW Step 9.

Step 8 introduced SHORT64-HV routing:

    short watermark ID + local HDC descriptor -> opaque route keys -> candidates

That made SHORT64 more practical at web scale, but the route index was still a
plain multimap.  This file adds the Step 9 authenticated-map layer.  It commits
each route key to the complete candidate set for that key using the sparse
Merkle map implemented in ``oprow.authmap.sparse_merkle``.

The intended deployment shape is:

* The indexer builds an off-chain map:
      route_key -> canonical candidate set
* The indexer publishes or mirrors the candidate-set data off-chain.
* The indexer anchors only the compact map root through a modular trust backend
  in later steps, for example ASI:chain.
* A verifier queries one or more route keys and receives:
      candidate set + sparse Merkle proof + root record
* The verifier checks proof completeness before fetching/verifying manifests.

Important privacy boundary
==========================

This module does **not** put raw HDC hypervectors, raw PEDs, or live query logs
into the map.  It also does not put anything on-chain.  The map value is a list
of manifest references for a route key.  The future ASI:chain adapter should
anchor only ``AuthenticatedIndexRootRecord`` or a hash of it, not route buckets
or media fingerprints.

Important security boundary
===========================

An authenticated route hit is still only a retrieval result.  It proves that the
candidate set came from a committed index snapshot.  It does not prove the media
is authentic.  Final verification still requires OProW's normal checks:
locator self-consistency, manifest signatures, essence/content binding, and
local trust policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from oprow.core.canonical import canonical_cbor_dumps, canonical_cbor_loads
from oprow.core.errors import ValidationError
from oprow.core.identifiers import Hash256, ManifestKey, NamespaceId, ShortId
from oprow.core.models import Artifact, SignedManifest, StorageHint
from oprow.hdc.encoders import HDCEncoder, HDCEncoding, SymbolicBundlingHDCEncoder
from oprow.hdc.profiles import DEFAULT_HDC_EPOCH, HDCProfile, default_hdc_profile
from oprow.hdc.routing import RoutePrecision, RouteToken, RouteTokenSet, derive_route_tokens
from oprow.manifest.codec import signed_manifest_to_bytes
from oprow.short64.models import HASH_TRUNCATED_DERIVATION, Short64IndexReference, Short64LookupResult, short64_reference_from_primitive

from .sparse_merkle import AuthenticatedMapOpening, SMT_ALG_ID, SparseMerkleMap, SparseMerkleProof


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _drop_absent(m: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in m.items() if v is not None and v != [] and v != {}}


def _reference_key(ref: Short64IndexReference) -> str:
    """Stable-ish deduplication key for candidate references.

    Deduplication is not a security decision; final verification hashes and
    checks the returned manifest bytes.  We prefer the FULL160 manifest key when
    present, then the manifest hash, then the document bytes hash.
    """
    if ref.manifest_key is not None:
        return "mk:" + ref.manifest_key.to_hex()
    if ref.manifest_hash is not None:
        return "mh:" + ref.manifest_hash.to_hex()
    if ref.document_bytes is not None:
        return "doc:" + Hash256.from_data(ref.document_bytes).to_hex()
    return "sid:" + ref.short_id.to_hex()


def _reference_sort_key(ref: Short64IndexReference) -> tuple[bytes, bytes, bytes, str]:
    mk = ref.manifest_key.value if ref.manifest_key is not None else b""
    mh = ref.manifest_hash.value if ref.manifest_hash is not None else b""
    doc_hash = Hash256.from_data(ref.document_bytes).value if ref.document_bytes is not None else b""
    return (ref.short_id.value, mk or mh or doc_hash, bytes(ref.namespace_id) if ref.namespace_id else b"", ref.derivation_profile)


@dataclass(frozen=True)
class RouteCandidateSet:
    """Canonical value stored at one SHORT64-HV route key.

    ``complete=True`` means the reference list is the indexer's complete set for
    this route key at this epoch.  If a production index uses bucket truncation
    or overfull-bucket markers, it should set ``complete=False`` and include
    ``total_available`` so verifiers can downgrade to an ambiguity/DoS status.
    """

    route_key: Hash256
    references: list[Short64IndexReference] = field(default_factory=list)
    complete: bool = True
    total_available: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    version: int = 1

    def __post_init__(self) -> None:
        if self.version <= 0:
            raise ValidationError("RouteCandidateSet.version must be positive")
        if self.total_available is not None and self.total_available < len(self.references):
            raise ValidationError("total_available cannot be smaller than returned reference count")

    def sorted_references(self) -> list[Short64IndexReference]:
        return sorted(self.references, key=_reference_sort_key)

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({
            "version": self.version,
            "route_key": self.route_key,
            "complete": self.complete,
            "total_available": self.total_available,
            "references": self.sorted_references(),
            "metadata": self.metadata,
        })

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    @classmethod
    def from_bytes(cls, data: bytes | bytearray | memoryview) -> "RouteCandidateSet":
        value = canonical_cbor_loads(bytes(data))
        return route_candidate_set_from_primitive(value)


@dataclass(frozen=True)
class AuthenticatedIndexRootRecord:
    """Commitment record for an authenticated SHORT64-HV route index.

    This is the compact object that later trust backends should anchor.  In a
    future ASI:chain integration, a contract event can contain a hash of this
    canonical record or its essential fields: ``index_id``, ``epoch_id``,
    ``root_hash``, ``profile_id``, and entry counts.
    """

    index_id: str
    epoch_id: str
    root_hash: Hash256
    profile_id: str
    map_alg_id: str = SMT_ALG_ID
    route_key_count: int = 0
    candidate_reference_count: int = 0
    created_at: datetime = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)
    version: int = 1

    def to_canonical(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "index_id": self.index_id,
            "epoch_id": self.epoch_id,
            "root_hash": self.root_hash,
            "profile_id": self.profile_id,
            "map_alg_id": self.map_alg_id,
            "route_key_count": self.route_key_count,
            "candidate_reference_count": self.candidate_reference_count,
            "created_at": self.created_at,
            "metadata": self.metadata,
        }

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    def record_hash(self) -> Hash256:
        return Hash256.from_data(self.canonical_bytes())


@dataclass(frozen=True)
class RouteCandidateSetOpening:
    """Typed authenticated opening for a route-key candidate set."""

    route_key: Hash256
    candidate_set: RouteCandidateSet | None
    proof: SparseMerkleProof
    root_record: AuthenticatedIndexRootRecord
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def exists(self) -> bool:
        return self.candidate_set is not None

    @property
    def references(self) -> list[Short64IndexReference]:
        return list(self.candidate_set.references if self.candidate_set is not None else [])

    @property
    def value_bytes(self) -> bytes | None:
        return self.candidate_set.canonical_bytes() if self.candidate_set is not None else None

    def verify(self) -> bool:
        """Verify that this opening is consistent with its root record."""
        if self.proof.key != self.route_key:
            return False
        if self.candidate_set is not None and self.candidate_set.route_key != self.route_key:
            return False
        return self.proof.verify(self.root_record.root_hash, self.value_bytes)

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({
            "route_key": self.route_key,
            "candidate_set": self.candidate_set,
            "proof": self.proof,
            "root_record": self.root_record,
            "metadata": self.metadata,
        })


@dataclass(frozen=True)
class AuthenticatedShort64HVLookupResult:
    """Proof-carrying result for a SHORT64-HV route lookup."""

    route_tokens: list[RouteToken]
    openings: list[RouteCandidateSetOpening]
    references: list[Short64IndexReference]
    root_record: AuthenticatedIndexRootRecord
    route_hit_counts: dict[str, int] = field(default_factory=dict)
    complete: bool = True
    proof_verified: bool = True
    total_available: int | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)

    @property
    def found(self) -> bool:
        return bool(self.references)

    @property
    def candidate_count(self) -> int:
        return len(self.references)

    def to_short64_lookup_result(self, short_id: ShortId | None = None) -> Short64LookupResult:
        result_sid = short_id if short_id is not None else (self.references[0].short_id if self.references else ShortId(b"\x00" * 8))
        return Short64LookupResult(
            short_id=result_sid,
            references=list(self.references),
            complete=self.complete and self.proof_verified,
            total_available=self.total_available,
            diagnostics={
                **self.diagnostics,
                "authenticated_map": True,
                "proof_verified": self.proof_verified,
                "root_hash": self.root_record.root_hash.to_hex(),
                "root_record_hash": self.root_record.record_hash().to_hex(),
                "route_hit_counts": self.route_hit_counts,
            },
        )


class AuthenticatedShort64HVIndex:
    """Profile-aware SHORT64-HV index with sparse-Merkle candidate-set proofs.

    This class intentionally mirrors the Step 8 ``MemoryShort64HVIndex`` API so
    it can be used by the existing resolver during incremental development.  It
    adds proof-oriented methods:

    * ``root_record()`` returns the compact commitment to the current epoch.
    * ``open_route_key(k)`` returns a proof for a single route key.
    * ``lookup_authenticated(tokens, ...)`` returns candidate refs plus all
      route-key openings needed to verify completeness.

    The in-memory design is not production storage.  A production resolver would
    keep candidate-set values in a database/object store and serve openings from
    a persisted SMT snapshot.  The algorithmic contract should remain the same.
    """

    def __init__(
        self,
        profile: HDCProfile | None = None,
        *,
        name: str = "authenticated-short64-hv-index",
        index_id: str = "oprow-short64-hv-authmap-v1",
        epoch_id: str = DEFAULT_HDC_EPOCH,
        metadata: Mapping[str, Any] | None = None,
    ):
        self.name = name
        self.profile = profile or default_hdc_profile()
        self.index_id = index_id
        self.epoch_id = epoch_id
        self.metadata = dict(metadata or {})
        self._by_route_key: dict[Hash256, list[Short64IndexReference]] = {}
        self._smt: SparseMerkleMap | None = None
        self._root_record: AuthenticatedIndexRootRecord | None = None

    def add_reference(self, reference: Short64IndexReference, tokens: Iterable[RouteToken]) -> None:
        for token in tokens:
            bucket = self._by_route_key.setdefault(token.route_key, [])
            key = _reference_key(reference)
            if not any(_reference_key(existing) == key for existing in bucket):
                bucket.append(reference)
        self._mark_dirty()

    def add_manifest(
        self,
        manifest: SignedManifest,
        *,
        artifact: Artifact,
        encoder: HDCEncoder | None = None,
        include_document_bytes: bool = True,
        namespace_id: NamespaceId | None = None,
        storage_hints: Iterable[StorageHint] | None = None,
        epoch_id: str | None = None,
        precision: RoutePrecision | None = None,
        created_at: datetime | None = None,
        metadata: Mapping[str, Any] | None = None,
    ) -> Short64IndexReference:
        """Compute route tokens for a manifest/artifact pair and index them.

        The HDC descriptor is computed locally from the artifact exactly as the
        verifier will compute it during lookup.  The descriptor itself is not
        stored in the map.  Only opaque route keys and manifest references are
        stored.
        """
        enc = encoder or SymbolicBundlingHDCEncoder(profile=self.profile)
        encoding = enc.encode_artifact(artifact)
        token_set = derive_route_tokens(
            short_id=manifest.short_id_hash_truncated(),
            encoding=encoding,
            namespace_id=namespace_id,
            epoch_id=epoch_id or self.epoch_id,
            precision=precision,
        )
        ref = Short64IndexReference(
            short_id=manifest.short_id_hash_truncated(),
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
        return ref

    def _mark_dirty(self) -> None:
        self._smt = None
        self._root_record = None

    def _candidate_set_for_route_key(self, route_key: Hash256) -> RouteCandidateSet | None:
        refs = self._by_route_key.get(route_key)
        if not refs:
            return None
        return RouteCandidateSet(route_key=route_key, references=list(refs), complete=True, total_available=len(refs))

    def _ensure_built(self) -> None:
        if self._smt is not None and self._root_record is not None:
            return
        entries: dict[Hash256, bytes] = {}
        ref_count = 0
        for route_key in sorted(self._by_route_key, key=lambda k: k.value):
            candidate_set = self._candidate_set_for_route_key(route_key)
            if candidate_set is None:
                continue
            entries[route_key] = candidate_set.canonical_bytes()
            ref_count += len(candidate_set.references)
        self._smt = SparseMerkleMap(entries)
        self._root_record = AuthenticatedIndexRootRecord(
            index_id=self.index_id,
            epoch_id=self.epoch_id,
            root_hash=self._smt.root_hash(),
            profile_id=self.profile.profile_id,
            route_key_count=len(entries),
            candidate_reference_count=ref_count,
            metadata=dict(self.metadata),
        )

    def root_record(self) -> AuthenticatedIndexRootRecord:
        self._ensure_built()
        assert self._root_record is not None
        return self._root_record

    def open_route_key(self, route_key: Hash256) -> RouteCandidateSetOpening:
        self._ensure_built()
        assert self._smt is not None and self._root_record is not None
        opening = self._smt.open(route_key)
        candidate_set = RouteCandidateSet.from_bytes(opening.value) if opening.value is not None else None
        typed = RouteCandidateSetOpening(route_key=route_key, candidate_set=candidate_set, proof=opening.proof, root_record=self._root_record)
        # Because this is a reference implementation, fail fast if we somehow
        # generated an invalid proof.  A network resolver should return the proof
        # and let the client perform this same check.
        if not typed.verify():
            raise ValidationError("internal error: generated authenticated route opening does not verify")
        return typed

    def lookup_authenticated(
        self,
        route_tokens: Iterable[RouteToken],
        *,
        short_id: ShortId | None = None,
        namespace_id: NamespaceId | None = None,
        min_token_matches: int = 1,
        max_results: int | None = None,
    ) -> AuthenticatedShort64HVLookupResult:
        if min_token_matches <= 0:
            raise ValidationError("min_token_matches must be positive")
        token_list = list(route_tokens)
        root_record = self.root_record()
        openings = [self.open_route_key(token.route_key) for token in token_list]
        proof_verified = all(opening.verify() and opening.root_record.root_hash == root_record.root_hash for opening in openings)

        by_key: dict[str, Short64IndexReference] = {}
        hit_counts: dict[str, int] = {}
        total_bucket_refs = 0
        complete = proof_verified
        for opening in openings:
            if opening.candidate_set is not None:
                if not opening.candidate_set.complete:
                    complete = False
                total_bucket_refs += len(opening.candidate_set.references)
            for ref in opening.references:
                if short_id is not None and ref.short_id != short_id:
                    continue
                if namespace_id is not None and ref.namespace_id != namespace_id:
                    continue
                key = _reference_key(ref)
                by_key.setdefault(key, ref)
                hit_counts[key] = hit_counts.get(key, 0) + 1

        refs = [ref for key, ref in by_key.items() if hit_counts.get(key, 0) >= min_token_matches]
        refs.sort(key=lambda ref: (-hit_counts[_reference_key(ref)], _reference_sort_key(ref)))
        total_available = len(refs)
        if max_results is not None and len(refs) > max_results:
            refs = refs[:max_results]
            complete = False

        return AuthenticatedShort64HVLookupResult(
            route_tokens=token_list,
            openings=openings,
            references=refs,
            root_record=root_record,
            route_hit_counts=hit_counts,
            complete=complete,
            proof_verified=proof_verified,
            total_available=total_available,
            diagnostics={
                "index_id": self.index_id,
                "epoch_id": self.epoch_id,
                "root_hash": root_record.root_hash.to_hex(),
                "root_record_hash": root_record.record_hash().to_hex(),
                "route_tokens": len(token_list),
                "route_key_openings": len(openings),
                "raw_bucket_references": total_bucket_refs,
                "unique_candidates": total_available,
                "map_alg_id": root_record.map_alg_id,
            },
        )

    def lookup_tokens(
        self,
        route_tokens: list[RouteToken],
        *,
        short_id: ShortId | None = None,
        namespace_id: NamespaceId | None = None,
        min_token_matches: int = 1,
        max_results: int | None = None,
    ) -> Short64LookupResult:
        """Compatibility method consumed by the Step 8 resolver protocol."""
        auth = self.lookup_authenticated(
            route_tokens,
            short_id=short_id,
            namespace_id=namespace_id,
            min_token_matches=min_token_matches,
            max_results=max_results,
        )
        return auth.to_short64_lookup_result(short_id=short_id)

    def route_key_count(self) -> int:
        return len(self._by_route_key)

    def public_route_keys(self) -> list[Hash256]:
        """Return opaque route keys for P2 cover-query sampling.

        Only route-key hashes are exposed.  A production service may publish a
        filtered public bucket catalogue or aggregate stats, but this local helper
        is enough for reference tests and does not leak raw HDC descriptors.
        """
        return sorted(self._by_route_key.keys(), key=lambda k: k.value)

    def route_keys(self) -> list[Hash256]:
        """Alias for ``public_route_keys`` used by privacy samplers."""
        return self.public_route_keys()


def route_candidate_set_from_primitive(value: Any) -> RouteCandidateSet:
    if not isinstance(value, Mapping):
        raise ValidationError("RouteCandidateSet primitive must be a map")
    raw_route_key = value.get("route_key")
    if not isinstance(raw_route_key, bytes):
        raise ValidationError("RouteCandidateSet.route_key must be bytes")
    refs_raw = value.get("references", [])
    if not isinstance(refs_raw, list):
        raise ValidationError("RouteCandidateSet.references must be a list")
    return RouteCandidateSet(
        version=int(value.get("version", 1)),
        route_key=Hash256(raw_route_key),
        references=[short64_reference_from_primitive(x) for x in refs_raw],
        complete=bool(value.get("complete", True)),
        total_available=value.get("total_available"),
        metadata=dict(value.get("metadata", {}) or {}),
    )


def build_authenticated_short64_hv_index(
    manifests_and_artifacts: Iterable[tuple[SignedManifest, Artifact]],
    *,
    profile: HDCProfile | None = None,
    include_document_bytes: bool = True,
    index_id: str = "oprow-short64-hv-authmap-v1",
    epoch_id: str = DEFAULT_HDC_EPOCH,
) -> AuthenticatedShort64HVIndex:
    idx = AuthenticatedShort64HVIndex(profile=profile or default_hdc_profile(), index_id=index_id, epoch_id=epoch_id)
    for manifest, artifact in manifests_and_artifacts:
        idx.add_manifest(manifest, artifact=artifact, include_document_bytes=include_document_bytes)
    return idx


__all__ = [
    "RouteCandidateSet",
    "AuthenticatedIndexRootRecord",
    "RouteCandidateSetOpening",
    "AuthenticatedShort64HVLookupResult",
    "AuthenticatedShort64HVIndex",
    "route_candidate_set_from_primitive",
    "build_authenticated_short64_hv_index",
]
