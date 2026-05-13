"""Draft models for C2PA Soft Binding Resolution API interop.

C2PA guidance describes manifest repositories and a Soft Binding Resolution API
with routes such as ``/matches/byBinding`` and ``/manifests``. Step 6 does not
implement an HTTP service; Step 4 already gave us generic HTTP/local/CAS
resolvers. This file defines the *data shapes* that an OProW implementation would
send to or receive from a C2PA-compatible repository.

Privacy design note
===================

The C2PA guidance encourages client-side computation of soft bindings where
possible to avoid transmitting the full asset to a lookup service. That is the
same principle we use for OProW's future SHORT64-HV privacy modes: the client
computes descriptors locally and sends only route/binding tokens appropriate for
its privacy profile. The request model below therefore centers ``byBinding``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from oprow.core.errors import ValidationError
from oprow.core.identifiers import Hash256

from .models import C2PAAssertion, C2PAManifestStore, C2PA_SOFT_BINDING_LABEL


@dataclass(frozen=True)
class SoftBindingMatchRequest:
    """Request body for a draft ``/matches/byBinding`` lookup.

    ``binding`` is a C2PA soft-binding assertion body, not a whole asset. In the
    OProW profile the binding may contain a FULL160 or SHORT64 locator. Later HDC
    privacy profiles will replace or augment this with bucketized route tokens;
    this Step 6 request is intentionally simple.
    """

    alg: str
    binding: dict[str, Any]
    return_manifest_store: bool = False
    max_results: int = 16
    client_metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.alg:
            raise ValidationError("SoftBindingMatchRequest.alg must be non-empty")
        if self.max_results <= 0:
            raise ValidationError("SoftBindingMatchRequest.max_results must be positive")

    @classmethod
    def from_soft_binding_assertion(cls, assertion: C2PAAssertion, *, return_manifest_store: bool = False, max_results: int = 16) -> "SoftBindingMatchRequest":
        if assertion.label != C2PA_SOFT_BINDING_LABEL:
            raise ValidationError("only c2pa.soft-binding assertions can be used for byBinding lookup")
        alg = assertion.data.get("alg")
        if not isinstance(alg, str) or not alg:
            raise ValidationError("soft-binding assertion is missing alg")
        return cls(alg=alg, binding=dict(assertion.data), return_manifest_store=return_manifest_store, max_results=max_results)

    def to_canonical(self) -> dict[str, Any]:
        return {
            "alg": self.alg,
            "binding": dict(self.binding),
            "return_manifest_store": self.return_manifest_store,
            "max_results": self.max_results,
            "client_metadata": dict(self.client_metadata),
        }


@dataclass(frozen=True)
class SoftBindingMatch:
    """One repository match returned from a soft-binding lookup."""

    manifest_id: str
    manifest_store_uri: str | None = None
    manifest_store_hash: Hash256 | None = None
    confidence: str = "candidate"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.manifest_id:
            raise ValidationError("SoftBindingMatch.manifest_id must be non-empty")

    def to_canonical(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "manifest_id": self.manifest_id,
            "confidence": self.confidence,
            "metadata": dict(self.metadata),
        }
        if self.manifest_store_uri is not None:
            out["manifest_store_uri"] = self.manifest_store_uri
        if self.manifest_store_hash is not None:
            out["manifest_store_hash"] = self.manifest_store_hash
        return out


@dataclass(frozen=True)
class SoftBindingMatchResponse:
    """Draft response from a soft-binding manifest repository."""

    matches: list[SoftBindingMatch]
    manifest_stores: list[C2PAManifestStore] = field(default_factory=list)
    repository_metadata: dict[str, Any] = field(default_factory=dict)

    def to_canonical(self) -> dict[str, Any]:
        return {
            "matches": self.matches,
            "manifest_stores": self.manifest_stores,
            "repository_metadata": dict(self.repository_metadata),
        }


def build_match_response_for_store(store: C2PAManifestStore, *, uri: str | None = None, include_store: bool = True) -> SoftBindingMatchResponse:
    """Convenience helper for tests and prototype in-memory repositories."""
    active = store.active_manifest()
    match = SoftBindingMatch(
        manifest_id=active.manifest_id,
        manifest_store_uri=uri,
        manifest_store_hash=Hash256.from_data(store.canonical_bytes()),
        confidence="exact_binding",
    )
    return SoftBindingMatchResponse(matches=[match], manifest_stores=[store] if include_store else [])
