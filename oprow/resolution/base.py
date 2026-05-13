"""Step 4 resolution base types and helper algorithms.

The OProW design separates *resolution* from *verification*.  Resolution means:
"given a pointer recovered from a watermark or metadata, find one or more
candidate signed manifests."  Verification is stricter and later checks locator
self-consistency, signatures, essence/content binding, and trust policy.

This separation is essential because every storage mechanism is potentially
untrusted.  Embedded metadata can be stale, sidecar paths can point to attacker
files, CAS nodes can omit objects, and HTTP gateways can lie.  A resolver is
therefore a retrieval component, not an authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Protocol

from oprow.core.enums import PointerMode
from oprow.core.errors import OProWError, ValidationError
from oprow.core.models import Artifact, ManifestEnvelope, ManifestLocator, SignedManifest, StorageHint
from oprow.manifest.codec import ManifestCodecError, decode_manifest_document
from oprow.manifest.verification import verify_locator_self_consistency


class ResolutionStatus(str, Enum):
    """Coarse resolver outcome."""

    FOUND = "found"
    NOT_FOUND = "not_found"
    PARTIAL = "partial"
    ERROR = "error"
    UNSUPPORTED = "unsupported"


class CandidateValidationStatus(str, Enum):
    """Result of checking a candidate against a request locator."""

    LOCATOR_MATCH = "locator_match"
    LOCATOR_MISMATCH = "locator_mismatch"
    DECODE_FAILED = "decode_failed"
    UNSUPPORTED_DERIVATION = "unsupported_derivation"


@dataclass(frozen=True)
class ResolutionRequest:
    """Input supplied to a resolver.

    ``locator`` is the security-relevant pointer recovered by a watermark or
    metadata parser.  ``artifact`` is optional because FULL160 CAS lookup does
    not need media bytes, while embedded lookup needs artifact metadata and
    future SHORT64-HV lookup will need media-derived HDC routes.
    """

    locator: ManifestLocator
    artifact: Artifact | None = None
    storage_hints: list[StorageHint] = field(default_factory=list)
    allow_network: bool = True
    max_candidates: int = 64
    max_bytes: int = 8 * 1024 * 1024
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResolutionCandidate:
    """One candidate manifest returned by a resolver.

    A candidate with ``LOCATOR_MATCH`` has passed only the pointer derivation
    check.  It may still have invalid signatures, mismatched essence, revoked
    keys, untrusted signers, or conflicting claims.  Step 5 will build the full
    verifier orchestrator on top of this object.
    """

    envelope: ManifestEnvelope
    source: str
    validation_status: CandidateValidationStatus
    raw_bytes: bytes | None = None
    diagnostics: dict[str, Any] = field(default_factory=dict)

    @property
    def manifest(self) -> SignedManifest:
        return self.envelope.manifest

    @property
    def locator(self) -> ManifestLocator:
        return self.envelope.locator


@dataclass(frozen=True)
class ResolverDiagnosticEvent:
    """Human-readable trace item for resolver debugging."""

    resolver: str
    event: str
    detail: str = ""
    data: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ResolutionResult:
    """Resolver output: candidates plus diagnostics."""

    status: ResolutionStatus
    candidates: list[ResolutionCandidate] = field(default_factory=list)
    diagnostics: list[ResolverDiagnosticEvent] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return bool(self.candidates)

    @classmethod
    def not_found(cls, resolver: str, detail: str = "") -> "ResolutionResult":
        return cls(status=ResolutionStatus.NOT_FOUND, diagnostics=[ResolverDiagnosticEvent(resolver, "not_found", detail)])

    @classmethod
    def unsupported(cls, resolver: str, detail: str = "") -> "ResolutionResult":
        return cls(status=ResolutionStatus.UNSUPPORTED, diagnostics=[ResolverDiagnosticEvent(resolver, "unsupported", detail)])

    @classmethod
    def error(cls, resolver: str, exc: Exception, detail: str = "") -> "ResolutionResult":
        msg = f"{detail}: {exc}" if detail else str(exc)
        return cls(status=ResolutionStatus.ERROR, diagnostics=[ResolverDiagnosticEvent(resolver, "error", msg)], errors=[msg])


class Resolver(Protocol):
    """Protocol implemented by every resolver backend."""

    name: str

    def resolve(self, request: ResolutionRequest) -> ResolutionResult:
        ...


class ResolverError(OProWError):
    """Base class for resolution/storage failures."""


class ResolverConfigurationError(ResolverError):
    """Raised when a resolver is configured with invalid paths/templates."""


def _candidate_key(candidate: ResolutionCandidate) -> str:
    """Deduplicate by derived FULL160 key.

    Two sources returning byte-identical or semantically identical canonical
    manifests should not force the verifier to repeat work.  Source names are
    deliberately excluded because source is not authoritative.
    """
    return candidate.manifest.manifest_key().to_hex()


def deduplicate_candidates(candidates: Iterable[ResolutionCandidate]) -> list[ResolutionCandidate]:
    seen: set[str] = set()
    out: list[ResolutionCandidate] = []
    for c in candidates:
        key = _candidate_key(c)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def candidate_from_document_bytes(
    data: bytes,
    *,
    request_locator: ManifestLocator,
    source: str,
    require_canonical: bool = True,
) -> ResolutionCandidate:
    """Decode resolver bytes and check locator self-consistency.

    Algorithm:
      1. Decode bytes as either ``SignedManifest`` or ``ManifestEnvelope``.
      2. Normalize to an envelope.
      3. Check that ``request_locator`` derives from the envelope's
         ``SignedManifest`` canonical bytes.

    This is necessary but not sufficient for provenance verification.
    """
    envelope = decode_manifest_document(data, require_canonical=require_canonical)
    if request_locator.mode in (PointerMode.SHORT64, PointerMode.SHORT64_HV) and request_locator.derivation_profile != "hash_truncated":
        status = CandidateValidationStatus.UNSUPPORTED_DERIVATION
    else:
        status = CandidateValidationStatus.LOCATOR_MATCH if verify_locator_self_consistency(envelope.manifest, request_locator) else CandidateValidationStatus.LOCATOR_MISMATCH
    return ResolutionCandidate(envelope=envelope, source=source, validation_status=status, raw_bytes=data)


def filter_matching_candidates(candidates: Iterable[ResolutionCandidate]) -> list[ResolutionCandidate]:
    return [c for c in candidates if c.validation_status == CandidateValidationStatus.LOCATOR_MATCH]


def result_from_candidates(resolver: str, candidates: list[ResolutionCandidate], diagnostics: list[ResolverDiagnosticEvent] | None = None) -> ResolutionResult:
    deduped = deduplicate_candidates(candidates)
    matching = filter_matching_candidates(deduped)
    events = list(diagnostics or [])
    events.append(ResolverDiagnosticEvent(resolver, "candidates", data={"seen": len(deduped), "matching": len(matching)}))
    return ResolutionResult(status=ResolutionStatus.FOUND if matching else ResolutionStatus.NOT_FOUND, candidates=matching, diagnostics=events)


def read_limited_file(path: Path, max_bytes: int) -> bytes:
    """Read a manifest candidate file with a maximum-size guard."""
    if max_bytes <= 0:
        raise ValidationError("max_bytes must be positive")
    size = path.stat().st_size
    if size > max_bytes:
        raise ResolverError(f"manifest file exceeds max_bytes: {path} ({size} > {max_bytes})")
    return path.read_bytes()
