"""C2PA-facing protocol models for the OProW reference SDK.

Step 6 does **not** attempt to re-implement the complete C2PA stack. A full C2PA
implementation has to deal with JUMBF boxes, COSE signatures, certificate chains,
time stamps, file-format embedding rules, validation status codes, and other
details that are deliberately outside the OProW core prototype. This file instead
defines a small, typed *adapter model* that lets the rest of the Python reference
implementation talk about C2PA concepts precisely and testably.

Why keep this as a skeleton?
============================

The design goal of OProW v3 is not to compete with C2PA, but to make OProW a
C2PA-compatible Durable Content Credentials profile. In that framing:

* C2PA remains the industry-facing provenance manifest ecosystem.
* OProW contributes a robust in-band watermark pointer, privacy-preserving
  resolution, HDC-assisted short lookup, decentralized trust adapters, and local
  policy tooling.
* The official C2PA SDK, when available in a production deployment, should be
  used to create the final C2PA Manifest Store and sign it with the appropriate
  C2PA credentials.

The objects below are therefore **C2PA-like**, not normative C2PA wire objects.
They preserve the shape we need for interoperability work:

* a Manifest Store contains one or more Manifests;
* a Manifest contains a Claim;
* a Claim references Assertions;
* Assertions include standard labels such as ``c2pa.soft-binding`` and custom
  extension labels such as ``org.oprow.manifest.v1``.

This is enough to let Step 6 implement and test the important architectural
choice: OProW's signed manifest bytes and locator are carried as C2PA assertions
and soft bindings, while the authoritative OProW verification still happens via
OProW signatures, essence matching, and trust policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from oprow.core.canonical import canonical_cbor_dumps
from oprow.core.errors import ValidationError
from oprow.core.hashes import h256
from oprow.core.identifiers import Hash256


C2PA_SOFT_BINDING_LABEL = "c2pa.soft-binding"
C2PA_ACTIONS_LABEL = "c2pa.actions"
C2PA_METADATA_LABEL = "c2pa.metadata"

OPROW_MANIFEST_ASSERTION_LABEL = "org.oprow.manifest.v1"
OPROW_LOCATOR_ASSERTION_LABEL = "org.oprow.locator.v1"
OPROW_ESSENCE_ASSERTION_LABEL = "org.oprow.essence.v1"
OPROW_SIGNATURE_SUMMARY_ASSERTION_LABEL = "org.oprow.signature-summary.v1"
OPROW_TRUST_EVIDENCE_ASSERTION_LABEL = "org.oprow.trust-evidence.v1"


@dataclass(frozen=True)
class C2PAAssertion:
    """A minimal representation of a C2PA assertion.

    Theory implemented
    ------------------
    In C2PA, assertions are the statements that make up the provenance data. The
    claim references assertions, and the claim is signed. This reference model
    does not produce a real C2PA COSE-signed claim; instead it gives the adapter a
    deterministic and inspectable assertion container.

    Implementation choices
    ----------------------
    ``data`` is a primitive canonicalizable map. It may contain byte strings. Our
    debug JSON encoder represents bytes as base64url wrapper objects, while our
    canonical CBOR encoder keeps them as bytes. This matches OProW's own use of
    CBOR for security-sensitive bytes and JSON only for human inspection.

    ``instance`` is optional. C2PA permits multiple assertions with the same
    label, so production C2PA packaging often distinguishes assertion instances.
    Here we make the assertion URI deterministic by deriving it from label and
    list position if no explicit instance is supplied.
    """

    label: str
    data: Mapping[str, Any]
    kind: str = "json"
    instance: int | None = None

    def __post_init__(self) -> None:
        if not self.label:
            raise ValidationError("C2PAAssertion.label must be non-empty")
        if not isinstance(self.data, Mapping):
            raise ValidationError("C2PAAssertion.data must be a mapping")

    def to_canonical(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "kind": self.kind,
            "instance": self.instance,
            "data": dict(self.data),
        }

    def assertion_ref(self, index: int) -> str:
        """Return a deterministic local reference for this assertion.

        A real C2PA claim would use JUMBF references such as
        ``self#jumbf=c2pa.assertions/...``. We keep a deliberately simple form
        that can later be translated by an official C2PA SDK bridge.
        """
        suffix = self.instance if self.instance is not None else index
        safe_label = self.label.replace("/", ".")
        return f"self#oprow-c2pa-assertion/{safe_label}/{suffix}"


@dataclass(frozen=True)
class C2PAClaim:
    """Minimal C2PA claim model used by the adapter.

    A C2PA claim binds a claim generator, an asset format, and a set of assertion
    references. It is normally signed by the signer credential in the official
    C2PA packaging. This skeleton records the claim fields but does not create a
    C2PA claim signature; OProW signatures remain in the OProW signed manifest.
    """

    claim_generator: str
    format: str
    instance_id: str
    assertion_refs: list[str]
    title: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.claim_generator:
            raise ValidationError("C2PAClaim.claim_generator must be non-empty")
        if not self.format:
            raise ValidationError("C2PAClaim.format must be non-empty")
        if not self.instance_id:
            raise ValidationError("C2PAClaim.instance_id must be non-empty")
        if not self.assertion_refs:
            raise ValidationError("C2PAClaim.assertion_refs must be non-empty")

    def to_canonical(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "claim_generator": self.claim_generator,
            "format": self.format,
            "instance_id": self.instance_id,
            "assertions": list(self.assertion_refs),
            "metadata": dict(self.metadata),
        }
        if self.title is not None:
            out["title"] = self.title
        return out


@dataclass(frozen=True)
class C2PAManifest:
    """A minimal C2PA Manifest object for adapter tests and prototypes.

    The important design separation is:

    * ``C2PAManifest`` is a compatibility/export object.
    * ``SignedManifest`` remains the authoritative OProW signed/addressed object.

    The adapter embeds exact OProW ``SignedManifest`` bytes inside a custom C2PA
    assertion. That gives us lossless round-tripping while also allowing C2PA
    consumers to see familiar assertion labels such as ``c2pa.soft-binding``.
    """

    manifest_id: str
    claim: C2PAClaim
    assertions: list[C2PAAssertion]
    active: bool = True
    signature_info: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.manifest_id:
            raise ValidationError("C2PAManifest.manifest_id must be non-empty")
        if not self.assertions:
            raise ValidationError("C2PAManifest.assertions must be non-empty")

    def to_canonical(self) -> dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "active": self.active,
            "claim": self.claim,
            "assertions": self.assertions,
            "signature_info": dict(self.signature_info),
            "metadata": dict(self.metadata),
        }

    def canonical_bytes(self) -> bytes:
        """Deterministic bytes for tests, not official C2PA wire bytes."""
        return canonical_cbor_dumps(self)

    def digest(self) -> Hash256:
        """Hash of this adapter object, useful as a local manifest-store key."""
        return Hash256(h256(self.canonical_bytes()))

    def assertion_by_label(self, label: str) -> list[C2PAAssertion]:
        return [a for a in self.assertions if a.label == label]


@dataclass(frozen=True)
class C2PAManifestStore:
    """A minimal manifest store containing one active C2PA manifest.

    C2PA uses a Manifest Store to hold one or more manifests associated with an
    asset. Durable Content Credentials workflows may retrieve an entire store
    from a manifest repository after a soft-binding lookup. This class lets Step
    6 model that flow without implementing file embedding or JUMBF.
    """

    active_manifest_id: str
    manifests: list[C2PAManifest]
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.manifests:
            raise ValidationError("C2PAManifestStore.manifests must be non-empty")
        ids = {m.manifest_id for m in self.manifests}
        if self.active_manifest_id not in ids:
            raise ValidationError("active_manifest_id does not name a manifest in the store")

    def active_manifest(self) -> C2PAManifest:
        for manifest in self.manifests:
            if manifest.manifest_id == self.active_manifest_id:
                return manifest
        raise ValidationError("active manifest not found")

    def to_canonical(self) -> dict[str, Any]:
        return {
            "active_manifest_id": self.active_manifest_id,
            "manifests": self.manifests,
            "metadata": dict(self.metadata),
        }

    def canonical_bytes(self) -> bytes:
        """Deterministic bytes for repository/cache tests."""
        return canonical_cbor_dumps(self)


@dataclass(frozen=True)
class C2PAMappingNote:
    """One human-readable note produced during OProW<->C2PA mapping.

    The adapter intentionally reports what it could map exactly, what it mapped
    approximately, and what it preserved only as a custom OProW assertion. That
    makes later integration with an official C2PA SDK safer: a coding agent or
    implementer can inspect the report and decide which placeholders need to be
    replaced by first-class C2PA structures.
    """

    code: str
    message: str
    severity: str = "info"

    def to_canonical(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "severity": self.severity}


@dataclass(frozen=True)
class C2PAAdapterResult:
    """Return object for adapter operations."""

    manifest: C2PAManifest
    mapping_notes: list[C2PAMappingNote] = field(default_factory=list)

    def to_canonical(self) -> dict[str, Any]:
        return {"manifest": self.manifest, "mapping_notes": self.mapping_notes}
