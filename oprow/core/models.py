"""Core OProW dataclasses.

The theory implemented here is the corrected algorithm framework discussed in
our design pass:

* ``ManifestCore`` is the semantic object that signers attest to.  It has no
  signatures, locator, resolver proof, blockchain receipt, or C2PA evidence.
* ``SignedManifest`` is ``ManifestCore`` plus signatures.  FULL160 and default
  SHORT64 locators are derived from its canonical bytes.
* ``ManifestEnvelope`` is the transport wrapper that may carry the locator,
  storage hints, ASI:chain receipts, transparency proofs, C2PA evidence, or
  authenticated-index proofs.  The envelope is not the object pointed to by the
  watermark.

This separation prevents the self-reference bug where a manifest key is computed
and then inserted back into the hashed bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from .canonical import canonical_cbor_dumps
from .enums import ClaimType, HashAlgorithm, PointerMode, SignatureRole, StorageHintType, TrustEvidenceType
from .errors import ValidationError
from .hashes import frame_parts, hash_framed
from .identifiers import Hash256, KeyId, ManifestKey, NamespaceId, ShortId


def _drop_absent(m: Mapping[str, Any]) -> dict[str, Any]:
    """Drop None and empty containers to minimize disclosed metadata."""
    return {k: v for k, v in m.items() if v is not None and v != [] and v != {}}


@dataclass(frozen=True)
class Artifact:
    """Runtime media object; not normally serialized into a manifest."""
    media_type: str
    data: bytes | None = None
    path: Path | str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.data is None and self.path is None:
            raise ValidationError("Artifact requires data or path")
        if self.data is not None and not isinstance(self.data, bytes):
            object.__setattr__(self, "data", bytes(self.data))
        if self.path is not None and not isinstance(self.path, Path):
            object.__setattr__(self, "path", Path(self.path))

    @classmethod
    def from_bytes(cls, data: bytes, media_type: str, metadata: dict[str, Any] | None = None) -> "Artifact":
        return cls(media_type=media_type, data=bytes(data), metadata=metadata or {})

    @classmethod
    def from_path(cls, path: str | Path, media_type: str, metadata: dict[str, Any] | None = None) -> "Artifact":
        return cls(media_type=media_type, path=Path(path), metadata=metadata or {})

    def read_bytes(self) -> bytes:
        if self.data is not None:
            return self.data
        if self.path is None:
            raise ValidationError("Artifact has neither data nor path")
        return self.path.read_bytes()


@dataclass(frozen=True)
class RegionCommitment:
    """Optional tile/frame/region commitment for high-assurance profiles."""
    region_id: str
    alg_id: str
    commitment: Hash256
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({"region_id": self.region_id, "alg_id": self.alg_id, "commitment": self.commitment, "metadata": self.metadata})


@dataclass(frozen=True)
class ArtifactBinding:
    """Signed binding between claims and standardized media essence.

    The primary commitment is ``essence_hash``: usually H256(PED) for a registered
    perceptual essence descriptor such as PED-IMG-1.  Strict byte/decode hashes
    are optional extras for closed-loop archival or forensic workflows.
    """
    media_type: str
    essence_alg_id: str
    essence_hash: Hash256
    hash_alg: str | HashAlgorithm = HashAlgorithm.SHA256
    wm_alg_id: str | None = None
    strict_byte_hash: Hash256 | None = None
    strict_decode_hash: Hash256 | None = None
    region_commitments: list[RegionCommitment] = field(default_factory=list)

    def to_canonical(self) -> dict[str, Any]:
        alg = self.hash_alg.value if isinstance(self.hash_alg, HashAlgorithm) else str(self.hash_alg)
        return _drop_absent({
            "media_type": self.media_type,
            "essence_alg_id": self.essence_alg_id,
            "essence_hash": self.essence_hash,
            "hash_alg": alg,
            "wm_alg_id": self.wm_alg_id,
            "strict_byte_hash": self.strict_byte_hash,
            "strict_decode_hash": self.strict_decode_hash,
            "region_commitments": self.region_commitments,
        })


@dataclass(frozen=True)
class Claim:
    """Generic extensible claim: explicit type plus canonicalizable body."""
    type: str
    body: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.type:
            raise ValidationError("Claim.type must be non-empty")
        if "type" in self.body:
            raise ValidationError("Claim.body must not contain top-level 'type'")

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({"type": self.type, **self.body})


@dataclass(frozen=True, init=False)
class CaptureClaim(Claim):
    """Claim that a sensor/device captured content; not proof of event truth."""
    def __init__(self, timestamp: datetime | None = None, location: dict[str, Any] | None = None, device_attestation: dict[str, Any] | None = None, statement: str | None = None, extra: dict[str, Any] | None = None):
        body = _drop_absent({"timestamp": timestamp, "location": location, "device_attestation": device_attestation, "statement": statement, **(extra or {})})
        object.__setattr__(self, "type", ClaimType.CAPTURE.value)
        object.__setattr__(self, "body", body)
        Claim.__post_init__(self)


@dataclass(frozen=True, init=False)
class GenerationClaim(Claim):
    """Claim that software/model/runtime generated content."""
    def __init__(self, model_id: str | None = None, runtime_attestation: dict[str, Any] | None = None, input_commitments: Iterable[Hash256] | None = None, extra: dict[str, Any] | None = None):
        body = _drop_absent({"model_id": model_id, "runtime_attestation": runtime_attestation, "input_commitments": list(input_commitments or []), **(extra or {})})
        object.__setattr__(self, "type", ClaimType.GENERATION.value)
        object.__setattr__(self, "body", body)
        Claim.__post_init__(self)


@dataclass(frozen=True, init=False)
class EditClaim(Claim):
    """Claim that an editing tool transformed one or more inputs."""
    def __init__(self, tool_id: str, operation: str | None = None, inputs: Iterable[Any] | None = None, parameters_commitment: Hash256 | None = None, extra: dict[str, Any] | None = None):
        if not tool_id:
            raise ValidationError("EditClaim.tool_id is required")
        body = _drop_absent({"tool_id": tool_id, "operation": operation, "inputs": list(inputs or []), "parameters_commitment": parameters_commitment, **(extra or {})})
        object.__setattr__(self, "type", ClaimType.EDIT.value)
        object.__setattr__(self, "body", body)
        Claim.__post_init__(self)


@dataclass(frozen=True, init=False)
class NotaryClaim(Claim):
    """Third-party attestation by a notary/newsroom/DAO/auditor."""
    def __init__(self, notary_id: str, statement: str, scope: Iterable[str] | None = None, extra: dict[str, Any] | None = None):
        if not notary_id or not statement:
            raise ValidationError("NotaryClaim requires notary_id and statement")
        body = _drop_absent({"notary_id": notary_id, "statement": statement, "scope": list(scope or []), **(extra or {})})
        object.__setattr__(self, "type", ClaimType.NOTARY.value)
        object.__setattr__(self, "body", body)
        Claim.__post_init__(self)

@dataclass(frozen=True)
class SignatureRecord:
    """Metadata and bytes for a signature over ManifestCore.

    Step 1 does not implement real signing.  Step 2 will define Signer/Verifier
    classes and algorithms.  This record still participates in SignedManifest
    canonicalization, so placeholder test signatures must be deterministic.
    """
    kid: KeyId
    alg: str
    signature: bytes
    role: str | SignatureRole
    signed_at: datetime | None = None
    certificate_chain: list[bytes] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_canonical(self) -> dict[str, Any]:
        role = self.role.value if isinstance(self.role, SignatureRole) else str(self.role)
        return _drop_absent({"kid": self.kid, "alg": self.alg, "sig": self.signature, "role": role, "signed_at": self.signed_at, "certificate_chain": self.certificate_chain, "metadata": self.metadata})


@dataclass(frozen=True)
class ManifestCore:
    """Semantic object signed by provenance keys."""
    version: int
    artifact: ArtifactBinding
    claims: list[Claim]
    created_at: datetime | None = None
    c2pa: dict[str, Any] | None = None
    encrypted_claims: dict[str, Any] | None = None
    extensions: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.version <= 0:
            raise ValidationError("ManifestCore.version must be positive")
        if not self.claims:
            raise ValidationError("ManifestCore.claims must be non-empty")

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({"manifest_version": self.version, "artifact": self.artifact, "claims": self.claims, "created_at": self.created_at, "c2pa": self.c2pa, "encrypted_claims": self.encrypted_claims, "extensions": self.extensions})

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    def signing_preimage(self) -> bytes:
        """Domain-separated preimage for Step 2 signature algorithms."""
        return frame_parts("oprow-manifest-core-signing-v1", [self.canonical_bytes()])

    def signing_digest(self) -> bytes:
        """H256 of the signing preimage for digest-signing profiles."""
        return hash_framed("oprow-manifest-core-signing-v1", self.canonical_bytes())

    def signing_bytes(self) -> bytes:
        """Compatibility alias for signing_preimage()."""
        return self.signing_preimage()


@dataclass(frozen=True)
class SignedManifest:
    """ManifestCore plus signatures; this is the addressed object.

    The locator for a manifest is derived from canonical bytes of this object.
    Signature order must therefore be deterministic.  We sort signature records
    by their own canonical CBOR bytes during initialization.  This keeps a
    two-signer manifest byte-identical whether the caller supplies signatures as
    [Alice, Bob] or [Bob, Alice].
    """
    core: ManifestCore
    signatures: list[SignatureRecord]

    def __post_init__(self) -> None:
        if not self.signatures:
            raise ValidationError("SignedManifest requires at least one signature")
        # Frozen dataclasses may still normalize fields via object.__setattr__
        # during __post_init__.  The canonical encoder preserves list order, so
        # this is a protocol-level normalization, not just a cosmetic sort.
        object.__setattr__(self, "signatures", sorted(list(self.signatures), key=canonical_cbor_dumps))

    def to_canonical(self) -> dict[str, Any]:
        return {"core": self.core, "signatures": self.signatures}

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    def manifest_hash(self, alg: str | HashAlgorithm = HashAlgorithm.SHA256) -> Hash256:
        return Hash256.from_data(self.canonical_bytes(), alg=alg)

    def manifest_key(self, alg: str | HashAlgorithm = HashAlgorithm.SHA256) -> ManifestKey:
        return ManifestKey.from_manifest_bytes(self.canonical_bytes(), alg=alg)

    def short_id_hash_truncated(self, alg: str | HashAlgorithm = HashAlgorithm.SHA256) -> ShortId:
        return ShortId.from_manifest_bytes_hash_truncated(self.canonical_bytes(), alg=alg)


@dataclass(frozen=True)
class ManifestLocator:
    """Pointer recovered from watermark/metadata."""
    mode: PointerMode
    value: ManifestKey | ShortId
    namespace_id: NamespaceId | None = None
    hdc_profile_id: str | None = None
    derivation_profile: str = "hash_truncated"

    def __post_init__(self) -> None:
        if self.mode in (PointerMode.FULL160, PointerMode.FULL160_RATELESS):
            if not isinstance(self.value, ManifestKey):
                raise ValidationError(f"{self.mode.value} requires ManifestKey")
        elif self.mode in (PointerMode.SHORT64, PointerMode.SHORT64_HV):
            if not isinstance(self.value, ShortId):
                raise ValidationError(f"{self.mode.value} requires ShortId")
        else:
            raise ValidationError(f"unknown pointer mode: {self.mode!r}")

    @classmethod
    def from_signed_manifest(cls, manifest: SignedManifest, mode: PointerMode = PointerMode.FULL160, namespace_id: NamespaceId | None = None, hdc_profile_id: str | None = None, derivation_profile: str = "hash_truncated") -> "ManifestLocator":
        if mode in (PointerMode.FULL160, PointerMode.FULL160_RATELESS):
            return cls(mode=mode, value=manifest.manifest_key(), namespace_id=namespace_id, derivation_profile="h160")
        if derivation_profile != "hash_truncated":
            raise ValidationError("cannot derive registry-assigned short ID from manifest bytes")
        return cls(mode=mode, value=manifest.short_id_hash_truncated(), namespace_id=namespace_id, hdc_profile_id=hdc_profile_id, derivation_profile=derivation_profile)

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({"mode": self.mode.value, "value": self.value, "namespace_id": self.namespace_id, "hdc_profile_id": self.hdc_profile_id, "derivation_profile": self.derivation_profile})


@dataclass(frozen=True)
class StorageHint:
    """Non-authoritative retrieval hint; integrity is verified after fetch."""
    hint_type: str | StorageHintType
    uri: str
    content_hash: Hash256 | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_canonical(self) -> dict[str, Any]:
        typ = self.hint_type.value if isinstance(self.hint_type, StorageHintType) else str(self.hint_type)
        return _drop_absent({"type": typ, "uri": self.uri, "content_hash": self.content_hash, "metadata": self.metadata})


@dataclass(frozen=True)
class TrustEvidence:
    """Verification evidence carried outside SignedManifest."""
    evidence_type: str | TrustEvidenceType
    body: dict[str, Any]

    def to_canonical(self) -> dict[str, Any]:
        typ = self.evidence_type.value if isinstance(self.evidence_type, TrustEvidenceType) else str(self.evidence_type)
        return {"type": typ, "body": self.body}


@dataclass(frozen=True)
class ManifestEnvelope:
    """Transport wrapper for a signed manifest plus optional evidence."""
    manifest: SignedManifest
    locator: ManifestLocator
    storage_hints: list[StorageHint] = field(default_factory=list)
    trust_evidence: list[TrustEvidence] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        checkable = self.locator.mode in (PointerMode.FULL160, PointerMode.FULL160_RATELESS) or (self.locator.mode in (PointerMode.SHORT64, PointerMode.SHORT64_HV) and self.locator.derivation_profile == "hash_truncated")
        if checkable:
            expected = ManifestLocator.from_signed_manifest(self.manifest, mode=self.locator.mode, namespace_id=self.locator.namespace_id, hdc_profile_id=self.locator.hdc_profile_id, derivation_profile=self.locator.derivation_profile)
            if expected.value != self.locator.value:
                raise ValidationError("locator does not match SignedManifest canonical bytes")

    def addressed_bytes(self) -> bytes:
        """Bytes named by the watermark pointer: SignedManifest canonical bytes."""
        return self.manifest.canonical_bytes()

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({"manifest": self.manifest, "locator": self.locator, "storage_hints": self.storage_hints, "trust_evidence": self.trust_evidence, "metadata": self.metadata})

    def canonical_bytes(self) -> bytes:
        """Envelope bytes are useful for storage/logging, not pointer derivation."""
        return canonical_cbor_dumps(self)
