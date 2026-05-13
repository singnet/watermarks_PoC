"""Step 4 manifest wire codec: parse resolver bytes back into objects.

OProW Step 4 introduces the *resolution layer*: a verifier may obtain candidate
manifest bytes from embedded metadata, a sidecar file, a local content-addressed
store, or an HTTP gateway. Those bytes are not trusted merely because they came
from a resolver. They must be parsed, re-canonicalized, and then checked against
whatever pointer was recovered from the watermark.

This module implements that parsing boundary.

Why this codec exists
=====================

The Step 1/2/3 objects are Python dataclasses, but the protocol object is the
canonical byte string. A resolver cannot safely return an arbitrary Python
object; it returns bytes. To verify them we need a deterministic inverse map:

    canonical CBOR bytes -> primitive dict/list/bytes values -> dataclasses

The decoder intentionally understands only the OProW schema we have defined so
far. It preserves unknown claim bodies and extension maps as ordinary primitive
objects, which keeps the core extensible without letting unknown structures
change the signed/addressed bytes.

Security model
==============

* ``SignedManifest`` bytes are the addressed object. FULL160 is
  ``H160(canonical_cbor(SignedManifest))`` and hash-truncated SHORT64 is
  ``Trunc64(H256(canonical_cbor(SignedManifest)))``.
* ``ManifestEnvelope`` bytes are a transport wrapper. They may carry storage
  hints, ASI:chain receipts, C2PA evidence, or resolver proofs, but they are not
  part of the watermark locator preimage.
* Decoding accepts only canonical CBOR by default. This catches non-canonical
  storage data early and prevents two encodings of the same semantic object from
  confusing resolver diagnostics.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from oprow.core.canonical import canonical_cbor_loads
from oprow.core.enums import PointerMode
from oprow.core.errors import CanonicalizationError, ValidationError
from oprow.core.identifiers import Hash256, KeyId, ManifestKey, NamespaceId, ShortId
from oprow.core.models import (
    ArtifactBinding,
    Claim,
    ManifestCore,
    ManifestEnvelope,
    ManifestLocator,
    RegionCommitment,
    SignatureRecord,
    SignedManifest,
    StorageHint,
    TrustEvidence,
)


class ManifestCodecError(ValidationError):
    """Raised when resolver bytes do not decode to a valid OProW object."""


def _require_mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ManifestCodecError(f"{label} must be a map, got {type(value).__name__}")
    return value


def _require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ManifestCodecError(f"{label} must be a list, got {type(value).__name__}")
    return value


def _require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestCodecError(f"{label} must be a non-empty string")
    return value


def _require_int(value: Any, label: str) -> int:
    if not isinstance(value, int):
        raise ManifestCodecError(f"{label} must be an integer")
    return value


def _require_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, bytes):
        raise ManifestCodecError(f"{label} must be bytes")
    return value


def _optional_hash256(value: Any, label: str) -> Hash256 | None:
    if value is None:
        return None
    return Hash256(_require_bytes(value, label))


def _parse_datetime(value: Any, label: str) -> datetime | None:
    """Parse the UTC RFC3339 strings emitted by core.normalize_datetime()."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        raise ManifestCodecError(f"{label} must be datetime text")
    if not value.endswith("Z"):
        raise ManifestCodecError(f"{label} must be UTC RFC3339 text ending in 'Z'")
    try:
        body = value[:-1]
        if "." in body:
            dt = datetime.strptime(body, "%Y-%m-%dT%H:%M:%S.%f")
        else:
            dt = datetime.strptime(body, "%Y-%m-%dT%H:%M:%S")
        return dt.replace(tzinfo=timezone.utc)
    except ValueError as exc:
        raise ManifestCodecError(f"invalid datetime for {label}: {value!r}") from exc


def region_commitment_from_primitive(value: Any) -> RegionCommitment:
    m = _require_mapping(value, "RegionCommitment")
    return RegionCommitment(
        region_id=_require_str(m.get("region_id"), "region_id"),
        alg_id=_require_str(m.get("alg_id"), "alg_id"),
        commitment=Hash256(_require_bytes(m.get("commitment"), "commitment")),
        metadata=dict(_require_mapping(m.get("metadata", {}), "metadata")),
    )


def artifact_binding_from_primitive(value: Any) -> ArtifactBinding:
    """Decode the signed artifact binding.

    The primary security-relevant value here is ``essence_hash``. It is a
    32-byte commitment to a deterministic perceptual essence descriptor such as
    PED-IMG-1. Strict hashes are optional extra commitments for closed-loop
    archival workflows; they are not required for the Step 4 resolver layer.
    """
    m = _require_mapping(value, "ArtifactBinding")
    region_values = _require_list(m.get("region_commitments", []), "region_commitments")
    return ArtifactBinding(
        media_type=_require_str(m.get("media_type"), "artifact.media_type"),
        essence_alg_id=_require_str(m.get("essence_alg_id"), "artifact.essence_alg_id"),
        essence_hash=Hash256(_require_bytes(m.get("essence_hash"), "artifact.essence_hash")),
        hash_alg=_require_str(m.get("hash_alg", "sha256"), "artifact.hash_alg"),
        wm_alg_id=m.get("wm_alg_id"),
        strict_byte_hash=_optional_hash256(m.get("strict_byte_hash"), "artifact.strict_byte_hash"),
        strict_decode_hash=_optional_hash256(m.get("strict_decode_hash"), "artifact.strict_decode_hash"),
        region_commitments=[region_commitment_from_primitive(x) for x in region_values],
    )


def claim_from_primitive(value: Any) -> Claim:
    """Decode a claim without assuming a closed set of claim schemas."""
    m = dict(_require_mapping(value, "Claim"))
    typ = _require_str(m.pop("type", None), "claim.type")
    return Claim(type=typ, body=m)


def signature_record_from_primitive(value: Any) -> SignatureRecord:
    m = _require_mapping(value, "SignatureRecord")
    chain = _require_list(m.get("certificate_chain", []), "certificate_chain")
    return SignatureRecord(
        kid=KeyId(_require_str(m.get("kid"), "signature.kid")),
        alg=_require_str(m.get("alg"), "signature.alg"),
        signature=_require_bytes(m.get("sig"), "signature.sig"),
        role=_require_str(m.get("role"), "signature.role"),
        signed_at=_parse_datetime(m.get("signed_at"), "signature.signed_at"),
        certificate_chain=[_require_bytes(x, "certificate_chain entry") for x in chain],
        metadata=dict(_require_mapping(m.get("metadata", {}), "signature.metadata")),
    )


def manifest_core_from_primitive(value: Any) -> ManifestCore:
    m = _require_mapping(value, "ManifestCore")
    return ManifestCore(
        version=_require_int(m.get("manifest_version"), "manifest_version"),
        artifact=artifact_binding_from_primitive(m.get("artifact")),
        claims=[claim_from_primitive(x) for x in _require_list(m.get("claims"), "claims")],
        created_at=_parse_datetime(m.get("created_at"), "created_at"),
        c2pa=m.get("c2pa"),
        encrypted_claims=m.get("encrypted_claims"),
        extensions=dict(_require_mapping(m.get("extensions", {}), "extensions")),
    )


def signed_manifest_from_primitive(value: Any) -> SignedManifest:
    m = _require_mapping(value, "SignedManifest")
    return SignedManifest(
        core=manifest_core_from_primitive(m.get("core")),
        signatures=[signature_record_from_primitive(x) for x in _require_list(m.get("signatures"), "signatures")],
    )


def manifest_locator_from_primitive(value: Any) -> ManifestLocator:
    m = _require_mapping(value, "ManifestLocator")
    mode = PointerMode(_require_str(m.get("mode"), "locator.mode"))
    raw_value = _require_bytes(m.get("value"), "locator.value")
    if mode in (PointerMode.FULL160, PointerMode.FULL160_RATELESS):
        pointer_value: ManifestKey | ShortId = ManifestKey(raw_value)
    else:
        pointer_value = ShortId(raw_value)
    ns = m.get("namespace_id")
    return ManifestLocator(
        mode=mode,
        value=pointer_value,
        namespace_id=NamespaceId(ns) if ns is not None else None,
        hdc_profile_id=m.get("hdc_profile_id"),
        derivation_profile=_require_str(m.get("derivation_profile", "hash_truncated"), "locator.derivation_profile"),
    )


def storage_hint_from_primitive(value: Any) -> StorageHint:
    m = _require_mapping(value, "StorageHint")
    return StorageHint(
        hint_type=_require_str(m.get("type"), "storage_hint.type"),
        uri=_require_str(m.get("uri"), "storage_hint.uri"),
        content_hash=_optional_hash256(m.get("content_hash"), "storage_hint.content_hash"),
        metadata=dict(_require_mapping(m.get("metadata", {}), "storage_hint.metadata")),
    )


def trust_evidence_from_primitive(value: Any) -> TrustEvidence:
    m = _require_mapping(value, "TrustEvidence")
    return TrustEvidence(
        evidence_type=_require_str(m.get("type"), "trust_evidence.type"),
        body=dict(_require_mapping(m.get("body"), "trust_evidence.body")),
    )


def envelope_from_primitive(value: Any) -> ManifestEnvelope:
    m = _require_mapping(value, "ManifestEnvelope")
    return ManifestEnvelope(
        manifest=signed_manifest_from_primitive(m.get("manifest")),
        locator=manifest_locator_from_primitive(m.get("locator")),
        storage_hints=[storage_hint_from_primitive(x) for x in _require_list(m.get("storage_hints", []), "storage_hints")],
        trust_evidence=[trust_evidence_from_primitive(x) for x in _require_list(m.get("trust_evidence", []), "trust_evidence")],
        metadata=dict(_require_mapping(m.get("metadata", {}), "envelope.metadata")),
    )


def signed_manifest_to_bytes(manifest: SignedManifest) -> bytes:
    """Serialize a SignedManifest as its canonical addressed bytes."""
    return manifest.canonical_bytes()


def signed_manifest_from_bytes(data: bytes, *, require_canonical: bool = True) -> SignedManifest:
    """Parse canonical SignedManifest bytes from a resolver."""
    try:
        primitive = canonical_cbor_loads(data, require_canonical=require_canonical)
        return signed_manifest_from_primitive(primitive)
    except (CanonicalizationError, ValidationError, ValueError, TypeError) as exc:
        if isinstance(exc, ManifestCodecError):
            raise
        raise ManifestCodecError(f"could not decode SignedManifest: {exc}") from exc


def envelope_to_bytes(envelope: ManifestEnvelope) -> bytes:
    """Serialize a ManifestEnvelope for transport/storage.

    These bytes are not the locator preimage. They are useful when a storage
    node wants to return a manifest together with storage hints, ASI receipts, or
    future authenticated-index proofs.
    """
    return envelope.canonical_bytes()


def envelope_from_bytes(data: bytes, *, require_canonical: bool = True) -> ManifestEnvelope:
    try:
        primitive = canonical_cbor_loads(data, require_canonical=require_canonical)
        return envelope_from_primitive(primitive)
    except (CanonicalizationError, ValidationError, ValueError, TypeError) as exc:
        if isinstance(exc, ManifestCodecError):
            raise
        raise ManifestCodecError(f"could not decode ManifestEnvelope: {exc}") from exc


def decode_manifest_document(data: bytes, *, require_canonical: bool = True) -> ManifestEnvelope:
    """Decode either a SignedManifest document or a ManifestEnvelope document.

    Storage systems MAY choose to store only the addressed ``SignedManifest`` or
    a richer ``ManifestEnvelope``. The resolver normalizes both cases to an
    envelope so downstream code can treat them uniformly.
    """
    primitive = canonical_cbor_loads(data, require_canonical=require_canonical)
    m = _require_mapping(primitive, "manifest document")
    if "manifest" in m and "locator" in m:
        return envelope_from_primitive(m)
    if "core" in m and "signatures" in m:
        manifest = signed_manifest_from_primitive(m)
        locator = ManifestLocator.from_signed_manifest(manifest)
        return ManifestEnvelope(manifest=manifest, locator=locator)
    raise ManifestCodecError("document is neither SignedManifest nor ManifestEnvelope")


def assert_round_trip_signed_manifest(manifest: SignedManifest) -> None:
    """Debug/test helper ensuring the codec preserves canonical bytes exactly."""
    data = signed_manifest_to_bytes(manifest)
    decoded = signed_manifest_from_bytes(data)
    if decoded.canonical_bytes() != data:
        raise ManifestCodecError("SignedManifest codec changed canonical bytes")


def assert_round_trip_envelope(envelope: ManifestEnvelope) -> None:
    data = envelope_to_bytes(envelope)
    decoded = envelope_from_bytes(data)
    if decoded.canonical_bytes() != data:
        raise ManifestCodecError("ManifestEnvelope codec changed canonical bytes")
