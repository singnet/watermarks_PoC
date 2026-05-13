"""Trust-layer records for OProW Step 11.

This file implements the *chain-agnostic* trust vocabulary that sits above
particular blockchains such as ASI:chain.

Why a separate trust vocabulary?
================================

The OProW verifier already knows how to validate the media/manifest binding:

    watermark/locator -> candidate manifest -> signature -> essence hash

That is deliberately independent of storage and routing.  The trust layer adds a
second kind of evidence: public, append-only commitments that make it difficult
for infrastructure operators to rewrite history.  Examples include:

* a key-transparency log root;
* an authenticated SHORT64-HV index root;
* a trust-bundle descriptor hash;
* a namespace-controller record;
* a revocation-map root.

The key architectural rule is that these commitments are *external evidence*.
They are not inserted into ``SignedManifest`` and therefore do not affect the
manifest locator.  This avoids the self-reference bug where a manifest hash is
computed, anchored, then the receipt is inserted back into the bytes that were
hashed.

What goes on-chain?
===================

Only compact commitments and receipts should be anchored.  Raw media, raw PEDs,
raw HDC hypervectors, live query buckets, route-token query logs, encrypted
private claims, and full manifests should remain off-chain.  A blockchain is an
accountability substrate, not an object store and not a fingerprint database.

This module contains no ASI:chain-specific code.  It defines canonical records
that any trust backend can publish/verify.  ``oprow.asi_chain`` then implements
one concrete backend.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping

from oprow.core.canonical import canonical_cbor_dumps
from oprow.core.enums import TrustEvidenceType
from oprow.core.errors import ValidationError
from oprow.core.hashes import hash_framed
from oprow.core.identifiers import Hash256, KeyId, NamespaceId
from oprow.core.models import TrustEvidence


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _drop_absent(m: Mapping[str, Any]) -> dict[str, Any]:
    """Drop empty optional fields before canonicalization.

    We use this only for optional metadata-like fields.  Required fields are
    retained even when their value is zero or an empty string would be invalid.
    """
    return {k: v for k, v in m.items() if v is not None and v != [] and v != {}}


class AnchorObjectType(str, Enum):
    """Kinds of compact objects the trust layer can anchor.

    The enum values are protocol strings.  They are intentionally not tied to
    ASI:chain contract names because the same record can be anchored through a
    memory backend, ASI:chain, Ethereum, Bitcoin, a Certificate-Transparency-like
    witness network, or multiple backends simultaneously.
    """

    TRANSPARENCY_ROOT = "transparency_root"
    INDEX_ROOT = "index_root"
    TRUST_BUNDLE = "trust_bundle"
    NAMESPACE_RECORD = "namespace_record"
    REVOCATION_ROOT = "revocation_root"
    GENERIC_COMMITMENT = "generic_commitment"


class KeyEventType(str, Enum):
    """Lifecycle events for provenance signing keys.

    Step 11 does not implement a full transparency log service.  It defines the
    canonical key-event record that a future log can append and later anchor.
    """

    ADD = "add"
    ROTATE = "rotate"
    REVOKE = "revoke"
    DELEGATE = "delegate"


class KeyStatusValue(str, Enum):
    """Verifier-facing key-status values returned by trust backends."""

    UNKNOWN = "unknown"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"


@dataclass(frozen=True)
class VerificationCheck:
    """Small success/failure object for trust-layer checks.

    Verification should be explainable.  A boolean is insufficient because users
    and calling code need to distinguish "receipt hash mismatch" from "backend
    unavailable" from "anchored object is well-formed but not accepted by local
    policy".
    """

    ok: bool
    reason: str
    backend_id: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({"ok": self.ok, "reason": self.reason, "backend_id": self.backend_id, "evidence": self.evidence})


@dataclass(frozen=True)
class AnchorRecord:
    """Canonical object submitted to a trust backend.

    ``object_hash`` is the commitment that ultimately matters.  ``body`` may
    include public context such as ``log_id`` or ``tree_size``.  The canonical
    bytes of this record are hashed again to produce ``record_hash``; backends
    usually anchor that record hash rather than each body field independently.

    The double layer is useful:

    * ``object_hash`` commits to the external object, e.g. an authenticated index
      root record or a transparency root record.
    * ``record_hash`` commits to the statement "backend X is anchoring object Y
      as type Z with this public context".
    """

    object_type: str | AnchorObjectType
    object_hash: Hash256
    body: dict[str, Any] = field(default_factory=dict)
    subject_id: str | None = None
    created_at: datetime | None = None
    version: int = 1

    def __post_init__(self) -> None:
        if self.version <= 0:
            raise ValidationError("AnchorRecord.version must be positive")
        typ = self.object_type.value if isinstance(self.object_type, AnchorObjectType) else str(self.object_type)
        if not typ:
            raise ValidationError("AnchorRecord.object_type must be non-empty")

    @property
    def object_type_value(self) -> str:
        return self.object_type.value if isinstance(self.object_type, AnchorObjectType) else str(self.object_type)

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({
            "version": self.version,
            "object_type": self.object_type_value,
            "object_hash": self.object_hash,
            "subject_id": self.subject_id,
            "body": self.body,
            "created_at": self.created_at,
        })

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    def record_hash(self) -> Hash256:
        return Hash256.from_data(self.canonical_bytes())

    @classmethod
    def generic(cls, object_hash: Hash256, *, subject_id: str | None = None, body: Mapping[str, Any] | None = None) -> "AnchorRecord":
        return cls(AnchorObjectType.GENERIC_COMMITMENT, object_hash=object_hash, subject_id=subject_id, body=dict(body or {}))


@dataclass(frozen=True)
class AnchorReceipt:
    """Backend-neutral proof/receipt that an ``AnchorRecord`` was published.

    This receipt is intentionally normalized.  A Bitcoin backend, ASI:chain
    backend, memory backend, or future witness network can all return the same
    outer shape while storing backend-specific data in ``metadata``.

    ``anchored_record_hash`` should equal ``AnchorRecord.record_hash()``.
    ``anchored_object_hash`` should equal ``AnchorRecord.object_hash``.
    Verifiers check both so that an attacker cannot reuse a receipt for a
    different object of the same size or a different public context.
    """

    backend_id: str
    network: str
    anchor_type: str
    anchored_object_hash: Hash256
    anchored_record_hash: Hash256
    transaction_id: str | None = None
    block_hash: str | None = None
    block_height: int | None = None
    finality_proof: bytes | None = None
    observed_at: datetime = field(default_factory=_utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)
    version: int = 1

    def __post_init__(self) -> None:
        if self.version <= 0:
            raise ValidationError("AnchorReceipt.version must be positive")
        if not self.backend_id:
            raise ValidationError("AnchorReceipt.backend_id must be non-empty")
        if not self.network:
            raise ValidationError("AnchorReceipt.network must be non-empty")

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({
            "version": self.version,
            "backend_id": self.backend_id,
            "network": self.network,
            "anchor_type": self.anchor_type,
            "anchored_object_hash": self.anchored_object_hash,
            "anchored_record_hash": self.anchored_record_hash,
            "transaction_id": self.transaction_id,
            "block_hash": self.block_hash,
            "block_height": self.block_height,
            "finality_proof": self.finality_proof,
            "observed_at": self.observed_at,
            "metadata": self.metadata,
        })

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    def receipt_hash(self) -> Hash256:
        return Hash256.from_data(self.canonical_bytes())

    def to_trust_evidence(self, *, evidence_type: TrustEvidenceType | str = TrustEvidenceType.BLOCKCHAIN_ANCHOR_RECEIPT) -> TrustEvidence:
        """Wrap this receipt for attachment to a ManifestEnvelope.

        The receipt remains outside ``SignedManifest``.  This helper is useful
        when a publisher wants to distribute manifest + receipt together while
        keeping the watermark locator stable.
        """
        return TrustEvidence(evidence_type=evidence_type, body=self.to_canonical())


@dataclass(frozen=True)
class TransparencyRootRecord:
    """Checkpoint for an append-only key-transparency log.

    A full transparency log needs inclusion/consistency proofs and append-only
    semantics.  This record is just the compact root checkpoint that a backend
    anchors periodically.
    """

    log_id: str
    tree_size: int
    root_hash: Hash256
    previous_root_hash: Hash256 | None = None
    period_start: datetime | None = None
    period_end: datetime | None = None
    operator_kid: KeyId | None = None
    operator_signature: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    version: int = 1

    def __post_init__(self) -> None:
        if not self.log_id:
            raise ValidationError("TransparencyRootRecord.log_id is required")
        if self.tree_size < 0:
            raise ValidationError("TransparencyRootRecord.tree_size must be non-negative")

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({
            "version": self.version,
            "log_id": self.log_id,
            "tree_size": self.tree_size,
            "root_hash": self.root_hash,
            "previous_root_hash": self.previous_root_hash,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "operator_kid": self.operator_kid,
            "operator_signature": self.operator_signature,
            "metadata": self.metadata,
        })

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    def record_hash(self) -> Hash256:
        return Hash256.from_data(self.canonical_bytes())

    def to_anchor_record(self) -> AnchorRecord:
        return AnchorRecord(
            object_type=AnchorObjectType.TRANSPARENCY_ROOT,
            object_hash=self.record_hash(),
            subject_id=self.log_id,
            body={"log_id": self.log_id, "tree_size": self.tree_size, "root_hash": self.root_hash},
        )


@dataclass(frozen=True)
class TrustBundleDescriptor:
    """Public descriptor for a signed trust bundle.

    The full trust bundle may be large and should normally live in CAS/IPFS/HTTP
    mirrors.  The descriptor commits to it with ``bundle_hash`` and gives
    non-authoritative retrieval hints.  Anchoring the descriptor record prevents
    a bundle issuer from silently rewriting history.
    """

    bundle_id: str
    bundle_version: str
    bundle_hash: Hash256
    issuer_kid: KeyId | None = None
    bundle_uri: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    signature: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    version: int = 1

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({
            "version": self.version,
            "bundle_id": self.bundle_id,
            "bundle_version": self.bundle_version,
            "bundle_hash": self.bundle_hash,
            "issuer_kid": self.issuer_kid,
            "bundle_uri": self.bundle_uri,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "signature": self.signature,
            "metadata": self.metadata,
        })

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    def record_hash(self) -> Hash256:
        return Hash256.from_data(self.canonical_bytes())

    def to_anchor_record(self) -> AnchorRecord:
        return AnchorRecord(
            object_type=AnchorObjectType.TRUST_BUNDLE,
            object_hash=self.record_hash(),
            subject_id=self.bundle_id,
            body={"bundle_id": self.bundle_id, "bundle_version": self.bundle_version, "bundle_hash": self.bundle_hash, "bundle_uri": self.bundle_uri},
        )


@dataclass(frozen=True)
class NamespaceRecord:
    """Controller record for a namespaced SHORT64 allocation.

    Namespaces help avoid arbitrary short-ID flooding.  A namespace controller
    can sign and rate-limit records for its prefix.  The blockchain/trust backend
    should anchor the controller record and revocations, not every media item.
    """

    namespace_id: NamespaceId
    controller_kid: KeyId
    display_name: str | None = None
    policy_uri: str | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    signature: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    version: int = 1

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({
            "version": self.version,
            "namespace_id": self.namespace_id,
            "controller_kid": self.controller_kid,
            "display_name": self.display_name,
            "policy_uri": self.policy_uri,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "signature": self.signature,
            "metadata": self.metadata,
        })

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    def record_hash(self) -> Hash256:
        return Hash256.from_data(self.canonical_bytes())

    def to_anchor_record(self) -> AnchorRecord:
        return AnchorRecord(
            object_type=AnchorObjectType.NAMESPACE_RECORD,
            object_hash=self.record_hash(),
            subject_id=self.namespace_id.to_tagged(),
            body={"namespace_id": self.namespace_id, "controller_kid": self.controller_kid, "display_name": self.display_name},
        )


@dataclass(frozen=True)
class RevocationRootRecord:
    """Checkpoint for a revocation map/log.

    A production revocation system may be a CRL, OCSP-like service, transparency
    log, or sparse Merkle map.  This record anchors its compact root.
    """

    revocation_set_id: str
    root_hash: Hash256
    entry_count: int = 0
    valid_at: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    version: int = 1

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({
            "version": self.version,
            "revocation_set_id": self.revocation_set_id,
            "root_hash": self.root_hash,
            "entry_count": self.entry_count,
            "valid_at": self.valid_at,
            "metadata": self.metadata,
        })

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    def record_hash(self) -> Hash256:
        return Hash256.from_data(self.canonical_bytes())

    def to_anchor_record(self) -> AnchorRecord:
        return AnchorRecord(
            object_type=AnchorObjectType.REVOCATION_ROOT,
            object_hash=self.record_hash(),
            subject_id=self.revocation_set_id,
            body={"revocation_set_id": self.revocation_set_id, "root_hash": self.root_hash, "entry_count": self.entry_count},
        )


@dataclass(frozen=True)
class KeyEvent:
    """Canonical key-lifecycle event for future transparency logs."""

    subject_id: str
    event_type: str | KeyEventType
    kid: KeyId
    public_key_hash: Hash256 | None = None
    prev_event_hash: Hash256 | None = None
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    controller_kid: KeyId | None = None
    signature: bytes | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    version: int = 1

    @property
    def event_type_value(self) -> str:
        return self.event_type.value if isinstance(self.event_type, KeyEventType) else str(self.event_type)

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({
            "version": self.version,
            "subject_id": self.subject_id,
            "event_type": self.event_type_value,
            "kid": self.kid,
            "public_key_hash": self.public_key_hash,
            "prev_event_hash": self.prev_event_hash,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "controller_kid": self.controller_kid,
            "signature": self.signature,
            "metadata": self.metadata,
        })

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    def event_hash(self) -> Hash256:
        return Hash256.from_data(self.canonical_bytes())


@dataclass(frozen=True)
class KeyStatus:
    """Status answer for a signing key at a point in time."""

    kid: KeyId
    status: str | KeyStatusValue = KeyStatusValue.UNKNOWN
    reason: str = "not_checked"
    checked_at: datetime = field(default_factory=_utc_now)
    valid_from: datetime | None = None
    valid_until: datetime | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def status_value(self) -> str:
        return self.status.value if isinstance(self.status, KeyStatusValue) else str(self.status)

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({
            "kid": self.kid,
            "status": self.status_value,
            "reason": self.reason,
            "checked_at": self.checked_at,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "evidence": self.evidence,
        })


def index_root_to_anchor_record(root_record: Any) -> AnchorRecord:
    """Convert Step 9 ``AuthenticatedIndexRootRecord``-like objects to anchors.

    The function is intentionally duck-typed: it only needs the object to expose
    ``record_hash()``, ``index_id``, ``epoch_id``, and ``root_hash``.  This keeps
    the trust layer decoupled from the authmap package and avoids circular
    imports in lightweight deployments.
    """
    try:
        object_hash = root_record.record_hash()
        body = {
            "index_id": root_record.index_id,
            "epoch_id": root_record.epoch_id,
            "root_hash": root_record.root_hash,
            "profile_id": getattr(root_record, "profile_id", None),
            "map_alg_id": getattr(root_record, "map_alg_id", None),
            "route_key_count": getattr(root_record, "route_key_count", None),
            "candidate_reference_count": getattr(root_record, "candidate_reference_count", None),
        }
        subject_id = f"{root_record.index_id}:{root_record.epoch_id}"
    except AttributeError as exc:
        raise ValidationError("root_record does not look like an AuthenticatedIndexRootRecord") from exc
    return AnchorRecord(object_type=AnchorObjectType.INDEX_ROOT, object_hash=object_hash, subject_id=subject_id, body=body)


def domain_hash_for_test_anchor(label: str, *parts: bytes) -> Hash256:
    """Convenience helper used by tests/examples to make deterministic roots."""
    return Hash256(hash_framed("oprow-step11-test-anchor", label.encode("utf-8"), *parts))
