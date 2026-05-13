"""Trust backend interface and memory implementation for OProW Step 11.

A trust backend is a pluggable append-only commitment publisher/verifier.  The
backend may be:

* an in-memory test backend;
* ASI:chain;
* another blockchain;
* a witnessed transparency network;
* a multi-backend aggregator.

The interface deliberately does not expose media, raw HDC hypervectors, route
queries, or private claims.  It publishes compact public commitments only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol, runtime_checkable

from oprow.core.identifiers import Hash256, KeyId, NamespaceId

from .models import (
    AnchorRecord,
    AnchorReceipt,
    KeyStatus,
    KeyStatusValue,
    NamespaceRecord,
    RevocationRootRecord,
    TransparencyRootRecord,
    TrustBundleDescriptor,
    VerificationCheck,
    index_root_to_anchor_record,
)


@runtime_checkable
class TrustBackend(Protocol):
    """Protocol implemented by modular OProW trust backends."""

    @property
    def backend_id(self) -> str: ...

    @property
    def network(self) -> str: ...

    def publish_anchor(self, anchor: AnchorRecord) -> AnchorReceipt: ...

    def verify_anchor(self, anchor: AnchorRecord, receipt: AnchorReceipt) -> VerificationCheck: ...

    def resolve_key_status(self, kid: KeyId, at_time: datetime | None = None) -> KeyStatus: ...

    def resolve_trust_bundle(self, bundle_id: str, version: str | None = None) -> TrustBundleDescriptor | None: ...

    def resolve_namespace(self, namespace_id: NamespaceId) -> NamespaceRecord | None: ...


@dataclass
class MemoryTrustBackend:
    """Deterministic test/reference backend.

    This backend stores anchor records and receipts in ordinary Python
    dictionaries.  It gives tests and examples the exact same high-level API as
    ASI:chain without needing network access or private deployment keys.

    Security semantics:
      * This is not decentralized and not append-only beyond process memory.
      * It is useful for exercising the object model, canonical hashes, and
        verifier wiring before plugging in a chain backend.
    """

    backend_id_value: str = "memory-trust-backend"
    network_value: str = "local-memory"
    _anchors_by_record_hash: dict[Hash256, AnchorRecord] = field(default_factory=dict)
    _receipts_by_record_hash: dict[Hash256, AnchorReceipt] = field(default_factory=dict)
    _trust_bundles: dict[tuple[str, str], TrustBundleDescriptor] = field(default_factory=dict)
    _namespaces: dict[NamespaceId, NamespaceRecord] = field(default_factory=dict)
    _key_status: dict[str, KeyStatus] = field(default_factory=dict)

    @property
    def backend_id(self) -> str:
        return self.backend_id_value

    @property
    def network(self) -> str:
        return self.network_value

    def publish_anchor(self, anchor: AnchorRecord) -> AnchorReceipt:
        record_hash = anchor.record_hash()
        receipt = AnchorReceipt(
            backend_id=self.backend_id,
            network=self.network,
            anchor_type=anchor.object_type_value,
            anchored_object_hash=anchor.object_hash,
            anchored_record_hash=record_hash,
            transaction_id=f"memtx:{record_hash.to_hex()[:24]}",
            metadata={"anchor_body": anchor.body, "memory_backend": True},
        )
        self._anchors_by_record_hash[record_hash] = anchor
        self._receipts_by_record_hash[record_hash] = receipt
        return receipt

    def verify_anchor(self, anchor: AnchorRecord, receipt: AnchorReceipt) -> VerificationCheck:
        expected_record_hash = anchor.record_hash()
        if receipt.backend_id != self.backend_id:
            return VerificationCheck(False, "backend_id_mismatch", self.backend_id, {"receipt_backend_id": receipt.backend_id})
        if receipt.network != self.network:
            return VerificationCheck(False, "network_mismatch", self.backend_id, {"receipt_network": receipt.network})
        if receipt.anchored_record_hash != expected_record_hash:
            return VerificationCheck(False, "anchored_record_hash_mismatch", self.backend_id)
        if receipt.anchored_object_hash != anchor.object_hash:
            return VerificationCheck(False, "anchored_object_hash_mismatch", self.backend_id)
        stored = self._anchors_by_record_hash.get(expected_record_hash)
        if stored is None:
            return VerificationCheck(False, "anchor_not_found", self.backend_id)
        if stored.canonical_bytes() != anchor.canonical_bytes():
            return VerificationCheck(False, "stored_anchor_bytes_mismatch", self.backend_id)
        return VerificationCheck(True, "anchor_verified", self.backend_id, {"transaction_id": receipt.transaction_id})

    def publish_index_root(self, root_record: Any) -> AnchorReceipt:
        """Anchor a Step 9 AuthenticatedIndexRootRecord-like object."""
        return self.publish_anchor(index_root_to_anchor_record(root_record))

    def verify_index_root(self, root_record: Any, receipt: AnchorReceipt) -> VerificationCheck:
        return self.verify_anchor(index_root_to_anchor_record(root_record), receipt)

    def publish_transparency_root(self, record: TransparencyRootRecord) -> AnchorReceipt:
        return self.publish_anchor(record.to_anchor_record())

    def publish_trust_bundle(self, descriptor: TrustBundleDescriptor) -> AnchorReceipt:
        self._trust_bundles[(descriptor.bundle_id, descriptor.bundle_version)] = descriptor
        return self.publish_anchor(descriptor.to_anchor_record())

    def publish_namespace_record(self, record: NamespaceRecord) -> AnchorReceipt:
        self._namespaces[record.namespace_id] = record
        return self.publish_anchor(record.to_anchor_record())

    def publish_revocation_root(self, record: RevocationRootRecord) -> AnchorReceipt:
        return self.publish_anchor(record.to_anchor_record())

    def set_key_status(self, status: KeyStatus) -> None:
        self._key_status[str(status.kid)] = status

    def resolve_key_status(self, kid: KeyId, at_time: datetime | None = None) -> KeyStatus:
        status = self._key_status.get(str(kid))
        if status is not None:
            return status
        return KeyStatus(kid=kid, status=KeyStatusValue.UNKNOWN, reason="not_in_memory_backend")

    def resolve_trust_bundle(self, bundle_id: str, version: str | None = None) -> TrustBundleDescriptor | None:
        if version is not None:
            return self._trust_bundles.get((bundle_id, version))
        matches = [desc for (bid, _), desc in self._trust_bundles.items() if bid == bundle_id]
        if not matches:
            return None
        # Deterministic fallback: lexicographically latest version string.  A
        # production bundle resolver should apply semantic-version and validity
        # window rules.
        return sorted(matches, key=lambda d: d.bundle_version)[-1]

    def resolve_namespace(self, namespace_id: NamespaceId) -> NamespaceRecord | None:
        return self._namespaces.get(namespace_id)


@dataclass
class MultiTrustBackend:
    """Small fan-out verifier/publisher for multi-chain anchoring experiments."""

    backends: list[TrustBackend]

    @property
    def backend_id(self) -> str:
        return "multi-trust-backend"

    @property
    def network(self) -> str:
        return "+".join(b.network for b in self.backends)

    def publish_anchor(self, anchor: AnchorRecord) -> AnchorReceipt:
        if not self.backends:
            raise ValueError("MultiTrustBackend requires at least one backend")
        # Return the first receipt for compatibility; callers that need all
        # receipts should call ``publish_anchor_all``.
        return self.backends[0].publish_anchor(anchor)

    def publish_anchor_all(self, anchor: AnchorRecord) -> list[AnchorReceipt]:
        return [backend.publish_anchor(anchor) for backend in self.backends]

    def verify_anchor(self, anchor: AnchorRecord, receipt: AnchorReceipt) -> VerificationCheck:
        for backend in self.backends:
            if backend.backend_id == receipt.backend_id and backend.network == receipt.network:
                return backend.verify_anchor(anchor, receipt)
        return VerificationCheck(False, "no_matching_backend_for_receipt", self.backend_id)

    def resolve_key_status(self, kid: KeyId, at_time: datetime | None = None) -> KeyStatus:
        for backend in self.backends:
            status = backend.resolve_key_status(kid, at_time=at_time)
            if status.status_value != KeyStatusValue.UNKNOWN.value:
                return status
        return KeyStatus(kid=kid, status=KeyStatusValue.UNKNOWN, reason="not_found_in_any_backend")

    def resolve_trust_bundle(self, bundle_id: str, version: str | None = None) -> TrustBundleDescriptor | None:
        for backend in self.backends:
            found = backend.resolve_trust_bundle(bundle_id, version=version)
            if found is not None:
                return found
        return None

    def resolve_namespace(self, namespace_id: NamespaceId) -> NamespaceRecord | None:
        for backend in self.backends:
            found = backend.resolve_namespace(namespace_id)
            if found is not None:
                return found
        return None
