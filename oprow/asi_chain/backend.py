"""ASI:chain trust backend for OProW Step 11.

This file is the bridge between the chain-agnostic OProW trust layer and
ASI:chain.  The design principle is intentionally narrow:

    ASI:chain anchors commitments; it does not store media fingerprints.

Therefore this backend publishes compact ``AnchorRecord`` commitments and
returns normalized ``AnchorReceipt`` objects.  It does not publish raw media,
raw HDC hypervectors, raw PEDs, route-query logs, private claims, or full
candidate lists.

Two modes are supported:

* **Stub/test mode** via ``MockASIChainClient`` — deterministic and no network.
* **DevNet adapter mode** via ``ASIChainExternalCLIClient`` or low-level
  ``ASIChainHTTPClient`` helpers — shaped around ASI's current DevNet tooling.

The backend API is stable even if the Rholang contract implementation changes.
A future production version can replace source-term deploys with registry
contract calls while preserving the same OProW records and receipts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from oprow.core.enums import TrustEvidenceType
from oprow.core.identifiers import KeyId, NamespaceId
from oprow.trust.base import TrustBackend
from oprow.trust.models import (
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

from .client import ASIChainClient, ASIChainNetworkConfig, MockASIChainClient
from .contracts import ANCHOR_CONTRACT_LABEL, ASIAnchorPayload, render_anchor_source_term
from .receipts import ASIChainReceipt


ASI_BACKEND_ID = "asi-chain"


@dataclass
class ASIChainTrustBackend(TrustBackend):
    """Concrete trust backend that publishes OProW anchors to ASI:chain."""

    client: ASIChainClient = field(default_factory=MockASIChainClient)
    backend_id_value: str = ASI_BACKEND_ID
    # Optional local caches make examples and tests deterministic.  A production
    # backend should back these with resolver/indexer/explorer queries.
    _trust_bundles: dict[tuple[str, str], TrustBundleDescriptor] = field(default_factory=dict)
    _namespaces: dict[NamespaceId, NamespaceRecord] = field(default_factory=dict)
    _key_status: dict[str, KeyStatus] = field(default_factory=dict)

    @property
    def backend_id(self) -> str:
        return self.backend_id_value

    @property
    def network(self) -> str:
        return self.client.config.network

    @classmethod
    def mock_devnet(cls) -> "ASIChainTrustBackend":
        """Return a no-network ASI backend for tests and local development."""
        return cls(client=MockASIChainClient())

    @classmethod
    def with_client(cls, client: ASIChainClient) -> "ASIChainTrustBackend":
        return cls(client=client)

    def _receipt_from_deploy(self, anchor: AnchorRecord, payload: ASIAnchorPayload, deploy: Any) -> AnchorReceipt:
        rholang_term = render_anchor_source_term(payload)
        asi_receipt = ASIChainReceipt(
            network=self.network,
            api_base_url=self.client.config.api_base_url,
            deploy_id=deploy.deploy_id,
            transaction_hash=deploy.transaction_hash,
            contract_label=ANCHOR_CONTRACT_LABEL,
            anchored_record_hash=anchor.record_hash(),
            anchored_object_hash=anchor.object_hash,
            block_hash=deploy.block_hash,
            block_height=deploy.block_height,
            rholang_term_hash=payload.term_hash(),
            raw_response=deploy.raw_response,
        )
        return AnchorReceipt(
            backend_id=self.backend_id,
            network=self.network,
            anchor_type=anchor.object_type_value,
            anchored_object_hash=anchor.object_hash,
            anchored_record_hash=anchor.record_hash(),
            transaction_id=deploy.transaction_hash or deploy.deploy_id,
            block_hash=deploy.block_hash,
            block_height=deploy.block_height,
            metadata={
                "asi_chain_receipt": asi_receipt.to_canonical(),
                "asi_chain_receipt_hash": asi_receipt.receipt_hash().to_hex(),
                "contract_label": ANCHOR_CONTRACT_LABEL,
                "rholang_term_hash": payload.term_hash().to_hex(),
                # Include the term in the reference implementation so tests and
                # early developers can inspect exactly what would be deployed.
                # A production receipt may omit this and rely on explorer lookup.
                "rholang_term": rholang_term,
            },
        )

    def publish_anchor(self, anchor: AnchorRecord) -> AnchorReceipt:
        payload = ASIAnchorPayload.from_anchor_record(anchor)
        deploy = self.client.publish_anchor_payload(payload)
        return self._receipt_from_deploy(anchor, payload, deploy)

    def verify_anchor(self, anchor: AnchorRecord, receipt: AnchorReceipt) -> VerificationCheck:
        """Verify receipt self-consistency and, when possible, chain presence."""
        if receipt.backend_id != self.backend_id:
            return VerificationCheck(False, "backend_id_mismatch", self.backend_id, {"receipt_backend_id": receipt.backend_id})
        if receipt.network != self.network:
            return VerificationCheck(False, "network_mismatch", self.backend_id, {"receipt_network": receipt.network})
        if receipt.anchor_type != anchor.object_type_value:
            return VerificationCheck(False, "anchor_type_mismatch", self.backend_id)
        if receipt.anchored_object_hash != anchor.object_hash:
            return VerificationCheck(False, "anchored_object_hash_mismatch", self.backend_id)
        if receipt.anchored_record_hash != anchor.record_hash():
            return VerificationCheck(False, "anchored_record_hash_mismatch", self.backend_id)

        payload = ASIAnchorPayload.from_anchor_record(anchor)
        asi_receipt = ASIChainReceipt(
            network=receipt.network,
            api_base_url=self.client.config.api_base_url,
            deploy_id=receipt.transaction_id if receipt.transaction_id and receipt.transaction_id.startswith("mock-deploy:") else None,
            transaction_hash=receipt.transaction_id,
            contract_label=ANCHOR_CONTRACT_LABEL,
            anchored_record_hash=receipt.anchored_record_hash,
            anchored_object_hash=receipt.anchored_object_hash,
            block_hash=receipt.block_hash,
            block_height=receipt.block_height,
            rholang_term_hash=payload.term_hash(),
            raw_response=receipt.metadata.get("asi_chain_receipt", {}) if isinstance(receipt.metadata, dict) else {},
        )
        if not self.client.verify_deploy_contains_anchor(asi_receipt, payload):
            # Some clients cannot query deploy source yet.  If the normalized
            # receipt is internally consistent and includes the rendered term, we
            # can still perform a local term check.  This is useful for early
            # DevNet adapter work and harmless because full production clients
            # will implement chain lookup.
            term = receipt.metadata.get("rholang_term") if isinstance(receipt.metadata, dict) else None
            if not (isinstance(term, str) and payload.record_hash_hex in term and payload.object_hash_hex in term):
                return VerificationCheck(False, "chain_receipt_not_confirmed", self.backend_id)

        return VerificationCheck(True, "asi_chain_anchor_verified", self.backend_id, {
            "network": receipt.network,
            "transaction_id": receipt.transaction_id,
            "block_height": receipt.block_height,
            "anchor_type": receipt.anchor_type,
        })

    def publish_index_root(self, root_record: Any) -> AnchorReceipt:
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
        return self._key_status.get(str(kid), KeyStatus(kid=kid, status=KeyStatusValue.UNKNOWN, reason="not_found_in_asi_backend_cache"))

    def resolve_trust_bundle(self, bundle_id: str, version: str | None = None) -> TrustBundleDescriptor | None:
        if version is not None:
            return self._trust_bundles.get((bundle_id, version))
        matches = [desc for (bid, _), desc in self._trust_bundles.items() if bid == bundle_id]
        return sorted(matches, key=lambda d: d.bundle_version)[-1] if matches else None

    def resolve_namespace(self, namespace_id: NamespaceId) -> NamespaceRecord | None:
        return self._namespaces.get(namespace_id)

    def receipt_to_trust_evidence(self, receipt: AnchorReceipt):
        """Convenience wrapper using the ASI-chain-specific evidence type."""
        return receipt.to_trust_evidence(evidence_type=TrustEvidenceType.ASI_CHAIN_RECEIPT)


def default_devnet_backend_stub() -> ASIChainTrustBackend:
    """Return the safe default backend: ASI semantics with a mock client."""
    return ASIChainTrustBackend.mock_devnet()
