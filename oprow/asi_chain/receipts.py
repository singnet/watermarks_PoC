"""ASI:chain-specific receipt records for OProW Step 11.

The core trust layer exposes backend-neutral ``AnchorReceipt`` objects.  This
module adds an ASI:chain-flavored receipt with fields a developer will expect
when debugging a chain deployment: deploy id, transaction hash, block reference,
contract/channel label, and raw node response.

The ASI-specific receipt is not required for generic verification.  It is stored
inside ``AnchorReceipt.metadata`` so verifiers can ignore it unless they want to
show ASI:chain-specific details or re-query the DevNet/explorer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from oprow.core.canonical import canonical_cbor_dumps
from oprow.core.identifiers import Hash256


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _drop_absent(m: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in m.items() if v is not None and v != [] and v != {}}


@dataclass(frozen=True)
class ASIChainReceipt:
    """Normalized ASI:chain publication receipt.

    ``deploy_id`` is the identifier returned by a deployment path.  On some
    RChain-derived systems, deploy identifiers and block inclusion details are
    obtained through separate APIs.  The reference adapter therefore allows
    partial receipts: a publish call can return a deploy/transaction id now and a
    later monitor can fill block/finality fields.
    """

    network: str
    api_base_url: str | None
    deploy_id: str | None
    transaction_hash: str | None
    contract_label: str
    anchored_record_hash: Hash256
    anchored_object_hash: Hash256
    block_hash: str | None = None
    block_height: int | None = None
    finality_proof: bytes | None = None
    rholang_term_hash: Hash256 | None = None
    observed_at: datetime = field(default_factory=_utc_now)
    raw_response: dict[str, Any] = field(default_factory=dict)
    version: int = 1

    def to_canonical(self) -> dict[str, Any]:
        return _drop_absent({
            "version": self.version,
            "network": self.network,
            "api_base_url": self.api_base_url,
            "deploy_id": self.deploy_id,
            "transaction_hash": self.transaction_hash,
            "contract_label": self.contract_label,
            "anchored_record_hash": self.anchored_record_hash,
            "anchored_object_hash": self.anchored_object_hash,
            "block_hash": self.block_hash,
            "block_height": self.block_height,
            "finality_proof": self.finality_proof,
            "rholang_term_hash": self.rholang_term_hash,
            "observed_at": self.observed_at,
            "raw_response": self.raw_response,
        })

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    def receipt_hash(self) -> Hash256:
        return Hash256.from_data(self.canonical_bytes())
