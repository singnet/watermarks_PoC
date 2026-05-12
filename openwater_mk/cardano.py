"""Cardano metadata anchoring per §16.6 of the OpenWater design doc.

Implements the metadata-transaction path (Approach 1), which the design
doc identifies as the fastest path to a deployable V1: Cardano metadata
publishes a compact commitment to a canonical OpenWater anchor record;
the full record + operator signature live off-chain on Arweave/IPFS.

This module provides:

- :class:`AnchorRecord`           canonical, signable anchor record
- :func:`anchor_record_hash`      H256 of canonical CBOR
- :func:`build_metadata_payload`  compact CBOR-friendly Cardano metadata map
- :class:`AnchorReceipt`          normalized receipt returned after submit
- :class:`MockCardanoBackend`     in-process backend used for the POC
- :class:`BlockfrostCardanoBackend` stub for the real path

No real Cardano transactions are submitted in the default ("mock") flow.
The mock backend persists a JSON "ledger" file under a configurable root
so that ``submit`` and ``fetch_transaction`` round-trip across processes,
which is what the verifier needs to do.

The metadata label ``40961`` is the experimental label recommended for
MVP use by the design doc. It should be replaced with a community-agreed
label or registry entry before production.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from oprow.core.canonical import canonical_cbor_dumps


OPENWATER_CARDANO_METADATA_LABEL: int = 40961
ANCHOR_PROFILE: str = "openwater-cardano-anchor-v1"
ANCHOR_SCHEMA_VERSION: int = 1


# ---------------------------------------------------------------------------
# Anchor record (signable, chain-independent)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AnchorRecord:
    """Chain-independent OpenWater anchor record.

    Mirrors §16.6.5 of the design doc. Fields:

    - ``record_type``    short string, e.g. "index_root", "manifest_root"
    - ``subject_id``     opaque bytes; what is being anchored (namespace, manifest, etc.)
    - ``epoch``          monotonic integer epoch within the subject
    - ``root_hash``      32-byte commitment over the subject's state
    - ``ar_ref``         optional ``ar://`` URI of the off-chain anchor object
    - ``ip_ref``         optional ``ipfs://`` URI of the off-chain anchor object
    - ``operator_kid``   key id (string) of the signing operator
    - ``created_at``     ISO8601 timestamp (off-chain bookkeeping)
    """

    record_type: str
    subject_id: bytes
    epoch: int
    root_hash: bytes
    operator_kid: str
    ar_ref: str | None = None
    ip_ref: str | None = None
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self) -> None:
        if len(self.root_hash) != 32:
            raise ValueError("root_hash must be 32 bytes (sha256)")
        if not self.record_type:
            raise ValueError("record_type must be non-empty")
        if self.epoch < 0:
            raise ValueError("epoch must be non-negative")

    def to_canonical(self) -> dict[str, Any]:
        """Field order is deterministic for canonical CBOR encoding."""
        out: dict[str, Any] = {
            "p": ANCHOR_PROFILE,
            "v": ANCHOR_SCHEMA_VERSION,
            "t": self.record_type,
            "sid": self.subject_id,
            "e": self.epoch,
            "rh": self.root_hash,
            "ok": self.operator_kid,
            "ts": self.created_at,
        }
        if self.ar_ref:
            out["ar"] = self.ar_ref
        if self.ip_ref:
            out["ip"] = self.ip_ref
        return out


def canonical_anchor_bytes(record: AnchorRecord) -> bytes:
    return canonical_cbor_dumps(record.to_canonical())


def anchor_record_hash(record: AnchorRecord) -> bytes:
    return hashlib.sha256(canonical_anchor_bytes(record)).digest()


def operator_kid_short(kid: str) -> bytes:
    """Compact representation of the operator key id for on-chain payload."""
    return hashlib.sha256(kid.encode("utf-8")).digest()[:16]


def build_metadata_payload(
    record: AnchorRecord,
    *,
    label: int = OPENWATER_CARDANO_METADATA_LABEL,
) -> dict[int, dict[str, Any]]:
    """Compact Cardano metadata structure committing to an AnchorRecord.

    Returns ``{label: payload}``. ``payload`` follows the schema sketched
    in §16.6.4:

      { v, p, t, sid, e, rh, ah, refs?, ok }

    Long fields are kept as bytes/short strings so that the canonical CBOR
    encoding stays well under the Cardano metadata string-size limits
    (64-byte strings/bytestrings).
    """
    payload: dict[str, Any] = {
        "v": ANCHOR_SCHEMA_VERSION,
        "p": ANCHOR_PROFILE,
        "t": record.record_type,
        "sid": record.subject_id,
        "e": record.epoch,
        "rh": record.root_hash,
        "ah": anchor_record_hash(record),
        "ok": operator_kid_short(record.operator_kid),
    }
    refs: dict[str, str] = {}
    if record.ar_ref:
        refs["ar"] = record.ar_ref
    if record.ip_ref:
        refs["ip"] = record.ip_ref
    if refs:
        payload["refs"] = refs
    return {label: payload}


def metadata_payload_size_bytes(payload: Mapping[int, Mapping[str, Any]]) -> int:
    """CBOR size of the metadata payload (rough fee estimator)."""
    return len(canonical_cbor_dumps({str(k): v for k, v in payload.items()}))


# ---------------------------------------------------------------------------
# Anchor receipt (returned after submit)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AnchorReceipt:
    """Normalized anchor receipt; chain-agnostic envelope around evidence."""

    backend: str
    network: str
    anchor_record_hash: bytes
    metadata_label: int
    chain_evidence: dict[str, Any]
    submitted_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_json(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "network": self.network,
            "anchor_record_hash": self.anchor_record_hash.hex(),
            "metadata_label": self.metadata_label,
            "chain_evidence": {
                k: (v.hex() if isinstance(v, bytes) else v)
                for k, v in self.chain_evidence.items()
            },
            "submitted_at": self.submitted_at,
        }

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> "AnchorReceipt":
        ev = dict(data["chain_evidence"])
        return cls(
            backend=data["backend"],
            network=data["network"],
            anchor_record_hash=bytes.fromhex(data["anchor_record_hash"]),
            metadata_label=int(data["metadata_label"]),
            chain_evidence=ev,
            submitted_at=data.get("submitted_at", ""),
        )


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------


@dataclass
class MockCardanoBackend:
    """Process-local fake Cardano backend used for the POC.

    The "ledger" is a single JSON file at ``ledger_path``. Each call to
    :meth:`submit` appends a fake transaction shaped like a real Cardano
    metadata transaction (random 32-byte tx hash, monotonically increasing
    slot, fake block hash). :meth:`fetch_transaction` looks the tx back up
    by hash. This is enough to drive the verification flow end-to-end and
    test the metadata schema before any real wallet is involved.
    """

    ledger_path: Path
    network: str = "mock"
    name: str = "mock_cardano"

    def __post_init__(self) -> None:
        self.ledger_path = Path(self.ledger_path)
        self.ledger_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.ledger_path.exists():
            self.ledger_path.write_text(json.dumps({"txs": []}, indent=2))

    def _load(self) -> dict[str, Any]:
        return json.loads(self.ledger_path.read_text())

    def _save(self, data: dict[str, Any]) -> None:
        self.ledger_path.write_text(json.dumps(data, indent=2))

    def submit(
        self,
        metadata: Mapping[int, Mapping[str, Any]],
    ) -> dict[str, Any]:
        # Reduce metadata to canonical bytes for the on-chain "size" estimate.
        size = metadata_payload_size_bytes(metadata)

        data = self._load()
        slot = (data["txs"][-1]["slot"] + 1) if data["txs"] else int(time.time())
        tx_hash = secrets.token_bytes(32)
        block_hash = secrets.token_bytes(32)
        tx = {
            "tx_hash": tx_hash.hex(),
            "slot": slot,
            "block_hash": block_hash.hex(),
            "block_height": slot,  # 1:1 in mock
            "metadata_size_bytes": size,
            "metadata": {
                str(k): _cbor_friendly_to_json(v) for k, v in metadata.items()
            },
            "metadata_label": next(iter(metadata)),
        }
        data["txs"].append(tx)
        self._save(data)
        return tx

    def fetch_transaction(self, tx_hash_hex: str) -> dict[str, Any] | None:
        for tx in self._load()["txs"]:
            if tx["tx_hash"] == tx_hash_hex:
                return tx
        return None


def _cbor_friendly_to_json(value: Any) -> Any:
    """Render a CBOR-friendly value into a JSON-safe form (bytes -> hex)."""
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Mapping):
        return {str(k): _cbor_friendly_to_json(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_cbor_friendly_to_json(v) for v in value]
    return value


def _json_to_cbor_friendly(value: Any, hex_keys: Iterable[str] = ()) -> Any:
    """Inverse of :func:`_cbor_friendly_to_json` for designated hex fields."""
    hex_keys = set(hex_keys)
    if isinstance(value, Mapping):
        return {
            k: (bytes.fromhex(v) if k in hex_keys and isinstance(v, str) else _json_to_cbor_friendly(v, hex_keys))
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_json_to_cbor_friendly(v, hex_keys) for v in value]
    return value


@dataclass
class BlockfrostCardanoBackend:
    """Real Cardano via Blockfrost API. Stub.

    Wiring once the project_id is available:

        import requests
        BASE = "https://cardano-preprod.blockfrost.io/api/v0"
        headers = {"project_id": os.environ["BLOCKFROST_PROJECT_ID"]}

        # submit needs a built+signed tx (pycardano + a funded wallet)
        # fetch is straightforward:
        r = requests.get(f"{BASE}/txs/{tx_hash}/metadata", headers=headers)
    """

    project_id: str | None = field(default_factory=lambda: os.environ.get("BLOCKFROST_PROJECT_ID"))
    network: str = "preprod"
    name: str = "blockfrost_cardano"

    def submit(self, metadata: Mapping[int, Mapping[str, Any]]) -> dict[str, Any]:  # pragma: no cover
        raise NotImplementedError("Blockfrost submit requires pycardano + funded wallet; see V1 doc")

    def fetch_transaction(self, tx_hash_hex: str) -> dict[str, Any] | None:  # pragma: no cover
        raise NotImplementedError("Blockfrost fetch needs project_id + requests; see V1 doc")


# ---------------------------------------------------------------------------
# Top-level publish + verify
# ---------------------------------------------------------------------------


METADATA_HEX_KEYS = {"sid", "rh", "ah", "ok"}


@dataclass(frozen=True)
class AnchorResult:
    anchor_record: AnchorRecord
    receipt: AnchorReceipt
    anchor_record_path: Path
    receipt_path: Path
    metadata_path: Path


def publish_anchor(
    *,
    record: AnchorRecord,
    backend: MockCardanoBackend | BlockfrostCardanoBackend,
    out_dir: Path,
) -> AnchorResult:
    """Publish an anchor record via the chosen backend; persist artifacts."""
    out_dir.mkdir(parents=True, exist_ok=True)

    metadata = build_metadata_payload(record)
    tx = backend.submit(metadata)

    receipt = AnchorReceipt(
        backend=backend.name,
        network=backend.network,
        anchor_record_hash=anchor_record_hash(record),
        metadata_label=OPENWATER_CARDANO_METADATA_LABEL,
        chain_evidence={
            "mode": "metadata",
            "tx_hash": tx["tx_hash"],
            "slot": tx["slot"],
            "block_hash": tx["block_hash"],
            "block_height": tx.get("block_height"),
            "metadata_label": tx["metadata_label"],
            "metadata_size_bytes": tx["metadata_size_bytes"],
        },
    )

    anchor_path = out_dir / "anchor_record.json"
    anchor_path.write_text(json.dumps(_anchor_to_json(record), indent=2))
    receipt_path = out_dir / "receipt.json"
    receipt_path.write_text(json.dumps(receipt.to_json(), indent=2))
    metadata_path = out_dir / "metadata.json"
    metadata_path.write_text(json.dumps(
        {str(k): _cbor_friendly_to_json(v) for k, v in metadata.items()},
        indent=2,
    ))

    return AnchorResult(
        anchor_record=record,
        receipt=receipt,
        anchor_record_path=anchor_path,
        receipt_path=receipt_path,
        metadata_path=metadata_path,
    )


def _anchor_to_json(record: AnchorRecord) -> dict[str, Any]:
    d = asdict(record)
    d["subject_id"] = record.subject_id.hex()
    d["root_hash"] = record.root_hash.hex()
    return d


def _anchor_from_json(data: Mapping[str, Any]) -> AnchorRecord:
    return AnchorRecord(
        record_type=data["record_type"],
        subject_id=bytes.fromhex(data["subject_id"]),
        epoch=int(data["epoch"]),
        root_hash=bytes.fromhex(data["root_hash"]),
        operator_kid=data["operator_kid"],
        ar_ref=data.get("ar_ref"),
        ip_ref=data.get("ip_ref"),
        created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
    )


@dataclass(frozen=True)
class AnchorVerification:
    ok: bool
    failures: tuple[str, ...]
    chain_evidence: dict[str, Any]


def verify_anchor(
    *,
    record: AnchorRecord,
    receipt: AnchorReceipt,
    backend: MockCardanoBackend | BlockfrostCardanoBackend,
    min_confirmations: int = 1,
) -> AnchorVerification:
    """Verify an anchor according to §16.6.6 of the design doc.

    Checks:
      1. Anchor record hash matches the receipt.
      2. Transaction exists in the backend's ledger.
      3. Block height advanced past ``min_confirmations``.
      4. On-chain metadata fields match the anchor record.
    """
    failures: list[str] = []

    recomputed_hash = anchor_record_hash(record)
    if recomputed_hash != receipt.anchor_record_hash:
        failures.append(
            "anchor_record_hash mismatch: "
            f"receipt={receipt.anchor_record_hash.hex()} "
            f"recomputed={recomputed_hash.hex()}"
        )

    tx_hash = receipt.chain_evidence.get("tx_hash")
    if not tx_hash:
        failures.append("receipt.chain_evidence missing tx_hash")
        tx = None
    else:
        tx = backend.fetch_transaction(tx_hash)
        if tx is None:
            failures.append(f"transaction {tx_hash} not found via backend {backend.name}")

    chain_evidence: dict[str, Any] = {"backend": backend.name}
    if tx is not None:
        chain_evidence.update(
            tx_hash=tx["tx_hash"],
            slot=tx["slot"],
            block_hash=tx["block_hash"],
            block_height=tx.get("block_height"),
        )
        # Mock ledger uses block_height == len(txs after submit). For mock
        # the "confirmations" count = total ledger length - this block_height + 1.
        # For Blockfrost this would use a chain-tip lookup.
        block_height = tx.get("block_height", 0)
        if isinstance(backend, MockCardanoBackend):
            tip = max((t.get("block_height", 0) for t in backend._load()["txs"]), default=0)
            confirmations = max(0, tip - block_height + 1)
            chain_evidence["confirmations"] = confirmations
            if confirmations < min_confirmations:
                failures.append(
                    f"insufficient confirmations: have {confirmations}, need {min_confirmations}"
                )

        label_str = str(receipt.metadata_label)
        md_payload = tx.get("metadata", {}).get(label_str)
        if not md_payload:
            failures.append(f"metadata label {label_str} not present in tx")
        else:
            expected = _cbor_friendly_to_json(
                build_metadata_payload(record)[receipt.metadata_label]
            )
            for key, value in expected.items():
                if md_payload.get(key) != value:
                    failures.append(
                        f"metadata field {key!r} mismatch: tx={md_payload.get(key)!r} expected={value!r}"
                    )

    return AnchorVerification(
        ok=not failures,
        failures=tuple(failures),
        chain_evidence=chain_evidence,
    )


__all__ = [
    "OPENWATER_CARDANO_METADATA_LABEL",
    "ANCHOR_PROFILE",
    "ANCHOR_SCHEMA_VERSION",
    "AnchorRecord",
    "AnchorReceipt",
    "AnchorResult",
    "AnchorVerification",
    "MockCardanoBackend",
    "BlockfrostCardanoBackend",
    "anchor_record_hash",
    "canonical_anchor_bytes",
    "build_metadata_payload",
    "metadata_payload_size_bytes",
    "publish_anchor",
    "verify_anchor",
    "_anchor_to_json",
    "_anchor_from_json",
]
