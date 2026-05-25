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
- :class:`BlockfrostCardanoBackend` real testnet/mainnet Blockfrost backend

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
import inspect
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from oprow.core.canonical import canonical_cbor_dumps


OPENWATER_CARDANO_METADATA_LABEL: int = 40961
ANCHOR_PROFILE: str = "openwater-cardano-anchor-v1"
ANCHOR_SCHEMA_VERSION: int = 1
CARDANO_BACKEND_NAMES: tuple[str, ...] = ("mock", "blockfrost")
CARDANO_NETWORK_NAMES: tuple[str, ...] = ("preprod", "preview", "mainnet")
DEFAULT_BLOCKFROST_URLS: dict[str, str] = {
    "preprod": "https://cardano-preprod.blockfrost.io/api/v0",
    "preview": "https://cardano-preview.blockfrost.io/api/v0",
    "mainnet": "https://cardano-mainnet.blockfrost.io/api/v0",
}
DEFAULT_HTTP_TIMEOUT_SECONDS = 60


def _urlopen_bytes(
    request: str | urllib.request.Request,
    *,
    timeout: int = DEFAULT_HTTP_TIMEOUT_SECONDS,
) -> bytes:
    """Small urllib wrapper so tests can monkeypatch Blockfrost calls."""
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


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
    """Real Cardano backend using Blockfrost and optional pycardano.

    Fetching uses Blockfrost directly. Submitting requires ``pycardano`` plus a
    funded wallet configured via:

    - ``BLOCKFROST_PROJECT_ID``
    - ``OPENWATER_CARDANO_NETWORK`` (``preprod`` by default)
    - ``OPENWATER_CARDANO_PAYMENT_SKEY``
    - ``OPENWATER_CARDANO_PAYMENT_ADDRESS``

    The submit path creates a small self-transfer carrying OpenWater metadata.
    """

    project_id: str | None = field(default_factory=lambda: os.environ.get("BLOCKFROST_PROJECT_ID"))
    network: str = field(default_factory=lambda: os.environ.get("OPENWATER_CARDANO_NETWORK", "preprod"))
    base_url: str | None = field(default_factory=lambda: os.environ.get("OPENWATER_CARDANO_BLOCKFROST_URL"))
    payment_skey_path: Path | None = field(default_factory=lambda: (
        Path(os.environ["OPENWATER_CARDANO_PAYMENT_SKEY"])
        if os.environ.get("OPENWATER_CARDANO_PAYMENT_SKEY") else None
    ))
    payment_address: str | None = field(default_factory=lambda: os.environ.get("OPENWATER_CARDANO_PAYMENT_ADDRESS"))
    submit_lovelace: int = field(default_factory=lambda: int(os.environ.get("OPENWATER_CARDANO_SUBMIT_LOVELACE", "1500000")))
    name: str = "blockfrost_cardano"

    def __post_init__(self) -> None:
        self.network = self.network.lower()
        if self.network not in DEFAULT_BLOCKFROST_URLS and not self.base_url:
            raise ValueError(
                f"unknown Cardano network {self.network!r}; expected one of "
                f"{tuple(DEFAULT_BLOCKFROST_URLS)} or set OPENWATER_CARDANO_BLOCKFROST_URL"
            )
        if self.base_url is None:
            self.base_url = DEFAULT_BLOCKFROST_URLS[self.network]
        self.base_url = self.base_url.rstrip("/")

    def _require_project_id(self) -> str:
        if not self.project_id:
            raise RuntimeError("Blockfrost backend requires BLOCKFROST_PROJECT_ID")
        return self.project_id

    def _request_json(self, path: str) -> Any:
        project_id = self._require_project_id()
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            headers={"project_id": project_id},
            method="GET",
        )
        raw = _urlopen_bytes(request)
        return json.loads(raw.decode("utf-8"))

    def _request_bytes(
        self,
        path: str,
        *,
        data: bytes,
        content_type: str = "application/cbor",
    ) -> bytes:
        project_id = self._require_project_id()
        request = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"project_id": project_id, "Content-Type": content_type},
            method="POST",
        )
        return _urlopen_bytes(request)

    def submit(self, metadata: Mapping[int, Mapping[str, Any]]) -> dict[str, Any]:
        if not self.payment_skey_path or not self.payment_address:
            raise RuntimeError(
                "Blockfrost submit requires OPENWATER_CARDANO_PAYMENT_SKEY and "
                "OPENWATER_CARDANO_PAYMENT_ADDRESS"
            )
        try:
            from pycardano import (  # type: ignore[import-not-found]
                Address,
                AlonzoMetadata,
                AuxiliaryData,
                BlockFrostChainContext,
                Metadata,
                Network,
                PaymentSigningKey,
                TransactionBuilder,
                TransactionOutput,
            )
        except ImportError as exc:  # pragma: no cover - optional dependency
            raise RuntimeError(
                "Blockfrost submit requires optional dependency pycardano"
            ) from exc

        project_id = self._require_project_id()
        network = Network.MAINNET if self.network == "mainnet" else Network.TESTNET
        context_kwargs: dict[str, Any] = {"project_id": project_id}
        context_params = inspect.signature(BlockFrostChainContext).parameters
        if "base_url" in context_params:
            context_kwargs["base_url"] = self.base_url
        elif "network" in context_params:
            context_kwargs["network"] = network
        context = BlockFrostChainContext(**context_kwargs)
        signing_key = PaymentSigningKey.load(str(self.payment_skey_path))
        address = Address.from_primitive(self.payment_address)
        builder = TransactionBuilder(context)
        builder.add_input_address(address)
        builder.add_output(TransactionOutput(address, self.submit_lovelace))
        builder.auxiliary_data = AuxiliaryData(
            AlonzoMetadata(metadata=Metadata({int(k): v for k, v in metadata.items()}))
        )
        signed_tx = builder.build_and_sign(
            signing_keys=[signing_key],
            change_address=address,
        )
        submitted = context.submit_tx(signed_tx.to_cbor())
        tx_hash = submitted.hex() if isinstance(submitted, bytes) else str(submitted)
        fetched = None
        # Blockfrost may need a moment to index. Return a useful receipt even
        # when the tx is not immediately fetchable.
        try:
            fetched = self.fetch_transaction(tx_hash)
        except urllib.error.URLError:
            fetched = None
        return fetched or {
            "tx_hash": tx_hash,
            "slot": None,
            "block_hash": None,
            "block_height": None,
            "metadata_label": next(iter(metadata)),
            "metadata_size_bytes": metadata_payload_size_bytes(metadata),
            "metadata": {str(k): _cbor_friendly_to_json(v) for k, v in metadata.items()},
        }

    def fetch_transaction(self, tx_hash_hex: str) -> dict[str, Any] | None:
        quoted_hash = urllib.parse.quote(tx_hash_hex)
        try:
            tx_info = self._request_json(f"/txs/{quoted_hash}")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise
        metadata: dict[str, Any] = {}
        try:
            metadata_items = self._request_json(f"/txs/{quoted_hash}/metadata")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                metadata_items = []
            else:
                raise
        if isinstance(metadata_items, list):
            for item in metadata_items:
                label = str(item.get("label"))
                if not label:
                    continue
                if item.get("json_metadata") is not None:
                    metadata[label] = _normalise_blockfrost_json_metadata(item["json_metadata"])
                elif item.get("cbor_metadata") is not None:
                    metadata[label] = _normalise_blockfrost_cbor_metadata(
                        str(item["cbor_metadata"]),
                        label=label,
                    )

        block_height = tx_info.get("block_height")
        confirmations = None
        if block_height is not None:
            try:
                latest = self._request_json("/blocks/latest")
                tip_height = latest.get("height")
                if tip_height is not None:
                    confirmations = max(0, int(tip_height) - int(block_height) + 1)
            except urllib.error.URLError:
                confirmations = None

        label = next(iter(metadata), str(OPENWATER_CARDANO_METADATA_LABEL))
        return {
            "tx_hash": tx_info.get("hash", tx_hash_hex),
            "slot": tx_info.get("slot"),
            "block_hash": tx_info.get("block"),
            "block_height": block_height,
            "metadata_size_bytes": tx_info.get("metadata_size")
                or metadata_payload_size_bytes({OPENWATER_CARDANO_METADATA_LABEL: {}}),
            "metadata": metadata,
            "metadata_label": int(label),
            "confirmations": confirmations,
        }


def _normalise_blockfrost_json_metadata(value: Any) -> Any:
    """Normalize Blockfrost JSON metadata into the verifier's debug shape."""
    if isinstance(value, Mapping):
        # Some submitters encode bytes as {"bytes": "..."} in JSON metadata.
        if set(value.keys()) == {"bytes"} and isinstance(value.get("bytes"), str):
            return value["bytes"]
        return {str(k): _normalise_blockfrost_json_metadata(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_normalise_blockfrost_json_metadata(v) for v in value]
    return value


class _CborDecodeError(ValueError):
    pass


def _decode_cbor_head(data: bytes, offset: int) -> tuple[int, int, int]:
    if offset >= len(data):
        raise _CborDecodeError("truncated CBOR")
    first = data[offset]
    offset += 1
    major = first >> 5
    ai = first & 0x1F
    if ai < 24:
        return major, ai, offset
    if ai == 24:
        nbytes = 1
    elif ai == 25:
        nbytes = 2
    elif ai == 26:
        nbytes = 4
    elif ai == 27:
        nbytes = 8
    else:
        raise _CborDecodeError("indefinite/reserved CBOR lengths are unsupported")
    end = offset + nbytes
    if end > len(data):
        raise _CborDecodeError("truncated CBOR integer")
    return major, int.from_bytes(data[offset:end], "big"), end


def _decode_cardano_metadata_cbor(data: bytes, offset: int = 0) -> tuple[Any, int]:
    """Decode the restricted Cardano metadata subset OpenWater emits."""
    major, arg, offset = _decode_cbor_head(data, offset)
    if major == 0:
        return arg, offset
    if major == 1:
        return -1 - arg, offset
    if major == 2:
        end = offset + arg
        if end > len(data):
            raise _CborDecodeError("truncated CBOR bytes")
        return data[offset:end], end
    if major == 3:
        end = offset + arg
        if end > len(data):
            raise _CborDecodeError("truncated CBOR string")
        return data[offset:end].decode("utf-8"), end
    if major == 4:
        values = []
        for _ in range(arg):
            value, offset = _decode_cardano_metadata_cbor(data, offset)
            values.append(value)
        return values, offset
    if major == 5:
        out: dict[Any, Any] = {}
        for _ in range(arg):
            key, offset = _decode_cardano_metadata_cbor(data, offset)
            value, offset = _decode_cardano_metadata_cbor(data, offset)
            out[key] = value
        return out, offset
    if major == 7 and arg in {20, 21, 22}:
        return ({20: False, 21: True, 22: None}[arg]), offset
    raise _CborDecodeError(f"unsupported Cardano metadata CBOR major type {major}")


def _normalise_blockfrost_cbor_metadata(cbor_hex: str, *, label: str) -> Any:
    try:
        decoded, offset = _decode_cardano_metadata_cbor(bytes.fromhex(cbor_hex))
        if offset != len(bytes.fromhex(cbor_hex)):
            raise _CborDecodeError("trailing CBOR bytes")
    except (ValueError, _CborDecodeError):
        return {"cbor_metadata": cbor_hex}
    if isinstance(decoded, Mapping):
        for label_key in (int(label), label):
            if label_key in decoded and len(decoded) == 1:
                decoded = decoded[label_key]
                break
    return _cbor_friendly_to_json(decoded)


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
            "slot": tx.get("slot"),
            "block_hash": tx.get("block_hash"),
            "block_height": tx.get("block_height"),
            "metadata_label": tx.get("metadata_label", OPENWATER_CARDANO_METADATA_LABEL),
            "metadata_size_bytes": tx.get("metadata_size_bytes", metadata_payload_size_bytes(metadata)),
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
            tx_hash=tx.get("tx_hash"),
            slot=tx.get("slot"),
            block_hash=tx.get("block_hash"),
            block_height=tx.get("block_height"),
        )
        # Mock ledger uses block_height == len(txs after submit). For mock
        # the "confirmations" count = total ledger length - this block_height + 1.
        # Blockfrost computes confirmations from /blocks/latest when available.
        block_height = tx.get("block_height", 0)
        if isinstance(backend, MockCardanoBackend):
            tip = max((t.get("block_height", 0) for t in backend._load()["txs"]), default=0)
            confirmations = max(0, tip - block_height + 1)
            chain_evidence["confirmations"] = confirmations
        else:
            confirmations = tx.get("confirmations")
            if confirmations is not None:
                chain_evidence["confirmations"] = confirmations
        if confirmations is None and min_confirmations > 0:
            failures.append("confirmation count unavailable from backend")
        elif confirmations is not None and confirmations < min_confirmations:
            failures.append(
                f"insufficient confirmations: have {confirmations}, need {min_confirmations}"
            )

        label_str = str(receipt.metadata_label)
        md_payload = tx.get("metadata", {}).get(label_str)
        if not md_payload:
            failures.append(f"metadata label {label_str} not present in tx")
        elif not isinstance(md_payload, Mapping):
            failures.append(f"metadata label {label_str} is not a map")
        elif "cbor_metadata" in md_payload and len(md_payload) == 1:
            failures.append(
                f"metadata label {label_str} has only CBOR metadata; JSON fields unavailable"
            )
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
    "CARDANO_BACKEND_NAMES",
    "CARDANO_NETWORK_NAMES",
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
