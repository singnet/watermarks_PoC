"""Tests for the Cardano metadata anchor (§16.6) implementation."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from openwater_mk import (
    OPENWATER_CARDANO_METADATA_LABEL,
    AnchorRecord,
    AnchorReceipt,
    MockCardanoBackend,
    anchor_record_hash,
    build_metadata_payload,
    publish_anchor,
    verify_anchor,
)
from openwater_mk.cardano import (
    ANCHOR_PROFILE,
    ANCHOR_SCHEMA_VERSION,
    canonical_anchor_bytes,
    metadata_payload_size_bytes,
)
from openwater_mk.cli import main as cli_main


# ---------------------------------------------------------------------------
# Schema-level unit tests
# ---------------------------------------------------------------------------


def _sample_record(**overrides) -> AnchorRecord:
    defaults = dict(
        record_type="manifest_root",
        subject_id=bytes.fromhex("aa" * 20),
        epoch=0,
        root_hash=bytes.fromhex("11" * 32),
        operator_kid="oprow-key:Ed25519:abc",
    )
    defaults.update(overrides)
    return AnchorRecord(**defaults)


def test_anchor_record_hash_is_deterministic() -> None:
    r1 = _sample_record()
    r2 = _sample_record()
    # created_at differs each call so set it explicitly to test determinism
    r2 = AnchorRecord(
        record_type=r1.record_type,
        subject_id=r1.subject_id,
        epoch=r1.epoch,
        root_hash=r1.root_hash,
        operator_kid=r1.operator_kid,
        created_at=r1.created_at,
    )
    assert anchor_record_hash(r1) == anchor_record_hash(r2)


def test_anchor_record_rejects_bad_root_hash() -> None:
    with pytest.raises(ValueError):
        _sample_record(root_hash=b"\x00" * 16)  # not 32 bytes


def test_metadata_payload_uses_label_40961() -> None:
    record = _sample_record()
    metadata = build_metadata_payload(record)
    assert list(metadata.keys()) == [OPENWATER_CARDANO_METADATA_LABEL]
    payload = metadata[OPENWATER_CARDANO_METADATA_LABEL]
    assert payload["v"] == ANCHOR_SCHEMA_VERSION
    assert payload["p"] == ANCHOR_PROFILE
    assert payload["t"] == "manifest_root"
    assert payload["sid"] == record.subject_id
    assert payload["rh"] == record.root_hash
    assert payload["ah"] == anchor_record_hash(record)
    assert payload["ok"]  # operator kid short id (16 bytes)


def test_metadata_payload_includes_storage_refs() -> None:
    record = _sample_record(ar_ref="ar://abc", ip_ref="ipfs://bafy")
    payload = build_metadata_payload(record)[OPENWATER_CARDANO_METADATA_LABEL]
    assert payload["refs"]["ar"] == "ar://abc"
    assert payload["refs"]["ip"] == "ipfs://bafy"


def test_metadata_payload_size_under_cardano_limit() -> None:
    """The compact payload must comfortably fit under per-tx metadata limits."""
    record = _sample_record(
        ar_ref="ar://" + "x" * 43,
        ip_ref="ipfs://" + "b" + "a" * 58,
    )
    size = metadata_payload_size_bytes(build_metadata_payload(record))
    # Hard ceiling: Cardano metadata can be megabytes, but individual strings
    # must be <=64 bytes. A few hundred is fine; flag if we ever blow past
    # ~16k since that would dominate tx fees.
    assert size < 1024, f"metadata payload too large: {size} bytes"


# ---------------------------------------------------------------------------
# Mock backend round-trip
# ---------------------------------------------------------------------------


def test_mock_backend_submit_then_fetch(tmp_path: Path) -> None:
    backend = MockCardanoBackend(ledger_path=tmp_path / "ledger.json")
    record = _sample_record()
    tx = backend.submit(build_metadata_payload(record))
    fetched = backend.fetch_transaction(tx["tx_hash"])
    assert fetched is not None
    assert fetched["tx_hash"] == tx["tx_hash"]
    assert fetched["metadata_label"] == OPENWATER_CARDANO_METADATA_LABEL


def test_mock_backend_slots_are_monotonic(tmp_path: Path) -> None:
    backend = MockCardanoBackend(ledger_path=tmp_path / "ledger.json")
    s1 = backend.submit(build_metadata_payload(_sample_record(epoch=0)))["slot"]
    s2 = backend.submit(build_metadata_payload(_sample_record(epoch=1)))["slot"]
    assert s2 == s1 + 1


def test_publish_and_verify_roundtrip(tmp_path: Path) -> None:
    backend = MockCardanoBackend(ledger_path=tmp_path / "ledger.json")
    record = _sample_record()
    result = publish_anchor(record=record, backend=backend, out_dir=tmp_path / "out")
    verification = verify_anchor(record=record, receipt=result.receipt, backend=backend)
    assert verification.ok, verification.failures
    assert verification.chain_evidence["confirmations"] >= 1


def test_verify_rejects_tampered_record(tmp_path: Path) -> None:
    backend = MockCardanoBackend(ledger_path=tmp_path / "ledger.json")
    record = _sample_record()
    result = publish_anchor(record=record, backend=backend, out_dir=tmp_path / "out")

    # Reanchor a different epoch but try to claim the original receipt.
    tampered = _sample_record(epoch=42, created_at=record.created_at)
    verification = verify_anchor(record=tampered, receipt=result.receipt, backend=backend)
    assert not verification.ok
    assert any("anchor_record_hash mismatch" in f for f in verification.failures)


def test_verify_rejects_missing_tx(tmp_path: Path) -> None:
    backend = MockCardanoBackend(ledger_path=tmp_path / "ledger.json")
    record = _sample_record()
    result = publish_anchor(record=record, backend=backend, out_dir=tmp_path / "out")

    # Point at a different backend (empty ledger) → tx not found
    other_backend = MockCardanoBackend(ledger_path=tmp_path / "other.json")
    verification = verify_anchor(record=record, receipt=result.receipt, backend=other_backend)
    assert not verification.ok
    assert any("not found" in f for f in verification.failures)


def test_receipt_round_trips_through_json(tmp_path: Path) -> None:
    backend = MockCardanoBackend(ledger_path=tmp_path / "ledger.json")
    record = _sample_record()
    result = publish_anchor(record=record, backend=backend, out_dir=tmp_path / "out")
    raw = json.loads(result.receipt_path.read_text())
    receipt = AnchorReceipt.from_json(raw)
    assert receipt.anchor_record_hash == result.receipt.anchor_record_hash
    assert receipt.chain_evidence["tx_hash"] == result.receipt.chain_evidence["tx_hash"]


# ---------------------------------------------------------------------------
# CLI end-to-end: sign-embed -> anchor -> verify-anchor
# ---------------------------------------------------------------------------


def test_cli_anchor_then_verify_anchor(tmp_path: Path) -> None:
    se_dir = tmp_path / "se"
    rc = cli_main([
        "sign-embed",
        "--storage", "fake-arweave",
        "--out", str(se_dir),
    ])
    assert rc == 0

    cardano_dir = tmp_path / "cardano"
    rc = cli_main(["anchor", str(se_dir), "--out", str(cardano_dir)])
    assert rc == 0
    assert (cardano_dir / "anchor_record.json").exists()
    assert (cardano_dir / "receipt.json").exists()
    assert (cardano_dir / "metadata.json").exists()
    assert (cardano_dir / "ledger.json").exists()

    rc = cli_main(["verify-anchor", str(cardano_dir)])
    assert rc == 0


def test_cli_verify_anchor_writes_report(tmp_path: Path) -> None:
    se_dir = tmp_path / "se"
    cli_main(["sign-embed", "--out", str(se_dir)])
    cardano_dir = tmp_path / "c"
    cli_main(["anchor", str(se_dir), "--out", str(cardano_dir)])
    report_path = tmp_path / "report.json"
    rc = cli_main([
        "verify-anchor",
        str(cardano_dir),
        "--report", str(report_path),
    ])
    assert rc == 0
    report = json.loads(report_path.read_text())
    assert report["ok"] is True
    assert report["chain_evidence"]["backend"] == "mock_cardano"
