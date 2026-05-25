"""CLI-surface tests for the ``openwater`` subcommands.

These drive the argparse entrypoint, exercise the on-disk artifacts produced
by ``sign-embed``, and confirm cross-process ``verify`` works against them.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from openwater_mk.cli import main as cli_main


def test_demo_subcommand_baseline_default_profile_extracts(tmp_path: Path) -> None:
    """Default profile is dct_qim. Baseline run must extract locator (rc=0).
    Essence binding is documented to V0 content_mismatch for non-alpha-LSB
    profiles; full verified=True is exercised by the alpha_lsb test below.
    """
    rc = cli_main(["demo", "--out", str(tmp_path)])
    assert rc == 0
    report = json.loads((tmp_path / "verify_report.json").read_text())
    assert report["extraction_status"] == "extracted"
    assert report["profile"] == "dct_qim"


def test_demo_subcommand_baseline_alpha_lsb_verifies(tmp_path: Path) -> None:
    rc = cli_main(["demo", "--profile", "alpha_lsb", "--out", str(tmp_path)])
    assert rc == 0
    report = json.loads((tmp_path / "verify_report.json").read_text())
    assert report["verified"] is True


def test_demo_subcommand_tamper_returns_zero_on_correct_rejection(tmp_path: Path) -> None:
    rc = cli_main(["demo", "--tamper", "--profile", "alpha_lsb", "--out", str(tmp_path)])
    assert rc == 0  # success = verification correctly rejected
    report = json.loads((tmp_path / "verify_report.json").read_text())
    assert report["verified"] is False
    assert report["verification_status"] == "content_mismatch"


def test_demo_subcommand_jpeg_destroys_alpha_lsb_locator(tmp_path: Path) -> None:
    rc = cli_main(["demo", "--profile", "alpha_lsb", "--transform", "jpeg_q82", "--out", str(tmp_path)])
    assert rc == 1
    report = json.loads((tmp_path / "verify_report.json").read_text())
    assert report["extraction_status"] == "no_watermark"


def test_demo_subcommand_jpeg_survives_dct_qim(tmp_path: Path) -> None:
    rc = cli_main(["demo", "--profile", "dct_qim", "--transform", "jpeg_q82", "--out", str(tmp_path)])
    assert rc == 0
    report = json.loads((tmp_path / "verify_report.json").read_text())
    assert report["extraction_status"] == "extracted"


def test_sign_embed_then_verify_roundtrip_alpha_lsb(tmp_path: Path) -> None:
    workdir = tmp_path / "se"
    rc = cli_main(["sign-embed", "--profile", "alpha_lsb", "--out", str(workdir)])
    assert rc == 0
    assert (workdir / "watermarked.png").exists()
    assert (workdir / "key.json").exists()
    assert (workdir / "manifests").is_dir()
    mk_hex = (workdir / "manifest_key.txt").read_text().strip()
    assert len(mk_hex) == 40  # 20 bytes hex

    rc = cli_main([
        "verify",
        str(workdir / "watermarked.png"),
        "--profile", "alpha_lsb",
        "--manifest-store", str(workdir / "manifests"),
        "--key", str(workdir / "key.json"),
        "--report", str(workdir / "verify_report.json"),
    ])
    assert rc == 0
    report = json.loads((workdir / "verify_report.json").read_text())
    assert report["verified"] is True


def test_poc_subcommand_runs_storage_verify_anchor_roundtrip(tmp_path: Path) -> None:
    workdir = tmp_path / "poc"
    rc = cli_main(["poc", "--out", str(workdir)])
    assert rc == 0

    report = json.loads((workdir / "poc_report.json").read_text())
    assert report["profile"] == "alpha_lsb"
    assert report["real_network"] is False
    assert report["storage_backend"] == "fake-arweave"
    assert report["storage_is_fake"] is True
    assert report["storage_uri"].startswith("ar://")
    assert report["verified"] is True
    assert report["extraction_status"] == "extracted"
    assert report["verification_status"] == "verified"
    assert report["anchor_ok"] is True
    assert report["cardano_backend"] == "mock_cardano"
    assert report["cardano_is_mock"] is True
    assert report["metadata_label"] == 40961
    assert len(report["tx_hash"]) == 64
    assert (workdir / "sign_embed" / "watermarked.png").exists()
    assert (workdir / "cardano" / "receipt.json").exists()


def test_inspect_extracts_locator_alpha_lsb(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    workdir = tmp_path / "ins"
    cli_main(["sign-embed", "--profile", "alpha_lsb", "--out", str(workdir)])
    capsys.readouterr()  # drop sign-embed stdout
    rc = cli_main(["inspect", "--profile", "alpha_lsb", str(workdir / "watermarked.png")])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "extracted"
    assert data["locator_mode"] == "full160"
    assert len(data["locator_hex"]) == 40


def test_inspect_extracts_locator_dct_qim(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    workdir = tmp_path / "ins"
    cli_main(["sign-embed", "--profile", "dct_qim", "--out", str(workdir)])
    capsys.readouterr()
    rc = cli_main(["inspect", "--profile", "dct_qim", str(workdir / "watermarked.png")])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "extracted"
    assert data["locator_mode"] == "full160"


def test_verify_rejects_tampered_image_alpha_lsb(tmp_path: Path) -> None:
    """Manually tamper a sign-embed output and confirm verify rejects it."""
    from io import BytesIO

    from PIL import Image

    workdir = tmp_path / "ver"
    cli_main(["sign-embed", "--profile", "alpha_lsb", "--out", str(workdir)])

    # Strip alpha so the locator is destroyed AND the essence changes.
    src = Image.open(workdir / "watermarked.png").convert("RGB")
    buf = BytesIO()
    src.save(buf, format="PNG")
    tampered = workdir / "tampered.png"
    tampered.write_bytes(buf.getvalue())

    rc = cli_main([
        "verify",
        str(tampered),
        "--profile", "alpha_lsb",
        "--manifest-store", str(workdir / "manifests"),
        "--key", str(workdir / "key.json"),
    ])
    assert rc == 1
