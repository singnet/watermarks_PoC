"""CLI-surface tests for the ``openwater`` subcommands.

These drive the argparse entrypoint, exercise the on-disk artifacts produced
by ``sign-embed``, and confirm cross-process ``verify`` works against them.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from openwater_mk.cli import main as cli_main


def test_demo_subcommand_baseline(tmp_path: Path) -> None:
    rc = cli_main(["demo", "--out", str(tmp_path)])
    assert rc == 0
    report = json.loads((tmp_path / "verify_report.json").read_text())
    assert report["verified"] is True


def test_demo_subcommand_tamper_returns_zero_on_correct_rejection(tmp_path: Path) -> None:
    rc = cli_main(["demo", "--tamper", "--out", str(tmp_path)])
    assert rc == 0  # success = verification correctly rejected
    report = json.loads((tmp_path / "verify_report.json").read_text())
    assert report["verified"] is False
    assert report["verification_status"] == "content_mismatch"


def test_demo_subcommand_jpeg_destroys_locator(tmp_path: Path) -> None:
    rc = cli_main(["demo", "--transform", "jpeg_q82", "--out", str(tmp_path)])
    assert rc == 1
    report = json.loads((tmp_path / "verify_report.json").read_text())
    assert report["extraction_status"] == "no_watermark"


def test_sign_embed_then_verify_roundtrip(tmp_path: Path) -> None:
    workdir = tmp_path / "se"
    rc = cli_main(["sign-embed", "--out", str(workdir)])
    assert rc == 0
    assert (workdir / "watermarked.png").exists()
    assert (workdir / "key.json").exists()
    assert (workdir / "manifests").is_dir()
    mk_hex = (workdir / "manifest_key.txt").read_text().strip()
    assert len(mk_hex) == 40  # 20 bytes hex

    rc = cli_main([
        "verify",
        str(workdir / "watermarked.png"),
        "--manifest-store", str(workdir / "manifests"),
        "--key", str(workdir / "key.json"),
        "--report", str(workdir / "verify_report.json"),
    ])
    assert rc == 0
    report = json.loads((workdir / "verify_report.json").read_text())
    assert report["verified"] is True


def test_inspect_extracts_locator(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    workdir = tmp_path / "ins"
    cli_main(["sign-embed", "--out", str(workdir)])
    capsys.readouterr()  # drop sign-embed stdout
    rc = cli_main(["inspect", str(workdir / "watermarked.png")])
    assert rc == 0
    data = json.loads(capsys.readouterr().out)
    assert data["status"] == "extracted"
    assert data["locator_mode"] == "full160"
    assert len(data["locator_hex"]) == 40


def test_verify_rejects_tampered_image(tmp_path: Path) -> None:
    """Manually tamper a sign-embed output and confirm verify rejects it."""
    from io import BytesIO

    from PIL import Image

    workdir = tmp_path / "ver"
    cli_main(["sign-embed", "--out", str(workdir)])

    # Strip alpha so the locator is destroyed AND the essence changes.
    src = Image.open(workdir / "watermarked.png").convert("RGB")
    buf = BytesIO()
    src.save(buf, format="PNG")
    tampered = workdir / "tampered.png"
    tampered.write_bytes(buf.getvalue())

    rc = cli_main([
        "verify",
        str(tampered),
        "--manifest-store", str(workdir / "manifests"),
        "--key", str(workdir / "key.json"),
    ])
    assert rc == 1
