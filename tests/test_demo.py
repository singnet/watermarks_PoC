"""Integration tests for the OpenWater internal demo orchestration.

These hit the real oprow SDK in-process. They are not unit tests; they
exercise the same `run_demo` path the CLI calls. CI uses them as the
acceptance suite for changes to the demo orchestration.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from openwater_mk import run_demo


def test_baseline_verifies(tmp_path: Path) -> None:
    out = run_demo(out_dir=tmp_path)
    assert out["verified"] is True
    assert out["extraction_status"] == "extracted"
    assert out["verification_status"] == "verified"
    assert out["locator_mode"] == "full160"
    assert out["watermark_alg_id"] == "IMG-ALPHA-LSB-REF-1"
    assert (tmp_path / "watermarked.png").exists()
    assert (tmp_path / "verify_report.json").exists()


def test_tamper_rejected_with_content_mismatch(tmp_path: Path) -> None:
    """RGB tamper must be rejected even though the locator survives in alpha."""
    out = run_demo(out_dir=tmp_path, tamper=True)
    assert out["verified"] is False
    # locator extractable: alpha channel untouched
    assert out["extraction_status"] == "extracted"
    # but essence binding rejects the mutated content
    assert out["verification_status"] == "content_mismatch"
    assert (tmp_path / "tampered.png").exists()


def test_png_rgba_transform_preserves_locator(tmp_path: Path) -> None:
    out = run_demo(out_dir=tmp_path, transform="png_rgba")
    assert out["verified"] is True
    assert out["extraction_status"] == "extracted"
    assert (tmp_path / "transformed_png_rgba.png").exists()


def test_png_rgb_transform_destroys_locator(tmp_path: Path) -> None:
    """RGB-only re-encode strips the alpha-LSB carrier; locator must not survive."""
    out = run_demo(out_dir=tmp_path, transform="png_rgb")
    assert out["verified"] is False
    assert out["extraction_status"] == "no_watermark"


def test_jpeg_transform_destroys_locator(tmp_path: Path) -> None:
    """Lossy JPEG destroys the alpha-LSB carrier."""
    out = run_demo(out_dir=tmp_path, transform="jpeg_q82")
    assert out["verified"] is False
    assert out["extraction_status"] == "no_watermark"


def test_tamper_and_transform_mutually_exclusive(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        run_demo(out_dir=tmp_path, tamper=True, transform="png_rgba")


def test_real_input_path(tmp_path: Path) -> None:
    """Round-trip against a user-supplied PNG (uses the first synthetic sample written to disk)."""
    # First make a real PNG to read from disk.
    bootstrap_out = tmp_path / "bootstrap"
    run_demo(out_dir=bootstrap_out)
    src_png = bootstrap_out / "watermarked.png"
    # Strip the watermark by re-saving as RGB-only so the demo gets a fresh image.
    from PIL import Image
    fresh = tmp_path / "fresh.png"
    Image.open(src_png).convert("RGB").save(fresh, format="PNG")

    out = run_demo(input_path=fresh, out_dir=tmp_path / "run")
    assert out["verified"] is True
    assert out["input"] == str(fresh)
