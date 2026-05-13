"""Integration tests for the OpenWater internal demo orchestration.

These hit the real oprow SDK in-process. They are not unit tests; they
exercise the same `run_demo` path the CLI calls. CI uses them as the
acceptance suite for changes to the demo orchestration.

Profile semantics in V0:

- ``alpha_lsb`` does not perturb luminance, so PED-IMG-1 essence binding
  round-trips and we can assert full ``verified=True``.
- ``dct_qim`` (and its robust variant, see Tier 2) perturbs luminance at
  embed time. PED-IMG-1 is exact-hash in V0, so essence binding always
  reports ``content_mismatch`` even when the locator survives. For those
  profiles we only assert ``extraction_status == "extracted"``. A
  perceptual essence with bounded-distance comparison is V1+ work.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from openwater_mk import run_demo


def test_baseline_verifies_alpha_lsb(tmp_path: Path) -> None:
    out = run_demo(out_dir=tmp_path, profile="alpha_lsb")
    assert out["verified"] is True
    assert out["extraction_status"] == "extracted"
    assert out["verification_status"] == "verified"
    assert out["locator_mode"] == "full160"
    assert out["watermark_alg_id"] == "IMG-ALPHA-LSB-REF-1"
    assert out["profile"] == "alpha_lsb"
    assert (tmp_path / "watermarked.png").exists()
    assert (tmp_path / "verify_report.json").exists()


def test_baseline_extracts_dct_qim(tmp_path: Path) -> None:
    """DCT-QIM locator round-trips; essence binding is V0 exact-hash so
    verification reports content_mismatch — that is the documented V0
    behaviour, not a regression."""
    out = run_demo(out_dir=tmp_path, profile="dct_qim")
    assert out["extraction_status"] == "extracted"
    assert out["watermark_alg_id"] == "IMG-DCT-QIM-REF-1"
    assert out["profile"] == "dct_qim"
    assert out["verification_status"] == "content_mismatch"
    assert out["verified"] is False


def test_tamper_rejected_with_content_mismatch(tmp_path: Path) -> None:
    """RGB tamper must be rejected even though the locator survives in alpha.

    Test stays alpha-LSB-specific: the ``_tamper_rgb`` helper preserves the
    alpha channel by construction so the locator survives only with the
    alpha-LSB carrier. The same demonstration for DCT-QIM needs a tamper
    that preserves luminance mid-frequency coefficients while shifting
    pixel content — design that in a follow-up.
    """
    out = run_demo(out_dir=tmp_path, tamper=True, profile="alpha_lsb")
    assert out["verified"] is False
    # locator extractable: alpha channel untouched
    assert out["extraction_status"] == "extracted"
    # but essence binding rejects the mutated content
    assert out["verification_status"] == "content_mismatch"
    assert (tmp_path / "tampered.png").exists()


def test_png_rgba_alpha_lsb_preserves_locator(tmp_path: Path) -> None:
    out = run_demo(out_dir=tmp_path, transform="png_rgba", profile="alpha_lsb")
    assert out["verified"] is True
    assert out["extraction_status"] == "extracted"
    assert (tmp_path / "transformed_png_rgba.png").exists()


def test_png_rgb_alpha_lsb_destroys_locator(tmp_path: Path) -> None:
    """RGB-only re-encode strips the alpha-LSB carrier; locator must not survive."""
    out = run_demo(out_dir=tmp_path, transform="png_rgb", profile="alpha_lsb")
    assert out["verified"] is False
    assert out["extraction_status"] == "no_watermark"


def test_jpeg_q82_alpha_lsb_destroys_locator(tmp_path: Path) -> None:
    """Lossy JPEG destroys the alpha-LSB carrier."""
    out = run_demo(out_dir=tmp_path, transform="jpeg_q82", profile="alpha_lsb")
    assert out["verified"] is False
    assert out["extraction_status"] == "no_watermark"


def test_png_rgb_dct_qim_survives(tmp_path: Path) -> None:
    """RGB-only re-encode preserves the DCT/QIM luminance carrier."""
    out = run_demo(out_dir=tmp_path, transform="png_rgb", profile="dct_qim")
    assert out["extraction_status"] == "extracted"


def test_jpeg_q82_dct_qim_survives(tmp_path: Path) -> None:
    """JPEG q=82 preserves the DCT/QIM locator (mid-frequency Y coefficient)."""
    out = run_demo(out_dir=tmp_path, transform="jpeg_q82", profile="dct_qim")
    assert out["extraction_status"] == "extracted"


def test_tamper_and_transform_mutually_exclusive(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        run_demo(out_dir=tmp_path, tamper=True, transform="png_rgba")


def test_unknown_profile_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        run_demo(out_dir=tmp_path, profile="not_a_real_profile")


def test_real_input_path(tmp_path: Path) -> None:
    """Round-trip against a user-supplied PNG (uses the first synthetic sample written to disk)."""
    # First make a real PNG to read from disk.
    bootstrap_out = tmp_path / "bootstrap"
    run_demo(out_dir=bootstrap_out, profile="alpha_lsb")
    src_png = bootstrap_out / "watermarked.png"
    # Strip the watermark by re-saving as RGB-only so the demo gets a fresh image.
    from PIL import Image
    fresh = tmp_path / "fresh.png"
    Image.open(src_png).convert("RGB").save(fresh, format="PNG")

    out = run_demo(input_path=fresh, out_dir=tmp_path / "run", profile="alpha_lsb")
    assert out["verified"] is True
    assert out["input"] == str(fresh)
