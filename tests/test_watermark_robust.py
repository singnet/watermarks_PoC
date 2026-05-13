"""Tier 1+2 channel-robustness matrix.

These tests pin the *empirical* robustness of each watermark profile on
the synthetic image corpus the demo uses by default. A regression in
either the embed or the extract path will surface here as a profile
suddenly failing a transform it used to pass.

The "passes" are intentionally weak: ``extraction_status == "extracted"``
for the DCT-QIM family, ``verified is True`` only for alpha-LSB. Why:
PED-IMG-1 is exact-hash in V0, so any luminance-domain watermark
perturbs the essence at embed time and again under JPEG, and the
verifier reports ``content_mismatch``. That is V0 SDK behaviour, not a
demo bug — see test_demo.py for the documented expectations and
openwater_mk/watermark_robust.py for the design notes.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from openwater_mk import run_demo
from openwater_mk.pipeline import _resolve_profile
from openwater_mk.transforms import TRANSFORMS
from openwater_mk.watermark_robust import RobustDCTQIMImageWatermarkProfile
from oprow.core.enums import SignatureRole
from oprow.manifest.keys import (
    PrivateKeyRecord,
    PrivateKeyEncoding,
    PublicKeyRecord,
    PublicKeyEncoding,
    derive_reference_key_id,
    SignatureAlgorithm,
)

# Fixed timestamp and key so the derived ManifestKey (and therefore the
# carrier bit pattern) is deterministic across pytest runs. Some
# DCT-QIM cells sit on a JPEG-quantization knife edge where flipping a
# single carrier bit decides CRC pass/fail, so the test would otherwise
# be flaky based on wall-clock time and OS random state.
FIXED_CREATED_AT = datetime(2026, 5, 13, 12, 0, 0, tzinfo=timezone.utc)


def _fixed_key() -> PrivateKeyRecord:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    # 32-byte deterministic Ed25519 private key.
    seed = bytes.fromhex("11" * 32)
    private = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
    pub_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    alg = SignatureAlgorithm.ED25519.value
    public = PublicKeyRecord(
        kid=derive_reference_key_id(alg, pub_bytes),
        alg=alg,
        public_key_bytes=pub_bytes,
        encoding=PublicKeyEncoding.RAW,
        roles=(SignatureRole.TOOL.value,),
        created_at=FIXED_CREATED_AT,
    )
    return PrivateKeyRecord(public=public, private_key_bytes=seed, private_key_encoding=PrivateKeyEncoding.RAW)


FIXED_KEY = _fixed_key()


# (profile, transform) -> required extraction_status. ``None`` means the
# row is skipped (e.g. geometry transforms are out of scope for V0).
EXPECTED: dict[tuple[str, str | None], str] = {
    # alpha-LSB: PNG round-trip preserving alpha is the only survivable
    # path. Everything else strips the alpha channel or perturbs RGB.
    ("alpha_lsb", None):                "extracted",
    ("alpha_lsb", "png_rgba"):          "extracted",
    ("alpha_lsb", "png_rgb"):           "no_watermark",
    ("alpha_lsb", "jpeg_q82"):          "no_watermark",
    ("alpha_lsb", "jpeg_q70"):          "no_watermark",
    ("alpha_lsb", "jpeg_q60"):          "no_watermark",
    ("alpha_lsb", "jpeg_cascade_85_70"):"no_watermark",
    ("alpha_lsb", "social_pipeline"):   "no_watermark",
    ("alpha_lsb", "resize_0_9"):        "no_watermark",

    # DCT-QIM reference: locator survives PNG-RGB and JPEG down to q60
    # plus a one-shot cascade. Geometry-bearing transforms (resize,
    # social pipeline) drop it because there's no sync template yet.
    ("dct_qim", None):                  "extracted",
    ("dct_qim", "png_rgba"):            "extracted",
    ("dct_qim", "png_rgb"):             "extracted",
    ("dct_qim", "jpeg_q82"):            "extracted",
    ("dct_qim", "jpeg_q70"):            "extracted",
    ("dct_qim", "jpeg_q60"):            "extracted",
    ("dct_qim", "jpeg_cascade_85_70"):  "extracted",
    ("dct_qim", "social_pipeline"):     "no_watermark",
    ("dct_qim", "resize_0_9"):          "no_watermark",

    # Robust DCT-QIM: structurally identical to the reference at this
    # qim_delta on this corpus (see watermark_robust.py module docstring
    # on why the spread doesn't beat the reference under correlated JPEG
    # noise). It is shipped as a template for production tuning, not as
    # an out-of-the-box improvement.
    ("dct_qim_robust", None):                 "extracted",
    ("dct_qim_robust", "png_rgba"):           "extracted",
    ("dct_qim_robust", "png_rgb"):            "extracted",
    ("dct_qim_robust", "jpeg_q82"):           "extracted",
    ("dct_qim_robust", "jpeg_q70"):           "extracted",
    ("dct_qim_robust", "jpeg_q60"):           "extracted",
    ("dct_qim_robust", "jpeg_cascade_85_70"): "extracted",
    ("dct_qim_robust", "social_pipeline"):    "no_watermark",
    ("dct_qim_robust", "resize_0_9"):         "no_watermark",
}


@pytest.mark.parametrize("profile,transform,expected", [
    (prof, tx, expected_status)
    for (prof, tx), expected_status in EXPECTED.items()
])
def test_robustness_matrix(
    tmp_path: Path,
    profile: str,
    transform: str | None,
    expected: str,
) -> None:
    out = run_demo(
        out_dir=tmp_path,
        transform=transform,
        profile=profile,
        created_at=FIXED_CREATED_AT,
        key=FIXED_KEY,
    )
    assert out["extraction_status"] == expected, (
        f"profile={profile} transform={transform!r}: "
        f"expected extraction={expected!r}, got {out['extraction_status']!r} "
        f"(verification={out['verification_status']!r})"
    )


def test_alpha_lsb_baseline_fully_verified(tmp_path: Path) -> None:
    """Sanity check the only profile whose essence binding round-trips."""
    out = run_demo(out_dir=tmp_path, profile="alpha_lsb")
    assert out["verified"] is True
    assert out["verification_status"] == "verified"


def test_robust_profile_uses_five_coefficients(tmp_path: Path) -> None:
    """Lock in the spectral-spread shape so a future edit doesn't silently
    revert to the SDK's single-coefficient reference."""
    profile = _resolve_profile("dct_qim_robust")
    assert isinstance(profile, RobustDCTQIMImageWatermarkProfile)
    assert len(profile.coefficients) == 5
    assert (0, 0) not in profile.coefficients
    # All mid-frequency: cell sum (u+v) between 2 and 5, exclusive of DC.
    assert all(2 <= (u + v) <= 5 for (u, v) in profile.coefficients)


def test_robust_profile_rejects_dc_coefficient() -> None:
    """The DC coefficient (0,0) carries average luminance — never embed there."""
    from oprow.core.errors import ValidationError
    with pytest.raises(ValidationError):
        RobustDCTQIMImageWatermarkProfile(coefficients=((0, 0), (1, 1)))


def test_robust_profile_rejects_duplicates() -> None:
    from oprow.core.errors import ValidationError
    with pytest.raises(ValidationError):
        RobustDCTQIMImageWatermarkProfile(coefficients=((2, 1), (2, 1)))


def test_transforms_registry_complete() -> None:
    """Tier 2 adds three transforms beyond the original four."""
    assert {"jpeg_q70", "jpeg_cascade_85_70", "social_pipeline", "resize_0_9"} <= set(TRANSFORMS)
