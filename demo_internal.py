"""OpenWater internal demo.

End-to-end: sign manifest -> embed alpha-LSB watermark locator -> persist
watermarked PNG -> extract locator -> verify (signature + essence + trust).

This is the V0->internal-demo target from the OpenWater implementation-time
estimates doc. Local CAS, local Ed25519 key, reference (alpha-LSB) carrier.
Not a robust watermark, not a hosted service. See README for V1+ scope.

Usage:

    python demo_internal.py                            # synthetic sample image
    python demo_internal.py --input pic.png            # real input
    python demo_internal.py --tamper                   # mutate RGB after embed; verify must fail
    python demo_internal.py --transform png_rgba       # benign re-encode preserving alpha; verify passes
    python demo_internal.py --transform png_rgb        # alpha-stripping re-encode; locator destroyed
    python demo_internal.py --transform jpeg_q82       # lossy JPEG; alpha-LSB carrier dies
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path

from io import BytesIO

from PIL import Image

from oprow import (
    AlphaLSBImageWatermarkProfile,
    Artifact,
    CASResolver,
    GenerationClaim,
    ManifestCore,
    MemoryCAS,
    MemoryKeyRegistry,
    OProWSigner,
    PointerMode,
    TrustPolicyStub,
    WatermarkStrength,
    build_artifact_binding,
    create_signed_manifest,
    default_synthetic_image_corpus,
    embed_manifest_locator,
    generate_ed25519_keypair,
    verify_artifact_from_watermark,
)
from oprow.benchmark.transforms import (
    JPEGRecompressTransform,
    PNGRoundTripTransform,
)
from oprow.core.enums import SignatureRole


TRANSFORMS = {
    "png_rgba": PNGRoundTripTransform(mode="RGBA", name="png_roundtrip_rgba"),
    "png_rgb": PNGRoundTripTransform(mode="RGB", name="png_roundtrip_rgb"),
    "jpeg_q82": JPEGRecompressTransform(quality=82),
    "jpeg_q60": JPEGRecompressTransform(quality=60),
}


def _load_artifact(path: Path | None) -> Artifact:
    if path is None:
        return default_synthetic_image_corpus()[0]
    return Artifact.from_bytes(path.read_bytes(), media_type="image/png")


def _tamper_rgb(png_bytes: bytes) -> bytes:
    """Mutate visible RGB content while preserving the alpha channel.

    Alpha-LSB watermark survives — locator still extractable — but PED-IMG-1
    essence is computed on RGB, so the manifest's essence binding must reject
    the tampered artifact. Demonstrates the security boundary: watermark
    recovery is not proof of provenance.
    """
    img = Image.open(BytesIO(png_bytes)).convert("RGBA")
    w, h = img.size
    pixels = img.load()
    cx0, cy0 = w // 4, h // 4
    cx1, cy1 = (3 * w) // 4, (3 * h) // 4
    for x in range(cx0, cx1):
        for y in range(cy0, cy1):
            r, g, b, a = pixels[x, y]
            pixels[x, y] = (255 - r, 255 - g, 255 - b, a)  # invert RGB, keep alpha
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _to_jsonable(obj):
    if obj is None or isinstance(obj, (str, int, float, bool)):
        return obj
    if isinstance(obj, bytes):
        return obj.hex()
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_jsonable(v) for v in obj]
    if is_dataclass(obj):
        return _to_jsonable(asdict(obj))
    if hasattr(obj, "value"):
        return obj.value
    return str(obj)


def run_demo(
    *,
    input_path: Path | None = None,
    out_dir: Path = Path("out"),
    tamper: bool = False,
    transform: str | None = None,
) -> dict:
    """Run the full sign/embed/verify pipeline once. Returns the report dict.

    The dict is also written to ``out_dir/verify_report.json``.
    """
    if tamper and transform:
        raise ValueError("tamper and transform are mutually exclusive")
    out_dir.mkdir(parents=True, exist_ok=True)

    artifact = _load_artifact(input_path)
    key = generate_ed25519_keypair(roles=[SignatureRole.TOOL])
    profile = AlphaLSBImageWatermarkProfile()

    binding = build_artifact_binding(artifact, wm_alg_id=profile.alg_id)
    core = ManifestCore(
        version=1,
        artifact=binding,
        claims=[GenerationClaim(model_id="openwater-demo")],
        created_at=datetime.now(timezone.utc),
    )
    signed = create_signed_manifest(core, [OProWSigner(key, SignatureRole.TOOL)])

    strength = WatermarkStrength(name="demo-alpha-lsb", repetitions=3)
    embedded = embed_manifest_locator(
        artifact, signed,
        pointer_mode=PointerMode.FULL160,
        watermark_profile=profile,
        strength=strength,
    )

    watermarked_path = out_dir / "watermarked.png"
    watermarked_path.write_bytes(embedded.artifact.read_bytes())

    verify_input = embedded.artifact
    tampered_path: Path | None = None
    transformed_path: Path | None = None
    if tamper:
        tampered_bytes = _tamper_rgb(embedded.artifact.read_bytes())
        tampered_path = out_dir / "tampered.png"
        tampered_path.write_bytes(tampered_bytes)
        verify_input = Artifact.from_bytes(tampered_bytes, media_type="image/png")
    elif transform:
        tx = TRANSFORMS[transform]
        verify_input = tx.apply(embedded.artifact)
        ext = "jpg" if verify_input.media_type == "image/jpeg" else "png"
        transformed_path = out_dir / f"transformed_{transform}.{ext}"
        transformed_path.write_bytes(verify_input.read_bytes())

    cas = MemoryCAS()
    cas.put_manifest(signed)
    report = verify_artifact_from_watermark(
        verify_input,
        watermark_profile=profile,
        strength=strength,
        resolver=CASResolver([cas]),
        key_resolver=MemoryKeyRegistry.from_public_keys([key.public]),
        trust_policy=TrustPolicyStub(
            trusted_key_ids={str(key.kid)},
            accepted_roles={"tool"},
        ),
    )

    out = {
        "input": str(input_path) if input_path else "synthetic",
        "tampered": tamper,
        "transform": transform,
        "watermarked_path": str(watermarked_path),
        "tampered_path": str(tampered_path) if tampered_path else None,
        "transformed_path": str(transformed_path) if transformed_path else None,
        "key_id": str(key.kid),
        "pointer_mode": PointerMode.FULL160.value,
        "watermark_alg_id": profile.alg_id,
        "extraction_status": report.extraction.status.value,
        "locator_mode": (
            report.extraction.locator.mode.value
            if report.extraction.locator else None
        ),
        "verification_status": (
            report.verification.status.value if report.verification else None
        ),
        "verified": report.verified,
        "embed_diagnostics": _to_jsonable(embedded.diagnostics),
    }
    report_path = out_dir / "verify_report.json"
    report_path.write_text(json.dumps(out, indent=2, default=str))
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, default=None,
                   help="input PNG path (default: synthetic sample)")
    p.add_argument("--out", type=Path, default=Path("out"),
                   help="output directory (default: out/)")
    p.add_argument("--tamper", action="store_true",
                   help="invert center RGB after embed; verify must reject")
    p.add_argument("--transform", choices=sorted(TRANSFORMS), default=None,
                   help="apply a transform to the watermarked image before verify")
    args = p.parse_args(argv)
    if args.tamper and args.transform:
        p.error("--tamper and --transform are mutually exclusive")

    out = run_demo(
        input_path=args.input,
        out_dir=args.out,
        tamper=args.tamper,
        transform=args.transform,
    )
    report_path = args.out / "verify_report.json"
    print(
        f"verified={out['verified']}  "
        f"extraction={out['extraction_status']}  "
        f"verification={out['verification_status']}  "
        f"report={report_path}"
    )
    # Tamper case inverts: success = verification was correctly rejected.
    if args.tamper:
        return 0 if not out["verified"] else 1
    return 0 if out["verified"] else 1


if __name__ == "__main__":
    sys.exit(main())
