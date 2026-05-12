"""OpenWater internal demo.

End-to-end: sign manifest -> embed alpha-LSB watermark locator -> persist
watermarked PNG -> extract locator -> verify (signature + essence + trust).

This is the V0->internal-demo target from the OpenWater implementation-time
estimates doc. Local CAS, local Ed25519 key, reference (alpha-LSB) carrier.
Not a robust watermark, not a hosted service. See README for V1+ scope.

Usage:

    python demo_internal.py                   # synthetic sample image
    python demo_internal.py --input pic.png   # real input
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path

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
from oprow.core.enums import SignatureRole


def _load_artifact(path: Path | None) -> Artifact:
    if path is None:
        return default_synthetic_image_corpus()[0]
    return Artifact.from_bytes(path.read_bytes(), media_type="image/png")


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


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, default=None,
                   help="input PNG path (default: synthetic sample)")
    p.add_argument("--out", type=Path, default=Path("out"),
                   help="output directory (default: out/)")
    args = p.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)

    artifact = _load_artifact(args.input)
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

    watermarked_path = args.out / "watermarked.png"
    watermarked_path.write_bytes(embedded.artifact.read_bytes())

    cas = MemoryCAS()
    cas.put_manifest(signed)
    report = verify_artifact_from_watermark(
        embedded.artifact,
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
        "input": str(args.input) if args.input else "synthetic",
        "watermarked_path": str(watermarked_path),
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
    report_path = args.out / "verify_report.json"
    report_path.write_text(json.dumps(out, indent=2, default=str))

    print(
        f"verified={report.verified}  "
        f"extraction={out['extraction_status']}  "
        f"verification={out['verification_status']}  "
        f"report={report_path}"
    )
    return 0 if report.verified else 1


if __name__ == "__main__":
    sys.exit(main())
