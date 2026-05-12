"""``openwater`` command-line interface.

Subcommands:

- ``openwater demo``         — in-process one-shot end-to-end pipeline
- ``openwater sign-embed``   — sign + embed; persists key, manifest store, watermarked PNG
- ``openwater verify``       — verify a watermarked PNG against persisted key + manifest store
- ``openwater inspect``      — extract locator only, no manifest fetch

The CLI is intentionally narrow. It targets the Version-1 surface from
the OpenWater implementation-time estimates: image-only, FULL160 pointer,
alpha-LSB reference carrier, local FileCAS manifest store, local key file.
Arweave/IPFS storage and Cardano metadata anchors are future phases.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .pipeline import (
    inspect_only,
    run_demo,
    sign_and_embed,
    verify,
)
from .transforms import TRANSFORMS


def _cmd_demo(args: argparse.Namespace) -> int:
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
    if args.tamper:
        return 0 if not out["verified"] else 1
    return 0 if out["verified"] else 1


def _cmd_sign_embed(args: argparse.Namespace) -> int:
    result = sign_and_embed(input_path=args.input, out_dir=args.out)
    print(f"watermarked={result.watermarked_path}")
    print(f"manifest_store={result.manifest_store}")
    print(f"manifest_key={result.manifest_key_hex}")
    print(f"key={result.key_path}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    result = verify(
        watermarked_path=args.watermarked,
        manifest_store=args.manifest_store,
        key_envelope_path=args.key,
    )
    if args.report:
        args.report.write_text(json.dumps(result.report, indent=2))
    print(
        f"verified={result.verified}  "
        f"extraction={result.extraction_status}  "
        f"verification={result.verification_status}"
    )
    return 0 if result.verified else 1


def _cmd_inspect(args: argparse.Namespace) -> int:
    out = inspect_only(watermarked_path=args.watermarked)
    print(json.dumps(out, indent=2))
    return 0 if out["status"] == "extracted" else 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="openwater",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    # demo
    pd = sub.add_parser("demo", help="run the in-process end-to-end demo")
    pd.add_argument("--input", type=Path, default=None,
                    help="input PNG (default: synthetic sample)")
    pd.add_argument("--out", type=Path, default=Path("out"),
                    help="output directory (default: out/)")
    pd.add_argument("--tamper", action="store_true",
                    help="invert center RGB after embed; verify must reject")
    pd.add_argument("--transform", choices=sorted(TRANSFORMS), default=None,
                    help="apply a channel transform to the watermarked image before verify")
    pd.set_defaults(func=_cmd_demo)

    # sign-embed
    pse = sub.add_parser("sign-embed", help="sign a manifest, embed locator, persist all artifacts")
    pse.add_argument("--input", type=Path, default=None,
                     help="input PNG (default: synthetic sample)")
    pse.add_argument("--out", type=Path, required=True,
                     help="output directory; will contain watermarked.png, key.json, manifests/, manifest_key.txt")
    pse.set_defaults(func=_cmd_sign_embed)

    # verify
    pv = sub.add_parser("verify", help="verify a watermarked PNG against a persisted manifest store + key")
    pv.add_argument("watermarked", type=Path,
                    help="path to the watermarked image")
    pv.add_argument("--manifest-store", dest="manifest_store", type=Path, required=True,
                    help="FileCAS root containing the signed manifest")
    pv.add_argument("--key", type=Path, required=True,
                    help="path to the key envelope JSON (key.json from sign-embed)")
    pv.add_argument("--report", type=Path, default=None,
                    help="optional path to write a JSON verify report")
    pv.set_defaults(func=_cmd_verify)

    # inspect
    pi = sub.add_parser("inspect", help="extract the locator from a watermarked image, no manifest fetch")
    pi.add_argument("watermarked", type=Path,
                    help="path to the watermarked image")
    pi.set_defaults(func=_cmd_inspect)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "cmd", None) == "demo" and args.tamper and args.transform:
        parser.error("--tamper and --transform are mutually exclusive")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
