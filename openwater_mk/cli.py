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
    anchor_sign_embed_output,
    inspect_only,
    run_demo,
    sign_and_embed,
    verify,
    verify_anchor_dir,
)
from .storage import BACKEND_NAMES
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
    result = sign_and_embed(
        input_path=args.input,
        out_dir=args.out,
        storage_backend=args.storage,
    )
    print(f"watermarked={result.watermarked_path}")
    print(f"manifest_store={result.manifest_store}  ({result.manifest_store_backend})")
    print(f"storage_uri={result.storage_uri}")
    print(f"manifest_key={result.manifest_key_hex}")
    print(f"key={result.key_path}")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    stores: list = []
    for spec in args.manifest_store:
        # accept either "PATH" (auto-detect) or "BACKEND:PATH" (explicit)
        if ":" in spec and not Path(spec).exists():
            backend, _, root = spec.partition(":")
            stores.append((backend, Path(root)))
        else:
            stores.append(Path(spec))
    result = verify(
        watermarked_path=args.watermarked,
        manifest_stores=stores,
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


def _cmd_serve(args: argparse.Namespace) -> int:
    from .web import UnsafeBindError, run as _run
    try:
        _run(
            host=args.host,
            port=args.port,
            jobs_root=args.jobs_root,
            unsafe_public=args.unsafe_public,
        )
    except UnsafeBindError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


def _cmd_anchor(args: argparse.Namespace) -> int:
    result = anchor_sign_embed_output(
        sign_embed_dir=args.sign_embed_dir,
        cardano_dir=args.out,
        epoch=args.epoch,
        record_type=args.record_type,
    )
    print(f"anchor_record={result.anchor_record_path}")
    print(f"receipt={result.receipt_path}")
    print(f"metadata={result.metadata_path}")
    print(f"tx_hash={result.receipt.chain_evidence['tx_hash']}")
    print(f"slot={result.receipt.chain_evidence['slot']}")
    print(f"metadata_label={result.receipt.metadata_label}")
    print(f"metadata_size_bytes={result.receipt.chain_evidence['metadata_size_bytes']}")
    return 0


def _cmd_verify_anchor(args: argparse.Namespace) -> int:
    result = verify_anchor_dir(
        cardano_dir=args.cardano_dir,
        min_confirmations=args.min_confirmations,
    )
    if args.report:
        args.report.write_text(json.dumps({
            "ok": result.ok,
            "failures": list(result.failures),
            "chain_evidence": result.chain_evidence,
        }, indent=2))
    if result.ok:
        print(f"anchor_ok=True  confirmations={result.chain_evidence.get('confirmations')}")
        return 0
    print(f"anchor_ok=False  failures={list(result.failures)}")
    return 1


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
                     help="output directory; will contain watermarked.png, key.json, manifests/, manifest_key.txt, storage_uri.txt")
    pse.add_argument("--storage", choices=BACKEND_NAMES, default="local",
                     help="manifest-store backend (default: local). fake-arweave/fake-ipfs emit realistic txid/CID shapes without network calls.")
    pse.set_defaults(func=_cmd_sign_embed)

    # verify
    pv = sub.add_parser("verify", help="verify a watermarked PNG against one or more persisted manifest stores")
    pv.add_argument("watermarked", type=Path,
                    help="path to the watermarked image")
    pv.add_argument("--manifest-store", dest="manifest_store", action="append", required=True,
                    help="manifest-store path (backend auto-detected); pass multiple to try several. Accepts BACKEND:PATH for explicit backend.")
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

    # anchor
    pa = sub.add_parser(
        "anchor",
        help="publish a Cardano metadata anchor for a sign-embed output (mock backend)",
    )
    pa.add_argument("sign_embed_dir", type=Path,
                    help="directory produced by `openwater sign-embed`")
    pa.add_argument("--out", type=Path, required=True,
                    help="output directory for ledger.json + anchor_record.json + receipt.json + metadata.json")
    pa.add_argument("--epoch", type=int, default=0,
                    help="monotonic anchor epoch (default 0)")
    pa.add_argument("--record-type", default="manifest_root",
                    help="anchor record type label (default: manifest_root)")
    pa.set_defaults(func=_cmd_anchor)

    # serve
    ps = sub.add_parser("serve", help="run the openwater.mk web service via uvicorn")
    ps.add_argument("--host", default="127.0.0.1", help="bind host (default 127.0.0.1)")
    ps.add_argument("--port", type=int, default=8000, help="bind port (default 8000)")
    ps.add_argument("--jobs-root", type=Path, default=None,
                    help="per-job storage root (default $OPENWATER_JOBS_ROOT or /tmp/openwater-mk-jobs)")
    ps.add_argument("--unsafe-public", action="store_true",
                    help="allow binding to a non-loopback host. The service has no authentication; "
                         "passing this flag waives the safety check. See SECURITY.md.")
    ps.set_defaults(func=_cmd_serve)

    # verify-anchor
    pva = sub.add_parser(
        "verify-anchor",
        help="re-verify a Cardano metadata anchor against the local mock ledger",
    )
    pva.add_argument("cardano_dir", type=Path,
                     help="directory produced by `openwater anchor`")
    pva.add_argument("--min-confirmations", type=int, default=1,
                     help="minimum block confirmations required (default: 1)")
    pva.add_argument("--report", type=Path, default=None,
                     help="optional path to write a JSON verification report")
    pva.set_defaults(func=_cmd_verify_anchor)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "cmd", None) == "demo" and args.tamper and args.transform:
        parser.error("--tamper and --transform are mutually exclusive")
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
