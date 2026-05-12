"""FastAPI app for openwater.mk.

Mounted endpoints (see also ``/docs``):

  GET  /healthz                         liveness
  GET  /                                static HTML index
  POST /sign-embed                      multipart PNG upload; returns job_id
  GET  /jobs                            list jobs
  GET  /jobs/{job_id}                   job manifest
  GET  /jobs/{job_id}/watermarked.png   raw watermarked image
  POST /jobs/{job_id}/verify            verify the job's own image
  POST /verify                          verify an uploaded image against a job
  POST /jobs/{job_id}/anchor            publish a mock Cardano anchor
  GET  /jobs/{job_id}/anchor            anchor metadata + re-verification
  GET  /jobs/{job_id}/report.html       human-readable verify report
  GET  /jobs/{job_id}/report.json       JSON verify report

The verify endpoints are intentionally lenient about what content they
accept: any PNG that has been processed by ``sign-embed`` for this job
can be checked. Out-of-band tampering or hostile-channel transforms are
expected to fail verification; that is the point.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response

from ..pipeline import (
    anchor_sign_embed_output,
    sign_and_embed,
    verify,
    verify_anchor_dir,
)
from ..storage import BACKEND_NAMES
from .jobs import JobStore
from .templates import render_index, render_verify_report_html


def _verify_response(job_id: str, image_path: Path, manifest_store: Path, key_path: Path) -> dict[str, Any]:
    result = verify(
        watermarked_path=image_path,
        manifest_stores=manifest_store,
        key_envelope_path=key_path,
    )
    report = dict(result.report)
    report["job_id"] = job_id
    report["verified"] = result.verified
    report["extraction_status"] = result.extraction_status
    report["verification_status"] = result.verification_status
    report["locator_mode"] = result.locator_mode
    return report


def build_app(*, jobs_root: Path | None = None) -> FastAPI:
    """Construct the FastAPI app. ``jobs_root`` controls per-job storage."""
    root = Path(jobs_root or os.environ.get("OPENWATER_JOBS_ROOT", "/tmp/openwater-mk-jobs"))
    store = JobStore(root=root)

    app = FastAPI(
        title="openwater.mk",
        version="0.1.0",
        summary="Reference web service for the OpenWater provenance stack",
    )
    app.state.store = store

    @app.exception_handler(FileNotFoundError)
    async def _not_found(_request: Request, exc: FileNotFoundError) -> JSONResponse:
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        return {"ok": True, "jobs_root": str(store.root)}

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return render_index()

    @app.post("/sign-embed")
    async def sign_embed_endpoint(
        file: UploadFile | None = File(default=None),
        storage: str = Form(default="local"),
    ) -> JSONResponse:
        if storage not in BACKEND_NAMES:
            raise HTTPException(400, f"storage must be one of {BACKEND_NAMES}")

        job_id = store.new_job()
        se_dir = store.sign_embed_dir(job_id)
        input_path: Path | None = None
        if file is not None:
            data = await file.read()
            if not data:
                input_path = None
            else:
                input_path = se_dir.parent / "input.png"
                input_path.parent.mkdir(parents=True, exist_ok=True)
                input_path.write_bytes(data)

        result = sign_and_embed(
            input_path=input_path,
            out_dir=se_dir,
            storage_backend=storage,
        )
        return JSONResponse({
            "job_id": job_id,
            "watermarked_url": f"/jobs/{job_id}/watermarked.png",
            "report_url": f"/jobs/{job_id}/report.json",
            "manifest_key": result.manifest_key_hex,
            "storage_uri": result.storage_uri,
            "storage_backend": result.manifest_store_backend,
        })

    @app.get("/jobs")
    def list_jobs() -> dict[str, Any]:
        return {"jobs": store.list_jobs()}

    @app.get("/jobs/{job_id}")
    def get_job(job_id: str) -> dict[str, Any]:
        se = store.sign_embed_dir(job_id)
        if not se.is_dir():
            raise HTTPException(404, f"job {job_id} not found")
        manifest_key = (se / "manifest_key.txt").read_text().strip()
        storage_uri = (se / "storage_uri.txt").read_text().strip() if (se / "storage_uri.txt").exists() else None
        return {
            "job_id": job_id,
            "manifest_key": manifest_key,
            "storage_uri": storage_uri,
            "watermarked_url": f"/jobs/{job_id}/watermarked.png",
            "has_anchor": store.anchor_dir(job_id).is_dir(),
        }

    @app.get("/jobs/{job_id}/watermarked.png")
    def get_watermarked(job_id: str) -> FileResponse:
        path = store.sign_embed_dir(job_id) / "watermarked.png"
        if not path.exists():
            raise HTTPException(404, "watermarked image not found")
        return FileResponse(path, media_type="image/png")

    @app.post("/jobs/{job_id}/verify")
    def verify_self(job_id: str) -> JSONResponse:
        se = store.sign_embed_dir(job_id)
        report = _verify_response(
            job_id=job_id,
            image_path=se / "watermarked.png",
            manifest_store=se / "manifests",
            key_path=se / "key.json",
        )
        store.save_verify_report(job_id, report)
        return JSONResponse(report)

    @app.post("/verify")
    async def verify_uploaded(
        job_id: str = Form(...),
        file: UploadFile = File(...),
    ) -> JSONResponse:
        se = store.sign_embed_dir(job_id)
        if not se.is_dir():
            raise HTTPException(404, f"job {job_id} not found")
        upload_path = store.job_dir(job_id) / "uploaded.png"
        upload_path.write_bytes(await file.read())
        report = _verify_response(
            job_id=job_id,
            image_path=upload_path,
            manifest_store=se / "manifests",
            key_path=se / "key.json",
        )
        store.save_verify_report(job_id, report)
        return JSONResponse(report)

    @app.get("/jobs/{job_id}/report.json")
    def report_json(job_id: str) -> JSONResponse:
        path = store.job_dir(job_id) / "verify_report.json"
        if not path.exists():
            # Lazily generate from the job's own image.
            return verify_self(job_id)
        return JSONResponse(json.loads(path.read_text()))

    @app.get("/jobs/{job_id}/report.html", response_class=HTMLResponse)
    def report_html(job_id: str) -> str:
        path = store.job_dir(job_id) / "verify_report.json"
        if not path.exists():
            verify_self(job_id)
        report = json.loads(path.read_text())
        return render_verify_report_html(report)

    @app.post("/jobs/{job_id}/anchor")
    def post_anchor(job_id: str, epoch: int = 0, record_type: str = "manifest_root") -> JSONResponse:
        se = store.sign_embed_dir(job_id)
        if not se.is_dir():
            raise HTTPException(404, f"job {job_id} not found")
        anchor_dir = store.anchor_dir(job_id)
        result = anchor_sign_embed_output(
            sign_embed_dir=se,
            cardano_dir=anchor_dir,
            epoch=epoch,
            record_type=record_type,
        )
        return JSONResponse({
            "tx_hash": result.receipt.chain_evidence["tx_hash"],
            "slot": result.receipt.chain_evidence["slot"],
            "metadata_label": result.receipt.metadata_label,
            "metadata_size_bytes": result.receipt.chain_evidence["metadata_size_bytes"],
            "anchor_record_hash": result.receipt.anchor_record_hash.hex(),
            "anchor_url": f"/jobs/{job_id}/anchor",
        })

    @app.get("/jobs/{job_id}/anchor")
    def get_anchor(job_id: str) -> JSONResponse:
        anchor_dir = store.anchor_dir(job_id)
        if not anchor_dir.is_dir():
            raise HTTPException(404, "no anchor for this job")
        verification = verify_anchor_dir(cardano_dir=anchor_dir)
        return JSONResponse({
            "anchor_record": json.loads((anchor_dir / "anchor_record.json").read_text()),
            "receipt": json.loads((anchor_dir / "receipt.json").read_text()),
            "metadata": json.loads((anchor_dir / "metadata.json").read_text()),
            "verification": {
                "ok": verification.ok,
                "failures": list(verification.failures),
                "chain_evidence": verification.chain_evidence,
            },
        })

    return app


def run(host: str = "127.0.0.1", port: int = 8000, jobs_root: Path | None = None) -> None:
    """Start the openwater.mk web service via uvicorn."""
    import uvicorn

    app = build_app(jobs_root=jobs_root)
    uvicorn.run(app, host=host, port=port)
