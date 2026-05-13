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

import ipaddress
import re

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from ..pipeline import (
    PROFILE_NAMES,
    anchor_sign_embed_output,
    sign_and_embed,
    verify,
    verify_anchor_dir,
)
from ..storage import BACKEND_NAMES
from .jobs import JobStore
from .templates import render_index, render_verify_report_html


DEFAULT_MAX_UPLOAD_BYTES = 1 * 1024 * 1024  # 1 MB
JOB_ID_RE = re.compile(r"^[0-9a-f]{32}$")
# The web service defaults to ``alpha_lsb`` so small uploads (under ~64x64)
# fit the per-block capacity of the DCT/QIM family and so a self-verify
# round-trip can report ``verified=True``. Callers wanting JPEG-robust
# locator survival pass ``profile=dct_qim`` (or ``dct_qim_robust``)
# explicitly via the ``profile`` form field.
WEB_DEFAULT_PROFILE = "alpha_lsb"


def _max_upload_bytes() -> int:
    raw = os.environ.get("OPENWATER_MAX_UPLOAD_BYTES")
    if raw is None:
        return DEFAULT_MAX_UPLOAD_BYTES
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(
            f"OPENWATER_MAX_UPLOAD_BYTES must be an integer, got {raw!r}"
        ) from exc
    if value <= 0:
        raise ValueError("OPENWATER_MAX_UPLOAD_BYTES must be positive")
    return value


def _admin_token() -> str | None:
    """Return the configured admin token, or None if listing is disabled."""
    tok = os.environ.get("OPENWATER_ADMIN_TOKEN", "").strip()
    return tok or None


def _validate_job_id(job_id: str) -> None:
    if not JOB_ID_RE.match(job_id):
        raise HTTPException(400, f"invalid job id: {job_id!r}")


class MaxBodySizeMiddleware(BaseHTTPMiddleware):
    """Cut off requests whose declared Content-Length exceeds the cap.

    This rejects oversize requests *before* FastAPI parses them. The
    handler-side ``await file.read()`` is still bounded by the same cap
    via the ``request._receive`` wrapper below, which guards against a
    client that lies about ``Content-Length``.
    """

    def __init__(self, app, max_bytes: int) -> None:
        super().__init__(app)
        self.max_bytes = max_bytes

    async def dispatch(self, request: Request, call_next):
        cl = request.headers.get("content-length")
        if cl is not None:
            try:
                if int(cl) > self.max_bytes:
                    return JSONResponse(
                        {"detail": f"request body exceeds {self.max_bytes} bytes"},
                        status_code=413,
                    )
            except ValueError:
                return JSONResponse({"detail": "invalid Content-Length"}, status_code=400)

        original_receive = request._receive
        total = 0
        cap = self.max_bytes

        async def guarded_receive():
            nonlocal total
            message = await original_receive()
            if message.get("type") == "http.request":
                body = message.get("body", b"")
                total += len(body)
                if total > cap:
                    return {
                        "type": "http.request",
                        "body": b"",
                        "more_body": False,
                    }
            return message

        request._receive = guarded_receive
        try:
            return await call_next(request)
        except Exception:
            if total > cap:
                return JSONResponse(
                    {"detail": f"request body exceeds {cap} bytes"},
                    status_code=413,
                )
            raise


def _job_profile(sign_embed_dir: Path) -> str:
    """Return the profile used when this job was signed/embedded.

    Falls back to ``WEB_DEFAULT_PROFILE`` for legacy jobs that predate the
    profile.txt sidecar, so older jobs still verify.
    """
    pf = sign_embed_dir / "profile.txt"
    if pf.exists():
        candidate = pf.read_text().strip()
        if candidate in PROFILE_NAMES:
            return candidate
    return WEB_DEFAULT_PROFILE


def _verify_response(
    job_id: str,
    image_path: Path,
    manifest_store: Path,
    key_path: Path,
    profile: str = WEB_DEFAULT_PROFILE,
) -> dict[str, Any]:
    result = verify(
        watermarked_path=image_path,
        manifest_stores=manifest_store,
        key_envelope_path=key_path,
        profile=profile,
    )
    report = dict(result.report)
    report["job_id"] = job_id
    report["profile"] = profile
    report["verified"] = result.verified
    report["extraction_status"] = result.extraction_status
    report["verification_status"] = result.verification_status
    report["locator_mode"] = result.locator_mode
    return report


def build_app(
    *,
    jobs_root: Path | None = None,
    max_upload_bytes: int | None = None,
) -> FastAPI:
    """Construct the FastAPI app. ``jobs_root`` controls per-job storage.

    ``max_upload_bytes`` caps every incoming request body. Defaults to
    ``OPENWATER_MAX_UPLOAD_BYTES`` env var, then ``DEFAULT_MAX_UPLOAD_BYTES``
    (1 MB).
    """
    root = Path(jobs_root or os.environ.get("OPENWATER_JOBS_ROOT", "/tmp/openwater-mk-jobs"))
    store = JobStore(root=root)
    cap = max_upload_bytes if max_upload_bytes is not None else _max_upload_bytes()

    app = FastAPI(
        title="openwater.mk",
        version="0.1.0",
        summary="Reference web service for the OpenWater provenance stack",
    )
    app.state.store = store
    app.state.max_upload_bytes = cap
    app.add_middleware(MaxBodySizeMiddleware, max_bytes=cap)

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
        profile: str = Form(default=WEB_DEFAULT_PROFILE),
    ) -> JSONResponse:
        if storage not in BACKEND_NAMES:
            raise HTTPException(400, f"storage must be one of {BACKEND_NAMES}")
        if profile not in PROFILE_NAMES:
            raise HTTPException(400, f"profile must be one of {list(PROFILE_NAMES)}")

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
            profile=profile,
        )
        (se_dir / "profile.txt").write_text(profile + "\n")
        return JSONResponse({
            "job_id": job_id,
            "profile": profile,
            "watermarked_url": f"/jobs/{job_id}/watermarked.png",
            "report_url": f"/jobs/{job_id}/report.json",
            "manifest_key": result.manifest_key_hex,
            "storage_uri": result.storage_uri,
            "storage_backend": result.manifest_store_backend,
        })

    @app.get("/jobs")
    def list_jobs(request: Request) -> JSONResponse:
        """List jobs. Gated behind OPENWATER_ADMIN_TOKEN; 403 if unset.

        The default closed posture is intentional: a public listing would
        leak every job id, which is enough to fetch the watermarked image
        and verify report. See SECURITY.md.
        """
        expected = _admin_token()
        if expected is None:
            return JSONResponse(
                {"detail": "listing disabled: set OPENWATER_ADMIN_TOKEN to enable"},
                status_code=403,
            )
        supplied = request.headers.get("x-admin-token") or request.query_params.get("token")
        if supplied != expected:
            return JSONResponse({"detail": "forbidden"}, status_code=403)
        return JSONResponse({"jobs": store.list_jobs()})

    @app.get("/jobs/{job_id}")
    def get_job(job_id: str) -> dict[str, Any]:
        _validate_job_id(job_id)
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
        _validate_job_id(job_id)
        path = store.sign_embed_dir(job_id) / "watermarked.png"
        if not path.exists():
            raise HTTPException(404, "watermarked image not found")
        return FileResponse(path, media_type="image/png")

    @app.post("/jobs/{job_id}/verify")
    def verify_self(job_id: str) -> JSONResponse:
        _validate_job_id(job_id)
        se = store.sign_embed_dir(job_id)
        report = _verify_response(
            job_id=job_id,
            image_path=se / "watermarked.png",
            manifest_store=se / "manifests",
            key_path=se / "key.json",
            profile=_job_profile(se),
        )
        store.save_verify_report(job_id, report)
        return JSONResponse(report)

    @app.post("/verify")
    async def verify_uploaded(
        job_id: str = Form(...),
        file: UploadFile = File(...),
    ) -> JSONResponse:
        _validate_job_id(job_id)
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
            profile=_job_profile(se),
        )
        store.save_verify_report(job_id, report)
        return JSONResponse(report)

    @app.get("/jobs/{job_id}/report.json")
    def report_json(job_id: str) -> JSONResponse:
        _validate_job_id(job_id)
        path = store.job_dir(job_id) / "verify_report.json"
        if not path.exists():
            # Lazily generate from the job's own image.
            return verify_self(job_id)
        return JSONResponse(json.loads(path.read_text()))

    @app.get("/jobs/{job_id}/report.html", response_class=HTMLResponse)
    def report_html(job_id: str) -> str:
        _validate_job_id(job_id)
        path = store.job_dir(job_id) / "verify_report.json"
        if not path.exists():
            verify_self(job_id)
        report = json.loads(path.read_text())
        return render_verify_report_html(report)

    @app.post("/jobs/{job_id}/anchor")
    def post_anchor(job_id: str, epoch: int = 0, record_type: str = "manifest_root") -> JSONResponse:
        _validate_job_id(job_id)
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
        _validate_job_id(job_id)
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


def _is_loopback(host: str) -> bool:
    """Return True if ``host`` is a loopback literal.

    Hostnames (e.g. ``localhost``) are not resolved here — the caller is
    expected to pass an IP literal in production deployments. Accept the
    common loopback strings explicitly.
    """
    if host in {"localhost", "127.0.0.1", "::1", "0:0:0:0:0:0:0:1"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback


class UnsafeBindError(RuntimeError):
    """Raised when ``run`` is asked to bind to a non-loopback address without ``unsafe_public=True``."""


def run(
    host: str = "127.0.0.1",
    port: int = 8000,
    jobs_root: Path | None = None,
    *,
    unsafe_public: bool = False,
) -> None:
    """Start the openwater.mk web service via uvicorn.

    Refuses to bind to anything other than a loopback address unless
    ``unsafe_public=True`` is set. The web service has no authentication
    by default (see SECURITY.md), so binding publicly without explicit
    consent would expose every endpoint to unauthenticated callers.
    """
    if not unsafe_public and not _is_loopback(host):
        raise UnsafeBindError(
            f"refusing to bind to non-loopback host {host!r} without unsafe_public=True; "
            "the service has no authentication by default. See SECURITY.md."
        )

    import uvicorn

    app = build_app(jobs_root=jobs_root)
    uvicorn.run(app, host=host, port=port)
