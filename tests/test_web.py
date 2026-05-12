"""Tests for the openwater.mk FastAPI service.

These exercise the HTTP surface end-to-end via FastAPI's TestClient. No
real network is opened. Per-test jobs root is isolated under ``tmp_path``.
"""
from __future__ import annotations

import json
from io import BytesIO
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image

from openwater_mk.web import UnsafeBindError, build_app
from openwater_mk.web.server import _is_loopback, run as web_run


@pytest.fixture()
def client(tmp_path: Path) -> TestClient:
    app = build_app(jobs_root=tmp_path / "jobs")
    return TestClient(app)


def _new_job(client: TestClient, storage: str = "local") -> str:
    r = client.post("/sign-embed", data={"storage": storage})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["job_id"]
    return body["job_id"]


def test_healthz(client: TestClient) -> None:
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_index_serves_html(client: TestClient) -> None:
    r = client.get("/")
    assert r.status_code == 200
    assert "openwater.mk" in r.text


def test_sign_embed_synthetic_and_download(client: TestClient) -> None:
    job_id = _new_job(client)
    r = client.get(f"/jobs/{job_id}/watermarked.png")
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/png"
    assert len(r.content) > 1000  # not empty


def test_sign_embed_with_uploaded_png(client: TestClient) -> None:
    buf = BytesIO()
    Image.new("RGB", (96, 96), color=(220, 100, 40)).save(buf, format="PNG")
    buf.seek(0)
    r = client.post("/sign-embed", files={"file": ("input.png", buf, "image/png")})
    assert r.status_code == 200
    body = r.json()
    assert body["watermarked_url"].startswith("/jobs/")


def test_sign_embed_storage_backends(client: TestClient) -> None:
    for backend, prefix in [("local", "file://"), ("fake-arweave", "ar://"), ("fake-ipfs", "ipfs://")]:
        r = client.post("/sign-embed", data={"storage": backend})
        assert r.status_code == 200, r.text
        assert r.json()["storage_uri"].startswith(prefix)


def test_self_verify_succeeds(client: TestClient) -> None:
    job_id = _new_job(client)
    r = client.post(f"/jobs/{job_id}/verify")
    assert r.status_code == 200
    body = r.json()
    assert body["verified"] is True
    assert body["job_id"] == job_id


def test_verify_uploaded_image_rejected_when_tampered(client: TestClient) -> None:
    """Upload a PNG that is NOT the job's watermarked image; verify must reject."""
    job_id = _new_job(client)

    # Wholly unrelated PNG
    buf = BytesIO()
    Image.new("RGB", (64, 64), color=(0, 0, 0)).save(buf, format="PNG")
    buf.seek(0)

    r = client.post(
        "/verify",
        data={"job_id": job_id},
        files={"file": ("attack.png", buf, "image/png")},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["verified"] is False


def test_report_html_renders_status_chip(client: TestClient) -> None:
    job_id = _new_job(client)
    r = client.get(f"/jobs/{job_id}/report.html")
    assert r.status_code == 200
    assert "VERIFIED" in r.text
    assert "openwater.mk" in r.text


def test_anchor_then_get(client: TestClient) -> None:
    job_id = _new_job(client, storage="fake-arweave")
    r = client.post(f"/jobs/{job_id}/anchor", params={"epoch": 0})
    assert r.status_code == 200
    body = r.json()
    assert body["metadata_label"] == 40961
    assert len(body["tx_hash"]) == 64

    r2 = client.get(f"/jobs/{job_id}/anchor")
    assert r2.status_code == 200
    payload = r2.json()
    assert payload["verification"]["ok"] is True
    assert payload["metadata"]["40961"]["p"] == "openwater-cardano-anchor-v1"


def test_jobs_listing_forbidden_without_token(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Default posture: no admin token configured -> /jobs returns 403."""
    monkeypatch.delenv("OPENWATER_ADMIN_TOKEN", raising=False)
    _new_job(client)
    r = client.get("/jobs")
    assert r.status_code == 403
    assert "listing disabled" in r.json()["detail"]


def test_jobs_listing_with_admin_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """When OPENWATER_ADMIN_TOKEN is set, the right token returns the list."""
    monkeypatch.setenv("OPENWATER_ADMIN_TOKEN", "s3cr3t")
    app = build_app(jobs_root=tmp_path / "jobs")
    client = TestClient(app)
    j1 = _new_job(client)
    j2 = _new_job(client)

    # Wrong token -> 403
    r = client.get("/jobs", params={"token": "wrong"})
    assert r.status_code == 403

    # Right token via query param -> 200
    r = client.get("/jobs", params={"token": "s3cr3t"})
    assert r.status_code == 200
    ids = {entry["job_id"] for entry in r.json()["jobs"]}
    assert {j1, j2}.issubset(ids)

    # Right token via header -> 200
    r = client.get("/jobs", headers={"X-Admin-Token": "s3cr3t"})
    assert r.status_code == 200


def test_unknown_job_returns_404(client: TestClient) -> None:
    """A well-formed UUID that does not exist on disk -> 404."""
    fake = "0" * 32
    r = client.get(f"/jobs/{fake}")
    assert r.status_code == 404
    r = client.get(f"/jobs/{fake}/watermarked.png")
    assert r.status_code == 404


def test_malformed_job_id_rejected(client: TestClient) -> None:
    """A job id that does not match the 32-hex-char shape -> 400, never read from disk."""
    for bad in ["deadbeef", "Z" * 32, "0" * 31, "0" * 33]:
        r = client.get(f"/jobs/{bad}")
        assert r.status_code == 400, bad


def test_path_traversal_attempt_does_not_reach_handler(client: TestClient) -> None:
    """``../`` segments must never resolve into the handler — router rejects them with 404."""
    for bad in ["../../etc/passwd", "..%2F..%2Fetc%2Fpasswd"]:
        r = client.get(f"/jobs/{bad}")
        assert r.status_code in (400, 404), (bad, r.status_code)


def test_oversize_upload_rejected_with_413(tmp_path: Path) -> None:
    """A request with Content-Length above the cap returns 413."""
    app = build_app(jobs_root=tmp_path / "jobs", max_upload_bytes=4096)
    client = TestClient(app)
    big = b"\x00" * 8192
    r = client.post(
        "/sign-embed",
        files={"file": ("big.png", big, "image/png")},
    )
    assert r.status_code == 413
    assert "exceeds" in r.json()["detail"]


def test_upload_just_under_cap_is_accepted(tmp_path: Path) -> None:
    """A small valid PNG under the cap goes through end-to-end."""
    from io import BytesIO
    buf = BytesIO()
    Image.new("RGB", (32, 32), color=(120, 200, 50)).save(buf, format="PNG")
    payload = buf.getvalue()
    app = build_app(jobs_root=tmp_path / "jobs", max_upload_bytes=128 * 1024)
    client = TestClient(app)
    r = client.post("/sign-embed", files={"file": ("small.png", payload, "image/png")})
    assert r.status_code == 200


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_loopback_hosts_recognized(host: str) -> None:
    assert _is_loopback(host) is True


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.1", "10.0.0.5", "8.8.8.8", "openwater.mk"])
def test_non_loopback_hosts_recognized(host: str) -> None:
    assert _is_loopback(host) is False


def test_run_refuses_non_loopback_without_flag() -> None:
    with pytest.raises(UnsafeBindError):
        web_run(host="0.0.0.0", port=0)


def test_run_refuses_external_ip_without_flag() -> None:
    with pytest.raises(UnsafeBindError):
        web_run(host="8.8.8.8", port=0)
