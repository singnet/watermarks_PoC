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

from openwater_mk.web import build_app


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


def test_jobs_listing(client: TestClient) -> None:
    j1 = _new_job(client)
    j2 = _new_job(client)
    r = client.get("/jobs")
    assert r.status_code == 200
    ids = {entry["job_id"] for entry in r.json()["jobs"]}
    assert {j1, j2}.issubset(ids)


def test_unknown_job_returns_404(client: TestClient) -> None:
    r = client.get("/jobs/deadbeef")
    assert r.status_code == 404
    r = client.get("/jobs/deadbeef/watermarked.png")
    assert r.status_code == 404
