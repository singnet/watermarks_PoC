"""Per-job working-directory layout used by the web service.

Each ``POST /sign-embed`` creates a new job UUID and a directory tree that
mirrors what the CLI produces locally. Verify/anchor endpoints then look
up artifacts by job id rather than uploading them per request.

Layout::

    <jobs_root>/<job_id>/
        sign_embed/
            watermarked.png
            key.json
            manifest_key.txt
            storage_uri.txt
            manifests/...
        anchor/
            ledger.json
            anchor_record.json
            receipt.json
            metadata.json
        verify_report.json
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class JobStore:
    root: Path

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self.root.mkdir(parents=True, exist_ok=True)

    def new_job(self) -> str:
        job_id = uuid.uuid4().hex
        (self.root / job_id).mkdir(parents=True)
        return job_id

    def job_dir(self, job_id: str) -> Path:
        path = self.root / job_id
        if not path.is_dir():
            raise FileNotFoundError(f"unknown job: {job_id!r}")
        return path

    def sign_embed_dir(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "sign_embed"

    def anchor_dir(self, job_id: str) -> Path:
        return self.job_dir(job_id) / "anchor"

    def list_jobs(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for child in sorted(self.root.iterdir()):
            if not child.is_dir():
                continue
            se = child / "sign_embed"
            entry = {
                "job_id": child.name,
                "has_sign_embed": se.is_dir(),
                "has_anchor": (child / "anchor").is_dir(),
            }
            mk = se / "manifest_key.txt"
            if mk.exists():
                entry["manifest_key"] = mk.read_text().strip()
            uri = se / "storage_uri.txt"
            if uri.exists():
                entry["storage_uri"] = uri.read_text().strip()
            result.append(entry)
        return result

    def save_verify_report(self, job_id: str, report: dict[str, Any]) -> Path:
        path = self.job_dir(job_id) / "verify_report.json"
        path.write_text(json.dumps(report, indent=2))
        return path
