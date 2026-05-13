"""Benchmark report objects for OProW Step 14.

This module is intentionally boring in the best possible way: it provides small,
JSON-serializable dataclasses that all Step 14 harnesses can share.  The theory
implemented here is not cryptographic; it is *measurement hygiene*.

Why this matters for OProW
==========================

The OProW design deliberately separates several claims that are easy to confuse:

* a watermark extractor may or may not recover the embedded locator;
* a resolver may or may not find candidate manifests;
* the manifest signatures may or may not be valid;
* the received artifact may or may not match the signed essence commitment;
* a local policy may or may not trust the signing keys.

The benchmark layer follows the same separation.  A benchmark case records what
was measured and what succeeded, but it never upgrades a retrieval result into a
provenance result.  The JSON report is meant to feed notebooks, dashboards, and
CI regressions without losing the details needed to diagnose failures.

Serialization rules
===================

The core OProW protocol uses deterministic CBOR for manifests and signatures.
Benchmark reports are not signed protocol objects; they are research artifacts.
For convenience they use JSON, with explicit conversion of bytes-like and
identifier-like objects into readable strings.  If a deployment wants signed
benchmark attestations later, these dataclasses can be wrapped in the Step 1
canonical CBOR machinery.
"""

from __future__ import annotations

from dataclasses import dataclass, field, is_dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
from statistics import mean, pstdev
from typing import Any, Iterable, Mapping


def utc_now_iso() -> str:
    """Return an ISO-8601 timestamp with UTC timezone information."""

    return datetime.now(timezone.utc).isoformat()


def _stringify_key(key: Any) -> str:
    if isinstance(key, str):
        return key
    return str(key)


def to_jsonable(value: Any) -> Any:
    """Convert a benchmark value into a JSON-compatible representation.

    The helper is intentionally conservative.  Benchmark code often handles
    OProW identifiers such as ``Hash256`` or ``ManifestKey`` whose canonical form
    is bytes but whose human-readable form is more helpful in a report.  We avoid
    importing every core type here; instead we look for common protocol methods
    and attributes:

    * ``to_canonical``: used by most OProW dataclasses;
    * dataclass fields: useful for Step 14 report objects;
    * ``value`` bytes: used by identifier wrappers;
    * bytes: encoded as lowercase hex.
    """

    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Mapping):
        return {_stringify_key(k): to_jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in value]
    if hasattr(value, "to_canonical"):
        return to_jsonable(value.to_canonical())
    if is_dataclass(value):
        return {k: to_jsonable(v) for k, v in value.__dict__.items()}
    if hasattr(value, "value") and isinstance(getattr(value, "value"), bytes):
        return getattr(value, "value").hex()
    if hasattr(value, "value") and isinstance(getattr(value, "value"), (str, int, float, bool)):
        return getattr(value, "value")
    return repr(value)


@dataclass(frozen=True)
class MetricSample:
    """One named numeric or categorical measurement.

    Examples include ``psnr_db``, ``watermark_extracted``, ``ped_hash_matches``,
    ``hdc_normalized_hamming``, or ``candidate_count``.  The value is deliberately
    typed as ``Any`` because many benchmark signals are booleans or labels, but
    aggregate helpers only operate on numeric samples.
    """

    name: str
    value: Any
    unit: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": to_jsonable(self.value),
            "unit": self.unit,
            "metadata": to_jsonable(self.metadata),
        }


@dataclass(frozen=True)
class BenchmarkCase:
    """One row in a benchmark report.

    ``kind`` names the benchmark family, e.g. ``watermark``, ``essence``,
    ``hdc``, or ``adversarial``.  ``status`` is a short label meaningful within
    that family.  Detailed measurements live in ``metrics`` and non-numeric
    context lives in ``diagnostics``.
    """

    kind: str
    name: str
    artifact_id: str
    transform: str
    profile_id: str
    status: str
    metrics: list[MetricSample] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    def metric_map(self) -> dict[str, Any]:
        return {m.name: m.value for m in self.metrics}

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "name": self.name,
            "artifact_id": self.artifact_id,
            "transform": self.transform,
            "profile_id": self.profile_id,
            "status": self.status,
            "metrics": [m.to_dict() for m in self.metrics],
            "diagnostics": to_jsonable(self.diagnostics),
            "error": self.error,
        }


@dataclass
class BenchmarkReport:
    """A complete report for a benchmark suite.

    The object is mutable so runners can append cases as they go.  It remains
    deterministic enough for CI because case order is the execution order and the
    summary is computed from the recorded cases.
    """

    suite_name: str
    created_at: str = field(default_factory=utc_now_iso)
    description: str = ""
    cases: list[BenchmarkCase] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_case(self, case: BenchmarkCase) -> None:
        self.cases.append(case)

    def extend(self, cases: Iterable[BenchmarkCase]) -> None:
        for case in cases:
            self.add_case(case)

    def cases_by_kind(self, kind: str) -> list[BenchmarkCase]:
        return [c for c in self.cases if c.kind == kind]

    def count_by_status(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for case in self.cases:
            counts[case.status] = counts.get(case.status, 0) + 1
        return dict(sorted(counts.items()))

    def numeric_metric_values(self, metric_name: str) -> list[float]:
        values: list[float] = []
        for case in self.cases:
            for metric in case.metrics:
                if metric.name == metric_name and isinstance(metric.value, (int, float)):
                    values.append(float(metric.value))
        return values

    def summarize_numeric_metric(self, metric_name: str) -> dict[str, float | int | None]:
        values = self.numeric_metric_values(metric_name)
        if not values:
            return {"count": 0, "mean": None, "stdev": None, "min": None, "max": None}
        return {
            "count": len(values),
            "mean": mean(values),
            "stdev": pstdev(values) if len(values) > 1 else 0.0,
            "min": min(values),
            "max": max(values),
        }

    def summary(self) -> dict[str, Any]:
        """Return a compact machine-readable summary.

        The report does not assume one universal success metric.  Instead it
        counts status labels and aggregates common numeric metrics when present.
        """

        common_metrics = [
            "psnr_db",
            "watermark_extracted",
            "locator_matches",
            "essence_hash_matches",
            "ped_dct_hamming_fraction",
            "hdc_normalized_hamming",
            "route_token_overlap_fraction",
        ]
        return {
            "case_count": len(self.cases),
            "status_counts": self.count_by_status(),
            "numeric_metrics": {
                name: self.summarize_numeric_metric(name)
                for name in common_metrics
                if self.numeric_metric_values(name)
            },
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite_name": self.suite_name,
            "created_at": self.created_at,
            "description": self.description,
            "metadata": to_jsonable(self.metadata),
            "summary": self.summary(),
            "cases": [c.to_dict() for c in self.cases],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    def write_json(self, path: str | Path, *, indent: int = 2) -> Path:
        path = Path(path)
        path.write_text(self.to_json(indent=indent), encoding="utf-8")
        return path


__all__ = [
    "BenchmarkCase",
    "BenchmarkReport",
    "MetricSample",
    "to_jsonable",
    "utc_now_iso",
]
