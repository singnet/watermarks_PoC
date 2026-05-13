"""Benchmark harness for OProW HDC / SHORT64-HV routing.

HDC in OProW is a fuzzy routing layer.  It helps a verifier ask a resolver for a
small candidate set when the watermark only carries a SHORT64 locator.  It is not
cryptography, and it must not be treated as proof of provenance.

This module measures two questions:

1. Stability: how far does the media-derived hypervector move after benign
   transforms such as JPEG recompression or resizing?
2. Separation: how far apart are hypervectors for distinct artifacts?

For route-token profiles it can also measure token overlap.  A high overlap
under benign transforms is good for recall.  A high overlap between unrelated
artifacts is a collision/ambiguity risk and should be handled as candidate-set
expansion, not as verification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from oprow.core.identifiers import ShortId
from oprow.core.models import Artifact
from oprow.hdc.encoders import HDCEncoder
from oprow.hdc.routing import RoutePrecision, derive_route_tokens

from .reports import BenchmarkCase, BenchmarkReport, MetricSample
from .transforms import ArtifactTransform, TransformSuite, safe_apply_transform


@dataclass(frozen=True)
class HDCTrialResult:
    """One HDC stability result for one artifact/transform pair."""

    artifact_id: str
    transform_name: str
    profile_id: str
    transformed: bool
    normalized_hamming: float | None
    route_token_overlap_fraction: float | None = None
    metrics: dict[str, float | int | bool] = field(default_factory=dict)
    diagnostics: dict[str, object] = field(default_factory=dict)
    error: str | None = None

    @property
    def status(self) -> str:
        if not self.transformed:
            return "transform_failed"
        if self.normalized_hamming is None:
            return "encode_failed"
        return "hdc_measured"

    def to_case(self) -> BenchmarkCase:
        metrics = dict(self.metrics)
        if self.normalized_hamming is not None:
            metrics["hdc_normalized_hamming"] = self.normalized_hamming
        if self.route_token_overlap_fraction is not None:
            metrics["route_token_overlap_fraction"] = self.route_token_overlap_fraction
        return BenchmarkCase(
            kind="hdc",
            name=f"{self.profile_id}:{self.transform_name}",
            artifact_id=self.artifact_id,
            transform=self.transform_name,
            profile_id=self.profile_id,
            status=self.status,
            metrics=[MetricSample(k, v) for k, v in metrics.items()],
            diagnostics=self.diagnostics,
            error=self.error,
        )


def _default_artifact_id(index: int, artifact: Artifact) -> str:
    return str(artifact.metadata.get("artifact_id") or artifact.metadata.get("name") or f"artifact-{index}")


def _token_overlap(a: set[bytes], b: set[bytes]) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / float(len(a | b))


def run_hdc_trial(
    *,
    artifact: Artifact,
    artifact_id: str,
    transform: ArtifactTransform,
    encoder: HDCEncoder,
    short_id: ShortId | None = None,
    route_precision: RoutePrecision | None = None,
) -> HDCTrialResult:
    """Run one HDC stability trial.

    Algorithm:
      1. Encode the original artifact to a hypervector.
      2. Apply the transform.
      3. Encode the transformed artifact.
      4. Measure normalized Hamming distance.
      5. Optionally derive route tokens for both and measure set overlap.
    """

    try:
        original = encoder.encode_artifact(artifact)
    except Exception as exc:
        return HDCTrialResult(
            artifact_id=artifact_id,
            transform_name=transform.name,
            profile_id=getattr(encoder.profile, "profile_id", "unknown"),
            transformed=False,
            normalized_hamming=None,
            error=f"original HDC encoding failed: {exc}",
        )

    app = safe_apply_transform(transform, artifact)
    if not app.succeeded or app.artifact is None:
        return HDCTrialResult(
            artifact_id=artifact_id,
            transform_name=transform.name,
            profile_id=encoder.profile.profile_id,
            transformed=False,
            normalized_hamming=None,
            error=app.error,
        )

    try:
        transformed = encoder.encode_artifact(app.artifact)
        distance = original.hypervector.normalized_hamming_distance(transformed.hypervector)
        overlap = None
        diagnostics: dict[str, object] = {
            "original_ped_hash": original.ped_hash.to_hex(),
            "transformed_ped_hash": transformed.ped_hash.to_hex(),
            "ped_length": original.ped_length,
            "transform": app.diagnostics,
        }
        if short_id is not None:
            route_a = derive_route_tokens(short_id=short_id, encoding=original, precision=route_precision)
            route_b = derive_route_tokens(short_id=short_id, encoding=transformed, precision=route_precision)
            keys_a = {t.route_key.value for t in route_a.tokens}
            keys_b = {t.route_key.value for t in route_b.tokens}
            overlap = _token_overlap(keys_a, keys_b)
            diagnostics["route_tokens_original"] = len(keys_a)
            diagnostics["route_tokens_transformed"] = len(keys_b)
        return HDCTrialResult(
            artifact_id=artifact_id,
            transform_name=transform.name,
            profile_id=encoder.profile.profile_id,
            transformed=True,
            normalized_hamming=distance,
            route_token_overlap_fraction=overlap,
            metrics={"same_ped_hash": original.ped_hash == transformed.ped_hash},
            diagnostics=diagnostics,
        )
    except Exception as exc:
        return HDCTrialResult(
            artifact_id=artifact_id,
            transform_name=transform.name,
            profile_id=encoder.profile.profile_id,
            transformed=True,
            normalized_hamming=None,
            error=f"transformed HDC encoding failed: {exc}",
        )


def benchmark_hdc_stability(
    *,
    encoder: HDCEncoder,
    artifacts: Iterable[Artifact],
    transforms: Iterable[ArtifactTransform] | TransformSuite,
    short_id: ShortId | None = None,
    route_precision: RoutePrecision | None = None,
    suite_name: str = "hdc_stability_benchmark",
) -> BenchmarkReport:
    """Run HDC stability benchmark over artifacts and transforms."""

    transform_list = list(transforms.transforms if isinstance(transforms, TransformSuite) else transforms)
    report = BenchmarkReport(
        suite_name=suite_name,
        description="OProW HDC stability and route-token overlap benchmark.",
        metadata={"profile_id": encoder.profile.profile_id, "transforms": [t.name for t in transform_list]},
    )
    for i, artifact in enumerate(artifacts):
        artifact_id = _default_artifact_id(i, artifact)
        for transform in transform_list:
            report.add_case(
                run_hdc_trial(
                    artifact=artifact,
                    artifact_id=artifact_id,
                    transform=transform,
                    encoder=encoder,
                    short_id=short_id,
                    route_precision=route_precision,
                ).to_case()
            )
    return report


def benchmark_hdc_separation(
    *,
    encoder: HDCEncoder,
    artifacts: Iterable[Artifact],
    suite_name: str = "hdc_separation_benchmark",
) -> BenchmarkReport:
    """Measure pairwise HDC distances between distinct artifacts."""

    items = list(artifacts)
    encoded = []
    for i, artifact in enumerate(items):
        encoded.append((_default_artifact_id(i, artifact), encoder.encode_artifact(artifact)))
    report = BenchmarkReport(
        suite_name=suite_name,
        description="Pairwise distinct-artifact HDC separation benchmark.",
        metadata={"profile_id": encoder.profile.profile_id, "artifact_count": len(items)},
    )
    for i in range(len(encoded)):
        for j in range(i + 1, len(encoded)):
            aid, a = encoded[i]
            bid, b = encoded[j]
            d = a.hypervector.normalized_hamming_distance(b.hypervector)
            report.add_case(
                BenchmarkCase(
                    kind="hdc_separation",
                    name=f"{encoder.profile.profile_id}:pairwise",
                    artifact_id=f"{aid}__vs__{bid}",
                    transform="pairwise_distinct",
                    profile_id=encoder.profile.profile_id,
                    status="separated",
                    metrics=[MetricSample("hdc_normalized_hamming", d)],
                    diagnostics={"left_ped_hash": a.ped_hash.to_hex(), "right_ped_hash": b.ped_hash.to_hex()},
                )
            )
    return report


__all__ = [
    "HDCTrialResult",
    "benchmark_hdc_separation",
    "benchmark_hdc_stability",
    "run_hdc_trial",
]
