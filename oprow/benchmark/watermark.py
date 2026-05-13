"""Benchmark harness for OProW watermark profiles.

The watermark layer carries a locator through hostile media channels.  Its
performance must therefore be measured as a communication channel:

    payload -> embed -> transform -> extract -> decoded locator

This module benchmarks that channel without conflating it with final provenance
verification.  A trial is successful if the extractor recovers the expected
locator.  That still does not mean the artifact is verified; Step 5/12 verifier
workflows must resolve the manifest, check signatures, compare essence, and
apply trust policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable

from oprow.core.models import Artifact
from oprow.watermark.base import WatermarkProfile, WatermarkStrength
from oprow.watermark.payload import WatermarkPayload

from .metrics import byte_difference_fraction, finite_psnr_rgb
from .reports import BenchmarkCase, BenchmarkReport, MetricSample
from .transforms import ArtifactTransform, TransformSuite, safe_apply_transform


PayloadFactory = Callable[[Artifact, int], WatermarkPayload]


@dataclass(frozen=True)
class WatermarkTrialResult:
    """One embed/transform/extract trial for a watermark profile."""

    artifact_id: str
    transform_name: str
    profile_id: str
    embedded: bool
    transformed: bool
    extracted: bool
    locator_matches: bool
    extraction_status: str | None = None
    metrics: dict[str, float | int | bool] = field(default_factory=dict)
    diagnostics: dict[str, object] = field(default_factory=dict)
    error: str | None = None

    @property
    def status(self) -> str:
        if not self.embedded:
            return "embed_failed"
        if not self.transformed:
            return "transform_failed"
        if not self.extracted:
            return "extract_failed"
        return "locator_match" if self.locator_matches else "locator_mismatch"

    def to_case(self) -> BenchmarkCase:
        return BenchmarkCase(
            kind="watermark",
            name=f"{self.profile_id}:{self.transform_name}",
            artifact_id=self.artifact_id,
            transform=self.transform_name,
            profile_id=self.profile_id,
            status=self.status,
            metrics=[MetricSample(k, v) for k, v in self.metrics.items()],
            diagnostics={"extraction_status": self.extraction_status, **self.diagnostics},
            error=self.error,
        )


def _default_artifact_id(index: int, artifact: Artifact) -> str:
    return str(artifact.metadata.get("artifact_id") or artifact.metadata.get("name") or f"artifact-{index}")


def constant_payload_factory(payload: WatermarkPayload) -> PayloadFactory:
    """Return a factory that reuses the same payload for every artifact.

    This is useful for pure channel tests where the payload is just a known bit
    string/locator.  End-to-end provenance tests should instead use the Step 12
    ``embed_manifest_locator`` workflow so the payload is derived from a signed
    manifest.
    """

    def factory(_artifact: Artifact, _index: int) -> WatermarkPayload:
        return payload

    return factory


def run_watermark_trial(
    *,
    artifact: Artifact,
    artifact_id: str,
    transform: ArtifactTransform,
    profile: WatermarkProfile,
    payload: WatermarkPayload,
    strength: WatermarkStrength | None = None,
) -> WatermarkTrialResult:
    """Run one watermark robustness trial.

    Algorithm:
      1. Embed the payload in the source artifact.
      2. Measure embedding distortion against the source image where possible.
      3. Apply one transform to the watermarked artifact.
      4. Extract a payload/locator from the transformed artifact.
      5. Compare the extracted locator with the expected locator.
    """

    try:
        embedded = profile.embed(artifact, payload, strength=strength)
    except Exception as exc:
        return WatermarkTrialResult(
            artifact_id=artifact_id,
            transform_name=transform.name,
            profile_id=profile.alg_id,
            embedded=False,
            transformed=False,
            extracted=False,
            locator_matches=False,
            error=f"embed failed: {exc}",
        )

    metrics: dict[str, float | int | bool] = {
        "payload_bits": len(payload.to_bits()),
        "embed_byte_difference_fraction": byte_difference_fraction(artifact.read_bytes(), embedded.artifact.read_bytes()),
    }
    try:
        metrics["psnr_db"] = finite_psnr_rgb(artifact, embedded.artifact)
    except Exception:
        # Non-image carriers can still use this harness; PSNR is optional.
        pass

    app = safe_apply_transform(transform, embedded.artifact)
    if not app.succeeded or app.artifact is None:
        return WatermarkTrialResult(
            artifact_id=artifact_id,
            transform_name=transform.name,
            profile_id=profile.alg_id,
            embedded=True,
            transformed=False,
            extracted=False,
            locator_matches=False,
            metrics=metrics,
            diagnostics={"embed": embedded.diagnostics},
            error=app.error,
        )

    try:
        extraction = profile.extract(app.artifact, strength=strength, hdc_profile_id=payload.hdc_profile_id)
        expected = payload.to_locator()
        extracted = bool(extraction.extracted)
        locator_matches = bool(extracted and extraction.locator == expected)
        metrics.update(
            {
                "watermark_extracted": extracted,
                "locator_matches": locator_matches,
            }
        )
        return WatermarkTrialResult(
            artifact_id=artifact_id,
            transform_name=transform.name,
            profile_id=profile.alg_id,
            embedded=True,
            transformed=True,
            extracted=extracted,
            locator_matches=locator_matches,
            extraction_status=extraction.status.value,
            metrics=metrics,
            diagnostics={
                "embed": embedded.diagnostics,
                "extraction": extraction.diagnostics,
                "transform": app.diagnostics,
            },
            error=extraction.error,
        )
    except Exception as exc:
        return WatermarkTrialResult(
            artifact_id=artifact_id,
            transform_name=transform.name,
            profile_id=profile.alg_id,
            embedded=True,
            transformed=True,
            extracted=False,
            locator_matches=False,
            metrics=metrics,
            diagnostics={"embed": embedded.diagnostics},
            error=f"extract failed: {exc}",
        )


def benchmark_watermark_profile(
    *,
    profile: WatermarkProfile,
    artifacts: Iterable[Artifact],
    payload_factory: PayloadFactory,
    transforms: Iterable[ArtifactTransform] | TransformSuite,
    strength: WatermarkStrength | None = None,
    suite_name: str = "watermark_profile_benchmark",
) -> BenchmarkReport:
    """Run a watermark benchmark over artifacts and transforms."""

    transform_list = list(transforms.transforms if isinstance(transforms, TransformSuite) else transforms)
    report = BenchmarkReport(
        suite_name=suite_name,
        description="OProW watermark channel benchmark: embed, transform, extract, compare locator.",
        metadata={"profile_id": profile.alg_id, "transforms": [t.name for t in transform_list]},
    )
    for i, artifact in enumerate(artifacts):
        artifact_id = _default_artifact_id(i, artifact)
        payload = payload_factory(artifact, i)
        for transform in transform_list:
            report.add_case(
                run_watermark_trial(
                    artifact=artifact,
                    artifact_id=artifact_id,
                    transform=transform,
                    profile=profile,
                    payload=payload,
                    strength=strength,
                ).to_case()
            )
    return report


__all__ = [
    "PayloadFactory",
    "WatermarkTrialResult",
    "benchmark_watermark_profile",
    "constant_payload_factory",
    "run_watermark_trial",
]
