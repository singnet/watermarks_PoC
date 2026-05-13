"""Convenience orchestration for OProW Step 14 benchmarks.

The individual benchmark modules are intentionally focused: watermark channel,
essence stability, HDC stability/separation, and adversarial probes.  This file
provides a lightweight harness that can run several of them and merge their
cases into one report.

The harness is deliberately not a magic evaluator.  It does not declare a
watermark or HDC profile "secure".  It produces repeatable evidence that another
human, dashboard, or CI policy can inspect.  This matches the OProW philosophy:
trust decisions are local and contextual, not dictated by the protocol.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from oprow.core.models import Artifact
from oprow.essence.base import EssenceProfile
from oprow.hdc.encoders import HDCEncoder
from oprow.watermark.base import WatermarkProfile, WatermarkStrength
from oprow.watermark.payload import WatermarkPayload

from .essence import benchmark_essence_profile, benchmark_essence_separation
from .hdc import benchmark_hdc_separation, benchmark_hdc_stability
from .reports import BenchmarkReport
from .transforms import TransformSuite, quick_image_transform_suite
from .watermark import PayloadFactory, benchmark_watermark_profile, constant_payload_factory


@dataclass
class BenchmarkHarness:
    """Small orchestrator for combined OProW benchmark reports."""

    artifacts: list[Artifact]
    transform_suite: TransformSuite = field(default_factory=quick_image_transform_suite)
    suite_name: str = "oprow_combined_benchmark"

    def combined_report(self, *, description: str = "Combined OProW Step 14 benchmark report.") -> BenchmarkReport:
        return BenchmarkReport(
            suite_name=self.suite_name,
            description=description,
            metadata={"artifact_count": len(self.artifacts), "transform_suite": self.transform_suite.name},
        )

    def run_essence(self, profile: EssenceProfile) -> BenchmarkReport:
        return benchmark_essence_profile(profile=profile, artifacts=self.artifacts, transforms=self.transform_suite)

    def run_essence_with_separation(self, profile: EssenceProfile) -> BenchmarkReport:
        report = self.combined_report(description="Essence robustness plus pairwise separation.")
        report.extend(benchmark_essence_profile(profile=profile, artifacts=self.artifacts, transforms=self.transform_suite).cases)
        report.extend(benchmark_essence_separation(profile=profile, artifacts=self.artifacts).cases)
        return report

    def run_watermark(
        self,
        *,
        profile: WatermarkProfile,
        payload: WatermarkPayload | None = None,
        payload_factory: PayloadFactory | None = None,
        strength: WatermarkStrength | None = None,
    ) -> BenchmarkReport:
        if payload_factory is None:
            if payload is None:
                raise ValueError("run_watermark requires payload or payload_factory")
            payload_factory = constant_payload_factory(payload)
        return benchmark_watermark_profile(
            profile=profile,
            artifacts=self.artifacts,
            payload_factory=payload_factory,
            transforms=self.transform_suite,
            strength=strength,
        )

    def run_hdc(self, encoder: HDCEncoder) -> BenchmarkReport:
        report = self.combined_report(description="HDC stability plus pairwise separation.")
        report.extend(benchmark_hdc_stability(encoder=encoder, artifacts=self.artifacts, transforms=self.transform_suite).cases)
        report.extend(benchmark_hdc_separation(encoder=encoder, artifacts=self.artifacts).cases)
        return report

    def run_all_basic(
        self,
        *,
        essence_profile: EssenceProfile | None = None,
        hdc_encoder: HDCEncoder | None = None,
        watermark_profile: WatermarkProfile | None = None,
        watermark_payload: WatermarkPayload | None = None,
        watermark_strength: WatermarkStrength | None = None,
    ) -> BenchmarkReport:
        """Run all provided benchmark families and merge cases.

        Any family whose profile/payload is omitted is skipped.  This makes the
        method convenient for examples: pass only the components available in a
        particular step or experiment.
        """

        report = self.combined_report()
        if essence_profile is not None:
            report.extend(benchmark_essence_profile(profile=essence_profile, artifacts=self.artifacts, transforms=self.transform_suite).cases)
            report.extend(benchmark_essence_separation(profile=essence_profile, artifacts=self.artifacts).cases)
        if hdc_encoder is not None:
            report.extend(benchmark_hdc_stability(encoder=hdc_encoder, artifacts=self.artifacts, transforms=self.transform_suite).cases)
            report.extend(benchmark_hdc_separation(encoder=hdc_encoder, artifacts=self.artifacts).cases)
        if watermark_profile is not None and watermark_payload is not None:
            report.extend(
                benchmark_watermark_profile(
                    profile=watermark_profile,
                    artifacts=self.artifacts,
                    payload_factory=constant_payload_factory(watermark_payload),
                    transforms=self.transform_suite,
                    strength=watermark_strength,
                ).cases
            )
        return report


__all__ = ["BenchmarkHarness"]
