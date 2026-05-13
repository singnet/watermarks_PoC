"""Benchmark harness for OProW essence profiles.

The essence layer is the signed content-binding layer in OProW.  A verifier
recomputes the artifact's PED-based essence hash and compares it with the signed
manifest field.  The core engineering question is therefore empirical:

    Which benign transforms preserve the essence hash, and which content changes
    produce a mismatch?

This module measures exactly that.  It does not decide whether a transform
*should* pass; it records what happens for a profile, corpus, and transform
suite.  For PED-IMG-1 it also records diagnostic distances between the original
and transformed PEDs so profile authors can see how close a mismatch was.

Security boundary
=================

A stable essence hash is necessary for robust verification, but a perceptual
hash/PED can admit collisions or near-collisions.  OProW still relies on signed
manifests, key trust, and UI semantics.  The benchmark harness helps quantify
the tradeoff; it is not a proof that an essence profile is adversary-proof.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from oprow.core.models import Artifact
from oprow.essence.base import EssenceProfile
from oprow.essence.image import PED_IMG_1_ALG_ID, compare_ped_img1

from .reports import BenchmarkCase, BenchmarkReport, MetricSample, to_jsonable
from .transforms import ArtifactTransform, TransformSuite, safe_apply_transform


@dataclass(frozen=True)
class EssenceTrialResult:
    """One essence-profile result for one artifact/transform pair."""

    artifact_id: str
    transform_name: str
    profile_id: str
    transformed: bool
    essence_hash_matches: bool
    original_hash: str | None = None
    transformed_hash: str | None = None
    metrics: dict[str, float | int | bool] = field(default_factory=dict)
    diagnostics: dict[str, object] = field(default_factory=dict)
    error: str | None = None

    @property
    def status(self) -> str:
        if not self.transformed:
            return "transform_failed"
        return "essence_match" if self.essence_hash_matches else "essence_mismatch"

    def to_case(self) -> BenchmarkCase:
        return BenchmarkCase(
            kind="essence",
            name=f"{self.profile_id}:{self.transform_name}",
            artifact_id=self.artifact_id,
            transform=self.transform_name,
            profile_id=self.profile_id,
            status=self.status,
            metrics=[MetricSample(k, v) for k, v in self.metrics.items()],
            diagnostics={
                "original_hash": self.original_hash,
                "transformed_hash": self.transformed_hash,
                **self.diagnostics,
            },
            error=self.error,
        )


def _default_artifact_id(index: int, artifact: Artifact) -> str:
    return str(artifact.metadata.get("artifact_id") or artifact.metadata.get("name") or f"artifact-{index}")


def run_essence_trial(
    *,
    artifact: Artifact,
    artifact_id: str,
    transform: ArtifactTransform,
    profile: EssenceProfile,
) -> EssenceTrialResult:
    """Run one essence robustness trial.

    Algorithm:
      1. Compute the original artifact's PED and essence hash.
      2. Apply the transform.
      3. Compute the transformed artifact's PED and essence hash.
      4. Compare hashes and, where possible, PED diagnostic distances.
    """

    try:
        original = profile.compute(artifact)
    except Exception as exc:
        return EssenceTrialResult(
            artifact_id=artifact_id,
            transform_name=transform.name,
            profile_id=getattr(profile, "alg_id", "unknown"),
            transformed=False,
            essence_hash_matches=False,
            error=f"original essence failed: {exc}",
        )

    app = safe_apply_transform(transform, artifact)
    if not app.succeeded or app.artifact is None:
        return EssenceTrialResult(
            artifact_id=artifact_id,
            transform_name=transform.name,
            profile_id=profile.alg_id,
            transformed=False,
            essence_hash_matches=False,
            original_hash=original.essence_hash.to_hex(),
            error=app.error,
        )

    try:
        transformed = profile.compute(app.artifact)
    except Exception as exc:
        return EssenceTrialResult(
            artifact_id=artifact_id,
            transform_name=transform.name,
            profile_id=profile.alg_id,
            transformed=True,
            essence_hash_matches=False,
            original_hash=original.essence_hash.to_hex(),
            error=f"transformed essence failed: {exc}",
        )

    metrics: dict[str, float | int | bool] = {
        "essence_hash_matches": original.essence_hash == transformed.essence_hash,
        "original_ped_bytes": len(original.ped),
        "transformed_ped_bytes": len(transformed.ped),
    }
    diagnostics: dict[str, object] = {
        "transform_diagnostics": app.diagnostics,
        "original_metadata": original.metadata,
        "transformed_metadata": transformed.metadata,
    }

    if profile.alg_id == PED_IMG_1_ALG_ID and len(original.ped) == len(transformed.ped):
        distance = compare_ped_img1(original.ped, transformed.ped)
        metrics.update(
            {
                "ped_mean_abs_block_delta": distance.mean_absolute_block_delta,
                "ped_max_block_delta": distance.max_block_delta,
                "ped_dct_hamming": distance.dct_sign_hamming,
                "ped_dct_hamming_fraction": distance.dct_sign_hamming_fraction,
            }
        )

    return EssenceTrialResult(
        artifact_id=artifact_id,
        transform_name=transform.name,
        profile_id=profile.alg_id,
        transformed=True,
        essence_hash_matches=original.essence_hash == transformed.essence_hash,
        original_hash=original.essence_hash.to_hex(),
        transformed_hash=transformed.essence_hash.to_hex(),
        metrics=metrics,
        diagnostics=diagnostics,
    )


def benchmark_essence_profile(
    *,
    profile: EssenceProfile,
    artifacts: Iterable[Artifact],
    transforms: Iterable[ArtifactTransform] | TransformSuite,
    suite_name: str = "essence_profile_benchmark",
) -> BenchmarkReport:
    """Run an essence benchmark over artifacts and transforms."""

    transform_list = list(transforms.transforms if isinstance(transforms, TransformSuite) else transforms)
    report = BenchmarkReport(
        suite_name=suite_name,
        description="OProW essence/PED stability benchmark.",
        metadata={"profile_id": profile.alg_id, "transforms": [t.name for t in transform_list]},
    )
    for i, artifact in enumerate(artifacts):
        artifact_id = _default_artifact_id(i, artifact)
        for transform in transform_list:
            trial = run_essence_trial(artifact=artifact, artifact_id=artifact_id, transform=transform, profile=profile)
            report.add_case(trial.to_case())
    return report


def benchmark_essence_separation(
    *,
    profile: EssenceProfile,
    artifacts: Iterable[Artifact],
    suite_name: str = "essence_separation_benchmark",
) -> BenchmarkReport:
    """Compare all artifact pairs to find accidental same-essence results.

    The separation benchmark is a small-scale guardrail for obvious collisions.
    It is not an adversarial search.  Large deployments should run much larger
    corpus tests and adversarial optimization attacks.
    """

    items = list(artifacts)
    computations = []
    for i, artifact in enumerate(items):
        artifact_id = _default_artifact_id(i, artifact)
        computations.append((artifact_id, profile.compute(artifact)))

    report = BenchmarkReport(
        suite_name=suite_name,
        description="Pairwise distinct-artifact essence separation benchmark.",
        metadata={"profile_id": profile.alg_id, "artifact_count": len(items)},
    )
    for i in range(len(computations)):
        for j in range(i + 1, len(computations)):
            aid, a = computations[i]
            bid, b = computations[j]
            same_hash = a.essence_hash == b.essence_hash
            metrics = [MetricSample("essence_hash_matches", same_hash)]
            diagnostics = {"left_hash": a.essence_hash.to_hex(), "right_hash": b.essence_hash.to_hex()}
            if profile.alg_id == PED_IMG_1_ALG_ID and len(a.ped) == len(b.ped):
                d = compare_ped_img1(a.ped, b.ped)
                metrics.extend(
                    [
                        MetricSample("ped_mean_abs_block_delta", d.mean_absolute_block_delta),
                        MetricSample("ped_max_block_delta", d.max_block_delta),
                        MetricSample("ped_dct_hamming", d.dct_sign_hamming),
                        MetricSample("ped_dct_hamming_fraction", d.dct_sign_hamming_fraction),
                    ]
                )
            report.add_case(
                BenchmarkCase(
                    kind="essence_separation",
                    name=f"{profile.alg_id}:pairwise",
                    artifact_id=f"{aid}__vs__{bid}",
                    transform="pairwise_distinct",
                    profile_id=profile.alg_id,
                    status="collision" if same_hash else "separated",
                    metrics=metrics,
                    diagnostics=to_jsonable(diagnostics),
                )
            )
    return report


__all__ = [
    "EssenceTrialResult",
    "benchmark_essence_profile",
    "benchmark_essence_separation",
    "run_essence_trial",
]
