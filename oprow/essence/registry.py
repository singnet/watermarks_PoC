"""Essence profile registry.

The OProW draft emphasizes algorithm agility: manifests carry an
``artifact.essence_alg_id`` so verifiers know which PED profile to recompute.
This registry provides the library-side mechanism for that agility.  A verifier
will later read the algorithm ID from a manifest, ask the registry for that
profile, compute the artifact's essence hash, and compare it to the signed
binding.

The registry is intentionally small and local.  It is not a global authority or
trust root.  Production ecosystems may publish community registries and test
vectors, but this Python object is just a mapping from ``alg_id`` to a profile
implementation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from ..core.errors import UnsupportedAlgorithmError, ValidationError
from ..core.identifiers import Hash256
from ..core.models import Artifact, ArtifactBinding
from .base import EssenceComputation, EssenceProfile
from .image import ImagePED1, PED_IMG_1_ALG_ID
from .strict import compute_strict_byte_hash


@dataclass
class EssenceRegistry:
    """Mutable registry of essence profiles known to this verifier/creator."""

    _profiles: dict[str, EssenceProfile] = field(default_factory=dict)

    def register(self, profile: EssenceProfile, *, replace: bool = False) -> None:
        """Register a profile implementation.

        Replacing an existing profile is disabled by default because changing a
        profile's implementation under the same ID would make signatures appear
        to fail.  Tests may use ``replace=True`` deliberately.
        """
        alg_id = getattr(profile, "alg_id", "")
        if not alg_id:
            raise ValidationError("essence profile must have a non-empty alg_id")
        if alg_id in self._profiles and not replace:
            raise ValidationError(f"essence profile {alg_id!r} is already registered")
        self._profiles[alg_id] = profile

    def get(self, alg_id: str) -> EssenceProfile:
        try:
            return self._profiles[alg_id]
        except KeyError as exc:
            raise UnsupportedAlgorithmError(f"unknown essence profile: {alg_id}") from exc

    def alg_ids(self) -> list[str]:
        return sorted(self._profiles)

    def compute(self, artifact: Artifact, alg_id: str) -> EssenceComputation:
        return self.get(alg_id).compute(artifact)

    def compute_hash(self, artifact: Artifact, alg_id: str) -> Hash256:
        return self.compute(artifact, alg_id).essence_hash

    def build_artifact_binding(
        self,
        artifact: Artifact,
        *,
        alg_id: str = PED_IMG_1_ALG_ID,
        wm_alg_id: str | None = None,
        include_strict_byte_hash: bool = False,
        include_strict_decode_hash: bool = False,
    ) -> ArtifactBinding:
        """Build a manifest ``ArtifactBinding`` using a registered profile.

        Profiles may implement their own richer ``build_artifact_binding``
        method.  If they do not, this method computes the primary essence hash
        and optionally adds a strict byte hash.  Decode-strict hashing is
        profile-specific, so the generic fallback rejects that request.
        """
        profile = self.get(alg_id)
        if hasattr(profile, "build_artifact_binding"):
            # The ImagePED1 implementation supports strict decoded RGB hashing.
            return getattr(profile, "build_artifact_binding")(
                artifact,
                wm_alg_id=wm_alg_id,
                include_strict_byte_hash=include_strict_byte_hash,
                include_strict_decode_hash=include_strict_decode_hash,
            )
        if include_strict_decode_hash:
            raise UnsupportedAlgorithmError(f"profile {alg_id} does not implement strict decode hashing")
        computation = profile.compute(artifact)
        return computation.to_artifact_binding(
            wm_alg_id=wm_alg_id,
            strict_byte_hash=compute_strict_byte_hash(artifact) if include_strict_byte_hash else None,
        )


DEFAULT_ESSENCE_REGISTRY = EssenceRegistry()
DEFAULT_ESSENCE_REGISTRY.register(ImagePED1())


def default_essence_registry(extra_profiles: Iterable[EssenceProfile] | None = None) -> EssenceRegistry:
    """Return a fresh registry populated with baseline profiles.

    A fresh object avoids global mutation bugs in tests and applications.
    """
    registry = EssenceRegistry()
    registry.register(ImagePED1())
    for profile in extra_profiles or []:
        registry.register(profile)
    return registry


def compute_essence_hash(artifact: Artifact, alg_id: str = PED_IMG_1_ALG_ID) -> Hash256:
    """Convenience function using the default registry."""
    return DEFAULT_ESSENCE_REGISTRY.compute_hash(artifact, alg_id)


def build_artifact_binding(
    artifact: Artifact,
    *,
    alg_id: str = PED_IMG_1_ALG_ID,
    wm_alg_id: str | None = None,
    include_strict_byte_hash: bool = False,
    include_strict_decode_hash: bool = False,
) -> ArtifactBinding:
    """Convenience function for ManifestCore construction."""
    return DEFAULT_ESSENCE_REGISTRY.build_artifact_binding(
        artifact,
        alg_id=alg_id,
        wm_alg_id=wm_alg_id,
        include_strict_byte_hash=include_strict_byte_hash,
        include_strict_decode_hash=include_strict_decode_hash,
    )
