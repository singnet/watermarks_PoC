"""OProW Step 3: essence profile interfaces and hash framing.

This file is the conceptual hinge between the cryptographic manifest layer
(Steps 1-2) and the media-processing layer (Step 3).  In OProW, signatures do
not normally bind directly to container bytes.  Container bytes are too brittle:
metadata can be reordered, JPEG quantization tables can change, files can be
re-encoded by messaging apps, and video/audio codecs may produce slightly
different decoded samples across platforms.  Instead, OProW signs an
``ArtifactBinding`` containing an ``essence_hash``.  The essence hash is the
cryptographic hash of a deterministic *Perceptual Essence Descriptor* (PED).

A PED is not cryptography.  It is a registered, deterministic media descriptor
intended to remain stable under common benign transformations while changing
when the human-perceived content changes materially.  The cryptographic hash
wrapped around the PED gives us a compact commitment suitable for signatures.
Future profiles may use better descriptors, region-level commitments, or
modality-specific fingerprints.  The library therefore exposes a small profile
interface rather than hard-coding one algorithm.

Security model implemented here:

* The final verifier will compare an artifact's recomputed essence hash against
  the signed manifest field.  A match is evidence that the received artifact
  corresponds to the signed content under that profile.
* The essence hash is not a proof of reality.  It says only that a signer signed
  a claim about media whose PED equals this value.
* The PED profile identifier is included in the hash preimage using explicit
  domain separation and length framing.  This prevents accidental cross-profile
  collisions and avoids ambiguous concatenation bugs.

The v2/v3 OProW draft writes the baseline formula informally as something like
``H256(PED || "OProW-PED" || essence_alg_id)``.  This reference code implements
that intent using Step 1's length-framed ``hash_framed`` helper:

    H256(frame("oprow-ped-essence-hash-v1", essence_alg_id, PED))

Length framing is slightly more verbose, but it is the safer protocol habit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from ..core.enums import HashAlgorithm
from ..core.errors import UnsupportedAlgorithmError
from ..core.hashes import hash_framed
from ..core.identifiers import Hash256
from ..core.models import Artifact, ArtifactBinding


@dataclass(frozen=True)
class EssenceComputation:
    """Complete result of running an essence profile over an artifact.

    ``ped`` is retained because later steps need it for HDC routing and for
    benchmarking robustness.  Applications concerned about privacy should avoid
    logging or uploading PEDs, because a PED can function as a media fingerprint.
    The signed manifest normally contains only ``essence_hash`` and
    ``essence_alg_id``.
    """

    alg_id: str
    ped: bytes
    essence_hash: Hash256
    media_type: str
    metadata: dict[str, object] = field(default_factory=dict)

    def to_artifact_binding(
        self,
        *,
        wm_alg_id: str | None = None,
        strict_byte_hash: Hash256 | None = None,
        strict_decode_hash: Hash256 | None = None,
    ) -> ArtifactBinding:
        """Build the manifest-layer binding for this computed essence."""
        return ArtifactBinding(
            media_type=self.media_type,
            essence_alg_id=self.alg_id,
            essence_hash=self.essence_hash,
            hash_alg=HashAlgorithm.SHA256,
            wm_alg_id=wm_alg_id,
            strict_byte_hash=strict_byte_hash,
            strict_decode_hash=strict_decode_hash,
        )


@runtime_checkable
class EssenceProfile(Protocol):
    """Protocol implemented by every registered essence profile.

    A profile must be deterministic.  For the same artifact bytes and same
    decoding environment, it must return the same PED and therefore the same
    ``essence_hash``.  Cross-platform determinism is the hard part of real media
    standards; this reference implementation spells out the image resampler and
    luminance conversion to make the baseline more reproducible.
    """

    alg_id: str
    media_types: set[str]

    def compute_ped(self, artifact: Artifact) -> bytes:
        """Return profile-specific PED bytes for ``artifact``."""
        ...

    def compute(self, artifact: Artifact) -> EssenceComputation:
        """Return PED plus its OProW essence hash."""
        ...

    def compute_hash(self, artifact: Artifact) -> Hash256:
        """Return only the signed commitment value."""
        ...


def ped_hash(ped: bytes, alg_id: str, *, hash_alg: str | HashAlgorithm = HashAlgorithm.SHA256) -> Hash256:
    """Hash a PED into the manifest commitment value.

    The profile identifier is part of the preimage.  Without that, identical PED
    bytes produced by two unrelated algorithms would imply the same signed
    commitment even though verifiers might interpret the bytes differently.
    """
    if not alg_id:
        raise ValueError("essence alg_id must be non-empty")
    return Hash256(hash_framed("oprow-ped-essence-hash-v1", alg_id.encode("utf-8"), bytes(ped), alg=hash_alg))


class BaseEssenceProfile:
    """Convenience base class for profiles that only need ``compute_ped``.

    Subclasses set ``alg_id`` and ``media_types`` and implement ``compute_ped``.
    The base methods perform the domain-separated PED hash and return structured
    ``EssenceComputation`` objects.  This keeps all profiles consistent about
    the signed commitment format.
    """

    alg_id: str = "UNSET"
    media_types: set[str] = set()

    def compute_ped(self, artifact: Artifact) -> bytes:  # pragma: no cover - abstract helper
        raise NotImplementedError

    def supports(self, artifact: Artifact) -> bool:
        return artifact.media_type in self.media_types or not self.media_types

    def compute(self, artifact: Artifact) -> EssenceComputation:
        if not self.supports(artifact):
            raise UnsupportedAlgorithmError(f"{self.alg_id} does not support media type {artifact.media_type!r}")
        ped = self.compute_ped(artifact)
        return EssenceComputation(
            alg_id=self.alg_id,
            ped=ped,
            essence_hash=ped_hash(ped, self.alg_id),
            media_type=artifact.media_type,
            metadata={"ped_length": len(ped)},
        )

    def compute_hash(self, artifact: Artifact) -> Hash256:
        return self.compute(artifact).essence_hash
