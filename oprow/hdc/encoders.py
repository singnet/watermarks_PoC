"""HDC encoders: PED bytes -> high-dimensional routing vectors.

The baseline encoder here is intentionally simple, deterministic, and heavily
commented.  It implements a symbolic-bundling HDC scheme:

    for each PED byte position i and quantized value q:
        slot_i  = random hypervector(seed, "slot", i)
        value_q = random hypervector(seed, "value", q)
        symbol  = bind(slot_i, value_q)      # XOR in binary representation
        bundle(symbol)                       # majority superposition

The result is a single hypervector representing the whole PED.  This mirrors the
HDC/VSA idea that a structured object can be represented by binding positions to
values and bundling all bindings.

Why not use a neural embedding?
==============================

A neural embedding could work well for retrieval, but it would introduce model
versioning, opaque training data, and cross-platform determinism problems.  The
reference implementation starts with a fully deterministic algorithm whose test
vectors can be reproduced by anyone.  Production deployments can register more
powerful HDC profiles later, provided they publish deterministic extraction
rules and robustness benchmarks.

Security boundary
=================

The encoder output is a routing descriptor.  It is *not* a cryptographic
commitment and it is not a provenance verifier.  An attacker who creates an HDC
collision should at worst cause a candidate-list ambiguity or DoS condition;
final verification still checks manifest signatures and the signed essence hash.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

import numpy as np

from oprow.core.errors import UnsupportedAlgorithmError, ValidationError
from oprow.core.hashes import hash_framed
from oprow.core.identifiers import Hash256
from oprow.core.models import Artifact
from oprow.essence.registry import EssenceRegistry, default_essence_registry

from .profiles import HDCProfile, default_hdc_profile
from .vectors import HyperVector, MajorityBundler


@dataclass(frozen=True)
class HDCEncoding:
    """Result of HDC encoding.

    ``ped_hash`` is included for diagnostics and reproducibility.  It should not
    be sent to public resolvers in privacy-preserving modes because it can act as
    a fingerprint.  Route-token derivation uses only the hypervector locally and
    publishes opaque hashed route keys.
    """

    profile: HDCProfile
    hypervector: HyperVector
    ped_alg_id: str
    ped_hash: Hash256
    ped_length: int
    metadata: dict[str, object] = field(default_factory=dict)

    def to_canonical(self) -> dict[str, object]:
        return {
            "profile_id": self.profile.profile_id,
            "hypervector": self.hypervector,
            "ped_alg_id": self.ped_alg_id,
            "ped_hash": self.ped_hash,
            "ped_length": self.ped_length,
            "metadata": self.metadata,
        }


@runtime_checkable
class HDCEncoder(Protocol):
    """Protocol for all OProW HDC encoders."""

    profile: HDCProfile

    def encode_ped(self, ped: bytes, *, ped_alg_id: str | None = None) -> HDCEncoding:
        ...

    def encode_artifact(self, artifact: Artifact) -> HDCEncoding:
        ...


def _u32(n: int) -> bytes:
    if n < 0 or n >= 2**32:
        raise ValidationError("integer out of u32 range")
    return n.to_bytes(4, "big")


def _u16(n: int) -> bytes:
    if n < 0 or n >= 2**16:
        raise ValidationError("integer out of u16 range")
    return n.to_bytes(2, "big")


def quantize_byte(value: int, levels: int) -> int:
    """Map an 8-bit PED byte to a small robust value bin."""
    if not (0 <= value <= 255):
        raise ValidationError("PED byte value out of range")
    if not (2 <= levels <= 256):
        raise ValidationError("levels must be between 2 and 256")
    # ``min`` handles value=255 cleanly when levels does not divide 256.
    return min(levels - 1, (value * levels) // 256)


class SymbolicBundlingHDCEncoder:
    """Deterministic symbolic-bundling encoder for PED bytes.

    The implementation generates slot and value hypervectors on demand using the
    public profile seed.  It does not cache them yet; this keeps the code easier
    to audit.  A production implementation can cache ``slot_i`` and ``value_q``
    because they are deterministic and profile-specific.
    """

    def __init__(self, profile: HDCProfile | None = None, essence_registry: EssenceRegistry | None = None):
        self.profile = profile or default_hdc_profile()
        if self.profile.encoder_id != "symbolic-bundling-v1":
            raise UnsupportedAlgorithmError(f"unsupported HDC encoder_id for this class: {self.profile.encoder_id}")
        self.essence_registry = essence_registry or default_essence_registry()

    def _slot_hv(self, index: int) -> HyperVector:
        return HyperVector.random(
            domain="oprow-hdc-slot-hv-v1",
            parts=[self.profile.seed, self.profile.profile_id.encode("utf-8"), _u32(index)],
            dimension=self.profile.dimension,
        )

    def _value_hv(self, q: int) -> HyperVector:
        return HyperVector.random(
            domain="oprow-hdc-value-hv-v1",
            parts=[self.profile.seed, self.profile.profile_id.encode("utf-8"), _u16(q)],
            dimension=self.profile.dimension,
        )

    def encode_ped(self, ped: bytes, *, ped_alg_id: str | None = None) -> HDCEncoding:
        if not ped:
            raise ValidationError("cannot HDC-encode an empty PED")
        ped_alg = ped_alg_id or self.profile.ped_profile_id
        bundler = MajorityBundler(self.profile.dimension)
        levels = self.profile.value_quantization_levels
        for i, raw in enumerate(ped):
            q = quantize_byte(raw, levels)
            # Binding position and value makes the representation order-aware:
            # a dark block at position 5 is not the same as a dark block at
            # position 900.  XOR is binary HDC binding.
            symbol = self._slot_hv(i).xor(self._value_hv(q))
            bundler.add(symbol)
        hv = bundler.result()
        ped_hash = Hash256(hash_framed("oprow-hdc-ped-diagnostic-hash-v1", ped_alg.encode("utf-8"), ped))
        return HDCEncoding(
            profile=self.profile,
            hypervector=hv,
            ped_alg_id=ped_alg,
            ped_hash=ped_hash,
            ped_length=len(ped),
            metadata={"encoder": self.profile.encoder_id, "bundled_symbols": bundler.items, "value_levels": levels},
        )

    def encode_artifact(self, artifact: Artifact) -> HDCEncoding:
        """Compute the profile's PED for ``artifact`` and encode it.

        This method intentionally keeps the raw PED local.  The returned
        ``HDCEncoding`` is still sensitive and should be treated as verifier-side
        state, not as something to put on-chain or send to a public resolver.
        """
        essence = self.essence_registry.compute(artifact, self.profile.ped_profile_id)
        return self.encode_ped(essence.ped, ped_alg_id=essence.alg_id)


class RandomProjectionHDCEncoder:
    """Small experimental random-projection encoder.

    This class is included for research comparison.  It computes a deterministic
    signed random projection without materializing a full dense matrix: each
    hypervector coordinate gets a public pseudo-random +/-1 vector over PED byte
    positions and thresholds the dot product.

    It is much slower than it should be and is not the default.  Its purpose is
    to give benchmark authors a second encoder family without adding a heavy ML
    dependency in Step 8.
    """

    def __init__(self, profile: HDCProfile | None = None, essence_registry: EssenceRegistry | None = None):
        profile = profile or default_hdc_profile()
        object.__setattr__(self, "profile", profile)
        self.essence_registry = essence_registry or default_essence_registry()

    def encode_ped(self, ped: bytes, *, ped_alg_id: str | None = None) -> HDCEncoding:
        if not ped:
            raise ValidationError("cannot HDC-encode an empty PED")
        x = np.frombuffer(bytes(ped), dtype=np.uint8).astype(np.int16) - 128
        bits = np.zeros(self.profile.dimension, dtype=np.bool_)
        for j in range(self.profile.dimension):
            signs_hv = HyperVector.random(
                domain="oprow-hdc-rp-coordinate-v1",
                parts=[self.profile.seed, self.profile.profile_id.encode("utf-8"), _u32(j)],
                dimension=len(ped),
            )
            signs = np.where(signs_hv.to_bool_array(), -1, 1).astype(np.int16)
            bits[j] = int(np.dot(x, signs)) < 0
        hv = HyperVector.from_bool_array(bits)
        ped_alg = ped_alg_id or self.profile.ped_profile_id
        ped_hash = Hash256(hash_framed("oprow-hdc-ped-diagnostic-hash-v1", ped_alg.encode("utf-8"), ped))
        return HDCEncoding(self.profile, hv, ped_alg, ped_hash, len(ped), {"encoder": "random-projection-v1"})

    def encode_artifact(self, artifact: Artifact) -> HDCEncoding:
        essence = self.essence_registry.compute(artifact, self.profile.ped_profile_id)
        return self.encode_ped(essence.ped, ped_alg_id=essence.alg_id)
