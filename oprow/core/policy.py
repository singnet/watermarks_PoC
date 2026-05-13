"""Lightweight policy containers for Step 1.

The full SDK will include real policy engines.  These immutable dataclasses only
record caller intent so later modules do not pass unstructured dictionaries.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .enums import HashAlgorithm, PointerMode


@dataclass(frozen=True)
class CreationPolicy:
    essence_profile: str = "PED-IMG-1"
    watermark_profile: str = "IMG-DCT-QIM-1"
    pointer_mode: PointerMode = PointerMode.FULL160
    hash_alg: HashAlgorithm = HashAlgorithm.SHA256
    c2pa_compatible: bool = True


@dataclass(frozen=True)
class ResolutionLimits:
    """Anti-flood caps for future SHORT64/SHORT64-HV resolution."""
    max_candidates: int = 512
    max_manifest_fetches: int = 64
    max_signature_checks: int = 128
    max_essence_profiles: int = 4


@dataclass(frozen=True)
class TrustPolicyStub:
    trusted_key_ids: set[str] = field(default_factory=set)
    trusted_bundle_ids: list[str] = field(default_factory=list)
    accepted_roles: set[str] = field(default_factory=lambda: {"creator", "device", "tool", "notary"})
    require_transparency: bool = False
    limits: ResolutionLimits = field(default_factory=ResolutionLimits)
