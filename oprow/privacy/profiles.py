"""Privacy profiles for SHORT64-HV resolution (OProW Step 10).

Step 8 introduced the SHORT64-HV resolution idea:

    short watermark ID + local HDC descriptor -> opaque route keys -> candidates

Step 9 made route-key lookup auditable with authenticated-map openings.  Step 10
adds query privacy.  The issue is that a precise HDC route key can behave like a
media fingerprint: a resolver seeing that key may infer which artifact, or which
visually similar artifact, a user is checking.  This file defines three practical
privacy profiles:

* P0_PUBLIC_FAST: precise, fast route-token lookup; lowest lookup privacy.
* P1_K_ANON_BUCKET: coarser route tokens chosen to target a larger anonymity set.
* P2_RELAY_COVER: P1 plus plausible cover route keys for relay/batched lookup.

These profiles do not make HDC cryptographic.  They only control candidate
retrieval.  Final provenance verification still requires locator consistency,
manifest signatures, essence matching, and trust policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Iterable

from oprow.core.errors import ValidationError
from oprow.hdc.profiles import HDCProfile
from oprow.hdc.routing import RoutePrecision


class Short64HVPrivacyProfile(Enum):
    """Named privacy profiles for SHORT64-HV lookup."""

    P0_PUBLIC_FAST = "P0_PUBLIC_FAST"
    P1_K_ANON_BUCKET = "P1_K_ANON_BUCKET"
    P2_RELAY_COVER = "P2_RELAY_COVER"


def _clamped_precision(short_prefix_bits: int, hv_band_bits: int, profile: HDCProfile) -> RoutePrecision:
    """Create a RoutePrecision that is legal for the supplied HDC profile."""
    if not 0 <= short_prefix_bits <= 64:
        raise ValidationError("short_prefix_bits must be 0..64")
    bits = max(1, min(hv_band_bits, profile.band_width()))
    return RoutePrecision(short_prefix_bits=short_prefix_bits, hv_band_bits=bits, band_ids=tuple(range(profile.num_bands)))


@dataclass(frozen=True)
class Short64HVPrivacyPolicy:
    """Concrete knobs for SHORT64-HV privacy planning.

    ``candidate_precisions`` is an ordered search ladder.  Fewer short-ID prefix
    bits and fewer HDC band bits mean broader buckets and usually more privacy,
    at the cost of more candidates.  In production, indexers should publish
    route entries for the precisions that their clients may query.

    ``min_anonymity_set`` is a target, not a guarantee.  In a small corpus there
    may simply not be enough bucket occupancy to hide among.  The planner reports
    that as a warning rather than overstating privacy.

    ``send_exact_short_id_to_resolver`` is intentionally false for these
    profiles.  The public query contains opaque route keys; exact short-ID
    filtering happens locally after candidate references are returned.
    """

    profile: Short64HVPrivacyProfile
    min_anonymity_set: int = 128
    max_candidate_bucket: int = 512
    cover_query_count: int = 0
    min_token_matches: int = 1
    response_padding: bool = True
    manifest_fetch_padding: bool = False
    send_exact_short_id_to_resolver: bool = False
    candidate_precisions: tuple[RoutePrecision, ...] = field(default_factory=tuple)
    notes: str = ""

    def __post_init__(self) -> None:
        if self.min_anonymity_set < 1:
            raise ValidationError("min_anonymity_set must be positive")
        if self.max_candidate_bucket < 1:
            raise ValidationError("max_candidate_bucket must be positive")
        if self.cover_query_count < 0:
            raise ValidationError("cover_query_count cannot be negative")
        if self.min_token_matches < 1:
            raise ValidationError("min_token_matches must be positive")
        if self.profile != Short64HVPrivacyProfile.P2_RELAY_COVER and self.cover_query_count:
            raise ValidationError("cover_query_count is only valid for P2_RELAY_COVER")

    def effective_precisions(self, hdc_profile: HDCProfile) -> tuple[RoutePrecision, ...]:
        """Return the normalized precision ladder for this policy."""
        if self.candidate_precisions:
            return unique_precisions(self.candidate_precisions, hdc_profile)
        if self.profile == Short64HVPrivacyProfile.P0_PUBLIC_FAST:
            return (_clamped_precision(64, hdc_profile.bits_per_band, hdc_profile),)
        return tuple(
            _clamped_precision(short_bits, hdc_bits, hdc_profile)
            for short_bits, hdc_bits in (
                (16, 6),
                (20, 8),
                (24, 10),
                (32, 12),
                (40, hdc_profile.bits_per_band),
            )
        )

    def to_diagnostics(self) -> dict[str, object]:
        return {
            "profile": self.profile.value,
            "min_anonymity_set": self.min_anonymity_set,
            "max_candidate_bucket": self.max_candidate_bucket,
            "cover_query_count": self.cover_query_count,
            "min_token_matches": self.min_token_matches,
            "response_padding": self.response_padding,
            "manifest_fetch_padding": self.manifest_fetch_padding,
            "send_exact_short_id_to_resolver": self.send_exact_short_id_to_resolver,
            "notes": self.notes,
        }


def public_fast_policy() -> Short64HVPrivacyPolicy:
    return Short64HVPrivacyPolicy(
        profile=Short64HVPrivacyProfile.P0_PUBLIC_FAST,
        min_anonymity_set=1,
        max_candidate_bucket=128,
        response_padding=False,
        manifest_fetch_padding=False,
        notes="Precise fast lookup; resolver may learn a near-exact artifact route.",
    )


def k_anonymous_bucket_policy(*, min_anonymity_set: int = 128, max_candidate_bucket: int = 512) -> Short64HVPrivacyPolicy:
    return Short64HVPrivacyPolicy(
        profile=Short64HVPrivacyProfile.P1_K_ANON_BUCKET,
        min_anonymity_set=min_anonymity_set,
        max_candidate_bucket=max_candidate_bucket,
        response_padding=True,
        manifest_fetch_padding=True,
        notes="Coarse route-token lookup plus local exact filtering.",
    )


def relay_cover_policy(*, min_anonymity_set: int = 128, max_candidate_bucket: int = 512, cover_query_count: int = 4) -> Short64HVPrivacyPolicy:
    return Short64HVPrivacyPolicy(
        profile=Short64HVPrivacyProfile.P2_RELAY_COVER,
        min_anonymity_set=min_anonymity_set,
        max_candidate_bucket=max_candidate_bucket,
        cover_query_count=cover_query_count,
        response_padding=True,
        manifest_fetch_padding=True,
        notes="P1 plus plausible cover route keys for relay/batched lookup.",
    )


def default_short64_hv_privacy_policy(profile: Short64HVPrivacyProfile | str | None = None) -> Short64HVPrivacyPolicy:
    """Return a default policy.  ``None`` means safer P1, not fast P0."""
    if profile is None:
        return k_anonymous_bucket_policy()
    if isinstance(profile, str):
        profile = Short64HVPrivacyProfile(profile)
    if profile == Short64HVPrivacyProfile.P0_PUBLIC_FAST:
        return public_fast_policy()
    if profile == Short64HVPrivacyProfile.P1_K_ANON_BUCKET:
        return k_anonymous_bucket_policy()
    if profile == Short64HVPrivacyProfile.P2_RELAY_COVER:
        return relay_cover_policy()
    raise ValidationError(f"unknown SHORT64-HV privacy profile: {profile!r}")


def precision_fingerprint(precision: RoutePrecision, hdc_profile: HDCProfile) -> tuple[int, int, tuple[int, ...]]:
    p = precision.normalized(hdc_profile)
    return (p.short_prefix_bits, int(p.hv_band_bits), tuple(p.band_ids or ()))


def unique_precisions(precisions: Iterable[RoutePrecision], hdc_profile: HDCProfile) -> tuple[RoutePrecision, ...]:
    """Normalize and deduplicate RoutePrecision values while preserving order."""
    seen: set[tuple[int, int, tuple[int, ...]]] = set()
    out: list[RoutePrecision] = []
    for precision in precisions:
        norm = precision.normalized(hdc_profile)
        fp = precision_fingerprint(norm, hdc_profile)
        if fp not in seen:
            seen.add(fp)
            out.append(norm)
    return tuple(out)
