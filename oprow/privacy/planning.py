"""Client-side query planning for SHORT64-HV privacy profiles.

The planner consumes the full short ID and the media-derived HDC hypervector
locally, then produces only opaque route-key queries.  The raw PED, raw
hypervector, and exact short ID are not serialized in the public query shape.

This is not a cryptographic privacy layer.  P1 broadens buckets to reduce exact
fingerprinting; P2 adds cover traffic.  Both are operational mitigations.  The
final OProW trust decision remains independent of HDC routing.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Iterable, Protocol

from oprow.core.hashes import hash_framed
from oprow.core.identifiers import Hash256, NamespaceId, ShortId
from oprow.hdc.profiles import DEFAULT_HDC_EPOCH, HDCProfile
from oprow.hdc.routing import HDCRouter, RoutePrecision, RouteToken
from oprow.hdc.vectors import HyperVector

from .profiles import Short64HVPrivacyPolicy, Short64HVPrivacyProfile, default_short64_hv_privacy_policy


class RouteQueryKind(Enum):
    REAL = "real"
    COVER = "cover"


def precision_to_diagnostics(precision: RoutePrecision) -> dict[str, object]:
    return {
        "short_prefix_bits": precision.short_prefix_bits,
        "hv_band_bits": precision.hv_band_bits,
        "band_ids": list(precision.band_ids or []),
    }


@dataclass(frozen=True)
class BucketEstimate:
    """Planner estimate for a candidate route precision."""

    precision: RoutePrecision
    token_count: int
    estimated_candidates: int | None = None
    token_candidate_counts: tuple[int | None, ...] = field(default_factory=tuple)
    source: str = "unknown"

    def to_diagnostics(self) -> dict[str, object]:
        return {
            "precision": precision_to_diagnostics(self.precision),
            "token_count": self.token_count,
            "estimated_candidates": self.estimated_candidates,
            "token_candidate_counts": list(self.token_candidate_counts),
            "source": self.source,
        }


@dataclass(frozen=True)
class PlannedRouteQuery:
    """One real or cover route-token query.

    ``kind`` is an internal label; normal public resolver requests omit it so the
    resolver cannot trivially separate real and cover queries.
    """

    token: RouteToken
    kind: RouteQueryKind = RouteQueryKind.REAL
    label: str | None = None

    def public_query(self, *, include_private_labels: bool = False) -> dict[str, object]:
        data: dict[str, object] = {
            "route_key": self.token.route_key.to_hex(),
            "profile_id": self.token.profile_id,
            "epoch_id": self.token.epoch_id,
            "band_id": self.token.band_id,
            "precision": precision_to_diagnostics(self.token.precision),
        }
        if include_private_labels:
            data["kind"] = self.kind.value
            data["label"] = self.label
        return data


@dataclass(frozen=True)
class Short64HVQueryPlan:
    """Complete public/private query plan for one SHORT64-HV lookup."""

    policy: Short64HVPrivacyPolicy
    selected_precision: RoutePrecision
    real_queries: tuple[PlannedRouteQuery, ...]
    cover_queries: tuple[PlannedRouteQuery, ...] = field(default_factory=tuple)
    estimates: tuple[BucketEstimate, ...] = field(default_factory=tuple)
    selected_estimate: BucketEstimate | None = None
    warnings: tuple[str, ...] = field(default_factory=tuple)

    @property
    def all_queries(self) -> tuple[PlannedRouteQuery, ...]:
        queries = list(self.real_queries + self.cover_queries)
        seed_material = b"".join(q.token.route_key.value for q in queries)
        seed = int.from_bytes(hash_framed("oprow-step10-query-shuffle", seed_material)[:8], "big")
        rng = random.Random(seed)
        rng.shuffle(queries)
        return tuple(queries)

    @property
    def route_tokens_for_lookup(self) -> list[RouteToken]:
        return [q.token for q in self.all_queries]

    def public_queries(self, *, include_private_labels: bool = False) -> list[dict[str, object]]:
        return [q.public_query(include_private_labels=include_private_labels) for q in self.all_queries]

    def to_diagnostics(self) -> dict[str, object]:
        return {
            "policy": self.policy.to_diagnostics(),
            "selected_precision": precision_to_diagnostics(self.selected_precision),
            "real_query_count": len(self.real_queries),
            "cover_query_count": len(self.cover_queries),
            "total_query_count": len(self.all_queries),
            "selected_estimate": self.selected_estimate.to_diagnostics() if self.selected_estimate else None,
            "estimates": [e.to_diagnostics() for e in self.estimates],
            "warnings": list(self.warnings),
            "public_queries_redacted": self.public_queries(include_private_labels=False),
        }


class RouteStatsProvider(Protocol):
    def lookup_tokens(self, route_tokens: list[RouteToken], **kwargs: Any):
        ...


class CoverRouteSampler(Protocol):
    def sample_cover_tokens(self, *, count: int, profile: HDCProfile, precision: RoutePrecision, exclude_route_keys: set[Hash256]) -> list[RouteToken]:
        ...


class NullCoverRouteSampler:
    def sample_cover_tokens(self, *, count: int, profile: HDCProfile, precision: RoutePrecision, exclude_route_keys: set[Hash256]) -> list[RouteToken]:
        return []


class StaticCoverRouteSampler:
    """Cover sampler backed by a public list of route keys.

    In production this list might come from popular public buckets, signed index
    statistics, or a relay service.  The sampler stores only opaque route-key
    hashes and never stores raw media descriptors.
    """

    def __init__(self, route_keys: Iterable[Hash256], *, seed: bytes = b"OProW-step10-static-cover"):
        self.route_keys = sorted(set(route_keys), key=lambda k: k.value)
        self.seed = bytes(seed)

    @classmethod
    def from_index(cls, index: Any, *, seed: bytes = b"OProW-step10-static-cover") -> "StaticCoverRouteSampler":
        if hasattr(index, "public_route_keys"):
            keys = index.public_route_keys()
        elif hasattr(index, "route_keys"):
            keys = index.route_keys()
        elif hasattr(index, "_by_route_key"):
            keys = list(index._by_route_key.keys())  # type: ignore[attr-defined]
        else:
            keys = []
        return cls(keys, seed=seed)

    def sample_cover_tokens(self, *, count: int, profile: HDCProfile, precision: RoutePrecision, exclude_route_keys: set[Hash256]) -> list[RouteToken]:
        available = [key for key in self.route_keys if key not in exclude_route_keys]
        if count <= 0 or not available:
            return []
        seed_material = self.seed + b"".join(k.value for k in sorted(exclude_route_keys, key=lambda k: k.value))
        seed = int.from_bytes(hash_framed("oprow-step10-cover-sampler", seed_material)[:8], "big")
        rng = random.Random(seed)
        rng.shuffle(available)
        return [
            RouteToken(
                route_key=key,
                profile_id=profile.profile_id,
                epoch_id="cover",
                band_id=-1,
                precision=precision,
                metadata={"cover": True, "source": "static-public-route-key-list"},
            )
            for key in available[:count]
        ]


class Short64HVPrivacyPlanner:
    """Build P0/P1/P2 route query plans.

    The planner can use local in-memory index statistics in this reference SDK.
    A deployed client should preferably use public signed aggregate statistics or
    locally cached shards so planning itself does not become an online probe.
    """

    def __init__(self, *, stats_provider: RouteStatsProvider | Any | None = None, cover_sampler: CoverRouteSampler | None = None):
        self.stats_provider = stats_provider
        self.cover_sampler = cover_sampler or NullCoverRouteSampler()

    def plan(
        self,
        *,
        short_id: ShortId,
        hv: HyperVector,
        profile: HDCProfile,
        router: HDCRouter | None = None,
        namespace_id: NamespaceId | None = None,
        epoch_id: str = DEFAULT_HDC_EPOCH,
        policy: Short64HVPrivacyPolicy | None = None,
        fallback_precision: RoutePrecision | None = None,
    ) -> Short64HVQueryPlan:
        policy = policy or default_short64_hv_privacy_policy()
        router = router or HDCRouter(profile)
        precisions = policy.effective_precisions(profile)
        if policy.profile == Short64HVPrivacyProfile.P0_PUBLIC_FAST and fallback_precision is not None:
            precisions = (fallback_precision.normalized(profile),)

        candidates: list[tuple[RoutePrecision, list[RouteToken], BucketEstimate]] = []
        estimates: list[BucketEstimate] = []
        for precision in precisions:
            tokens = list(router.derive_route_tokens(short_id=short_id, hv=hv, namespace_id=namespace_id, epoch_id=epoch_id, precision=precision))
            estimate = self.estimate_tokens(tokens, precision=precision)
            candidates.append((precision, tokens, estimate))
            estimates.append(estimate)

        selected_precision, selected_tokens, selected_estimate = self._select(policy, candidates)
        warnings = list(self._warnings(policy, selected_estimate))
        real_queries = tuple(PlannedRouteQuery(t, RouteQueryKind.REAL, f"real-{i}") for i, t in enumerate(selected_tokens))

        cover_queries: tuple[PlannedRouteQuery, ...] = ()
        if policy.profile == Short64HVPrivacyProfile.P2_RELAY_COVER and policy.cover_query_count:
            covers = self.cover_sampler.sample_cover_tokens(
                count=policy.cover_query_count,
                profile=profile,
                precision=selected_precision,
                exclude_route_keys={q.token.route_key for q in real_queries},
            )
            if len(covers) < policy.cover_query_count:
                warnings.append(f"requested {policy.cover_query_count} cover queries but sampler returned {len(covers)}")
            cover_queries = tuple(PlannedRouteQuery(t, RouteQueryKind.COVER, f"cover-{i}") for i, t in enumerate(covers))

        return Short64HVQueryPlan(
            policy=policy,
            selected_precision=selected_precision,
            real_queries=real_queries,
            cover_queries=cover_queries,
            estimates=tuple(estimates),
            selected_estimate=selected_estimate,
            warnings=tuple(warnings),
        )

    def estimate_tokens(self, tokens: list[RouteToken], *, precision: RoutePrecision) -> BucketEstimate:
        if self.stats_provider is None:
            return BucketEstimate(precision=precision, token_count=len(tokens), estimated_candidates=None, token_candidate_counts=tuple(None for _ in tokens))
        if hasattr(self.stats_provider, "estimate_route_tokens"):
            try:
                est = self.stats_provider.estimate_route_tokens(tokens)  # type: ignore[attr-defined]
                if isinstance(est, BucketEstimate):
                    return est
            except Exception:
                pass
        if hasattr(self.stats_provider, "lookup_tokens"):
            try:
                result = self.stats_provider.lookup_tokens(tokens, short_id=None, namespace_id=None, min_token_matches=1, max_results=None)
                n = result.total_available if getattr(result, "total_available", None) is not None else len(result.references)
                return BucketEstimate(precision=precision, token_count=len(tokens), estimated_candidates=int(n), source="local_index_lookup_tokens")
            except Exception:
                pass
        return BucketEstimate(precision=precision, token_count=len(tokens), estimated_candidates=None, token_candidate_counts=tuple(None for _ in tokens))

    @staticmethod
    def _select(policy: Short64HVPrivacyPolicy, choices: list[tuple[RoutePrecision, list[RouteToken], BucketEstimate]]) -> tuple[RoutePrecision, list[RouteToken], BucketEstimate]:
        if policy.profile == Short64HVPrivacyProfile.P0_PUBLIC_FAST:
            return choices[0]
        for choice in choices:
            n = choice[2].estimated_candidates
            if n is not None and policy.min_anonymity_set <= n <= policy.max_candidate_bucket:
                return choice
        known = [c for c in choices if c[2].estimated_candidates is not None]
        if known:
            below = [c for c in known if int(c[2].estimated_candidates or 0) < policy.min_anonymity_set]
            if below:
                return max(below, key=lambda c: int(c[2].estimated_candidates or 0))
            return min(known, key=lambda c: int(c[2].estimated_candidates or 10**18))
        return choices[0]

    @staticmethod
    def _warnings(policy: Short64HVPrivacyPolicy, estimate: BucketEstimate) -> tuple[str, ...]:
        if estimate.estimated_candidates is None:
            return ("no bucket-size statistics available; anonymity set is unknown",)
        warnings: list[str] = []
        if estimate.estimated_candidates < policy.min_anonymity_set:
            warnings.append(f"selected bucket estimate {estimate.estimated_candidates} is below requested anonymity set {policy.min_anonymity_set}")
        if estimate.estimated_candidates > policy.max_candidate_bucket:
            warnings.append(f"selected bucket estimate {estimate.estimated_candidates} exceeds max candidate bucket {policy.max_candidate_bucket}")
        return tuple(warnings)
