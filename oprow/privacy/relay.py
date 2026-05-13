"""Relay/batch request shape for P2 cover-query lookup.

This is not a network implementation.  It records the public query batch that a
relay would carry after the client has mixed real and cover route tokens.  A real
relay should also provide origin privacy, response padding, and timing/size
normalization.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .planning import Short64HVQueryPlan


@dataclass(frozen=True)
class RelayQueryBatch:
    public_queries: list[dict[str, object]]
    response_padding: bool = True
    manifest_fetch_padding: bool = True
    metadata: dict[str, object] = field(default_factory=dict)

    @classmethod
    def from_plan(cls, plan: Short64HVQueryPlan) -> "RelayQueryBatch":
        return cls(
            public_queries=plan.public_queries(include_private_labels=False),
            response_padding=plan.policy.response_padding,
            manifest_fetch_padding=plan.policy.manifest_fetch_padding,
            metadata={
                "privacy_profile": plan.policy.profile.value,
                "query_count": len(plan.all_queries),
                "selected_precision": {
                    "short_prefix_bits": plan.selected_precision.short_prefix_bits,
                    "hv_band_bits": plan.selected_precision.hv_band_bits,
                },
            },
        )
