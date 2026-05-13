"""Privacy-aware authenticated SHORT64-HV resolver (Step 10).

The base ``AuthenticatedShort64HVRouteResolver`` now has optional privacy-policy
fields.  This wrapper simply selects the safer P1_K_ANON_BUCKET default so
callers can opt into Step 10 behavior by class name.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from oprow.privacy import Short64HVPrivacyPolicy, k_anonymous_bucket_policy

from .authenticated_short64_hv import AuthenticatedShort64HVRouteResolver


@dataclass
class PrivacyPreservingAuthenticatedShort64HVResolver(AuthenticatedShort64HVRouteResolver):
    """Authenticated SHORT64-HV resolver with P1 privacy by default."""

    privacy_policy: Short64HVPrivacyPolicy | None = field(default_factory=k_anonymous_bucket_policy)
    name: str = "privacy_preserving_authenticated_short64_hv_route"


PrivacyAwareAuthenticatedShort64HVRouteResolver = PrivacyPreservingAuthenticatedShort64HVResolver
