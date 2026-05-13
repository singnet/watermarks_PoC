"""Minimal local trust evaluator for OProW Step 5.

The OProW protocol proves statements about bytes, keys, and signed claims.  It
does not impose one global trust store.  A verifier must decide locally which
keys and roles matter.  This file implements a deliberately simple policy:

* a signature must be cryptographically valid;
* its role string must be in ``TrustPolicyStub.accepted_roles``;
* its key ID must be in ``TrustPolicyStub.trusted_key_ids``.

If no key is trusted, a valid manifest becomes ``SIGNED_BUT_UNTRUSTED`` rather
than ``VERIFIED``.  Later steps can replace this class with a richer engine that
consults trust bundles, key-transparency logs, revocation state, C2PA evidence,
or ASI:chain anchor receipts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from oprow.core.models import SignedManifest
from oprow.core.policy import TrustPolicyStub
from oprow.manifest.signatures import SignatureCheck
from oprow.manifest.verification import ManifestSignatureReport

from .result import TrustDecision


@dataclass(frozen=True)
class SimpleTrustEvaluator:
    """Evaluate valid signatures against a small local key/role policy."""

    policy: TrustPolicyStub = field(default_factory=TrustPolicyStub)

    def _role_accepted(self, check: SignatureCheck) -> bool:
        return check.role in {str(role) for role in self.policy.accepted_roles}

    def _kid_accepted(self, check: SignatureCheck) -> bool:
        trusted = {str(kid) for kid in self.policy.trusted_key_ids}
        # ``*`` is a testing/demo convenience.  Production deployments should
        # use explicit keys or trust bundles.
        return "*" in trusted or str(check.kid) in trusted

    def evaluate(self, manifest: SignedManifest, signature_report: ManifestSignatureReport) -> TrustDecision:
        valid = signature_report.valid_checks
        if not valid:
            return TrustDecision(accepted=False, reason="no_valid_signatures")

        trusted_checks = [c for c in valid if self._role_accepted(c) and self._kid_accepted(c)]
        trusted_records = [c.record for c in trusted_checks]
        untrusted_records = [c.record for c in valid if c not in trusted_checks]

        if trusted_records:
            reason = "accepted_by_local_key_policy"
            if "*" in {str(kid) for kid in self.policy.trusted_key_ids}:
                reason = "accepted_by_wildcard_policy_for_testing"
            return TrustDecision(
                accepted=True,
                trusted_signatures=trusted_records,
                untrusted_valid_signatures=untrusted_records,
                accepted_claims=list(manifest.core.claims),
                reason=reason,
                evidence={
                    "trusted_key_ids": sorted(str(kid) for kid in self.policy.trusted_key_ids),
                    "accepted_roles": sorted(str(role) for role in self.policy.accepted_roles),
                },
            )

        reasons: list[str] = []
        if not self.policy.trusted_key_ids:
            reasons.append("no_trusted_key_ids_configured")
        if any(not self._role_accepted(c) for c in valid):
            reasons.append("role_not_accepted")
        if any(not self._kid_accepted(c) for c in valid):
            reasons.append("kid_not_trusted")
        return TrustDecision(
            accepted=False,
            trusted_signatures=[],
            untrusted_valid_signatures=[c.record for c in valid],
            accepted_claims=[],
            reason=";".join(reasons) or "no_valid_signature_met_policy",
            evidence={
                "trusted_key_ids": sorted(str(kid) for kid in self.policy.trusted_key_ids),
                "accepted_roles": sorted(str(role) for role in self.policy.accepted_roles),
            },
        )


def trust_any_valid_signature_policy(accepted_roles: Iterable[str] | None = None) -> TrustPolicyStub:
    """Testing/demo policy that trusts any valid signature for accepted roles."""
    return TrustPolicyStub(
        trusted_key_ids={"*"},
        accepted_roles=set(accepted_roles or {"creator", "device", "tool", "notary"}),
    )
