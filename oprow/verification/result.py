"""Rich verification result types for OProW Step 5.

OProW verification is deliberately not a Boolean.  A media artifact can have no
watermark, have a pointer but no available manifest, have a manifest whose
locator does not match, have valid signatures from unknown keys, have matching
signatures but a mismatched essence hash, or have multiple valid candidate
manifests that must be treated as ambiguous.  The classes in this file encode
that layered state explicitly.

Theory encoded here:

* Watermarks and resolvers are discovery mechanisms.
* Signatures prove that a key signed a specific ManifestCore.
* Essence hashes bind the received artifact to the signed content commitment.
* Trust policy is local; a valid signature is not automatically trusted.

These result objects are intentionally verbose enough for a UI, CLI, or future
coding agent to explain exactly which layer failed.  Later steps can add HDC
route diagnostics, authenticated-map proofs, C2PA evidence, and ASI:chain
receipts without changing the basic model.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from oprow.core.identifiers import Hash256, KeyId
from oprow.core.models import Claim, ManifestEnvelope, SignatureRecord, SignedManifest
from oprow.manifest.verification import ManifestSignatureReport
from oprow.resolution.base import ResolutionResult


class VerificationStatus(str, Enum):
    """Stable public status values returned by the verifier."""

    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    SIGNED_BUT_UNTRUSTED = "signed_but_untrusted"

    NO_WATERMARK = "no_watermark"
    MANIFEST_NOT_FOUND = "manifest_not_found"
    RESOLUTION_ERROR = "resolution_error"
    RESOLUTION_CANDIDATE_FLOOD = "resolution_candidate_flood"
    INDEX_PROOF_FAILED = "index_proof_failed"

    MANIFEST_KEY_MISMATCH = "manifest_key_mismatch"
    MANIFEST_SHORT_ID_MISMATCH = "manifest_short_id_mismatch"
    UNSUPPORTED_POINTER_MODE = "unsupported_pointer_mode"

    NO_VALID_SIGNATURES = "no_valid_signatures"
    SIGNATURE_POLICY_FAILED = "signature_policy_failed"

    UNSUPPORTED_ESSENCE_PROFILE = "unsupported_essence_profile"
    ESSENCE_COMPUTATION_FAILED = "essence_computation_failed"
    CONTENT_MISMATCH = "content_mismatch"

    AMBIGUOUS_MULTIPLE_VALID = "ambiguous_multiple_valid"
    CONFLICTING_PROVENANCE = "conflicting_provenance"
    NO_VALID_CANDIDATE = "no_valid_candidate"


@dataclass(frozen=True)
class EssenceCheck:
    """Comparison of signed essence commitment against recomputed artifact PED."""

    alg_id: str
    expected_hash: Hash256
    computed_hash: Hash256 | None
    matched: bool
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TrustDecision:
    """Local interpretation of valid signatures under a verifier policy.

    This is intentionally small in Step 5.  A later trust engine can populate
    ``evidence`` with trust-bundle, transparency-log, revocation, C2PA, or
    ASI:chain evidence while preserving this shape.
    """

    accepted: bool
    trusted_signatures: list[SignatureRecord] = field(default_factory=list)
    untrusted_valid_signatures: list[SignatureRecord] = field(default_factory=list)
    accepted_claims: list[Claim] = field(default_factory=list)
    reason: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)

    @property
    def trusted_kids(self) -> set[KeyId]:
        return {record.kid for record in self.trusted_signatures}


@dataclass(frozen=True)
class CandidateVerification:
    """Verification report for one resolved candidate manifest.

    SHORT64 and future SHORT64-HV modes may return many candidates.  Every
    candidate is checked independently.  Candidate ambiguity or flooding must
    produce an explicit failure/ambiguous status, never a false "verified".
    """

    envelope: ManifestEnvelope
    source: str
    status: VerificationStatus
    locator_ok: bool
    signature_report: ManifestSignatureReport | None = None
    essence_check: EssenceCheck | None = None
    trust_decision: TrustDecision | None = None
    warnings: list[str] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)

    @property
    def manifest(self) -> SignedManifest:
        return self.envelope.manifest

    @property
    def cryptographically_valid(self) -> bool:
        """True when locator, signatures, and essence matching all passed."""
        return (
            self.locator_ok
            and self.signature_report is not None
            and self.signature_report.has_valid_signature
            and self.essence_check is not None
            and self.essence_check.matched
        )

    @property
    def trusted_valid(self) -> bool:
        return self.cryptographically_valid and self.trust_decision is not None and self.trust_decision.accepted


@dataclass(frozen=True)
class VerificationResult:
    """Final output of the Step 5 provenance verifier."""

    status: VerificationStatus
    verified_manifests: list[SignedManifest] = field(default_factory=list)
    trusted_claims: list[Claim] = field(default_factory=list)
    valid_signatures: list[SignatureRecord] = field(default_factory=list)
    candidate_reports: list[CandidateVerification] = field(default_factory=list)
    resolution: ResolutionResult | None = None
    warnings: list[str] = field(default_factory=list)
    diagnostics: dict[str, Any] = field(default_factory=dict)

    @property
    def verified(self) -> bool:
        return self.status == VerificationStatus.VERIFIED

    def summary(self) -> dict[str, Any]:
        """Small JSON-friendly summary for examples and CLIs."""
        return {
            "status": self.status.value,
            "verified_manifest_count": len(self.verified_manifests),
            "trusted_claim_count": len(self.trusted_claims),
            "valid_signature_count": len(self.valid_signatures),
            "candidate_count": len(self.candidate_reports),
            "warnings": list(self.warnings),
        }
