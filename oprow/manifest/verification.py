"""OProW Step 2: manifest-level signature verification reports.

This module turns a ``SignedManifest`` into a structured report.  It does not
perform complete provenance verification.  In the full OProW workflow, signature
checks are only one stage:

1. Extract watermark pointer.
2. Resolve candidate manifests.
3. Check FULL160/SHORT64 locator self-consistency.
4. Verify signatures.          <-- this module
5. Compute and compare essence hash.
6. Apply trust policy, trust bundles, transparency logs, ASI:chain receipts.
7. Render an appropriate UX status.

A valid signature proves that a key signed a specific ManifestCore and protected
signature header.  It does not prove the key is trusted, the key was not revoked,
the media matches the essence hash, or the resolver protected user privacy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from oprow.core.enums import PointerMode
from oprow.core.errors import ValidationError
from oprow.core.identifiers import KeyId
from oprow.core.models import ManifestLocator, SignatureRecord, SignedManifest
from .keys import KeyResolver, PublicKeyRecord
from .signatures import SignatureCheck, verify_signature_record


@dataclass(frozen=True)
class ManifestSignatureReport:
    """Summary of signature verification for a SignedManifest."""
    checks: list[SignatureCheck] = field(default_factory=list)

    @property
    def valid_checks(self) -> list[SignatureCheck]:
        return [c for c in self.checks if c.valid]

    @property
    def invalid_checks(self) -> list[SignatureCheck]:
        return [c for c in self.checks if not c.valid]

    @property
    def has_valid_signature(self) -> bool:
        return any(c.valid for c in self.checks)

    @property
    def valid_records(self) -> list[SignatureRecord]:
        return [c.record for c in self.valid_checks]

    @property
    def valid_kids(self) -> set[KeyId]:
        return {c.kid for c in self.valid_checks}

    def valid_for_role(self, role: str) -> list[SignatureCheck]:
        """Return valid checks whose record role string equals ``role``.

        This is only a convenience filter.  A future trust-policy engine must
        still check that the key is authorized for that role by a trust bundle,
        device attestation, DID document, certificate chain, or transparency log.
        """
        return [c for c in self.valid_checks if c.role == role]

    def require_any_valid(self) -> None:
        if not self.has_valid_signature:
            reasons = ", ".join(c.reason for c in self.checks) or "no signatures"
            raise ValidationError(f"SignedManifest has no valid signatures: {reasons}")


def _resolve_public_key(resolver: KeyResolver, kid: KeyId) -> PublicKeyRecord | None:
    return resolver.resolve_public_key(kid)


def verify_manifest_signatures(manifest: SignedManifest, resolver: KeyResolver) -> ManifestSignatureReport:
    """Verify all signatures on a SignedManifest.

    We verify every signature, even after finding a valid one.  Later policy may
    require combinations such as creator+notary or classical+post-quantum.  Full
    diagnostics also help debug key-rotation and resolver problems.
    """
    checks: list[SignatureCheck] = []
    for record in manifest.signatures:
        public_key = _resolve_public_key(resolver, record.kid)
        checks.append(verify_signature_record(manifest.core, record, public_key))
    return ManifestSignatureReport(checks=checks)


def verify_locator_self_consistency(manifest: SignedManifest, locator: ManifestLocator) -> bool:
    """Check that a SignedManifest matches a recovered locator.

    The full resolver layer will own this in Step 4.  The core rule is that
    FULL160 and hash-truncated SHORT64 locators derive from ``SignedManifest``
    bytes, not from ``ManifestCore`` and not from ``ManifestEnvelope``.
    """
    if locator.mode in (PointerMode.FULL160, PointerMode.FULL160_RATELESS):
        return locator.value == manifest.manifest_key()
    if locator.mode in (PointerMode.SHORT64, PointerMode.SHORT64_HV):
        if locator.derivation_profile != "hash_truncated":
            return False
        return locator.value == manifest.short_id_hash_truncated()
    return False


def require_locator_self_consistency(manifest: SignedManifest, locator: ManifestLocator) -> None:
    if not verify_locator_self_consistency(manifest, locator):
        raise ValidationError("manifest does not match locator")


def valid_signature_records_for_roles(report: ManifestSignatureReport, roles: Iterable[str]) -> list[SignatureRecord]:
    """Convenience helper for examples and early policy experiments."""
    role_set = {str(r) for r in roles}
    return [c.record for c in report.valid_checks if c.role in role_set]
