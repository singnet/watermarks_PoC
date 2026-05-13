"""OProW Step 2: manifest signature creation and low-level verification.

The OProW manifest architecture avoids the self-reference bug in which a
manifest key is computed and then inserted into the same bytes being hashed.
Step 1 defined the object layering:

    ManifestCore        -- semantic claims and artifact binding; signed object
    SignedManifest      -- ManifestCore plus signatures; addressed object
    ManifestEnvelope    -- transport/evidence wrapper; not addressed

This file implements the cryptographic signing rule for ``ManifestCore``.

A subtle but important design point is that a signature should not merely cover
``core.canonical_bytes()``.  The signature record contains fields such as
``kid``, ``alg``, ``role``, and ``signed_at``.  If those fields were not covered,
an attacker could copy a valid signature record and change the informational
role from ``tool`` to ``notary``.  Trust policy should never rely solely on that
role field, but the reference implementation nevertheless binds these fields in
a protected header, similar in spirit to a JOSE/COSE protected header.

The bytes signed by Step 2 are:

    frame("oprow-signature-preimage-v1",
          canonical_cbor(SignatureProtectedHeader),
          canonical_cbor(ManifestCore))

The manifest locator is derived later from canonical ``SignedManifest`` bytes.
Blockchain receipts, C2PA evidence, resolver proofs, and ASI:chain anchors stay
outside that addressed object in ``ManifestEnvelope``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from oprow.core.canonical import canonical_cbor_dumps
from oprow.core.enums import HashAlgorithm, SignatureRole
from oprow.core.errors import UnsupportedAlgorithmError, ValidationError
from oprow.core.hashes import frame_parts
from oprow.core.identifiers import KeyId
from oprow.core.models import ManifestCore, SignatureRecord, SignedManifest
from .keys import PrivateKeyRecord, PublicKeyRecord, SignatureAlgorithm, normalize_alg


SIGNATURE_PROFILE = "oprow-signature-v1"
SIGNATURE_PREIMAGE_DOMAIN = "oprow-signature-preimage-v1"


def _normalize_role(role: str | SignatureRole) -> str:
    return role.value if isinstance(role, SignatureRole) else str(role)


def _normalize_signed_at(signed_at: datetime | None) -> datetime | None:
    """Require signed_at to be timezone-aware if supplied."""
    if signed_at is None:
        return None
    if signed_at.tzinfo is None or signed_at.utcoffset() is None:
        raise ValidationError("signed_at must be timezone-aware")
    return signed_at.astimezone(timezone.utc)


@dataclass(frozen=True)
class SignatureProtectedHeader:
    """Fields that are cryptographically bound to a signature.

    The corresponding ``SignatureRecord`` fields are still stored top-level so a
    resolver/verifier can inspect them without parsing a nested header.  The
    verifier reconstructs this protected header from the record and verifies the
    signature against it.  If an attacker mutates the top-level ``kid``, ``alg``,
    ``role``, or ``signed_at``, the reconstructed header changes and the
    signature fails.
    """
    kid: KeyId
    alg: str
    role: str
    signed_at: datetime | None = None
    profile: str = SIGNATURE_PROFILE
    hash_alg: str = HashAlgorithm.SHA256.value

    def __post_init__(self) -> None:
        object.__setattr__(self, "alg", normalize_alg(self.alg))
        object.__setattr__(self, "role", str(self.role))
        object.__setattr__(self, "signed_at", _normalize_signed_at(self.signed_at))

    def to_canonical(self) -> dict[str, object]:
        out: dict[str, object] = {
            "profile": self.profile,
            "kid": self.kid,
            "alg": self.alg,
            "role": self.role,
            "hash_alg": self.hash_alg,
        }
        if self.signed_at is not None:
            out["signed_at"] = self.signed_at
        return out

    @classmethod
    def from_signature_record(cls, record: SignatureRecord) -> "SignatureProtectedHeader":
        return cls(kid=record.kid, alg=record.alg, role=_normalize_role(record.role), signed_at=record.signed_at)


def signature_preimage(core: ManifestCore, protected: SignatureProtectedHeader) -> bytes:
    """Return the exact byte string signed by every Step 2 algorithm.

    We use length-framed domain separation rather than raw concatenation.  This
    prevents ambiguity between fields and makes the signature context explicit.
    The preimage includes canonical ManifestCore bytes, not SignedManifest bytes,
    so additional signatures can be added without invalidating earlier ones.
    """
    return frame_parts(SIGNATURE_PREIMAGE_DOMAIN, [canonical_cbor_dumps(protected), core.canonical_bytes()])


@dataclass(frozen=True)
class OProWSigner:
    """Reference signer backed by a local ``PrivateKeyRecord``.

    This class embodies the Step 2 signing algorithm but does not know about
    storage, watermarks, C2PA, ASI:chain, or trust bundles.  A production KMS/HSM
    signer can implement the same ``sign_core`` method while keeping private
    material outside Python memory.
    """
    private_key: PrivateKeyRecord
    role: str | SignatureRole
    default_metadata: dict[str, object] = field(default_factory=dict)

    @property
    def kid(self) -> KeyId:
        return self.private_key.kid

    @property
    def alg(self) -> str:
        return self.private_key.alg

    def sign_core(self, core: ManifestCore, *, signed_at: datetime | None = None) -> SignatureRecord:
        """Sign a ManifestCore and return a protected SignatureRecord."""
        role_s = _normalize_role(self.role)
        signed_at = _normalize_signed_at(signed_at)
        protected = SignatureProtectedHeader(kid=self.kid, alg=self.alg, role=role_s, signed_at=signed_at)
        message = signature_preimage(core, protected)
        private = self.private_key.load_private_key()

        if self.alg == SignatureAlgorithm.ED25519.value:
            if not isinstance(private, ed25519.Ed25519PrivateKey):
                raise UnsupportedAlgorithmError("private key is not Ed25519")
            sig = private.sign(message)
        elif self.alg == SignatureAlgorithm.ES256.value:
            sig = private.sign(message, ec.ECDSA(crypto_hashes.SHA256()))
        else:
            raise UnsupportedAlgorithmError(f"unsupported signing algorithm: {self.alg}")

        metadata = dict(self.default_metadata)
        metadata.setdefault("signature_profile", SIGNATURE_PROFILE)
        metadata.setdefault("protected_header_rule", "reconstruct-from-record-fields")
        return SignatureRecord(
            kid=self.kid,
            alg=self.alg,
            signature=sig,
            role=role_s,
            signed_at=signed_at,
            metadata=metadata,
        )


@dataclass(frozen=True)
class SignatureCheck:
    """Result of checking one signature record."""
    record: SignatureRecord
    valid: bool
    reason: str
    public_key: PublicKeyRecord | None = None

    @property
    def kid(self) -> KeyId:
        return self.record.kid

    @property
    def role(self) -> str:
        return _normalize_role(self.record.role)


def verify_signature_record(core: ManifestCore, record: SignatureRecord, public_key: PublicKeyRecord | None) -> SignatureCheck:
    """Verify one SignatureRecord against ManifestCore and a public key.

    Algorithm:
      1. Require a public key for record.kid.
      2. Require record.alg to equal the public key algorithm.
      3. Reconstruct the protected header from record fields.
      4. Verify the signature over the Step 2 preimage.

    HDC route scores, watermark confidence, resolver trust, and ASI:chain
    receipts play no role here.  This is pure signature verification.
    """
    if public_key is None:
        return SignatureCheck(record=record, valid=False, reason="missing_public_key")

    record_alg = normalize_alg(record.alg)
    if record_alg != public_key.alg:
        return SignatureCheck(record=record, valid=False, public_key=public_key, reason="algorithm_mismatch")

    try:
        protected = SignatureProtectedHeader.from_signature_record(record)
        message = signature_preimage(core, protected)
        pk = public_key.load_public_key()

        if record_alg == SignatureAlgorithm.ED25519.value:
            if not isinstance(pk, ed25519.Ed25519PublicKey):
                return SignatureCheck(record=record, valid=False, public_key=public_key, reason="wrong_public_key_type")
            pk.verify(record.signature, message)
        elif record_alg == SignatureAlgorithm.ES256.value:
            pk.verify(record.signature, message, ec.ECDSA(crypto_hashes.SHA256()))
        else:
            return SignatureCheck(record=record, valid=False, public_key=public_key, reason="unsupported_algorithm")
    except InvalidSignature:
        return SignatureCheck(record=record, valid=False, public_key=public_key, reason="invalid_signature")
    except Exception as exc:
        return SignatureCheck(record=record, valid=False, public_key=public_key, reason=f"verification_error:{exc.__class__.__name__}")

    return SignatureCheck(record=record, valid=True, public_key=public_key, reason="valid")


def signature_sort_key(record: SignatureRecord) -> bytes:
    """Canonical sort key for signature arrays.

    The manifest locator is derived from canonical SignedManifest bytes.  If two
    implementations produce the same set of signatures in different list orders,
    they would otherwise derive different locators.  Sorting by each record's
    canonical bytes makes multi-signer manifests deterministic.
    """
    return canonical_cbor_dumps(record)


def sort_signature_records(records: Iterable[SignatureRecord]) -> list[SignatureRecord]:
    return sorted(list(records), key=signature_sort_key)


def create_signed_manifest(core: ManifestCore, signers: Iterable[OProWSigner], *, signed_at: datetime | None = None) -> SignedManifest:
    """Create a SignedManifest from a ManifestCore and one or more signers."""
    signatures = [signer.sign_core(core, signed_at=signed_at) for signer in signers]
    if not signatures:
        raise ValidationError("at least one signer is required")
    return SignedManifest(core=core, signatures=sort_signature_records(signatures))


def add_signature(manifest: SignedManifest, signer: OProWSigner, *, signed_at: datetime | None = None) -> SignedManifest:
    """Return a new SignedManifest with one additional signature.

    Adding a signature intentionally changes SignedManifest bytes and therefore
    changes its manifest locator.  Signature gathering should therefore usually
    happen before watermark embedding and publication.
    """
    new_sig = signer.sign_core(manifest.core, signed_at=signed_at)
    return SignedManifest(core=manifest.core, signatures=sort_signature_records([*manifest.signatures, new_sig]))
