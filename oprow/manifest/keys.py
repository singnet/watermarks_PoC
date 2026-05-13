"""OProW Step 2: key records, key generation, and key resolution.

This file implements the *key side* of manifest signing and verification.  The
OProW protocol deliberately separates three concerns that are often blurred in
prototype code:

1. **Key material**: the actual Ed25519 or P-256 private/public key bytes.
2. **Key identifiers**: stable names such as DIDs, X.509 subject-key IDs, or
   raw-key hashes.  A verifier uses the identifier in a signature record to find
   the public key with which to verify the signature.
3. **Trust**: the policy question of whether a verified key is meaningful for a
   role such as creator, device, tool, or notary.  Step 2 does *not* decide
   trust.  Later steps will add trust bundles, transparency logs, revocation,
   and ASI:chain anchoring.  Step 2 only answers the cryptographic question:
   "did this public key verify this signature over this ManifestCore?"

Implementation choices:

* Ed25519 is the default reference algorithm: deterministic, compact, and easy
  to test.  Determinism matters because manifest locators are derived from
  canonical SignedManifest bytes.
* ES256 / ECDSA P-256 is included for compatibility with PKI-like ecosystems.
  ECDSA signatures are usually randomized, so repeated signing may produce
  different SignedManifest bytes and different locators.
* Reference ``kid`` values are domain-separated hashes of public key bytes.
  Production deployments may instead use DIDs, X.509 identifiers, hardware
  attestation identities, or transparency-log subjects.

No private key is ever included in a canonical manifest object.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Iterable, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519

from oprow.core.canonical import canonical_cbor_dumps
from oprow.core.enums import SignatureRole
from oprow.core.errors import UnsupportedAlgorithmError, ValidationError
from oprow.core.hashes import hash_framed
from oprow.core.identifiers import KeyId, b64url_encode


class SignatureAlgorithm(str, Enum):
    """Signature algorithm identifiers used by Step 2."""
    ED25519 = "Ed25519"
    ES256 = "ES256"


class PublicKeyEncoding(str, Enum):
    """How public key bytes are serialized in a PublicKeyRecord."""
    RAW = "raw"
    SPKI_DER = "spki-der"


class PrivateKeyEncoding(str, Enum):
    """How private key bytes are serialized in a local PrivateKeyRecord."""
    RAW = "raw"
    PKCS8_DER = "pkcs8-der"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_alg(alg: str | SignatureAlgorithm) -> str:
    return alg.value if isinstance(alg, SignatureAlgorithm) else str(alg)


def derive_reference_key_id(alg: str | SignatureAlgorithm, public_key_bytes: bytes) -> KeyId:
    """Derive a stable raw-key identifier from public key bytes.

    OProW supports many identity systems.  For self-contained tests we need a
    deterministic key ID, so we compute:

        "oprow-key:" || alg || ":" || base64url(H256(domain, alg, pk))

    Domain separation prevents this digest from being confused with an essence
    hash, manifest locator, HDC route key, Merkle value, or chain anchor.
    """
    alg_s = normalize_alg(alg)
    digest = hash_framed("oprow-reference-key-id-v1", alg_s.encode("utf-8"), public_key_bytes)
    return KeyId(f"oprow-key:{alg_s}:{b64url_encode(digest)}")


@dataclass(frozen=True)
class PublicKeyRecord:
    """Public verification material plus descriptive metadata.

    This record is not a trust assertion.  It states only that a public key is
    available for a kid and algorithm.  Later trust layers decide whether that
    kid may act as a creator, tool, device, notary, bundle issuer, etc.
    """
    kid: KeyId
    alg: str | SignatureAlgorithm
    public_key_bytes: bytes
    encoding: str | PublicKeyEncoding
    roles: tuple[str, ...] = ()
    created_at: datetime | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    metadata: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.public_key_bytes:
            raise ValidationError("PublicKeyRecord.public_key_bytes must be non-empty")
        object.__setattr__(self, "alg", normalize_alg(self.alg))
        enc = self.encoding.value if isinstance(self.encoding, PublicKeyEncoding) else str(self.encoding)
        object.__setattr__(self, "encoding", enc)
        object.__setattr__(self, "roles", tuple(str(r) for r in self.roles))

    def to_canonical(self) -> dict[str, object]:
        out: dict[str, object] = {
            "kid": self.kid,
            "alg": self.alg,
            "public_key_bytes": self.public_key_bytes,
            "encoding": self.encoding,
            "roles": list(self.roles),
        }
        if self.created_at is not None:
            out["created_at"] = self.created_at
        if self.not_before is not None:
            out["not_before"] = self.not_before
        if self.not_after is not None:
            out["not_after"] = self.not_after
        if self.metadata:
            out["metadata"] = self.metadata
        return out

    def canonical_bytes(self) -> bytes:
        return canonical_cbor_dumps(self)

    def load_public_key(self):
        """Deserialize the cryptography public-key object for verification."""
        if self.alg == SignatureAlgorithm.ED25519.value:
            if self.encoding != PublicKeyEncoding.RAW.value:
                raise UnsupportedAlgorithmError("Ed25519 public keys must use raw encoding")
            return ed25519.Ed25519PublicKey.from_public_bytes(self.public_key_bytes)
        if self.alg == SignatureAlgorithm.ES256.value:
            if self.encoding != PublicKeyEncoding.SPKI_DER.value:
                raise UnsupportedAlgorithmError("ES256 public keys must use SPKI DER encoding")
            return serialization.load_der_public_key(self.public_key_bytes)
        raise UnsupportedAlgorithmError(f"unsupported public-key algorithm: {self.alg}")


@dataclass(frozen=True)
class PrivateKeyRecord:
    """Local private key wrapper used by examples/tests.

    This is a reference helper, not a production storage recommendation.  Real
    deployments should use HSM/KMS/secure-enclave/remote-signing backends.
    """
    public: PublicKeyRecord
    private_key_bytes: bytes
    private_key_encoding: str | PrivateKeyEncoding
    created_at: datetime = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if not self.private_key_bytes:
            raise ValidationError("PrivateKeyRecord.private_key_bytes must be non-empty")
        enc = self.private_key_encoding.value if isinstance(self.private_key_encoding, PrivateKeyEncoding) else str(self.private_key_encoding)
        object.__setattr__(self, "private_key_encoding", enc)

    @property
    def kid(self) -> KeyId:
        return self.public.kid

    @property
    def alg(self) -> str:
        return str(self.public.alg)

    def load_private_key(self):
        if self.alg == SignatureAlgorithm.ED25519.value:
            if self.private_key_encoding != PrivateKeyEncoding.RAW.value:
                raise UnsupportedAlgorithmError("Ed25519 private keys must use raw encoding")
            return ed25519.Ed25519PrivateKey.from_private_bytes(self.private_key_bytes)
        if self.alg == SignatureAlgorithm.ES256.value:
            if self.private_key_encoding != PrivateKeyEncoding.PKCS8_DER.value:
                raise UnsupportedAlgorithmError("ES256 private keys must use PKCS8 DER encoding")
            return serialization.load_der_private_key(self.private_key_bytes, password=None)
        raise UnsupportedAlgorithmError(f"unsupported private-key algorithm: {self.alg}")


def _role_values(roles: Iterable[str | SignatureRole] | None) -> tuple[str, ...]:
    if roles is None:
        return ()
    return tuple(role.value if isinstance(role, SignatureRole) else str(role) for role in roles)


def generate_ed25519_keypair(*, kid: KeyId | None = None, roles: Iterable[str | SignatureRole] | None = None, metadata: dict[str, object] | None = None) -> PrivateKeyRecord:
    """Generate an Ed25519 keypair for reference use."""
    private = ed25519.Ed25519PrivateKey.generate()
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    alg = SignatureAlgorithm.ED25519.value
    public = PublicKeyRecord(
        kid=kid or derive_reference_key_id(alg, public_bytes),
        alg=alg,
        public_key_bytes=public_bytes,
        encoding=PublicKeyEncoding.RAW,
        roles=_role_values(roles),
        created_at=_utc_now(),
        metadata=metadata or {},
    )
    return PrivateKeyRecord(public=public, private_key_bytes=private_bytes, private_key_encoding=PrivateKeyEncoding.RAW)


def generate_p256_keypair(*, kid: KeyId | None = None, roles: Iterable[str | SignatureRole] | None = None, metadata: dict[str, object] | None = None) -> PrivateKeyRecord:
    """Generate an ES256 / ECDSA P-256 keypair for reference use."""
    private = ec.generate_private_key(ec.SECP256R1())
    private_bytes = private.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    alg = SignatureAlgorithm.ES256.value
    public = PublicKeyRecord(
        kid=kid or derive_reference_key_id(alg, public_bytes),
        alg=alg,
        public_key_bytes=public_bytes,
        encoding=PublicKeyEncoding.SPKI_DER,
        roles=_role_values(roles),
        created_at=_utc_now(),
        metadata=metadata or {},
    )
    return PrivateKeyRecord(public=public, private_key_bytes=private_bytes, private_key_encoding=PrivateKeyEncoding.PKCS8_DER)


class KeyResolver(Protocol):
    """Protocol for anything that can resolve kid -> PublicKeyRecord."""
    def resolve_public_key(self, kid: KeyId) -> PublicKeyRecord | None:
        ...


@dataclass
class MemoryKeyRegistry:
    """Tiny in-memory key resolver for tests, examples, and local prototypes."""
    _public: dict[KeyId, PublicKeyRecord] = field(default_factory=dict)

    def add_public_key(self, record: PublicKeyRecord) -> None:
        if record.kid in self._public and self._public[record.kid] != record:
            raise ValidationError(f"conflicting public key for kid {record.kid}")
        self._public[record.kid] = record

    def add_private_key(self, record: PrivateKeyRecord) -> None:
        self.add_public_key(record.public)

    def resolve_public_key(self, kid: KeyId) -> PublicKeyRecord | None:
        return self._public.get(kid)

    def require_public_key(self, kid: KeyId) -> PublicKeyRecord:
        record = self.resolve_public_key(kid)
        if record is None:
            raise ValidationError(f"no public key registered for kid {kid}")
        return record

    def __contains__(self, kid: KeyId) -> bool:
        return kid in self._public

    @classmethod
    def from_public_keys(cls, records: Iterable[PublicKeyRecord]) -> "MemoryKeyRegistry":
        registry = cls()
        for record in records:
            registry.add_public_key(record)
        return registry


@dataclass(frozen=True)
class FunctionKeyResolver:
    """Adapter from a Python callable to the KeyResolver protocol."""
    fn: Callable[[KeyId], PublicKeyRecord | None]

    def resolve_public_key(self, kid: KeyId) -> PublicKeyRecord | None:
        return self.fn(kid)
