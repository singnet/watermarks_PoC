"""Typed identifiers for OProW.

The protocol has several compact byte strings with different meanings.  This
module makes them distinct Python types: a 32-byte essence commitment is not a
20-byte FULL160 manifest key, and neither is an 8-byte short ID.

Canonical CBOR serializes these identifiers as raw byte strings.  Debug JSON uses
tagged hex strings such as ``h160:abcd...``.
"""

from __future__ import annotations

import base64
from typing import ClassVar, TypeVar

from .enums import HashAlgorithm
from .errors import IdentifierError
from .hashes import h160 as _h160, h256 as _h256, trunc64 as _trunc64

T = TypeVar("T", bound="FixedBytesIdentifier")


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str) or not text:
        raise IdentifierError("base64url input must be a non-empty string")
    try:
        return base64.urlsafe_b64decode((text + "=" * (-len(text) % 4)).encode("ascii"))
    except Exception as exc:
        raise IdentifierError(f"invalid base64url: {text!r}") from exc


class FixedBytesIdentifier:
    """Immutable fixed-size identifier base class."""
    SIZE_BYTES: ClassVar[int]
    TAG: ClassVar[str]
    __slots__ = ("_value",)

    def __init__(self, value: bytes | bytearray | memoryview):
        raw = bytes(value)
        if len(raw) != self.SIZE_BYTES:
            raise IdentifierError(f"{self.__class__.__name__} must be {self.SIZE_BYTES} bytes, got {len(raw)}")
        self._value = raw

    @property
    def value(self) -> bytes:
        return self._value

    def __bytes__(self) -> bytes:
        return self._value

    def __len__(self) -> int:
        return len(self._value)

    def __eq__(self, other: object) -> bool:
        return self.__class__ is other.__class__ and self._value == other._value  # type: ignore[attr-defined]

    def __hash__(self) -> int:
        return hash((self.__class__, self._value))

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}.from_hex({self.to_hex()!r})"

    def __str__(self) -> str:
        return self.to_tagged()

    def to_canonical(self) -> bytes:
        return self._value

    def to_json_value(self) -> str:
        return self.to_tagged()

    def to_hex(self) -> str:
        return self._value.hex()

    def to_tagged(self) -> str:
        return f"{self.TAG}:{self.to_hex()}"

    @classmethod
    def from_hex(cls: type[T], text: str) -> T:
        prefix = f"{cls.TAG}:"
        if text.startswith(prefix):
            text = text[len(prefix):]
        try:
            return cls(bytes.fromhex(text))
        except ValueError as exc:
            raise IdentifierError(f"invalid hex for {cls.__name__}: {text!r}") from exc

    @classmethod
    def from_base64url(cls: type[T], text: str) -> T:
        return cls(b64url_decode(text))


class Hash256(FixedBytesIdentifier):
    """A 32-byte digest or commitment."""
    SIZE_BYTES = 32
    TAG = "h256"

    @classmethod
    def from_data(cls, data: bytes | bytearray | memoryview, alg: str | HashAlgorithm = HashAlgorithm.SHA256) -> "Hash256":
        return cls(_h256(data, alg=alg))


class ManifestKey(FixedBytesIdentifier):
    """A 20-byte FULL160 locator derived from canonical SignedManifest bytes."""
    SIZE_BYTES = 20
    TAG = "h160"

    @classmethod
    def from_manifest_bytes(cls, data: bytes | bytearray | memoryview, alg: str | HashAlgorithm = HashAlgorithm.SHA256) -> "ManifestKey":
        return cls(_h160(data, alg=alg))


class ShortId(FixedBytesIdentifier):
    """An 8-byte short locator; useful for routing, not final proof."""
    SIZE_BYTES = 8
    TAG = "sid64"

    @classmethod
    def from_manifest_bytes_hash_truncated(cls, data: bytes | bytearray | memoryview, alg: str | HashAlgorithm = HashAlgorithm.SHA256) -> "ShortId":
        return cls(_trunc64(data, alg=alg))


class NamespaceId:
    """2–4 byte namespace prefix for registry-assigned short IDs."""
    MIN_BYTES: ClassVar[int] = 2
    MAX_BYTES: ClassVar[int] = 4
    TAG: ClassVar[str] = "ns"
    __slots__ = ("_value",)

    def __init__(self, value: bytes | bytearray | memoryview):
        raw = bytes(value)
        if not (self.MIN_BYTES <= len(raw) <= self.MAX_BYTES):
            raise IdentifierError(f"NamespaceId must be {self.MIN_BYTES}..{self.MAX_BYTES} bytes, got {len(raw)}")
        self._value = raw

    @property
    def value(self) -> bytes:
        return self._value

    def __bytes__(self) -> bytes:
        return self._value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, NamespaceId) and self._value == other._value

    def __hash__(self) -> int:
        return hash((NamespaceId, self._value))

    def to_canonical(self) -> bytes:
        return self._value

    def to_json_value(self) -> str:
        return self.to_tagged()

    def to_hex(self) -> str:
        return self._value.hex()

    def to_tagged(self) -> str:
        return f"{self.TAG}:{self.to_hex()}"

    @classmethod
    def from_hex(cls, text: str) -> "NamespaceId":
        prefix = f"{cls.TAG}:"
        if text.startswith(prefix):
            text = text[len(prefix):]
        try:
            return cls(bytes.fromhex(text))
        except ValueError as exc:
            raise IdentifierError(f"invalid hex for NamespaceId: {text!r}") from exc


class KeyId:
    """Textual key identifier: DID URL, X.509 ID, raw-key URI, etc."""
    __slots__ = ("value",)

    def __init__(self, value: str):
        if not isinstance(value, str) or not value.strip():
            raise IdentifierError("KeyId must be a non-empty string")
        self.value = value

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"KeyId({self.value!r})"

    def __eq__(self, other: object) -> bool:
        return isinstance(other, KeyId) and self.value == other.value

    def __hash__(self) -> int:
        return hash((KeyId, self.value))

    def to_canonical(self) -> str:
        return self.value

    def to_json_value(self) -> str:
        return self.value
