"""Hash helpers for OProW.

OProW uses hashes for several different jobs: 256-bit content commitments,
160-bit FULL160 locators, 64-bit SHORT64 IDs, Merkle roots, HDC route tokens,
and blockchain/index commitments.  The functions here make those byte-level
uses explicit and provide domain-separated, length-prefixed framing.

Never hash ``a + b + c`` when fields have protocol meaning.  Without lengths,
``("ab", "c")`` and ``("a", "bc")`` collide at the concatenation level.  The
``frame_parts`` helper avoids that class of bug.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Union

from .enums import HashAlgorithm
from .errors import UnsupportedAlgorithmError

BytesLike = Union[bytes, bytearray, memoryview]


def _as_bytes(data: BytesLike) -> bytes:
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    raise TypeError(f"expected bytes-like object, got {type(data)!r}")


def hash_bytes(data: BytesLike, alg: str | HashAlgorithm = HashAlgorithm.SHA256) -> bytes:
    """Return a 32-byte digest using SHA-256 or optional BLAKE3-256."""
    alg_value = alg.value if isinstance(alg, HashAlgorithm) else str(alg)
    raw = _as_bytes(data)
    if alg_value == HashAlgorithm.SHA256.value:
        return hashlib.sha256(raw).digest()
    if alg_value == HashAlgorithm.BLAKE3_256.value:
        try:
            import blake3  # type: ignore
        except Exception as exc:  # pragma: no cover
            raise UnsupportedAlgorithmError("BLAKE3 requested but optional package 'blake3' is not installed") from exc
        return blake3.blake3(raw).digest(length=32)
    raise UnsupportedAlgorithmError(f"unsupported hash algorithm: {alg_value}")


def h256(data: BytesLike, alg: str | HashAlgorithm = HashAlgorithm.SHA256) -> bytes:
    """OProW H256 primitive: a 256-bit digest."""
    digest = hash_bytes(data, alg=alg)
    if len(digest) != 32:
        raise UnsupportedAlgorithmError(f"hash returned {len(digest)} bytes, expected 32")
    return digest


def h160(data: BytesLike, alg: str | HashAlgorithm = HashAlgorithm.SHA256) -> bytes:
    """First 160 bits of H256(data), used as the FULL160 manifest locator."""
    return h256(data, alg=alg)[:20]


def trunc64(data: BytesLike, alg: str | HashAlgorithm = HashAlgorithm.SHA256) -> bytes:
    """First 64 bits of H256(data), used by the baseline SHORT64 profile."""
    return h256(data, alg=alg)[:8]


def _u64be(n: int) -> bytes:
    if n < 0 or n >= 2**64:
        raise ValueError(f"length out of u64 range: {n}")
    return n.to_bytes(8, "big")


def frame_parts(domain: str, parts: Iterable[BytesLike]) -> bytes:
    """Return a domain-separated, length-framed byte preimage."""
    domain_b = domain.encode("utf-8")
    out = bytearray(b"OProW-FRAME-v1")
    out.extend(_u64be(len(domain_b)))
    out.extend(domain_b)
    for part in parts:
        part_b = _as_bytes(part)
        out.extend(_u64be(len(part_b)))
        out.extend(part_b)
    return bytes(out)


def hash_framed(domain: str, *parts: BytesLike, alg: str | HashAlgorithm = HashAlgorithm.SHA256) -> bytes:
    """Domain-separated H256 over length-prefixed fields."""
    return h256(frame_parts(domain, parts), alg=alg)
