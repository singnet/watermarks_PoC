"""SHORT64-HV route-token derivation.

This module implements the Step 8 bridge between a short watermark payload and a
media-derived HDC descriptor:

    extracted short_id + locally computed hypervector -> route tokens

A route token is an opaque 256-bit hash key used by an index/resolver.  It is
constructed from a short-ID prefix, a coarse HDC band code, and public profile
metadata.  The resolver can match token equality without seeing the raw PED or
raw hypervector.

Important limitations
=====================

Step 8 is deliberately *not* the full privacy system.  It defines the route-token
mechanism that Step 10 will wrap in privacy profiles P0/P1/P2.  It already
follows two privacy-preserving habits:

* raw PEDs and hypervectors are not serialized into route queries;
* route keys are domain-separated hashes of coarse band codes.

However, a very precise route token can still identify an artifact.  Production
clients should later use k-anonymous coarse tokens, relays, cover traffic, or PIR
for sensitive lookups.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from oprow.core.errors import ValidationError
from oprow.core.hashes import hash_framed
from oprow.core.identifiers import Hash256, NamespaceId, ShortId

from .encoders import HDCEncoding
from .profiles import DEFAULT_HDC_EPOCH, HDCProfile
from .vectors import HyperVector


def _u16(n: int) -> bytes:
    if n < 0 or n >= 2**16:
        raise ValidationError("integer out of u16 range")
    return n.to_bytes(2, "big")


def _u32(n: int) -> bytes:
    if n < 0 or n >= 2**32:
        raise ValidationError("integer out of u32 range")
    return n.to_bytes(4, "big")


def bit_prefix(data: bytes, n_bits: int) -> bytes:
    """Return a MSB-first bit prefix, padded with zero bits in the final byte."""
    if n_bits < 0 or n_bits > len(data) * 8:
        raise ValidationError("invalid prefix bit length")
    if n_bits == 0:
        return b""
    n_bytes = (n_bits + 7) // 8
    out = bytearray(data[:n_bytes])
    unused = (8 - (n_bits % 8)) % 8
    if unused:
        out[-1] &= (0xFF << unused) & 0xFF
    return bytes(out)


@dataclass(frozen=True)
class RoutePrecision:
    """Controls how specific an HDC route query is.

    Step 8 defaults to ``short_prefix_bits=64`` and the profile's
    ``bits_per_band`` because it is focused on deterministic routing.  Step 10
    will lower these values for privacy profiles that need larger anonymity
    sets.
    """

    short_prefix_bits: int = 64
    hv_band_bits: int | None = None
    band_ids: tuple[int, ...] | None = None

    def normalized(self, profile: HDCProfile) -> "RoutePrecision":
        band_bits = self.hv_band_bits if self.hv_band_bits is not None else profile.bits_per_band
        if self.short_prefix_bits < 0 or self.short_prefix_bits > 64:
            raise ValidationError("short_prefix_bits must be 0..64")
        if band_bits <= 0 or band_bits > profile.band_width():
            raise ValidationError("hv_band_bits must fit inside profile band width")
        ids = self.band_ids if self.band_ids is not None else tuple(range(profile.num_bands))
        if not ids:
            raise ValidationError("at least one band_id is required")
        for i in ids:
            if i < 0 or i >= profile.num_bands:
                raise ValidationError("band_id out of range")
        return RoutePrecision(self.short_prefix_bits, band_bits, tuple(ids))

    def to_canonical(self) -> dict[str, object]:
        return {"short_prefix_bits": self.short_prefix_bits, "hv_band_bits": self.hv_band_bits, "band_ids": list(self.band_ids or [])}


@dataclass(frozen=True)
class RouteToken:
    """Opaque key used to query a SHORT64-HV resolver.

    ``route_key`` is what a public resolver sees.  ``short_prefix`` and
    ``band_code`` are retained only for local diagnostics and tests; they should
    not be placed in a public API response or blockchain record.  Step 10 will
    introduce stricter query objects that omit these debug fields by default.
    """

    route_key: Hash256
    profile_id: str
    epoch_id: str
    band_id: int
    precision: RoutePrecision
    namespace_id: NamespaceId | None = None
    short_prefix: bytes = b""
    band_code: bytes = b""
    metadata: dict[str, object] = field(default_factory=dict)

    def to_query_key(self) -> Hash256:
        """Return the only value a normal resolver needs to receive."""
        return self.route_key

    def to_canonical(self) -> dict[str, object]:
        return {
            "route_key": self.route_key,
            "profile_id": self.profile_id,
            "epoch_id": self.epoch_id,
            "band_id": self.band_id,
            "precision": self.precision,
            "namespace_id": self.namespace_id,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class RouteTokenSet:
    """All route tokens derived for one artifact/short-ID/profile tuple."""

    short_id: ShortId
    profile_id: str
    epoch_id: str
    tokens: list[RouteToken]
    namespace_id: NamespaceId | None = None

    def query_keys(self) -> list[Hash256]:
        return [t.route_key for t in self.tokens]

    def to_canonical(self) -> dict[str, object]:
        return {
            "short_id": self.short_id,
            "profile_id": self.profile_id,
            "epoch_id": self.epoch_id,
            "namespace_id": self.namespace_id,
            "tokens": self.tokens,
        }


def derive_band_code(hv: HyperVector, profile: HDCProfile, *, band_id: int, bits: int) -> bytes:
    """Derive a coarse LSH-like code from one hypervector band.

    Exact band-code equality is a simple locality-sensitive routing primitive:
    related artifacts may share some bands even if their full hypervectors differ
    slightly.  The code takes the first ``bits`` bits of a contiguous band.  More
    advanced profiles can replace this with random bit sampling, SimHash bands,
    multi-probe LSH, or learned quantizers.
    """
    if hv.dimension != profile.dimension:
        raise ValidationError("hypervector dimension does not match HDC profile")
    return hv.band_slice(band_id=band_id, num_bands=profile.num_bands, bits_per_band=bits)


def derive_route_key(
    *,
    profile: HDCProfile,
    epoch_id: str,
    namespace_id: NamespaceId | None,
    short_prefix_bits: int,
    short_prefix: bytes,
    band_id: int,
    hv_band_bits: int,
    band_code: bytes,
) -> Hash256:
    """Domain-separated hash that hides raw HDC band bits from resolvers."""
    ns = namespace_id.value if namespace_id is not None else b""
    return Hash256(
        hash_framed(
            "oprow-short64-hv-route-token-v1",
            profile.profile_id.encode("utf-8"),
            epoch_id.encode("utf-8"),
            ns,
            _u16(short_prefix_bits),
            short_prefix,
            _u16(band_id),
            _u16(hv_band_bits),
            band_code,
        )
    )


def derive_route_tokens(
    *,
    short_id: ShortId,
    encoding: HDCEncoding | HyperVector,
    profile: HDCProfile | None = None,
    namespace_id: NamespaceId | None = None,
    epoch_id: str = DEFAULT_HDC_EPOCH,
    precision: RoutePrecision | None = None,
) -> RouteTokenSet:
    """Derive all query tokens for SHORT64-HV lookup.

    The same function is used by an indexer when publishing a manifest and by a
    verifier when resolving a watermarked artifact.  Determinism here is crucial:
    any disagreement means the verifier will query the wrong route buckets.
    """
    if isinstance(encoding, HDCEncoding):
        hv = encoding.hypervector
        profile = profile or encoding.profile
    else:
        hv = encoding
        if profile is None:
            raise ValidationError("profile is required when encoding is a raw HyperVector")
    if hv.dimension != profile.dimension:
        raise ValidationError("hypervector dimension does not match profile")
    if not epoch_id:
        raise ValidationError("epoch_id must be non-empty")
    precision = (precision or RoutePrecision()).normalized(profile)
    short_pref = bit_prefix(short_id.value, precision.short_prefix_bits)
    tokens: list[RouteToken] = []
    for band_id in precision.band_ids or tuple(range(profile.num_bands)):
        code = derive_band_code(hv, profile, band_id=band_id, bits=int(precision.hv_band_bits))
        key = derive_route_key(
            profile=profile,
            epoch_id=epoch_id,
            namespace_id=namespace_id,
            short_prefix_bits=precision.short_prefix_bits,
            short_prefix=short_pref,
            band_id=band_id,
            hv_band_bits=int(precision.hv_band_bits),
            band_code=code,
        )
        tokens.append(
            RouteToken(
                route_key=key,
                profile_id=profile.profile_id,
                epoch_id=epoch_id,
                band_id=band_id,
                precision=precision,
                namespace_id=namespace_id,
                short_prefix=short_pref,
                band_code=code,
                metadata={"route_profile": "SHORT64-HV-Step8"},
            )
        )
    return RouteTokenSet(short_id=short_id, profile_id=profile.profile_id, epoch_id=epoch_id, tokens=tokens, namespace_id=namespace_id)


# ---------------------------------------------------------------------------
# Compatibility/convenience API for the Step 8 public package surface.
# ---------------------------------------------------------------------------

def short_id_prefix_bytes(short_id: ShortId, prefix_bits: int) -> bytes:
    """Return a canonical MSB-first prefix of a ``ShortId``.

    This is a clearer name for ``bit_prefix(short_id.value, prefix_bits)`` and
    matches the architecture notes for the later privacy profiles.
    """
    return bit_prefix(short_id.value, prefix_bits)


def band_bit_positions(profile: HDCProfile, band_id: int, nbits: int) -> list[int]:
    """Return the contiguous bit positions used by the baseline band profile."""
    if not (0 <= band_id < profile.num_bands):
        raise ValidationError("band_id out of range")
    if nbits <= 0 or nbits > profile.band_width():
        raise ValidationError("nbits must fit inside profile band")
    start = band_id * profile.band_width()
    return list(range(start, start + nbits))


def extract_band_code(hv: HyperVector, profile: HDCProfile, band_id: int, nbits: int) -> bytes:
    """Compatibility wrapper for ``derive_band_code``."""
    return derive_band_code(hv, profile, band_id=band_id, bits=nbits)


def route_key_for_band(
    *,
    profile: HDCProfile,
    short_id: ShortId,
    hv: HDCEncoding | HyperVector,
    band_id: int,
    precision: RoutePrecision,
    namespace_id: NamespaceId | None = None,
    epoch_id: str = DEFAULT_HDC_EPOCH,
) -> RouteToken:
    """Derive a single route token for one band.

    The main ``derive_route_tokens`` function returns a full ``RouteTokenSet``.
    This helper is useful for tests and for code that wants to query only one
    selected band.
    """
    normalized = precision.normalized(profile)
    one_band = RoutePrecision(
        short_prefix_bits=normalized.short_prefix_bits,
        hv_band_bits=normalized.hv_band_bits,
        band_ids=(band_id,),
    )
    return derive_route_tokens(
        short_id=short_id,
        encoding=hv,
        profile=profile,
        namespace_id=namespace_id,
        epoch_id=epoch_id,
        precision=one_band,
    ).tokens[0]


class HDCRouter:
    """Object-oriented wrapper around ``derive_route_tokens``.

    The router is deliberately thin.  It exists to give the resolver/indexer a
    stable object with a configured profile, while the protocol logic remains in
    pure functions above.
    """

    def __init__(self, profile: HDCProfile | None = None):
        from .profiles import default_hdc_profile
        self.profile = profile or default_hdc_profile()

    def derive_route_tokens(
        self,
        *,
        short_id: ShortId,
        hv: HDCEncoding | HyperVector,
        namespace_id: NamespaceId | None = None,
        precision: RoutePrecision | None = None,
        epoch_id: str = DEFAULT_HDC_EPOCH,
        bands: Iterable[int] | None = None,
    ) -> list[RouteToken]:
        if bands is not None:
            base = (precision or RoutePrecision()).normalized(self.profile)
            precision = RoutePrecision(base.short_prefix_bits, base.hv_band_bits, tuple(bands))
        return derive_route_tokens(
            short_id=short_id,
            encoding=hv,
            profile=self.profile,
            namespace_id=namespace_id,
            epoch_id=epoch_id,
            precision=precision,
        ).tokens
