"""HDC routing layer for OProW Step 8."""

from .profiles import (
    DEFAULT_HDC_EPOCH,
    DEFAULT_HDC_PROFILE_ID,
    DEFAULT_HDC_SEED,
    DEFAULT_ROUTE_EPOCH,
    HDCProfile,
    default_hdc_profile,
)
from .vectors import HyperVector, MajorityBundler, bundle_majority, expand_public_random_bits
from .encoders import (
    HDCEncoder,
    HDCEncoding,
    RandomProjectionHDCEncoder,
    SymbolicBundlingHDCEncoder,
    quantize_byte,
)
# Compatibility name used by the architectural outline.  The implementation is
# symbolic bundling rather than sparse ternary, but the security semantics are the
# same: local HDC routing only, never final verification.
SparseTernaryHDCEncoder = SymbolicBundlingHDCEncoder
HDCComputation = HDCEncoding
from .routing import (
    HDCRouter,
    RoutePrecision,
    RouteToken,
    RouteTokenSet,
    band_bit_positions,
    bit_prefix,
    derive_band_code,
    derive_route_key,
    derive_route_tokens,
    extract_band_code,
    route_key_for_band,
    short_id_prefix_bytes,
)
from .index import (
    MemoryShort64HVIndex,
    MemoryShort64HVRouteIndex,
    Short64HVIndex,
    Short64HVIndexedManifest,
    Short64HVLookupResult,
    Short64HVRouteIndex,
    build_short64_hv_index,
)

__all__ = [name for name in globals() if not name.startswith("_")]

# Convenience wrappers matching the architecture outline.
def encode_ped_to_hypervector(ped: bytes, profile: HDCProfile | None = None) -> HyperVector:
    return SymbolicBundlingHDCEncoder(profile or default_hdc_profile()).encode_ped(ped).hypervector


def encode_artifact_to_hypervector(artifact, profile: HDCProfile | None = None, essence_registry=None) -> HyperVector:
    return SymbolicBundlingHDCEncoder(profile or default_hdc_profile(), essence_registry=essence_registry).encode_artifact(artifact).hypervector

__all__ = [name for name in globals() if not name.startswith("_")]
