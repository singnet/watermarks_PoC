"""Step 13 rateless FULL160 watermark experiments.

The rateless package contains the experimental math and reference carrier for
recovering a 160-bit manifest locator from many local one-bit equations.  This is
an OProW research module: it helps evaluate the FULL160-RATELESS design path but
is not yet a production-grade robust watermark.
"""

from .gf2 import (
    GF2SolveResult,
    bit_list_to_int,
    bytes_to_int_be,
    gf2_rank,
    int_to_bit_list,
    int_to_fixed_bytes_be,
    parity_int,
    solve_gf2,
)
from .equations import (
    RATELESS_FULL160_EQUATION_ALG_ID,
    RATELESS_FULL160_KEY_BYTES,
    RATELESS_FULL160_WIDTH,
    RatelessDecodeResult,
    RatelessEquation,
    RatelessEquationProfile,
    deduplicate_equations,
    equation_for_key,
    equation_rhs_for_key,
    generate_equations_for_key,
    manifest_key_to_int,
    solve_manifest_key_from_equations,
    sparse_mask_for_equation,
)
from .records import (
    RATELESS_RECORD_BITS,
    RATELESS_RECORD_CRC_BITS,
    RATELESS_RECORD_ID_BITS,
    RATELESS_RECORD_VERSION,
    RATELESS_TILE_PREAMBLE_BITS,
    RATELESS_TILE_PREAMBLE_BYTES,
    RatelessTileRecord,
    RepeatedRecordDecode,
    encode_repeated_record,
    majority_decode_repeated_record,
)
from .image_alpha import (
    IMG_ALPHA_LSB_RATELESS_FULL160_EXP_ALG_ID,
    IMG_ALPHA_LSB_RATELESS_FULL160_EXP_NUMERIC_ID,
    RatelessAlphaLSBFull160Profile,
)

__all__ = [name for name in globals() if not name.startswith("_")]
