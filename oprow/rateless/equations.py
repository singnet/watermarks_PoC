"""Rateless equation generation for FULL160 OProW locators.

This module converts a manifest key into many deterministic linear equations.
It is the theory layer behind the Step 13 watermark experiment.

The construction
----------------
Given a 160-bit manifest key ``K`` and an equation identifier ``i``:

1. Derive a pseudo-random sparse binary vector ``a_i`` from a public profile seed
   and ``i``.  The vector is deterministic, so the extractor/verifier can
   regenerate it without storing it in the watermark.
2. Compute the one-bit response ``y_i = parity(a_i & K)``.
3. Embed the pair ``(i, y_i)`` in a media region.

At extraction time, every recovered pair ``(i, y_i)`` regenerates the same vector
``a_i``.  Enough independent equations solve for ``K`` via GF(2) Gaussian
elimination.

Security boundary
-----------------
The recovered key is still only a locator.  A successful rateless solve is not a
claim that the media is authentic.  It only gives the verifier a FULL160-style
manifest key.  The normal OProW verifier must still resolve the manifest and
check locator self-consistency, signatures, essence/content binding, and trust
policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable
import hashlib

from oprow.core.errors import ValidationError
from oprow.core.identifiers import ManifestKey
from .gf2 import GF2SolveResult, bytes_to_int_be, int_to_fixed_bytes_be, parity_int, solve_gf2

RATELESS_FULL160_EQUATION_ALG_ID = "RATELESS-FULL160-SPARSE-GF2-1"
RATELESS_FULL160_WIDTH = 160
RATELESS_FULL160_KEY_BYTES = 20


@dataclass(frozen=True)
class RatelessEquationProfile:
    """Profile controlling deterministic equation generation.

    ``equation_weight`` is the Hamming weight of each random row.  Very sparse
    rows are cheap but can rank up more slowly; very dense rows are less local
    and may be less convenient for some future carrier designs.  This reference
    profile uses a moderate odd sparse weight.  Benchmarks should tune it.
    """

    alg_id: str = RATELESS_FULL160_EQUATION_ALG_ID
    width: int = RATELESS_FULL160_WIDTH
    equation_weight: int = 41
    seed: bytes = b"OProW-Rateless-FULL160-SPARSE-GF2-1"
    max_equation_id: int = (1 << 16) - 1
    metadata: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.width != RATELESS_FULL160_WIDTH:
            # The solver itself supports arbitrary width, but this Step 13
            # profile is intentionally a FULL160 experiment.  Generalized widths
            # should be added as separate algorithm IDs.
            raise ValidationError("Step 13 rateless profile is fixed to width 160")
        if not (1 <= self.equation_weight <= self.width):
            raise ValidationError("equation_weight must be in 1..width")
        if self.max_equation_id <= 0:
            raise ValidationError("max_equation_id must be positive")


@dataclass(frozen=True)
class RatelessEquation:
    """One recovered or generated equation about the manifest key."""

    equation_id: int
    mask: int
    rhs: int
    confidence: float = 1.0
    source: str | None = None

    def __post_init__(self) -> None:
        if self.equation_id < 0:
            raise ValidationError("equation_id must be non-negative")
        if self.mask < 0:
            raise ValidationError("equation mask must be non-negative")
        if int(self.rhs) not in (0, 1):
            raise ValidationError("equation rhs must be 0/1")
        if self.confidence < 0:
            raise ValidationError("confidence must be non-negative")

    def pair(self) -> tuple[int, int]:
        """Return the ``(mask, rhs)`` pair consumed by ``solve_gf2``."""

        return int(self.mask), int(self.rhs)


@dataclass(frozen=True)
class RatelessDecodeResult:
    """Result of attempting to recover a manifest key from equations."""

    profile: RatelessEquationProfile
    equations_seen: int
    unique_equations: int
    solve_report: GF2SolveResult
    recovered_key: ManifestKey | None
    diagnostics: dict[str, object] = field(default_factory=dict)

    @property
    def solved(self) -> bool:
        return self.recovered_key is not None and self.solve_report.solved


def _hash_blocks(seed: bytes, label: bytes, equation_id: int) -> Iterable[bytes]:
    """Yield deterministic SHA-256 blocks for a seed/label/equation ID.

    This acts as a tiny local XOF.  It is public and not a secret PRF.  Its job
    is simply to make independent-looking equation vectors reproducible.
    """

    if equation_id < 0:
        raise ValidationError("equation_id must be non-negative")
    eid = equation_id.to_bytes(8, "big")
    counter = 0
    while True:
        ctr = counter.to_bytes(4, "big")
        yield hashlib.sha256(seed + b"\x00" + label + b"\x00" + eid + ctr).digest()
        counter += 1


def sparse_mask_for_equation(profile: RatelessEquationProfile, equation_id: int) -> int:
    """Derive the sparse binary vector ``a_i`` for an equation ID.

    The function samples 16-bit chunks from SHA-256 output and reduces them modulo
    the vector width.  Duplicate positions are ignored until the target Hamming
    weight is reached.  The exact method is simple, deterministic, and specified
    by this reference implementation; production profiles may choose a different
    row-generation algorithm with a different ``alg_id``.
    """

    if equation_id < 0 or equation_id > profile.max_equation_id:
        raise ValidationError(f"equation_id {equation_id} outside profile range 0..{profile.max_equation_id}")
    positions: set[int] = set()
    for block in _hash_blocks(profile.seed, b"mask", equation_id):
        for offset in range(0, len(block), 2):
            value = int.from_bytes(block[offset : offset + 2], "big")
            positions.add(value % profile.width)
            if len(positions) >= profile.equation_weight:
                mask = 0
                for pos in positions:
                    mask |= 1 << pos
                return mask
    raise AssertionError("unreachable: hash block generator is infinite")


def manifest_key_to_int(key: ManifestKey | bytes | int) -> int:
    """Normalize a manifest key to an integer."""

    if isinstance(key, ManifestKey):
        return bytes_to_int_be(key.value)
    if isinstance(key, bytes):
        if len(key) != RATELESS_FULL160_KEY_BYTES:
            raise ValidationError("FULL160 rateless keys must be exactly 20 bytes")
        return bytes_to_int_be(key)
    value = int(key)
    if value < 0 or value >= (1 << RATELESS_FULL160_WIDTH):
        raise ValidationError("FULL160 rateless key integer does not fit 160 bits")
    return value


def equation_rhs_for_key(profile: RatelessEquationProfile, equation_id: int, key: ManifestKey | bytes | int) -> int:
    """Compute ``y_i = <a_i, K>`` for a manifest key and equation ID."""

    mask = sparse_mask_for_equation(profile, equation_id)
    return parity_int(mask & manifest_key_to_int(key))


def equation_for_key(
    profile: RatelessEquationProfile,
    equation_id: int,
    key: ManifestKey | bytes | int,
    *,
    confidence: float = 1.0,
    source: str | None = None,
) -> RatelessEquation:
    """Generate one deterministic equation for a key."""

    mask = sparse_mask_for_equation(profile, equation_id)
    rhs = parity_int(mask & manifest_key_to_int(key))
    return RatelessEquation(equation_id=equation_id, mask=mask, rhs=rhs, confidence=confidence, source=source)


def generate_equations_for_key(
    key: ManifestKey | bytes | int,
    *,
    count: int,
    profile: RatelessEquationProfile | None = None,
    start_equation_id: int = 0,
    source: str | None = None,
) -> list[RatelessEquation]:
    """Generate ``count`` sequential equations for ``key``."""

    if count < 0:
        raise ValidationError("equation count must be non-negative")
    prof = profile or RatelessEquationProfile()
    return [equation_for_key(prof, start_equation_id + i, key, source=source) for i in range(count)]


def deduplicate_equations(equations: Iterable[RatelessEquation]) -> list[RatelessEquation]:
    """Keep one equation per equation ID, preferring higher-confidence records.

    Tile extraction may recover the same equation more than once if future
    profiles add spatial repetition or multi-channel embedding.  The reference
    decoder keeps the highest-confidence record for each ID.  Conflicting
    duplicates with the same confidence are left to the first-seen order.
    """

    best: dict[int, RatelessEquation] = {}
    for eq in equations:
        current = best.get(eq.equation_id)
        if current is None or eq.confidence > current.confidence:
            best[eq.equation_id] = eq
    return [best[k] for k in sorted(best)]


def solve_manifest_key_from_equations(
    equations: Iterable[RatelessEquation],
    *,
    profile: RatelessEquationProfile | None = None,
) -> RatelessDecodeResult:
    """Attempt to recover a FULL160 ``ManifestKey`` from equations."""

    prof = profile or RatelessEquationProfile()
    all_equations = list(equations)
    unique = deduplicate_equations(all_equations)
    report = solve_gf2(((eq.mask, eq.rhs) for eq in unique), width=prof.width)
    recovered: ManifestKey | None = None
    if report.solved and report.solution is not None:
        recovered = ManifestKey(int_to_fixed_bytes_be(report.solution, RATELESS_FULL160_KEY_BYTES))
    return RatelessDecodeResult(
        profile=prof,
        equations_seen=len(all_equations),
        unique_equations=len(unique),
        solve_report=report,
        recovered_key=recovered,
        diagnostics={
            "rank": report.rank,
            "missing_rank": report.missing_rank,
            "redundant_equations": report.redundant_equations,
            "inconsistent_equations": report.inconsistent_equations,
        },
    )
