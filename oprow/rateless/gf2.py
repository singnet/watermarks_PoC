"""Linear algebra over GF(2) for rateless FULL160 watermark experiments.

This file implements the mathematical core of the Step 13 experiment: recover a
160-bit OProW manifest key from many small, independently embedded linear
constraints.

Why GF(2)?
-----------
The rateless watermark idea discussed for OProW is to avoid placing the entire
160-bit locator in one fragile payload block.  Instead, many spatial/temporal
regions each carry one equation about the locator ``K``:

    <a_i, K> = y_i   over GF(2)

where ``a_i`` is a deterministic pseudo-random binary vector and ``y_i`` is one
bit.  If a crop, transcode, or local damage destroys some regions, the extractor
still keeps whichever equations survived.  Once it has enough independent
surviving equations, it solves for the original locator.

This does **not** beat Shannon capacity.  A verifier still needs at least 160
independent reliable bits of information, plus margin for synchronization and
errors.  The benefit is distribution: no single tile/frame/window needs to carry
the whole locator.

Implementation choices
----------------------
Rows are represented as Python integers.  Bit ``j`` of an integer corresponds to
variable ``x_j``.  A GF(2) row with right-hand side bit ``b`` is stored as an
"augmented row" integer:

    augmented = (mask << 1) | b

The least significant bit is the RHS.  The remaining bits are the variable mask.
This makes row addition simply XOR.  Python's arbitrary-precision integers make
this concise and fast enough for reference use.

The solver maintains a reduced row-echelon basis keyed by pivot bit index.  It is
not optimized for million-row systems; it is deliberately transparent so future
coding agents can replace it with a Rust/C++/NumPy implementation without
changing the public OProW API.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from oprow.core.errors import ValidationError


def parity_int(value: int) -> int:
    """Return the parity bit of ``value``: 1 if it has odd Hamming weight.

    Python 3.10's ``int.bit_count`` is exact and efficient for arbitrary-size
    integers.  GF(2) inner products can therefore be written as:

        parity_int(mask & key_int)
    """

    if value < 0:
        raise ValidationError("parity_int expects a non-negative integer")
    return value.bit_count() & 1


def bytes_to_int_be(data: bytes) -> int:
    """Decode bytes as a big-endian integer.

    OProW identifiers are displayed and serialized as big-endian byte strings.
    Internally, GF(2) bit index 0 is the integer least-significant bit.  That is
    fine as long as we convert key bytes to/from integers consistently.
    """

    return int.from_bytes(data, "big")


def int_to_fixed_bytes_be(value: int, length: int) -> bytes:
    """Encode ``value`` as exactly ``length`` big-endian bytes."""

    if value < 0:
        raise ValidationError("cannot encode negative integer as bytes")
    if value >= (1 << (8 * length)):
        raise ValidationError(f"integer does not fit in {length} bytes")
    return int(value).to_bytes(length, "big")


def bit_list_to_int(bits: Sequence[int]) -> int:
    """Convert a big-endian bit list to an integer.

    This helper is mainly used by tests and diagnostics.  The rateless solver
    itself operates directly on integer masks.
    """

    out = 0
    for bit in bits:
        b = int(bit)
        if b not in (0, 1):
            raise ValidationError(f"expected bit 0/1, got {bit!r}")
        out = (out << 1) | b
    return out


def int_to_bit_list(value: int, width: int) -> list[int]:
    """Return ``value`` as exactly ``width`` big-endian bits."""

    if width < 0:
        raise ValidationError("width must be non-negative")
    if value < 0:
        raise ValidationError("cannot encode negative integer as bits")
    if value >= (1 << width):
        raise ValidationError(f"integer does not fit in {width} bits")
    return [(value >> shift) & 1 for shift in range(width - 1, -1, -1)]


@dataclass(frozen=True)
class GF2SolveResult:
    """Diagnostic result for a GF(2) linear solve.

    ``solution`` is an integer containing the recovered vector if the system is
    consistent and full-rank.  If the system is underdetermined, the result may
    still be consistent but has no unique solution.  OProW rateless watermarking
    must treat that as extraction failure, not as partial verification.
    """

    width: int
    equations_seen: int
    rank: int
    consistent: bool
    solution: int | None
    redundant_equations: int = 0
    inconsistent_equations: int = 0

    @property
    def solved(self) -> bool:
        """True if the system has a unique width-bit solution."""

        return self.consistent and self.rank == self.width and self.solution is not None

    @property
    def missing_rank(self) -> int:
        """Number of additional independent equations required, ignoring noise."""

        return max(0, self.width - self.rank)

    def solution_bytes(self, *, length: int | None = None) -> bytes:
        """Return the solved vector as bytes or raise if unsolved."""

        if not self.solved or self.solution is None:
            raise ValidationError("GF(2) system is not uniquely solved")
        byte_len = length if length is not None else (self.width + 7) // 8
        return int_to_fixed_bytes_be(self.solution, byte_len)


def _validate_row(mask: int, rhs: int, width: int) -> tuple[int, int]:
    if width <= 0:
        raise ValidationError("GF(2) width must be positive")
    if mask < 0:
        raise ValidationError("GF(2) row mask must be non-negative")
    if mask >= (1 << width):
        raise ValidationError(f"GF(2) row mask exceeds width {width}")
    b = int(rhs)
    if b not in (0, 1):
        raise ValidationError(f"GF(2) RHS must be 0/1, got {rhs!r}")
    return mask, b


def gf2_rank(rows: Iterable[int], *, width: int) -> int:
    """Return the rank of a collection of GF(2) row masks.

    The algorithm is the same pivot-basis elimination used by ``solve_gf2`` but
    without RHS bits.  It is useful for experiments that ask, for example, how
    many tile equations survived and whether they are independent.
    """

    basis: dict[int, int] = {}
    for raw in rows:
        mask = int(raw)
        if mask < 0 or mask >= (1 << width):
            raise ValidationError(f"row mask does not fit width {width}")
        while mask:
            pivot = mask.bit_length() - 1
            existing = basis.get(pivot)
            if existing is None:
                basis[pivot] = mask
                break
            mask ^= existing
    return len(basis)


def solve_gf2(equations: Iterable[tuple[int, int]], *, width: int) -> GF2SolveResult:
    """Solve a binary linear system over GF(2).

    Parameters
    ----------
    equations:
        Iterable of ``(mask, rhs)`` pairs.  Each mask is a width-bit integer
        selecting variables with coefficient 1.  ``rhs`` is 0 or 1.
    width:
        Number of unknown bits.  For OProW FULL160 this is 160.

    Returns
    -------
    GF2SolveResult
        Contains rank, consistency, and the unique solution if rank == width.

    Notes
    -----
    The basis is kept in reduced form: whenever a new pivot row is inserted, it
    is XORed out of all existing rows that contain that pivot.  If the final rank
    is full, each pivot row directly encodes one solution bit in its RHS.
    """

    if width <= 0:
        raise ValidationError("GF(2) width must be positive")

    basis: dict[int, int] = {}
    seen = 0
    redundant = 0
    inconsistent = 0

    for mask_raw, rhs_raw in equations:
        seen += 1
        mask, rhs = _validate_row(int(mask_raw), int(rhs_raw), width)
        row = (mask << 1) | rhs

        # Reduce against every existing pivot.  It is not enough to stop at
        # the first new high pivot: lower pivot columns in the row would then
        # remain, and reading solution bits directly from RHS values would be
        # wrong.  Iterating high-to-low keeps the basis in reduced form.
        for pivot in sorted(basis.keys(), reverse=True):
            if ((row >> 1) >> pivot) & 1:
                row ^= basis[pivot]

        remaining_mask = row >> 1
        if remaining_mask == 0:
            if row & 1:
                inconsistent += 1
                return GF2SolveResult(
                    width=width,
                    equations_seen=seen,
                    rank=len(basis),
                    consistent=False,
                    solution=None,
                    redundant_equations=redundant,
                    inconsistent_equations=inconsistent,
                )
            redundant += 1
            continue

        pivot = remaining_mask.bit_length() - 1

        # Make the new pivot absent from all existing rows.  This is the small
        # extra step that turns ordinary echelon form into reduced echelon form.
        for existing_pivot, existing_row in list(basis.items()):
            if ((existing_row >> 1) >> pivot) & 1:
                basis[existing_pivot] = existing_row ^ row
        basis[pivot] = row

    solution: int | None = None
    if len(basis) == width:
        sol = 0
        for pivot, row in basis.items():
            if row & 1:
                sol |= 1 << pivot
        solution = sol

    return GF2SolveResult(
        width=width,
        equations_seen=seen,
        rank=len(basis),
        consistent=True,
        solution=solution,
        redundant_equations=redundant,
        inconsistent_equations=inconsistent,
    )
