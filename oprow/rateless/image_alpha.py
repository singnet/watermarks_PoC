"""Reference image carrier for rateless FULL160 equations.

This file implements an experimental, intentionally transparent carrier:
``IMG-ALPHA-LSB-RATELESS-FULL160-EXP-1``.

Why another alpha-LSB carrier?
------------------------------
Step 12 already included an alpha-LSB profile that stores a whole framed payload
at the start of the image.  Step 13 tests a different mathematical idea: spread
one-bit equations about the FULL160 locator across many independent tiles.  The
alpha channel is used again because it lets us exercise that algorithm while
preserving RGB values and therefore preserving the signed PED-IMG-1 essence
commitment.  This is a research carrier, not a production watermark.

Carrier structure
-----------------
* Convert the image to RGBA PNG.
* Divide it into fixed-size square tiles, default 16x16 pixels.
* Each tile receives one repeated ``RatelessTileRecord`` in alpha LSBs.
* The tile index is the equation ID.  The equation vector is regenerated from a
  public seed and the ID; only the ID and RHS bit are embedded.
* Extraction decodes records from all tiles, regenerates equations, and solves
  the GF(2) system for the manifest key.

What this demonstrates
----------------------
If some tiles are erased, overwritten, or fail CRC, the decoder can still recover
as long as enough independent equations survive.  This is the "rateless" property
we want to benchmark for real image/video/audio carriers.

What this does not demonstrate
------------------------------
This carrier does not solve geometric synchronization, JPEG survival, screenshots,
or crop-induced grid shifts.  A production version would need robust sync marks,
DCT/spread-spectrum embedding, soft-decision decoding, and transform benchmarks.
The solver and equation layer here are reusable; the alpha-LSB tile carrier is a
laboratory harness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from io import BytesIO
from typing import Iterable

import numpy as np
from PIL import Image, ImageOps

from oprow.core.enums import PointerMode
from oprow.core.errors import ValidationError
from oprow.core.identifiers import ManifestKey
from oprow.core.models import Artifact
from oprow.watermark.base import (
    WatermarkCapacityError,
    WatermarkEmbedResult,
    WatermarkExtraction,
    WatermarkExtractionStatus,
    WatermarkStrength,
)
from oprow.watermark.payload import WATERMARK_PAYLOAD_VERSION, WatermarkPayload
from .equations import (
    RatelessEquation,
    RatelessEquationProfile,
    equation_for_key,
    solve_manifest_key_from_equations,
)
from .records import RATELESS_RECORD_BITS, RatelessTileRecord, encode_repeated_record, majority_decode_repeated_record

IMG_ALPHA_LSB_RATELESS_FULL160_EXP_ALG_ID = "IMG-ALPHA-LSB-RATELESS-FULL160-EXP-1"
IMG_ALPHA_LSB_RATELESS_FULL160_EXP_NUMERIC_ID = 0x013


@dataclass(frozen=True)
class RatelessAlphaLSBFull160Profile:
    """Experimental tile-based rateless image watermark profile.

    The profile conforms to the Step 12 ``WatermarkProfile`` protocol, but its
    extraction algorithm does not decode a conventional framed payload.  Instead
    it reconstructs a FULL160 locator from local equations and then constructs a
    ``WatermarkPayload`` object around the recovered key.
    """

    alg_id: str = IMG_ALPHA_LSB_RATELESS_FULL160_EXP_ALG_ID
    numeric_id: int = IMG_ALPHA_LSB_RATELESS_FULL160_EXP_NUMERIC_ID
    tile_size: int = 16
    equation_profile: RatelessEquationProfile = field(default_factory=RatelessEquationProfile)
    media_types: set[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.media_types is None:
            object.__setattr__(self, "media_types", {"image/png", "image/jpeg", "image/webp", "image/*"})
        if self.tile_size <= 0:
            raise ValidationError("tile_size must be positive")

    def _decode_rgba(self, artifact: Artifact) -> tuple[Image.Image, np.ndarray]:
        try:
            with Image.open(BytesIO(artifact.read_bytes())) as img:
                normalized = ImageOps.exif_transpose(img).convert("RGBA")
                return normalized, np.asarray(normalized, dtype=np.uint8).copy()
        except Exception as exc:
            raise ValidationError(f"failed to decode image for rateless alpha-LSB watermarking: {exc}") from exc

    def _tile_coords(self, width: int, height: int) -> list[tuple[int, int, int]]:
        """Return ``(equation_id, x0, y0)`` for complete tiles.

        We intentionally ignore partial edge tiles.  A production robust profile
        might use overlapping windows or scale-normalized coordinates; this
        reference profile keeps the mapping deterministic and simple.
        """

        tiles_x = width // self.tile_size
        tiles_y = height // self.tile_size
        coords: list[tuple[int, int, int]] = []
        eid = 0
        for ty in range(tiles_y):
            for tx in range(tiles_x):
                if eid > self.equation_profile.max_equation_id:
                    return coords
                coords.append((eid, tx * self.tile_size, ty * self.tile_size))
                eid += 1
        return coords

    def _tile_capacity_bits(self) -> int:
        return self.tile_size * self.tile_size

    def _record_repetitions(self, strength: WatermarkStrength | None) -> int:
        # Reuse the generic WatermarkStrength.repetitions knob.  For this
        # carrier it means local repetition inside each tile, not repetition of a
        # whole frame.  The default 3 fits in 16x16 tiles.
        return int((strength or WatermarkStrength(name="rateless-alpha", repetitions=3)).repetitions)

    def capacity_bits(self, artifact: Artifact, *, strength: WatermarkStrength | None = None) -> int:
        image, _ = self._decode_rgba(artifact)
        return len(self._tile_coords(*image.size)) * self._tile_capacity_bits()

    def equation_capacity(self, artifact: Artifact) -> int:
        """Return the number of tile equations available in an artifact."""

        image, _ = self._decode_rgba(artifact)
        return len(self._tile_coords(*image.size))

    def _alpha_lsb_bits_for_tile(self, arr: np.ndarray, x0: int, y0: int) -> list[int]:
        alpha = arr[y0 : y0 + self.tile_size, x0 : x0 + self.tile_size, 3]
        return [int(v) & 1 for v in alpha.reshape(-1)]

    def _write_alpha_lsb_bits_to_tile(self, arr: np.ndarray, x0: int, y0: int, bits: Iterable[int]) -> None:
        alpha_tile = arr[y0 : y0 + self.tile_size, x0 : x0 + self.tile_size, 3]
        flat_alpha = alpha_tile.reshape(-1).copy()
        b = [int(bit) & 1 for bit in bits]
        if len(b) > len(flat_alpha):
            raise WatermarkCapacityError("record bitstream does not fit in tile")
        # Use fully opaque alpha values with the requested LSB.  ``reshape`` on
        # a strided tile slice may return a copy, so we write the modified flat
        # buffer back into the 2D tile explicitly.  This tiny implementation
        # detail matters: otherwise every tile would remain all-opaque alpha and
        # extraction would see no preambles.
        for i, bit in enumerate(b):
            flat_alpha[i] = 254 | bit
        alpha_tile[:, :] = flat_alpha.reshape(alpha_tile.shape)

    def embed(self, artifact: Artifact, payload: WatermarkPayload, *, strength: WatermarkStrength | None = None) -> WatermarkEmbedResult:
        """Embed a rateless FULL160 locator as tile equations."""

        repetitions = self._record_repetitions(strength)
        record_bits = RATELESS_RECORD_BITS * repetitions
        if record_bits > self._tile_capacity_bits():
            raise WatermarkCapacityError(
                f"tile capacity {self._tile_capacity_bits()} bits is insufficient for {record_bits} repeated record bits"
            )
        if payload.pointer_mode != PointerMode.FULL160_RATELESS:
            raise ValidationError("RatelessAlphaLSBFull160Profile requires pointer_mode FULL160_RATELESS")
        if not isinstance(payload.pointer, ManifestKey):
            raise ValidationError("FULL160_RATELESS payload requires ManifestKey pointer")

        image, arr = self._decode_rgba(artifact)
        coords = self._tile_coords(*image.size)
        if not coords:
            raise WatermarkCapacityError("image has no complete tiles for rateless watermarking")
        for equation_id, x0, y0 in coords:
            eq = equation_for_key(self.equation_profile, equation_id, payload.pointer, source="embed_tile")
            record = RatelessTileRecord(equation_id=equation_id, rhs=eq.rhs)
            bits = encode_repeated_record(record, repetitions=repetitions)
            self._write_alpha_lsb_bits_to_tile(arr, x0, y0, bits)

        out = Image.fromarray(arr, mode="RGBA")
        buf = BytesIO()
        out.save(buf, format="PNG")
        return WatermarkEmbedResult(
            artifact=Artifact.from_bytes(
                buf.getvalue(),
                media_type="image/png",
                metadata={**artifact.metadata, "oprow_watermark_profile": self.alg_id},
            ),
            payload=payload,
            locator=payload.to_locator(),
            profile_id=self.alg_id,
            diagnostics={
                "carrier": "rateless_alpha_lsb_tiles",
                "tile_size": self.tile_size,
                "record_bits": RATELESS_RECORD_BITS,
                "record_repetitions": repetitions,
                "equations_embedded": len(coords),
                "equation_width": self.equation_profile.width,
                "equation_weight": self.equation_profile.equation_weight,
                "mode": payload.pointer_mode.value,
            },
        )

    def extract(self, artifact: Artifact, *, strength: WatermarkStrength | None = None, hdc_profile_id: str | None = None) -> WatermarkExtraction:
        """Extract tile equations and solve for a FULL160 locator."""

        repetitions = self._record_repetitions(strength)
        try:
            image, arr = self._decode_rgba(artifact)
            coords = self._tile_coords(*image.size)
            equations: list[RatelessEquation] = []
            decode_failures = 0
            bit_disagreements = 0
            for _expected_id, x0, y0 in coords:
                try:
                    bits = self._alpha_lsb_bits_for_tile(arr, x0, y0)
                    decoded = majority_decode_repeated_record(bits, repetitions=repetitions)
                    record = decoded.record
                    # The tile location is not trusted for the equation ID; the
                    # record carries its ID so future carriers can repeat the
                    # same equation in multiple regions or channels.
                    mask_eq = equation_for_key(
                        self.equation_profile,
                        record.equation_id,
                        0,  # placeholder key; rhs is replaced below
                        confidence=decoded.confidence,
                        source="extract_tile",
                    )
                    equations.append(
                        RatelessEquation(
                            equation_id=record.equation_id,
                            mask=mask_eq.mask,
                            rhs=record.rhs,
                            confidence=decoded.confidence,
                            source="extract_tile",
                        )
                    )
                    bit_disagreements += decoded.bit_disagreements
                except Exception:
                    decode_failures += 1
                    continue

            result = solve_manifest_key_from_equations(equations, profile=self.equation_profile)
            diagnostics = {
                "carrier": "rateless_alpha_lsb_tiles",
                "tile_size": self.tile_size,
                "record_repetitions": repetitions,
                "tiles_seen": len(coords),
                "equations_recovered": len(equations),
                "decode_failures": decode_failures,
                "bit_disagreements": bit_disagreements,
                "rank": result.solve_report.rank,
                "missing_rank": result.solve_report.missing_rank,
                "unique_equations": result.unique_equations,
                "equation_width": self.equation_profile.width,
                "equation_weight": self.equation_profile.equation_weight,
            }
            if not result.solved or result.recovered_key is None:
                return WatermarkExtraction(
                    status=WatermarkExtractionStatus.NO_WATERMARK,
                    profile_id=self.alg_id,
                    diagnostics=diagnostics,
                    error="not enough independent rateless equations to recover FULL160 locator",
                )
            payload = WatermarkPayload(
                version=WATERMARK_PAYLOAD_VERSION,
                wm_alg_id=self.numeric_id,
                pointer_mode=PointerMode.FULL160_RATELESS,
                pointer=result.recovered_key,
            ).with_computed_crc()
            return WatermarkExtraction(
                status=WatermarkExtractionStatus.EXTRACTED,
                payload=payload,
                locator=payload.to_locator(),
                profile_id=self.alg_id,
                diagnostics=diagnostics,
            )
        except Exception as exc:
            return WatermarkExtraction(
                status=WatermarkExtractionStatus.ERROR,
                profile_id=self.alg_id,
                error=str(exc),
                diagnostics={"carrier": "rateless_alpha_lsb_tiles"},
            )
