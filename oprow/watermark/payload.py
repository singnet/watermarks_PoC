"""OProW watermark payload and sync-frame codec.

This file implements the compact pointer payload described in the OProW design:

* 4 bits  -- OProW watermark payload version
* 12 bits -- watermark algorithm numeric identifier
* 8 bits  -- flags, with bits 0..1 selecting pointer mode
* 160 bits for FULL160 / FULL160_RATELESS locators, or 64 bits for SHORT64 /
  SHORT64-HV locators
* 16 bits -- CRC-16 over the header and pointer bits

The resulting raw payload is 200 bits in FULL160 mode and 104 bits in SHORT64
mode.  The frame codec then prepends a sync preamble and payload-length field
before handing the bits to an ECC layer.  This mirrors the paper-level design:
the watermark carrier is an unreliable channel; the payload format is a compact
semantic object; ECC/synchronization are engineering wrappers around it.

Important security boundary:

The decoded payload is only a **locator**.  A successful CRC does not mean the
media is verified.  It only means the extractor probably recovered a well-formed
pointer.  The verifier must still resolve a manifest and check locator
self-consistency, signatures, essence binding, and trust policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from oprow.core.enums import PointerMode
from oprow.core.errors import ValidationError
from oprow.core.identifiers import ManifestKey, ShortId
from oprow.core.models import ManifestLocator, SignedManifest
from .bits import bits_to_bytes, bits_to_int, bytes_to_bits, int_to_bits, normalize_bits
from .crc import crc16_ccitt_false
from .ecc import RepetitionCode, RepetitionDecodeReport

WATERMARK_PAYLOAD_VERSION = 1

# Numeric IDs are a compact 12-bit wire field.  String algorithm identifiers are
# still used in manifests and registries; these numeric IDs are only the in-band
# watermark profile hint.  The Step 12 IDs are intentionally in a private/reference
# range and can be remapped by a future standards registry.
IMG_ALPHA_LSB_REF_NUMERIC_ID = 0x001
IMG_DCT_QIM_REF_NUMERIC_ID = 0x002

POINTER_MODE_FLAG_MASK = 0b00000011
_MODE_TO_FLAG = {
    PointerMode.FULL160: 0,
    PointerMode.SHORT64: 1,
    PointerMode.SHORT64_HV: 2,
    PointerMode.FULL160_RATELESS: 3,
}
_FLAG_TO_MODE = {v: k for k, v in _MODE_TO_FLAG.items()}

_HEADER_BITS = 4 + 12 + 8
_CRC_BITS = 16
_FULL_POINTER_BITS = 160
_SHORT_POINTER_BITS = 64

# 0x4f505257 is ASCII "OPRW".  It functions as a sync/preamble marker for the
# reference carriers.  Production robust watermarks will likely use a stronger
# spread synchronization template, but a fixed preamble is enough for this
# Python reference codec.
FRAME_PREAMBLE_BITS = bytes_to_bits(b"OPRW")
FRAME_LENGTH_BITS = 16


@dataclass(frozen=True)
class WatermarkPayload:
    """Compact locator payload recovered from an in-band watermark.

    ``wm_alg_id`` is numeric because the payload field is only 12 bits.  The
    corresponding profile exposes a human-readable string ``alg_id`` such as
    ``IMG-ALPHA-LSB-REF-1``.  ``extra_flags`` stores flag bits above the pointer
    mode bits; by default they are zero.
    """

    version: int
    wm_alg_id: int
    pointer_mode: PointerMode
    pointer: ManifestKey | ShortId
    extra_flags: int = 0
    crc16: int | None = None
    # The HDC profile ID and derivation profile are not in the compact payload
    # in this draft.  They are verifier context used to reconstruct a locator.
    hdc_profile_id: str | None = None
    derivation_profile: str = "hash_truncated"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not (0 <= self.version <= 0xF):
            raise ValidationError("watermark version must fit in 4 bits")
        if not (0 <= self.wm_alg_id <= 0xFFF):
            raise ValidationError("wm_alg_id must fit in 12 bits")
        if not (0 <= self.extra_flags <= 0xFC):
            raise ValidationError("extra_flags must fit in the non-mode bits of the 8-bit flags field")
        if self.extra_flags & POINTER_MODE_FLAG_MASK:
            raise ValidationError("extra_flags must not set pointer-mode bits 0..1")
        if self.pointer_mode in (PointerMode.FULL160, PointerMode.FULL160_RATELESS):
            if not isinstance(self.pointer, ManifestKey):
                raise ValidationError(f"{self.pointer_mode.value} payload requires ManifestKey pointer")
        elif self.pointer_mode in (PointerMode.SHORT64, PointerMode.SHORT64_HV):
            if not isinstance(self.pointer, ShortId):
                raise ValidationError(f"{self.pointer_mode.value} payload requires ShortId pointer")
        else:
            raise ValidationError(f"unsupported pointer mode {self.pointer_mode!r}")
        if self.crc16 is not None and not (0 <= self.crc16 <= 0xFFFF):
            raise ValidationError("crc16 must fit in 16 bits")

    @property
    def flags(self) -> int:
        """Return the complete 8-bit flags field."""

        return self.extra_flags | _MODE_TO_FLAG[self.pointer_mode]

    @property
    def pointer_bit_length(self) -> int:
        """Return 160 for FULL locators or 64 for SHORT locators."""

        if self.pointer_mode in (PointerMode.FULL160, PointerMode.FULL160_RATELESS):
            return _FULL_POINTER_BITS
        return _SHORT_POINTER_BITS

    @property
    def payload_bit_length(self) -> int:
        """Total raw payload bits including CRC."""

        return _HEADER_BITS + self.pointer_bit_length + _CRC_BITS

    def bits_without_crc(self) -> list[int]:
        """Serialize the version, algorithm ID, flags, and pointer bits."""

        bits: list[int] = []
        bits.extend(int_to_bits(self.version, 4))
        bits.extend(int_to_bits(self.wm_alg_id, 12))
        bits.extend(int_to_bits(self.flags, 8))
        bits.extend(bytes_to_bits(self.pointer.value))
        return bits

    def compute_crc16(self) -> int:
        """CRC over header+pointer bits packed into bytes."""

        return crc16_ccitt_false(bits_to_bytes(self.bits_without_crc(), pad=True))

    def to_bits(self) -> list[int]:
        """Serialize the full payload, computing CRC if absent."""

        crc = self.compute_crc16() if self.crc16 is None else self.crc16
        return self.bits_without_crc() + int_to_bits(crc, 16)

    def with_computed_crc(self) -> "WatermarkPayload":
        """Return an equivalent payload with ``crc16`` populated."""

        return WatermarkPayload(
            version=self.version,
            wm_alg_id=self.wm_alg_id,
            pointer_mode=self.pointer_mode,
            pointer=self.pointer,
            extra_flags=self.extra_flags,
            crc16=self.compute_crc16(),
            hdc_profile_id=self.hdc_profile_id,
            derivation_profile=self.derivation_profile,
            metadata=dict(self.metadata),
        )

    @classmethod
    def from_locator(
        cls,
        locator: ManifestLocator,
        *,
        wm_alg_id: int,
        version: int = WATERMARK_PAYLOAD_VERSION,
        extra_flags: int = 0,
    ) -> "WatermarkPayload":
        """Create a payload from a manifest locator."""

        return cls(
            version=version,
            wm_alg_id=wm_alg_id,
            pointer_mode=locator.mode,
            pointer=locator.value,
            extra_flags=extra_flags,
            hdc_profile_id=locator.hdc_profile_id,
            derivation_profile=locator.derivation_profile,
        ).with_computed_crc()

    @classmethod
    def from_signed_manifest(
        cls,
        manifest: SignedManifest,
        *,
        pointer_mode: PointerMode,
        wm_alg_id: int,
        hdc_profile_id: str | None = None,
    ) -> "WatermarkPayload":
        """Derive the appropriate locator from a signed manifest and encode it."""

        locator = ManifestLocator.from_signed_manifest(manifest, mode=pointer_mode, hdc_profile_id=hdc_profile_id)
        return cls.from_locator(locator, wm_alg_id=wm_alg_id)

    def to_locator(self) -> ManifestLocator:
        """Convert this decoded payload back to a ``ManifestLocator``.

        FULL160/FULL160_RATELESS locators are content-addressed H160 pointers.
        SHORT64/SHORT64-HV locators use the configured short-ID derivation
        profile, which defaults to ``hash_truncated`` in this draft.
        """

        derivation = "h160" if self.pointer_mode in (PointerMode.FULL160, PointerMode.FULL160_RATELESS) else self.derivation_profile
        return ManifestLocator(
            mode=self.pointer_mode,
            value=self.pointer,
            hdc_profile_id=self.hdc_profile_id,
            derivation_profile=derivation,
        )

    @classmethod
    def decode_bits(
        cls,
        bits: Sequence[int],
        *,
        hdc_profile_id: str | None = None,
        derivation_profile: str = "hash_truncated",
        require_crc: bool = True,
    ) -> "WatermarkPayload":
        """Decode a payload bitstream and validate CRC by default."""

        normalized = normalize_bits(bits)
        if len(normalized) < _HEADER_BITS:
            raise ValidationError("not enough bits to decode watermark payload header")
        version = bits_to_int(normalized[0:4])
        wm_alg_id = bits_to_int(normalized[4:16])
        flags = bits_to_int(normalized[16:24])
        try:
            mode = _FLAG_TO_MODE[flags & POINTER_MODE_FLAG_MASK]
        except KeyError as exc:
            raise ValidationError(f"unknown pointer mode flag {flags & POINTER_MODE_FLAG_MASK}") from exc
        pointer_bits = _FULL_POINTER_BITS if mode in (PointerMode.FULL160, PointerMode.FULL160_RATELESS) else _SHORT_POINTER_BITS
        total = _HEADER_BITS + pointer_bits + _CRC_BITS
        if len(normalized) < total:
            raise ValidationError(f"not enough bits to decode {mode.value} payload: need {total}, got {len(normalized)}")
        pointer_bytes = bits_to_bytes(normalized[_HEADER_BITS : _HEADER_BITS + pointer_bits], pad=False)
        pointer = ManifestKey(pointer_bytes) if pointer_bits == _FULL_POINTER_BITS else ShortId(pointer_bytes)
        crc = bits_to_int(normalized[_HEADER_BITS + pointer_bits : total])
        payload = cls(
            version=version,
            wm_alg_id=wm_alg_id,
            pointer_mode=mode,
            pointer=pointer,
            extra_flags=flags & ~POINTER_MODE_FLAG_MASK,
            crc16=crc,
            hdc_profile_id=hdc_profile_id,
            derivation_profile=derivation_profile,
        )
        if require_crc and payload.compute_crc16() != crc:
            raise ValidationError(f"watermark payload CRC mismatch: expected {payload.compute_crc16():04x}, got {crc:04x}")
        return payload


def payload_bit_length_for_mode(mode: PointerMode) -> int:
    """Return raw payload bits including CRC for a pointer mode."""

    pointer_bits = _FULL_POINTER_BITS if mode in (PointerMode.FULL160, PointerMode.FULL160_RATELESS) else _SHORT_POINTER_BITS
    return _HEADER_BITS + pointer_bits + _CRC_BITS


@dataclass(frozen=True)
class WatermarkFrameDecodeReport:
    """Result of decoding a sync frame around a payload."""

    payload_bits: list[int]
    decoded_bits_seen: int
    preamble_offset: int
    repetition_report: RepetitionDecodeReport


@dataclass(frozen=True)
class WatermarkFrameCodec:
    """Sync-frame codec plus a pluggable error-correction layer.

    The frame format before ECC is:

    ``FRAME_PREAMBLE_BITS || payload_bit_length_u16 || payload_bits``

    The current extractor assumes the frame begins at the first carrier bit but
    still scans a small configurable window for the preamble.  This is a toy
    version of geometric/sync recovery: it catches small leading offsets in
    tests without pretending to solve rotation, crop, or scale correction.
    """

    ecc: RepetitionCode = field(default_factory=lambda: RepetitionCode(3))
    max_preamble_scan_bits: int = 64

    def encode_payload_bits(self, payload_bits: Sequence[int]) -> list[int]:
        payload_bits_norm = normalize_bits(payload_bits)
        if len(payload_bits_norm) >= (1 << FRAME_LENGTH_BITS):
            raise ValidationError("payload bitstream too long for 16-bit watermark frame length")
        raw = list(FRAME_PREAMBLE_BITS)
        raw.extend(int_to_bits(len(payload_bits_norm), FRAME_LENGTH_BITS))
        raw.extend(payload_bits_norm)
        return self.ecc.encode(raw)

    def encode_payload(self, payload: WatermarkPayload) -> list[int]:
        """Serialize and ECC-frame a ``WatermarkPayload``."""

        return self.encode_payload_bits(payload.to_bits())

    def decode_payload_bits(self, carrier_bits: Sequence[int]) -> WatermarkFrameDecodeReport:
        """Decode ECC carrier bits, find preamble, and return raw payload bits."""

        report = self.ecc.decode(carrier_bits)
        bits = report.decoded_bits
        search_limit = min(max(0, self.max_preamble_scan_bits), max(0, len(bits) - len(FRAME_PREAMBLE_BITS)))
        preamble_offset = -1
        for offset in range(search_limit + 1):
            if bits[offset : offset + len(FRAME_PREAMBLE_BITS)] == FRAME_PREAMBLE_BITS:
                preamble_offset = offset
                break
        if preamble_offset < 0:
            raise ValidationError("watermark sync preamble not found")
        pos = preamble_offset + len(FRAME_PREAMBLE_BITS)
        if len(bits) < pos + FRAME_LENGTH_BITS:
            raise ValidationError("watermark frame missing length field")
        payload_len = bits_to_int(bits[pos : pos + FRAME_LENGTH_BITS])
        start = pos + FRAME_LENGTH_BITS
        end = start + payload_len
        if len(bits) < end:
            raise ValidationError(f"watermark frame truncated: need {end} decoded bits, got {len(bits)}")
        return WatermarkFrameDecodeReport(
            payload_bits=bits[start:end],
            decoded_bits_seen=len(bits),
            preamble_offset=preamble_offset,
            repetition_report=report,
        )

    def decode_payload(
        self,
        carrier_bits: Sequence[int],
        *,
        hdc_profile_id: str | None = None,
        derivation_profile: str = "hash_truncated",
    ) -> tuple[WatermarkPayload, WatermarkFrameDecodeReport]:
        """Decode a framed payload and return payload plus diagnostics."""

        frame = self.decode_payload_bits(carrier_bits)
        payload = WatermarkPayload.decode_bits(
            frame.payload_bits,
            hdc_profile_id=hdc_profile_id,
            derivation_profile=derivation_profile,
            require_crc=True,
        )
        return payload, frame
