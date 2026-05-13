# OProW Step 12 — Watermark Reference Implementation

This package carries forward Steps 1–11 and adds a first-draft watermark layer:

```text
oprow/watermark/
  bits.py        # explicit bit packing/unpacking helpers
  crc.py         # CRC-16/CCITT-FALSE payload checksum
  ecc.py         # toy repetition-code ECC boundary
  payload.py     # OProW compact watermark payload + sync frame codec
  base.py        # profile interfaces, extraction/embed result types, registry
  image_lsb.py   # lossless PNG alpha-LSB reference/test profile
  image_qim.py   # pure-Python DCT/QIM image watermark prototype
  workflow.py    # high-level embed/extract/verify helpers
```

The code is intentionally literate.  Each file explains the theory it implements,
the security boundary, and what is merely a reference/testing choice.

## What Step 12 implements

The compact payload follows the OProW watermark design:

```text
4 bits   version
12 bits  watermark algorithm numeric id
8 bits   flags, with bits 0..1 encoding pointer mode
160 bits FULL160 / FULL160_RATELESS pointer, or 64 bits SHORT64 / SHORT64-HV pointer
16 bits  CRC-16 checksum over header+pointer
```

The frame codec wraps that payload as:

```text
"OPRW" preamble || 16-bit payload length || payload bits
```

then applies a toy repetition code.  This is deliberately not a production ECC
layer.  It provides a clear boundary where BCH/LDPC/rateless codes can be added
later.

## Included profiles

### `IMG-ALPHA-LSB-REF-1`

A deterministic, lossless PNG test carrier.  It stores the framed bitstream in
the least significant bit of the alpha channel.  It preserves RGB values, so the
Step 3 `PED-IMG-1` essence hash remains stable in tests.

This is **not** robust against JPEG conversion, alpha stripping, screenshots, or
social-media pipelines.

### `IMG-DCT-QIM-REF-1`

A pure-Python block-DCT/QIM prototype.  It modifies one mid-frequency luminance
coefficient per 8×8 block.  It shows how the baseline OProW DCT/QIM idea plugs
into the same payload and ECC boundary.

This is a research/prototype carrier, not a production robust watermark.

## Security boundary

Watermark extraction only recovers a locator.  It does **not** prove provenance.
The final `VERIFIED` result still requires:

1. manifest resolution,
2. locator self-consistency,
3. valid manifest signatures,
4. essence/content binding,
5. local trust-policy acceptance.

The workflow helper `verify_artifact_from_watermark(...)` makes that boundary
explicit by first extracting a locator and then calling the Step 5 verifier.

## Example

```bash
python examples/step12_watermark_reference.py
```

Expected output includes:

```text
watermark extraction: extracted
verification status: verified
verified: True
```

## Tests

```bash
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest -q
```
