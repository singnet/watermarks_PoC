# OProW Python reference draft — Step 13

Step 13 adds **rateless FULL160 experiments** on top of the Step 1–12 OProW SDK draft.

The new idea is to recover a 160-bit manifest locator from many local one-bit equations rather than embedding one conventional 160-bit payload block.  Each tile/window carries:

```text
equation_id, rhs_bit
```

The equation vector is regenerated deterministically from a public seed:

```text
a_i = SparseMask(seed, equation_id)
y_i = <a_i, manifest_key> mod 2
```

Extraction collects surviving equations and solves a GF(2) linear system.  If enough independent equations survive, the decoder reconstructs the original FULL160 manifest key and hands it to the normal OProW verifier.

## New modules

```text
oprow/rateless/
  gf2.py          # transparent GF(2) Gaussian elimination over Python ints
  equations.py    # deterministic sparse equation generation for FULL160 keys
  records.py      # compact repeated tile records carrying equation_id + rhs
  image_alpha.py  # experimental alpha-LSB tile carrier for images
```

## Important caveats

The included carrier `IMG-ALPHA-LSB-RATELESS-FULL160-EXP-1` is a **research harness**, not a production watermark.  It preserves RGB values and therefore keeps `PED-IMG-1` stable, which is useful for end-to-end tests.  It does not solve robust geometric synchronization, JPEG survival, screenshots, crop-induced grid shifts, or social-media transcoding.  Those should be addressed by later native DCT/spread-spectrum/video/audio carriers.

The security boundary remains unchanged:

```text
rateless solve -> recovered locator only
recovered locator -> resolve candidate manifest
candidate manifest -> verify locator consistency, signatures, essence, trust policy
```

A successful GF(2) solve is not provenance verification by itself.

## Run tests

```bash
python -m pytest -q
```

## Run the example

```bash
python examples/step13_rateless_full160.py
```
