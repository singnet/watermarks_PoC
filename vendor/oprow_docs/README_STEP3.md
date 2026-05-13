# OProW Python reference draft — Step 3

This package carries forward Steps 1 and 2 and adds the first media essence
profile: `PED-IMG-1`.

The design point is important: an OProW manifest should sign a commitment to
standardized media essence, not fragile container bytes.  The baseline image
profile computes a deterministic 1056-byte perceptual essence descriptor:

```text
1024 bytes: 32 x 32 grid of rounded block means over 256 x 256 luminance
  32 bytes: packed signs of 255 low-frequency DCT coefficients over 64 x 64 luminance
```

The signed `essence_hash` is:

```text
H256(frame("oprow-ped-essence-hash-v1", essence_alg_id, PED))
```

This length-framed form implements the OProW draft's intent while avoiding
ambiguous concatenation.

## Files added in Step 3

```text
oprow/essence/base.py      profile interface and PED hash framing
oprow/essence/image.py     PED-IMG-1 reference implementation
oprow/essence/strict.py    optional strict byte hash
oprow/essence/registry.py  local essence profile registry
examples/step3_compute_ped_img1.py
tests/test_step3_essence_img1.py
```

## Run tests

```bash
python -m pip install -e . pytest
python -m pytest
```

## Caveats

`PED-IMG-1` is a simple reference profile.  It is deterministic and useful for
architecture work, but it must be benchmarked before any production claims about
robustness.  Step 14 will add transform/adversarial tests for JPEG/WebP/AVIF,
resize, crop, screenshot simulation, and malicious near-collisions.
