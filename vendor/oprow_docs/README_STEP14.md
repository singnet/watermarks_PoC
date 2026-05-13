# OProW Step 14 — Transform and Adversarial Benchmark Harness

Step 14 adds a first-draft measurement harness to the OProW Python reference SDK.
The goal is not to certify any watermark, essence, or HDC profile as secure. The
goal is to make the right experiments easy to run and hard to misinterpret.

The new package is:

```text
oprow/benchmark/
  reports.py       # JSON-serializable benchmark cases and reports
  metrics.py       # image PSNR/MSE, byte and bit diagnostics
  transforms.py    # deterministic image transform suites
  essence.py       # PED/essence stability and separation benchmarks
  watermark.py     # embed -> transform -> extract channel benchmarks
  hdc.py           # HDC stability, separation, and route-token overlap
  adversarial.py   # stripping, occlusion, alpha copy/paste probes
  samples.py       # tiny deterministic synthetic image corpus
  pipeline.py      # convenience harness for combined reports
```

The benchmark layer follows the OProW security boundary from the draft: the
watermark and HDC layers are retrieval/routing aids; final provenance still
requires manifest locator consistency, valid signatures, essence/content binding,
and local trust policy. In particular, copy/paste watermark attacks are expected
to produce a recoverable locator but then fail the signed essence check.

## Example

```python
from oprow import (
    AlphaLSBImageWatermarkProfile, BenchmarkHarness, HDCProfile, ImagePED1,
    ManifestKey, PointerMode, SymbolicBundlingHDCEncoder, WatermarkPayload,
    WatermarkStrength, default_synthetic_image_corpus, quick_image_transform_suite,
)

artifacts = default_synthetic_image_corpus()
harness = BenchmarkHarness(artifacts=artifacts, transform_suite=quick_image_transform_suite())

wm = AlphaLSBImageWatermarkProfile()
payload = WatermarkPayload(
    version=1,
    wm_alg_id=wm.numeric_id,
    pointer_mode=PointerMode.FULL160,
    pointer=ManifestKey(b"\x42" * 20),
).with_computed_crc()

encoder = SymbolicBundlingHDCEncoder(HDCProfile(
    profile_id="HV-PED-IMG-1-D512-EXAMPLE",
    dimension=512,
    num_bands=8,
    bits_per_band=8,
))

report = harness.run_all_basic(
    essence_profile=ImagePED1(),
    hdc_encoder=encoder,
    watermark_profile=wm,
    watermark_payload=payload,
    watermark_strength=WatermarkStrength(name="example-alpha", repetitions=3),
)
print(report.summary())
```

Run the bundled example:

```bash
python examples/step14_benchmark_harness.py
```

## Implementation notes

* The transform suite is deterministic and local. It includes identity, PNG
  round-trip, JPEG recompression, resizing, crop/resize, blur, noise, screenshot
  simulation, and a generic social-media-like pipeline.
* The watermark benchmark measures locator recovery only. It does not claim
  provenance verification.
* The essence benchmark measures whether the profile's hash stays stable under
  transforms and records PED-IMG-1 diagnostic distances.
* The HDC benchmark measures normalized Hamming distance and optional route-token
  overlap. HDC is treated as fuzzy routing, not cryptography.
* The adversarial helpers include alpha-LSB stripping and a toy alpha-carrier
  copy/paste attack. The included test confirms that the copied locator is
  rejected by the final verifier because the target image's essence does not
  match the signed manifest.

## Current limitations

This is a first-draft benchmark harness. It is not yet a large-scale evaluation
system. Missing pieces include video/audio transform suites, real social-platform
capture pipelines, multiprocessing, corpus manifests, FAISS/HDC large-corpus
candidate-count experiments, richer adversarial optimization attacks, and CI
threshold policies.
