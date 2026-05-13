# OProW Python Reference Draft — Step 1

This is the first implementation slice for the Open Provenance Watermarking
(OProW) Python SDK.  It contains:

1. Core protocol models.
2. Deterministic canonical CBOR encoding.
3. Typed identifiers and domain-separated hash helpers.

The code is intentionally dependency-light and heavily commented.  Later steps
will add real signing, essence hashing, resolution, C2PA adapters, HDC routing,
ASI:chain adapters, watermarking, and benchmarks.

The central model-layer fix is:

```text
ManifestCore     = signed semantic object, no locator and no signatures
SignedManifest   = ManifestCore + signatures; this is addressed by FULL160/SHORT64
ManifestEnvelope = transport wrapper with locator, storage hints, ASI/C2PA/index evidence
```

That split avoids self-referential hashing: the locator is derived from stable
`SignedManifest` bytes and is not inserted back into those bytes.

Smoke test:

```bash
cd oprow_step1_clean
python examples/step1_build_manifest.py
python -m pytest -q
```
