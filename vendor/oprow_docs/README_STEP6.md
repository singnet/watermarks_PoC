# OProW Python Reference Draft — Step 6

Step 6 adds a C2PA / Durable Content Credentials adapter skeleton on top of the
Step 1–5 OProW prototype.

The important design choice is that this code does **not** try to replace C2PA.
Instead, it treats OProW as a C2PA-compatible profile:

- C2PA-style manifests carry a standard-looking `c2pa.soft-binding` assertion.
- The soft binding carries the OProW locator recovered from a watermark.
- A custom `org.oprow.manifest.v1` assertion preserves the exact OProW
  `SignedManifest` bytes for lossless OProW verification.
- Custom OProW assertions expose the perceptual essence commitment, locator,
  and signature summary for debugging and future official-SDK integration.
- A placeholder `C2PASDKBridge` makes it explicit where a production C2PA SDK
  should eventually package, embed, and sign real C2PA Manifest Stores.

## New files

```text
oprow/c2pa/
  models.py        # C2PA-like Manifest / Claim / Assertion / ManifestStore models
  soft_binding.py  # OProW locator as c2pa.soft-binding assertion
  adapter.py       # OProW SignedManifest/Envelope -> C2PA-like Manifest mapping
  repository.py    # Draft Soft Binding Resolution API request/response shapes
  bridge.py        # Placeholder interface for official C2PA SDK integration
  __init__.py
examples/
  step6_c2pa_adapter.py
tests/
  test_step6_c2pa.py
```

## What this step deliberately does not implement

This is not a normative C2PA JUMBF/COSE/crJSON writer. The exact C2PA packaging
is intentionally deferred to an official SDK bridge. This draft gives the coding
agent a clear adapter architecture and testable data structures without making
OProW's core verifier depend on the C2PA stack.

## Run tests

```bash
python -m pytest -q
```

Expected result for this draft:

```text
40 passed
```
