# OpenWater Internal Demo — Runbook

Show in 5 commands. Total walkthrough ~3 minutes.

## Prereqs (one-time)

```bash
cd openwater-demo
./scripts/setup.sh
```

This creates `.venv/`, installs the upstream oprow Version 0 SDK editable
from the sibling directory, and runs its 85-case test suite as a smoke check.

## The demo

### 1. Healthy path — sign, embed, verify (in-process)

```bash
./scripts/demo.sh
# equivalent: openwater demo
```

Expected last line:
```
verified=True  extraction=extracted  verification=verified  report=out/verify_report.json
```

Then show:
```bash
ls out/
cat out/verify_report.json
```

Talking points:
- Local Ed25519 key generated in-memory.
- PED-IMG-1 perceptual essence computed and bound into the signed manifest.
- 160-bit pointer encoded into the alpha channel LSBs with 3x redundancy
  (744 of 36864 carrier bits used — plenty of headroom for a real payload).
- Verifier extracted the locator, fetched the manifest from local CAS,
  validated the signature, matched the essence, and applied the local
  trust policy.

### 2. Security boundary — copy/paste / tamper attack

```bash
./scripts/demo.sh --tamper
```

Expected:
```
verified=False  extraction=extracted  verification=content_mismatch
```

Talking point: **locator recovery is not proof of provenance.** The alpha
channel still carries the original pointer, so a naive verifier would say
"manifest found". OpenWater requires the manifest's essence binding to
match the artifact's PED-IMG-1 hash — and it does not, so the artifact is
correctly rejected. This is what kills copy/paste attacks: the attacker
can move the watermark, but the essence binding does not move with it.
See §21.1–21.2 of the OpenWater design doc.

### 3. Channel robustness — what alpha-LSB survives

```bash
./scripts/demo.sh --transform png_rgba   # PNG re-encode keeping alpha  -> verified
./scripts/demo.sh --transform png_rgb    # PNG re-encode stripping alpha -> no_watermark
./scripts/demo.sh --transform jpeg_q82   # JPEG q=82                      -> no_watermark
```

Talking point: the alpha-LSB carrier is the **reference / profile** carrier.
Real social-media channels recompress to JPEG and strip alpha — the
locator does not survive. A production deployment uses a DCT/QIM carrier
or a licensed library; that work is the V8 line item in the
implementation-time-estimates doc and is not on the path to first alpha.

### 4. Tests as living acceptance criteria

```bash
.venv/bin/python -m pytest tests/ -v
```

Should show 7 passing in under a second. These pin the security-boundary
and robustness expectations so future changes cannot silently regress.

### 4b. Cross-process workflow (closer to the V1 shape)

```bash
openwater sign-embed --out /tmp/run1
openwater inspect /tmp/run1/watermarked.png      # locator only, no verify
openwater verify /tmp/run1/watermarked.png \
    --manifest-store /tmp/run1/manifests \
    --key /tmp/run1/key.json
```

Talking point: this is the shape the real product will use. The manifest
store will move from local `FileCAS` to Arweave/IPFS in the next phase;
the trust-policy and key-resolver pieces will move from a local JSON
envelope to a registry-backed lookup. The CLI surface stays the same.

### 5. Cleanup (optional)

```bash
rm -rf out/watermarked.png out/verify_report.json out/transformed_*
# Keep out/_tamper_sample/ and out/_transform_samples/ — they are committed.
```

## Where things live

| Thing | Path |
| --- | --- |
| Orchestration | `demo_internal.py` (`run_demo()` is the entry function) |
| Tests | `tests/test_demo.py` |
| Upstream oprow SDK | `../oprow_step14_benchmarks/` (editable install) |
| Sample outputs | `out/_tamper_sample/`, `out/_transform_samples/<name>/` |
| Design doc | `../OpenWater_Comprehensive_Design.pdf` (74 pages) |
| Effort estimates | `../OpenWater_Implementation_Time_Estimates_v0_1.pdf` |
| Source code, oprow | sibling dir, treated as Version 0 reference scaffold |

## Honest caveats to flag verbally

1. **Reference-grade watermark.** Alpha-LSB is fragile by design. It exists
   so the rest of the stack can be demoed; production carriers are V8 work.
2. **No chain anchor yet.** Manifests live in an in-process MemoryCAS.
   Arweave/IPFS storage and Cardano metadata anchors are the next two
   phases (V1 path per estimates doc).
3. **Local trust policy only.** No transparency log, no trust bundle from
   a registry, no key transparency. The verifier accepts the local
   ephemeral key as trusted for demo purposes only.
4. **Provenance not authenticity.** A `verified=true` result means "this
   artifact's essence binds to a signed manifest from a trusted key". It
   does **not** mean "the events depicted are true" — the OpenWater UX
   layer is responsible for making that distinction visible.
