# openwater-mk — Internal Demo

Licensed under the [Apache License 2.0](LICENSE).


Minimal runnable end-to-end demo of the OpenWater provenance watermark stack,
built on top of the `oprow_step14_benchmarks` Version-0 reference SDK (sibling
directory).

**Scope:** internal demo only. Image-only. Local CAS. Local Ed25519 keys.
Reference (alpha-LSB) watermark carrier — **not** robust against
JPEG/social-media recompression. No Arweave/IPFS, no Cardano anchor, no
Rholang, no Hyperon. Those land in V1+ per the OpenWater roadmap.

## What this shows

1. Sign a manifest binding artifact essence (PED-IMG-1) + creation claims
   with an Ed25519 key.
2. Embed the manifest locator into the artifact via alpha-LSB carrier.
3. Persist watermarked PNG to disk.
4. Extract the locator from the watermarked image, resolve the manifest from
   a local content-addressed store, verify signature + essence binding +
   local trust policy.
5. Emit a JSON verification report.

The security boundary, per the OpenWater design doc:

> Watermark/HDC layers are retrieval/routing aids. Final provenance requires
> manifest locator consistency, valid signatures, essence/content binding,
> and local trust policy.

The `--tamper` flag demonstrates this: a copy/paste or pixel-mutation attack
can leave the locator recoverable but **must** fail the essence check.

## Quick start

```bash
./scripts/setup.sh          # create .venv, install oprow editable from sibling
./scripts/demo.sh           # run end-to-end demo with synthetic image
ls out/                     # watermarked.png, verify_report.json
```

Or by hand:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ../oprow_step14_benchmarks
python demo_internal.py
python demo_internal.py --tamper           # negative case: verified=false
```

## Layout

```
openwater-demo/
├── demo_internal.py        # the demo script
├── scripts/
│   ├── setup.sh            # venv + install
│   └── demo.sh             # one-shot run
├── out/                    # demo outputs
│   ├── watermarked.png     # last healthy run
│   ├── verify_report.json
│   └── _tamper_sample/     # captured --tamper run for reference
└── README.md
```

## Security boundary check

With `--tamper`, the script inverts the center RGB region of the watermarked
image, leaving the alpha channel (which carries the locator) intact. The
expected outcome:

| Field | Value | Meaning |
| --- | --- | --- |
| `extraction_status` | `extracted` | locator survived (alpha bits unchanged) |
| `verification_status` | `content_mismatch` | PED-IMG-1 essence disagrees with the manifest |
| `verified` | `false` | rejection is correct |

This is the watermark/copy-paste resistance story from §21.1–21.2 of the
OpenWater design doc: extracting a locator is **not** proof of provenance —
the manifest's essence binding must match the artifact's content.

## Defer to V1+

- CLI entrypoint (`openwater sign|embed|verify`)
- Arweave / IPFS manifest storage
- Cardano metadata anchoring
- SHORT64-HV pointer mode (for low-capacity channels)
- C2PA SDK / JUMBF packaging
- Rholang trust-machine contracts
- Hyperon/MeTTa policy evaluation
- Robust DCT/QIM watermark (alpha-LSB survives PNG round-trip only — fails
  JPEG, social-media re-encode, screenshots)
